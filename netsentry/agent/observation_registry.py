"""短观察名与真实调用/记录/证据身份的类型化映射；不读取任何新数据。"""
import hashlib,json
from typing import Annotated,Literal
from pydantic import Field,create_model
from netsentry.api.schemas import StrictModel
from netsentry.services.flow_analysis import AnalysisArguments
from .multistep_protocol import MultiDecision,summarize


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


class RegisteredObservation(StrictModel):
    observation_id: str
    investigation_id: str
    call_id: str
    tool: str
    kind: Literal['alert','anchor','analysis','knowledge']
    record_ids: list[str]
    evidence_ids: list[str]
    source_sha256: list[str]
    result_sha256: str


def register(state: dict) -> list[dict]:
    registry=state.setdefault('observation_registry',[])
    by_call={row['call_id']:row for row in registry}
    for observation in state['observations']:
        call=observation['call_id'];tool=observation['tool'];r=observation['result']
        if call in by_call:
            old=RegisteredObservation.model_validate(by_call[call])
            if old.investigation_id!=state['investigation_id'] or old.result_sha256!=digest(r):raise ValueError('observation_source_integrity_error')
            continue
        trace=next((t for t in state['tool_call_history'] if t['call_id']==call and t['status']=='ok'),None)
        if trace is None:raise ValueError('observation_without_successful_call')
        records=[];evidence=[];sources=[]
        if tool=='get_alert_detail':records=[r['alert']['record_id']];sources=[r['alert']['source_sha256']];kind='alert'
        elif tool=='get_anchor_flow':records=[r['record_id']];sources=[r['source_sha256']];kind='anchor'
        elif tool=='search_security_knowledge':kind='knowledge'
        else:
            kind='analysis'
            for item in r.get('records',[]):
                records.append(item.get('related_record_id') or item['record_id'])
                sources.append(item['source_sha256'])
                if item.get('evidence_id'):evidence.append(item['evidence_id'])
            if r.get('source_sha256'):sources.append(r['source_sha256'])
        # Investigation-specific short namespace prevents a valid ID from another investigation aliasing this one.
        oid=f"obs_{state['investigation_id'][:8]}_{len(registry)+1:02d}"
        row=RegisteredObservation(observation_id=oid,investigation_id=state['investigation_id'],call_id=call,tool=tool,kind=kind,
            record_ids=sorted(set(records)),evidence_ids=sorted(set(evidence)),source_sha256=sorted(set(sources)),result_sha256=digest(r)).model_dump()
        registry.append(row);by_call[call]=row
    if len(registry)>12:raise ValueError('observation_registry_budget')
    return registry


def catalog(state: dict) -> list[dict]:
    register(state);rows=[]
    for entry in state['observation_registry']:
        o=next(o for o in state['observations'] if o['call_id']==entry['call_id']);r=o['result']
        if entry['kind']=='alert':
            values={k:r['alert'][k] for k in ('model_id','model_status','attack_related_score')}
            values['score_is_calibrated_probability']=False
        elif entry['kind']=='anchor':
            values={k:r.get(k) for k in ('source_ip','destination_ip','source_port','destination_port','protocol','timestamp')}
        else:
            s=summarize(o)
            values={k:s[k] for k in ('query','total','analyzed_count','loaded','has_more','scan_truncated','statistics','knowledge_reference_only')}
        rows.append({'observation_id':entry['observation_id'],'description':entry['tool'],
                     'kind':entry['kind'],'available_fields':list(values),'values':values})
    return rows


class PlanningAction(StrictModel):
    investigation_goal: MultiDecision.model_fields['goal'].annotation
    action: MultiDecision.model_fields['action'].annotation
    arguments: AnalysisArguments
    supporting_observation_ids: Annotated[list[str],Field(min_length=1,max_length=3)]
    question: Annotated[str,Field(min_length=1,max_length=180)]
    reason: Annotated[str,Field(min_length=1,max_length=240)]
    decision: MultiDecision.model_fields['decision'].annotation


def planning_schema(allowed: list[str]):
    if not allowed:raise ValueError('no_registered_observations')
    return create_model('ScopedPlanningAction',__base__=PlanningAction,
        supporting_observation_ids=(Annotated[list[Literal[tuple(allowed)]],Field(min_length=1,max_length=3)],...))
