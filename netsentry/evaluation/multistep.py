"""指标定义明确区分观察引用代理指标与不可证明的模型因果推理质量。"""
from copy import deepcopy
from .metrics import evaluate,ratio
from netsentry.services.flow_analysis import TOOLS
from netsentry.agent.multistep_protocol import GOALS


def evaluate_multistep(state: dict, wall_ms: float | None=None) -> dict:
    if not state.get('multistep'):return evaluate(state,wall_ms=wall_ms)
    base=deepcopy(state);base.get('gemini',{})['decisions']=[]
    result=evaluate(base,wall_ms=wall_ms)
    rounds=state['decision_trace'];calls=state.get('gemini',{}).get('calls',[])
    executed=[d for d in rounds if d['actual_execution_status']=='executed']
    followups=[d for d in rounds if d['observations_before']]
    fidelity=[]
    for d in executed:
        o=next(o for o in state['observations'] if o['call_id']==d['result_observation_id'])
        trace=next(t for t in state['tool_call_history'] if t['call_id']==o['call_id'])
        wire=trace.get('http_request') or {};params=wire.get('parameters',{})
        if d['tool_selected'] in TOOLS:
            ok=params==d['tool_arguments']|{'tool':d['tool_selected']} and wire.get('path')=='/api/v1/flows/'+state['anchor_flow']['record_id']+'/analysis'
        else:
            from .metrics import parameter_fidelity
            tmp=deepcopy(state);tmp['gemini']={'decisions':[{'actions':[{'tool':d['tool_selected'],**d['tool_arguments']}]}]}
            ok=parameter_fidelity(tmp)['value']==1
        fidelity.append({'iteration':d['iteration'],'http_conditions_match':ok})
    records={state['anchor_flow']['record_id']}
    for o in state['observations']:
        for r in o['result'].get('records',[]):records.add(r.get('related_record_id') or r['record_id'])
    obs={d['result_observation_id'] for d in executed}
    used={x for d in rounds for x in d['evidence_references']}
    if state.get('draft_report'):
        cited={f['reference_id'] for f in state['draft_report']['observed_facts']}
        used|={oid for oid in obs if 'call:'+oid in cited}
    stops=[d for d in rounds if d['tool_selected']=='stop']
    duplicate=sum(d['actual_execution_status']=='duplicate_blocked' for d in rounds)
    result.update(tool_choice_validity=ratio(sum(d['tool_selected'] in GOALS.get(d['investigation_goal'],set()) for d in rounds),len(rounds)),
        parameter_execution_fidelity=ratio(sum(x['http_conditions_match'] for x in fidelity),len(fidelity))|{'details':fidelity},
        multi_step_decision_validity=ratio(sum(bool(d['evidence_references']) and d['actual_execution_status'] in ('executed','stopped_without_external_call','executed_local_knowledge') for d in followups),len(followups)),
        evidence_conditioned_decision_rate=ratio(sum(d['observations_before'][-1]['observation_id'] in d['evidence_references'] for d in followups),len(followups)),
        evidence_conditioned_scope='Exposure + valid acknowledgement proxy; not proof of causal LLM reasoning. Fake intervention tests are separate.',
        stop_decision_validity=ratio(sum(d['actual_execution_status']=='stopped_without_external_call' for d in stops),len(stops)),
        unique_evidence_records=len(records),unique_evidence_added=len(set(rid for d in rounds for rid in d['new_record_ids'])),
        unique_evidence_definition='Distinct returned record_id not present in earlier loaded records, excluding initial anchor; aggregate counts not added.',
        duplicate_query_rate=ratio(duplicate,sum(d['tool_selected']!='stop' for d in rounds)),
        tool_result_utilization=ratio(len(obs&used),len(obs)),
        tool_result_utilization_scope='Observation referenced in later plan or deterministic report facts; not semantic correctness of free-form reasons.',
        coverage_limit_disclosure=bool(state['draft_report'] and any('抽样' in x for x in state['draft_report']['uncertainty'])),
        tool_budget_compliance=state['calls_used']<=8 and len(calls)<=4 and state['plan_iterations']<=3,
        planning_ms=sum(c['duration_ms'] for c in calls if c['purpose']=='multistep_planning'),
        provider_error_rate=ratio(sum(c['status']!='validated' for c in calls),len(calls)),
        partial_failure_recovery={'progress_retained':bool(executed),'resume_implemented':False},
        genuine_multitool_candidate=len(executed)>=2 and bool(followups) and bool(state['draft_report']),
        decision_trace=rounds)
    return result
