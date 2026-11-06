"""Finite goals/actions and public reasons, never private chain-of-thought."""
import hashlib,json
from typing import Annotated,Literal
from pydantic import Field,model_validator
from netsentry.api.schemas import StrictModel
from netsentry.services.flow_analysis import AnalysisArguments

GOALS={'host_behavior':{'summarize_host_behavior','query_host_flows'},
       'port_analysis':{'analyze_port_distribution'},'temporal_analysis':{'analyze_temporal_bursts','build_flow_timeline'},
       'evidence_correlation':{'expand_evidence_page','query_related_evidence','build_flow_timeline'},
       'knowledge_lookup':{'search_security_knowledge'},'evidence_sufficiency':{'stop'}}


class MultiDecision(StrictModel):
    goal: Literal['host_behavior','temporal_analysis','port_analysis','evidence_correlation','knowledge_lookup','evidence_sufficiency']
    action: Literal['summarize_host_behavior','analyze_port_distribution','analyze_temporal_bursts',
                    'build_flow_timeline','expand_evidence_page','query_related_evidence','query_host_flows',
                    'search_security_knowledge','stop']
    arguments: AnalysisArguments
    question: Annotated[str,Field(min_length=1,max_length=180)]
    reason: Annotated[str,Field(min_length=1,max_length=240)]
    expected_information: Annotated[str,Field(max_length=180)]
    missing_evidence: Annotated[list[str],Field(max_length=4)]
    based_on_observation_ids: Annotated[list[str],Field(max_length=3)]
    decision: Literal['continue','change_direction','stop_insufficient_evidence','stop_sufficient_for_report','request_external_evidence']

    @model_validator(mode='after')
    def coherent(self):
        if self.action not in GOALS[self.goal]:raise ValueError('goal_action_mismatch')
        stopping=self.decision.startswith('stop_') or self.decision=='request_external_evidence'
        if stopping!=(self.action=='stop'):raise ValueError('stop_action_mismatch')
        if any(len(s)>180 for s in self.missing_evidence):raise ValueError('missing_evidence_too_long')
        if self.action!='expand_evidence_page' and self.arguments.offset!=0:raise ValueError('offset_requires_paging_tool')
        if self.action in ('query_related_evidence','query_host_flows') and (self.arguments.center_offset_seconds!=0 or self.arguments.window_seconds>60):raise ValueError('legacy_tool_parameter_mismatch')
        return self


def summarize(observation: dict) -> dict:
    r=observation['result']
    stats=r.get('statistics',{})
    # Bucket and port lists are bounded again for prompt size, full output persists for review.
    compact={k:(v[:6] if isinstance(v,list) else v) for k,v in stats.items()}
    return {'observation_id':observation['call_id'],'tool':observation['tool'],
            'query':observation['parameters'],'total':r.get('total'),
            'analyzed_count':r.get('analyzed_count'),'loaded':len(r.get('records',[])),
            'has_more':r.get('has_more',False),'scan_truncated':r.get('scan_truncated',False),
            'statistics':compact,'knowledge_reference_only':r.get('knowledge',[]),'source_sha256':r.get('source_sha256'),
            'result_sha256':hashlib.sha256(json.dumps(r,sort_keys=True).encode()).hexdigest()}


def context(state: dict) -> dict:
    observations=[summarize(o) for o in state['observations'] if o['tool'] not in ('get_alert_detail','get_anchor_flow')]
    last=observations[-1] if observations else None
    return {'anchor':{k:state['anchor_flow'].get(k) for k in ('source_ip','destination_ip','timestamp','protocol')},
        'model':state['model_context'],'iteration':state['plan_iterations'],
        'previous_action':last['tool'] if last else None,'previous_observation_summary':last,
        'observations':observations[-3:],
        'allowed_observation_ids':[o['observation_id'] for o in observations[-3:]],
        'new_evidence_ids':state['decision_trace'][-1].get('new_record_ids',[]) if state['decision_trace'] else [],
        'missing_evidence':state['missing_information'][-4:],
        'tools_already_used':[{'tool':o['tool'],'arguments':o['parameters'] if o['tool'] not in ('get_alert_detail','get_anchor_flow') else {}} for o in state['observations']],
        'remaining_budget':{'planning_including_current':state['limits']['max_plans']+1-state['plan_iterations'],
                            'http':state['limits']['max_calls']-state['calls_used'],'report_requests_reserved':1},
        'available_tools':{g:sorted(a) for g,a in GOALS.items()},
        'rules': 'Choose one useful action, change direction or stop; no fixed sequence required. '
            'based_on_observation_ids MUST be [] on the first planning turn, since allowed_observation_ids is empty. '
            'In later turns use ONLY exact values from allowed_observation_ids. record_id, evidence_id and source_sha256 are NOT observation IDs. '
            'After the first tool, cite its observation_id in based_on_observation_ids and explain the next observable question. '
            'All new analysis tools use anchor-selected IP on either endpoint in a half-open centered window (total seconds). '
            'Host summary computes sample records, peers, ports, directions. Port tool counts either-endpoint ports. '
            'Temporal tool gives sampled record density by 5/10/30/60 second buckets, not packet rate. '
            'Timeline orders traceable records. Expand page uses offset; use same window/endpoint of previous query. '
            'Legacy related tool uses closed +/- floor(span/2); no offset/center changes; legacy host is half-open. '
            'limit <=10, window<=300 (legacy<=60), center offset -120..120, offset<=1000. '
            'Never repeat an identical effective query. Explain only public action reasons, not hidden reasoning. '
            'Only currently returned record IDs are loaded evidence; aggregates do not add individual record evidence. '
            'Sampled Week1 DEV_ONLY; score uncalibrated, no authentication/host logs. Do not confirm an attack. '
            'request_external_evidence is a stop/human request, not an actual external query. '
            'Stop action uses goal evidence_sufficiency; search_security_knowledge uses fixed local knowledge query.'}
