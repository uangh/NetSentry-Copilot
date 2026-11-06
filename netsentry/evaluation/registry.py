"""Scoped acceptance and feedback integrity; not an oracle for LLM causal reasoning."""
from .multistep import evaluate_multistep
from .metrics import ratio
from netsentry.agent.observation_registry import digest


def evaluate_registry(state: dict,wall_ms: float | None=None) -> dict:
    result=evaluate_multistep(state,wall_ms)
    if not state.get('observation_registry'):return result
    attempts=state.get('planning_attempts',[]);rounds=state['decision_trace'];registry=state['observation_registry']
    accepted=[d for d in rounds if d['actual_execution_status'] in ('executed','executed_local_knowledge','stopped_without_external_call')]
    refs=[ref for d in accepted for ref in d['evidence_references']]
    known={r['observation_id']:r for r in registry};feedback=[]
    for attempt in attempts[1:]:
        oid=attempt['latest_tool_observation_id'];entry=known.get(oid)
        actual=next((o for o in state['observations'] if entry and o['call_id']==entry['call_id']),None)
        supplied=next((r for r in attempt['input_projection']['observations'] if r['observation_id']==oid),None)
        from netsentry.agent.multistep_protocol import summarize
        fields=('query','total','analyzed_count','loaded','has_more','scan_truncated','statistics','knowledge_reference_only')
        expected={k:summarize(actual)[k] for k in fields} if actual else None
        verified=bool(actual and supplied and supplied['values']==expected and entry['result_sha256']==digest(actual['result']))
        feedback.append({'round':attempt['round_number'],'observation_id':oid,'source_call_id':entry['call_id'] if entry else None,'verified':verified})
    executed=[d for d in accepted if d['actual_execution_status']=='executed']
    # 新协议再核对原始结构化动作和服务最终执行条件，不能只比较HTTP构造参数。
    fidelity=[]
    from netsentry.services.flow_analysis import TOOLS
    for d in executed:
        if d['tool_selected'] not in TOOLS:continue
        attempt=next(a for a in reversed(attempts) if a['round_number']==d['iteration'] and 'raw_structured_action' in a)
        raw=attempt['raw_structured_action']
        observation=next(o for o in state['observations'] if o['call_id']==d['result_observation_id'])
        trace=next(t for t in state['tool_call_history'] if t['call_id']==observation['call_id'])
        parameters=d['tool_arguments'];wire=trace.get('http_request') or {}
        matched=(raw['action']==d['tool_selected']==observation['tool'] and raw['arguments']==parameters==observation['result']['query']
                 and wire.get('parameters')==parameters|{'tool':d['tool_selected']})
        fidelity.append({'round':d['iteration'],'all_five_layers_match':matched,'call_id':observation['call_id']})
    report=bool(state['draft_report']);complete=bool(len(accepted)>=2 and feedback and all(f['verified'] for f in feedback) and report and state['review_status']=='pending_review')
    result.update(planning_contract_acceptance=ratio(len(accepted),len(attempts)),
        observation_reference_validity=ratio(sum(r in known for r in refs),len(refs)),
        evidence_feedback_integrity=ratio(sum(f['verified'] for f in feedback),len(feedback))|{'details':feedback},
        evidence_conditioned_decision_rate=ratio(sum(f['verified'] for f in feedback),len(feedback)),
        valid_multi_round_completion=complete,two_tool_completion=complete and len(executed)>=2,
        report_completion=ratio(int(report),1),provider_failure_count=sum(c.get('http_status') in (429,503,504) for c in state.get('gemini',{}).get('calls',[])),
        analysis_parameter_five_layer_fidelity=ratio(sum(x['all_five_layers_match'] for x in fidelity),len(fidelity))|{'details':fidelity},
        per_round=[{'round':d['iteration'],'tool':d['tool_selected'],'references':d['evidence_references'],
                    'duration_ms':d.get('request_duration_ms'),'known_tokens':d.get('known_total_tokens')} for d in rounds],
        interpretation='Observed transport, scope, acknowledgement and trace validity. Not proof of general reasoning accuracy or causal use.')
    return result
