"""Provider failures are not planning-format errors; preserve separate denominators."""
from .registry import evaluate_registry
from .metrics import ratio
from netsentry.agent.observation_registry import digest
from netsentry.agent.multistep_protocol import summarize


def evaluate_recovery(state: dict,historical_calls: int=0) -> dict:
    calls=state['gemini']['calls'];new=calls[historical_calls:];attempts=state.get('planning_attempts',[])
    decisions=state.get('decision_trace',[])
    accepted=[d for d in decisions if d['actual_execution_status'] in ('executed','executed_local_knowledge','stopped_without_external_call')]
    new_accepted=[d for d in accepted if not historical_calls or d.get('attempt_id')]
    responses=[c for c in new if c['purpose']=='multistep_planning' and (c.get('http_status')==200 or c['status'] in ('validated','invalid_structured_output'))]
    ids={r['observation_id']:r for r in state.get('observation_registry',[])};feedback=[]
    for a in attempts:
        oid=a.get('latest_tool_observation_id')
        if not oid:continue
        r=ids.get(oid);obs=next((o for o in state['observations'] if r and o['call_id']==r['call_id']),None)
        supplied=next((v for v in a['input_projection']['observations'] if v['observation_id']==oid),None)
        fields=('query','total','analyzed_count','loaded','has_more','scan_truncated','statistics','knowledge_reference_only')
        verified=bool(obs and supplied and supplied['values']=={k:summarize(obs)[k] for k in fields} and digest(obs['result'])==r['result_sha256'])
        feedback.append({'round':a['round_number'],'attempt_id':a.get('attempt_id'),'observation_id':oid,'verified':verified,'planning_accepted':a['status']=='contract_validated'})
    references=[i for d in accepted for i in d['evidence_references']]
    invalid={'invalid_observation_ids':0,'invalid_tool_arguments':0,'invalid_tool_names':0}
    for c in new:
        locations=[e.get('loc',[]) for e in c.get('validation_error',{}).get('issues',[])]
        for metric,field in [('invalid_observation_ids','supporting_observation_ids'),('invalid_tool_arguments','arguments'),('invalid_tool_names','action')]:
            invalid[metric]+=int(any(field in loc for loc in locations))
    invalid['invalid_observation_ids']+=sum(a.get('validation_error',{}).get('code') in ('unknown_observation_reference','latest_observation_not_acknowledged') for a in attempts)
    metrics=evaluate_registry(state)
    metrics.update(provider={'generation_requests':len(new),'underlying_http_attempts':sum(c.get('http_attempt_count') or 0 for c in new),
        **{f'http_{code}_count':sum(c.get('http_status')==code or any(h.get('status')==code for h in c.get('http_attempts',[])) for c in new) for code in (200,400,403,429,503,504)},
        'unknown_token_usage_requests':sum(c.get('total_tokens') is None for c in new),'known_total_tokens':sum(c.get('total_tokens') or 0 for c in new),
        'historical_calls_excluded':historical_calls,'lifetime_generation_requests':len(calls)},
        planning_contract={'planning_responses_received':len(responses),'planning_contract_accepted':len(new_accepted),
            'acceptance':ratio(len(new_accepted),len(responses)),**invalid},
        evidence_feedback=ratio(sum(f['verified'] for f in feedback),len(feedback))|{'details':feedback},
        observation_references_valid=ratio(sum(i in ids for i in references),len(references)),
        second_round_decision_verified=any(f['round']>=2 and f['verified'] and f['planning_accepted'] for f in feedback),
        real_planning_rounds=sum(c.get('live_provider') is True and c['status']=='validated' and c['purpose']=='multistep_planning' for c in new),
        successful_tool_executions=sum(d['actual_execution_status']=='executed' for d in decisions),
        report_completed=bool(state['draft_report']),pending_review=state['review_status']=='pending_review',
        stopping_decision=state.get('stop_reason'),tool_budget_compliance=len(calls)<=state.get('recovery',{}).get('generation_limit',4) and state['calls_used']<=8 and state['plan_iterations']<=3)
    return metrics
