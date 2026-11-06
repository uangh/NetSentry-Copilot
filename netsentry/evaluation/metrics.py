"""Contract-grounding metrics; denominators explicit, no ground-truth labels or human-efficiency claims."""
import json
from datetime import datetime,timedelta
from netsentry.agent.reporting import facts_and_references,render_summary

ALLOWED={'get_alert_detail','get_anchor_flow','query_related_evidence','query_host_flows','search_security_knowledge','stop'}
def ratio(numerator: int, denominator: int) -> dict:
    return {'numerator':numerator,'denominator':denominator,'value':numerator/denominator if denominator else None}

def parameter_fidelity(state: dict) -> dict:
    actions=[a for d in state.get('gemini',{}).get('decisions',[]) for a in d['actions'] if a['tool']!='stop']
    traces=state['tool_call_history'];used=set();matches=0;details=[]
    for a in actions:
        index=next((i for i,t in enumerate(traces) if i not in used and t['tool']==a['tool']),None)
        if index is None:details.append({'action':a,'match':False,'reason':'not_executed'});continue
        used.add(index);t=traces[index];keys=['window_seconds','limit','offset','endpoint']
        normalized=all(t['parameters'].get(k)==a.get(k,0 if k=='offset' else None) for k in keys)
        wire=t.get('http_request');wire_ok=None
        if wire:
            p=wire['parameters']
            if a['tool']=='query_related_evidence':wire_ok=all(p.get(k)==t['parameters'].get(k) for k in ('endpoint','limit','offset')) and p.get('window_seconds')==a['window_seconds']//2
            else:
                stamp=datetime.fromisoformat(state['anchor_flow']['timestamp']);half=timedelta(seconds=a['window_seconds']/2)
                wire_ok=p.get('host_ip')==state['anchor_flow'].get(a['endpoint']+'_ip') and p.get('limit')==a['limit'] and p.get('offset')==a.get('offset',0) and datetime.fromisoformat(p['start'])==stamp-half and datetime.fromisoformat(p['end'])==stamp+half
        ok=normalized and wire_ok is True;matches+=ok
        details.append({'action':a,'match':ok,'normalized_parameters_match':normalized,'wire_parameters_match':wire_ok,
            'reason':'historical_no_wire_projection' if wire is None else 'checked'})
    return ratio(matches,len(actions))|{'details':details,'scope':'Gemini non-stop actions vs actual trace and HTTP projection'}

def evaluate(state: dict, *, wall_ms: float | None=None) -> dict:
    report=state.get('draft_report');observations=state['observations'];facts,refs=facts_and_references(state)
    canonical={r['reference_id']:r for r in refs};expected={f['fact_id']:f for f in facts}
    actual_facts=report['observed_facts'] if report else [];actual_refs=report['evidence_references'] if report else []
    good_refs=sum(r['reference_id'] in canonical and r==canonical[r['reference_id']] for r in actual_refs)
    grounded=sum(f['fact_id'] in expected and f==expected[f['fact_id']] for f in actual_facts)
    summary_ok=bool(report and report['investigation_summary']==render_summary(facts,state.get('narrative')))
    confirmed=bool(report and (report['hypothesis']!='insufficient_evidence' or any(r['association_status']!='candidate_unverified' for r in report['candidate_relations'])))
    records=[]
    for o in observations:
        if o['tool']=='query_related_evidence':records.extend(r['flow'] for r in o['result']['records'])
        elif o['tool']=='query_host_flows':records.extend(o['result']['records'])
    decisions=[a for d in state.get('gemini',{}).get('decisions',[]) for a in d['actions']]
    tools=decisions or [{'tool':t['tool']} for t in state['tool_call_history']]
    calls=state.get('gemini',{}).get('calls',[]);timings=state.get('gemini',{}).get('step_timings',[])
    knowledge={k['chunk_id']:k for k in state['knowledge_references']};reported_knowledge=report['knowledge_references'] if report else []
    return {'scope':'bounded report contract; not general natural-language truth or IDS accuracy','report_available':bool(report),
        'citation_validity':ratio(good_refs,len(actual_refs)),'fact_grounding':ratio(grounded,len(actual_facts)),
        'unique_evidence_records':len({r['record_id'] for r in records}),'loaded_record_occurrences':len(records),
        'report_reference_count':len(actual_refs),'unique_source_files':len({r['source_sha256'] for r in records}),
        'knowledge_citation_validity':ratio(sum(k['chunk_id'] in knowledge and k==knowledge[k['chunk_id']] for k in reported_knowledge),len(reported_knowledge)),
        'unsupported_claim_count':len(actual_facts)-grounded+int(not summary_ok)+int(confirmed) if report else None,
        'unsupported_claim_scope':'fact-field mismatches plus non-contract summary/confirmed-attack statements; no free-text semantic oracle',
        'candidate_to_confirmed_violation':confirmed,
        'missing_evidence_disclosure':bool(report and any('认证' in x for x in report['missing_evidence']) and any('独立' in x for x in report['missing_evidence'])),
        'tool_choice_validity':ratio(sum(a['tool'] in ALLOWED for a in tools),len(tools)),
        'parameter_execution_fidelity':parameter_fidelity(state),
        'tool_budget_compliance':state['calls_used']<=6 and len(calls)<=3 and state['plan_iterations']<=2,
        'stop_reason':state.get('stop_reason'),'review_status':state['review_status'],
        'failure_handling':{'failed_tool_calls':sum(t['status']=='error' for t in state['tool_call_history']),
            'failed_llm_calls':sum(c['status']!='validated' for c in calls),'report_not_fabricated_on_failure':not report if state['review_status']=='failed' else None},
        'llm_requests':len(calls),'known_tokens':sum(c.get('total_tokens') or 0 for c in calls),
        'unknown_usage_requests':sum(c.get('total_tokens') is None for c in calls),
        'total_tokens':None if any(c.get('total_tokens') is None for c in calls) else sum(c.get('total_tokens') or 0 for c in calls),
        'planning_ms':sum(c['duration_ms'] for c in calls if c['purpose']=='planning'),
        'report_ms':sum(c['duration_ms'] for c in calls if c['purpose']=='narrative'),
        'tool_query_ms':sum(t['duration_ms'] for t in state['tool_call_history'] if t['tool']!='search_security_knowledge'),
        'rag_ms':sum(t['duration_ms'] for t in state['tool_call_history'] if t['tool']=='search_security_knowledge'),
        'end_to_end_ms':wall_ms,'llm_failures':[{'status':c['status'],'http_status':c.get('http_status'),'reason':c.get('provider_message')} for c in calls if c['status']!='validated'],
        'knowledge_documents':len({k['document_id'] for k in state['knowledge_references']}),'knowledge_chunks':len(state['knowledge_references'])}
