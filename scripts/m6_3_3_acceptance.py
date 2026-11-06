"""One explicitly authorized acceptance; global eight underlying HTTP attempts, no probes generating text."""
import argparse,json,os,sqlite3,sys,time
from contextlib import closing
from datetime import datetime,timezone
from pathlib import Path
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from netsentry.agent.acceptance import AcceptanceBudget,grant_acceptance,backup_allowed,retry_delay,acceptance_levels
from netsentry.agent.recovery_engine import RecoveryEngine,ResumeRequest
from netsentry.agent.gemini_adapter import GeminiAdapter
from netsentry.agent.tools import M3Tools
from netsentry.evaluation.scenarios import sha
from start_netsentry_dev import running_services
from m6_gemini_smoke_test import port
from m6_2_evaluate import read_state

SOURCE=ROOT/'outputs/m6_3_2/live_20261105T113743'
IID='b33c7c879981453dba01501ef2aa40bb'
ALERT='f0b6b3ce455e4c62bcaed98f94634568'

def save(path: Path,value) -> None:
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')

def copy_db(source: Path,target: Path) -> None:
    with closing(sqlite3.connect(source.resolve().as_uri()+'?mode=ro',uri=True)) as src,closing(sqlite3.connect(target)) as dst:src.backup(dst)

def verify_contract() -> dict:
    approved=ROOT/'outputs/m3/runtime';manifest=json.loads((approved/'runtime_manifest.json').read_text())
    assets={name:sha(approved/name) for name in manifest['assets']}
    if assets!=manifest['assets']:raise RuntimeError('approved_runtime_changed')
    paths=['netsentry/services/flow_analysis.py','netsentry/agent/analysis_tools.py','netsentry/agent/multistep_protocol.py',
        'netsentry/agent/observation_registry.py','netsentry/agent/reporting.py','netsentry/agent/tools.py',
        'netsentry/services/evidence_service.py','netsentry/api/schemas.py']
    historical={r['path'].replace('\\','/'):r['sha256'] for r in json.loads((ROOT/'work/m6_3_2_before.json').read_text())}
    actual={p:sha(ROOT/p) for p in paths}
    if any(historical.get(p)!=h for p,h in actual.items()):raise RuntimeError('tool_contract_changed')
    return {'runtime_assets':assets,'tool_contract':actual,'labels_accessed':False,'week2_accessed':False}

def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--live',action='store_true',required=True)
    parser.add_argument('--project-free-tier-confirmed',action='store_true');args=parser.parse_args()
    if not os.environ.get('GEMINI_API_KEY'):raise RuntimeError('missing_backend_key')
    base=ROOT/'outputs/m6_3_3';base.mkdir(exist_ok=True)
    run_id=uuid4().hex;out=base/('acceptance_'+run_id);out.mkdir()
    with (base/'acceptance_attempt.json').open('x',encoding='utf-8') as marker:
        json.dump({'acceptance_run_id':run_id,'output':str(out),'global_http_limit':8,'branch_A_limit':3},marker)
    contract=verify_contract();save(out/'contract.json',contract)
    source_hash={n:sha(SOURCE/n) for n in ('checkpoints.sqlite','alerts.sqlite')}
    budget=AcceptanceBudget(out/'http_budget.json');branches=[]
    os.environ.update(NETSENTRY_GEMINI_NO_FALLBACK='1',NETSENTRY_ENABLE_RECOVERY='0',LANGSMITH_TRACING='false')
    started=time.perf_counter()
    def factory(branch: str,model: str,cap: int):
        adapter=GeminiAdapter(model=model)
        def before(request):
            if request.url.path.endswith(':generateContent'):budget.reserve(branch,model,cap)
        def after(response):
            if response.request.url.path.endswith(':generateContent'):
                budget.records[-1].update(http_status=response.status_code,outcome='response_received');budget.save()
        adapter.http_client.event_hooks['request'].insert(0,before)
        adapter.http_client.event_hooks['response'].append(after)
        return adapter
    for branch,model,cap in [('A','gemini-3.5-flash-lite',3),('B','gemini-3.1-flash-lite',5)]:
        branch_out=out/branch;branch_out.mkdir()
        conditions={'structured_outputs':True,'official_free_standard_text':True,
            'project_free_tier_confirmed':args.project_free_tier_confirmed,
            'billing_basis':'owner attestation: Free Tier, billing not enabled',
            'pricing_url':'https://aistudio.google.com/docs/pricing',
            'model_url':'https://aistudio.google.com/docs/models/gemini-3.1-flash-lite'}
        if branch=='B':
            if not args.project_free_tier_confirmed:
                branches.append({'branch':'B','status':'BLOCKED','conditions':conditions});break
            adapter=factory(branch,model,cap)
            try:catalog=adapter.probe()
            finally:adapter.close()
            save(branch_out/'catalog.json',catalog);conditions['project_access']=catalog['ready']
            # Catalog proves access only. Actual first planning validates usable quota, never an extra generation probe.
            conditions['quota_prior_to_first_planning']='unverified; stop immediately on 429'
            if not backup_allowed(conditions):
                branches.append({'branch':'B','status':'BLOCKED','conditions':conditions});break
        copy_db(SOURCE/'alerts.sqlite',branch_out/'alerts.sqlite')
        if branch=='A':copy_db(SOURCE/'checkpoints.sqlite',branch_out/'checkpoints.sqlite')
        cp=branch_out/'checkpoints.sqlite';historical=read_state(cp,IID) if branch=='A' else None
        if historical:save(branch_out/'before_state.json',historical)
        prior_calls=len(historical['gemini']['calls']) if historical else 0
        human_wait=0.
        if historical:
            with closing(sqlite3.connect(cp)) as db:
                finished=db.execute('SELECT MAX(finished_at) FROM recovery_runs WHERE iid=?',(IID,)).fetchone()[0]
            human_wait=max(0,time.time()-datetime.fromisoformat(finished).timestamp())
        with running_services(backend_port=port(),frontend_port=port(),checkpoint=cp,alert_db=branch_out/'alerts.sqlite',logs=branch_out/'services') as urls:
            tools=M3Tools(urls['backend'])
            engine=RecoveryEngine(cp,tools,recovery_enabled=True,adapter_factory=lambda:factory(branch,model,cap))
            try:
                if branch=='A':
                    iid=IID;grant_acceptance(engine,iid,run_id,cap,sha(out/'contract.json'))
                    status=engine.status(iid)
                    status=engine.resume_failed_investigation(iid,ResumeRequest(request_id=uuid4().hex,expected_checkpoint=status['recovery']['checkpoint_id']))
                else:
                    status=engine.start(ALERT,'gemini_multistep');iid=status['investigation_id']
                first=deep_state(engine,iid);save(branch_out/'first_state.json',first)
                # One explicit retry only for 503; no loops and no configuration/quota/504 retry.
                new=first['gemini']['calls'][prior_calls:];last=new[-1] if new else {}
                remaining_http=min(cap-sum(r['branch']==branch for r in budget.records),8-len(budget.records))
                info=status.get('recovery',{});delay=retry_delay(last,info.get('active_seconds_remaining',0))
                if status['review_status']=='failed' and last.get('http_status')==503 and remaining_http>0 and delay is not None:
                    if branch=='B':grant_acceptance(engine,iid,run_id,remaining_http,sha(out/'contract.json'));status=engine.status(iid)
                    if status['recovery']['can_resume']:
                        save(branch_out/'retry.json',{'delay_seconds':delay,'reason':'one_explicit_503_retry','same_failed_stage':info['failure']['stage']})
                        time.sleep(delay)
                        # Backoff is active acceptance time; never recharge the 270 second investigation budget.
                        state=deep_state(engine,iid);state.setdefault('recovery',{})['active_seconds_used']=info['active_seconds_used']+delay
                        engine.graph.update_state(engine.config(iid),state,as_node='failed');status=engine.status(iid)
                        status=engine.resume_failed_investigation(iid,ResumeRequest(request_id=uuid4().hex,expected_checkpoint=status['recovery']['checkpoint_id']))
                state=deep_state(engine,iid);save(branch_out/'after_state.json',state);save(branch_out/'after_status.json',status)
                calls=state['gemini']['calls'];new=calls[prior_calls:]
                result={'branch':branch,'model':model,'investigation_id':iid,'source_checkpoint':str(SOURCE/'checkpoints.sqlite') if historical else None,
                    'historical_attempts':sum(c.get('http_attempt_count') or 0 for c in calls[:prior_calls]),
                    'new_attempts':sum(c.get('http_attempt_count') or 0 for c in new),
                    'lifetime_attempts':sum(c.get('http_attempt_count') or 0 for c in calls),
                    'new_known_tokens':sum(c.get('total_tokens') or 0 for c in new),'new_unknown_usage_requests':sum(c.get('total_tokens') is None for c in new),
                    'new_request_ms':sum(c['duration_ms'] for c in new),'review_status':state['review_status'],
                    'levels':acceptance_levels(state),'status':state['gemini']['verification_status'],
                    'conditions':conditions if branch=='B' else None,'new_calls':new,
                    'historical_calls_retained':calls[:prior_calls]==historical['gemini']['calls'] if historical else True,
                    'historical_observations_retained':state['observations'][:len(historical['observations'])]==historical['observations'] if historical else True,
                    'active_seconds_used':status['recovery']['active_seconds_used'],
                    'human_wait_seconds':human_wait,
                    'human_wait_basis':'not charged; original ledger finished_at recorded in before_state/after_status',
                    'output':str(branch_out),'automatic_review':False}
                branches.append(result);save(branch_out/'result.json',result)
            finally:engine.close()
        if result['levels']['report_validated'] and result['levels']['pending_review']:break
    result={'acceptance_run_id':run_id,'output':str(out),'branches':branches,'new_http_attempts':len(budget.records),
        'http_limit':8,'remaining_http_allowance':8-len(budget.records),'elapsed_seconds':time.perf_counter()-started,
        'source_sha256':source_hash,'source_unchanged':all(sha(SOURCE/n)==h for n,h in source_hash.items()),
        'automatic_review':False,'no_additional_generation_after_this_run':True}
    save(out/'acceptance.json',result);save(ROOT/'delivery/M6_3_3_ACCEPTANCE.json',result)
    print(json.dumps({'output':str(out),'new_http_attempts':len(budget.records),'branches':[{k:r.get(k) for k in ('branch','status','review_status','new_attempts')} for r in branches]}),flush=True)

def deep_state(engine,iid: str) -> dict:
    from copy import deepcopy
    return deepcopy(dict(engine.graph.get_state(engine.config(iid)).values))

if __name__=='__main__':main()
