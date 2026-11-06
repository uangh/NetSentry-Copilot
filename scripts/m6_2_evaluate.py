"""Frozen paired evaluation: max 3 live cases / 6 generation calls, no retries or approvals."""
import argparse
from contextlib import closing
from datetime import datetime,timezone
import json,os,secrets,shutil,sqlite3,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import httpx
from langgraph.checkpoint.sqlite import SqliteSaver
from netsentry.evaluation.scenarios import sha
from netsentry.evaluation.metrics import evaluate
from netsentry.evaluation.report import comparison,save
from start_netsentry_dev import running_services
from m6_gemini_smoke_test import port

def read_state(checkpoint: Path, iid: str) -> dict:
    with closing(sqlite3.connect(checkpoint.resolve().as_uri()+'?mode=ro',uri=True)) as c:
        saver=SqliteSaver(c);saver.is_setup=True
        data=saver.get_tuple({'configurable':{'thread_id':iid}})
        if data is None:raise ValueError('checkpoint missing')
        return dict(data.checkpoint['channel_values'])

def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--live',action='store_true');parser.add_argument('--browser',action='store_true');parser.add_argument('--out',type=Path);args=parser.parse_args()
    frozen=ROOT/'outputs/m6_2/frozen';manifest_path=frozen/'manifest.json'
    if sha(manifest_path)!=(frozen/'manifest.sha256').read_text():raise ValueError('frozen manifest changed')
    manifest=json.loads(manifest_path.read_text())
    if sha(frozen/'alerts.sqlite')!=manifest['alert_db_sha256'] or len(manifest['cases'])>3:raise ValueError('case source/budget mismatch')
    out=args.out or ROOT/'outputs/m6_2'/('paired_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'));out.mkdir(parents=True,exist_ok=False)
    result={'provenance':'real_CIDDS_Week1_Train_Validation','manifest_sha256':sha(manifest_path),'live_requested':args.live,
        'generation_requests':0,'max_generation_requests':6,'max_live_cases':3,'live_cases_completed':0,'stop_reason':None,'rows':[]}
    if args.live and not os.environ.get('GEMINI_API_KEY'):
        result['stop_reason']='missing_GEMINI_API_KEY';save(out/'evaluation.json',result);print(json.dumps(result));raise SystemExit(2)
    if not args.live:
        os.environ.pop('GEMINI_API_KEY',None);os.environ.pop('GOOGLE_API_KEY',None)
    os.environ.update(NETSENTRY_GEMINI_PLAN_LIMIT='1',NETSENTRY_GEMINI_MODEL='gemini-3.5-flash-lite',NETSENTRY_GEMINI_NO_FALLBACK='1')
    alert_db=out/'alerts.sqlite'
    with closing(sqlite3.connect((frozen/'alerts.sqlite').resolve().as_uri()+'?mode=ro',uri=True)) as src,closing(sqlite3.connect(alert_db)) as target:src.backup(target)
    with closing(sqlite3.connect((ROOT/'outputs/m3/alerts.sqlite').resolve().as_uri()+'?mode=ro',uri=True)) as src,closing(sqlite3.connect(alert_db)) as target:
        row=src.execute('SELECT * FROM alerts WHERE alert_id=?',('d921f53d7ed74100b814e6027fe6cc1f',)).fetchone()
        if row:target.execute('INSERT OR IGNORE INTO alerts VALUES('+','.join('?' for _ in row)+')',row);target.commit()
    token=secrets.token_urlsafe(32);checkpoint=out/'checkpoints.sqlite';started_all=time.perf_counter()
    with running_services(backend_port=port(),frontend_port=port(),checkpoint=checkpoint,token=token,logs=out,alert_db=alert_db) as urls:
        with httpx.Client(base_url=urls['backend'],trust_env=False,timeout=170) as client:
            def run(case: dict, mode: str):
                started=time.perf_counter();response=client.post('/api/v1/investigations',json={'alert_id':case['alert_id'],'mode':mode},headers={'X-API-Token':token})
                elapsed=(time.perf_counter()-started)*1000
                if response.status_code!=201:return {'case_id':case['case_id'],'mode':mode,'http_status':response.status_code,'error':'start_failed'}
                status=response.json();state=read_state(checkpoint,status['investigation_id']);metrics=evaluate(state,wall_ms=elapsed)
                folder=out/case['case_id']/mode;folder.mkdir(parents=True)
                for name,value in [('status',status),('state',state),('metrics',metrics),('tool_trace',state['tool_call_history'])]:save(folder/(name+'.json'),value)
                save(folder/'evidence.json',client.get('/api/v1/console/investigations/'+status['investigation_id']+'/evidence').json())
                return {'case_id':case['case_id'],'mode':mode,'provenance':'real_Gemini' if mode=='gemini_llm' else 'real_M3_scripted_offline',
                    'investigation_id':status['investigation_id'],'verification_status':state.get('gemini',{}).get('verification_status'),
                    'metrics':metrics,'generation_calls':state.get('gemini',{}).get('calls',[])}
            for case in manifest['cases']:result['rows'].append(run(case,'offline'))
            result['rows'].append(run({'case_id':'historical_m61','alert_id':'d921f53d7ed74100b814e6027fe6cc1f'},'offline'))
            prior=json.loads((ROOT/'delivery/M6_1_VERIFIED_CASE.json').read_text())['investigation']
            old=read_state(ROOT/'outputs/m6_1/live_20261104T170802/checkpoints.sqlite',prior['investigation_id'])
            result['rows'].append({'case_id':'historical_m61','mode':'gemini_llm','provenance':'historical_real_Gemini_not_rerun','investigation_id':prior['investigation_id'],'metrics':evaluate(old,wall_ms=42422.73)})
            if args.live:
                consecutive_504=0
                for case in manifest['cases']:
                    if result['generation_requests']+2>6:result['stop_reason']='generation_budget';break
                    row=run(case,'gemini_llm');result['rows'].append(row);result['generation_requests']+=len(row.get('generation_calls',[]));save(out/'evaluation.json',result)
                    if row.get('error'):result['stop_reason']='start_failed';break
                    failures=[c for c in row['generation_calls'] if c['status']!='validated']
                    if failures:
                        code=failures[-1].get('http_status');consecutive_504=consecutive_504+1 if code==504 else 0
                        reason=(failures[-1].get('provider_message') or '').lower()
                        if code in (403,429) or 'quota' in reason or 'resource_exhausted' in reason or consecutive_504>=2:result['stop_reason']=failures[-1]['status'];break
                    else:
                        consecutive_504=0
                        if row.get('verification_status')=='VERIFIED':result['live_cases_completed']+=1
            if args.browser:
                env=os.environ.copy()
                for key in ('GEMINI_API_KEY','GOOGLE_API_KEY','NETSENTRY_API_TOKEN','NETSENTRY_TEST_TOKEN'):env.pop(key,None)
                entries=[r for r in result['rows'] if r.get('investigation_id') and r['case_id']!='historical_m61']
                env.update(NETSENTRY_M62_CASES=json.dumps(entries),NETSENTRY_FRONTEND_URL=urls['frontend'],NETSENTRY_E2E_OUT=str(out/'browser'))
                with (out/'browser.log').open('w',encoding='utf-8') as log:
                    r=subprocess.run([shutil.which('node'),str(ROOT/'frontend/node_modules/@playwright/test/cli.js'),'test','evidence-evaluation.spec.ts'],cwd=ROOT/'frontend',env=env,stdout=log,stderr=log,timeout=100)
                result['browser_exit_code']=r.returncode
    result.update(wall_time_ms=round((time.perf_counter()-started_all)*1000,2),paired_comparison=comparison([r for r in result['rows'] if 'metrics' in r]),frozen_manifest_unchanged=sha(manifest_path)==result['manifest_sha256'])
    save(out/'evaluation.json',result);save(ROOT/'delivery/M6_2_LIVE_EVALUATION.json' if args.live else ROOT/'delivery/M6_2_OFFLINE_EVALUATION.json',result)
    (ROOT/'delivery/M6_2_LATEST_RUN.txt').write_text(str(out))
    print(json.dumps({'output':str(out),'generation_requests':result['generation_requests'],'completed':result['live_cases_completed'],'stop_reason':result['stop_reason']}))

if __name__=='__main__':main()
