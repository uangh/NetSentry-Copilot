"""Real services + real provider only. A blocked run is evidence, never a fake success."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import httpx
from start_netsentry_dev import running_services
from netsentry.agent.gemini_adapter import connection_status

ALERT='d921f53d7ed74100b814e6027fe6cc1f'


def write(path: Path, value: dict) -> None:path.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
def port() -> int:
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
def sha(path: Path) -> str:
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def metrics(state: dict | None, elapsed: float | None) -> dict:
    if not state:return {'verified':False}
    report=state.get('report');g=state.get('gemini',{})
    return {'verified':bool(report),'http_calls':state['external_calls_used'],'planning_iterations':state['planning_iterations'],
        'decisions':g.get('decisions',[]),'report_structure':bool(report),'reference_validation':g.get('report_validated',bool(report)),
        'unsupported_network_facts':'none accepted by deterministic projection validator' if report else 'not evaluated',
        'insufficient_evidence':report['hypothesis'] if report else None,'budget_respected':state['external_calls_used']<=6 and len(g.get('calls',[]))<=3,
        'elapsed_ms':elapsed,'generation_calls':len(g.get('calls',[])),
        'known_total_tokens':sum(c['total_tokens'] or 0 for c in g.get('calls',[])),
        'unknown_usage_calls':sum(c['total_tokens'] is None for c in g.get('calls',[]))}


def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path);parser.add_argument('--offline-only',action='store_true')
    parser.add_argument('--plan-limit',type=int,choices=(1,2),default=1)
    args=parser.parse_args()
    os.environ['NETSENTRY_GEMINI_PLAN_LIMIT']=str(args.plan_limit)
    out=args.out or ROOT/'outputs/m6'/('smoke_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    out.mkdir(parents=True,exist_ok=False)
    status={'ready':False,'status':'offline_regression_only'} if args.offline_only else connection_status()
    write(out/'connection.json',status)
    token=secrets.token_urlsafe(32);db=ROOT/'outputs/m3/alerts.sqlite';before=sha(db)
    result={'real_provider':True,'connection':status,'generation_requests':0,'gemini_verified':False,
        'browser_gemini_verified':False,'review_actor':'automated_browser_test_not_human','output':str(out)}
    offline=None;gemini=None;times={}
    try:
        with running_services(backend_port=port(),frontend_port=port(),checkpoint=out/'checkpoints.sqlite',token=token,logs=out) as urls:
            with httpx.Client(base_url=urls['backend'],trust_env=False,timeout=60) as client:
                started=time.perf_counter();response=client.post('/api/v1/investigations',json={'alert_id':ALERT,'mode':'offline'},headers={'X-API-Token':token})
                response.raise_for_status();offline=response.json();times['offline']=(time.perf_counter()-started)*1000
                write(out/'offline.json',offline)
                if status['ready']:
                    started=time.perf_counter();response=client.post('/api/v1/investigations',json={'alert_id':ALERT,'mode':'gemini_llm'},headers={'X-API-Token':token})
                    times['gemini']=(time.perf_counter()-started)*1000
                    if response.status_code==201:
                        gemini=response.json();write(out/'gemini.json',gemini)
                        result['generation_requests']=len(gemini.get('gemini',{}).get('calls',[]))
                        result['gemini_verified']=bool(gemini.get('report') and gemini['gemini']['status']=='completed' and gemini['gemini']['decisions'])
                    else:result['start_http_status']=response.status_code
            env=os.environ.copy()
            for secret in ('GEMINI_API_KEY','GOOGLE_API_KEY','NETSENTRY_API_TOKEN'):env.pop(secret,None)
            env.update(NETSENTRY_TEST_TOKEN=token,NETSENTRY_FRONTEND_URL=urls['frontend'],NETSENTRY_E2E_OUT=str(out/'browser'))
            # Original E2E needs an unused alert checkpoint to exercise creation.
            # Use only the extra Gemini browser spec here; full original tests have a separate driver.
            specs=['gemini-unavailable.spec.ts']
            if result['gemini_verified']:
                env['NETSENTRY_GEMINI_INVESTIGATION']=gemini['investigation_id'];specs=['gemini-live.spec.ts']
            command=[shutil.which('node'),str(ROOT/'frontend/node_modules/@playwright/test/cli.js'),'test',*specs]
            with (out/'browser.log').open('w',encoding='utf-8') as log:
                run=subprocess.run(command,cwd=ROOT/'frontend',env=env,stdout=log,stderr=log,timeout=150)
            result['browser_exit_code']=run.returncode
            result['browser_gemini_verified']=result['gemini_verified'] and run.returncode==0
            if result['gemini_verified']:
                with httpx.Client(base_url=urls['backend'],trust_env=False) as client:
                    reviewed=client.get('/api/v1/investigations/'+gemini['investigation_id']).json()
                    write(out/'gemini_after_browser_review.json',reviewed)
                    result['review_status']=reviewed['review_status']
    except (httpx.HTTPError,RuntimeError,subprocess.TimeoutExpired) as exc:
        result['failure']=type(exc).__name__  # Never serialize exception text or authentication headers.
    finally:
        result['original_alert_db_before']=before;result['original_alert_db_after']=sha(db)
        result['original_unchanged']=before==result['original_alert_db_after']
        write(out/'comparison.json',{'scope':'single approved development alert; not a statistical evaluation',
            'offline':metrics(offline,times.get('offline')),'gemini':metrics(gemini,times.get('gemini'))})
        write(out/'result.json',result)
        (ROOT/'delivery/M6_LATEST_SMOKE.txt').write_text(str(out),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))
    raise SystemExit(0 if result['gemini_verified'] and result['browser_gemini_verified'] and result['original_unchanged'] else 2)


if __name__=='__main__':main()
