"""Three explicit local demos, reusing the existing service launcher and engine."""
import argparse,json,os,sys,time,subprocess,shutil
from pathlib import Path
from uuid import uuid4
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from start_netsentry_dev import running_services
from m6_3_3_acceptance import copy_db,save,SOURCE,IID,ALERT
from netsentry.agent.recovery_engine import RecoveryEngine
from netsentry.agent.tools import M3Tools
from netsentry.agent.gemini_adapter import GeminiAdapter
from netsentry.evaluation.scenarios import sha
from netsentry.runtime_paths import RuntimePaths
from netsentry.agent.model_config import resolve_model,APPROVED_MODELS

def configure_mode(mode: str) -> None:
    if mode not in ('enhanced_rules','saved_live_replay','live_gemini'):raise ValueError('invalid_demo_mode')
    if mode=='live_gemini' and not os.environ.get('GEMINI_API_KEY'):raise RuntimeError('missing_backend_key; use existing hidden-input PowerShell launcher')
    if mode!='live_gemini':
        for key in ('GEMINI_API_KEY','GOOGLE_API_KEY'):os.environ.pop(key,None)
    os.environ.update(NETSENTRY_DEMO_MODE=mode,NETSENTRY_ENABLE_RECOVERY='0',NETSENTRY_GEMINI_NO_FALLBACK='1')

def saved_path(value: str) -> Path:
    # 冻结包搬到另一目录后使用包内outputs；不依赖历史机器绝对路径。
    normalized=value.replace('\\','/')
    if '/outputs/' not in normalized:raise ValueError('saved_path_outside_outputs')
    relative=Path('outputs')/normalized.split('/outputs/',1)[1]
    archive=RuntimePaths.resolve(ROOT).archive
    target=(archive/relative.relative_to('outputs')).resolve()
    if not target.is_relative_to(archive):raise ValueError('saved_path_outside_outputs')
    return target

def main() -> None:
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['enhanced_rules','saved_live_replay','live_gemini'],required=True)
    p.add_argument('--case',choices=['success','partial','acceptance'],default='acceptance');p.add_argument('--browser-test',action='store_true')
    p.add_argument('--serving',choices=['static','vite'],default='static');p.add_argument('--live',action='store_true');p.add_argument('--model',choices=APPROVED_MODELS)
    p.add_argument('--backend-port',type=int,default=8000);p.add_argument('--frontend-port',type=int,default=5173);args=p.parse_args()
    if args.mode=='live_gemini' and not args.live:p.error('live_gemini requires explicit --live; no generation sent')
    if args.model:os.environ['NETSENTRY_GEMINI_MODEL']=args.model
    configure_mode(args.mode)
    paths=RuntimePaths.resolve(ROOT);paths.require_runtime()
    selected,config_source=resolve_model(args.model)
    print('New investigation model: '+selected+'; source: '+config_source,flush=True)
    out=paths.work/('demo_'+uuid4().hex);out.mkdir(parents=True)
    source=paths.archive/'m6_3_2/live_20261105T113743';iid=IID;origin='M6.3.2 / gemini-3.5-flash-lite / 2026-11-05T11:37:43Z / PARTIALLY_VERIFIED'
    if args.mode=='saved_live_replay':
        if args.case=='success':
            source=saved_path((ROOT/'delivery/M6_1_LATEST_RUN.txt').read_text().strip())
            iid=json.loads((source/'result.json').read_text())['investigation_id'];origin='M6.1 / gemini-3.5-flash-lite / 2026-11-04T17:08:02Z / VERIFIED（旧单轮闭环，不是多轮成功）'
        elif args.case=='acceptance':
            result=json.loads((ROOT/'delivery/M6_3_3_ACCEPTANCE.json').read_text(encoding='utf-8'))
            row=next((r for r in result['branches'] if r.get('levels',{}).get('report_validated')),result['branches'][0])
            source=saved_path(row['output']);iid=row['investigation_id'];origin=f"M6.3.3 / {row['model']} / {row['status']} / 2026-11-05 / {result['acceptance_run_id']}"
        copy_db(source/'checkpoints.sqlite',out/'checkpoints.sqlite')
    original=source/'checkpoints.sqlite';before=sha(original)
    alerts=source/'alerts.sqlite' if (source/'alerts.sqlite').exists() else paths.archive/'m6_3_2/live_20261105T113743/alerts.sqlite'
    copy_db(alerts,out/'alerts.sqlite')
    os.environ['NETSENTRY_DEMO_ORIGIN']=origin if args.mode=='saved_live_replay' else 'v0.1.1 / CIDDS Week1 Train+Validation / F2_logistic DEV_ONLY / pending_review 后停止'
    with running_services(backend_port=args.backend_port,frontend_port=args.frontend_port,checkpoint=out/'checkpoints.sqlite',alert_db=out/'alerts.sqlite',logs=out/'services',serving=args.serving) as urls:
        if args.mode!='saved_live_replay':
            engine=RecoveryEngine(out/'checkpoints.sqlite',M3Tools(urls['backend']),recovery_enabled=False,
                adapter_factory=lambda:GeminiAdapter(model=args.model))
            try:
                status=engine.start(ALERT,'gemini_multistep' if args.mode=='live_gemini' else 'enhanced_deterministic_baseline');iid=status['investigation_id']
                save(out/'status.json',status)
            finally:engine.close()
        url=urls['frontend']+'/investigations/'+iid
        print(url+'\nMode: '+args.mode+'\nCtrl+C closes both services.',flush=True)
        proof={'mode':args.mode,'serving':args.serving,'launch':urls,'source':str(source),'investigation_id':iid,'url':url,'new_gemini_calls':0 if args.mode!='live_gemini' else len(status['gemini']['calls'])}
        if args.browser_test:
            env=os.environ.copy()
            for key in ('GEMINI_API_KEY','GOOGLE_API_KEY','NETSENTRY_API_TOKEN','NETSENTRY_TEST_TOKEN'):env.pop(key,None)
            env.update(NETSENTRY_FRONTEND_URL=urls['frontend'],NETSENTRY_DEMO_IID=iid,NETSENTRY_E2E_OUT=str(out/'browser'))
            with (out/'browser.log').open('w',encoding='utf-8') as log:
                r=subprocess.run([shutil.which('node'),str(ROOT/'frontend/node_modules/@playwright/test/cli.js'),'test','demo.spec.ts'],cwd=ROOT/'frontend',env=env,stdout=log,stderr=log,timeout=100)
            proof['browser_exit_code']=r.returncode
        else:
            try:
                while True:time.sleep(.5)
            except KeyboardInterrupt:pass
        proof['source_checkpoint_unchanged']=before==sha(original);save(out/'result.json',proof)
        print(json.dumps(proof),flush=True)
        if args.browser_test:raise SystemExit(r.returncode)

if __name__=='__main__':main()
