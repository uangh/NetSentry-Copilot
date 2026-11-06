"""本地双进程启动器；令牌只在内存/子进程环境，退出关闭自身进程。"""
import argparse
import json
from uuid import uuid4
from contextlib import contextmanager,closing
from datetime import datetime
import getpass
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[1]


@contextmanager
def running_services(*,backend_port:int=8000,frontend_port:int=5173,checkpoint:Path|None=None,token:str|None=None,logs:Path|None=None,alert_db:Path|None=None,serving:str="vite"):
    node=shutil.which('node');vite=ROOT/'frontend/node_modules/vite/bin/vite.js'
    if serving not in ('vite','static'):raise ValueError('invalid_serving_mode')
    if serving=='vite' and (not node or not vite.is_file()):raise RuntimeError('缺少Node或前端依赖，请先在frontend运行pnpm install --frozen-lockfile')
    sys.path.insert(0,str(ROOT))
    from netsentry.runtime_paths import RuntimePaths
    paths=RuntimePaths.resolve(ROOT);paths.require_runtime()
    if serving=='static' and not (ROOT/'frontend/dist/index.html').is_file():raise RuntimeError('Missing frontend/dist; build frontend first')
    for port in ((backend_port,frontend_port) if serving=='vite' else (backend_port,)):
        if not 1024<=port<=65535:raise ValueError('端口必须在1024到65535之间')
        with socket.socket() as check:
            try:check.bind(('127.0.0.1',port))
            except OSError as exc:raise RuntimeError(f'本地端口 {port} 已被占用，请关闭占用服务或指定其他端口') from exc
    if serving=='vite' and backend_port==frontend_port:raise ValueError('前后端端口不能相同')
    default=checkpoint is None;checkpoint=checkpoint or ROOT/'outputs/m5/checkpoints.sqlite'
    checkpoint.parent.mkdir(parents=True,exist_ok=True)
    # 默认首次启动备份已有M4调查到新M5库；历史M4原库保持只读。
    old=ROOT/'outputs/m4/checkpoints.sqlite'
    if default and not checkpoint.exists() and old.is_file():
        with closing(sqlite3.connect(old.resolve().as_uri()+'?mode=ro',uri=True)) as source,closing(sqlite3.connect(checkpoint)) as target:source.backup(target)
    logs=logs or ROOT/'outputs/m5'/('dev_'+datetime.now().strftime('%Y%m%dT%H%M%S'))
    logs.mkdir(parents=True,exist_ok=True);env=os.environ.copy()
    env.update({'PYTHONUTF8':'1','PYTHONIOENCODING':'utf-8','NETSENTRY_BACKEND_PORT':str(backend_port),'LANGSMITH_TRACING':'false'})
    if token:env['NETSENTRY_API_TOKEN']=token
    else:env.pop('NETSENTRY_API_TOKEN',None)
    instance_id=uuid4().hex;env['NETSENTRY_INSTANCE_ID']=instance_id
    processes=[];handles=[];started=[]
    try:
        commands=[([sys.executable,'-m','netsentry.web_console','--port',str(backend_port),'--checkpoint',str(checkpoint)],ROOT,'backend.log'),
                  ([node,str(vite),'--host','127.0.0.1','--port',str(frontend_port),'--strictPort'],ROOT/'frontend','frontend.log')]
        if serving=='static':commands=commands[:1];commands[0][0].append('--static')
        for command,cwd,filename in commands:
            if filename=='backend.log' and alert_db:command+=['--alert-db',str(alert_db)]
            handle=(logs/filename).open('w',encoding='utf-8');handles.append(handle)
            child_env=env.copy()
            if filename=='frontend.log':
                for secret in ('GEMINI_API_KEY','GOOGLE_API_KEY','NETSENTRY_API_TOKEN'):child_env.pop(secret,None)
            processes.append(subprocess.Popen(command,cwd=cwd,env=child_env,stdout=handle,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)))
            started.append({'pid':getattr(processes[-1],'pid',None),'cwd':str(cwd),'command':command})
        deadline=time.monotonic()+60
        # 冷启动/迁移目录时HTML可先于Vite API代理就绪；演示开始前确认真实转发。
        checks=[(backend_port,'/health'),(backend_port,'/api/v1/models')]
        if serving=='vite':checks += [(frontend_port,'/'),(frontend_port,'/health')]
        else:checks += [(backend_port,'/')]
        for port,path in checks:
            while True:
                if any(p.poll() is not None for p in processes):raise RuntimeError(f'服务退出，请查看 {logs}')
                try:
                    with urlopen(f'http://127.0.0.1:{port}{path}',timeout=1) as response:
                        if response.status==200:break
                except OSError:
                    if time.monotonic()>deadline:raise RuntimeError(f'服务启动超时，请查看 {logs}')
                    time.sleep(.2)
        info={'frontend':f'http://127.0.0.1:{frontend_port if serving=="vite" else backend_port}','backend':f'http://127.0.0.1:{backend_port}',
              'logs':str(logs),'instance_id':instance_id,'serving':serving,'processes':started,'runtime':str(paths.runtime),'agent_base_url':f'http://127.0.0.1:{backend_port}'}
        (logs/'launch.json').write_text(json.dumps(info,indent=2),encoding='utf-8')
        yield info
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=8)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        for handle in handles:handle.close()
        (logs/'shutdown.json').write_text(json.dumps({'owned_processes':[{'pid':getattr(p,'pid',None),'exit_code':p.poll()} for p in processes],'all_owned_stopped':all(p.poll() is not None for p in processes)}),encoding='utf-8')


def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--backend-port',type=int,default=8000);parser.add_argument('--frontend-port',type=int,default=5173)
    parser.add_argument('--read-only',action='store_true');parser.add_argument('--gemini',action='store_true');args=parser.parse_args()
    token=None if args.read_only else os.environ.get('NETSENTRY_API_TOKEN') or getpass.getpass('设置本地写令牌（至少24字符；输入隐藏；稍后在网页右上角输入同一个值）：')
    if token is not None and len(token)<24:parser.error('本地写令牌至少24字符')
    os.environ['NETSENTRY_ENABLE_RECOVERY']='1' if args.gemini and token else '0'
    try:
        checkpoint=ROOT/'outputs/m6/checkpoints.sqlite' if args.gemini else None
        with running_services(backend_port=args.backend_port,frontend_port=args.frontend_port,token=token,checkpoint=checkpoint) as urls:
            print(f"NetSentry: {urls['frontend']}\nBackend: {urls['backend']}\n按 Ctrl+C 关闭前后端。",flush=True)
            while True:time.sleep(.5)
    except KeyboardInterrupt:print('前后端已关闭。')
    except (RuntimeError,ValueError) as exc:print(str(exc),file=sys.stderr);raise SystemExit(1)


if __name__=='__main__':main()
