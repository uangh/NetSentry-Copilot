"""Local-only source + approved runtime + saved real cases snapshot. No Git mutation or network."""
import argparse,hashlib,json,re,zipfile,sqlite3,tempfile
from contextlib import closing
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def sha(path: Path) -> str:
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def sqlite_payload(source: Path,target: Path) -> None:
    # 主文件可能落后于已提交WAL；只读连接执行SQLite一致性备份，不改归档原件。
    with closing(sqlite3.connect(source.resolve().as_uri()+'?mode=ro',uri=True)) as src,closing(sqlite3.connect(target)) as dst:
        src.backup(dst)
        if dst.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise RuntimeError('sqlite_backup_integrity_failed')

def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--version',choices=['v0.1','v0.1.1'],default='v0.1');args=parser.parse_args()
    selected=set()
    def add_tree(folder: str) -> None:
        for p in (ROOT/folder).rglob('*'):
            if not p.is_file() or any(x in p.parts for x in ('__pycache__','node_modules','.git','test-results','playwright-report')):continue
            if p.name.startswith('.env') or p.suffix in ('.pyc','.part') or p.name.endswith(('-wal','-shm')):continue
            selected.add(p)
    for folder in ('netsentry','tests','sample_data','knowledge','licenses','frontend/src','frontend/e2e','frontend/dist','scripts','outputs/m3/runtime'):add_tree(folder)
    for glob in ('requirements-*.txt','frontend/*.json','frontend/*.yaml','frontend/*.ts','frontend/index.html','delivery/M6_3_3*','docs/M6_3_3_RESULTS.md','docs/V0_1_DEMO_GUIDE.md'):
        selected.update(p for p in ROOT.glob(glob) if p.is_file())
    for name in ('README.md','AGENTS.md','.gitignore','docs/STATUS.md','delivery/M6_1_LATEST_RUN.txt','delivery/V0_1_CAPABILITY_MANIFEST.json','outputs/m3/alerts.sqlite'):
        selected.add(ROOT/name)
    if args.version=='v0.1.1':
        selected.add(ROOT/'.env.example')
        for pattern in ('docs/M7A*.md','docs/V0_1_1_QUICKSTART.md','delivery/M7A_DELIVERY.md','delivery/V0_1_1_CAPABILITY_MANIFEST.json'):
            selected.update(ROOT.glob(pattern))
    acceptance=json.loads((ROOT/'delivery/M6_3_3_ACCEPTANCE.json').read_text(encoding='utf-8'))
    source_success=ROOT/'outputs/m6_1/live_20261104T170802'
    for folder in (source_success,ROOT/'outputs/m6_3_2/live_20261105T113743'):
        for name in ('checkpoints.sqlite','alerts.sqlite','result.json'):
            if (folder/name).exists():selected.add(folder/name)
    base=ROOT/'outputs/m6_3_3'
    selected.add(base/'acceptance_attempt.json')
    live=Path(acceptance['output'])
    for p in live.rglob('*'):
        if p.is_file() and p.suffix in ('.json','.log','.png','.sqlite'):
            if p.suffix=='.sqlite' and 'browser_copy' in p.parts:continue
            selected.add(p)
    records=[];payloads={};temporary=tempfile.TemporaryDirectory(prefix='netsentry_release_')
    # 冻结日志由调用方在打包结束后写入，不能把正在变化的日志打进自身快照。
    selected.discard(ROOT/'delivery/M6_3_3_FREEZE_LOG.txt')
    for p in sorted(selected):
        if not p.is_relative_to(ROOT):raise RuntimeError('outside_workspace')
        if p.suffix in ('.py','.ps1','.json','.txt','.md','.ts','.tsx','.yaml','.log'):
            if re.search(rb'AIza[0-9A-Za-z_-]{35}',p.read_bytes()):raise RuntimeError('possible_key_in_selected_file:'+str(p.relative_to(ROOT)))
        payload=p;relative=p.relative_to(ROOT).as_posix()
        if p.suffix=='.sqlite' and not relative.startswith('outputs/m3/runtime/'):
            payload=Path(temporary.name)/(str(len(payloads))+'.sqlite');sqlite_payload(p,payload)
        elif p.suffix=='.sqlite' and Path(str(p)+'-wal').exists() and Path(str(p)+'-wal').stat().st_size:
            raise RuntimeError('readonly_runtime_has_uncheckpointed_wal')
        payloads[relative]=payload
        records.append({'path':relative,'bytes':payload.stat().st_size,'sha256':sha(payload),
                        'source_main_sha256':sha(p),'sqlite_consistent_backup':payload!=p})
    release=ROOT/'releases';release.mkdir(exist_ok=True)
    target=release/('NetSentry-'+args.version+'-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.zip')
    manifest={'version':args.version,'created_at':datetime.now(timezone.utc).isoformat(),'files':records,
        'private_local_snapshot':True,'raw_data_included':False,'approved_week1_runtime_included':True,'keys_included':False,
        'git_history_created':False,'remote_push':False,'dependency_environments_included':False}
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for row in records:archive.write(payloads[row['path']],row['path'])
        archive.writestr('SNAPSHOT_MANIFEST.json',json.dumps(manifest,indent=2))
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None:raise RuntimeError('archive_crc_failed')
        for row in records:
            if hashlib.sha256(archive.read(row['path'])).hexdigest()!=row['sha256']:raise RuntimeError('snapshot_sha_mismatch')
    manifest.update(archive=str(target),archive_bytes=target.stat().st_size,archive_sha256=sha(target),archive_members_verified=True)
    manifest_name='V0_1_SNAPSHOT.json' if args.version=='v0.1' else 'V0_1_1_SNAPSHOT.json'
    (ROOT/'delivery'/manifest_name).write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    temporary.cleanup()
    print(json.dumps({k:manifest[k] for k in ('archive','archive_bytes','archive_sha256','archive_members_verified')}))

if __name__=='__main__':main()
