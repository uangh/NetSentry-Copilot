"""M2A：只读M1.7存储，重新核验真实CSV，生成离线特征/目标/划分协议。无模型训练。"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import shutil
import sys
import tempfile

from .cic_source import file_sha256
from .labeled_flows import dumps, parse_number, parse_metadata, PROFILES
from .labeled_query import OfflineFlowStore, LabeledFlowQuery
from .label_policy import map_target, label_policy
from .feature_contract import feature_contract, build_features
from .data_split import make_split, STRATEGIES, DEFAULT_CUTS
from .leakage_checks import validate_event

VERSION = 'netsentry.protocol.m2a.v1'
MAX_ROWS = 100_000
MAX_SOURCE_BYTES = 512*1024*1024


def digest(value: object) -> str:
    return hashlib.sha256(dumps(value).encode()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')


def source_hashes(csv_path: Path, store_path: Path) -> dict:
    paths = {'csv':csv_path,'offline':store_path/'offline.sqlite','events':store_path/'events.sqlite'}
    if any(not p.is_file() or p.stat().st_size>MAX_SOURCE_BYTES for p in paths.values()):
        raise ValueError('源文件缺失或超过512MiB预算')
    return {key:file_sha256(path,MAX_SOURCE_BYTES) for key,path in paths.items()}


def checked_base(text: dict) -> dict:
    """复核旧导入器的无效数值标记；质量问题可计数排除，不能静默填0。"""
    result = {}
    for name,column in [('flow_duration','Duration'),('packets','Packets'),('bytes','Bytes')]:
        try:
            value = parse_number(text[column],scaled_bytes=name=='bytes')
        except ValueError:
            value = None
        valid = value is not None and math.isfinite(value) and value>=0
        if valid and name=='packets' and not value.is_integer():
            valid = False
        result[name] = float(value) if valid else None
    return result


def load_samples(csv_path: Path, store_path: Path, hashes: dict) -> tuple[list[dict],dict]:
    """CSV只补充M1.7未入记录的Flags/标注分组；按SHA+原行引用核验，禁止猜测join。"""
    rows = []
    with OfflineFlowStore(store_path/'offline.sqlite') as offline, LabeledFlowQuery(store_path/'events.sqlite') as events:
        report = offline.report
        if report['profile']!='cidds001' or report['source']['sha256']!=hashes['csv']:
            raise ValueError('只支持摘要匹配的CIDDS-001 M1.7存储')
        selection = report['selection']
        identity_sha = report['source']['identity_sha256']
        required = set(report['columns'])
        with csv_path.open(encoding='utf-8-sig',newline='') as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames!=report['actual_header'] or len(set(reader.fieldnames or []))!=len(reader.fieldnames or []):
                raise ValueError('实际标题与M1.7存储不一致')
            needed = {'Duration','Packets','Bytes','Flags','class','attackType','attackID','Date first seen','Src IP Addr','Dst IP Addr'}
            if not needed<=required:
                raise ValueError('缺少M2A所需的实际字段，不能补造')
            for local_row,raw in enumerate(reader,2):
                if len(rows)>=MAX_ROWS or set(raw)!=required or any(v is None for v in raw.values()):
                    raise ValueError('超过10万行预算或CSV结构不符')
                text = {key:value.strip() for key,value in raw.items()}
                original_row = selection['first_original_row_number']+(local_row-2)*selection['every']
                rid = digest([report['source']['manifest']['dataset_id'] if 'manifest' in report['source'] else 'CIDDS-001',identity_sha,original_row])
                record = offline.get_record(rid)
                if record is None or record['source_sha256']!=hashes['csv'] or record['original_row_number']!=original_row:
                    raise ValueError(f'来源记录不能匹配: {local_row}')
                expected = checked_base(text)
                if record['label']!=(text['class'] or None) or record['features']!=expected:
                    raise ValueError(f'CSV与离线记录标签/特征不符: {local_row}')
                try:expected_time = parse_metadata('timestamp',text['Date first seen'],PROFILES['cidds001'])
                except ValueError:expected_time = None
                if record['timestamp']!=expected_time:
                    raise ValueError('CSV与离线时间不符')
                event = events.get_flow_detail(rid)['record']
                validate_event(event)
                expected_event = {k:record[k] for k in ['record_id','dataset_id','source_ip','destination_ip','source_port','destination_port','protocol','timestamp','flow_duration','source_sha256']}
                if event!={**expected_event,'flow_duration_unit':'seconds','time_basis':'source_local_unverified','provenance_kind':report['source']['provenance']}:
                    raise ValueError('事件库内容与离线允许元数据不符')
                reference = events.get_flow_provenance(rid)['record']
                expected_reference = {'record_id':rid,'source_ref':'sha256:'+hashes['csv'],'source_sha256':hashes['csv'],
                                      'original_row_number':original_row,'imported_row_number':local_row,
                                      'imported_physical_end_line':reader.line_num,'row_number_basis':'logical_csv_record_header_is_1',
                                      'parent_member_sha256':report['source']['parent_member_sha256'],'provenance_kind':report['source']['provenance']}
                if reference!=expected_reference:
                    raise ValueError('事件来源接口含未知字段或引用不符')
                targets = {};target_errors = {}
                for task in ['A','B','C']:
                    try:targets[task] = map_target(record['label'],text['attackType'],task)
                    except ValueError as exc:targets[task]=None;target_errors[task]=str(exc)
                attack_group = None
                if record['label'] in ('attacker','victim'):
                    if not text['attackID'].isascii() or not text['attackID'].isdecimal() or int(text['attackID'])<=0:
                        raise ValueError('攻击相关记录缺少可用attackID，不能保证活动分组')
                    attack_group = digest(['CIDDS-001',identity_sha,'attack',text['attackID']])
                elif record['label']=='normal' and text['attackID']!='---':
                    raise ValueError('normal记录出现非空attackID，需先人工审查')
                # 匿名身份仅用于离线稳定分组，不进入X或Agent；不用所有normal共用一个---组。
                endpoints = sorted([text['Src IP Addr'],text['Dst IP Addr']])
                hour = record['timestamp'][:13] if record['timestamp'] else 'unknown_time'
                normal_group = digest([identity_sha,'normal_pair_hour',endpoints,hour]) if record['label']=='normal' else None
                metadata_complete = all(record[k] is not None for k in ['source_ip','destination_ip','source_port','destination_port','protocol','timestamp'])
                rows.append({'record':record,'extra':{'Flags':text['Flags'],'Bytes':text['Bytes']},
                             'targets':targets,'target_errors':target_errors,'attack_type':text['attackType'],
                             'attack_id':text['attackID'],'attack_group':attack_group,'normal_group':normal_group,
                             'full_row_key':digest(list(raw.values())),'metadata_complete':metadata_complete,
                             'any_ip':record['source_ip'] is not None or record['destination_ip'] is not None,
                             'both_ips':record['source_ip'] is not None and record['destination_ip'] is not None,
                             'feature_keys':{}})
        if len(rows)!=report['rows'] or len(rows)!=offline.connection.execute('SELECT COUNT(*) FROM records').fetchone()[0] or len(rows)!=events.connection.execute('SELECT COUNT(*) FROM events').fetchone()[0]:
            raise ValueError('CSV与两个数据库记录数不符')
    return rows,report


def population_summary(rows: list[dict], selected: list[dict]) -> dict:
    before = Counter(r['record']['label'] for r in rows)
    after = Counter(r['record']['label'] for r in selected)
    return {'rows':len(selected),'class_counts':dict(sorted(after.items())),
            'by_class':{label:{'before':n,'after':after[label],'retention':after[label]/n,
                               'share_before':n/len(rows),'share_after':after[label]/len(selected) if selected else None,
                               'share_change_pp':100*(after[label]/len(selected)-n/len(rows)) if selected else None}
                        for label,n in sorted(before.items())}}


def numeric_summary(values: list[float | int | None]) -> dict:
    finite = sorted(v for v in values if v is not None and math.isfinite(v))
    def quantile(p: float) -> float | None:
        return finite[max(0,math.ceil(p*len(finite))-1)] if finite else None
    return {'rows':len(values),'missing':sum(v is None for v in values),
            'non_finite':sum(v is not None and not math.isfinite(v) for v in values),
            'zero':sum(v==0 for v in finite),'negative':sum(v<0 for v in finite),
            'min':finite[0] if finite else None,'p25':quantile(.25),'median':quantile(.5),
            'p95':quantile(.95),'p99':quantile(.99),'max':finite[-1] if finite else None,
            'quantiles':'nearest rank; descriptive only; NOT preprocessing fit parameters'}


def analyze_features(rows: list[dict], scheme: str, output: Path) -> dict:
    groups = {};columns:dict[str,list] = defaultdict(list)
    exclusions = Counter();excluded_labels = Counter();eligible = 0;scaled_classes = Counter()
    with (output/f'{scheme}_X.jsonl').open('w',encoding='utf-8') as stream:
        for row in rows:
            result = build_features(row['record'],row['extra'],scheme)
            rid = row['record']['record_id']
            if result['scaled_bytes']:
                scaled_classes[row['record']['label']]+=1
            if not result['eligible']:
                exclusions.update(result['reasons']);excluded_labels[row['record']['label']]+=1
                row['feature_keys'][scheme] = None
                continue
            x = result['X'];key = digest(x);eligible+=1
            row['feature_keys'][scheme] = key
            stream.write(dumps({'record_id':rid,'X':x})+'\n')
            for name,value in x.items():columns[name].append(value)
            if key not in groups:
                groups[key] = {'X':x,'rows':0,'labels':{t:Counter() for t in ['A','B','C']},'example_record_ids':[]}
            group = groups[key];group['rows']+=1
            for task,target in row['targets'].items():
                if target is not None:group['labels'][task][target]+=1
            if len(group['example_record_ids'])<3:group['example_record_ids'].append(rid)
    conflicts = {}
    for task in ['A','B','C']:
        detail = [{'group_key':key,'rows':g['rows'],'labels':dict(sorted(g['labels'][task].items())),
                   'X':g['X'],'example_record_ids':g['example_record_ids']}
                  for key,g in sorted(groups.items()) if len(g['labels'][task])>1]
        conflicts[task] = {'groups':len(detail),'rows_in_conflict_groups':sum(g['rows'] for g in detail),'details':detail}
    return {'contract':feature_contract(scheme),'eligible_rows':eligible,'excluded_rows':len(rows)-eligible,
            'exclusion_reasons':dict(exclusions),'excluded_original_labels':dict(excluded_labels),
            'group_count':len(groups),'duplicate_excess':eligible-len(groups),'largest_group':max((g['rows'] for g in groups.values()),default=0),
            'conflicts':conflicts,'statistics':{key:numeric_summary(value) for key,value in columns.items()},
            'scaled_bytes_rows':sum(scaled_classes.values()),'if_scaled_excluded_class_losses':dict(scaled_classes)}


def base_analysis(rows: list[dict]) -> dict:
    full = Counter(r['full_row_key'] for r in rows)
    dates:dict[str,Counter] = defaultdict(Counter)
    activities = {}
    for row in rows:
        record = row['record'];day = record['timestamp'][:10] if record['timestamp'] else 'unparseable'
        dates[day][record['label']]+=1
        if row['attack_group'] is not None:
            group = activities.setdefault(row['attack_id'],{'rows':0,'classes':Counter(),'attack_types':Counter(),'dates':set()})
            group['rows']+=1;group['classes'][record['label']]+=1;group['attack_types'][row['attack_type']]+=1;group['dates'].add(day)
    activities = {key:{**value,'dates':sorted(value['dates'])} for key,value in sorted(activities.items(),key=lambda x:int(x[0]))}
    return {'original_classes':dict(Counter(r['record']['label'] for r in rows)),
            'tasks':{task:{'policy':label_policy(task),'counts':dict(Counter(r['targets'][task] for r in rows if r['targets'][task] is not None)),
                           'excluded':sum(r['targets'][task] is None for r in rows)} for task in ['A','B','C']},
            'selection':{'all':population_summary(rows,rows),
                         'complete_metadata':population_summary(rows,[r for r in rows if r['metadata_complete']]),
                         'both_valid_ips':population_summary(rows,[r for r in rows if r['both_ips']]),
                         'any_valid_ip_query':population_summary(rows,[r for r in rows if r['any_ip']])},
            'full_duplicate_excess':sum(n-1 for n in full.values()),'full_duplicate_groups':sum(n>1 for n in full.values()),
            'attack_type_counts':dict(Counter(r['attack_type'] for r in rows)),
            'flags_counts':dict(Counter(r['extra']['Flags'] for r in rows)),
            'activities':activities,'attack_activity_count':len(activities),
            'activity_counts_by_type':dict(Counter(t for v in activities.values() for t in v['attack_types'])),
            'dates':dict(sorted(dates.items())),
            'time':{'minimum':min((r['record']['timestamp'] for r in rows if r['record']['timestamp']),default=None),'maximum':max((r['record']['timestamp'] for r in rows if r['record']['timestamp']),default=None),
                    'backward_steps':sum(bool(a['record']['timestamp'] and b['record']['timestamp'] and a['record']['timestamp']>b['record']['timestamp']) for a,b in zip(rows,rows[1:])),
                    'unparseable':sum(r['record']['timestamp'] is None for r in rows),
                    'timezone':None,'time_basis':'source_local_unverified'},'features':{}}


def split_rows(rows: list[dict], scheme: str, task: str = 'B') -> list[dict]:
    return [{'record_id':r['record']['record_id'],'y':r['targets'][task],'feature_key':r['feature_keys'][scheme],
             'attack_group':r['attack_group'],'normal_group':r['normal_group'],'timestamp':r['record']['timestamp'],
             'duration':r['record']['flow_duration']} for r in rows
            if r['feature_keys'][scheme] is not None and r['targets'][task] is not None]


def export_sidecars(rows: list[dict], output: Path) -> None:
    with (output/'targets.jsonl').open('w',encoding='utf-8') as target, (output/'offline_metadata.jsonl').open('w',encoding='utf-8') as meta:
        for row in rows:
            record = row['record']
            target.write(dumps({'record_id':record['record_id'],'original_class':record['label'],
                               'targets':row['targets'],'target_errors':row['target_errors']})+'\n')
            meta.write(dumps({'record_id':record['record_id'],'source_sha256':record['source_sha256'],
                             'original_row_number':record['original_row_number'],'timestamp':record['timestamp'],
                             'attackID':row['attack_id'],'attackType':row['attack_type'],'attack_group':row['attack_group'],
                             'normal_group':row['normal_group'],'metadata_complete':row['metadata_complete']})+'\n')


def generate_splits(rows: list[dict], output: Path, seed: int, minimum: int) -> dict:
    reports = {}
    for scheme in ['F1','F2','F3']:
        samples = split_rows(rows,scheme)
        reports[scheme] = {}
        for strategy in STRATEGIES:
            if not samples:
                reports[scheme][strategy] = {'status':'infeasible','reason':'no eligible rows','fallback_used':False}
                continue
            result = make_split(samples,strategy,seed=seed,min_per_class=minimum,required_classes=label_policy('B')['classes'])
            directory = output/'splits'/scheme/strategy
            assignment_files = {}
            for name,ids in result.pop('assignments').items():
                path = directory/f'{name}.ids.json';write_json(path,ids)
                assignment_files[name] = {'path':path.relative_to(output).as_posix(),'sha256':file_sha256(path,MAX_SOURCE_BYTES),'rows':len(ids)}
            purged = result.pop('purge_reasons')
            write_json(directory/'quarantine_reasons.json',purged)
            result['assignment_files'] = assignment_files
            result['input_rows'] = len(samples)
            result['ineligible_rows'] = len(rows)-len(samples)
            write_json(directory/'report.json',result)
            reports[scheme][strategy] = result
    # 更细目标是否满足同一最低支持门槛，不能借二分类覆盖替其背书。
    for task in ['A','C']:
        rows_task = split_rows(rows,'F2',task)
        if rows_task:
            result = make_split(rows_task,'C_purged',seed=seed,min_per_class=minimum,required_classes=label_policy(task)['classes'])
            result.pop('assignments');result.pop('purge_reasons')
            reports['task_'+task+'_F2_temporal_diagnostic'] = result
    return reports


def common_comparison(rows: list[dict], output: Path, seed: int, minimum: int) -> dict:
    """比较特征方案必须固定样本：用共同合格行及最粗F1组约束冻结同一划分。"""
    common = [r for r in rows if all(r['feature_keys'][s] is not None for s in ['F1','F2','F3']) and r['targets']['B'] is not None]
    if not common:
        return {'status':'infeasible','reason':'no common eligible rows','fallback_used':False}
    result = make_split(split_rows(common,'F1'),'C_purged',seed=seed,min_per_class=minimum,required_classes=label_policy('B')['classes'])
    files = {}
    for name,ids in result.pop('assignments').items():
        path = output/'comparison_common'/f'{name}.ids.json';write_json(path,ids)
        files[name] = {'path':path.relative_to(output).as_posix(),'sha256':file_sha256(path,MAX_SOURCE_BYTES),'rows':len(ids)}
    write_json(output/'comparison_common/quarantine_reasons.json',result.pop('purge_reasons'))
    result.update(assignment_files=files,eligible_rows=len(common),ineligible_rows=len(rows)-len(common),
                  grouping_basis='F1, coarsest approved feature vector; same IDs for all feature ablations',
                  use='primary proposed protocol; infeasible blocks training, no automatic relaxation')
    write_json(output/'comparison_common/report.json',result)
    return result


def prepare_protocol(csv_path: str | Path, store_path: str | Path, output: str | Path, *, seed: int = 42, min_per_class: int = 20) -> dict:
    csv_path,store_path,output = Path(csv_path).resolve(),Path(store_path).resolve(),Path(output).resolve()
    if output.exists():
        raise ValueError('输出已存在，不覆盖')
    before = source_hashes(csv_path,store_path)
    if shutil.disk_usage(output.parent if output.parent.exists() else Path.cwd()).free<1024**3:
        raise ValueError('要求至少1GiB可用磁盘空间')
    rows,old_report = load_samples(csv_path,store_path,before)
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.m2a-',dir=output.parent) as temporary:
        ready = Path(temporary)/'ready';ready.mkdir()
        analysis = base_analysis(rows)
        for scheme in ['F1','F2','F3']:
            analysis['features'][scheme] = analyze_features(rows,scheme,ready)
        analysis['selection']['model_F1'] = population_summary(rows,[r for r in rows if r['feature_keys']['F1'] is not None and r['targets']['B'] is not None])
        analysis['selection']['joint_F1_and_metadata'] = population_summary(rows,[r for r in rows if r['feature_keys']['F1'] is not None and r['targets']['B'] is not None and r['metadata_complete']])
        export_sidecars(rows,ready)
        splits = generate_splits(rows,ready,seed,min_per_class)
        comparison = common_comparison(rows,ready,seed,min_per_class)
        after = source_hashes(csv_path,store_path)
        if before!=after:
            raise ValueError('原CSV或M1.7数据库被改变，拒绝发布')
        result = {'version':VERSION,'data_kind':old_report['source']['provenance'],'rows':len(rows),
                  'source':{'csv_sha256':before['csv'],'offline_sqlite_sha256':before['offline'],'events_sqlite_sha256':before['events'],
                            'csv_name':csv_path.name,'original_file':old_report['source']['original_file'],
                            'original_member_sha256':old_report['source']['parent_member_sha256'],
                            'source_manifest':old_report['source'].get('manifest'),'selection':old_report['selection'],
                            'hashes_before':before,'hashes_after':after,'unchanged':True},
                  'seed':seed,'min_per_class_per_set':min_per_class,'sample_rule':'all approved numeric records; NO IP validity filter',
                  'analysis':analysis,'splits':splits,'comparison_common':comparison,'agent_check':{'all_records_checked':len(rows),'label_or_X_leak_detected':False,
                     'allowed_shared_attribute':'flow_duration is existing event metadata; no complete X, packets, bytes or Flags'},
                  'preprocessing':{'fit_performed':False,'descriptive_statistics_must_not_be_used_as_fit_parameters':True},
                  'training_performed':False,'training_readiness':'NOT READY',
                  'blockers':['independent external test absent','near-duplicate/host/environment independence unverified',
                              'frozen target/feature/purge selection needs review','scaled byte precision and source timezone unverified'],
                  'recommendation':{'task':'B','baseline':'F1','expanded_candidate':'F2','port_protocol_ablation_only':'F3',
                                    'primary_candidate':'comparison_common: F1-group C_purged on common eligible IDs','final_test':'new independently acquired and locked batch; current test is internal diagnostic only'},
                  'resource_scope':{'max_rows':MAX_ROWS,'max_source_bytes':MAX_SOURCE_BYTES,'in_memory_group_analysis':True},
                  'code_sha256':{name:file_sha256(Path(__file__).with_name(name),MAX_SOURCE_BYTES) for name in
                                 ['label_policy.py','feature_contract.py','leakage_checks.py','data_split.py','prepare_training.py']}}
        artifacts = {p.relative_to(ready).as_posix():{'sha256':file_sha256(p,MAX_SOURCE_BYTES),'bytes':p.stat().st_size}
                     for p in sorted(ready.rglob('*')) if p.is_file()}
        result['artifacts'] = artifacts
        write_json(ready/'manifest.json',result)
        if output.exists():
            raise ValueError('输出目录冲突')
        ready.rename(output)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv',type=Path,required=True)
    parser.add_argument('--store',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--seed',type=int,default=42)
    parser.add_argument('--min-per-class',type=int,default=20)
    args = parser.parse_args(argv)
    try:
        report = prepare_protocol(args.csv,args.store,args.out,seed=args.seed,min_per_class=args.min_per_class)
    except (ValueError,OSError,csv.Error) as exc:
        print(json.dumps({'error':str(exc)},ensure_ascii=True),file=sys.stderr)
        return 2
    print(json.dumps({'rows':report['rows'],'training_readiness':report['training_readiness'],
                      'label_counts':report['analysis']['tasks']['B']['counts'],
                      'F2_primary':{k:report['splits']['F2']['C_purged'][k] for k in ['status','set_sizes','checks']},
                      'source_unchanged':report['source']['unchanged']},indent=2,ensure_ascii=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
