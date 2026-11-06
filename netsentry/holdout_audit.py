"""固定预算的跨周关联审计；只封存候选，绝不拟合或选择模型。"""
from __future__ import annotations
import argparse
from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path

import numpy as np

from .feature_contract import build_features, feature_contract
from .ids_data import ROOT, BASE, binary_label, matrix, read_json, sha, verified, write_json
from .labeled_flows import parse_number

WEEK1=ROOT/'data/raw/cidds001_week1_subset/CIDDS-001-internal-week1.every100.csv'
WEEK2=ROOT/'data/raw/cidds001_week2_candidate/CIDDS-001-internal-week2.every100.csv'
EXPECTED=['Date first seen','Duration','Proto','Src IP Addr','Src Pt','Dst IP Addr','Dst Pt',
          'Packets','Bytes','Flows','Flags','Tos','class','attackType','attackID','attackDescription']


def fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def near_key(x: dict) -> str:
    copy=x.copy()
    for name,width in [('flow_duration',0.001),('bytes',16),('mean_bytes_per_packet',16)]:
        if name in copy and copy[name] is not None:copy[name]=int(copy[name]//width)
    return fingerprint(copy)


def features_from_csv(row: dict, scheme: str) -> dict:
    protocol={'TCP':6,'UDP':17,'ICMP':1,'IGMP':2}.get(row['Proto'].strip(),0)
    ports={}
    for side,key in [('source','Src Pt'),('destination','Dst Pt')]:
        text=row[key].strip()
        ports[side+'_port']=int(text) if text.isdecimal() and 0<=int(text)<=65535 else None
    record={'features':{'flow_duration':float(row['Duration']),'packets':float(row['Packets']),
                        'bytes':parse_number(row['Bytes'].strip(),scaled_bytes=True)},'protocol':protocol,**ports}
    result=build_features(record,{'Bytes':row['Bytes'],'Flags':row['Flags']},scheme)
    if not result['eligible']:raise ValueError('真实行不满足冻结特征契约: '+str(result['reasons']))
    return result['X']


def session_key(row: dict) -> tuple | None:
    if row['Proto'].strip()!='TCP':return None
    try:
        endpoints=[]
        for ip,port in [('Src IP Addr','Src Pt'),('Dst IP Addr','Dst Pt')]:
            address=str(ipaddress.ip_address(row[ip].strip())); value=int(row[port])
            if not 0<=value<=65535:return None
            endpoints.append((address,value))
        return tuple(sorted(endpoints))
    except ValueError:
        return None  # 匿名标识不是有效 IP，不据此声称会话已匹配。


def continuation_candidates(left: dict, right: dict) -> list[dict]:
    result=[]
    for key in left.keys() & right.keys():
        gap=(right[key]-left[key]).total_seconds()
        if gap<=120:
            result.append({'five_tuple_hash':fingerprint(key),'week1_max_end':left[key].isoformat(),
                           'week2_min_start':right[key].isoformat(),'gap_seconds':gap})
    return sorted(result,key=lambda x:x['gap_seconds'])


def _scan(path: Path, output: Path | None) -> dict:
    source=read_json(path.parent/'source.json'); verified(path,source['sha256'])
    if source['provenance']!='public_dataset' or source['dataset_id']!='CIDDS-001':raise ValueError('来源不符')
    if not source['source_url'].startswith('https://www.hs-coburg.de/'):raise ValueError('非已授权官方来源')
    if not source['selection']['crc32_verified']:raise ValueError('压缩成员未验证')
    exact={s:set() for s in ('F1','F2','F3')}; near={s:set() for s in exact}
    full=set(); directed=set(); bidirectional=set(); sessions={}; hosts=set(); activities=set()
    labels=Counter(); types=Counter(); rows=0; invalid_tcp=0; min_time=max_time=None
    files={}
    if output is not None:
        output.mkdir(parents=True,exist_ok=False)
        files={s:(output/(s+'_X.jsonl')).open('x',encoding='utf-8') for s in exact}
        files['targets']=(output/'targets.jsonl').open('x',encoding='utf-8')
    try:
        with path.open(newline='',encoding='utf-8-sig') as stream:
            reader=csv.DictReader(stream)
            if reader.fieldnames!=EXPECTED:raise ValueError('实际字段与已审计 schema 不符')
            for index,row in enumerate(reader):
                if index>=200000 or None in row or any(v is None for v in row.values()):raise ValueError('扫描预算/列宽不符')
                rows+=1; labels[row['class']]+=1; binary_label(row['class'])
                if row['class']!='normal':types[row['attackType']]+=1;activities.add(row['attackID'])
                full.add(fingerprint([row[k] for k in EXPECTED]))
                endpoints=tuple((row[ip].strip(),row[port].strip()) for ip,port in [('Src IP Addr','Src Pt'),('Dst IP Addr','Dst Pt')])
                directed.add((row['Proto'].strip(),*endpoints));bidirectional.add((row['Proto'].strip(),*sorted(endpoints)))
                hosts.update(e[0] for e in endpoints)
                start=datetime.fromisoformat(row['Date first seen']);end=start+timedelta(seconds=float(row['Duration']))
                min_time=start if min_time is None else min(min_time,start);max_time=end if max_time is None else max(max_time,end)
                key=session_key(row)
                if key is not None:
                    stamp=end if output is None else start
                    sessions[key]=(max if output is None else min)(sessions.get(key,stamp),stamp)
                elif row['Proto'].strip()=='TCP':invalid_tcp+=1
                rid=fingerprint([source['dataset_id'],source['selection']['original_member_sha256'],2+index*100])
                for scheme in exact:
                    x=features_from_csv(row,scheme); exact[scheme].add(fingerprint(x));near[scheme].add(near_key(x))
                    if output is not None:files[scheme].write(json.dumps({'record_id':rid,'X':x},allow_nan=False)+'\n')
                if output is not None:files['targets'].write(json.dumps({'record_id':rid,'y':binary_label(row['class'])})+'\n')
    finally:
        for file in files.values():file.close()
    verified(path,source['sha256'])
    if rows!=source['selection']['selected_rows']:raise ValueError('子集行数不符')
    return {'source':source,'rows':rows,'labels':dict(labels),'attack_types':dict(types),'full':full,
        'exact':exact,'near':near,'directed':directed,'bidirectional':bidirectional,'sessions':sessions,
        'hosts':hosts,'activities':activities,'unresolved_anonymized_tcp_rows':invalid_tcp,
        'min_time':min_time.isoformat(),'max_end':max_time.isoformat()}


def audit_week2(out: Path) -> dict:
    from .train_ids import PLAN, PLAN_SHA
    verified(PLAN,PLAN_SHA);out=Path(out);out.mkdir(parents=True,exist_ok=False)
    left=_scan(WEEK1,None);right=_scan(WEEK2,out/'sealed_data')
    candidates=continuation_candidates(left['sessions'],right['sessions'])
    blocking=[]
    if left['full']&right['full']:blocking.append('cross-week identical full CSV rows')
    if left['activities']&right['activities']:blocking.append('observed attack IDs reused across weeks')
    if candidates:blocking.append(f'{len(candidates)} valid TCP five-tuples have cross-week gap <=120s or overlap; session continuation unresolved')
    if left['max_end']>=right['min_time']:blocking.append('cross-week duration intervals overlap')
    overlaps={}
    for scheme in ('F1','F2','F3'):
        affected=near_only=0
        with (out/'sealed_data'/f'{scheme}_X.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                x=json.loads(line)['X'];same=fingerprint(x) in left['exact'][scheme]
                affected+=same; near_only+=(not same and near_key(x) in left['near'][scheme])
        overlaps[scheme]={'exact_shared_groups':len(left['exact'][scheme]&right['exact'][scheme]),
                         'week2_exact_affected_rows':affected,'near_bin_shared_groups':len(left['near'][scheme]&right['near'][scheme]),
                         'week2_near_only_rows':near_only,'rule':'fixed duration 1ms; bytes/mean 16; others exact; bin edges may miss neighbors'}
    report={'version':'netsentry.m2b.holdout.v1','sealed':not blocking,'blocking_reasons':blocking,
        'test_type':'same_environment_cross_week_holdout','audit_only_no_model_predictions':True,
        'audited_at_utc':datetime.now(timezone.utc).isoformat(),'plan_sha256':PLAN_SHA,
        'week1':left['source'],'week2':right['source'],'schema':EXPECTED,
        'week1_rows':left['rows'],'week2_rows':right['rows'],'week2_labels':right['labels'],'week2_attack_types':right['attack_types'],
        'full_row_shared_groups':len(left['full']&right['full']),
        'directed_5tuple_shared_groups':len(left['directed']&right['directed']),
        'bidirectional_5tuple_shared_groups':len(left['bidirectional']&right['bidirectional']),
        'shared_host_identifiers':len(left['hosts']&right['hosts']),
        'attack_ids_week1':sorted(left['activities']),'attack_ids_week2':sorted(right['activities']),
        'shared_attack_ids':sorted(left['activities']&right['activities']),
        'session_continuation_candidates':candidates,'week1_max_end':left['max_end'],'week2_min_start':right['min_time'],
        'unresolved_anonymized_tcp_rows':{'week1':left['unresolved_anonymized_tcp_rows'],'week2':right['unresolved_anonymized_tcp_rows']},
        'feature_overlap':overlaps,'contracts':{s:feature_contract(s) for s in overlaps},
        'artifacts':{p.name:sha(p) for p in (out/'sealed_data').glob('*')},
        'source_manifest_sha256':{'week1':sha(WEEK1.parent/'source.json'),'week2':sha(WEEK2.parent/'source.json')},
        'evaluator_sha256':sha(Path(__file__).with_name('evaluate_ids.py')),
        'audit_code_sha256':sha(Path(__file__)),
        'limits':['systematic every100 subset only; no inference about unsampled parent records',
                  'same lab hosts and scripts; attack IDs and labels not independently verified',
                  'unknown timezone; local dataset clock only',
                  '5tuple/120s is conservative candidate screen, not packet-proven TCP session identity',
                  'anonymized endpoints and missing packets prevent complete session independence proof',
                  'near-bin check is not all-pairs similarity search; duplicates alone are not attacks']}
    write_json(out/'manifest.json',report)
    write_json(out/'access_audit.json',{'action':'source_schema_overlap_audit','model_predictions':False,
        'manifest_sha256':sha(out/'manifest.json'),'selected_rows_removed':0})
    print(json.dumps({k:report[k] for k in ['sealed','blocking_reasons','feature_overlap','full_row_shared_groups','session_continuation_candidates']},indent=2))
    return report


def load_sealed_week2(path: Path, scheme: str, expected_sha: str) -> tuple[np.ndarray,np.ndarray]:
    manifest=read_json(verified(path,expected_sha))
    if not manifest['sealed']:raise ValueError('Week 2 未封存')
    verified(WEEK2,manifest['week2']['sha256'])
    features=verified(path.parent/'sealed_data'/f'{scheme}_X.jsonl',manifest['artifacts'][f'{scheme}_X.jsonl'])
    targets=verified(path.parent/'sealed_data'/'targets.jsonl',manifest['artifacts']['targets.jsonl'])
    xs=[];ys=[]
    with features.open(encoding='utf-8') as fs, targets.open(encoding='utf-8') as ts:
        from itertools import zip_longest
        for a,b in zip_longest(fs,ts):
            if a is None or b is None:raise ValueError('X/y 行数不符')
            x=json.loads(a);y=json.loads(b)
            if x['record_id']!=y['record_id']:raise ValueError('X/y 记录错位')
            xs.append(x['X']);ys.append(y['y'])
    if len(xs)!=manifest['week2_rows']:raise ValueError('Week 2 行数不符')
    return matrix(xs,scheme),np.asarray(ys,dtype=np.int8)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True)
    audit_week2(parser.parse_args().out)
