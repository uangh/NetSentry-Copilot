"""M1.7：流式 CSV 审计与导入，离线标签库和事件查询库物理分离。"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from typing import TypedDict
import unicodedata

from .audit_csv import _HashedReader, _records, AuditError
from .audit_dataset import _count_value, _observed_type
from .cic_source import file_sha256

VERSION='netsentry.labeled.v1'
PROFILES=json.loads(Path(__file__).with_name('labeled_profiles.json').read_text(encoding='utf-8'))
FORBIDDEN=re.compile(r'label|attack|target|class|ground.?truth|prediction|filename|row.?number|flow.?id|timestamp|source.?ip|destination.?ip',re.I)


class NetworkFlowRecord(TypedDict):
    record_id: str
    dataset_id: str
    original_file: str
    original_row_number: int
    flow_id: str | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: int | None
    timestamp: str | None
    flow_duration: float | None
    label: str | None
    features: dict[str,float | None]
    source_sha256: str


@dataclass(frozen=True)
class ImportLimits:
    max_bytes: int=200*1024*1024
    max_rows: int=1_000_000
    max_seconds: int=300
    max_db_bytes: int=512*1024*1024

    def __post_init__(self):
        for name, ceiling in [('max_bytes',200*1024*1024),('max_rows',1_000_000),('max_seconds',3600),('max_db_bytes',512*1024*1024)]:
            value=getattr(self,name)
            if type(value) is not int or not 0<value<=ceiling:raise ValueError(f'{name} 不在预算范围')
        if self.max_db_bytes<256*1024:raise ValueError('数据库预算至少256KiB')


def dumps(value: object) -> str:
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)


def normalized(value: str) -> str:
    return ' '.join(unicodedata.normalize('NFKC',value).strip().casefold().split())


def map_fields(raw: list[str], profile: dict) -> tuple[list[str],dict[str,int],dict[str,int]]:
    columns=[unicodedata.normalize('NFKC',c).strip() for c in raw]
    names=[normalized(c) for c in columns]
    if not columns or len(columns)>256 or any(not n for n in names) or len(set(names))!=len(names):
        raise ValueError('空/重复/过多列名')
    def match(mapping: dict) -> dict:
        result={}
        for role,aliases in mapping.items():
            found=[i for i,n in enumerate(names) if n in {normalized(a) for a in aliases}]
            if len(found)>1:raise ValueError(f'字段角色有歧义: {role}')
            if found:result[role]=found[0]
        return result
    roles=match(profile['roles']);features=match(profile['features'])
    required={'source_ip','destination_ip','source_port','destination_port','protocol','timestamp','label'}
    if not required<=roles.keys() or 'flow_duration' not in features:
        raise ValueError('缺少统一契约必需的IP/端口/协议/时间/标签/持续时间列')
    for key,index in features.items():
        if FORBIDDEN.search(key) or FORBIDDEN.search(columns[index]) or index in roles.values():
            raise ValueError('特征白名单包含禁止字段')
    return columns,roles,features


def parse_number(text: str, *, scaled_bytes: bool=False) -> float:
    if scaled_bytes:
        match=re.fullmatch(r'([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*([kKmMgG])',text)
        if match:return float(match[1])*{'k':1e3,'m':1e6,'g':1e9}[match[2].lower()]
    return float(text)


def parse_metadata(role: str, text: str, profile: dict) -> object:
    if role in ('source_ip','destination_ip'):
        if '%' in text:raise ValueError('未知IPv6 zone')
        return str(ipaddress.ip_address(text))
    if role in ('source_port','destination_port'):
        if not re.fullmatch(r'\d+',text) or not 0<=int(text)<=65535:raise ValueError('非法端口')
        return int(text)
    if role=='protocol':
        known={'TCP':6,'UDP':17,'ICMP':1,'ICMP6':58,'ICMPV6':58,'IGMP':2}
        value=known.get(text.upper(),int(text) if text.isascii() and text.isdecimal() else None)
        if value is None or not 0<=value<=255:raise ValueError('未知协议')
        return value
    if role=='timestamp':
        for fmt in profile['timestamp_formats']:
            try:return datetime.strptime(text,fmt).isoformat(timespec='microseconds')
            except ValueError:continue
        raise ValueError('时间不符合已声明格式')
    raise ValueError('未知元数据角色')


def _database(path: Path, max_bytes: int) -> sqlite3.Connection:
    connection=sqlite3.connect(path)
    connection.execute('PRAGMA page_size=4096')
    connection.execute(f'PRAGMA max_page_count={max_bytes//4096}')
    connection.execute('PRAGMA cache_size=-4096')
    connection.execute('PRAGMA journal_mode=OFF')
    connection.execute('CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL)')
    return connection


def _tables(offline: sqlite3.Connection, events: sqlite3.Connection) -> None:
    offline.executescript('''
      CREATE TABLE records(record_id TEXT PRIMARY KEY,record TEXT NOT NULL,model_ready INTEGER,label TEXT);
      CREATE TABLE full_rows(value TEXT PRIMARY KEY,n INTEGER) WITHOUT ROWID;
      CREATE TABLE feature_groups(value TEXT PRIMARY KEY,n INTEGER,label TEXT,conflict INTEGER) WITHOUT ROWID;
      CREATE TABLE flow_ids(value TEXT PRIMARY KEY,n INTEGER) WITHOUT ROWID;
    ''')
    events.executescript('''
      CREATE TABLE events(record_id TEXT PRIMARY KEY,source_ip TEXT,destination_ip TEXT,source_port INTEGER,
        destination_port INTEGER,timestamp TEXT,record TEXT,provenance TEXT);
      CREATE INDEX src_time ON events(source_ip,timestamp);
      CREATE INDEX dst_time ON events(destination_ip,timestamp);
    ''')


def _profile() -> dict:
    return {'missing':0,'non_finite':0,'numeric_parse_errors':0,'negative':0,'domain_errors':0,'scaled_si_values':0,
            'non_finite_breakdown':{'nan':0,'positive_infinity':0,'negative_infinity':0},
            'type_counts':{'integer':0,'float':0,'non_finite':0,'text':0},'finite_min':None,'finite_max':None}


def _scan(stream, offline: sqlite3.Connection, events: sqlite3.Connection, profile_name: str,
          source: dict, selection: dict, limits: ImportLimits, deadline: float) -> dict:
    profile=PROFILES[profile_name]
    iterator=_records(stream)
    first=next(iterator,None)
    if first is None:raise ValueError('空CSV')
    columns,roles,features=map_fields(first[0],profile)
    profiles={name:_profile() for name in columns}
    metadata_roles=['source_ip','destination_ip','source_port','destination_port','protocol','timestamp']
    validations={key:{'valid':0,'invalid':0,'missing':0} for key in metadata_roles}
    labels:Counter=Counter()
    rows=repeated=model_ready_count=event_ready_count=supervised_count=joint_count=label_missing=flow_missing=0
    minimum=maximum=previous=None
    backwards=0
    feature_indices=set(features.values())
    text_indices={roles[key] for key in ('source_ip','destination_ip','timestamp','flow_id','label') if key in roles}
    blocked=[c for i,c in enumerate(columns) if i not in feature_indices and (FORBIDDEN.search(c) or i in roles.values())]
    unknown=[c for i,c in enumerate(columns) if i not in feature_indices and i not in roles.values()]
    for record_number,(raw,line) in enumerate(iterator,2):
        if record_number-1>limits.max_rows or time.monotonic()>deadline:raise ValueError('记录数或时间预算超限')
        if len(raw)!=len(columns):raise ValueError(f'CSV物理结束行{line}列宽错误')
        if [normalized(c) for c in raw]==[normalized(c) for c in columns]:
            repeated+=1;continue
        rows+=1
        values=[c.strip() for c in raw]
        parsed_features={}
        for i,column in enumerate(columns):
            p=profiles[column];value=values[i]
            feature=next((key for key,index in features.items() if index==i),None)
            numeric=i in feature_indices or i in [roles['source_port'],roles['destination_port']]
            converted=value
            if profile_name=='cidds001' and feature=='bytes' and re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)\s*[kKmMgG]',value):
                converted=str(parse_number(value,scaled_bytes=True));p['scaled_si_values']+=1
            if i in text_indices:
                # 地址、身份、时间、标签是文本；Python能把10002_113转数字不代表它是数值特征。
                if value:p['type_counts']['text']+=1
                else:p['missing']+=1
            else:
                _count_value(p,converted,numeric)
            if feature:
                number=None
                try:
                    candidate=float(converted)
                    if math.isfinite(candidate):
                        if candidate<0:p['negative']+=1
                        elif feature in ('packets','fwd_packets','bwd_packets') and not candidate.is_integer():p['domain_errors']+=1
                        else:number=0.0 if candidate==0 else candidate
                except ValueError:pass  # 已由 _count_value 计入空值或解析失败；不填造数值。
                parsed_features[feature]=number
        meta={}
        for role in metadata_roles:
            value=values[roles[role]]
            parsed=None
            if not value:validations[role]['missing']+=1
            else:
                try:parsed=parse_metadata(role,value,profile)
                except ValueError:validations[role]['invalid']+=1
                else:validations[role]['valid']+=1
            meta[role]=parsed
        timestamp=meta['timestamp']
        if timestamp is not None:
            if previous is not None and timestamp<previous:backwards+=1
            previous=timestamp
            minimum=timestamp if minimum is None else min(minimum,timestamp)
            maximum=timestamp if maximum is None else max(maximum,timestamp)
        label=values[roles['label']] or None
        if label is None:label_missing+=1
        else:
            if len(label)>256:raise ValueError('标签过长')
            labels[label]+=1
            if len(labels)>100:raise ValueError('标签超过100类')
        flow_id=values[roles['flow_id']] or None if 'flow_id' in roles else None
        if flow_id is None:flow_missing+=1
        else:offline.execute('INSERT INTO flow_ids VALUES (?,1) ON CONFLICT(value) DO UPDATE SET n=n+1',(flow_id,))
        original_row=selection['first_original_row_number']+(record_number-2)*selection['every']
        identity=[profile['dataset_id'],source['identity_sha256'],original_row]
        record_id=hashlib.sha256(dumps(identity).encode()).hexdigest()
        record:NetworkFlowRecord={'record_id':record_id,'dataset_id':profile['dataset_id'],
            'original_file':source['original_file'],'original_row_number':original_row,'flow_id':flow_id,
            **meta,'flow_duration':parsed_features['flow_duration'],'label':label,'features':parsed_features,
            'source_sha256':source['sha256']}
        model_ready=all(value is not None for value in parsed_features.values())
        event_ready=all(value is not None for value in meta.values())
        model_ready_count+=model_ready;event_ready_count+=event_ready
        supervised_count+=model_ready and label is not None
        joint_count+=model_ready and event_ready and label is not None
        offline.execute('INSERT INTO records VALUES (?,?,?,?)',(record_id,dumps(record),int(model_ready),label))
        offline.execute('INSERT INTO full_rows VALUES (?,1) ON CONFLICT(value) DO UPDATE SET n=n+1',(dumps(raw),))
        if model_ready:
            offline.execute('INSERT INTO feature_groups VALUES (?,1,?,0) ON CONFLICT(value) DO UPDATE SET n=n+1,conflict=MAX(conflict,label IS NOT excluded.label)',(dumps(parsed_features),label))
        # 构造新对象而不是从完整记录删Label；未获批准的字段根本不进入事件库。
        event={'record_id':record_id,'dataset_id':profile['dataset_id'],**meta,
               'flow_duration':parsed_features['flow_duration'],'flow_duration_unit':profile['duration_unit'],
               'source_sha256':source['sha256'],'time_basis':'source_local_unverified',
               'provenance_kind':source['provenance']}
        reference={'record_id':record_id,'source_ref':'sha256:'+source['sha256'],'source_sha256':source['sha256'],
                   'original_row_number':original_row,'imported_row_number':record_number,
                   'imported_physical_end_line':line,'row_number_basis':'logical_csv_record_header_is_1',
                   'parent_member_sha256':source['parent_member_sha256'],'provenance_kind':source['provenance']}
        events.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?)',(
            record_id,meta['source_ip'],meta['destination_ip'],meta['source_port'],meta['destination_port'],timestamp,dumps(event),dumps(reference)))
        if rows%10000==0:offline.commit();events.commit()
    if rows==0:raise ValueError('没有数据记录')
    for p in profiles.values():p['observed_type']=_observed_type(p)
    full=offline.execute('SELECT COALESCE(SUM(n-1),0) FROM full_rows').fetchone()[0]
    duplicate_ids=offline.execute('SELECT COALESCE(SUM(n-1),0),COALESCE(SUM(n>1),0) FROM flow_ids').fetchone()
    feat=offline.execute('SELECT COALESCE(SUM(n-1),0),COALESCE(SUM(conflict),0) FROM feature_groups').fetchone()
    return {'schema_version':VERSION,'profile':profile_name,'rows':rows,'repeated_headers':repeated,
            'actual_header':first[0],'columns':columns,'column_count':len(columns),'column_profiles':profiles,
            'field_mapping':{key:columns[i] for key,i in roles.items()},'feature_mapping':{key:columns[i] for key,i in features.items()},
            'feature_order':list(features),'blocked_from_model':blocked,'unapproved_columns':unknown,
            'metadata_validation':validations,'labels':{'counts':dict(sorted(labels.items())),'missing':label_missing,
                'majority_minority_ratio':max(labels.values())/min(labels.values()) if len(labels)>1 else None,
                'definition':'publisher class; no binary relabeling; not independently verified'},
            'flow_id':{'present':'flow_id' in roles,'missing':flow_missing,'duplicate_excess':duplicate_ids[0],'duplicate_groups':duplicate_ids[1]},
            'duplicates':{'full_row_excess':full,'feature_excess':feat[0],'feature_label_conflict_groups':feat[1],
                'full_comparison':'exact parsed cell strings','feature_comparison':'finite nonnegative parsed numeric model view; invalid rows excluded',
                'near_duplicates':'not_checked','cross_file_duplicates':'not_checked'},
            'time':{'minimum':minimum,'maximum':maximum,'backward_steps':backwards,'timezone':None,'basis':'source_local_unverified'},
            'model_ready_rows':model_ready_count,'event_ready_rows':event_ready_count,'supervised_ready_rows':supervised_count,
            'joint_ready_rows':joint_count,'training_readiness':{'ready':False,'training_performed':False,
                'blockers':['split_protocol_not_frozen','label_semantics_review','cross_batch_evaluation_missing','timezone_unverified','quality_policy_review']}}


def import_labeled_flows(csv_path: str | Path, *, output_dir: str | Path | None=None,
                         profile: str='cicids2017_glf', provenance: str='unknown',
                         manifest: str | Path | None=None, limits: ImportLimits=ImportLimits()) -> dict:
    if profile not in PROFILES or provenance not in ('synthetic','public_dataset','user_supplied','unknown'):raise ValueError('非法数据集配置或来源类别')
    path=Path(csv_path).resolve()
    if not path.is_file() or path.stat().st_size>limits.max_bytes:raise ValueError('输入不存在或超过200MiB预算')
    start=time.monotonic()
    before=file_sha256(path,limits.max_bytes)
    target=Path(output_dir).resolve() if output_dir is not None else Path('artifacts/m1_7')/before[:16]
    if target.exists():raise ValueError('输出已存在，不覆盖')
    selection={'method':'full_local_file','every':1,'first_original_row_number':2,'random_seed':None}
    source={'original_file':path.name,'file_name':path.name,'size_bytes':path.stat().st_size,'sha256':before,
            'identity_sha256':before,'parent_member_sha256':None,'provenance':provenance,'source_authenticity':'caller_declared'}
    if manifest is not None:
        manifest_path=Path(manifest)
        if manifest_path.stat().st_size>1024*1024:raise ValueError('来源清单过大')
        supplied=json.loads(manifest_path.read_text(encoding='utf-8'))
        if supplied.get('sha256')!=before or supplied.get('file_name')!=path.name or supplied.get('size_bytes')!=path.stat().st_size or supplied.get('dataset_id')!=PROFILES[profile]['dataset_id']:
            raise ValueError('来源清单与文件/配置不符')
        if supplied.get('provenance')!=provenance:raise ValueError('来源类别与清单不符')
        chosen=supplied.get('selection',{})
        if chosen.get('method')!='systematic_every_nth_record' or type(chosen.get('every')) is not int or not 1<=chosen['every']<=10000 or chosen.get('first_original_row_number')!=2 or not re.fullmatch('[0-9a-f]{64}',str(chosen.get('original_member_sha256',''))):
            raise ValueError('不支持或无效的子集来源映射')
        selection=chosen
        source.update(original_file=supplied['original_file'],parent_member_sha256=chosen['original_member_sha256'],
                      identity_sha256=chosen['original_member_sha256'],manifest=supplied,
                      source_authenticity='manifest_bound_by_sha256_not_publisher_signature')
    target.parent.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(target.parent).free<limits.max_db_bytes+16*1024*1024:raise ValueError('磁盘预算不足')
    try:
        with tempfile.TemporaryDirectory(prefix='.labeled-',dir=target.parent) as temp:
            ready=Path(temp)/'ready';ready.mkdir()
            offline=_database(ready/'offline.sqlite',limits.max_db_bytes*3//4)
            events=None
            try:
                events=_database(ready/'events.sqlite',limits.max_db_bytes//4)
                _tables(offline,events)
                with path.open('rb') as raw:
                    hashed=_HashedReader(raw,limits.max_bytes)
                    with io.TextIOWrapper(io.BufferedReader(hashed),encoding='utf-8-sig',newline='') as text:
                        report=_scan(text,offline,events,profile,source,selection,limits,start+limits.max_seconds)
                    observed=hashed.digest.hexdigest()
                after=file_sha256(path,limits.max_bytes)
                if before!=after or before!=observed:raise ValueError('扫描前/中/后摘要不一致')
                if 'selected_rows' in selection and selection['selected_rows']!=report['rows']+report['repeated_headers']:
                    raise ValueError('子集记录数与来源清单不符')
                source.update(sha256_after=after,input_unchanged=True)
                report.update(source=source,selection=selection,local_scan='complete_no_estimation',resource_limits=asdict(limits))
                safe={'schema_version':VERSION,'store_kind':'events_only','dataset_id':PROFILES[profile]['dataset_id'],
                      'time_basis':'source_local_unverified','feature_values_present':False,'labels_present':False}
                events.execute('INSERT INTO metadata VALUES (?,?)',('contract',dumps(safe)))
                offline.execute('INSERT INTO metadata VALUES (?,?)',('report',dumps(report)))
                offline.commit();events.commit()
            finally:
                offline.close()
                if events is not None:events.close()
            report['database_bytes']={name:(ready/name).stat().st_size for name in ['offline.sqlite','events.sqlite']}
            (ready/'audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
            if time.monotonic()-start>limits.max_seconds:raise ValueError('导入总时间超限')
            # 两个库及审计放在同一个新目录中提交；绝不修改原始CSV。
            if target.exists():raise ValueError('输出目录冲突')
            ready.rename(target)
        return report
    except (AuditError,UnicodeError,sqlite3.Error,OSError) as exc:
        raise ValueError(f'导入失败，未提交部分结果: {exc}') from exc


def main(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv',type=Path)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--profile',required=True,choices=sorted(PROFILES))
    parser.add_argument('--provenance',default='unknown')
    parser.add_argument('--manifest',type=Path)
    try:
        args=parser.parse_args(argv)
        report=import_labeled_flows(args.csv,output_dir=args.out,profile=args.profile,provenance=args.provenance,manifest=args.manifest)
    except (ValueError,OSError) as exc:
        print(json.dumps({'error':str(exc)},ensure_ascii=True),file=sys.stderr);return 2
    print(json.dumps({key:report[key] for key in ['rows','column_count','model_ready_rows','event_ready_rows','joint_ready_rows','source','training_readiness']},ensure_ascii=True,indent=2))
    return 0


if __name__=='__main__':raise SystemExit(main())
