"""M2A.1：三种协议的相同样本比较；Week2候选禁止进入开发输入。"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timedelta
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
from .data_split import make_split, DEFAULT_CUTS
from .leakage_checks import inspect_split, ACTIVE_SETS
from .split_diagnostics import counts, temporal_reasons, attribute_losses, RULE_ORDER, group_report, component_report, overlap_report
from .prepare_training import source_hashes, load_samples, base_analysis, digest, write_json, MAX_SOURCE_BYTES
from .feature_contract import build_features, feature_contract
from .cic_source import file_sha256

VERSION='netsentry.split_comparison.v1'
PROTOCOLS=('A_strict','B_time_activity','C_activity')


def validate_development_source(source: dict) -> None:
    if source.get('original_file')!='CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week1.csv':
        raise ValueError('本轮开发只允许已批准Week1；Week2候选不能参与划分选择')


def time_audit(rows: list[dict], assignments: dict) -> dict:
    by_id={r['record_id']:r for r in rows};ranges={}
    for split in ACTIVE_SETS:
        selected=[by_id[i] for i in assignments[split]]
        starts=[datetime.fromisoformat(r['timestamp']) for r in selected if r['timestamp']]
        ends=[datetime.fromisoformat(r['timestamp'])+timedelta(seconds=r['duration']) for r in selected if r['timestamp']]
        ranges[split]={'min_start':min(starts).isoformat() if starts else None,'max_end':max(ends).isoformat() if ends else None,
                       'days':dict(sorted(Counter(r['timestamp'][:10] for r in selected if r['timestamp']).items()))}
    pairs=[]
    for left,right in [('train','validation'),('validation','test'),('train','test')]:
        a,b=ranges[left]['max_end'],ranges[right]['min_start']
        pairs.append({'earlier':left,'later':right,'chronologically_separated':a is not None and b is not None and a<b})
    return {'ranges':ranges,'ordered_pairs':pairs,'all_chronological':all(p['chronologically_separated'] for p in pairs),
            'timezone':'source_local_unverified','near_duplicate_independence':'not_verified'}


def compare_protocols(rows: list[dict], *, seed: int=42, minimum: int=20, min_activities: int=3) -> dict:
    if type(min_activities) is not int or min_activities<1:raise ValueError('活动支持门槛必须为正整数')
    rows=sorted(rows,key=lambda r:r['record_id'])
    if not rows or len({r['record_id'] for r in rows})!=len(rows):raise ValueError('空输入或重复ID')
    reasons=temporal_reasons(rows)
    a=make_split(rows,'C_purged',seed=seed,min_per_class=minimum,required_classes=['normal','attack-related'])
    c=make_split(rows,'D_activity',seed=seed,min_per_class=minimum,required_classes=['normal','attack-related'])
    b_assign={s:[] for s in (*ACTIVE_SETS,'quarantine')};b_reasons={}
    for split,ids in reasons['assignments'].items():
        for rid in ids:
            why=[r for r in reasons['reasons'][rid] if r!='feature_key_crosses_time']
            b_assign['quarantine' if why else split].append(rid)
            if why:b_reasons[rid]=why
    b={'assignments':{s:sorted(ids) for s,ids in b_assign.items()},'purge_reasons':b_reasons,'fallback_used':False}
    result={};by_id={r['record_id']:r for r in rows}
    for name,base in zip(PROTOCOLS,(a,b,c)):
        assigned=base['assignments'];checks=inspect_split(rows,assigned,min_per_class=minimum,required_classes=['normal','attack-related'])
        activity={s:len({by_id[i]['attack_group'] for i in assigned[s] if by_id[i]['attack_group']}) for s in ACTIVE_SETS}
        overlap={scheme:overlap_report([{**r,'chosen_key':r['feature_keys'][scheme]} for r in rows],assigned,'chosen_key') for scheme in ['F1','F2','F3']}
        activity_ok=all(n>=min_activities for n in activity.values())
        constraints=['attack_cross_groups','normal_block_cross_groups']+(['feature_cross_groups'] if name=='A_strict' else [])
        feasible=checks['record_ids_disjoint'] and checks['all_records_accounted'] and checks['class_coverage_ok'] and activity_ok and all(checks[k]==0 for k in constraints)
        populations={}
        for split,ids in assigned.items():
            selected=[by_id[i] for i in ids];population=counts(selected)
            population['class_shares']={k:v/len(ids) for k,v in population['classes'].items()} if ids else {}
            population['metadata_complete']=counts([r for r in selected if r['metadata_complete']])
            population['any_ip_query']=counts([r for r in selected if r['any_ip']])
            populations[split]=population
        isolated=set(assigned['quarantine'])
        kept=[r for r in rows if r['record_id'] not in isolated]
        totals=counts(rows)['classes'];remaining=counts(kept)['classes']
        result[name]={'version':VERSION,'protocol':name,'seed':seed,'minimum_per_class':minimum,'minimum_activities':min_activities,
                      'feature_schemes':['F1','F2','F3'],'shared_record_lists':True,'status':'feasible' if feasible else 'infeasible',
                      'fallback_used':False,'assignments':assigned,'purge_reasons':base.get('purge_reasons',{}),
                      'checks':checks,'enforced_constraints':constraints,'feature_overlap':overlap,
                      'full_row_overlap':overlap_report(rows,assigned,'full_row_key'),'activity_counts':activity,'activity_coverage_ok':activity_ok,
                      'time_audit':time_audit(rows,assigned),'populations':populations,
                      'retention':len(kept)/len(rows),'class_retention':{k:remaining.get(k,0)/n for k,n in totals.items()},
                      'test_role':'internal_diagnostic_NOT_final_test','independence':'no claim of near-duplicate or environment independence',
                      'time_cuts':list(DEFAULT_CUTS) if name!='C_activity' else None,'embargo_seconds':60 if name!='C_activity' else None}
    return result


def prepare_comparison(csv_path: Path, store: Path, baseline: Path, output: Path) -> dict:
    csv_path,store,baseline,output=(p.resolve() for p in (csv_path,store,baseline,output))
    if output.exists():raise ValueError('不覆盖已有目录')
    if shutil.disk_usage(output.parent if output.parent.exists() else Path.cwd()).free<1024**3:raise ValueError('至少需要1GiB磁盘空间')
    before=source_hashes(csv_path,store)
    old=json.loads((baseline/'manifest.json').read_text(encoding='utf-8'))
    validate_development_source(old['source'])
    if before!=old['source']['hashes_after']:raise ValueError('源CSV/存储不匹配M2A基线')
    for name,ref in old['artifacts'].items():
        path=(baseline/name).resolve()
        if not path.is_relative_to(baseline.resolve()) or file_sha256(path,MAX_SOURCE_BYTES)!=ref['sha256']:raise ValueError('M2A产物摘要不匹配')
    samples,source_report=load_samples(csv_path,store,before)
    validate_development_source(source_report['source'])
    analysis=base_analysis(samples);eligible=[];qualification=[]
    feature_counts=Counter();label_valid=0
    for sample in samples:
        record=sample['record'];why=[]
        if sample['targets']['B'] is None:why.append('invalid_target')
        else:label_valid+=1
        keys={}
        for scheme in ['F1','F2','F3']:
            built=build_features(record,sample['extra'],scheme)
            if built['eligible']:feature_counts[scheme]+=1;keys[scheme]=digest(built['X'])
            else:why.extend(scheme+':'+r for r in built['reasons'])
        qualification.append({'record_id':record['record_id'],'original_class':record['label'],'y':sample['targets']['B'],
                              'state':'ineligible' if why else 'eligible','reasons':why})
        if not why:
            eligible.append({'record_id':record['record_id'],'y':sample['targets']['B'],'original_class':record['label'],
                             'feature_key':keys['F1'],'feature_keys':keys,'attack_group':sample['attack_group'],
                             'normal_group':sample['normal_group'],'timestamp':record['timestamp'],'duration':record['flow_duration'],
                             'full_row_key':sample['full_row_key'],'attack_id':sample['attack_id'],
                             'metadata_complete':sample['metadata_complete'],'any_ip':sample['any_ip']})
    temporal=temporal_reasons(eligible)
    attrition=attribute_losses(eligible,temporal['reasons'],RULE_ORDER)
    compared=compare_protocols(eligible)
    prior_assign={s:json.loads((baseline/ref['path']).read_text()) for s,ref in old['comparison_common']['assignment_files'].items()}
    if compared['A_strict']['assignments']!=prior_assign:raise ValueError('严格A重新执行与旧M2A清单不一致')
    group_details={s:group_report(eligible,s) for s in ['F1','F2','F3']}
    components={s:{strategy:component_report([{**r,'feature_key':r['feature_keys'][s]} for r in eligible],strategy)
                   for strategy in ['B_feature','D_activity','E_components']} for s in ['F1','F2','F3']}
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.m2a1-',dir=output.parent) as tmp:
        ready=Path(tmp)/'ready';ready.mkdir()
        write_json(ready/'attrition.json',attrition);write_json(ready/'groups.json',{'features':group_details,'components':components})
        owners={p:{i:s for s,ids in report['assignments'].items() for i in ids} for p,report in compared.items()}
        candidate_owner={i:s for s,ids in temporal['assignments'].items() for i in ids}
        eligible_by_id={r['record_id']:r for r in eligible}
        with (ready/'record_decisions.jsonl').open('w',encoding='utf-8') as stream:
            for q in qualification:
                rid=q['record_id'];row=eligible_by_id.get(rid)
                stream.write(json.dumps({**q,'feature_keys':row['feature_keys'] if row else None,'candidate_set':candidate_owner.get(rid),
                    'all_strict_reasons':temporal['reasons'].get(rid,[]),'protocols':{p:{'set':owners[p].get(rid,'ineligible'),
                    'reasons':report['purge_reasons'].get(rid,[]) or (['invalid_time'] if owners[p].get(rid)=='quarantine' else [])} for p,report in compared.items()},
                    'deleted_from_source':False},sort_keys=True)+'\n')
        for name,report in compared.items():
            refs={}
            for split,ids in report.pop('assignments').items():
                path=ready/name/(split+'.ids.json');write_json(path,ids)
                refs[split]={'path':path.relative_to(ready).as_posix(),'sha256':file_sha256(path,MAX_SOURCE_BYTES),'rows':len(ids)}
            write_json(ready/name/'quarantine_reasons.json',report.pop('purge_reasons'))
            report['assignment_files']=refs;report['X_files']={s:{'baseline_relative_path':s+'_X.jsonl',**old['artifacts'][s+'_X.jsonl']} for s in ['F1','F2','F3']}
            write_json(ready/name/'manifest.json',report)
        after=source_hashes(csv_path,store)
        if before!=after:raise ValueError('源文件改变，拒绝发布')
        result={'version':VERSION,'source':old['source'],'input_rows':len(samples),'label_valid_rows':label_valid,
                'feature_valid_rows':dict(feature_counts),'common_eligible_rows':len(eligible),'ineligible_rows':len(samples)-len(eligible),
                'base_analysis':analysis,'protocols':compared,'strict_reproduces_old_ids':True,
                'source_hashes_before':before,'source_hashes_after':after,'agent_all_rows_checked':len(samples),
                'baseline_manifest_sha256':file_sha256(baseline/'manifest.json',MAX_SOURCE_BYTES),
                'candidate_final_test_used_for_development':False,'development_batch':'internal-week1 only',
                'training_performed':False,'training_readiness':'NOT READY','seed':42,
                'boundary_rationale':'keep 60s from M2A; explicit flow end overlap also checked; source time precision/near-duplicate uncertainty remains',
                'code_sha256':{p.name:file_sha256(p,MAX_SOURCE_BYTES) for p in Path(__file__).parent.glob('*.py')}}
        result['artifacts']={p.relative_to(ready).as_posix():{'bytes':p.stat().st_size,'sha256':file_sha256(p,MAX_SOURCE_BYTES)} for p in sorted(ready.rglob('*')) if p.is_file()}
        write_json(ready/'manifest.json',result)
        if output.exists():raise ValueError('输出冲突')
        publish_directory(ready,output)
    return result


def publish_directory(ready: Path, output: Path) -> None:
    """Windows可能暂时拒绝新文件目录改名；有限重试，不覆盖任何既存目录。"""
    for attempt in range(3):
        if output.exists():raise ValueError('输出目录已存在')
        try:
            ready.rename(output)
            return
        except PermissionError:
            if attempt==2:raise
            time.sleep(.2)


def main(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['csv','store','baseline','out']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args(argv)
    try:report=prepare_comparison(args.csv,args.store,args.baseline,args.out)
    except (ValueError,OSError) as exc:
        print(json.dumps({'error':str(exc)},ensure_ascii=True),file=sys.stderr);return 2
    print(json.dumps({'rows':report['input_rows'],'protocols':{k:{'status':r['status'],'populations':r['populations'],'activities':r['activity_counts']} for k,r in report['protocols'].items()},'readiness':report['training_readiness']},indent=2))
    return 0


if __name__=='__main__':raise SystemExit(main())
