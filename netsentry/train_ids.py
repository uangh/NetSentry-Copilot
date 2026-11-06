"""M2B：预定小规模基线，Train 拟合，Validation 选型，冻结后才测试。"""
from __future__ import annotations
import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import warnings

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from threadpoolctl import threadpool_limits

from .feature_contract import feature_contract
from .ids_data import ROOT, BASE, SPLIT_SHA, FrozenWeek1, read_json, require_training_role, sha, verified, write_json
from .evaluate_ids import attack_scores, evaluate_model
from .model_registry import ModelRegistry

PLAN=ROOT/'delivery/M2B_EXPERIMENT_PLAN.json'
PLAN_SHA='3ec0f7c85c54825d1e50a3927718927085bf10b1e0f9097f4dc65e97afc310b9'


def make_pipeline(scheme: str, kind: str) -> Pipeline:
    fields=feature_contract(scheme)['fields']
    categorical=[i for i,f in enumerate(fields) if f['dtype']=='categorical_integer']
    numeric=[i for i in range(len(fields)) if i not in categorical]
    transforms=[('numeric',Pipeline([('impute',SimpleImputer(strategy='median',keep_empty_features=True)),
                                     ('scale',StandardScaler())]),numeric)]
    if categorical:
        transforms.append(('ports',Pipeline([('impute',SimpleImputer(strategy='constant',fill_value=-1,keep_empty_features=True)),
            ('encode',OneHotEncoder(handle_unknown='ignore',max_categories=64,min_frequency=10,sparse_output=False))]),categorical))
    if kind=='dummy': classifier=DummyClassifier(strategy='most_frequent')
    elif kind=='logistic': classifier=LogisticRegression(C=1,class_weight='balanced',max_iter=2000,random_state=42)
    elif kind in ('rf100','rf200'):
        classifier=RandomForestClassifier(n_estimators=100 if kind=='rf100' else 200,
            max_depth=12 if kind=='rf100' else 18,min_samples_leaf=3 if kind=='rf100' else 5,
            class_weight='balanced_subsample',n_jobs=2,random_state=42)
    else:raise ValueError('模型不在预先固定的候选清单内')
    return Pipeline([('preprocess',ColumnTransformer(transforms,remainder='drop')),
                     ('classifier',classifier)])


def _worker(run: Path, scheme: str, kind: str) -> None:
    inputs=np.load(run/'training_inputs'/f'{scheme}.npz',allow_pickle=False)
    model=make_pipeline(scheme,kind); model_id=scheme+'_'+kind
    with threadpool_limits(limits=2), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always'); started=time.perf_counter()
        model.fit(inputs['train_x'],inputs['train_y']); train_seconds=time.perf_counter()-started
        result=evaluate_model(model,inputs['validation_x'],inputs['validation_y'])
        registry=ModelRegistry(run/'models')
        manifest=registry.save(model_id,model,scheme,{'training_role':'train','source_protocol_sha256':SPLIT_SHA,
            'experiment_plan_sha256':PLAN_SHA,'train_rows':len(inputs['train_y']),
            'validation_rows':len(inputs['validation_y']), 'data_summary_sha256':sha(run/'data_summary.json')})
        before=attack_scores(model,inputs['validation_x'][:256])
        loaded,_=registry.load(model_id,manifest['sha256'])
        after=attack_scores(loaded,inputs['validation_x'][:256])
        # 并行森林的浮点累加次序可造成约 1e-16 差异；类别必须完全相同。
        max_difference=float(np.max(np.abs(before-after)))
        if not np.allclose(before,after,rtol=0,atol=1e-12) or not np.array_equal(before>=0.5,after>=0.5):
            raise ValueError('模型保存/重载预测超出浮点容差或分类改变')
    result.update(model_id=model_id,scheme=scheme,kind=kind,training_seconds=train_seconds,
                  reloaded_prediction_equal=True,reload_score_max_abs_difference=max_difference,
                  reload_score_absolute_tolerance=1e-12,reload_classes_exactly_equal=True,
                  warning_messages=[str(w.message) for w in caught])
    write_json(run/'validation'/f'{model_id}.json',result)
    print(json.dumps(result,ensure_ascii=False),flush=True)


def _inference_store(run: Path, data: FrozenWeek1, scheme: str) -> None:
    target=run/'inference.sqlite'
    if target.exists():raise FileExistsError(target)
    with closing(sqlite3.connect(target)) as connection, connection:
        connection.execute('CREATE TABLE features(record_id TEXT PRIMARY KEY,x TEXT NOT NULL)')
        count=0
        with data.artifact(scheme+'_X.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                item=json.loads(line)
                connection.execute('INSERT INTO features VALUES (?,?)',(item['record_id'],json.dumps(item['X'],allow_nan=False)))
                count+=1
    write_json(run/'inference_store.json',{'scheme':scheme,'sha256':sha(target),'rows':count,
        'columns':['record_id','x'],'source_feature_sha256':data.base['artifacts'][scheme+'_X.jsonl']['sha256'],
        'label_access':False})


def selection_allowed(candidates_only: bool, evaluate_final: bool, access_root: Path) -> None:
    if candidates_only and evaluate_final:raise ValueError('补齐候选模式禁止测试')
    if not candidates_only and any(Path(access_root).glob('*.json')):
        raise ValueError('正式测试已经访问，禁止重新选型；只能 --candidates-only 补齐固定实验')


def complete_candidates(results: list[dict], failures: list[dict]) -> None:
    expected={(s,k) for s in ('F1','F2') for k in ('dummy','logistic','rf100','rf200')}
    if not expected<={(r['scheme'],r['kind']) for r in results} or any(f['scheme'] in ('F1','F2') for f in failures):
        raise ValueError('F1/F2 预定候选未全部成功，禁止冻结或访问最终测试')


def train_baselines(out: Path, *, training_role: str='train', evaluate_final: bool=False,
                    candidates_only: bool=False) -> dict:
    require_training_role(training_role)
    selection_allowed(candidates_only,evaluate_final,ROOT/'artifacts/m2b/test_access')
    plan=read_json(verified(PLAN,PLAN_SHA)); out=Path(out).resolve()
    out.mkdir(parents=True,exist_ok=False)
    write_json(out/'experiment_plan.json',plan)
    data=FrozenWeek1()
    write_json(out/'data_summary.json',{'protocol':'B_time_activity','manifest_sha256':SPLIT_SHA,
        'assignment_files':data.protocol['assignment_files'],'class_counts':data.protocol['checks']['class_counts'],
        'source_hashes':data.split['source_hashes_before'],'preprocessing_fit_role':'train',
        'no_ip_filter':True,'threshold':0.5})
    (out/'training_inputs').mkdir(); results=[]; failures=[]
    env=dict(os.environ,OMP_NUM_THREADS='2',OPENBLAS_NUM_THREADS='2',MKL_NUM_THREADS='2',PYTHONIOENCODING='utf-8')
    for scheme in ('F1','F2','F3'):
        tx,ty,_=data.load(scheme,'train'); vx,vy,_=data.load(scheme,'validation')
        np.savez_compressed(out/'training_inputs'/f'{scheme}.npz',train_x=tx,train_y=ty,validation_x=vx,validation_y=vy)
        for kind in ('dummy','logistic','rf100','rf200'):
            command=[sys.executable,'-m','netsentry.train_ids','--worker',str(out),scheme,kind]
            print(f'START {scheme}_{kind}',flush=True)
            try:
                process=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',timeout=180)
                log=process.stdout+'\n'+process.stderr
                if process.returncode:raise RuntimeError(log)
                result=read_json(out/'validation'/f'{scheme}_{kind}.json');results.append(result)
                print(log,flush=True)
            except (subprocess.TimeoutExpired,RuntimeError) as error:
                log=str(error); failures.append({'scheme':scheme,'kind':kind,'error':log})
                print(log,flush=True)
            (out/f'{scheme}_{kind}.log').write_text(log,encoding='utf-8')
        del tx,ty,vx,vy
    write_json(out/'comparison.json',{'validation':results,'failures':failures,'threshold':0.5})
    complete_candidates(results,failures)
    if candidates_only:
        print('CANDIDATES_ONLY: no selection, no freezing, no Test access',flush=True)
        return {'validation':results,'failures':failures,'selection_performed':False}
    eligible=[r for r in results if r['scheme'] in ('F1','F2')]
    if not eligible:raise ValueError('F1/F2 没有成功训练模型')
    best=sorted(eligible,key=lambda r:(-r['macro_f1'],r['false_positive_rate'],r['model_id']))[0]
    model,manifest=ModelRegistry(out/'models').load(best['model_id'])
    holdout_path=ROOT/'outputs/m2b/week2_audit_final/manifest.json'
    holdout=read_json(holdout_path) if holdout_path.exists() else {'sealed':False,'blocking_reasons':['audit absent']}
    frozen={'model_id':best['model_id'],'model_sha256':manifest['sha256'],'scheme':best['scheme'],
            'threshold':0.5,'feature_contract':manifest['contract'],'selection_rule':plan['primary_selection'],
            'created_at_utc':datetime.now(timezone.utc).isoformat(),'plan_sha256':PLAN_SHA,
            'prediction_status':'RESEARCH_ONLY' if holdout['sealed'] else 'DEV_ONLY',
            'holdout_manifest_sha256':sha(holdout_path) if holdout_path.exists() else None,
            'evaluator_sha256':sha(Path(__file__).with_name('evaluate_ids.py')),
            'code_sha256':{p.name:sha(p) for p in Path(__file__).parent.glob('*.py')},
            'test_selection_or_refit_allowed':False}
    write_json(out/'frozen_model.json',frozen)
    _inference_store(out,data,best['scheme'])
    if evaluate_final:
        # 冻结完成后才打开内部 Test 的 X/y。持久化 claim 独立于输出目录。
        verified(Path(__file__).with_name('evaluate_ids.py'),frozen['evaluator_sha256'])
        tx,ty,_=data.load(best['scheme'],'test',frozen_test=True)
        report=evaluate_model(model,tx,ty,role='week1_internal_test',test_authorization={
            'root':ROOT/'artifacts/m2b/test_access','data_sha':data.protocol['assignment_files']['test']['sha256'],
            'model_sha':manifest['sha256'],'sealed':True,'freeze_path':out/'frozen_model.json'})
        write_json(out/'week1_internal_test.json',report);print(json.dumps(report),flush=True)
        if holdout['sealed']:
            from .holdout_audit import load_sealed_week2
            hx,hy=load_sealed_week2(holdout_path,best['scheme'],frozen['holdout_manifest_sha256'])
            report=evaluate_model(model,hx,hy,role='week2',test_authorization={
                'root':ROOT/'artifacts/m2b/test_access','data_sha':holdout['week2']['sha256'],
                'model_sha':manifest['sha256'],'sealed':True,'freeze_path':out/'frozen_model.json',
                'holdout_manifest_path':holdout_path})
            report['test_type']='same_environment_cross_week_holdout'
            write_json(out/'week2_test.json',report);print(json.dumps(report),flush=True)
        else:print('Week 2 formal evaluation BLOCKED: '+str(holdout['blocking_reasons']),flush=True)
    print('FROZEN '+json.dumps(frozen,ensure_ascii=False),flush=True)
    return frozen


def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path)
    parser.add_argument('--evaluate-final',action='store_true')
    parser.add_argument('--candidates-only',action='store_true')
    parser.add_argument('--worker',nargs=3,metavar=('RUN','SCHEME','KIND'))
    args=parser.parse_args()
    if args.worker:_worker(Path(args.worker[0]),args.worker[1],args.worker[2])
    elif args.out:train_baselines(args.out,evaluate_final=args.evaluate_final,candidates_only=args.candidates_only)
    else:parser.error('需要 --out；历史输出目录不可覆盖')


if __name__=='__main__':main()
