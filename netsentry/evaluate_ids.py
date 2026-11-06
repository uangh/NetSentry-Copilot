"""离线评测：一次性测试访问登记与固定 0.5 阈值。"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import re
import time

import numpy as np
from sklearn import metrics as skm

from .ids_data import read_json, sha, verified, write_json


def attack_scores(model: object, x: np.ndarray) -> np.ndarray:
    classes=list(model.classes_)
    if 1 not in classes:return np.zeros(len(x))
    return model.predict_proba(x)[:,classes.index(1)]


def metrics(y: np.ndarray, scores: np.ndarray, threshold: float=0.5) -> dict:
    y=np.asarray(y); scores=np.asarray(scores)
    if y.ndim!=1 or not len(y) or scores.shape!=y.shape or not set(np.unique(y))<={0,1}:
        raise ValueError('非法评测数组')
    if not np.isfinite(scores).all() or np.any((scores<0)|(scores>1)) or threshold!=0.5:
        raise ValueError('分数无效或阈值偏离冻结方案')
    prediction=(scores>=threshold).astype(int)
    tn,fp,fn,tp=skm.confusion_matrix(y,prediction,labels=[0,1]).ravel()
    both=len(np.unique(y))==2
    return {'rows':len(y),'attack_related':int(y.sum()),'threshold':threshold,
            'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]],
            'accuracy':float(skm.accuracy_score(y,prediction)),
            'precision':float(skm.precision_score(y,prediction,zero_division=0)),
            'recall':float(skm.recall_score(y,prediction,zero_division=0)),
            'f1':float(skm.f1_score(y,prediction,zero_division=0)),
            'macro_f1':float(skm.f1_score(y,prediction,labels=[0,1],average='macro',zero_division=0)),
            'balanced_accuracy':float(((tp/(tp+fn))+(tn/(tn+fp)))/2) if both else None,
            'false_positive_rate':float(fp/(fp+tn)) if fp+tn else None,
            'pr_auc_average_precision':float(skm.average_precision_score(y,scores)) if y.sum() else None,
            'roc_auc':float(skm.roc_auc_score(y,scores)) if both else None}


def claim_test(root: Path, role: str, data_sha: str, model_sha: str, sealed: bool) -> Path:
    if role not in ('week1_internal_test','week2'):raise ValueError('未知正式测试角色')
    if not sealed:raise ValueError('测试集/模型未通过封存，禁止评测')
    if not all(re.fullmatch('[0-9a-f]{64}',v) for v in (data_sha,model_sha)):raise ValueError('非法哈希')
    path=Path(root)/(role+'-'+data_sha+'.json')
    write_json(path,{'role':role,'data_sha256':data_sha,'model_sha256':model_sha,
                     'started_at_utc':datetime.now(timezone.utc).isoformat(),
                     'policy':'one attempt; failure does not release claim'})
    return path


def evaluate_model(model: object, x: np.ndarray, y: np.ndarray, *, role: str='validation',
                   test_authorization: dict | None=None) -> dict:
    if role!='validation':
        if not test_authorization:raise ValueError('测试评估需要冻结授权')
        auth=dict(test_authorization)
        freeze_path=auth.pop('freeze_path',None)
        if freeze_path is None:raise ValueError('缺少冻结模型文件')
        frozen=read_json(Path(freeze_path))
        if frozen['model_sha256']!=auth['model_sha'] or frozen['threshold']!=0.5:
            raise ValueError('测试模型不符合冻结声明')
        verified(Path(__file__),frozen['evaluator_sha256'])
        manifest_path=auth.pop('holdout_manifest_path',None)
        if role=='week2':
            if manifest_path is None:raise ValueError('缺少 Week 2 封存 Manifest')
            manifest=read_json(verified(Path(manifest_path),frozen['holdout_manifest_sha256']))
            if not manifest['sealed'] or manifest['week2']['sha256']!=auth['data_sha']:
                raise ValueError('Week 2 来源或封存状态不符')
            verified(Path(__file__),manifest['evaluator_sha256'])
        claim_test(role=role,**auth)
    started=time.perf_counter(); scores=attack_scores(model,x)
    seconds=time.perf_counter()-started
    result=metrics(y,scores); result.update(role=role,prediction_seconds=seconds)
    return result
