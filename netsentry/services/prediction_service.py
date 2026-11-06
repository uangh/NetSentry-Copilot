"""仅装载批准运行包：真实预测器、无标签特征库、显式模型白名单。"""
from pathlib import Path
from threading import RLock
from uuid import uuid4

from netsentry.ids_data import read_json, verified
from netsentry.predict_ids import IDSPredictor

ASSETS={'models/F2_logistic.json','models/F2_logistic.joblib','models/F2_rf100.json','models/F2_rf100.joblib',
        'inference.sqlite','inference_store.json','events.sqlite','development_ids.json'}


def verify_runtime(runtime: Path) -> dict:
    manifest=read_json(runtime/'runtime_manifest.json')
    if manifest['version']!='netsentry.api.runtime.v1' or set(manifest['assets'])!=ASSETS:
        raise ValueError('不是批准的无标签运行包')
    if manifest['record_scope']!='Week1 B Train+Validation only' or manifest['default_model']!='F2_logistic':
        raise ValueError('运行数据/模型范围不符')
    for name,digest in manifest['assets'].items():verified(runtime/name,digest)
    return manifest


class PredictionService:
    def __init__(self, runtime: Path) -> None:
        self.runtime=Path(runtime);self.manifest=verify_runtime(self.runtime)
        self.predictors={};self.lock=RLock()
        for model_id in ('F2_logistic','F2_rf100'):
            predictor=IDSPredictor(self.runtime,model_id=model_id)
            if predictor.scheme!='F2' or predictor.status!='DEV_ONLY':raise ValueError('禁止升级模型或变更特征契约')
            # 两个模型共用同一批准的 F2 数据库，避免RF另建/误读离线数据。
            predictor._feature_path=verified(self.runtime/'inference.sqlite',self.manifest['assets']['inference.sqlite'])
            self.predictors[model_id]=predictor

    def models(self) -> list[dict]:
        return [{'model_id':key,'model_version':p.manifest['model_version'],
            'feature_contract_version':p.manifest['contract']['version'],'model_status':'DEV_ONLY','threshold':0.5,
            'is_default':key=='F2_logistic','score_is_calibrated_probability':False} for key,p in self.predictors.items()]

    def predict(self, *, features: dict | None=None, record_id: str | None=None,
                model_id: str='F2_logistic') -> dict:
        if model_id not in self.predictors:raise ValueError('未知模型')
        if (features is None)==(record_id is None):raise ValueError('特征与ID输入必须二选一')
        with self.lock:
            predictor=self.predictors[model_id]
            result=predictor.predict_for_record(record_id) if record_id else predictor.predict_one(features)
        return {'prediction_id':uuid4().hex,'record_id':record_id,**result}
