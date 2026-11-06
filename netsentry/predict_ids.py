"""可直接调用的无标签推理入口；只读取登记模型和无标签特征库。"""
from __future__ import annotations
import argparse
from contextlib import closing
import json
from pathlib import Path
import re
import sqlite3

from .ids_data import ROOT, matrix, read_json, verified
from .model_registry import ModelRegistry
from .evaluate_ids import attack_scores


class IDSPredictor:
    def __init__(self, run: Path, *, model_id: str | None=None) -> None:
        self.run=Path(run); self.status='DEV_ONLY'
        expected=None
        if model_id is None:
            frozen=read_json(self.run/'frozen_model.json')
            model_id=frozen['model_id']; expected=frozen['model_sha256']
            self.status=frozen['prediction_status']
            # 只允许审计发现的问题降低状态，绝不借此升级历史模型。
            status_path=self.run/'operational_status.json'
            if status_path.exists():
                status=read_json(status_path)
                if status['model_sha256']!=expected:raise ValueError('状态声明模型哈希不符')
                if status['prediction_status']=='DEV_ONLY':self.status='DEV_ONLY'
        self.model,self.manifest=ModelRegistry(self.run/'models').load(model_id,expected)
        self.scheme=self.manifest['scheme']
        self._feature_path=None

    def predict_one(self, features: dict) -> dict:
        score=float(attack_scores(self.model,matrix([features],self.scheme))[0])
        return {'prediction':'attack-related' if score>=0.5 else 'normal',
                'attack_related_score':score,'threshold':0.5,'model_id':self.manifest['model_id'],
                'model_version':self.manifest['model_version'],
                'feature_contract_version':self.manifest['contract']['version'],
                'prediction_status':self.status,'score_is_calibrated_probability':False}

    def predict_for_record(self, record_id: str) -> dict:
        if not isinstance(record_id,str) or not re.fullmatch('[0-9a-f]{64}',record_id):
            raise ValueError('非法 record_id')
        if self._feature_path is None:
            manifest=read_json(self.run/'inference_store.json')
            if manifest['scheme']!=self.scheme:raise ValueError('推理特征库方案不符')
            self._feature_path=verified(self.run/'inference.sqlite',manifest['sha256'])
        uri=self._feature_path.resolve().as_uri()+'?mode=ro&immutable=1'
        with closing(sqlite3.connect(uri,uri=True)) as connection:
            item=connection.execute('SELECT x FROM features WHERE record_id=?',(record_id,)).fetchone()
        if item is None:raise KeyError('没有此记录的无标签特征')
        return {'record_id':record_id,**self.predict_one(json.loads(item[0]))}


def predict_one(features: dict, *, run: Path=ROOT/'outputs/m2b/release') -> dict:
    return IDSPredictor(run).predict_one(features)


def predict_for_record(record_id: str, *, run: Path=ROOT/'outputs/m2b/release') -> dict:
    return IDSPredictor(run).predict_for_record(record_id)


def main() -> None:
    parser=argparse.ArgumentParser(); parser.add_argument('--run',type=Path,default=ROOT/'outputs/m2b/release')
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--record-id'); group.add_argument('--features-json',type=Path)
    args=parser.parse_args(); predictor=IDSPredictor(args.run)
    result=predictor.predict_for_record(args.record_id) if args.record_id else predictor.predict_one(read_json(args.features_json))
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
