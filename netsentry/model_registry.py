"""只加载本地可信训练目录登记且哈希一致的模型；哈希不是来源签名。"""
from __future__ import annotations
import platform
from pathlib import Path
import re

import joblib
import sklearn

from .feature_contract import feature_contract
from .ids_data import read_json, sha, verified, write_json


class ModelRegistry:
    def __init__(self, root: Path) -> None:
        self.root=Path(root)

    @staticmethod
    def _name(model_id: str) -> None:
        if not isinstance(model_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',model_id):
            raise ValueError('非法模型标识；不接受权重文件路径')

    def save(self, model_id: str, model: object, scheme: str, summary: dict) -> dict:
        self._name(model_id); self.root.mkdir(parents=True,exist_ok=True)
        target=self.root/(model_id+'.joblib')
        # xb 避免覆盖历史权重。只能由本项目训练入口登记。
        with target.open('xb') as stream:joblib.dump(model,stream,compress=3)
        contract=feature_contract(scheme)
        manifest={'origin':'netsentry_internal_training','model_id':model_id,'model_version':'m2b.v1',
                  'scheme':scheme,'sha256':sha(target),'python':platform.python_version(),
                  'sklearn':sklearn.__version__,'contract':contract,
                  'feature_order':[f['name'] for f in contract['fields']], 'summary':summary,
                  'estimator_params':model.named_steps['classifier'].get_params()}
        write_json(self.root/(model_id+'.json'),manifest)
        return manifest

    def load(self, model_id: str, expected_sha: str | None=None) -> tuple[object,dict]:
        self._name(model_id)
        manifest_path=self.root/(model_id+'.json')
        if not manifest_path.is_file():raise ValueError('模型未在本地可信目录登记')
        manifest=read_json(manifest_path)
        if manifest['origin']!='netsentry_internal_training' or manifest['model_id']!=model_id:
            raise ValueError('来源登记不符')
        if manifest['sklearn']!=sklearn.__version__ or manifest['python']!=platform.python_version():
            raise ValueError('运行版本与训练版本不符，请使用锁定环境')
        contract=feature_contract(manifest['scheme'])
        if manifest['contract']!=contract or manifest['feature_order']!=[f['name'] for f in contract['fields']]:
            raise ValueError('模型特征契约发生改变')
        if expected_sha is not None and expected_sha!=manifest['sha256']:raise ValueError('最终模型冻结哈希不符')
        path=verified(self.root/(model_id+'.joblib'),manifest['sha256'])
        return joblib.load(path),manifest
