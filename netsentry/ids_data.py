"""M2B 数据边界：固定记录清单，训练数据与推理输入分别读取。"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
import math
from pathlib import Path

import numpy as np

from .feature_contract import feature_contract

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'artifacts/m2a/release'
SPLIT = ROOT / 'artifacts/m2a_1/release'
SPLIT_SHA = '6de1f86599a2a469e0603e67bc3e8c357a1e29da2fb5c64b9962f4865bf52bd5'


def sha(path: Path) -> str:
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path: Path) -> dict | list:
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)


def verified(path: Path, expected: str) -> Path:
    if sha(path) != expected:
        raise ValueError(f'SHA256 不一致: {path}')
    return path


def binary_label(label: str) -> int:
    if label not in ('normal', 'attacker', 'victim'):
        raise ValueError('未知真实标签，禁止自动归入正常类')
    return int(label != 'normal')


def require_training_role(role: str) -> None:
    if role != 'train':
        raise ValueError('只有固定 Week 1 Train 可以 fit；禁止测试集参与训练')


def matrix(records: list[dict], scheme: str) -> np.ndarray:
    fields = feature_contract(scheme)['fields']
    names = [f['name'] for f in fields]
    rows = []
    for record in records:
        if type(record) is not dict or set(record) != set(names):
            raise ValueError('模型输入缺少字段或包含白名单外字段')
        values = []
        for field in fields:
            name = field['name']; value = record[name]
            nullable = name in ('mean_bytes_per_packet', 'source_port', 'destination_port')
            if value is None and nullable:
                values.append(np.nan); continue
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError(f'非法数值: {name}')
            if field['dtype'] == 'binary' and value not in (0, 1):
                raise ValueError(f'非二进制标志: {name}')
            if name == 'packets' and not float(value).is_integer():
                raise ValueError('packets 必须为整数')
            if field['dtype'] == 'categorical_integer' and (not float(value).is_integer() or value > 65535):
                raise ValueError('端口超出范围')
            values.append(value)
        # 不允许派生字段与基础统计矛盾。
        if scheme != 'F1':
            p = record['packets']; mean = record['mean_bytes_per_packet']
            if record['duration_zero'] != int(record['flow_duration'] == 0) or record['mean_bytes_per_packet_missing'] != int(p == 0):
                raise ValueError('派生指示字段不一致')
            if (p == 0 and mean is not None) or (p > 0 and (mean is None or not math.isclose(mean,record['bytes']/p))):
                raise ValueError('平均包字节数不一致')
        if scheme == 'F3':
            if sum(record['protocol_'+p] for p in ('tcp','udp','icmp','igmp','other')) != 1:
                raise ValueError('协议 one-hot 不一致')
            applicable = bool(record['protocol_tcp'] or record['protocol_udp'])
            for side in ('source','destination'):
                if record[side+'_port_not_applicable'] != int(not applicable):
                    raise ValueError('端口适用性不一致')
                if record[side+'_port_missing'] != int(applicable and record[side+'_port'] is None):
                    raise ValueError('端口缺失标志不一致')
                if not applicable and record[side+'_port'] is not None:
                    raise ValueError('非传输协议不得填造端口')
        rows.append(values)
    return np.asarray(rows, dtype=np.float64).reshape((-1,len(fields)))


class FrozenWeek1:
    """只使用已封存的 B 协议；默认仅导出训练/验证，不重划分。"""
    def __init__(self) -> None:
        self.split = read_json(verified(SPLIT/'manifest.json',SPLIT_SHA))
        self.base = read_json(verified(BASE/'manifest.json',self.split['baseline_manifest_sha256']))
        self.protocol = self.split['protocols']['B_time_activity']
        self.ids = {}
        for role, info in self.protocol['assignment_files'].items():
            ids = read_json(verified(SPLIT/info['path'],info['sha256']))
            if len(ids) != info['rows'] or len(set(ids)) != len(ids):
                raise ValueError('记录清单数量/唯一性不符')
            self.ids[role] = ids
        all_ids = [rid for ids in self.ids.values() for rid in ids]
        if len(set(all_ids)) != len(all_ids):
            raise ValueError('Train/Validation/Test/Quarantine 记录相交')
        # 源 CSV 和两个历史数据库保持逐字节可追溯。
        paths={'csv':ROOT/'data/raw/cidds001_week1_subset/CIDDS-001-internal-week1.every100.csv',
               'offline':ROOT/'artifacts/m1_7/cidds001_release/offline.sqlite',
               'events':ROOT/'artifacts/m1_7/cidds001_release/events.sqlite'}
        for role, expected in self.split['source_hashes_before'].items():
            verified(paths[role],expected)
        self._check_groups()

    def artifact(self, name: str) -> Path:
        return verified(BASE/name,self.base['artifacts'][name]['sha256'])

    def _check_groups(self) -> None:
        membership={rid:role for role,ids in self.ids.items() if role!='quarantine' for rid in ids}
        groups: dict[tuple,str] = {}; ranges: dict[str,list] = {}
        for line in self.artifact('offline_metadata.jsonl').open(encoding='utf-8'):
            item=json.loads(line); role=membership.get(item['record_id'])
            if role is None: continue
            for key in ('attack_group','normal_group'):
                value=item[key]
                if value is not None:
                    if (key,value) in groups and groups[key,value]!=role:
                        raise ValueError('活动或普通流量时间块跨集合')
                    groups[key,value]=role
            timestamp=datetime.fromisoformat(item['timestamp'])
            bounds=ranges.setdefault(role,[timestamp,timestamp])
            bounds[0]=min(bounds[0],timestamp); bounds[1]=max(bounds[1],timestamp)
        for a,b in [('train','validation'),('validation','test')]:
            if ranges[a][1]>=ranges[b][0]:raise ValueError('时间边界交叉')
        if not all(x['chronologically_separated'] for x in self.protocol['time_audit']['ordered_pairs']):
            raise ValueError('历史持续时间 embargo 未通过')

    def load(self, scheme: str, role: str, *, frozen_test: bool=False) -> tuple[np.ndarray,np.ndarray,list[str]]:
        if role not in ('train','validation','test') or (role=='test' and not frozen_test):
            raise ValueError('未授权的数据角色；内部 Test 需冻结后访问')
        if self.base['analysis']['features'][scheme]['contract'] != feature_contract(scheme):
            raise ValueError('特征映射与历史 Manifest 不一致')
        ids=self.ids[role]; wanted=set(ids); xs={}; ys={}
        with self.artifact(scheme+'_X.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                item=json.loads(line); rid=item['record_id']
                if rid in wanted:
                    if rid in xs:raise ValueError('特征记录重复')
                    xs[rid]=item['X']
        with self.artifact('targets.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                item=json.loads(line); rid=item['record_id']
                if rid in wanted:
                    if rid in ys:raise ValueError('目标记录重复')
                    ys[rid]=binary_label(item['original_class'])
                    if item['targets']['B'] != ('attack-related' if ys[rid] else 'normal'):
                        raise ValueError('标签映射与已封存 B 目标不符')
        if set(xs)!=wanted or set(ys)!=wanted:raise ValueError('特征或标签缺失')
        y=np.asarray([ys[rid] for rid in ids], dtype=np.int8)
        expected=self.protocol['checks']['class_counts'][role]
        if int(y.sum())!=expected['attack-related'] or len(y)-int(y.sum())!=expected['normal']:
            raise ValueError('类别计数不符')
        return matrix([xs[rid] for rid in ids],scheme),y,ids
