"""M2A：划分核验与Agent允许字段检查；不拟合任何模型。"""
from __future__ import annotations
from collections import Counter, defaultdict

EVENT_FIELDS = {'record_id','dataset_id','source_ip','destination_ip','source_port','destination_port',
                'protocol','timestamp','flow_duration','flow_duration_unit','source_sha256','time_basis','provenance_kind'}
ACTIVE_SETS = ('train','validation','test')


def validate_event(event: dict) -> None:
    """持续时间是M1.7已允许的事件属性，禁止完整X及新增模型统计。"""
    if not isinstance(event,dict) or set(event)-EVENT_FIELDS:
        raise ValueError('事件视图包含未批准字段/标签/模型X')
    if any(isinstance(v,(dict,list)) for v in event.values()):
        raise ValueError('事件字段不允许嵌套答案对象')


def inspect_split(rows: list[dict], assignments: dict[str,list[str]], *, min_per_class: int = 20,
                  required_classes: list[str] | None = None) -> dict:
    if type(min_per_class) is not int or min_per_class < 1:
        raise ValueError('每类最低数量必须为正整数')
    by_id = {r['record_id']:r for r in rows}
    if len(by_id) != len(rows):
        raise ValueError('输入record_id重复')
    if set(assignments)-set((*ACTIVE_SETS,'quarantine')):
        raise ValueError('未知集合名称')
    seen:dict[str,set] = defaultdict(set)
    repeated = 0
    for split,ids in assignments.items():
        repeated += len(ids)-len(set(ids))
        for record_id in ids:
            if record_id not in by_id:
                raise ValueError('划分含未知record_id')
            seen[record_id].add(split)
    cross = sum(len(v)>1 for v in seen.values())
    groups = {key:defaultdict(set) for key in ['feature_key','attack_group','normal_group']}
    counts = {}
    required = sorted(required_classes if required_classes is not None else {r['y'] for r in rows})
    missing = {}
    for split in ACTIVE_SETS:
        ids = assignments.get(split,[])
        counts[split] = dict(sorted(Counter(by_id[i]['y'] for i in ids).items()))
        missing[split] = {label:counts[split].get(label,0) for label in required if counts[split].get(label,0)<min_per_class}
        for i in ids:
            for key,index in groups.items():
                group = by_id[i].get(key)
                if group is not None:
                    index[group].add(split)
    crossings = {key:sorted(k for k,v in index.items() if len(v)>1) for key,index in groups.items()}
    return {'record_ids_disjoint':not cross and not repeated,'overlapping_record_ids':cross,
            'within_set_duplicate_ids':repeated,'all_records_accounted':set(seen)==set(by_id),
            'feature_cross_groups':len(crossings['feature_key']),
            'attack_cross_groups':len(crossings['attack_group']),
            'normal_block_cross_groups':len(crossings['normal_group']),
            'cross_group_examples':{k:v[:10] for k,v in crossings.items()},
            'class_counts':counts,'required_classes':required,'min_per_class':min_per_class,
            'class_coverage_ok':not any(missing.values()),'insufficient_classes':missing,
            'near_duplicate_independence':'not_verified','external_test_independence':'not_verified'}
