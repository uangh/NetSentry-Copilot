"""M2A：确定性候选划分；任何严格条件失败均不回退到随机行。"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import hashlib
from .leakage_checks import inspect_split, ACTIVE_SETS

SPLIT_VERSION = 'netsentry.split.v1'
STRATEGIES = ('A_random','B_feature','C_time','D_activity','E_components','C_purged')
DEFAULT_CUTS = ('2017-03-20T00:00:00','2017-03-21T00:00:00')


def stable_key(value: str, seed: int) -> str:
    return hashlib.sha256(f'{seed}\0{value}'.encode()).hexdigest()


def _group_ids(rows: list[dict], strategy: str) -> dict[str,list[str]]:
    parent = {r['record_id']:r['record_id'] for r in rows}
    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value
    keys = ['feature_key'] if strategy=='B_feature' else ['attack_group','normal_group']
    if strategy=='E_components':
        keys = ['feature_key','attack_group','normal_group']
    seen = {}
    for row in sorted(rows,key=lambda r:r['record_id']):
        for key in keys:
            value = row.get(key)
            if value is None:
                continue
            pair = (key,value)
            if pair in seen:
                left,right = find(row['record_id']),find(seen[pair])
                parent[max(left,right)] = min(left,right)
            else:
                seen[pair] = row['record_id']
    groups:dict[str,list] = defaultdict(list)
    for row in rows:
        groups[find(row['record_id'])].append(row['record_id'])
    return dict(groups)


def _allocate(groups: dict[str,list[str]], by_id: dict, seed: int) -> dict[str,list[str]]:
    """按组从大到小贪心接近60/20/20；不切组，不保证比例或覆盖。"""
    ratios = dict(zip(ACTIVE_SETS,(0.6,0.2,0.2)))
    totals = Counter(row['y'] for row in by_id.values())
    assigned = {name:Counter() for name in ACTIVE_SETS}
    result = {name:[] for name in ACTIVE_SETS}
    ordered = sorted(groups,key=lambda g:(-len(groups[g]),stable_key(g,seed)))
    for group in ordered:
        counts = Counter(by_id[i]['y'] for i in groups[group])
        # 比较加入该组前后的归一化平方误差，不依赖任何模型分数。
        def cost(split: str) -> tuple:
            delta = sum(((assigned[split][label]+n-totals[label]*ratios[split])**2
                         -(assigned[split][label]-totals[label]*ratios[split])**2)/max(1,totals[label])
                        for label,n in counts.items())
            return delta,ACTIVE_SETS.index(split)
        chosen = min(ACTIVE_SETS,key=cost)
        result[chosen].extend(groups[group]);assigned[chosen].update(counts)
    return result


def _time_assign(rows: list[dict], cuts: tuple[str,str]) -> dict[str,list[str]]:
    first,second = (datetime.fromisoformat(c) for c in cuts)
    if first.tzinfo is not None or second.tzinfo is not None or first>=second:
        raise ValueError('需要递增且无时区的源内本地时间切点')
    result = {name:[] for name in (*ACTIVE_SETS,'quarantine')}
    for row in rows:
        try:
            stamp = datetime.fromisoformat(row['timestamp'])
            if stamp.tzinfo is not None:
                raise ValueError('时区未核验')
        except (ValueError,TypeError):
            result['quarantine'].append(row['record_id']);continue
        split = 'train' if stamp<first else 'validation' if stamp<second else 'test'
        result[split].append(row['record_id'])
    return result


def _purge(rows: list[dict], assignments: dict, cuts: tuple[str,str], embargo_seconds: int) -> dict[str,list[str]]:
    owner = {i:s for s in ACTIVE_SETS for i in assignments[s]}
    group_sets:dict[tuple,set] = defaultdict(set)
    for row in rows:
        if row['record_id'] not in owner:
            continue
        for key in ['feature_key','attack_group','normal_group']:
            if row.get(key) is not None:
                group_sets[(key,row[key])].add(owner[row['record_id']])
    crossing = {key for key,parts in group_sets.items() if len(parts)>1}
    excluded:dict[str,list[str]] = {}
    cut_times = [datetime.fromisoformat(c) for c in cuts]
    for row in rows:
        if row['record_id'] not in owner:
            continue
        reasons = [key+'_crosses_time' for key in ['feature_key','attack_group','normal_group']
                   if (key,row.get(key)) in crossing]
        stamp = datetime.fromisoformat(row['timestamp'])
        end = stamp+timedelta(seconds=row['duration'])
        if any(stamp<c+timedelta(seconds=embargo_seconds) and end>=c-timedelta(seconds=embargo_seconds) for c in cut_times):
            reasons.append('boundary_embargo_or_flow_overlap')
        if reasons:
            excluded[row['record_id']] = reasons
    for split in ACTIVE_SETS:
        assignments[split] = [i for i in assignments[split] if i not in excluded]
    assignments['quarantine'].extend(excluded)
    return excluded


def make_split(rows: list[dict], strategy: str, *, seed: int = 42, min_per_class: int = 20,
               cuts: tuple[str,str] = DEFAULT_CUTS, embargo_seconds: int = 60,
               required_classes: list[str] | None = None) -> dict:
    if strategy not in STRATEGIES or type(seed) is not int or not 0<=seed<2**32:
        raise ValueError('非法策略或种子')
    if type(embargo_seconds) is not int or not 0<=embargo_seconds<=86400 or len(cuts)!=2:
        raise ValueError('非法时间设置')
    by_id = {r['record_id']:r for r in rows}
    if len(by_id)!=len(rows) or not rows:
        raise ValueError('输入为空或record_id重复')
    purge_reasons = {};groups = {}
    if strategy=='A_random':
        assignments = {name:[] for name in ACTIVE_SETS}
        for label in sorted({r['y'] for r in rows}):
            ids = sorted((r['record_id'] for r in rows if r['y']==label),key=lambda i:stable_key(i,seed))
            n_train,n_val = int(len(ids)*0.6),int(len(ids)*0.2)
            for name,part in zip(ACTIVE_SETS,(ids[:n_train],ids[n_train:n_train+n_val],ids[n_train+n_val:])):
                assignments[name].extend(part)
    elif strategy in ('C_time','C_purged'):
        assignments = _time_assign(rows,cuts)
        if strategy=='C_purged':
            purge_reasons = _purge(rows,assignments,cuts,embargo_seconds)
    else:
        groups = _group_ids(rows,strategy)
        assignments = _allocate(groups,by_id,seed)
    assignments.setdefault('quarantine',[])
    assignments = {name:sorted(ids) for name,ids in assignments.items()}
    checks = inspect_split(rows,assignments,min_per_class=min_per_class,required_classes=required_classes)
    constraints = []
    if strategy in ('B_feature','E_components','C_purged'):
        constraints.append('feature_cross_groups')
    if strategy in ('D_activity','E_components','C_purged'):
        constraints.extend(['attack_cross_groups','normal_block_cross_groups'])
    satisfied = checks['record_ids_disjoint'] and checks['all_records_accounted'] and checks['class_coverage_ok'] and all(checks[k]==0 for k in constraints)
    return {'version':SPLIT_VERSION,'strategy':strategy,'seed':seed,'status':'feasible' if satisfied else 'infeasible',
            'fallback_used':False,'assignments':assignments,'checks':checks,'enforced_constraints':constraints,
            'ratios_requested':[0.6,0.2,0.2] if strategy not in ('C_time','C_purged') else None,
            'time_cuts':list(cuts) if strategy in ('C_time','C_purged') else None,'embargo_seconds':embargo_seconds if strategy=='C_purged' else None,
            'group_count':len(groups),'largest_group':max(map(len,groups.values()),default=0),
            'purge_reasons':dict(sorted(purge_reasons.items())),
            'set_sizes':{name:len(ids) for name,ids in assignments.items()},
            'quarantine_classes':dict(sorted(Counter(by_id[i]['y'] for i in assignments['quarantine']).items())),
            'test_role':'internal_comparison_holdout_NOT_final_independent_test',
            'independence_claim':'only checked constraints; no guarantee for near-duplicates, host/environment or unseen sites'}
