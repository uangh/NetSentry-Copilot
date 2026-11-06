"""M2A.1：可加总损失归因、等值组与连通组审计；不修改源记录。"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from itertools import combinations
from .data_split import DEFAULT_CUTS, _time_assign, _group_ids

RULE_ORDER = ['invalid_time','attack_group_crosses_time','normal_group_crosses_time',
              'feature_key_crosses_time','boundary_embargo_or_flow_overlap']


def counts(rows: list[dict]) -> dict:
    labels = Counter(r['y'] if r['y'] is not None else 'invalid_target' for r in rows)
    return {'rows':len(rows),'classes':dict(sorted(labels.items()))}


def attribute_losses(rows: list[dict], reasons: dict[str,list[str]], order: list[str]) -> dict:
    """独立影响、互斥原因组合、顺序增量分别报告，避免多原因重复相加。"""
    by_id = {r['record_id']:r for r in rows}
    if len(by_id)!=len(rows) or set(reasons)-set(by_id) or len(set(order))!=len(order) or len(order)>8:
        raise ValueError('重复ID、未知原因ID或非法规则表')
    normalized = {i:set(reasons.get(i,[])) for i in by_id}
    if any(v-set(order) for v in normalized.values()):
        raise ValueError('未知排除规则')
    affected = {rule:{i for i,v in normalized.items() if rule in v} for rule in order}
    def measure(ids: set) -> dict:
        return counts([by_id[i] for i in sorted(ids)])
    removed:set[str] = set();stages=[]
    for rule in order:
        new = affected[rule]-removed
        removed |= affected[rule]
        stages.append({'rule':rule,'newly_removed':measure(new),'remaining':measure(set(by_id)-removed)})
    masks:dict[tuple,set] = defaultdict(set)
    for i,v in normalized.items():masks[tuple(rule for rule in order if rule in v)].add(i)
    subsets = []
    for length in range(1,len(order)+1):
        for combo in combinations(order,length):
            union = set().union(*(affected[r] for r in combo))
            subsets.append({'rules':list(combo),'union_loss':measure(union)})
    return {'input':counts(rows),'order':order,'standalone':{r:measure(ids) for r,ids in affected.items()},
            'exclusive':{r:measure({i for i,v in normalized.items() if v=={r}}) for r in order},
            'exact_reason_combinations':[{'reasons':list(k),**measure(v)} for k,v in sorted(masks.items())],
            'all_rule_subsets':subsets,'stages':stages,'union_loss':measure(removed),
            'order_note':'stages are attribution order, not causal order; masks use original candidate groups',
            'cleaned_deleted_rows':0}


def temporal_reasons(rows: list[dict], *, cuts: tuple[str,str] = DEFAULT_CUTS, embargo: int = 60) -> dict:
    if type(embargo) is not int or not 0<=embargo<=86400:
        raise ValueError('边界隔离秒数非法')
    assigned = _time_assign(rows,cuts)
    owner = {i:s for s,ids in assigned.items() for i in ids}
    if len(owner)!=len(rows):raise ValueError('重复记录ID')
    groups:dict[tuple,set] = defaultdict(set)
    for row in rows:
        split = owner[row['record_id']]
        if split=='quarantine':continue
        for key in ['feature_key','attack_group','normal_group']:
            if row.get(key) is not None:groups[key,row[key]].add(split)
    crossing = {key for key,sets in groups.items() if len(sets)>1}
    boundaries = [datetime.fromisoformat(c) for c in cuts]
    reasons = {}
    for row in rows:
        rid = row['record_id']
        if owner[rid]=='quarantine':
            reasons[rid]=['invalid_time'];continue
        why = [key+'_crosses_time' for key in ['attack_group','normal_group','feature_key'] if (key,row.get(key)) in crossing]
        stamp = datetime.fromisoformat(row['timestamp'])
        end = stamp+timedelta(seconds=row['duration'])
        if any(stamp<c+timedelta(seconds=embargo) and end>=c-timedelta(seconds=embargo) for c in boundaries):
            why.append('boundary_embargo_or_flow_overlap')
        reasons[rid]=why
    return {'assignments':assigned,'reasons':reasons,'cross_groups':{key:sum(k[0]==key for k in crossing) for key in ['feature_key','attack_group','normal_group']}}


def overlap_report(rows: list[dict], assignments: dict, key: str) -> dict:
    owner = {i:s for s,ids in assignments.items() if s!='quarantine' for i in ids}
    groups:dict[str,list] = defaultdict(list)
    for row in rows:
        if row['record_id'] in owner and row.get(key) is not None:groups[row[key]].append(row)
    crossed = {k:v for k,v in groups.items() if len({owner[r['record_id']] for r in v})>1}
    return {'groups':len(crossed),'affected':counts([r for g in crossed.values() for r in g]),
            'examples':sorted(crossed)[:10]}


def group_report(rows: list[dict], scheme: str) -> dict:
    projected = [{**r,'feature_key':r['feature_keys'][scheme]} for r in rows]
    assigned = _time_assign(projected,DEFAULT_CUTS)
    owner = {i:s for s,ids in assigned.items() for i in ids}
    groups:dict[str,list] = defaultdict(list)
    for row in projected:groups[row['feature_key']].append(row)
    def describe(key: str) -> dict:
        group=groups[key]
        return {'key':key,**counts(group),'original_classes':dict(sorted(Counter(r.get('original_class',r['y']) for r in group).items())),
                'attack_activities':len({r['attack_group'] for r in group if r['attack_group']}),
                'candidate_sets':sorted({owner[r['record_id']] for r in group}),
                'example_record_ids':sorted(r['record_id'] for r in group)[:3]}
    ordered=sorted(groups,key=lambda k:(-len(groups[k]),k))
    conflicts=[k for k in ordered if len({r['y'] for r in groups[k]})>1]
    cross=overlap_report(projected,assigned,'feature_key')
    return {'unique_groups':len(groups),'duplicate_excess':len(rows)-len(groups),
            'largest_group':len(groups[ordered[0]]) if ordered else 0,'top_groups':[describe(k) for k in ordered[:10]],
            'time_cross_groups':cross['groups'],'time_cross_affected':cross['affected'],
            'conflict_groups':len(conflicts),'conflict_rows':sum(len(groups[k]) for k in conflicts),
            'conflicts':[describe(k) for k in conflicts]}


def component_report(rows: list[dict], strategy: str) -> dict:
    if strategy not in ('B_feature','D_activity','E_components'):raise ValueError('未知连通策略')
    groups=_group_ids(rows,strategy);by_id={r['record_id']:r for r in rows}
    order=sorted(groups,key=lambda k:(-len(groups[k]),k))
    details=[]
    for key in order[:10]:
        group=[by_id[i] for i in groups[key]]
        times=sorted(r['timestamp'] for r in group if r['timestamp'])
        details.append({'root_record_id':key,**counts(group),'attack_activities':len({r['attack_group'] for r in group if r['attack_group']}),
                        'normal_blocks':len({r['normal_group'] for r in group if r['normal_group']}),
                        'first_time':times[0] if times else None,'last_time':times[-1] if times else None})
    return {'strategy':strategy,'group_count':len(groups),'largest_group':max(map(len,groups.values()),default=0),'top_components':details,
            'size_histogram':dict(sorted(Counter(len(g) for g in groups.values()).items()))}
