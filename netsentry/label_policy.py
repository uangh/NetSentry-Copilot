"""M2A：离线监督目标；保留原标注，不向调查接口提供目标。"""
from __future__ import annotations

POLICY_VERSION = 'netsentry.labels.v1'
ATTACK_TYPES = ('bruteForce', 'dos', 'pingScan', 'portScan')


def label_policy(task: str = 'B') -> dict:
    classes = {'A': ['normal', 'attacker', 'victim'],
               'B': ['normal', 'attack-related'],
               'C': ['normal', *ATTACK_TYPES]}
    if task not in classes:
        raise ValueError('未知监督任务，要求A/B/C')
    return {'version': POLICY_VERSION, 'task': task, 'classes': classes[task],
            'unknown_policy': 'reject_and_report; never map unknown/suspicious to normal',
            'mapping': {'A': 'retain original role',
                        'B': 'normal -> normal; attacker/victim -> attack-related',
                        'C': 'normal -> normal; attacker/victim -> validated attackType'}[task],
            'scope': 'CIDDS-001 offline benchmark targets; not attack success or host guilt'}


def map_target(original_class: str, attack_type: str, task: str = 'B') -> str:
    """映射是派生目标，绝不覆盖CSV中的class/attackType。"""
    label_policy(task)
    if original_class not in ('normal', 'attacker', 'victim'):
        raise ValueError(f'不支持或不确定的原始类别: {original_class!r}')
    if task == 'A':
        return original_class
    if task == 'B':
        return 'normal' if original_class == 'normal' else 'attack-related'
    if original_class == 'normal':
        if attack_type != '---':
            raise ValueError('normal与attackType标注冲突')
        return 'normal'
    if attack_type not in ATTACK_TYPES:
        raise ValueError('攻击相关记录缺少已知attackType')
    return attack_type
