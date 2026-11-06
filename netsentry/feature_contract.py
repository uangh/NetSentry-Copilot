"""M2A：无拟合的特征白名单；不读取IP、标签、行号或评测结论。"""
from __future__ import annotations
import hashlib
import json
import math
import re

TRANSFORM_VERSION = 'netsentry.features.v1'
FLAGS = tuple(zip('UAPRSF', ['urg', 'ack', 'psh', 'rst', 'syn', 'fin']))
EXCLUDED = ['class', 'label', 'attackType', 'attackID', 'attackDescription', 'record_id',
            'original_row_number', 'flow_id', 'original_file', 'source_ip', 'destination_ip',
            'anonymous_identity', 'timestamp', 'review_decision', 'evaluation_result', 'Flows', 'Tos']


def feature_contract(scheme: str, scaled_policy: str = 'si_approx') -> dict:
    if scheme not in ('F1', 'F2', 'F3') or scaled_policy not in ('si_approx', 'exclude'):
        raise ValueError('未知特征或缩写字节处理方案')
    fields = [dict(name=n, dtype='float64', unit=u, missing='ineligible') for n,u in
              [('flow_duration','seconds'), ('packets','packets; integral'), ('bytes','bytes; scaled values approximate')]]
    if scheme != 'F1':
        fields += [dict(name='mean_bytes_per_packet',dtype='float64',unit='bytes/packet',missing='null + indicator; train-only imputer later'),
                   dict(name='mean_bytes_per_packet_missing',dtype='binary',unit='indicator',missing='none'),
                   dict(name='duration_zero',dtype='binary',unit='indicator',missing='none')]
        fields += [dict(name='flag_'+name,dtype='binary',unit='OR across flow; not flag count',missing='ineligible') for _,name in FLAGS]
    if scheme == 'F3':
        fields += [dict(name='protocol_'+p,dtype='binary',unit='fixed category',missing='other category')
                   for p in ['tcp','udp','icmp','igmp','other']]
        for side in ['source','destination']:
            fields += [dict(name=side+'_port',dtype='categorical_integer',unit='TCP/UDP port 0..65535',missing='null; train-only encoder later'),
                       dict(name=side+'_port_missing',dtype='binary',unit='invalid transport port',missing='none'),
                       dict(name=side+'_port_not_applicable',dtype='binary',unit='non TCP/UDP',missing='none')]
    result = {'scheme':scheme,'transform_version':TRANSFORM_VERSION,'fields':fields,'excluded':EXCLUDED.copy(),
              'scaled_bytes_policy':scaled_policy,'scaled_multipliers':{'K':1000,'M':1000000,'G':1000000000},
              'finite_nonnegative_required':True,'flags_positions':'UAPRSF; dot means absent',
              'preprocessing_fit_performed':False,'ip_filter':False}
    result['version'] = contract_version(result)
    return result


def contract_version(contract: dict) -> str:
    """内容寻址：类型、单位、白名单或缺失规则变化都会改变版本。"""
    canonical = {k:v for k,v in contract.items() if k != 'version'}
    text = json.dumps(canonical,sort_keys=True,separators=(',',':'),ensure_ascii=False)
    return TRANSFORM_VERSION + ':' + hashlib.sha256(text.encode()).hexdigest()


def build_features(record: dict, extra: dict, scheme: str = 'F1', *, scaled_policy: str = 'si_approx') -> dict:
    contract = feature_contract(scheme,scaled_policy)
    x = {name:record['features'].get(name) for name in ['flow_duration','packets','bytes']}
    reasons = []
    for name,value in x.items():
        if type(value) not in (float,int) or not math.isfinite(value) or value < 0:
            reasons.append('invalid_'+name)
    if not reasons and not float(x['packets']).is_integer():
        reasons.append('fractional_packets')
    scaled = bool(re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)\s*[kKmMgG]',extra.get('Bytes','').strip()))
    if scaled and scaled_policy == 'exclude':
        reasons.append('scaled_bytes_excluded')
    if reasons:
        return {'X':None,'eligible':False,'reasons':reasons,'scaled_bytes':scaled,'contract_version':contract['version']}
    x = {name:float(value) for name,value in x.items()}
    if scheme != 'F1':
        flags = extra.get('Flags','').strip()
        if len(flags) != 6 or any(c not in ('.',letter) for c,(letter,_) in zip(flags,FLAGS)):
            return {'X':None,'eligible':False,'reasons':['invalid_flags'],'scaled_bytes':scaled,'contract_version':contract['version']}
        x['mean_bytes_per_packet'] = x['bytes']/x['packets'] if x['packets'] else None
        x['mean_bytes_per_packet_missing'] = int(x['packets'] == 0)
        x['duration_zero'] = int(x['flow_duration'] == 0)
        x.update({'flag_'+name:int(flags[i] == letter) for i,(letter,name) in enumerate(FLAGS)})
    if scheme == 'F3':
        protocol = record.get('protocol')
        category = {6:'tcp',17:'udp',1:'icmp',2:'igmp'}.get(protocol,'other')
        x.update({'protocol_'+p:int(category == p) for p in ['tcp','udp','icmp','igmp','other']})
        for side in ['source','destination']:
            value = record.get(side+'_port')
            applicable = protocol in (6,17)
            valid = type(value) is int and 0 <= value <= 65535
            x[side+'_port'] = value if applicable and valid else None
            x[side+'_port_missing'] = int(applicable and not valid)
            x[side+'_port_not_applicable'] = int(not applicable)
    if set(x) != {f['name'] for f in contract['fields']}:
        raise ValueError('特征与白名单不一致')
    return {'X':x,'eligible':True,'reasons':[],'scaled_bytes':scaled,'contract_version':contract['version']}
