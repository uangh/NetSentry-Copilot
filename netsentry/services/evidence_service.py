"""复用 M1.7 固定只读查询，投影为公开字段，候选关联不是事件结论。"""
from datetime import datetime, timedelta
import hashlib
from pathlib import Path

from netsentry.api.schemas import Flow, FlowFilters
from netsentry.labeled_query import LabeledFlowQuery

LIMITATIONS=['候选流量不证明同一次攻击或攻击成功','源时间为数据集本地时间，时区未验证',
             '匿名化IP保持null；没有认证日志','仅Week1 Train/Validation系统子集，可能遗漏相关流量']


def public_flow(record: dict) -> dict:
    return Flow.model_validate({key:record[key] for key in Flow.model_fields}).model_dump(mode='json')


class RestrictedFlowQuery(LabeledFlowQuery):
    def related_endpoint(self, anchor: dict, radius: int, endpoint: str, limit: int, offset: int) -> dict:
        if endpoint not in ('source','destination'):raise ValueError('invalid endpoint')
        ip=anchor[endpoint+'_ip']
        if not ip or not anchor['timestamp']:return {'records':[],'total':0}
        stamp=datetime.fromisoformat(anchor['timestamp'])
        where='record_id<>? AND timestamp>=? AND timestamp<=? AND (source_ip=? OR destination_ip=?)'
        return self._page(where,[anchor['record_id'],(stamp-timedelta(seconds=radius)).isoformat(timespec='microseconds'),
            (stamp+timedelta(seconds=radius)).isoformat(timespec='microseconds'),ip,ip],
            rule='share selected anchor endpoint; closed time radius',limit=limit,offset=offset)

    def filtered(self, filters: FlowFilters) -> dict:
        # 继承只读连接、预算和分页实现；新增协议/任一端口筛选发生在分页之前。
        if filters.host_ip is not None:
            where='(source_ip=? OR destination_ip=?)';params=[str(filters.host_ip)]*2
        else:
            column='source_ip' if filters.source_ip is not None else 'destination_ip'
            where=column+'=?';params=[str(getattr(filters,column))]
        where+=' AND timestamp>=? AND timestamp<?'
        params.extend([filters.start.isoformat(timespec='microseconds'),filters.end.isoformat(timespec='microseconds')])
        if filters.protocol is not None:
            where+=" AND json_extract(record,'$.protocol')=?";params.append(filters.protocol)
        if filters.port is not None:
            where+=' AND (source_port=? OR destination_port=?)';params.extend([filters.port]*2)
        return self._page(where,params,rule='fixed IP/time/protocol/port filters',limit=filters.limit,offset=filters.offset)


class EvidenceService:
    def __init__(self, database: Path) -> None:self.database=Path(database)

    def flow(self, record_id: str) -> dict:
        with RestrictedFlowQuery(self.database) as query:record=query.get_flow_detail(record_id)['record']
        if record is None:raise KeyError('flow not found in approved development scope')
        return public_flow(record)

    def flows(self, filters: FlowFilters) -> dict:
        with RestrictedFlowQuery(self.database) as query:page=query.filtered(filters)
        return {key:([public_flow(r) for r in page[key]] if key=='records' else page[key])
                for key in ('records','total','limit','offset','has_more')}

    @staticmethod
    def item(anchor: dict, related: dict, window: dict | None, exact: bool) -> dict:
        status='exact_record' if exact else 'candidate_unverified'
        key='|'.join([anchor['record_id'],related['record_id'],status,str(window)])
        ips=sorted(set(filter(None,[anchor['source_ip'],anchor['destination_ip']])) &
                   set(filter(None,[related['source_ip'],related['destination_ip']])))
        return {'evidence_id':hashlib.sha256(key.encode()).hexdigest(),
            'evidence_type':'record_identity' if exact else 'endpoint_time_candidate',
            'source_record_id':anchor['record_id'],'related_record_id':related['record_id'],
            'match_reason':'同一record_id的确定性记录关联，不是攻击结论' if exact else '共享端点IP '+','.join(ips)+'，流开始时间在闭区间内',
            'query_window':window,'source_sha256':related['source_sha256'],'association_status':status,
            'limitations':LIMITATIONS,'flow':related}

    def evidence(self, record_id: str, window_seconds: int, limit: int, offset: int, *, endpoint: str='both') -> dict:
        if not 0<=window_seconds<=3600 or not 1<=limit<=100 or not 0<=offset<=10000:raise ValueError('证据预算超限')
        if endpoint not in ('both','source','destination'):raise ValueError('invalid endpoint')
        anchor=self.flow(record_id);window=None
        usable=bool(anchor['timestamp'] and ((anchor['source_ip'] or anchor['destination_ip']) if endpoint=='both' else anchor[endpoint+'_ip']))
        records=[self.item(anchor,anchor,None,True)] if offset==0 else []
        total=1
        if usable:
            stamp=datetime.fromisoformat(anchor['timestamp'])
            window={'start':(stamp-timedelta(seconds=window_seconds)).isoformat(timespec='microseconds'),
                    'end':(stamp+timedelta(seconds=window_seconds)).isoformat(timespec='microseconds'),
                    'boundary':'closed','time_basis':'source_local_unverified'}
            available=limit-len(records)
            with RestrictedFlowQuery(self.database) as query:
                page=query.query_related_flows(record_id,window_seconds,limit=max(1,available),offset=max(0,offset-1)) if endpoint=='both' else query.related_endpoint(anchor,window_seconds,endpoint,max(1,available),max(0,offset-1))
            total+=page['total']
            records.extend(self.item(anchor,public_flow(r),window,False) for r in page['records'][:available])
        return {'anchor':anchor,'association_status':'candidate_unverified' if usable else 'insufficient_metadata',
                'records':records,'total':total,'limit':limit,'offset':offset,'has_more':offset+len(records)<total}
