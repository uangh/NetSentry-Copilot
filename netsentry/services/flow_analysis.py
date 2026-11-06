"""批准事件库上的有界确定性分析；所有数量都是抽样流记录，不是连接或攻击。"""
from collections import Counter
from datetime import datetime, timedelta
import hashlib
import json
import time
from typing import Annotated, Literal
from pydantic import Field,field_validator,model_validator
from netsentry.api.schemas import StrictModel, Evidence
from .evidence_service import EvidenceService, RestrictedFlowQuery, public_flow, LIMITATIONS

AnalysisTool = Literal['summarize_host_behavior','analyze_port_distribution','analyze_temporal_bursts',
                       'build_flow_timeline','expand_evidence_page']
TOOLS = ('summarize_host_behavior','analyze_port_distribution','analyze_temporal_bursts',
         'build_flow_timeline','expand_evidence_page')


class AnalysisArguments(StrictModel):
    endpoint: Literal['source','destination']='source'
    window_seconds: Annotated[int,Field(ge=10,le=300)]=60
    limit: Annotated[int,Field(ge=1,le=10)]=10
    offset: Annotated[int,Field(ge=0,le=1000)]=0
    bucket_seconds: Literal[5,10,30,60]=10
    center_offset_seconds: Annotated[int,Field(ge=-120,le=120)]=0

    @field_validator('bucket_seconds',mode='before')
    @classmethod
    def bucket_from_http(cls,value):
        return int(value) if isinstance(value,str) and value.isdecimal() else value


class AnalysisRequest(AnalysisArguments):
    tool: AnalysisTool


Count=Annotated[int,Field(ge=0,le=10000000)]
class CommonStats(StrictModel):
    host_records_missing_timestamp_outside_window: Count

class HostStats(CommonStats):
    flow_count: Count
    unique_peers: Count
    unique_destination_ports: Count
    protocol_distribution: dict[str,Count]
    outbound_records: Count
    inbound_records: Count
    self_records: Count
    missing_peer_records: Count
    missing_destination_port: Count

class PortCount(StrictModel):
    port: Annotated[int,Field(ge=0,le=65535)]
    flow_count: Count

class PortStats(CommonStats):
    unique_ports: Count
    observed_ports: Annotated[list[Annotated[int,Field(ge=0,le=65535)]],Field(max_length=100)]
    ports_list_truncated: bool
    port_role: Literal['either_endpoint_each_record_once_per_port']
    port_counts: Annotated[list[PortCount],Field(max_length=100)]
    top_ports: Annotated[list[PortCount],Field(max_length=10)]
    missing_port_records: Count

class Bucket(StrictModel):
    start: str
    end: str
    flow_count: Count

class TemporalStats(CommonStats):
    density_kind: Literal['sampled_flow_record_density']
    buckets: Annotated[list[Bucket],Field(max_length=60)]
    peak_count: Count
    peak_buckets: Annotated[list[Bucket],Field(max_length=60)]
    valid_samples: Count
    missing_timestamps_in_scanned_rows: Count

class TimelineRow(StrictModel):
    record_id: str
    delta_seconds: Annotated[float,Field(ge=-270,le=270)]

class TimelineStats(CommonStats):
    timeline: Annotated[list[TimelineRow],Field(max_length=10)]

STATS={'summarize_host_behavior':HostStats,'analyze_port_distribution':PortStats,
       'analyze_temporal_bursts':TemporalStats,'build_flow_timeline':TimelineStats,'expand_evidence_page':CommonStats}


class AnalysisResult(StrictModel):
    tool: AnalysisTool
    anchor_record_id: str
    source_sha256: str
    query: AnalysisArguments
    query_window: dict
    total: Annotated[int,Field(ge=0)]
    analyzed_count: Annotated[int,Field(ge=0,le=5000)]
    analyzed_record_ids_sha256: str
    scan_truncated: bool
    sampled_source: Literal[True]
    statistics: dict
    records: Annotated[list[Evidence],Field(max_length=10)]
    limit: int
    offset: int
    has_more: bool
    limitations: list[str]
    duration_ms: float

    @model_validator(mode='after')
    def typed_statistics(self):
        self.statistics=STATS[self.tool].model_validate(self.statistics).model_dump()
        return self


def calculate(tool: str, rows: list[dict], ip: str, start: str, span: int, bucket: int, limit: int) -> dict:
    """只计算已经实际扫描的行；缺失单独计数，不估计完整网络数量。"""
    if tool=='summarize_host_behavior':
        peers={r[k] for r in rows for k in ('source_ip','destination_ip') if r[k] and r[k]!=ip}
        ports={r['destination_port'] for r in rows if r['destination_port'] is not None}
        return {'flow_count':len(rows),'unique_peers':len(peers),'unique_destination_ports':len(ports),
                'protocol_distribution':dict(Counter(str(r['protocol']) for r in rows)),
                'outbound_records':sum(r['source_ip']==ip for r in rows),
                'inbound_records':sum(r['destination_ip']==ip for r in rows),
                'self_records':sum(r['source_ip']==ip==r['destination_ip'] for r in rows),
                'missing_peer_records':sum(not r['source_ip'] or not r['destination_ip'] for r in rows),
                'missing_destination_port':sum(r['destination_port'] is None for r in rows)}
    if tool=='analyze_port_distribution':
        counts=Counter(p for r in rows for p in {r['source_port'],r['destination_port']} if p is not None)
        ordered=sorted(counts.items(),key=lambda x:(-x[1],x[0]))
        return {'unique_ports':len(counts),'observed_ports':sorted(counts)[:100],
                'ports_list_truncated':len(counts)>100,'port_role':'either_endpoint_each_record_once_per_port',
                'port_counts':[{'port':p,'flow_count':n} for p,n in ordered[:100]],
                'top_ports':[{'port':p,'flow_count':n} for p,n in ordered[:limit]],
                'missing_port_records':sum(r['source_port'] is None or r['destination_port'] is None for r in rows)}
    if tool=='analyze_temporal_bursts':
        origin=datetime.fromisoformat(start);counts=Counter();missing=0
        for r in rows:
            if r['timestamp'] is None:missing+=1;continue
            counts[int((datetime.fromisoformat(r['timestamp'])-origin).total_seconds()//bucket)]+=1
        buckets=[{'start':(origin+timedelta(seconds=i)).isoformat(timespec='microseconds'),
                  'end':(origin+timedelta(seconds=min(i+bucket,span))).isoformat(timespec='microseconds'),
                  'flow_count':counts[i//bucket]} for i in range(0,span,bucket)]
        peak=max((b['flow_count'] for b in buckets),default=0)
        return {'density_kind':'sampled_flow_record_density','buckets':buckets,
                'peak_count':peak,'peak_buckets':[b for b in buckets if b['flow_count']==peak and peak>0],
                'valid_samples':len(rows)-missing,'missing_timestamps_in_scanned_rows':missing}
    return {}


class FlowAnalysisService:
    def __init__(self, evidence: EvidenceService):self.evidence=evidence

    def run(self, record_id: str, request: AnalysisRequest) -> dict:
        started=time.perf_counter();anchor=self.evidence.flow(record_id)
        ip=anchor[request.endpoint+'_ip']
        if not ip or not anchor['timestamp']:raise ValueError('insufficient_metadata')
        center=datetime.fromisoformat(anchor['timestamp'])+timedelta(seconds=request.center_offset_seconds)
        start=(center-timedelta(seconds=request.window_seconds/2)).isoformat(timespec='microseconds')
        end=(center+timedelta(seconds=request.window_seconds/2)).isoformat(timespec='microseconds')
        window={'start':start,'end':end,'boundary':'half_open','time_basis':'source_local_unverified'}
        # 固定SQL、只读连接、最多5000行用于统计。查询总量与实际扫描量分开。
        where='(source_ip=? OR destination_ip=?) AND timestamp>=? AND timestamp<?'
        params=(ip,ip,start,end)
        with RestrictedFlowQuery(self.evidence.database) as q:
            q.connection.set_progress_handler(lambda: int(time.perf_counter()-started>2),1000)
            total=q.connection.execute('SELECT COUNT(*) FROM events WHERE '+where,params).fetchone()[0]
            missing=q.connection.execute('SELECT COUNT(*) FROM events WHERE (source_ip=? OR destination_ip=?) AND timestamp IS NULL',(ip,ip)).fetchone()[0]
            cursor=q.connection.execute('SELECT record FROM events WHERE '+where+' ORDER BY timestamp,record_id LIMIT 5000',params)
            rows=[public_flow(json.loads(row[0])) for row in cursor]
        args=AnalysisArguments.model_validate(request.model_dump(exclude={'tool'}))
        stats=calculate(request.tool,rows,ip,start,request.window_seconds,request.bucket_seconds,request.limit)
        selected=rows[request.offset:request.offset+request.limit]
        if request.tool=='build_flow_timeline':
            stats['timeline']=[{'record_id':r['record_id'],'delta_seconds':(datetime.fromisoformat(r['timestamp'])-datetime.fromisoformat(anchor['timestamp'])).total_seconds()} for r in selected]
        records=[]
        for row in selected:
            item=self.evidence.item(anchor,row,window,row['record_id']==record_id)
            if row['record_id']!=record_id:item['match_reason']='共享选定锚点IP '+ip+'；流开始时间在半开窗口内；候选未确认'
            records.append(item)
        stats['host_records_missing_timestamp_outside_window']=missing
        return AnalysisResult(tool=request.tool,anchor_record_id=record_id,source_sha256=anchor['source_sha256'],
            query=args,query_window=window,total=total,analyzed_count=len(rows),
            analyzed_record_ids_sha256=hashlib.sha256('\n'.join(r['record_id'] for r in rows).encode()).hexdigest(),
            scan_truncated=total>len(rows),sampled_source=True,statistics=stats,records=records,
            limit=request.limit,offset=request.offset,has_more=request.offset+len(records)<total,
            limitations=LIMITATIONS+['每100行系统抽样；数量不外推为完整网络、连接、带宽或攻击',
                '统计最多扫描按时间/ID排序的前5000行；缺失时间无法归入窗口；方向仅表示相对选定IP的记录方向'],
            duration_ms=(time.perf_counter()-started)*1000).model_dump(mode='json')
