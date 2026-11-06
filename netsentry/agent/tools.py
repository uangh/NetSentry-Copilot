"""只读M3 HTTP工具。URL固定，响应严格验证，预算在图状态中持久化。"""
from datetime import datetime, timedelta
import json
import time
from urllib.parse import urlparse
from typing import Annotated

import httpx
from pydantic import TypeAdapter, Field, field_validator
from netsentry.api.schemas import AlertDetail, Alert, Flow, FlowPage, Evidence, EvidencePage, Identifier, RecordID, FlowFilters


class ValidatedFlow(Flow):
    source_port: Annotated[int,Field(ge=0,le=65535)] | None
    destination_port: Annotated[int,Field(ge=0,le=65535)] | None
    protocol: Annotated[int,Field(ge=0,le=255)] | None
    flow_duration: Annotated[float,Field(ge=0)] | None
    source_sha256: RecordID

    @field_validator('timestamp')
    @classmethod
    def timestamp_contract(cls, value: str | None) -> str | None:
        if value is not None and datetime.fromisoformat(value).tzinfo is not None:
            raise ValueError('当前M3数据时区未知，拒绝混入带时区值')
        return value


class ValidatedAlert(Alert):
    alert_id: Identifier
    source_sha256: RecordID
    attack_related_score: Annotated[float,Field(ge=0,le=1)]


class ValidatedDetail(AlertDetail):
    alert: ValidatedAlert
    flow: ValidatedFlow


class ValidatedPage(FlowPage):
    records: list[ValidatedFlow]
    total: Annotated[int,Field(ge=0)]


class ValidatedEvidence(Evidence):
    flow: ValidatedFlow
    source_sha256: RecordID


class ValidatedEvidencePage(EvidencePage):
    anchor: ValidatedFlow
    records: list[ValidatedEvidence]
    total: Annotated[int,Field(ge=0)]


class ToolError(RuntimeError):pass


def local_url(value: str) -> str:
    parsed=urlparse(value)
    if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.username or parsed.query or parsed.fragment or parsed.path not in ('','/'):
        raise ValueError('只允许显式127.0.0.1回环服务地址')
    if not parsed.port or not 1024<=parsed.port<=65535:raise ValueError('需要有效本地端口')
    return value.rstrip('/')


class M3Tools:
    def __init__(self, base_url: str, *, transport=None) -> None:
        self.base_url=local_url(base_url)
        self.client=httpx.Client(base_url=self.base_url,timeout=3,trust_env=False,follow_redirects=False,transport=transport)
        self.last_trace=None
        self.last_request=None

    def close(self) -> None:self.client.close()

    def _get(self, path: str, schema: type, *, params: dict | None=None, deadline: float) -> dict:
        self.last_request={'method':'GET','path':path,'parameters':params or {}}
        remaining=deadline-time.time()
        if remaining<=0:raise ToolError('total_time_budget')
        try:
            with self.client.stream('GET',path,params=params,timeout=min(3,remaining)) as response:
                if response.status_code!=200:raise ToolError('http_'+str(response.status_code))
                self.last_trace=response.headers.get('X-Trace-ID');data=bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data)>512*1024 or time.time()>deadline:raise ToolError('response_budget')
                return schema.model_validate(json.loads(data)).model_dump(mode='json')
        except (httpx.HTTPError,ValueError) as exc:
            raise ToolError('invalid_or_unavailable_response') from exc

    def get_alert_detail(self, alert_id: str, *, deadline: float) -> dict:
        TypeAdapter(Identifier).validate_python(alert_id)
        result=self._get('/api/v1/alerts/'+alert_id,ValidatedDetail,deadline=deadline)
        if result['alert']['alert_id']!=alert_id or result['flow']['record_id']!=result['alert']['record_id']:
            raise ToolError('alert_scope_mismatch')
        if result['alert']['source_sha256']!=result['flow']['source_sha256'] or result['alert']['source_dataset']!=result['flow']['dataset_id']:
            raise ToolError('alert_source_mismatch')
        return result

    def get_anchor_flow(self, record_id: str, *, deadline: float) -> dict:
        TypeAdapter(RecordID).validate_python(record_id)
        result=self._get('/api/v1/flows/'+record_id,ValidatedFlow,deadline=deadline)
        if result['record_id']!=record_id:raise ToolError('record_scope_mismatch')
        return result

    def query_related_evidence(self, alert_id: str, record_id: str, *, window_seconds: int, limit: int, offset: int, deadline: float, endpoint: str | None=None) -> dict:
        TypeAdapter(Identifier).validate_python(alert_id)
        if not 1<=window_seconds<=3600 or not 1<=limit<=100 or not 0<=offset<=100:raise ToolError('invalid_budget')
        if endpoint is not None and endpoint not in ('source','destination'):raise ToolError('invalid_endpoint')
        result=self._get(f'/api/v1/alerts/{alert_id}/evidence',ValidatedEvidencePage,
            params={'window_seconds':window_seconds//2,'limit':limit,'offset':offset,**({'endpoint':endpoint} if endpoint else {})},deadline=deadline)
        if result['anchor']['record_id']!=record_id or len(result['records'])>limit:raise ToolError('evidence_scope_mismatch')
        if result['limit']!=limit or result['offset']!=offset or result['total']<len(result['records']):raise ToolError('page_scope_mismatch')
        for evidence in result['records']:
            if evidence['source_record_id']!=record_id or evidence['related_record_id']!=evidence['flow']['record_id']:
                raise ToolError('evidence_identity_mismatch')
            if evidence['source_sha256']!=evidence['flow']['source_sha256']:raise ToolError('evidence_source_mismatch')
            if evidence['source_sha256']!=result['anchor']['source_sha256']:raise ToolError('cross_source_evidence')
            anchor=result['anchor'];flow=evidence['flow']
            if evidence['association_status']=='exact_record':
                if evidence['evidence_type']!='record_identity' or flow!=anchor:raise ToolError('false_exact_record')
            else:
                ips=set(filter(None,[anchor[endpoint+'_ip']] if endpoint else [anchor['source_ip'],anchor['destination_ip']]))
                if flow['record_id']==record_id or not ips.intersection([flow['source_ip'],flow['destination_ip']]):raise ToolError('unrelated_endpoints')
                if not anchor['timestamp'] or not flow['timestamp']:raise ToolError('missing_candidate_time')
                stamp=datetime.fromisoformat(anchor['timestamp']);moment=datetime.fromisoformat(flow['timestamp'])
                if abs((moment-stamp).total_seconds())>window_seconds//2:raise ToolError('candidate_outside_window')
                window=evidence['query_window']
                if not window or window.get('start')!=(stamp-timedelta(seconds=window_seconds//2)).isoformat(timespec='microseconds') or window.get('end')!=(stamp+timedelta(seconds=window_seconds//2)).isoformat(timespec='microseconds'):
                    raise ToolError('candidate_window_mismatch')
        return result

    def query_host_flows(self, anchor: dict, *, endpoint: str, window_seconds: int, limit: int, offset: int, deadline: float) -> dict:
        if endpoint not in ('source','destination'):raise ToolError('invalid_endpoint')
        ip=anchor[endpoint+'_ip']
        if ip is None or anchor['timestamp'] is None:raise ToolError('insufficient_metadata')
        if not 1<=window_seconds<=3600 or not 1<=limit<=100 or not 0<=offset<=100:raise ToolError('invalid_budget')
        stamp=datetime.fromisoformat(anchor['timestamp'])
        # 总跨度window_seconds；与Evidence的±半径语义分别记录。
        filters=FlowFilters(host_ip=ip,start=stamp-timedelta(seconds=window_seconds/2),
            end=stamp+timedelta(seconds=window_seconds/2),limit=limit,offset=offset)
        params=filters.model_dump(mode='json',exclude_none=True)
        result=self._get('/api/v1/flows',ValidatedPage,params=params,deadline=deadline)
        if len(result['records'])>limit:raise ToolError('response_rows_exceeded')
        if result['limit']!=limit or result['offset']!=offset or result['total']<len(result['records']):raise ToolError('page_scope_mismatch')
        for record in result['records']:
            if record['source_sha256']!=anchor['source_sha256'] or record['dataset_id']!=anchor['dataset_id']:raise ToolError('host_source_mismatch')
            if ip not in (record['source_ip'],record['destination_ip']):raise ToolError('host_scope_mismatch')
            if record['timestamp'] is None or not filters.start<=datetime.fromisoformat(record['timestamp'])<filters.end:
                raise ToolError('time_scope_mismatch')
        return result|{'query':params}
