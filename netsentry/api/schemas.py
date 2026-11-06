"""请求和公开响应的白名单；拒绝额外字段和非有限数值。"""
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator
from netsentry.ids_data import matrix

RecordID=Annotated[str,Field(pattern=r'^[0-9a-f]{64}$')]
ModelID=Literal['F2_logistic','F2_rf100']
Identifier=Annotated[str,Field(pattern=r'^[0-9a-f]{32}$')]
Number=Annotated[float,Field(strict=True,ge=0,allow_inf_nan=False)]
Bit=Annotated[int,Field(strict=True,ge=0,le=1)]


class StrictModel(BaseModel):
    model_config=ConfigDict(extra='forbid',allow_inf_nan=False)


class F2Features(StrictModel):
    flow_duration: Number
    packets: Number
    bytes: Number
    mean_bytes_per_packet: Number | None
    mean_bytes_per_packet_missing: Bit
    duration_zero: Bit
    flag_urg: Bit
    flag_ack: Bit
    flag_psh: Bit
    flag_rst: Bit
    flag_syn: Bit
    flag_fin: Bit

    @model_validator(mode='after')
    def contract(self) -> 'F2Features':
        matrix([self.model_dump()],'F2')
        return self


class PredictionInput(StrictModel):
    features: F2Features
    model_id: ModelID='F2_logistic'


class RecordInput(StrictModel):
    record_id: RecordID
    model_id: ModelID='F2_logistic'


class DetectInput(StrictModel):
    record_ids: Annotated[list[RecordID],Field(min_length=1,max_length=20)]
    model_id: ModelID='F2_logistic'


class Page(StrictModel):
    limit: Annotated[int,Field(ge=1,le=100)]=20
    offset: Annotated[int,Field(ge=0,le=10000)]=0


class FlowFilters(Page):
    source_ip: IPvAnyAddress | None=None
    destination_ip: IPvAnyAddress | None=None
    host_ip: IPvAnyAddress | None=None
    start: datetime
    end: datetime
    protocol: Annotated[int,Field(ge=0,le=255)] | None=None
    port: Annotated[int,Field(ge=0,le=65535)] | None=None

    @model_validator(mode='after')
    def scope(self) -> 'FlowFilters':
        if sum(v is not None for v in [self.source_ip,self.destination_ip,self.host_ip])!=1:
            raise ValueError('恰需一种IP过滤条件')
        if self.start.tzinfo is not None or self.end.tzinfo is not None:
            raise ValueError('源数据时区未核验，请用无时区本地时间')
        if not 0<(self.end-self.start).total_seconds()<=86400:
            raise ValueError('流查询时间窗口须为正且不超过24小时')
        return self


class AlertFilters(Page):
    alert_status: Literal['candidate','reviewed','dismissed'] | None=None
    model_id: ModelID | None=None
    start: datetime | None=None
    end: datetime | None=None
    sort: Literal['score_desc','score_asc','created_desc']='score_desc'

    @model_validator(mode='after')
    def range(self) -> 'AlertFilters':
        if (self.start is None)!=(self.end is None):raise ValueError('开始和结束时间需同时提供')
        if self.start is not None:
            if self.start.tzinfo is None or self.end.tzinfo is None:raise ValueError('告警创建时间使用带时区时间')
            if not 0<(self.end-self.start).total_seconds()<=31*86400:raise ValueError('告警时间窗口不超过31天')
            self.start=self.start.astimezone(timezone.utc);self.end=self.end.astimezone(timezone.utc)
        return self


class EvidenceFilters(Page):
    window_seconds: Annotated[int,Field(ge=0,le=3600)]=60
    endpoint: Literal['both','source','destination']='both'


class ModelInfo(StrictModel):
    model_id: ModelID
    model_version: str
    feature_contract_version: str
    model_status: Literal['DEV_ONLY']
    threshold: float
    is_default: bool
    score_is_calibrated_probability: Literal[False]


class ModelsResponse(StrictModel):
    models: list[ModelInfo]


class Prediction(StrictModel):
    prediction_id: str
    record_id: RecordID | None=None
    prediction: Literal['normal','attack-related']
    attack_related_score: Annotated[float,Field(ge=0,le=1)]
    threshold: float
    model_id: ModelID
    model_version: str
    prediction_status: Literal['DEV_ONLY']
    feature_contract_version: str
    score_is_calibrated_probability: Literal[False]


class Flow(StrictModel):
    record_id: RecordID
    source_ip: IPvAnyAddress | None
    destination_ip: IPvAnyAddress | None
    source_port: int | None
    destination_port: int | None
    protocol: int | None
    timestamp: str | None
    flow_duration: float | None
    dataset_id: str
    source_sha256: str


class FlowPage(StrictModel):
    records: list[Flow]
    total: int
    limit: int
    offset: int
    has_more: bool


class Alert(StrictModel):
    alert_id: str
    record_id: RecordID
    prediction_id: str
    predicted_label: Literal['attack-related']
    attack_related_score: float
    threshold: float
    model_id: ModelID
    model_version: str
    model_status: Literal['DEV_ONLY']
    feature_contract_version: str
    source_dataset: str
    source_sha256: str
    alert_status: Literal['candidate','reviewed','dismissed']
    created_at: str
    updated_at: str
    trigger_rule_version: str


class AlertPage(StrictModel):
    alerts: list[Alert]
    total: int
    limit: int
    offset: int
    has_more: bool


class AlertDetail(StrictModel):
    alert: Alert
    flow: Flow


class DetectionFailure(StrictModel):
    record_id: RecordID
    code: Literal['not_found','prediction_unavailable']


class DetectionResult(StrictModel):
    processed: int
    created: int
    duplicates: int
    below_threshold: int
    failures: list[DetectionFailure]
    alerts: list[Alert]


class Evidence(StrictModel):
    evidence_id: str
    evidence_type: Literal['record_identity','endpoint_time_candidate']
    source_record_id: RecordID
    related_record_id: RecordID
    match_reason: str
    query_window: dict[str,str] | None
    source_sha256: str
    association_status: Literal['exact_record','candidate_unverified']
    limitations: list[str]
    flow: Flow


class EvidencePage(StrictModel):
    anchor: Flow
    association_status: Literal['candidate_unverified','insufficient_metadata']
    records: list[Evidence]
    total: int
    limit: int
    offset: int
    has_more: bool
