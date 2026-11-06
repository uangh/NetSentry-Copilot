"""Agent的输入/报告/审核契约。工具参数不接受任意路径、URL或代码。"""
from typing import Annotated, Literal, TypedDict
from pydantic import Field
from netsentry.api.schemas import StrictModel, Identifier


class Limits(StrictModel):
    max_calls: Annotated[int,Field(ge=1,le=6)]=6
    max_plans: Annotated[int,Field(ge=1,le=2)]=2
    page_size: Annotated[int,Field(ge=1,le=100)]=10
    window_seconds: Annotated[int,Field(ge=1,le=3600)]=60
    total_seconds: Annotated[int,Field(ge=1,le=45)]=30


class Choice(StrictModel):
    tool: Literal['query_related_evidence','query_host_flows','stop']
    endpoint: Literal['source','destination']='source'
    window_seconds: Annotated[int,Field(ge=1,le=3600)]=60
    limit: Annotated[int,Field(ge=1,le=100)]=10
    offset: Annotated[int,Field(ge=0,le=100)]=0


class Plan(StrictModel):
    actions: Annotated[list[Choice],Field(max_length=2)]


class Paragraph(StrictModel):
    lead: Literal['已取得以下可追溯观察。','以下关联仅供复核。','仍需补充独立证据。']
    fact_ids: Annotated[list[str],Field(max_length=12)]


class Narrative(StrictModel):
    paragraphs: Annotated[list[Paragraph],Field(min_length=1,max_length=3)]


class Start(StrictModel):
    alert_id: Identifier
    mode: Literal['offline','llm_agent','gemini_llm','gemini_multistep','enhanced_deterministic_baseline']='offline'


class Review(StrictModel):
    request_id: Identifier
    decision: Literal['approve','reject','request_revision']
    note: Annotated[str,Field(max_length=1000)]=''
    expected_version: Annotated[int,Field(ge=1,le=3)]


class Fact(StrictModel):
    fact_id: str
    field: str
    value: str | int | float | None
    reference_id: str
    scope: str


class Reference(StrictModel):
    reference_id: str
    kind: Literal['alert_response','flow_response','evidence','flow_query']
    record_id: str | None
    source_sha256: str | None
    call_id: str
    evidence_id: str | None=None


class KnowledgeHit(StrictModel):
    document_id: str
    chunk_id: str
    title: str
    source_url: str
    source_version: str
    document_sha256: str
    text: str
    score: float


class ToolTrace(StrictModel):
    call_id: str
    tool: str
    parameters: dict
    status: Literal['ok','error','duplicate_blocked','budget_blocked']
    duration_ms: float
    returned_count: int
    source_references: list[str]
    http_trace_id: str | None=None
    http_request: dict | None=None


class CandidateRelation(StrictModel):
    reference_id: str
    source_record_id: str
    related_record_id: str
    association_status: Literal['candidate_unverified']


class Report(StrictModel):
    investigation_id: Identifier
    alert_id: Identifier
    model_id: str
    model_version: str
    feature_contract_version: str
    predicted_class: str
    model_status: Literal['DEV_ONLY']
    prediction_score: Annotated[float,Field(ge=0,le=1)]
    score_is_calibrated_probability: Literal[False]
    investigation_summary: str
    observed_facts: list[Fact]
    candidate_relations: list[CandidateRelation]
    evidence_references: list[Reference]
    knowledge_references: list[KnowledgeHit]
    hypothesis: Literal['insufficient_evidence']
    uncertainty: list[str]
    missing_evidence: list[str]
    recommended_next_steps: list[str]
    reasoning_mode: Literal['deterministic_offline','llm_agent','gemini_llm','gemini_multistep','enhanced_deterministic_baseline']
    tool_call_trace: list[ToolTrace]
    review_status: Literal['pending_review','approved','rejected']
    generated_at: str
    report_version: Annotated[int,Field(ge=1,le=3)]


class State(TypedDict,total=False):
    investigation_id: str
    alert_id: str
    mode: str
    model_context: dict
    anchor_flow: dict
    collected_evidence: list[dict]
    candidate_relations: list[dict]
    knowledge_references: list[dict]
    tool_call_history: list[dict]
    investigation_steps: list[str]
    missing_information: list[str]
    confidence_limitations: list[str]
    draft_report: dict | None
    review_status: str
    stop_reason: str | None
    alert_detail: dict | None
    observations: list[dict]
    plan_iterations: int
    pending_actions: list[dict]
    calls_used: int
    seen_calls: list[str]
    deadline: float
    report_version: int
    generated_at: str
    narrative: dict | None
    review_history: list[dict]
    limits: dict
    summaries: list[dict]
    llm_events: list[dict]
    gemini: dict

    decision_trace: list[dict]
    multistep: dict

    observation_registry: list[dict]
    planning_attempts: list[dict]
    recovery: dict
