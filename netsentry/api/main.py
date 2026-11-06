"""FastAPI 工厂、依赖注入及受限端点。启动失败时不回退到其他模型。"""
from contextlib import asynccontextmanager
from dataclasses import dataclass
import hmac
import logging
import time
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import Settings
from .schemas import (AlertDetail,AlertFilters,AlertPage,DetectInput,DetectionResult,EvidenceFilters,EvidencePage,
                      Flow,FlowFilters,FlowPage,Identifier,ModelsResponse,Prediction,PredictionInput,RecordID,RecordInput)
from netsentry.repositories.alert_repository import AlertRepository
from netsentry.services.alert_service import AlertService
from netsentry.services.evidence_service import EvidenceService
from netsentry.services.prediction_service import PredictionService
from netsentry.services.flow_analysis import FlowAnalysisService, AnalysisRequest, AnalysisResult

LOG=logging.getLogger('netsentry.api')
token_header=APIKeyHeader(name='X-API-Token',auto_error=False)


@dataclass
class Services:
    prediction: PredictionService
    evidence: EvidenceService
    alerts: AlertRepository
    detection: AlertService

    @classmethod
    def load(cls, settings: Settings) -> 'Services':
        prediction=PredictionService(settings.runtime)
        evidence=EvidenceService(settings.runtime/'events.sqlite')
        alerts=AlertRepository(settings.alert_db)
        return cls(prediction,evidence,alerts,AlertService(prediction,evidence,alerts))


def get_services(request: Request) -> Services:
    services=request.app.state.services
    if services is None:raise HTTPException(503,'service_unavailable')
    return services


def authorize(request: Request, token: str | None=Depends(token_header)) -> None:
    expected=request.app.state.settings.token
    if expected is None:raise HTTPException(503,'write_token_not_configured')
    if token is None or not hmac.compare_digest(token.encode(),expected.encode()):raise HTTPException(401,'unauthorized')


def error_response(request: Request, status: int, code: str, details: list | None=None) -> JSONResponse:
    return JSONResponse(status_code=status,content={'error':{'code':code,'trace_id':getattr(request.state,'trace_id','unavailable'),
        'details':details or []}})


def create_app(settings: Settings | None=None, *, services: Services | None=None) -> FastAPI:
    settings=settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if app.state.services is None:app.state.services=Services.load(settings)
        yield

    app=FastAPI(title='NetSentry local evidence API',version='m3.v1',lifespan=lifespan,
                description='DEV_ONLY; candidate evidence is not confirmed attack. No ground truth or training endpoints.')
    app.state.settings=settings;app.state.services=services
    app.add_middleware(CORSMiddleware,allow_origins=list(settings.origins),allow_credentials=False,
                       allow_methods=['GET','POST'],allow_headers=['Content-Type','X-API-Token'],expose_headers=['X-Trace-ID'])
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=['127.0.0.1','localhost','testserver'])

    @app.middleware('http')
    async def trace(request: Request, call_next):
        request.state.trace_id=uuid4().hex;started=time.perf_counter()
        # 本地服务器只允许小JSON请求。提前按流读取限额，不保存任意大请求体。
        if request.method in ('POST','PUT','PATCH'):
            size=0;chunks=[]
            async for chunk in request.stream():
                size+=len(chunk)
                if size>65536:
                    response=error_response(request,413,'request_too_large');break
                chunks.append(chunk)
            else:
                request._body=b''.join(chunks)
                response=None
        else:response=None
        if response is None:
            try:response=await call_next(request)
            except Exception:
                # 不记录异常文本、请求体、token、模型路径或用户输入。
                response=error_response(request,500,'internal_error')
        response.headers['X-Trace-ID']=request.state.trace_id
        response.headers['Cache-Control']='no-store'
        route=request.scope.get('route');route_name=getattr(route,'path','unmatched')
        LOG.info('trace_id=%s method=%s route=%s status=%s duration_ms=%.2f',request.state.trace_id,
                 request.method,route_name,response.status_code,(time.perf_counter()-started)*1000)
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError):
        return error_response(request,422,'invalid_request',[{'loc':list(e['loc']),'type':e['type']} for e in exc.errors()])

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        codes={401:'unauthorized',404:'not_found',405:'method_not_allowed',503:'service_unavailable'}
        return error_response(request,exc.status_code,codes.get(exc.status_code,'http_error'))

    @app.exception_handler(KeyError)
    async def missing(request: Request, exc: KeyError):return error_response(request,404,'not_found')

    @app.exception_handler(ValueError)
    async def invalid_value(request: Request, exc: ValueError):return error_response(request,422,'invalid_value')

    @app.get('/health')
    def health(s: Services=Depends(get_services)) -> dict:
        return {'status':'ok','service_version':'m3.v1','model_status':'DEV_ONLY','write_enabled':settings.token is not None}

    @app.get('/api/v1/models',response_model=ModelsResponse)
    def models(s: Services=Depends(get_services)):return {'models':s.prediction.models()}

    @app.post('/api/v1/predictions',response_model=Prediction)
    def predict(body: PredictionInput,s: Services=Depends(get_services)):
        return s.prediction.predict(features=body.features.model_dump(),model_id=body.model_id)

    @app.post('/api/v1/predictions/by-record',response_model=Prediction)
    def predict_record(body: RecordInput,s: Services=Depends(get_services)):
        return s.prediction.predict(record_id=body.record_id,model_id=body.model_id)

    @app.post('/api/v1/alerts/detect',response_model=DetectionResult,dependencies=[Depends(authorize)])
    def detect(body: DetectInput,s: Services=Depends(get_services)):
        return s.detection.detect(body.record_ids,body.model_id)

    @app.get('/api/v1/alerts',response_model=AlertPage)
    def alerts(filters: Annotated[AlertFilters,Query()],s: Services=Depends(get_services)):
        return s.alerts.list(filters)

    @app.get('/api/v1/alerts/{alert_id}',response_model=AlertDetail)
    def alert(alert_id: Identifier,s: Services=Depends(get_services)):
        item=s.alerts.get(alert_id);return {'alert':item,'flow':s.evidence.flow(item['record_id'])}

    @app.get('/api/v1/alerts/{alert_id}/evidence',response_model=EvidencePage)
    def evidence(alert_id: Identifier,filters: Annotated[EvidenceFilters,Query()],s: Services=Depends(get_services)):
        item=s.alerts.get(alert_id)
        if filters.endpoint=='both':return s.evidence.evidence(item['record_id'],filters.window_seconds,filters.limit,filters.offset)
        return s.evidence.evidence(item['record_id'],filters.window_seconds,filters.limit,filters.offset,endpoint=filters.endpoint)

    @app.get('/api/v1/flows',response_model=FlowPage)
    def flows(filters: Annotated[FlowFilters,Query()],s: Services=Depends(get_services)):
        return s.evidence.flows(filters)

    @app.get('/api/v1/flows/{record_id}',response_model=Flow)
    def flow(record_id: RecordID,s: Services=Depends(get_services)):return s.evidence.flow(record_id)

    @app.get('/api/v1/flows/{record_id}/analysis',response_model=AnalysisResult)
    def analyze(record_id: RecordID,filters: Annotated[AnalysisRequest,Query()],s: Services=Depends(get_services)):
        return FlowAnalysisService(s.evidence).run(record_id,filters)

    return app
