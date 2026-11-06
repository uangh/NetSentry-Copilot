"""在原M3应用上挂载调查路由；原告警/流量模块及数据保持不变。"""
from contextlib import asynccontextmanager
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from netsentry.api.main import create_app as create_m3_app, authorize
from netsentry.api.schemas import Identifier
from .engine import InvestigationEngine, BusyError, ReviewConflict
from .schemas import Start, Review
from .recovery_engine import ResumeRequest, RecoveryConflict
from .tools import M3Tools

ROOT=Path(__file__).resolve().parents[2]


def get_engine(request: Request) -> InvestigationEngine:
    return request.app.state.investigations


def create_app(*, base_url: str='http://127.0.0.1:8000', checkpoint: Path | None=None, settings=None,
               services=None, engine: InvestigationEngine | None=None, engine_factory=InvestigationEngine):
    app=create_m3_app(settings,services=services);previous=app.router.lifespan_context
    app.state.investigations=engine
    @asynccontextmanager
    async def lifespan(app):
        async with previous(app):
            if app.state.investigations is None:
                app.state.investigations=engine_factory(checkpoint or ROOT/'outputs/m4/checkpoints.sqlite',M3Tools(base_url))
            try:yield
            finally:
                if engine is None:app.state.investigations.close()
    app.router.lifespan_context=lifespan
    router=APIRouter(prefix='/api/v1/investigations',tags=['investigations'])

    @router.post('',status_code=201,dependencies=[Depends(authorize)])
    def start(body: Start, agent: InvestigationEngine=Depends(get_engine)):
        return agent.start(body.alert_id,body.mode)

    @router.get('/{investigation_id}')
    def status(investigation_id: Identifier,agent: InvestigationEngine=Depends(get_engine)):
        return agent.get_investigation_status(investigation_id)

    @router.get('/{investigation_id}/report')
    def report(investigation_id: Identifier,agent: InvestigationEngine=Depends(get_engine)):
        value=agent.status(investigation_id)['report']
        if value is None:raise HTTPException(409,'report_unavailable')
        return value

    @router.post('/{investigation_id}/review',dependencies=[Depends(authorize)])
    def review(investigation_id: Identifier,body: Review,agent: InvestigationEngine=Depends(get_engine)):
        return agent.review(investigation_id,body)

    @router.post('/{investigation_id}/resume',dependencies=[Depends(authorize)])
    def resume(investigation_id: Identifier,body: ResumeRequest,agent: InvestigationEngine=Depends(get_engine)):
        if not hasattr(agent,'resume_failed_investigation'):raise HTTPException(409,'recovery_unavailable')
        return agent.resume_failed_investigation(investigation_id,body)

    from netsentry.api.main import error_response
    @app.exception_handler(BusyError)
    async def busy(request,exc):return error_response(request,429,'investigation_busy')
    @app.exception_handler(ReviewConflict)
    async def conflict(request,exc):return error_response(request,409,'review_conflict')
    @app.exception_handler(RecoveryConflict)
    async def recovery_conflict(request,exc):return error_response(request,409,'recovery_conflict')
    app.include_router(router)
    return app
