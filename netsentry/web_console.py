"""M5只读产品投影；复用M3/M4，不创建第二套调查或预测逻辑。"""
import argparse
import os
from collections import Counter
from pathlib import Path
from typing import Annotated

from fastapi import Depends, Query
import uvicorn
from netsentry.agent.api import create_app as create_agent_app, get_engine
from netsentry.agent.engine import InvestigationEngine
from netsentry.agent.recovery_engine import RecoveryEngine
from netsentry.agent.gemini_adapter import GeminiError, connection_status
from netsentry.agent.schemas import ToolTrace,KnowledgeHit
from netsentry.api.main import get_services, Services
from netsentry.api.schemas import Identifier, Evidence, Flow, StrictModel

ROOT=Path(__file__).resolve().parents[1]


class InvestigationItem(StrictModel):
    investigation_id: str
    alert_id: str
    review_status: str
    report_version: int
    generated_at: str | None
    reasoning_mode: str


class InvestigationList(StrictModel):
    records: list[InvestigationItem]
    total: int
    scanned: int
    truncated: bool
    counts: dict[str,int]


class EvidenceView(StrictModel):
    records: list[Evidence]
    anchor: Flow | None
    pages: list[dict]
    tool_call_trace: list[ToolTrace]
    missing_information: list[str]
    queried_flows: list[dict]=[]
    knowledge_references: list[KnowledgeHit]=[]


def list_investigations(engine: InvestigationEngine, alert_id: str | None=None) -> dict:
    # 固定只读SQL仅列出根thread；实际状态仍由LangGraph读取，最多1000个。
    engine.checkpointer.setup()
    with engine.checkpointer.cursor(transaction=False) as cursor:
        total=cursor.execute("SELECT COUNT(DISTINCT thread_id) FROM checkpoints WHERE checkpoint_ns='' ").fetchone()[0]
        rows=cursor.execute("SELECT thread_id,MAX(checkpoint_id) AS latest FROM checkpoints WHERE checkpoint_ns='' GROUP BY thread_id ORDER BY latest DESC LIMIT 1000").fetchall()
    items=[]
    for iid,_ in rows:
        status=engine.status(iid);report=status['report']
        if alert_id and status['alert_id']!=alert_id:continue
        items.append({'investigation_id':iid,'alert_id':status['alert_id'],'review_status':status['review_status'],
            'report_version':status['report_version'],'generated_at':report['generated_at'] if report else None,
            'reasoning_mode':report['reasoning_mode'] if report else 'unavailable'})
    return {'records':items,'total':total,'scanned':len(rows),'truncated':total>len(rows),
            'counts':dict(Counter(item['review_status'] for item in items))}


def create_app(*,base_url='http://127.0.0.1:8000',checkpoint=None,settings=None,services=None,engine=None,static_dir=None):
    app=create_agent_app(base_url=base_url,checkpoint=checkpoint or ROOT/'outputs/m5/checkpoints.sqlite',settings=settings,services=services,engine=engine,engine_factory=RecoveryEngine)
    from netsentry.api.main import error_response
    @app.exception_handler(GeminiError)
    async def gemini_error(request,exc):return error_response(request,503,'gemini_unavailable')

    # Cached catalog status: reading the UI never triggers a paid generation.
    status_cache={}
    @app.get('/api/v1/console/gemini')
    def gemini_status(agent: InvestigationEngine=Depends(get_engine)):
        if not status_cache:status_cache.update(connection_status())
        actual=getattr(agent,'provider_status',{})
        return actual if actual.get('status')!='not_checked' and actual else status_cache
    @app.get('/api/v1/console/investigations',response_model=InvestigationList)
    def investigations(alert_id: Annotated[Identifier | None,Query()]=None,agent: InvestigationEngine=Depends(get_engine)):
        return list_investigations(agent,alert_id)

    @app.get('/api/v1/console/runtime')
    def runtime(s: Services=Depends(get_services),agent: InvestigationEngine=Depends(get_engine)) -> dict:
        manifest=s.prediction.manifest
        return {'instance_id':os.environ.get('NETSENTRY_INSTANCE_ID','direct_app'),
            'agent_base_url':getattr(agent.tools,'base_url','injected_tools'),
            'demo_mode':os.environ.get('NETSENTRY_DEMO_MODE','development'),
            'demo_origin':os.environ.get('NETSENTRY_DEMO_ORIGIN',''),
            'record_scope':manifest['record_scope'],'rows':manifest['rows'],'default_model':manifest['default_model'],
            'model_status':manifest['all_models_status'],'ground_truth_read':manifest['ground_truth_read'],
            'test_records_exported':manifest['test_records_exported'],'week2_accessed':manifest['week2_accessed'],
            'source_description':'CIDDS-001 Week1 · every100 system subset',
            'source_url':'https://www.hs-coburg.de/forschung/forschungsbereiche/informatik/cidds-coburg-intrusion-detection-data-sets/',
            'scope_kind':'development_dataset','llm_status':'NOT VERIFIED',
            'limitations':['公开抽样与匿名化端点；源时间时区未核验','DEV_ONLY；未完成正式独立最终验收','流记录不等于连接、登录失败次数或攻击成功']}

    @app.get('/api/v1/console/investigations/{investigation_id}/evidence',response_model=EvidenceView)
    def evidence(investigation_id: Identifier,agent: InvestigationEngine=Depends(get_engine)):
        agent.status(investigation_id)  # 不存在时404，禁止空状态冒充成功。
        state=dict(agent.graph.get_state(agent.config(investigation_id)).values)
        pages=[{'tool':o['tool'],'parameters':o['parameters'],'total':o['result']['total'],
            'returned':len(o['result']['records']),'limit':o['result']['limit'],'offset':o['result']['offset'],
            'has_more':o['result']['has_more']} for o in state['observations'] if 'records' in o['result']]
        return {'records':state['collected_evidence'],'anchor':state.get('anchor_flow') or None,'pages':pages,
                'tool_call_trace':state['tool_call_history'],'missing_information':state['missing_information'],
                'knowledge_references':state['knowledge_references'],
                'queried_flows':[{'flow':r,'call_id':o['call_id'],'parameters':o['parameters']} for o in state['observations']
                    if o['tool']=='query_host_flows' for r in o['result']['records']]}
    if static_dir is not None:
        from netsentry.static_console import mount_console
        mount_console(app,Path(static_dir))
    return app


def main() -> None:
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--checkpoint',type=Path,default=ROOT/'outputs/m5/checkpoints.sqlite')
    parser.add_argument('--alert-db',type=Path)
    parser.add_argument('--static',action='store_true')
    args=parser.parse_args()
    if not 1024<=args.port<=65535:parser.error('非法本地端口')
    from dataclasses import replace
    from netsentry.api.config import Settings
    settings=Settings.from_env()
    if args.alert_db:settings=replace(settings,alert_db=args.alert_db)
    uvicorn.run(create_app(base_url=f'http://127.0.0.1:{args.port}',checkpoint=args.checkpoint,settings=settings,
                static_dir=ROOT/'frontend/dist' if args.static else None),host='127.0.0.1',port=args.port,
                access_log=False,proxy_headers=False,limit_concurrency=32)


if __name__=='__main__':main()
