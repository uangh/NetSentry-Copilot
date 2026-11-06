"""Gemini node overrides; offline path and M3 tool execution remain unchanged."""
import time
import os
from .engine import InvestigationEngine, BusyError
from .gemini_adapter import GeminiAdapter, GeminiError, GeminiPlan
from .reporting import build_report, facts_and_references
from .gemini_protocol import planning_context, report_context


class GeminiInvestigationEngine(InvestigationEngine):
    supports_gemini=True

    def __init__(self, *args, adapter_factory=GeminiAdapter, **kwargs) -> None:
        self.gemini_seconds=kwargs['limits'].total_seconds if kwargs.get('limits') else 150
        self.gemini_plan_limit=int(os.environ.get('NETSENTRY_GEMINI_PLAN_LIMIT','2'))
        if self.gemini_plan_limit not in (1,2):raise ValueError('Gemini planning limit must be 1 or 2')
        self.adapter_factory=adapter_factory;self.active=None
        self.provider_status={'provider':'Google Gemini','ready':False,'configured':False,
            'generation_verified':False,'model':None,'models':[],'status':'not_checked'}
        super().__init__(*args,**kwargs)

    def start(self, alert_id: str, mode: str='offline') -> dict:
        if mode not in ('gemini_llm','gemini_multistep'):return super().start(alert_id,mode)
        if not self.lock.acquire(timeout=.1):raise BusyError('investigation_busy')
        try:
            self.active=self.adapter_factory()
            if mode=='gemini_multistep':self.active.max_requests=4
            # Discovery does not use a generation request. Never silently switch after a failed generation.
            self.provider_status=self.active.probe()
            if not self.provider_status['ready']:raise GeminiError(self.provider_status['status'])
            return super().start(alert_id,mode)
        finally:
            if self.active:self.active.close()
            self.active=None;self.lock.release()

    def initial_provider_state(self, mode: str) -> dict:
        if mode not in ('gemini_llm','gemini_multistep'):return {}
        return {'deadline':time.time()+self.gemini_seconds,
            'limits':self.limits.model_dump()|{'max_plans':min(self.limits.max_plans,self.gemini_plan_limit),'total_seconds':self.gemini_seconds},
            'gemini':{'provider':'Google Gemini','model':self.active.model,'config_source':self.active.connection.get('config_source','injected_provider'),
            'started_at_epoch':time.time(),'duration_ms':0.,'calls':[],'decisions':[],
            'status':'running','generation_verified':False,'report_validated':False,
            'verification_status':'NOT_VERIFIED','live_provider_verified':False,'step_timings':[],
            'total_budget_seconds':self.gemini_seconds,'single_call_budget_seconds':60}}

    @staticmethod
    def finish_step(state: dict) -> None:
        active=state.get('gemini',{}).pop('active_step',None)
        if active:state['gemini']['step_timings'].append({'step':active['step'],'duration_ms':round((time.time()-active['started'])*1000,2)})

    def step(self, state: dict, name: str) -> None:
        if state.get('mode') in ('gemini_llm','gemini_multistep') and state.get('gemini'):
            self.finish_step(state);state['gemini']['active_step']={'step':name,'started':time.time()}
        super().step(state,name)

    def sync(self, state: dict) -> None:
        if self.active is None:return
        state['gemini']['calls']=[c.copy() for c in self.active.calls]
        state['gemini']['generation_verified']=self.active.connection['generation_verified']
        state['gemini']['live_provider_verified']=bool(self.active.live_provider and self.active.connection['generation_verified'])
        self.provider_status.update(self.active.connection)
        state['gemini']['duration_ms']=round((time.time()-state['gemini']['started_at_epoch'])*1000,2)

    def fail(self, state: dict, code: str) -> dict:
        state['gemini']['status']='failed';state['gemini']['failure']=code
        state['gemini']['verification_status']='PARTIALLY_VERIFIED' if state['gemini']['decisions'] else 'NOT_VERIFIED'
        state['stop_reason']=code;state['pending_actions']=[]
        state['llm_events'].append({'purpose':'gemini','status':code});self.sync(state);return state

    def node_plan_investigation(self, state: dict) -> dict:
        if state['mode'] not in ('gemini_llm','gemini_multistep'):return super().node_plan_investigation(state)
        self.step(state,'plan_investigation');state['plan_iterations']+=1
        context=planning_context(state)
        try:
            plan=GeminiPlan.model_validate(self.active.plan(context,state['deadline']))
            state['gemini']['decisions'].append({'iteration':state['plan_iterations'],**plan.model_dump()})
            state['gemini']['verification_status']='PARTIALLY_VERIFIED'
            state['pending_actions']=[]
            for choice in plan.actions:
                if choice.tool=='stop':state['stop_reason']='planner_stopped';state['pending_actions']=[];break
                if choice.limit>min(10,state['limits']['page_size']) or choice.window_seconds>state['limits']['window_seconds']:
                    return self.fail(state,'plan_exceeds_configured_budget')
                if not state['anchor_flow'].get(choice.endpoint+'_ip'):
                    return self.fail(state,'insufficient_metadata')
                state['pending_actions'].append(choice.model_dump())
            state['llm_events'].append({'purpose':'planning','status':'validated'})
        except (GeminiError,ValueError):return self.fail(state,'gemini_plan_failed')
        self.sync(state);return state

    def node_assess_evidence(self, state: dict) -> dict:
        if state['mode'] not in ('gemini_llm','gemini_multistep'):return super().node_assess_evidence(state)
        self.step(state,'assess_evidence')
        if state['gemini']['status']=='failed':state['draft_report']=None;return state
        try:
            facts,_=facts_and_references(state)
            state['narrative']=self.active.narrate(report_context(state,facts),state['deadline'])
            # Narrow narrative references to the bounded facts actually shown to the model.
            allowed={f['fact_id'] for f in report_context(state,facts)['facts']}
            if any(fid not in allowed for paragraph in state['narrative']['paragraphs'] for fid in paragraph['fact_ids']):
                raise ValueError('reference_outside_supplied_context')
            state['review_status']='pending_review';state['draft_report']=build_report(state)
            state['llm_events'].append({'purpose':'narrative','status':'validated'})
        except (GeminiError,ValueError):
            state['draft_report']=None;return self.fail(state,'gemini_report_failed')
        self.sync(state);return state

    def node_validate_report(self, state: dict) -> dict:
        if state['mode'] not in ('gemini_llm','gemini_multistep'):return super().node_validate_report(state)
        if state['gemini']['status']=='failed':return state
        state=super().node_validate_report(state)
        state['gemini']['report_validated']=state['draft_report'] is not None
        state['gemini']['status']='completed' if state['draft_report'] else 'failed'
        tool_verified=any(o['tool'] in ('query_host_flows','query_related_evidence') for o in state['observations'])
        state['gemini']['verification_status']='VERIFIED' if state['draft_report'] and tool_verified else 'PARTIALLY_VERIFIED'
        self.finish_step(state)
        return state

    def node_revise_report(self, state: dict) -> dict:
        if state['mode'] in ('gemini_llm','gemini_multistep'):
            state['confidence_limitations'].append('人工修订使用原证据确定性重建，没有新增Gemini请求或网络事实')
        return super().node_revise_report(state)

    def node_failed(self, state: dict) -> dict:
        if state['mode'] in ('gemini_llm','gemini_multistep'):
            state['gemini']['status']='failed'
            state['gemini']['failure']=state.get('stop_reason') or 'investigation_failed'
            self.sync(state)
            state['gemini']['verification_status']='PARTIALLY_VERIFIED' if state['gemini']['decisions'] else 'NOT_VERIFIED'
        result=super().node_failed(state);self.finish_step(state);return result

    def status(self, iid: str) -> dict:
        result=super().status(iid)
        state=dict(self.graph.get_state(self.config(iid)).values)
        if state.get('gemini'):result['gemini']=state['gemini']
        return result
