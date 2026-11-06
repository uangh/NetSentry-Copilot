"""有界StateGraph：只读调查、真实检索、强校验、持久化人工审核。"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from threading import RLock
import time
from uuid import uuid4

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import interrupt, Command
from langsmith import tracing_context
from pydantic import TypeAdapter

from netsentry.api.schemas import Identifier
from .schemas import State, Limits, Choice, Plan, Review
from .knowledge import KnowledgeIndex
from .tools import M3Tools, ToolError
from .reporting import build_report, validate_report, facts_and_references
from .llm import LocalLLM


class BusyError(RuntimeError):pass
class ReviewConflict(ValueError):pass


class InvestigationEngine:
    supports_gemini=False

    def initial_provider_state(self, mode: str) -> dict:return {}

    def __init__(self, checkpoint: Path, tools: M3Tools, *, knowledge: KnowledgeIndex | None=None,
                 limits: Limits | None=None, llm=None) -> None:
        self.tools=tools;self.knowledge=knowledge or KnowledgeIndex.default();self.limits=limits or Limits();self.llm=llm
        checkpoint=Path(checkpoint);checkpoint.parent.mkdir(parents=True,exist_ok=True)
        self.connection=sqlite3.connect(checkpoint,check_same_thread=False,timeout=2)
        self.checkpointer=SqliteSaver(self.connection);self.lock=RLock()
        graph=StateGraph(State)
        for name in ('load_alert','validate_context','plan_investigation','execute_tool','summarize_evidence',
                     'retrieve_knowledge','assess_evidence','validate_report','human_review','revise_report','finalize_report','failed'):
            graph.add_node(name,getattr(self,'node_'+name))
        graph.add_edge(START,'load_alert')
        graph.add_conditional_edges('load_alert',lambda s:'validate_context' if s.get('alert_detail') else 'failed')
        graph.add_conditional_edges('validate_context',lambda s:'retrieve_knowledge' if s.get('stop_reason') else 'plan_investigation')
        graph.add_conditional_edges('plan_investigation',lambda s:'execute_tool' if s['pending_actions'] else 'retrieve_knowledge')
        graph.add_conditional_edges('execute_tool',lambda s:'execute_tool' if s['pending_actions'] and not s.get('stop_reason') else 'summarize_evidence')
        graph.add_conditional_edges('summarize_evidence',lambda s:'plan_investigation' if self.can_plan(s) else 'retrieve_knowledge')
        graph.add_edge('retrieve_knowledge','assess_evidence');graph.add_edge('assess_evidence','validate_report')
        graph.add_conditional_edges('validate_report',lambda s:'human_review' if s.get('draft_report') else 'failed')
        graph.add_conditional_edges('human_review',lambda s:'revise_report' if s['review_history'][-1]['reviewer_decision']=='request_revision' else 'finalize_report')
        graph.add_edge('revise_report','validate_report');graph.add_edge('finalize_report',END);graph.add_edge('failed',END)
        self.graph=graph.compile(checkpointer=self.checkpointer,name='netsentry_m4_investigation')

    def close(self) -> None:
        self.connection.close();self.tools.close()

    @staticmethod
    def config(identifier: str) -> dict:
        TypeAdapter(Identifier).validate_python(identifier)
        return {'configurable':{'thread_id':identifier},'recursion_limit':40}

    @staticmethod
    def step(state: dict, name: str) -> None:state['investigation_steps']=[*state['investigation_steps'],name]

    def can_plan(self, state: dict) -> bool:
        return not state.get('stop_reason') and state['plan_iterations']<state['limits']['max_plans'] and state['calls_used']<state['limits']['max_calls'] and time.time()<state['deadline']

    def call(self, state: dict, name: str, parameters: dict) -> dict | None:
        key=json.dumps([name,parameters],sort_keys=True);call_id=uuid4().hex
        trace={'call_id':call_id,'tool':name,'parameters':parameters,'status':'ok','duration_ms':0.,'returned_count':0,
               'source_references':[],'http_trace_id':None}
        if key in state['seen_calls']:
            trace['status']='duplicate_blocked';state['stop_reason']='duplicate_tool_call'
        elif state['calls_used']>=state['limits']['max_calls'] or time.time()>=state['deadline']:
            trace['status']='budget_blocked';state['stop_reason']='budget_exhausted'
        else:
            state['seen_calls']=[*state['seen_calls'],key];state['calls_used']+=1;started=time.perf_counter()
            self.tools.last_request=None
            try:
                if name=='get_alert_detail':result=self.tools.get_alert_detail(**parameters,deadline=state['deadline'])
                elif name=='get_anchor_flow':result=self.tools.get_anchor_flow(**parameters,deadline=state['deadline'])
                elif name=='query_related_evidence':result=self.tools.query_related_evidence(**parameters,deadline=state['deadline'])
                elif name=='query_host_flows':result=self.tools.query_host_flows(state['anchor_flow'],**parameters,deadline=state['deadline'])
                elif name in ('summarize_host_behavior','analyze_port_distribution','analyze_temporal_bursts','build_flow_timeline','expand_evidence_page'):
                    from .analysis_tools import run_analysis
                    result=run_analysis(self.tools,state['anchor_flow'],name,parameters,state['deadline'])
                else:raise ToolError('unapproved_tool')
                if name=='query_related_evidence' and result['anchor']!=state['anchor_flow']:
                    raise ToolError('evidence_anchor_context_mismatch')
                trace['returned_count']=len(result.get('records',[])) if 'records' in result else 1
                trace['http_trace_id']=self.tools.last_trace
                trace['http_request']=getattr(self.tools,'last_request',None)
                sources=[result.get('source_sha256'),result.get('alert',{}).get('source_sha256'),result.get('anchor',{}).get('source_sha256')]
                sources += [r.get('source_sha256') for r in result.get('records',[])]
                trace['source_references']=sorted({s for s in sources if s})
                state['observations']=[*state['observations'],{'call_id':call_id,'tool':name,'parameters':parameters,'result':result}]
                trace['duration_ms']=(time.perf_counter()-started)*1000
                state['tool_call_history']=[*state['tool_call_history'],trace]
                return result
            except (ToolError,ValueError,KeyError) as exc:
                trace['status']='error';state['stop_reason']='tool_unavailable_or_invalid'
                trace['http_request']=getattr(self.tools,'last_request',None)
                state['missing_information']=[*state['missing_information'],name+': unavailable or invalid response']
                trace['duration_ms']=(time.perf_counter()-started)*1000
        state['tool_call_history']=[*state['tool_call_history'],trace]
        return None

    def node_load_alert(self, state: State) -> State:
        self.step(state,'load_alert');result=self.call(state,'get_alert_detail',{'alert_id':state['alert_id']})
        state['alert_detail']=result
        if result:state['model_context']={k:result['alert'][k] for k in ('model_id','model_version','model_status','attack_related_score','feature_contract_version')}
        return state

    def node_validate_context(self, state: State) -> State:
        self.step(state,'validate_context')
        flow=self.call(state,'get_anchor_flow',{'record_id':state['alert_detail']['alert']['record_id']})
        if flow:
            if flow!=state['alert_detail']['flow']:
                state['stop_reason']='context_mismatch';state['missing_information'].append('M3锚点与告警上下文不一致')
            else:state['anchor_flow']=flow
        if not state.get('anchor_flow') or not state['anchor_flow'].get('timestamp') or not any(state['anchor_flow'].get(k) for k in ('source_ip','destination_ip')):
            state['stop_reason']=state.get('stop_reason') or 'insufficient_metadata'
            state['missing_information'].append('缺少可查询的锚点时间或两端IP，不猜测地址')
        return state

    def node_plan_investigation(self, state: State) -> State:
        self.step(state,'plan_investigation');state['plan_iterations']+=1
        if time.time()>=state['deadline'] or state['calls_used']>=state['limits']['max_calls']:
            state['stop_reason']='budget_exhausted';state['pending_actions']=[];return state
        window=state['limits']['window_seconds'];limit=state['limits']['page_size'];flow=state['anchor_flow']
        if state['mode']=='llm_agent':
            context={'has_source_ip':flow['source_ip'] is not None,'has_destination_ip':flow['destination_ip'] is not None,
                     'iteration':state['plan_iterations'],'remaining_calls':state['limits']['max_calls']-state['calls_used'],
                     'summaries':state['summaries'],'available_tools':['query_related_evidence','query_host_flows','stop']}
            try:
                plan=Plan.model_validate(self.llm.plan(context,state['deadline']))
                state['llm_events'].append({'purpose':'planning','status':'validated'})
            except Exception:
                state['llm_events'].append({'purpose':'planning','status':'rejected'});state['stop_reason']='invalid_llm_plan'
                state['pending_actions']=[];return state
        else:
            if state['plan_iterations']==1:
                actions=[{'tool':'query_related_evidence','window_seconds':window,'limit':limit}]
            else:
                side='source' if flow['source_ip'] else 'destination'
                actions=[{'tool':'query_host_flows','endpoint':side,'window_seconds':window,'limit':limit}]
                if flow['source_ip'] and flow['destination_ip'] and flow['source_ip']!=flow['destination_ip']:
                    actions.append({'tool':'query_host_flows','endpoint':'destination','window_seconds':window,'limit':limit})
            plan=Plan(actions=actions)
        state['pending_actions']=[]
        for choice in plan.actions:
            if choice.tool=='stop':state['stop_reason']='planner_stopped';break
            if choice.limit>limit or choice.window_seconds>window:
                state['stop_reason']='plan_exceeds_configured_budget';break
            if choice.tool=='query_host_flows' and flow[choice.endpoint+'_ip'] is None:
                state['stop_reason']='insufficient_metadata';break
            state['pending_actions'].append(choice.model_dump())
        if state.get('stop_reason'):state['pending_actions']=[]
        return state

    def node_execute_tool(self, state: State) -> State:
        self.step(state,'execute_tool');choice=Choice.model_validate(state['pending_actions'].pop(0))
        parameters={'window_seconds':choice.window_seconds,'limit':choice.limit,'offset':choice.offset}
        if choice.tool=='query_related_evidence':parameters|={'alert_id':state['alert_id'],'record_id':state['anchor_flow']['record_id']}
        else:parameters['endpoint']=choice.endpoint
        if choice.tool=='query_related_evidence' and state['mode']=='gemini_llm':parameters['endpoint']=choice.endpoint
        result=self.call(state,choice.tool,parameters)
        if result and choice.tool=='query_related_evidence':
            state['collected_evidence']+=result['records']
            for evidence in result['records']:
                if evidence['association_status']=='candidate_unverified':
                    state['candidate_relations'].append({'reference_id':evidence['evidence_id'],
                        'source_record_id':evidence['source_record_id'],'related_record_id':evidence['related_record_id'],
                        'association_status':'candidate_unverified'})
        if result and result.get('has_more'):
            state['confidence_limitations'].append('结果过多，仅保存受限页面；total不等于已逐条审查数量')
        return state

    def node_summarize_evidence(self, state: State) -> State:
        self.step(state,'summarize_evidence')
        state['summaries']=[{'tool':o['tool'],'returned':len(o['result']['records']),'total':o['result']['total'],
            'has_more':o['result']['has_more']} for o in state['observations'] if 'records' in o['result']]
        if state['summaries'] and all(s['total']==0 for s in state['summaries']):state['missing_information'].append('受限查询没有候选记录')
        if not self.can_plan(state) and not state.get('stop_reason'):state['stop_reason']='bounded_investigation_complete'
        return state

    def node_retrieve_knowledge(self, state: State) -> State:
        self.step(state,'retrieve_knowledge')
        query='candidate evidence review network endpoint time'
        if state.get('stop_reason')=='insufficient_metadata':query+=' missing endpoint timestamp'
        if any(s['has_more'] for s in state['summaries']):query+=' partial page observation limits'
        query+=' missing authentication independent evidence'
        started=time.perf_counter();hits=self.knowledge.search(query,3);state['knowledge_references']=hits
        state['tool_call_history'].append({'call_id':uuid4().hex,'tool':'search_security_knowledge',
            'parameters':{'query':query,'top_k':3},'status':'ok','duration_ms':(time.perf_counter()-started)*1000,
            'returned_count':len(hits),'source_references':[h['chunk_id'] for h in hits],'http_trace_id':None})
        if not hits:state['missing_information'].append('本地知识库无相关命中')
        return state

    def node_assess_evidence(self, state: State) -> State:
        self.step(state,'assess_evidence');state['review_status']='pending_review'
        if state['mode']=='llm_agent' and time.time()<state['deadline']:
            facts,_=facts_and_references(state)
            context={'facts':[{'fact_id':f['fact_id'],'field':f['field']} for f in facts],
                     'knowledge':[{'document_id':h['document_id'],'title':h['title'],'text':h['text']} for h in state['knowledge_references']]}
            try:
                state['narrative']=self.llm.narrate(context,state['deadline'])
                build_report(state);state['llm_events'].append({'purpose':'narrative','status':'validated'})
            except Exception:
                state['narrative']=None;state['llm_events'].append({'purpose':'narrative','status':'rejected_template_fallback'})
                state['confidence_limitations'].append('LLM叙述未通过契约，使用确定性报告内容')
        state['draft_report']=build_report(state);return state

    def node_validate_report(self, state: State) -> State:
        self.step(state,'validate_report')
        try:state['draft_report']=validate_report(state['draft_report'],state)
        except ValueError:
            state['draft_report']=None;state['stop_reason']='report_validation_failed'
        return state

    def node_human_review(self, state: State) -> State:
        # interrupt前无写入或HTTP副作用；恢复只在此重入。
        decision=Review.model_validate(interrupt({'investigation_id':state['investigation_id'],
            'report_version':state['report_version'],'review_status':'pending_review'}))
        self.step(state,'human_review')
        state['review_history'].append({'request_id':decision.request_id,'reviewer_decision':decision.decision,
            'reviewer_note':decision.note,'reviewed_at':datetime.now(timezone.utc).isoformat(),
            'investigation_id':state['investigation_id'],'report_version':state['report_version']})
        return state

    def node_revise_report(self, state: State) -> State:
        self.step(state,'revise_report');state['report_version']+=1;state['narrative']=None
        state['confidence_limitations'].append('人工请求修订：保留原证据，审阅备注不自动成为网络事实')
        state['draft_report']=build_report(state);return state

    def node_finalize_report(self, state: State) -> State:
        self.step(state,'finalize_report')
        state['review_status']='approved' if state['review_history'][-1]['reviewer_decision']=='approve' else 'rejected'
        state['draft_report']=build_report(state);validate_report(state['draft_report'],state);return state

    def node_failed(self, state: State) -> State:
        self.step(state,'failed');state['review_status']='failed';state['draft_report']=None;return state

    def start(self, alert_id: str, mode: str='offline') -> dict:
        TypeAdapter(Identifier).validate_python(alert_id)
        supported=mode in ('offline','llm_agent') or (mode=='gemini_llm' and self.supports_gemini) or (mode in ('gemini_multistep','enhanced_deterministic_baseline') and getattr(self,'supports_multistep',False))
        if not supported:raise ValueError('未知模式')
        if mode=='llm_agent' and self.llm is None:self.llm=LocalLLM()
        if not self.lock.acquire(timeout=0.1):raise BusyError('investigation_busy')
        try:
            iid=uuid4().hex
            state={'investigation_id':iid,'alert_id':alert_id,'mode':mode,'model_context':{},'anchor_flow':{},
                'collected_evidence':[],'candidate_relations':[],'knowledge_references':[],'tool_call_history':[],
                'investigation_steps':[],'missing_information':[],'confidence_limitations':[], 'draft_report':None,
                'review_status':'running','stop_reason':None,'alert_detail':None,'observations':[],
                'plan_iterations':0,'pending_actions':[],'calls_used':0,'seen_calls':[],
                'deadline':time.time()+self.limits.total_seconds,'report_version':1,
                'generated_at':datetime.now(timezone.utc).isoformat(),'narrative':None,'review_history':[],
                'limits':self.limits.model_dump(),'summaries':[],'llm_events':[]}
            state.update(self.initial_provider_state(mode))
            with tracing_context(enabled=False):self.graph.invoke(state,self.config(iid))
            return self.status(iid)
        finally:self.lock.release()

    def status(self, iid: str) -> dict:
        snapshot=self.graph.get_state(self.config(iid));state=dict(snapshot.values)
        if not state:raise KeyError('investigation_not_found')
        return {'investigation_id':iid,'thread_id':iid,'alert_id':state['alert_id'],'review_status':state['review_status'],
            'report_version':state['report_version'],'stop_reason':state['stop_reason'],
            'investigation_steps':state['investigation_steps'],'report':state['draft_report'],
            'remaining_external_calls':max(0,state['limits']['max_calls']-state['calls_used']),
            'external_calls_used':state['calls_used'],'planning_iterations':state['plan_iterations'],
            'review_history':state['review_history'],'llm_events':state['llm_events'],'interrupted':bool(snapshot.interrupts)}

    def get_investigation_status(self, iid: str) -> dict:return self.status(iid)

    def review(self, iid: str, payload: Review) -> dict:
        if not self.lock.acquire(timeout=0.1):raise BusyError('investigation_busy')
        try:
            current=self.status(iid)
            for previous in current['review_history']:
                if previous['request_id']==payload.request_id:
                    if previous['reviewer_decision']!=payload.decision or previous['reviewer_note']!=payload.note or previous['report_version']!=payload.expected_version:
                        raise ReviewConflict('idempotency_key_conflict')
                    return current
            if not current['interrupted'] or current['review_status']!='pending_review' or payload.expected_version!=current['report_version']:
                raise ReviewConflict('stale_or_final_review')
            if payload.decision=='request_revision' and current['report_version']>=3:raise ReviewConflict('revision_budget_exhausted')
            with tracing_context(enabled=False):self.graph.invoke(Command(resume=payload.model_dump()),self.config(iid))
            return self.status(iid)
        finally:self.lock.release()
