"""复用原StateGraph循环、HTTP预算、引用校验与HITL；新协议独立保留旧模式。"""
import hashlib,json,time,os
from .gemini_engine import GeminiInvestigationEngine
from .engine import InvestigationEngine
from .gemini_adapter import GeminiError
from .multistep_protocol import MultiDecision,context,summarize
from .reporting import facts_and_references,build_report
from .gemini_protocol import report_context
from netsentry.services.flow_analysis import TOOLS

MODES=('gemini_multistep','enhanced_deterministic_baseline')


def baseline_decision(ctx: dict) -> dict:
    """透明规则基线：概览→按观察选择端口/时间→覆盖扩展或时间线；可提前停止。"""
    endpoint='source' if ctx['anchor']['source_ip'] else 'destination'
    args={'endpoint':endpoint,'window_seconds':60,'limit':10,'offset':0,'bucket_seconds':10,'center_offset_seconds':0}
    prior=ctx['previous_observation_summary'];tool='summarize_host_behavior';goal='host_behavior'
    decision='continue';reason='先统计样本主机行为范围'
    if prior:
        stats=prior['statistics'];n=prior.get('analyzed_count') or prior.get('total') or 0
        if n<=1:tool='stop';goal='evidence_sufficiency';decision='stop_insufficient_evidence';reason='仅有锚点或空结果，需要独立证据'
        elif ctx['iteration']==2 and stats.get('unique_destination_ports',0)>3:
            tool='analyze_port_distribution';goal='port_analysis';reason='概览包含多种目标端口，核对端口记录分布'
        elif ctx['iteration']==2:
            tool='analyze_temporal_bursts';goal='temporal_analysis';reason='样本记录多于锚点，查看时间分布'
        elif prior['has_more']:
            tool='expand_evidence_page';goal='evidence_correlation';reason='已有查询仍有未加载记录，扩展下一页'
            args.update(prior['query']);args['offset']=prior['query']['offset']+prior['loaded']
        else:tool='build_flow_timeline';goal='temporal_analysis';reason='已有分布观察，按时间查看可追溯记录'
    return {'goal':goal,'action':tool,'arguments':args,'question':reason,'reason':reason,
            'expected_information':'有界统计或逐条证据','missing_evidence':['缺少独立认证与主机日志'],
            'based_on_observation_ids':[prior['observation_id']] if prior else [],'decision':decision}


def effective_key(action: str, args: dict) -> str:
    # 忽略对工具没有作用的参数，避免修改bucket等无关字段绕过重复检测。
    keys=['endpoint','window_seconds','center_offset_seconds']
    if action in ('expand_evidence_page','build_flow_timeline','query_related_evidence','query_host_flows'):keys+=['limit','offset']
    if action=='analyze_port_distribution':keys+=['limit']
    if action=='analyze_temporal_bursts':keys+=['bucket_seconds']
    if action=='search_security_knowledge':keys=[]
    return json.dumps([action,{k:args[k] for k in keys}],sort_keys=True)


class MultiStepEngine(GeminiInvestigationEngine):
    supports_multistep=True

    def planning_context(self, state: dict) -> dict:
        return context(state)

    def planning_action(self, state: dict, ctx: dict) -> dict:
        return self.active.generate('multistep_planning',ctx,MultiDecision,state['deadline']) if state['mode']=='gemini_multistep' else baseline_decision(ctx)

    def initial_provider_state(self, mode: str) -> dict:
        result=super().initial_provider_state(mode)
        if mode not in MODES:return result
        plans=int(os.environ.get('NETSENTRY_MULTISTEP_MAX_PLANS','3')) if mode=='gemini_multistep' else 3
        if plans not in (1,2,3):raise ValueError('invalid_multistep_planning_budget')
        if mode=='gemini_multistep':self.active.max_requests=plans+1
        result.update(deadline=time.time()+270,limits={'max_calls':8,'max_plans':plans,'page_size':10,'window_seconds':300,'total_seconds':270},
                      decision_trace=[],multistep={'protocol':'m6.3.v1','effective_queries':[],
                          'baseline':'fixed_observation_rules_v1' if mode==MODES[1] else None,'request_limit':plans+1,'planning_limit':plans})
        if mode=='gemini_multistep':
            result['gemini'].update(total_budget_seconds=270,request_limit=plans+1)
        return result

    def node_plan_investigation(self, state: dict) -> dict:
        if state['mode'] not in MODES:return super().node_plan_investigation(state)
        self.step(state,'plan_investigation');state['plan_iterations']+=1
        ctx=self.planning_context(state);state['pending_actions']=[]
        try:
            raw=self.planning_action(state,ctx)
            plan=MultiDecision.model_validate(raw);args=plan.arguments.model_dump()
            known={o['observation_id'] for o in ctx['observations']}
            if any(ref not in known for ref in plan.based_on_observation_ids):raise ValueError('unknown_observation_reference')
            if ctx['previous_observation_summary'] and ctx['previous_observation_summary']['observation_id'] not in plan.based_on_observation_ids:
                raise ValueError('latest_observation_not_acknowledged')
            trace={'iteration':state['plan_iterations'],'investigation_goal':plan.goal,'tool_selected':plan.action,
                'tool_arguments':args,'question':plan.question,'reason':plan.reason,'expected_information':plan.expected_information,
                'observations_before':ctx['observations'],'new_observations_after':None,
                'evidence_references':plan.based_on_observation_ids,'missing_evidence':plan.missing_evidence,
                'remaining_budget':ctx['remaining_budget'],'decision_to_continue_or_stop':plan.decision,
                'actual_execution_status':'planned','new_record_ids':[],
                'planning_input_sha256':hashlib.sha256(json.dumps(ctx,sort_keys=True).encode()).hexdigest(),
                'planning_input':ctx,'decision_source':state['mode']}
            state['decision_trace'].append(trace)
            if state['mode']=='gemini_multistep':
                state['gemini']['decisions'].append({'iteration':state['plan_iterations'],'reason':plan.reason,
                    'actions':[{'tool':plan.action,**args}]})
                state['gemini']['verification_status']='PARTIALLY_VERIFIED';self.sync(state)
            if plan.action=='stop':
                state['stop_reason']=plan.decision;trace['actual_execution_status']='stopped_without_external_call'
                state['missing_information']+=plan.missing_evidence
                return state
            if plan.action!='search_security_knowledge' and not state['anchor_flow'].get(args['endpoint']+'_ip'):
                raise ValueError('insufficient_metadata')
            key=effective_key(plan.action,args)
            if key in state['multistep']['effective_queries']:
                trace['actual_execution_status']='duplicate_blocked';state['stop_reason']='duplicate_tool_call';return state
            if plan.action=='expand_evidence_page':
                matching=[o for o in state['observations'] if o['tool'] in TOOLS and all(o['parameters'].get(k)==args[k] for k in ('endpoint','window_seconds','center_offset_seconds'))]
                if not matching:raise ValueError('paging_context_missing')
                last=matching[-1]['result']
                if not last['has_more'] or args['offset']<last['offset']+len(last['records']):raise ValueError('paging_not_new')
            state['multistep']['effective_queries'].append(key)
            state['pending_actions']=[{'tool':plan.action,**args}]
        except (GeminiError,ValueError) as exc:
            if state.get('decision_trace') and state['decision_trace'][-1]['iteration']==state['plan_iterations']:
                state['decision_trace'][-1]['actual_execution_status']='rejected'
            # Only bounded local codes, never raw SDK errors or untrusted model text.
            state['multistep']['rejected_decision']='structured_or_context_validation_failed'
            allowed_codes={'unknown_observation_reference','latest_observation_not_acknowledged','insufficient_metadata','paging_context_missing','paging_not_new'}
            state['multistep']['rejection_reason']=str(exc) if str(exc) in allowed_codes else 'provider_or_schema_validation_failed'
            if state['mode']=='gemini_multistep':return self.fail(state,'multistep_plan_failed')
            state['stop_reason']='invalid_baseline_plan'
        return state

    def node_summarize_evidence(self, state: dict) -> dict:
        result=super().node_summarize_evidence(state)
        if state['mode'] in MODES and state.get('stop_reason')=='bounded_investigation_complete':
            state['stop_reason']='planning_budget_exhausted' if state['plan_iterations']>=3 else 'http_or_time_budget_exhausted'
        return result

    def node_execute_tool(self, state: dict) -> dict:
        if state['mode'] not in MODES:return super().node_execute_tool(state)
        self.step(state,'execute_tool');choice=state['pending_actions'].pop(0);tool=choice.pop('tool')
        trace=state['decision_trace'][-1]
        before={e['related_record_id'] for e in state['collected_evidence']}|{state['anchor_flow']['record_id']}
        for o in state['observations']:
            if o['tool']=='query_host_flows':before.update(r['record_id'] for r in o['result']['records'])
        if tool=='search_security_knowledge':
            self.node_retrieve_knowledge(state);trace['actual_execution_status']='executed_local_knowledge'
            observation={'call_id':state['tool_call_history'][-1]['call_id'],'tool':tool,'parameters':{},
                'result':{'statistics':{'knowledge_reference_count':len(state['knowledge_references'])},
                    'knowledge':[{'chunk_id':k['chunk_id'],'title':k['title'],'text':k['text'][:240]} for k in state['knowledge_references']]}}
            state['observations'].append(observation)
            trace['new_observations_after']=summarize(observation)
            trace['result_observation_id']=observation['call_id']
            return state
        parameters=choice.copy()
        if tool in ('query_related_evidence','query_host_flows'):
            parameters={k:choice[k] for k in ('endpoint','window_seconds','limit','offset')}
            if tool=='query_related_evidence':parameters.update(alert_id=state['alert_id'],record_id=state['anchor_flow']['record_id'])
        result=self.call(state,tool,parameters)
        trace['actual_execution_status']='executed' if result else 'failed'
        if not result:
            if state['mode']=='gemini_multistep':return self.fail(state,'multistep_tool_failed')
            return state
        if tool in TOOLS or tool=='query_related_evidence':
            existing={e['evidence_id'] for e in state['collected_evidence']}
            for e in result['records']:
                if e['evidence_id'] not in existing:state['collected_evidence'].append(e);existing.add(e['evidence_id'])
                if e['association_status']=='candidate_unverified' and not any(c['reference_id']==e['evidence_id'] for c in state['candidate_relations']):
                    state['candidate_relations'].append({'reference_id':e['evidence_id'],'source_record_id':e['source_record_id'],
                        'related_record_id':e['related_record_id'],'association_status':'candidate_unverified'})
            ids={e['related_record_id'] for e in result['records']}
        else:ids={r['record_id'] for r in result['records']}
        trace['new_record_ids']=sorted(ids-before)
        trace['new_observations_after']=summarize(state['observations'][-1])
        trace['result_observation_id']=state['observations'][-1]['call_id']
        trace['remaining_http_calls_after']=8-state['calls_used']
        if result.get('has_more') or result.get('scan_truncated'):
            state['confidence_limitations'].append('仅分析受限样本与已加载页面；未加载记录没有逐条审核')
        return state

    def node_assess_evidence(self, state: dict) -> dict:
        if state['mode'] not in MODES:return super().node_assess_evidence(state)
        if state['mode']==MODES[1]:return InvestigationEngine.node_assess_evidence(self,state)
        self.step(state,'assess_evidence')
        if state['gemini']['status']=='failed':state['draft_report']=None;return state
        facts,_=facts_and_references(state)
        # Give the report actual computed observations rather than only anchor fields.
        analysis_facts=[f for f in facts if f['scope'].startswith('bounded_analysis:')]
        refs=list(dict.fromkeys(f['reference_id'] for f in analysis_facts))
        chosen=facts[:2]
        for ref in refs:
            group=[f for f in analysis_facts if f['reference_id']==ref]
            chosen+=group[:2]+[f for f in group if f['field'] in ('unique_peers','unique_destination_ports','top_ports','peak_count','timeline')][:1]
        if len(chosen)<3:chosen=facts[:12]
        ctx=report_context(state,chosen)
        ctx['decision_summary']=[{'iteration':d['iteration'],'question':d['question'],'reason':d['reason'],
            'new_records':len(d['new_record_ids']),'decision':d['decision_to_continue_or_stop']} for d in state['decision_trace']]
        try:
            state['narrative']=self.active.narrate(ctx,state['deadline'])
            allowed={f['fact_id'] for f in ctx['facts']}
            if any(fid not in allowed for p in state['narrative']['paragraphs'] for fid in p['fact_ids']):raise ValueError('reference_outside_context')
            state['review_status']='pending_review';state['draft_report']=build_report(state)
        except (GeminiError,ValueError):
            state['draft_report']=None;return self.fail(state,'gemini_report_failed')
        self.sync(state);return state

    def node_validate_report(self, state: dict) -> dict:
        result=super().node_validate_report(state)
        if state['mode']=='gemini_multistep' and state.get('draft_report'):
            state['gemini']['verification_status']='VERIFIED' if state['decision_trace'] else 'PARTIALLY_VERIFIED'
            state['multistep']['multi_tool_trace_valid']=sum(d['actual_execution_status']=='executed' for d in state['decision_trace'])>=2
            state['multistep']['real_multitool_verified']=state['multistep']['multi_tool_trace_valid'] and state['gemini']['live_provider_verified']
        return result

    def status(self, iid: str) -> dict:
        result=super().status(iid);state=dict(self.graph.get_state(self.config(iid)).values)
        if state.get('multistep'):
            result.update(decision_trace=state.get('decision_trace',[]),multistep=state['multistep'],
                          analysis_results=[o for o in state['observations'] if o['tool'] in TOOLS])
        return result
