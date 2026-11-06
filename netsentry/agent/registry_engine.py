"""M6.3.1契约适配：不增加工具、不替换模型动作，沿用M6.3图和执行器。"""
from pydantic import ValidationError
from .multistep_engine import MultiStepEngine
from .observation_registry import register,catalog,PlanningAction,planning_schema,digest
from .multistep_protocol import GOALS


class RegistryEngine(MultiStepEngine):
    def initial_provider_state(self,mode: str) -> dict:
        state=super().initial_provider_state(mode)
        if mode=='gemini_multistep':
            state['observation_registry']=[];state['planning_attempts']=[]
            state['multistep']['protocol']='m6.3.1.v1'
        return state

    def node_validate_context(self,state: dict) -> dict:
        state=super().node_validate_context(state)
        if state['mode']=='gemini_multistep':register(state)
        return state

    def planning_context(self,state: dict) -> dict:
        if state['mode']!='gemini_multistep':return super().planning_context(state)
        rows=catalog(state);analyses=[r for r in rows if r['kind'] in ('analysis','knowledge')]
        previous=analyses[-1] if analyses else None
        return {'iteration':state['plan_iterations'],'observations':rows,
            'allowed_observation_ids':[r['observation_id'] for r in rows],
            'previous_observation_summary':previous,
            'latest_tool_observation_id':previous['observation_id'] if previous else None,
            'tools_already_used':[{'tool':o['tool'],'arguments':o['parameters']} for o in state['observations'] if o['tool'] not in ('get_alert_detail','get_anchor_flow')],
            'remaining_budget':{'planning_including_current':state['limits']['max_plans']+1-state['plan_iterations'],
                'http':8-state['calls_used'],'report_requests_reserved':1},
            'missing_evidence':['No independent authentication, host or service health logs.'],
            'tool_catalog':{g:sorted(t) for g,t in GOALS.items()},
            'rules':'Choose one useful action or an explicit stop; no prescribed tool sequence. '
                'Cite supporting_observation_ids ONLY from the supplied short-ID list. Initial alert and anchor are real registered observations. '
                'After a tool result, cite latest_tool_observation_id to explain the next observable question or stop. '
                'Do not produce record_id, evidence_id, call_id or hashes: Python owns their source mapping. '
                'Host tools require a valid anchor endpoint IP and timestamp. endpoint selects source/destination anchor IP on either flow side. '
                'All five analysis tools: half-open centered total window10..300 sec, center_offset_seconds -120..120, limit1..10; '
                'bucket_seconds only5/10/30/60. summarize_host_behavior gives peers/ports/direction counts; analyze_port_distribution gives either-endpoint port frequencies; '
                'analyze_temporal_bursts gives sampled record density, not bandwidth; build_flow_timeline orders returned records; '
                'expand_evidence_page requires a previous analysis query with same endpoint/window/center and a new offset<=1000. '
                'Other tools use offset0; legacy query_related_evidence and query_host_flows require window<=60 and center0. '
                'Legacy related uses closed +/-floor(span/2); legacy host is half-open. '
                'search_security_knowledge is a fixed local query and produces reference knowledge, never network facts. '
                'Never repeat the same effective query; sampled counts do not prove attacks. DEV_ONLY score is uncalibrated. '
                'stop uses goal evidence_sufficiency and decision stop_insufficient_evidence, stop_sufficient_for_report, or request_external_evidence. '
                'External evidence request stops for human input, not an actual network query. Keep public reasons short.'}

    def planning_action(self,state: dict,ctx: dict) -> dict:
        if state['mode']!='gemini_multistep':return super().planning_action(state,ctx)
        attempt={'round_number':state['plan_iterations'],'allowed_observation_ids':ctx['allowed_observation_ids'],
                 'latest_tool_observation_id':ctx['latest_tool_observation_id'],'input_projection':ctx,
                 'input_projection_sha256':digest(ctx),'status':'requested'}
        state['planning_attempts'].append(attempt)
        try:
            raw=self.active.generate('multistep_planning',ctx,planning_schema(ctx['allowed_observation_ids']),state['deadline'])
            plan=PlanningAction.model_validate(raw)
            if any(i not in ctx['allowed_observation_ids'] for i in plan.supporting_observation_ids):raise ValueError('unknown_observation_reference')
            if ctx['latest_tool_observation_id'] and ctx['latest_tool_observation_id'] not in plan.supporting_observation_ids:raise ValueError('latest_observation_not_acknowledged')
            attempt.update(status='contract_validated',raw_structured_action=raw)
            return {'goal':plan.investigation_goal,'action':plan.action,'arguments':plan.arguments.model_dump(),
                    'based_on_observation_ids':plan.supporting_observation_ids,'question':plan.question,'reason':plan.reason,
                    'decision':plan.decision,'missing_evidence':[],'expected_information':plan.question}
        except (ValueError,RuntimeError) as exc:
            code=str(exc) if str(exc) in ('unknown_observation_reference','latest_observation_not_acknowledged') else 'provider_or_schema_validation_failed'
            attempt.update(status='rejected',validation_error={'code':code,'allowed_observation_ids':ctx['allowed_observation_ids']})
            raise

    def node_plan_investigation(self,state: dict) -> dict:
        state=super().node_plan_investigation(state)
        if state['mode']=='gemini_multistep':
            attempt=state['planning_attempts'][-1]
            if state['gemini']['status']=='failed' and attempt['status']=='contract_validated':
                attempt.update(status='rejected',validation_error={'code':state['multistep'].get('rejection_reason','local_plan_rejected')})
            if state['decision_trace'] and state['decision_trace'][-1]['iteration']==state['plan_iterations']:
                d=state['decision_trace'][-1];c=state['gemini']['calls'][-1]
                d.update(round_number=d['iteration'],model_name=state['gemini']['model'],observation_ids_used=d['evidence_references'],
                    input_tokens=c.get('input_tokens'),output_tokens=c.get('output_tokens'),known_total_tokens=c.get('total_tokens'),
                    request_duration_ms=c['duration_ms'],new_observation_ids=[])
        return state

    def node_execute_tool(self,state: dict) -> dict:
        before={r['observation_id'] for r in state.get('observation_registry',[])}
        state=super().node_execute_tool(state)
        if state['mode']=='gemini_multistep':
            register(state);d=state['decision_trace'][-1]
            d['new_observation_ids']=[r['observation_id'] for r in state['observation_registry'] if r['observation_id'] not in before]
            d['tool_http_trace_id']=state['tool_call_history'][-1].get('http_trace_id')
        return state

    def status(self,iid: str) -> dict:
        result=super().status(iid);state=dict(self.graph.get_state(self.config(iid)).values)
        if state.get('observation_registry') is not None:
            result.update(observation_registry=state['observation_registry'],planning_attempts=state.get('planning_attempts',[]))
        return result
