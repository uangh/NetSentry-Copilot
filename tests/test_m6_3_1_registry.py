"""Reference contracts and evidence feedback; all providers synthetic."""
import json,tempfile,unittest,time
from pathlib import Path
from netsentry.agent.registry_engine import RegistryEngine
from netsentry.agent.observation_registry import register,planning_schema,PlanningAction
from netsentry.agent.multistep_engine import baseline_decision
from netsentry.agent.analysis_tools import run_analysis
from netsentry.services.flow_analysis import TOOLS
from m6_3_fixture import fixture,ReactiveFake,AID,RID


class RegistryFake(ReactiveFake):
    def generate(self,task,ctx,schema,deadline):
        # Reactive rules consume actual synthetic HTTP observations, not a fixed sequence.
        anchor=next(r['values'] for r in ctx['observations'] if r['kind']=='anchor')
        previous=ctx['previous_observation_summary']
        old={'anchor':anchor,'iteration':ctx['iteration'],'previous_observation_summary':
             (previous['values']|{'observation_id':previous['observation_id']}) if previous else None}
        alter=self.alter;self.alter=None
        raw=super().generate(task,old,schema,deadline);self.alter=alter;self.inputs[-1]=ctx
        result={'investigation_goal':raw['goal'],'action':raw['action'],'arguments':raw['arguments'],
                'question':raw['question'],'reason':raw['reason'],'decision':raw['decision'],
                'supporting_observation_ids':[previous['observation_id'] if previous else ctx['observations'][-1]['observation_id']]}
        return alter(result,ctx) if alter else result


class RegistryTests(unittest.TestCase):
    def run_case(self,alter=None,fail_at=None,**options):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        tools,service,requests=fixture(Path(temp.name),**options);fake=RegistryFake(alter,fail_at)
        e=RegistryEngine(Path(temp.name)/'cp',tools,adapter_factory=lambda:fake);self.addCleanup(e.close)
        status=e.start(AID,'gemini_multistep');state=dict(e.graph.get_state(e.config(status['investigation_id'])).values)
        return status,state,fake,e,service

    def test_initial_real_sources_registered(self):
        _,s,f,_,_=self.run_case()
        self.assertEqual([r['kind'] for r in f.inputs[0]['observations']],['alert','anchor'])
        self.assertTrue(all(i.startswith('obs_') for i in f.inputs[0]['allowed_observation_ids']))
        self.assertNotIn(RID,json.dumps(f.inputs[0]));self.assertEqual(s['observation_registry'][1]['record_ids'],[RID])

    def test_record_id_cannot_be_observation(self):
        status,s,_,_,_=self.run_case(alter=lambda p,c:p|{'supporting_observation_ids':[RID]})
        self.assertEqual(status['review_status'],'failed');self.assertEqual(s['calls_used'],2)
        self.assertEqual(s['planning_attempts'][0]['validation_error']['code'],'unknown_observation_reference')

    def test_invented_reference_rejected(self):
        status,_,_,_,_=self.run_case(alter=lambda p,c:p|{'supporting_observation_ids':['obs_fake_99']})
        self.assertEqual(status['review_status'],'failed')

    def test_cross_investigation_reference_rejected(self):
        _,s,_,_,_=self.run_case();foreign=s['observation_registry'][0]['observation_id']
        status,_,_,_,_=self.run_case(alter=lambda p,c:p|{'supporting_observation_ids':[foreign]})
        self.assertEqual(status['review_status'],'failed')

    def test_schema_enumerates_only_current_scope(self):
        model=planning_schema(['obs_abc_01','obs_abc_02'])
        self.assertEqual(model.model_json_schema()['properties']['supporting_observation_ids']['items']['enum'],['obs_abc_01','obs_abc_02'])

    def test_second_input_contains_first_result(self):
        _,s,f,_,_=self.run_case()
        oid=s['decision_trace'][0]['new_observation_ids'][0]
        self.assertEqual(f.inputs[1]['latest_tool_observation_id'],oid)
        row=next(r for r in f.inputs[1]['observations'] if r['observation_id']==oid)
        self.assertEqual(row['values']['statistics']['flow_count'],30)
        self.assertEqual(s['decision_trace'][1]['observation_ids_used'],[oid])

    def test_latest_observation_required_not_just_initial_anchor(self):
        def mutate(p,c):
            if c['iteration']==2:p['supporting_observation_ids']=[c['observations'][1]['observation_id']]
            return p
        status,s,_,_,_=self.run_case(alter=mutate)
        self.assertEqual(status['review_status'],'failed')
        self.assertEqual(s['planning_attempts'][1]['validation_error']['code'],'latest_observation_not_acknowledged')

    def test_registry_idempotent_and_integrity_checked(self):
        _,s,_,_,_=self.run_case();n=len(register(s));self.assertEqual(len(register(s)),n)
        s['observations'][0]['result']['alert']['attack_related_score']=.01
        with self.assertRaisesRegex(ValueError,'integrity'):register(s)

    def test_cross_scope_registry_mapping_rejected(self):
        _,s,_,_,_=self.run_case();s['observation_registry'][0]['investigation_id']='other'
        with self.assertRaisesRegex(ValueError,'integrity'):register(s)

    def test_new_source_has_call_evidence_and_hash(self):
        _,s,_,_,_=self.run_case();entry=s['observation_registry'][2]
        self.assertTrue(entry['evidence_ids']);self.assertEqual(entry['source_sha256'],['c'*64])
        self.assertEqual(entry['call_id'],s['decision_trace'][0]['result_observation_id'])

    def test_all_five_http_parameter_layers_match(self):
        _,s,_,e,_=self.run_case()
        for tool in TOOLS:
            args={'endpoint':'source','window_seconds':30,'limit':4,'offset':0,'bucket_seconds':5,'center_offset_seconds':0}
            with self.subTest(tool=tool):
                r=run_analysis(e.tools,s['anchor_flow'],tool,args,time.time()+5)
                self.assertEqual(e.tools.last_request['parameters'],args|{'tool':tool})
                self.assertEqual(r['query'],args);self.assertEqual(r['tool'],tool)

    def test_illegal_parameters_rejected(self):
        status,s,_,_,_=self.run_case(alter=lambda p,c:p|{'arguments':p['arguments']|{'window_seconds':301}})
        self.assertEqual(status['review_status'],'failed');self.assertEqual(s['calls_used'],2)

    def test_duplicate_tool_blocked(self):
        def mutate(p,c):
            if c['iteration']>1:p.update(action='summarize_host_behavior',investigation_goal='host_behavior')
            return p
        status,s,_,_,_=self.run_case(alter=mutate)
        self.assertEqual(status['stop_reason'],'duplicate_tool_call');self.assertEqual(s['calls_used'],3)

    def test_sparse_stops(self):
        status,s,_,_,_=self.run_case(count=1)
        self.assertEqual(status['stop_reason'],'stop_insufficient_evidence');self.assertEqual(s['calls_used'],3)

    def test_observation_changes_branch(self):
        _,a,_,_,_=self.run_case(ports=1);_,b,_,_,_=self.run_case(ports=8)
        self.assertNotEqual(a['decision_trace'][1]['tool_selected'],b['decision_trace'][1]['tool_selected'])

    def test_planning_budget(self):
        status,s,f,_,_=self.run_case();self.assertEqual(len(f.calls),4)
        self.assertEqual(status['planning_iterations'],3);self.assertLessEqual(s['calls_used'],8)

    def test_second_round_503_preserves_observation(self):
        status,s,_,_,_=self.run_case(fail_at=2)
        self.assertEqual(status['gemini']['verification_status'],'PARTIALLY_VERIFIED')
        self.assertEqual(len(s['observation_registry']),3);self.assertIsNone(status['report'])
        self.assertEqual(s['gemini']['calls'][-1]['http_status'],503)

    def test_report_503_no_fake_report(self):
        status,s,_,_,_=self.run_case(fail_at=4)
        self.assertIsNone(status['report']);self.assertEqual(len(s['observation_registry']),5)

    def test_valid_report_and_no_labels(self):
        from netsentry.agent.reporting import validate_report
        status,s,f,_,_=self.run_case();validate_report(status['report'],s)
        self.assertEqual(status['review_status'],'pending_review')
        text=json.dumps(f.inputs)
        for field in ('attackType','attackID','ground_truth','"Label"'):self.assertNotIn(field,text)

    def test_official_sdk_config_contains_current_reference_enum(self):
        from types import SimpleNamespace as NS
        from netsentry.agent.gemini_adapter import GeminiAdapter,PREFERRED
        _,s,f,_,_=self.run_case();ctx=f.inputs[0];payload=s['planning_attempts'][0]['raw_structured_action'];seen=[]
        def generate(**kwargs):
            seen.append(kwargs['config']);return NS(text=json.dumps(payload),usage_metadata=NS(prompt_token_count=1,candidates_token_count=1,total_token_count=2),model_version='synthetic')
        a=GeminiAdapter(client=NS(models=NS(generate_content=generate),close=lambda:None));a.model=PREFERRED;a.connection['ready']=True
        try:
            self.assertEqual(a.generate('multistep_planning',ctx,planning_schema(ctx['allowed_observation_ids']),time.time()+5),payload)
            self.assertEqual(seen[0].response_json_schema['properties']['supporting_observation_ids']['items']['enum'],ctx['allowed_observation_ids'])
            self.assertFalse(a.live_provider)
        finally:a.close()

    def test_sdk_validation_error_records_field_without_raw_payload(self):
        from types import SimpleNamespace as NS
        from netsentry.agent.gemini_adapter import GeminiAdapter, GeminiError,PREFERRED
        _,s,f,_,_=self.run_case();ctx=f.inputs[0];payload=s['planning_attempts'][0]['raw_structured_action']|{'supporting_observation_ids':[RID]}
        a=GeminiAdapter(client=NS(models=NS(generate_content=lambda **kw:NS(text=json.dumps(payload),usage_metadata=None)),close=lambda:None));a.model=PREFERRED;a.connection['ready']=True
        try:
            with self.assertRaises(GeminiError):a.generate('multistep_planning',ctx,planning_schema(ctx['allowed_observation_ids']),time.time()+5)
            self.assertEqual(a.calls[0]['validation_error']['issues'][0]['loc'][0],'supporting_observation_ids')
            self.assertNotIn(RID,json.dumps(a.calls))
        finally:a.close()

    def test_checkpoint_reopen_retains_partial_without_reexecution(self):
        status,state,_,engine,_=self.run_case(fail_at=2)
        count=state['calls_used'];iid=status['investigation_id']
        import sqlite3
        db=engine.graph.checkpointer.conn.execute('PRAGMA database_list').fetchone()[2]
        reopened=RegistryEngine(Path(db),engine.tools,adapter_factory=lambda:self.fail('replay must not generate'))
        try:reread=reopened.status(iid)
        finally:reopened.close()
        self.assertEqual(reread['external_calls_used'],count)
        self.assertEqual(reread['observation_registry'],state['observation_registry'])
        self.assertFalse(reread['interrupted'])

    def test_metric_rejects_response_query_drift(self):
        from netsentry.evaluation.registry import evaluate_registry
        _,state,_,_,_=self.run_case()
        self.assertEqual(evaluate_registry(state)['analysis_parameter_five_layer_fidelity']['value'],1)
        result=next(o['result'] for o in state['observations'] if o['tool']=='summarize_host_behavior')
        result['query']['limit']=9
        self.assertLess(evaluate_registry(state)['analysis_parameter_five_layer_fidelity']['value'],1)
