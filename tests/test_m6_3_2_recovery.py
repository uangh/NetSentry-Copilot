"""Synthetic providers only; original milestone tests remain untouched."""
import copy,tempfile,time,unittest
from pathlib import Path
from netsentry.agent.recovery_engine import RecoveryEngine,ResumeRequest,RecoveryConflict,failure_info
from test_m6_3_1_registry import RegistryFake
from m6_3_fixture import fixture,AID,RID

class RecoveryTests(unittest.TestCase):
    def setup_case(self,fail_at=1,next_fail=None,enabled=True):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        tools,_,requests=fixture(Path(folder.name))
        providers=[RegistryFake(fail_at=fail_at),RegistryFake(fail_at=next_fail),RegistryFake()]
        engine=RecoveryEngine(Path(folder.name)/'cp',tools,adapter_factory=lambda:providers.pop(0),recovery_enabled=enabled)
        self.addCleanup(engine.close);status=engine.start(AID,'gemini_multistep')
        return engine,status,requests
    def request(self,status,number=1):
        return ResumeRequest(request_id=f'{number:032x}',expected_checkpoint=status['recovery']['checkpoint_id'])
    def state(self,e,s):return copy.deepcopy(dict(e.graph.get_state(e.config(s['investigation_id'])).values))
    def test_first_503_resume_same_thread(self):
        e,s,_=self.setup_case();r=e.resume_failed_investigation(s['investigation_id'],self.request(s))
        self.assertEqual(r['investigation_id'],s['investigation_id']);self.assertEqual(r['review_status'],'pending_review')
        self.assertEqual(r['gemini']['calls'][0]['http_status'],503);self.assertEqual(len(r['gemini']['calls']),5)
    def test_second_503_reuses_successful_tool(self):
        e,s,_=self.setup_case(2);before=self.state(e,s)
        r=e.resume_failed_investigation(s['investigation_id'],self.request(s));after=self.state(e,r)
        self.assertEqual(after['observations'][:3],before['observations']);self.assertEqual(r['external_calls_used'],5)
    def test_report_503_only_regenerates_report(self):
        e,s,_=self.setup_case(4);before=self.state(e,s)
        r=e.resume_failed_investigation(s['investigation_id'],self.request(s));after=self.state(e,r)
        self.assertEqual(before['tool_call_history'],after['tool_call_history']);self.assertEqual(before['decision_trace'],after['decision_trace'])
        self.assertTrue(r['interrupted']);self.assertEqual(r['report_version'],1)
    def test_idempotent_same_request(self):
        e,s,_=self.setup_case();q=self.request(s);r=e.resume_failed_investigation(s['investigation_id'],q)
        again=e.resume_failed_investigation(s['investigation_id'],q);self.assertEqual(r,again)
    def test_stale_different_request_rejected(self):
        e,s,_=self.setup_case();e.resume_failed_investigation(s['investigation_id'],self.request(s))
        with self.assertRaises(RecoveryConflict):e.resume_failed_investigation(s['investigation_id'],self.request(s,2))
    def test_readonly_cannot_resume(self):
        e,s,_=self.setup_case(enabled=False);self.assertFalse(s['recovery']['can_resume'])
        with self.assertRaises(RecoveryConflict):e.resume_failed_investigation(s['investigation_id'],self.request(s))
    def test_503_does_not_count_contract_error(self):
        e,s,_=self.setup_case();self.assertEqual(s['recovery']['failure']['source'],'provider')
        self.assertEqual(s['recovery']['failure']['http_status'],503)
    def test_registry_retained(self):
        e,s,_=self.setup_case(2);old=s['observation_registry']
        r=e.resume_failed_investigation(s['investigation_id'],self.request(s));self.assertEqual(old,r['observation_registry'][:len(old)])
    def test_call_budget_and_unknown_tokens(self):
        e,s,_=self.setup_case();r=e.resume_failed_investigation(s['investigation_id'],self.request(s))
        self.assertEqual(r['recovery']['calls_used'],5);self.assertEqual(r['recovery']['generation_limit'],6)
        self.assertEqual(r['recovery']['unknown_usage_requests'],5)
    def test_deadline_inherits_active_budget(self):
        e,s,_=self.setup_case();r=e.resume_failed_investigation(s['investigation_id'],self.request(s))
        self.assertGreater(r['recovery']['active_seconds_used'],0)
        self.assertLess(r['recovery']['active_seconds_remaining'],270)
    def test_failed_resume_keeps_history(self):
        e,s,_=self.setup_case(next_fail=2);r=e.resume_failed_investigation(s['investigation_id'],self.request(s))
        self.assertEqual(r['review_status'],'failed');self.assertEqual(len(r['recovery']['attempts']),1)
        self.assertEqual([c['http_status'] for c in r['gemini']['calls']],[503,503])
    def test_invalid_observation_is_not_recoverable(self):
        e,s,_=self.setup_case();e.adapter_factory=lambda:RegistryFake(alter=lambda p,c:p|{'supporting_observation_ids':[RID]})
        r=e.resume_failed_investigation(s['investigation_id'],self.request(s));self.assertFalse(r['recovery']['can_resume'])
        self.assertEqual(r['recovery']['failure']['source'],'planning_contract')
    def test_unknown_provider_codes_distinct(self):
        for code in (400,403,429,503,504):
            with self.subTest(code=code):
                self.assertEqual(failure_info({'stop_reason':'multistep_plan_failed','gemini':{'calls':[{'status':'failed','http_status':code}]}})['http_status'],code)
        self.assertEqual(failure_info({'stop_reason':'report_validation_failed','gemini':{'calls':[{'status':'validated'}]}})['source'],'report_contract')
    def test_corrupt_registry_rejected(self):
        e,s,_=self.setup_case();state=self.state(e,s);state['observation_registry'][0]['result_sha256']='bad'
        e.graph.update_state(e.config(s['investigation_id']),state,as_node='failed');s=e.status(s['investigation_id'])
        with self.assertRaises(ValueError):e.resume_failed_investigation(s['investigation_id'],self.request(s))
    def test_process_interruption_not_automatically_replayed(self):
        e,s,_=self.setup_case()
        class Crash(RegistryFake):
            def generate(self,*a):raise KeyboardInterrupt()
        e.adapter_factory=Crash
        with self.assertRaises(KeyboardInterrupt):e.resume_failed_investigation(s['investigation_id'],self.request(s))
        r=e.status(s['investigation_id']);self.assertFalse(r['recovery']['can_resume'])
        self.assertEqual(r['recovery']['attempts'][0]['status'],'interrupted')
    def test_one_explicit_retry_and_no_duplicate_history_tokens(self):
        from unittest.mock import patch
        e,s,_=self.setup_case(next_fail=2);q=self.request(s).model_copy(update={'max_retries':1})
        with patch('netsentry.agent.recovery_engine.time.sleep') as wait:
            r=e.resume_failed_investigation(s['investigation_id'],q);wait.assert_called_once_with(5)
        self.assertEqual(len(r['gemini']['calls']),6);self.assertEqual(len(r['recovery']['attempts']),2)
        self.assertEqual(r['review_status'],'pending_review')
        again=e.resume_failed_investigation(s['investigation_id'],q);self.assertEqual(r,again)
    def test_retry_allowance_exhausted(self):
        e,s,_=self.setup_case(next_fail=2);e.adapter_factory=lambda:RegistryFake(fail_at=len(e.status(s['investigation_id'])['gemini']['calls'])+1)
        r=e.resume_failed_investigation(s['investigation_id'],self.request(s))
        r=e.resume_failed_investigation(s['investigation_id'],self.request(r,2))
        self.assertFalse(r['recovery']['can_resume']);self.assertEqual(len(r['gemini']['calls']),3)
    def test_api_auth_and_same_request(self):
        from types import SimpleNamespace
        from fastapi.testclient import TestClient
        from netsentry.web_console import create_app
        from netsentry.api.config import Settings
        e,s,_=self.setup_case();token='synthetic-test-write-token-long'
        with TestClient(create_app(settings=Settings(token=token),services=SimpleNamespace(),engine=e)) as client:
            url='/api/v1/investigations/'+s['investigation_id']+'/resume';q=self.request(s).model_dump()
            self.assertEqual(client.post(url,json=q).status_code,401)
            response=client.post(url,json=q,headers={'X-API-Token':token});self.assertEqual(response.status_code,200)
            self.assertEqual(client.post(url,json=q,headers={'X-API-Token':token}).json(),response.json())
            offline=e.start(AID,'offline')
            self.assertEqual(client.post('/api/v1/investigations/'+offline['investigation_id']+'/resume',json=q,headers={'X-API-Token':token}).status_code,409)
    def test_provider_failure_denominator_not_format_error(self):
        from netsentry.evaluation.recovery import evaluate_recovery
        e,s,_=self.setup_case();m=evaluate_recovery(self.state(e,s))
        self.assertEqual(m['planning_contract']['planning_responses_received'],0)
        self.assertIsNone(m['planning_contract']['acceptance']['value'])
        self.assertEqual(m['provider']['http_503_count'],1)
    def test_recovered_parameter_fidelity_and_feedback(self):
        from netsentry.evaluation.recovery import evaluate_recovery
        e,s,_=self.setup_case();r=e.resume_failed_investigation(s['investigation_id'],self.request(s));m=evaluate_recovery(self.state(e,r),1)
        self.assertEqual(m['analysis_parameter_five_layer_fidelity']['value'],1)
        self.assertEqual(m['evidence_feedback']['value'],1);self.assertTrue(m['second_round_decision_verified'])
    def test_lifetime_budget_is_not_reset(self):
        e,s,_=self.setup_case();state=self.state(e,s);state['recovery']={'generation_limit':1,'active_seconds_used':0}
        e.graph.update_state(e.config(s['investigation_id']),state,as_node='failed')
        self.assertFalse(e.status(s['investigation_id'])['recovery']['can_resume'])
    def test_no_time_left_is_not_resumable(self):
        e,s,_=self.setup_case();state=self.state(e,s);state['recovery']={'generation_limit':6,'active_seconds_used':270}
        e.graph.update_state(e.config(s['investigation_id']),state,as_node='failed')
        self.assertFalse(e.status(s['investigation_id'])['recovery']['can_resume'])
    def test_same_request_payload_conflict(self):
        e,s,_=self.setup_case();q=self.request(s);e.resume_failed_investigation(s['investigation_id'],q)
        with self.assertRaises(RecoveryConflict):e.resume_failed_investigation(s['investigation_id'],q.model_copy(update={'backoff_seconds':6}))
    def test_legacy_provider_error_projection_preserves_raw_history(self):
        e,s,_=self.setup_case();state=self.state(e,s)
        state['planning_attempts'][0]['validation_error']={'code':'provider_or_schema_validation_failed'}
        e.graph.update_state(e.config(s['investigation_id']),state,as_node='failed')
        shown=e.status(s['investigation_id'])
        self.assertNotIn('validation_error',shown['planning_attempts'][0])
        self.assertIn('validation_error',self.state(e,s)['planning_attempts'][0])
    def test_recovery_ledger_with_background_checkpoint_writer(self):
        # LangGraph后台保存与调用前reservation会交错；重复多个阶段实际写库。
        for stage in (1,2,4,1,2,4,1,2):
            with self.subTest(stage=stage):
                e,s,_=self.setup_case(stage)
                r=e.resume_failed_investigation(s['investigation_id'],self.request(s))
                self.assertEqual(r['review_status'],'pending_review')
                self.assertEqual(sum(a['reserved_requests'] for a in r['recovery']['attempts']),len(r['gemini']['calls'])-stage)
