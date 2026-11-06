"""Bounded acceptance accounting; all model responses in this file are synthetic."""
import tempfile,time,unittest
from pathlib import Path
from netsentry.agent.acceptance import grant_acceptance,AcceptanceBudget,acceptance_levels,backup_allowed,retry_delay
from netsentry.agent.recovery_engine import RecoveryEngine,ResumeRequest,RecoveryConflict
from m6_3_fixture import fixture,AID
from test_m6_3_1_registry import RegistryFake

class AcceptanceTests(unittest.TestCase):
    def setup_case(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);tools,_,_=fixture(Path(t.name))
        providers=[RegistryFake(fail_at=2),RegistryFake()]
        e=RecoveryEngine(Path(t.name)/'cp',tools,recovery_enabled=True,adapter_factory=lambda:providers.pop(0));self.addCleanup(e.close)
        s=e.start(AID,'gemini_multistep');return e,s,Path(t.name)
    def test_grant_keeps_history_and_existing_observations(self):
        e,s,_=self.setup_case();before=dict(e.graph.get_state(e.config(s['investigation_id'])).values)
        grant_acceptance(e,s['investigation_id'],'synthetic_run',3,'synthetic_contract')
        after=dict(e.graph.get_state(e.config(s['investigation_id'])).values)
        self.assertEqual(before['gemini']['calls'],after['gemini']['calls']);self.assertEqual(before['observations'],after['observations'])
        self.assertEqual(after['recovery']['generation_limit'],5)
    def test_resume_does_not_repeat_first_tool(self):
        e,s,_=self.setup_case();grant_acceptance(e,s['investigation_id'],'synthetic_run',3,'synthetic_contract')
        s=e.status(s['investigation_id']);r=e.resume_failed_investigation(s['investigation_id'],ResumeRequest(request_id='a'*32,expected_checkpoint=s['recovery']['checkpoint_id']))
        self.assertEqual(r['review_status'],'pending_review');self.assertEqual(r['external_calls_used'],5)
    def test_grant_cannot_cover_pending_review(self):
        e,s,_=self.setup_case();s=e.resume_failed_investigation(s['investigation_id'],ResumeRequest(request_id='a'*32,expected_checkpoint=s['recovery']['checkpoint_id']))
        with self.assertRaises(RecoveryConflict):grant_acceptance(e,s['investigation_id'],'new',3,'contract')
    def test_grant_idempotent_not_additive(self):
        e,s,_=self.setup_case();grant_acceptance(e,s['investigation_id'],'one',3,'contract')
        with self.assertRaises(RecoveryConflict):grant_acceptance(e,s['investigation_id'],'one',3,'contract')
    def test_global_budget_includes_failed_attempts(self):
        with tempfile.TemporaryDirectory() as t:
            b=AcceptanceBudget(Path(t)/'budget.json',limit=8)
            for _ in range(8):b.reserve('B','model',8)
            with self.assertRaises(RuntimeError):b.reserve('B','model',8)
            self.assertEqual(len(b.records),8)
    def test_branch_budget_and_ownership(self):
        with tempfile.TemporaryDirectory() as t:
            b=AcceptanceBudget(Path(t)/'budget.json')
            for _ in range(3):b.reserve('A','original',3)
            with self.assertRaises(RuntimeError):b.reserve('A','original',3)
            b.reserve('B','backup',5);self.assertEqual([r['model'] for r in b.records],['original']*3+['backup'])
    def test_unknown_billing_blocks_backup(self):
        self.assertFalse(backup_allowed({'structured_outputs':True,'official_free_standard_text':True,'project_access':True}))
    def test_replay_removes_key_and_disables_recovery(self):
        import os,sys
        from unittest.mock import patch
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
        from netsentry_demo import configure_mode
        with patch.dict(os.environ,{'GEMINI_API_KEY':'synthetic-not-a-key','GOOGLE_API_KEY':'synthetic'}):
            configure_mode('saved_live_replay')
            self.assertNotIn('GEMINI_API_KEY',os.environ);self.assertNotIn('GOOGLE_API_KEY',os.environ)
            self.assertEqual(os.environ['NETSENTRY_ENABLE_RECOVERY'],'0')
    def test_model_cannot_change_inside_branch(self):
        with tempfile.TemporaryDirectory() as t:
            b=AcceptanceBudget(Path(t)/'budget.json');b.reserve('A','original',3)
            with self.assertRaises(RuntimeError):b.reserve('A','backup',3)
    def test_persisted_failed_reservation_survives_restart(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'budget.json';b=AcceptanceBudget(p,1);b.reserve('A','original',3)
            with self.assertRaises(RuntimeError):AcceptanceBudget(p,1).reserve('A','original',3)
    def test_provider_failure_is_not_complete(self):
        levels=acceptance_levels({'planning_attempts':[{'round_number':2,'latest_tool_observation_id':'obs_03','status':'provider_failed'}]})
        self.assertTrue(levels['observation_feedback_sent']);self.assertFalse(levels['second_planning_accepted']);self.assertFalse(levels['report_validated'])
    def test_all_backup_conditions_required(self):
        values=dict(structured_outputs=True,official_free_standard_text=True,project_free_tier_confirmed=True,project_access=True)
        self.assertTrue(backup_allowed(values))
        self.assertFalse(backup_allowed(values|{'project_access':False}))
    def test_retry_after_and_insufficient_time(self):
        self.assertEqual(retry_delay({'retry_after_seconds':7},10),7)
        self.assertIsNone(retry_delay({'retry_after_seconds':30},10))
        self.assertIsNone(retry_delay({'http_status':429},10))
    def test_early_stop_not_two_tool_execution(self):
        state={'decision_trace':[{'iteration':1,'actual_execution_status':'executed','tool_selected':'summarize_host_behavior'},
            {'iteration':2,'actual_execution_status':'stopped_without_external_call','tool_selected':'stop'}],
            'planning_attempts':[{'round_number':2,'latest_tool_observation_id':'obs_real','status':'contract_validated'}],
            'gemini':{'report_validated':True,'calls':[{'purpose':'multistep_planning','status':'validated'}]},'review_status':'pending_review'}
        levels=acceptance_levels(state);self.assertTrue(levels['valid_early_stop']);self.assertFalse(levels['second_tool_executed'])
