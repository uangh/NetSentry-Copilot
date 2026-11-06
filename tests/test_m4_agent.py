"""M4合成场景；真实M3 HTTP调查由独立smoke验证。"""
from pathlib import Path
import tempfile
import unittest

from netsentry.agent.engine import InvestigationEngine
from netsentry.agent.knowledge import KnowledgeIndex
from netsentry.agent.schemas import Limits, Plan, Review
from netsentry.agent.reporting import validate_report
from m4_fixture import make_tools, AID
import copy


class ContractTests(unittest.TestCase):
    def test_limits(self):
        with self.assertRaises(ValueError):Limits(max_calls=7)
        with self.assertRaises(ValueError):Limits(window_seconds=3601)
    def test_tool_whitelist(self):
        with self.assertRaises(ValueError):Plan(actions=[{'tool':'shell','command':'whoami'}])
    def test_no_llm_url_argument(self):
        with self.assertRaises(ValueError):Plan(actions=[{'tool':'query_host_flows','url':'https://bad.invalid'}])
    def test_review_contract(self):
        with self.assertRaises(ValueError):Review(request_id='a'*32,decision='confirmed',expected_version=1)
    def test_rag_real_rank_and_no_hit(self):
        index=KnowledgeIndex.default()
        self.assertTrue(index.search('network availability bandwidth denial of service',3))
        self.assertEqual(index.search('zzqxxyy999',3),[])
    def test_index_reproducible(self):
        self.assertEqual(KnowledgeIndex.default().export(),KnowledgeIndex.default().export())


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.engines=[]
    def tearDown(self):
        for engine in self.engines:engine.close()
        self.temp.cleanup()
    def engine(self,scenario='complete',**kwargs):
        tools,calls=make_tools(scenario)
        engine=InvestigationEngine(self.root/(str(len(self.engines))+'.sqlite'),tools,**kwargs)
        self.engines.append(engine);return engine,calls
    def test_actual_graph_and_interrupt(self):
        engine,calls=self.engine();state=engine.start(AID)
        self.assertEqual(state['review_status'],'pending_review');self.assertTrue(state['interrupted'])
        self.assertEqual(state['report']['reasoning_mode'],'deterministic_offline')
        self.assertEqual(state['external_calls_used'],5);self.assertEqual(len(calls),5)
    def test_missing_both_ips(self):
        engine,calls=self.engine('no_ip');state=engine.start(AID)
        self.assertEqual(state['external_calls_used'],2);self.assertEqual(state['stop_reason'],'insufficient_metadata')
        self.assertTrue(state['report']['missing_evidence']);self.assertTrue(state['interrupted'])
    def test_single_endpoint_routes(self):
        for scenario in ('source_only','dest_only'):
            engine,calls=self.engine(scenario);state=engine.start(AID)
            self.assertEqual(state['external_calls_used'],4)
    def test_empty_evidence(self):
        engine,_=self.engine('empty');state=engine.start(AID)
        self.assertEqual(state['report']['hypothesis'],'insufficient_evidence')
        self.assertTrue(any('没有候选' in s for s in state['report']['missing_evidence']))
    def test_too_many_records_summary(self):
        engine,_=self.engine('many');state=engine.start(AID)
        self.assertTrue(any('受限页面' in s for s in state['report']['uncertainty']))
    def test_unavailable_no_fabricated_report(self):
        engine,_=self.engine('unavailable');state=engine.start(AID)
        self.assertEqual(state['review_status'],'failed');self.assertIsNone(state['report'])
    def test_invalid_fields_rejected(self):
        engine,_=self.engine('invalid_fields');state=engine.start(AID)
        self.assertIsNone(state['report'])
    def test_timeout_ends(self):
        engine,_=self.engine('timeout');state=engine.start(AID)
        self.assertEqual(state['review_status'],'failed')
    def test_budget_exhaustion(self):
        engine,calls=self.engine(limits=Limits(max_calls=2));state=engine.start(AID)
        self.assertEqual(len(calls),2);self.assertEqual(state['stop_reason'],'budget_exhausted')
    def test_approve_and_idempotency(self):
        engine,calls=self.engine();state=engine.start(AID);iid=state['investigation_id'];count=len(calls)
        payload=Review(request_id='d'*32,decision='approve',expected_version=1)
        result=engine.review(iid,payload)
        self.assertEqual(result['review_status'],'approved');self.assertFalse(result['interrupted'])
        self.assertEqual(engine.review(iid,payload),result);self.assertEqual(len(calls),count)
        self.assertEqual(result['report']['hypothesis'],'insufficient_evidence')
    def test_revision_and_reject(self):
        engine,calls=self.engine();state=engine.start(AID);iid=state['investigation_id'];count=len(calls)
        revision=engine.review(iid,Review(request_id='d'*32,decision='request_revision',expected_version=1,note='Please review'))
        self.assertEqual(revision['report_version'],2);self.assertTrue(revision['interrupted'])
        rejected=engine.review(iid,Review(request_id='e'*32,decision='reject',expected_version=2))
        self.assertEqual(rejected['review_status'],'rejected');self.assertEqual(len(calls),count)
    def test_restart_resume(self):
        engine,calls=self.engine();state=engine.start(AID);path=self.root/'0.sqlite'
        engine.close();self.engines.remove(engine)
        tools,new_calls=make_tools();replacement=InvestigationEngine(path,tools);self.engines.append(replacement)
        after=replacement.review(state['investigation_id'],Review(request_id='f'*32,decision='approve',expected_version=1))
        self.assertEqual(after['review_status'],'approved');self.assertEqual(new_calls,[])
    def test_unknown_reference_rejected(self):
        engine,_=self.engine();status=engine.start(AID)
        state=dict(engine.graph.get_state(engine.config(status['investigation_id'])).values)
        report=copy.deepcopy(status['report']);report['observed_facts'][0]['reference_id']='fake'
        with self.assertRaises(ValueError):validate_report(report,state)
    def test_valid_reference_wrong_value_rejected(self):
        engine,_=self.engine();status=engine.start(AID)
        state=dict(engine.graph.get_state(engine.config(status['investigation_id'])).values)
        report=copy.deepcopy(status['report']);report['observed_facts'][1]['value']='8.8.8.8'
        with self.assertRaises(ValueError):validate_report(report,state)
    def test_fabricated_authentication_rejected(self):
        engine,_=self.engine();status=engine.start(AID)
        state=dict(engine.graph.get_state(engine.config(status['investigation_id'])).values)
        report=copy.deepcopy(status['report']);report['investigation_summary']='SSH login succeeded 100 times'
        with self.assertRaises(ValueError):validate_report(report,state)


if __name__=='__main__':unittest.main()
