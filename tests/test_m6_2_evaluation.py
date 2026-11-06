import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from netsentry.evaluation.scenarios import synthetic_tools,SCENARIOS
from netsentry.evaluation.metrics import evaluate,parameter_fidelity
from netsentry.evaluation.runner import SyntheticModels,run_engine
from netsentry.evaluation.rag import evaluate_rag
from netsentry.agent.gemini_adapter import GeminiAdapter
from netsentry.agent.gemini_engine import GeminiInvestigationEngine
from types import SimpleNamespace as NS

class EvaluationTests(unittest.TestCase):
    def state(self,name='complete'):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);tools,_=synthetic_tools(name)
        a=GeminiAdapter(model='gemini-3.5-flash-lite',client=NS(models=SyntheticModels(),close=lambda:None))
        engine=GeminiInvestigationEngine(Path(tmp.name)/'c',tools,adapter_factory=lambda:a);self.addCleanup(engine.close)
        s=engine.start('a'*32,'gemini_llm')
        return dict(engine.graph.get_state(engine.config(s['investigation_id'])).values)
    def test_declared_scenarios_cover_required_boundaries(self):
        self.assertEqual(len(SCENARIOS),12);self.assertIn('untrusted_rag',SCENARIOS);self.assertIn('invalid_reference',SCENARIOS)
    def test_valid_citations_and_grounding_denominators(self):
        m=evaluate(self.state());self.assertEqual(m['citation_validity']['value'],1);self.assertGreater(m['fact_grounding']['denominator'],0)
        self.assertEqual(m['unsupported_claim_count'],0);self.assertTrue(m['missing_evidence_disclosure']);self.assertEqual(m['parameter_execution_fidelity']['value'],1)
    def test_nonexistent_reference_detected_independently(self):
        state=self.state();state['draft_report']['evidence_references'][0]['reference_id']='not-present'
        self.assertLess(evaluate(state)['citation_validity']['value'],1)
    def test_changed_fact_and_false_confirmation_detected(self):
        state=self.state();state['draft_report']['observed_facts'][0]['value']=999
        state['draft_report']['hypothesis']='confirmed_attack'
        m=evaluate(state);self.assertLess(m['fact_grounding']['value'],1);self.assertGreater(m['unsupported_claim_count'],0);self.assertTrue(m['candidate_to_confirmed_violation'])
    def test_unique_records_not_reference_or_occurrence_count(self):
        state=self.state();observation=next(o for o in state['observations'] if o['tool']=='query_related_evidence')
        state['observations'].append(copy.deepcopy(observation));m=evaluate(state)
        self.assertEqual(m['unique_evidence_records'],2);self.assertEqual(m['loaded_record_occurrences'],4)
    def test_missing_wire_endpoint_is_not_fidelity_success(self):
        state=self.state();trace=next(t for t in state['tool_call_history'] if t['tool']=='query_related_evidence')
        trace['http_request']['parameters'].pop('endpoint');self.assertEqual(parameter_fidelity(state)['value'],0)
    def test_unknown_token_usage_not_zero(self):
        m=evaluate(self.state());self.assertGreater(m['unknown_usage_requests'],0)
    def test_pagination_is_not_full_review(self):
        state=self.state('many');m=evaluate(state);self.assertEqual(m['unique_evidence_records'],2)
        self.assertEqual(next(o for o in state['observations'] if o['tool']=='query_related_evidence')['result']['total'],5000)
    def test_failure_has_no_report_and_no_false_citation_rate(self):
        m=evaluate(self.state('unavailable'));self.assertFalse(m['report_available']);self.assertIsNone(m['citation_validity']['value'])
    def test_rag_manifest_relevance_and_source_dedup(self):
        m=evaluate_rag();self.assertEqual(m['hit_at_3'],{'numerator':4,'denominator':4})
        for row in m['rows']:self.assertLessEqual(row['unique_documents'],row['chunks'])
