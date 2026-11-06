"""M6.1 offline regression: synthetic SDK/HTTP only, never real credentials."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

import httpx
from netsentry.agent.gemini_adapter import GeminiAdapter, GeminiError
from netsentry.agent.gemini_protocol import InvestigationAction, wire_schema, planning_context, report_context
from netsentry.agent.gemini_engine import GeminiInvestigationEngine
from m4_fixture import make_tools,AID
from test_m6_gemini import FakeModels


class M61Tests(unittest.TestCase):
    def test_minimal_schema_has_only_three_top_level_fields(self):
        schema=wire_schema(InvestigationAction)
        self.assertEqual(set(schema['properties']),{'action','arguments','reason'})
        self.assertEqual(set(schema['required']),set(schema['properties']))
        text=json.dumps(schema)
        for unsupported in ('$defs','$ref','default','title','anyOf'):self.assertNotIn('"'+unsupported+'"',text)
    def test_argument_sql_rejected(self):
        with self.assertRaises(ValueError):InvestigationAction(action='query_host_flows',arguments={'endpoint':'source','window_seconds':30,'limit':10,'sql':'SELECT'},reason='compare_endpoint_activity')
    def test_tool_and_bounds_rejected(self):
        for action,limit in [('shell',1),('query_related_evidence',11)]:
            with self.assertRaises(ValueError):InvestigationAction(action=action,arguments={'endpoint':'source','window_seconds':30,'limit':limit},reason='inspect_candidate_relations')
    def test_planning_context_never_contains_entire_responses(self):
        state={'model_context':{'model_id':'F2_logistic'},'alert_detail':{'alert':{'predicted_label':'attack-related'}},
            'anchor_flow':{'source_ip':'192.0.2.1','destination_ip':'192.0.2.2','timestamp':'2017-01-01','source_sha256':'x'*64},
            'plan_iterations':1,'calls_used':2,'limits':{'max_plans':2},'summaries':[],
            'observations':[{'tool':'query_host_flows','parameters':{'limit':10},'result':{'records':[{'secret':'DO_NOT_SEND'}]*100}}]}
        data=planning_context(state);self.assertLess(len(json.dumps(data)),4000);self.assertNotIn('DO_NOT_SEND',json.dumps(data));self.assertNotIn('source_sha256',json.dumps(data))
    def test_report_context_is_explicitly_bounded(self):
        facts=[{'fact_id':str(i),'field':'total','value':i,'scope':'candidate_unverified'} for i in range(100)]
        state={'knowledge_references':[{'chunk_id':'k','title':'title','text':'x'*9000}]*5,'confidence_limitations':['x'*1000]*9,'missing_information':[],'summaries':[]}
        data=report_context(state,facts);self.assertEqual(len(data['facts']),12);self.assertEqual(data['omitted_facts'],88)
        self.assertLess(len(json.dumps(data)),6000)
    def official_adapter(self,status=200):
        seen=[]
        def handler(request):
            seen.append(request)
            if request.method=='GET':return httpx.Response(200,json={'models':[{'name':'models/gemini-3.5-flash-lite','supportedGenerationMethods':['generateContent']}]})
            if status!=200:return httpx.Response(status,json={'error':{'message':'synthetic exact reason','status':'RESOURCE_EXHAUSTED' if status==429 else 'DEADLINE_EXCEEDED'}})
            text=json.dumps({'action':'query_host_flows','arguments':{'endpoint':'destination','window_seconds':30,'limit':5},'reason':'compare_endpoint_activity'})
            return httpx.Response(200,json={'candidates':[{'content':{'parts':[{'text':text}]},'finishReason':'STOP'}],'usageMetadata':{'promptTokenCount':10,'candidatesTokenCount':5,'totalTokenCount':15}})
        a=GeminiAdapter(model='gemini-3.5-flash-lite',api_key='synthetic-not-real',transport=httpx.MockTransport(handler));a.probe();return a,seen
    def test_official_sdk_minimal_plan_and_wire_count(self):
        a,seen=self.official_adapter()
        try:
            result=a.plan({},time.time()+60);self.assertEqual(result['actions'][0]['endpoint'],'destination')
            self.assertEqual(a.calls[0]['http_attempt_count'],1);self.assertEqual(a.calls[0]['http_attempts'][0]['status'],200)
            self.assertEqual(a.calls[0]['validated_output']['action'],'query_host_flows')
            self.assertEqual(a.calls[0]['execution_source'],'google_genai_sdk')
            self.assertEqual(len([r for r in seen if r.method=='POST']),1)
        finally:a.close()
    def test_429_504_one_wire_attempt_no_implicit_retry(self):
        for status in (429,504,400):
            with self.subTest(status=status):
                a,seen=self.official_adapter(status)
                try:
                    with self.assertRaises(GeminiError):a.plan({},time.time()+60)
                    self.assertEqual(len([r for r in seen if r.method=='POST']),1)
                    self.assertEqual(a.calls[0]['http_attempt_count'],1)
                    self.assertEqual(a.calls[0]['http_status'],status);self.assertEqual(a.calls[0]['provider_message'],'synthetic exact reason')
                finally:a.close()
    def test_wire_budget_refuses_fourth_business_call(self):
        a,seen=self.official_adapter()
        try:
            for _ in range(3):a.plan({},time.time()+60)
            with self.assertRaises(GeminiError):a.plan({},time.time()+60)
            self.assertEqual(len([r for r in seen if r.method=='POST']),3)
        finally:a.close()
    def test_partial_report_failure_preserves_tool_evidence(self):
        m=FakeModels();a=GeminiAdapter(model='gemini-3.5-flash-lite',client=NS(models=m,close=lambda:None));a.probe()
        a.narrate=lambda *args:(_ for _ in ()).throw(GeminiError('gateway_timeout'))
        tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            e=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                s=e.start(AID,'gemini_llm');self.assertEqual(s['gemini']['verification_status'],'PARTIALLY_VERIFIED')
                self.assertEqual(s['review_status'],'failed');self.assertIsNone(s['report']);self.assertFalse(s['interrupted'])
                state=dict(e.graph.get_state(e.config(s['investigation_id'])).values)
                self.assertTrue(any(o['tool']=='query_host_flows' for o in state['observations']))
                self.assertTrue(s['gemini']['step_timings']);self.assertGreater(s['gemini']['duration_ms'],0)
            finally:e.close()
    def test_fake_success_disclosed_separately_from_live_verification(self):
        m=FakeModels();a=GeminiAdapter(model='gemini-3.5-flash-lite',client=NS(models=m,close=lambda:None));a.probe();tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            e=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                s=e.start(AID,'gemini_llm');self.assertEqual(s['gemini']['verification_status'],'VERIFIED')
                self.assertFalse(s['gemini']['live_provider_verified']);self.assertEqual(s['review_status'],'pending_review');self.assertEqual(s['review_history'],[])
            finally:e.close()
    def test_first_plan_failure_is_not_verified_and_no_more_generations(self):
        m=FakeModels();m.fail=type('Rate',(Exception,),{'code':429})('synthetic')
        a=GeminiAdapter(model='gemini-3.5-flash-lite',client=NS(models=m,close=lambda:None));a.probe();tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            e=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                s=e.start(AID,'gemini_llm');self.assertEqual(s['gemini']['verification_status'],'NOT_VERIFIED');self.assertEqual(len(m.requests),1)
            finally:e.close()
