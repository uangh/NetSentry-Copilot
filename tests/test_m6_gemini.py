"""Fake SDK / synthetic HTTP only; real Gemini is a separate smoke run."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

from netsentry.agent.gemini_adapter import GeminiAdapter, GeminiError, GeminiPlan
from netsentry.agent.gemini_engine import GeminiInvestigationEngine
from netsentry.agent.schemas import Narrative
from m4_fixture import make_tools, AID


class FakeModels:
    def __init__(self): self.requests=[]; self.fail=None; self.bad=False
    def list(self, **kwargs):
        return [NS(name='models/gemini-3.5-flash-lite',supported_actions=['generateContent'])]
    def generate_content(self, **kwargs):
        self.requests.append(kwargs)
        if self.fail: raise self.fail
        context=json.loads(kwargs['contents'])['data']
        if json.loads(kwargs['contents'])['task']=='planning':
            data={'actions':[{'tool':'query_host_flows','endpoint':'destination'}], 'reason':'compare_endpoint_activity'}
            if context.get('iteration',1)>1: data={'actions':[{'tool':'stop'}],'reason':'budget_or_sufficient_context'}
        else: data={'paragraphs':[{'lead':'以下关联仅供复核。','fact_ids':[context['facts'][0]['fact_id']]}]}
        return NS(text='invalid' if self.bad else json.dumps(data),usage_metadata=NS(prompt_token_count=11,candidates_token_count=7,total_token_count=18,thoughts_token_count=0))


class GeminiTests(unittest.TestCase):
    def adapter(self):
        models=FakeModels(); adapter=GeminiAdapter(model='gemini-3.5-flash-lite',client=NS(models=models,close=lambda:None))
        adapter.probe(); return adapter,models
    def test_real_sdk_config(self):
        with patch('google.genai.Client') as client:
            a=GeminiAdapter(api_key='synthetic-secret')
            options=client.call_args.kwargs['http_options']
            self.assertEqual(options.retry_options.attempts,1)
            self.assertEqual(options.base_url,'https://generativelanguage.googleapis.com')
            self.assertFalse(client.call_args.kwargs['vertexai']);a.close()
    def test_catalog_is_not_generation_verification(self):
        a,_=self.adapter();self.assertTrue(a.connection['ready']);self.assertFalse(a.connection['generation_verified']);self.assertEqual(a.connection['model'],'gemini-3.5-flash-lite')
    def test_missing_key(self):
        with patch.dict('os.environ',{},clear=True),self.assertRaises(GeminiError):GeminiAdapter()
    def test_structured_plan_and_usage(self):
        a,m=self.adapter();plan=a.plan({'iteration':1},time.time()+30)
        self.assertEqual(plan['actions'][0]['endpoint'],'destination');self.assertEqual(a.calls[0]['total_tokens'],18)
        self.assertTrue(m.requests[0]['config'].automatic_function_calling.disable)
    def test_three_request_budget(self):
        a,m=self.adapter()
        for _ in range(3):a.plan({},time.time()+30)
        with self.assertRaises(GeminiError):a.plan({},time.time()+30)
        self.assertEqual(len(m.requests),3)
    def test_deadline_no_request(self):
        a,m=self.adapter()
        with self.assertRaises(GeminiError):a.plan({},time.time()-1)
        self.assertEqual(m.requests,[])
    def test_quota_no_retry_or_secret(self):
        a,m=self.adapter();m.fail=type('Quota',(Exception,),{'code':429})('synthetic-secret')
        with self.assertRaisesRegex(GeminiError,'quota_or_rate_limit'):a.plan({},time.time()+30)
        self.assertEqual(len(m.requests),1);self.assertNotIn('synthetic-secret',json.dumps(a.calls))
    def test_denied(self):
        a,m=self.adapter();m.fail=type('Denied',(Exception,),{'code':403})('secret')
        with self.assertRaisesRegex(GeminiError,'access_denied'):a.plan({},time.time()+30)
    def test_invalid_json(self):
        a,m=self.adapter();m.bad=True
        with self.assertRaises(GeminiError):a.plan({},time.time()+30)
        self.assertEqual(a.calls[0]['status'],'invalid_structured_output')
    def test_unknown_tool_rejected(self):
        with self.assertRaises(ValueError):GeminiPlan(actions=[{'tool':'shell'}],reason='inspect_candidate_relations')
    def test_over_limit_rejected(self):
        with self.assertRaises(ValueError):GeminiPlan(actions=[{'tool':'query_host_flows','limit':11}],reason='compare_endpoint_activity')
    def test_engine_gemini_selects_destination_and_review(self):
        from netsentry.agent.schemas import Review
        a,m=self.adapter();tools,paths=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            engine=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                s=engine.start(AID,'gemini_llm');self.assertEqual(s['review_status'],'pending_review');self.assertTrue(s['interrupted'])
                self.assertEqual(s['report']['reasoning_mode'],'gemini_llm');self.assertEqual(len(m.requests),3)
                self.assertEqual(s['gemini']['decisions'][0]['actions'][0]['endpoint'],'destination')
                self.assertEqual(s['external_calls_used'],3);self.assertEqual(s['gemini']['status'],'completed')
                self.assertTrue(any('/flows' in p for p in paths));self.assertNotIn('"label"',json.dumps(m.requests,default=str))
                reviewed=engine.review(s['investigation_id'],Review(request_id='c'*32,decision='approve',expected_version=1))
                self.assertEqual(reviewed['review_status'],'approved');self.assertEqual(len(m.requests),3)
            finally:engine.close()
    def test_offline_does_not_construct_sdk(self):
        tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            engine=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda: self.fail('SDK invoked'))
            try:self.assertEqual(engine.start(AID)['report']['reasoning_mode'],'deterministic_offline')
            finally:engine.close()
    def test_bad_reference_fails_closed(self):
        a,_=self.adapter();a.narrate=lambda *args:{'paragraphs':[{'lead':'已取得以下可追溯观察。','fact_ids':['invented']}]}
        tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            engine=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                s=engine.start(AID,'gemini_llm');self.assertIsNone(s['report']);self.assertEqual(s['review_status'],'failed')
            finally:engine.close()

    def test_quota_failure_persisted_without_report(self):
        a,m=self.adapter();m.fail=type('Quota',(Exception,),{'code':429})('secret')
        tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            engine=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                s=engine.start(AID,'gemini_llm');self.assertIsNone(s['report']);self.assertEqual(s['review_status'],'failed')
                self.assertEqual(s['gemini']['calls'][0]['status'],'quota_or_rate_limit');self.assertEqual(len(m.requests),1)
            finally:engine.close()

    def test_api_gemini_mode_and_write_auth(self):
        from fastapi.testclient import TestClient
        from netsentry.web_console import create_app
        from netsentry.api.config import Settings
        a,_=self.adapter();tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            engine=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                client=TestClient(create_app(engine=engine,services=NS(),settings=Settings(token='synthetic-token-long-enough')))
                body={'alert_id':AID,'mode':'gemini_llm'}
                self.assertEqual(client.post('/api/v1/investigations',json=body).status_code,401)
                response=client.post('/api/v1/investigations',json=body,headers={'X-API-Token':'synthetic-token-long-enough'})
                self.assertEqual(response.status_code,201);self.assertEqual(response.json()['gemini']['status'],'completed')
                with patch('netsentry.web_console.connection_status',return_value={'ready':False}) as probe:
                    provider=client.get('/api/v1/console/gemini').json()
                    self.assertTrue(provider['generation_verified']);client.get('/api/v1/console/gemini');self.assertEqual(probe.call_count,1)
                client.close()
            finally:engine.close()

    def test_catalog_failure_no_generation(self):
        a,m=self.adapter();m.list=lambda **kwargs:(_ for _ in ()).throw(type('Denied',(Exception,),{'code':403})('secret'))
        result=a.probe();self.assertFalse(result['ready']);self.assertEqual(result['http_status'],403);self.assertEqual(m.requests,[])

    def test_no_fallback_to_another_catalog_model(self):
        a,m=self.adapter();m.list=lambda **kwargs:[NS(name='models/gemini-3.1-flash-lite',supported_actions=['generateContent']),NS(name='models/expensive-pro',supported_actions=['generateContent'])]
        self.assertIsNone(a.probe()['model'])

    def test_refuse_unknown_model(self):
        a,m=self.adapter();a.requested='expensive-pro';m.list=lambda **kwargs:[NS(name='models/expensive-pro',supported_actions=['generateContent'])]
        self.assertFalse(a.probe()['ready'])

    def test_http_timeout_bounded_by_remaining_budget(self):
        a,m=self.adapter();a.plan({},time.time()+5)
        timeout=m.requests[0]['config'].http_options.timeout
        self.assertLessEqual(timeout,5000);self.assertGreater(timeout,0)

    def test_gateway_timeout_classified(self):
        a,m=self.adapter();m.fail=type('Gateway',(Exception,),{'code':504})('no secret output')
        with self.assertRaisesRegex(GeminiError,'gateway_timeout'):a.plan({},time.time()+30)
        self.assertEqual(len(m.requests),1)

    def test_official_error_message_redacts_key(self):
        from google.genai.errors import APIError
        a,m=self.adapter()
        with patch.dict('os.environ',{'GEMINI_API_KEY':'synthetic-private-key'}):
            m.fail=APIError(400,{'error':{'message':'Schema rejected; synthetic-private-key','status':'INVALID_ARGUMENT'}})
            with self.assertRaisesRegex(GeminiError,'invalid_generation_request'):a.plan({},time.time()+30)
        self.assertNotIn('synthetic-private-key',json.dumps(a.calls));self.assertIn('[REDACTED]',a.calls[0]['provider_message'])

    def test_single_plan_mode_preserves_report_and_budget(self):
        a,m=self.adapter();tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp,patch.dict('os.environ',{'NETSENTRY_GEMINI_PLAN_LIMIT':'1'}):
            engine=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                s=engine.start(AID,'gemini_llm');self.assertEqual(s['review_status'],'pending_review')
                self.assertEqual(s['planning_iterations'],1);self.assertEqual(len(m.requests),2)
            finally:engine.close()

    def test_official_sdk_serializes_schema_on_fake_http(self):
        import httpx
        from google import genai
        from google.genai import types
        requests=[]
        def respond(request):
            requests.append(request)
            if request.method=='GET':return httpx.Response(200,json={'models':[{'name':'models/gemini-3.5-flash-lite','supportedGenerationMethods':['generateContent']}]})
            return httpx.Response(200,json={'candidates':[{'content':{'parts':[{'text':json.dumps({'actions':[{'tool':'stop'}],'reason':'budget_or_sufficient_context'})}]},'finishReason':'STOP'}],
                'usageMetadata':{'promptTokenCount':10,'candidatesTokenCount':5,'totalTokenCount':15},'modelVersion':'gemini-3.5-flash-lite'})
        client=genai.Client(api_key='synthetic-not-real',vertexai=False,http_options=types.HttpOptions(httpx_client=httpx.Client(transport=httpx.MockTransport(respond))))
        adapter=GeminiAdapter(model='gemini-3.5-flash-lite',client=client)
        try:
            self.assertTrue(adapter.probe()['ready']);self.assertEqual(adapter.plan({},time.time()+15)['actions'][0]['tool'],'stop')
            body=json.loads(requests[-1].content);self.assertEqual(body['generationConfig']['responseMimeType'],'application/json')
            self.assertIn('responseJsonSchema',body['generationConfig']);self.assertNotIn('responseSchema',body['generationConfig'])
            self.assertFalse(body['generationConfig']['responseJsonSchema']['additionalProperties']);self.assertNotIn('tools',body)
            self.assertEqual(adapter.calls[0]['total_tokens'],15)
        finally:adapter.close()

    def test_sdk_timeout_no_retry(self):
        import httpx
        a,m=self.adapter();m.fail=httpx.ReadTimeout('secret must not be logged')
        with self.assertRaisesRegex(GeminiError,'timeout'):a.plan({},time.time()+30)
        self.assertEqual(len(m.requests),1)

    def test_stopped_graph_never_exposes_offline_labels(self):
        a,m=self.adapter();tools,_=make_tools('invalid_fields')
        with tempfile.TemporaryDirectory() as tmp:
            engine=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                s=engine.start(AID,'gemini_llm');self.assertEqual(s['review_status'],'failed');self.assertEqual(len(m.requests),0)
                self.assertEqual(s['gemini']['status'],'failed')
            finally:engine.close()

    def test_explicit_short_deadline_respected(self):
        from netsentry.agent.schemas import Limits
        a,_=self.adapter();tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            engine=GeminiInvestigationEngine(Path(tmp)/'db',tools,limits=Limits(total_seconds=1),adapter_factory=lambda:a)
            try:
                engine.active=a
                self.assertLessEqual(engine.initial_provider_state('gemini_llm')['deadline']-time.time(),1)
            finally:engine.close()

    def test_revision_no_extra_provider_calls(self):
        from netsentry.agent.schemas import Review
        a,m=self.adapter();tools,_=make_tools()
        with tempfile.TemporaryDirectory() as tmp:
            engine=GeminiInvestigationEngine(Path(tmp)/'db',tools,adapter_factory=lambda:a)
            try:
                s=engine.start(AID,'gemini_llm')
                revised=engine.review(s['investigation_id'],Review(request_id='d'*32,decision='request_revision',expected_version=1))
                self.assertEqual(revised['report_version'],2);self.assertEqual(len(m.requests),3)
                self.assertTrue(any('没有新增Gemini请求' in x for x in revised['report']['uncertainty']))
            finally:engine.close()

    def test_frontend_child_never_receives_backend_secrets(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('m6_start_test',Path(__file__).resolve().parents[1]/'scripts/start_netsentry_dev.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        children=[]
        def child(*args,**kwargs):
            children.append(kwargs['env']);return NS(poll=lambda:0,terminate=lambda:None)
        with tempfile.TemporaryDirectory() as tmp,patch.dict('os.environ',{'GEMINI_API_KEY':'synthetic-secret','GOOGLE_API_KEY':'synthetic-google'}),patch.object(module.subprocess,'Popen',side_effect=child):
            with self.assertRaises(RuntimeError):
                with module.running_services(backend_port=15643,frontend_port=15644,checkpoint=Path(tmp)/'db',logs=Path(tmp),token='synthetic-local-token'):pass
        self.assertEqual(children[0]['GEMINI_API_KEY'],'synthetic-secret')
        for key in ('GEMINI_API_KEY','GOOGLE_API_KEY','NETSENTRY_API_TOKEN'):self.assertNotIn(key,children[1])
