"""轻量只读投影测试，合成HTTP工具；不替代真实浏览器联调。"""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from fastapi.testclient import TestClient
from netsentry.web_console import create_app
from netsentry.agent.engine import InvestigationEngine
from netsentry.api.config import Settings
from m4_fixture import make_tools,AID


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();tools,self.calls=make_tools()
        self.engine=InvestigationEngine(Path(self.temp.name)/'checkpoint.sqlite',tools)
        self.client=TestClient(create_app(settings=Settings(token='synthetic-local-test-token-long'),services=SimpleNamespace(),engine=self.engine))
    def tearDown(self):self.client.close();self.engine.close();self.temp.cleanup()
    def test_empty_list(self):
        data=self.client.get('/api/v1/console/investigations').json()
        self.assertEqual(data['records'],[]);self.assertEqual(data['total'],0)
    def test_actual_checkpoint_list(self):
        state=self.engine.start(AID);data=self.client.get('/api/v1/console/investigations').json()
        self.assertEqual(data['total'],1);self.assertEqual(data['records'][0]['investigation_id'],state['investigation_id'])
        self.assertEqual(data['counts'],{'pending_review':1})
    def test_alert_filter(self):
        self.engine.start(AID)
        self.assertEqual(self.client.get('/api/v1/console/investigations?alert_id='+'e'*32).json()['records'],[])
    def test_invalid_filter(self):self.assertEqual(self.client.get('/api/v1/console/investigations?alert_id=bad').status_code,422)
    def test_evidence_snapshot_no_extra_http(self):
        iid=self.engine.start(AID)['investigation_id'];count=len(self.calls)
        response=self.client.get('/api/v1/console/investigations/'+iid+'/evidence')
        self.assertEqual(response.status_code,200);self.assertEqual(len(self.calls),count)
        self.assertEqual(response.json()['records'][0]['association_status'],'exact_record')
        for field in ('"label"','attackType','attackID','offline.sqlite'):self.assertNotIn(field,response.text)
    def test_missing_investigation(self):self.assertEqual(self.client.get('/api/v1/console/investigations/'+'e'*32+'/evidence').status_code,404)
    def test_original_m4_routes_exist(self):
        paths=self.client.get('/openapi.json').json()['paths']
        for path in ['/api/v1/investigations','/api/v1/investigations/{investigation_id}/review','/api/v1/models']:
            self.assertIn(path,paths)
    def test_failed_investigation_exposes_real_error_trace(self):
        self.engine.tools.close();self.engine.tools,_=make_tools('unavailable')
        iid=self.engine.start(AID)['investigation_id']
        data=self.client.get('/api/v1/console/investigations/'+iid+'/evidence').json()
        self.assertEqual(data['tool_call_trace'][0]['status'],'error')
        self.assertTrue(data['missing_information']);self.assertEqual(data['records'],[])


if __name__=='__main__':unittest.main()
