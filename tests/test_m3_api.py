"""M3 合成边界测试；真实 HTTP 联调另由 m3_smoke_test 执行。"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient
from netsentry.api.main import create_app
from netsentry.api.config import Settings
from netsentry.api.schemas import FlowFilters
from netsentry.repositories.alert_repository import AlertRepository
from netsentry.services.alert_service import AlertService

RID='a'*64
TOKEN='synthetic-test-token-not-a-real-secret'


class FakePrediction:
    def models(self):
        return [{'model_id':m,'model_version':'synthetic.v1','feature_contract_version':'synthetic.f2',
                 'model_status':'DEV_ONLY','threshold':0.5,'is_default':m=='F2_logistic',
                 'score_is_calibrated_probability':False} for m in ['F2_logistic','F2_rf100']]

    def predict(self, features=None, record_id=None, model_id='F2_logistic'):
        if record_id=='f'*64:raise KeyError('unknown')
        return {'prediction_id':'p_'+(record_id or RID),'record_id':record_id,'prediction':'attack-related',
                'attack_related_score':0.8,'threshold':0.5,'model_id':model_id,'model_version':'synthetic.v1',
                'feature_contract_version':'synthetic.f2','prediction_status':'DEV_ONLY',
                'score_is_calibrated_probability':False}


class FakeEvidence:
    def flow(self, rid):
        if rid=='f'*64:raise KeyError('unknown')
        return {'record_id':rid,'source_ip':'192.0.2.1','destination_ip':None,'source_port':1234,
            'destination_port':80,'protocol':6,'timestamp':'2017-03-15T10:00:00.000000','flow_duration':1,
            'dataset_id':'synthetic','source_sha256':'b'*64}

    def flows(self, filters):
        return {'records':[self.flow(RID)],'total':1,'limit':filters.limit,'offset':filters.offset,'has_more':False}

    def evidence(self, rid, window, limit, offset):
        return {'anchor':self.flow(rid),'association_status':'candidate_unverified','records':[],
                'total':0,'limit':limit,'offset':offset,'has_more':False}


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.repo=AlertRepository(self.root/'alerts.sqlite')
        from types import SimpleNamespace
        self.services=SimpleNamespace(prediction=FakePrediction(),evidence=FakeEvidence(),alerts=self.repo)
        self.services.detection=AlertService(self.services.prediction,self.services.evidence,self.repo)
        self.client=TestClient(create_app(Settings(runtime=self.root/'runtime',alert_db=self.root/'alerts.sqlite',token=TOKEN),services=self.services))

    def tearDown(self):
        self.client.close();self.temp.cleanup()

    def detect(self, ids=None, **kwargs):
        return self.client.post('/api/v1/alerts/detect',json={'record_ids':ids or [RID],**kwargs},headers={'X-API-Token':TOKEN})

    def test_health(self):self.assertEqual(self.client.get('/health').status_code,200)
    def test_models(self):
        models=self.client.get('/api/v1/models').json()['models']
        self.assertEqual([m['model_id'] for m in models if m['is_default']],['F2_logistic'])
        self.assertTrue(all(m['model_status']=='DEV_ONLY' for m in models))

    def test_write_auth(self):
        result=self.client.post('/api/v1/alerts/detect',json={'record_ids':[RID]})
        self.assertEqual(result.status_code,401);self.assertIn('trace_id',result.json()['error'])

    def test_bad_token_not_reflected(self):
        r=self.client.post('/api/v1/alerts/detect',json={'record_ids':[RID]},headers={'X-API-Token':'secret-wrong'})
        self.assertEqual(r.status_code,401);self.assertNotIn('secret-wrong',r.text)

    def test_detect_idempotency(self):
        first=self.detect().json();second=self.detect().json()
        self.assertEqual(first['created'],1);self.assertEqual(second['duplicates'],1)
        aid=first['alerts'][0]['alert_id']
        self.assertEqual(self.client.get('/api/v1/alerts/'+aid).json()['alert']['model_status'],'DEV_ONLY')

    def test_concurrent_no_duplicates(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses=list(pool.map(lambda _:self.detect().json(),range(8)))
        self.assertEqual(sum(r['created'] for r in responses),1)
        self.assertEqual(sum(r['duplicates'] for r in responses),7)

    def test_batch_limit(self):self.assertEqual(self.detect([RID]*21).status_code,422)
    def test_empty_batch(self):
        self.assertEqual(self.client.post('/api/v1/alerts/detect',json={'record_ids':[]},headers={'X-API-Token':TOKEN}).status_code,422)
    def test_partial_failure(self):
        body=self.detect([RID,'f'*64]).json();self.assertEqual(len(body['failures']),1);self.assertEqual(body['created'],1)
    def test_label_injection(self):self.assertEqual(self.detect(label='attacker').status_code,422)
    def test_attack_id_injection(self):
        self.assertEqual(self.client.post('/api/v1/predictions/by-record',json={'record_id':RID,'attackID':'secret'}).status_code,422)
    def test_unknown_model(self):self.assertEqual(self.detect(model_id='../../weights.joblib').status_code,422)
    def test_by_record_default(self):
        r=self.client.post('/api/v1/predictions/by-record',json={'record_id':RID}).json()
        self.assertEqual(r['model_id'],'F2_logistic');self.assertEqual(r['prediction_status'],'DEV_ONLY')
    def test_explicit_rf(self):
        r=self.client.post('/api/v1/predictions/by-record',json={'record_id':RID,'model_id':'F2_rf100'}).json()
        self.assertEqual(r['model_id'],'F2_rf100');self.test_models()
    def test_missing_features(self):
        self.assertEqual(self.client.post('/api/v1/predictions',json={'features':{'packets':1}}).status_code,422)
    def test_flow(self):self.assertIsNone(self.client.get('/api/v1/flows/'+RID).json()['destination_ip'])
    def test_not_found(self):self.assertEqual(self.client.get('/api/v1/flows/'+'f'*64).status_code,404)
    def test_invalid_record(self):self.assertEqual(self.client.get('/api/v1/flows/invalid').status_code,422)
    def test_evidence(self):
        aid=self.detect().json()['alerts'][0]['alert_id']
        r=self.client.get('/api/v1/alerts/'+aid+'/evidence').json()
        self.assertEqual(r['association_status'],'candidate_unverified')
    def test_no_ground_truth(self):
        payload=self.detect().text
        for name in ['attackType','attackID','attackDescription','"label"']:
            self.assertNotIn(name,payload)
    def test_page_limits(self):
        for url in ['/api/v1/alerts?limit=101','/api/v1/alerts?offset=-1','/api/v1/alerts?sort=DROP']:
            self.assertEqual(self.client.get(url).status_code,422)
    def test_filter_requires_ip_and_bounded_window(self):
        with self.assertRaises(ValueError):FlowFilters(start='2017-03-15',end='2017-03-17',host_ip='192.0.2.1')
    def test_trace_id(self):
        r=self.client.get('/health');self.assertRegex(r.headers['X-Trace-ID'],r'^[0-9a-f]{32}$')
    def test_cors_no_wildcard(self):
        r=self.client.options('/api/v1/alerts/detect',headers={'Origin':'https://evil.invalid','Access-Control-Request-Method':'POST'})
        self.assertNotEqual(r.headers.get('access-control-allow-origin'),'*')


if __name__=='__main__':unittest.main()
