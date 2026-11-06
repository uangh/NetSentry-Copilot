"""M3真实服务实现的合成SQLite边界测试，和公开数据HTTP实测分开。"""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from netsentry.api.config import Settings
from netsentry.api.schemas import FlowFilters, AlertFilters, F2Features
from netsentry.ids_data import sha, write_json
from netsentry.services.evidence_service import EvidenceService, RestrictedFlowQuery
from netsentry.services.prediction_service import ASSETS, PredictionService
from netsentry.services.alert_service import AlertService
from netsentry.repositories.alert_repository import AlertRepository
from test_m3_api import APITests, FakeEvidence, FakePrediction, RID, TOKEN


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.db=self.root/'events.sqlite'
        with closing(sqlite3.connect(self.db)) as c,c:
            c.executescript('CREATE TABLE metadata(name TEXT,value TEXT); CREATE TABLE events(record_id TEXT PRIMARY KEY,source_ip TEXT,destination_ip TEXT,source_port INTEGER,destination_port INTEGER,timestamp TEXT,record TEXT,provenance TEXT);')
            c.execute('INSERT INTO metadata VALUES(?,?)',('contract',json.dumps({'schema_version':'netsentry.labeled.v1','store_kind':'events_only','labels_present':False})))
            self.records=[]
            for index,(src,dst,seconds,protocol) in enumerate([
                ('192.0.2.1','192.0.2.2',0,6),('192.0.2.2','192.0.2.1',5,6),
                ('192.0.2.1','192.0.2.3',10,17),('192.0.2.1','192.0.2.2',120,6),(None,None,0,6)]):
                rid=f'{index+1:064x}';stamp=(datetime(2017,3,15,10)+timedelta(seconds=seconds)).isoformat(timespec='microseconds')
                flow={'record_id':rid,'source_ip':src,'destination_ip':dst,'source_port':1000+index,'destination_port':80,
                      'protocol':protocol,'timestamp':stamp,'flow_duration':1,'dataset_id':'synthetic','source_sha256':'b'*64}
                self.records.append(flow)
                c.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?)',(rid,src,dst,1000+index,80,stamp,json.dumps(flow),'{}'))
        self.before=sha(self.db);self.service=EvidenceService(self.db)

    def tearDown(self):
        self.assertEqual(sha(self.db),self.before);self.temp.cleanup()

    def filters(self, **options):
        return FlowFilters(host_ip='192.0.2.1',start='2017-03-15T10:00:00',end='2017-03-15T10:01:00',**options)

    def test_forward_reverse(self):self.assertEqual(self.service.flows(self.filters())['total'],3)
    def test_protocol_filter_before_pagination(self):
        page=self.service.flows(self.filters(protocol=17,limit=1));self.assertEqual(page['total'],1)
        self.assertEqual(page['records'][0]['protocol'],17)
    def test_port_filter(self):self.assertEqual(self.service.flows(self.filters(port=1001))['total'],1)
    def test_source_vs_destination(self):
        source=FlowFilters(source_ip='192.0.2.1',start='2017-03-15T10:00:00',end='2017-03-15T10:01:00')
        dest=FlowFilters(destination_ip='192.0.2.1',start=source.start,end=source.end)
        self.assertEqual(self.service.flows(source)['total'],2);self.assertEqual(self.service.flows(dest)['total'],1)
    def test_empty_result(self):self.assertEqual(self.service.flows(self.filters(port=65535))['records'],[])
    def test_evidence_candidates_and_source(self):
        page=self.service.evidence(self.records[0]['record_id'],60,10,0)
        self.assertEqual(page['total'],3);self.assertEqual(page['records'][0]['association_status'],'exact_record')
        self.assertTrue(all(r['association_status']=='candidate_unverified' for r in page['records'][1:]))
        self.assertTrue(all(r['source_sha256']=='b'*64 for r in page['records']))
    def test_evidence_pagination_no_repeat(self):
        rid=self.records[0]['record_id'];pages=[self.service.evidence(rid,60,1,i) for i in range(4)]
        self.assertEqual([len(p['records']) for p in pages],[1,1,1,0])
        self.assertEqual(len({p['records'][0]['related_record_id'] for p in pages[:3]}),3)
    def test_insufficient_ip_keeps_exact_record(self):
        page=self.service.evidence(self.records[-1]['record_id'],60,5,0)
        self.assertEqual(page['association_status'],'insufficient_metadata');self.assertEqual(page['total'],1)
        self.assertIsNone(page['anchor']['source_ip']);self.assertEqual(page['records'][0]['association_status'],'exact_record')
    def test_readonly_connection(self):
        with RestrictedFlowQuery(self.db) as query:
            with self.assertRaises(sqlite3.OperationalError):query.connection.execute('DELETE FROM events')
    def test_no_sql_injection(self):
        with self.assertRaises(ValueError):FlowFilters(host_ip="' OR 1=1",start='2017-03-15',end='2017-03-16')
    def test_timezone_rejected(self):
        with self.assertRaises(ValueError):FlowFilters(host_ip='192.0.2.1',start='2017-03-15T00:00:00Z',end='2017-03-15T01:00:00Z')
    def test_evidence_window_budget(self):
        with self.assertRaises(ValueError):self.service.evidence(self.records[0]['record_id'],3601,1,0)


class ModelBoundaryTests(unittest.TestCase):
    def test_hash_failure_before_model_load(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ASSETS:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'synthetic')
            manifest={'version':'netsentry.api.runtime.v1','record_scope':'Week1 B Train+Validation only',
                'default_model':'F2_logistic','assets':{name:sha(root/name) for name in ASSETS}}
            write_json(root/'runtime_manifest.json',manifest)
            (root/'models/F2_logistic.joblib').write_bytes(b'tampered')
            with patch('netsentry.services.prediction_service.IDSPredictor') as predictor:
                with self.assertRaises(ValueError):PredictionService(root)
                predictor.assert_not_called()

    def test_forbidden_runtime_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);write_json(root/'runtime_manifest.json',{'version':'netsentry.api.runtime.v1','assets':{'offline.sqlite':'0'*64}})
            with self.assertRaises(ValueError):PredictionService(root)

    def test_public_cors_refused(self):
        with self.assertRaises(ValueError):Settings(origins=('https://example.com',))

    def test_no_write_database_inside_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):Settings(runtime=Path(directory),alert_db=Path(directory)/'events.sqlite')

    def test_existing_foreign_database_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'foreign.sqlite'
            with closing(sqlite3.connect(path)) as c,c:c.execute('CREATE TABLE original(x)')
            before=sha(path)
            with self.assertRaises(ValueError):AlertRepository(path)
            self.assertEqual(before,sha(path))


class HTTPValidationTests(APITests):
    """仅新测试被显式装载，避免重复统计父类测试。"""
    def features(self):
        return dict(flow_duration=1.,packets=2.,bytes=200.,mean_bytes_per_packet=100.,mean_bytes_per_packet_missing=0,
                    duration_zero=0,flag_urg=0,flag_ack=0,flag_psh=0,flag_rst=0,flag_syn=1,flag_fin=0)
    def test_valid_features(self):
        self.assertEqual(self.client.post('/api/v1/predictions',json={'features':self.features()}).status_code,200)
    def test_feature_injection(self):
        for key in ['Label','attackID','attackType','attackDescription','model_path']:
            features=self.features();features[key]='forbidden'
            self.assertEqual(self.client.post('/api/v1/predictions',json={'features':features}).status_code,422)
    def test_nan_and_infinity(self):
        for value in ['NaN','Infinity','-Infinity']:
            raw=json.dumps({'features':self.features()}).replace('"flow_duration": 1.0','"flow_duration": '+value)
            r=self.client.post('/api/v1/predictions',content=raw,headers={'Content-Type':'application/json'})
            self.assertEqual(r.status_code,422);self.assertNotIn(value,r.text)
    def test_invalid_number_and_missing_derived(self):
        for value in [-1,True,'1']:
            features=self.features();features['packets']=value
            self.assertEqual(self.client.post('/api/v1/predictions',json={'features':features}).status_code,422)
    def test_large_request(self):
        self.assertEqual(self.client.post('/api/v1/predictions',content='x'*65537).status_code,413)
    def test_malformed_json(self):self.assertEqual(self.client.post('/api/v1/predictions',content='{').status_code,422)
    def test_no_token_configured(self):
        from netsentry.api.main import create_app
        with TestClient(create_app(Settings(runtime=self.root/'runtime',alert_db=self.root/'alerts.sqlite'),services=self.services)) as client:
            self.assertEqual(client.post('/api/v1/alerts/detect',json={'record_ids':[RID]},headers={'X-API-Token':TOKEN}).status_code,503)
    def test_pagination_filter_sort(self):
        for i,score in enumerate([0.6,0.9,0.8]):
            prediction=FakePrediction().predict(record_id=f'{i:064x}')
            prediction['attack_related_score']=score
            self.repo.create(prediction,FakeEvidence().flow(f'{i:064x}'))
        result=self.client.get('/api/v1/alerts?limit=2&sort=score_desc').json()
        self.assertEqual([a['attack_related_score'] for a in result['alerts']],[0.9,0.8])
        self.assertTrue(result['has_more'])
        result=self.client.get('/api/v1/alerts?model_id=F2_rf100').json();self.assertEqual(result['total'],0)
    def test_below_threshold_no_alert(self):
        with patch.object(self.services.prediction,'predict',return_value={**FakePrediction().predict(record_id=RID),'prediction':'normal','attack_related_score':0.1}):
            result=self.detect().json();self.assertEqual(result['below_threshold'],1);self.assertEqual(result['created'],0)
    def test_unknown_query_field_rejected(self):
        self.assertEqual(self.client.get('/api/v1/alerts?database=offline.sqlite').status_code,422)


def load_tests(loader, tests, pattern):
    suite=unittest.TestSuite()
    for cls in (EvidenceTests,ModelBoundaryTests,HTTPValidationTests):
        for name in cls.__dict__:
            if name.startswith('test_'):suite.addTest(cls(name))
    return suite
