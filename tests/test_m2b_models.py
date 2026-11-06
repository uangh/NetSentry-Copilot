"""M2B 合成测试：用于验证软件契约，不是模型效果证据。"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from netsentry.ids_data import matrix, binary_label, require_training_role
from netsentry.train_ids import make_pipeline, complete_candidates, selection_allowed
from netsentry.evaluate_ids import metrics, claim_test
from netsentry.model_registry import ModelRegistry
from netsentry.predict_ids import IDSPredictor
from netsentry.evaluate_ids import evaluate_model
from netsentry.feature_contract import build_features
from netsentry.holdout_audit import continuation_candidates, near_key, load_sealed_week2
from netsentry.ids_data import sha, verified, write_json
from datetime import datetime, timedelta
import sqlite3
from contextlib import closing


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.x = np.array([[i, i % 3 + 1, i * 100] for i in range(30)], dtype=float)
        self.y = np.array([int(i > 14) for i in range(30)])

    def tearDown(self):
        self.temp.cleanup()

    def test_labels(self):
        self.assertEqual([binary_label(x) for x in ['normal', 'attacker', 'victim']], [0, 1, 1])
        with self.assertRaises(ValueError): binary_label('unknown')

    def test_whitelist(self):
        for key in ['label', 'attackType', 'record_id', 'timestamp', 'source_ip']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                matrix([dict(flow_duration=1, packets=1, bytes=100, **{key: 1})], 'F1')

    def test_order(self):
        np.testing.assert_equal(matrix([{'bytes':100,'packets':2,'flow_duration':1}], 'F1'), [[1,2,100]])

    def test_missing(self):
        with self.assertRaises(ValueError): matrix([{'packets':1,'bytes':1}], 'F1')

    def test_invalid_numbers(self):
        for bad in [None, -1, True, float('nan'), float('inf'), '2']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                matrix([dict(flow_duration=bad, packets=1, bytes=1)], 'F1')

    def test_fractional_packets(self):
        with self.assertRaises(ValueError): matrix([dict(flow_duration=1,packets=1.2,bytes=2)], 'F1')

    def test_training_roles(self):
        require_training_role('train')
        for role in ['validation','test','week2','same_environment_cross_week_holdout']:
            with self.subTest(role=role), self.assertRaises(ValueError): require_training_role(role)

    def test_three_estimators(self):
        for kind in ['dummy','logistic','rf100']:
            with self.subTest(kind=kind):
                model = make_pipeline('F1', kind)
                model.fit(self.x, self.y)
                self.assertEqual(len(model.predict(self.x)), 30)

    def test_preprocessing_train_only(self):
        model = make_pipeline('F1', 'logistic').fit(self.x, self.y)
        scaler = model.named_steps['preprocess'].named_transformers_['numeric'].named_steps['scale']
        mean = scaler.mean_.copy()
        model.predict(np.array([[999999, 999999, 999999]], dtype=float))
        np.testing.assert_array_equal(scaler.mean_, mean)
        np.testing.assert_allclose(mean, self.x.mean(axis=0))

    def test_persistence(self):
        model = make_pipeline('F1','logistic').fit(self.x,self.y)
        registry = ModelRegistry(self.root)
        registry.save('example', model, 'F1', {'synthetic':True})
        loaded, manifest = registry.load('example')
        np.testing.assert_array_equal(loaded.predict_proba(self.x), model.predict_proba(self.x))
        self.assertEqual(manifest['scheme'], 'F1')

    def test_unknown_model(self):
        with self.assertRaises(ValueError): ModelRegistry(self.root).load('../outside')

    def test_tampered_model_rejected_before_load(self):
        registry = ModelRegistry(self.root)
        registry.save('example', make_pipeline('F1','dummy').fit(self.x,self.y), 'F1', {})
        (self.root/'example.joblib').write_bytes(b'untrusted')
        with patch('netsentry.model_registry.joblib.load') as load:
            with self.assertRaises(ValueError): registry.load('example')
            load.assert_not_called()

    def test_metrics(self):
        result = metrics(np.array([0,0,1,1]), np.array([0.1,0.6,0.7,0.8]))
        self.assertEqual(result['confusion_matrix'], [[1,1],[0,2]])
        self.assertEqual(result['false_positive_rate'], 0.5)
        self.assertEqual(result['recall'], 1)

    def test_single_class_metrics(self):
        self.assertIsNone(metrics(np.array([0,0]), np.array([0.1,0.2]))['roc_auc'])

    def test_unsealed_test(self):
        with self.assertRaises(ValueError): claim_test(self.root, 'week2', 'a'*64, 'b'*64, False)
        self.assertFalse(list(self.root.glob('*.json')))

    def test_test_once(self):
        claim_test(self.root,'week2','a'*64,'b'*64,True)
        with self.assertRaises(FileExistsError): claim_test(self.root,'week2','a'*64,'b'*64,True)

    def test_prediction_isolation(self):
        registry=ModelRegistry(self.root/'models')
        registry.save('example',make_pipeline('F1','dummy').fit(self.x,self.y),'F1',{})
        predictor=IDSPredictor(self.root, model_id='example')
        with patch('builtins.open', side_effect=AssertionError('推理不应读取标签文件')):
            result=predictor.predict_one(dict(flow_duration=1,packets=2,bytes=100))
        self.assertNotIn('label',result)
        self.assertNotIn('attackType',result)
        self.assertEqual(result['prediction_status'],'DEV_ONLY')
        self.assertIn('attack_related_score',result)

    def test_evaluate_test_requires_freeze(self):
        model=make_pipeline('F1','dummy').fit(self.x,self.y)
        with self.assertRaises(ValueError):evaluate_model(model,self.x,self.y,role='week2')

    def test_blocked_week2_cannot_load(self):
        path=self.root/'manifest.json';write_json(path,{'sealed':False})
        with self.assertRaises(ValueError):load_sealed_week2(path,'F1',sha(path))

    def test_session_candidate_reverse_and_boundary(self):
        now=datetime(2017,3,22);key=(('10.0.0.1',1234),('10.0.0.2',80))
        self.assertEqual(len(continuation_candidates({key:now},{key:now+timedelta(seconds=120)})),1)
        self.assertEqual(continuation_candidates({key:now},{key:now+timedelta(seconds=121)}),[])

    def test_near_duplicates_not_labels(self):
        self.assertEqual(near_key(dict(flow_duration=1.0001,bytes=101,packets=1)),
                         near_key(dict(flow_duration=1.0002,bytes=102,packets=1)))

    def test_sha_does_not_modify_source(self):
        path=self.root/'original.csv';path.write_bytes(b'Duration,Label\n1,normal\n')
        before=path.read_bytes();verified(path,sha(path));self.assertEqual(before,path.read_bytes())

    def test_sha_mismatch(self):
        path=self.root/'original.csv';path.write_bytes(b'original')
        with self.assertRaises(ValueError):verified(path,'0'*64)

    def test_f3_ports_contract_and_encoder(self):
        x=build_features({'features':{'flow_duration':1,'packets':2,'bytes':200},'protocol':6,
            'source_port':123,'destination_port':80},{'Bytes':'200','Flags':'....S.'},'F3')['X']
        arr=matrix([x]*30,'F3');model=make_pipeline('F3','logistic').fit(arr,self.y)
        x['source_port']=65535
        model.predict(matrix([x],'F3'))
        x['source_port']=65536
        with self.assertRaises(ValueError):matrix([x],'F3')

    def test_f2_derived_field_consistency(self):
        x=build_features({'features':{'flow_duration':1,'packets':2,'bytes':200}},
                         {'Bytes':'200','Flags':'......'},'F2')['X']
        x['mean_bytes_per_packet']=999
        with self.assertRaises(ValueError):matrix([x],'F2')

    def test_record_prediction_reads_only_feature_store(self):
        ModelRegistry(self.root/'models').save('example',make_pipeline('F1','dummy').fit(self.x,self.y),'F1',{})
        target=self.root/'inference.sqlite';rid='a'*64
        with closing(sqlite3.connect(target)) as connection, connection:
            connection.execute('CREATE TABLE features(record_id TEXT PRIMARY KEY,x TEXT)')
            connection.execute('INSERT INTO features VALUES (?,?)',(rid,json.dumps(dict(flow_duration=1,packets=2,bytes=100))))
        write_json(self.root/'inference_store.json',{'scheme':'F1','sha256':sha(target)})
        predictor=IDSPredictor(self.root,model_id='example')
        result=predictor.predict_for_record(rid)
        self.assertEqual(result['record_id'],rid)
        self.assertFalse(any('label' in key.lower() for key in result))
        with self.assertRaises(KeyError):predictor.predict_for_record('b'*64)
        with self.assertRaises(ValueError):predictor.predict_for_record("' OR 1=1")

    def test_registry_never_overwrites(self):
        registry=ModelRegistry(self.root);model=make_pipeline('F1','dummy').fit(self.x,self.y)
        registry.save('example',model,'F1',{})
        with self.assertRaises(FileExistsError):registry.save('example',model,'F1',{})

    def test_incomplete_candidates_cannot_freeze(self):
        with self.assertRaises(ValueError):complete_candidates([{'scheme':'F1','kind':'logistic'}],[])

    def test_no_reselection_after_test_access(self):
        write_json(self.root/'prior_test.json',{'test_accessed':True})
        with self.assertRaises(ValueError):selection_allowed(False,False,self.root)
        selection_allowed(True,False,self.root)

    def test_completion_mode_forbids_tests(self):
        with self.assertRaises(ValueError):selection_allowed(True,True,self.root)

    def test_random_forest_reload_classes_and_tolerance(self):
        rng=np.random.default_rng(42);x=rng.normal(size=(100,3));y=(x[:,0]>0).astype(int)
        model=make_pipeline('F1','rf100').fit(x,y);registry=ModelRegistry(self.root)
        registry.save('forest',model,'F1',{});loaded,_=registry.load('forest')
        a=model.predict_proba(x);b=loaded.predict_proba(x)
        np.testing.assert_allclose(a,b,rtol=0,atol=1e-12)
        np.testing.assert_array_equal(a[:,1]>=0.5,b[:,1]>=0.5)

    def test_complete_candidates_requires_every_baseline(self):
        complete=[{'scheme':s,'kind':k} for s in ('F1','F2') for k in ('dummy','logistic','rf100','rf200')]
        complete_candidates(complete,[])
        with self.assertRaises(ValueError):complete_candidates(complete[:-1],[])


if __name__ == '__main__': unittest.main()
