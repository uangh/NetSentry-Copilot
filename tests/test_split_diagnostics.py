"""M2A.1合成夹具：验证归因和协议，不代表公开数据上的模型成绩。"""
import copy
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from netsentry.split_diagnostics import attribute_losses, temporal_reasons, group_report, component_report
from netsentry.split_comparison import compare_protocols, validate_development_source, prepare_comparison
from netsentry.leakage_checks import validate_event
from netsentry.labeled_flows import import_labeled_flows
from netsentry.prepare_training import prepare_protocol


def fixture(n=60):
    return [{'record_id':str(i),'y':'normal' if i%2==0 else 'attack-related',
             'feature_key':str(i),'feature_keys':{s:str(i) for s in ['F1','F2','F3']},
             'full_row_key':str(i),'attack_group':None if i%2==0 else 'a'+str(i),
             'normal_group':'n'+str(i) if i%2==0 else None,
             'timestamp':f'2017-03-{19+i%3:02d}T12:00:00','duration':1.0,
             'original_class':'normal' if i%2==0 else 'attacker','attack_id':str(i),
             'metadata_complete':i%3==0,'any_ip':True} for i in range(n)]


class AttributionTests(unittest.TestCase):
    def test_stages_conserve_counts(self):
        r=attribute_losses(fixture(3),{'0':['a'],'1':['a','b'],'2':[]},['a','b'])
        self.assertEqual(r['union_loss']['rows'],2)
        self.assertEqual(r['stages'][-1]['remaining']['rows'],1)
        self.assertEqual(sum(s['newly_removed']['rows'] for s in r['stages']),2)

    def test_duplicate_reason_not_double_counted(self):
        r=attribute_losses(fixture(2),{'0':['a','a','b'],'1':[]},['a','b'])
        self.assertEqual(r['standalone']['a']['rows'],1)
        self.assertEqual(r['union_loss']['rows'],1)
        self.assertEqual(r['exclusive']['a']['rows'],0)

    def test_rule_order_only_changes_marginal(self):
        rows=fixture(2);why={'0':['a','b'],'1':['b']}
        a=attribute_losses(rows,why,['a','b']);b=attribute_losses(rows,why,['b','a'])
        self.assertEqual(a['union_loss'],b['union_loss'])
        self.assertNotEqual(a['stages'],b['stages'])

    def test_unknown_reason_rejected(self):
        with self.assertRaises(ValueError):attribute_losses(fixture(1),{'0':['bad']},['a'])

    def test_unknown_id_rejected(self):
        with self.assertRaises(ValueError):attribute_losses(fixture(1),{'z':['a']},['a'])

    def test_empty_loss_conserves_all(self):
        self.assertEqual(attribute_losses(fixture(5),{},['a'])['union_loss']['rows'],0)

    def test_temporal_feature_and_activity_reasons(self):
        rows=fixture(6)
        rows[1]['feature_key']=rows[0]['feature_key']
        rows[1]['attack_group']=rows[3]['attack_group']='same'
        result=temporal_reasons(rows)
        self.assertIn('feature_key_crosses_time',result['reasons']['0'])
        self.assertIn('attack_group_crosses_time',result['reasons']['1'])

    def test_boundary_flow_end_overlap(self):
        rows=fixture(1);rows[0].update(timestamp='2017-03-19T23:58:00',duration=61)
        self.assertIn('boundary_embargo_or_flow_overlap',temporal_reasons(rows)['reasons']['0'])

    def test_boundary_far_record_retained(self):
        self.assertEqual(temporal_reasons(fixture(1))['reasons']['0'],[])

    def test_invalid_timestamp_reason(self):
        rows=fixture(1);rows[0]['timestamp']=None
        self.assertEqual(temporal_reasons(rows)['reasons']['0'],['invalid_time'])

    def test_group_conflict_and_crossing(self):
        rows=fixture(3);rows[1]['feature_keys']['F1']=rows[0]['feature_keys']['F1']
        report=group_report(rows,'F1')
        self.assertEqual(report['unique_groups'],2)
        self.assertEqual(report['conflict_groups'],1)
        self.assertEqual(report['time_cross_groups'],1)

    def test_transitive_components(self):
        rows=fixture(4)
        rows[0]['feature_key']=rows[1]['feature_key']='same'
        rows[1]['attack_group']=rows[3]['attack_group']='attack'
        report=component_report(rows,'E_components')
        self.assertEqual(report['largest_group'],3)


class ComparisonTests(unittest.TestCase):
    def test_three_protocols_same_feature_ids(self):
        report=compare_protocols(fixture(),minimum=1,min_activities=1)
        self.assertEqual(set(report),{'A_strict','B_time_activity','C_activity'})
        for r in report.values():
            self.assertEqual(r['feature_schemes'],['F1','F2','F3'])
            self.assertTrue(r['checks']['record_ids_disjoint'])
            self.assertTrue(r['checks']['all_records_accounted'])

    def test_b_retains_feature_duplicates_but_reports(self):
        rows=fixture();rows[1]['feature_key']=rows[0]['feature_key']='same'
        rows[1]['feature_keys']['F1']=rows[0]['feature_keys']['F1']='same'
        r=compare_protocols(rows,minimum=1,min_activities=1)
        self.assertIn('0',r['A_strict']['assignments']['quarantine'])
        self.assertNotIn('0',r['B_time_activity']['assignments']['quarantine'])
        self.assertEqual(r['B_time_activity']['feature_overlap']['F1']['groups'],1)

    def test_b_isolates_attack_activity(self):
        rows=fixture();rows[1]['attack_group']=rows[3]['attack_group']='same'
        r=compare_protocols(rows,minimum=1,min_activities=1)['B_time_activity']
        self.assertEqual(r['checks']['attack_cross_groups'],0)
        self.assertIn('1',r['assignments']['quarantine'])

    def test_c_preserves_business_groups(self):
        rows=fixture();rows[1]['attack_group']=rows[3]['attack_group']='same'
        r=compare_protocols(rows,minimum=1,min_activities=1)['C_activity']
        self.assertEqual(r['checks']['attack_cross_groups'],0)
        self.assertEqual(r['checks']['normal_block_cross_groups'],0)

    def test_reproducible_order_independent(self):
        a=compare_protocols(fixture(),minimum=1,min_activities=1)
        b=compare_protocols(list(reversed(fixture())),minimum=1,min_activities=1)
        self.assertEqual(a,b)

    def test_infeasible_no_fallback(self):
        for r in compare_protocols(fixture(6)).values():
            self.assertEqual(r['status'],'infeasible')
            self.assertFalse(r['fallback_used'])

    def test_activity_support_separate_from_row_support(self):
        rows=fixture();r=compare_protocols(rows,minimum=1,min_activities=100)['C_activity']
        self.assertTrue(r['checks']['class_coverage_ok'])
        self.assertFalse(r['activity_coverage_ok'])
        self.assertEqual(r['status'],'infeasible')

    def test_duplicate_id_rejected(self):
        rows=fixture(3);rows[1]['record_id']='0'
        with self.assertRaises(ValueError):compare_protocols(rows)

    def test_no_input_mutation(self):
        rows=fixture();before=copy.deepcopy(rows)
        compare_protocols(rows)
        self.assertEqual(before,rows)

    def test_bad_seed_rejected(self):
        with self.assertRaises(ValueError):compare_protocols(fixture(),seed=-1)

    def test_week2_rejected_for_development(self):
        with self.assertRaises(ValueError):validate_development_source({'original_file':'CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week2.csv'})

    def test_week1_allowed(self):
        validate_development_source({'original_file':'CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week1.csv'})

    def test_event_answers_rejected(self):
        for field in ['label','attackType','attackID','attackDescription','X']:
            with self.subTest(field=field),self.assertRaises(ValueError):validate_event({'record_id':'a',field:'answer'})

    def test_agent_population_not_same_as_model_population(self):
        r=compare_protocols(fixture(),minimum=1,min_activities=1)['C_activity']
        self.assertEqual(sum(v['rows'] for v in r['populations'].values()),60)
        self.assertLess(sum(v['metadata_complete']['rows'] for v in r['populations'].values()),60)


class ComparisonIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.csv=self.root/'synthetic.csv';self.store=self.root/'store';self.baseline=self.root/'baseline'
        header=['Date first seen','Duration','Proto','Src IP Addr','Src Pt','Dst IP Addr','Dst Pt','Packets','Bytes','Flows','Flags','Tos','class','attackType','attackID','attackDescription']
        with self.csv.open('w',encoding='utf-8',newline='') as stream:
            writer=csv.writer(stream);writer.writerow(header)
            for i in range(30):
                label='normal' if i%2==0 else 'attacker'
                writer.writerow([f'2017-03-{19+i%3:02d} 12:00:00.000',1,'TCP','DNS',123,'192.0.2.1',80,2,100+i,1,'.AP...',0,label,'---' if label=='normal' else 'dos','---' if label=='normal' else i,'---'])
        sha=hashlib.sha256(self.csv.read_bytes()).hexdigest()
        # 仅借用路径契约测试分支；provenance始终synthetic，绝非官方数据。
        source={'sha256':sha,'size_bytes':self.csv.stat().st_size,'file_name':self.csv.name,'dataset_id':'CIDDS-001','provenance':'synthetic',
                'original_file':'CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week1.csv',
                'selection':{'method':'systematic_every_nth_record','every':1,'first_original_row_number':2,'original_member_sha256':sha}}
        manifest=self.root/'source.json';manifest.write_text(json.dumps(source))
        import_labeled_flows(self.csv,output_dir=self.store,profile='cidds001',provenance='synthetic',manifest=manifest)
        prepare_protocol(self.csv,self.store,self.baseline)

    def test_full_pipeline_integrity_and_ledger(self):
        files=[self.csv,self.store/'offline.sqlite',self.store/'events.sqlite',*self.baseline.rglob('*.json')]
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        result=prepare_comparison(self.csv,self.store,self.baseline,self.root/'out')
        self.assertEqual(result['input_rows'],30)
        self.assertFalse(result['candidate_final_test_used_for_development'])
        self.assertTrue(result['strict_reproduces_old_ids'])
        self.assertEqual(len((self.root/'out/record_decisions.jsonl').read_text().splitlines()),30)
        self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files})

    def test_output_refuses_overwrite(self):
        out=self.root/'mine';out.mkdir();(out/'user.txt').write_text('keep')
        with self.assertRaises(ValueError):prepare_comparison(self.csv,self.store,self.baseline,out)
        self.assertEqual((out/'user.txt').read_text(),'keep')

    def test_baseline_tampering_rejected(self):
        (self.baseline/'F1_X.jsonl').write_text('changed')
        with self.assertRaises(ValueError):prepare_comparison(self.csv,self.store,self.baseline,self.root/'bad')
        self.assertFalse((self.root/'bad').exists())

    def test_raw_source_change_rejected(self):
        with self.csv.open('a') as stream:stream.write('\n')
        with self.assertRaises(ValueError):prepare_comparison(self.csv,self.store,self.baseline,self.root/'bad')


if __name__=='__main__':unittest.main()
