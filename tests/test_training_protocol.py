"""M2A 合成边界测试；不使用夹具声称真实数据验证。"""
import copy
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from netsentry.label_policy import label_policy, map_target
from netsentry.feature_contract import feature_contract, build_features, contract_version
from netsentry.data_split import make_split
from netsentry.leakage_checks import inspect_split, validate_event
from netsentry.prepare_training import prepare_protocol
from netsentry.labeled_flows import import_labeled_flows


def samples(n=60):
    return [{'record_id':str(i),'y':'normal' if i%2==0 else 'attack-related',
             'feature_key':str(i),'attack_group':None if i%2==0 else 'a'+str(i),
             'normal_group':'n'+str(i) if i%2==0 else None,
             'timestamp':f'2017-03-{15+i%7:02d}T12:00:00.000000','duration':1.0}
            for i in range(n)]


class PolicyTests(unittest.TestCase):
    def test_binary_mapping_preserves_victim_as_related(self):
        self.assertEqual(map_target('victim','dos','B'),'attack-related')
        self.assertEqual(map_target('normal','---','B'),'normal')

    def test_three_class(self):
        self.assertEqual(map_target('victim','dos','A'),'victim')

    def test_attack_type_target(self):
        self.assertEqual(map_target('attacker','portScan','C'),'portScan')
        self.assertEqual(map_target('normal','---','C'),'normal')

    def test_unknown_and_ambiguous_labels_rejected(self):
        for label in ['unknown','suspicious','ATTACKER','',None]:
            with self.subTest(label=label),self.assertRaises(ValueError):map_target(label,'---','B')

    def test_inconsistent_type_rejected(self):
        for label,kind in [('normal','dos'),('attacker','---'),('victim','madeup')]:
            with self.subTest(label=label),self.assertRaises(ValueError):map_target(label,kind,'C')

    def test_policy_has_version_and_fixed_classes(self):
        self.assertIn('attack-related',label_policy('B')['classes'])
        self.assertTrue(label_policy('B')['version'])


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.record={'features':{'flow_duration':0.0,'packets':2.0,'bytes':200.0},
                     'protocol':6,'source_port':40000,'destination_port':443,'source_ip':None,
                     'label':'SECRET','record_id':'SECRET_ID'}
        self.extra={'Flags':'.AP...','Bytes':'200','attackType':'SECRET','attackID':'SECRET'}

    def test_f1_exact_whitelist(self):
        self.assertEqual(set(build_features(self.record,self.extra,'F1')['X']),{'flow_duration','packets','bytes'})

    def test_f2_flags_and_derived_statistic(self):
        x=build_features(self.record,self.extra,'F2')['X']
        self.assertEqual(x['mean_bytes_per_packet'],100.0)
        self.assertEqual(x['flag_ack'],1)
        self.assertEqual(x['duration_zero'],1)
        self.assertNotIn('protocol_tcp',x)

    def test_f3_protocol_and_nontransport_ports(self):
        self.record.update(protocol=1,destination_port=None)
        x=build_features(self.record,self.extra,'F3')['X']
        self.assertEqual(x['protocol_icmp'],1)
        self.assertEqual(x['destination_port_not_applicable'],1)
        self.assertIsNone(x['destination_port'])

    def test_missing_anonymized_ip_not_filtered(self):
        self.assertTrue(build_features(self.record,self.extra,'F1')['eligible'])

    def test_invalid_base_feature_not_filled(self):
        for value in [None,float('nan'),float('inf'),-1]:
            self.record['features']['bytes']=value
            self.assertFalse(build_features(self.record,self.extra,'F1')['eligible'])

    def test_fractional_packets_rejected(self):
        self.record['features']['packets']=1.5
        self.assertFalse(build_features(self.record,self.extra,'F2')['eligible'])

    def test_zero_packets_ratio_missing(self):
        self.record['features']['packets']=0
        x=build_features(self.record,self.extra,'F2')['X']
        self.assertIsNone(x['mean_bytes_per_packet'])
        self.assertEqual(x['mean_bytes_per_packet_missing'],1)

    def test_bad_flags_no_silent_coercion(self):
        self.extra['Flags']='SECRET_ATTACK'
        self.assertFalse(build_features(self.record,self.extra,'F2')['eligible'])
        self.assertTrue(build_features(self.record,self.extra,'F1')['eligible'])

    def test_scaled_bytes_exclusion_is_explicit(self):
        self.extra['Bytes']='1.5 M'
        self.assertFalse(build_features(self.record,self.extra,'F1',scaled_policy='exclude')['eligible'])
        self.assertTrue(build_features(self.record,self.extra,'F1')['eligible'])

    def test_contract_change_changes_version(self):
        base=feature_contract('F2');changed=copy.deepcopy(base)
        changed['fields'][0]['unit']='milliseconds'
        self.assertNotEqual(contract_version(base),contract_version(changed))

    def test_no_sensitive_fields_in_any_x(self):
        for scheme in ['F1','F2','F3']:
            result=build_features(self.record,self.extra,scheme)
            self.assertNotIn('SECRET',json.dumps(result['X']))
            self.assertEqual(set(result['X']),{v['name'] for v in feature_contract(scheme)['fields']})


class SplitTests(unittest.TestCase):
    def test_reproducible_and_order_independent(self):
        a=make_split(samples(),'A_random',min_per_class=1)
        b=make_split(list(reversed(samples())),'A_random',min_per_class=1)
        self.assertEqual(a,b)
        self.assertEqual(sum(len(v) for v in a['assignments'].values()),60)

    def test_feature_group_never_split(self):
        rows=samples()
        for i,r in enumerate(rows):r['feature_key']=str(i//2)
        result=make_split(rows,'B_feature',min_per_class=1)
        self.assertEqual(result['checks']['feature_cross_groups'],0)

    def test_attack_group_never_split(self):
        rows=samples()
        for i,r in enumerate(rows):
            if r['attack_group']:r['attack_group']='activity'+str(i//6)
        result=make_split(rows,'D_activity',min_per_class=1)
        self.assertEqual(result['checks']['attack_cross_groups'],0)

    def test_overlap_detected(self):
        rows=samples(6)
        report=inspect_split(rows,{'train':['0','1'],'validation':['1','2'],'test':['3','4','5']},min_per_class=1)
        self.assertFalse(report['record_ids_disjoint'])

    def test_feature_and_activity_leakage_detected(self):
        rows=samples(6);rows[0]['feature_key']=rows[1]['feature_key']='duplicate'
        rows[1]['attack_group']=rows[3]['attack_group']='same_activity'
        check=inspect_split(rows,{'train':['0','3'],'validation':['1','2'],'test':['4','5']},min_per_class=1)
        self.assertEqual(check['feature_cross_groups'],1)
        self.assertEqual(check['attack_cross_groups'],1)

    def test_duplicate_input_id_rejected(self):
        rows=samples(6);rows[1]['record_id']=rows[0]['record_id']
        with self.assertRaises(ValueError):make_split(rows,'A_random')

    def test_coverage_infeasible_no_fallback(self):
        rows=samples()
        for r in rows:r['feature_key']='giant'
        result=make_split(rows,'B_feature',min_per_class=1)
        self.assertEqual(result['status'],'infeasible')
        self.assertEqual(result['strategy'],'B_feature')
        self.assertFalse(result['fallback_used'])

    def test_combined_components_preserve_transitive_links(self):
        rows=samples()
        for r in rows:r['feature_key']='one_component'
        result=make_split(rows,'E_components',min_per_class=1)
        self.assertEqual(result['status'],'infeasible')
        self.assertEqual(result['largest_group'],60)
        self.assertEqual(result['checks']['feature_cross_groups'],0)
        self.assertEqual(result['checks']['attack_cross_groups'],0)

    def test_absent_required_class_is_not_ignored(self):
        result=make_split(samples(),'A_random',min_per_class=1,required_classes=['normal','attack-related','new_class'])
        self.assertEqual(result['status'],'infeasible')
        self.assertIn('new_class',result['checks']['insufficient_classes']['train'])

    def test_time_and_purging(self):
        rows=samples()
        rows[0]['feature_key']=rows[5]['feature_key']='cross_time'
        a=make_split(rows,'C_time',min_per_class=1)
        b=make_split(rows,'C_purged',min_per_class=1)
        self.assertGreaterEqual(a['checks']['feature_cross_groups'],1)
        self.assertEqual(b['checks']['feature_cross_groups'],0)
        self.assertIn('0',b['assignments']['quarantine'])

    def test_purge_embargo_and_duration_overlap(self):
        rows=samples();rows[0].update(timestamp='2017-03-19T23:59:00.000000',duration=120)
        result=make_split(rows,'C_purged',min_per_class=1)
        self.assertIn('0',result['assignments']['quarantine'])

    def test_unknown_strategy_and_bad_seed(self):
        with self.assertRaises(ValueError):make_split(samples(),'fallback')
        with self.assertRaises(ValueError):make_split(samples(),'A_random',seed=True)

    def test_agent_no_label_no_x(self):
        event={'record_id':'x','source_ip':None,'flow_duration':1.0}
        validate_event(event)
        for key in ['class','label','attackType','attackID','X','features','packets','bytes']:
            with self.subTest(key=key),self.assertRaises(ValueError):validate_event({**event,key:1})


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.csv=self.root/'synthetic.csv';self.store=self.root/'m17'
        header=['Date first seen','Duration','Proto','Src IP Addr','Src Pt','Dst IP Addr','Dst Pt','Packets','Bytes','Flows','Flags','Tos','class','attackType','attackID','attackDescription']
        with self.csv.open('w',encoding='utf-8',newline='') as stream:
            writer=csv.writer(stream);writer.writerow(header)
            for i in range(60):
                label='normal' if i%2==0 else 'attacker'
                writer.writerow([f'2017-03-{15+i%7:02d} 12:00:00.000',i+1,'TCP','DNS',1234,'192.0.2.1',80,2,100+i,1,'.AP...',0,label,'---' if label=='normal' else 'dos','---' if label=='normal' else i,'---'])
        import_labeled_flows(self.csv,output_dir=self.store,profile='cidds001',provenance='synthetic')

    def test_real_pipeline_on_synthetic_fixture_and_immutability(self):
        paths=[self.csv,self.store/'offline.sqlite',self.store/'events.sqlite']
        before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
        result=prepare_protocol(self.csv,self.store,self.root/'result',min_per_class=1)
        self.assertEqual(result['data_kind'],'synthetic')
        self.assertEqual(result['rows'],60)
        self.assertEqual(result['analysis']['selection']['complete_metadata']['rows'],0)
        self.assertEqual(result['analysis']['features']['F1']['eligible_rows'],60)
        self.assertEqual(before,[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths])
        self.assertTrue(result['source']['csv_sha256'])
        self.assertTrue((self.root/'result/splits/F1/C_purged/train.ids.json').is_file())

    def test_source_mismatch_rejected(self):
        with self.csv.open('a') as stream:stream.write('\n')
        with self.assertRaises(ValueError):prepare_protocol(self.csv,self.store,self.root/'bad')
        self.assertFalse((self.root/'bad').exists())

    def test_output_conflict_not_overwritten(self):
        target=self.root/'existing';target.mkdir();(target/'mine.txt').write_text('keep')
        with self.assertRaises(ValueError):prepare_protocol(self.csv,self.store,target)
        self.assertEqual((target/'mine.txt').read_text(),'keep')

    def test_invalid_numeric_and_timestamp_excluded_without_fabrication(self):
        text=self.csv.read_text(encoding='utf-8').replace('2017-03-15 12:00:00.000,1,TCP','bad_time,NaN,TCP',1)
        self.csv.write_text(text,encoding='utf-8')
        fresh=self.root/'m17_changed'
        import_labeled_flows(self.csv,output_dir=fresh,profile='cidds001',provenance='synthetic')
        result=prepare_protocol(self.csv,fresh,self.root/'quality',min_per_class=1)
        self.assertEqual(result['analysis']['features']['F1']['excluded_rows'],1)
        self.assertEqual(result['analysis']['time']['unparseable'],1)

    def test_common_ids_contract(self):
        result=prepare_protocol(self.csv,self.store,self.root/'common',min_per_class=1)
        self.assertEqual(result['comparison_common']['eligible_rows'],60)
        self.assertEqual(result['comparison_common']['checks']['feature_cross_groups'],0)
        self.assertEqual(result['comparison_common']['checks']['attack_cross_groups'],0)
        self.assertEqual(len(result['code_sha256']),5)


if __name__=='__main__':unittest.main()
