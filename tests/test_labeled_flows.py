"""M1.7 合成验收，真实文件验证另行记录。"""
import csv
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from netsentry.labeled_flows import import_labeled_flows, ImportLimits
from netsentry.labeled_query import LabeledFlowQuery, OfflineFlowStore

HEADER = ['Flow ID',' Source IP',' Source Port',' Destination IP',' Destination Port',' Protocol',' Timestamp',' Flow Duration',' Total Fwd Packets',' Label','attackDescription','mystery']
ROWS = [
    ['DUPLICATE','192.0.2.1','1234','198.51.100.2','443','6','04/07/2017 10:00:00','1000','2','SECRET_BENIGN','SECRET_DESCRIPTION','SECRET_UNKNOWN'],
    ['DUPLICATE','198.51.100.2','443','192.0.2.1','1234','6','04/07/2017 10:00:01','1000','2','SECRET_ATTACK','SECRET_DESCRIPTION','SECRET_UNKNOWN'],
    ['OTHER','192.0.2.10','1234','203.0.113.8','80','6','04/07/2017 10:10:00','3000','3','SECRET_BENIGN','',''],
]
WINDOW = ('2017-07-04T10:00:00','2017-07-04T10:01:00')


class LabeledTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.csv = self.root/'SECRET_FILENAME.csv'
        self.out = self.root/'imported'

    def write(self, rows=None, header=None):
        with self.csv.open('w',encoding='utf-8',newline='') as stream:
            writer=csv.writer(stream)
            writer.writerow(HEADER if header is None else header)
            writer.writerows(ROWS if rows is None else rows)

    def run_import(self, **kwargs):
        return import_labeled_flows(self.csv, output_dir=self.out, profile='cicids2017_glf', provenance='synthetic', **kwargs)

    def query(self):
        query=LabeledFlowQuery(self.out/'events.sqlite')
        self.addCleanup(query.close)
        return query

    def store(self):
        store=OfflineFlowStore(self.out/'offline.sqlite')
        self.addCleanup(store.close)
        return store

    def test_dual_views_have_same_record_identity(self):
        self.write()
        report=self.run_import()
        result=self.query().query_flows_by_source_ip('192.0.2.1', WINDOW)
        event=result['records'][0]
        model=self.store().get_model_view(event['record_id'])
        self.assertEqual(model['record_id'],event['record_id'])
        self.assertEqual(model['X'],{'flow_duration':1000.0,'fwd_packets':2.0})
        self.assertEqual(report['rows'],3)
        self.assertEqual(self.store().get_training_target(event['record_id'])['label'],'SECRET_BENIGN')

    def test_all_agent_outputs_and_database_are_label_free(self):
        self.write()
        self.run_import()
        query=self.query()
        record=query.query_flows_by_host_ip('192.0.2.1',WINDOW)['records'][0]
        outputs=[query.get_flow_detail(record['record_id']),query.get_flow_provenance(record['record_id']),
                 query.query_related_flows(record['record_id'],10),query.query_flows_by_destination_ip('192.0.2.1',WINDOW)]
        content=json.dumps(outputs)+str((self.out/'events.sqlite').read_bytes())
        for secret in ['SECRET_BENIGN','SECRET_ATTACK','SECRET_DESCRIPTION','SECRET_UNKNOWN','SECRET_FILENAME','DUPLICATE']:
            self.assertNotIn(secret,content)
        self.assertNotIn('offline.sqlite',json.dumps(outputs))

    def test_features_exclude_metadata_label_and_unknown(self):
        self.write()
        self.run_import()
        record=self.query().query_flows_by_host_ip('192.0.2.1',WINDOW)['records'][0]
        features=self.store().get_model_view(record['record_id'])['X']
        self.assertEqual(set(features),{'flow_duration','fwd_packets'})

    def test_duplicate_flow_id_never_overwrites(self):
        self.write()
        report=self.run_import()
        self.assertEqual(report['flow_id']['duplicate_excess'],1)
        self.assertEqual(len(self.query().query_flows_by_host_ip('192.0.2.1',WINDOW)['records']),2)

    def test_reverse_and_exact_ip_queries(self):
        self.write()
        self.run_import()
        query=self.query()
        self.assertEqual(len(query.query_flows_by_source_ip('192.0.2.1',WINDOW)['records']),1)
        self.assertEqual(len(query.query_flows_by_destination_ip('192.0.2.1',WINDOW)['records']),1)
        self.assertEqual(len(query.query_flows_by_host_ip('192.0.2.1',WINDOW)['records']),2)
        self.assertEqual(query.query_flows_by_host_ip('192.0.2.10',WINDOW)['records'],[])

    def test_time_bounds_ports_and_pagination(self):
        self.write()
        self.run_import()
        query=self.query()
        result=query.query_flows_by_host_ip('192.0.2.1',WINDOW,limit=1)
        self.assertTrue(result['has_more'])
        self.assertEqual(result['total'],2)
        other=query.query_flows_by_host_ip('192.0.2.1',WINDOW,limit=1,offset=1)
        self.assertNotEqual(result['records'][0]['record_id'],other['records'][0]['record_id'])
        self.assertEqual(len(query.query_flows_by_host_ip('192.0.2.1',(WINDOW[0],'2017-07-04T10:00:01'))['records']),1)
        self.assertEqual(len(query.query_flows_by_host_ip('192.0.2.1',WINDOW,destination_port=443)['records']),1)

    def test_empty_results(self):
        self.write()
        self.run_import()
        query=self.query()
        self.assertEqual(query.query_flows_by_source_ip('203.0.113.99',WINDOW)['records'],[])
        self.assertIsNone(query.get_flow_detail('x')['record'])
        self.assertIsNone(query.get_flow_provenance('x')['record'])
        self.assertEqual(query.query_related_flows('x',10)['records'],[])

    def test_related_candidate_not_confirmed(self):
        self.write()
        self.run_import()
        query=self.query()
        record=query.query_flows_by_source_ip('192.0.2.1',WINDOW)['records'][0]
        result=query.query_related_flows(record['record_id'],1)
        self.assertEqual(len(result['records']),1)
        self.assertEqual(result['association_status'],'unverified')

    def test_illegal_parameters(self):
        self.write()
        self.run_import()
        query=self.query()
        for address,window,options in [("a' OR 1=1",WINDOW,{}),('192.0.2.1',WINDOW,{'limit':1001}),
                ('192.0.2.1',WINDOW,{'source_port':70000}),('192.0.2.1',(WINDOW[1],WINDOW[0]),{}),
                ('192.0.2.1',('2017-07-04T10:00:00Z','2017-07-04T11:00:00Z'),{}),
                ('192.0.2.1',WINDOW,{'offset':-1})]:
            with self.subTest(options=options,address=address,window=window):
                with self.assertRaises(ValueError): query.query_flows_by_host_ip(address,window,**options)

    def test_invalid_ip_port_time_are_not_fabricated(self):
        row=ROWS[0].copy()
        row[1]='ATTACKER1';row[2]='70000';row[6]='not a timestamp'
        self.write([row])
        report=self.run_import()
        self.assertEqual(report['metadata_validation']['source_ip']['invalid'],1)
        self.assertEqual(report['metadata_validation']['source_port']['invalid'],1)
        self.assertEqual(report['metadata_validation']['timestamp']['invalid'],1)
        self.assertEqual(report['event_ready_rows'],0)

    def test_ipv6_normalized(self):
        row=ROWS[0].copy();row[1]='2001:0db8::1'
        self.write([row]);self.run_import()
        self.assertEqual(len(self.query().query_flows_by_source_ip('2001:db8::1',WINDOW)['records']),1)

    def test_no_original_flow_id_remains_null(self):
        self.write([row[1:] for row in ROWS],HEADER[1:])
        self.run_import()
        event=self.query().query_flows_by_source_ip('192.0.2.1',WINDOW)['records'][0]
        self.assertIsNone(self.store().get_record(event['record_id'])['flow_id'])

    def test_missing_label_header_fails_without_output(self):
        self.write([[v for i,v in enumerate(row) if i!=9] for row in ROWS],[v for i,v in enumerate(HEADER) if i!=9])
        with self.assertRaises(ValueError):self.run_import()
        self.assertFalse(self.out.exists())

    def test_missing_label_value_unavailable_for_supervision(self):
        row=ROWS[0].copy();row[9]=''
        self.write([row]);report=self.run_import()
        self.assertEqual(report['labels']['missing'],1)
        self.assertEqual(report['supervised_ready_rows'],0)

    def test_duplicate_columns_rejected(self):
        self.write([['x','y']],['Label',' label '])
        with self.assertRaises(ValueError):self.run_import()

    def test_ambiguous_role_alias_rejected(self):
        self.write([ROWS[0]+['192.0.2.4']],HEADER+['Src IP'])
        with self.assertRaises(ValueError):self.run_import()

    def test_empty_bad_encoding_and_broken_csv(self):
        for data in [b'',b'\xff',b'Label,Source IP\n"unclosed']:
            self.csv.write_bytes(data)
            with self.assertRaises(ValueError):self.run_import()
        self.assertFalse(self.out.exists())

    def test_quality_nonfinite_negative_and_parse_failure(self):
        rows=[]
        for value in ['NaN','Infinity','-Infinity','bad','-1','']:
            row=ROWS[0].copy();row[7]=value;rows.append(row)
        self.write(rows);report=self.run_import()
        p=report['column_profiles']['Flow Duration']
        self.assertEqual((p['non_finite'],p['numeric_parse_errors'],p['negative'],p['missing']),(3,1,1,1))
        self.assertEqual(report['model_ready_rows'],0)

    def test_full_duplicates_and_feature_label_conflict(self):
        self.write([ROWS[0],ROWS[0],ROWS[1]])
        report=self.run_import()
        self.assertEqual(report['duplicates']['full_row_excess'],1)
        self.assertEqual(report['duplicates']['feature_label_conflict_groups'],1)

    def test_stable_id_and_original_provenance(self):
        self.write();self.run_import()
        query=self.query();event=query.query_flows_by_source_ip('192.0.2.1',WINDOW)['records'][0]
        copied=self.root/'renamed.csv';copied.write_bytes(self.csv.read_bytes())
        other=self.root/'other'
        import_labeled_flows(copied,output_dir=other,profile='cicids2017_glf',provenance='synthetic')
        with LabeledFlowQuery(other/'events.sqlite') as q:
            self.assertEqual(event['record_id'],q.query_flows_by_source_ip('192.0.2.1',WINDOW)['records'][0]['record_id'])
        provenance=query.get_flow_provenance(event['record_id'])['record']
        self.assertEqual(provenance['original_row_number'],2)

    def test_hash_unchanged(self):
        self.write();before=hashlib.sha256(self.csv.read_bytes()).hexdigest()
        report=self.run_import()
        self.assertEqual(before,report['source']['sha256'])
        self.assertEqual(before,report['source']['sha256_after'])
        self.assertEqual(before,hashlib.sha256(self.csv.read_bytes()).hexdigest())

    def test_limits_and_output_conflict(self):
        self.write()
        with self.assertRaises(ValueError):self.run_import(limits=ImportLimits(max_rows=1))
        self.assertFalse(self.out.exists())
        self.run_import()
        with self.assertRaises(ValueError):self.run_import()

    def test_readonly_and_wrong_database_rejected(self):
        self.write();self.run_import()
        with self.assertRaises(sqlite3.OperationalError):self.query().connection.execute('DELETE FROM events')
        with self.assertRaises(ValueError):LabeledFlowQuery(self.out/'offline.sqlite')

    def test_cidds_profile_is_separate_and_excludes_attack_fields(self):
        self.write([['2017-03-15 10:00:00.000','0.1','TCP','192.168.100.1','1234','192.168.100.2','22','3','1.2 M','......','1','0','attacker','bruteForce','42','SECRET_DESCRIPTION']],
            ['Date first seen','Duration','Proto','Src IP Addr','Src Pt','Dst IP Addr','Dst Pt','Packets','Bytes','Flags','Flows','Tos','class','attackType','attackID','attackDescription'])
        report=import_labeled_flows(self.csv,output_dir=self.out,profile='cidds001',provenance='synthetic')
        self.assertEqual(report['rows'],1)
        event=self.query().query_flows_by_source_ip('192.168.100.1',('2017-03-15T09:00:00','2017-03-15T11:00:00'))['records'][0]
        model=self.store().get_model_view(event['record_id'])
        self.assertEqual(model['X']['bytes'],1200000.0)
        self.assertNotIn('SECRET',json.dumps(event))

    def test_feature_order_explicit(self):
        self.write();self.run_import()
        record=self.query().query_flows_by_source_ip('192.0.2.1',WINDOW)['records'][0]
        view=self.store().get_model_view(record['record_id'])
        self.assertEqual(list(view['X']),view['feature_order'])

    def test_fractional_packet_count_ineligible(self):
        row=ROWS[0].copy();row[8]='2.5'
        self.write([row]);report=self.run_import()
        self.assertEqual(report['model_ready_rows'],0)
        self.assertEqual(report['column_profiles']['Total Fwd Packets']['domain_errors'],1)

    def test_blank_and_multiline_provenance(self):
        row=ROWS[0].copy();row[11]='line one\nline two'
        self.write([row]);self.run_import()
        record=self.query().query_flows_by_source_ip('192.0.2.1',WINDOW)['records'][0]
        reference=self.query().get_flow_provenance(record['record_id'])['record']
        self.assertEqual(reference['original_row_number'],2)
        self.assertEqual(reference['imported_physical_end_line'],3)

    def test_repeated_header_is_counted_not_imported(self):
        self.write([ROWS[0],HEADER,ROWS[1]])
        report=self.run_import()
        self.assertEqual((report['rows'],report['repeated_headers']),(2,1))

    def test_missing_source_ip_fails_contract(self):
        self.write([[v for i,v in enumerate(row) if i!=1] for row in ROWS],[v for i,v in enumerate(HEADER) if i!=1])
        with self.assertRaises(ValueError):self.run_import()

    def test_database_size_failure_is_atomic(self):
        self.write([ROWS[0]]*1000)
        with self.assertRaises(ValueError):self.run_import(limits=ImportLimits(max_db_bytes=256*1024))
        self.assertFalse(self.out.exists())

    def test_file_size_and_limits(self):
        self.write()
        with self.assertRaises(ValueError):self.run_import(limits=ImportLimits(max_bytes=5))
        with self.assertRaises(ValueError):ImportLimits(max_bytes=201*1024*1024)

    def test_source_change_rejected(self):
        from unittest.mock import patch
        self.write()
        with patch('netsentry.labeled_flows.file_sha256',side_effect=['a'*64,'b'*64]):
            with self.assertRaises(ValueError):self.run_import()
        self.assertFalse(self.out.exists())

    def test_anonymized_address_not_classified_as_numeric(self):
        row=ROWS[0].copy();row[1]='10002_113'
        self.write([row]);report=self.run_import()
        self.assertEqual(report['column_profiles']['Source IP']['observed_type'],'text')
        self.assertIsNone(report['column_profiles']['Source IP']['finite_min'])
        self.assertEqual(report['metadata_validation']['source_ip']['invalid'],1)


if __name__=='__main__':unittest.main()
