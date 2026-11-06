"""Synthetic arithmetic and strict request contract; no provider calls."""
import unittest
from netsentry.services.flow_analysis import calculate, AnalysisArguments


class AnalysisTests(unittest.TestCase):
    def rows(self):
        return [dict(record_id=str(i),source_ip='192.0.2.1',destination_ip='192.0.2.'+str(i+2),
                     source_port=1234,destination_port=p,protocol=6,timestamp=f'2017-03-15T10:00:{i:02d}.000000')
                for i,p in enumerate([80,80,443])]

    def test_host_counts_are_records(self):
        stats=calculate('summarize_host_behavior',self.rows(),'192.0.2.1','2017-03-15T10:00:00',60,10,10)
        self.assertEqual(stats['flow_count'],3)
        self.assertEqual(stats['unique_peers'],3)
        self.assertEqual(stats['unique_destination_ports'],2)
        self.assertEqual(stats['outbound_records'],3)

    def test_ports_count_each_record_once_per_distinct_port(self):
        stats=calculate('analyze_port_distribution',self.rows(),'192.0.2.1','2017-03-15T10:00:00',60,10,10)
        self.assertEqual(stats['unique_ports'],3)
        self.assertEqual(stats['top_ports'][0],{'port':1234,'flow_count':3})

    def test_temporal_buckets_sum(self):
        stats=calculate('analyze_temporal_bursts',self.rows(),'192.0.2.1','2017-03-15T10:00:00',60,10,10)
        self.assertEqual(sum(x['flow_count'] for x in stats['buckets']),3)
        self.assertEqual(stats['density_kind'],'sampled_flow_record_density')

    def test_invalid_and_extra_arguments(self):
        for kwargs in ({'limit':11},{'offset':1001},{'bucket_seconds':3},{'endpoint':'both'},{'sql':'DROP TABLE events'}):
            with self.assertRaises(ValueError):AnalysisArguments(**kwargs)

    def test_empty_statistics(self):
        self.assertEqual(calculate('summarize_host_behavior',[],'192.0.2.1','2017-03-15T10:00:00',60,10,10)['flow_count'],0)
