"""M1.6 合成夹具验收；不代表 CIC 真实 PCAP 验证。"""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import struct

from pcap_fixture import frame, write_pcap
from netsentry.pcap_extract import extract_pcap, FlowConfig, Limits, PcapError
from netsentry.flow_query import FlowQuery
from netsentry.pcap_alignment import assess_alignment


class PcapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pcap = self.root / "synthetic.pcap"
        self.db = self.root / "flows.sqlite"

    def run_extract(self, records=None, **kwargs):
        write_pcap(self.pcap, records)
        return extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test", **kwargs)

    def query(self):
        query = FlowQuery(self.db)
        self.addCleanup(query.close)
        return query

    def test_bidirectional_tcp_and_provenance(self):
        report = self.run_extract()
        self.assertEqual((report["packet_count"], report["flow_count"]), (2, 1))
        query = self.query()
        result = query.query_flows_by_source_ip("192.0.2.1", (0, 1800000000 * 10**9))
        flow = result["records"][0]
        self.assertEqual((flow["forward_packet_count"], flow["backward_packet_count"]), (1, 1))
        self.assertEqual((flow["forward_bytes"], flow["backward_bytes"]), (54, 54))
        self.assertEqual(flow["duration"], 1.0)
        evidence = query.get_flow_provenance(flow["flow_id"])
        self.assertEqual([r["packet_index"] for r in evidence["records"]], [1, 2])
        self.assertEqual([r["record_offset"] for r in evidence["records"]], [24, 94])
        self.assertEqual(flow["alignment_status"], "unverified")
        self.assertNotIn("label", flow)
        self.assertEqual(evidence["source"]["provenance"], "synthetic")

    def test_udp(self):
        self.run_extract([(1, 0, frame(protocol=17, dport=53))])
        flow = self.query().query_flows_by_destination_ip("198.51.100.2", (0, 2*10**9))["records"][0]
        self.assertEqual((flow["protocol"], flow["destination_port"]), (17, 53))

    def test_ipv6(self):
        self.run_extract([(1, 0, frame("2001:db8::1", "2001:db8::2", ipv6=True))])
        self.assertEqual(len(self.query().query_flows_by_source_ip("2001:0db8::1", (0, 2*10**9))["records"]), 1)

    def test_no_ports(self):
        self.run_extract([(1, 0, frame(protocol=1))])
        flow = self.query().query_flows_by_source_ip("192.0.2.1", (0, 2*10**9))["records"][0]
        self.assertIsNone(flow["source_port"])
        self.assertIsNone(flow["destination_port"])

    def test_idle_timeout_boundary(self):
        report = self.run_extract([(1, 0, frame()), (61, 0, frame())])
        self.assertEqual(report["flow_count"], 2)

    def test_active_timeout(self):
        report = self.run_extract([(1, 0, frame()), (40, 0, frame()), (61, 0, frame())],
                                  config=FlowConfig(idle_timeout_ns=60*10**9, active_timeout_ns=60*10**9))
        self.assertEqual(report["flow_count"], 2)

    def test_time_regression_splits(self):
        self.assertEqual(self.run_extract([(2, 0, frame()), (1, 0, frame())])["flow_count"], 2)

    def test_id_stability_and_config_identity(self):
        self.run_extract()
        first = self.query().query_flows_by_source_ip("192.0.2.1", (0, 1800000000*10**9))["records"][0]["flow_id"]
        for name, config, equal in [("second", FlowConfig(), True), ("third", FlowConfig(idle_timeout_ns=1), False)]:
            target = self.root / (name + ".sqlite")
            extract_pcap(self.pcap, target, provenance="synthetic", source_uri="fixture://unit-test", config=config)
            with FlowQuery(target) as query:
                other = query.query_flows_by_source_ip("192.0.2.1", (0, 1800000000*10**9))["records"][0]["flow_id"]
            self.assertEqual(first == other, equal)

    def test_precise_queries_and_half_open_time(self):
        self.run_extract([(1, 0, frame()), (2, 0, frame(sport=2222))])
        query = self.query()
        self.assertEqual(len(query.query_flows_by_source_ip("192.0.2.1", (10**9, 2*10**9))["records"]), 1)
        self.assertEqual(len(query.query_flows_by_destination_ip("198.51.100.2", (0, 3*10**9), source_port=2222, destination_port=443)["records"]), 1)
        self.assertEqual(query.query_flows_by_source_ip("192.0.2.10", (0, 3*10**9))["records"], [])
        with self.assertRaises(ValueError):
            query.query_flows_by_source_ip("192.0.2.1' OR 1=1", (0, 3*10**9))

    def test_related_is_candidate_and_excludes_anchor(self):
        self.run_extract([(1, 0, frame()), (2, 0, frame(sport=2222)), (3, 0, frame("203.0.113.1", "203.0.113.2"))])
        query = self.query()
        flow = query.query_flows_by_source_ip("192.0.2.1", (0, 2*10**9))["records"][0]
        result = query.query_related_flows(flow["flow_id"], 2*10**9)
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["association_status"], "unverified")
        self.assertNotEqual(result["records"][0]["flow_id"], flow["flow_id"])

    def test_hash_unchanged(self):
        write_pcap(self.pcap)
        before = hashlib.sha256(self.pcap.read_bytes()).hexdigest()
        result = extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")
        self.assertEqual(before, result["source"]["sha256_before"])
        self.assertEqual(before, result["source"]["sha256_after"])
        self.assertEqual(before, hashlib.sha256(self.pcap.read_bytes()).hexdigest())

    def test_zero_byte_empty(self):
        self.pcap.write_bytes(b"")
        with self.assertRaises(PcapError):
            extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")
        self.assertFalse(self.db.exists())

    def test_header_only_empty_capture(self):
        report = self.run_extract([])
        self.assertEqual((report["packet_count"], report["flow_count"]), (0, 0))

    def test_corrupt_record(self):
        write_pcap(self.pcap)
        self.pcap.write_bytes(self.pcap.read_bytes()[:-1])
        with self.assertRaises(PcapError):
            extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")
        self.assertFalse(self.db.exists())

    def test_size_limit(self):
        with self.assertRaises(PcapError):
            self.run_extract(limits=Limits(max_bytes=30))

    def test_packet_limit_atomic(self):
        with self.assertRaises(PcapError):
            self.run_extract(limits=Limits(max_packets=1))
        self.assertFalse(self.db.exists())

    def test_resource_configuration(self):
        with self.assertRaises(ValueError):
            Limits(max_bytes=201*1024*1024)
        with self.assertRaises(ValueError):
            FlowConfig(idle_timeout_ns=0)

    def test_no_overwrite(self):
        self.run_extract()
        before = self.db.read_bytes()
        with self.assertRaises(PcapError):
            extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")
        self.assertEqual(before, self.db.read_bytes())

    def test_pcapng_explicit_rejection(self):
        self.pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\0"*20)
        with self.assertRaisesRegex(PcapError, "PCAPNG"):
            extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")

    def test_big_endian_nanosecond(self):
        write_pcap(self.pcap, [(1, 123456789, frame())], endian=">", nano=True)
        extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")
        flow = self.query().query_flows_by_source_ip("192.0.2.1", (0, 2*10**9))["records"][0]
        self.assertEqual(flow["first_seen"], "1970-01-01T00:00:01.123456789Z")

    def test_non_ip_and_bad_packet_accounted(self):
        result = self.run_extract([(1, 0, bytes.fromhex("00112233445566778899aabb88b5") + b"\0"*20), (2, 0, b"bad")])
        self.assertEqual(result["flow_count"], 0)
        self.assertEqual(sum(result["packet_status_counts"].values()), 2)
        self.assertEqual(result["packet_status_counts"], {"non_ip_or_unsupported_ethertype": 1, "malformed_packet": 1})

    def test_fragment_not_silently_merged(self):
        payload = bytearray(frame())
        payload[20:22] = b"\x20\x00"
        result = self.run_extract([(1, 0, bytes(payload))])
        self.assertEqual(result["packet_status_counts"], {"fragment_not_reassembled": 1})
        self.assertEqual(result["flow_count"], 0)

    def test_ipv6_icmp_no_ports(self):
        self.run_extract([(1, 0, frame("2001:db8::1", "2001:db8::2", ipv6=True, protocol=58))])
        record = self.query().query_flows_by_source_ip("2001:db8::1", (0, 2*10**9))["records"][0]
        self.assertEqual(record["protocol"], 58)
        self.assertIsNone(record["source_port"])

    def test_capture_truncation_excluded(self):
        write_pcap(self.pcap, [(1, 0, frame())])
        content = bytearray(self.pcap.read_bytes())
        content[36:40] = struct.pack("<I", 200)
        self.pcap.write_bytes(content)
        result = extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")
        self.assertEqual(result["packet_status_counts"], {"capture_truncated": 1})
        self.assertEqual(result["flow_count"], 0)

    def test_unsupported_linktype(self):
        write_pcap(self.pcap, linktype=113)
        with self.assertRaisesRegex(PcapError, "UNSUPPORTED_LINKTYPE"):
            extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")

    def test_raw_ip(self):
        write_pcap(self.pcap, [(1, 0, frame()[14:])], linktype=101)
        result = extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")
        self.assertEqual(result["flow_count"], 1)

    def test_invalid_timestamp_fraction(self):
        write_pcap(self.pcap, [(1, 1000000, frame())])
        with self.assertRaisesRegex(PcapError, "CORRUPT_RECORD"):
            extract_pcap(self.pcap, self.db, provenance="synthetic", source_uri="fixture://unit-test")

    def test_disk_budget(self):
        from collections import namedtuple
        usage = namedtuple("usage", "total used free")(1024, 1024, 0)
        with patch("netsentry.pcap_extract.shutil.disk_usage", return_value=usage):
            with self.assertRaisesRegex(PcapError, "DISK_BUDGET"):
                self.run_extract()
        self.assertFalse(self.db.exists())

    def test_database_budget_no_partial_output(self):
        records = [(1, 0, frame(sport=n)) for n in range(100)]
        with self.assertRaisesRegex(PcapError, "EXTRACTION_IO_OR_RESOURCE_ERROR"):
            self.run_extract(records, limits=Limits(max_db_bytes=65536))
        self.assertFalse(self.db.exists())

    def test_changed_input_not_published(self):
        with patch("netsentry.pcap_extract.sha256_file", side_effect=["a"*64, "b"*64]):
            with self.assertRaisesRegex(PcapError, "SOURCE_CHANGED"):
                self.run_extract()
        self.assertFalse(self.db.exists())

    def test_timeout_no_partial_output(self):
        with patch("netsentry.pcap_extract.time.monotonic", side_effect=[0, 301]):
            with self.assertRaisesRegex(PcapError, "RESOURCE_LIMIT"):
                self.run_extract()
        self.assertFalse(self.db.exists())

    def test_invalid_queries(self):
        self.run_extract()
        query = self.query()
        for options in ({"limit": 1001}, {"destination_port": 65536}, {"offset": -1}):
            with self.assertRaises(ValueError):
                query.query_flows_by_source_ip("192.0.2.1", (0, 2*10**9), **options)
        with self.assertRaises(ValueError):
            query.query_flows_by_source_ip("192.0.2.1", (2, 1))

    def test_query_read_only_and_pagination(self):
        self.run_extract()
        query = self.query()
        with self.assertRaises(sqlite3.OperationalError):
            query.connection.execute("DELETE FROM flows")
        flow = query.query_flows_by_source_ip("192.0.2.1", (0, 1800000000*10**9))["records"][0]
        self.assertTrue(query.get_flow_provenance(flow["flow_id"], limit=1)["has_more"])
        self.assertIsNone(query.get_flow_detail("does-not-exist")["record"])

    def test_alignment_never_transfers_label(self):
        result = assess_alignment()
        self.assertEqual(result["status"], "unmatchable")
        self.assertIsNone(result["label"])
        self.assertFalse(result["compatible_with_78_features"])


if __name__ == "__main__":
    unittest.main()
