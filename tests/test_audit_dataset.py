"""M1.5 合成单元测试；与真实官方文件审计分别记录。"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import TestCase


class DatasetAuditTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "data.csv"

    def audit(self, content, **options):
        from netsentry.audit_dataset import audit_dataset
        self.path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        before = self.path.read_bytes()
        report = audit_dataset(self.path, provenance="synthetic", **options)
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(report["source"]["sha256"], hashlib.sha256(before).hexdigest())
        return report

    def test_counts_types_labels_duplicates(self):
        r = self.audit("Flow Duration,Flow Byts/s,Label\n1,NaN,Benign\n1,NaN,Benign\n,Infinity,Attack\nbad,-Infinity,Attack\n")
        self.assertEqual(r["row_count"], 4)
        self.assertEqual(r["label_distribution"]["counts"], {"Benign": 2, "Attack": 2})
        c = r["column_profiles"]["Flow Duration"]
        self.assertEqual((c["missing"], c["numeric_parse_errors"]), (1, 1))
        self.assertEqual(c["observed_type"], "mixed_numeric_text")
        self.assertEqual(r["column_profiles"]["Flow Byts/s"]["non_finite"], 4)
        self.assertEqual(r["column_profiles"]["Flow Byts/s"]["non_finite_breakdown"],
                         {"nan": 2, "positive_infinity": 1, "negative_infinity": 1})
        self.assertEqual(r["affected_rows"], {"missing": 1, "non_finite": 4, "numeric_parse_errors": 1})
        self.assertEqual(r["duplicates"]["full_row"]["excess_records"], 1)
        self.assertEqual(r["label_distribution"]["majority_minority_ratio"], 1)

    def test_missing_label_is_audited_but_not_training_ready(self):
        r = self.audit("Flow Duration\n1\n2\n")
        self.assertEqual(r["label_columns"], [])
        self.assertEqual(r["label_distribution"]["status"], "unavailable")
        self.assertIn("LABEL_UNAVAILABLE", r["warnings"])
        self.assertFalse(r["training_readiness"]["ready"])

    def test_label_aliases_ambiguity_never_choose_silently(self):
        r = self.audit("Flow Duration,Label,target\n1,Benign,Attack\n")
        self.assertEqual(r["label_distribution"]["status"], "ambiguous")
        self.assertNotIn("Label", r["feature_candidates"])
        self.assertNotIn("target", r["feature_candidates"])

    def test_metadata_validation_and_label_leak_candidates(self):
        r = self.audit("Source IP,Dst IP,Timestamp,Dst Port,Flow Duration,ground_truth,Label\n192.0.2.1,invalid,01/03/2018 10:00:00,70000,5,A,Benign\n")
        self.assertEqual(r["metadata_validation"]["Source IP"]["valid"], 1)
        self.assertEqual(r["metadata_validation"]["Dst IP"]["invalid"], 1)
        self.assertEqual(r["metadata_validation"]["Dst Port"]["invalid"], 1)
        self.assertEqual(r["metadata_validation"]["Timestamp"]["valid"], 1)
        self.assertIn("ground_truth", r["suspected_leakage_columns"])
        self.assertNotIn("ground_truth", r["feature_candidates"])
        self.assertFalse(r["authentication_evidence_available"])

    def test_repeated_headers_accounted_separately(self):
        r = self.audit("Flow Duration,Label\n1,Benign\nFlow Duration,Label\n2,Attack\n")
        self.assertEqual(r["records_seen"], 3)
        self.assertEqual(r["repeated_header_records"], 1)
        self.assertEqual(r["row_count"], 2)
        self.assertEqual(sum(r["label_distribution"]["counts"].values()), 2)

    def test_feature_duplicate_label_conflicts(self):
        r = self.audit("Flow Duration,Timestamp,Label\n5,01/03/2018 10:00:00,Benign\n5,01/03/2018 10:01:00,Attack\n")
        self.assertEqual(r["duplicates"]["full_row"]["excess_records"], 0)
        self.assertEqual(r["duplicates"]["candidate_features"]["excess_records"], 1)
        self.assertEqual(r["duplicates"]["candidate_features"]["conflicting_label_groups"], 1)

    def test_empty_corrupt_and_bad_headers(self):
        from netsentry.audit_csv import AuditError
        cases = [(b"", "EMPTY_FILE"), (b"x\n\xff", "INVALID_ENCODING"),
                 ('x\n"bad\n', "MALFORMED_CSV"), ("x,X\n1,2\n", "DUPLICATE_COLUMNS"),
                 ("x, \n1,2\n", "EMPTY_COLUMN_NAME"), ("x,y\n1\n", "ROW_WIDTH_MISMATCH"),
                 ("x\n", "NO_DATA_ROWS")]
        for data, code in cases:
            with self.subTest(code=code), self.assertRaises(AuditError) as caught:
                self.audit(data)
            self.assertEqual(caught.exception.code, code)

    def test_resource_limits_and_expected_sha(self):
        from netsentry.audit_csv import AuditError
        for options, expected in [({"max_bytes": 2}, "FILE_TOO_LARGE"),
                                  ({"max_rows": 1}, "RESOURCE_LIMIT"),
                                  ({"expected_sha256": "0" * 64}, "HASH_MISMATCH"),
                                  ({"max_labels": 1}, "RESOURCE_LIMIT")]:
            with self.subTest(options=options), self.assertRaises(AuditError) as caught:
                self.audit("Flow Duration,Label\n1,A\n2,B\n", **options)
            self.assertEqual(caught.exception.code, expected)

    def test_timestamp_order_and_missing_labels(self):
        r = self.audit("Timestamp,Flow Duration,Label\n01/03/2018 11:00:00,1,A\n01/03/2018 10:00:00,2, \nnot-time,3,A\n")
        self.assertEqual(r["time_summary"]["backward_steps"], 1)
        self.assertEqual(r["metadata_validation"]["Timestamp"]["invalid"], 1)
        self.assertEqual(r["label_distribution"]["missing"], 1)
        self.assertEqual(r["label_distribution"]["class_count"], 1)
        self.assertIsNone(r["label_distribution"]["majority_minority_ratio"])

    def test_unknown_column_not_silently_declared_numeric(self):
        r = self.audit("custom,Flow Duration,Label\nabc,1,Benign\n2,3,Attack\n")
        self.assertEqual(r["column_profiles"]["custom"]["expected_role"], "unknown")
        self.assertEqual(r["column_profiles"]["custom"]["numeric_parse_errors"], 0)
        self.assertNotIn("custom", r["feature_candidates"])

    def test_blank_lines_and_multiline_cells(self):
        r = self.audit('\nFlow Duration,note,Label\n1,"a\n\nb",Benign\n\n2,,Attack\n')
        self.assertEqual(r["row_count"], 2)
        self.assertEqual(r["column_profiles"]["note"]["missing"], 1)

    def test_cli_json_output_and_source_manifest(self):
        self.path.write_text("Flow Duration,Label\n1,Benign\n", encoding="utf-8")
        manifest = self.root / "source.json"
        manifest.write_text(json.dumps({"sha256": hashlib.sha256(self.path.read_bytes()).hexdigest(),
            "file_name": self.path.name, "size_bytes": self.path.stat().st_size,
            "provenance": "synthetic", "selection": {"method": "full_object"}}))
        output = self.root / "audit"
        result = subprocess.run([sys.executable,"-m","netsentry.audit_dataset",str(self.path),
            "--manifest",str(manifest),"--out",str(output)], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((output / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual(report["source"]["provenance"], "synthetic")
        self.assertEqual(report["scope"]["local_file_scan"], "complete")
        self.assertIn("完整扫描", (output / "audit.md").read_text(encoding="utf-8"))

    def test_input_output_collision(self):
        from netsentry.audit_dataset import main
        self.path = self.root / "audit.json"
        self.path.write_text("x,Label\n1,Benign\n", encoding="utf-8")
        self.assertEqual(main([str(self.path),"--out",str(self.root)]), 2)
        self.assertEqual(self.path.read_text(), "x,Label\n1,Benign\n")

    def test_missing_file(self):
        from netsentry.audit_dataset import audit_dataset
        from netsentry.audit_csv import AuditError
        with self.assertRaises(AuditError) as caught:
            audit_dataset(self.path)
        self.assertEqual(caught.exception.code, "INPUT_NOT_FOUND")

    def test_file_over_m1_limit_supported(self):
        from netsentry.audit_csv import AuditError, audit_csv
        content = "Flow Duration,note,Label\n" + ("1," + "x" * 1024 + ",Benign\n") * 21500
        r = self.audit(content)
        self.assertGreater(r["source"]["size_bytes"], 20 * 1024 * 1024)
        self.assertEqual(r["row_count"], 21500)
        self.assertEqual(r["duplicates"]["full_row"]["excess_records"], 21499)
        with self.assertRaises(AuditError) as caught:
            audit_csv(self.path)
        self.assertEqual(caught.exception.code, "FILE_TOO_LARGE")

    def test_sqlite_budget_failure_is_explicit(self):
        from netsentry.audit_csv import AuditError
        content = "Flow Duration,note,Label\n" + "\n".join(f"{i},{'x' * 2048},Benign" for i in range(20))
        with self.assertRaises(AuditError) as caught:
            self.audit(content, max_temp_bytes=16384)
        self.assertEqual(caught.exception.code, "RESOURCE_LIMIT")

    def test_cli_failure_preserves_previous_output(self):
        from netsentry.audit_dataset import main
        output = self.root / "output"
        output.mkdir()
        (output / "audit.json").write_bytes(b"keep")
        self.path.write_bytes(b"x,x\n1,2\n")
        self.assertEqual(main([str(self.path), "--out", str(output)]), 2)
        self.assertEqual((output / "audit.json").read_bytes(), b"keep")

    def test_unicode_header_normalization_and_blank_file(self):
        r = self.audit("\ufeff Flow Duration , Label \n1,A\n")
        self.assertEqual(r["columns"], ["Flow Duration", "Label"])
        self.assertEqual(r["raw_columns"], [" Flow Duration ", " Label "])
        from netsentry.audit_csv import AuditError
        with self.assertRaises(AuditError) as caught:
            self.audit("\ufeff\n \t\n")
        self.assertEqual(caught.exception.code, "EMPTY_FILE")
