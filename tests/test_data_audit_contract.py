"""M1 冻结验收测试。应用实现前应失败；合成夹具不用于模型效果评测。"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "sample_data"


class DataAuditContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.output = self.work / "output"

    def create_input(self, content, name="input.csv"):
        path = self.work / name
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    def run_cli(self, path, provenance="synthetic"):
        return subprocess.run(
            [sys.executable, "-m", "netsentry.audit_csv", str(path),
             "--provenance", provenance, "--out", str(self.output)],
            cwd=ROOT, text=True, encoding="utf-8", capture_output=True, timeout=20,
        )

    def success(self, path, provenance="synthetic"):
        result = self.run_cli(path, provenance)
        self.assertEqual(result.returncode, 0, result.stderr)
        json_file = self.output / "report.json"
        md_file = self.output / "report.md"
        self.assertTrue(json_file.is_file(), "必须写 JSON 报告")
        self.assertTrue(md_file.is_file(), "必须写 Markdown 报告")
        return json.loads(json_file.read_text(encoding="utf-8"))

    def failure(self, path, expected_code):
        result = self.run_cli(path)
        self.assertEqual(result.returncode, 2, result.stderr)
        error = json.loads(result.stderr.strip())
        self.assertEqual(error["error"]["code"], expected_code)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse((self.output / "report.json").exists())

    @staticmethod
    def warning_codes(report):
        return {warning["code"] for warning in report["warnings"]}

    def test_01_valid_features_only_is_not_rejected(self):
        report = self.success(SAMPLES / "features_only.csv")
        self.assertEqual(report["schema_version"], "netsentry.data_audit.v1")
        self.assertEqual(report["row_count"], 3)
        self.assertEqual(len(report["columns"]), 8)

    def test_02_missing_ip_is_reported_not_invented(self):
        report = self.success(SAMPLES / "features_only.csv")
        flags = report["schema_capabilities"]
        self.assertIs(flags["has_source_ip_column"], False)
        self.assertIs(flags["has_destination_ip_column"], False)
        self.assertIn("SOURCE_IP_UNAVAILABLE", self.warning_codes(report))
        self.assertNotIn("source_ip", report["columns"])

    def test_03_labels_and_timestamp_excluded_from_candidates(self):
        report = self.success(SAMPLES / "features_only.csv")
        self.assertEqual(report["label_columns"], ["Label"])
        self.assertNotIn("Label", report["feature_candidates"])
        self.assertNotIn("Timestamp", report["feature_candidates"])
        self.assertIn("Flow Duration", report["feature_candidates"])
        self.assertIn("LABEL_EXCLUDED", self.warning_codes(report))

    def test_04_label_aliases_all_excluded(self):
        path = self.create_input("Flow Duration,Label,target,attack_cat,class\n5,A,B,C,D\n")
        report = self.success(path)
        self.assertEqual(set(report["label_columns"]), {"Label", "target", "attack_cat", "class"})
        self.assertEqual(report["feature_candidates"], ["Flow Duration"])

    def test_05_ip_metadata_does_not_become_model_feature(self):
        report = self.success(SAMPLES / "with_network_metadata.csv")
        flags = report["schema_capabilities"]
        self.assertIs(flags["has_source_ip_column"], True)
        self.assertIs(flags["has_destination_ip_column"], True)
        self.assertIs(flags["has_timestamp_column"], True)
        self.assertIs(flags["has_destination_port_column"], True)
        self.assertNotIn("Source IP", report["feature_candidates"])
        self.assertNotIn("Destination IP", report["feature_candidates"])

    def test_06_never_invent_authentication_evidence(self):
        report = self.success(SAMPLES / "with_network_metadata.csv")
        self.assertIs(report["authentication_evidence_available"], False)
        self.assertIn("AUTH_LOG_UNAVAILABLE", self.warning_codes(report))

    def test_07_numeric_issues_are_separate_counts(self):
        report = self.success(SAMPLES / "broken_numeric.csv")
        self.assertEqual(report["row_count"], 3)
        self.assertEqual(report["non_finite_values"]["Flow Byts/s"], 2)
        self.assertEqual(report["missing_values"]["Flow Duration"], 1)
        self.assertEqual(report["numeric_parse_errors"]["Flow Duration"], 1)
        self.assertEqual(report["numeric_parse_errors"]["Flow Byts/s"], 0)
        self.assertIn("NON_FINITE_VALUES", self.warning_codes(report))

    def test_08_source_hash_and_input_preservation(self):
        path = self.create_input((SAMPLES / "features_only.csv").read_bytes())
        before = path.read_bytes()
        report = self.success(path)
        self.assertEqual(report["source"]["sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(path.read_bytes(), before)

    def test_09_synthetic_provenance_is_explicit(self):
        report = self.success(SAMPLES / "features_only.csv")
        self.assertEqual(report["source"]["provenance"], "synthetic")
        self.assertIn("SYNTHETIC_DATA", self.warning_codes(report))

    def test_10_bom_and_header_spaces(self):
        path = self.create_input("\ufeff Flow Duration , Label \n1,BENIGN\n".replace("\\ufeff", "\ufeff"))
        report = self.success(path)
        self.assertEqual(report["columns"], ["Flow Duration", "Label"])
        self.assertEqual(report["label_columns"], ["Label"])

    def test_11_duplicate_normalized_headers_fail(self):
        self.failure(SAMPLES / "duplicate_headers.csv", "DUPLICATE_COLUMNS")

    def test_12_case_insensitive_duplicates_fail(self):
        path = self.create_input("Flow Duration,flow duration\n1,2\n")
        self.failure(path, "DUPLICATE_COLUMNS")

    def test_13_empty_file_fails(self):
        self.failure(SAMPLES / "empty.csv", "EMPTY_FILE")

    def test_14_header_only_fails(self):
        path = self.create_input("Flow Duration,Label\n")
        self.failure(path, "NO_DATA_ROWS")

    def test_15_ragged_record_fails(self):
        path = self.create_input("Flow Duration,Label\n1,BENIGN,EXTRA\n")
        self.failure(path, "ROW_WIDTH_MISMATCH")

    def test_16_input_not_found_fails(self):
        self.failure(self.work / "does_not_exist.csv", "INPUT_NOT_FOUND")

    def test_17_quoted_comma_is_one_cell(self):
        path = self.create_input('Flow Duration,note,Label\n1,"hello, world",BENIGN\n')
        report = self.success(path)
        self.assertEqual(report["row_count"], 1)
        self.assertEqual(len(report["columns"]), 3)

    def test_18_nonstandard_values_are_computed(self):
        path = self.create_input("Flow Duration,Label\n17,BENIGN\n23,BENIGN\n-Inf,EXAMPLE_ATTACK\n34,BENIGN\n58,BENIGN\n")
        report = self.success(path)
        self.assertEqual(report["row_count"], 5)
        self.assertEqual(report["non_finite_values"]["Flow Duration"], 1)
        self.assertEqual(report["missing_values"]["Flow Duration"], 0)

    def test_19_unknown_provenance_remains_unknown(self):
        report = self.success(SAMPLES / "features_only.csv", provenance="unknown")
        self.assertEqual(report["source"]["provenance"], "unknown")
        self.assertIn("UNKNOWN_PROVENANCE", self.warning_codes(report))

    def test_20_markdown_discloses_limits(self):
        self.success(SAMPLES / "features_only.csv")
        text = (self.output / "report.md").read_text(encoding="utf-8")
        self.assertIn("synthetic", text)
        self.assertIn("不能证明登录成功", text)


if __name__ == "__main__":
    unittest.main()
