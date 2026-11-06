"""新增边界测试；所有输入均在本地构造，不代表真实网络事件。"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DataAuditEdgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "input.csv"
        self.out = self.root / "reports"

    def run_cli(self, content, extra=(), out=None):
        self.path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return subprocess.run(
            [sys.executable, "-m", "netsentry.audit_csv", str(self.path),
             "--out", str(out or self.out), *extra],
            cwd=ROOT, capture_output=True, encoding="utf-8", timeout=20,
        )

    def success(self, content, extra=()):
        result = self.run_cli(content, extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads((self.out / "report.json").read_text(encoding="utf-8"))

    def failure(self, content, code):
        result = self.run_cli(content)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(len(result.stderr.splitlines()), 1)
        self.assertEqual(json.loads(result.stderr)["error"]["code"], code)
        self.assertFalse(self.out.exists())
        self.assertNotIn("Traceback", result.stderr)

    def test_invalid_utf8(self):
        self.failure(b"value\n\xff\n", "INVALID_ENCODING")

    def test_unclosed_quote(self):
        self.failure('value\n"unterminated\n', "MALFORMED_CSV")

    def test_empty_header(self):
        self.failure("a, ,b\n1,2,3\n", "EMPTY_COLUMN_NAME")

    def test_short_row_reports_line(self):
        result = self.run_cli("a,b\n1\n")
        self.assertEqual(result.returncode, 2)
        error = json.loads(result.stderr)["error"]
        self.assertEqual(error["code"], "ROW_WIDTH_MISMATCH")
        self.assertIn("2", error["message"])

    def test_whitespace_only_file(self):
        self.failure("\ufeff\n  \t\n\r\n", "EMPTY_FILE")

    def test_blank_physical_lines_but_not_empty_records(self):
        report = self.success('\n  \t\nvalue\n\n  \n""\n1\n')
        self.assertEqual(report["row_count"], 2)
        self.assertEqual(report["missing_values"], {"value": 1})

    def test_all_empty_cells_count_as_record(self):
        report = self.success("a,b\n,\n")
        self.assertEqual(report["row_count"], 1)
        self.assertEqual(report["missing_values"], {"a": 1, "b": 1})

    def test_multiline_quoted_value(self):
        report = self.success('Flow Duration,note\n2,"hello\n\nworld, \'quoted\'"\n')
        self.assertEqual(report["row_count"], 1)
        self.assertNotIn("hello", json.dumps(report))

    def test_cr_newlines_and_bom_hash(self):
        content = b'\xef\xbb\xbfvalue\r1\r2\r'
        report = self.success(content)
        self.assertEqual(report["row_count"], 2)
        self.assertEqual(report["source"]["sha256"], hashlib.sha256(content).hexdigest())

    def test_all_aliases_and_ambiguity(self):
        names = ["Src IP", "source_ip", "Dst IP", "destination_ip", "time_stamp",
                 "Flow Start Time", "Flow ID", "flow_id", "attack_type", "TARGET",
                 "Source Port", "destination_port", "Protocol"]
        report = self.success(",".join(names) + "\n" + ",".join(["1"] * len(names)) + "\n")
        self.assertEqual(report["feature_candidates"], ["Source Port", "destination_port", "Protocol"])
        ambiguous = [w for w in report["warnings"] if w["code"] == "AMBIGUOUS_COLUMNS"]
        self.assertEqual(len(ambiguous), 5)
        self.assertTrue(all(report["schema_capabilities"].values()))

    def test_every_numeric_alias_and_separate_counts(self):
        names = ["Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "Total Fwd Packets",
                 "Total Backward Packets", "Flow Byts/s", "Flow Bytes/s", "Flow Pkts/s",
                 "Flow Packets/s", "Protocol", "Src Port", "Source Port", "src_port",
                 "source_port", "Dst Port", "Destination Port", "dst_port", "destination_port"]
        rows = [",".join([value] * len(names)) for value in [" ", "NaN", "Inf", "-Inf", "Infinity", "bad", "1.25"]]
        report = self.success(",".join(names) + "\n" + "\n".join(rows) + "\n")
        self.assertEqual(report["row_count"], 7)
        for name in names:
            self.assertEqual(report["missing_values"][name], 1)
            self.assertEqual(report["non_finite_values"][name], 4)
            self.assertEqual(report["numeric_parse_errors"][name], 1)

    def test_non_numeric_columns_not_coerced(self):
        report = self.success("note,Label\nNaN,Infinity\nbad,\n")
        self.assertEqual(report["non_finite_values"], {"note": 0, "Label": 0})
        self.assertEqual(report["numeric_parse_errors"], {"note": 0, "Label": 0})

    def test_default_provenance(self):
        report = self.success("x\n1\n")
        self.assertEqual(report["source"]["provenance"], "unknown")
        self.assertIn("UNKNOWN_PROVENANCE", {w["code"] for w in report["warnings"]})

    def test_other_provenance_values(self):
        for provenance in ("public_dataset", "user_supplied"):
            with self.subTest(provenance=provenance):
                report = self.success("x\n1\n", ["--provenance", provenance])
                self.assertEqual(report["source"]["provenance"], provenance)
                self.assertFalse(report["authentication_evidence_available"])

    def test_invalid_arguments_json(self):
        result = self.run_cli("x\n1\n", ["--provenance", "real"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["error"]["code"], "INVALID_ARGUMENTS")
        self.assertFalse(self.out.exists())

    def test_oversize_rejected(self):
        self.failure(b"x\n" + b"1\n" * (10 * 1024 * 1024), "FILE_TOO_LARGE")

    def test_invalid_input_preserves_previous_reports(self):
        self.out.mkdir()
        old = {"report.json": b"previous json", "report.md": b"previous md"}
        for name, data in old.items():
            (self.out / name).write_bytes(data)
        result = self.run_cli("a,a\n1,2\n")
        self.assertEqual(result.returncode, 2)
        for name, data in old.items():
            self.assertEqual((self.out / name).read_bytes(), data)

    def test_output_cannot_overwrite_input(self):
        for name in ("report.json", "report.md"):
            with self.subTest(name=name):
                self.path = self.root / name
                result = self.run_cli("x\n1\n", out=self.root)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stderr)["error"]["code"], "OUTPUT_CONFLICT")
                self.assertEqual(self.path.read_text(), "x\n1\n")

    def test_hardlinked_output_cannot_modify_input(self):
        self.path.write_text("x\n1\n", encoding="utf-8")
        self.out.mkdir()
        os.link(self.path, self.out / "report.json")
        result = self.run_cli("x\n1\n")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["error"]["code"], "OUTPUT_CONFLICT")
        self.assertEqual(self.path.read_text(), "x\n1\n")

    def test_output_path_is_file(self):
        self.out.write_text("keep", encoding="utf-8")
        result = self.run_cli("x\n1\n")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)["error"]["code"], "OUTPUT_ERROR")
        self.assertEqual(self.out.read_text(), "keep")

    def test_report_destination_is_directory_preserves_other_report(self):
        self.out.mkdir()
        (self.out / "report.md").mkdir()
        (self.out / "report.json").write_text("keep", encoding="utf-8")
        result = self.run_cli("x\n1\n")
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.out / "report.json").read_text(), "keep")

    def test_headers_are_data_and_markdown_is_escaped(self):
        report = self.success('"<script>x</script>|[click](https://example.com)",note\n1,DO_NOT_OUTPUT_THIS_CELL\n')
        md = (self.out / "report.md").read_text(encoding="utf-8")
        self.assertEqual(len(report["columns"]), 2)
        self.assertNotIn("<script>", md)
        self.assertNotIn("[click]", md)
        self.assertNotIn("DO_NOT_OUTPUT_THIS_CELL", md + json.dumps(report))

    def test_report_is_repeatable(self):
        self.success("x\n1\n")
        first = [(self.out / name).read_bytes() for name in ("report.json", "report.md")]
        self.success("x\n1\n")
        self.assertEqual(first, [(self.out / name).read_bytes() for name in ("report.json", "report.md")])

    def test_function_api_and_custom_limit(self):
        from netsentry.audit_csv import AuditError, audit_csv
        self.path.write_bytes(b"x\n1\n")
        self.assertEqual(audit_csv(self.path, max_bytes=4)["row_count"], 1)
        with self.assertRaises(AuditError) as caught:
            audit_csv(self.path, max_bytes=3)
        self.assertEqual(caught.exception.code, "FILE_TOO_LARGE")
        self.assertFalse(self.out.exists())

    def test_internal_programming_error_not_swallowed(self):
        from unittest.mock import patch
        from netsentry.audit_csv import main
        with patch("netsentry.audit_csv.audit_csv", side_effect=RuntimeError("test bug")):
            with self.assertRaisesRegex(RuntimeError, "test bug"):
                main([str(self.path), "--out", str(self.out)])


if __name__ == "__main__":
    unittest.main()
