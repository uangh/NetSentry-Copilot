"""下载器单元测试：HTTP 响应为本地合成，不把它称为官方实测。"""
import hashlib
import io
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


class Response(io.BytesIO):
    def __init__(self, data=b"", size=None, status=200, etag='"fixture"'):
        super().__init__(data)
        self.status = status
        self.headers = {"Content-Length": str(size if size is not None else len(data)),
                        "ETag": etag, "Last-Modified": "fixture-only"}

    def geturl(self):
        return "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/fixture.csv"


class CICSourceTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / "raw"

    def test_download_hash_and_full_scope(self):
        from netsentry.cic_source import download_official
        content = b"Flow Duration,Label\n1,Benign\n"
        with patch("netsentry.cic_source.urlopen", side_effect=[Response(size=len(content)), Response(content)]):
            manifest = download_official("Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", self.out)
        self.assertEqual(manifest["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(manifest["selection"]["method"], "full_object")
        self.assertEqual((self.out / manifest["file_name"]).read_bytes(), content)
        self.assertTrue((self.out / "source.json").is_file())

    def test_oversize_stops_before_body(self):
        from netsentry.cic_source import download_official
        from netsentry.audit_csv import AuditError
        with patch("netsentry.cic_source.urlopen", return_value=Response(size=100)) as request:
            with self.assertRaises(AuditError) as caught:
                download_official("x.csv", self.out, max_bytes=10)
        self.assertEqual(caught.exception.code, "FILE_TOO_LARGE")
        self.assertEqual(request.call_count, 1)
        self.assertFalse(self.out.exists())

    def test_truncated_transfer_has_no_committed_data(self):
        from netsentry.cic_source import download_official
        from netsentry.audit_csv import AuditError
        with patch("netsentry.cic_source.urlopen", side_effect=[Response(size=10), Response(b"x",size=10)]):
            with self.assertRaises(AuditError):
                download_official("x.csv", self.out)
        self.assertFalse((self.out / "x.csv").exists())
        self.assertFalse((self.out / "source.json").exists())

    def test_etag_change_is_rejected(self):
        from netsentry.cic_source import download_official
        from netsentry.audit_csv import AuditError
        with patch("netsentry.cic_source.urlopen", side_effect=[Response(size=1), Response(b"x",etag='"changed"')]):
            with self.assertRaises(AuditError) as caught:
                download_official("x.csv", self.out)
        self.assertEqual(caught.exception.code, "SOURCE_CHANGED")

    def test_invalid_filename_never_requests_network(self):
        from netsentry.cic_source import download_official
        from netsentry.audit_csv import AuditError
        for name in ("../x.csv", "https://example.com/x.csv", "x.txt", "x\\y.csv"):
            with self.subTest(name=name), patch("netsentry.cic_source.urlopen") as request:
                with self.assertRaises(AuditError):
                    download_official(name, self.out)
                request.assert_not_called()

    def test_existing_data_never_overwritten(self):
        from netsentry.cic_source import download_official
        from netsentry.audit_csv import AuditError
        self.out.mkdir()
        (self.out / "x.csv").write_bytes(b"keep")
        with patch("netsentry.cic_source.urlopen") as request:
            with self.assertRaises(AuditError):
                download_official("x.csv", self.out)
            request.assert_not_called()
        self.assertEqual((self.out / "x.csv").read_bytes(), b"keep")
