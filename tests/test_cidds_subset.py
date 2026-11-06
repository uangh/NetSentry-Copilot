"""下载部分使用模拟HTTP响应；解压部分使用自造deflate，不访问网络。"""
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zlib

from scripts.fetch_cidds_subset import save_subset, fetch_range


class CiddsSubsetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def compressed(self,plain):
        compressor=zlib.compressobj(wbits=-15)
        path=self.root/'compressed.bin'
        path.write_bytes(compressor.compress(plain)+compressor.flush())
        return path,{'uncompressed_bytes':len(plain),'crc32':zlib.crc32(plain)}

    def test_selection_crc_hash_and_multiline(self):
        plain=b'a,b\r\n1,"two\nlines"\r\n2,x\r\n3,y\r\n'
        path,member=self.compressed(plain)
        output=self.root/'subset.csv'
        result=save_subset(path,output,member,2)
        self.assertEqual(output.read_bytes(),b'a,b\r\n1,"two\nlines"\r\n3,y\r\n')
        self.assertEqual(result['original_member_sha256'],hashlib.sha256(plain).hexdigest())
        self.assertEqual((result['original_member_rows'],result['selected_rows']),(3,2))

    def test_corrupt_crc_and_short_stream(self):
        path,member=self.compressed(b'a,b\n1,2\n')
        with self.assertRaises(ValueError):save_subset(path,self.root/'crc.csv',{**member,'crc32':0},1)
        path.write_bytes(path.read_bytes()[:-2])
        with self.assertRaises(ValueError):save_subset(path,self.root/'short.csv',member,1)

    def test_inflated_length_budget(self):
        path,member=self.compressed(b'a,b\n1,2\n')
        with self.assertRaises(ValueError):save_subset(path,self.root/'limit.csv',{**member,'uncompressed_bytes':1},1)

    def test_oversize_request_before_network(self):
        with patch('scripts.fetch_cidds_subset.subprocess.run') as request:
            with self.assertRaises(ValueError):fetch_range(0,201*1024*1024,{'archive_bytes':500*1024*1024},self.root/'x')
            request.assert_not_called()

    def test_server_ignores_range_is_rejected(self):
        target=self.root/'part.bin';target.write_bytes(b'123')
        target.with_suffix('.headers').write_text('HTTP/1.1 200 OK\nETag: "v1"\n')
        with patch('scripts.fetch_cidds_subset.subprocess.run',return_value=subprocess.CompletedProcess([],0,'','')):
            with self.assertRaises(ValueError):fetch_range(0,3,{'archive_bytes':100,'etag':'"v1"'},target)

    def test_exact_response_and_etag_change(self):
        target=self.root/'part.bin';target.write_bytes(b'123')
        target.with_suffix('.headers').write_text('HTTP/1.1 206 Partial Content\nETag: "v1"\nContent-Range: bytes 0-2/100\n')
        with patch('scripts.fetch_cidds_subset.subprocess.run',return_value=subprocess.CompletedProcess([],0,'','')):
            result=fetch_range(0,3,{'archive_bytes':100,'etag':'"v1"'},target)
            self.assertEqual(result['sha256'],hashlib.sha256(b'123').hexdigest())
            with self.assertRaises(ValueError):fetch_range(0,3,{'archive_bytes':100,'etag':'"v2"'},target)


if __name__=='__main__':unittest.main()
