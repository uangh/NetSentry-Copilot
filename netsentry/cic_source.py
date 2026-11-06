"""下载一个官方 CIC-IDS2018 CSV；无凭证、固定来源、大小受限、不覆盖。"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .audit_csv import AuditError, _ArgumentParser

HOST = "cse-cic-ids2018.s3.ca-central-1.amazonaws.com"
PREFIX = "Processed Traffic Data for ML Algorithms/"
DEFAULT_FILE = "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
MAX_DOWNLOAD = 128 * 1024 * 1024


def file_sha256(path: Path, max_bytes: int = 512 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise AuditError("FILE_TOO_LARGE", "计算摘要时超过文件大小上限。")
            digest.update(chunk)
    return digest.hexdigest()


def _check_response(response, size: int | None = None, etag: str | None = None) -> int:
    if response.status != 200 or urlsplit(response.geturl()).hostname != HOST:
        raise AuditError("SOURCE_RESPONSE_ERROR", "只接受官方 HTTPS S3 的完整对象响应。")
    if urlsplit(response.geturl()).scheme != "https":
        raise AuditError("SOURCE_RESPONSE_ERROR", "不接受降级为 HTTP。")
    try:
        length = int(response.headers["Content-Length"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuditError("SOURCE_RESPONSE_ERROR", "官方响应缺少合法 Content-Length。") from exc
    if length <= 0:
        raise AuditError("SOURCE_RESPONSE_ERROR", "远程对象为空。")
    if size is not None and (length != size or response.headers.get("ETag") != etag):
        raise AuditError("SOURCE_CHANGED", "下载前后对象大小或 ETag 改变，已停止。")
    return length


def download_official(file_name: str, output_dir: str | Path, *,
                      max_bytes: int = MAX_DOWNLOAD, max_seconds: float = 300) -> dict:
    """下载完整单文件，不做抽样；超过资源预算时明确失败。"""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.csv", file_name):
        raise AuditError("INVALID_ARGUMENTS", "仅接受官方处理目录中的 CSV 基础文件名。")
    if not 0 < max_bytes <= MAX_DOWNLOAD or max_seconds <= 0:
        raise AuditError("INVALID_ARGUMENTS", "下载上限必须为正数且不超过 128 MiB。")
    output = Path(output_dir)
    target, sidecar = output / file_name, output / "source.json"
    if target.exists() or sidecar.exists():
        raise AuditError("OUTPUT_CONFLICT", "目标数据或来源清单已存在；不会覆盖，请核验已有文件或选新目录。")
    url = f"https://{HOST}/" + quote(PREFIX + file_name, safe="/")
    request_headers = {"User-Agent": "NetSentry-M1.5", "Accept-Encoding": "identity"}
    start = time.monotonic()
    try:
        with urlopen(Request(url, method="HEAD", headers=request_headers), timeout=30) as response:
            size = _check_response(response)
            etag = response.headers.get("ETag")
            modified = response.headers.get("Last-Modified")
        if size > max_bytes:
            raise AuditError("FILE_TOO_LARGE", f"远程文件 {size} 字节，超过下载上限 {max_bytes}。")
        if not etag:
            raise AuditError("SOURCE_RESPONSE_ERROR", "缺少 ETag，无法固定下载对象。")
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".download-", dir=output) as scratch:
            temporary = Path(scratch) / "data.part"
            digest, received = hashlib.sha256(), 0
            with urlopen(Request(url, headers={**request_headers, "If-Match": etag}), timeout=30) as response:
                _check_response(response, size, etag)
                with temporary.open("xb") as stream:
                    while chunk := response.read(64 * 1024):
                        received += len(chunk)
                        if received > size or received > max_bytes:
                            raise AuditError("FILE_TOO_LARGE", "响应超过预期大小，下载已停止。")
                        if time.monotonic() - start > max_seconds:
                            raise AuditError("RESOURCE_LIMIT", "下载超过时间预算，未提交部分文件。")
                        stream.write(chunk)
                        digest.update(chunk)
            if received != size:
                raise AuditError("INCOMPLETE_DOWNLOAD", "下载字节数与远程对象不符。")
            manifest = {
                "schema_version": "netsentry.cic_source.v1", "provenance": "public_dataset",
                "dataset": "CSE-CIC-IDS2018", "file_name": file_name, "url": url,
                "bucket": "cse-cic-ids2018", "key": PREFIX + file_name,
                "size_bytes": received, "sha256": digest.hexdigest(), "etag": etag,
                "last_modified": modified, "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
                "selection": {"method": "full_object", "random_seed": None,
                              "scope": "one_official_csv_not_entire_dataset"},
                "publisher_sha256": None,
                "integrity_note": "SHA256 本地计算；ETag 是对象标识，不当作 SHA256 或完整文件 MD5。",
                "citation": "CSE-CIC-IDS2018, Canadian Institute for Cybersecurity / CSE",
                "license_url": "https://www.unb.ca/cic/datasets/ids-2018.html",
                "registry_url": "https://registry.opendata.aws/cse-cic-ids2018/",
            }
            manifest_temp = Path(scratch) / "source.json"
            manifest_temp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            # 硬链接的创建是“不覆盖”提交；失败时只回滚本次创建的目标。
            os.link(temporary, target)
            try:
                os.link(manifest_temp, sidecar)
            except OSError:
                target.unlink()
                raise
            return manifest
    except (OSError, URLError) as exc:
        raise AuditError("SOURCE_IO_ERROR", f"官方数据获取失败：{type(exc).__name__}；未关闭 TLS 校验。") from exc


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="Download one bounded official CIC-IDS2018 CSV")
    parser.add_argument("--file", default=DEFAULT_FILE)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-mib", type=int, default=128)
    try:
        args = parser.parse_args(argv)
        result = download_official(args.file, args.out, max_bytes=args.max_mib * 1024 * 1024)
    except AuditError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": str(exc)}}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
