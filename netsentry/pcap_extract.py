"""M1.6：离线 classic PCAP → 包索引及双向流；不抓包、不推断标签。"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import sys
import tempfile
import time
from typing import TypedDict

VERSION = "netsentry.pcap.v1"
MAX_BYTES = 200 * 1024 * 1024
NS = 10**9


class NetworkFlowRecord(TypedDict):
    flow_id: str
    source_id: str
    pcap_sha256: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: int
    ip_version: int
    first_seen: str
    last_seen: str
    first_seen_ns: int
    last_seen_ns: int
    duration: float
    forward_packet_count: int
    backward_packet_count: int
    forward_bytes: int
    backward_bytes: int
    first_packet_index: int
    last_packet_index: int
    extractor_version: str
    flow_timeout_config: dict[str, int]
    close_reason: str
    alignment_status: str
    authentication_evidence_available: bool


class PcapError(ValueError):
    """输入或资源限制错误；失败时不发布部分数据库。"""


@dataclass(frozen=True)
class FlowConfig:
    idle_timeout_ns: int = 60 * NS
    active_timeout_ns: int = 120 * NS

    def __post_init__(self):
        for value in asdict(self).values():
            if type(value) is not int or not 0 < value <= 86400 * NS:
                raise ValueError("超时必须是正整数纳秒，最多一天")


@dataclass(frozen=True)
class Limits:
    max_bytes: int = MAX_BYTES
    max_packets: int = 1_000_000
    max_seconds: int = 300
    max_db_bytes: int = 512 * 1024 * 1024

    def __post_init__(self):
        for name, ceiling in (("max_bytes", MAX_BYTES), ("max_packets", 1_000_000),
                              ("max_seconds", 3600), ("max_db_bytes", 512*1024*1024)):
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= ceiling:
                raise ValueError(f"{name} 必须为正整数且不超过 {ceiling}")
        if self.max_db_bytes < 65536:
            raise ValueError("数据库预算至少 64 KiB")


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def iso_time(timestamp_ns: int) -> str:
    seconds, fraction = divmod(timestamp_ns, NS)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"


def sha256_file(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024*1024):
            count += len(chunk)
            if count > limit:
                raise PcapError("FILE_TOO_LARGE: 摘要读取超过上限")
            digest.update(chunk)
    return digest.hexdigest()


def read_header(stream) -> dict:
    raw = stream.read(24)
    magic = raw[:4]
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 10**6), b"\xa1\xb2\xc3\xd4": (">", 10**6),
               b"\x4d\x3c\xb2\xa1": ("<", NS), b"\xa1\xb2\x3c\x4d": (">", NS)}
    if magic == b"\x0a\x0d\x0d\x0a":
        raise PcapError("UNSUPPORTED_PCAPNG: 本版仅接受 classic PCAP；请保留原件另行转换并记录转换链")
    if len(raw) != 24 or magic not in formats:
        raise PcapError("INVALID_PCAP: 空文件、短标题或未知 magic")
    endian, resolution = formats[magic]
    major, minor, zone, accuracy, snaplen, linktype = struct.unpack(endian + "HHiIII", raw[4:])
    if (major, minor) != (2, 4) or not 0 < snaplen <= 1024*1024:
        raise PcapError("UNSUPPORTED_HEADER: 仅支持 2.4、最大 snaplen 1 MiB")
    if linktype not in (1, 101, 228, 229):
        raise PcapError(f"UNSUPPORTED_LINKTYPE: {linktype}; 支持 Ethernet/RAW/IPv4/IPv6")
    return {"format": "classic_pcap", "endian": endian, "timestamp_resolution": resolution,
            "thiszone_raw": zone, "sigfigs_raw": accuracy, "snaplen": snaplen, "linktype": linktype}


def decode_packet(payload: bytes, linktype: int) -> dict:
    """复用 dpkt 解码；不保留 payload。只取最外层 IP，不穿透隧道。"""
    import dpkt
    empty = {"source_ip": None, "destination_ip": None, "source_port": None,
             "destination_port": None, "protocol": None, "ip_version": None}
    try:
        if linktype == 1:
            packet = dpkt.ethernet.Ethernet(payload).data
        else:
            if not payload:
                return {**empty, "status": "malformed_packet"}
            version = payload[0] >> 4
            if version not in (4, 6) or (linktype == 228 and version != 4) or (linktype == 229 and version != 6):
                return {**empty, "status": "malformed_packet"}
            packet = dpkt.ip.IP(payload) if version == 4 else dpkt.ip6.IP6(payload)
        if not isinstance(packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return {**empty, "status": "non_ip_or_unsupported_ethertype"}
        protocol = getattr(packet, "p", packet.nxt if isinstance(packet, dpkt.ip6.IP6) else None)
        record = {**empty, "source_ip": str(ipaddress.ip_address(packet.src)),
                  "destination_ip": str(ipaddress.ip_address(packet.dst)), "protocol": protocol,
                  "ip_version": packet.v}
        if isinstance(packet, dpkt.ip.IP):
            if packet.v != 4 or packet.hl < 5 or packet.len < packet.hl*4 or len(packet) < packet.len:
                return {**record, "status": "malformed_ip_length"}
            fragmented = packet.offset != 0 or packet.mf != 0
        else:
            if packet.v != 6 or packet.plen == 0 or len(packet) < 40 + packet.plen:
                return {**record, "status": "unsupported_or_malformed_ipv6_length"}
            fragmented = 44 in packet.extension_hdrs
            if protocol is None:
                return {**record, "status": "unsupported_ipv6_extension"}
        if fragmented:
            return {**record, "status": "fragment_not_reassembled"}
        transport = packet.data
        if protocol in (6, 17):
            expected = dpkt.tcp.TCP if protocol == 6 else dpkt.udp.UDP
            if not isinstance(transport, expected):
                return {**record, "status": "malformed_transport"}
            if protocol == 6 and (transport.off < 5 or len(transport) < transport.off*4):
                return {**record, "status": "malformed_transport"}
            if protocol == 17 and (transport.ulen < 8 or len(transport) != transport.ulen):
                return {**record, "status": "malformed_transport"}
            record.update(source_port=transport.sport, destination_port=transport.dport)
        return {**record, "status": "ok"}
    except (dpkt.UnpackError, ValueError, IndexError, struct.error, RecursionError) as exc:
        return {**empty, "status": "malformed_packet", "parser_error": type(exc).__name__}


def create_tables(connection: sqlite3.Connection, limits: Limits) -> None:
    connection.execute("PRAGMA page_size=4096")
    connection.execute(f"PRAGMA max_page_count={limits.max_db_bytes // 4096}")
    connection.execute("PRAGMA cache_size=-8192")
    connection.execute("PRAGMA temp_store=MEMORY")
    # 数据库仅在临时目录内构建；失败丢弃整个文件，因此无需另建 rollback journal。
    connection.execute("PRAGMA journal_mode=OFF")
    connection.executescript("""
        CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE flows (flow_id TEXT PRIMARY KEY, source_ip TEXT, destination_ip TEXT,
            source_port INTEGER, destination_port INTEGER, first_ns INTEGER, last_ns INTEGER,
            record TEXT NOT NULL);
        CREATE TABLE active (tuple_key TEXT PRIMARY KEY, flow_id TEXT NOT NULL);
        CREATE TABLE packets (packet_index INTEGER PRIMARY KEY, flow_id TEXT, record TEXT NOT NULL);
        CREATE INDEX src_time ON flows(source_ip, first_ns);
        CREATE INDEX dst_time ON flows(destination_ip, first_ns);
        CREATE INDEX flow_packets ON packets(flow_id, packet_index);
    """)


def add_to_flow(connection: sqlite3.Connection, packet: dict, source: dict, config: FlowConfig) -> str:
    endpoints = [(packet["source_ip"], packet["source_port"]),
                 (packet["destination_ip"], packet["destination_port"])]
    tuple_key = canonical_json([packet["ip_version"], packet["protocol"], sorted(endpoints, key=canonical_json)])
    row = connection.execute("SELECT f.record FROM active a JOIN flows f ON a.flow_id=f.flow_id WHERE a.tuple_key=?", (tuple_key,)).fetchone()
    flow = json.loads(row[0]) if row else None
    stamp = packet["timestamp_ns"]
    reason = None
    if flow:
        if stamp < flow["last_seen_ns"]:
            reason = "timestamp_regression"
        elif stamp - flow["last_seen_ns"] >= config.idle_timeout_ns:
            reason = "idle_timeout"
        elif stamp - flow["first_seen_ns"] >= config.active_timeout_ns:
            reason = "active_timeout"
        if reason:
            flow["close_reason"] = reason
            connection.execute("UPDATE flows SET record=? WHERE flow_id=?", (canonical_json(flow), flow["flow_id"]))
            flow = None
    if flow is None:
        identity = [source["source_id"], VERSION, source["dpkt_version"], asdict(config), tuple_key, packet["packet_index"]]
        flow_id = hashlib.sha256(canonical_json(identity).encode()).hexdigest()
        flow = {"flow_id": flow_id, "source_id": source["source_id"], "pcap_sha256": source["sha256_before"],
                **{key: packet[key] for key in ("source_ip", "destination_ip", "source_port", "destination_port", "protocol", "ip_version")},
                "first_seen_ns": stamp, "last_seen_ns": stamp, "first_seen": iso_time(stamp), "last_seen": iso_time(stamp),
                "duration": 0.0, "forward_packet_count": 0, "backward_packet_count": 0,
                "forward_bytes": 0, "backward_bytes": 0, "first_packet_index": packet["packet_index"],
                "last_packet_index": packet["packet_index"], "extractor_version": VERSION,
                "flow_timeout_config": asdict(config), "close_reason": "end_of_capture",
                "alignment_status": "unverified", "authentication_evidence_available": False}
        connection.execute("INSERT OR REPLACE INTO active VALUES (?,?)", (tuple_key, flow_id))
    forward = (packet["source_ip"], packet["source_port"]) == (flow["source_ip"], flow["source_port"])
    direction = "forward" if forward else "backward"
    flow[direction + "_packet_count"] += 1
    flow[direction + "_bytes"] += packet["captured_length"]
    flow.update(last_seen_ns=stamp, last_seen=iso_time(stamp), duration=(stamp-flow["first_seen_ns"])/NS,
                last_packet_index=packet["packet_index"])
    connection.execute("INSERT OR REPLACE INTO flows VALUES (?,?,?,?,?,?,?,?)", (
        flow["flow_id"], flow["source_ip"], flow["destination_ip"], flow["source_port"],
        flow["destination_port"], flow["first_seen_ns"], stamp, canonical_json(flow)))
    return flow["flow_id"]


def scan_packets(stream, connection: sqlite3.Connection, source: dict, config: FlowConfig,
                 limits: Limits, started: float) -> dict:
    header = read_header(stream)
    counts: Counter = Counter()
    count = backwards = 0
    previous = minimum = maximum = None
    while True:
        offset = stream.tell()
        raw = stream.read(16)
        if not raw:
            break
        count += 1
        if count > limits.max_packets or time.monotonic() - started > limits.max_seconds:
            raise PcapError("RESOURCE_LIMIT: 包数量或时间超过预算")
        if len(raw) != 16:
            raise PcapError(f"CORRUPT_RECORD: packet {count}, offset {offset}, 短记录标题")
        seconds, fraction, captured, original = struct.unpack(header["endian"] + "IIII", raw)
        if fraction >= header["timestamp_resolution"] or captured > header["snaplen"] or captured > original:
            raise PcapError(f"CORRUPT_RECORD: packet {count}, 非法时间或长度")
        if stream.tell() + captured > limits.max_bytes:
            raise PcapError("FILE_TOO_LARGE: 读取中超过预算")
        payload = stream.read(captured)
        if len(payload) != captured:
            raise PcapError(f"CORRUPT_RECORD: packet {count}, offset {offset}, 短数据")
        stamp = seconds * NS + fraction * (NS // header["timestamp_resolution"])
        if previous is not None and stamp < previous:
            backwards += 1
        previous = stamp
        minimum = stamp if minimum is None else min(minimum, stamp)
        maximum = stamp if maximum is None else max(maximum, stamp)
        packet = {"packet_index": count, "record_offset": offset, "payload_offset": offset+16,
                  "timestamp_seconds_raw": seconds, "timestamp_fraction_raw": fraction,
                  "timestamp_resolution": header["timestamp_resolution"], "timestamp_ns": stamp,
                  "timestamp": iso_time(stamp), "captured_length": captured, "original_length": original,
                  **decode_packet(payload, header["linktype"])}
        if captured < original:
            packet["status"] = "capture_truncated"
        counts[packet["status"]] += 1
        flow_id = add_to_flow(connection, packet, source, config) if packet["status"] == "ok" else None
        packet["flow_id"] = flow_id
        connection.execute("INSERT INTO packets VALUES (?,?,?)", (count, flow_id, canonical_json(packet)))
    return {"pcap_header": header, "packet_count": count, "packet_status_counts": dict(counts),
            "timestamp_regressions": backwards, "first_timestamp_ns": minimum, "last_timestamp_ns": maximum,
            "flow_count": connection.execute("SELECT COUNT(*) FROM flows").fetchone()[0]}


def extract_pcap(input_path: str | Path, output_db: str | Path, *, provenance: str,
                 source_uri: str, config: FlowConfig = FlowConfig(), limits: Limits = Limits()) -> dict:
    """完整扫描受限单文件；来源为调用者声明，SHA256 仅证明字节一致。"""
    import dpkt
    if dpkt.__version__ != "1.9.8":
        raise PcapError("DEPENDENCY_VERSION: 请安装 requirements-pcap.txt 的固定版本")
    if provenance not in ("synthetic", "public_dataset", "user_supplied", "unknown") or not 0 < len(source_uri) <= 2048:
        raise PcapError("INVALID_SOURCE: 需要来源类别和最多 2048 字符的来源 URI")
    path, target = Path(input_path).resolve(), Path(output_db).resolve()
    if target.exists() or path == target:
        raise PcapError("OUTPUT_CONFLICT: 不覆盖任何输入或已有输出")
    if not path.is_file() or path.stat().st_size > limits.max_bytes:
        raise PcapError("INPUT_MISSING_OR_TOO_LARGE: 需要不超过 200 MiB 上限的本地普通文件")
    started = time.monotonic()
    before = sha256_file(path, limits.max_bytes)
    source = {"source_id": "sha256:" + before, "sha256_before": before, "sha256_after": None,
              "local_path": str(path), "source_uri": source_uri, "provenance": provenance,
              "provenance_verification": "caller_declared_not_authenticated", "size_bytes": path.stat().st_size,
              "dpkt_version": dpkt.__version__, "extractor_version": VERSION,
              "clock_semantics": "epoch interpreted as UTC; capture clock accuracy and original timezone unverified"}
    target.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(target.parent).free < limits.max_db_bytes + 16*1024*1024:
        raise PcapError("DISK_BUDGET: 可用空间不足以容纳数据库预算和 16 MiB 余量")
    try:
        with tempfile.TemporaryDirectory(prefix=".pcap-", dir=target.parent) as scratch:
            temporary = Path(scratch) / "flows.sqlite"
            connection = sqlite3.connect(temporary)
            try:
                create_tables(connection, limits)
                with path.open("rb") as stream:
                    report = scan_packets(stream, connection, source, config, limits, started)
                source["sha256_after"] = sha256_file(path, limits.max_bytes)
                if before != source["sha256_after"]:
                    raise PcapError("SOURCE_CHANGED: 读取前后 SHA256 不同")
                if time.monotonic() - started > limits.max_seconds:
                    raise PcapError("RESOURCE_LIMIT: 时间超过预算")
                report.update(source=source, schema_version=VERSION, limits=asdict(limits),
                              flow_timeout_config=asdict(config), scope="full_scan_of_supplied_file_no_sampling",
                              real_pcap_verified=False if provenance == "synthetic" else "not_authenticated",
                              alignment_status="unverified")
                connection.execute("INSERT INTO metadata VALUES ('report',?)", (canonical_json(report),))
                connection.commit()
            finally:
                connection.close()
            os.link(temporary, target)
        return report
    except (sqlite3.Error, OSError) as exc:
        raise PcapError(f"EXTRACTION_IO_OR_RESOURCE_ERROR: {type(exc).__name__}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--provenance", required=True, choices=["synthetic", "public_dataset", "user_supplied", "unknown"])
    parser.add_argument("--source-uri", required=True)
    parser.add_argument("--idle-seconds", type=int, default=60)
    parser.add_argument("--active-seconds", type=int, default=120)
    parser.add_argument("--max-mib", type=int, default=200)
    try:
        args = parser.parse_args(argv)
        report = extract_pcap(args.input, args.db, provenance=args.provenance, source_uri=args.source_uri,
                              config=FlowConfig(args.idle_seconds*NS, args.active_seconds*NS),
                              limits=Limits(max_bytes=args.max_mib*1024*1024))
    except (PcapError, ValueError, OSError, ImportError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
