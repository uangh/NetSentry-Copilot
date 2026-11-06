"""固定查询函数，只读 SQLite；关联候选不等于同一安全事件。"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import sqlite3


class FlowQuery:
    def __init__(self, database: str | Path):
        path = Path(database).resolve()
        self.connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        self.connection.execute("PRAGMA query_only=ON")
        self.connection.execute("PRAGMA cache_size=-8192")
        try:
            row = self.connection.execute("SELECT value FROM metadata WHERE name='report'").fetchone()
            self.report = json.loads(row[0])
            if self.report["schema_version"] != "netsentry.pcap.v1":
                raise ValueError("不支持的数据库版本")
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            self.close()
            raise

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _envelope(self, rule: str) -> dict:
        return {"source": self.report["source"], "association_status": "unverified", "rule": rule,
                "limitations": ["候选流量不证明同一事件、恶意或登录成功", "未继承任何 CSV Label"]}

    @staticmethod
    def _bounds(time_range: tuple[int, int], limit: int, offset: int) -> None:
        if len(time_range) != 2 or any(type(t) is not int for t in time_range) or not 0 <= time_range[0] < time_range[1] <= 2**63-1:
            raise ValueError("time_range 必须是非负整数纳秒 [start,end)，且 start < end")
        if type(limit) is not int or not 1 <= limit <= 1000 or type(offset) is not int or not 0 <= offset <= 1_000_000:
            raise ValueError("limit 为 1..1000，offset 为 0..1000000 的整数")

    def get_flow_detail(self, flow_id: str) -> dict:
        row = self.connection.execute("SELECT record FROM flows WHERE flow_id=?", (flow_id,)).fetchone()
        return {**self._envelope("exact flow_id"), "record": json.loads(row[0]) if row else None}

    def _query_ip(self, column: str, address: str, time_range: tuple[int, int], *,
                  source_port: int | None = None, destination_port: int | None = None,
                  limit: int = 100, offset: int = 0) -> dict:
        self._bounds(time_range, limit, offset)
        if "%" in address:
            raise ValueError("不接受未记录的 IPv6 zone 标识")
        address = str(ipaddress.ip_address(address))
        # column 来自本文件的常量；所有用户值都作为 SQL 参数。
        sql = f"SELECT record FROM flows WHERE {column}=? AND first_ns<? AND last_ns>=?"
        params: list = [address, time_range[1], time_range[0]]
        for name, port in (("source_port", source_port), ("destination_port", destination_port)):
            if port is not None:
                if type(port) is not int or not 0 <= port <= 65535:
                    raise ValueError("端口必须是 0..65535 的整数")
                sql += f" AND {name}=?"
                params.append(port)
        rows = self.connection.execute(sql + " ORDER BY first_ns,flow_id LIMIT ? OFFSET ?", (*params, limit+1, offset)).fetchall()
        return {**self._envelope(f"exact {column}; flow overlaps [start_ns,end_ns); exact optional ports"),
                "query": {"ip": address, "time_range_ns": time_range, "source_port": source_port,
                          "destination_port": destination_port, "limit": limit, "offset": offset},
                "records": [json.loads(row[0]) for row in rows[:limit]], "has_more": len(rows) > limit}

    def query_flows_by_source_ip(self, source_ip: str, time_range: tuple[int, int], **options) -> dict:
        return self._query_ip("source_ip", source_ip, time_range, **options)

    def query_flows_by_destination_ip(self, destination_ip: str, time_range: tuple[int, int], **options) -> dict:
        return self._query_ip("destination_ip", destination_ip, time_range, **options)

    def query_related_flows(self, flow_id: str, time_window: int, *, limit: int = 100, offset: int = 0) -> dict:
        if type(time_window) is not int or not 0 <= time_window <= 86400*10**9:
            raise ValueError("时间窗口为整数纳秒，最大一天")
        self._bounds((0, 1), limit, offset)
        anchor = self.get_flow_detail(flow_id)["record"]
        result = self._envelope("share either endpoint IP; overlap closed [anchor.first-window,anchor.last+window]; exclude anchor")
        if anchor is None:
            return {**result, "records": [], "has_more": False, "anchor_found": False}
        start, end = max(0, anchor["first_seen_ns"]-time_window), anchor["last_seen_ns"]+time_window
        ips = (anchor["source_ip"], anchor["destination_ip"])
        rows = self.connection.execute("""SELECT record FROM flows WHERE flow_id<>? AND first_ns<=? AND last_ns>=?
            AND (source_ip IN (?,?) OR destination_ip IN (?,?)) ORDER BY first_ns,flow_id LIMIT ? OFFSET ?""",
            (flow_id, end, start, *ips, *ips, limit+1, offset)).fetchall()
        return {**result, "anchor_found": True, "anchor_flow_id": flow_id,
                "query": {"time_window_ns": time_window, "limit": limit, "offset": offset},
                "records": [json.loads(row[0]) for row in rows[:limit]], "has_more": len(rows) > limit}

    def get_flow_provenance(self, flow_id: str, *, limit: int = 100, offset: int = 0) -> dict:
        self._bounds((0, 1), limit, offset)
        rows = self.connection.execute("SELECT record FROM packets WHERE flow_id=? ORDER BY packet_index LIMIT ? OFFSET ?",
                                       (flow_id, limit+1, offset)).fetchall()
        return {**self._envelope("exact flow_id membership; 1-based packet index; 0-based byte offsets"),
                "flow_id": flow_id, "records": [json.loads(row[0]) for row in rows[:limit]],
                "has_more": len(rows) > limit, "offset": offset, "limit": limit,
                "packet_count": self.connection.execute("SELECT COUNT(*) FROM packets WHERE flow_id=?", (flow_id,)).fetchone()[0]}
