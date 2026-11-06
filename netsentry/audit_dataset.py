"""M1.5：完整流式扫描一个 CSV，统计质量、类别、重复和训练准备阻塞。"""
from __future__ import annotations

from collections import Counter
from contextlib import closing
from datetime import datetime
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import time

from .audit_csv import (ALIASES, NUMERIC_NAMES, PROVENANCES, AuditError,
                        _ArgumentParser, _HashedReader, _headers, _md, _records)
from .cic_source import file_sha256

SCHEMA = json.loads(Path(__file__).with_name("cic_schema.json").read_text(encoding="utf-8"))
NUMERIC = NUMERIC_NAMES | {c.casefold() for c in SCHEMA["numeric_columns"]}
MAX_BYTES = 512 * 1024 * 1024
MAX_ROWS = 2_000_000
INTEGER = re.compile(r"[+-]?\d+\Z")
SUSPICIOUS = re.compile(r"label|attack|target|class|ground.?truth|prediction|category|file.?name|^unnamed|^index$", re.I)


def _roles(columns: list[str]) -> tuple[dict[str, list[str]], list[str], list[str]]:
    roles = {role: [c for c in columns if c.casefold() in aliases] for role, aliases in ALIASES.items()}
    excluded = {c for role in ("label", "source_ip", "destination_ip", "timestamp", "flow_id") for c in roles[role]}
    suspect = [c for c in columns if SUSPICIOUS.search(c) and c not in roles["label"]]
    # 明确白名单：未知列不因“碰巧能转数字”自动成为模型候选。
    candidates = [c for c in columns if c.casefold() in NUMERIC and c not in excluded and c not in suspect]
    return roles, suspect, candidates


def _new_profile(column: str, roles: dict[str, list[str]]) -> dict:
    matched = [role for role, names in roles.items() if column in names]
    expected = matched[0] if matched else ("numeric" if column.casefold() in NUMERIC else "unknown")
    return {"expected_role": expected, "role_basis": "column_name_only",
            "missing": 0, "non_finite": 0, "numeric_parse_errors": 0,
            "non_finite_breakdown": {"nan": 0, "positive_infinity": 0, "negative_infinity": 0},
            "type_counts": {"integer": 0, "float": 0, "non_finite": 0, "text": 0},
            "finite_min": None, "finite_max": None, "constant_nonmissing": True}


def _count_value(profile: dict, value: str, expected_numeric: bool) -> str | None:
    if not value:
        profile["missing"] += 1
        return "missing"
    try:
        number = float(value)
    except ValueError:
        profile["type_counts"]["text"] += 1
        if expected_numeric:
            profile["numeric_parse_errors"] += 1
            return "numeric_parse_errors"
        return
    if not math.isfinite(number):
        profile["type_counts"]["non_finite"] += 1
        if expected_numeric:
            profile["non_finite"] += 1
            kind = "nan" if math.isnan(number) else ("positive_infinity" if number > 0 else "negative_infinity")
            profile["non_finite_breakdown"][kind] += 1
            return "non_finite"
        return
    kind = "integer" if INTEGER.fullmatch(value) else "float"
    profile["type_counts"][kind] += 1
    for key, choose in (("finite_min", min), ("finite_max", max)):
        profile[key] = number if profile[key] is None else choose(profile[key], number)


def _observed_type(profile: dict) -> str:
    counts = profile["type_counts"]
    numeric = counts["integer"] + counts["float"] + counts["non_finite"]
    if counts["text"]:
        return "mixed_numeric_text" if numeric else "text"
    if counts["float"]:
        return "float"
    if counts["integer"]:
        return "integer_with_nonfinite" if counts["non_finite"] else "integer"
    return "nonfinite_only" if numeric else "empty"


def _validate_metadata(role: str, value: str, timestamp_format: str) -> datetime | None:
    if role in ("source_ip", "destination_ip"):
        ipaddress.ip_address(value)
    elif role in ("source_port", "destination_port"):
        if not INTEGER.fullmatch(value) or not 0 <= int(value) <= 65535:
            raise ValueError("invalid port")
    elif role == "timestamp":
        return datetime.strptime(value, timestamp_format)
    return None


def _prepare_database(db: sqlite3.Connection, max_bytes: int) -> None:
    db.execute("PRAGMA page_size=4096")
    db.execute(f"PRAGMA max_page_count={max_bytes // 4096}")
    db.execute("PRAGMA cache_size=-4096")
    db.execute("PRAGMA temp_store=FILE")
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("CREATE TABLE full_rows (v TEXT PRIMARY KEY, n INTEGER NOT NULL) WITHOUT ROWID")
    db.execute("CREATE TABLE features (v TEXT PRIMARY KEY, n INTEGER NOT NULL, label TEXT, conflict INTEGER) WITHOUT ROWID")


def _add_duplicate_keys(db: sqlite3.Connection, row: list[str], indices: list[int], label: str | None) -> None:
    # 完整序列化值作键，不仅依赖摘要，避免把哈希碰撞称为重复。
    full_key = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
    db.execute("INSERT INTO full_rows VALUES (?,1) ON CONFLICT(v) DO UPDATE SET n=n+1", (full_key,))
    if indices:
        feature_key = json.dumps([row[i] for i in indices], ensure_ascii=False, separators=(",", ":"))
        db.execute("INSERT INTO features VALUES (?,1,?,0) ON CONFLICT(v) DO UPDATE SET "
                   "n=n+1, conflict=MAX(conflict, CASE WHEN label IS NOT excluded.label THEN 1 ELSE 0 END)",
                   (feature_key, label))


def _duplicate_summary(db: sqlite3.Connection, has_features: bool) -> dict:
    full = db.execute("SELECT COUNT(*),COALESCE(SUM(n-1),0),COALESCE(SUM(n>1),0) FROM full_rows").fetchone()
    feat = db.execute("SELECT COUNT(*),COALESCE(SUM(n-1),0),COALESCE(SUM(n>1),0),COALESCE(SUM(conflict),0) FROM features").fetchone()
    return {"comparison": "exact parsed cell strings; no numerical/whitespace normalization; repeated headers excluded",
            "full_row": dict(zip(("unique_records", "excess_records", "duplicate_groups"), full)),
            "candidate_features": {"status": "available" if has_features else "unavailable",
                **dict(zip(("unique_records", "excess_records", "duplicate_groups", "conflicting_label_groups"), feat))},
            "near_duplicates": "not_checked", "cross_file_duplicates": "not_checked"}


def _scan_dataset(stream: io.TextIOWrapper, db: sqlite3.Connection, *, max_rows: int,
                  max_labels: int, timestamp_format: str, deadline: float) -> dict:
    records = _records(stream)
    first = next(records, None)
    if first is None:
        raise AuditError("EMPTY_FILE", "文件为空或仅有空白物理行。")
    raw_columns, line = first
    columns = _headers(raw_columns, line)
    if len(columns) > 512:
        raise AuditError("RESOURCE_LIMIT", "列数超过 512 的保护上限。")
    roles, suspect, candidates = _roles(columns)
    profiles = {c: _new_profile(c, roles) for c in columns}
    is_numeric = [c.casefold() in NUMERIC for c in columns]
    first_values: dict[str, str] = {}
    candidate_indices = [columns.index(c) for c in candidates]
    label_index = columns.index(roles["label"][0]) if len(roles["label"]) == 1 else None
    metadata = {c: {"role": role, "valid": 0, "invalid": 0, "missing": 0}
                for role in ("source_ip", "destination_ip", "timestamp", "source_port", "destination_port") for c in roles[role]}
    metadata_indices = [(columns.index(c), c, entry) for c, entry in metadata.items()]
    counts: Counter[str] = Counter()
    affected_rows = {"missing": 0, "non_finite": 0, "numeric_parse_errors": 0}
    time_bins: Counter[tuple[str, str]] = Counter()
    total = repeated = rows = label_missing = backward = 0
    earliest = latest = previous = None
    repeated_lines: list[int] = []
    for row, line in records:
        total += 1
        if total > max_rows or time.monotonic() > deadline:
            raise AuditError("RESOURCE_LIMIT", "扫描达到记录数或时间预算；未发布部分统计作为完整报告。")
        if len(row) != len(columns):
            raise AuditError("ROW_WIDTH_MISMATCH", f"物理行 {line} 列数 {len(row)} 与标题 {len(columns)} 不符。")
        if len(columns) > 1 and [v.strip().casefold() for v in row] == [c.casefold() for c in columns]:
            repeated += 1
            if len(repeated_lines) < 20:
                repeated_lines.append(line)
            continue
        rows += 1
        stripped = [v.strip() for v in row]
        label = stripped[label_index] if label_index is not None else None
        if label_index is not None:
            if label:
                counts[label] += 1
                if len(counts) > max_labels or len(label) > 256:
                    raise AuditError("RESOURCE_LIMIT", "类别数量或标签长度超过保护上限。")
            else:
                label_missing += 1
        row_issues: set[str] = set()
        for index, column in enumerate(columns):
            value = stripped[index]
            profile = profiles[column]
            issue = _count_value(profile, value, is_numeric[index])
            if issue:
                row_issues.add(issue)
            if value:
                if column not in first_values:
                    first_values[column] = value
                elif value != first_values[column]:
                    profile["constant_nonmissing"] = False
        for issue in row_issues:
            affected_rows[issue] += 1
        for index, column, entry in metadata_indices:
            value = stripped[index]
            if not value:
                entry["missing"] += 1
                continue
            try:
                parsed = _validate_metadata(entry["role"], value, timestamp_format)
            except ValueError:
                entry["invalid"] += 1
                continue
            entry["valid"] += 1
            # 只有单一、无歧义时间列时才聚合时间分布。
            if parsed is not None and len(roles["timestamp"]) == 1:
                earliest = parsed if earliest is None else min(earliest, parsed)
                latest = parsed if latest is None else max(latest, parsed)
                if previous is not None and parsed < previous:
                    backward += 1
                previous = parsed
                time_bins[(parsed.strftime("%Y-%m-%d %H:00"), label or "<missing_or_unavailable>")] += 1
                if len(time_bins) > 10000:
                    raise AuditError("RESOURCE_LIMIT", "时间与类别分组超过 10000。")
        _add_duplicate_keys(db, row, candidate_indices, label)
        if rows % 10000 == 0:
            db.commit()
    if rows == 0:
        raise AuditError("NO_DATA_ROWS", "没有数据记录（重复标题不当作流量记录）。")
    db.commit()
    for column, profile in profiles.items():
        profile["observed_type"] = _observed_type(profile)
        if column not in first_values:
            profile["constant_nonmissing"] = None
    label_status = "available" if label_index is not None else ("ambiguous" if roles["label"] else "unavailable")
    warnings = ["AUTH_LOG_UNAVAILABLE", "SINGLE_FILE_SCOPE", "GENERALIZATION_UNVERIFIED"]
    if label_status != "available":
        warnings.append("LABEL_AMBIGUOUS" if roles["label"] else "LABEL_UNAVAILABLE")
    for role in ("source_ip", "destination_ip", "timestamp", "source_port", "destination_port"):
        if not roles[role]:
            warnings.append(role.upper() + "_UNAVAILABLE")
    if repeated:
        warnings.append("REPEATED_HEADER_RECORDS")
    if any(p["non_finite"] for p in profiles.values()):
        warnings.append("NON_FINITE_VALUES")
    if any(p["numeric_parse_errors"] for p in profiles.values()):
        warnings.append("NUMERIC_PARSE_ERRORS")
    if any(p["invalid"] for p in metadata.values()):
        warnings.append("INVALID_METADATA_VALUES")
    if suspect:
        warnings.append("POTENTIAL_LABEL_LEAKAGE_COLUMNS")
    if any(len(names) > 1 for names in roles.values()):
        warnings.append("AMBIGUOUS_COLUMNS")
    return {"schema_version": "netsentry.dataset_audit.v1", "records_seen": total,
            "row_count": rows, "column_count": len(columns), "raw_columns": raw_columns, "columns": columns,
            "repeated_header_records": repeated, "repeated_header_first_physical_lines": repeated_lines,
            "column_profiles": profiles, "affected_rows": affected_rows,
            "role_matches": roles, "metadata_validation": metadata,
            "label_columns": roles["label"], "feature_candidates": candidates,
            "suspected_leakage_columns": suspect, "authentication_evidence_available": False,
            "label_distribution": {"status": label_status, "counts": dict(sorted(counts.items())),
                "missing": label_missing if label_index is not None else None, "class_count": len(counts),
                "majority_minority_ratio": max(counts.values()) / min(counts.values()) if len(counts) > 1 else None,
                "normalization": "strip whitespace only; no binary relabeling"},
            "time_summary": {"format": timestamp_format, "timezone": "unknown_not_inferred",
                "minimum": earliest.isoformat() if earliest else None, "maximum": latest.isoformat() if latest else None,
                "backward_steps": backward,
                "hour_label_counts": [{"hour": h, "label": label, "count": n} for (h, label), n in sorted(time_bins.items())]},
            "duplicates": _duplicate_summary(db, bool(candidates)), "warnings": warnings,
            "training_readiness": {"ready": False, "training_performed": False,
                "blockers": ["split_protocol_not_approved", "cross_batch_generalization_not_evaluated",
                             "quality_handling_not_implemented", "label_validity_not_independently_verified"]}}


def audit_dataset(input_path: str | Path, *, provenance: str = "unknown",
                  expected_sha256: str | None = None, max_bytes: int = MAX_BYTES,
                  max_rows: int = MAX_ROWS, max_labels: int = 100, max_seconds: float = 300,
                  max_temp_bytes: int = 512 * 1024 * 1024,
                  timestamp_format: str = "%d/%m/%Y %H:%M:%S") -> dict:
    """完整扫描，绝不把提前终止的统计冒充完整结果；不修改输入。"""
    if provenance not in PROVENANCES or not 0 < max_bytes <= MAX_BYTES:
        raise AuditError("INVALID_ARGUMENTS", "来源类别无效，或文件上限不在 1–512 MiB 范围内。")
    if max_rows <= 0 or max_labels <= 0 or max_seconds <= 0 or max_temp_bytes < 16384:
        raise AuditError("INVALID_ARGUMENTS", "资源预算必须为正数，临时数据库至少 16 KiB。")
    path = Path(input_path)
    start = time.monotonic()
    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise AuditError("FILE_TOO_LARGE", f"输入 {size} 字节超过 {max_bytes} 字节扫描上限。")
        before = file_sha256(path, max_bytes)
        if expected_sha256 is not None and before != expected_sha256:
            raise AuditError("HASH_MISMATCH", "文件 SHA256 与来源清单不一致。")
        with tempfile.TemporaryDirectory(prefix="netsentry-audit-") as scratch:
            with closing(sqlite3.connect(str(Path(scratch) / "duplicates.sqlite"))) as db:
                _prepare_database(db, max_temp_bytes)
                with path.open("rb") as raw:
                    hashed = _HashedReader(raw, max_bytes)
                    with io.TextIOWrapper(io.BufferedReader(hashed), encoding="utf-8-sig", newline="") as stream:
                        report = _scan_dataset(stream, db, max_rows=max_rows, max_labels=max_labels,
                            timestamp_format=timestamp_format, deadline=start + max_seconds)
                    observed = hashed.digest.hexdigest()
                report["resource_usage"] = {"temporary_db_bytes": (Path(scratch) / "duplicates.sqlite").stat().st_size,
                                            "sqlite_cache_kib": 4096}
        after = file_sha256(path, max_bytes)
        if before != after or before != observed:
            raise AuditError("INPUT_CHANGED", "审计前、扫描中、审计后摘要不一致，拒绝发布结果。")
    except FileNotFoundError as exc:
        raise AuditError("INPUT_NOT_FOUND", "输入文件不存在。") from exc
    except UnicodeDecodeError as exc:
        raise AuditError("INVALID_ENCODING", "文件不是 UTF-8 或 UTF-8 BOM 编码。") from exc
    except sqlite3.OperationalError as exc:
        if getattr(exc, "sqlite_errorcode", 0) & 0xFF in (sqlite3.SQLITE_FULL, sqlite3.SQLITE_IOERR, sqlite3.SQLITE_CANTOPEN):
            raise AuditError("RESOURCE_LIMIT", "临时数据库空间或操作失败，未输出不完整统计。") from exc
        raise
    except OSError as exc:
        raise AuditError("INPUT_IO_ERROR", "读取数据或临时磁盘操作失败。") from exc
    report["source"] = {"file_name": path.name, "size_bytes": size, "provenance": provenance,
                        "sha256": before, "sha256_after": after, "input_unchanged": True}
    report["scope"] = {"local_file_scan": "complete", "population": "provided_file_only",
                       "sampling": "none", "random_seed": None, "estimated_metrics": [],
                       "all_cicids2018_files_scanned": False}
    report["resource_limits"] = {"max_bytes": max_bytes, "max_rows": max_rows, "max_labels": max_labels,
                                 "max_seconds": max_seconds, "max_temp_bytes": max_temp_bytes,
                                 "max_columns": 512, "max_time_label_groups": 10000}
    report["resource_usage"]["elapsed_seconds"] = round(time.monotonic() - start, 3)
    return report


def render_audit(report: dict) -> str:
    source = report["source"]
    lines = ["# M1.5 数据质量审计", "", "本报告为所提供文件的完整扫描，无抽样估计；不代表整个 CIC-IDS2018。",
             f"来源：{source['provenance']}；文件：{_md(source['file_name'])}；大小：{source['size_bytes']} 字节。",
             f"SHA256：`{source['sha256']}`；审计后摘要一致：{source['input_unchanged']}。", "",
             f"数据记录 {report['row_count']}；列数 {report['column_count']}；重复标题记录 {report['repeated_header_records']}（单独计数）。",
             "", "## 每列类型与质量", "", "| 实际字段 | 推断角色 | 观测类型 | 缺失 | 非有限 | 数值解析失败 |",
             "|---|---|---|---:|---:|---:|"]
    for c, p in report["column_profiles"].items():
        lines.append(f"| {_md(c)} | {p['expected_role']} | {p['observed_type']} | {p['missing']} | {p['non_finite']} | {p['numeric_parse_errors']} |")
    lines += ["", "类型为全文件词法观测，不是 CSV 内置类型或模型 dtype；角色由列名匹配。未知列不自动进入候选特征。",
              "缺失仅指空白；NaN/Inf 单独计数。数值解析失败只针对声明为数值的列。", "", "## 标签与重复", ""]
    labels = report["label_distribution"]
    lines.append(f"标签统计状态：{labels['status']}；类别数：{labels['class_count']}；缺失标签：{labels['missing']}。")
    for label, count in labels["counts"].items():
        lines.append(f"- {_md(label)}：{count}（{count / report['row_count']:.2%}）。")
    lines += [f"完整记录重复（首次之后）：{report['duplicates']['full_row']['excess_records']}。",
              f"候选特征相同（首次之后）：{report['duplicates']['candidate_features']['excess_records']}；标签冲突组：{report['duplicates']['candidate_features']['conflicting_label_groups']}。",
              "重复使用解析后单元格原文字串比较；未做近重复或跨文件检查，没有删除任何原始记录。",
              "", "## 能力与值验证", ""]
    for role, columns in report["role_matches"].items():
        lines.append(f"- {role}：{'、'.join(_md(c) for c in columns) or '不存在匹配列'}。")
    for c, p in report["metadata_validation"].items():
        lines.append(f"- {_md(c)} 格式/范围检查：有效 {p['valid']}，无效 {p['invalid']}，缺失 {p['missing']}。")
    lines += ["IP 只校验语法，未验证主机身份；时间只按声明格式解析，时区未知；端口只校验整数范围。",
              "认证日志未接入，不能证明登录成功。标签没有作为模型输入；本轮没有模型训练。",
              "", "## 待处理风险", "", *[f"- {w}" for w in report["warnings"]],
              "", "训练准备未放行：需要确认划分协议、质量处理和独立标签核验。"]
    return "\n\n".join(lines[:1]) + "\n" + "\n".join(lines[1:]) + "\n"


def _write_outputs(report: dict, output: Path, protected: list[Path]) -> None:
    targets = [output / "audit.json", output / "audit.md"]
    for target in targets:
        for source in protected:
            if target.resolve() == source.resolve() or (target.exists() and source.exists() and target.samefile(source)):
                raise AuditError("OUTPUT_CONFLICT", "报告会覆盖输入或来源清单，已拒绝。")
        if target.exists() and not target.is_file():
            raise AuditError("OUTPUT_CONFLICT", "报告目标不是普通文件。")
    contents = [json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", render_audit(report)]
    try:
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".report-", dir=output) as scratch:
            for target, content in zip(targets, contents):
                staged = Path(scratch) / target.name
                staged.write_text(content, encoding="utf-8")
            for target in targets:
                os.replace(Path(scratch) / target.name, target)
    except OSError as exc:
        raise AuditError("OUTPUT_ERROR", "无法写入报告；检查目录和磁盘空间。") from exc


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="M1.5 bounded streaming dataset audit; no model training")
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--provenance", choices=PROVENANCES, default="unknown")
    parser.add_argument("--max-mib", type=int, default=512)
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS)
    parser.add_argument("--timestamp-format", default=SCHEMA["timestamp_format"])
    try:
        args = parser.parse_args(argv)
        manifest = {}
        if args.manifest:
            try:
                if args.manifest.stat().st_size > 1024 * 1024:
                    raise ValueError("manifest too large")
                manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
                if (not isinstance(manifest, dict) or manifest.get("file_name") != args.input.name
                    or not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("sha256", "")))
                    or manifest.get("size_bytes") != args.input.stat().st_size
                    or manifest.get("provenance") not in PROVENANCES):
                    raise ValueError("invalid manifest")
            except (OSError, ValueError) as exc:
                raise AuditError("INVALID_MANIFEST", "来源清单无效、不可读或与输入不匹配。") from exc
        report = audit_dataset(args.input, provenance=manifest.get("provenance", args.provenance),
            expected_sha256=manifest.get("sha256"), max_bytes=args.max_mib * 1024 * 1024,
            max_rows=args.max_rows, timestamp_format=args.timestamp_format)
        if manifest:
            report["source_manifest"] = manifest
        _write_outputs(report, args.out, [args.input] + ([args.manifest] if args.manifest else []))
    except AuditError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": str(exc)}}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "ok", "rows": report["row_count"], "columns": report["column_count"],
                      "sha256": report["source"]["sha256"], "scope": report["scope"],
                      "out": str(args.out)}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
