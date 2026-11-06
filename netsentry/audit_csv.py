"""M1：只读、流式 CSV 审计。运行：python -m netsentry.audit_csv --help。"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import math
import os
from pathlib import Path
import sys
import tempfile
from typing import BinaryIO, Iterator, NoReturn, TextIO, TypedDict

MAX_BYTES = 20 * 1024 * 1024
PROVENANCES = ("synthetic", "public_dataset", "user_supplied", "unknown")
ALIASES = {
    "source_ip": {"src ip", "source ip", "src_ip", "source_ip"},
    "destination_ip": {"dst ip", "destination ip", "dst_ip", "destination_ip"},
    "timestamp": {"timestamp", "time_stamp", "flow start time"},
    "destination_port": {"dst port", "destination port", "dst_port", "destination_port"},
    "source_port": {"src port", "source port", "src_port", "source_port"},
    "flow_id": {"flow id", "flow_id"},
    "label": {"label", "attack_cat", "attack_type", "target", "class"},
}
NUMERIC_NAMES = {
    "flow duration", "tot fwd pkts", "tot bwd pkts", "total fwd packets",
    "total backward packets", "flow byts/s", "flow bytes/s", "flow pkts/s",
    "flow packets/s", "protocol",
} | ALIASES["source_port"] | ALIASES["destination_port"]


class WarningItem(TypedDict):
    code: str
    message: str


class Source(TypedDict):
    file_name: str
    sha256: str
    provenance: str


class AuditReport(TypedDict):
    schema_version: str
    source: Source
    row_count: int
    columns: list[str]
    label_columns: list[str]
    feature_candidates: list[str]
    schema_capabilities: dict[str, bool]
    authentication_evidence_available: bool
    missing_values: dict[str, int]
    non_finite_values: dict[str, int]
    numeric_parse_errors: dict[str, int]
    warnings: list[WarningItem]


class AuditError(Exception):
    """可预期的输入或文件系统错误；编程错误不转换成这个异常。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _HashedReader(io.RawIOBase):
    """同一遍读取同时计算原始字节摘要，并防止文件增长绕过大小上限。"""

    def __init__(self, stream: BinaryIO, max_bytes: int) -> None:
        super().__init__()
        self.stream = stream
        self.max_bytes = max_bytes
        self.count = 0
        self.digest = hashlib.sha256()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray) -> int:
        data = self.stream.read(min(len(buffer), self.max_bytes - self.count + 1))
        self.count += len(data)
        if self.count > self.max_bytes:
            raise AuditError("FILE_TOO_LARGE", f"文件超过 {self.max_bytes} 字节上限。")
        self.digest.update(data)
        buffer[:len(data)] = data
        return len(data)


class _PhysicalLines:
    """识别纯空白物理行，保留引号内空行与显式空单元格记录。"""

    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.record_is_blank = True

    def __iter__(self) -> _PhysicalLines:
        return self

    def __next__(self) -> str:
        line = next(self.stream)
        self.record_is_blank = self.record_is_blank and not line.strip()
        return line


def _records(stream: TextIO) -> Iterator[tuple[list[str], int]]:
    lines = _PhysicalLines(stream)
    reader = csv.reader(lines, strict=True)
    while True:
        lines.record_is_blank = True
        try:
            row = next(reader)
        except StopIteration:
            return
        except csv.Error as exc:
            # 不回显单元格内容，避免将自由文本复制到错误日志。
            raise AuditError("MALFORMED_CSV", f"物理行 {reader.line_num} 附近 CSV 语法错误或字段超过解析器长度限制。") from exc
        if not lines.record_is_blank:
            yield row, reader.line_num


def _headers(raw: list[str], line: int) -> list[str]:
    columns = [name.strip() for name in raw]
    if any(not name for name in columns):
        raise AuditError("EMPTY_COLUMN_NAME", f"标题行 {line} 包含空列名。")
    normalized = [name.casefold() for name in columns]
    if len(set(normalized)) != len(normalized):
        raise AuditError("DUPLICATE_COLUMNS", f"标题行 {line} 包含去空格、忽略大小写后的重复列名。")
    return columns


def _new_report(columns: list[str], path: Path, provenance: str) -> AuditReport:
    matches = {role: [c for c in columns if c.casefold() in names]
               for role, names in ALIASES.items()}
    excluded = set()
    for role in ("label", "source_ip", "destination_ip", "timestamp", "flow_id"):
        excluded.update(matches[role])
    warnings: list[WarningItem] = []
    for role, message in (
        ("source_ip", "缺少源 IP 字段，不能承诺按源 IP 关联调查。"),
        ("destination_ip", "缺少目标 IP 字段，不能承诺按目标 IP 关联调查。"),
        ("timestamp", "缺少时间戳字段，不能承诺按时间关联调查。"),
    ):
        if not matches[role]:
            warnings.append({"code": role.upper() + "_UNAVAILABLE", "message": message})
    for role, matched in matches.items():
        if len(matched) > 1:
            warnings.append({"code": "AMBIGUOUS_COLUMNS", "message": f"语义 {role} 匹配多列：{', '.join(matched)}；未选择或合并。"})
    if matches["label"]:
        warnings.append({"code": "LABEL_EXCLUDED", "message": "所有标签列已排除出候选特征；完整审计报告只供开发评测，不可直接提供给 Agent。"})
    if provenance == "synthetic":
        warnings.append({"code": "SYNTHETIC_DATA", "message": "合成测试数据，只验证软件逻辑，不支持真实检测效果声明。"})
    if provenance == "unknown":
        warnings.append({"code": "UNKNOWN_PROVENANCE", "message": "来源未登记，不能支持产品性能声明。"})
    warnings.append({"code": "AUTH_LOG_UNAVAILABLE", "message": "当前输入契约不支持认证日志，不能证明登录成功。"})
    return {
        "schema_version": "netsentry.data_audit.v1",
        "source": {"file_name": path.name, "sha256": "", "provenance": provenance},
        "row_count": 0,
        "columns": columns,
        "label_columns": matches["label"],
        "feature_candidates": [c for c in columns if c not in excluded],
        "schema_capabilities": {f"has_{role}_column": bool(matches[role]) for role in
                                ("source_ip", "destination_ip", "timestamp", "destination_port")},
        "authentication_evidence_available": False,
        "missing_values": dict.fromkeys(columns, 0),
        "non_finite_values": dict.fromkeys(columns, 0),
        "numeric_parse_errors": dict.fromkeys(columns, 0),
        "warnings": warnings,
    }


def _count_cell(report: AuditReport, column: str, value: str) -> None:
    value = value.strip()
    if not value:
        report["missing_values"][column] += 1
        return
    if column.casefold() not in NUMERIC_NAMES:
        return
    try:
        number = float(value)
    except ValueError:
        report["numeric_parse_errors"][column] += 1
        return
    if not math.isfinite(number):
        report["non_finite_values"][column] += 1


def _scan(stream: TextIO, path: Path, provenance: str) -> AuditReport:
    records = _records(stream)
    first = next(records, None)
    if first is None:
        raise AuditError("EMPTY_FILE", "文件为空或仅含空白物理行。")
    columns = _headers(*first)
    report = _new_report(columns, path, provenance)
    for row, line in records:
        if len(row) != len(columns):
            raise AuditError("ROW_WIDTH_MISMATCH", f"结束于物理行 {line} 的记录有 {len(row)} 列，标题有 {len(columns)} 列。")
        report["row_count"] += 1
        for column, value in zip(columns, row):
            _count_cell(report, column, value)
    if report["row_count"] == 0:
        raise AuditError("NO_DATA_ROWS", "只有标题，没有数据记录。")
    for key, code, message in (
        ("non_finite_values", "NON_FINITE_VALUES", "存在非有限数值，未修复或删除。"),
        ("numeric_parse_errors", "NUMERIC_PARSE_ERRORS", "存在无法解析的已知数值字段，未修复或删除。"),
    ):
        if any(report[key].values()):
            report["warnings"].append({"code": code, "message": message})
    return report


def audit_csv(input_path: str | Path, provenance: str = "unknown",
              *, max_bytes: int = MAX_BYTES) -> AuditReport:
    """返回审计统计，不创建文件；来源为调用者声明，不是真实性认证。"""
    if provenance not in PROVENANCES:
        raise AuditError("INVALID_ARGUMENTS", "provenance 必须使用约定的四种来源类别。")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    path = Path(input_path)
    try:
        if path.stat().st_size > max_bytes:
            raise AuditError("FILE_TOO_LARGE", f"文件超过 {max_bytes} 字节上限。")
        with path.open("rb") as raw:
            hashed = _HashedReader(raw, max_bytes)
            with io.TextIOWrapper(io.BufferedReader(hashed), encoding="utf-8-sig", newline="") as stream:
                report = _scan(stream, path, provenance)
            report["source"]["sha256"] = hashed.digest.hexdigest()
    except FileNotFoundError as exc:
        raise AuditError("INPUT_NOT_FOUND", "找不到输入文件，请检查路径。") from exc
    except UnicodeDecodeError as exc:
        raise AuditError("INVALID_ENCODING", "输入不是有效 UTF-8；请提供 UTF-8 或 UTF-8 BOM 文件。") from exc
    except OSError as exc:
        raise AuditError("INPUT_READ_ERROR", "无法读取输入文件，请检查文件类型、权限与存储设备。") from exc
    return report


def _md(value: str) -> str:
    """标题和文件名是不可信数据：转义 HTML、Markdown 与控制字符。"""
    value = "".join(c if c.isprintable() else " " for c in value)
    value = html.escape(value, quote=True)
    for char in "\\`*_{}[]()#+-.!|":
        value = value.replace(char, "\\" + char)
    return value


def render_markdown(report: AuditReport) -> str:
    source = report["source"]
    lines = ["# CSV 数据审计报告", "",
             f"- 文件：{_md(source['file_name'])}",
             f"- 数据来源类别：{source['provenance']}（使用者声明，未经自动真实性核验）",
             f"- 数据记录数：{report['row_count']}（不是 TCP 连接数、登录失败数或密码尝试数）",
             f"- 原始文件 SHA256：`{source['sha256']}`", "",
             "## 字段与基础质量", "",
             "| 字段 | 缺失 | 非有限数值 | 数值解析失败 |",
             "|---|---:|---:|---:|"]
    for column in report["columns"]:
        lines.append(f"| {_md(column)} | {report['missing_values'][column]} | {report['non_finite_values'][column]} | {report['numeric_parse_errors'][column]} |")
    labels = "、".join(_md(c) for c in report["label_columns"]) or "无"
    candidates = "、".join(_md(c) for c in report["feature_candidates"]) or "无"
    lines += ["", f"标签列：{labels}。标签隔离：标签不进入候选特征，完整报告仅供开发评测，不应直接作为 Agent 上下文。",
              "", f"候选特征：{candidates}。候选不等于模型可直接使用。", "", "## 字段能力与限制", ""]
    for role, title in (("source_ip", "源 IP"), ("destination_ip", "目标 IP"),
                        ("timestamp", "时间戳"), ("destination_port", "目标端口")):
        present = report["schema_capabilities"][f"has_{role}_column"]
        lines.append(f"- {title}列：{'存在（仅列名匹配，值未验证）' if present else '缺失（相关字段能力不可用）'}。")
    lines += ["", "M1 未验证 IP/时间格式与模型特征兼容性，也未校验端口范围。字段存在不保证可关联调查；多列歧义需要人工确认。",
              "认证证据不可用，不能证明登录成功。端口号仅是线索，不能证明服务或攻击。",
              "synthetic 是合成测试数据，不能当作真实数据或检测成果。本次执行没有核验真实用户数据，也没有用户收益评测。",
              "这里只统计缺失和已知数值列的基础质量，不复制原始数据行，不修复或删除数据。",
              "", "## 警告", ""]
    lines.extend(f"- {w['code']}：{_md(w['message'])}" for w in report["warnings"])
    return "\n".join(lines) + "\n"


def write_reports(report: AuditReport, output_dir: str | Path, input_path: str | Path) -> None:
    """解析成功后才写报告；预检两个目标，单文件临时写入后原子替换。"""
    output = Path(output_dir)
    source = Path(input_path).resolve()
    targets = [output / "report.json", output / "report.md"]
    contents = [json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
                render_markdown(report)]
    pending: list[tuple[Path, Path]] = []
    try:
        for target in targets:
            if target.resolve() == source or (target.exists() and target.samefile(source)):
                raise AuditError("OUTPUT_CONFLICT", "报告路径与输入文件相同或指向同一文件，已拒绝覆盖。")
            if target.exists() and not target.is_file():
                raise AuditError("OUTPUT_ERROR", "报告目标不是普通文件，请更换输出目录。")
        output.mkdir(parents=True, exist_ok=True)
        for target, content in zip(targets, contents):
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                             dir=output, prefix=".audit-", delete=False) as handle:
                temporary = Path(handle.name)
                pending.append((temporary, target))
                handle.write(content)
        for temporary, target in pending:
            os.replace(temporary, target)
    except OSError as exc:
        raise AuditError("OUTPUT_ERROR", "无法保存报告，请检查输出路径、权限与磁盘空间。") from exc
    finally:
        for temporary, _ in pending:
            temporary.unlink(missing_ok=True)


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise AuditError("INVALID_ARGUMENTS", "命令参数无效，请运行 --help 查看必填参数和来源选项。")


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="M1 offline CSV audit (standard library only)")
    parser.add_argument("input", type=Path, help="UTF-8 CSV file, maximum 20 MiB")
    parser.add_argument("--out", required=True, type=Path, help="report output directory")
    parser.add_argument("--provenance", choices=PROVENANCES, default="unknown")
    try:
        args = parser.parse_args(argv)
        report = audit_csv(args.input, args.provenance)
        write_reports(report, args.out, args.input)
    except AuditError as exc:
        # ASCII 转义是合法 JSON；Windows 默认终端编码也不会破坏中文错误。
        print(json.dumps({"error": {"code": exc.code, "message": str(exc)}}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "ok", "row_count": report["row_count"],
                      "reports": [str(args.out / "report.json"), str(args.out / "report.md")]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
