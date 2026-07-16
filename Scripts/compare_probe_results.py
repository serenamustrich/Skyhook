#!/usr/bin/env python3
"""Compare probe result exports from Supercore and Sparkle/Mihomo.

Usage:
    python3 Scripts/compare_probe_results.py \
      --supercore /tmp/supercore_probe.json \
      --external /tmp/sparkle_probe.json \
      --top 20

输入支持如下格式：
- JSON：节点列表，或包含 "results" 字段的对象
- CSV：表头包含节点名/延迟/成功字段

脚本会对齐同名节点并输出：
- 总节点/可用率
- 失败分类
- 50/90 分位（可用节点）
- 前 N 个同名节点的逐条延迟、可用性差异
"""

from __future__ import annotations

import argparse
import csv
import json
from statistics import median
from math import ceil

import pathlib


def read_json_records(path: pathlib.Path):
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        if "results" in raw and isinstance(raw["results"], list):
            raw = raw["results"]
        elif "items" in raw and isinstance(raw["items"], list):
            raw = raw["items"]
        elif "probes" in raw and isinstance(raw["probes"], list):
            raw = raw["probes"]
        elif "nodes" in raw and isinstance(raw["nodes"], list):
            raw = raw["nodes"]
    if not isinstance(raw, list):
        raise ValueError(f"{path} 不是节点列表 JSON（需要 list 或含 results 的 dict）")
    return raw


def read_csv_records(path: pathlib.Path):
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def normalize_key(record, candidates, cast=None, default=None):
    for key in candidates:
        if key in record and record[key] is not None:
            val = record[key]
            if cast is None:
                return val
            try:
                return cast(val)
            except Exception:
                return default
    return default


def normalize_records(records):
    normalized = {}
    for row in records:
        name = normalize_key(
            row,
            ["name", "node", "proxy", "outbound", "server", "target"],
            cast=str,
            default="",
        )
        if not name:
            continue

        success = normalize_key(
            row,
            [
                "success",
                "ok",
                "isSuccess",
                "is_success",
                "healthy",
            ],
            cast=lambda x: bool(int(x)) if isinstance(x, (int, float, str)) and str(x).isdigit() else bool(x) if isinstance(x, bool) else None,
            default=None,
        )

        if success is None:
            # 有些导出表是用延迟是否为正数代表可用
            latency = normalize_key(
                row,
                [
                    "latency_ms",
                    "latencyMs",
                    "latency",
                    "delay_ms",
                    "delay",
                    "ms",
                ],
                cast=int,
                default=None,
            )
            if latency is None:
                success = None
            else:
                success = latency >= 0
        else:
            latency = normalize_key(
                row,
                [
                    "latency_ms",
                    "latencyMs",
                    "latency",
                    "delay_ms",
                    "delay",
                    "ms",
                ],
                cast=int,
                default=None,
            )

        if latency is None:
            latency = normalize_key(
                row,
                ["time_ms", "time"],
                cast=int,
                default=None,
            )

        failure_kind = normalize_key(
            row,
            [
                "failure_kind",
                "failureKind",
                "failure-kind",
                "failure",
                "error_code",
            ],
            cast=str,
            default=None,
        )
        if failure_kind:
            failure_kind = failure_kind.strip()

        error = normalize_key(
            row,
            ["error", "error_msg", "message", "msg"],
            cast=str,
            default=None,
        )

        normalized[str(name)] = {
            "name": str(name),
            "success": success,
            "latency_ms": latency,
            "failure_kind": failure_kind,
            "error": error,
        }
    return normalized


def load_records(path: str):
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(f"找不到文件：{p}")

    if p.suffix.lower() in {".csv"}:
        return normalize_records(read_csv_records(p))
    return normalize_records(read_json_records(p))


def percentiles(values, percent):
    if not values:
        return None
    values = sorted(values)
    idx = (percent / 100) * (len(values) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(values) - 1)
    if lo == hi:
        return values[lo]
    w = idx - lo
    return values[lo] * (1 - w) + values[hi] * w


def latency_text(value):
    return "n/a" if value is None else f"{value}ms"


def summarize(records):
    total = len(records)
    available = [r for r in records.values() if r["success"]]
    unavailable = [r for r in records.values() if r["success"] is False]
    unknown = [r for r in records.values() if r["success"] is None]
    available_lat = [r["latency_ms"] for r in available if isinstance(r["latency_ms"], int)]
    by_kind = {}
    for r in unavailable:
        by_kind[r["failure_kind"] or "unknown"] = by_kind.get(r["failure_kind"] or "unknown", 0) + 1
    return {
        "total": total,
        "available": len(available),
        "unavailable": len(unavailable),
        "unknown": len(unknown),
        "availability_rate": (len(available) / total * 100.0) if total else 0.0,
        "p50": percentiles(available_lat, 50),
        "p90": percentiles(available_lat, 90),
        "failure_kind": by_kind,
    }


def fmt_summary(label, summary):
    print(f"[{label}] 节点总数: {summary['total']}")
    print(f"[ {label}] 可用: {summary['available']} / {summary['total']} ({summary['availability_rate']:.2f}%)")
    print(f"[ {label}] 不可用: {summary['unavailable']}, 未知: {summary['unknown']}")
    p50 = summary["p50"]
    p90 = summary["p90"]
    p50_text = "n/a" if p50 is None else f"{p50}ms"
    p90_text = "n/a" if p90 is None else f"{p90}ms"
    print(f"[ {label}] P50: {p50_text}, P90: {p90_text}")
    if summary["failure_kind"]:
        parts = sorted(summary["failure_kind"].items())
        print(f"[ {label}] 失败分类: " + ", ".join(f"{k}={v}" for k, v in parts))


def main():
    parser = argparse.ArgumentParser(description="比对 Supercore 与外部方案的 probe 结果")
    parser.add_argument("--supercore", required=True)
    parser.add_argument("--external", required=True)
    parser.add_argument("--top", type=int, default=20, help="打印同名节点差异前 N 条")
    args = parser.parse_args()

    left = load_records(args.supercore)
    right = load_records(args.external)

    print("===== 对比汇总 =====")
    left_summary = summarize(left)
    right_summary = summarize(right)
    fmt_summary("Supercore", left_summary)
    fmt_summary("外部", right_summary)

    both = sorted(set(left.keys()) & set(right.keys()))
    only_left = sorted(set(left.keys()) - set(right.keys()))
    only_right = sorted(set(right.keys()) - set(left.keys()))

    print("\n===== 同名节点 ====")
    print(f"重合节点数: {len(both)}")
    if both:
        diffs = []
        for name in both:
            a = left[name]
            b = right[name]
            if a["success"] != b["success"]:
                diffs.append((name, a, b, "可用性"))
                continue
            if a["success"] and b["success"] and a["latency_ms"] is not None and b["latency_ms"] is not None:
                d = abs((a["latency_ms"] or 0) - (b["latency_ms"] or 0))
                if d > 0:
                    diffs.append((name, a, b, f"延迟差值 {d}ms"))

        if not diffs:
            print("同名节点无显著差异（可用性一致）")
        else:
            print(f"发现 {len(diffs)} 个同名节点差异（显示前 {min(args.top, len(diffs))} 条）:")
            for name, a, b, reason in diffs[: args.top]:
                print(f"- {name}: {reason}")
                print(f"  Supercore: success={a['success']}, latency={a['latency_ms']}, failure_kind={a['failure_kind']}")
                print(f"  外部:    success={b['success']}, latency={b['latency_ms']}, failure_kind={b['failure_kind']}")

    print("\n===== 仅存在于一侧 =====")
    print(f"仅 Supercore: {len(only_left)} 个")
    if only_left:
        print("  " + ", ".join(only_left[:10]) + (" ..." if len(only_left) > 10 else ""))
    print(f"仅外部: {len(only_right)} 个")
    if only_right:
        print("  " + ", ".join(only_right[:10]) + (" ..." if len(only_right) > 10 else ""))

    # 仅聚焦同名节点前 N 条，可用于人工核验
    sample = both[: args.top]
    if sample:
        with_stats = []
        for name in sample:
            a = left[name]
            b = right[name]
            with_stats.append((name, a["success"], b["success"], a["latency_ms"], b["latency_ms"]))
        print("\n===== 前同名节点清单（最多 top） =====")
        for name, ls, rs, lms, rms in with_stats:
            print(f"{name}: supercore={ls}/{latency_text(lms)} external={rs}/{latency_text(rms)}")


if __name__ == "__main__":
    main()
