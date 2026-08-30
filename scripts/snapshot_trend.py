#!/usr/bin/env python3
"""Read back HelvetiScan's monthly snapshots (data/snapshots/month=YYYY-MM/*.parquet) and answer
the questions task 23 built the feature for: which CVE matches appeared/disappeared between two
months, and which domains entered or left the dataset — outside SQLite, with Polars, per the
original design doc (tasks/done/task_23_monthly_snapshots.md).

Depends on tasks/done/task_26_snapshot_cross_month_readability.md (hive-partitioned
`month=YYYY-MM/` layout, explicit `month` column) and
tasks/done/task_28_snapshot_coverage_metrics.md (per-month `manifest.json` coverage, read here
without touching SQLite at all — this script never opens domains.db).

Usage (--snapshots-dir, if given, must come before the subcommand — it's a top-level option):
    python3 scripts/snapshot_trend.py [--snapshots-dir data/snapshots] verify
        Read every month present and fail loudly if one is unreadable or was never marked 'ok'.
        Run this right after a snapshot (or in CI) so a format regression surfaces immediately,
        not at the next time someone actually needs a trend.

    python3 scripts/snapshot_trend.py cve-diff --month-a 2026-07 --month-b 2026-08
        CVE matches that appeared / disappeared between two months, per domain and in aggregate.

    python3 scripts/snapshot_trend.py domains-diff --month-a 2026-07 --month-b 2026-08
        Domains that entered / left the dataset, with a coverage-aware caveat distinguishing
        "genuinely gone" from "we just didn't scan it that month" (task 28's whole point).

Requires: polars (`pip install polars` or `uv pip install polars`).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import polars as pl

# The exact read pattern verified in task 26: hive partitioning derives `month` from the
# `month=YYYY-MM/` directory name for free; `extra_columns="ignore"` and
# `missing_columns="insert"` are required because schema drifts across months as this repo's
# migrations land (a column added last month is simply absent — as NULL — in an older month's
# frame, rather than blowing up the whole multi-month read).
SCAN_KWARGS = dict(hive_partitioning=True, extra_columns="ignore", missing_columns="insert")


def month_dirs(snapshots_dir: Path) -> list[Path]:
    return sorted(p for p in snapshots_dir.glob("month=*") if p.is_dir())


def load_manifest(month_dir: Path) -> dict | None:
    manifest_path = month_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    return json.loads(manifest_path.read_text())


def scan_table(snapshots_dir: Path, table: str) -> pl.LazyFrame:
    return pl.scan_parquet(str(snapshots_dir / "month=*" / f"{table}.parquet"), **SCAN_KWARGS)


# ---- verify ----


def cmd_verify(args: argparse.Namespace) -> int:
    snapshots_dir = Path(args.snapshots_dir)
    dirs = month_dirs(snapshots_dir)
    if not dirs:
        print(f"no month=* directories found under {snapshots_dir}", file=sys.stderr)
        return 1

    ok = True
    for month_dir in dirs:
        month = month_dir.name.removeprefix("month=")
        manifest = load_manifest(month_dir)
        if manifest is None:
            print(f"{month}: FAIL — no manifest.json (incomplete or pre-task-27 snapshot)")
            ok = False
            continue

        tables = manifest.get("tables", [])
        missing = [t["file"] for t in tables if not (month_dir / t["file"]).exists()]
        if missing:
            print(f"{month}: FAIL — missing files: {', '.join(missing)}")
            ok = False
            continue

        try:
            for t in tables:
                pl.scan_parquet(str(month_dir / t["file"])).select(pl.len()).collect()
        except Exception as e:  # noqa: BLE001 - report and keep checking other months
            print(f"{month}: FAIL — unreadable ({e})")
            ok = False
            continue

        coverage = manifest.get("coverage", {})
        low = {
            name: f"{m['coverage_pct']:.1f}%"
            for name, m in coverage.items()
            if m.get("coverage_pct", 100) < 90
        }
        low_note = f" — low coverage: {low}" if low else ""
        print(f"{month}: ok — {len(tables)} table(s){low_note}")

    return 0 if ok else 1


# ---- cve-diff ----


def cmd_cve_diff(args: argparse.Namespace) -> int:
    snapshots_dir = Path(args.snapshots_dir)
    warn_low_coverage(snapshots_dir, [args.month_a, args.month_b], "http")

    cve = scan_table(snapshots_dir, "cve_matches").select(
        "month", "domain", "cve_id", "technology", "severity", "cvss_score"
    )
    a = cve.filter(pl.col("month") == args.month_a).collect()
    b = cve.filter(pl.col("month") == args.month_b).collect()

    key = ["domain", "cve_id"]
    appeared = b.join(a, on=key, how="anti").sort("severity", "domain")
    disappeared = a.join(b, on=key, how="anti").sort("severity", "domain")

    print(f"CVE matches: {args.month_a} -> {args.month_b}")
    print(f"  {args.month_a}: {a.height} match(es)  {args.month_b}: {b.height} match(es)")
    print(f"  appeared:    {appeared.height}")
    print(f"  disappeared: {disappeared.height}")

    if appeared.height:
        print(f"\n  new in {args.month_b}:")
        print(appeared.select("domain", "cve_id", "technology", "severity"))
    if disappeared.height:
        print(f"\n  gone since {args.month_a}:")
        print(disappeared.select("domain", "cve_id", "technology", "severity"))

    return 0


# ---- domains-diff ----


def cmd_domains_diff(args: argparse.Namespace) -> int:
    snapshots_dir = Path(args.snapshots_dir)
    warn_low_coverage(snapshots_dir, [args.month_a, args.month_b], "http")

    domains = scan_table(snapshots_dir, "domains").select("month", "domain")
    a = set(domains.filter(pl.col("month") == args.month_a).collect()["domain"])
    b = set(domains.filter(pl.col("month") == args.month_b).collect()["domain"])

    entered = sorted(b - a)
    left = sorted(a - b)

    print(f"Domains: {args.month_a} -> {args.month_b}")
    print(f"  {args.month_a}: {len(a)}  {args.month_b}: {len(b)}")
    print(f"  entered: {len(entered)}  left: {len(left)}")
    print(
        "  NOTE: 'left' conflates 'domain genuinely gone' with 'we failed to scan it that "
        "month' (task 28) — cross-check against manifest.json coverage above before reading "
        "this as churn."
    )
    if entered:
        print(f"\n  entered (first 20): {entered[:20]}")
    if left:
        print(f"\n  left (first 20): {left[:20]}")

    return 0


def warn_low_coverage(snapshots_dir: Path, months: list[str], module: str) -> None:
    for month in months:
        manifest = load_manifest(snapshots_dir / f"month={month}")
        if manifest is None:
            print(f"WARNING: {month} has no manifest.json — coverage unknown", file=sys.stderr)
            continue
        mc = manifest.get("coverage", {}).get(module)
        if mc and mc["coverage_pct"] < 90:
            print(
                f"WARNING: {month} {module} coverage was only {mc['coverage_pct']:.1f}% "
                f"({mc['scanned']}/{mc['total']}) — treat this month's numbers with caution",
                file=sys.stderr,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshots-dir", default="data/snapshots")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("verify", help="read every month present, fail loudly on an unreadable one")

    cve_diff = sub.add_parser("cve-diff", help="CVE matches that appeared/disappeared between two months")
    cve_diff.add_argument("--month-a", required=True)
    cve_diff.add_argument("--month-b", required=True)

    domains_diff = sub.add_parser("domains-diff", help="domains that entered/left between two months")
    domains_diff.add_argument("--month-a", required=True)
    domains_diff.add_argument("--month-b", required=True)

    args = parser.parse_args()

    if args.command == "verify":
        return cmd_verify(args)
    if args.command == "cve-diff":
        return cmd_cve_diff(args)
    if args.command == "domains-diff":
        return cmd_domains_diff(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
