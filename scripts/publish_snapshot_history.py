#!/usr/bin/env python3
"""Regenerate website/data/snapshot-history.json from data/snapshots/snapshot_*.json.

The flat `snapshot_<month>.json` files (see docs/SNAPSHOTS.md) are `helvetiscan snapshot`'s
per-month summary — written straight from the `risk_score` view, one file per month, under
`data/snapshots/` (gitignored, never shipped to the website). This script picks the handful of
headline fields the "Snapshot Trend" section on the website actually renders, trims them down,
and writes the result to `website/data/snapshot-history.json` (tracked in git, deployed by
deploy-website.yml) sorted oldest-to-newest so the page can diff consecutive entries client-side.

Run this after every `helvetiscan snapshot` you want reflected on the website — it is not wired
into scripts/monthly.sh automatically, since not every snapshot is meant to be published.

No third-party deps (stdlib json only) — these are small flat JSON files, not a dataframe job.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS_DIR = REPO_ROOT / "data" / "snapshots"
OUTPUT_PATH = REPO_ROOT / "website" / "data" / "snapshot-history.json"

# Metric keys pulled from SnapshotMetrics (src/snapshot.rs) — kept to the subset the website
# renders as trend cards. Each is a fraction-of-domains percentage; "lower_is_better" drives
# which direction the website colors green vs red when comparing two months.
METRICS = [
    ("missing_hsts_pct", "Missing HSTS", True),
    ("weak_tls_pct", "Weak/expired TLS", True),
    ("cert_expiring_30d_pct", "Certs expiring <30d", True),
    ("no_dnssec_pct", "No DNSSEC", True),
    ("dmarc_weak_pct", "DMARC weak/absent", True),
    ("exposed_db_port_pct", "Exposed DB port", True),
    ("has_critical_cve_pct", "Has CRITICAL CVE", True),
    ("no_dkim_pct", "No DKIM", True),
]


def load_summary(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def trim(summary: dict) -> dict:
    metrics = summary.get("metrics", {})
    coverage = summary.get("coverage", {})
    coverage_pcts = {
        module: round(m.get("coverage_pct", 0.0), 1)
        for module, m in coverage.items()
    }
    min_coverage_pct = min(coverage_pcts.values(), default=0.0)
    # A snapshot taken mid-scan (any module under full coverage) is "partial": its metrics
    # are honest for what has been scanned, but will keep moving as the scan completes. The
    # website surfaces this rather than presenting partial numbers as settled.
    partial = any(pct < 99.5 for pct in coverage_pcts.values())
    return {
        "snapshot_month": summary["snapshot_month"],
        "finished_at": summary.get("finished_at"),
        "total_domains": metrics.get("total_domains"),
        "avg_risk_score": metrics.get("avg_risk_score"),
        "min_module_coverage_pct": round(min_coverage_pct, 1),
        "partial": partial,
        "coverage": coverage_pcts,
        "metrics": {
            key: metrics.get(key) for key, _label, _lower_is_better in METRICS
        },
    }


def main() -> int:
    files = sorted(SNAPSHOTS_DIR.glob("snapshot_*.json"))
    if not files:
        print(
            f"no snapshot_*.json files under {SNAPSHOTS_DIR} — writing empty history "
            "(this is expected before the first `helvetiscan snapshot` run)",
            file=sys.stderr,
        )
    entries = [trim(load_summary(f)) for f in files]
    entries.sort(key=lambda e: e["snapshot_month"])

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(entries, indent=2) + "\n")
    print(f"wrote {len(entries)} snapshot(s) to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
