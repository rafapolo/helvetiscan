#!/bin/bash
# Monthly snapshot run: load any new domains, full re-scan of the whole namespace, refresh the
# CVE catalog from every available source, then freeze the result as a dated Parquet snapshot.
#
# Each stage is timed into logs/benchmark-<YYYY-MM>.log, which is also copied into the
# snapshot's own directory once it exists (data/snapshots/month=<YYYY-MM>/benchmark.log).
# `set -e` stops the chain on the first failing stage (rather than snapshotting a run that
# never actually finished).
#
# DOMAINS_LIST: point this at the freshest full .ch zone pull available (see project memory
# for how to get one via AXFR) — falls back to the checked-in static list if unset.
#
# SEQUENTIAL_SCAN=1 (default): run each Phase 1 module (scan/dns/tls/ports/subdomains) as its
# own standalone command, one after another, instead of `helvetiscan full`'s concurrent 5-module
# orchestration. Observed 2026-08-30: `full` hangs (CPU-burning but zero DB writes for 5+
# minutes) at real full-namespace scale, while the same http scan run standalone is steady at
# ~18/s with no hang — looks like resource contention or a deadlock between modules sharing one
# process under `full`, not a bug in the scan logic itself. Set SEQUENTIAL_SCAN=0 to use `full`
# once that's root-caused and fixed.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=./target/release/helvetiscan
DB=data/domains.db
DOMAINS_LIST="${DOMAINS_LIST:-data/sorted_domains.txt}"
OUTPUT_DIR=data/snapshots
PARALLEL_DIVISOR="${PARALLEL_DIVISOR:-3}"
SEQUENTIAL_SCAN="${SEQUENTIAL_SCAN:-1}"
STAMP=$(date +%Y-%m)
LOG_DIR=logs
BENCH_LOG="$LOG_DIR/benchmark-$STAMP.log"
mkdir -p "$LOG_DIR"

stage() {
    local name="$1"
    shift
    local t0 t1 rc
    t0=$(date +%s)
    echo "=== [$name] started $(date -Iseconds) ===" | tee -a "$BENCH_LOG"
    "$@" 2>&1 | tee -a "$BENCH_LOG"
    rc=${PIPESTATUS[0]}
    t1=$(date +%s)
    echo "=== [$name] finished $(date -Iseconds) — $((t1 - t0))s (exit $rc) ===" | tee -a "$BENCH_LOG"
    return "$rc"
}

stage init        "$BIN" init --input "$DOMAINS_LIST" --db "$DB"

if [ "$SEQUENTIAL_SCAN" = "1" ]; then
    stage scan       "$BIN" scan --db "$DB"
    stage dns         "$BIN" dns --db "$DB"
    stage tls         "$BIN" tls --db "$DB"
    stage ports       "$BIN" ports --db "$DB"
    stage subdomains "$BIN" subdomains --db "$DB"
    stage smtp-check "$BIN" smtp-check --db "$DB"
    stage update-cves "$BIN" update-cves --db "$DB"
    stage classify     "$BIN" classify --db "$DB"
    stage sovereignty "$BIN" sovereignty --db "$DB"
    stage benchmark   "$BIN" benchmark --db "$DB"
else
    stage full "$BIN" full --db "$DB" --parallel-divisor "$PARALLEL_DIVISOR"
fi

stage fetch-feeds "$BIN" fetch-feeds --all --db "$DB"
stage snapshot     "$BIN" snapshot --db "$DB" --month "$STAMP" --output-dir "$OUTPUT_DIR"

# Mirror the benchmark log into the snapshot's own directory now that it exists.
cp "$BENCH_LOG" "$OUTPUT_DIR/month=$STAMP/benchmark.log" 2>/dev/null || true

echo "=== monthly run complete for $STAMP ==="
