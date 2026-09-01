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
# SCAN_MODE selects how the five independent Phase-1 network modules
# (scan/dns/tls/ports/subdomains) are run:
#
#   concurrent (default) — each as its own standalone OS process, all five at once, against the
#     one WAL database. Every module resolves/scans a different remote service (DNS resolver,
#     :80/:443, TLS, TCP ports, CT logs) so they overlap cleanly, and SQLite WAL handles the
#     concurrent single-writer-per-connection load without contention. Local scale test
#     (60k fail-fast domains, task_30): 120.5s vs 474.9s sequential — 3.94x faster, every module
#     wrote all 60k rows, `PRAGMA integrity_check` = ok, WAL fully checkpointed, zero
#     busy/locked/error. This is the recommended mode: it gets `full`'s overlap benefit while
#     side-stepping the in-process `full` hang (see task_29 / SCAN_MODE=full below).
#
#   sequential — each module one after another. Slowest (sum of all stages) but the most
#     conservative; use it if a concurrent run ever misbehaves on the production host.
#
#   full — `helvetiscan full`'s in-process 5-module orchestration. Observed 2026-08-30: at real
#     full-namespace scale it stalls (process alive, ~1 core busy, but zero DB writes for 5+
#     minutes), while the same modules run standalone stay healthy. Root cause never reproduced
#     locally with fail-fast synthetic domains (no in-process lock/static-sharing bug was found;
#     leading hypothesis is multi-writer + real-TLS-crypto scheduling pressure on a 4-vCPU box).
#     Left in only for debugging — do not use for a production run until it is root-caused.
#
# Back-compat: SEQUENTIAL_SCAN=1 still forces sequential, SEQUENTIAL_SCAN=0 still forces full,
# but only when SCAN_MODE is not set explicitly.
#
# NOTE: `update-cves --db` requires a binary built from src/main.rs's `UpdateCvesArgs` fix
# (task_36). Before that fix, `update-cves` was a bare subcommand with zero args, so `--db "$DB"`
# after it failed with "unexpected argument '--db' found" and (under `set -e`) killed the whole
# run — confirmed on the 2026-08-30/31 production run, which died here every time after ~19h of
# Phase 1 + smtp-check work. Deploying this script without the matching binary reintroduces that
# crash — deploy them together.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=./target/release/helvetiscan
DB=data/domains.db
DOMAINS_LIST="${DOMAINS_LIST:-data/sorted_domains.txt}"
OUTPUT_DIR=data/snapshots
PARALLEL_DIVISOR="${PARALLEL_DIVISOR:-3}"
STAMP=$(date +%Y-%m)
LOG_DIR=logs
BENCH_LOG="$LOG_DIR/benchmark-$STAMP.log"
mkdir -p "$LOG_DIR"

# Resolve SCAN_MODE, honouring the legacy SEQUENTIAL_SCAN toggle when SCAN_MODE is unset.
if [ -z "${SCAN_MODE:-}" ]; then
    case "${SEQUENTIAL_SCAN:-}" in
        1) SCAN_MODE=sequential ;;
        0) SCAN_MODE=full ;;
        *) SCAN_MODE=concurrent ;;
    esac
fi

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

# Run one Phase-1 module as a background process, timing it into its own log file (concurrent
# stages must not interleave into the shared benchmark log). Progress bars are suppressed with
# --quiet so the captured logs stay readable. Prints a one-line PASS/FAIL and returns the
# module's exit code so the barrier below can fail the whole run if any module failed.
bg_stage() {
    local name="$1"
    shift
    local log="$LOG_DIR/benchmark-$STAMP-$name.log"
    local t0 t1 rc
    t0=$(date +%s)
    echo "=== [$name] started $(date -Iseconds) ===" > "$log"
    "$@" --quiet >> "$log" 2>&1
    rc=$?
    t1=$(date +%s)
    echo "=== [$name] finished $(date -Iseconds) — $((t1 - t0))s (exit $rc) ===" >> "$log"
    echo "  [$name] $([ $rc -eq 0 ] && echo PASS || echo FAIL) — $((t1 - t0))s (exit $rc)"
    return "$rc"
}

# Launch the five Phase-1 modules concurrently, wait for all of them, then fold their per-module
# logs into the shared benchmark log. Fails (non-zero) if any module failed.
run_phase1_concurrent() {
    local mods=(scan dns tls ports subdomains)
    local pids=() rc=0 t0 t1
    t0=$(date +%s)
    echo "=== [phase1-concurrent] started $(date -Iseconds) ===" | tee -a "$BENCH_LOG"
    for m in "${mods[@]}"; do
        bg_stage "$m" "$BIN" "$m" --db "$DB" &
        pids+=("$!")
    done
    for i in "${!pids[@]}"; do
        if ! wait "${pids[$i]}"; then
            rc=1
            echo "  phase1 module ${mods[$i]} FAILED" | tee -a "$BENCH_LOG"
        fi
    done
    t1=$(date +%s)
    for m in "${mods[@]}"; do
        cat "$LOG_DIR/benchmark-$STAMP-$m.log" >> "$BENCH_LOG" 2>/dev/null || true
    done
    echo "=== [phase1-concurrent] finished $(date -Iseconds) — $((t1 - t0))s (rc $rc) ===" | tee -a "$BENCH_LOG"
    return "$rc"
}

stage init        "$BIN" init --input "$DOMAINS_LIST" --db "$DB"

case "$SCAN_MODE" in
    concurrent)
        run_phase1_concurrent
        # Phase 2/3 — sequential; each depends on Phase-1 data being present. Mirrors
        # cmd_full_pipeline's order: detect must precede update-cves (which folds in
        # software_detections and ports_info banners), verify-cves after update-cves.
        stage smtp-check   "$BIN" smtp-check --db "$DB"
        stage detect         "$BIN" detect --db "$DB"
        stage update-cves   "$BIN" update-cves --db "$DB"
        stage verify-cves   "$BIN" verify-cves --db "$DB"
        stage classify       "$BIN" classify --db "$DB"
        stage sovereignty   "$BIN" sovereignty --db "$DB"
        stage benchmark     "$BIN" benchmark --db "$DB"
        ;;
    sequential)
        # Mirrors `full`'s own phase order (cmd_full_pipeline in src/main.rs) exactly — Phase 1
        # (scan/dns/tls/ports/subdomains) then Phase 2 (smtp-check/detect/update-cves/verify-cves/
        # classify/sovereignty) then benchmark. Previously missing `detect` and `verify-cves` here
        # meant update-cves's CVE matching ran against a stale/empty software_detections table
        # (JS libs, frameworks, WP plugins) — detect must run before update-cves, which also folds
        # in ports_info banners, so it needs to come after `ports` too.
        stage scan         "$BIN" scan --db "$DB"
        stage dns           "$BIN" dns --db "$DB"
        stage tls           "$BIN" tls --db "$DB"
        stage ports         "$BIN" ports --db "$DB"
        stage subdomains   "$BIN" subdomains --db "$DB"
        stage smtp-check   "$BIN" smtp-check --db "$DB"
        stage detect         "$BIN" detect --db "$DB"
        stage update-cves   "$BIN" update-cves --db "$DB"
        stage verify-cves   "$BIN" verify-cves --db "$DB"
        stage classify       "$BIN" classify --db "$DB"
        stage sovereignty   "$BIN" sovereignty --db "$DB"
        stage benchmark     "$BIN" benchmark --db "$DB"
        ;;
    full)
        stage full "$BIN" full --db "$DB" --parallel-divisor "$PARALLEL_DIVISOR"
        ;;
    *)
        echo "unknown SCAN_MODE=$SCAN_MODE (expected concurrent|sequential|full)" >&2
        exit 2
        ;;
esac

stage fetch-feeds "$BIN" fetch-feeds --all --db "$DB"
stage snapshot     "$BIN" snapshot --db "$DB" --month "$STAMP" --output-dir "$OUTPUT_DIR"

# Mirror the benchmark log into the snapshot's own directory now that it exists.
cp "$BENCH_LOG" "$OUTPUT_DIR/month=$STAMP/benchmark.log" 2>/dev/null || true

echo "=== monthly run complete for $STAMP ($SCAN_MODE mode) ==="
