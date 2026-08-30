# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

HelvetiScan scans, maps, and risk-scores the entire Swiss `.ch` domain namespace (HTTP, DNS, TLS, ports, SMTP,
WHOIS, CVEs). It is a single Rust CLI binary (`helvetiscan`) that writes everything into one SQLite database
(`data/domains.db`). A secondary Bun/JS pipeline (`web/`, `src/process/`) converts that data into Arrow/Parquet
for a force-graph dataviz frontend, and `website/` is a static marketing/report site deployed separately.

## Commands

### Rust CLI (main product)
```bash
cargo build --release            # release binary at target/release/helvetiscan
cargo test                       # unit tests + one live e2e test (sample_domains_e2e_scan, hits the network)
cargo test sanitize_domain       # run a single test by name (substring match)
cargo test --lib -- --skip e2e   # skip the network-dependent e2e test

cargo run -- init                          # populate domains.db from data/sorted_domains.txt
cargo run -- --domain example.ch           # run all scan modules against one domain
cargo run -- scan / dns / tls / ports / subdomains / smtp-check
cargo run -- full                          # full pipeline: parallel scans -> post-processing -> benchmark
cargo run -- show --domain example.ch      # dump every table's row for one domain
```
Every scan subcommand accepts `--db`, `--domain` (single-domain mode), `--concurrency`, and
`--retry-errors <kind>` (re-scan rows whose `error_kind` matches, e.g. `timeout`).

### Bun/JS dataviz pipeline
```bash
bun run convert   # src/process/csv-to-arrow.js — CSV -> Arrow for the frontend
bun run serve     # web/serve.js — static file server (serves .arrow/.parquet as raw bytes)
```

## Architecture

### The CLI: one crate, one binary, per-module files
`src/main.rs` defines the `clap` CLI and dispatches to sibling modules — one file per scan type
(`http_scan.rs`, `dns_scan.rs`, `tls_scan.rs`, `ports_scan.rs`, `smtp_check.rs`, `subdomains.rs`,
`email_security.rs`, `cve.rs`, `classify.rs`, `sovereignty.rs`, `benchmark.rs`, `geocode.rs`). `shared.rs` holds
common row structs, the `ErrorKind`/`ScanStatus` enums, the async DNS resolver, SQL escaping helpers, and the
progress-bar/reporter machinery. `schema.rs` owns all `CREATE TABLE`/`CREATE VIEW` DDL and runs on every DB open.

Every scan module follows the same shape:
```rust
pub(crate) async fn cmd_xxx(
    args: XxxArgs,
    cancel_rx: Option<watch::Receiver<bool>>,   // cooperative cancellation (used by `full`)
    progress: Option<Arc<Progress>>,             // shared counters (used by `full`'s live reporter)
) -> Result<()>
```
It loads domains missing the corresponding `_at`/status column, fans out over `tokio` with a bounded
`--concurrency`, and flushes results back to SQLite in batches. When `cmd_xxx` is invoked standalone it
creates its own `Progress`/cancellation defaults; `full` wires in shared ones so all modules report through
one multi-line progress display and one error-rate supervisor.

### `full` pipeline phases (`cmd_full_pipeline` in main.rs)
1. **Phase 1 — parallel network scans**: http, dns, tls, ports, subdomains run concurrently as a
   `JoinSet`, each with its own cancellation channel. An `error_rate_supervisor` cancels a module early if its
   error rate exceeds `--error-threshold` after `min_samples` requests. Ctrl-C/SIGTERM triggers a global
   shutdown that fans out to every module's cancel channel; a second Ctrl-C forces an immediate exit.
2. **Phase 2 — sequential post-processing**: smtp-check, update-cves, classify, sovereignty (each depends on
   Phase 1 data being present).
3. **Phase 3 — benchmark**: reads everything through the `risk_score` SQL view.

### Data model
Single SQLite DB (`data/domains.db`, WAL mode, opened via `shared::open_db`) with one row per domain per table:
`domains` (core status/HTTP result), `dns_info`, `tls_info`, `ports_info`, `subdomains`,
`http_headers`, `email_security`, `smtp_tls_check`, `domain_classification`, `cve_catalog`/`cve_matches`. The
`risk_score` view aggregates across tables into a per-domain score; `domain_percentile` and `ns_concentration`
are derived views used by `benchmark`/`sovereignty`. **`docs/SCHEMA.md` is the source-of-truth ER diagram for
these tables — update it whenever a table or column changes.**

Domains move through the pipeline via nullable "scanned at" timestamp columns: each module's `load_pending_*`
query selects domains missing that module's timestamp (or matching `--retry-errors`), so modules are safe to
re-run repeatedly and pick up only unfinished work.

### CVE correlation (`cve.rs`)
Pulls the CISA KEV feed plus built-in seed entries into `cve_catalog`, then matches detected software/versions
(from HTTP `Server`/`X-Powered-By` headers and port banners) against `affected_from`/`affected_to` ranges into
`cve_matches`. See `TODO.md` for known gaps (no NVD/OSV/GHSA feeds yet, banner version extraction incomplete for
most services, no plugin/JS-library CVE matching).

### Export/import (`src/processing/`)
`export_as_parquet.rs`/`import_from_parquet.rs` round-trip every table (or a subset via `--exclude`) between
SQLite and per-table `.parquet` files in a directory, used to move scan results to the Arrow/Parquet-based
dataviz pipeline without shipping the raw SQLite file.

### Dataviz frontend (`web/`, `src/process/`)
`src/process/csv-to-arrow.js` converts exported CSVs to Arrow IPC files (`nodes.arrow`/`edges.arrow`) consumed
by a Cosmograph force-graph frontend served statically from `web/` (`web/serve.js` is a plain Bun HTTP server;
binary formats like `.arrow`/`.parquet` are served as raw bytes, not text, since they'd otherwise get mangled
by UTF-8 decoding).

### `website/`
Static site, deployed to GitHub Pages by `.github/workflows/deploy-website.yml` on any push to `main` that
touches `website/**`.

### Releases
Pushing a `v*` tag runs `.github/workflows/release.yml`, cross-compiling the CLI for `aarch64-apple-darwin` and
`x86_64-unknown-linux-musl` (via `cross`, statically linked) and attaching both binaries to a GitHub Release.
