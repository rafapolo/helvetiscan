use std::collections::BTreeMap;
use std::fs;

use anyhow::{anyhow, Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::processing::export_as_parquet::export_tables;
use crate::SnapshotArgs;

/// Tables (and the `risk_score` view) captured in each monthly snapshot. Chosen for trend
/// value — technology/CVE evolution and risk posture over time — deliberately excluding bulky,
/// low-signal tables (`subdomains`, staging tables) to keep snapshots small. See
/// tasks/done/task_23_monthly_snapshots.md for the design rationale.
const SNAPSHOT_TABLES: &[&str] = &[
    "domains",
    "dns_info",
    "tls_info",
    "ports_info",
    "email_security",
    "smtp_tls_check",
    "domain_classification",
    "cve_matches",
    "cve_catalog",
    "risk_score",
];

/// Per-module scan coverage (tasks/done/task_28_snapshot_coverage_metrics.md): which table and
/// "scanned at" column say a domain was actually attempted (the same missing-column-means-
/// pending convention `load_pending_*` uses elsewhere), plus an optional per-row error column
/// to break errors down by kind.
struct CoverageModule {
    name: &'static str,
    table: &'static str,
    marker_col: &'static str,
    error_col: Option<&'static str>,
    /// Multiple rows per domain (e.g. one per port) — count DISTINCT domain instead of rows.
    distinct_domain: bool,
}

const COVERAGE_MODULES: &[CoverageModule] = &[
    CoverageModule { name: "http", table: "domains", marker_col: "updated_at", error_col: Some("error_kind"), distinct_domain: false },
    CoverageModule { name: "dns", table: "dns_info", marker_col: "resolved_at", error_col: Some("error_kind"), distinct_domain: false },
    CoverageModule { name: "tls", table: "tls_info", marker_col: "scanned_at", error_col: Some("error_kind"), distinct_domain: false },
    CoverageModule { name: "ports", table: "domains", marker_col: "ports_scanned_at", error_col: None, distinct_domain: false },
    CoverageModule { name: "email_security", table: "email_security", marker_col: "scanned_at", error_col: None, distinct_domain: false },
    CoverageModule { name: "smtp", table: "smtp_tls_check", marker_col: "checked_at", error_col: None, distinct_domain: true },
    CoverageModule { name: "classification", table: "domain_classification", marker_col: "classified_at", error_col: None, distinct_domain: false },
];

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ModuleCoverage {
    scanned: i64,
    total: i64,
    coverage_pct: f64,
    errors: BTreeMap<String, i64>,
    freshest_at: Option<String>,
    stalest_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TableManifestEntry {
    table: String,
    row_count: i64,
    columns: Vec<String>,
    file: String,
    sha256: String,
}

/// Headline dataset metrics for this month, computed straight off the `risk_score` view (the
/// same definitions used everywhere else in the project — README's "Mapping" numbers, the
/// benchmark command, etc.) plus a few counts from `cve_matches`/`domains`/`domain_classification`
/// not carried by that view. Written into `snapshot_<month>.json` (see `SnapshotSummary` below)
/// so month-over-month trend reading doesn't require opening Parquet with Polars just to answer
/// "did CVE exposure go up or down" — a flat JSON history is enough for that, and cheap to diff.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct SnapshotMetrics {
    total_domains: i64,
    avg_risk_score: Option<f64>,
    missing_hsts_pct: f64,
    missing_csp_pct: f64,
    missing_caa_pct: f64,
    weak_tls_pct: f64,
    cert_expired_pct: f64,
    cert_expiring_30d_pct: f64,
    no_dnssec_pct: f64,
    dmarc_weak_pct: f64,
    exposed_db_port_pct: f64,
    exposed_risky_port_pct: f64,
    exposed_ftp_pct: f64,
    exposed_docker_api_pct: f64,
    has_critical_cve_pct: f64,
    spf_permissive_pct: f64,
    no_dkim_pct: f64,
    smtp_no_starttls_pct: f64,
    smtp_starttls_fails_pct: f64,
    cve_total_matches: i64,
    cve_domains_affected: i64,
    cve_kev_matches: i64,
    cve_critical_matches: i64,
    top_cms: Vec<(String, i64)>,
    top_sectors: Vec<(String, i64)>,
}

/// The `snapshot_<month>.json` file itself — one per month, written flat under `output_dir`
/// (not inside `month=YYYY-MM/`) so `data/snapshots/snapshot_*.json` glob-reads across every
/// month present without descending into hive-partitioned directories, and survives a
/// `month=YYYY-MM/` dir being pruned/archived independently of this lighter-weight history.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SnapshotSummary {
    snapshot_month: String,
    tool_version: String,
    started_at: String,
    finished_at: String,
    duration_seconds: Option<i64>,
    row_counts: BTreeMap<String, i64>,
    coverage: BTreeMap<String, ModuleCoverage>,
    metrics: SnapshotMetrics,
}

/// Written last into each month's directory — a completeness marker readable without opening
/// SQLite at all (tasks/done/task_27_snapshot_export_atomicity.md step 4). `snapshot_runs`
/// stays the source of truth for anything that needs querying across months from the DB side;
/// this is its self-contained, directory-local mirror for readers that only have Parquet.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SnapshotManifest {
    snapshot_month: String,
    tool_version: String,
    started_at: String,
    finished_at: String,
    tables: Vec<TableManifestEntry>,
    coverage: BTreeMap<String, ModuleCoverage>,
}

pub(crate) fn cmd_snapshot(args: SnapshotArgs) -> Result<()> {
    let conn = crate::shared::open_db(&args.db).with_context(|| format!("opening {:?}", args.db))?;
    crate::schema::ensure_schema(&conn)?;

    let month = match args.month.clone() {
        Some(m) => m,
        None => current_month(),
    };
    validate_month(&month)?;

    if args.verify {
        return verify_snapshot(&args.output_dir, &month);
    }

    let started_at = chrono::Utc::now().to_rfc3339();
    record_running(&conn, &month, &started_at, &args.output_dir)?;

    match run_snapshot(&conn, &args, &month, &started_at) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = record_failed(&conn, &month, &e.to_string());
            Err(e)
        }
    }
}

fn run_snapshot(
    conn: &Connection,
    args: &SnapshotArgs,
    month: &str,
    started_at: &str,
) -> Result<()> {
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("creating snapshot output dir {:?}", args.output_dir))?;

    // Only snapshot tables/views that actually exist — lets an older db missing a newer table
    // still snapshot the rest instead of failing outright.
    let mut present_stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type IN ('table','view')")?;
    let present: std::collections::HashSet<String> = present_stmt
        .query_map([], |r| r.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    drop(present_stmt);

    let tables: Vec<String> = SNAPSHOT_TABLES
        .iter()
        .filter(|t| present.contains(**t))
        .map(|t| t.to_string())
        .collect();

    if tables.is_empty() {
        return Err(anyhow!(
            "snapshot: none of the expected tables/views exist in {:?}",
            args.db
        ));
    }

    // Coverage is computed up front — before any file is written — so `--min-coverage` can
    // refuse a bad month without leaving a partial (even if temp-dir'd) export behind.
    let coverage = compute_coverage(conn)?;
    for (name, mc) in &coverage {
        if mc.coverage_pct < 100.0 {
            eprintln!(
                "snapshot {month}: WARNING {name} coverage {:.1}% ({}/{})",
                mc.coverage_pct, mc.scanned, mc.total
            );
        }
    }
    if let Some(min) = args.min_coverage {
        if let Some((name, mc)) = coverage
            .iter()
            .find(|(_, mc)| mc.coverage_pct < min)
        {
            return Err(anyhow!(
                "snapshot {month}: refusing — {name} coverage {:.1}% is below --min-coverage {min:.1}%",
                mc.coverage_pct
            ));
        }
    }

    // Hive-partitioned path (`month=YYYY-MM/`) so a Polars/Arrow reader gets the month back as
    // a column for free (tasks/done/task_26_snapshot_cross_month_readability.md). Exported into
    // a sibling temp dir first, then swapped into place with one atomic rename, so a reader
    // never sees a half-written mix of old and new tables (task 27).
    let final_dir = args.output_dir.join(format!("month={month}"));
    let temp_dir = args
        .output_dir
        .join(format!(".tmp-month={month}-{}", std::process::id()));
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).ok();
    }
    fs::create_dir_all(&temp_dir)
        .with_context(|| format!("creating snapshot temp dir {:?}", temp_dir))?;

    eprintln!(
        "snapshot {month}: {} table(s)/view(s) → {}",
        tables.len(),
        final_dir.display()
    );
    // Explicit `month` column, in addition to the hive-partition directory name: cheap
    // insurance that survives a single Parquet file being copied out of its `month=YYYY-MM/`
    // directory (task 26 step 2).
    let exported = export_tables(conn, &tables, &temp_dir, Some(("month", month)))?;
    eprintln!("snapshot {month}: exported");

    let finished_at = chrono::Utc::now().to_rfc3339();

    let manifest_entries: Vec<TableManifestEntry> = exported
        .iter()
        .map(|t| -> Result<TableManifestEntry> {
            let file_path = temp_dir.join(format!("{}.parquet", t.table));
            let sha256 = sha256_file(&file_path)?;
            Ok(TableManifestEntry {
                table: t.table.clone(),
                row_count: t.row_count,
                columns: t.columns.clone(),
                file: format!("{}.parquet", t.table),
                sha256,
            })
        })
        .collect::<Result<_>>()?;

    let manifest = SnapshotManifest {
        snapshot_month: month.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at: started_at.to_string(),
        finished_at: finished_at.clone(),
        tables: manifest_entries.clone(),
        coverage: coverage.clone(),
    };
    let manifest_path = temp_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
        .with_context(|| format!("writing {:?}", manifest_path))?;

    // Atomic swap: remove any pre-existing final dir (stale files from a previous run that no
    // longer produces them, task 27 step 3), then rename the completed temp dir onto the final
    // path. Rename is atomic within a filesystem, so a concurrent reader sees either the
    // previous complete snapshot or the new one — never a mix.
    if final_dir.exists() {
        fs::remove_dir_all(&final_dir)
            .with_context(|| format!("removing stale snapshot dir {:?}", final_dir))?;
    }
    fs::rename(&temp_dir, &final_dir)
        .with_context(|| format!("renaming {:?} -> {:?}", temp_dir, final_dir))?;

    let tables_json = serde_json::to_string(&tables)?;
    let row_counts_json = serde_json::to_string(
        &exported
            .iter()
            .map(|t| (t.table.clone(), t.row_count))
            .collect::<BTreeMap<String, i64>>(),
    )?;
    let columns_json = serde_json::to_string(
        &exported
            .iter()
            .map(|t| (t.table.clone(), t.columns.clone()))
            .collect::<BTreeMap<String, Vec<String>>>(),
    )?;
    let coverage_json = serde_json::to_string(&coverage)?;

    conn.execute(
        "UPDATE snapshot_runs SET
            finished_at     = ?2,
            output_dir      = ?3,
            tables_json     = ?4,
            row_counts_json = ?5,
            columns_json    = ?6,
            coverage_json   = ?7,
            status          = 'ok',
            error           = NULL
         WHERE snapshot_month = ?1",
        rusqlite::params![
            month,
            finished_at,
            final_dir.to_string_lossy(),
            tables_json,
            row_counts_json,
            columns_json,
            coverage_json,
        ],
    )?;

    // Final step: compute headline dataset metrics and write the flat, cross-month
    // `snapshot_<month>.json` history file, so next month's run (or any offline analysis) has
    // real numbers to compare against without opening Parquet — deliberately last, after
    // everything that can fail has already succeeded.
    let metrics = compute_metrics(conn)?;
    let duration_seconds = chrono::DateTime::parse_from_rfc3339(started_at)
        .ok()
        .zip(chrono::DateTime::parse_from_rfc3339(&finished_at).ok())
        .map(|(s, f)| (f - s).num_seconds());
    let row_counts: BTreeMap<String, i64> = exported
        .iter()
        .map(|t| (t.table.clone(), t.row_count))
        .collect();
    let summary = SnapshotSummary {
        snapshot_month: month.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at: started_at.to_string(),
        finished_at,
        duration_seconds,
        row_counts,
        coverage,
        metrics,
    };
    write_snapshot_summary(&args.output_dir, &summary)?;

    eprintln!("snapshot {month}: done");
    Ok(())
}

fn record_running(
    conn: &Connection,
    month: &str,
    started_at: &str,
    output_dir: &std::path::Path,
) -> Result<()> {
    conn.execute(
        "INSERT INTO snapshot_runs (snapshot_month, started_at, output_dir, status)
         VALUES (?1, ?2, ?3, 'running')
         ON CONFLICT(snapshot_month) DO UPDATE SET
            started_at  = excluded.started_at,
            output_dir  = excluded.output_dir,
            status      = 'running',
            error       = NULL",
        rusqlite::params![month, started_at, output_dir.to_string_lossy()],
    )?;
    Ok(())
}

fn record_failed(conn: &Connection, month: &str, error: &str) -> Result<()> {
    conn.execute(
        "UPDATE snapshot_runs SET status = 'failed', error = ?2, finished_at = ?3
         WHERE snapshot_month = ?1",
        rusqlite::params![month, error, chrono::Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

// ---- coverage (task 28) ----

fn compute_coverage(conn: &Connection) -> Result<BTreeMap<String, ModuleCoverage>> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM domains", [], |r| r.get(0))?;

    let mut out = BTreeMap::new();
    for m in COVERAGE_MODULES {
        let scanned: i64 = if m.distinct_domain {
            conn.query_row(
                &format!(
                    "SELECT COUNT(DISTINCT domain) FROM \"{}\" WHERE {} IS NOT NULL",
                    m.table, m.marker_col
                ),
                [],
                |r| r.get(0),
            )?
        } else {
            conn.query_row(
                &format!(
                    "SELECT COUNT(*) FROM \"{}\" WHERE {} IS NOT NULL",
                    m.table, m.marker_col
                ),
                [],
                |r| r.get(0),
            )?
        };

        let (freshest_at, stalest_at): (Option<String>, Option<String>) = conn.query_row(
            &format!(
                "SELECT MAX({0}), MIN({0}) FROM \"{1}\" WHERE {0} IS NOT NULL",
                m.marker_col, m.table
            ),
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let mut errors = BTreeMap::new();
        if let Some(error_col) = m.error_col {
            let mut stmt = conn.prepare(&format!(
                "SELECT {error_col}, COUNT(*) FROM \"{}\" WHERE {error_col} IS NOT NULL GROUP BY {error_col}",
                m.table
            ))?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?;
            for row in rows.filter_map(|r| r.ok()) {
                errors.insert(row.0, row.1);
            }
        }

        let coverage_pct = if total > 0 {
            (scanned as f64 / total as f64) * 100.0
        } else {
            100.0
        };

        out.insert(
            m.name.to_string(),
            ModuleCoverage {
                scanned,
                total,
                coverage_pct,
                errors,
                freshest_at,
                stalest_at,
            },
        );
    }
    Ok(out)
}

fn compute_metrics(conn: &Connection) -> Result<SnapshotMetrics> {
    let mut m = SnapshotMetrics::default();

    // One pass over risk_score for every percentage — same flag definitions used across the
    // rest of the project, so these numbers are directly comparable to README/benchmark output.
    conn.query_row(
        "SELECT
            COUNT(*),
            AVG(score),
            AVG(missing_hsts) * 100.0,
            AVG(missing_csp) * 100.0,
            AVG(missing_caa) * 100.0,
            AVG(weak_tls) * 100.0,
            AVG(cert_expired) * 100.0,
            AVG(cert_expiring) * 100.0,
            AVG(no_dnssec) * 100.0,
            AVG(dmarc_weak) * 100.0,
            AVG(exposed_db_port) * 100.0,
            AVG(exposed_risky_port) * 100.0,
            AVG(exposed_ftp) * 100.0,
            AVG(exposed_docker_api) * 100.0,
            AVG(has_critical_cve) * 100.0,
            AVG(spf_permissive) * 100.0,
            AVG(no_dkim) * 100.0,
            AVG(smtp_no_starttls) * 100.0,
            AVG(smtp_starttls_fails) * 100.0
         FROM risk_score",
        [],
        |r| {
            m.total_domains = r.get(0)?;
            m.avg_risk_score = r.get(1)?;
            m.missing_hsts_pct = r.get::<_, Option<f64>>(2)?.unwrap_or(0.0);
            m.missing_csp_pct = r.get::<_, Option<f64>>(3)?.unwrap_or(0.0);
            m.missing_caa_pct = r.get::<_, Option<f64>>(4)?.unwrap_or(0.0);
            m.weak_tls_pct = r.get::<_, Option<f64>>(5)?.unwrap_or(0.0);
            m.cert_expired_pct = r.get::<_, Option<f64>>(6)?.unwrap_or(0.0);
            m.cert_expiring_30d_pct = r.get::<_, Option<f64>>(7)?.unwrap_or(0.0);
            m.no_dnssec_pct = r.get::<_, Option<f64>>(8)?.unwrap_or(0.0);
            m.dmarc_weak_pct = r.get::<_, Option<f64>>(9)?.unwrap_or(0.0);
            m.exposed_db_port_pct = r.get::<_, Option<f64>>(10)?.unwrap_or(0.0);
            m.exposed_risky_port_pct = r.get::<_, Option<f64>>(11)?.unwrap_or(0.0);
            m.exposed_ftp_pct = r.get::<_, Option<f64>>(12)?.unwrap_or(0.0);
            m.exposed_docker_api_pct = r.get::<_, Option<f64>>(13)?.unwrap_or(0.0);
            m.has_critical_cve_pct = r.get::<_, Option<f64>>(14)?.unwrap_or(0.0);
            m.spf_permissive_pct = r.get::<_, Option<f64>>(15)?.unwrap_or(0.0);
            m.no_dkim_pct = r.get::<_, Option<f64>>(16)?.unwrap_or(0.0);
            m.smtp_no_starttls_pct = r.get::<_, Option<f64>>(17)?.unwrap_or(0.0);
            m.smtp_starttls_fails_pct = r.get::<_, Option<f64>>(18)?.unwrap_or(0.0);
            Ok(())
        },
    )?;

    conn.query_row(
        "SELECT COUNT(*), COUNT(DISTINCT domain) FROM cve_matches",
        [],
        |r| {
            m.cve_total_matches = r.get(0)?;
            m.cve_domains_affected = r.get(1)?;
            Ok(())
        },
    )?;
    m.cve_kev_matches = conn.query_row(
        "SELECT COUNT(*) FROM cve_matches WHERE in_kev = 1",
        [],
        |r| r.get(0),
    )?;
    m.cve_critical_matches = conn.query_row(
        "SELECT COUNT(*) FROM cve_matches WHERE severity = 'CRITICAL'",
        [],
        |r| r.get(0),
    )?;

    let mut cms_stmt = conn.prepare(
        "SELECT cms, COUNT(*) c FROM domains WHERE cms IS NOT NULL AND cms != '' \
         GROUP BY cms ORDER BY c DESC LIMIT 10",
    )?;
    m.top_cms = cms_stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .filter_map(|r| r.ok())
        .collect();

    let mut sector_stmt = conn.prepare(
        "SELECT sector, COUNT(*) c FROM domain_classification WHERE sector IS NOT NULL AND sector != '' \
         GROUP BY sector ORDER BY c DESC LIMIT 10",
    )?;
    m.top_sectors = sector_stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(m)
}

/// Writes `output_dir/snapshot_<month>.json` — the flat, cross-month-glob-friendly summary
/// (see `SnapshotSummary`). Temp-file-then-rename, same atomicity reasoning as the month
/// directory itself: a reader never sees a half-written summary for a month.
fn write_snapshot_summary(
    output_dir: &std::path::Path,
    summary: &SnapshotSummary,
) -> Result<()> {
    let final_path = output_dir.join(format!("snapshot_{}.json", summary.snapshot_month));
    let temp_path = output_dir.join(format!(
        ".tmp-snapshot_{}-{}.json",
        summary.snapshot_month,
        std::process::id()
    ));
    fs::write(&temp_path, serde_json::to_string_pretty(summary)?)
        .with_context(|| format!("writing {:?}", temp_path))?;
    fs::rename(&temp_path, &final_path)
        .with_context(|| format!("renaming {:?} -> {:?}", temp_path, final_path))?;
    Ok(())
}

// ---- verify (task 30) ----

/// Re-reads a month's manifest, recomputes each file's checksum, and confirms it matches what
/// was recorded at export time — cheap corruption detection for data that, unlike current
/// scanner state, cannot be regenerated by re-scanning.
fn verify_snapshot(output_dir: &std::path::Path, month: &str) -> Result<()> {
    let dir = output_dir.join(format!("month={month}"));
    let manifest_path = dir.join("manifest.json");
    let manifest: SnapshotManifest = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("reading {:?} — has this month been snapshotted?", manifest_path))?,
    )
    .with_context(|| format!("parsing {:?}", manifest_path))?;

    let mut ok = true;
    for entry in &manifest.tables {
        let file_path = dir.join(&entry.file);
        let actual = match sha256_file(&file_path) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("snapshot {month}: MISSING/UNREADABLE {} ({e})", entry.file);
                ok = false;
                continue;
            }
        };
        if actual != entry.sha256 {
            eprintln!(
                "snapshot {month}: CHECKSUM MISMATCH {} — expected {}, got {actual}",
                entry.file, entry.sha256
            );
            ok = false;
        } else {
            eprintln!("snapshot {month}: ok {} ({} rows)", entry.file, entry.row_count);
        }
    }

    if ok {
        eprintln!("snapshot {month}: verify passed — {} table(s) intact", manifest.tables.len());
        Ok(())
    } else {
        Err(anyhow!("snapshot {month}: verify FAILED — see above"))
    }
}

fn sha256_file(path: &std::path::Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("reading {:?}", path))?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>())
}

fn current_month() -> String {
    chrono::Utc::now().format("%Y-%m").to_string()
}

/// Accepts only 'YYYY-MM' — this becomes both a directory name and a SQL primary key, so
/// reject anything else up front rather than writing a snapshot no one can find later.
fn validate_month(month: &str) -> Result<()> {
    let bytes = month.as_bytes();
    let ok = bytes.len() == 7
        && bytes[4] == b'-'
        && month[..4].bytes().all(|b| b.is_ascii_digit())
        && month[5..7].bytes().all(|b| b.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(anyhow!("--month must be 'YYYY-MM', got {month:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ensure_schema;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn validate_month_accepts_well_formed() {
        assert!(validate_month("2026-08").is_ok());
        assert!(validate_month("2000-01").is_ok());
    }

    #[test]
    fn validate_month_rejects_malformed() {
        assert!(validate_month("2026-8").is_err());
        assert!(validate_month("2026/08").is_err());
        assert!(validate_month("august").is_err());
        assert!(validate_month("").is_err());
        assert!(validate_month("2026-08-01").is_err());
    }

    #[test]
    fn current_month_matches_yyyy_mm_shape() {
        assert!(validate_month(&current_month()).is_ok());
    }

    fn test_args(db_path: &std::path::Path, out_dir: &std::path::Path, month: &str) -> SnapshotArgs {
        SnapshotArgs {
            db: db_path.to_path_buf(),
            month: Some(month.to_string()),
            output_dir: out_dir.to_path_buf(),
            min_coverage: None,
            verify: false,
        }
    }

    #[test]
    fn cmd_snapshot_writes_parquet_and_records_run() {
        let dir = tempdir();
        let db_path = dir.join("snap_test.db");
        let out_dir = dir.join("snapshots");

        let conn = Connection::open(&db_path).unwrap();
        ensure_schema(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain, status, cms, sovereignty_score, updated_at) VALUES
                ('a.ch', 'ok', 'wordpress', 0, datetime('now')),
                ('b.ch', 'ok', NULL, 1, datetime('now'));",
        )
        .unwrap();
        drop(conn);

        let args = test_args(&db_path, &out_dir, "2026-08");
        cmd_snapshot(args).unwrap();

        let month_dir = out_dir.join("month=2026-08");
        assert!(month_dir.join("domains.parquet").exists());
        assert!(month_dir.join("risk_score.parquet").exists());
        assert!(month_dir.join("manifest.json").exists());

        let summary_path = out_dir.join("snapshot_2026-08.json");
        assert!(summary_path.exists(), "snapshot_<month>.json should be written flat under output_dir");
        let summary: SnapshotSummary =
            serde_json::from_str(&fs::read_to_string(&summary_path).unwrap()).unwrap();
        assert_eq!(summary.snapshot_month, "2026-08");
        assert_eq!(summary.metrics.total_domains, 2);
        assert_eq!(summary.row_counts.get("domains"), Some(&2));

        let conn = Connection::open(&db_path).unwrap();
        let (started_at, tables_json, status): (String, String, String) = conn
            .query_row(
                "SELECT started_at, tables_json, status FROM snapshot_runs WHERE snapshot_month = '2026-08'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(!started_at.is_empty());
        assert!(tables_json.contains("domains"));
        assert_eq!(status, "ok");

        let row_counts_json: String = conn
            .query_row(
                "SELECT row_counts_json FROM snapshot_runs WHERE snapshot_month = '2026-08'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let counts: BTreeMap<String, i64> = serde_json::from_str(&row_counts_json).unwrap();
        assert_eq!(counts.get("domains"), Some(&2));

        cleanup(&dir);
    }

    #[test]
    fn cmd_snapshot_is_idempotent_for_same_month() {
        let dir = tempdir();
        let db_path = dir.join("snap_test2.db");
        let out_dir = dir.join("snapshots");

        let conn = Connection::open(&db_path).unwrap();
        ensure_schema(&conn).unwrap();
        conn.execute_batch("INSERT INTO domains (domain, status) VALUES ('a.ch', 'ok');")
            .unwrap();
        drop(conn);

        let args = || test_args(&db_path, &out_dir, "2026-08");
        cmd_snapshot(args()).unwrap();
        cmd_snapshot(args()).unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let run_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM snapshot_runs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(run_count, 1, "re-running the same month should overwrite, not duplicate");

        // Stale-file check (task 27 step 3): a file from a previous run that the current
        // export no longer produces must not survive a re-run.
        let month_dir = out_dir.join("month=2026-08");
        let stale = month_dir.join("stale_leftover.parquet");
        fs::write(&stale, b"stale").unwrap();
        cmd_snapshot(args()).unwrap();
        assert!(!stale.exists(), "re-running a month must remove files it no longer produces");

        cleanup(&dir);
    }

    #[test]
    fn cmd_snapshot_rejects_bad_month() {
        let dir = tempdir();
        let db_path = dir.join("snap_test3.db");
        let conn = Connection::open(&db_path).unwrap();
        ensure_schema(&conn).unwrap();
        drop(conn);

        let args = test_args(&db_path, &dir.join("snapshots"), "not-a-month");
        assert!(cmd_snapshot(args).is_err());
        cleanup(&dir);
    }

    #[test]
    fn cmd_snapshot_verify_detects_tampering() {
        let dir = tempdir();
        let db_path = dir.join("snap_test4.db");
        let out_dir = dir.join("snapshots");

        let conn = Connection::open(&db_path).unwrap();
        ensure_schema(&conn).unwrap();
        conn.execute_batch("INSERT INTO domains (domain, status) VALUES ('a.ch', 'ok');")
            .unwrap();
        drop(conn);

        cmd_snapshot(test_args(&db_path, &out_dir, "2026-08")).unwrap();

        let mut verify_args = test_args(&db_path, &out_dir, "2026-08");
        verify_args.verify = true;
        assert!(cmd_snapshot(verify_args).is_ok(), "unmodified snapshot should verify clean");

        // Corrupt a file and confirm verify catches it.
        fs::write(out_dir.join("month=2026-08").join("domains.parquet"), b"corrupted").unwrap();
        let mut verify_args = test_args(&db_path, &out_dir, "2026-08");
        verify_args.verify = true;
        assert!(cmd_snapshot(verify_args).is_err(), "tampered snapshot must fail verify");

        cleanup(&dir);
    }

    #[test]
    fn compute_metrics_reports_cve_and_top_breakdowns() {
        let dir = tempdir();
        let db_path = dir.join("snap_test6.db");
        let conn = Connection::open(&db_path).unwrap();
        ensure_schema(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain, status, status_code, cms) VALUES
                ('a.ch', 'ok', 200, 'wordpress'),
                ('b.ch', 'ok', 200, 'wordpress'),
                ('c.ch', 'ok', 200, 'drupal');
             INSERT INTO domain_classification (domain, sector) VALUES
                ('a.ch', 'finance'), ('b.ch', 'finance'), ('c.ch', 'government');
             INSERT INTO cve_matches (domain, technology, cve_id, severity, in_kev) VALUES
                ('a.ch', 'wordpress', 'CVE-2024-0001', 'CRITICAL', 1),
                ('b.ch', 'wordpress', 'CVE-2024-0002', 'MEDIUM', 0);",
        )
        .unwrap();

        let metrics = compute_metrics(&conn).unwrap();
        assert_eq!(metrics.total_domains, 3);
        assert_eq!(metrics.cve_total_matches, 2);
        assert_eq!(metrics.cve_domains_affected, 2);
        assert_eq!(metrics.cve_kev_matches, 1);
        assert_eq!(metrics.cve_critical_matches, 1);
        assert!((metrics.has_critical_cve_pct - 100.0 / 3.0).abs() < 0.01);
        assert_eq!(metrics.top_cms.first(), Some(&("wordpress".to_string(), 2)));
        assert_eq!(metrics.top_sectors.first(), Some(&("finance".to_string(), 2)));

        cleanup(&dir);
    }

    #[test]
    fn cmd_snapshot_min_coverage_refuses_below_threshold() {
        let dir = tempdir();
        let db_path = dir.join("snap_test5.db");
        let out_dir = dir.join("snapshots");

        let conn = Connection::open(&db_path).unwrap();
        ensure_schema(&conn).unwrap();
        // 4 domains, none scanned (updated_at NULL) -> http coverage is 0%.
        conn.execute_batch(
            "INSERT INTO domains (domain, status) VALUES ('a.ch', NULL), ('b.ch', NULL), ('c.ch', NULL), ('d.ch', NULL);",
        )
        .unwrap();
        drop(conn);

        let mut args = test_args(&db_path, &out_dir, "2026-08");
        args.min_coverage = Some(50.0);
        let err = cmd_snapshot(args).unwrap_err();
        assert!(err.to_string().contains("coverage"), "error should mention coverage: {err}");
        assert!(!out_dir.join("month=2026-08").exists(), "a refused snapshot must not leave a final dir");

        let conn = Connection::open(&db_path).unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM snapshot_runs WHERE snapshot_month = '2026-08'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "failed");

        cleanup(&dir);
    }

    // ---- tiny temp-dir helper (avoids pulling in a tempfile crate dependency) ----
    //
    // Names must be unique across concurrently-running test threads, not merely time-based:
    // four snapshot tests call this on separate threads, and two landing within the clock's
    // effective resolution used to collide on the same directory — whichever finished first
    // would `remove_dir_all` it out from under the other, still-running test (task 31).

    static TEMPDIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tempdir() -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = TEMPDIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tid = format!("{:?}", std::thread::current().id());
        dir.push(format!("helvetiscan-snapshot-test-{nanos}-{seq}-{tid}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }
}
