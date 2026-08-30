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
