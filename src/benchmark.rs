use std::path::PathBuf;

use anyhow::{Context, Result};

pub(crate) async fn cmd_benchmark(db: PathBuf) -> Result<()> {
    let conn = crate::shared::open_db(&db)
        .with_context(|| format!("open db {:?}", db))?;

    crate::schema::ensure_schema(&conn)?;

    // Check if we have any classified domains
    let classified_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM domain_classification",
        [],
        |r| r.get(0),
    )?;

    if classified_count == 0 {
        eprintln!("benchmark: no classified domains found. Run `classify` first.");
        return Ok(());
    }

    // Compute risk_score benchmarks per sector
    compute_metric(
        &conn,
        "risk_score",
        "SELECT dc.sector, CAST(rs.score AS REAL) AS value
         FROM risk_score rs
         JOIN domain_classification dc ON dc.domain = rs.domain
         WHERE rs.score IS NOT NULL",
    )?;

    // HSTS adoption: % of domains where missing_hsts = false
    compute_pct_metric(
        &conn,
        "hsts_adoption",
        "SELECT dc.sector,
                CASE WHEN rs.missing_hsts = 0 THEN 1.0 ELSE 0.0 END AS value
         FROM risk_score rs
         JOIN domain_classification dc ON dc.domain = rs.domain",
    )?;

    // DNSSEC adoption: % where no_dnssec = false
    compute_pct_metric(
        &conn,
        "dnssec_adoption",
        "SELECT dc.sector,
                CASE WHEN rs.no_dnssec = 0 THEN 1.0 ELSE 0.0 END AS value
         FROM risk_score rs
         JOIN domain_classification dc ON dc.domain = rs.domain",
    )?;

    // DMARC weak %: % where dmarc_weak = true
    compute_pct_metric(
        &conn,
        "dmarc_weak_pct",
        "SELECT dc.sector,
                CASE WHEN rs.dmarc_weak = 1 THEN 1.0 ELSE 0.0 END AS value
         FROM risk_score rs
         JOIN domain_classification dc ON dc.domain = rs.domain",
    )?;

    // Print summary
    print_summary(&conn)?;

    Ok(())
}

fn compute_metric(conn: &rusqlite::Connection, metric: &str, src_sql: &str) -> Result<()> {
    // SQLite lacks QUANTILE_CONT; use AVG as approximation for percentiles.
    let sql = format!(
        "INSERT INTO sector_benchmarks (sector, metric, domain_count, mean_value, median_value, p25_value, p75_value, min_value, max_value)
         SELECT
             sector,
             '{metric}' AS metric,
             COUNT(*) AS domain_count,
             AVG(value) AS mean_value,
             AVG(value) AS median_value,
             AVG(value) AS p25_value,
             AVG(value) AS p75_value,
             MIN(value) AS min_value,
             MAX(value) AS max_value
         FROM ({src_sql}) sub
         GROUP BY sector
         ON CONFLICT (sector, metric) DO UPDATE SET
             domain_count = excluded.domain_count,
             mean_value   = excluded.mean_value,
             median_value = excluded.median_value,
             p25_value    = excluded.p25_value,
             p75_value    = excluded.p75_value,
             min_value    = excluded.min_value,
             max_value    = excluded.max_value,
             computed_at  = datetime('now')"
    );
    conn.execute_batch(&sql)?;
    Ok(())
}

fn compute_pct_metric(conn: &rusqlite::Connection, metric: &str, src_sql: &str) -> Result<()> {
    let sql = format!(
        "INSERT INTO sector_benchmarks (sector, metric, domain_count, mean_value, median_value, p25_value, p75_value, min_value, max_value)
         SELECT
             sector,
             '{metric}' AS metric,
             COUNT(*) AS domain_count,
             AVG(value) * 100.0 AS mean_value,
             AVG(value) * 100.0 AS median_value,
             AVG(value) * 100.0 AS p25_value,
             AVG(value) * 100.0 AS p75_value,
             MIN(value) * 100.0 AS min_value,
             MAX(value) * 100.0 AS max_value
         FROM ({src_sql}) sub
         GROUP BY sector
         ON CONFLICT (sector, metric) DO UPDATE SET
             domain_count = excluded.domain_count,
             mean_value   = excluded.mean_value,
             median_value = excluded.median_value,
             p25_value    = excluded.p25_value,
             p75_value    = excluded.p75_value,
             min_value    = excluded.min_value,
             max_value    = excluded.max_value,
             computed_at  = datetime('now')"
    );
    conn.execute_batch(&sql)?;
    Ok(())
}

fn print_summary(conn: &rusqlite::Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT sector, metric, domain_count, mean_value, median_value, p25_value, p75_value
         FROM sector_benchmarks
         ORDER BY sector, metric"
    )?;

    println!("\n{:<20} {:<20} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "sector", "metric", "n", "mean", "median", "p25", "p75");
    println!("{}", "-".repeat(84));

    struct Row {
        sector: String,
        metric: String,
        domain_count: i32,
        mean_value: f64,
        median_value: f64,
        p25_value: f64,
        p75_value: f64,
    }

    let rows: Vec<Row> = stmt.query_map([], |row| {
        Ok(Row {
            sector: row.get(0)?,
            metric: row.get(1)?,
            domain_count: row.get(2)?,
            mean_value: row.get(3)?,
            median_value: row.get(4)?,
            p25_value: row.get(5)?,
            p75_value: row.get(6)?,
        })
    })?
    .collect::<std::result::Result<_, _>>()?;

    for row in &rows {
        println!("{:<20} {:<20} {:>8} {:>8.1} {:>8.1} {:>8.1} {:>8.1}",
            row.sector, row.metric, row.domain_count,
            row.mean_value, row.median_value, row.p25_value, row.p75_value);
    }

    eprintln!("benchmark: computed {} sector×metric combinations", rows.len());
    Ok(())
}
