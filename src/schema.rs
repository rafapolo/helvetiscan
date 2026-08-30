use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use crate::shared::sanitize_domain;
use crate::InitArgs;

pub(crate) fn ensure_schema(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS domains (
            domain           TEXT PRIMARY KEY,
            status           TEXT,
            final_url        TEXT,
            status_code      INTEGER,
            title            TEXT,
            body_hash        TEXT,
            error_kind       TEXT,
            elapsed_ms       INTEGER,
            ip               TEXT,
            updated_at       TEXT,
            server           TEXT,
            powered_by       TEXT,
            redirect_chain   TEXT,
            cms              TEXT,
            sovereignty_score INTEGER,
            country_code     TEXT
        );

        CREATE TABLE IF NOT EXISTS dns_info (
            domain        TEXT PRIMARY KEY,
            status        TEXT,
            error_kind    TEXT,
            ns            TEXT,
            mx            TEXT,
            cname         TEXT,
            a             TEXT,
            aaaa          TEXT,
            txt_spf       TEXT,
            txt_dmarc     TEXT,
            ttl           INTEGER,
            ptr           TEXT,
            dnssec        INTEGER,
            dnssec_signed INTEGER,
            dnssec_valid  INTEGER,
            caa           TEXT,
            wildcard      INTEGER,
            txt_all       TEXT,
            resolved_at   TEXT
        );

        CREATE TABLE IF NOT EXISTS tls_info (
            domain              TEXT PRIMARY KEY,
            status              TEXT,
            error_kind          TEXT,
            cert_issuer         TEXT,
            cert_subject        TEXT,
            valid_from          TEXT,
            valid_to            TEXT,
            days_remaining      INTEGER,
            expired             INTEGER,
            self_signed         INTEGER,
            tls_version         TEXT,
            cipher              TEXT,
            san                 TEXT,
            key_algorithm       TEXT,
            key_size            INTEGER,
            signature_algorithm TEXT,
            cert_fingerprint    TEXT,
            ct_logged           INTEGER,
            ocsp_must_staple    INTEGER,
            scanned_at          TEXT
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            domain        TEXT,
            subdomain     TEXT,
            source        TEXT,
            discovered_at TEXT,
            PRIMARY KEY (domain, subdomain)
        );

        CREATE TABLE IF NOT EXISTS http_headers (
            domain                 TEXT PRIMARY KEY,
            hsts                   TEXT,
            csp                    TEXT,
            x_frame_options        TEXT,
            x_content_type_options TEXT,
            cors_origin            TEXT,
            referrer_policy        TEXT,
            permissions_policy     TEXT,
            scanned_at             TEXT
        );

        CREATE TABLE IF NOT EXISTS cve_catalog (
            cve_id        TEXT PRIMARY KEY,
            technology    TEXT NOT NULL,
            affected_from TEXT,
            affected_to   TEXT,
            severity      TEXT,
            cvss_score    REAL,
            in_kev        INTEGER DEFAULT 0,
            summary       TEXT,
            published_at  TEXT,
            epss_score       REAL,
            epss_percentile  REAL
        );

        CREATE TABLE IF NOT EXISTS domain_technologies (
            domain        TEXT NOT NULL,
            technology    TEXT NOT NULL,
            version       TEXT,
            detected_at   TEXT DEFAULT (datetime('now')),
            last_seen     TEXT DEFAULT (datetime('now')),
            source        TEXT,
            PRIMARY KEY (domain, technology)
        );

        CREATE TABLE IF NOT EXISTS cve_matches (
            domain        TEXT NOT NULL,
            technology    TEXT NOT NULL,
            version       TEXT,
            cve_id        TEXT NOT NULL,
            severity      TEXT,
            cvss_score    REAL,
            in_kev        INTEGER,
            published_at  TEXT,
            matched_at    TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (domain, cve_id)
        );

        CREATE TABLE IF NOT EXISTS cve_verifications (
            domain        TEXT NOT NULL,
            cve_id        TEXT NOT NULL,
            verified      INTEGER NOT NULL DEFAULT 0,
            checked_at    TEXT,
            check_method  TEXT,
            proof         TEXT,
            PRIMARY KEY (domain, cve_id)
        );

        CREATE TABLE IF NOT EXISTS software_detections (
            domain       TEXT NOT NULL,
            kind         TEXT NOT NULL,   -- 'js_lib' | 'framework' | 'wp_plugin'
            name         TEXT NOT NULL,
            version      TEXT,
            detected_at  TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (domain, kind, name)
        );

        CREATE TABLE IF NOT EXISTS email_security (
            domain                 TEXT PRIMARY KEY,
            spf_present            INTEGER,
            spf_policy             TEXT,
            spf_too_permissive     INTEGER,
            spf_dns_lookups        INTEGER,
            spf_over_limit         INTEGER,
            dmarc_present          INTEGER,
            dmarc_policy           TEXT,
            dmarc_subdomain_policy TEXT,
            dmarc_has_reporting    INTEGER,
            dmarc_pct              INTEGER,
            dkim_default           INTEGER,
            dkim_google            INTEGER,
            dkim_found             INTEGER,
            scanned_at             TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS domain_classification (
            domain        TEXT PRIMARY KEY,
            sector        TEXT,
            subsector     TEXT,
            source        TEXT,
            confidence    REAL,
            classified_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sector_benchmarks (
            sector        TEXT NOT NULL,
            metric        TEXT NOT NULL,
            domain_count  INTEGER,
            mean_value    REAL,
            median_value  REAL,
            p25_value     REAL,
            p75_value     REAL,
            min_value     REAL,
            max_value     REAL,
            computed_at   TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (sector, metric)
        );

        CREATE TABLE IF NOT EXISTS ns_staging (
            domain   TEXT NOT NULL,
            operator TEXT NOT NULL,
            PRIMARY KEY (domain, operator)
        );

        CREATE TABLE IF NOT EXISTS ns_operators (
            operator     TEXT NOT NULL PRIMARY KEY,
            sample_ns    TEXT,
            resolved_ip  TEXT,
            asn          TEXT,
            asn_org      TEXT,
            country_code TEXT,
            jurisdiction TEXT NOT NULL DEFAULT 'OTHER',
            updated_at   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS snapshot_runs (
            snapshot_month  TEXT PRIMARY KEY,   -- 'YYYY-MM'
            started_at      TEXT,
            finished_at     TEXT,
            output_dir      TEXT,
            tables_json     TEXT,               -- JSON array of table/view names exported
            row_counts_json TEXT                -- JSON object {table: row_count}
        );
    ",
    )?;
    migrate_ports_info(conn)?;
    migrate_ports_open_only(conn)?;
    migrate_domains_country_code(conn)?;
    migrate_ports_ip_from_domains(conn)?;
    migrate_ports_targeted_at(conn)?;
    migrate_snapshot_runs_status_coverage(conn)?;

    migrate_cve_catalog_epss(conn)?;

    // The risk_score view below references smtp_tls_check, so that table must exist for
    // any consumer of ensure_schema (not just the smtp-check command).
    ensure_smtp_tls_check_schema(conn)?;

    conn.execute_batch("DROP VIEW IF EXISTS risk_score;")?;
    conn.execute_batch("
        CREATE VIEW risk_score AS
        SELECT
            d.domain,
            (h.hsts IS NULL AND d.status_code = 200)                                    AS missing_hsts,
            (h.csp  IS NULL AND d.status_code = 200)                                    AS missing_csp,
            (dns.caa IS NULL OR json_array_length(dns.caa) = 0)                         AS missing_caa,
            (t.tls_version IN ('TLSv1.0','TLSv1.1') OR t.expired = 1)                  AS weak_tls,
            (t.expired = 1)                                                              AS cert_expired,
            (t.days_remaining BETWEEN 0 AND 29)                                         AS cert_expiring,
            (NOT COALESCE(dns.dnssec_signed, 0))                                        AS no_dnssec,
            (CASE WHEN es.domain IS NOT NULL
                  THEN (COALESCE(es.dmarc_policy,'') = 'none' OR NOT COALESCE(es.dmarc_present, 0))
                  ELSE (dns.txt_dmarc IS NULL) END)                                     AS dmarc_weak,
            EXISTS(
                SELECT 1 FROM ports_info p
                WHERE p.domain = d.domain
                  AND p.port IN (3306,5432,6379,9200,27017,11211)
            )                                                                            AS exposed_db_port,
            EXISTS(
                SELECT 1 FROM ports_info p
                WHERE p.domain = d.domain
                  AND p.port IN (445,23,3389,5900)
            )                                                                            AS exposed_risky_port,
            EXISTS(
                SELECT 1 FROM ports_info p
                WHERE p.domain = d.domain AND p.port = 21
            )                                                                            AS exposed_ftp,
            EXISTS(
                SELECT 1 FROM ports_info p
                WHERE p.domain = d.domain AND p.port = 2375
            )                                                                            AS exposed_docker_api,
            EXISTS(SELECT 1 FROM cve_matches m WHERE m.domain = d.domain AND m.severity = 'CRITICAL') AS has_critical_cve,
            (COALESCE(es.spf_too_permissive, 0))                                        AS spf_permissive,
            (NOT COALESCE(es.dkim_found, 0))                                            AS no_dkim,
            EXISTS(
                SELECT 1 FROM smtp_tls_check st
                WHERE st.domain = d.domain
                  AND st.has_starttls = 0
                  AND st.error IS NULL
            )                                                                            AS smtp_no_starttls,
            EXISTS(
                SELECT 1 FROM smtp_tls_check st
                WHERE st.domain = d.domain
                  AND st.starttls_works = 0
                  AND st.has_starttls = 1
                  AND st.error IS NULL
            )                                                                            AS smtp_starttls_fails,
            d.sovereignty_score,
            CASE COALESCE(d.sovereignty_score, 0)
                WHEN 3 THEN -5
                WHEN 2 THEN -3
                WHEN 1 THEN -1
                ELSE 0
            END                                                                          AS sovereignty_penalty,
            MAX(0,
                100
                - CASE WHEN h.hsts IS NULL AND d.status_code = 200                        THEN 10 ELSE 0 END
                - CASE WHEN h.csp  IS NULL AND d.status_code = 200                        THEN 10 ELSE 0 END
                - CASE WHEN dns.caa IS NULL OR json_array_length(dns.caa) = 0             THEN  8 ELSE 0 END
                - CASE WHEN t.tls_version IN ('TLSv1.0','TLSv1.1') OR t.expired = 1      THEN 10 ELSE 0 END
                - CASE WHEN t.expired = 1                                                  THEN 20 ELSE 0 END
                - CASE WHEN t.days_remaining BETWEEN 0 AND 29                             THEN 15 ELSE 0 END
                - CASE WHEN NOT COALESCE(dns.dnssec_signed, 0)                            THEN  5 ELSE 0 END
                - CASE WHEN (CASE WHEN es.domain IS NOT NULL
                                  THEN (COALESCE(es.dmarc_policy,'') = 'none' OR NOT COALESCE(es.dmarc_present, 0))
                                  ELSE (dns.txt_dmarc IS NULL) END)                       THEN  7 ELSE 0 END
                - CASE WHEN EXISTS(
                      SELECT 1 FROM ports_info p
                      WHERE p.domain = d.domain
                        AND p.port IN (3306,5432,6379,9200,27017,11211)
                  )                                                                        THEN 10 ELSE 0 END
                - CASE WHEN EXISTS(
                      SELECT 1 FROM ports_info p
                      WHERE p.domain = d.domain
                        AND p.port IN (445,23,3389,5900)
                  )                                                                        THEN 10 ELSE 0 END
                - CASE WHEN EXISTS(
                      SELECT 1 FROM ports_info p
                      WHERE p.domain = d.domain AND p.port = 21
                  )                                                                        THEN 10 ELSE 0 END
                - CASE WHEN EXISTS(
                      SELECT 1 FROM ports_info p
                      WHERE p.domain = d.domain AND p.port = 2375
                  )                                                                        THEN 10 ELSE 0 END
                - CASE WHEN EXISTS(SELECT 1 FROM cve_matches m WHERE m.domain = d.domain AND m.severity = 'CRITICAL') THEN 15 ELSE 0 END
                - CASE WHEN COALESCE(es.spf_too_permissive, 0)                            THEN  7 ELSE 0 END
                - CASE WHEN NOT COALESCE(es.dkim_found, 0)                                THEN  5 ELSE 0 END
                - CASE WHEN EXISTS(
                      SELECT 1 FROM smtp_tls_check st
                      WHERE st.domain = d.domain
                        AND st.has_starttls = 0
                        AND st.error IS NULL
                  )                                                                        THEN 12 ELSE 0 END
                - CASE WHEN EXISTS(
                      SELECT 1 FROM smtp_tls_check st
                      WHERE st.domain = d.domain
                        AND st.starttls_works = 0
                        AND st.has_starttls = 1
                        AND st.error IS NULL
                  )                                                                        THEN  8 ELSE 0 END
                - CASE COALESCE(d.sovereignty_score, 0)
                      WHEN 3 THEN 5
                      WHEN 2 THEN 3
                      WHEN 1 THEN 1
                      ELSE 0
                  END
            )                                                                            AS score
        FROM domains d
        LEFT JOIN http_headers  h   ON h.domain   = d.domain
        LEFT JOIN dns_info      dns ON dns.domain  = d.domain
        LEFT JOIN tls_info      t   ON t.domain    = d.domain
        LEFT JOIN email_security es ON es.domain   = d.domain;
    ")?;

    conn.execute_batch("DROP VIEW IF EXISTS domain_percentile;")?;
    conn.execute_batch("
        CREATE VIEW domain_percentile AS
        SELECT
            rs.domain,
            rs.score,
            dc.sector,
            sb.median_value AS sector_median,
            PERCENT_RANK() OVER (PARTITION BY dc.sector ORDER BY rs.score) AS percentile_in_sector
        FROM risk_score rs
        JOIN domain_classification dc ON dc.domain = rs.domain
        JOIN sector_benchmarks sb ON sb.sector = dc.sector AND sb.metric = 'risk_score';
    ")?;

    conn.execute_batch("DROP VIEW IF EXISTS ns_concentration;")?;
    conn.execute_batch("
        CREATE VIEW ns_concentration AS
        SELECT
            operator                                                                       AS ns_operator,
            COUNT(DISTINCT domain)                                                         AS domain_count,
            ROUND(100.0 * COUNT(DISTINCT domain)
                / (SELECT COUNT(*) FROM domains WHERE status = 'ok'), 2)                  AS pct_of_ch
        FROM ns_staging
        GROUP BY operator
        ORDER BY domain_count DESC;
    ")?;

    // Must run after every view above is (re)defined: SQLite's ALTER TABLE DROP COLUMN
    // validates all dependent views before dropping a column, so it fails outright if any
    // view elsewhere in the schema has a stale/broken definition (e.g. one still being fixed
    // up by an earlier migration in this same function run).
    migrate_drop_whois(conn)?;
    Ok(())
}

pub(crate) fn migrate_domains_country_code(conn: &rusqlite::Connection) -> Result<()> {
    let has_col: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('domains') WHERE name = 'country_code'",
        [],
        |r| r.get(0),
    ).unwrap_or(false);
    if !has_col {
        conn.execute_batch("ALTER TABLE domains ADD COLUMN country_code TEXT;")?;
    }
    Ok(())
}

/// WHOIS lookups were removed (whois.nic.ch centralizes and rate-limit-blocks bulk
/// queries, so the data was never reliably populated) — drop the table and the
/// denormalized domains columns on any pre-existing database.
pub(crate) fn migrate_drop_whois(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch("DROP TABLE IF EXISTS whois_info;")?;
    let has_col: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('domains') WHERE name = 'whois_registrar'",
        [],
        |r| r.get(0),
    ).unwrap_or(false);
    if has_col {
        conn.execute_batch("ALTER TABLE domains DROP COLUMN whois_registrar;")?;
        conn.execute_batch("ALTER TABLE domains DROP COLUMN whois_created;")?;
    }
    Ok(())
}

pub(crate) fn migrate_ports_info(conn: &rusqlite::Connection) -> Result<()> {
    // Check if the old wide-boolean table still exists (presence of 'p80' column)
    let has_legacy: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('ports_info') WHERE name = 'p80'",
        [],
        |r| r.get(0),
    ).unwrap_or(false);

    if has_legacy {
        conn.execute_batch("ALTER TABLE ports_info RENAME TO ports_info_legacy;")?;
    }

    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS ports_info (
            domain     TEXT    NOT NULL,
            port       INTEGER NOT NULL,
            service    TEXT,
            open       INTEGER NOT NULL DEFAULT 0,
            banner     TEXT,
            ip         TEXT,
            scanned_at TEXT,
            PRIMARY KEY (domain, port)
        );
        CREATE INDEX IF NOT EXISTS idx_ports_info_port ON ports_info(port);
    ")?;

    if has_legacy {
        let pairs: &[(i32, &str, &str)] = &[
            (80,    "http",         "p80"),
            (443,   "https",        "p443"),
            (22,    "ssh",          "p22"),
            (21,    "ftp",          "p21"),
            (25,    "smtp",         "p25"),
            (587,   "submission",   "p587"),
            (3306,  "mysql",        "p3306"),
            (5432,  "postgresql",   "p5432"),
            (6379,  "redis",        "p6379"),
            (8080,  "http-alt",     "p8080"),
            (8443,  "https-alt",    "p8443"),
        ];
        let mut backfill = String::from("BEGIN;\n");
        for (port, service, col) in pairs {
            backfill.push_str(&format!(
                "INSERT INTO ports_info (domain, port, service, open, ip, scanned_at)
                 SELECT domain, {port}, '{service}', 1, ip, scanned_at
                 FROM ports_info_legacy WHERE {col} = 1
                 ON CONFLICT (domain, port) DO NOTHING;\n"
            ));
        }
        backfill.push_str("COMMIT;");
        conn.execute_batch(&backfill)?;
        conn.execute_batch("DROP TABLE IF EXISTS ports_info_legacy;")?;
    }
    Ok(())
}

pub(crate) fn migrate_ports_ip_from_domains(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch("
        UPDATE ports_info
        SET ip = (SELECT ip FROM domains WHERE domains.domain = ports_info.domain)
        WHERE (ports_info.ip IS NULL OR ports_info.ip = '127.0.0.1')
          AND EXISTS (
              SELECT 1 FROM domains
              WHERE domains.domain = ports_info.domain
                AND domains.ip IS NOT NULL
                AND domains.ip <> '127.0.0.1'
          );
    ")?;
    Ok(())
}

pub(crate) fn migrate_ports_open_only(conn: &rusqlite::Connection) -> Result<()> {
    // Idempotency check: already migrated if ports_scanned_at exists on domains
    let already_done: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('domains') WHERE name = 'ports_scanned_at'",
        [],
        |r| r.get(0),
    ).unwrap_or(false);
    if already_done {
        return Ok(());
    }

    // Add ports_scanned_at to domains; backfill from existing ports_info rows
    conn.execute_batch("
        ALTER TABLE domains ADD COLUMN ports_scanned_at TEXT;
        UPDATE domains
           SET ports_scanned_at = (SELECT MAX(scanned_at) FROM ports_info WHERE ports_info.domain = domains.domain)
         WHERE EXISTS (SELECT 1 FROM ports_info WHERE ports_info.domain = domains.domain);
    ")?;

    // Drop open column: recreate ports_info keeping only open rows
    let has_open: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('ports_info') WHERE name = 'open'",
        [],
        |r| r.get(0),
    ).unwrap_or(false);

    if has_open {
        conn.execute_batch("
            DELETE FROM ports_info WHERE open = 0;
            CREATE TABLE ports_info_new (
                domain     TEXT NOT NULL,
                port       INTEGER NOT NULL,
                service    TEXT,
                banner     TEXT,
                ip         TEXT,
                scanned_at TEXT,
                PRIMARY KEY (domain, port)
            );
            INSERT INTO ports_info_new SELECT domain, port, service, banner, ip, scanned_at FROM ports_info;
            DROP TABLE ports_info;
            ALTER TABLE ports_info_new RENAME TO ports_info;
        ")?;
    }

    Ok(())
}

pub(crate) fn ensure_smtp_tls_check_schema(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS smtp_tls_check (
            domain          TEXT    NOT NULL,
            port            INTEGER NOT NULL,
            smtp_banner     TEXT,
            ehlo_response   TEXT,
            has_starttls    INTEGER NOT NULL DEFAULT 0,
            starttls_works  INTEGER NOT NULL DEFAULT 0,
            tls_version     TEXT,
            cipher          TEXT,
            auth_mechanisms TEXT,
            allows_relay    INTEGER,
            error           TEXT,
            checked_at      TEXT,
            PRIMARY KEY (domain, port)
        );
    ",
    )?;
    migrate_smtp_tls_check(conn)?;
    Ok(())
}

fn migrate_cve_catalog_epss(conn: &rusqlite::Connection) -> Result<()> {
    let has_epss: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('cve_catalog') WHERE name = 'epss_score'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if !has_epss {
        conn.execute_batch(
            "ALTER TABLE cve_catalog ADD COLUMN epss_score REAL;
             ALTER TABLE cve_catalog ADD COLUMN epss_percentile REAL;",
        )?;
    }
    Ok(())
}

fn migrate_smtp_tls_check(conn: &rusqlite::Connection) -> Result<()> {
    let has_auth: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('smtp_tls_check')
             WHERE name = 'auth_mechanisms'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if !has_auth {
        conn.execute_batch(
            "ALTER TABLE smtp_tls_check ADD COLUMN auth_mechanisms TEXT;
             ALTER TABLE smtp_tls_check ADD COLUMN allows_relay INTEGER;",
        )?;
    }
    Ok(())
}

pub(crate) fn migrate_ports_targeted_at(conn: &rusqlite::Connection) -> Result<()> {
    let has_col: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('domains') WHERE name = 'ports_targeted_at'",
        [],
        |r| r.get(0),
    ).unwrap_or(false);
    if !has_col {
        conn.execute_batch("ALTER TABLE domains ADD COLUMN ports_targeted_at TEXT;")?;
    }
    Ok(())
}

/// tasks/done/task_27_snapshot_export_atomicity.md + task_28_snapshot_coverage_metrics.md:
/// track whether a snapshot run actually completed (rather than inferring it from row
/// presence), what failed if it didn't, per-table column lists (so a reader can detect
/// schema drift without opening every file — task 26), and per-module scan coverage so a
/// month with a cut-short scan doesn't read as a silent dip in a later trend.
pub(crate) fn migrate_snapshot_runs_status_coverage(conn: &rusqlite::Connection) -> Result<()> {
    let has_col: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('snapshot_runs') WHERE name = 'status'",
        [],
        |r| r.get(0),
    ).unwrap_or(false);
    if !has_col {
        conn.execute_batch(
            "
            ALTER TABLE snapshot_runs ADD COLUMN status TEXT;        -- 'running' | 'ok' | 'failed'
            ALTER TABLE snapshot_runs ADD COLUMN error TEXT;         -- error message when status='failed'
            ALTER TABLE snapshot_runs ADD COLUMN columns_json TEXT;  -- JSON object {table: [col, ...]}
            ALTER TABLE snapshot_runs ADD COLUMN coverage_json TEXT; -- JSON object {module: {...}} (task 28)
            ",
        )?;
    }
    Ok(())
}

pub(crate) fn ensure_domain_exists(db: &PathBuf, domain: &str) -> Result<String> {
    let domain = sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?;
    let conn = crate::shared::open_db(db).with_context(|| format!("open db {:?}", db))?;
    ensure_schema(&conn)?;
    conn.execute(
        "INSERT INTO domains (
            domain, status, final_url, status_code, title, body_hash, error_kind,
            elapsed_ms, ip, updated_at, server, powered_by
         ) VALUES (?1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
         ON CONFLICT(domain) DO NOTHING",
        rusqlite::params![domain.as_str()],
    )?;
    Ok(domain)
}

pub(crate) fn cmd_init(args: InitArgs) -> Result<()> {
    let conn =
        crate::shared::open_db(&args.db).with_context(|| format!("open db {:?}", args.db))?;

    ensure_schema(&conn)?;

    let existing: i64 = conn.query_row("SELECT COUNT(*) FROM domains", [], |r| r.get(0))?;
    if existing > 0 {
        eprintln!(
            "init: table already has {existing} rows — loading any new domains from {:?} \
             (existing rows are left untouched, INSERT OR IGNORE)",
            args.input
        );
    }

    let file =
        std::fs::File::open(&args.input).with_context(|| format!("open {:?}", args.input))?;
    let reader = std::io::BufReader::new(file);

    use std::io::BufRead;
    let mut seen: u64 = 0;
    let mut inserted: u64 = 0;
    let mut buf: Vec<String> = Vec::with_capacity(100_000);

    for line in reader.lines() {
        let line = line?;
        if let Some(domain) = sanitize_domain(&line) {
            buf.push(domain);
            if buf.len() >= 100_000 {
                inserted += flush_domain_init_batch(&conn, &buf)?;
                seen += buf.len() as u64;
                eprintln!("init: {seen} domains processed ({inserted} new)...");
                buf.clear();
            }
        }
    }
    if !buf.is_empty() {
        inserted += flush_domain_init_batch(&conn, &buf)?;
        seen += buf.len() as u64;
    }

    eprintln!("init: done - {inserted} new domain(s) inserted ({seen} processed).");
    Ok(())
}

/// Returns the number of rows actually inserted (0 for domains already present).
fn flush_domain_init_batch(conn: &rusqlite::Connection, domains: &[String]) -> Result<u64> {
    conn.execute_batch("BEGIN")?;
    let mut inserted = 0u64;
    {
        let mut stmt = conn.prepare("INSERT OR IGNORE INTO domains (domain) VALUES (?1)")?;
        for domain in domains {
            inserted += stmt.execute(rusqlite::params![domain.as_str()])? as u64;
        }
    }
    conn.execute_batch("COMMIT")?;
    Ok(inserted)
}
