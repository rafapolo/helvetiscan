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
            whois_registrar  TEXT,
            whois_created    TEXT,
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

        CREATE TABLE IF NOT EXISTS whois_info (
            domain           TEXT PRIMARY KEY,
            registrar        TEXT,
            whois_created    TEXT,
            expires_at       TEXT,
            status           TEXT,
            dnssec_delegated INTEGER,
            queried_at       TEXT
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
            published_at  TEXT
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
    ",
    )?;
    migrate_ports_info(conn)?;
    migrate_ports_open_only(conn)?;
    migrate_domains_country_code(conn)?;
    migrate_ports_ip_from_domains(conn)?;
    migrate_ports_targeted_at(conn)?;

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
            (w.expires_at < date('now', '+30 days'))                                    AS domain_expiring,
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
                - CASE WHEN w.expires_at < date('now', '+30 days')                        THEN  5 ELSE 0 END
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
        LEFT JOIN whois_info    w   ON w.domain    = d.domain
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
            ns_operator,
            COUNT(DISTINCT domain)                                                         AS domain_count,
            ROUND(100.0 * COUNT(DISTINCT domain)
                / (SELECT COUNT(*) FROM domains WHERE status = 'ok'), 2)                  AS pct_of_ch
        FROM ns_operators
        GROUP BY ns_operator
        ORDER BY domain_count DESC;
    ")?;
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
        eprintln!("init: table already has {existing} rows, skipping load.");
        return Ok(());
    }

    let file =
        std::fs::File::open(&args.input).with_context(|| format!("open {:?}", args.input))?;
    let reader = std::io::BufReader::new(file);

    use std::io::BufRead;
    let mut count: u64 = 0;
    let mut buf: Vec<String> = Vec::with_capacity(100_000);

    for line in reader.lines() {
        let line = line?;
        if let Some(domain) = sanitize_domain(&line) {
            buf.push(domain);
            if buf.len() >= 100_000 {
                flush_domain_init_batch(&conn, &buf)?;
                count += buf.len() as u64;
                eprintln!("init: {count} domains loaded...");
                buf.clear();
            }
        }
    }
    if !buf.is_empty() {
        flush_domain_init_batch(&conn, &buf)?;
        count += buf.len() as u64;
    }

    eprintln!("init: done - {count} domains inserted.");
    Ok(())
}

fn flush_domain_init_batch(conn: &rusqlite::Connection, domains: &[String]) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare("INSERT OR IGNORE INTO domains (domain) VALUES (?1)")?;
        for domain in domains {
            stmt.execute(rusqlite::params![domain.as_str()])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    Ok(())
}
