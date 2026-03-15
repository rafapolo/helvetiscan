use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use crate::shared::sanitize_domain;
use crate::InitArgs;

pub(crate) fn ensure_schema(conn: &duckdb::Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS domains (
            domain      VARCHAR PRIMARY KEY,
            status      VARCHAR,
            final_url   VARCHAR,
            status_code INTEGER,
            title       VARCHAR,
            body_hash   VARCHAR,
            error_kind  VARCHAR,
            elapsed_ms  BIGINT,
            ip          VARCHAR,
            updated_at  TIMESTAMP
        );
        ALTER TABLE domains ADD COLUMN IF NOT EXISTS status           VARCHAR;
        ALTER TABLE domains ADD COLUMN IF NOT EXISTS server           VARCHAR;
        ALTER TABLE domains ADD COLUMN IF NOT EXISTS powered_by       VARCHAR;
        ALTER TABLE domains ADD COLUMN IF NOT EXISTS whois_registrar  VARCHAR;
        ALTER TABLE domains ADD COLUMN IF NOT EXISTS whois_created    DATE;
        ALTER TABLE domains ADD COLUMN IF NOT EXISTS redirect_chain   VARCHAR[];
        ALTER TABLE domains ADD COLUMN IF NOT EXISTS cms              VARCHAR;

        CREATE TABLE IF NOT EXISTS dns_info (
            domain      VARCHAR PRIMARY KEY,
            status      VARCHAR,
            error_kind  VARCHAR,
            ns          VARCHAR[],
            mx          VARCHAR[],
            cname       VARCHAR,
            a           VARCHAR[],
            aaaa        VARCHAR[],
            txt_spf     VARCHAR,
            txt_dmarc   VARCHAR,
            ttl         INTEGER,
            ptr         VARCHAR,
            dnssec      BOOLEAN,
            resolved_at TIMESTAMP
        );

        ALTER TABLE dns_info ADD COLUMN IF NOT EXISTS dnssec_signed BOOLEAN;
        ALTER TABLE dns_info ADD COLUMN IF NOT EXISTS dnssec_valid  BOOLEAN;
        ALTER TABLE dns_info ADD COLUMN IF NOT EXISTS caa           VARCHAR[];
        ALTER TABLE dns_info ADD COLUMN IF NOT EXISTS wildcard      BOOLEAN;
        ALTER TABLE dns_info ADD COLUMN IF NOT EXISTS txt_all       VARCHAR[];

        CREATE TABLE IF NOT EXISTS tls_info (
            domain         VARCHAR PRIMARY KEY,
            status         VARCHAR,
            error_kind     VARCHAR,
            cert_issuer    VARCHAR,
            cert_subject   VARCHAR,
            valid_from     DATE,
            valid_to       DATE,
            days_remaining INTEGER,
            expired        BOOLEAN,
            self_signed    BOOLEAN,
            tls_version    VARCHAR,
            cipher         VARCHAR,
            scanned_at     TIMESTAMP
        );

        ALTER TABLE tls_info ADD COLUMN IF NOT EXISTS san                  VARCHAR[];
        ALTER TABLE tls_info ADD COLUMN IF NOT EXISTS key_algorithm        VARCHAR;
        ALTER TABLE tls_info ADD COLUMN IF NOT EXISTS key_size             INTEGER;
        ALTER TABLE tls_info ADD COLUMN IF NOT EXISTS signature_algorithm  VARCHAR;
        ALTER TABLE tls_info ADD COLUMN IF NOT EXISTS cert_fingerprint     VARCHAR;
        ALTER TABLE tls_info ADD COLUMN IF NOT EXISTS ct_logged            BOOLEAN;
        ALTER TABLE tls_info ADD COLUMN IF NOT EXISTS ocsp_must_staple     BOOLEAN;

        CREATE TABLE IF NOT EXISTS subdomains (
            domain        VARCHAR,
            subdomain     VARCHAR,
            source        VARCHAR,
            discovered_at TIMESTAMP,
            PRIMARY KEY (domain, subdomain)
        );

        CREATE TABLE IF NOT EXISTS whois_info (
            domain           VARCHAR PRIMARY KEY,
            registrar        VARCHAR,
            whois_created    DATE,
            expires_at       DATE,
            status           VARCHAR,
            dnssec_delegated BOOLEAN,
            queried_at       TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS http_headers (
            domain                 VARCHAR PRIMARY KEY,
            hsts                   VARCHAR,
            csp                    VARCHAR,
            x_frame_options        VARCHAR,
            x_content_type_options VARCHAR,
            cors_origin            VARCHAR,
            referrer_policy        VARCHAR,
            permissions_policy     VARCHAR,
            scanned_at             TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS cve_catalog (
            cve_id        VARCHAR PRIMARY KEY,
            technology    VARCHAR NOT NULL,
            affected_from VARCHAR,
            affected_to   VARCHAR,
            severity      VARCHAR,
            cvss_score    DOUBLE,
            in_kev        BOOLEAN DEFAULT FALSE,
            summary       VARCHAR,
            published_at  DATE
        );

        CREATE TABLE IF NOT EXISTS cve_matches (
            domain        VARCHAR NOT NULL,
            technology    VARCHAR NOT NULL,
            version       VARCHAR,
            cve_id        VARCHAR NOT NULL,
            severity      VARCHAR,
            cvss_score    DOUBLE,
            in_kev        BOOLEAN,
            published_at  DATE,
            matched_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (domain, cve_id)
        );

        CREATE TABLE IF NOT EXISTS email_security (
            domain                 VARCHAR PRIMARY KEY,
            spf_present            BOOLEAN,
            spf_policy             VARCHAR,
            spf_too_permissive     BOOLEAN,
            spf_dns_lookups        INTEGER,
            spf_over_limit         BOOLEAN,
            dmarc_present          BOOLEAN,
            dmarc_policy           VARCHAR,
            dmarc_subdomain_policy VARCHAR,
            dmarc_has_reporting    BOOLEAN,
            dmarc_pct              INTEGER,
            dkim_default           BOOLEAN,
            dkim_google            BOOLEAN,
            dkim_found             BOOLEAN,
            scanned_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS domain_classification (
            domain        VARCHAR PRIMARY KEY,
            sector        VARCHAR,
            subsector     VARCHAR,
            source        VARCHAR,
            confidence    DOUBLE,
            classified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sector_benchmarks (
            sector        VARCHAR NOT NULL,
            metric        VARCHAR NOT NULL,
            domain_count  INTEGER,
            mean_value    DOUBLE,
            median_value  DOUBLE,
            p25_value     DOUBLE,
            p75_value     DOUBLE,
            min_value     DOUBLE,
            max_value     DOUBLE,
            computed_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (sector, metric)
        );
    ",
    )?;
    migrate_ports_info(conn)?;
    conn.execute_batch("
        CREATE OR REPLACE VIEW risk_score AS
        SELECT
            d.domain,
            (h.hsts IS NULL AND d.status_code = 200)                                    AS missing_hsts,
            (h.csp  IS NULL AND d.status_code = 200)                                    AS missing_csp,
            (dns.caa IS NULL OR len(dns.caa) = 0)                                       AS missing_caa,
            (t.tls_version IN ('TLSv1.0','TLSv1.1') OR t.expired = true)               AS weak_tls,
            (t.expired = true)                                                           AS cert_expired,
            (t.days_remaining BETWEEN 0 AND 29)                                         AS cert_expiring,
            (NOT coalesce(dns.dnssec_signed, false))                                    AS no_dnssec,
            (CASE WHEN es.domain IS NOT NULL
                  THEN (coalesce(es.dmarc_policy,'') = 'none' OR NOT coalesce(es.dmarc_present, false))
                  ELSE (dns.txt_dmarc IS NULL) END)                                     AS dmarc_weak,
            (w.expires_at::TIMESTAMP < (current_timestamp::TIMESTAMP + INTERVAL '30 days'))                           AS domain_expiring,
            EXISTS(
                SELECT 1 FROM ports_info p
                WHERE p.domain = d.domain AND p.open = true
                  AND p.port IN (3306,5432,6379,9200,27017,11211,2375)
            )                                                                            AS exposed_db_port,
            EXISTS(
                SELECT 1 FROM ports_info p
                WHERE p.domain = d.domain AND p.open = true
                  AND p.port IN (445,23,3389,5900)
            )                                                                            AS exposed_risky_port,
            EXISTS(SELECT 1 FROM cve_matches m WHERE m.domain = d.domain AND m.severity = 'CRITICAL') AS has_critical_cve,
            (coalesce(es.spf_too_permissive, false))                                    AS spf_permissive,
            (NOT coalesce(es.dkim_found, false))                                        AS no_dkim,
            GREATEST(0,
                100
                - CASE WHEN h.hsts IS NULL AND d.status_code = 200                        THEN 10 ELSE 0 END
                - CASE WHEN h.csp  IS NULL AND d.status_code = 200                        THEN 10 ELSE 0 END
                - CASE WHEN dns.caa IS NULL OR len(dns.caa) = 0                           THEN  8 ELSE 0 END
                - CASE WHEN t.tls_version IN ('TLSv1.0','TLSv1.1') OR t.expired = true   THEN 10 ELSE 0 END
                - CASE WHEN t.expired = true                                               THEN 20 ELSE 0 END
                - CASE WHEN t.days_remaining BETWEEN 0 AND 29                             THEN 15 ELSE 0 END
                - CASE WHEN NOT coalesce(dns.dnssec_signed, false)                        THEN  5 ELSE 0 END
                - CASE WHEN (CASE WHEN es.domain IS NOT NULL
                                  THEN (coalesce(es.dmarc_policy,'') = 'none' OR NOT coalesce(es.dmarc_present, false))
                                  ELSE (dns.txt_dmarc IS NULL) END)                       THEN  7 ELSE 0 END
                - CASE WHEN w.expires_at::TIMESTAMP < (current_timestamp::TIMESTAMP + INTERVAL '30 days')               THEN  5 ELSE 0 END
                - CASE WHEN EXISTS(
                      SELECT 1 FROM ports_info p
                      WHERE p.domain = d.domain AND p.open = true
                        AND p.port IN (3306,5432,6379,9200,27017,11211,2375)
                  )                                                                        THEN 10 ELSE 0 END
                - CASE WHEN EXISTS(
                      SELECT 1 FROM ports_info p
                      WHERE p.domain = d.domain AND p.open = true
                        AND p.port IN (445,23,3389,5900)
                  )                                                                        THEN 10 ELSE 0 END
                - CASE WHEN EXISTS(SELECT 1 FROM cve_matches m WHERE m.domain = d.domain AND m.severity = 'CRITICAL') THEN 15 ELSE 0 END
                - CASE WHEN coalesce(es.spf_too_permissive, false)                        THEN  7 ELSE 0 END
                - CASE WHEN NOT coalesce(es.dkim_found, false)                            THEN  5 ELSE 0 END
            )                                                                            AS score
        FROM domains d
        LEFT JOIN http_headers  h   ON h.domain   = d.domain
        LEFT JOIN dns_info      dns ON dns.domain  = d.domain
        LEFT JOIN tls_info      t   ON t.domain    = d.domain
        LEFT JOIN whois_info    w   ON w.domain    = d.domain
        LEFT JOIN email_security es ON es.domain   = d.domain;
    ")?;
    conn.execute_batch("
        CREATE OR REPLACE VIEW domain_percentile AS
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
    Ok(())
}

pub(crate) fn migrate_ports_info(conn: &duckdb::Connection) -> Result<()> {
    // Check if the old wide-boolean table still exists (presence of 'p80' column)
    let has_legacy: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM information_schema.columns
         WHERE table_name = 'ports_info' AND column_name = 'p80'",
        [],
        |r| r.get(0),
    ).unwrap_or(false);

    if has_legacy {
        conn.execute_batch("ALTER TABLE ports_info RENAME TO ports_info_legacy;")?;
    }

    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS ports_info (
            domain     VARCHAR   NOT NULL,
            port       INTEGER   NOT NULL,
            service    VARCHAR,
            open       BOOLEAN   NOT NULL DEFAULT false,
            banner     VARCHAR,
            ip         VARCHAR,
            scanned_at TIMESTAMP,
            PRIMARY KEY (domain, port)
        );
    ")?;

    if has_legacy {
        // Backfill one row per true boolean per domain
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
                 SELECT domain, {port}, '{service}', true, ip, scanned_at
                 FROM ports_info_legacy WHERE {col} = true
                 ON CONFLICT (domain, port) DO NOTHING;\n"
            ));
        }
        backfill.push_str("COMMIT;");
        conn.execute_batch(&backfill)?;
        conn.execute_batch("DROP TABLE IF EXISTS ports_info_legacy;")?;
    }
    Ok(())
}

pub(crate) fn append_empty_domain_row(appender: &mut duckdb::Appender<'_>, domain: &str) -> Result<()> {
    appender.append_row(duckdb::params![
        domain,
        Option::<&str>::None,  // status
        Option::<&str>::None,  // final_url
        Option::<i32>::None,   // status_code
        Option::<&str>::None,  // title
        Option::<&str>::None,  // body_hash
        Option::<&str>::None,  // error_kind
        Option::<i64>::None,   // elapsed_ms
        Option::<&str>::None,  // ip
        Option::<&str>::None,  // updated_at
        Option::<&str>::None,  // server
        Option::<&str>::None,  // powered_by
        Option::<&str>::None,  // whois_registrar
        Option::<&str>::None,  // whois_created
    ])?;
    Ok(())
}

pub(crate) fn ensure_domain_exists(db: &PathBuf, domain: &str) -> Result<String> {
    let domain = sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?;
    let conn = duckdb::Connection::open(db).with_context(|| format!("open duckdb {:?}", db))?;
    ensure_schema(&conn)?;
    conn.execute(
        "INSERT INTO domains (
            domain, status, final_url, status_code, title, body_hash, error_kind,
            elapsed_ms, ip, updated_at, server, powered_by
         ) VALUES (?1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
         ON CONFLICT(domain) DO NOTHING",
        duckdb::params![domain.as_str()],
    )?;
    Ok(domain)
}

pub(crate) fn cmd_init(args: InitArgs) -> Result<()> {
    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;

    ensure_schema(&conn)?;

    let existing: i64 = conn.query_row("SELECT COUNT(*) FROM domains", [], |r| r.get(0))?;
    if existing > 0 {
        eprintln!("init: table already has {existing} rows, skipping load.");
        return Ok(());
    }

    let file =
        std::fs::File::open(&args.input).with_context(|| format!("open {:?}", args.input))?;
    let reader = std::io::BufReader::new(file);

    let mut appender = conn.appender("domains")?;
    let mut count: u64 = 0;

    use std::io::BufRead;
    for line in reader.lines() {
        let line = line?;
        if let Some(domain) = sanitize_domain(&line) {
            append_empty_domain_row(&mut appender, &domain)?;
            count += 1;
            if count % 100_000 == 0 {
                eprintln!("init: {count} domains loaded...");
            }
        }
    }

    appender.flush()?;
    eprintln!("init: done - {count} domains inserted.");
    Ok(())
}
