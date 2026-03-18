use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::Value;

// ---- Structs ----

#[allow(dead_code)]
pub(crate) struct CveCatalogRow {
    pub cve_id: String,
    pub technology: String,
    pub affected_from: Option<String>,
    pub affected_to: Option<String>,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub in_kev: bool,
    pub summary: Option<String>,
    pub published_at: Option<String>,
}

#[allow(dead_code)]
pub(crate) struct CveMatchRow {
    pub domain: String,
    pub technology: String,
    pub version: Option<String>,
    pub cve_id: String,
    pub severity: Option<String>,
    pub cvss_score: Option<f64>,
    pub in_kev: Option<bool>,
    pub published_at: Option<String>,
}

// ---- Hardcoded seed CVEs (technology, cve_id, severity, cvss_score, affected_from, affected_to, summary) ----

const SEED_CVES: &[(&str, &str, &str, f64, &str, &str, &str)] = &[
    // WordPress
    ("wordpress", "CVE-2023-2745", "HIGH", 8.8, "6.0", "6.2.9", "WordPress core authenticated stored XSS via block editor"),
    ("wordpress", "CVE-2022-21661", "HIGH", 8.8, "5.6", "5.8.3", "WordPress SQL injection via WP_Query"),
    ("wordpress", "CVE-2021-44223", "CRITICAL", 9.8, "0", "5.8", "WordPress Gutenberg plugin arbitrary file upload"),
    ("wordpress", "CVE-2019-17671", "HIGH", 7.5, "0", "5.2.3", "WordPress unauthenticated view of private posts"),
    // Drupal
    ("drupal", "CVE-2018-7600", "CRITICAL", 9.8, "7.0", "8.5.1", "Drupalgeddon2 — remote code execution"),
    ("drupal", "CVE-2018-7602", "CRITICAL", 9.8, "7.0", "7.59", "Drupalgeddon2 SA-CORE-2018-004 follow-up"),
    ("drupal", "CVE-2019-6340", "CRITICAL", 9.8, "8.6", "8.6.9", "Drupal REST API remote code execution"),
    // Joomla
    ("joomla", "CVE-2023-23752", "MEDIUM", 5.3, "4.0.0", "4.2.7", "Joomla improper API access leading to info disclosure"),
    ("joomla", "CVE-2015-8562", "CRITICAL", 9.8, "1.5", "3.4.5", "Joomla PHP object injection via session data"),
    ("joomla", "CVE-2017-8917", "CRITICAL", 9.8, "3.7.0", "3.7.0", "Joomla SQL injection in com_fields"),
    // Apache
    ("apache", "CVE-2021-41773", "CRITICAL", 9.8, "2.4.49", "2.4.49", "Apache HTTP Server path traversal and RCE"),
    ("apache", "CVE-2021-42013", "CRITICAL", 9.8, "2.4.49", "2.4.50", "Apache HTTP Server path traversal follow-up"),
    ("apache", "CVE-2017-7679", "CRITICAL", 9.8, "2.2.0", "2.2.32", "Apache mod_mime buffer overread"),
    ("apache", "CVE-2022-31813", "HIGH", 7.5, "2.4.0", "2.4.53", "Apache HTTP Server request smuggling"),
    // nginx
    ("nginx", "CVE-2021-23017", "HIGH", 7.7, "0.6.18", "1.20.0", "nginx DNS resolver off-by-one heap write"),
    ("nginx", "CVE-2019-9511", "HIGH", 7.5, "1.0.7", "1.17.2", "nginx HTTP/2 DoS (Data Dribble attack)"),
    ("nginx", "CVE-2019-9513", "HIGH", 7.5, "1.0.7", "1.17.2", "nginx HTTP/2 DoS (Resource Loop attack)"),
    // PHP
    ("php", "CVE-2023-3824", "CRITICAL", 9.8, "8.0.0", "8.1.22", "PHP buffer overread in PHAR parsing"),
    ("php", "CVE-2022-31628", "HIGH", 7.8, "7.4.0", "8.1.11", "PHP phar wrapper stack buffer overflow"),
    ("php", "CVE-2021-21706", "MEDIUM", 4.3, "5.3.0", "7.4.25", "PHP ZipArchive::extractTo path traversal"),
    ("php", "CVE-2019-11043", "CRITICAL", 9.8, "7.1.0", "7.3.10", "PHP-FPM buffer underflow in env_path_info"),
    // TYPO3
    ("typo3", "CVE-2023-24814", "CRITICAL", 9.8, "9.0.0", "12.1.1", "TYPO3 SQL injection in page tree"),
    ("typo3", "CVE-2022-36020", "HIGH", 8.8, "9.0.0", "11.5.16", "TYPO3 improper access control in backend"),
    ("typo3", "CVE-2019-12747", "CRITICAL", 8.8, "8.0.0", "9.5.7", "TYPO3 Extbase deserialization attack"),
    // OpenSSL
    ("openssl", "CVE-2022-0778", "HIGH", 7.5, "1.0.2", "3.0.1", "OpenSSL BN_mod_sqrt infinite loop DoS"),
    ("openssl", "CVE-2022-3602", "HIGH", 7.5, "3.0.0", "3.0.6", "OpenSSL X.509 punycode buffer overflow"),
    ("openssl", "CVE-2014-0160", "HIGH", 7.5, "1.0.1", "1.0.1f", "Heartbleed — OpenSSL memory disclosure"),
    // Craft CMS
    ("craft cms", "CVE-2024-56145", "CRITICAL", 9.8, "3.0.0", "5.5.2", "Craft CMS code injection via template rendering"),
    ("craft cms", "CVE-2025-23209", "HIGH", 8.8, "4.0.0", "5.5.5", "Craft CMS code injection via improper input validation"),
    ("craft cms", "CVE-2025-35939", "HIGH", 8.0, "3.0.0", "5.6.2", "Craft CMS external control of assumed-immutable web parameter"),
    // LiteSpeed
    ("litespeed", "CVE-2022-0073", "HIGH", 8.8, "5.0", "6.0.12", "LiteSpeed Web Server privilege escalation via dashboard"),
    ("litespeed", "CVE-2022-0074", "HIGH", 8.8, "5.0", "6.0.12", "LiteSpeed Web Server RCE via log injection"),
    ("litespeed", "CVE-2020-36641", "CRITICAL", 9.8, "5.0", "5.4.12", "LiteSpeed Cache Plugin path traversal"),
    // Microsoft IIS
    ("microsoft-iis", "CVE-2017-7269", "CRITICAL", 9.8, "6.0", "6.0", "Microsoft IIS 6.0 WebDAV buffer overflow RCE"),
    ("microsoft-iis", "CVE-2015-1635", "CRITICAL", 9.8, "7.5", "8.5", "Microsoft IIS HTTP.sys remote code execution"),
    ("microsoft-iis", "CVE-2021-31166", "CRITICAL", 9.8, "10.0", "10.0", "Microsoft IIS HTTP Protocol Stack RCE"),
    // Tomcat
    ("tomcat", "CVE-2025-24813", "CRITICAL", 9.8, "9.0.0", "11.0.2", "Apache Tomcat path equivalence RCE"),
    ("tomcat", "CVE-2020-1938", "CRITICAL", 9.8, "7.0.0", "9.0.30", "Apache Tomcat AJP Ghostcat file read/inclusion"),
    ("tomcat", "CVE-2017-12617", "HIGH", 8.1, "7.0.0", "9.0.1", "Apache Tomcat JSP upload via HTTP PUT"),
    ("tomcat", "CVE-2016-8735", "CRITICAL", 9.8, "6.0.0", "9.0.0", "Apache Tomcat RCE via JMX listener"),
];

// ---- CISA KEV fetcher ----

pub(crate) async fn cmd_update_cves(db: PathBuf) -> Result<()> {
    let conn = crate::shared::open_db(&db)
        .with_context(|| format!("open db {:?}", db))?;

    crate::schema::ensure_schema(&conn)?;

    // Seed hardcoded entries first
    let seeded = seed_hardcoded_cves(&conn)?;
    eprintln!("cve: seeded {seeded} hardcoded CVE entries");

    // Fetch CISA KEV feed
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    eprintln!("cve: fetching {url}");

    let resp = client.get(url).send().await
        .context("fetching CISA KEV feed")?;

    let bytes = resp.bytes().await.context("reading CISA KEV response body")?;
    let json: Value = serde_json::from_slice(&bytes).context("parsing CISA KEV JSON")?;

    let vulnerabilities = json["vulnerabilities"]
        .as_array()
        .context("missing vulnerabilities array")?;

    let relevant_vendors = &["wordpress", "drupal", "joomla", "apache", "nginx", "openssl", "php", "typo3", "craft cms", "tomcat", "litespeed"];

    let mut inserted = 0usize;
    for entry in vulnerabilities {
        let vendor = entry["vendorProject"].as_str().unwrap_or("").to_ascii_lowercase();
        let product = entry["product"].as_str().unwrap_or("").to_ascii_lowercase();
        let combined = format!("{vendor} {product}");

        let matched_tech = relevant_vendors.iter().find(|&&v| combined.contains(v));
        let Some(&technology) = matched_tech else { continue };

        let cve_id = entry["cveID"].as_str().unwrap_or("").to_string();
        if cve_id.is_empty() { continue; }

        let summary: Option<String> = entry["shortDescription"].as_str().map(|s: &str| s.to_string());
        let published_at: Option<String> = entry["dateAdded"].as_str().map(|s: &str| s.to_string());

        conn.execute(
            "INSERT INTO cve_catalog (cve_id, technology, severity, in_kev, summary, published_at)
             VALUES (?1, ?2, 'CRITICAL', 1, ?3, ?4)
             ON CONFLICT(cve_id) DO UPDATE SET
                technology   = excluded.technology,
                severity     = excluded.severity,
                in_kev       = excluded.in_kev,
                summary      = excluded.summary,
                published_at = excluded.published_at",
            rusqlite::params![
                cve_id.as_str(),
                technology,
                summary.as_deref(),
                published_at.as_deref(),
            ],
        )?;
        inserted += 1;
    }

    eprintln!("cve: inserted/updated {inserted} KEV entries");

    let matched = run_cve_matching(&conn)?;
    eprintln!("cve: {matched} domain-CVE matches recorded");

    Ok(())
}

fn seed_hardcoded_cves(conn: &rusqlite::Connection) -> Result<usize> {
    let mut count = 0usize;
    for &(technology, cve_id, severity, cvss_score, affected_from, affected_to, summary) in SEED_CVES {
        conn.execute(
            "INSERT INTO cve_catalog (cve_id, technology, affected_from, affected_to, severity, cvss_score, in_kev, summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
             ON CONFLICT(cve_id) DO UPDATE SET
                technology    = excluded.technology,
                affected_from = excluded.affected_from,
                affected_to   = excluded.affected_to,
                severity      = excluded.severity,
                cvss_score    = excluded.cvss_score,
                summary       = excluded.summary",
            rusqlite::params![
                cve_id,
                technology,
                affected_from,
                affected_to,
                severity,
                cvss_score,
                summary,
            ],
        )?;
        count += 1;
    }
    Ok(count)
}

pub(crate) fn run_cve_matching(conn: &rusqlite::Connection) -> Result<usize> {
    conn.execute_batch(
        "INSERT INTO cve_matches (domain, technology, version, cve_id, severity, cvss_score, in_kev, published_at)
         SELECT d.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM domains d
         JOIN cve_catalog c ON lower(coalesce(d.cms, '')) = c.technology
                            OR lower(coalesce(d.server, '')) LIKE '%' || c.technology || '%'
                            OR lower(coalesce(d.powered_by, '')) LIKE '%' || c.technology || '%'
         WHERE d.cms IS NOT NULL OR d.server IS NOT NULL OR d.powered_by IS NOT NULL
         ON CONFLICT (domain, cve_id) DO UPDATE SET matched_at = datetime('now')",
    )?;

    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM cve_matches",
        [],
        |r| r.get(0),
    )?;

    Ok(count as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_memory_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::schema::ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn seed_inserts_all_hardcoded_cves() {
        let conn = in_memory_db();
        let count = seed_hardcoded_cves(&conn).unwrap();
        assert_eq!(count, SEED_CVES.len());

        let in_db: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve_catalog", [], |r| r.get(0))
            .unwrap();
        assert_eq!(in_db as usize, SEED_CVES.len());
    }

    #[test]
    fn seed_is_idempotent() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        seed_hardcoded_cves(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve_catalog", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count as usize, SEED_CVES.len());
    }

    #[test]
    fn run_cve_matching_matches_wordpress_domain() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();

        conn.execute_batch(
            "INSERT INTO domains (domain, status, cms) VALUES ('wp-site.ch', 'ok', 'WordPress')",
        )
        .unwrap();

        let matched = run_cve_matching(&conn).unwrap();
        assert!(matched > 0, "expected at least one WordPress CVE match");

        let domain_match: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cve_matches WHERE domain='wp-site.ch'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(domain_match > 0);
    }

    #[test]
    fn run_cve_matching_no_match_for_unknown_cms() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();

        conn.execute_batch(
            "INSERT INTO domains (domain, status, cms) VALUES ('unknown.ch', 'ok', 'SomeCMS')",
        )
        .unwrap();

        let matched = run_cve_matching(&conn).unwrap();
        assert_eq!(matched, 0);
    }

    #[test]
    fn all_seed_cves_have_valid_cve_ids() {
        for &(_, cve_id, _, _, _, _, _) in SEED_CVES {
            assert!(
                cve_id.starts_with("CVE-"),
                "expected CVE ID format for: {cve_id}"
            );
        }
    }

    #[test]
    fn all_seed_cves_have_known_severity() {
        let valid = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
        for &(_, _, severity, _, _, _, _) in SEED_CVES {
            assert!(
                valid.contains(&severity),
                "unexpected severity '{severity}'"
            );
        }
    }
}
