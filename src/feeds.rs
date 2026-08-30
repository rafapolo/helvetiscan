//! Additional CVE data sources beyond CISA KEV and the built-in seed list: NVD (CPE
//! version ranges), OSV.dev (open-source package advisories), and the GitHub Advisory
//! Database (GHSA). Each feed has a pure `parse_*` function (unit-tested against sample
//! payloads) and a thin async fetcher. Fetchers degrade gracefully: a network failure or a
//! missing GitHub token logs a warning and is skipped rather than aborting `update-cves`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

/// A catalog entry produced by an external feed.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FeedCve {
    pub cve_id: String,
    pub technology: String,
    pub affected_from: Option<String>,
    pub affected_to: Option<String>,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub summary: Option<String>,
}

fn severity_from_score(score: f64) -> &'static str {
    match score {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        _ => "LOW",
    }
}

fn normalize_severity(word: &str) -> &'static str {
    match word.to_ascii_lowercase().as_str() {
        "critical" => "CRITICAL",
        "high" => "HIGH",
        "moderate" | "medium" => "MEDIUM",
        _ => "LOW",
    }
}

// ---- NVD API 2.0 ----

/// Parse an NVD `/cves/2.0` response, keeping only CVEs whose CPE `criteria` mention
/// `cpe_product`, tagged with `technology`. Version bounds come from the CPE match ranges.
pub(crate) fn parse_nvd_response(json: &Value, technology: &str, cpe_product: &str) -> Vec<FeedCve> {
    let mut out = Vec::new();
    let Some(vulns) = json["vulnerabilities"].as_array() else {
        return out;
    };
    for v in vulns {
        let cve = &v["cve"];
        let Some(cve_id) = cve["id"].as_str() else { continue };

        let summary = cve["descriptions"]
            .as_array()
            .and_then(|ds| ds.iter().find(|d| d["lang"] == "en"))
            .and_then(|d| d["value"].as_str())
            .map(|s| s.to_string());

        let (cvss_score, severity) = nvd_metric(cve);

        // Find the first CPE range that names the product.
        let mut range = None;
        if let Some(configs) = cve["configurations"].as_array() {
            'outer: for cfg in configs {
                for node in cfg["nodes"].as_array().into_iter().flatten() {
                    for m in node["cpeMatch"].as_array().into_iter().flatten() {
                        let criteria = m["criteria"].as_str().unwrap_or("");
                        if !criteria.contains(cpe_product) {
                            continue;
                        }
                        let from = m["versionStartIncluding"].as_str()
                            .or_else(|| m["versionStartExcluding"].as_str())
                            .map(|s| s.to_string());
                        let to = m["versionEndIncluding"].as_str()
                            .or_else(|| m["versionEndExcluding"].as_str())
                            .map(|s| s.to_string());
                        range = Some((from, to));
                        break 'outer;
                    }
                }
            }
        }
        let (affected_from, affected_to) = range.unwrap_or((None, None));

        out.push(FeedCve {
            cve_id: cve_id.to_string(),
            technology: technology.to_string(),
            affected_from,
            affected_to,
            severity: severity.to_string(),
            cvss_score,
            summary,
        });
    }
    out
}

fn nvd_metric(cve: &Value) -> (Option<f64>, String) {
    let metrics = &cve["metrics"];
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(arr) = metrics[key].as_array() {
            if let Some(first) = arr.first() {
                let data = &first["cvssData"];
                if let Some(score) = data["baseScore"].as_f64() {
                    let sev = data["baseSeverity"].as_str()
                        .map(normalize_severity)
                        .unwrap_or_else(|| severity_from_score(score));
                    return (Some(score), sev.to_string());
                }
            }
        }
    }
    (None, "HIGH".to_string())
}

// ---- OSV.dev ----

/// Parse an OSV `/v1/query` response for a package, tagged with `technology`. Prefers the
/// CVE alias as the id; falls back to the OSV/GHSA id.
pub(crate) fn parse_osv_response(json: &Value, technology: &str) -> Vec<FeedCve> {
    let mut out = Vec::new();
    let Some(vulns) = json["vulns"].as_array() else {
        return out;
    };
    for vuln in vulns {
        let aliases: Vec<&str> = vuln["aliases"].as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let cve_id = aliases.iter().find(|a| a.starts_with("CVE-"))
            .copied()
            .or_else(|| vuln["id"].as_str())
            .unwrap_or("");
        if cve_id.is_empty() {
            continue;
        }

        let summary = vuln["summary"].as_str().or_else(|| vuln["details"].as_str()).map(|s| s.to_string());

        // Version range from the first SEMVER/ECOSYSTEM range.
        let (mut from, mut to) = (None, None);
        if let Some(affected) = vuln["affected"].as_array() {
            'outer: for aff in affected {
                for r in aff["ranges"].as_array().into_iter().flatten() {
                    for ev in r["events"].as_array().into_iter().flatten() {
                        if let Some(i) = ev["introduced"].as_str() {
                            from = Some(i.to_string());
                        }
                        if let Some(f) = ev["fixed"].as_str() {
                            to = Some(f.to_string());
                        }
                    }
                    if from.is_some() || to.is_some() {
                        break 'outer;
                    }
                }
            }
        }

        let cvss_score = osv_cvss(vuln);
        let severity = cvss_score.map(severity_from_score).unwrap_or("HIGH");

        out.push(FeedCve {
            cve_id: cve_id.to_string(),
            technology: technology.to_string(),
            affected_from: from,
            affected_to: to,
            severity: severity.to_string(),
            cvss_score,
            summary,
        });
    }
    out
}

fn osv_cvss(vuln: &Value) -> Option<f64> {
    // OSV encodes severity as a CVSS vector string; a numeric score is not guaranteed.
    vuln["database_specific"]["cvss"]["score"].as_f64()
}

// ---- GitHub Advisory Database ----

/// Parse a semver constraint like ">= 1.0.0, < 4.17.12" into (from, to). The upper bound is
/// taken from a `<`/`<=` clause; the lower from `>=`/`>`.
pub(crate) fn parse_semver_range(range: &str) -> (Option<String>, Option<String>) {
    let (mut from, mut to) = (None, None);
    for clause in range.split(',') {
        let clause = clause.trim();
        if let Some(v) = clause.strip_prefix("<=").or_else(|| clause.strip_prefix('<')) {
            to = Some(v.trim().to_string());
        } else if let Some(v) = clause.strip_prefix(">=").or_else(|| clause.strip_prefix('>')) {
            from = Some(v.trim().to_string());
        } else if let Some(v) = clause.strip_prefix('=') {
            let v = v.trim().to_string();
            from = Some(v.clone());
            to = Some(v);
        }
    }
    (from, to)
}

/// Parse the GitHub REST `/advisories` array response, tagged with `technology`.
pub(crate) fn parse_ghsa_response(json: &Value, technology: &str) -> Vec<FeedCve> {
    let mut out = Vec::new();
    let Some(advisories) = json.as_array() else {
        return out;
    };
    for adv in advisories {
        let cve_id = adv["cve_id"].as_str().filter(|s| s.starts_with("CVE-"))
            .or_else(|| adv["ghsa_id"].as_str())
            .unwrap_or("");
        if cve_id.is_empty() {
            continue;
        }
        let summary = adv["summary"].as_str().map(|s| s.to_string());
        let severity = adv["severity"].as_str().map(normalize_severity).unwrap_or("HIGH");
        let cvss_score = adv["cvss"]["score"].as_f64();

        let (mut from, mut to) = (None, None);
        if let Some(first) = adv["vulnerabilities"].as_array().and_then(|v| v.first()) {
            if let Some(r) = first["vulnerable_version_range"].as_str() {
                let (f, t) = parse_semver_range(r);
                from = f;
                to = t;
            }
            // A first_patched_version is the fixed version (exclusive upper bound).
            if to.is_none() {
                to = first["first_patched_version"]["identifier"].as_str().map(|s| s.to_string());
            }
        }

        out.push(FeedCve {
            cve_id: cve_id.to_string(),
            technology: technology.to_string(),
            affected_from: from,
            affected_to: to,
            severity: severity.to_string(),
            cvss_score,
            summary,
        });
    }
    out
}

// ---- Upsert ----

/// Insert or update feed-sourced CVEs. Existing `in_kev` flags and non-null cvss/summary are
/// preserved on conflict so a feed never downgrades KEV metadata.
pub(crate) fn upsert_feed_cves(conn: &rusqlite::Connection, entries: &[FeedCve]) -> Result<usize> {
    let mut n = 0usize;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO cve_catalog
                (cve_id, technology, affected_from, affected_to, severity, cvss_score, in_kev, summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
             ON CONFLICT(cve_id) DO UPDATE SET
                technology    = excluded.technology,
                affected_from = COALESCE(excluded.affected_from, cve_catalog.affected_from),
                affected_to   = COALESCE(excluded.affected_to, cve_catalog.affected_to),
                severity      = excluded.severity,
                cvss_score    = COALESCE(excluded.cvss_score, cve_catalog.cvss_score),
                summary       = COALESCE(excluded.summary, cve_catalog.summary)",
        )?;
        for e in entries {
            if !e.cve_id.starts_with("CVE-") {
                continue; // catalog is keyed on CVE ids; skip bare GHSA/OSV ids
            }
            n += stmt.execute(rusqlite::params![
                e.cve_id, e.technology, e.affected_from, e.affected_to, e.severity, e.cvss_score, e.summary,
            ])?;
        }
    }
    tx.commit()?;
    Ok(n)
}

// ---- Fetchers ----

/// (technology tag, NVD keyword, CPE product token).
const NVD_TARGETS: &[(&str, &str, &str)] = &[
    ("apache", "apache http server", "http_server"),
    ("nginx", "nginx", "nginx"),
    ("php", "php", "php"),
    ("openssh", "openssh", "openssh"),
    ("tomcat", "apache tomcat", "tomcat"),
];

/// (technology tag, OSV ecosystem, package name).
const OSV_TARGETS: &[(&str, &str, &str)] = &[
    ("jquery", "npm", "jquery"),
    ("bootstrap", "npm", "bootstrap"),
    ("lodash", "npm", "lodash"),
    ("angular", "npm", "angular"),
    ("moment", "npm", "moment"),
    ("laravel", "Packagist", "laravel/framework"),
];

/// (technology tag, GHSA ecosystem, package name).
const GHSA_TARGETS: &[(&str, &str, &str)] = &[
    ("jquery", "npm", "jquery"),
    ("lodash", "npm", "lodash"),
    ("laravel", "composer", "laravel/framework"),
];

pub(crate) async fn cmd_fetch_feeds(db: PathBuf, nvd: bool, osv: bool, ghsa: bool) -> Result<()> {
    let conn = crate::shared::open_db(&db).with_context(|| format!("open db {:?}", db))?;
    crate::schema::ensure_schema(&conn)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("helvetiscan-feeds/1.0")
        .build()
        .context("building feeds HTTP client")?;

    let mut total = 0usize;
    if nvd {
        total += fetch_nvd(&conn, &client).await.unwrap_or_else(|e| { eprintln!("feeds: NVD failed: {e:#}"); 0 });
    }
    if osv {
        total += fetch_osv(&conn, &client).await.unwrap_or_else(|e| { eprintln!("feeds: OSV failed: {e:#}"); 0 });
    }
    if ghsa {
        total += fetch_ghsa(&conn, &client).await.unwrap_or_else(|e| { eprintln!("feeds: GHSA failed: {e:#}"); 0 });
    }
    eprintln!("feeds: upserted {total} CVE catalog entries; re-matching");
    crate::cve::run_cve_matching(&conn)?;
    Ok(())
}

async fn fetch_nvd(conn: &rusqlite::Connection, client: &reqwest::Client) -> Result<usize> {
    let mut n = 0usize;
    for (tech, keyword, product) in NVD_TARGETS {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=200",
            urlencode(keyword)
        );
        eprintln!("feeds: NVD {keyword}");
        match client.get(&url).send().await.and_then(|r| r.error_for_status()) {
            Ok(resp) => {
                let bytes = resp.bytes().await.context("read NVD body")?;
                let json: Value = serde_json::from_slice(&bytes).context("parse NVD json")?;
                let entries = parse_nvd_response(&json, tech, product);
                n += upsert_feed_cves(conn, &entries)?;
            }
            Err(e) => eprintln!("feeds: NVD {keyword} request failed: {e}"),
        }
        // NVD asks unauthenticated clients to stay under ~5 requests / 30s.
        tokio::time::sleep(Duration::from_secs(6)).await;
    }
    Ok(n)
}

async fn fetch_osv(conn: &rusqlite::Connection, client: &reqwest::Client) -> Result<usize> {
    let mut n = 0usize;
    for (tech, ecosystem, package) in OSV_TARGETS {
        let body = serde_json::json!({ "package": { "ecosystem": ecosystem, "name": package } });
        let body_str = serde_json::to_string(&body).unwrap_or_default();
        eprintln!("feeds: OSV {ecosystem}/{package}");
        let req = client.post("https://api.osv.dev/v1/query")
            .header("content-type", "application/json")
            .body(body_str);
        match req.send().await.and_then(|r| r.error_for_status()) {
            Ok(resp) => {
                let bytes = resp.bytes().await.context("read OSV body")?;
                let json: Value = serde_json::from_slice(&bytes).context("parse OSV json")?;
                let entries = parse_osv_response(&json, tech);
                n += upsert_feed_cves(conn, &entries)?;
            }
            Err(e) => eprintln!("feeds: OSV {package} request failed: {e}"),
        }
    }
    Ok(n)
}

async fn fetch_ghsa(conn: &rusqlite::Connection, client: &reqwest::Client) -> Result<usize> {
    let Ok(token) = std::env::var("GITHUB_TOKEN") else {
        eprintln!("feeds: GHSA skipped (set GITHUB_TOKEN to enable)");
        return Ok(0);
    };
    let mut n = 0usize;
    for (tech, ecosystem, package) in GHSA_TARGETS {
        let url = format!(
            "https://api.github.com/advisories?ecosystem={ecosystem}&affects={}&per_page=100",
            urlencode(package)
        );
        eprintln!("feeds: GHSA {ecosystem}/{package}");
        let req = client.get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        match req.send().await.and_then(|r| r.error_for_status()) {
            Ok(resp) => {
                let bytes = resp.bytes().await.context("read GHSA body")?;
                let json: Value = serde_json::from_slice(&bytes).context("parse GHSA json")?;
                let entries = parse_ghsa_response(&json, tech);
                n += upsert_feed_cves(conn, &entries)?;
            }
            Err(e) => eprintln!("feeds: GHSA {package} request failed: {e}"),
        }
    }
    Ok(n)
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ' ' => "%20".to_string(),
            '/' => "%2F".to_string(),
            c if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') => c.to_string(),
            c => format!("%{:02X}", c as u32),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::schema::ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn nvd_parses_cpe_range_and_metric() {
        let json: Value = serde_json::from_str(r#"{
          "vulnerabilities": [{
            "cve": {
              "id": "CVE-2021-41773",
              "descriptions": [{"lang":"en","value":"Path traversal in Apache HTTP Server 2.4.49"}],
              "metrics": {"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
              "configurations": [{"nodes":[{"cpeMatch":[
                {"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*","versionStartIncluding":"2.4.49","versionEndIncluding":"2.4.49"}
              ]}]}]
            }
          }]
        }"#).unwrap();
        let out = parse_nvd_response(&json, "apache", "http_server");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cve_id, "CVE-2021-41773");
        assert_eq!(out[0].affected_from.as_deref(), Some("2.4.49"));
        assert_eq!(out[0].affected_to.as_deref(), Some("2.4.49"));
        assert_eq!(out[0].severity, "CRITICAL");
        assert_eq!(out[0].cvss_score, Some(9.8));
    }

    #[test]
    fn nvd_skips_unrelated_product() {
        let json: Value = serde_json::from_str(r#"{
          "vulnerabilities": [{"cve":{"id":"CVE-2020-0001","descriptions":[],"metrics":{},
            "configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:other:thing:1.0"}]}]}]}}]
        }"#).unwrap();
        let out = parse_nvd_response(&json, "apache", "http_server");
        assert_eq!(out.len(), 1);
        // Product not matched → no range attached.
        assert_eq!(out[0].affected_from, None);
        assert_eq!(out[0].affected_to, None);
    }

    #[test]
    fn osv_prefers_cve_alias_and_reads_fixed() {
        let json: Value = serde_json::from_str(r#"{
          "vulns": [{
            "id":"GHSA-jf85-cpcp-j695",
            "aliases":["CVE-2019-10744"],
            "summary":"Prototype pollution in lodash",
            "affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.12"}]}]}]
          }]
        }"#).unwrap();
        let out = parse_osv_response(&json, "lodash");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cve_id, "CVE-2019-10744");
        assert_eq!(out[0].affected_from.as_deref(), Some("0"));
        assert_eq!(out[0].affected_to.as_deref(), Some("4.17.12"));
    }

    #[test]
    fn semver_range_parsing() {
        assert_eq!(parse_semver_range(">= 1.0.0, < 4.17.12"), (Some("1.0.0".into()), Some("4.17.12".into())));
        assert_eq!(parse_semver_range("<= 2.3.4"), (None, Some("2.3.4".into())));
        assert_eq!(parse_semver_range("= 1.2.3"), (Some("1.2.3".into()), Some("1.2.3".into())));
    }

    #[test]
    fn ghsa_parses_cve_and_range() {
        let json: Value = serde_json::from_str(r#"[
          {
            "ghsa_id":"GHSA-x5rq-j2xg-h7qm",
            "cve_id":"CVE-2019-10744",
            "summary":"Prototype pollution in lodash",
            "severity":"critical",
            "cvss":{"score":9.1},
            "vulnerabilities":[{"vulnerable_version_range":"< 4.17.12","first_patched_version":{"identifier":"4.17.12"}}]
          }
        ]"#).unwrap();
        let out = parse_ghsa_response(&json, "lodash");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cve_id, "CVE-2019-10744");
        assert_eq!(out[0].severity, "CRITICAL");
        assert_eq!(out[0].affected_to.as_deref(), Some("4.17.12"));
        assert_eq!(out[0].cvss_score, Some(9.1));
    }

    #[test]
    fn upsert_inserts_and_preserves_kev() {
        let conn = db();
        // Pre-existing KEV entry.
        conn.execute(
            "INSERT INTO cve_catalog (cve_id, technology, severity, in_kev) VALUES ('CVE-2021-41773','apache','CRITICAL',1)",
            [],
        ).unwrap();
        let entries = vec![
            FeedCve { cve_id:"CVE-2021-41773".into(), technology:"apache".into(),
                affected_from:Some("2.4.49".into()), affected_to:Some("2.4.49".into()),
                severity:"CRITICAL".into(), cvss_score:Some(9.8), summary:Some("path traversal".into()) },
            FeedCve { cve_id:"GHSA-only-id".into(), technology:"x".into(), affected_from:None, affected_to:None,
                severity:"HIGH".into(), cvss_score:None, summary:None }, // skipped (not a CVE id)
        ];
        let n = upsert_feed_cves(&conn, &entries).unwrap();
        assert_eq!(n, 1);
        let (in_kev, from): (i64, String) = conn
            .query_row("SELECT in_kev, affected_from FROM cve_catalog WHERE cve_id='CVE-2021-41773'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(in_kev, 1, "feed upsert must not clear the KEV flag");
        assert_eq!(from, "2.4.49");
    }
}
