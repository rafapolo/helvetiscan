//! Passive software fingerprinting: JavaScript libraries, web frameworks, and WordPress
//! plugins detected from a page's HTML and response headers. The parsers here are pure and
//! unit-tested; `cmd_detect` fetches each domain's homepage and stores what they find into
//! `software_detections`, which `cve.rs` then matches against the CVE catalog.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;

const HTTP_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_BODY: usize = 256 * 1024;

/// A single detection: (kind, name, version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Detection {
    pub kind: &'static str,
    pub name: String,
    pub version: Option<String>,
}

/// Find the first dotted-numeric version (at least `major.minor`) within `window` chars
/// after the first case-insensitive occurrence of `marker`.
fn version_near(haystack_lower: &str, original: &str, marker: &str, window: usize) -> Option<String> {
    let pos = haystack_lower.find(marker)?;
    let start = pos + marker.len();
    let end = (start + window).min(original.len());
    // Snap to char boundaries.
    let mut end = end;
    while end > start && !original.is_char_boundary(end) {
        end -= 1;
    }
    let slice = &original[start..end];
    crate::cve::extract_version_generic(slice)
}

/// Known JS libraries and the substrings that identify them in asset URLs.
const JS_LIBS: &[(&str, &str)] = &[
    ("jquery-ui", "jquery-ui"),
    ("jquery", "jquery"),
    ("bootstrap", "bootstrap"),
    ("angular", "angular"),
    ("react", "react"),
    ("vue", "vue"),
    ("lodash", "lodash"),
    ("underscore", "underscore"),
    ("moment", "moment"),
    ("d3", "d3"),
    ("backbone", "backbone"),
    ("handlebars", "handlebars"),
    ("ember", "ember"),
    ("swiper", "swiper"),
];

/// Detect JS libraries and versions referenced in a page's HTML.
pub(crate) fn detect_js_libraries(html: &str) -> Vec<Detection> {
    let lower = html.to_ascii_lowercase();
    let mut out: Vec<Detection> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for (needle, canonical) in JS_LIBS {
        if !lower.contains(needle) {
            continue;
        }
        // Skip a substring that is really part of a longer, already-handled lib name
        // (e.g. "jquery" inside "jquery-ui" is handled by the jquery-ui entry first).
        if *canonical == "jquery" && seen.contains("jquery-ui") && !mentions_bare(&lower, "jquery") {
            continue;
        }
        if !seen.insert(canonical) {
            continue;
        }
        // Look for a version right after the lib name in any of the common asset shapes:
        //   jquery-3.6.0.min.js   jquery.min.js?ver=3.6.0   /jquery/3.6.0/
        let version = version_near(&lower, html, &format!("{needle}-"), 12)
            .or_else(|| version_near(&lower, html, &format!("{needle}/"), 12))
            .or_else(|| version_near(&lower, html, &format!("{needle}@"), 12))
            .or_else(|| version_near(&lower, html, &format!("{needle}.min.js?ver="), 12))
            .or_else(|| version_near(&lower, html, &format!("{needle}?ver="), 12));
        out.push(Detection { kind: "js_lib", name: canonical.to_string(), version });
    }
    out
}

/// True if `needle` appears somewhere not immediately followed by `-ui` etc. Cheap guard so
/// a page that only loads jquery-ui does not also report bare jquery without evidence.
fn mentions_bare(lower: &str, needle: &str) -> bool {
    let mut idx = 0;
    while let Some(p) = lower[idx..].find(needle) {
        let at = idx + p;
        let after = &lower[at + needle.len()..];
        if !after.starts_with("-ui") {
            return true;
        }
        idx = at + needle.len();
    }
    false
}

/// Detect a web framework from response headers and Set-Cookie values. `headers_blob` and
/// `cookies` should be lowercased `name: value` / cookie strings.
pub(crate) fn detect_web_frameworks(headers_blob: &str, cookies: &str) -> Vec<Detection> {
    let h = headers_blob.to_ascii_lowercase();
    let c = cookies.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut add = |name: &str| out.push(Detection { kind: "framework", name: name.to_string(), version: None });

    if h.contains("x-powered-by: express") || h.contains("x-powered-by:express") {
        add("express");
    }
    if h.contains("x-aspnet-version") || h.contains("asp.net") {
        add("asp.net");
    }
    if h.contains("x-powered-by: next.js") || h.contains("x-nextjs") {
        add("next.js");
    }
    if c.contains("laravel_session") || c.contains("xsrf-token") {
        add("laravel");
    }
    if c.contains("csrftoken") || c.contains("django") {
        add("django");
    }
    if h.contains("x-runtime") || h.contains("phusion passenger") || c.contains("_session_id") {
        add("rails");
    }
    if h.contains("werkzeug") {
        add("flask");
    }
    if h.contains("struts") || h.contains("x-struts") || c.contains("struts") {
        add("apache-struts");
    }
    if h.contains("shiro") || c.contains("rememberme=deleteme") || c.contains("shiro") {
        add("apache-shiro");
    }
    if h.contains("log4j") || h.contains("log4shell") {
        add("apache-log4j");
    }
    out
}

/// Detect WordPress plugins (and versions where a `?ver=` query is present) from asset URLs
/// of the form `/wp-content/plugins/<slug>/...?ver=X.Y`.
pub(crate) fn detect_wp_plugins(html: &str) -> Vec<Detection> {
    let lower = html.to_ascii_lowercase();
    let marker = "/wp-content/plugins/";
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut idx = 0;
    while let Some(p) = lower[idx..].find(marker) {
        let at = idx + p + marker.len();
        idx = at;
        // Slug runs until the next '/'.
        let rest = &lower[at..];
        let slug_end = rest.find('/').unwrap_or(rest.len());
        let slug = &rest[..slug_end];
        if slug.is_empty() || !slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            continue;
        }
        if !seen.insert(slug.to_string()) {
            continue;
        }
        // Version: look for "ver=" within the same asset reference (until a quote/space).
        let asset_end = rest.find(['"', '\'', ' ', ')', '>']).unwrap_or(rest.len());
        let asset = &rest[..asset_end];
        let version = asset
            .find("ver=")
            .and_then(|vp| crate::cve::extract_version_generic(&asset[vp + 4..]));
        out.push(Detection { kind: "wp_plugin", name: slug.to_string(), version });
    }
    out
}

/// Run all fingerprint parsers over one response.
pub(crate) fn fingerprint_response(html: &str, headers_blob: &str, cookies: &str) -> Vec<Detection> {
    let mut out = detect_js_libraries(html);
    out.extend(detect_web_frameworks(headers_blob, cookies));
    out.extend(detect_wp_plugins(html));
    out
}

fn store_detections(conn: &rusqlite::Connection, domain: &str, dets: &[Detection]) -> Result<()> {
    let mut stmt = conn.prepare(
        "INSERT INTO software_detections (domain, kind, name, version, detected_at)
         VALUES (?1, ?2, ?3, ?4, datetime('now'))
         ON CONFLICT(domain, kind, name) DO UPDATE SET
            version = excluded.version, detected_at = excluded.detected_at",
    )?;
    for d in dets {
        stmt.execute(rusqlite::params![domain, d.kind, d.name, d.version])?;
    }
    Ok(())
}

async fn fetch_fingerprints(client: &reqwest::Client, domain: &str) -> Option<Vec<Detection>> {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{domain}/");
        let Ok(resp) = client.get(&url).send().await else { continue };
        let header = |name: &str| -> String {
            resp.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
        };
        let headers_blob = format!(
            "server: {}\nx-powered-by: {}\nx-aspnet-version: {}\nx-runtime: {}\nx-nextjs-cache: {}",
            header("server"), header("x-powered-by"), header("x-aspnet-version"),
            header("x-runtime"), header("x-nextjs-cache"),
        );
        let cookies = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join("; ");
        let body = resp.text().await.unwrap_or_default();
        let body = crate::cve_verify::truncate_on_char_boundary(&body, MAX_BODY);
        return Some(fingerprint_response(body, &headers_blob, &cookies));
    }
    None
}

pub(crate) async fn cmd_detect(db: PathBuf, concurrency: usize, limit: Option<usize>) -> Result<()> {
    let conn = crate::shared::open_db(&db).with_context(|| format!("open db {:?}", db))?;
    crate::schema::ensure_schema(&conn)?;

    // Only reachable web domains, and only those not already fingerprinted.
    let sql = "SELECT domain FROM domains
               WHERE status_code IS NOT NULL AND status_code < 500
                 AND domain NOT IN (SELECT DISTINCT domain FROM software_detections)
               ORDER BY domain";
    let mut domains: Vec<String> = {
        let mut stmt = conn.prepare(sql)?;
        let v: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(0))?.filter_map(|r| r.ok()).collect();
        v
    };
    if let Some(l) = limit {
        domains.truncate(l);
    }
    if domains.is_empty() {
        eprintln!("detect: no pending domains");
        return Ok(());
    }
    eprintln!("detect: fingerprinting {} domains", domains.len());

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(4))
            .user_agent("helvetiscan-detect/1.0")
            .build()
            .unwrap_or_default(),
    );
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, Vec<Detection>)>(1024);

    let conn2 = crate::shared::open_db(&db)?;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let writer = tokio::task::spawn_blocking(move || {
        while let Some((domain, dets)) = rx.blocking_recv() {
            if let Err(e) = store_detections(&conn2, &domain, &dets) {
                eprintln!("detect: store error for {domain}: {e}");
            }
        }
        let _ = done_tx.send(());
    });

    for domain in domains {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let tx = tx.clone();
        let client = client.clone();
        tokio::spawn(async move {
            if let Some(dets) = fetch_fingerprints(&client, &domain).await {
                let _ = tx.send((domain, dets)).await;
            }
            drop(permit);
        });
    }
    drop(tx);
    let _ = done_rx.await;
    let _ = writer.await;

    let n: i64 = conn.query_row("SELECT COUNT(*) FROM software_detections", [], |r| r.get(0))?;
    eprintln!("detect: done — {n} detections stored");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(dets: &[Detection]) -> Vec<(&str, Option<&str>)> {
        dets.iter().map(|d| (d.name.as_str(), d.version.as_deref())).collect()
    }

    #[test]
    fn js_detects_jquery_with_version() {
        let html = r#"<script src="/assets/jquery-3.6.0.min.js"></script>"#;
        let d = detect_js_libraries(html);
        assert!(names(&d).contains(&("jquery", Some("3.6.0"))));
    }

    #[test]
    fn js_detects_bootstrap_from_cdn_path() {
        let html = r#"<link href="https://cdn.example/bootstrap/4.5.2/css/bootstrap.min.css">"#;
        let d = detect_js_libraries(html);
        assert!(names(&d).iter().any(|(n, v)| *n == "bootstrap" && *v == Some("4.5.2")));
    }

    #[test]
    fn js_detects_query_param_version() {
        let html = r#"<script src="/js/lodash.min.js?ver=4.17.21"></script>"#;
        let d = detect_js_libraries(html);
        assert!(names(&d).contains(&("lodash", Some("4.17.21"))));
    }

    #[test]
    fn js_no_false_positive_on_plain_page() {
        let d = detect_js_libraries("<html><body>hello</body></html>");
        assert!(d.is_empty());
    }

    #[test]
    fn framework_express_from_header() {
        let d = detect_web_frameworks("x-powered-by: Express", "");
        assert!(names(&d).iter().any(|(n, _)| *n == "express"));
    }

    #[test]
    fn framework_laravel_from_cookie() {
        let d = detect_web_frameworks("server: nginx", "laravel_session=abc; path=/");
        assert!(names(&d).iter().any(|(n, _)| *n == "laravel"));
    }

    #[test]
    fn framework_django_from_cookie() {
        let d = detect_web_frameworks("server: gunicorn", "csrftoken=xyz");
        assert!(names(&d).iter().any(|(n, _)| *n == "django"));
    }

    #[test]
    fn framework_none_when_nothing_matches() {
        let d = detect_web_frameworks("server: nginx", "sessionish=1");
        assert!(d.is_empty());
    }

    #[test]
    fn wp_plugin_with_version() {
        let html = r#"<link href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.7.2">"#;
        let d = detect_wp_plugins(html);
        assert_eq!(names(&d), vec![("contact-form-7", Some("5.7.2"))]);
    }

    #[test]
    fn wp_plugin_without_version_dedup() {
        let html = r#"
            <script src="/wp-content/plugins/elementor/assets/js/frontend.js"></script>
            <link href="/wp-content/plugins/elementor/assets/css/frontend.css">
        "#;
        let d = detect_wp_plugins(html);
        assert_eq!(names(&d), vec![("elementor", None)]);
    }

    #[test]
    fn store_and_readback() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::schema::ensure_schema(&conn).unwrap();
        let dets = vec![
            Detection { kind: "js_lib", name: "jquery".into(), version: Some("1.12.4".into()) },
            Detection { kind: "wp_plugin", name: "woocommerce".into(), version: None },
        ];
        store_detections(&conn, "shop.ch", &dets).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM software_detections WHERE domain='shop.ch'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
    }
}
