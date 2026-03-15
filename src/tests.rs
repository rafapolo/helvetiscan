use std::fs;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;

use crate::schema::{ensure_schema, cmd_init};
use crate::shared::{
    dedupe_sorted, sanitize_domain, Row, HttpHeadersRow, WhoisRow, ScanStatus,
};
use crate::http_scan::{
    flush_batch, flush_http_headers_batch, detect_cms, pending_domains_sql,
    load_pending_domains, candidate_urls, should_try_www, cmd_scan,
};
use crate::dns_scan::{load_scan_targets, cmd_dns};
use crate::email_security::{parse_spf, parse_dmarc};
use crate::classify::classify_by_keywords;
use crate::tls_scan::cmd_tls;
use crate::ports_scan::{grab_banner, cmd_ports};
use crate::whois::parse_whois_response;
use crate::{BackfillMode, InitArgs, ScanArgs, DnsArgs, TlsArgs, PortsArgs};

#[test]
fn sanitize_domain_basic() {
    assert_eq!(sanitize_domain("example.com"), Some("example.com".to_string()));
    assert_eq!(
        sanitize_domain(" https://example.com/path "),
        Some("example.com".to_string())
    );
    assert_eq!(sanitize_domain("http://example.com/"), Some("example.com".to_string()));
}

#[test]
fn should_try_www_rules() {
    assert!(should_try_www("example.com"));
    assert!(!should_try_www("www.example.com"));
    assert!(!should_try_www("127.0.0.1"));
}

#[test]
fn candidate_urls_include_www() {
    let urls = candidate_urls("example.com");
    assert_eq!(urls[0], "https://example.com/");
    assert_eq!(urls[1], "https://www.example.com/");
    assert_eq!(urls[2], "http://example.com/");
    assert_eq!(urls[3], "http://www.example.com/");
}

#[test]
fn dedupe_sorted_strips_empty_and_trailing_dot() {
    assert_eq!(
        dedupe_sorted(vec![
            "ns2.example.com.".into(),
            "ns1.example.com".into(),
            "".into(),
            "ns1.example.com".into()
        ]),
        vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()]
    );
}

#[test]
fn pending_domains_sql_matches_backfill_modes() {
    assert!(pending_domains_sql(None).contains("updated_at IS NULL"));
    assert!(pending_domains_sql(Some(BackfillMode::Ip)).contains("ip IS NULL"));
    assert!(pending_domains_sql(Some(BackfillMode::Server)).contains("server IS NULL"));
    assert_eq!(
        pending_domains_sql(Some(BackfillMode::Full)),
        "SELECT domain FROM domains ORDER BY domain"
    );
}

#[test]
fn single_domain_bypasses_batch_queries() {
    let conn = duckdb::Connection::open_in_memory().unwrap();
    assert_eq!(
        load_pending_domains(&conn, Some("example.ch"), None, None).unwrap(),
        vec!["example.ch".to_string()]
    );
    assert_eq!(
        load_scan_targets(&conn, Some("example.ch"), "dns_info", "resolved_at", false, None).unwrap(),
        vec!["example.ch".to_string()]
    );
}

#[test]
fn flush_batch_roundtrip() {
    let conn = duckdb::Connection::open_in_memory().unwrap();
    conn.execute_batch("
        CREATE TABLE domains (
            domain VARCHAR PRIMARY KEY,
            status VARCHAR,
            final_url VARCHAR, status_code INTEGER,
            title VARCHAR, body_hash VARCHAR, error_kind VARCHAR,
            elapsed_ms BIGINT, ip VARCHAR, updated_at TIMESTAMP,
            server VARCHAR, powered_by VARCHAR,
            redirect_chain VARCHAR[], cms VARCHAR, tech_version VARCHAR
        );
        INSERT INTO domains VALUES ('test.ch', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    ").unwrap();

    let mut batch = vec![Row {
        domain: "test.ch".into(),
        status: ScanStatus::Ok,
        ip: Some("1.2.3.4".into()),
        final_url: Some("https://test.ch/".into()),
        status_code: Some(200),
        title: None,
        body_hash: Some("d41d8cd98f00b204e9800998ecf8427e".into()),
        server: Some("nginx".into()),
        powered_by: None,
        error_kind: None,
        elapsed_ms: 123,
        redirect_chain: vec![],
        cms: None,
        tech_version: None,
    }];

    flush_batch(&conn, &mut batch).unwrap();
    assert!(batch.is_empty());

    let url: String = conn
        .query_row("SELECT final_url FROM domains WHERE domain='test.ch'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(url, "https://test.ch/");

    let updated_at_is_set: bool = conn
        .query_row(
            "SELECT updated_at IS NOT NULL FROM domains WHERE domain='test.ch'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(updated_at_is_set);
}

#[tokio::test]
#[ignore = "network-dependent end-to-end scan over sample_domains.txt"]
async fn sample_domains_e2e_scan() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sample_input = manifest_dir.join("data/sample_domains.txt");
    let db_path = std::env::temp_dir().join(format!(
        "helvetiscan-sample-{}-{}.duckdb",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));

    cmd_init(InitArgs {
        input: sample_input,
        db: db_path.clone(),
    })
    .unwrap();

    cmd_scan(ScanArgs {
        db: db_path.clone(),
        domain: None,
        write_batch_size: 25,
        concurrency: 10,
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        max_kbytes: 64,
        max_redirects: 5,
        user_agent: "helvetiscan/test".into(),
        progress_interval: Duration::from_secs(5),
        no_progress: true,
        limit_success: None,
        backfill: None,
        retry_errors: None,
    })
    .await
    .unwrap();

    cmd_dns(DnsArgs {
        db: db_path.clone(),
        domain: None,
        write_batch_size: 25,
        concurrency: 10,
        progress_interval: Duration::from_secs(5),
        no_progress: true,
        rescan: false,
        retry_errors: None,
    })
    .await
    .unwrap();

    cmd_tls(TlsArgs {
        db: db_path.clone(),
        domain: None,
        write_batch_size: 25,
        concurrency: 10,
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(8),
        progress_interval: Duration::from_secs(5),
        no_progress: true,
        rescan: false,
        retry_errors: None,
    })
    .await
    .unwrap();

    cmd_ports(PortsArgs {
        db: db_path.clone(),
        domain: None,
        write_batch_size: 25,
        concurrency: 10,
        connect_timeout: Duration::from_millis(800),
        progress_interval: Duration::from_secs(5),
        no_progress: true,
        rescan: false,
        retry_errors: None,
    })
    .await
    .unwrap();

    let conn = duckdb::Connection::open(&db_path).unwrap();
    let domains_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM domains", [], |r| r.get(0))
        .unwrap();
    let http_scanned_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM domains WHERE updated_at IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let dns_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM dns_info", [], |r| r.get(0))
        .unwrap();
    let tls_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM tls_info", [], |r| r.get(0))
        .unwrap();
    let ports_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ports_info", [], |r| r.get(0))
        .unwrap();

    assert_eq!(domains_count, 25);
    assert_eq!(http_scanned_count, 25);
    assert_eq!(dns_count, 25);
    assert_eq!(tls_count, 25);
    assert_eq!(ports_count, 25);

    drop(conn);
    let _ = fs::remove_file(&db_path);
}

// ---- detect_cms ----

fn cms_name(result: Option<(String, Option<String>)>) -> Option<String> {
    result.map(|(name, _)| name)
}

#[test]
fn wp_content_in_body() {
    assert_eq!(cms_name(detect_cms(None, b"<link rel='stylesheet' href='/wp-content/themes/x/style.css'>", None, None)), Some("WordPress".into()));
}

#[test]
fn wp_includes_in_body() {
    assert_eq!(cms_name(detect_cms(None, b"<script src='/wp-includes/js/jquery.js'></script>", None, None)), Some("WordPress".into()));
}

#[test]
fn powered_by_wordpress() {
    assert_eq!(cms_name(detect_cms(Some("WordPress 6.4"), b"", None, None)), Some("WordPress".into()));
}

#[test]
fn drupal_settings_in_body() {
    assert_eq!(cms_name(detect_cms(None, b"jQuery.extend(Drupal.settings, {});", None, None)), Some("Drupal".into()));
}

#[test]
fn joomla_com_in_body() {
    assert_eq!(cms_name(detect_cms(None, b"<a href='/components/com_content/'>read more</a>", None, None)), Some("Joomla".into()));
}

#[test]
fn typo3conf_in_body() {
    assert_eq!(cms_name(detect_cms(None, b"<link href='/typo3conf/ext/theme/Resources/Public/main.css'>", None, None)), Some("TYPO3".into()));
}

#[test]
fn blank_html_returns_none() {
    assert_eq!(detect_cms(None, b"<!DOCTYPE html><html><head></head><body></body></html>", None, None), None);
}

#[test]
fn empty_body_returns_none() {
    assert_eq!(detect_cms(None, b"", None, None), None);
}

#[test]
fn server_header_apache_version() {
    let result = detect_cms(None, b"", Some("Apache/2.4.57"), None);
    assert_eq!(cms_name(result.clone()), Some("apache".into()));
    assert_eq!(result.and_then(|(_, v)| v), Some("2.4.57".into()));
}

#[test]
fn server_header_nginx_version() {
    let result = detect_cms(None, b"", Some("nginx/1.24.0"), None);
    assert_eq!(cms_name(result.clone()), Some("nginx".into()));
    assert_eq!(result.and_then(|(_, v)| v), Some("1.24.0".into()));
}

#[test]
fn powered_by_php_version() {
    let result = detect_cms(Some("PHP/8.2.1"), b"", None, None);
    assert_eq!(cms_name(result.clone()), Some("php".into()));
    assert_eq!(result.and_then(|(_, v)| v), Some("8.2.1".into()));
}

// ---- flush_http_headers_batch ----

#[test]
fn flush_http_headers_roundtrip() {
    let conn = duckdb::Connection::open_in_memory().unwrap();
    conn.execute_batch("
        CREATE TABLE http_headers (
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
    ").unwrap();

    // Insert row with all headers populated
    let mut batch = vec![HttpHeadersRow {
        domain: "test.ch".into(),
        hsts: Some("max-age=31536000; includeSubDomains".into()),
        csp: Some("default-src 'self'".into()),
        x_frame_options: Some("DENY".into()),
        x_content_type_options: Some("nosniff".into()),
        cors_origin: Some("https://example.ch".into()),
        referrer_policy: Some("no-referrer".into()),
        permissions_policy: Some("geolocation=()".into()),
    }];
    flush_http_headers_batch(&conn, &mut batch).unwrap();
    assert!(batch.is_empty());

    let hsts: Option<String> = conn
        .query_row("SELECT hsts FROM http_headers WHERE domain='test.ch'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(hsts.as_deref(), Some("max-age=31536000; includeSubDomains"));

    // Insert row with all headers NULL — verify ON CONFLICT UPDATE overwrites
    let mut batch2 = vec![HttpHeadersRow {
        domain: "test.ch".into(),
        hsts: None,
        csp: None,
        x_frame_options: None,
        x_content_type_options: None,
        cors_origin: None,
        referrer_policy: None,
        permissions_policy: None,
    }];
    flush_http_headers_batch(&conn, &mut batch2).unwrap();

    let hsts_after: Option<String> = conn
        .query_row("SELECT hsts FROM http_headers WHERE domain='test.ch'", [], |r| r.get(0))
        .unwrap();
    assert!(hsts_after.is_none(), "ON CONFLICT UPDATE should have overwritten hsts with NULL");
}

// ---- parse_whois_response ----

fn make_whois_lines(text: &str) -> Vec<String> {
    text.lines().map(|l| l.to_string()).collect()
}

#[test]
fn parses_registrar() {
    let lines = make_whois_lines("Registrar: Switch\nFirst Registration Date: 2001-01-01\n");
    let mut row = WhoisRow { domain: "x.ch".into(), registrar: None, whois_created: None, expires_at: None, status: None, dnssec_delegated: None };
    parse_whois_response(&mut row, &lines);
    assert_eq!(row.registrar, Some("Switch".into()));
}

#[test]
fn parses_registered_date() {
    let lines = make_whois_lines("First Registration Date: 2001-01-01\n");
    let mut row = WhoisRow { domain: "x.ch".into(), registrar: None, whois_created: None, expires_at: None, status: None, dnssec_delegated: None };
    parse_whois_response(&mut row, &lines);
    assert_eq!(row.whois_created, Some(chrono::NaiveDate::from_ymd_opt(2001, 1, 1).unwrap()));
}

#[test]
fn parses_expiration_date() {
    let lines = make_whois_lines("Expiration Date: 2030-06-15\n");
    let mut row = WhoisRow { domain: "x.ch".into(), registrar: None, whois_created: None, expires_at: None, status: None, dnssec_delegated: None };
    parse_whois_response(&mut row, &lines);
    assert_eq!(row.expires_at, Some(chrono::NaiveDate::from_ymd_opt(2030, 6, 15).unwrap()));
}

#[test]
fn parses_state() {
    let lines = make_whois_lines("State: active\n");
    let mut row = WhoisRow { domain: "x.ch".into(), registrar: None, whois_created: None, expires_at: None, status: None, dnssec_delegated: None };
    parse_whois_response(&mut row, &lines);
    assert_eq!(row.status, Some("active".into()));
}

#[test]
fn dnssec_signed_delegation() {
    let lines = make_whois_lines("DNSSEC: Signed Delegation\n");
    let mut row = WhoisRow { domain: "x.ch".into(), registrar: None, whois_created: None, expires_at: None, status: None, dnssec_delegated: None };
    parse_whois_response(&mut row, &lines);
    assert_eq!(row.dnssec_delegated, Some(true));
}

#[test]
fn dnssec_unsigned() {
    let lines = make_whois_lines("DNSSEC: unsigned delegation\n");
    let mut row = WhoisRow { domain: "x.ch".into(), registrar: None, whois_created: None, expires_at: None, status: None, dnssec_delegated: None };
    parse_whois_response(&mut row, &lines);
    assert_eq!(row.dnssec_delegated, Some(false));
}

// ---- grab_banner ----

#[tokio::test]
async fn grab_banner_returns_line() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use std::net::{IpAddr, Ipv4Addr};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_8.9\r\n").await;
        }
    });

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let banner = grab_banner(ip, port).await;
    assert_eq!(banner, Some("SSH-2.0-OpenSSH_8.9".into()));
}

#[tokio::test]
async fn grab_banner_no_listener_returns_none() {
    use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener};

    // Bind and immediately drop to get a free port
    let l = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(grab_banner(ip, port).await.is_none());
}

// ---- risk_score VIEW ----

#[test]
fn risk_score_view_flags_and_score() {
    let conn = duckdb::Connection::open_in_memory().unwrap();
    ensure_schema(&conn).unwrap();

    // Insert a domain with status_code=200 — no http_headers row → missing_hsts should be true
    conn.execute_batch("
        INSERT INTO domains (domain, status, status_code)
        VALUES ('probe.ch', 'ok', 200);
    ").unwrap();

    let missing_hsts: bool = conn
        .query_row("SELECT missing_hsts FROM risk_score WHERE domain='probe.ch'", [], |r| r.get(0))
        .unwrap();
    assert!(missing_hsts, "missing_hsts should be true when no http_headers row");

    // Open port 3306 → exposed_db_port should be true
    conn.execute_batch("
        INSERT INTO ports_info (domain, port, service, open)
        VALUES ('probe.ch', 3306, 'mysql', true);
    ").unwrap();

    let exposed_db_port: bool = conn
        .query_row("SELECT exposed_db_port FROM risk_score WHERE domain='probe.ch'", [], |r| r.get(0))
        .unwrap();
    assert!(exposed_db_port, "exposed_db_port should be true when port 3306 is open");

    // Score must be in [0, 100]
    let score: i64 = conn
        .query_row("SELECT score FROM risk_score WHERE domain='probe.ch'", [], |r| r.get(0))
        .unwrap();
    assert!((0..=100).contains(&score), "score {} should be in [0, 100]", score);
}

// ---- parse_spf ----

#[test]
fn spf_plus_all_is_too_permissive() {
    let r = parse_spf("v=spf1 +all");
    assert!(r.present);
    assert!(r.too_permissive);
}

#[test]
fn spf_minus_all_is_not_permissive() {
    let r = parse_spf("v=spf1 -all");
    assert!(r.present);
    assert!(!r.too_permissive);
    assert_eq!(r.policy.as_deref(), Some("-all"));
}

#[test]
fn spf_tilde_all_is_not_permissive() {
    let r = parse_spf("v=spf1 ~all");
    assert!(!r.too_permissive);
}

#[test]
fn spf_question_all_is_permissive() {
    let r = parse_spf("v=spf1 ?all");
    assert!(r.too_permissive);
}

#[test]
fn spf_counts_include_mechanisms() {
    let r = parse_spf("v=spf1 include:spf.example.com include:spf2.example.com mx -all");
    assert_eq!(r.dns_lookups, 3); // 2 includes + 1 mx
    assert!(!r.over_limit);
}

#[test]
fn spf_over_limit() {
    let r = parse_spf("v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com -all");
    assert!(r.over_limit);
}

#[test]
fn spf_empty_not_present() {
    let r = parse_spf("");
    assert!(!r.present);
}

// ---- parse_dmarc ----

#[test]
fn dmarc_reject_with_reporting() {
    let r = parse_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com");
    assert!(r.present);
    assert_eq!(r.policy.as_deref(), Some("reject"));
    assert!(r.has_reporting);
}

#[test]
fn dmarc_none_policy() {
    let r = parse_dmarc("v=DMARC1; p=none");
    assert!(r.present);
    assert_eq!(r.policy.as_deref(), Some("none"));
    assert!(!r.has_reporting);
}

#[test]
fn dmarc_subdomain_policy_and_pct() {
    let r = parse_dmarc("v=DMARC1; p=quarantine; sp=reject; pct=50");
    assert!(r.present);
    assert_eq!(r.policy.as_deref(), Some("quarantine"));
    assert_eq!(r.subdomain_policy.as_deref(), Some("reject"));
    assert_eq!(r.pct, Some(50));
}

#[test]
fn dmarc_empty_not_present() {
    let r = parse_dmarc("");
    assert!(!r.present);
}

// ---- classify_by_keywords ----

#[test]
fn classify_bank_domain() {
    let result = classify_by_keywords("kantonalbank.ch", None);
    assert!(result.is_some());
    let (sector, subsector, confidence) = result.unwrap();
    assert_eq!(sector, "finance");
    assert_eq!(subsector, "banking");
    assert!(confidence >= 0.9);
}

#[test]
fn classify_hospital_in_title() {
    let result = classify_by_keywords("gesundheit.ch", Some("Spital Bern - Willkommen"));
    assert!(result.is_some());
    let (sector, _, _) = result.unwrap();
    assert_eq!(sector, "healthcare");
}

#[test]
fn classify_cantonal_domain_is_government() {
    let result = classify_by_keywords("zh.ch", None);
    assert!(result.is_some());
    let (sector, _, confidence) = result.unwrap();
    assert_eq!(sector, "government");
    assert!(confidence >= 0.9);
}

#[test]
fn classify_admin_ch_is_government() {
    let result = classify_by_keywords("www.admin.ch", None);
    assert!(result.is_some());
    let (sector, _, confidence) = result.unwrap();
    assert_eq!(sector, "government");
    assert!(confidence >= 0.95);
}

#[test]
fn classify_unknown_returns_none() {
    let result = classify_by_keywords("randomsite.ch", Some("Welcome to our website"));
    assert!(result.is_none());
}
