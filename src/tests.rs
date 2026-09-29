use std::fs;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use clap::Parser;

use crate::schema::{ensure_schema, cmd_init, migrate_domains_country_code};
use crate::shared::{
    dedupe_sorted, sanitize_domain, Row, HttpHeadersRow, ScanStatus,
};
use crate::http_scan::{
    flush_batch, flush_http_headers_batch, detect_cms,
    load_pending_domains, candidate_urls, should_try_www, cmd_scan,
};
use crate::dns_scan::{load_scan_targets, cmd_dns};
use crate::email_security::{parse_spf, parse_dmarc};
use crate::classify::classify_by_keywords;
use crate::tls_scan::cmd_tls;
use crate::ports_scan::{grab_banner, grab_mysql_banner, grab_memcached_banner, grab_redis_banner, cmd_ports};
use crate::{InitArgs, ScanArgs, DnsArgs, TlsArgs, PortsArgs};

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
fn single_domain_bypasses_batch_queries() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    assert_eq!(
        load_pending_domains(&conn, Some("example.ch"), None).unwrap(),
        vec!["example.ch".to_string()]
    );
    assert_eq!(
        load_scan_targets(&conn, Some("example.ch"), "dns_info", "resolved_at", None).unwrap(),
        vec!["example.ch".to_string()]
    );
}

#[test]
fn flush_batch_roundtrip() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("
        CREATE TABLE domains (
            domain TEXT PRIMARY KEY,
            status TEXT,
            final_url TEXT, status_code INTEGER,
            title TEXT, body_hash TEXT, error_kind TEXT,
            elapsed_ms INTEGER, ip TEXT, updated_at TEXT,
            server TEXT, powered_by TEXT,
            redirect_chain TEXT, cms TEXT,
            country_code TEXT
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
        country_code: None,
    }];

    flush_batch(&conn, &mut batch, None).unwrap();
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

#[test]
fn flush_batch_persists_preset_country_code() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("
        CREATE TABLE domains (
            domain TEXT PRIMARY KEY,
            status TEXT,
            final_url TEXT, status_code INTEGER,
            title TEXT, body_hash TEXT, error_kind TEXT,
            elapsed_ms INTEGER, ip TEXT, updated_at TEXT,
            server TEXT, powered_by TEXT,
            redirect_chain TEXT, cms TEXT,
            country_code TEXT
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
        body_hash: None,
        server: None,
        powered_by: None,
        error_kind: None,
        elapsed_ms: 10,
        redirect_chain: vec![],
        cms: None,
        country_code: Some("CH".into()),
    }];

    flush_batch(&conn, &mut batch, None).unwrap();
    assert!(batch.is_empty());

    let cc: Option<String> = conn
        .query_row("SELECT country_code FROM domains WHERE domain='test.ch'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cc.as_deref(), Some("CH"));
}

#[test]
fn flush_batch_enriches_country_from_mmdb() {
    let mmdb_path = Path::new("data/GeoLite2-Country.mmdb");
    if !mmdb_path.exists() {
        return;
    }

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("
        CREATE TABLE domains (
            domain TEXT PRIMARY KEY,
            status TEXT,
            final_url TEXT, status_code INTEGER,
            title TEXT, body_hash TEXT, error_kind TEXT,
            elapsed_ms INTEGER, ip TEXT, updated_at TEXT,
            server TEXT, powered_by TEXT,
            redirect_chain TEXT, cms TEXT,
            country_code TEXT
        );
        INSERT INTO domains VALUES ('test.ch', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    ").unwrap();

    let reader = maxminddb::Reader::open_readfile(mmdb_path).unwrap();
    let mut batch = vec![Row {
        domain: "test.ch".into(),
        status: ScanStatus::Ok,
        ip: Some("8.8.8.8".into()),
        final_url: Some("https://test.ch/".into()),
        status_code: Some(200),
        title: None,
        body_hash: None,
        server: None,
        powered_by: None,
        error_kind: None,
        elapsed_ms: 10,
        redirect_chain: vec![],
        cms: None,
        country_code: None,
    }];

    flush_batch(&conn, &mut batch, Some(&reader)).unwrap();

    let cc: Option<String> = conn
        .query_row("SELECT country_code FROM domains WHERE domain='test.ch'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cc.as_deref(), Some("US"));
}

#[test]
fn flush_batch_invalid_ip_leaves_country_none() {
    let mmdb_path = Path::new("data/GeoLite2-Country.mmdb");
    if !mmdb_path.exists() {
        return;
    }

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("
        CREATE TABLE domains (
            domain TEXT PRIMARY KEY,
            status TEXT,
            final_url TEXT, status_code INTEGER,
            title TEXT, body_hash TEXT, error_kind TEXT,
            elapsed_ms INTEGER, ip TEXT, updated_at TEXT,
            server TEXT, powered_by TEXT,
            redirect_chain TEXT, cms TEXT,
            country_code TEXT
        );
        INSERT INTO domains VALUES ('test.ch', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    ").unwrap();

    let reader = maxminddb::Reader::open_readfile(mmdb_path).unwrap();
    let mut batch = vec![Row {
        domain: "test.ch".into(),
        status: ScanStatus::Ok,
        ip: Some("not-an-ip".into()),
        final_url: Some("https://test.ch/".into()),
        status_code: Some(200),
        title: None,
        body_hash: None,
        server: None,
        powered_by: None,
        error_kind: None,
        elapsed_ms: 10,
        redirect_chain: vec![],
        cms: None,
        country_code: None,
    }];

    flush_batch(&conn, &mut batch, Some(&reader)).unwrap();

    let cc: Option<String> = conn
        .query_row("SELECT country_code FROM domains WHERE domain='test.ch'", [], |r| r.get(0))
        .unwrap();
    assert!(cc.is_none());
}

#[test]
fn migrate_domains_country_code_idempotent() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("
        CREATE TABLE domains (
            domain TEXT PRIMARY KEY,
            status TEXT
        );
    ").unwrap();

    // Column should not exist yet
    let has_col_before: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('domains') WHERE name = 'country_code'",
        [],
        |r| r.get(0),
    ).unwrap();
    assert!(!has_col_before);

    // First run: adds the column
    migrate_domains_country_code(&conn).unwrap();

    let has_col_after: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('domains') WHERE name = 'country_code'",
        [],
        |r| r.get(0),
    ).unwrap();
    assert!(has_col_after);

    // Second run: no error (idempotent)
    migrate_domains_country_code(&conn).unwrap();
}

#[tokio::test]
#[ignore = "network-dependent end-to-end scan over sample_domains.txt"]
async fn sample_domains_e2e_scan() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sample_input = manifest_dir.join("data/sample_domains.txt");
    let db_path = std::env::temp_dir().join(format!(
        "helvetiscan-sample-{}-{}.db",
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
        concurrency: 10,
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        max_kbytes: 64,
        max_redirects: 5,
        user_agent: "helvetiscan/test".into(),
        quiet: false,
        retry_errors: None,
        save_md: None,
        country_mmdb: std::path::PathBuf::from("data/GeoLite2-Country.mmdb"),
    }, None, None)
    .await
    .unwrap();

    cmd_dns(DnsArgs {
        db: db_path.clone(),
        domain: None,
        concurrency: 10,
        quiet: false,
        retry_errors: None,
    }, None, None)
    .await
    .unwrap();

    cmd_tls(TlsArgs {
        db: db_path.clone(),
        domain: None,
        concurrency: 10,
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(8),
        quiet: false,
        retry_errors: None,
    }, None, None)
    .await
    .unwrap();

    cmd_ports(PortsArgs {
        db: db_path.clone(),
        domain: None,
        concurrency: 10,
        connect_timeout: Duration::from_millis(800),
        quiet: false,
        retry_errors: None,
        grab_banners: false,
        ports: None,
    }, None, None)
    .await
    .unwrap();

    let conn = crate::shared::open_db(&db_path).unwrap();
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

#[test]
fn wp_content_in_body() {
    assert_eq!(detect_cms(None, b"<link rel='stylesheet' href='/wp-content/themes/x/style.css'>", None, None), Some("WordPress".into()));
}

#[test]
fn wp_includes_in_body() {
    assert_eq!(detect_cms(None, b"<script src='/wp-includes/js/jquery.js'></script>", None, None), Some("WordPress".into()));
}

#[test]
fn powered_by_wordpress() {
    assert_eq!(detect_cms(Some("WordPress 6.4"), b"", None, None), Some("WordPress".into()));
}

#[test]
fn drupal_settings_in_body() {
    assert_eq!(detect_cms(None, b"jQuery.extend(Drupal.settings, {});", None, None)
, Some("Drupal".into()));
}

#[test]
fn joomla_com_in_body() {
    assert_eq!(detect_cms(None, b"<a href='/components/com_content/'>read more</a>", None, None), Some("Joomla".into()));
}

#[test]
fn typo3conf_in_body() {
    assert_eq!(detect_cms(None, b"<link href='/typo3conf/ext/theme/Resources/Public/main.css'>", None, None), Some("TYPO3".into()));
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
    assert_eq!(detect_cms(None, b"", Some("Apache/2.4.57"), None), Some("apache".into()));
}

#[test]
fn server_header_nginx_version() {
    assert_eq!(detect_cms(None, b"", Some("nginx/1.24.0"), None), Some("nginx".into()));
}

#[test]
fn powered_by_php_version() {
    assert_eq!(detect_cms(Some("PHP/8.2.1"), b"", None, None), Some("php".into()));
}

#[test]
fn tomcat_via_coyote_header() {
    assert_eq!(detect_cms(None, b"", Some("Apache-Coyote/1.1"), None), Some("tomcat".into()));
}

#[test]
fn roundcube_in_body() {
    assert_eq!(detect_cms(None, b"Copyright (C) The Roundcube Dev Team", None, None), Some("roundcube".into()));
}

#[test]
fn exchange_via_owa_url() {
    assert_eq!(detect_cms(None, b"", None, Some("https://4814.ch/owa/auth/logon.aspx")), Some("exchange".into()));
}

#[test]
fn exchange_via_ecp_url() {
    assert_eq!(detect_cms(None, b"", None, Some("https://domain.ch/ecp/")), Some("exchange".into()));
}

#[test]
fn no_false_positive_domain_containing_owa() {
    // Domain name containing "nowak" must NOT match Exchange
    assert_eq!(detect_cms(None, b"", None, Some("https://a-nowak.ch/")), None);
}

// ---- flush_http_headers_batch ----

#[test]
fn flush_http_headers_roundtrip() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("
        CREATE TABLE http_headers (
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

#[tokio::test]
async fn grab_mysql_banner_extracts_version() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use std::net::{IpAddr, Ipv4Addr};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let version = b"8.0.35";
            let mut packet = vec![0u8; 5 + version.len() + 1];
            packet[4] = 0x0a; // protocol version 10
            packet[5..5 + version.len()].copy_from_slice(version);
            packet[5 + version.len()] = 0x00;
            let _ = stream.write_all(&packet).await;
        }
    });

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let banner = grab_mysql_banner(ip, port).await;
    assert_eq!(banner, Some("MySQL 8.0.35".into()));
}

#[tokio::test]
async fn grab_memcached_banner_extracts_version() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use std::net::{IpAddr, Ipv4Addr};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Read the "version\r\n" probe then respond
            let mut buf = [0u8; 16];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            let _ = stream.write_all(b"VERSION 1.6.12\r\n").await;
        }
    });

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let banner = grab_memcached_banner(ip, port).await;
    assert_eq!(banner, Some("VERSION 1.6.12".into()));
}

#[tokio::test]
async fn grab_redis_banner_extracts_version() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use std::net::{IpAddr, Ipv4Addr};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Read the INFO probe then respond with INFO server output
            let mut buf = [0u8; 32];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            let _ = stream.write_all(b"# Server\r\nredis_version:7.2.4\r\n").await;
        }
    });

    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let banner = grab_redis_banner(ip, port).await;
    assert_eq!(banner, Some("Redis 7.2.4".into()));
}

// ---- risk_score VIEW ----

#[test]
fn risk_score_view_flags_and_score() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
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
        INSERT INTO ports_info (domain, port, service)
        VALUES ('probe.ch', 3306, 'mysql');
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

// ---- parallel pipeline infrastructure ----

#[test]
fn progress_total_is_atomic() {
    use std::sync::atomic::Ordering;
    use crate::shared::Progress;

    let p = Progress::new(0, "ok", "err");
    assert_eq!(p.total.load(Ordering::Relaxed), 0);
    p.total.store(500, Ordering::Relaxed);
    assert_eq!(p.total.load(Ordering::Relaxed), 500);
}

#[test]
fn progress_total_set_by_new() {
    use std::sync::atomic::Ordering;
    use crate::shared::Progress;

    let p = Progress::new(1234, "ok", "err");
    assert_eq!(p.total.load(Ordering::Relaxed), 1234);
}

#[tokio::test]
async fn error_rate_supervisor_cancels_on_high_error_rate() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use crate::shared::Progress;

    // The supervisor judges each 2s window's transport-error rate and cancels only after the rate
    // stays over threshold for SUPERVISOR_DEBOUNCE_WINDOWS in a row — so a static snapshot can't
    // trip it; we need a module that keeps producing results. This driver emits ~100 completions
    // every 300ms at a 60% transport-error rate (> the 0.35 threshold), past min_samples.
    let prog = Arc::new(Progress::new(10_000_000, "ok", "err"));
    prog.total.store(10_000_000, Ordering::Relaxed);

    let driver_prog = prog.clone();
    let driver = tokio::spawn(async move {
        loop {
            driver_prog.completed.fetch_add(100, Ordering::Relaxed);
            driver_prog.transport_errors.fetch_add(60, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });

    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);

    let supervisor = tokio::spawn(crate::error_rate_supervisor(
        vec![("test-module", prog, cancel_tx)],
        0.35, // threshold
        100, // min_samples (warm-up gate; small so the driver clears it quickly in-test)
    ));

    // Needs SUPERVISOR_DEBOUNCE_WINDOWS (3) × 2s ≈ 6s of sustained overload; allow generous slack.
    tokio::time::timeout(Duration::from_secs(15), async {
        cancel_rx.changed().await.unwrap();
        assert!(*cancel_rx.borrow(), "cancel channel should be set to true");
    })
    .await
    .expect("supervisor did not cancel a sustained-overload module in time");

    driver.abort();
    supervisor.abort();
}

#[tokio::test]
async fn error_rate_supervisor_does_not_cancel_below_threshold() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use crate::shared::Progress;

    let prog = Arc::new(Progress::new(200, "ok", "err"));
    prog.total.store(200, Ordering::Relaxed);
    prog.completed.store(150, Ordering::Relaxed); // past min_samples
    prog.transport_errors.store(30, Ordering::Relaxed); // 20% transport rate, below 35% threshold

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    // Run supervisor for a couple of poll cycles.
    let supervisor = tokio::spawn(crate::error_rate_supervisor(
        vec![("test-module", prog, cancel_tx)],
        0.35,
        100,
    ));

    tokio::time::sleep(Duration::from_millis(4500)).await;

    // Cancel channel should remain false
    assert!(!*cancel_rx.borrow(), "supervisor should not cancel a module below the transport-error threshold");

    supervisor.abort();
}

#[tokio::test]
async fn error_rate_supervisor_does_not_cancel_below_min_samples() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use crate::shared::Progress;

    let prog = Arc::new(Progress::new(200, "ok", "err"));
    prog.total.store(200, Ordering::Relaxed);
    prog.completed.store(50, Ordering::Relaxed); // only 50 samples, below min_samples=100
    prog.transport_errors.store(50, Ordering::Relaxed); // 100% transport rate, but must be ignored

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    let supervisor = tokio::spawn(crate::error_rate_supervisor(
        vec![("test-module", prog, cancel_tx)],
        0.35,
        100, // min_samples
    ));

    tokio::time::sleep(Duration::from_millis(2500)).await;

    assert!(!*cancel_rx.borrow(), "supervisor must not cancel before min_samples is reached");

    supervisor.abort();
}

#[tokio::test]
async fn error_rate_supervisor_exits_when_all_done() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use crate::shared::Progress;

    // completed == total → all done
    let prog = Arc::new(Progress::new(100, "ok", "err"));
    prog.total.store(100, Ordering::Relaxed);
    prog.completed.store(100, Ordering::Relaxed);
    prog.errors.store(5, Ordering::Relaxed); // low error rate

    let (cancel_tx, _cancel_rx) = tokio::sync::watch::channel(false);

    let supervisor = tokio::spawn(crate::error_rate_supervisor(
        vec![("test-module", prog, cancel_tx)],
        0.5,
        100,
    ));

    // Supervisor should exit naturally (completed >= total) within a few poll cycles
    tokio::time::timeout(Duration::from_secs(6), supervisor)
        .await
        .expect("supervisor did not exit after all modules completed")
        .expect("supervisor task panicked");
}

#[tokio::test]
async fn ext_shutdown_rx_stops_dns_reader() {
    // Verify: a pre-fired shutdown_rx causes the reader to stop immediately,
    // resulting in zero enqueued domains even when there are pending ones in the DB.
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use crate::shared::Progress;

    // Set up a temp DB with a few domains
    let db_path = std::env::temp_dir().join(format!(
        "helvetiscan-shutdown-test-{}.db",
        std::process::id()
    ));
    crate::schema::cmd_init(crate::InitArgs {
        input: std::path::PathBuf::from("data/sample_domains.txt"),
        db: db_path.clone(),
    })
    .unwrap();

    // Pre-fire the shutdown channel (send true before passing to module)
    let (tx, rx) = tokio::sync::watch::channel(false);
    tx.send(true).unwrap();

    let prog = Arc::new(Progress::new(0, "resolved", "errors"));

    let result = crate::dns_scan::cmd_dns(
        crate::DnsArgs {
            db: db_path.clone(),
            domain: None,
            concurrency: 10,
            quiet: false,
            retry_errors: None,
        },
        Some(rx),
        Some(prog.clone()),
    )
    .await;

    let _ = std::fs::remove_file(&db_path);

    assert!(result.is_ok(), "cmd_dns with pre-fired shutdown should return Ok");
    // total was set (domains existed in DB); enqueued should be 0 because reader broke immediately
    let total = prog.total.load(Ordering::Relaxed);
    let enqueued = prog.enqueued.load(Ordering::Relaxed);
    assert!(total > 0, "progress.total should have been set to number of pending domains");
    assert_eq!(enqueued, 0, "no domains should have been enqueued after immediate shutdown");
}

#[tokio::test]
async fn ext_progress_total_set_by_module() {
    // Verify: when ext_progress is passed, the module stores pending.len() into progress.total.
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use crate::shared::Progress;

    let db_path = std::env::temp_dir().join(format!(
        "helvetiscan-extprog-test-{}.db",
        std::process::id()
    ));
    crate::schema::cmd_init(crate::InitArgs {
        input: std::path::PathBuf::from("data/sample_domains.txt"),
        db: db_path.clone(),
    })
    .unwrap();

    let prog = Arc::new(Progress::new(0, "resolved", "errors"));
    assert_eq!(prog.total.load(Ordering::Relaxed), 0);

    // Pre-fire shutdown so no actual DNS queries are made
    let (tx, rx) = tokio::sync::watch::channel(false);
    tx.send(true).unwrap();

    let _ = crate::dns_scan::cmd_dns(
        crate::DnsArgs {
            db: db_path.clone(),
            domain: None,
            concurrency: 4,
            quiet: false,
            retry_errors: None,
        },
        Some(rx),
        Some(prog.clone()),
    )
    .await;

    let _ = std::fs::remove_file(&db_path);

    // Module should have stored the actual pending count into total
    let total = prog.total.load(Ordering::Relaxed);
    assert!(total > 0, "module must update progress.total with the number of pending domains (got 0)");
}

#[test]
fn test_cli_scan_quiet_default() {
    let args = crate::ScanArgs::parse_from(["scan"]);
    assert!(!args.quiet, "--quiet should default to false");
}

#[test]
fn test_cli_scan_quiet_flag() {
    let args = crate::ScanArgs::parse_from(["scan", "--quiet"]);
    assert!(args.quiet, "--quiet flag should set quiet to true");
}

#[test]
fn test_cli_scan_retry_errors_default() {
    let args = crate::ScanArgs::parse_from(["scan"]);
    assert!(args.retry_errors.is_none(), "--retry-errors should default to None");
}

#[test]
fn test_cli_scan_retry_errors_value() {
    let args = crate::ScanArgs::parse_from(["scan", "--retry-errors", "timeout"]);
    assert_eq!(args.retry_errors.as_deref(), Some("timeout"), "--retry-errors should parse the value");
}

#[test]
fn test_cli_dns_quiet_and_retry() {
    let args = crate::DnsArgs::parse_from(["dns", "--quiet", "--retry-errors", "io_error"]);
    assert!(args.quiet, "--quiet should be true");
    assert_eq!(args.retry_errors.as_deref(), Some("io_error"), "--retry-errors should parse");
}

#[test]
fn test_cli_subdomains_quiet_and_retry() {
    let args = crate::SubdomainsArgs::parse_from(["subdomains", "--quiet", "--retry-errors", "nxdomain"]);
    assert!(args.quiet, "--quiet should be true");
    assert_eq!(args.retry_errors.as_deref(), Some("nxdomain"), "--retry-errors should parse");
}


// ---- error-rate supervisor (windowed, transport-only, debounced) ----

use crate::{supervisor_step, SUPERVISOR_DEBOUNCE_WINDOWS};

#[test]
fn supervisor_holds_streak_at_zero_during_warmup() {
    // Below min_samples the run is still warming up: even a 100% window must not build a streak.
    let s = supervisor_step(2, /*completed_total*/ 4_999, /*win_completed*/ 500, /*win_errs*/ 500, 0.35, 5_000);
    assert_eq!(s, 0);
}

#[test]
fn supervisor_builds_streak_only_on_sustained_over_threshold_windows() {
    // Warmed up, transport-error rate 60% > 35% threshold: streak increments each window.
    let mut streak = 0;
    for _ in 0..SUPERVISOR_DEBOUNCE_WINDOWS {
        streak = supervisor_step(streak, 10_000, 1_000, 600, 0.35, 5_000);
    }
    assert_eq!(streak, SUPERVISOR_DEBOUNCE_WINDOWS, "sustained overload should reach the cancel threshold");
}

#[test]
fn supervisor_resets_streak_on_a_healthy_window() {
    // Two bad windows then a healthy one (10% < 35%) must reset — a blip can't accumulate to a cancel.
    let streak = supervisor_step(2, 10_000, 1_000, 100, 0.35, 5_000);
    assert_eq!(streak, 0);
}

#[test]
fn supervisor_freezes_streak_on_a_no_progress_window() {
    // A window with zero completions (module stalled) neither grows nor resets the streak.
    let streak = supervisor_step(2, 10_000, 0, 0, 0.35, 5_000);
    assert_eq!(streak, 2);
}

#[test]
fn supervisor_ignores_a_high_lifetime_rate_when_the_recent_window_is_clean() {
    // The whole point of windowing: a run that had a rough warm-up but is now healthy is judged on
    // the recent window (5% here), not on any cumulative lifetime ratio.
    let streak = supervisor_step(0, 2_000_000, 800, 40, 0.35, 5_000);
    assert_eq!(streak, 0);
}

#[test]
fn supervisor_zone_facts_never_trip_it() {
    // A stage like subdomains/ports feeds zero transport errors even at 100% "errors": streak stays 0.
    let streak = supervisor_step(2, 1_000_000, 1_000, 0, 0.35, 5_000);
    assert_eq!(streak, 0);
}

#[test]
fn maxminddb_asn_and_country_lookup_real_files() {
    let (a, c) = (Path::new("data/GeoLite2-ASN.mmdb"), Path::new("data/GeoLite2-Country.mmdb"));
    if !a.exists() || !c.exists() {
        return;
    }
    let ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let asn_reader = maxminddb::Reader::open_readfile(a).unwrap();
    let asn: maxminddb::geoip2::Asn = asn_reader.lookup(ip).unwrap().decode().unwrap().unwrap();
    assert_eq!(asn.autonomous_system_number, Some(15169));
    let country_reader = maxminddb::Reader::open_readfile(c).unwrap();
    let cc: maxminddb::geoip2::Country = country_reader.lookup(ip).unwrap().decode().unwrap().unwrap();
    assert_eq!(cc.country.iso_code, Some("US"));
}
