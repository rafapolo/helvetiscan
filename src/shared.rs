use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{ResolveError, TokioResolver};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use chrono::NaiveDate;

// ---- Constants ----

pub(crate) const DISPATCH_BATCH_SIZE: usize = 255;
pub(crate) const DISPATCH_BATCH_SLEEP: Duration = Duration::from_millis(500);
pub(crate) const PORTS: &[(u16, &str)] = &[
    (80,    "http"),
    (443,   "https"),
    (22,    "ssh"),
    (21,    "ftp"),
    (25,    "smtp"),
    (587,   "submission"),
    (3306,  "mysql"),
    (5432,  "postgresql"),
    (6379,  "redis"),
    (8080,  "http-alt"),
    (8443,  "https-alt"),
    (23,    "telnet"),
    (445,   "smb"),
    (3389,  "rdp"),
    (5900,  "vnc"),
    (9200,  "elasticsearch"),
    (27017, "mongodb"),
    (11211, "memcached"),
    (2375,  "docker-api"),
    (6443,  "kubernetes-api"),
];
pub(crate) const BANNER_PORTS: &[u16] = &[22, 23, 25, 587, 9200, 27017, 11211];

// ---- Enums ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    Dns,
    Refused,
    Tls,
    Timeout,
    NotFound,
    ParseFailed,
    HttpStatus,
    Other,
}

impl ErrorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Dns => "dns",
            ErrorKind::Refused => "refused",
            ErrorKind::Tls => "tls_failed",
            ErrorKind::Timeout => "timeout",
            ErrorKind::NotFound => "not_found",
            ErrorKind::ParseFailed => "parse_failed",
            ErrorKind::HttpStatus => "http_status",
            ErrorKind::Other => "other",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanStatus {
    Ok,
    Error,
}

impl ScanStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ScanStatus::Ok => "ok",
            ScanStatus::Error => "error",
        }
    }
}

// ---- Row structs ----

#[derive(Debug)]
pub(crate) struct Row {
    pub(crate) domain: String,
    pub(crate) status: ScanStatus,
    pub(crate) ip: Option<String>,
    pub(crate) final_url: Option<String>,
    pub(crate) status_code: Option<u16>,
    pub(crate) title: Option<String>,
    pub(crate) body_hash: Option<String>,
    pub(crate) server: Option<String>,
    pub(crate) powered_by: Option<String>,
    pub(crate) error_kind: Option<ErrorKind>,
    pub(crate) elapsed_ms: u64,
    pub(crate) redirect_chain: Vec<String>,
    pub(crate) cms: Option<String>,
    pub(crate) country_code: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct HttpHeadersRow {
    pub(crate) domain: String,
    pub(crate) hsts: Option<String>,
    pub(crate) csp: Option<String>,
    pub(crate) x_frame_options: Option<String>,
    pub(crate) x_content_type_options: Option<String>,
    pub(crate) cors_origin: Option<String>,
    pub(crate) referrer_policy: Option<String>,
    pub(crate) permissions_policy: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DnsRow {
    pub(crate) domain: String,
    pub(crate) status: ScanStatus,
    pub(crate) error_kind: Option<ErrorKind>,
    pub(crate) ns: Vec<String>,
    pub(crate) mx: Vec<String>,
    pub(crate) cname: Option<String>,
    pub(crate) a: Vec<String>,
    pub(crate) aaaa: Vec<String>,
    pub(crate) txt_spf: Option<String>,
    pub(crate) txt_dmarc: Option<String>,
    pub(crate) ttl: Option<i32>,
    pub(crate) ptr: Option<String>,
    pub(crate) dnssec_signed: Option<bool>,
    pub(crate) dnssec_valid: Option<bool>,
    pub(crate) caa: Vec<String>,
    pub(crate) wildcard: bool,
    pub(crate) txt_all: Vec<String>,
    pub(crate) email_security: Option<crate::email_security::EmailSecurityRow>,
}

#[derive(Debug, Clone)]
pub(crate) struct TlsRow {
    pub(crate) domain: String,
    pub(crate) status: ScanStatus,
    pub(crate) error_kind: Option<ErrorKind>,
    pub(crate) cert_issuer: Option<String>,
    pub(crate) cert_subject: Option<String>,
    pub(crate) valid_from: Option<NaiveDate>,
    pub(crate) valid_to: Option<NaiveDate>,
    pub(crate) days_remaining: Option<i32>,
    pub(crate) expired: Option<bool>,
    pub(crate) self_signed: Option<bool>,
    pub(crate) tls_version: Option<String>,
    pub(crate) cipher: Option<String>,
    pub(crate) san: Vec<String>,
    pub(crate) key_algorithm: Option<String>,
    pub(crate) key_size: Option<i32>,
    pub(crate) signature_algorithm: Option<String>,
    pub(crate) cert_fingerprint: Option<String>,
    pub(crate) ct_logged: Option<bool>,
    pub(crate) ocsp_must_staple: Option<bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct PortResult {
    pub(crate) port: u16,
    pub(crate) service: &'static str,
    pub(crate) open: bool,
    pub(crate) banner: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PortsRow {
    pub(crate) domain: String,
    pub(crate) ip: Option<String>,
    pub(crate) results: Vec<PortResult>,
}

#[derive(Debug, Clone)]
pub(crate) struct WhoisRow {
    pub(crate) domain:           String,
    pub(crate) registrar:        Option<String>,
    pub(crate) whois_created:    Option<NaiveDate>,
    pub(crate) expires_at:       Option<NaiveDate>,
    pub(crate) status:           Option<String>,
    pub(crate) dnssec_delegated: Option<bool>,
    /// True when the TCP connection succeeded and a response was received.
    /// False means a network/timeout failure — row should not be persisted.
    pub(crate) connected:        bool,
}

#[derive(Debug)]
pub(crate) struct SubdomainRow {
    pub(crate) domain: String,
    /// Each entry is (fqdn, source) where source is "ct" | "axfr" | "mx_ns"
    pub(crate) found: Vec<(String, &'static str)>,
}

// ---- Progress ----

#[derive(Debug)]
pub(crate) struct Progress {
    pub(crate) started: Instant,
    pub(crate) total: AtomicU64,
    pub(crate) enqueued: AtomicU64,
    pub(crate) completed: AtomicU64,
    pub(crate) ok: AtomicU64,
    pub(crate) errors: AtomicU64,
    pub(crate) ok_label: &'static str,
    pub(crate) err_label: &'static str,
}

impl Progress {
    pub(crate) fn new(total: u64, ok_label: &'static str, err_label: &'static str) -> Self {
        Self {
            started: Instant::now(),
            total: AtomicU64::new(total),
            enqueued: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            ok: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            ok_label,
            err_label,
        }
    }
}

// ---- Resolver ----

#[derive(Clone)]
pub(crate) struct ReqwestHickoryResolver {
    pub(crate) resolver: TokioResolver,
}

impl Resolve for ReqwestHickoryResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let lookup = resolver.lookup_ip(host).await?;
            let addrs_vec: Vec<SocketAddr> = lookup.iter().map(|ip| SocketAddr::new(ip, 0)).collect();
            let addrs: Addrs = Box::new(addrs_vec.into_iter());
            Ok(addrs)
        })
    }
}

pub(crate) fn build_default_resolver() -> TokioResolver {
    TokioResolver::builder_with_config(ResolverConfig::cloudflare(), TokioConnectionProvider::default()).build()
}

// ---- SQL helpers ----

pub(crate) fn sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\0', "").replace('\'', "''"))
}

pub(crate) fn sql_string_opt(value: Option<&str>) -> String {
    value.map(sql_string).unwrap_or_else(|| "NULL".to_string())
}

pub(crate) fn sql_string_list(values: &[String]) -> String {
    let json = serde_json::to_string(values).unwrap_or_else(|_| "[]".to_string());
    format!("'{}'", json.replace('\'', "''"))
}

pub(crate) fn sql_bool(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

pub(crate) fn sql_bool_opt(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "1",
        Some(false) => "0",
        None => "NULL",
    }
}

// ---- DB helpers ----

pub(crate) fn open_db(path: &std::path::Path) -> rusqlite::Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open(path)?;
    conn.execute_batch("
        PRAGMA journal_mode=WAL;
        PRAGMA busy_timeout=10000;
        PRAGMA synchronous=NORMAL;
        PRAGMA cache_size=-32768;
    ")?;
    Ok(conn)
}

pub(crate) fn sql_int_opt(value: Option<i32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "NULL".to_string())
}

// ---- Utility functions ----

pub(crate) fn sanitize_domain(line: &str) -> Option<String> {
    let mut s = line.trim();
    if s.is_empty() {
        return None;
    }

    if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    }
    if let Some((host, _)) = s.split_once('/') {
        s = host;
    }
    s = s.trim().trim_matches('.');
    if s.is_empty() {
        return None;
    }

    if s.len() > 253 {
        return None;
    }
    if s.bytes().any(|b| b <= 0x20 || b == b',' || b == b'"') {
        return None;
    }

    Some(s.to_string())
}

pub(crate) fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }

    let (num, unit) = if let Some(v) = s.strip_suffix("ms") {
        (v, "ms")
    } else if let Some(v) = s.strip_suffix('s') {
        (v, "s")
    } else if let Some(v) = s.strip_suffix('m') {
        (v, "m")
    } else if let Some(v) = s.strip_suffix('h') {
        (v, "h")
    } else {
        return Err("duration must end with ms/s/m/h (e.g. 5s)".to_string());
    };

    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration number: {s}"))?;

    Ok(match unit {
        "ms" => Duration::from_millis(n),
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n.saturating_mul(60)),
        "h" => Duration::from_secs(n.saturating_mul(3600)),
        _ => return Err("unsupported duration unit".to_string()),
    })
}

pub(crate) fn dedupe_sorted(values: Vec<String>) -> Vec<String> {
    let mut values: Vec<String> = values.into_iter().filter_map(non_empty).collect();
    values.sort();
    values.dedup();
    values
}

pub(crate) fn non_empty<T: Into<String>>(value: T) -> Option<String> {
    let value = value.into();
    let trimmed = value.trim().trim_end_matches('.').trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

pub(crate) fn classify_dns_error(err: &ResolveError) -> ErrorKind {
    if err.is_nx_domain() || err.is_no_records_found() {
        return ErrorKind::NotFound;
    }
    let msg = err.to_string().to_ascii_lowercase();
    if msg.contains("timed out") || msg.contains("timeout") {
        return ErrorKind::Timeout;
    }
    if msg.contains("refused") {
        return ErrorKind::Refused;
    }
    ErrorKind::Dns
}

pub(crate) fn classify_io_error(err: &std::io::Error) -> ErrorKind {
    match err.kind() {
        std::io::ErrorKind::TimedOut => ErrorKind::Timeout,
        std::io::ErrorKind::ConnectionRefused => ErrorKind::Refused,
        _ => {
            let msg = err.to_string().to_ascii_lowercase();
            if msg.contains("nodename nor servname provided")
                || msg.contains("name or service not known")
                || msg.contains("failed to lookup")
                || msg.contains("no such host")
            {
                ErrorKind::Dns
            } else {
                ErrorKind::Other
            }
        }
    }
}

pub(crate) fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

pub(crate) fn progress_bar(done: u64, total: u64, width: usize) -> String {
    let filled = if total > 0 {
        ((done as f64 / total as f64) * width as f64) as usize
    } else {
        0
    }
    .min(width);
    format!("[{}{}]", "█".repeat(filled), "░".repeat(width - filled))
}

pub(crate) fn format_eta(secs: f64) -> String {
    let secs = secs as u64;
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

pub(crate) fn append_error_log(db_path: &std::path::Path, message: &str) {
    use std::io::Write;
    let log_path = db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("error.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = writeln!(file, "[{ts}] {message}");
    }
}

pub(crate) async fn wait_for_shutdown_signal() {
    // On Unix, SIGTERM triggers an immediate soft kill.
    // SIGINT (Ctrl+C) requires a second press.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let sigterm_fired = match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => false,
                    _ = sigterm.recv() => true,
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                false
            }
        };
        if sigterm_fired {
            return;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    // First Ctrl+C: prompt the user for a second press.
    eprintln!("\nPress Ctrl+C again to flush and exit...");
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("\nflushing batches...");
}

pub(crate) async fn multi_progress_reporter(
    modules: Vec<(&'static str, std::sync::Arc<Progress>)>,
    interval: std::time::Duration,
    mut done_rx: tokio::sync::oneshot::Receiver<()>,
) {
    use std::sync::atomic::Ordering;

    let interval = if interval.is_zero() {
        std::time::Duration::from_secs(1)
    } else {
        interval
    };
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let n = modules.len();
    let mut first = true;
    let mut last_done: Vec<u64> = vec![0; n];
    let mut last_t = std::time::Instant::now();

    loop {
        tokio::select! {
            _ = &mut done_rx => break,
            _ = ticker.tick() => {
                let now = std::time::Instant::now();
                let dt = (now - last_t).as_secs_f64().max(0.001);

                // Move cursor up to overwrite previous output
                if !first {
                    // Move up n lines (no \r — each line prefix handles its own column reset)
                    eprint!("\x1B[{}A", n);
                }

                for (i, (name, progress)) in modules.iter().enumerate() {
                    let done = progress.completed.load(Ordering::Relaxed);
                    let total = progress.total.load(Ordering::Relaxed);
                    let ok_count = progress.ok.load(Ordering::Relaxed);
                    let err_count = progress.errors.load(Ordering::Relaxed);
                    let elapsed = progress.started.elapsed().as_secs_f64().max(0.001);
                    let avg_rate = done as f64 / elapsed;

                    let delta = done.saturating_sub(last_done[i]) as f64;
                    let _inst_rate = delta / dt;

                    let eta_str = if avg_rate > 0.0 && total > done {
                        format_eta((total - done) as f64 / avg_rate)
                    } else if total > 0 && done >= total {
                        "done".to_string()
                    } else {
                        "?".to_string()
                    };

                    let bar = progress_bar(done, total, 24);
                    let pct = if total > 0 { done as f64 / total as f64 * 100.0 } else { 0.0 };

                    // \x1B[2K clears the entire line; \r resets to column 0 before writing
                    eprintln!(
                        "\x1B[2K\r{name:<12} {bar} {:5.1}% ETA {eta_str:<8}  {}={:<8} {}={:<6} {avg_rate:.1}/s",
                        pct,
                        progress.ok_label, fmt_num(ok_count),
                        progress.err_label, fmt_num(err_count),
                    );
                    last_done[i] = done;
                }

                last_t = now;
                first = false;
                let _ = std::io::Write::flush(&mut std::io::stderr());
            }
        }
    }
}

pub(crate) async fn progress_reporter(
    progress: std::sync::Arc<Progress>,
    interval: Duration,
    mut done_rx: tokio::sync::oneshot::Receiver<()>,
) {
    use std::sync::atomic::Ordering;

    let interval = if interval.is_zero() {
        Duration::from_secs(1)
    } else {
        interval
    };
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut last_done: u64 = 0;
    let mut last_t = Instant::now();
    let mut first = true;

    loop {
        tokio::select! {
            _ = &mut done_rx => {
                let enq = progress.enqueued.load(Ordering::Relaxed);
                let done = progress.completed.load(Ordering::Relaxed);
                let elapsed = progress.started.elapsed().as_secs_f64().max(0.001);
                let rate = (done as f64) / elapsed;
                eprintln!();
                eprintln!("completed: {done}/{enq} ({rate:.1}/s), elapsed: {elapsed:.1}s");
                loop {
                    ticker.tick().await;
                    let elapsed = progress.started.elapsed().as_secs_f64();
                    eprint!("\rdraining in-flight requests... elapsed: {elapsed:.1}s   ");
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
            }
            _ = ticker.tick() => {
                let enq = progress.enqueued.load(Ordering::Relaxed);
                let done = progress.completed.load(Ordering::Relaxed);
                let ok_count = progress.ok.load(Ordering::Relaxed);
                let err_count = progress.errors.load(Ordering::Relaxed);
                let inflight = enq.saturating_sub(done);
                let now = Instant::now();
                let dt = (now - last_t).as_secs_f64().max(0.001);
                let delta = done.saturating_sub(last_done) as f64;
                let _inst_rate = delta / dt;
                let elapsed = progress.started.elapsed().as_secs_f64().max(0.001);
                let avg_rate = (done as f64) / elapsed;
                let total = progress.total.load(Ordering::Relaxed);
                let eta_str = if avg_rate > 0.0 && total > done {
                    let remaining_secs = (total - done) as f64 / avg_rate;
                    format_eta(remaining_secs)
                } else {
                    "?".to_string()
                };

                let pct = if total > 0 { done as f64 / total as f64 * 100.0 } else { 0.0 };
                let bar = progress_bar(done, total, 32);
                let line1 = format!("{bar} {pct:.2}% · ETA {eta_str}");
                let line2 = format!(
                    "running: {} · queued: {} · pending {}",
                    fmt_num(inflight), fmt_num(enq), fmt_num(total)
                );
                let ok_label = progress.ok_label;
                let err_label = progress.err_label;
                let line3 = format!(
                    "{ok_label}: {} · {err_label}: {} · avg: {avg_rate:.1}/s",
                    fmt_num(ok_count), fmt_num(err_count)
                );

                if first {
                    eprint!("{line1}\n{line2}\n{line3}");
                    first = false;
                } else {
                    eprint!("\x1B[2A\r{line1}\n{line2}\n{line3}");
                }
                let _ = std::io::Write::flush(&mut std::io::stderr());

                last_done = done;
                last_t = now;
            }
        }
    }
}
