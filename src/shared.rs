use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::config::{ResolverConfig, CLOUDFLARE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::TokioResolver;
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
    (389,   "ldap"),
    (636,   "ldaps"),
    (1433,  "mssql"),
    (8009,  "ajp"),
    (8983,  "solr"),
    (8161,  "activemq"),
    (5984,  "couchdb"),
];
pub(crate) const UDP_PORTS: &[(u16, &str)] = &[
    (161, "snmp"),
];
pub(crate) const BANNER_PORTS: &[u16] = &[21, 22, 23, 25, 587, 3306, 5900, 6379, 9200, 11211, 27017, 2375, 6443, 389, 636, 1433, 161, 8009, 8983, 8161, 5984];

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

// ---- Adaptive concurrency ----
//
// Every scan module fans out over a fixed `tokio::sync::Semaphore` sized to its own
// `--concurrency` default (scan=500, dns=250, tls=150, ports=100, subdomains=200,
// smtp-check=300, detect=100 — each already tuned per-stage for that stage's own
// CPU/IO/network profile). Running that fixed size for the whole run means a stage either
// underuses an idle box (finland: 4 vCPUs sitting at ~0.1-0.3 load average while `detect` ran
// at a flat 100) or, on a smaller/busier host, overshoots and drives load through the roof.
//
// `AdaptiveSemaphore` replaces the fixed semaphore with one that grows and shrinks itself
// every tick, using the module's existing `--concurrency` value as a ceiling (never exceeded)
// rather than a fixed operating point. It starts conservatively at a small floor and probes
// upward while the host has headroom, backing off fast the moment it doesn't — same shape as
// TCP congestion control (slow additive growth, fast multiplicative backoff), because that
// asymmetry is what keeps a shared box from being pushed over LOAD_TARGET even by a stage that
// ramps hard.
//
// Two independent hardware signals feed the decision, since 1-minute load average is a lagging
// indicator that can miss a spike the tick after it happens:
//   - 1-minute system load average (`libc::getloadavg`, portable across the macOS/Linux release
//     targets) — the primary signal, kept under `LOAD_TARGET`.
//   - Instantaneous CPU busy % since the last tick, from `/proc/stat` deltas (Linux only; the
//     signal is simply skipped elsewhere, so macOS dev runs still work off load average alone).
// Either signal reporting "hot" is enough to shrink; both must report "comfortably cool" to grow.
//
// Rollout note: only `fingerprint::cmd_detect` (the `detect` stage) has been switched over to
// this so far — it's the stage that was actually observed idling on finland. The other six
// modules (http_scan, dns_scan, tls_scan, ports_scan, subdomains, smtp_check) all fan out with
// the exact same `Semaphore::new(args.concurrency)` + `acquire_owned()` pattern, so adopting
// this there is a mechanical swap once this primitive has run for real on a live pipeline.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Semaphore;

/// 1-minute load average ceiling the adaptive limiter tries to stay under.
const LOAD_TARGET: f64 = 0.9;
/// CPU busy% ceiling (Linux only) — a fast-reacting backstop for when load average hasn't
/// caught up yet.
const CPU_TARGET_PCT: f64 = 90.0;
/// Network-error-rate ceiling — the third front. CPU/load stay flat while a stage is
/// I/O-bound waiting on remote sockets, so a stage can drive the network into the ground
/// (timeouts, connection resets, upstream rate-limiting) without either of the other two
/// signals ever noticing. `record_result` feeds this from the caller's own fetch outcomes.
const ERROR_TARGET_PCT: f64 = 20.0;
/// Below this many attempts in a tick, the error rate is too noisy to act on (e.g. one failed
/// request out of two isn't "50% error", it's no data yet).
const MIN_SAMPLES_FOR_ERROR_SIGNAL: u64 = 20;
/// How often the background scaler re-samples load and adjusts permits.
const ADAPT_INTERVAL: Duration = Duration::from_secs(3);

pub(crate) struct AdaptiveSemaphore {
    sem: Arc<Semaphore>,
    current: AtomicUsize,
    floor: usize,
    ceiling: usize,
    label: &'static str,
    attempts: AtomicU64,
    errors: AtomicU64,
}

impl AdaptiveSemaphore {
    /// `ceiling` is the module's existing `--concurrency` value — the most it will ever grow
    /// to. `label` is just for the odd debug eprintln so a run's log says which stage's limiter
    /// is talking.
    pub(crate) fn new(ceiling: usize, label: &'static str) -> Arc<Self> {
        // `.max(4).min(ceiling)`, not `.clamp(4, ceiling)` — clamp panics on min > max, which
        // a ceiling below 4 would trigger.
        let floor = (ceiling / 8).max(4).min(ceiling);
        let this = Arc::new(Self {
            sem: Arc::new(Semaphore::new(floor)),
            current: AtomicUsize::new(floor),
            floor,
            ceiling,
            label,
            attempts: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        });
        Arc::clone(&this).spawn_scaler();
        this
    }

    /// Feed one fetch outcome into the network-health signal: `ok = false` for a connect
    /// failure, timeout, or similar transport-level error — not for "the request succeeded but
    /// found nothing", which isn't a network problem. Optional: a module that never calls this
    /// just runs on load average + CPU alone, exactly as before.
    pub(crate) fn record_result(&self, ok: bool) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn spawn_scaler(self: Arc<Self>) {
        if self.floor >= self.ceiling {
            return; // nothing to adapt — ceiling too small to bother scaling
        }
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(ADAPT_INTERVAL);
            let mut prev_jiffies = read_cpu_jiffies();
            loop {
                tick.tick().await;
                let load1 = load_average_1m();
                let cpu_pct = read_cpu_jiffies().and_then(|now| {
                    let pct = prev_jiffies.and_then(|prev| cpu_busy_pct(prev, now));
                    prev_jiffies = Some(now);
                    pct
                });
                let attempts = self.attempts.swap(0, Ordering::Relaxed);
                let errors = self.errors.swap(0, Ordering::Relaxed);
                let net_error_pct = (attempts >= MIN_SAMPLES_FOR_ERROR_SIGNAL)
                    .then(|| 100.0 * errors as f64 / attempts as f64);

                let cur = self.current.load(Ordering::Relaxed);
                match decide_scale(cur, self.floor, self.ceiling, load1, cpu_pct, net_error_pct) {
                    ScaleAction::Shrink(cut) => {
                        let forgotten = self.sem.forget_permits(cut);
                        if forgotten > 0 {
                            self.current.fetch_sub(forgotten, Ordering::Relaxed);
                        }
                    }
                    ScaleAction::Grow(grow) => {
                        self.sem.add_permits(grow);
                        self.current.fetch_add(grow, Ordering::Relaxed);
                    }
                    ScaleAction::Hold => {}
                }
                let _ = self.label; // reserved for future verbose/debug logging
            }
        });
    }

    pub(crate) async fn acquire_owned(self: &Arc<Self>) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.sem)
            .acquire_owned()
            .await
            .expect("adaptive semaphore is never closed")
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ScaleAction {
    Grow(usize),
    Shrink(usize),
    Hold,
}

/// The actual scaling decision, pulled out of `spawn_scaler`'s loop as a pure function so it's
/// testable without a live tokio runtime or real `/proc/stat`/`getloadavg` readings.
///
/// Three independent fronts feed this — CPU, (disk) I/O, and network — because a stage can
/// overwhelm any one of them without moving the others:
///   - `load1`: 1-minute load average. On Linux this counts both runnable *and*
///     uninterruptible-sleep (disk-wait) tasks, so it's the signal that catches I/O pressure —
///     there's no separate iowait check needed.
///   - `cpu_pct`: instantaneous CPU busy%, explicitly excluding iowait (see `read_cpu_jiffies`)
///     — a fast-reacting backstop for compute-bound stages, since load average lags a spike.
///   - `net_error_pct`: rising transport-error rate (timeouts, resets, refused connections).
///     This is the one CPU/load genuinely cannot see: an async I/O-bound stage waiting on
///     remote sockets can drive the network into the ground while local CPU and load both sit
///     near zero. `None` (module doesn't call `record_result`, or too few samples this tick)
///     never blocks growth — it's opt-in instrumentation, not a requirement.
///
/// `hot` (shrink trigger) is true if ANY signal says so — a single overloaded front is enough
/// to back off. `cool` (grow trigger) requires ALL signals to agree it's safe. A missing load
/// reading defaults `hot` to true (fail safe: if `getloadavg` fails, don't climb blind); a
/// missing `cpu_pct` or `net_error_pct` reading defaults to "not a problem" on both sides,
/// since those two are opt-in/platform-specific and their absence must never permanently wedge
/// the limiter (e.g. `cpu_pct` is always `None` on macOS, which has no `/proc/stat`).
fn decide_scale(
    cur: usize,
    floor: usize,
    ceiling: usize,
    load1: Option<f64>,
    cpu_pct: Option<f64>,
    net_error_pct: Option<f64>,
) -> ScaleAction {
    let hot = load1.map(|l| l >= LOAD_TARGET).unwrap_or(true)
        || cpu_pct.map(|c| c >= CPU_TARGET_PCT).unwrap_or(false)
        || net_error_pct.map(|e| e >= ERROR_TARGET_PCT).unwrap_or(false);
    let cool = load1.map(|l| l < LOAD_TARGET * 0.7).unwrap_or(false)
        && cpu_pct.map(|c| c < CPU_TARGET_PCT * 0.7).unwrap_or(true)
        && net_error_pct.map(|e| e < ERROR_TARGET_PCT * 0.5).unwrap_or(true);

    if hot && cur > floor {
        // Multiplicative backoff: cut ~25%, fast.
        ScaleAction::Shrink((cur / 4).max(1).min(cur - floor))
    } else if cool && cur < ceiling {
        // Additive growth: probe up ~10%, slow.
        ScaleAction::Grow((cur / 10).max(1).min(ceiling - cur))
    } else {
        ScaleAction::Hold
    }
}

fn load_average_1m() -> Option<f64> {
    let mut loads: [f64; 3] = [0.0; 3];
    let n = unsafe { libc::getloadavg(loads.as_mut_ptr(), 3) };
    if n <= 0 {
        None
    } else {
        Some(loads[0])
    }
}

#[cfg(target_os = "linux")]
fn read_cpu_jiffies() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/stat").ok()?;
    let line = s.lines().next()?; // "cpu  user nice system idle iowait irq softirq steal ..."
    let fields: Vec<u64> = line.split_whitespace().skip(1).filter_map(|f| f.parse().ok()).collect();
    if fields.len() < 4 {
        return None;
    }
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0); // idle + iowait
    let total: u64 = fields.iter().sum();
    Some((total, idle))
}

#[cfg(not(target_os = "linux"))]
fn read_cpu_jiffies() -> Option<(u64, u64)> {
    None
}

fn cpu_busy_pct(prev: (u64, u64), now: (u64, u64)) -> Option<f64> {
    let (prev_total, prev_idle) = prev;
    let (total, idle) = now;
    let total_delta = total.checked_sub(prev_total)?;
    let idle_delta = idle.checked_sub(prev_idle)?;
    if total_delta == 0 {
        return None;
    }
    Some(100.0 * (1.0 - idle_delta as f64 / total_delta as f64))
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
    TokioResolver::builder_with_config(ResolverConfig::udp_and_tcp(&CLOUDFLARE), TokioRuntimeProvider::default())
        .build()
        .expect("failed to build default DNS resolver")
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

pub(crate) fn classify_dns_error(err: &NetError) -> ErrorKind {
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
        width
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
                    } else {
                        "done".to_string()
                    };

                    let bar = progress_bar(done, total, 24);
                    let pct = if total > 0 { done as f64 / total as f64 * 100.0 } else { 100.0 };

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
                    "done".to_string()
                };

                let pct = if total > 0 { done as f64 / total as f64 * 100.0 } else { 100.0 };
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

#[cfg(test)]
mod tests {
    use super::*;

    // progress_bar

    #[test]
    fn progress_bar_zero_total_returns_full_bar() {
        let bar = progress_bar(0, 0, 4);
        assert_eq!(bar, "[████]");
    }

    #[test]
    fn progress_bar_half_done() {
        let bar = progress_bar(1, 2, 4);
        assert_eq!(bar, "[██░░]");
    }

    #[test]
    fn progress_bar_fully_done() {
        let bar = progress_bar(5, 5, 4);
        assert_eq!(bar, "[████]");
    }

    #[test]
    fn progress_bar_zero_done_nonzero_total() {
        let bar = progress_bar(0, 10, 4);
        assert_eq!(bar, "[░░░░]");
    }

    // format_eta

    #[test]
    fn format_eta_seconds() {
        assert_eq!(format_eta(45.0), "45s");
    }

    #[test]
    fn format_eta_minutes() {
        assert_eq!(format_eta(90.0), "1m30s");
    }

    #[test]
    fn format_eta_hours() {
        assert_eq!(format_eta(3661.0), "1h01m");
    }

    // AdaptiveSemaphore

    #[tokio::test]
    async fn adaptive_semaphore_starts_at_floor_and_allows_that_many_immediately() {
        let sem = AdaptiveSemaphore::new(100, "test");
        // floor = (100/8).clamp(4, 100) = 12
        let permits: Vec<_> = futures_util::future::join_all((0..12).map(|_| sem.acquire_owned())).await;
        assert_eq!(permits.len(), 12);
        // the 13th permit should not be immediately available (floor exhausted, no grow tick yet)
        assert!(sem.sem.try_acquire().is_err());
    }

    #[tokio::test]
    async fn adaptive_semaphore_floor_is_clamped_between_4_and_ceiling() {
        // `new` spawns the background scaler via `tokio::spawn`, so this needs a runtime even
        // though nothing here awaits it.
        assert_eq!(AdaptiveSemaphore::new(4, "tiny").floor, 4);
        assert_eq!(AdaptiveSemaphore::new(1, "tinier").floor, 1); // floor can't exceed ceiling
        assert_eq!(AdaptiveSemaphore::new(800, "big").floor, 100);
    }

    // cpu_busy_pct

    #[test]
    fn cpu_busy_pct_all_idle_is_zero() {
        let prev = (1000, 800);
        let now = (1100, 900); // +100 total, +100 idle
        assert_eq!(cpu_busy_pct(prev, now), Some(0.0));
    }

    #[test]
    fn cpu_busy_pct_all_busy_is_hundred() {
        let prev = (1000, 800);
        let now = (1100, 800); // +100 total, +0 idle
        assert_eq!(cpu_busy_pct(prev, now), Some(100.0));
    }

    #[test]
    fn cpu_busy_pct_half_busy() {
        let prev = (1000, 800);
        let now = (1200, 900); // +200 total, +100 idle -> 50% busy
        assert_eq!(cpu_busy_pct(prev, now), Some(50.0));
    }

    #[test]
    fn cpu_busy_pct_no_time_elapsed_is_none() {
        assert_eq!(cpu_busy_pct((1000, 800), (1000, 800)), None);
    }

    #[test]
    fn cpu_busy_pct_counter_went_backwards_is_none() {
        // e.g. /proc/stat counters reset or jiffy wraparound — don't report garbage
        assert_eq!(cpu_busy_pct((1000, 800), (900, 700)), None);
    }

    // decide_scale

    #[test]
    fn decide_scale_high_load_shrinks() {
        // load 1.2 >= LOAD_TARGET 0.9 -> hot
        assert_eq!(decide_scale(100, 10, 500, Some(1.2), Some(10.0), None), ScaleAction::Shrink(25));
    }

    #[test]
    fn decide_scale_high_cpu_alone_shrinks_even_with_low_load() {
        // load is comfortably low but CPU is pegged — any one signal being hot is enough
        assert_eq!(decide_scale(100, 10, 500, Some(0.1), Some(95.0), None), ScaleAction::Shrink(25));
    }

    #[test]
    fn decide_scale_high_network_error_rate_alone_shrinks_even_with_low_load_and_cpu() {
        // this is the front CPU/load can't see: an I/O-bound stage hammering the network while
        // local CPU and load both sit near zero.
        assert_eq!(decide_scale(100, 10, 500, Some(0.1), Some(5.0), Some(40.0)), ScaleAction::Shrink(25));
    }

    #[test]
    fn decide_scale_low_load_and_cpu_grows() {
        assert_eq!(decide_scale(100, 10, 500, Some(0.2), Some(10.0), None), ScaleAction::Grow(10));
    }

    #[test]
    fn decide_scale_middling_load_holds_steady() {
        // 0.63 (=0.9*0.7) <= load < 0.9 is neither hot nor cool
        assert_eq!(decide_scale(100, 10, 500, Some(0.8), Some(10.0), None), ScaleAction::Hold);
    }

    #[test]
    fn decide_scale_low_load_but_high_cpu_holds_not_grows() {
        // cool requires every signal comfortable; CPU still busy blocks growth
        assert_eq!(decide_scale(100, 10, 500, Some(0.1), Some(80.0), None), ScaleAction::Hold);
    }

    #[test]
    fn decide_scale_low_load_and_cpu_but_rising_errors_holds_not_grows() {
        // CPU and load both look great, but the network is starting to misbehave — still
        // shouldn't grow into that.
        assert_eq!(decide_scale(100, 10, 500, Some(0.1), Some(5.0), Some(15.0)), ScaleAction::Hold);
    }

    #[test]
    fn decide_scale_low_error_rate_permits_growth() {
        assert_eq!(decide_scale(100, 10, 500, Some(0.1), Some(5.0), Some(2.0)), ScaleAction::Grow(10));
    }

    #[test]
    fn decide_scale_missing_load_reading_is_treated_as_hot() {
        // getloadavg() failed -> fail safe, don't blindly grow, back off if above floor
        assert_eq!(decide_scale(100, 10, 500, None, Some(10.0), None), ScaleAction::Shrink(25));
    }

    #[test]
    fn decide_scale_missing_load_at_floor_holds_cannot_shrink_further() {
        assert_eq!(decide_scale(10, 10, 500, None, Some(10.0), None), ScaleAction::Hold);
    }

    #[test]
    fn decide_scale_missing_cpu_reading_low_load_still_grows() {
        // macOS has no /proc/stat -> cpu_pct is always None there; load average alone should
        // still be able to drive growth (cool's cpu_pct check defaults to true when absent).
        assert_eq!(decide_scale(100, 10, 500, Some(0.1), None, None), ScaleAction::Grow(10));
    }

    #[test]
    fn decide_scale_missing_error_rate_never_blocks_growth() {
        // a module that hasn't wired up record_result (or hasn't hit MIN_SAMPLES yet) must
        // behave exactly as if the network signal didn't exist — opt-in, not a requirement.
        assert_eq!(decide_scale(100, 10, 500, Some(0.1), Some(5.0), None), ScaleAction::Grow(10));
    }

    #[test]
    fn decide_scale_at_floor_cannot_shrink_further() {
        assert_eq!(decide_scale(10, 10, 500, Some(1.5), Some(99.0), None), ScaleAction::Hold);
    }

    #[test]
    fn decide_scale_at_ceiling_cannot_grow_further() {
        assert_eq!(decide_scale(500, 10, 500, Some(0.1), Some(1.0), None), ScaleAction::Hold);
    }

    #[test]
    fn decide_scale_shrink_never_cuts_below_floor() {
        // cur=12, floor=10: a 25% cut of 12 is 3, which would land at 9 (below floor) —
        // must clamp to exactly cur-floor=2 instead.
        assert_eq!(decide_scale(12, 10, 500, Some(1.5), Some(99.0), None), ScaleAction::Shrink(2));
    }

    #[test]
    fn decide_scale_grow_never_exceeds_ceiling() {
        // cur=495, ceiling=500: a 10% grow of 495 is 49, which would overshoot — must clamp to
        // exactly ceiling-cur=5 instead.
        assert_eq!(decide_scale(495, 10, 500, Some(0.1), Some(1.0), None), ScaleAction::Grow(5));
    }

    #[test]
    fn decide_scale_shrink_step_is_at_least_one() {
        // cur=11, floor=10: 25% of 11 rounds down to 2 via integer division... but even a
        // tiny cur must still make forward progress toward the floor.
        assert_eq!(decide_scale(11, 10, 500, Some(1.5), Some(99.0), None), ScaleAction::Shrink(1));
    }

    #[test]
    fn decide_scale_grow_step_is_at_least_one() {
        // cur=5: 10% of 5 rounds down to 0 via integer division, but growth must still make
        // forward progress — never a permanently-stuck no-op.
        assert_eq!(decide_scale(5, 4, 500, Some(0.1), Some(1.0), None), ScaleAction::Grow(1));
    }

    // AdaptiveSemaphore::record_result / net-error-rate wiring

    #[tokio::test]
    async fn record_result_counts_only_failures_as_errors() {
        let sem = AdaptiveSemaphore::new(500, "test");
        for _ in 0..15 {
            sem.record_result(true);
        }
        for _ in 0..5 {
            sem.record_result(false);
        }
        assert_eq!(sem.attempts.load(Ordering::Relaxed), 20);
        assert_eq!(sem.errors.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn min_samples_threshold_is_below_a_typical_tick_batch() {
        // sanity check on the constant relationship, not the algorithm: with a 3s tick and
        // realistic per-domain scan latency, MIN_SAMPLES should be reachable inside one tick
        // for any stage past its floor, or the network signal would never actually engage.
        assert!(MIN_SAMPLES_FOR_ERROR_SIGNAL <= 20);
    }
}
