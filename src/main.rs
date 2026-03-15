use std::error::Error as _;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{ResolveError, TokioResolver};
use reqwest::header::{HeaderMap, HeaderValue, RANGE};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::Client;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::{FromDer, X509Certificate};

const DISPATCH_BATCH_SIZE: usize = 255;
const DISPATCH_BATCH_SLEEP: Duration = Duration::from_millis(500);
const STANDARD_PORTS: [u16; 10] = [80, 443, 22, 21, 25, 587, 3306, 5432, 6379, 8080];
const EXTRA_PORTS: [u16; 1] = [8443];

#[derive(Clone)]
struct ReqwestHickoryResolver {
    resolver: TokioResolver,
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

// ---- CLI ----

#[derive(Parser, Debug)]
#[command(name = "helvetiscan")]
#[command(about = "Swiss internet scanner - HTTP, DNS, TLS and port intelligence for the .ch namespace")]
struct Cli {
    /// Scan only this single domain.
    #[arg(long)]
    domain: Option<String>,

    /// Run HTTP, DNS, TLS, and ports scans together.
    #[arg(long, default_value_t = false)]
    all: bool,

    #[arg(long, default_value = "data/domains.duckdb")]
    db: PathBuf,

    /// Full rescan shortcut using default arguments.
    #[arg(long)]
    full: Option<FullTarget>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Populate domains.duckdb from a plain-text domain list (one domain/line).
    /// Safe to re-run: skips if the table already has rows.
    Init(InitArgs),
    /// HTTP scan: fetch status, title, server headers for all pending domains.
    Scan(ScanArgs),
    /// Resolve DNS metadata for all domains missing a dns_info row.
    Dns(DnsArgs),
    /// Scan TLS metadata for all domains missing a tls_info row.
    Tls(TlsArgs),
    /// Scan a small fixed set of TCP ports for all domains missing a ports_info row.
    Ports(PortsArgs),
    /// Discover subdomains via DNS zone transfer (AXFR) and NS/MX record harvest.
    Subdomains(SubdomainsArgs),
    /// Fetch WHOIS registrar and registration date for all domains.
    Whois(WhoisArgs),
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum BackfillMode {
    Ip,
    Server,
    Full,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum FullTarget {
    Domain,
    Dns,
    Tls,
    Ports,
    Subdomains,
    All,
}

#[derive(Parser, Debug)]
struct InitArgs {
    #[arg(long, default_value = "data/sorted_domains.txt")]
    input: PathBuf,

    #[arg(long, default_value = "data/domains.duckdb")]
    db: PathBuf,
}

#[derive(Parser, Debug, Clone)]
struct ScanArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    db: PathBuf,

    #[arg(long)]
    domain: Option<String>,

    /// Number of rows per DuckDB write transaction.
    #[arg(long, default_value_t = 1_000)]
    write_batch_size: usize,

    #[arg(long, default_value_t = 500)]
    concurrency: usize,

    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    connect_timeout: Duration,

    #[arg(long, default_value = "20s", value_parser = parse_duration)]
    request_timeout: Duration,

    #[arg(long, default_value_t = 128)]
    max_kbytes: usize,

    #[arg(long, default_value_t = 5)]
    max_redirects: usize,

    #[arg(long, default_value = "helvetiscan/1.0")]
    user_agent: String,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    retry_errors: Option<String>,

    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    progress_interval: Duration,

    #[arg(skip)]
    no_progress: bool,

    /// Stop after this many successful HTTP 200 responses have been written.
    #[arg(long = "limit-success")]
    limit_success: Option<usize>,

    /// Re-scan a subset of existing HTTP rows: ip, server, or all domain rows.
    #[arg(long)]
    backfill: Option<BackfillMode>,
}

#[derive(Parser, Debug, Clone)]
struct DnsArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    db: PathBuf,

    #[arg(long)]
    domain: Option<String>,

    #[arg(long, default_value_t = 1_000)]
    write_batch_size: usize,

    #[arg(long, default_value_t = 250)]
    concurrency: usize,

    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    progress_interval: Duration,

    #[arg(skip)]
    no_progress: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    retry_errors: Option<String>,

    #[arg(long, default_value_t = false)]
    rescan: bool,
}

#[derive(Parser, Debug, Clone)]
struct TlsArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    db: PathBuf,

    #[arg(long)]
    domain: Option<String>,

    #[arg(long, default_value_t = 250)]
    write_batch_size: usize,

    #[arg(long, default_value_t = 150)]
    concurrency: usize,

    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    connect_timeout: Duration,

    #[arg(long, default_value = "8s", value_parser = parse_duration)]
    handshake_timeout: Duration,

    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    progress_interval: Duration,

    #[arg(skip)]
    no_progress: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    retry_errors: Option<String>,

    #[arg(long, default_value_t = false)]
    rescan: bool,
}

#[derive(Parser, Debug, Clone)]
struct PortsArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    db: PathBuf,

    #[arg(long)]
    domain: Option<String>,

    #[arg(long, default_value_t = 500)]
    write_batch_size: usize,

    #[arg(long, default_value_t = 300)]
    concurrency: usize,

    #[arg(long, default_value = "800ms", value_parser = parse_duration)]
    connect_timeout: Duration,

    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    progress_interval: Duration,

    #[arg(skip)]
    no_progress: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    retry_errors: Option<String>,

    #[arg(long, default_value_t = false)]
    rescan: bool,
}

#[derive(Parser, Debug, Clone)]
struct SubdomainsArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    db: PathBuf,

    #[arg(long)]
    domain: Option<String>,

    #[arg(long, default_value_t = 200)]
    concurrency: usize,

    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    progress_interval: Duration,

    #[arg(long, default_value_t = 500)]
    write_batch_size: usize,

    /// Re-probe domains already present in the subdomains table.
    #[arg(long, default_value_t = false)]
    rescan: bool,

    #[arg(skip)]
    no_progress: bool,
}

#[derive(Parser, Debug, Clone)]
struct WhoisArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    db: PathBuf,

    #[arg(long)]
    domain: Option<String>,

    #[arg(long, default_value_t = 500)]
    write_batch_size: usize,

    /// Keep concurrency low — whois.nic.ch rate-limits aggressively.
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    connect_timeout: Duration,

    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    progress_interval: Duration,

    #[arg(skip)]
    no_progress: bool,

    /// Re-fetch domains that already have a whois_registrar value.
    #[arg(long, default_value_t = false)]
    rescan: bool,
}

impl Default for WhoisArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.duckdb"),
            domain: None,
            write_batch_size: 500,
            concurrency: 5,
            connect_timeout: Duration::from_secs(5),
            progress_interval: Duration::from_secs(1),
            no_progress: false,
            rescan: false,
        }
    }
}

impl Default for ScanArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.duckdb"),
            domain: None,
            write_batch_size: 1_000,
            concurrency: 500,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
            max_kbytes: 128,
            max_redirects: 5,
            user_agent: "helvetiscan/1.0".to_string(),
            progress_interval: Duration::from_secs(1),
            no_progress: false,
            limit_success: None,
            backfill: None,
            retry_errors: None,
        }
    }
}

impl Default for DnsArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.duckdb"),
            domain: None,
            write_batch_size: 1_000,
            concurrency: 250,
            progress_interval: Duration::from_secs(1),
            no_progress: false,
            retry_errors: None,
            rescan: false,
        }
    }
}

impl Default for TlsArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.duckdb"),
            domain: None,
            write_batch_size: 250,
            concurrency: 150,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(8),
            progress_interval: Duration::from_secs(1),
            no_progress: false,
            retry_errors: None,
            rescan: false,
        }
    }
}

impl Default for SubdomainsArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.duckdb"),
            domain: None,
            concurrency: 200,
            progress_interval: Duration::from_secs(1),
            write_batch_size: 500,
            rescan: false,
            no_progress: false,
        }
    }
}

impl ScanArgs {
    fn max_bytes(&self) -> usize {
        self.max_kbytes.saturating_mul(1024)
    }
}

impl Default for PortsArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.duckdb"),
            domain: None,
            write_batch_size: 500,
            concurrency: 300,
            connect_timeout: Duration::from_millis(800),
            progress_interval: Duration::from_secs(1),
            no_progress: false,
            retry_errors: None,
            rescan: false,
        }
    }
}

// ---- domain types ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
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
    fn as_str(self) -> &'static str {
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
enum ScanStatus {
    Ok,
    Error,
}

impl ScanStatus {
    fn as_str(self) -> &'static str {
        match self {
            ScanStatus::Ok => "ok",
            ScanStatus::Error => "error",
        }
    }
}

#[derive(Debug)]
struct Row {
    domain: String,
    status: ScanStatus,
    ip: Option<String>,
    final_url: Option<String>,
    status_code: Option<u16>,
    title: Option<String>,
    body_hash: Option<String>,
    server: Option<String>,
    powered_by: Option<String>,
    error_kind: Option<ErrorKind>,
    elapsed_ms: u64,
}

#[derive(Debug, Clone)]
struct DnsRow {
    domain: String,
    status: ScanStatus,
    error_kind: Option<ErrorKind>,
    ns: Vec<String>,
    mx: Vec<String>,
    cname: Option<String>,
    a: Vec<String>,
    aaaa: Vec<String>,
    txt_spf: Option<String>,
    txt_dmarc: Option<String>,
    ttl: Option<i32>,
    ptr: Option<String>,
    dnssec: Option<bool>,
}

#[derive(Debug, Clone)]
struct TlsRow {
    domain: String,
    status: ScanStatus,
    error_kind: Option<ErrorKind>,
    cert_issuer: Option<String>,
    cert_subject: Option<String>,
    valid_from: Option<NaiveDate>,
    valid_to: Option<NaiveDate>,
    days_remaining: Option<i32>,
    expired: Option<bool>,
    self_signed: Option<bool>,
    tls_version: Option<String>,
    cipher: Option<String>,
}

#[derive(Debug, Clone)]
struct PortsRow {
    domain: String,
    status: ScanStatus,
    error_kind: Option<ErrorKind>,
    ip: Option<String>,
    p80: bool,
    p443: bool,
    p22: bool,
    p21: bool,
    p25: bool,
    p587: bool,
    p3306: bool,
    p5432: bool,
    p6379: bool,
    p8080: bool,
    p8443: bool,
    open_ports: Vec<i32>,
}

#[derive(Debug, Clone)]
struct WhoisRow {
    domain: String,
    registrar: Option<String>,
    whois_created: Option<NaiveDate>,
}

#[derive(Debug)]
struct SubdomainRow {
    domain: String,
    found: Vec<String>,   // FQDNs of discovered subdomains
    source: &'static str, // "axfr" | "mx_ns"
}

#[derive(Debug)]
struct Progress {
    started: Instant,
    total: u64,
    enqueued: AtomicU64,
    completed: AtomicU64,
    http_200: AtomicU64,
    timeout: AtomicU64,
}

impl Progress {
    fn new(total: u64) -> Self {
        Self {
            started: Instant::now(),
            total,
            enqueued: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            http_200: AtomicU64::new(0),
            timeout: AtomicU64::new(0),
        }
    }
}

// ---- main ----

fn raise_nofile_limit() {
    #[cfg(unix)]
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            let target = rl.rlim_max.min(65_536);
            if rl.rlim_cur < target {
                rl.rlim_cur = target;
                libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    raise_nofile_limit();
    let cli = Cli::parse();
    match (cli.domain, cli.all, cli.db, cli.full, cli.command) {
        (Some(domain), true, db, None, None) => cmd_single_all(db, &domain).await,
        (Some(_), false, _, None, None) => Err(anyhow!("use --domain together with --all or a subcommand")),
        (Some(_), true, _, Some(_), _) => Err(anyhow!("use either --all or --full, not both")),
        (Some(_), true, _, _, Some(_)) => Err(anyhow!("use either top-level --domain --all or a subcommand, not both")),
        (Some(_), false, _, Some(_), _) => Err(anyhow!("use either --domain with a subcommand or use --full")),
        (Some(_), false, _, _, Some(_)) => Err(anyhow!("top-level --domain is only supported with --all; use command --domain otherwise")),
        (None, false, _db, Some(_), Some(_)) => Err(anyhow!("use either a subcommand or --full, not both")),
        (None, false, db, Some(FullTarget::Domain), None) => {
            let args = ScanArgs { db, backfill: Some(BackfillMode::Full), ..ScanArgs::default() };
            cmd_scan(args).await
        }
        (None, false, db, Some(FullTarget::Dns), None) => {
            let args = DnsArgs { db, rescan: true, ..DnsArgs::default() };
            cmd_dns(args).await
        }
        (None, false, db, Some(FullTarget::Tls), None) => {
            let args = TlsArgs { db, rescan: true, ..TlsArgs::default() };
            cmd_tls(args).await
        }
        (None, false, db, Some(FullTarget::Ports), None) => {
            let args = PortsArgs { db, rescan: true, ..PortsArgs::default() };
            cmd_ports(args).await
        }
        (None, false, db, Some(FullTarget::Subdomains), None) => {
            let args = SubdomainsArgs { db, rescan: true, ..SubdomainsArgs::default() };
            cmd_subdomains(args).await
        }
        (None, false, db, Some(FullTarget::All), None) => {
            cmd_scan(ScanArgs { db: db.clone(), ..ScanArgs::default() }).await?;
            cmd_dns(DnsArgs { db: db.clone(), ..DnsArgs::default() }).await?;
            cmd_tls(TlsArgs { db: db.clone(), ..TlsArgs::default() }).await?;
            cmd_ports(PortsArgs { db: db.clone(), ..PortsArgs::default() }).await?;
            cmd_subdomains(SubdomainsArgs { db, ..SubdomainsArgs::default() }).await
        }
        (None, false, _, None, Some(Command::Init(args))) => cmd_init(args),
        (None, false, _, None, Some(Command::Scan(args))) => cmd_scan(args).await,
        (None, false, _, None, Some(Command::Dns(args))) => cmd_dns(args).await,
        (None, false, _, None, Some(Command::Tls(args))) => cmd_tls(args).await,
        (None, false, _, None, Some(Command::Ports(args))) => cmd_ports(args).await,
        (None, false, _, None, Some(Command::Subdomains(args))) => cmd_subdomains(args).await,
        (None, false, _, None, Some(Command::Whois(args))) => cmd_whois(args).await,
        (None, true, _, _, _) => Err(anyhow!("--all requires --domain")),
        (None, false, _, None, None) => Err(anyhow!("missing command: use a subcommand, or --domain <domain> --all, or --full <domain|dns|tls>")),
    }
}

// ---- init subcommand ----

fn cmd_init(args: InitArgs) -> Result<()> {
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

fn ensure_schema(conn: &duckdb::Connection) -> Result<()> {
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

        CREATE TABLE IF NOT EXISTS ports_info (
            domain     VARCHAR PRIMARY KEY,
            status     VARCHAR,
            error_kind VARCHAR,
            ip         VARCHAR,
            p80        BOOLEAN, p443  BOOLEAN,
            p22        BOOLEAN, p21   BOOLEAN,
            p25        BOOLEAN, p587  BOOLEAN,
            p3306      BOOLEAN, p5432 BOOLEAN,
            p6379      BOOLEAN, p8080 BOOLEAN, p8443 BOOLEAN,
            open_ports INTEGER[],
            scanned_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            domain        VARCHAR,
            subdomain     VARCHAR,
            source        VARCHAR,
            discovered_at TIMESTAMP,
            PRIMARY KEY (domain, subdomain)
        );
    ",
    )?;
    Ok(())
}

fn append_empty_domain_row(appender: &mut duckdb::Appender<'_>, domain: &str) -> Result<()> {
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

fn ensure_domain_exists(db: &PathBuf, domain: &str) -> Result<String> {
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

async fn cmd_single_all(db: PathBuf, domain: &str) -> Result<()> {
    let domain = ensure_domain_exists(&db, domain)?;
    cmd_scan(ScanArgs {
        db: db.clone(),
        domain: Some(domain.clone()),
        no_progress: true,
        ..ScanArgs::default()
    })
    .await?;
    cmd_dns(DnsArgs {
        db: db.clone(),
        domain: Some(domain.clone()),
        no_progress: true,
        ..DnsArgs::default()
    })
    .await?;
    cmd_tls(TlsArgs {
        db: db.clone(),
        domain: Some(domain.clone()),
        no_progress: true,
        ..TlsArgs::default()
    })
    .await?;
    cmd_ports(PortsArgs {
        db: db.clone(),
        domain: Some(domain.clone()),
        no_progress: true,
        ..PortsArgs::default()
    })
    .await?;
    print_single_domain_summary(&db, &domain)
}

struct SummaryRow {
    scan: &'static str,
    status: String,
    error_kind: String,
    details: String,
}

fn print_single_domain_summary(db: &PathBuf, domain: &str) -> Result<()> {
    let conn = duckdb::Connection::open(db).with_context(|| format!("open duckdb {:?}", db))?;
    let mut rows = Vec::new();

    let domain_row = conn.query_row(
        "SELECT status, error_kind, final_url, status_code, title, server, powered_by
         FROM domains WHERE domain = ?1",
        duckdb::params![domain],
        |r| {
            Ok(SummaryRow {
                scan: "domains",
                status: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                error_kind: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                details: format!(
                    "code={} url={} title={} server={} powered_by={}",
                    r.get::<_, Option<i32>>(3)?.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                    r.get::<_, Option<String>>(2)?.unwrap_or_else(|| "-".to_string()),
                    truncate_cell(&r.get::<_, Option<String>>(4)?.unwrap_or_else(|| "-".to_string()), 48),
                    r.get::<_, Option<String>>(5)?.unwrap_or_else(|| "-".to_string()),
                    r.get::<_, Option<String>>(6)?.unwrap_or_else(|| "-".to_string()),
                ),
            })
        },
    )?;
    rows.push(domain_row);

    let dns_row = conn.query_row(
        "SELECT status, error_kind, CAST(a AS VARCHAR), CAST(ns AS VARCHAR)
         FROM dns_info WHERE domain = ?1",
        duckdb::params![domain],
        |r| {
            Ok(SummaryRow {
                scan: "dns",
                status: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                error_kind: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                details: format!(
                    "a={} ns={}",
                    truncate_cell(&r.get::<_, Option<String>>(2)?.unwrap_or_else(|| "[]".to_string()), 32),
                    truncate_cell(&r.get::<_, Option<String>>(3)?.unwrap_or_else(|| "[]".to_string()), 32),
                ),
            })
        },
    )?;
    rows.push(dns_row);

    let tls_row = conn.query_row(
        "SELECT status, error_kind, tls_version, cipher, cert_issuer
         FROM tls_info WHERE domain = ?1",
        duckdb::params![domain],
        |r| {
            Ok(SummaryRow {
                scan: "tls",
                status: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                error_kind: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                details: format!(
                    "ver={} cipher={} issuer={}",
                    r.get::<_, Option<String>>(2)?.unwrap_or_else(|| "-".to_string()),
                    truncate_cell(&r.get::<_, Option<String>>(3)?.unwrap_or_else(|| "-".to_string()), 20),
                    truncate_cell(&r.get::<_, Option<String>>(4)?.unwrap_or_else(|| "-".to_string()), 28),
                ),
            })
        },
    )?;
    rows.push(tls_row);

    let ports_row = conn.query_row(
        "SELECT status, error_kind, CAST(open_ports AS VARCHAR)
         FROM ports_info WHERE domain = ?1",
        duckdb::params![domain],
        |r| {
            Ok(SummaryRow {
                scan: "ports",
                status: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                error_kind: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                details: format!(
                    "open_ports={}",
                    truncate_cell(&r.get::<_, Option<String>>(2)?.unwrap_or_else(|| "[]".to_string()), 40),
                ),
            })
        },
    )?;
    rows.push(ports_row);

    render_summary_table(domain, &rows);
    Ok(())
}

fn truncate_cell(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        let mut out = value.chars().take(max_len.saturating_sub(3)).collect::<String>();
        out.push_str("...");
        out
    }
}

fn render_summary_table(domain: &str, rows: &[SummaryRow]) {
    let scan_w = rows.iter().map(|r| r.scan.len()).max().unwrap_or(4).max(4);
    let status_w = rows.iter().map(|r| r.status.len()).max().unwrap_or(6).max(6);
    let error_w = rows.iter().map(|r| r.error_kind.len()).max().unwrap_or(10).max(10);
    let header = format!(
        "| {scan:<scan_w$} | {status:<status_w$} | {error:<error_w$} | details |",
        scan = "scan",
        status = "status",
        error = "error_kind",
        scan_w = scan_w,
        status_w = status_w,
        error_w = error_w,
    );
    let sep = format!(
        "|-{:-<scan_w$}-|-{:-<status_w$}-|-{:-<error_w$}-|---------|",
        "",
        "",
        "",
        scan_w = scan_w,
        status_w = status_w,
        error_w = error_w,
    );

    println!();
    println!("domain: {domain}");
    println!("{header}");
    println!("{sep}");
    for row in rows {
        println!(
            "| {scan:<scan_w$} | {status:<status_w$} | {error:<error_w$} | {details} |",
            scan = row.scan,
            status = row.status,
            error = row.error_kind,
            details = row.details,
            scan_w = scan_w,
            status_w = status_w,
            error_w = error_w,
        );
    }
}

// ---- scan subcommand ----

fn pending_domains_sql(backfill: Option<BackfillMode>) -> &'static str {
    match backfill {
        Some(BackfillMode::Ip) => {
            "SELECT domain FROM domains WHERE updated_at IS NOT NULL AND ip IS NULL ORDER BY domain"
        }
        Some(BackfillMode::Server) => {
            "SELECT domain FROM domains WHERE updated_at IS NOT NULL AND server IS NULL ORDER BY domain"
        }
        Some(BackfillMode::Full) => "SELECT domain FROM domains ORDER BY domain",
        None => "SELECT domain FROM domains WHERE updated_at IS NULL ORDER BY domain",
    }
}

fn load_pending_domains(
    conn: &duckdb::Connection,
    domain: Option<&str>,
    backfill: Option<BackfillMode>,
    retry_errors: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(domain) = domain {
        return Ok(vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]);
    }
    if let Some(kind) = retry_errors {
        let mut stmt = conn.prepare(
            "SELECT domain FROM domains WHERE error_kind = ? ORDER BY domain",
        )?;
        let domains: Vec<String> = stmt
            .query_map([kind], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        return Ok(domains);
    }
    let sql = pending_domains_sql(backfill);
    let mut stmt = conn.prepare(sql)?;
    let domains: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(domains)
}

fn load_scan_targets(
    conn: &duckdb::Connection,
    domain: Option<&str>,
    table: &str,
    timestamp_col: &str,
    rescan: bool,
    retry_errors: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(domain) = domain {
        return Ok(vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]);
    }
    if let Some(kind) = retry_errors {
        let sql = format!("SELECT domain FROM {table} WHERE error_kind = ? ORDER BY domain");
        let mut stmt = conn.prepare(&sql)?;
        let domains: Vec<String> = stmt
            .query_map([kind], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        return Ok(domains);
    }
    let sql = if rescan {
        "SELECT domain FROM domains ORDER BY domain".to_string()
    } else {
        format!(
            "SELECT d.domain
             FROM domains d
             LEFT JOIN {table} t ON t.domain = d.domain
             WHERE t.domain IS NULL OR t.{timestamp_col} IS NULL
             ORDER BY d.domain"
        )
    };
    let mut stmt = conn.prepare(&sql)?;
    let domains: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(domains)
}

async fn cmd_scan(args: ScanArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    if args.max_kbytes == 0 {
        return Err(anyhow!("--max-kbytes must be > 0"));
    }
    if args.max_bytes() > 16 * 1024 * 1024 {
        return Err(anyhow!(
            "--max-kbytes is unreasonably large (>{} bytes)",
            16 * 1024 * 1024
        ));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    let pending = load_pending_domains(&conn, args.domain.as_deref(), args.backfill, args.retry_errors.as_deref())?;
    drop(conn);

    eprintln!("scan: {} domains pending", pending.len());
    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let client = build_client(&args, resolver.clone())?;
    let progress = Arc::new(Progress::new(pending.len() as u64));

    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<Row>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = args.write_batch_size;
        let limit = args.limit_success;
        let progress = progress.clone();
        move || writer_loop_db(db_path, result_rx, progress, done_tx, batch_size, limit)
    });

    let reader_handle = tokio::spawn({
        let progress = progress.clone();
        async move {
            for domain in pending {
                if work_tx.send(domain).await.is_err() {
                    break;
                }
                progress.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Ok::<(), anyhow::Error>(())
        }
    });

    let progress_handle = if args.no_progress {
        None
    } else {
        Some(tokio::spawn(progress_reporter(
            progress.clone(),
            args.progress_interval,
            done_rx,
        )))
    };

    let sem = Semaphore::new(args.concurrency);
    let dispatcher_handle = tokio::spawn(dispatcher_loop(
        work_rx,
        result_tx,
        sem,
        client,
        resolver,
        args.clone(),
    ));

    reader_handle
        .await
        .context("reader task panicked")?
        .context("reader failed")?;
    dispatcher_handle
        .await
        .context("dispatcher task panicked")?
        .context("dispatcher failed")?;
    writer_handle
        .await
        .context("writer task panicked")?
        .context("writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

// ---- dns subcommand ----

async fn cmd_dns(args: DnsArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    if args.retry_errors.is_some() && args.rescan {
        return Err(anyhow!("--retry-errors and --rescan are mutually exclusive"));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    let pending = load_scan_targets(&conn, args.domain.as_deref(), "dns_info", "resolved_at", args.rescan, args.retry_errors.as_deref())?;
    drop(conn);

    eprintln!("dns: {} domains pending", pending.len());
    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let progress = Arc::new(Progress::new(pending.len() as u64));
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<DnsRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = args.write_batch_size;
        let progress = progress.clone();
        move || writer_loop_dns(db_path, result_rx, progress, done_tx, batch_size)
    });

    let reader_handle = tokio::spawn({
        let progress = progress.clone();
        async move {
            for domain in pending {
                if work_tx.send(domain).await.is_err() {
                    break;
                }
                progress.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Ok::<(), anyhow::Error>(())
        }
    });

    let progress_handle = if args.no_progress {
        None
    } else {
        Some(tokio::spawn(progress_reporter(
            progress.clone(),
            args.progress_interval,
            done_rx,
        )))
    };

    let dispatcher_handle = tokio::spawn(dispatcher_loop_dns(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        resolver,
        args.concurrency,
    ));

    reader_handle
        .await
        .context("dns reader task panicked")?
        .context("dns reader failed")?;
    dispatcher_handle
        .await
        .context("dns dispatcher task panicked")?
        .context("dns dispatcher failed")?;
    writer_handle
        .await
        .context("dns writer task panicked")?
        .context("dns writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

// ---- tls subcommand ----

async fn cmd_tls(args: TlsArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    if args.retry_errors.is_some() && args.rescan {
        return Err(anyhow!("--retry-errors and --rescan are mutually exclusive"));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    let pending = load_scan_targets(&conn, args.domain.as_deref(), "tls_info", "scanned_at", args.rescan, args.retry_errors.as_deref())?;
    drop(conn);

    eprintln!("tls: {} domains pending", pending.len());
    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let tls_connector = build_tls_connector();
    let progress = Arc::new(Progress::new(pending.len() as u64));
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<TlsRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = args.write_batch_size;
        let progress = progress.clone();
        move || writer_loop_tls(db_path, result_rx, progress, done_tx, batch_size)
    });

    let reader_handle = tokio::spawn({
        let progress = progress.clone();
        async move {
            for domain in pending {
                if work_tx.send(domain).await.is_err() {
                    break;
                }
                progress.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Ok::<(), anyhow::Error>(())
        }
    });

    let progress_handle = if args.no_progress {
        None
    } else {
        Some(tokio::spawn(progress_reporter(
            progress.clone(),
            args.progress_interval,
            done_rx,
        )))
    };

    let dispatcher_handle = tokio::spawn(dispatcher_loop_tls(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        tls_connector,
        resolver,
        args.clone(),
    ));

    reader_handle
        .await
        .context("tls reader task panicked")?
        .context("tls reader failed")?;
    dispatcher_handle
        .await
        .context("tls dispatcher task panicked")?
        .context("tls dispatcher failed")?;
    writer_handle
        .await
        .context("tls writer task panicked")?
        .context("tls writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

// ---- ports subcommand ----

async fn cmd_ports(args: PortsArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    if args.retry_errors.is_some() && args.rescan {
        return Err(anyhow!("--retry-errors and --rescan are mutually exclusive"));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    let pending = load_scan_targets(&conn, args.domain.as_deref(), "ports_info", "scanned_at", args.rescan, args.retry_errors.as_deref())?;
    drop(conn);

    eprintln!("ports: {} domains pending", pending.len());
    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let progress = Arc::new(Progress::new(pending.len() as u64));
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<PortsRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = args.write_batch_size;
        let progress = progress.clone();
        move || writer_loop_ports(db_path, result_rx, progress, done_tx, batch_size)
    });

    let reader_handle = tokio::spawn({
        let progress = progress.clone();
        async move {
            for domain in pending {
                if work_tx.send(domain).await.is_err() {
                    break;
                }
                progress.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Ok::<(), anyhow::Error>(())
        }
    });

    let progress_handle = if args.no_progress {
        None
    } else {
        Some(tokio::spawn(progress_reporter(
            progress.clone(),
            args.progress_interval,
            done_rx,
        )))
    };

    let dispatcher_handle = tokio::spawn(dispatcher_loop_ports(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        resolver,
        args.clone(),
    ));

    reader_handle
        .await
        .context("ports reader task panicked")?
        .context("ports reader failed")?;
    dispatcher_handle
        .await
        .context("ports dispatcher task panicked")?
        .context("ports dispatcher failed")?;
    writer_handle
        .await
        .context("ports writer task panicked")?
        .context("ports writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

// ---- writers ----

fn writer_loop_db(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<Row>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
    limit: Option<usize>,
) -> Result<()> {
    let conn = duckdb::Connection::open(&db_path)
        .with_context(|| format!("writer: open duckdb {:?}", db_path))?;

    let mut batch: Vec<Row> = Vec::with_capacity(batch_size);

    while let Some(row) = result_rx.blocking_recv() {
        if row.status_code == Some(200) {
            progress.http_200.fetch_add(1, Ordering::Relaxed);
        }
        if row.error_kind == Some(ErrorKind::Timeout) {
            progress.timeout.fetch_add(1, Ordering::Relaxed);
        }
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            flush_batch(&conn, &mut batch)?;
        }
        if limit.is_some_and(|l| progress.http_200.load(Ordering::Relaxed) as usize >= l) {
            break;
        }
    }

    if !batch.is_empty() {
        flush_batch(&conn, &mut batch)?;
    }

    let _ = done_tx.send(());
    Ok(())
}

fn writer_loop_dns(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<DnsRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = duckdb::Connection::open(&db_path)
        .with_context(|| format!("dns writer: open duckdb {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            flush_dns_batch(&conn, &mut batch)?;
        }
    }
    if !batch.is_empty() {
        flush_dns_batch(&conn, &mut batch)?;
    }
    let _ = done_tx.send(());
    Ok(())
}

fn writer_loop_tls(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<TlsRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = duckdb::Connection::open(&db_path)
        .with_context(|| format!("tls writer: open duckdb {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            flush_tls_batch(&conn, &mut batch)?;
        }
    }
    if !batch.is_empty() {
        flush_tls_batch(&conn, &mut batch)?;
    }
    let _ = done_tx.send(());
    Ok(())
}

fn writer_loop_ports(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<PortsRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = duckdb::Connection::open(&db_path)
        .with_context(|| format!("ports writer: open duckdb {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            flush_ports_batch(&conn, &mut batch)?;
        }
    }
    if !batch.is_empty() {
        flush_ports_batch(&conn, &mut batch)?;
    }
    let _ = done_tx.send(());
    Ok(())
}

fn flush_batch(conn: &duckdb::Connection, batch: &mut Vec<Row>) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "UPDATE domains SET
                status      = ?1,
                final_url   = ?2,
                status_code = ?3,
                title       = ?4,
                body_hash   = ?5,
                error_kind  = ?6,
                elapsed_ms  = ?7,
                ip          = ?8,
                server      = ?9,
                powered_by  = ?10,
                updated_at  = NOW()
             WHERE domain = ?11",
        )?;

        for row in batch.iter() {
            stmt.execute(duckdb::params![
                row.status.as_str(),
                row.final_url.as_deref(),
                row.status_code.map(|v| v as i32),
                row.title.as_deref(),
                row.body_hash.as_deref(),
                row.error_kind.map(|k| k.as_str()),
                row.elapsed_ms as i64,
                row.ip.as_deref(),
                row.server.as_deref(),
                row.powered_by.as_deref(),
                row.domain.as_str(),
            ])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}

fn flush_dns_batch(conn: &duckdb::Connection, batch: &mut Vec<DnsRow>) -> Result<()> {
    let mut sql = String::from("BEGIN;\n");
    for row in batch.iter() {
        sql.push_str(&format!(
            "INSERT INTO dns_info (
                domain, status, error_kind, ns, mx, cname, a, aaaa, txt_spf, txt_dmarc, ttl, ptr, dnssec, resolved_at
             ) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, NOW())
             ON CONFLICT(domain) DO UPDATE SET
                status = excluded.status,
                error_kind = excluded.error_kind,
                ns = excluded.ns,
                mx = excluded.mx,
                cname = excluded.cname,
                a = excluded.a,
                aaaa = excluded.aaaa,
                txt_spf = excluded.txt_spf,
                txt_dmarc = excluded.txt_dmarc,
                ttl = excluded.ttl,
                ptr = excluded.ptr,
                dnssec = excluded.dnssec,
                resolved_at = NOW();\n",
            sql_string(row.domain.as_str()),
            sql_string(row.status.as_str()),
            sql_string_opt(row.error_kind.map(|v| v.as_str())),
            sql_string_list(&row.ns),
            sql_string_list(&row.mx),
            sql_string_opt(row.cname.as_deref()),
            sql_string_list(&row.a),
            sql_string_list(&row.aaaa),
            sql_string_opt(row.txt_spf.as_deref()),
            sql_string_opt(row.txt_dmarc.as_deref()),
            sql_int_opt(row.ttl),
            sql_string_opt(row.ptr.as_deref()),
            sql_bool_opt(row.dnssec),
        ));
    }
    sql.push_str("COMMIT;");
    conn.execute_batch(&sql)?;
    batch.clear();
    Ok(())
}

fn flush_tls_batch(conn: &duckdb::Connection, batch: &mut Vec<TlsRow>) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO tls_info (
                domain, status, error_kind, cert_issuer, cert_subject, valid_from, valid_to,
                days_remaining, expired, self_signed, tls_version, cipher, scanned_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NOW())
             ON CONFLICT(domain) DO UPDATE SET
                status = excluded.status,
                error_kind = excluded.error_kind,
                cert_issuer = excluded.cert_issuer,
                cert_subject = excluded.cert_subject,
                valid_from = excluded.valid_from,
                valid_to = excluded.valid_to,
                days_remaining = excluded.days_remaining,
                expired = excluded.expired,
                self_signed = excluded.self_signed,
                tls_version = excluded.tls_version,
                cipher = excluded.cipher,
                scanned_at = NOW()",
        )?;

        for row in batch.iter() {
            stmt.execute(duckdb::params![
                row.domain.as_str(),
                row.status.as_str(),
                row.error_kind.map(|v| v.as_str()),
                row.cert_issuer.as_deref(),
                row.cert_subject.as_deref(),
                row.valid_from.map(|d| d.to_string()),
                row.valid_to.map(|d| d.to_string()),
                row.days_remaining,
                row.expired,
                row.self_signed,
                row.tls_version.as_deref(),
                row.cipher.as_deref(),
            ])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}

fn flush_ports_batch(conn: &duckdb::Connection, batch: &mut Vec<PortsRow>) -> Result<()> {
    let mut sql = String::from("BEGIN;\n");
    for row in batch.iter() {
        sql.push_str(&format!(
            "INSERT INTO ports_info (
                domain, status, error_kind, ip, p80, p443, p22, p21, p25, p587, p3306, p5432, p6379, p8080, p8443, open_ports, scanned_at
             ) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, NOW())
             ON CONFLICT(domain) DO UPDATE SET
                status = excluded.status,
                error_kind = excluded.error_kind,
                ip = excluded.ip,
                p80 = excluded.p80,
                p443 = excluded.p443,
                p22 = excluded.p22,
                p21 = excluded.p21,
                p25 = excluded.p25,
                p587 = excluded.p587,
                p3306 = excluded.p3306,
                p5432 = excluded.p5432,
                p6379 = excluded.p6379,
                p8080 = excluded.p8080,
                p8443 = excluded.p8443,
                open_ports = excluded.open_ports,
                scanned_at = NOW();\n",
            sql_string(row.domain.as_str()),
            sql_string(row.status.as_str()),
            sql_string_opt(row.error_kind.map(|v| v.as_str())),
            sql_string_opt(row.ip.as_deref()),
            sql_bool(row.p80),
            sql_bool(row.p443),
            sql_bool(row.p22),
            sql_bool(row.p21),
            sql_bool(row.p25),
            sql_bool(row.p587),
            sql_bool(row.p3306),
            sql_bool(row.p5432),
            sql_bool(row.p6379),
            sql_bool(row.p8080),
            sql_bool(row.p8443),
            sql_int_list(&row.open_ports),
        ));
    }
    sql.push_str("COMMIT;");
    conn.execute_batch(&sql)?;
    batch.clear();
    Ok(())
}

// ---- HTTP fetch ----

fn build_default_resolver() -> TokioResolver {
    TokioResolver::builder_with_config(ResolverConfig::cloudflare(), TokioConnectionProvider::default()).build()
}

fn build_client(args: &ScanArgs, resolver: TokioResolver) -> Result<Client> {
    let mut default_headers = HeaderMap::new();
    let max_bytes = args.max_bytes();
    if max_bytes >= 1 {
        let hi = max_bytes - 1;
        let range = format!("bytes=0-{hi}");
        default_headers.insert(RANGE, HeaderValue::from_str(&range)?);
    }

    let client = Client::builder()
        .connect_timeout(args.connect_timeout)
        .timeout(args.request_timeout)
        .redirect(reqwest::redirect::Policy::limited(args.max_redirects))
        .user_agent(args.user_agent.clone())
        .default_headers(default_headers)
        .dns_resolver(Arc::new(ReqwestHickoryResolver { resolver }))
        .pool_max_idle_per_host(64)
        .build()
        .context("building HTTP client")?;
    Ok(client)
}

async fn dispatcher_loop(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<Row>,
    sem: Semaphore,
    client: Client,
    resolver: TokioResolver,
    args: ScanArgs,
) -> Result<()> {
    let sem = Arc::new(sem);
    let client = Arc::new(client);
    let resolver = Arc::new(resolver);
    let mut joinset = JoinSet::<()>::new();
    let max_concurrency = args.concurrency;
    let mut batch = Vec::with_capacity(DISPATCH_BATCH_SIZE);

    while let Some(domain) = work_rx.recv().await {
        if result_tx.is_closed() {
            break;
        }
        batch.push(domain);
        if batch.len() < DISPATCH_BATCH_SIZE {
            continue;
        }

        for domain in batch.drain(..) {
            let permit = sem
                .clone()
                .acquire_owned()
                .await
                .context("semaphore closed")?;

            let client = client.clone();
            let resolver = resolver.clone();
            let tx = result_tx.clone();
            let args_task = args.clone();

            joinset.spawn(async move {
                let _permit = permit;
                if tx.is_closed() {
                    return;
                }
                let row = fetch_domain(&client, &resolver, domain, &args_task).await;
                let _ = tx.send(row).await;
            });

            while joinset.len() >= max_concurrency {
                if joinset.join_next().await.is_none() {
                    break;
                }
            }
        }

        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    for domain in batch.drain(..) {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .context("semaphore closed")?;

        let client = client.clone();
        let resolver = resolver.clone();
        let tx = result_tx.clone();
        let args_task = args.clone();

        joinset.spawn(async move {
            let _permit = permit;
            if tx.is_closed() {
                return;
            }
            let row = fetch_domain(&client, &resolver, domain, &args_task).await;
            let _ = tx.send(row).await;
        });

        while joinset.len() >= max_concurrency {
            if joinset.join_next().await.is_none() {
                break;
            }
        }
    }

    while joinset.join_next().await.is_some() {}
    drop(result_tx);
    Ok(())
}

// ---- DNS fetch ----

async fn dispatcher_loop_dns(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<DnsRow>,
    sem: Semaphore,
    resolver: TokioResolver,
    max_concurrency: usize,
) -> Result<()> {
    let sem = Arc::new(sem);
    let resolver = Arc::new(resolver);
    let mut joinset = JoinSet::<()>::new();
    let mut batch = Vec::with_capacity(DISPATCH_BATCH_SIZE);

    while let Some(domain) = work_rx.recv().await {
        if result_tx.is_closed() {
            break;
        }
        batch.push(domain);
        if batch.len() < DISPATCH_BATCH_SIZE {
            continue;
        }

        for domain in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let resolver = resolver.clone();
            let tx = result_tx.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_dns_info(&resolver, domain).await;
                let _ = tx.send(row).await;
            });

            while joinset.len() >= max_concurrency {
                if joinset.join_next().await.is_none() {
                    break;
                }
            }
        }

        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    for domain in batch.drain(..) {
        let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
        let resolver = resolver.clone();
        let tx = result_tx.clone();

        joinset.spawn(async move {
            let _permit = permit;
            let row = fetch_dns_info(&resolver, domain).await;
            let _ = tx.send(row).await;
        });

        while joinset.len() >= max_concurrency {
            if joinset.join_next().await.is_none() {
                break;
            }
        }
    }

    while joinset.join_next().await.is_some() {}
    drop(result_tx);
    Ok(())
}

async fn fetch_dns_info(resolver: &TokioResolver, domain: String) -> DnsRow {
    let dmarc_host = format!("_dmarc.{domain}");
    let (a_result, aaaa_result, ns_result, mx_result, cname_result, txt_result, dmarc_result) = tokio::join!(
        collect_ip_strings(resolver, &domain, RecordType::A),
        collect_ip_strings(resolver, &domain, RecordType::AAAA),
        collect_lookup_strings(resolver, &domain, RecordType::NS),
        collect_lookup_strings(resolver, &domain, RecordType::MX),
        collect_lookup_strings(resolver, &domain, RecordType::CNAME),
        collect_txt_records(resolver, &domain),
        collect_txt_records(resolver, &dmarc_host),
    );

    let mut status = ScanStatus::Ok;
    let mut error_kind = None;
    let primary_errors = [
        a_result.as_ref().err(),
        aaaa_result.as_ref().err(),
        ns_result.as_ref().err(),
        mx_result.as_ref().err(),
    ];
    if primary_errors.iter().all(|err| err.is_some()) {
        status = ScanStatus::Error;
        error_kind = primary_errors
            .into_iter()
            .flatten()
            .map(classify_dns_error)
            .next()
            .or(Some(ErrorKind::Dns));
    }

    let a = a_result.unwrap_or_default();
    let aaaa = aaaa_result.unwrap_or_default();
    let ns = ns_result.unwrap_or_default();
    let mx = mx_result.unwrap_or_default();
    let cname = cname_result.unwrap_or_default().into_iter().next();
    let txt_spf = txt_result
        .unwrap_or_default()
        .into_iter()
        .find(|txt| txt.to_ascii_lowercase().starts_with("v=spf1"));
    let txt_dmarc = dmarc_result.unwrap_or_default().into_iter().next();
    let dnssec = Some(has_dnssec_material(resolver, &domain).await);
    let ptr = first_ptr_record(resolver, &a, &aaaa).await;

    DnsRow {
        domain,
        status,
        error_kind,
        ns,
        mx,
        cname,
        a,
        aaaa,
        txt_spf,
        txt_dmarc,
        ttl: None,
        ptr,
        dnssec,
    }
}

async fn collect_lookup_strings(
    resolver: &TokioResolver,
    domain: &str,
    record_type: RecordType,
) -> std::result::Result<Vec<String>, ResolveError> {
    let lookup = resolver.lookup(domain, record_type).await?;

    let values = lookup
        .iter()
        .map(|record| match record {
            RData::NS(v) => v.to_utf8(),
            RData::CNAME(v) => v.to_utf8(),
            RData::MX(v) => v.exchange().to_utf8(),
            _ => record.to_string(),
        })
        .collect::<Vec<_>>();
    Ok(dedupe_sorted(values))
}

async fn collect_ip_strings(
    resolver: &TokioResolver,
    domain: &str,
    record_type: RecordType,
) -> std::result::Result<Vec<String>, ResolveError> {
    let lookup = resolver.lookup(domain, record_type).await?;

    let mut values = Vec::new();
    for record in lookup.iter() {
        match record {
            RData::A(v) => values.push(v.0.to_string()),
            RData::AAAA(v) => values.push(v.0.to_string()),
            _ => {}
        }
    }
    Ok(dedupe_sorted(values))
}

async fn collect_txt_records(
    resolver: &TokioResolver,
    domain: &str,
) -> std::result::Result<Vec<String>, ResolveError> {
    let lookup = resolver.lookup(domain, RecordType::TXT).await?;

    let mut values = Vec::new();
    for record in lookup.iter() {
        if let RData::TXT(txt) = record {
            let joined = txt
                .txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).to_string())
                .collect::<String>();
            if !joined.is_empty() {
                values.push(joined);
            }
        }
    }
    Ok(dedupe_sorted(values))
}

async fn has_dnssec_material(resolver: &TokioResolver, domain: &str) -> bool {
    let (dnskey, ds) = tokio::join!(
        resolver.lookup(domain, RecordType::DNSKEY),
        resolver.lookup(domain, RecordType::DS),
    );
    dnskey.is_ok() || ds.is_ok()
}

async fn first_ptr_record(
    resolver: &TokioResolver,
    ipv4: &[String],
    ipv6: &[String],
) -> Option<String> {
    for candidate in ipv4.iter().chain(ipv6.iter()) {
        let Ok(ip) = candidate.parse::<IpAddr>() else {
            continue;
        };
        let Ok(lookup) = resolver.reverse_lookup(ip).await else {
            continue;
        };
        if let Some(name) = lookup.iter().next() {
            return Some(name.to_utf8());
        }
    }
    None
}

async fn resolve_first_ip(resolver: &TokioResolver, domain: &str) -> std::result::Result<IpAddr, ErrorKind> {
    let lookup = resolver.lookup_ip(domain).await.map_err(|e| classify_dns_error(&e))?;
    lookup.iter().next().ok_or(ErrorKind::NotFound)
}

// ---- TLS fetch ----

fn build_tls_connector() -> TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn dispatcher_loop_tls(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<TlsRow>,
    sem: Semaphore,
    connector: TlsConnector,
    resolver: TokioResolver,
    args: TlsArgs,
) -> Result<()> {
    let sem = Arc::new(sem);
    let connector = Arc::new(connector);
    let resolver = Arc::new(resolver);
    let mut joinset = JoinSet::<()>::new();
    let mut batch = Vec::with_capacity(DISPATCH_BATCH_SIZE);

    while let Some(domain) = work_rx.recv().await {
        if result_tx.is_closed() {
            break;
        }
        batch.push(domain);
        if batch.len() < DISPATCH_BATCH_SIZE {
            continue;
        }

        for domain in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let connector = connector.clone();
            let resolver = resolver.clone();
            let tx = result_tx.clone();
            let args_task = args.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_tls_info(&connector, &resolver, domain, &args_task).await;
                let _ = tx.send(row).await;
            });

            while joinset.len() >= args.concurrency {
                if joinset.join_next().await.is_none() {
                    break;
                }
            }
        }

        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    for domain in batch.drain(..) {
        let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
        let connector = connector.clone();
        let resolver = resolver.clone();
        let tx = result_tx.clone();
        let args_task = args.clone();

        joinset.spawn(async move {
            let _permit = permit;
            let row = fetch_tls_info(&connector, &resolver, domain, &args_task).await;
            let _ = tx.send(row).await;
        });

        while joinset.len() >= args.concurrency {
            if joinset.join_next().await.is_none() {
                break;
            }
        }
    }

    while joinset.join_next().await.is_some() {}
    drop(result_tx);
    Ok(())
}

async fn fetch_tls_info(connector: &TlsConnector, resolver: &TokioResolver, domain: String, args: &TlsArgs) -> TlsRow {
    let mut row = TlsRow {
        domain: domain.clone(),
        status: ScanStatus::Error,
        error_kind: None,
        cert_issuer: None,
        cert_subject: None,
        valid_from: None,
        valid_to: None,
        days_remaining: None,
        expired: None,
        self_signed: None,
        tls_version: None,
        cipher: None,
    };

    let Ok(server_name) = ServerName::try_from(domain.clone()) else {
        row.error_kind = Some(ErrorKind::ParseFailed);
        return row;
    };

    let Ok(ip) = resolve_first_ip(resolver, &domain).await
    else {
        row.error_kind = Some(ErrorKind::Dns);
        return row;
    };

    let Ok(stream) = tokio::time::timeout(
        args.connect_timeout,
        TcpStream::connect(SocketAddr::new(ip, 443)),
    )
    .await
    else {
        row.error_kind = Some(ErrorKind::Timeout);
        return row;
    };
    let Ok(stream) = stream else {
        row.error_kind = Some(classify_io_error(&stream.unwrap_err()));
        return row;
    };

    let Ok(tls_stream) = tokio::time::timeout(
        args.handshake_timeout,
        connector.connect(server_name, stream),
    )
    .await
    else {
        row.error_kind = Some(ErrorKind::Timeout);
        return row;
    };
    let Ok(tls_stream) = tls_stream else {
        row.error_kind = Some(ErrorKind::Tls);
        return row;
    };

    let (_, session) = tls_stream.get_ref();
    row.tls_version = session.protocol_version().map(|v| format!("{v:?}"));
    row.cipher = session
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()));

    let Some(peer_cert) = session
        .peer_certificates()
        .and_then(|certs| certs.first())
    else {
        row.error_kind = Some(ErrorKind::ParseFailed);
        return row;
    };

    if let Ok((_, cert)) = X509Certificate::from_der(peer_cert.as_ref()) {
        populate_tls_cert_fields(&mut row, &cert);
        row.status = ScanStatus::Ok;
        row.error_kind = None;
    } else {
        row.error_kind = Some(ErrorKind::ParseFailed);
    }

    row
}

fn populate_tls_cert_fields(row: &mut TlsRow, cert: &X509Certificate<'_>) {
    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();
    let valid_from = asn1_date(cert.validity().not_before.timestamp());
    let valid_to = asn1_date(cert.validity().not_after.timestamp());

    row.cert_issuer = non_empty(issuer);
    row.cert_subject = non_empty(subject);
    row.valid_from = valid_from;
    row.valid_to = valid_to;
    row.self_signed = Some(cert.issuer() == cert.subject());

    if let Some(valid_to) = valid_to {
        let today = Utc::now().date_naive();
        let days = valid_to.signed_duration_since(today).num_days();
        row.days_remaining = Some(days.clamp(i32::MIN as i64, i32::MAX as i64) as i32);
        row.expired = Some(valid_to < today);
    } else {
        row.expired = None;
    }
}

fn asn1_date(ts: i64) -> Option<NaiveDate> {
    DateTime::from_timestamp(ts, 0).map(|dt| dt.date_naive())
}

// ---- ports fetch ----

async fn dispatcher_loop_ports(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<PortsRow>,
    sem: Semaphore,
    resolver: TokioResolver,
    args: PortsArgs,
) -> Result<()> {
    let sem = Arc::new(sem);
    let resolver = Arc::new(resolver);
    let mut joinset = JoinSet::<()>::new();
    let mut batch = Vec::with_capacity(DISPATCH_BATCH_SIZE);

    while let Some(domain) = work_rx.recv().await {
        if result_tx.is_closed() {
            break;
        }
        batch.push(domain);
        if batch.len() < DISPATCH_BATCH_SIZE {
            continue;
        }

        for domain in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let tx = result_tx.clone();
            let resolver = resolver.clone();
            let args_task = args.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_ports_info(&resolver, domain, &args_task).await;
                let _ = tx.send(row).await;
            });

            while joinset.len() >= args.concurrency {
                if joinset.join_next().await.is_none() {
                    break;
                }
            }
        }

        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    for domain in batch.drain(..) {
        let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
        let tx = result_tx.clone();
        let resolver = resolver.clone();
        let args_task = args.clone();

        joinset.spawn(async move {
            let _permit = permit;
            let row = fetch_ports_info(&resolver, domain, &args_task).await;
            let _ = tx.send(row).await;
        });

        while joinset.len() >= args.concurrency {
            if joinset.join_next().await.is_none() {
                break;
            }
        }
    }

    while joinset.join_next().await.is_some() {}
    drop(result_tx);
    Ok(())
}

async fn fetch_ports_info(resolver: &TokioResolver, domain: String, args: &PortsArgs) -> PortsRow {
    let (ip, error_kind) = match resolve_first_ip(resolver, &domain).await {
        Ok(ip) => (Some(ip), None),
        Err(kind) => (None, Some(kind)),
    };

    let mut open_ports = Vec::new();
    let mut last_probe_error = error_kind;

    if let Some(ip) = ip {
        let timeout = args.connect_timeout;
        let all_ports: Vec<u16> = STANDARD_PORTS.into_iter().chain(EXTRA_PORTS).collect();
        let results = futures_util::future::join_all(
            all_ports.iter().map(|&port| port_open(ip, port, timeout)),
        )
        .await;
        for (port, result) in all_ports.into_iter().zip(results) {
            match result {
                Ok(true) => open_ports.push(port as i32),
                Ok(false) => {}
                Err(kind) => last_probe_error = Some(kind),
            }
        }
    }

    PortsRow {
        domain,
        status: if ip.is_some() { ScanStatus::Ok } else { ScanStatus::Error },
        error_kind: if ip.is_some() { last_probe_error.filter(|_| open_ports.is_empty()) } else { last_probe_error },
        ip: ip.map(|ip| ip.to_string()),
        p80: open_ports.contains(&80),
        p443: open_ports.contains(&443),
        p22: open_ports.contains(&22),
        p21: open_ports.contains(&21),
        p25: open_ports.contains(&25),
        p587: open_ports.contains(&587),
        p3306: open_ports.contains(&3306),
        p5432: open_ports.contains(&5432),
        p6379: open_ports.contains(&6379),
        p8080: open_ports.contains(&8080),
        p8443: open_ports.contains(&8443),
        open_ports,
    }
}

async fn port_open(ip: IpAddr, port: u16, timeout: Duration) -> std::result::Result<bool, ErrorKind> {
    let socket = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(socket)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) => Err(classify_io_error(&e)),
        Err(_) => Err(ErrorKind::Timeout),
    }
}

// ---- HTTP row fetchers ----

async fn fetch_domain(client: &Client, resolver: &TokioResolver, domain: String, args: &ScanArgs) -> Row {
    let start = Instant::now();

    let ip = resolve_first_ip(resolver, &domain).await.ok().map(|ip| ip.to_string());

    let mut last_err: Option<FetchErr> = None;
    for url in candidate_urls(&domain) {
        if url.is_empty() {
            continue;
        }
        match fetch_url(client, &url, args).await {
            Ok(mut row) => {
                row.domain = domain;
                row.ip = ip;
                row.elapsed_ms = start.elapsed().as_millis() as u64;
                return row;
            }
            Err(e) => last_err = Some(e),
        }
    }

    let kind = last_err.and_then(|e| e.kind).unwrap_or(ErrorKind::Other);
    Row {
        domain,
        status: ScanStatus::Error,
        ip,
        final_url: None,
        status_code: None,
        title: None,
        body_hash: None,
        server: None,
        powered_by: None,
        error_kind: Some(kind),
        elapsed_ms: start.elapsed().as_millis() as u64,
    }
}

fn candidate_urls(domain: &str) -> [String; 4] {
    let https = format!("https://{domain}/");
    let http = format!("http://{domain}/");
    if should_try_www(domain) {
        let https_www = format!("https://www.{domain}/");
        let http_www = format!("http://www.{domain}/");
        [https, https_www, http, http_www]
    } else {
        [https, http, String::new(), String::new()]
    }
}

fn should_try_www(domain: &str) -> bool {
    let d = domain.trim().to_ascii_lowercase();
    if d.starts_with("www.") {
        return false;
    }
    if d.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    true
}

#[derive(Debug)]
struct FetchErr {
    kind: Option<ErrorKind>,
}

async fn raw_http_redirect_location(
    url: &str,
    user_agent: &str,
    connect_timeout: Duration,
) -> Option<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() { "/" } else { parsed.path() }.to_string();

    let addr = format!("{host}:{port}");
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\n\r\n"
    );

    let (read_half, mut write_half) = tokio::io::split(stream);
    write_half.write_all(request.as_bytes()).await.ok()?;
    drop(write_half);

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    reader.read_line(&mut line).await.ok()?;
    let status: u16 = line.split_whitespace().nth(1)?.parse().ok()?;
    if !(300..=399).contains(&status) {
        return None;
    }

    loop {
        line.clear();
        if reader.read_line(&mut line).await.is_err() {
            break;
        }
        if line.trim().is_empty() {
            break;
        }
        if line.to_ascii_lowercase().starts_with("location:") {
            let location = line[9..].trim().to_string();
            if !location.is_empty() {
                return Some(location);
            }
        }
    }
    None
}

async fn fetch_url(client: &Client, url: &str, args: &ScanArgs) -> std::result::Result<Row, FetchErr> {
    let row = fetch_url_inner(client, url, args).await?;

    if row.status_code == Some(400)
        && url.starts_with("http://")
        && row.final_url.as_deref() == Some(url)
    {
        if let Some(location) =
            raw_http_redirect_location(url, &args.user_agent, args.connect_timeout).await
        {
            return fetch_url_inner(client, &location, args).await;
        }
    }

    Ok(row)
}

async fn fetch_url_inner(
    client: &Client,
    url: &str,
    args: &ScanArgs,
) -> std::result::Result<Row, FetchErr> {
    let resp = client.get(url).send().await.map_err(|e| FetchErr {
        kind: Some(classify_reqwest_error(&e)),
    })?;

    let final_url = resp.url().to_string();
    let status = resp.status();
    let status_u16 = status.as_u16();
    let server = resp
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let powered_by = resp
        .headers()
        .get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let max_bytes = args.max_bytes();
    let mut body: Vec<u8> = Vec::with_capacity(max_bytes.min(65_536));
    let mut body_err_kind: Option<ErrorKind> = None;
    let mut stream = resp.bytes_stream();
    while let Some(chunk_res) = stream.next().await {
        let chunk = match chunk_res {
            Ok(c) => c,
            Err(e) => {
                body_err_kind = Some(classify_reqwest_error(&e));
                break;
            }
        };

        if body.len() >= max_bytes {
            break;
        }

        let remaining = max_bytes - body.len();
        let take = remaining.min(chunk.len());
        body.extend_from_slice(&chunk[..take]);
    }

    let mut error_kind = if status.is_client_error() || status.is_server_error() {
        Some(ErrorKind::HttpStatus)
    } else {
        None
    };
    if error_kind.is_none() {
        error_kind = body_err_kind;
    }

    let title = extract_title(&body);
    let body_hash = if body.is_empty() {
        None
    } else {
        Some(format!("{:x}", md5::compute(&body)))
    };

    Ok(Row {
        domain: String::new(),
        status: ScanStatus::Ok,
        ip: None,
        final_url: Some(final_url),
        status_code: Some(status_u16),
        title,
        body_hash,
        server,
        powered_by,
        error_kind,
        elapsed_ms: 0,
    })
}

fn extract_title(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();

    let start = lower.find("<title")?;
    let tag_close = lower[start..].find('>')? + start + 1;
    let end = lower[tag_close..].find("</title>")? + tag_close;

    let raw = &text[tag_close..end];
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let decoded = collapsed
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'");

    let trimmed = decoded.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn classify_reqwest_error(e: &reqwest::Error) -> ErrorKind {
    if e.is_timeout() {
        return ErrorKind::Timeout;
    }
    let mut msg = e.to_string().to_ascii_lowercase();
    let mut src: Option<&(dyn std::error::Error + 'static)> = e.source();
    while let Some(err) = src {
        msg.push_str(" | ");
        msg.push_str(&err.to_string().to_ascii_lowercase());
        src = err.source();
    }

    if msg.contains("certificate")
        || msg.contains("tls")
        || msg.contains("ssl")
        || msg.contains("handshake")
        || msg.contains("subjectaltname")
        || msg.contains("not valid for name")
        || msg.contains("invalid dns name")
        || msg.contains("cert")
    {
        return ErrorKind::Tls;
    }

    if e.is_connect() {
        if msg.contains("dns")
            || msg.contains("failed to lookup")
            || msg.contains("name or service not known")
            || msg.contains("nodename nor servname provided")
            || msg.contains("no such host")
        {
            return ErrorKind::Dns;
        }
        if msg.contains("refused") || msg.contains("connection refused") {
            return ErrorKind::Refused;
        }
        return ErrorKind::Other;
    }

    ErrorKind::Other
}

// ---- subdomains subcommand ----

/// Attempt DNS zone transfer (AXFR) from `ns_ip` for `domain`.
/// Returns discovered subdomain FQDNs or an empty vec on refusal/failure.
async fn axfr_from_ns_ip(ns_ip: IpAddr, domain: &str) -> Vec<String> {
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_resolver::proto::rr::Name;
    use hickory_resolver::proto::serialize::binary::{BinDecodable, BinEncodable};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(name) = Name::from_ascii(domain) else { return vec![]; };

    let mut msg = Message::new();
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);
    msg.add_query(Query::query(name, RecordType::AXFR));

    let Ok(msg_bytes) = msg.to_bytes() else { return vec![]; };

    let addr = SocketAddr::new(ns_ip, 53);
    let stream = match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return vec![],
    };

    let (mut read_half, mut write_half) = tokio::io::split(stream);

    // TCP DNS: 2-byte big-endian length prefix
    let len_prefix = (msg_bytes.len() as u16).to_be_bytes();
    if write_half.write_all(&len_prefix).await.is_err() { return vec![]; }
    if write_half.write_all(&msg_bytes).await.is_err() { return vec![]; }
    drop(write_half);

    let apex = format!("{}.", domain.trim_end_matches('.').to_ascii_lowercase());
    let apex_suffix = format!(".{apex}");
    let mut found = Vec::new();
    let mut soa_count = 0usize;

    loop {
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(Duration::from_secs(15), read_half.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65_535 { break; }

        let mut buf = vec![0u8; msg_len];
        match tokio::time::timeout(Duration::from_secs(15), read_half.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        let Ok(resp) = Message::from_bytes(&buf) else { break; };
        if resp.response_code() != ResponseCode::NoError { break; }

        for record in resp.answers() {
            if record.record_type() == RecordType::SOA {
                soa_count += 1;
            }
            let rname = record.name().to_ascii().to_ascii_lowercase();
            if rname != apex && rname.ends_with(&apex_suffix) {
                let sub = rname.trim_end_matches('.').to_string();
                found.push(sub);
            }
        }

        if soa_count >= 2 { break; }
    }

    found.sort();
    found.dedup();
    found
}

/// Discover subdomains via AXFR from authoritative NSes, falling back to NS/MX record harvest.
async fn probe_subdomains(resolver: Arc<TokioResolver>, domain: String) -> SubdomainRow {
    // Resolve NS records for the domain
    let ns_list = collect_lookup_strings(&resolver, &domain, RecordType::NS)
        .await
        .unwrap_or_default();

    // Try AXFR from each authoritative NS
    for ns in &ns_list {
        let ns_host = ns.trim_end_matches('.');
        let mut ns_ips = collect_ip_strings(&resolver, ns_host, RecordType::A)
            .await
            .unwrap_or_default();
        ns_ips.extend(
            collect_ip_strings(&resolver, ns_host, RecordType::AAAA)
                .await
                .unwrap_or_default(),
        );
        for ip_str in ns_ips {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let found = axfr_from_ns_ip(ip, &domain).await;
                if !found.is_empty() {
                    return SubdomainRow { domain, found, source: "axfr" };
                }
            }
        }
    }

    // Fallback: harvest subdomains embedded in NS and MX record values
    let (mx_result, ns_result) = tokio::join!(
        collect_lookup_strings(&resolver, &domain, RecordType::MX),
        collect_lookup_strings(&resolver, &domain, RecordType::NS),
    );

    let apex_bare = domain.trim_end_matches('.').to_ascii_lowercase();
    let apex_suffix = format!(".{apex_bare}");
    let mut found = Vec::new();
    for name in ns_result.unwrap_or_default().into_iter().chain(mx_result.unwrap_or_default()) {
        let clean = name.trim_end_matches('.').to_ascii_lowercase();
        if clean.ends_with(&apex_suffix) {
            found.push(clean);
        }
    }
    found.sort();
    found.dedup();

    SubdomainRow { domain, found, source: "mx_ns" }
}

async fn dispatcher_loop_subdomains(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<SubdomainRow>,
    sem: Semaphore,
    resolver: TokioResolver,
    max_concurrency: usize,
) -> Result<()> {
    let sem = Arc::new(sem);
    let resolver = Arc::new(resolver);
    let mut joinset = JoinSet::<()>::new();
    let mut batch = Vec::with_capacity(DISPATCH_BATCH_SIZE);

    while let Some(domain) = work_rx.recv().await {
        if result_tx.is_closed() { break; }
        batch.push(domain);
        if batch.len() < DISPATCH_BATCH_SIZE { continue; }

        for domain in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let resolver = resolver.clone();
            let tx = result_tx.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = probe_subdomains(resolver, domain).await;
                let _ = tx.send(row).await;
            });

            while joinset.len() >= max_concurrency {
                if joinset.join_next().await.is_none() { break; }
            }
        }

        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    for domain in batch.drain(..) {
        let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
        let resolver = resolver.clone();
        let tx = result_tx.clone();

        joinset.spawn(async move {
            let _permit = permit;
            let row = probe_subdomains(resolver, domain).await;
            let _ = tx.send(row).await;
        });

        while joinset.len() >= max_concurrency {
            if joinset.join_next().await.is_none() { break; }
        }
    }

    while joinset.join_next().await.is_some() {}
    drop(result_tx);
    Ok(())
}

fn writer_loop_subdomains(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<SubdomainRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = duckdb::Connection::open(&db_path)
        .with_context(|| format!("subdomains writer: open duckdb {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            flush_subdomains_batch(&conn, &mut batch)?;
        }
    }
    if !batch.is_empty() {
        flush_subdomains_batch(&conn, &mut batch)?;
    }
    let _ = done_tx.send(());
    Ok(())
}

fn flush_subdomains_batch(conn: &duckdb::Connection, batch: &mut Vec<SubdomainRow>) -> Result<()> {
    if batch.iter().all(|r| r.found.is_empty()) {
        batch.clear();
        return Ok(());
    }
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO subdomains (domain, subdomain, source, discovered_at)
             VALUES (?1, ?2, ?3, NOW())
             ON CONFLICT DO NOTHING",
        )?;
        for row in batch.iter() {
            for sub in &row.found {
                stmt.execute(duckdb::params![
                    row.domain.as_str(),
                    sub.as_str(),
                    row.source,
                ])?;
            }
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}

async fn cmd_subdomains(args: SubdomainsArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    ensure_schema(&conn)?;

    let pending: Vec<String> = if let Some(domain) = args.domain.as_deref() {
        vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]
    } else {
        let sql = if args.rescan {
            "SELECT domain FROM domains ORDER BY domain".to_string()
        } else {
            "SELECT d.domain FROM domains d WHERE NOT EXISTS \
             (SELECT 1 FROM subdomains s WHERE s.domain = d.domain) ORDER BY d.domain".to_string()
        };
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?
    };
    drop(conn);

    eprintln!("subdomains: {} domains pending", pending.len());
    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let progress = Arc::new(Progress::new(pending.len() as u64));
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<SubdomainRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = args.write_batch_size;
        let progress = progress.clone();
        move || writer_loop_subdomains(db_path, result_rx, progress, done_tx, batch_size)
    });

    let reader_handle = tokio::spawn({
        let progress = progress.clone();
        async move {
            for domain in pending {
                if work_tx.send(domain).await.is_err() { break; }
                progress.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Ok::<(), anyhow::Error>(())
        }
    });

    let progress_handle = if args.no_progress {
        None
    } else {
        Some(tokio::spawn(progress_reporter(
            progress.clone(),
            args.progress_interval,
            done_rx,
        )))
    };

    let dispatcher_handle = tokio::spawn(dispatcher_loop_subdomains(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        resolver,
        args.concurrency,
    ));

    reader_handle.await.context("subdomains reader task panicked")?.context("subdomains reader failed")?;
    dispatcher_handle.await.context("subdomains dispatcher task panicked")?.context("subdomains dispatcher failed")?;
    writer_handle.await.context("subdomains writer task panicked")?.context("subdomains writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

// ---- whois subcommand ----

async fn fetch_whois(domain: String, connect_timeout: Duration) -> WhoisRow {
    let mut row = WhoisRow { domain: domain.clone(), registrar: None, whois_created: None };

    // Resolve whois.nic.ch and prefer IPv4 — IPv6 is often unreachable.
    let addrs: Vec<std::net::SocketAddr> =
        match tokio::time::timeout(connect_timeout, tokio::net::lookup_host("whois.nic.ch:43")).await {
            Ok(Ok(iter)) => iter.collect(),
            _ => return row,
        };
    let addr = match addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first()) {
        Some(a) => *a,
        None => return row,
    };
    let stream = match tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return row,
    };

    use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};
    let (read_half, mut write_half) = tokio::io::split(stream);

    let query = format!("{}\r\n", domain);
    if write_half.write_all(query.as_bytes()).await.is_err() {
        return row;
    }
    drop(write_half);

    let mut reader = BufReader::new(read_half);
    let mut lines: Vec<String> = Vec::new();
    let mut buf = String::new();
    loop {
        buf.clear();
        match tokio::time::timeout(connect_timeout, reader.read_line(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => lines.push(buf.trim_end_matches(['\r', '\n']).to_string()),
        }
    }

    // Parse: label line ends with ':', value is the next non-empty line.
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if line.eq_ignore_ascii_case("Registrar:") {
            if let Some(val) = lines[i + 1..].iter().find(|l| !l.trim().is_empty()) {
                row.registrar = Some(val.trim().to_string());
            }
        }
        if line.eq_ignore_ascii_case("First registration date:") {
            if let Some(val) = lines[i + 1..].iter().find(|l| !l.trim().is_empty()) {
                let date_str = val.trim().trim_start_matches("before").trim();
                row.whois_created = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d").ok();
            }
        }
        i += 1;
    }

    row
}

async fn dispatcher_loop_whois(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<WhoisRow>,
    sem: Semaphore,
    connect_timeout: Duration,
    max_concurrency: usize,
) -> Result<()> {
    let sem = Arc::new(sem);
    let mut joinset = JoinSet::<()>::new();
    let mut batch = Vec::with_capacity(DISPATCH_BATCH_SIZE);

    while let Some(domain) = work_rx.recv().await {
        if result_tx.is_closed() { break; }
        batch.push(domain);
        if batch.len() < DISPATCH_BATCH_SIZE { continue; }

        for domain in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let tx = result_tx.clone();
            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_whois(domain, connect_timeout).await;
                let _ = tx.send(row).await;
            });
            while joinset.len() >= max_concurrency {
                if joinset.join_next().await.is_none() { break; }
            }
        }
        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    for domain in batch.drain(..) {
        let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
        let tx = result_tx.clone();
        joinset.spawn(async move {
            let _permit = permit;
            let row = fetch_whois(domain, connect_timeout).await;
            let _ = tx.send(row).await;
        });
        while joinset.len() >= max_concurrency {
            if joinset.join_next().await.is_none() { break; }
        }
    }

    while joinset.join_next().await.is_some() {}
    Ok(())
}

fn flush_whois_batch(conn: &duckdb::Connection, batch: &mut Vec<WhoisRow>) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO domains (domain, whois_registrar, whois_created)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(domain) DO UPDATE SET
                whois_registrar = excluded.whois_registrar,
                whois_created   = excluded.whois_created",
        )?;
        for row in batch.iter() {
            stmt.execute(duckdb::params![
                row.domain.as_str(),
                row.registrar.as_deref(),
                row.whois_created.map(|d| d.to_string()),
            ])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}

fn writer_loop_whois(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<WhoisRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = duckdb::Connection::open(&db_path)
        .with_context(|| format!("whois writer: open duckdb {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            flush_whois_batch(&conn, &mut batch)?;
        }
    }
    if !batch.is_empty() {
        flush_whois_batch(&conn, &mut batch)?;
    }
    let _ = done_tx.send(());
    Ok(())
}

async fn cmd_whois(args: WhoisArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    ensure_schema(&conn)?;

    let pending: Vec<String> = if let Some(domain) = args.domain.as_deref() {
        vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]
    } else {
        let sql = if args.rescan {
            "SELECT domain FROM domains ORDER BY domain".to_string()
        } else {
            "SELECT domain FROM domains WHERE whois_registrar IS NULL ORDER BY domain".to_string()
        };
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?
    };
    drop(conn);

    eprintln!("whois: {} domains pending", pending.len());
    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let progress = Arc::new(Progress::new(pending.len() as u64));
    let work_buf = (args.concurrency * 2).clamp(100, 10_000);
    let result_buf = (args.concurrency * 2).clamp(100, 10_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<WhoisRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = args.write_batch_size;
        let progress = progress.clone();
        move || writer_loop_whois(db_path, result_rx, progress, done_tx, batch_size)
    });

    let reader_handle = tokio::spawn({
        let progress = progress.clone();
        async move {
            for domain in pending {
                if work_tx.send(domain).await.is_err() { break; }
                progress.enqueued.fetch_add(1, Ordering::Relaxed);
            }
            Ok::<(), anyhow::Error>(())
        }
    });

    let progress_handle = if args.no_progress {
        None
    } else {
        Some(tokio::spawn(progress_reporter(
            progress.clone(),
            args.progress_interval,
            done_rx,
        )))
    };

    let dispatcher_handle = tokio::spawn(dispatcher_loop_whois(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        args.connect_timeout,
        args.concurrency,
    ));

    reader_handle.await.context("whois reader task panicked")?.context("whois reader failed")?;
    dispatcher_handle.await.context("whois dispatcher task panicked")?.context("whois dispatcher failed")?;
    writer_handle.await.context("whois writer task panicked")?.context("whois writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

// ---- utilities ----

fn sanitize_domain(line: &str) -> Option<String> {
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

fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
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

fn dedupe_sorted(values: Vec<String>) -> Vec<String> {
    let mut values: Vec<String> = values.into_iter().filter_map(non_empty).collect();
    values.sort();
    values.dedup();
    values
}

fn sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sql_string_opt(value: Option<&str>) -> String {
    value.map(sql_string).unwrap_or_else(|| "NULL".to_string())
}

fn sql_string_list(values: &[String]) -> String {
    if values.is_empty() {
        "[]".to_string()
    } else {
        format!(
            "[{}]",
            values
                .iter()
                .map(|value| sql_string(value))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn sql_int_list(values: &[i32]) -> String {
    if values.is_empty() {
        "[]".to_string()
    } else {
        format!(
            "[{}]",
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn sql_bool(value: bool) -> &'static str {
    if value { "TRUE" } else { "FALSE" }
}

fn sql_bool_opt(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "TRUE",
        Some(false) => "FALSE",
        None => "NULL",
    }
}

fn sql_int_opt(value: Option<i32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "NULL".to_string())
}

fn classify_dns_error(err: &ResolveError) -> ErrorKind {
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

fn classify_io_error(err: &std::io::Error) -> ErrorKind {
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

fn non_empty<T: Into<String>>(value: T) -> Option<String> {
    let value = value.into();
    let trimmed = value.trim().trim_end_matches('.').trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn fmt_num(n: u64) -> String {
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

fn progress_bar(done: u64, total: u64, width: usize) -> String {
    let filled = if total > 0 {
        ((done as f64 / total as f64) * width as f64) as usize
    } else {
        0
    }
    .min(width);
    format!("[{}{}]", "█".repeat(filled), "░".repeat(width - filled))
}

fn format_eta(secs: f64) -> String {
    let secs = secs as u64;
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

async fn progress_reporter(
    progress: Arc<Progress>,
    interval: Duration,
    mut done_rx: tokio::sync::oneshot::Receiver<()>,
) {
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
                let ok200 = progress.http_200.load(Ordering::Relaxed);
                let timeouts = progress.timeout.load(Ordering::Relaxed);
                let inflight = enq.saturating_sub(done);
                let now = Instant::now();
                let dt = (now - last_t).as_secs_f64().max(0.001);
                let delta = done.saturating_sub(last_done) as f64;
                let _inst_rate = delta / dt;
                let elapsed = progress.started.elapsed().as_secs_f64().max(0.001);
                let avg_rate = (done as f64) / elapsed;
                let total = progress.total;
                let eta_str = if avg_rate > 0.0 && total > done {
                    let remaining_secs = (total - done) as f64 / avg_rate;
                    format_eta(remaining_secs)
                } else {
                    "?".to_string()
                };

                let pct = if total > 0 { done as f64 / total as f64 * 100.0 } else { 0.0 };
                let bar = progress_bar(done, total, 32);
                let line1 = format!("{bar} {pct:.2}%  {}/{}", fmt_num(done), fmt_num(total));
                let line2 = format!(
                    "in-flight: {} · HTTP_OK: {} · timeout: {} · queued: {} · avg: {avg_rate:.1}/s · ETA: {eta_str}",
                    fmt_num(inflight), fmt_num(ok200), fmt_num(timeouts), fmt_num(enq)
                );

                if first {
                    eprint!("{line1}\n{line2}");
                    first = false;
                } else {
                    eprint!("\x1B[1A\r{line1}\n{line2}");
                }
                let _ = std::io::Write::flush(&mut std::io::stderr());

                last_done = done;
                last_t = now;
            }
        }
    }
}

// ---- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

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
                server VARCHAR, powered_by VARCHAR
            );
            INSERT INTO domains VALUES ('test.ch', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
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
}
