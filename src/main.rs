use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

mod shared;
mod schema;
mod http_scan;
mod dns_scan;
mod tls_scan;
mod ports_scan;
mod subdomains;
mod whois;
mod email_security;
mod cve;
mod classify;
mod benchmark;
mod sovereignty;
#[cfg(test)]
mod tests;

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
    /// Fetch/refresh the CVE catalog from CISA KEV and seed built-in entries.
    UpdateCves,
    /// Classify domains by industry sector using keyword heuristics.
    Classify(ClassifyArgs),
    /// Compute sector-level risk benchmarks across classified domains.
    Benchmark(BenchmarkArgs),
    /// Map NS operators by jurisdiction and compute per-domain sovereignty scores.
    Sovereignty(SovereigntyArgs),
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackfillMode {
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
    Whois,
    All,
}

#[derive(Parser, Debug)]
pub(crate) struct InitArgs {
    #[arg(long, default_value = "data/sorted_domains.txt")]
    pub(crate) input: PathBuf,

    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct ScanArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    /// Number of rows per DuckDB write transaction.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) write_batch_size: usize,

    #[arg(long, default_value_t = 500)]
    pub(crate) concurrency: usize,

    #[arg(long, default_value = "5s", value_parser = shared::parse_duration)]
    pub(crate) connect_timeout: Duration,

    #[arg(long, default_value = "20s", value_parser = shared::parse_duration)]
    pub(crate) request_timeout: Duration,

    #[arg(long, default_value_t = 128)]
    pub(crate) max_kbytes: usize,

    #[arg(long, default_value_t = 5)]
    pub(crate) max_redirects: usize,

    #[arg(long, default_value = "helvetiscan/1.0")]
    pub(crate) user_agent: String,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,

    #[arg(long, default_value = "1s", value_parser = shared::parse_duration)]
    pub(crate) progress_interval: Duration,

    #[arg(skip)]
    pub(crate) no_progress: bool,

    /// Stop after this many successful HTTP 200 responses have been written.
    #[arg(long = "limit-success")]
    pub(crate) limit_success: Option<usize>,

    /// Re-scan a subset of existing HTTP rows: ip, server, or all domain rows.
    #[arg(long)]
    pub(crate) backfill: Option<BackfillMode>,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct DnsArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 1_000)]
    pub(crate) write_batch_size: usize,

    #[arg(long, default_value_t = 250)]
    pub(crate) concurrency: usize,

    #[arg(long, default_value = "1s", value_parser = shared::parse_duration)]
    pub(crate) progress_interval: Duration,

    #[arg(skip)]
    pub(crate) no_progress: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,

    #[arg(long, default_value_t = false)]
    pub(crate) rescan: bool,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct TlsArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 250)]
    pub(crate) write_batch_size: usize,

    #[arg(long, default_value_t = 150)]
    pub(crate) concurrency: usize,

    #[arg(long, default_value = "5s", value_parser = shared::parse_duration)]
    pub(crate) connect_timeout: Duration,

    #[arg(long, default_value = "8s", value_parser = shared::parse_duration)]
    pub(crate) handshake_timeout: Duration,

    #[arg(long, default_value = "1s", value_parser = shared::parse_duration)]
    pub(crate) progress_interval: Duration,

    #[arg(skip)]
    pub(crate) no_progress: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,

    #[arg(long, default_value_t = false)]
    pub(crate) rescan: bool,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct PortsArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 500)]
    pub(crate) write_batch_size: usize,

    #[arg(long, default_value_t = 300)]
    pub(crate) concurrency: usize,

    #[arg(long, default_value = "800ms", value_parser = shared::parse_duration)]
    pub(crate) connect_timeout: Duration,

    #[arg(long, default_value = "1s", value_parser = shared::parse_duration)]
    pub(crate) progress_interval: Duration,

    #[arg(skip)]
    pub(crate) no_progress: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,

    #[arg(long, default_value_t = false)]
    pub(crate) rescan: bool,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct SubdomainsArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 200)]
    pub(crate) concurrency: usize,

    #[arg(long, default_value = "1s", value_parser = shared::parse_duration)]
    pub(crate) progress_interval: Duration,

    #[arg(long, default_value_t = 500)]
    pub(crate) write_batch_size: usize,

    /// Re-probe domains already present in the subdomains table.
    #[arg(long, default_value_t = false)]
    pub(crate) rescan: bool,

    #[arg(skip)]
    pub(crate) no_progress: bool,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct WhoisArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 500)]
    pub(crate) write_batch_size: usize,

    /// Keep concurrency low — whois.nic.ch rate-limits aggressively.
    #[arg(long, default_value_t = 5)]
    pub(crate) concurrency: usize,

    #[arg(long, default_value = "5s", value_parser = shared::parse_duration)]
    pub(crate) connect_timeout: Duration,

    #[arg(long, default_value = "1s", value_parser = shared::parse_duration)]
    pub(crate) progress_interval: Duration,

    #[arg(skip)]
    pub(crate) no_progress: bool,

    /// Re-fetch domains that already have a whois_registrar value.
    #[arg(long, default_value_t = false)]
    pub(crate) rescan: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct ClassifyArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,
}

#[derive(Parser, Debug)]
pub(crate) struct BenchmarkArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,
}

#[derive(Parser, Debug)]
pub(crate) struct SovereigntyArgs {
    #[arg(long, default_value = "data/domains.duckdb")]
    pub(crate) db: PathBuf,

    /// Path to GeoLite2-ASN.mmdb (offline ASN lookup).
    #[arg(long, default_value = "data/GeoLite2-ASN.mmdb")]
    pub(crate) asn_mmdb: PathBuf,

    /// Path to GeoLite2-Country.mmdb (offline country lookup).
    #[arg(long, default_value = "data/GeoLite2-Country.mmdb")]
    pub(crate) country_mmdb: PathBuf,

    /// Re-resolve all operators even if already present in ns_operators.
    #[arg(long, default_value_t = false)]
    pub(crate) rescan: bool,
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
    pub(crate) fn max_bytes(&self) -> usize {
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
            http_scan::cmd_scan(args).await
        }
        (None, false, db, Some(FullTarget::Dns), None) => {
            let args = DnsArgs { db, rescan: true, ..DnsArgs::default() };
            dns_scan::cmd_dns(args).await
        }
        (None, false, db, Some(FullTarget::Tls), None) => {
            let args = TlsArgs { db, rescan: true, ..TlsArgs::default() };
            tls_scan::cmd_tls(args).await
        }
        (None, false, db, Some(FullTarget::Ports), None) => {
            let args = PortsArgs { db, rescan: true, ..PortsArgs::default() };
            ports_scan::cmd_ports(args).await
        }
        (None, false, db, Some(FullTarget::Subdomains), None) => {
            let args = SubdomainsArgs { db, rescan: true, ..SubdomainsArgs::default() };
            subdomains::cmd_subdomains(args).await
        }
        (None, false, db, Some(FullTarget::Whois), None) => {
            let args = WhoisArgs { db, rescan: true, ..WhoisArgs::default() };
            whois::cmd_whois(args).await
        }
        (None, false, db, Some(FullTarget::All), None) => {
            http_scan::cmd_scan(ScanArgs { db: db.clone(), ..ScanArgs::default() }).await?;
            dns_scan::cmd_dns(DnsArgs { db: db.clone(), ..DnsArgs::default() }).await?;
            tls_scan::cmd_tls(TlsArgs { db: db.clone(), ..TlsArgs::default() }).await?;
            ports_scan::cmd_ports(PortsArgs { db: db.clone(), ..PortsArgs::default() }).await?;
            subdomains::cmd_subdomains(SubdomainsArgs { db, ..SubdomainsArgs::default() }).await
        }
        (None, false, _, None, Some(Command::Init(args))) => schema::cmd_init(args),
        (None, false, _, None, Some(Command::Scan(args))) => http_scan::cmd_scan(args).await,
        (None, false, _, None, Some(Command::Dns(args))) => dns_scan::cmd_dns(args).await,
        (None, false, _, None, Some(Command::Tls(args))) => tls_scan::cmd_tls(args).await,
        (None, false, _, None, Some(Command::Ports(args))) => ports_scan::cmd_ports(args).await,
        (None, false, _, None, Some(Command::Subdomains(args))) => subdomains::cmd_subdomains(args).await,
        (None, false, _, None, Some(Command::Whois(args))) => whois::cmd_whois(args).await,
        (None, false, db, None, Some(Command::UpdateCves)) => cve::cmd_update_cves(db).await,
        (None, false, _, None, Some(Command::Classify(args))) => classify::cmd_classify(args.db).await,
        (None, false, _, None, Some(Command::Benchmark(args))) => benchmark::cmd_benchmark(args.db).await,
        (None, false, _, None, Some(Command::Sovereignty(args))) => sovereignty::cmd_sovereignty(args).await,
        (None, true, _, _, _) => Err(anyhow!("--all requires --domain")),
        (None, false, _, None, None) => Err(anyhow!("missing command: use a subcommand, or --domain <domain> --all, or --full <domain|dns|tls>")),
    }
}

// ---- single-domain all-scans ----

async fn cmd_single_all(db: PathBuf, domain: &str) -> Result<()> {
    let domain = schema::ensure_domain_exists(&db, domain)?;
    http_scan::cmd_scan(ScanArgs {
        db: db.clone(),
        domain: Some(domain.clone()),
        no_progress: true,
        ..ScanArgs::default()
    })
    .await?;
    dns_scan::cmd_dns(DnsArgs {
        db: db.clone(),
        domain: Some(domain.clone()),
        no_progress: true,
        ..DnsArgs::default()
    })
    .await?;
    tls_scan::cmd_tls(TlsArgs {
        db: db.clone(),
        domain: Some(domain.clone()),
        no_progress: true,
        ..TlsArgs::default()
    })
    .await?;
    ports_scan::cmd_ports(PortsArgs {
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
        "SELECT COUNT(*) FILTER (WHERE open = true),
                string_agg(CAST(port AS VARCHAR), ',' ORDER BY port) FILTER (WHERE open = true)
         FROM ports_info WHERE domain = ?1",
        duckdb::params![domain],
        |r| {
            let open_count: i64 = r.get::<_, Option<i64>>(0)?.unwrap_or(0);
            let open_list: Option<String> = r.get(1)?;
            Ok(SummaryRow {
                scan: "ports",
                status: if open_count > 0 { "ok".to_string() } else { "-".to_string() },
                error_kind: String::new(),
                details: format!(
                    "open_ports=[{}]",
                    truncate_cell(&open_list.unwrap_or_default(), 40),
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
