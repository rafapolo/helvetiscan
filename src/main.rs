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
#[command(about = "Swiss Cyberspace scanner - HTTP, DNS, TLS, HTTP, ports, WHOIS, MX and CVEs")]
#[command(arg_required_else_help = true)]
struct Cli {
    /// Scan only this single domain.
    #[arg(long)]
    domain: Option<String>,

    #[arg(long, default_value = "data/domains.db")]
    db: PathBuf,

    /// Re-scan domains whose error_kind matches this value (e.g. 'timeout').
    #[arg(long)]
    retry_errors: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Populate domains.db from a plain-text domain list (one domain/line).
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
    /// Run the full pipeline: scan → dns → tls → ports → subdomains → whois → cves → classify → sovereignty → benchmark.
    Full(FullArgs),
}

#[derive(Parser, Debug)]
pub(crate) struct InitArgs {
    #[arg(long, default_value = "data/sorted_domains.txt")]
    pub(crate) input: PathBuf,

    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct ScanArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

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

    #[arg(skip)]
    pub(crate) no_progress: bool,

    /// Save each fetched HTML body to <path>/<domain>.html.zip
    #[arg(long)]
    pub(crate) save_html: Option<PathBuf>,

    /// Path to GeoLite2-Country.mmdb for hosting country lookup (optional).
    #[arg(long, default_value = "data/GeoLite2-Country.mmdb")]
    pub(crate) country_mmdb: PathBuf,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct DnsArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 250)]
    pub(crate) concurrency: usize,

    #[arg(skip)]
    pub(crate) no_progress: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct TlsArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 150)]
    pub(crate) concurrency: usize,

    #[arg(long, default_value = "5s", value_parser = shared::parse_duration)]
    pub(crate) connect_timeout: Duration,

    #[arg(long, default_value = "8s", value_parser = shared::parse_duration)]
    pub(crate) handshake_timeout: Duration,

    #[arg(skip)]
    pub(crate) no_progress: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct PortsArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 300)]
    pub(crate) concurrency: usize,

    #[arg(long, default_value = "800ms", value_parser = shared::parse_duration)]
    pub(crate) connect_timeout: Duration,

    #[arg(skip)]
    pub(crate) no_progress: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct SubdomainsArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 200)]
    pub(crate) concurrency: usize,

    #[arg(skip)]
    pub(crate) no_progress: bool,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct WhoisArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    /// Keep concurrency low — whois.nic.ch rate-limits aggressively.
    #[arg(long, default_value_t = 5)]
    pub(crate) concurrency: usize,

    #[arg(long, default_value = "5s", value_parser = shared::parse_duration)]
    pub(crate) connect_timeout: Duration,

    #[arg(skip)]
    pub(crate) no_progress: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct ClassifyArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,
}

#[derive(Parser, Debug)]
pub(crate) struct BenchmarkArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,
}

#[derive(Parser, Debug)]
pub(crate) struct SovereigntyArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    /// Path to GeoLite2-ASN.mmdb (offline ASN lookup).
    #[arg(long, default_value = "data/GeoLite2-ASN.mmdb")]
    pub(crate) asn_mmdb: PathBuf,

    /// Path to GeoLite2-Country.mmdb (offline country lookup).
    #[arg(long, default_value = "data/GeoLite2-Country.mmdb")]
    pub(crate) country_mmdb: PathBuf,

}

#[derive(Parser, Debug)]
pub(crate) struct FullArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    /// Path to GeoLite2-ASN.mmdb (offline ASN lookup).
    #[arg(long, default_value = "data/GeoLite2-ASN.mmdb")]
    pub(crate) asn_mmdb: PathBuf,

    /// Path to GeoLite2-Country.mmdb (offline country lookup).
    #[arg(long, default_value = "data/GeoLite2-Country.mmdb")]
    pub(crate) country_mmdb: PathBuf,

    /// Number of concurrent requests for network scans.
    #[arg(long, default_value_t = 500)]
    pub(crate) concurrency: usize,

    /// Save each fetched HTML body to <path>/<domain>.html.zip
    #[arg(long)]
    pub(crate) save_html: Option<PathBuf>,
}

impl Default for WhoisArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.db"),
            domain: None,
            concurrency: 5,
            connect_timeout: Duration::from_secs(5),
            no_progress: false,
        }
    }
}

impl Default for ScanArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.db"),
            domain: None,
            concurrency: 500,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
            max_kbytes: 128,
            max_redirects: 5,
            user_agent: "helvetiscan/1.0".to_string(),
            no_progress: false,
            retry_errors: None,
            save_html: None,
            country_mmdb: PathBuf::from("data/GeoLite2-Country.mmdb"),
        }
    }
}

impl Default for DnsArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.db"),
            domain: None,
            concurrency: 250,
            no_progress: false,
            retry_errors: None,
        }
    }
}

impl Default for TlsArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.db"),
            domain: None,
            concurrency: 150,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(8),
            no_progress: false,
            retry_errors: None,
        }
    }
}

impl Default for SubdomainsArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.db"),
            domain: None,
            concurrency: 200,
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
            db: PathBuf::from("data/domains.db"),
            domain: None,
            concurrency: 300,
            connect_timeout: Duration::from_millis(800),
            no_progress: false,
            retry_errors: None,
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
    let retry_errors = cli.retry_errors;
    match (cli.domain, cli.db, cli.command) {
        // --domain alone → run all scans on that domain
        (Some(domain), db, None) => cmd_single_all(db, &domain, retry_errors).await,
        // --domain with a subcommand → inject domain and top-level retry_errors into args
        (Some(domain), _, Some(cmd)) => {
            match cmd {
                Command::Scan(mut a) => { if a.domain.is_none() { a.domain = Some(domain); } if a.retry_errors.is_none() { a.retry_errors = retry_errors; } http_scan::cmd_scan(a).await }
                Command::Dns(mut a)  => { if a.domain.is_none() { a.domain = Some(domain); } if a.retry_errors.is_none() { a.retry_errors = retry_errors; } dns_scan::cmd_dns(a).await }
                Command::Tls(mut a)  => { if a.domain.is_none() { a.domain = Some(domain); } if a.retry_errors.is_none() { a.retry_errors = retry_errors; } tls_scan::cmd_tls(a).await }
                Command::Ports(mut a) => { if a.domain.is_none() { a.domain = Some(domain); } if a.retry_errors.is_none() { a.retry_errors = retry_errors; } ports_scan::cmd_ports(a).await }
                Command::Subdomains(mut a) => { if a.domain.is_none() { a.domain = Some(domain); } subdomains::cmd_subdomains(a).await }
                Command::Whois(mut a) => { if a.domain.is_none() { a.domain = Some(domain); } whois::cmd_whois(a).await }
                _ => Err(anyhow!("--domain is not supported with this subcommand")),
            }
        }
        // standalone subcommands — thread top-level retry_errors if not set in subcommand args
        (None, db, Some(cmd)) => {
            match cmd {
                Command::Init(args) => schema::cmd_init(args),
                Command::Scan(mut a) => { if a.retry_errors.is_none() { a.retry_errors = retry_errors; } http_scan::cmd_scan(a).await }
                Command::Dns(mut a)  => { if a.retry_errors.is_none() { a.retry_errors = retry_errors; } dns_scan::cmd_dns(a).await }
                Command::Tls(mut a)  => { if a.retry_errors.is_none() { a.retry_errors = retry_errors; } tls_scan::cmd_tls(a).await }
                Command::Ports(mut a) => { if a.retry_errors.is_none() { a.retry_errors = retry_errors; } ports_scan::cmd_ports(a).await }
                Command::Subdomains(a) => subdomains::cmd_subdomains(a).await,
                Command::Whois(a) => whois::cmd_whois(a).await,
                Command::UpdateCves => cve::cmd_update_cves(db).await,
                Command::Classify(a) => classify::cmd_classify(a.db).await,
                Command::Benchmark(a) => benchmark::cmd_benchmark(a.db).await,
                Command::Sovereignty(a) => sovereignty::cmd_sovereignty(a).await,
                Command::Full(a) => cmd_full_pipeline(a).await,
            }
        }
        (None, _, None) => unreachable!("clap ensures at least one argument is provided"),
    }
}

// ---- full pipeline ----

async fn cmd_full_pipeline(args: FullArgs) -> Result<()> {
    use std::io::Write;

    let db = args.db;
    let concurrency = args.concurrency;

    macro_rules! step {
        ($label:expr, $fut:expr) => {{
            eprint!("\n=== {} ===\n", $label);
            let t0 = std::time::Instant::now();
            let result = $fut;
            let secs = t0.elapsed().as_secs_f64();
            match &result {
                Ok(_) => eprintln!("=== {} done ({:.1}s) ===", $label, secs),
                Err(e) => eprintln!("=== {} FAILED ({:.1}s): {e} ===", $label, secs),
            }
            let _ = std::io::stderr().flush();
            result?;
        }};
    }

    step!("scan (HTTP)", http_scan::cmd_scan(ScanArgs {
        db: db.clone(), concurrency, save_html: args.save_html, ..ScanArgs::default()
    }).await);

    step!("dns + email security", dns_scan::cmd_dns(DnsArgs {
        db: db.clone(), concurrency: concurrency.min(250), ..DnsArgs::default()
    }).await);

    step!("tls", tls_scan::cmd_tls(TlsArgs {
        db: db.clone(), concurrency: concurrency.min(150), ..TlsArgs::default()
    }).await);

    step!("ports", ports_scan::cmd_ports(PortsArgs {
        db: db.clone(), concurrency: concurrency.min(300), ..PortsArgs::default()
    }).await);

    step!("subdomains", subdomains::cmd_subdomains(SubdomainsArgs {
        db: db.clone(), concurrency: concurrency.min(200), ..SubdomainsArgs::default()
    }).await);

    step!("whois", whois::cmd_whois(WhoisArgs {
        db: db.clone(), ..WhoisArgs::default()
    }).await);

    step!("update-cves", cve::cmd_update_cves(db.clone()).await);

    step!("classify", classify::cmd_classify(db.clone()).await);

    step!("sovereignty", sovereignty::cmd_sovereignty(SovereigntyArgs {
        db: db.clone(),
        asn_mmdb: args.asn_mmdb,
        country_mmdb: args.country_mmdb,
    }).await);

    step!("benchmark", benchmark::cmd_benchmark(db.clone()).await);

    eprintln!("\nfull pipeline complete.");
    Ok(())
}

// ---- single-domain all-scans ----

async fn cmd_single_all(db: PathBuf, domain: &str, retry_errors: Option<String>) -> Result<()> {
    use std::io::Write;
    macro_rules! step {
        ($label:expr, $fut:expr) => {{
            eprint!("  {:<12} ", concat!($label, "..."));
            let _ = std::io::stderr().flush();
            let result = $fut;
            match &result {
                Ok(_) => eprintln!("ok"),
                Err(e) => eprintln!("error: {e}"),
            }
            result?;
        }};
    }

    let domain = schema::ensure_domain_exists(&db, domain)?;
    eprintln!("scanning {domain}");
    step!("http",       http_scan::cmd_scan(ScanArgs {
        db: db.clone(), domain: Some(domain.clone()), no_progress: true,
        retry_errors: retry_errors.clone(), ..ScanArgs::default()
    }).await);
    step!("dns",        dns_scan::cmd_dns(DnsArgs {
        db: db.clone(), domain: Some(domain.clone()), no_progress: true,
        retry_errors: retry_errors.clone(), ..DnsArgs::default()
    }).await);
    step!("tls",        tls_scan::cmd_tls(TlsArgs {
        db: db.clone(), domain: Some(domain.clone()), no_progress: true,
        retry_errors: retry_errors.clone(), ..TlsArgs::default()
    }).await);
    step!("ports",      ports_scan::cmd_ports(PortsArgs {
        db: db.clone(), domain: Some(domain.clone()), no_progress: true,
        retry_errors: retry_errors.clone(), ..PortsArgs::default()
    }).await);
    step!("subdomains", subdomains::cmd_subdomains(SubdomainsArgs {
        db: db.clone(), domain: Some(domain.clone()), no_progress: true,
        ..SubdomainsArgs::default()
    }).await);
    step!("whois",      whois::cmd_whois(WhoisArgs {
        db: db.clone(), domain: Some(domain.clone()), no_progress: true,
        ..WhoisArgs::default()
    }).await);
    print_single_domain_summary(&db, &domain)
}

struct SummaryRow {
    scan: &'static str,
    status: String,
    error_kind: String,
    details: String,
}

fn print_single_domain_summary(db: &PathBuf, domain: &str) -> Result<()> {
    let conn = crate::shared::open_db(db).with_context(|| format!("open db {:?}", db))?;
    let mut rows = Vec::new();

    let domain_row = conn.query_row(
        "SELECT status, error_kind, final_url, status_code, title, server, powered_by
         FROM domains WHERE domain = ?1",
        rusqlite::params![domain],
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
        "SELECT status, error_kind, a, ns
         FROM dns_info WHERE domain = ?1",
        rusqlite::params![domain],
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
        rusqlite::params![domain],
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
        "SELECT SUM(CASE WHEN open = 1 THEN 1 ELSE 0 END),
                GROUP_CONCAT(port ORDER BY port) FILTER (WHERE open = 1)
         FROM ports_info WHERE domain = ?1",
        rusqlite::params![domain],
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
