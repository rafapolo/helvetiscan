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
mod geocode;
mod processing;
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
    /// Enrich domains with hosting country code from GeoLite2-Country.mmdb.
    Geocode(GeocodeArgs),
    /// Export all (or selected) tables from the SQLite database to Parquet files.
    ExportParquet(ExportParquetArgs),
    /// Import Parquet files from a directory back into the SQLite database.
    ImportParquet(ImportParquetArgs),
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

    #[arg(long, help = "Suppress progress bar output")]
    pub(crate) quiet: bool,

    /// Save each fetched HTML body converted to Markdown at <path>/<domain>.md
    #[arg(long)]
    pub(crate) save_md: Option<PathBuf>,

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

    #[arg(long, help = "Suppress progress bar output")]
    pub(crate) quiet: bool,

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

    #[arg(long, help = "Suppress progress bar output")]
    pub(crate) quiet: bool,

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

    #[arg(long, help = "Suppress progress bar output")]
    pub(crate) quiet: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,

    #[arg(long, help = "Re-grab banners for open ports that currently have no banner")]
    pub(crate) grab_banners: bool,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct SubdomainsArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    #[arg(long)]
    pub(crate) domain: Option<String>,

    #[arg(long, default_value_t = 200)]
    pub(crate) concurrency: usize,

    #[arg(long, help = "Suppress progress bar output")]
    pub(crate) quiet: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,
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

    #[arg(long, help = "Suppress progress bar output")]
    pub(crate) quiet: bool,

    #[arg(long, help = "Re-scan domains whose error_kind matches this value (e.g. 'timeout')")]
    pub(crate) retry_errors: Option<String>,
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
pub(crate) struct GeocodeArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    /// Path to GeoLite2-Country.mmdb (offline country lookup).
    #[arg(long, default_value = "data/GeoLite2-Country.mmdb")]
    pub(crate) country_mmdb: PathBuf,
}

#[derive(Parser, Debug)]
pub(crate) struct ExportParquetArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    /// Directory where .parquet files will be written.
    #[arg(long, default_value = "data/export")]
    pub(crate) output_dir: PathBuf,

    /// Tables to skip (can be repeated: --exclude foo --exclude bar).
    #[arg(long)]
    pub(crate) exclude: Vec<String>,
}

#[derive(Parser, Debug)]
pub(crate) struct ImportParquetArgs {
    #[arg(long, default_value = "data/domains.db")]
    pub(crate) db: PathBuf,

    /// Directory containing .parquet files to import.
    #[arg(long, default_value = "data/export")]
    pub(crate) input_dir: PathBuf,

    /// Tables to skip (can be repeated: --exclude foo --exclude bar).
    #[arg(long)]
    pub(crate) exclude: Vec<String>,

    /// How to handle conflicts: replace (default), ignore, or abort.
    #[arg(long, default_value = "replace")]
    pub(crate) on_conflict: String,
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

    /// Save each fetched HTML body converted to Markdown at <path>/<domain>.md
    #[arg(long)]
    pub(crate) save_md: Option<PathBuf>,

    /// Divide each module's default concurrency by this when running in parallel (default: 3).
    #[arg(long, default_value_t = 3)]
    pub(crate) parallel_divisor: usize,

    /// Cancel a module when its error rate exceeds this fraction (0.0-1.0, default: 0.5).
    #[arg(long, default_value_t = 0.5)]
    pub(crate) error_threshold: f64,
}

impl Default for WhoisArgs {
    fn default() -> Self {
        Self {
            db: PathBuf::from("data/domains.db"),
            domain: None,
            concurrency: 5,
            connect_timeout: Duration::from_secs(5),
            quiet: false,
            retry_errors: None,
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
            quiet: false,
            retry_errors: None,
            save_md: None,
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
            quiet: false,
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
            quiet: false,
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
            quiet: false,
            retry_errors: None,
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
            quiet: false,
            retry_errors: None,
            grab_banners: false,
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
                Command::Scan(mut a) => { if a.domain.is_none() { a.domain = Some(domain); } if a.retry_errors.is_none() { a.retry_errors = retry_errors; } http_scan::cmd_scan(a, None, None).await }
                Command::Dns(mut a)  => { if a.domain.is_none() { a.domain = Some(domain); } if a.retry_errors.is_none() { a.retry_errors = retry_errors; } dns_scan::cmd_dns(a, None, None).await }
                Command::Tls(mut a)  => { if a.domain.is_none() { a.domain = Some(domain); } if a.retry_errors.is_none() { a.retry_errors = retry_errors; } tls_scan::cmd_tls(a, None, None).await }
                Command::Ports(mut a) => { if a.domain.is_none() { a.domain = Some(domain); } if a.retry_errors.is_none() { a.retry_errors = retry_errors; } ports_scan::cmd_ports(a, None, None).await }
                Command::Subdomains(mut a) => { if a.domain.is_none() { a.domain = Some(domain); } subdomains::cmd_subdomains(a, None, None).await }
                Command::Whois(mut a) => { if a.domain.is_none() { a.domain = Some(domain); } whois::cmd_whois(a, None, None).await }
                _ => Err(anyhow!("--domain is not supported with this subcommand")),
            }
        }
        // standalone subcommands — thread top-level retry_errors if not set in subcommand args
        (None, db, Some(cmd)) => {
            match cmd {
                Command::Init(args) => schema::cmd_init(args),
                Command::Scan(mut a) => { if a.retry_errors.is_none() { a.retry_errors = retry_errors; } http_scan::cmd_scan(a, None, None).await }
                Command::Dns(mut a)  => { if a.retry_errors.is_none() { a.retry_errors = retry_errors; } dns_scan::cmd_dns(a, None, None).await }
                Command::Tls(mut a)  => { if a.retry_errors.is_none() { a.retry_errors = retry_errors; } tls_scan::cmd_tls(a, None, None).await }
                Command::Ports(mut a) => { if a.retry_errors.is_none() { a.retry_errors = retry_errors; } ports_scan::cmd_ports(a, None, None).await }
                Command::Subdomains(a) => subdomains::cmd_subdomains(a, None, None).await,
                Command::Whois(a) => whois::cmd_whois(a, None, None).await,
                Command::UpdateCves => cve::cmd_update_cves(db).await,
                Command::Classify(a) => classify::cmd_classify(a.db).await,
                Command::Benchmark(a) => benchmark::cmd_benchmark(a.db).await,
                Command::Sovereignty(a) => sovereignty::cmd_sovereignty(a).await,
                Command::Full(a) => cmd_full_pipeline(a).await,
                Command::Geocode(a) => geocode::cmd_geocode(geocode::GeoCodeArgs {
                    db: a.db,
                    country_mmdb: a.country_mmdb,
                }),
                Command::ExportParquet(a) => {
                    processing::export_as_parquet::cmd_export_parquet(a)
                }
                Command::ImportParquet(a) => {
                    processing::import_from_parquet::cmd_import_parquet(a)
                }
            }
        }
        (None, _, None) => unreachable!("clap ensures at least one argument is provided"),
    }
}

// ---- full pipeline ----

pub(crate) async fn error_rate_supervisor(
    modules: Vec<(&'static str, std::sync::Arc<crate::shared::Progress>, tokio::sync::watch::Sender<bool>)>,
    threshold: f64,
    min_samples: u64,
) {
    use std::sync::atomic::Ordering;
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let mut all_done = true;
        for (name, progress, cancel_tx) in &modules {
            let completed = progress.completed.load(Ordering::Relaxed);
            let total = progress.total.load(Ordering::Relaxed);
            let errors = progress.errors.load(Ordering::Relaxed);
            if total == 0 || completed < total {
                all_done = false;
            }
            if completed >= min_samples && errors > 0 {
                let rate = errors as f64 / completed as f64;
                if rate > threshold && !*cancel_tx.borrow() {
                    eprintln!(
                        "\n[pipeline] {name}: error rate {:.1}% exceeds {:.0}% threshold — cancelling",
                        rate * 100.0, threshold * 100.0
                    );
                    let _ = cancel_tx.send(true);
                }
            }
        }
        if all_done { break; }
    }
}

async fn cmd_full_pipeline(args: FullArgs) -> Result<()> {
    use std::sync::Arc;
    use std::io::Write;
    use tokio::task::JoinSet;

    let db = args.db;
    let div = args.parallel_divisor.max(1);
    let error_threshold = args.error_threshold;

    // ── Global shutdown (Ctrl+C / SIGTERM) ──────────────────────────────────
    let (global_tx, global_rx) = tokio::sync::watch::channel(false);
    {
        let tx = global_tx.clone();
        tokio::spawn(async move {
            crate::shared::wait_for_shutdown_signal().await;
            let _ = tx.send(true);
        });
    }

    // Helper: broadcast global shutdown to a list of per-module cancel senders
    let forward_global = |cancel_senders: Vec<tokio::sync::watch::Sender<bool>>| {
        let mut rx = global_rx.clone();
        tokio::spawn(async move {
            if rx.changed().await.is_ok() && *rx.borrow() {
                for tx in cancel_senders {
                    let _ = tx.send(true);
                }
            }
        });
    };

    // ═══════════════════════════════════════════════════════════════════════
    //  Phase 1 — Parallel network scans
    // ═══════════════════════════════════════════════════════════════════════
    eprintln!("\n=== Phase 1: parallel network scans ===");
    let phase1_t0 = std::time::Instant::now();

    // Per-module cancel channels
    let (http_ctx,   http_crx)   = tokio::sync::watch::channel(false);
    let (dns_ctx,    dns_crx)    = tokio::sync::watch::channel(false);
    let (tls_ctx,    tls_crx)    = tokio::sync::watch::channel(false);
    let (ports_ctx,  ports_crx)  = tokio::sync::watch::channel(false);
    let (sub_ctx,    sub_crx)    = tokio::sync::watch::channel(false);
    let (whois_ctx,  whois_crx)  = tokio::sync::watch::channel(false);

    forward_global(vec![
        http_ctx.clone(), dns_ctx.clone(), tls_ctx.clone(),
        ports_ctx.clone(), sub_ctx.clone(), whois_ctx.clone(),
    ]);

    // Per-module progress trackers
    let http_prog  = Arc::new(crate::shared::Progress::new(0, "HTTP 200",   "errors"));
    let dns_prog   = Arc::new(crate::shared::Progress::new(0, "resolved",   "errors"));
    let tls_prog   = Arc::new(crate::shared::Progress::new(0, "valid TLS",  "errors"));
    let ports_prog = Arc::new(crate::shared::Progress::new(0, "open ports", "no resolve"));
    let sub_prog   = Arc::new(crate::shared::Progress::new(0, "found",      "no result"));
    let whois_prog = Arc::new(crate::shared::Progress::new(0, "registrar",  "unknown"));

    // Concurrencies (each module's natural default / parallel_divisor)
    let http_conc  = (500_usize / div).max(1);
    let dns_conc   = (250_usize / div).max(1);
    let tls_conc   = (150_usize / div).max(1);
    let ports_conc = (300_usize / div).max(1);
    let sub_conc   = (200_usize / div).max(1);

    let mut phase1: JoinSet<(&'static str, Result<()>)> = JoinSet::new();

    phase1.spawn({
        let prog = http_prog.clone();
        let crx = http_crx;
        let db = db.clone();
        let save_md = args.save_md.clone();
        let country_mmdb = args.country_mmdb.clone();
        async move {
            let r = http_scan::cmd_scan(ScanArgs {
                db, concurrency: http_conc, save_md, country_mmdb, ..ScanArgs::default()
            }, Some(crx), Some(prog)).await;
            ("http", r)
        }
    });

    phase1.spawn({
        let prog = dns_prog.clone();
        let crx = dns_crx;
        let db = db.clone();
        async move {
            let r = dns_scan::cmd_dns(DnsArgs {
                db, concurrency: dns_conc, ..DnsArgs::default()
            }, Some(crx), Some(prog)).await;
            ("dns", r)
        }
    });

    phase1.spawn({
        let prog = tls_prog.clone();
        let crx = tls_crx;
        let db = db.clone();
        async move {
            let r = tls_scan::cmd_tls(TlsArgs {
                db, concurrency: tls_conc, ..TlsArgs::default()
            }, Some(crx), Some(prog)).await;
            ("tls", r)
        }
    });

    phase1.spawn({
        let prog = ports_prog.clone();
        let crx = ports_crx;
        let db = db.clone();
        async move {
            let r = ports_scan::cmd_ports(PortsArgs {
                db, concurrency: ports_conc, ..PortsArgs::default()
            }, Some(crx), Some(prog)).await;
            ("ports", r)
        }
    });

    phase1.spawn({
        let prog = sub_prog.clone();
        let crx = sub_crx;
        let db = db.clone();
        async move {
            let r = subdomains::cmd_subdomains(SubdomainsArgs {
                db, concurrency: sub_conc, ..SubdomainsArgs::default()
            }, Some(crx), Some(prog)).await;
            ("subdomains", r)
        }
    });

    phase1.spawn({
        let prog = whois_prog.clone();
        let crx = whois_crx;
        let db = db.clone();
        async move {
            let r = whois::cmd_whois(WhoisArgs {
                db, ..WhoisArgs::default()
            }, Some(crx), Some(prog)).await;
            ("whois", r)
        }
    });

    // Multi-line progress reporter for phase 1
    let (p1_done_tx, p1_done_rx) = tokio::sync::oneshot::channel::<()>();
    let reporter = tokio::spawn(crate::shared::multi_progress_reporter(
        vec![
            ("http",      http_prog.clone()),
            ("dns",       dns_prog.clone()),
            ("tls",       tls_prog.clone()),
            ("ports",     ports_prog.clone()),
            ("subdomains",sub_prog.clone()),
            ("whois",     whois_prog.clone()),
        ],
        std::time::Duration::from_secs(1),
        p1_done_rx,
    ));

    // Error-rate supervisor
    let supervisor = tokio::spawn(error_rate_supervisor(
        vec![
            ("http",      http_prog.clone(),  http_ctx),
            ("dns",       dns_prog.clone(),   dns_ctx),
            ("tls",       tls_prog.clone(),   tls_ctx),
            ("ports",     ports_prog.clone(), ports_ctx),
            ("subdomains",sub_prog.clone(),   sub_ctx),
            ("whois",     whois_prog.clone(), whois_ctx),
        ],
        error_threshold,
        100,
    ));

    // Collect phase 1 results silently — don't print while the reporter is live
    // (interleaved eprintln! would corrupt the ANSI cursor positioning).
    let mut phase1_results: Vec<(&str, Result<()>)> = Vec::new();
    let mut phase1_panics: Vec<String> = Vec::new();
    while let Some(join_result) = phase1.join_next().await {
        match join_result {
            Ok(result) => phase1_results.push(result),
            Err(e)     => phase1_panics.push(e.to_string()),
        }
    }

    // Stop reporter (prints one final frame) before printing any text
    let _ = p1_done_tx.send(());
    reporter.abort();
    supervisor.abort();

    let phase1_secs = phase1_t0.elapsed().as_secs_f64();
    eprintln!("\n=== Phase 1 done ({phase1_secs:.1}s) ===");
    for (name, result) in &phase1_results {
        match result {
            Ok(_)  => eprintln!("  {name}: ok"),
            Err(e) => eprintln!("  {name}: FAILED: {e}"),
        }
    }
    for msg in &phase1_panics {
        eprintln!("  task panicked: {msg}");
    }
    let _ = std::io::stderr().flush();

    // ═══════════════════════════════════════════════════════════════════════
    //  Phase 2 — Sequential post-processing (depends on Phase 1 data)
    // ═══════════════════════════════════════════════════════════════════════
    eprintln!("\n=== Phase 2: post-processing ===");
    let phase2_t0 = std::time::Instant::now();

    macro_rules! step2 {
        ($label:expr, $fut:expr) => {{
            eprint!("  {:<20} ", concat!($label, "..."));
            let _ = std::io::stderr().flush();
            let t0 = std::time::Instant::now();
            match $fut {
                Ok(_)  => eprintln!("ok ({:.1}s)", t0.elapsed().as_secs_f64()),
                Err(e) => eprintln!("FAILED ({:.1}s): {e}", t0.elapsed().as_secs_f64()),
            }
        }};
    }

    step2!("update-cves", cve::cmd_update_cves(db.clone()).await);
    step2!("classify",    classify::cmd_classify(db.clone()).await);
    step2!("sovereignty", sovereignty::cmd_sovereignty(SovereigntyArgs {
        db: db.clone(),
        asn_mmdb: args.asn_mmdb,
        country_mmdb: args.country_mmdb,
    }).await);

    let phase2_secs = phase2_t0.elapsed().as_secs_f64();
    eprintln!("=== Phase 2 done ({phase2_secs:.1}s) ===");

    // ═══════════════════════════════════════════════════════════════════════
    //  Phase 3 — Benchmark (reads all tables via risk_score VIEW)
    // ═══════════════════════════════════════════════════════════════════════
    eprintln!("\n=== Phase 3: benchmark ===");
    let phase3_t0 = std::time::Instant::now();
    match benchmark::cmd_benchmark(db.clone()).await {
        Ok(_)  => eprintln!("=== Phase 3 done ({:.1}s) ===", phase3_t0.elapsed().as_secs_f64()),
        Err(e) => eprintln!("=== Phase 3 FAILED ({:.1}s): {e} ===", phase3_t0.elapsed().as_secs_f64()),
    }

    let total_secs = phase1_t0.elapsed().as_secs_f64();
    eprintln!("\nfull pipeline complete ({total_secs:.1}s total).");
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
        db: db.clone(), domain: Some(domain.clone()), quiet: false,
        retry_errors: retry_errors.clone(), ..ScanArgs::default()
    }, None, None).await);
    step!("dns",        dns_scan::cmd_dns(DnsArgs {
        db: db.clone(), domain: Some(domain.clone()), quiet: false,
        retry_errors: retry_errors.clone(), ..DnsArgs::default()
    }, None, None).await);
    step!("tls",        tls_scan::cmd_tls(TlsArgs {
        db: db.clone(), domain: Some(domain.clone()), quiet: false,
        retry_errors: retry_errors.clone(), ..TlsArgs::default()
    }, None, None).await);
    step!("ports",      ports_scan::cmd_ports(PortsArgs {
        db: db.clone(), domain: Some(domain.clone()), quiet: false,
        retry_errors: retry_errors.clone(), ..PortsArgs::default()
    }, None, None).await);
    step!("subdomains", subdomains::cmd_subdomains(SubdomainsArgs {
        db: db.clone(), domain: Some(domain.clone()), quiet: false,
        retry_errors: retry_errors.clone(), ..SubdomainsArgs::default()
    }, None, None).await);
    step!("whois",      whois::cmd_whois(WhoisArgs {
        db: db.clone(), domain: Some(domain.clone()), quiet: false,
        retry_errors: retry_errors.clone(), ..WhoisArgs::default()
    }, None, None).await);
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
        "SELECT COUNT(*), GROUP_CONCAT(port ORDER BY port) FROM ports_info WHERE domain = ?1",
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
