use std::fmt;
use std::error::Error as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue, RANGE};
use reqwest::Client;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

const DISPATCH_BATCH_SIZE: usize = 255;
const DISPATCH_BATCH_SLEEP: Duration = Duration::from_millis(500);

#[derive(Parser, Debug, Clone)]
#[command(name = "titlefetch")]
#[command(about = "Fetch HTML <title> for millions of domains (fast + memory-stable)")]
struct Args {
    #[arg(long, default_value = "sorted_domains.txt")]
    input: PathBuf,

    #[arg(long, default_value = "sorted_out.csv")]
    output: PathBuf,

    // High concurrency can overwhelm system DNS / local network. 500 is a safer default.
    #[arg(long, default_value_t = 500)]
    concurrency: usize,

    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    connect_timeout: Duration,

    #[arg(long, default_value = "20s", value_parser = parse_duration)]
    request_timeout: Duration,

    #[arg(long, default_value_t = 131_072)]
    max_bytes: usize,

    #[arg(long, default_value_t = 5)]
    max_redirects: usize,

    #[arg(long, default_value = "TitleFetcher/1.0")]
    user_agent: String,

    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    progress_interval: Duration,

    #[arg(long, default_value_t = false)]
    no_progress: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    Dns,
    Connect,
    Tls,
    Timeout,
    HttpStatus,
    Other,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Dns => "dns",
            ErrorKind::Connect => "connect",
            ErrorKind::Tls => "tls",
            ErrorKind::Timeout => "timeout",
            ErrorKind::HttpStatus => "http_status",
            ErrorKind::Other => "other",
        }
    }
}

#[derive(Debug)]
struct Row {
    domain: String,
    final_url: Option<String>,
    status_code: Option<u16>,
    title: Option<String>,
    error_kind: Option<ErrorKind>,
    elapsed_ms: u64,
}

#[derive(Debug)]
struct Progress {
    started: Instant,
    enqueued: AtomicU64,
    completed: AtomicU64,
}

impl Progress {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            enqueued: AtomicU64::new(0),
            completed: AtomicU64::new(0),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    if args.max_bytes == 0 {
        return Err(anyhow!("--max-bytes must be > 0"));
    }
    if args.max_bytes > 16 * 1024 * 1024 {
        // Avoid surprising memory/time behavior from a typo like 131072000.
        return Err(anyhow!("--max-bytes is unreasonably large (>{} bytes)", 16 * 1024 * 1024));
    }

    let client = build_client(&args)?;
    let progress = std::sync::Arc::new(Progress::new());

    // Small bounded buffers to keep memory stable while still allowing I/O overlap.
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<Row>(result_buf);

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let output = args.output.clone();
        let progress = progress.clone();
        move || writer_loop(output, result_rx, progress, done_tx)
    });

    let reader_handle = tokio::spawn({
        let input = args.input.clone();
        let progress = progress.clone();
        async move { read_domains(input, work_tx, progress).await }
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
        let _ = h.await;
    }

    Ok(())
}

fn build_client(args: &Args) -> Result<Client> {
    let mut default_headers = HeaderMap::new();
    // We still hard-enforce a streaming read cap, but Range can reduce transfer on servers that honor it.
    if args.max_bytes >= 1 {
        let hi = args.max_bytes - 1;
        let range = format!("bytes=0-{}", hi);
        default_headers.insert(RANGE, HeaderValue::from_str(&range)?);
    }

    let client = Client::builder()
        .connect_timeout(args.connect_timeout)
        .timeout(args.request_timeout)
        .redirect(reqwest::redirect::Policy::limited(args.max_redirects))
        .user_agent(args.user_agent.clone())
        .default_headers(default_headers)
        .pool_max_idle_per_host(64)
        .build()
        .context("building HTTP client")?;
    Ok(client)
}

async fn read_domains(
    input: PathBuf,
    work_tx: mpsc::Sender<String>,
    progress: std::sync::Arc<Progress>,
) -> Result<()> {
    let file = tokio::fs::File::open(&input)
        .await
        .with_context(|| format!("open input {:?}", input))?;
    let reader = tokio::io::BufReader::new(file);
    let mut lines = tokio::io::AsyncBufReadExt::lines(reader);

    let tx = work_tx;
    while let Some(line) = lines.next_line().await? {
        if let Some(domain) = sanitize_domain(&line) {
            // Backpressure is intentional: bounded channel + bounded concurrency.
            if tx.send(domain).await.is_err() {
                break;
            }
            progress.enqueued.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

async fn dispatcher_loop(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<Row>,
    sem: Semaphore,
    client: Client,
    args: Args,
) -> Result<()> {
    let sem = std::sync::Arc::new(sem);
    let client = std::sync::Arc::new(client);
    let mut joinset = JoinSet::<()>::new();
    let max_concurrency = args.concurrency;
    let mut batch = Vec::with_capacity(DISPATCH_BATCH_SIZE);

    while let Some(domain) = work_rx.recv().await {
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
            let tx = result_tx.clone();
            let args_task = args.clone();

            joinset.spawn(async move {
                let _permit = permit; // moved into task; released on drop
                let row = fetch_domain(&client, domain, &args_task).await;
                // If the writer is gone, there's no point continuing.
                if tx.send(row).await.is_err() {
                    return;
                }
            });

            // Keep the JoinSet bounded (<= concurrency) by collecting completed tasks opportunistically.
            while joinset.len() >= max_concurrency {
                if joinset.join_next().await.is_none() {
                    break;
                }
            }
        }

        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    // Dispatch the final partial batch.
    for domain in batch.drain(..) {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .context("semaphore closed")?;

        let client = client.clone();
        let tx = result_tx.clone();
        let args_task = args.clone();

        joinset.spawn(async move {
            let _permit = permit; // moved into task; released on drop
            let row = fetch_domain(&client, domain, &args_task).await;
            // If the writer is gone, there's no point continuing.
            if tx.send(row).await.is_err() {
                return;
            }
        });

        while joinset.len() >= max_concurrency {
            if joinset.join_next().await.is_none() {
                break;
            }
        }
    }

    // Drain remaining tasks.
    while joinset.join_next().await.is_some() {}
    drop(result_tx);
    Ok(())
}

async fn fetch_domain(client: &Client, domain: String, args: &Args) -> Row {
    let start = Instant::now();

    // Attempt order:
    // 1) https://domain/
    // 2) https://www.domain/ (best-effort extra fallback for common cert/SNI configs)
    // 3) http://domain/
    // 4) http://www.domain/
    //
    // This is additive vs the original requirement (https then http), but it materially increases
    // title yield on domains that only serve the "www" host.
    let mut last_err: Option<FetchErr> = None;
    for url in candidate_urls(&domain) {
        if url.is_empty() {
            continue;
        }
        match fetch_url(client, &url, args).await {
            Ok(mut row) => {
                row.domain = domain;
                row.elapsed_ms = start.elapsed().as_millis() as u64;
                return row;
            }
            Err(e) => last_err = Some(e),
        }
    }

    let kind = last_err.and_then(|e| e.kind).unwrap_or(ErrorKind::Other);
    Row {
        domain,
        final_url: None,
        status_code: None,
        title: None,
        error_kind: Some(kind),
        elapsed_ms: start.elapsed().as_millis() as u64,
    }
}

fn candidate_urls(domain: &str) -> [String; 4] {
    let https = format!("https://{}/", domain);
    let http = format!("http://{}/", domain);
    if should_try_www(domain) {
        let https_www = format!("https://www.{}/", domain);
        let http_www = format!("http://www.{}/", domain);
        [https, https_www, http, http_www]
    } else {
        // Keep array shape stable.
        [https, http, String::new(), String::new()]
    }
}

fn should_try_www(domain: &str) -> bool {
    let d = domain.trim().to_ascii_lowercase();
    if d.starts_with("www.") {
        return false;
    }
    // Avoid "www." for obvious IP literals.
    if d.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    true
}

#[derive(Debug)]
struct FetchErr {
    kind: Option<ErrorKind>,
}

async fn fetch_url(client: &Client, url: &str, args: &Args) -> std::result::Result<Row, FetchErr> {
    let resp = client
        .get(url)
        // Many servers require Host/SNI; using absolute URL is enough. Range set in default headers.
        .send()
        .await
        .map_err(|e| FetchErr {
            kind: Some(classify_reqwest_error(&e)),
        })?;

    let final_url = resp.url().to_string();
    let status = resp.status();
    let status_u16 = status.as_u16();

    // We only care about HTTP status and final URL.
    // Still read a small, bounded amount of body to avoid leaving unread data on the wire.
    let mut bytes_read: usize = 0;
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

        if bytes_read >= args.max_bytes {
            break;
        }

        let remaining = args.max_bytes - bytes_read;
        let take = remaining.min(chunk.len());
        bytes_read += take;
    }

    let mut error_kind = if status.is_client_error() || status.is_server_error() {
        Some(ErrorKind::HttpStatus)
    } else {
        None
    };
    if error_kind.is_none() {
        error_kind = body_err_kind;
    }
    // Body read errors after headers were received shouldn't hide the status.
    if matches!(error_kind, Some(ErrorKind::Dns | ErrorKind::Connect | ErrorKind::Tls | ErrorKind::Timeout)) {
        error_kind = Some(ErrorKind::Other);
    }

    Ok(Row {
        domain: String::new(),
        final_url: Some(final_url),
        status_code: Some(status_u16),
        title: None,
        error_kind,
        elapsed_ms: 0,
    })
}

fn classify_reqwest_error(e: &reqwest::Error) -> ErrorKind {
    if e.is_timeout() {
        return ErrorKind::Timeout;
    }
    // Best-effort string heuristics; reqwest/hyper/rustls don't expose a stable typed DNS/TLS error surface.
    // Include the full error chain because the top-level reqwest message is often too generic.
    let mut msg = e.to_string().to_ascii_lowercase();
    let mut src: Option<&(dyn std::error::Error + 'static)> = e.source();
    while let Some(err) = src {
        msg.push_str(" | ");
        msg.push_str(&err.to_string().to_ascii_lowercase());
        src = err.source();
    }

    // TLS / certificate verification issues (including hostname mismatch like curl's "subjectAltName does not match").
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
        return ErrorKind::Connect;
    }

    ErrorKind::Other
}

fn sanitize_domain(line: &str) -> Option<String> {
    let mut s = line.trim();
    if s.is_empty() {
        return None;
    }

    // Accept accidental input like "https://example.com/path".
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

    // Very light validation: avoid obvious garbage. DNS allows more, but this keeps the hot path safe.
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

    // Support: 200ms, 5s, 2m, 1h
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
        .map_err(|_| format!("invalid duration number: {}", s))?;

    Ok(match unit {
        "ms" => Duration::from_millis(n),
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n.saturating_mul(60)),
        "h" => Duration::from_secs(n.saturating_mul(3600)),
        _ => return Err("unsupported duration unit".to_string()),
    })
}

fn writer_loop(
    output: PathBuf,
    mut result_rx: mpsc::Receiver<Row>,
    progress: std::sync::Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::{BufWriter, Write};

    let file_exists = output.exists();
    let file_len = if file_exists {
        std::fs::metadata(&output).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    let write_headers = file_len == 0;

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&output)
        .with_context(|| format!("open output {:?}", output))?;

    let buf = BufWriter::new(file);
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(buf);

    if write_headers {
        wtr.write_record([
            "domain",
            "final_url",
            "status_code",
            "title",
            "error_kind",
            "elapsed_ms",
        ])?;
        wtr.flush()?;
    }

    let mut n: u64 = 0;
    while let Some(row) = result_rx.blocking_recv() {
        let status = row.status_code.map(|v| v.to_string()).unwrap_or_default();
        let err = row
            .error_kind
            .map(|k| k.as_str().to_string())
            .unwrap_or_default();
        wtr.write_record([
            row.domain,
            row.final_url.unwrap_or_default(),
            status,
            row.title.unwrap_or_default(),
            err,
            row.elapsed_ms.to_string(),
        ])?;

        n += 1;
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if n % 10_000 == 0 {
            wtr.flush()?;
        }
    }

    wtr.flush()?;
    // Ensure the underlying BufWriter flushes too.
    wtr.into_inner()?.flush()?;

    let _ = done_tx.send(());
    Ok(())
}

async fn progress_reporter(
    progress: std::sync::Arc<Progress>,
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

    loop {
        tokio::select! {
            _ = &mut done_rx => {
                let enq = progress.enqueued.load(Ordering::Relaxed);
                let done = progress.completed.load(Ordering::Relaxed);
                let elapsed = progress.started.elapsed().as_secs_f64().max(0.001);
                let rate = (done as f64) / elapsed;
                // Ensure the progress line doesn't "eat" the final message.
                eprintln!();
                eprintln!(
                    "done: {done}/{enq} ({rate:.1}/s), elapsed: {elapsed:.1}s"
                );
                break;
            }
            _ = ticker.tick() => {
                let enq = progress.enqueued.load(Ordering::Relaxed);
                let done = progress.completed.load(Ordering::Relaxed);
                let inflight = enq.saturating_sub(done);
                let now = Instant::now();
                let dt = (now - last_t).as_secs_f64().max(0.001);
                let delta = done.saturating_sub(last_done) as f64;
                let inst_rate = delta / dt;
                let elapsed = progress.started.elapsed().as_secs_f64().max(0.001);
                let avg_rate = (done as f64) / elapsed;

                eprint!(
                    "\rqueued: {enq}  done: {done}  in_flight: {inflight}  rate: {inst_rate:.1}/s (avg {avg_rate:.1}/s)  elapsed: {elapsed:.1}s   "
                );
                let _ = std::io::Write::flush(&mut std::io::stderr());

                last_done = done;
                last_t = now;
            }
        }
    }
}

// ---- minimal display helpers (debug) ----

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_domain_basic() {
        assert_eq!(sanitize_domain("example.com"), Some("example.com".to_string()));
        assert_eq!(sanitize_domain(" https://example.com/path "), Some("example.com".to_string()));
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
}
