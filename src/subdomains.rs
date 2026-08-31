use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

use crate::shared::{
    build_default_resolver, progress_reporter, sanitize_domain,
    Progress, SubdomainRow,
    DISPATCH_BATCH_SIZE, DISPATCH_BATCH_SLEEP,
};
use crate::dns_scan::{collect_ip_strings, collect_lookup_strings};
use crate::SubdomainsArgs;

// ---- Global crt.sh rate limiter ----
//
// The old design paid a fixed 2s `sleep` in every task *after* its single crt.sh
// GET, ostensibly "to rate-limit crt.sh". Because each task only ever issues one
// crt.sh request, that sleep never actually throttled a task's request rate — it
// just added 2s of latency to every domain (~half the per-domain wall time on a
// well-connected host). This pacer instead caps the *aggregate* crt.sh request
// rate across all concurrent tasks to `rps` req/s, decoupled from task
// concurrency, and adds latency to a task only when crt.sh is the bottleneck.
struct CrtShPacer {
    interval: Option<Duration>,
    next: tokio::sync::Mutex<tokio::time::Instant>,
}

impl CrtShPacer {
    fn new(rps: f64) -> Self {
        let interval = if rps > 0.0 {
            Some(Duration::from_secs_f64(1.0 / rps))
        } else {
            None // 0 or negative => unlimited (no pacing)
        };
        Self {
            interval,
            next: tokio::sync::Mutex::new(tokio::time::Instant::now()),
        }
    }

    /// Wait until this task is allowed to issue its crt.sh request.
    async fn throttle(&self) {
        let Some(interval) = self.interval else { return };
        let scheduled = {
            let mut next = self.next.lock().await;
            let now = tokio::time::Instant::now();
            let scheduled = (*next).max(now);
            *next = scheduled + interval;
            scheduled
        };
        tokio::time::sleep_until(scheduled).await;
    }
}

// ---- Per-step timing instrumentation (gated by SUBDOMAINS_TIMING=1) ----
use std::sync::atomic::AtomicU64;

#[derive(Clone, Copy)]
enum TimingStep { Ct, Axfr, Harvest }

struct StepTimings {
    ns: [AtomicU64; 3],
    n: [AtomicU64; 3],
    max_ns: [AtomicU64; 3],
}

static TIMINGS: StepTimings = StepTimings {
    ns: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
    n: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
    max_ns: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
};

fn timing_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("SUBDOMAINS_TIMING").is_ok())
}

fn timing_record(step: TimingStep, d: Duration) {
    if !timing_enabled() { return; }
    let i = step as usize;
    let nanos = d.as_nanos() as u64;
    TIMINGS.ns[i].fetch_add(nanos, Ordering::Relaxed);
    TIMINGS.n[i].fetch_add(1, Ordering::Relaxed);
    TIMINGS.max_ns[i].fetch_max(nanos, Ordering::Relaxed);
}

fn timing_report() {
    if !timing_enabled() { return; }
    let labels = ["ct_fetch", "axfr_loop", "mx_ns_harvest"];
    eprintln!("=== subdomains per-step timing (wall time summed across concurrent tasks) ===");
    for i in 0..3 {
        let total = TIMINGS.ns[i].load(Ordering::Relaxed);
        let n = TIMINGS.n[i].load(Ordering::Relaxed).max(1);
        let max = TIMINGS.max_ns[i].load(Ordering::Relaxed);
        eprintln!(
            "  {:<14} avg {:>8.1}ms   max {:>8.1}ms   total {:>10.1}s   (n={})",
            labels[i],
            (total as f64 / n as f64) / 1e6,
            max as f64 / 1e6,
            total as f64 / 1e9,
            n,
        );
    }
}

pub(crate) async fn cmd_subdomains(
    args: SubdomainsArgs,
    ext_shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ext_progress: Option<std::sync::Arc<Progress>>,
) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }

    let conn =
        crate::shared::open_db(&args.db).with_context(|| format!("open db {:?}", args.db))?;
    crate::schema::ensure_schema(&conn)?;

    let pending: Vec<String> = if let Some(domain) = args.domain.as_deref() {
        vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]
    } else {
        let mut stmt = conn.prepare(
            "SELECT d.domain FROM domains d WHERE NOT EXISTS \
             (SELECT 1 FROM subdomains s WHERE s.domain = d.domain) ORDER BY d.domain"
        )?;
        let rows: Vec<String> = stmt.query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        rows
    };
    drop(conn);

    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let (progress, own_progress) = match ext_progress {
        Some(p) => {
            p.total.store(pending.len() as u64, std::sync::atomic::Ordering::Relaxed);
            (p, false)
        }
        None => (Arc::new(Progress::new(pending.len() as u64, "found", "no result")), true),
    };
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<SubdomainRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = 500_usize;
        let progress = progress.clone();
        move || writer_loop_subdomains(db_path, result_rx, progress, done_tx, batch_size)
    });

    let mut shutdown_rx = match ext_shutdown_rx {
        Some(rx) => rx,
        None => {
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                crate::shared::wait_for_shutdown_signal().await;
                let _ = shutdown_tx.send(true);
            });
            shutdown_rx
        }
    };

    let dispatcher_cancel_rx = shutdown_rx.clone();
    let reader_handle = tokio::spawn({
        let progress = progress.clone();
        async move {
            for domain in pending {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    result = work_tx.send(domain) => {
                        if result.is_err() { break; }
                        progress.enqueued.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        }
    });

    let progress_handle = if args.quiet || !own_progress {
        drop(done_rx);
        None
    } else {
        Some(tokio::spawn(progress_reporter(
            progress.clone(),
            Duration::from_secs(1),
            done_rx,
        )))
    };

    let pacer = Arc::new(CrtShPacer::new(args.crtsh_rps));
    let ct_client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(args.concurrency)
            .build()
            .context("build crt.sh HTTP client")?,
    );
    let dispatcher_handle = tokio::spawn(dispatcher_loop_subdomains(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        resolver,
        args.concurrency,
        dispatcher_cancel_rx,
        ct_client,
        pacer,
        args.axfr_budget,
    ));

    reader_handle.await.context("subdomains reader task panicked")?.context("subdomains reader failed")?;
    dispatcher_handle.await.context("subdomains dispatcher task panicked")?.context("subdomains dispatcher failed")?;
    writer_handle.await.context("subdomains writer task panicked")?.context("subdomains writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    timing_report();

    Ok(())
}

async fn dispatcher_loop_subdomains(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<SubdomainRow>,
    sem: Semaphore,
    resolver: TokioResolver,
    max_concurrency: usize,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
    client: Arc<reqwest::Client>,
    pacer: Arc<CrtShPacer>,
    axfr_budget: Duration,
) -> Result<()> {
    let sem = Arc::new(sem);
    let resolver = Arc::new(resolver);
    let mut joinset = JoinSet::<()>::new();
    let mut batch = Vec::with_capacity(DISPATCH_BATCH_SIZE);
    let mut cancelled = false;

    loop {
        let domain = tokio::select! {
            biased;
            _ = cancel_rx.changed() => { cancelled = true; break; }
            maybe = work_rx.recv() => match maybe { Some(d) => d, None => break },
        };
        if result_tx.is_closed() { break; }
        batch.push(domain);
        if batch.len() < DISPATCH_BATCH_SIZE { continue; }

        for domain in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let resolver = resolver.clone();
            let tx = result_tx.clone();
            let client = client.clone();
            let pacer = pacer.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = probe_subdomains(resolver, domain, client, pacer, axfr_budget).await;
                let _ = tx.send(row).await;
            });

            while joinset.len() >= max_concurrency {
                if joinset.join_next().await.is_none() { break; }
            }
        }

        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    if !cancelled {
        for domain in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let resolver = resolver.clone();
            let tx = result_tx.clone();
            let client = client.clone();
            let pacer = pacer.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = probe_subdomains(resolver, domain, client, pacer, axfr_budget).await;
                let _ = tx.send(row).await;
            });

            while joinset.len() >= max_concurrency {
                if joinset.join_next().await.is_none() { break; }
            }
        }

        while joinset.join_next().await.is_some() {}
    }

    drop(result_tx);
    Ok(())
}

async fn probe_subdomains(
    resolver: Arc<TokioResolver>,
    domain: String,
    client: Arc<reqwest::Client>,
    pacer: Arc<CrtShPacer>,
    axfr_budget: Duration,
) -> SubdomainRow {
    let apex_bare = domain.trim_end_matches('.').to_ascii_lowercase();
    let apex_suffix = format!(".{apex_bare}");

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut found: Vec<(String, &'static str)> = Vec::new();

    // CT logs (crt.sh HTTP) and DNS-based discovery (AXFR + NS/MX harvest) hit
    // completely independent services, so run them concurrently instead of
    // serializing CT -> sleep -> AXFR -> harvest. Per-domain wall time becomes
    // roughly max(ct, dns) rather than their sum.
    let ct_fut = async {
        let t = std::time::Instant::now();
        let subs = fetch_ct_subdomains(&apex_bare, &client, &pacer).await;
        timing_record(TimingStep::Ct, t.elapsed());
        subs
    };
    let dns_fut = dns_discovery(&resolver, &domain, &apex_suffix, axfr_budget);

    let (ct_subs, (axfr_subs, harvest_subs)) = tokio::join!(ct_fut, dns_fut);

    for sub in ct_subs {
        if seen.insert(sub.clone()) {
            found.push((sub, "ct"));
        }
    }
    for sub in axfr_subs {
        if seen.insert(sub.clone()) {
            found.push((sub, "axfr"));
        }
    }
    for sub in harvest_subs {
        if seen.insert(sub.clone()) {
            found.push((sub, "mx_ns"));
        }
    }

    found.sort_by(|a, b| a.0.cmp(&b.0));

    SubdomainRow { domain, found }
}

/// DNS-based subdomain discovery: an opportunistic AXFR attempt (bounded by
/// `axfr_budget`) plus an NS/MX harvest. Shares a single NS lookup between the
/// two (the old code looked NS up twice). Returns (axfr_subs, harvest_subs).
async fn dns_discovery(
    resolver: &Arc<TokioResolver>,
    domain: &str,
    apex_suffix: &str,
    axfr_budget: Duration,
) -> (Vec<String>, Vec<String>) {
    // NS and MX resolve concurrently; NS feeds both the AXFR attempt and harvest.
    let (ns_result, mx_result) = tokio::join!(
        collect_lookup_strings(resolver, domain, RecordType::NS),
        collect_lookup_strings(resolver, domain, RecordType::MX),
    );
    let ns_list = ns_result.unwrap_or_default();
    let mx_list = mx_result.unwrap_or_default();

    // AXFR attempt, capped by a single overall deadline instead of letting
    // per-NS connect/read timeouts multiply across every nameserver serially.
    let t = std::time::Instant::now();
    let axfr_subs = tokio::time::timeout(
        axfr_budget,
        try_axfr(resolver, domain, &ns_list),
    )
    .await
    .unwrap_or_default();
    timing_record(TimingStep::Axfr, t.elapsed());

    // NS/MX harvest fallback (reuses the NS list already fetched above).
    let t = std::time::Instant::now();
    let mut harvest = Vec::new();
    for name in ns_list.iter().chain(mx_list.iter()) {
        let clean = name.trim_end_matches('.').to_ascii_lowercase();
        if clean.ends_with(apex_suffix) {
            harvest.push(clean);
        }
    }
    timing_record(TimingStep::Harvest, t.elapsed());

    (axfr_subs, harvest)
}

/// Resolve every nameserver's A/AAAA concurrently, then attempt AXFR against the
/// resulting IPs, stopping at the first that yields a non-empty zone. The whole
/// function is meant to run under an external `timeout(axfr_budget, ...)`.
async fn try_axfr(
    resolver: &Arc<TokioResolver>,
    domain: &str,
    ns_list: &[String],
) -> Vec<String> {
    if ns_list.is_empty() {
        return Vec::new();
    }

    // Resolve A + AAAA for all nameservers in parallel (was serial A-then-AAAA,
    // per NS, across every NS — the dominant cost for the ~all .ch domains that
    // refuse zone transfer).
    let ip_futs = ns_list.iter().map(|ns| {
        let ns_host = ns.trim_end_matches('.').to_string();
        async move {
            let (a, aaaa) = tokio::join!(
                collect_ip_strings(resolver, &ns_host, RecordType::A),
                collect_ip_strings(resolver, &ns_host, RecordType::AAAA),
            );
            let mut ips = a.unwrap_or_default();
            ips.extend(aaaa.unwrap_or_default());
            ips
        }
    });
    let per_ns_ips = futures_util::future::join_all(ip_futs).await;

    let mut tried = std::collections::HashSet::new();
    for ip_str in per_ns_ips.into_iter().flatten() {
        if !tried.insert(ip_str.clone()) {
            continue;
        }
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            let axfr = axfr_from_ns_ip(ip, domain).await;
            if !axfr.is_empty() {
                return axfr;
            }
        }
    }
    Vec::new()
}

/// Attempt DNS zone transfer (AXFR) from `ns_ip` for `domain`.
/// Returns discovered subdomain FQDNs or an empty vec on refusal/failure.
async fn axfr_from_ns_ip(ns_ip: IpAddr, domain: &str) -> Vec<String> {
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_resolver::proto::rr::Name;
    use hickory_resolver::proto::serialize::binary::{BinDecodable, BinEncodable};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(name) = Name::from_ascii(domain) else { return vec![]; };

    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = false;
    msg.add_query(Query::query(name, RecordType::AXFR));

    let Ok(msg_bytes) = msg.to_bytes() else { return vec![]; };

    let addr = SocketAddr::new(ns_ip, 53);
    let stream = match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await {
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
        if resp.metadata.response_code != ResponseCode::NoError { break; }

        for record in &resp.answers {
            if record.record_type() == RecordType::SOA {
                soa_count += 1;
            }
            let rname = record.name.to_ascii().to_ascii_lowercase();
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

/// Issue one crt.sh GET. `Ok(body)` on success; `Err(retryable)` on failure,
/// where `retryable` is false for timeouts (already spent the full budget) and
/// true for fast connection-level errors worth one more attempt.
async fn send_ct_request(client: &reqwest::Client, url: &str) -> std::result::Result<String, bool> {
    match client.get(url).send().await {
        Ok(r) => r.text().await.map_err(|e| !e.is_timeout()),
        Err(e) => Err(!e.is_timeout()),
    }
}

/// Query crt.sh Certificate Transparency logs for known subdomains of `domain`.
async fn fetch_ct_subdomains(domain: &str, client: &reqwest::Client, pacer: &CrtShPacer) -> Vec<String> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    let apex = domain.trim_end_matches('.').to_ascii_lowercase();
    let suffix = format!(".{apex}");

    // Global rate limiter: paces aggregate crt.sh request rate across all tasks.
    pacer.throttle().await;

    // Try once; retry once only on a *fast* failure (connection/reset). A request
    // that already timed out consumed the full budget and would almost certainly
    // time out again on retry, so retrying it just doubled the worst-case tail
    // (30s + 30s = 60s) while pinning a concurrency slot — don't.
    let text = match send_ct_request(client, &url).await {
        Ok(t) => t,
        Err(retryable) => {
            if !retryable {
                return vec![];
            }
            match send_ct_request(client, &url).await {
                Ok(t) => t,
                Err(_) => return vec![],
            }
        }
    };

    let json: Vec<serde_json::Value> = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let mut found = Vec::new();
    for entry in &json {
        if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
            for name in name_value.split('\n') {
                let clean = name.trim().to_ascii_lowercase();
                if clean.ends_with(&suffix) && clean != apex {
                    found.push(clean);
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

fn writer_loop_subdomains(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<SubdomainRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = crate::shared::open_db(&db_path)
        .with_context(|| format!("subdomains writer: open db {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        if row.found.is_empty() {
            progress.errors.fetch_add(1, Ordering::Relaxed);
        } else {
            progress.ok.fetch_add(row.found.len() as u64, Ordering::Relaxed);
        }
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

fn flush_subdomains_batch(conn: &rusqlite::Connection, batch: &mut Vec<SubdomainRow>) -> Result<()> {
    if batch.iter().all(|r| r.found.is_empty()) {
        batch.clear();
        return Ok(());
    }
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO subdomains (domain, subdomain, source, discovered_at)
             VALUES (?1, ?2, ?3, datetime('now'))
             ON CONFLICT DO NOTHING",
        )?;
        for row in batch.iter() {
            for (sub, source) in &row.found {
                stmt.execute(rusqlite::params![
                    row.domain.as_str(),
                    sub.as_str(),
                    source,
                ])?;
            }
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::SubdomainRow;

    fn in_memory_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::schema::ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn flush_subdomains_batch_roundtrip() {
        let conn = in_memory_db();

        let mut batch = vec![SubdomainRow {
            domain: "example.ch".into(),
            found: vec![
                ("www.example.ch".into(), "ct"),
                ("mail.example.ch".into(), "ct"),
            ],
        }];

        flush_subdomains_batch(&conn, &mut batch).unwrap();
        assert!(batch.is_empty());

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM subdomains WHERE domain='example.ch'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);

        let source: String = conn
            .query_row(
                "SELECT source FROM subdomains WHERE subdomain='www.example.ch'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(source, "ct");
    }

    #[test]
    fn flush_subdomains_batch_empty_found_is_noop() {
        let conn = in_memory_db();

        let mut batch = vec![SubdomainRow {
            domain: "empty.ch".into(),
            found: vec![],
        }];

        flush_subdomains_batch(&conn, &mut batch).unwrap();
        assert!(batch.is_empty());

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM subdomains", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn flush_subdomains_batch_deduplicates_on_conflict() {
        let conn = in_memory_db();

        let row = SubdomainRow {
            domain: "dup.ch".into(),
            found: vec![("www.dup.ch".into(), "ct")],
        };

        flush_subdomains_batch(&conn, &mut vec![SubdomainRow { domain: "dup.ch".into(), found: vec![("www.dup.ch".into(), "ct")] }]).unwrap();
        flush_subdomains_batch(&conn, &mut vec![row]).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM subdomains WHERE domain='dup.ch'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "ON CONFLICT DO NOTHING should prevent duplicates");
    }
}
