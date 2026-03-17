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

    let progress_handle = if args.no_progress || !own_progress {
        drop(done_rx);
        None
    } else {
        Some(tokio::spawn(progress_reporter(
            progress.clone(),
            Duration::from_secs(1),
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

async fn probe_subdomains(resolver: Arc<TokioResolver>, domain: String) -> SubdomainRow {
    let apex_bare = domain.trim_end_matches('.').to_ascii_lowercase();
    let apex_suffix = format!(".{apex_bare}");

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut found: Vec<(String, &'static str)> = Vec::new();

    // 1. CT logs (primary)
    for sub in fetch_ct_subdomains(&apex_bare).await {
        if seen.insert(sub.clone()) {
            found.push((sub, "ct"));
        }
    }

    // 2. AXFR (opportunistic) — 2-second pause after CT fetch to rate-limit crt.sh
    tokio::time::sleep(Duration::from_secs(2)).await;

    let ns_list = collect_lookup_strings(&resolver, &domain, RecordType::NS)
        .await
        .unwrap_or_default();

    'axfr: for ns in &ns_list {
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
                let axfr = axfr_from_ns_ip(ip, &domain).await;
                if !axfr.is_empty() {
                    for sub in axfr {
                        if seen.insert(sub.clone()) {
                            found.push((sub, "axfr"));
                        }
                    }
                    break 'axfr;
                }
            }
        }
    }

    // 3. NS/MX harvest (fallback)
    let (mx_result, ns_result) = tokio::join!(
        collect_lookup_strings(&resolver, &domain, RecordType::MX),
        collect_lookup_strings(&resolver, &domain, RecordType::NS),
    );
    for name in ns_result.unwrap_or_default().into_iter().chain(mx_result.unwrap_or_default()) {
        let clean = name.trim_end_matches('.').to_ascii_lowercase();
        if clean.ends_with(&apex_suffix) && seen.insert(clean.clone()) {
            found.push((clean, "mx_ns"));
        }
    }

    found.sort_by(|a, b| a.0.cmp(&b.0));

    SubdomainRow { domain, found }
}

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

/// Query crt.sh Certificate Transparency logs for known subdomains of `domain`.
async fn fetch_ct_subdomains(domain: &str) -> Vec<String> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    let apex = domain.trim_end_matches('.').to_ascii_lowercase();
    let suffix = format!(".{apex}");

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    // Try once; on failure retry once
    let text = match client.get(&url).send().await {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(_) => return vec![],
        },
        Err(_) => match client.get(&url).send().await {
            Ok(r) => match r.text().await {
                Ok(t) => t,
                Err(_) => return vec![],
            },
            Err(_) => return vec![],
        },
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
