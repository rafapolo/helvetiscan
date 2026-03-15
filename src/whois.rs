use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

use crate::shared::{
    progress_reporter, sanitize_domain,
    Progress, WhoisRow,
    DISPATCH_BATCH_SIZE, DISPATCH_BATCH_SLEEP,
};
use crate::WhoisArgs;

pub(crate) async fn cmd_whois(args: WhoisArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    crate::schema::ensure_schema(&conn)?;

    let pending: Vec<String> = if let Some(domain) = args.domain.as_deref() {
        vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]
    } else {
        let sql = if args.rescan {
            "SELECT domain FROM domains ORDER BY domain".to_string()
        } else {
            "SELECT d.domain FROM domains d
             LEFT JOIN whois_info w ON w.domain = d.domain
             WHERE w.domain IS NULL
             ORDER BY d.domain".to_string()
        };
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?
    };
    drop(conn);

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

async fn fetch_whois(domain: String, connect_timeout: Duration) -> WhoisRow {
    let mut row = WhoisRow {
        domain: domain.clone(),
        registrar: None,
        whois_created: None,
        expires_at: None,
        status: None,
        dnssec_delegated: None,
    };

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

    parse_whois_response(&mut row, &lines);
    row
}

pub(crate) fn parse_whois_response(row: &mut WhoisRow, lines: &[String]) {
    // Helper: extract value — either inline after "Key: value" or from the next non-empty line
    let next_value = |i: usize, label_len: usize| -> Option<String> {
        let inline = lines[i][label_len..].trim().to_string();
        if !inline.is_empty() {
            Some(inline)
        } else {
            lines[i + 1..].iter().find(|l| !l.trim().is_empty()).map(|l| l.trim().to_string())
        }
    };

    for (i, raw_line) in lines.iter().enumerate() {
        let line = raw_line.trim();
        let lc = line.to_ascii_lowercase();

        if lc.starts_with("registrar:") && row.registrar.is_none() {
            row.registrar = next_value(i, "registrar:".len());
        } else if lc.starts_with("first registration date:") {
            if let Some(val) = next_value(i, "first registration date:".len()) {
                let s = val.trim_start_matches("before").trim().to_string();
                row.whois_created = chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok()
                    .or_else(|| chrono::NaiveDate::parse_from_str(s.get(..10).unwrap_or(""), "%Y-%m-%d").ok());
            }
        } else if lc.starts_with("expiration date:") || lc.starts_with("expires:") || lc.starts_with("expiry date:") {
            let key_len = if lc.starts_with("expiration date:") { "expiration date:".len() }
                          else if lc.starts_with("expiry date:")    { "expiry date:".len() }
                          else                                       { "expires:".len() };
            if let Some(val) = next_value(i, key_len) {
                row.expires_at = chrono::NaiveDate::parse_from_str(val.trim(), "%Y-%m-%d").ok()
                    .or_else(|| chrono::NaiveDate::parse_from_str(val.get(..10).unwrap_or(""), "%Y-%m-%d").ok());
            }
        } else if lc.starts_with("state:") || lc.starts_with("status:") {
            let key_len = if lc.starts_with("state:") { "state:".len() } else { "status:".len() };
            if row.status.is_none() {
                row.status = next_value(i, key_len);
            }
        } else if lc.starts_with("dnssec:") {
            if let Some(val) = next_value(i, "dnssec:".len()) {
                let lc = val.to_ascii_lowercase();
                row.dnssec_delegated = Some(lc.starts_with("signed delegation"));
            }
        }
    }
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

fn flush_whois_batch(conn: &duckdb::Connection, batch: &mut Vec<WhoisRow>) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO whois_info
                (domain, registrar, whois_created, expires_at, status, dnssec_delegated, queried_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NOW())
             ON CONFLICT(domain) DO UPDATE SET
                registrar        = excluded.registrar,
                whois_created    = excluded.whois_created,
                expires_at       = excluded.expires_at,
                status           = excluded.status,
                dnssec_delegated = excluded.dnssec_delegated,
                queried_at       = excluded.queried_at",
        )?;
        for row in batch.iter() {
            stmt.execute(duckdb::params![
                row.domain.as_str(),
                row.registrar.as_deref(),
                row.whois_created.map(|d| d.to_string()),
                row.expires_at.map(|d| d.to_string()),
                row.status.as_deref(),
                row.dnssec_delegated,
            ])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}
