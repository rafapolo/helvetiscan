use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hickory_resolver::TokioResolver;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

use crate::shared::{
    build_default_resolver, classify_io_error, progress_reporter, sanitize_domain,
    ErrorKind, PortResult, PortsRow, Progress,
    BANNER_PORTS, DISPATCH_BATCH_SIZE, DISPATCH_BATCH_SLEEP, PORTS,
};
use crate::dns_scan::resolve_first_ip;
use crate::PortsArgs;

pub(crate) fn load_ports_targets(
    conn: &duckdb::Connection,
    domain: Option<&str>,
    rescan: bool,
) -> Result<Vec<String>> {
    if let Some(domain) = domain {
        return Ok(vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]);
    }
    let sql = if rescan {
        "SELECT domain FROM domains ORDER BY domain".to_string()
    } else {
        "SELECT d.domain FROM domains d
         WHERE NOT EXISTS (SELECT 1 FROM ports_info p WHERE p.domain = d.domain)
         ORDER BY d.domain".to_string()
    };
    let mut stmt = conn.prepare(&sql)?;
    let domains: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(domains)
}

pub(crate) async fn cmd_ports(args: PortsArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    if args.retry_errors.is_some() && args.rescan {
        return Err(anyhow!("--retry-errors and --rescan are mutually exclusive"));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    let pending = load_ports_targets(&conn, args.domain.as_deref(), args.rescan)?;
    drop(conn);

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
    let ip = match resolve_first_ip(resolver, &domain).await {
        Ok(ip) => ip,
        Err(_) => return PortsRow { domain, ip: None, results: vec![] },
    };

    let timeout = args.connect_timeout;
    let probe_results = futures_util::future::join_all(
        PORTS.iter().map(|&(port, _)| port_open(ip, port, timeout)),
    ).await;

    let mut results: Vec<PortResult> = PORTS.iter().zip(probe_results)
        .map(|(&(port, service), result)| PortResult {
            port,
            service,
            open: result.unwrap_or(false),
            banner: None,
        })
        .collect();

    // Grab banners concurrently for banner-eligible open ports
    let banner_ports: Vec<u16> = results.iter()
        .filter(|r| r.open && BANNER_PORTS.contains(&r.port))
        .map(|r| r.port)
        .collect();

    let banners = futures_util::future::join_all(
        banner_ports.iter().map(|&port| grab_banner(ip, port)),
    ).await;

    for (port, banner) in banner_ports.iter().zip(banners) {
        if let Some(r) = results.iter_mut().find(|r| r.port == *port) {
            r.banner = banner;
        }
    }

    PortsRow { domain, ip: Some(ip.to_string()), results }
}

async fn port_open(ip: IpAddr, port: u16, timeout: Duration) -> std::result::Result<bool, ErrorKind> {
    let socket = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(socket)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) => Err(classify_io_error(&e)),
        Err(_) => Err(ErrorKind::Timeout),
    }
}

pub(crate) async fn grab_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let timeout = Duration::from_millis(500);
    let addr = SocketAddr::new(ip, port);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    let mut lines = BufReader::new(stream).lines();
    let line = tokio::time::timeout(timeout, lines.next_line())
        .await.ok()?.ok()??;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
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

fn flush_ports_batch(conn: &duckdb::Connection, batch: &mut Vec<PortsRow>) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO ports_info (domain, port, service, open, banner, ip, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NOW())
             ON CONFLICT (domain, port) DO UPDATE SET
                open       = excluded.open,
                banner     = excluded.banner,
                ip         = excluded.ip,
                scanned_at = excluded.scanned_at",
        )?;
        for row in batch.iter() {
            for result in row.results.iter() {
                stmt.execute(duckdb::params![
                    row.domain.as_str(),
                    result.port as i32,
                    result.service,
                    result.open,
                    result.banner.as_deref(),
                    row.ip.as_deref(),
                ])?;
            }
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}
