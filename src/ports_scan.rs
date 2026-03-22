use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
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
    conn: &rusqlite::Connection,
    domain: Option<&str>,
    retry_errors: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(domain) = domain {
        return Ok(vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]);
    }
    if let Some(kind) = retry_errors {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT domain FROM ports_info WHERE error_kind = ? ORDER BY domain"
        )?;
        let domains: Vec<String> = stmt
            .query_map([kind], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        return Ok(domains);
    }
    let mut stmt = conn.prepare(
        "SELECT domain FROM domains WHERE ports_scanned_at IS NULL ORDER BY domain"
    )?;
    let domains: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(domains)
}

pub(crate) fn load_banner_targets(
    conn: &rusqlite::Connection,
) -> Result<HashMap<String, Vec<(u16, IpAddr)>>> {
    let ports_in = BANNER_PORTS.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT domain, port, ip FROM ports_info
         WHERE banner IS NULL AND ip IS NOT NULL AND ip <> '127.0.0.1'
         AND port IN ({ports_in})
         ORDER BY domain"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut map: HashMap<String, Vec<(u16, IpAddr)>> = HashMap::new();
    let rows = stmt.query_map([], |row| {
        let domain: String = row.get(0)?;
        let port: u16 = row.get::<_, i64>(1)? as u16;
        let ip_str: String = row.get(2)?;
        Ok((domain, port, ip_str))
    })?;
    for row in rows {
        let (domain, port, ip_str) = row?;
        if let Ok(ip) = IpAddr::from_str(&ip_str) {
            map.entry(domain).or_default().push((port, ip));
        }
    }
    Ok(map)
}

pub(crate) async fn cmd_ports(
    args: PortsArgs,
    ext_shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ext_progress: Option<std::sync::Arc<Progress>>,
) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    let conn =
        crate::shared::open_db(&args.db).with_context(|| format!("open db {:?}", args.db))?;

    if args.grab_banners {
        let targets = load_banner_targets(&conn)?;
        drop(conn);
        return cmd_grab_banners(args, targets, ext_shutdown_rx, ext_progress).await;
    }

    let pending = load_ports_targets(&conn, args.domain.as_deref(), args.retry_errors.as_deref())?;
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
        None => (Arc::new(Progress::new(pending.len() as u64, "open ports", "no resolve")), true),
    };
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<PortsRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = 500_usize;
        let progress = progress.clone();
        move || writer_loop_ports(db_path, result_rx, progress, done_tx, batch_size)
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

    let dispatcher_handle = tokio::spawn(dispatcher_loop_ports(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        resolver,
        args.clone(),
        dispatcher_cancel_rx,
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
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
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

    if !cancelled {
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
    }

    drop(result_tx);
    Ok(())
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !a.is_loopback()
                && !a.is_private()
                && !a.is_link_local()
                && !a.is_broadcast()
                && o[0] != 0
        }
        IpAddr::V6(a) => !a.is_loopback() && !a.is_unspecified(),
    }
}

async fn fetch_ports_info(resolver: &TokioResolver, domain: String, args: &PortsArgs) -> PortsRow {
    let ip = match resolve_first_ip(resolver, &domain).await {
        Ok(ip) => ip,
        Err(_) => return PortsRow { domain, ip: None, results: vec![] },
    };
    if !is_public_ip(ip) {
        return PortsRow { domain, ip: Some(ip.to_string()), results: vec![] };
    }

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
        banner_ports.iter().map(|&port| grab_banner_for_port(ip, port)),
    ).await;

    for (port, banner) in banner_ports.iter().zip(banners) {
        if let Some(r) = results.iter_mut().find(|r| r.port == *port) {
            r.banner = banner;
        }
    }

    results.retain(|r| r.open);
    PortsRow { domain, ip: Some(ip.to_string()), results }
}

async fn grab_banner_for_port(ip: IpAddr, port: u16) -> Option<String> {
    match port {
        3306  => grab_mysql_banner(ip, port).await,
        6379  => grab_redis_banner(ip, port).await,
        9200  => grab_elasticsearch_banner(ip, port).await,
        2375  => grab_docker_banner(ip, port).await,
        11211 => grab_memcached_banner(ip, port).await,
        27017 => grab_mongodb_banner(ip, port).await,
        _     => grab_banner(ip, port).await,
    }
}

async fn fetch_banners_only(domain: String, targets: Vec<(u16, IpAddr)>) -> PortsRow {
    let ip = targets.first().map(|(_, ip)| ip.to_string());
    let banners = futures_util::future::join_all(
        targets.iter().map(|&(port, ip)| grab_banner_for_port(ip, port)),
    ).await;
    let results = targets.iter().zip(banners)
        .filter_map(|(&(port, _), banner)| {
            banner.map(|b| {
                let service = PORTS.iter()
                    .find(|&&(p, _)| p == port)
                    .map(|&(_, s)| s)
                    .unwrap_or("unknown");
                PortResult { port, service, open: true, banner: Some(b) }
            })
        })
        .collect();
    PortsRow { domain, ip, results }
}

async fn dispatcher_loop_banners(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<PortsRow>,
    sem: Semaphore,
    targets: Arc<HashMap<String, Vec<(u16, IpAddr)>>>,
    concurrency: usize,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let sem = Arc::new(sem);
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
            let Some(domain_targets) = targets.get(&domain).cloned() else { continue; };
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let tx = result_tx.clone();
            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_banners_only(domain, domain_targets).await;
                let _ = tx.send(row).await;
            });
            while joinset.len() >= concurrency {
                if joinset.join_next().await.is_none() { break; }
            }
        }
        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    if !cancelled {
        for domain in batch.drain(..) {
            let Some(domain_targets) = targets.get(&domain).cloned() else { continue; };
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let tx = result_tx.clone();
            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_banners_only(domain, domain_targets).await;
                let _ = tx.send(row).await;
            });
            while joinset.len() >= concurrency {
                if joinset.join_next().await.is_none() { break; }
            }
        }
        while joinset.join_next().await.is_some() {}
    }

    drop(result_tx);
    Ok(())
}

async fn cmd_grab_banners(
    args: PortsArgs,
    targets: HashMap<String, Vec<(u16, IpAddr)>>,
    ext_shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ext_progress: Option<Arc<Progress>>,
) -> Result<()> {
    let pending: Vec<String> = targets.keys().cloned().collect();
    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let targets = Arc::new(targets);
    let (progress, own_progress) = match ext_progress {
        Some(p) => { p.total.store(pending.len() as u64, Ordering::Relaxed); (p, false) }
        None => (Arc::new(Progress::new(pending.len() as u64, "banners", "no banner")), true),
    };
    let buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let (work_tx, work_rx) = mpsc::channel::<String>(buf);
    let (result_tx, result_rx) = mpsc::channel::<PortsRow>(buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let progress = progress.clone();
        move || writer_loop_ports(db_path, result_rx, progress, done_tx, 500)
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
        Some(tokio::spawn(progress_reporter(progress.clone(), Duration::from_secs(1), done_rx)))
    };

    let dispatcher_handle = tokio::spawn(dispatcher_loop_banners(
        work_rx, result_tx,
        Semaphore::new(args.concurrency),
        targets,
        args.concurrency,
        dispatcher_cancel_rx,
    ));

    reader_handle.await.context("banner reader panicked")?.context("banner reader failed")?;
    dispatcher_handle.await.context("banner dispatcher panicked")?.context("banner dispatcher failed")?;
    writer_handle.await.context("banner writer panicked")?.context("banner writer failed")?;

    if let Some(h) = progress_handle { h.abort(); let _ = h.await; }
    Ok(())
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

pub(crate) async fn grab_mysql_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let timeout = Duration::from_millis(500);
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await.ok()?.ok()?;
    // MySQL handshake v10: byte 4 = protocol version (0x0a),
    // bytes 5.. = server version string, null-terminated
    if n < 6 || buf[4] != 0x0a {
        return None;
    }
    let version_bytes = &buf[5..n];
    let end = version_bytes.iter().position(|&b| b == 0)?;
    let version = std::str::from_utf8(&version_bytes[..end]).ok()?.trim();
    if version.is_empty() { None } else { Some(format!("MySQL {version}")) }
}

pub(crate) async fn grab_memcached_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let timeout = Duration::from_millis(500);
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    tokio::time::timeout(timeout, stream.write_all(b"version\r\n"))
        .await.ok()?.ok()?;
    let mut lines = BufReader::new(stream).lines();
    let line = tokio::time::timeout(timeout, lines.next_line())
        .await.ok()?.ok()??;
    // Response: "VERSION 1.6.12"
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

pub(crate) async fn grab_redis_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let timeout = Duration::from_millis(500);
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    tokio::time::timeout(timeout, stream.write_all(b"INFO server\r\n"))
        .await.ok()?.ok()?;
    let mut lines = BufReader::new(stream).lines();
    // Scan lines for "redis_version:x.y.z"
    loop {
        let line = tokio::time::timeout(timeout, lines.next_line())
            .await.ok()?.ok()??;
        let trimmed = line.trim();
        if let Some(v) = trimmed.strip_prefix("redis_version:") {
            let version = v.trim();
            if !version.is_empty() {
                return Some(format!("Redis {version}"));
            }
        }
    }
}

pub(crate) async fn grab_elasticsearch_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let timeout = Duration::from_millis(1000);
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    let req = format!("GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await.ok()?.ok()?;
    let mut body = String::new();
    let mut lines = BufReader::new(stream).lines();
    while let Ok(Some(line)) = tokio::time::timeout(timeout, lines.next_line()).await.ok()? {
        body.push_str(&line);
        if body.len() > 4096 { break; }
    }
    // Extract "number":"8.14.0" from JSON
    let marker = "\"number\":\"";
    let start = body.find(marker)? + marker.len();
    let end = body[start..].find('"')? + start;
    let version = body[start..end].trim();
    if version.is_empty() { None } else { Some(format!("Elasticsearch {version}")) }
}

pub(crate) async fn grab_docker_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let timeout = Duration::from_millis(1000);
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    let req = format!("GET /version HTTP/1.0\r\nHost: {ip}\r\n\r\n");
    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await.ok()?.ok()?;
    let mut body = String::new();
    let mut lines = BufReader::new(stream).lines();
    while let Ok(Some(line)) = tokio::time::timeout(timeout, lines.next_line()).await.ok()? {
        body.push_str(&line);
        if body.len() > 4096 { break; }
    }
    // Extract "Version":"27.3.1" from JSON
    let marker = "\"Version\":\"";
    let start = body.find(marker)? + marker.len();
    let end = body[start..].find('"')? + start;
    let version = body[start..end].trim();
    if version.is_empty() { None } else { Some(format!("Docker {version}")) }
}

pub(crate) async fn grab_mongodb_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let timeout = Duration::from_millis(500);
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    // OP_QUERY isMaster against admin.$cmd
    // BSON: {isMaster: 1}
    let bson_doc: &[u8] = &[
        0x0f, 0x00, 0x00, 0x00,                         // doc length: 15
        0x10,                                            // int32 type
        b'i', b's', b'M', b'a', b's', b't', b'e', b'r', 0x00, // "isMaster\0"
        0x01, 0x00, 0x00, 0x00,                         // value: 1
        0x00,                                            // end of doc
    ];
    let coll: &[u8] = b"admin.$cmd\x00";
    // total = 16 (header) + 4 (flags) + coll.len() + 4 (skip) + 4 (return) + bson.len()
    let total = 16u32 + 4 + coll.len() as u32 + 4 + 4 + bson_doc.len() as u32;
    let mut msg = Vec::with_capacity(total as usize);
    msg.extend_from_slice(&total.to_le_bytes());         // messageLength
    msg.extend_from_slice(&1u32.to_le_bytes());          // requestID
    msg.extend_from_slice(&0u32.to_le_bytes());          // responseTo
    msg.extend_from_slice(&2004u32.to_le_bytes());       // opCode OP_QUERY
    msg.extend_from_slice(&0u32.to_le_bytes());          // flags
    msg.extend_from_slice(coll);                         // fullCollectionName
    msg.extend_from_slice(&0u32.to_le_bytes());          // numberToSkip
    msg.extend_from_slice(&1u32.to_le_bytes());          // numberToReturn
    msg.extend_from_slice(bson_doc);
    tokio::time::timeout(timeout, stream.write_all(&msg))
        .await.ok()?.ok()?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await.ok()?.ok()?;
    // Scan raw bytes for a version string pattern like "5.0.14\0" or in BSON string fields
    // The "version" BSON string field: \x02version\x00 <len:4> <str> \x00
    let needle = b"version\x00";
    let data = &buf[..n];
    let pos = data.windows(needle.len()).position(|w| w == needle)?;
    let after = pos + needle.len();
    if after + 4 >= n { return None; }
    let str_len = u32::from_le_bytes(data[after..after + 4].try_into().ok()?) as usize;
    let str_start = after + 4;
    if str_start + str_len > n || str_len == 0 { return None; }
    let version = std::str::from_utf8(&data[str_start..str_start + str_len - 1]).ok()?.trim();
    if version.is_empty() { None } else { Some(format!("MongoDB {version}")) }
}

fn writer_loop_ports(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<PortsRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = crate::shared::open_db(&db_path)
        .with_context(|| format!("ports writer: open db {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        let open_count = row.results.iter().filter(|r| r.open).count() as u64;
        if open_count > 0 {
            progress.ok.fetch_add(open_count, Ordering::Relaxed);
        } else if row.ip.is_none() {
            progress.errors.fetch_add(1, Ordering::Relaxed);
        }
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            if let Err(e) = flush_ports_batch(&conn, &mut batch) {
                crate::shared::append_error_log(&db_path, &format!("ports flush_batch: {e:#}"));
                return Err(e);
            }
        }
    }
    if !batch.is_empty() {
        if let Err(e) = flush_ports_batch(&conn, &mut batch) {
            crate::shared::append_error_log(&db_path, &format!("ports flush_batch (final): {e:#}"));
            return Err(e);
        }
    }
    let _ = done_tx.send(());
    Ok(())
}

fn flush_ports_batch(conn: &rusqlite::Connection, batch: &mut Vec<PortsRow>) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    {
        let mut port_stmt = conn.prepare(
            "INSERT INTO ports_info (domain, port, service, banner, ip, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
             ON CONFLICT (domain, port) DO UPDATE SET
                banner     = excluded.banner,
                ip         = excluded.ip,
                scanned_at = excluded.scanned_at",
        )?;
        let mut domain_stmt = conn.prepare(
            "UPDATE domains SET ports_scanned_at = datetime('now') WHERE domain = ?1",
        )?;
        for row in batch.iter() {
            for result in row.results.iter() {
                port_stmt.execute(rusqlite::params![
                    row.domain.as_str(),
                    result.port as i32,
                    result.service,
                    result.banner.as_deref(),
                    row.ip.as_deref(),
                ])?;
            }
            domain_stmt.execute(rusqlite::params![row.domain.as_str()])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}
