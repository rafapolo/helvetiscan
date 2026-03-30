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
    BANNER_PORTS, DISPATCH_BATCH_SIZE, DISPATCH_BATCH_SLEEP, PORTS, UDP_PORTS,
};
use crate::dns_scan::resolve_first_ip;
use crate::PortsArgs;

pub(crate) fn load_ports_targets(
    conn: &rusqlite::Connection,
    domain: Option<&str>,
    retry_errors: Option<&str>,
    ports_filter: Option<&[u16]>,
) -> Result<Vec<(String, Option<String>)>> {
    if let Some(domain) = domain {
        let d = sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?;
        return Ok(vec![(d, None)]);
    }
    if let Some(kind) = retry_errors {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT domain FROM ports_info WHERE error_kind = ? ORDER BY domain"
        )?;
        let rows: Vec<(String, Option<String>)> = stmt
            .query_map([kind], |row| row.get(0))?
            .map(|r| r.map(|d| (d, None)))
            .collect::<std::result::Result<_, _>>()?;
        return Ok(rows);
    }
    if ports_filter.is_some() {
        // Targeted scan: skip domains already processed by a previous --ports run
        let mut stmt = conn.prepare(
            "SELECT domain, ip FROM domains WHERE ports_targeted_at IS NULL ORDER BY domain"
        )?;
        let rows: Vec<(String, Option<String>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        return Ok(rows);
    }
    let mut stmt = conn.prepare(
        "SELECT domain, ip FROM domains WHERE ports_scanned_at IS NULL ORDER BY domain"
    )?;
    let rows: Vec<(String, Option<String>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(rows)
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
    crate::schema::migrate_ports_targeted_at(&conn)?;

    if args.grab_banners {
        let targets = load_banner_targets(&conn)?;
        drop(conn);
        return cmd_grab_banners(args, targets, ext_shutdown_rx, ext_progress).await;
    }

    let pending = load_ports_targets(&conn, args.domain.as_deref(), args.retry_errors.as_deref(), args.ports.as_deref())?;
    drop(conn);

    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let progress_label = if args.ports.is_some() { "port rescan" } else { "open ports" };
    let (progress, own_progress) = match ext_progress {
        Some(p) => {
            p.total.store(pending.len() as u64, std::sync::atomic::Ordering::Relaxed);
            (p, false)
        }
        None => (Arc::new(Progress::new(pending.len() as u64, progress_label, "no resolve")), true),
    };
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<(String, Option<String>)>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<PortsRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = 500_usize;
        let progress = progress.clone();
        let update_scanned_at = args.ports.is_none();
        move || writer_loop_ports(db_path, result_rx, progress, done_tx, batch_size, update_scanned_at)
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
    mut work_rx: mpsc::Receiver<(String, Option<String>)>,
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
        let item = tokio::select! {
            biased;
            _ = cancel_rx.changed() => { cancelled = true; break; }
            maybe = work_rx.recv() => match maybe { Some(d) => d, None => break },
        };
        if result_tx.is_closed() { break; }
        batch.push(item);
        if batch.len() < DISPATCH_BATCH_SIZE {
            continue;
        }

        for (domain, stored_ip) in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let tx = result_tx.clone();
            let resolver = resolver.clone();
            let args_task = args.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_ports_info(&resolver, domain, stored_ip, &args_task).await;
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
        for (domain, stored_ip) in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let tx = result_tx.clone();
            let resolver = resolver.clone();
            let args_task = args.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_ports_info(&resolver, domain, stored_ip, &args_task).await;
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

async fn fetch_ports_info(resolver: &TokioResolver, domain: String, stored_ip: Option<String>, args: &PortsArgs) -> PortsRow {
    let ip = if let Some(ref s) = stored_ip {
        match IpAddr::from_str(s) {
            Ok(ip) if is_public_ip(ip) => ip,
            _ => match resolve_first_ip(resolver, &domain).await {
                Ok(ip) => ip,
                Err(_) => return PortsRow { domain, ip: None, results: vec![] },
            },
        }
    } else {
        match resolve_first_ip(resolver, &domain).await {
            Ok(ip) => ip,
            Err(_) => return PortsRow { domain, ip: None, results: vec![] },
        }
    };
    if !is_public_ip(ip) {
        return PortsRow { domain, ip: Some(ip.to_string()), results: vec![] };
    }

    let timeout = args.connect_timeout;
    let tcp_ports: Vec<(u16, &str)> = match args.ports.as_deref() {
        None => PORTS.to_vec(),
        Some(f) => PORTS.iter().filter(|&&(p, _)| f.contains(&p)).copied().collect(),
    };
    let scan_snmp = args.ports.as_deref().map_or(true, |f| f.contains(&161));

    let (probe_results, snmp_banner) = tokio::join!(
        futures_util::future::join_all(tcp_ports.iter().map(|&(port, _)| port_open(ip, port, timeout))),
        async { if scan_snmp { grab_snmp_banner(ip, 161).await } else { None } },
    );

    let mut results: Vec<PortResult> = tcp_ports.iter().zip(probe_results)
        .map(|(&(port, service), result)| PortResult {
            port,
            service,
            open: result.unwrap_or(false),
            banner: None,
        })
        .collect();

    if scan_snmp {
        results.push(PortResult {
            port: 161,
            service: "snmp",
            open: snmp_banner.is_some(),
            banner: snmp_banner,
        });
    }

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
        21       => grab_banner(ip, port).await,
        22       => grab_banner(ip, port).await,
        25 | 587 => grab_smtp_banner(ip, port).await,
        3306     => grab_mysql_banner(ip, port).await,
        6379     => grab_redis_banner(ip, port).await,
        6443     => grab_kubernetes_banner(ip, port).await,
        9200     => grab_elasticsearch_banner(ip, port).await,
        2375     => grab_docker_banner(ip, port).await,
        11211    => grab_memcached_banner(ip, port).await,
        27017    => grab_mongodb_banner(ip, port).await,
        389      => grab_ldap_banner(ip, port).await,
        1433     => grab_mssql_banner(ip, port).await,
        161      => grab_snmp_banner(ip, port).await,
        _        => grab_banner(ip, port).await,
    }
}

pub(crate) async fn grab_smtp_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let timeout = Duration::from_millis(1000);
    let addr = SocketAddr::new(ip, port);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    // Read 220 greeting (multi-line greetings use "220-" continuation lines)
    let mut mta_info = String::new();
    loop {
        let line = tokio::time::timeout(timeout, lines.next_line())
            .await.ok()?.ok()??;
        let trimmed = line.trim();
        if mta_info.is_empty() {
            mta_info = trimmed
                .trim_start_matches("220-")
                .trim_start_matches("220 ")
                .to_string();
        }
        if !trimmed.starts_with("220-") {
            break;
        }
    }
    if mta_info.is_empty() {
        return None;
    }

    // Send EHLO to enumerate capabilities
    tokio::time::timeout(timeout, writer.write_all(b"EHLO scanner\r\n"))
        .await.ok()?.ok()?;

    let mut has_starttls = false;
    let mut auth_methods: Vec<String> = Vec::new();
    loop {
        let line = match tokio::time::timeout(timeout, lines.next_line()).await {
            Ok(Ok(Some(l))) => l,
            _ => break,
        };
        let trimmed = line.trim();
        let upper = trimmed.to_ascii_uppercase();
        if upper.contains("STARTTLS") {
            has_starttls = true;
        }
        if let Some(methods) = upper.strip_prefix("250-AUTH ").or_else(|| upper.strip_prefix("250 AUTH ")) {
            auth_methods.extend(methods.split_whitespace().map(|s| s.to_string()));
        }
        if !trimmed.starts_with("250-") {
            break;
        }
    }

    let mut result = mta_info;
    if has_starttls || !auth_methods.is_empty() {
        let mut caps = Vec::new();
        if has_starttls {
            caps.push("STARTTLS".to_string());
        }
        if !auth_methods.is_empty() {
            caps.push(format!("AUTH={}", auth_methods.join(",")));
        }
        result.push_str(&format!(" ({})", caps.join(" ")));
    }
    Some(result)
}

pub(crate) async fn grab_kubernetes_banner(ip: IpAddr, port: u16) -> Option<String> {
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
        if body.len() > 2048 {
            break;
        }
    }
    // Extract "gitVersion":"v1.28.3" from the JSON response
    let marker = "\"gitVersion\":\"";
    let start = body.find(marker)? + marker.len();
    let end = body[start..].find('"')? + start;
    let version = body[start..end].trim();
    if version.is_empty() { None } else { Some(format!("Kubernetes {version}")) }
}

async fn fetch_banners_only(domain: String, targets: Vec<(u16, IpAddr)>) -> PortsRow {
    let ip = targets.first().map(|(_, ip)| ip.to_string());
    let banners = futures_util::future::join_all(
        targets.iter().map(|&(port, ip)| grab_banner_for_port(ip, port)),
    ).await;
    let results = targets.iter().zip(banners)
        .map(|(&(port, _), banner)| {
            let service = PORTS.iter()
                .chain(UDP_PORTS.iter())
                .find(|&&(p, _)| p == port)
                .map(|&(_, s)| s)
                .unwrap_or("unknown");
            // Use "" as sentinel so banner IS NULL check excludes already-attempted ports
            PortResult { port, service, open: true, banner: Some(banner.unwrap_or_default()) }
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
        move || writer_loop_ports(db_path, result_rx, progress, done_tx, 500, true)
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

pub(crate) async fn grab_ldap_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let timeout = Duration::from_millis(1000);
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    // Anonymous LDAPv3 bind request (messageID=1, name="", simple auth "")
    let bind_req: &[u8] = &[
        0x30, 0x0c,        // LDAPMessage SEQUENCE
        0x02, 0x01, 0x01,  // messageID = 1
        0x60, 0x07,        // BindRequest [APPLICATION 0]
        0x02, 0x01, 0x03,  // version = 3
        0x04, 0x00,        // name = ""
        0x80, 0x00,        // simple = ""
    ];
    tokio::time::timeout(timeout, stream.write_all(bind_req)).await.ok()?.ok()?;
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n < 7 { return None; }
    let data = &buf[..n];
    // Find ENUMERATED result code: tag 0x0a, length 0x01, then result_code
    let pos = data.windows(2).position(|w| w[0] == 0x0a && w[1] == 0x01)?;
    let result_code = *data.get(pos + 2)?;
    Some(match result_code {
        0  => "LDAP anonymous bind accepted".to_string(),
        7  => "LDAP authentication method not supported".to_string(),
        49 => "LDAP authentication required".to_string(),
        _  => format!("LDAP result={result_code}"),
    })
}

pub(crate) async fn grab_mssql_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let timeout = Duration::from_millis(1000);
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await.ok()?.ok()?;
    // TDS prelogin packet (47 bytes):
    // 5 tokens (VERSION/ENCRYPTION/INSTOPT/THREADID/MARS) + terminator + data
    let prelogin: &[u8] = &[
        0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, // TDS header
        0x00, 0x00, 0x1a, 0x00, 0x06, // VERSION: stream-offset=26, len=6
        0x01, 0x00, 0x20, 0x00, 0x01, // ENCRYPTION: offset=32, len=1
        0x02, 0x00, 0x21, 0x00, 0x01, // INSTOPT: offset=33, len=1
        0x03, 0x00, 0x22, 0x00, 0x04, // THREADID: offset=34, len=4
        0x04, 0x00, 0x26, 0x00, 0x01, // MARS: offset=38, len=1
        0xff,                          // TERMINATOR
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // VERSION data (client version = 0)
        0x02,                          // ENCRYPTION = ENCRYPT_NOT_SUP
        0x00,                          // INSTOPT
        0x00, 0x00, 0x00, 0x00,        // THREADID
        0x00,                          // MARS
    ];
    tokio::time::timeout(timeout, stream.write_all(prelogin)).await.ok()?.ok()?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n < 8 { return None; }
    let data = &buf[..n];
    // Parse token stream starting at byte 8, find VERSION token (type=0x00)
    let mut i = 8usize;
    loop {
        if i >= n { return None; }
        let token_type = data[i];
        if token_type == 0xff { return None; }
        if i + 5 > n { return None; }
        let offset = u16::from_be_bytes([data[i + 1], data[i + 2]]) as usize;
        let length = u16::from_be_bytes([data[i + 3], data[i + 4]]) as usize;
        if token_type == 0x00 {
            let abs = 8 + offset;
            if abs + 4 > n || length < 4 { return None; }
            let major = data[abs];
            let minor = data[abs + 1];
            let build = u16::from_be_bytes([data[abs + 2], data[abs + 3]]);
            return Some(format!("MSSQL {major}.{minor} build {build}"));
        }
        i += 5;
    }
}

pub(crate) async fn grab_snmp_banner(ip: IpAddr, port: u16) -> Option<String> {
    use tokio::net::UdpSocket;
    let timeout = Duration::from_millis(1500);
    let bind_addr: SocketAddr = if ip.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind_addr).await.ok()?;
    socket.connect(SocketAddr::new(ip, port)).await.ok()?;
    // SNMP v1 GetRequest for sysDescr (OID 1.3.6.1.2.1.1.1.0), community "public"
    let pkt: &[u8] = &[
        0x30, 0x29,
        0x02, 0x01, 0x00,                                        // version = 0 (SNMPv1)
        0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',         // community = "public"
        0xa0, 0x1c,                                              // GetRequest-PDU
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,                      // request-id = 1
        0x02, 0x01, 0x00,                                        // error-status = 0
        0x02, 0x01, 0x00,                                        // error-index = 0
        0x30, 0x0e,                                              // VarBindList
        0x30, 0x0c,                                              // VarBind
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID 1.3.6.1.2.1.1.1.0
        0x05, 0x00,                                              // NULL value
    ];
    tokio::time::timeout(timeout, socket.send(pkt)).await.ok()?.ok()?;
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf)).await.ok()?.ok()?;
    let data = &buf[..n];
    // Find sysDescr OID in response, extract following OCTET STRING value
    let oid: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let pos = data.windows(oid.len()).position(|w| w == oid)?;
    let after = pos + oid.len();
    if after + 2 > n || data[after] != 0x04 {
        return Some("SNMP".to_string()); // responded but couldn't parse sysDescr
    }
    // BER length decoding
    let (str_len, header_bytes) = if data[after + 1] & 0x80 == 0 {
        (data[after + 1] as usize, 2usize)
    } else {
        let num_bytes = (data[after + 1] & 0x7f) as usize;
        if num_bytes == 0 || after + 2 + num_bytes > n {
            return Some("SNMP".to_string());
        }
        let mut l = 0usize;
        for i in 0..num_bytes {
            l = (l << 8) | (data[after + 2 + i] as usize);
        }
        (l, 2 + num_bytes)
    };
    let str_start = after + header_bytes;
    if str_start + str_len > n { return Some("SNMP".to_string()); }
    let desc: String = data[str_start..str_start + str_len]
        .iter()
        .filter(|&&b| b >= 0x20 && b < 0x7f)
        .take(200)
        .map(|&b| b as char)
        .collect();
    if desc.is_empty() { Some("SNMP".to_string()) } else { Some(desc) }
}

fn writer_loop_ports(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<PortsRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
    update_scanned_at: bool,
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
            if let Err(e) = flush_ports_batch(&conn, &mut batch, update_scanned_at) {
                crate::shared::append_error_log(&db_path, &format!("ports flush_batch: {e:#}"));
                return Err(e);
            }
        }
    }
    if !batch.is_empty() {
        if let Err(e) = flush_ports_batch(&conn, &mut batch, update_scanned_at) {
            crate::shared::append_error_log(&db_path, &format!("ports flush_batch (final): {e:#}"));
            return Err(e);
        }
    }
    let _ = done_tx.send(());
    Ok(())
}

fn flush_ports_batch(conn: &rusqlite::Connection, batch: &mut Vec<PortsRow>, update_scanned_at: bool) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    {
        let mut port_stmt = conn.prepare(
            "INSERT INTO ports_info (domain, port, service, banner, ip, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
             ON CONFLICT (domain, port) DO UPDATE SET
                banner     = COALESCE(excluded.banner, ports_info.banner),
                ip         = excluded.ip,
                scanned_at = excluded.scanned_at",
        )?;
        let mut scanned_stmt = conn.prepare(
            "UPDATE domains SET ports_scanned_at = datetime('now') WHERE domain = ?1",
        )?;
        let mut targeted_stmt = conn.prepare(
            "UPDATE domains SET ports_targeted_at = datetime('now') WHERE domain = ?1",
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
            if update_scanned_at {
                scanned_stmt.execute(rusqlite::params![row.domain.as_str()])?;
            } else {
                targeted_stmt.execute(rusqlite::params![row.domain.as_str()])?;
            }
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}
