use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use crate::shared::{
    build_default_resolver, progress_reporter, sql_bool, sql_string, sql_string_opt,
    DISPATCH_BATCH_SIZE, DISPATCH_BATCH_SLEEP, Progress,
};
use crate::dns_scan::resolve_first_ip;
use crate::SmtpCheckArgs;

#[derive(Debug, Clone)]
pub(crate) struct SmtpTlsRow {
    pub(crate) domain: String,
    pub(crate) port: u16,
    pub(crate) smtp_banner: Option<String>,
    pub(crate) ehlo_response: Option<String>,
    pub(crate) has_starttls: bool,
    pub(crate) starttls_works: bool,
    pub(crate) tls_version: Option<String>,
    pub(crate) cipher: Option<String>,
    pub(crate) error: Option<String>,
}

fn load_smtp_targets(
    conn: &rusqlite::Connection,
    domain: Option<&str>,
) -> Result<Vec<(String, u16)>> {
    if let Some(domain) = domain {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT domain, port FROM ports_info
             WHERE domain = ?1 AND port IN (25, 587)"
        )?;
        let rows: Vec<(String, u16)> = stmt
            .query_map([domain], |row| {
                let d: String = row.get(0)?;
                let p: i64 = row.get(1)?;
                Ok((d, p as u16))
            })?
            .filter_map(|r| r.ok())
            .collect();
        return Ok(rows);
    }

    let mut stmt = conn.prepare(
        "SELECT DISTINCT domain, port FROM ports_info
         WHERE port IN (25, 587)
         ORDER BY domain"
    )?;
    let rows: Vec<(String, u16)> = stmt
        .query_map([], |row| {
            let d: String = row.get(0)?;
            let p: i64 = row.get(1)?;
            Ok((d, p as u16))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

pub(crate) async fn cmd_smtp_check(
    args: SmtpCheckArgs,
    ext_shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ext_progress: Option<Arc<Progress>>,
) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow::anyhow!("--concurrency must be > 0"));
    }
    let conn = crate::shared::open_db(&args.db)
        .with_context(|| format!("open db {:?}", args.db))?;
    crate::schema::ensure_smtp_tls_check_schema(&conn)?;

    let pending = load_smtp_targets(&conn, args.domain.as_deref())?;
    drop(conn);

    if pending.is_empty() {
        eprintln!("No SMTP targets found (no open ports 25/587 in ports_info).");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let tls_connector = build_smtp_tls_connector();

    let (progress, own_progress) = match ext_progress {
        Some(p) => {
            p.total.store(pending.len() as u64, Ordering::Relaxed);
            (p, false)
        }
        None => (
            Arc::new(Progress::new(
                pending.len() as u64,
                "starttls ok",
                "no starttls",
            )),
            true,
        ),
    };
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<(String, u16)>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<SmtpTlsRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let progress = progress.clone();
        move || writer_loop(db_path, result_rx, progress, done_tx, 500)
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
            for target in pending {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    result = work_tx.send(target) => {
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

    let dispatcher_handle = tokio::spawn(dispatcher_loop(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        resolver,
        tls_connector,
        args.clone(),
        dispatcher_cancel_rx,
    ));

    reader_handle
        .await
        .context("smtp-check reader task panicked")?
        .context("smtp-check reader failed")?;
    dispatcher_handle
        .await
        .context("smtp-check dispatcher task panicked")?
        .context("smtp-check dispatcher failed")?;
    writer_handle
        .await
        .context("smtp-check writer task panicked")?
        .context("smtp-check writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

fn build_smtp_tls_connector() -> TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn dispatcher_loop(
    mut work_rx: mpsc::Receiver<(String, u16)>,
    result_tx: mpsc::Sender<SmtpTlsRow>,
    sem: Semaphore,
    resolver: hickory_resolver::TokioResolver,
    connector: TlsConnector,
    args: SmtpCheckArgs,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let sem = Arc::new(sem);
    let resolver = Arc::new(resolver);
    let connector = Arc::new(connector);
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
        if batch.len() < DISPATCH_BATCH_SIZE { continue; }
        for (domain, port) in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let tx = result_tx.clone();
            let resolver = resolver.clone();
            let connector = connector.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = check_smtp_tls(&connector, &resolver, domain, port).await;
                let _ = tx.send(row).await;
            });
            while joinset.len() >= args.concurrency {
                if joinset.join_next().await.is_none() { break; }
            }
        }
        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    if !cancelled {
        for (domain, port) in batch.drain(..) {
            let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
            let tx = result_tx.clone();
            let resolver = resolver.clone();
            let connector = connector.clone();
            joinset.spawn(async move {
                let _permit = permit;
                let row = check_smtp_tls(&connector, &resolver, domain, port).await;
                let _ = tx.send(row).await;
            });
            while joinset.len() >= args.concurrency {
                if joinset.join_next().await.is_none() { break; }
            }
        }
        while joinset.join_next().await.is_some() {}
    }

    drop(result_tx);
    Ok(())
}

async fn check_smtp_tls(
    connector: &TlsConnector,
    resolver: &hickory_resolver::TokioResolver,
    domain: String,
    port: u16,
) -> SmtpTlsRow {
    let timeout = Duration::from_secs(5);

    let ip = match resolve_first_ip(resolver, &domain).await {
        Ok(ip) => ip,
        Err(_) => {
            return SmtpTlsRow {
                domain,
                port,
                smtp_banner: None,
                ehlo_response: None,
                has_starttls: false,
                starttls_works: false,
                tls_version: None,
                cipher: None,
                error: Some("dns_resolution_failed".to_string()),
            };
        }
    };

    let addr = SocketAddr::new(ip, port);
    let stream = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            return SmtpTlsRow {
                domain,
                port,
                smtp_banner: None,
                ehlo_response: None,
                has_starttls: false,
                starttls_works: false,
                tls_version: None,
                cipher: None,
                error: Some("connection_failed".to_string()),
            };
        }
    };

    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let greeting = match tokio::time::timeout(timeout, read_smtp_greeting(&mut lines)).await {
        Ok(Some(g)) => g,
        _ => {
            return SmtpTlsRow {
                domain,
                port,
                smtp_banner: None,
                ehlo_response: None,
                has_starttls: false,
                starttls_works: false,
                tls_version: None,
                cipher: None,
                error: Some("no_greeting".to_string()),
            };
        }
    };

    let ehlo_result = match tokio::time::timeout(timeout, send_ehlo(&mut writer, &mut lines)).await {
        Ok(Some(r)) => r,
        _ => {
            return SmtpTlsRow {
                domain,
                port,
                smtp_banner: Some(greeting.clone()),
                ehlo_response: None,
                has_starttls: false,
                starttls_works: false,
                tls_version: None,
                cipher: None,
                error: Some("ehlo_failed".to_string()),
            };
        }
    };

    let (ehlo_text, has_starttls, _auth_methods) = ehlo_result;

    if !has_starttls {
        return SmtpTlsRow {
            domain,
            port,
            smtp_banner: Some(greeting),
            ehlo_response: Some(ehlo_text),
            has_starttls: false,
            starttls_works: false,
            tls_version: None,
            cipher: None,
            error: None,
        };
    }

    if tokio::time::timeout(timeout, writer.write_all(b"STARTTLS\r\n")).await.ok().and_then(|r| r.ok()).is_none() {
        return SmtpTlsRow {
            domain,
            port,
            smtp_banner: Some(greeting),
            ehlo_response: Some(ehlo_text),
            has_starttls: true,
            starttls_works: false,
            tls_version: None,
            cipher: None,
            error: Some("starttls_command_failed".to_string()),
        };
    }

    let starttls_response = match tokio::time::timeout(timeout, lines.next_line()).await {
        Ok(Ok(Some(line))) => line,
        _ => {
            return SmtpTlsRow {
                domain,
                port,
                smtp_banner: Some(greeting),
                ehlo_response: Some(ehlo_text),
                has_starttls: true,
                starttls_works: false,
                tls_version: None,
                cipher: None,
                error: Some("no_starttls_response".to_string()),
            };
        }
    };

    let trimmed = starttls_response.trim();
    if !trimmed.starts_with("220") {
        return SmtpTlsRow {
            domain,
            port,
            smtp_banner: Some(greeting),
            ehlo_response: Some(ehlo_text),
            has_starttls: true,
            starttls_works: false,
            tls_version: None,
            cipher: None,
            error: Some(format!("starttls_rejected: {}", trimmed)),
        };
    }

    let tcp_stream = match writer.reunite(lines.into_inner().into_inner()) {
        Ok(s) => s,
        Err(_) => {
            return SmtpTlsRow {
                domain,
                port,
                smtp_banner: Some(greeting),
                ehlo_response: Some(ehlo_text),
                has_starttls: true,
                starttls_works: false,
                tls_version: None,
                cipher: None,
                error: Some("reunite_failed".to_string()),
            };
        }
    };

    let server_name = match ServerName::try_from(domain.clone()) {
        Ok(n) => n,
        Err(_) => {
            return SmtpTlsRow {
                domain,
                port,
                smtp_banner: Some(greeting),
                ehlo_response: Some(ehlo_text),
                has_starttls: true,
                starttls_works: false,
                tls_version: None,
                cipher: None,
                error: Some("invalid_domain".to_string()),
            };
        }
    };

    let tls_handshake = tokio::time::timeout(timeout, connector.connect(server_name, tcp_stream)).await;

    match tls_handshake {
        Ok(Ok(tls_stream)) => {
            let (_, session) = tls_stream.get_ref();
            let tls_ver = session.protocol_version().map(|v| format!("{v:?}"));
            let cipher_str = session
                .negotiated_cipher_suite()
                .map(|suite| format!("{:?}", suite.suite()));

            SmtpTlsRow {
                domain,
                port,
                smtp_banner: Some(greeting),
                ehlo_response: Some(ehlo_text),
                has_starttls: true,
                starttls_works: true,
                tls_version: tls_ver,
                cipher: cipher_str,
                error: None,
            }
        }
        Ok(Err(e)) => {
            SmtpTlsRow {
                domain,
                port,
                smtp_banner: Some(greeting),
                ehlo_response: Some(ehlo_text),
                has_starttls: true,
                starttls_works: false,
                tls_version: None,
                cipher: None,
                error: Some(format!("tls_handshake_failed: {e}")),
            }
        }
        Err(_) => {
            SmtpTlsRow {
                domain,
                port,
                smtp_banner: Some(greeting),
                ehlo_response: Some(ehlo_text),
                has_starttls: true,
                starttls_works: false,
                tls_version: None,
                cipher: None,
                error: Some("tls_handshake_timeout".to_string()),
            }
        }
    }
}

async fn read_smtp_greeting(
    lines: &mut tokio::io::Lines<BufReader<OwnedReadHalf>>,
) -> Option<String> {
    let mut mta_info = String::new();
    loop {
        let line = lines.next_line().await.ok()??;
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
    if mta_info.is_empty() { None } else { Some(mta_info) }
}

async fn send_ehlo(
    writer: &mut OwnedWriteHalf,
    lines: &mut tokio::io::Lines<BufReader<OwnedReadHalf>>,
) -> Option<(String, bool, Vec<String>)> {
    writer.write_all(b"EHLO scanner\r\n").await.ok()?;
    let mut responses = Vec::new();
    let mut has_starttls = false;
    let mut auth_methods: Vec<String> = Vec::new();
    loop {
        let line = lines.next_line().await.ok()??;
        let trimmed = line.trim();
        let upper = trimmed.to_ascii_uppercase();
        responses.push(trimmed.to_string());
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
    Some((responses.join(" "), has_starttls, auth_methods))
}

fn writer_loop(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<SmtpTlsRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = crate::shared::open_db(&db_path)
        .with_context(|| format!("smtp-check writer: open db {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        if row.has_starttls && row.starttls_works {
            progress.ok.fetch_add(1, Ordering::Relaxed);
        } else {
            progress.errors.fetch_add(1, Ordering::Relaxed);
        }
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            if let Err(e) = flush_batch(&conn, &mut batch) {
                crate::shared::append_error_log(&db_path, &format!("smtp-check flush_batch: {e:#}"));
                return Err(e);
            }
        }
    }
    if !batch.is_empty() {
        if let Err(e) = flush_batch(&conn, &mut batch) {
            crate::shared::append_error_log(&db_path, &format!("smtp-check flush_batch (final): {e:#}"));
            return Err(e);
        }
    }
    let _ = done_tx.send(());
    Ok(())
}

fn flush_batch(conn: &rusqlite::Connection, batch: &mut Vec<SmtpTlsRow>) -> Result<()> {
    let mut sql = String::from("BEGIN;\n");
    for row in batch.iter() {
        sql.push_str(&format!(
            "INSERT INTO smtp_tls_check (
                domain, port, smtp_banner, ehlo_response,
                has_starttls, starttls_works, tls_version, cipher,
                error, checked_at
            ) VALUES ({}, {}, {}, {},
                      {}, {}, {}, {},
                      {}, datetime('now'))
            ON CONFLICT(domain, port) DO UPDATE SET
                smtp_banner      = excluded.smtp_banner,
                ehlo_response    = excluded.ehlo_response,
                has_starttls     = excluded.has_starttls,
                starttls_works   = excluded.starttls_works,
                tls_version      = excluded.tls_version,
                cipher           = excluded.cipher,
                error            = excluded.error,
                checked_at       = datetime('now');\n",
            sql_string(row.domain.as_str()),
            row.port,
            sql_string_opt(row.smtp_banner.as_deref()),
            sql_string_opt(row.ehlo_response.as_deref()),
            sql_bool(row.has_starttls),
            sql_bool(row.starttls_works),
            sql_string_opt(row.tls_version.as_deref()),
            sql_string_opt(row.cipher.as_deref()),
            sql_string_opt(row.error.as_deref()),
        ));
    }
    sql.push_str("COMMIT;");
    conn.execute_batch(&sql)?;
    batch.clear();
    Ok(())
}
