use std::error::Error as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue, RANGE};
use reqwest::Client;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

use crate::shared::{
    build_default_resolver, progress_reporter,
    sanitize_domain, sql_int_opt, sql_string, sql_string_list, sql_string_opt,
    ErrorKind, HttpHeadersRow, Progress, ReqwestHickoryResolver, Row, ScanStatus,
    DISPATCH_BATCH_SIZE, DISPATCH_BATCH_SLEEP,
};
use crate::ScanArgs;

pub(crate) fn load_pending_domains(
    conn: &rusqlite::Connection,
    domain: Option<&str>,
    retry_errors: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(domain) = domain {
        return Ok(vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]);
    }
    if let Some(kind) = retry_errors {
        let mut stmt = conn.prepare(
            "SELECT domain FROM domains WHERE error_kind = ? ORDER BY domain",
        )?;
        let domains: Vec<String> = stmt
            .query_map([kind], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        return Ok(domains);
    }
    let mut stmt = conn.prepare("SELECT domain FROM domains WHERE updated_at IS NULL ORDER BY domain")?;
    let domains: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(domains)
}

pub(crate) async fn cmd_scan(args: ScanArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    if args.max_kbytes == 0 {
        return Err(anyhow!("--max-kbytes must be > 0"));
    }
    if args.max_bytes() > 16 * 1024 * 1024 {
        return Err(anyhow!(
            "--max-kbytes is unreasonably large (>{} bytes)",
            16 * 1024 * 1024
        ));
    }

    let conn =
        crate::shared::open_db(&args.db).with_context(|| format!("open db {:?}", args.db))?;
    let pending = load_pending_domains(&conn, args.domain.as_deref(), args.retry_errors.as_deref())?;
    drop(conn);

    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let client = build_client(&args, resolver.clone())?;
    let progress = Arc::new(Progress::new(pending.len() as u64, "HTTP 200", "errors"));

    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<(Row, Option<HttpHeadersRow>)>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let progress = progress.clone();
        let country_mmdb = args.country_mmdb.clone();
        move || writer_loop_db(db_path, result_rx, progress, done_tx, country_mmdb)
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
            Duration::from_secs(1),
            done_rx,
        )))
    };

    let sem = Semaphore::new(args.concurrency);
    let dispatcher_handle = tokio::spawn(dispatcher_loop(
        work_rx,
        result_tx,
        sem,
        client,
        resolver,
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
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

fn build_client(args: &ScanArgs, resolver: hickory_resolver::TokioResolver) -> Result<Client> {
    let mut default_headers = HeaderMap::new();
    let max_bytes = args.max_bytes();
    if max_bytes >= 1 {
        let hi = max_bytes - 1;
        let range = format!("bytes=0-{hi}");
        default_headers.insert(RANGE, HeaderValue::from_str(&range)?);
    }

    let client = Client::builder()
        .connect_timeout(args.connect_timeout)
        .timeout(args.request_timeout)
        .redirect(reqwest::redirect::Policy::limited(args.max_redirects))
        .user_agent(args.user_agent.clone())
        .default_headers(default_headers)
        .dns_resolver(Arc::new(ReqwestHickoryResolver { resolver }))
        .pool_max_idle_per_host(64)
        .build()
        .context("building HTTP client")?;
    Ok(client)
}

async fn dispatcher_loop(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<(Row, Option<HttpHeadersRow>)>,
    sem: Semaphore,
    client: Client,
    resolver: hickory_resolver::TokioResolver,
    args: ScanArgs,
) -> Result<()> {
    let sem = Arc::new(sem);
    let client = Arc::new(client);
    let resolver = Arc::new(resolver);
    let mut joinset = JoinSet::<()>::new();
    let max_concurrency = args.concurrency;
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
            let permit = sem
                .clone()
                .acquire_owned()
                .await
                .context("semaphore closed")?;

            let client = client.clone();
            let resolver = resolver.clone();
            let tx = result_tx.clone();
            let args_task = args.clone();

            joinset.spawn(async move {
                let _permit = permit;
                if tx.is_closed() {
                    return;
                }
                let result = fetch_domain(&client, &resolver, domain, &args_task).await;
                let _ = tx.send(result).await;
            });

            while joinset.len() >= max_concurrency {
                if joinset.join_next().await.is_none() {
                    break;
                }
            }
        }

        tokio::time::sleep(DISPATCH_BATCH_SLEEP).await;
    }

    for domain in batch.drain(..) {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .context("semaphore closed")?;

        let client = client.clone();
        let resolver = resolver.clone();
        let tx = result_tx.clone();
        let args_task = args.clone();

        joinset.spawn(async move {
            let _permit = permit;
            if tx.is_closed() {
                return;
            }
            let result = fetch_domain(&client, &resolver, domain, &args_task).await;
            let _ = tx.send(result).await;
        });

        while joinset.len() >= max_concurrency {
            if joinset.join_next().await.is_none() {
                break;
            }
        }
    }

    while joinset.join_next().await.is_some() {}
    drop(result_tx);
    Ok(())
}

fn writer_loop_db(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<(Row, Option<HttpHeadersRow>)>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    country_mmdb: PathBuf,
) -> Result<()> {
    const BATCH_SIZE: usize = 500;
    let conn = crate::shared::open_db(&db_path)
        .with_context(|| format!("writer: open db {:?}", db_path))?;

    let country_reader: Option<maxminddb::Reader<Vec<u8>>> =
        maxminddb::Reader::open_readfile(&country_mmdb).ok();

    let mut batch: Vec<Row> = Vec::with_capacity(BATCH_SIZE);
    let mut headers_batch: Vec<HttpHeadersRow> = Vec::with_capacity(BATCH_SIZE);

    while let Some((row, headers)) = result_rx.blocking_recv() {
        if row.status_code == Some(200) {
            progress.ok.fetch_add(1, Ordering::Relaxed);
        }
        if row.error_kind.is_some() {
            progress.errors.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(h) = headers {
            headers_batch.push(h);
        }
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= BATCH_SIZE {
            flush_batch(&conn, &mut batch, country_reader.as_ref())?;
            flush_http_headers_batch(&conn, &mut headers_batch)?;
        }
    }

    if !batch.is_empty() {
        flush_batch(&conn, &mut batch, country_reader.as_ref())?;
    }
    if !headers_batch.is_empty() {
        flush_http_headers_batch(&conn, &mut headers_batch)?;
    }

    let _ = done_tx.send(());
    Ok(())
}

pub(crate) fn flush_batch(
    conn: &rusqlite::Connection,
    batch: &mut Vec<Row>,
    country_reader: Option<&maxminddb::Reader<Vec<u8>>>,
) -> Result<()> {
    use std::net::IpAddr;
    use std::str::FromStr;

    // Enrich rows with country_code if reader is available
    if let Some(reader) = country_reader {
        for row in batch.iter_mut() {
            if let Some(ip_str) = row.ip.as_deref() {
                if let Ok(ip) = IpAddr::from_str(ip_str) {
                    if let Ok(c) = reader.lookup::<maxminddb::geoip2::Country>(ip) {
                        row.country_code = c.country.and_then(|c| c.iso_code).map(str::to_owned);
                    }
                }
            }
        }
    }

    let mut sql = String::from("BEGIN;\n");
    for row in batch.iter() {
        sql.push_str(&format!(
            "UPDATE domains SET
                status         = {},
                final_url      = {},
                status_code    = {},
                title          = {},
                body_hash      = {},
                error_kind     = {},
                elapsed_ms     = {},
                ip             = {},
                server         = {},
                powered_by     = {},
                redirect_chain = {},
                cms            = {},
                country_code   = {},
                updated_at     = datetime('now')
             WHERE domain = {};\n",
            sql_string(row.status.as_str()),
            sql_string_opt(row.final_url.as_deref()),
            sql_int_opt(row.status_code.map(|v| v as i32)),
            sql_string_opt(row.title.as_deref()),
            sql_string_opt(row.body_hash.as_deref()),
            sql_string_opt(row.error_kind.map(|k| k.as_str())),
            row.elapsed_ms as i64,
            sql_string_opt(row.ip.as_deref()),
            sql_string_opt(row.server.as_deref()),
            sql_string_opt(row.powered_by.as_deref()),
            sql_string_list(&row.redirect_chain),
            sql_string_opt(row.cms.as_deref()),
            sql_string_opt(row.country_code.as_deref()),
            sql_string(row.domain.as_str()),
        ));
    }
    sql.push_str("COMMIT;");
    conn.execute_batch(&sql)?;
    batch.clear();
    Ok(())
}

pub(crate) fn flush_http_headers_batch(conn: &rusqlite::Connection, batch: &mut Vec<HttpHeadersRow>) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO http_headers (
                domain, hsts, csp, x_frame_options, x_content_type_options,
                cors_origin, referrer_policy, permissions_policy, scanned_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'))
             ON CONFLICT(domain) DO UPDATE SET
                hsts                   = excluded.hsts,
                csp                    = excluded.csp,
                x_frame_options        = excluded.x_frame_options,
                x_content_type_options = excluded.x_content_type_options,
                cors_origin            = excluded.cors_origin,
                referrer_policy        = excluded.referrer_policy,
                permissions_policy     = excluded.permissions_policy,
                scanned_at             = excluded.scanned_at",
        )?;
        for row in batch.iter() {
            stmt.execute(rusqlite::params![
                row.domain.as_str(),
                row.hsts.as_deref(),
                row.csp.as_deref(),
                row.x_frame_options.as_deref(),
                row.x_content_type_options.as_deref(),
                row.cors_origin.as_deref(),
                row.referrer_policy.as_deref(),
                row.permissions_policy.as_deref(),
            ])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}


pub(crate) async fn fetch_domain(
    client: &Client,
    resolver: &hickory_resolver::TokioResolver,
    domain: String,
    args: &ScanArgs,
) -> (Row, Option<HttpHeadersRow>) {
    use crate::dns_scan::resolve_first_ip;

    let start = Instant::now();

    let ip = resolve_first_ip(resolver, &domain).await.ok().map(|ip| ip.to_string());

    let mut last_err: Option<FetchErr> = None;
    for url in candidate_urls(&domain) {
        if url.is_empty() {
            continue;
        }
        match fetch_url(client, &url, &domain, args).await {
            Ok((mut row, mut headers)) => {
                let redirect_chain = if row.final_url.as_deref() != Some(url.as_str()) {
                    vec![url.clone()]
                } else {
                    vec![]
                };
                row.domain = domain.clone();
                row.ip = ip;
                row.elapsed_ms = start.elapsed().as_millis() as u64;
                row.redirect_chain = redirect_chain;
                if let Some(h) = headers.as_mut() {
                    h.domain = domain;
                }
                return (row, headers);
            }
            Err(e) => last_err = Some(e),
        }
    }

    let kind = last_err.and_then(|e| e.kind).unwrap_or(ErrorKind::Other);
    (Row {
        domain,
        status: ScanStatus::Error,
        ip,
        final_url: None,
        status_code: None,
        title: None,
        body_hash: None,
        server: None,
        powered_by: None,
        error_kind: Some(kind),
        elapsed_ms: start.elapsed().as_millis() as u64,
        redirect_chain: vec![],
        cms: None,
        country_code: None,
    }, None)
}

pub(crate) fn candidate_urls(domain: &str) -> [String; 4] {
    let https = format!("https://{domain}/");
    let http = format!("http://{domain}/");
    if should_try_www(domain) {
        let https_www = format!("https://www.{domain}/");
        let http_www = format!("http://www.{domain}/");
        [https, https_www, http, http_www]
    } else {
        [https, http, String::new(), String::new()]
    }
}

pub(crate) fn should_try_www(domain: &str) -> bool {
    let d = domain.trim().to_ascii_lowercase();
    if d.starts_with("www.") {
        return false;
    }
    if d.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    true
}

#[derive(Debug)]
struct FetchErr {
    kind: Option<ErrorKind>,
}

async fn raw_http_redirect_location(
    url: &str,
    user_agent: &str,
    connect_timeout: Duration,
) -> Option<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() { "/" } else { parsed.path() }.to_string();

    let addr = format!("{host}:{port}");
    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\n\r\n"
    );

    let (read_half, mut write_half) = tokio::io::split(stream);
    write_half.write_all(request.as_bytes()).await.ok()?;
    drop(write_half);

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    reader.read_line(&mut line).await.ok()?;
    let status: u16 = line.split_whitespace().nth(1)?.parse().ok()?;
    if !(300..=399).contains(&status) {
        return None;
    }

    loop {
        line.clear();
        if reader.read_line(&mut line).await.is_err() {
            break;
        }
        if line.trim().is_empty() {
            break;
        }
        if line.to_ascii_lowercase().starts_with("location:") {
            let location = line[9..].trim().to_string();
            if !location.is_empty() {
                return Some(location);
            }
        }
    }
    None
}

async fn fetch_url(client: &Client, url: &str, domain: &str, args: &ScanArgs) -> std::result::Result<(Row, Option<HttpHeadersRow>), FetchErr> {
    let (row, headers) = fetch_url_inner(client, url, domain, args).await?;

    if row.status_code == Some(400)
        && url.starts_with("http://")
        && row.final_url.as_deref() == Some(url)
    {
        if let Some(location) =
            raw_http_redirect_location(url, &args.user_agent, args.connect_timeout).await
        {
            return fetch_url_inner(client, &location, domain, args).await;
        }
    }

    Ok((row, headers))
}

async fn fetch_url_inner(
    client: &Client,
    url: &str,
    domain: &str,
    args: &ScanArgs,
) -> std::result::Result<(Row, Option<HttpHeadersRow>), FetchErr> {
    let resp = client.get(url).send().await.map_err(|e| FetchErr {
        kind: Some(classify_reqwest_error(&e)),
    })?;

    let final_url = resp.url().to_string();
    let status = resp.status();
    let status_u16 = status.as_u16();

    let hdr = |h: &str| -> Option<String> {
        resp.headers()
            .get(h)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };

    let server     = hdr("server");
    let powered_by = hdr("x-powered-by");
    let hsts                   = hdr("strict-transport-security");
    let csp                    = hdr("content-security-policy");
    let x_frame_options        = hdr("x-frame-options");
    let x_content_type_options = hdr("x-content-type-options");
    let cors_origin            = hdr("access-control-allow-origin");
    let referrer_policy        = hdr("referrer-policy");
    let permissions_policy     = hdr("permissions-policy");

    let max_bytes = args.max_bytes();
    let mut body: Vec<u8> = Vec::with_capacity(max_bytes.min(65_536));
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

        if body.len() >= max_bytes {
            break;
        }

        let remaining = max_bytes - body.len();
        let take = remaining.min(chunk.len());
        body.extend_from_slice(&chunk[..take]);
    }

    if let Some(ref base) = args.save_html {
        if status.is_success() && !body.is_empty() {
            save_html_zip(base, domain, body.clone()).await;
        }
    }

    let mut error_kind = if status.is_client_error() || status.is_server_error() {
        Some(ErrorKind::HttpStatus)
    } else {
        None
    };
    if error_kind.is_none() {
        error_kind = body_err_kind;
    }

    let title = extract_title(&body);
    let body_hash = if body.is_empty() {
        None
    } else {
        Some(format!("{:x}", md5::compute(&body)))
    };
    let cms = detect_cms(powered_by.as_deref(), &body, server.as_deref());

    let row = Row {
        domain: String::new(),
        status: ScanStatus::Ok,
        ip: None,
        final_url: Some(final_url.clone()),
        status_code: Some(status_u16),
        title,
        body_hash,
        server,
        powered_by,
        error_kind,
        elapsed_ms: 0,
        redirect_chain: vec![],
        cms,
        country_code: None,
    };

    let headers = HttpHeadersRow {
        domain: String::new(),
        hsts,
        csp,
        x_frame_options,
        x_content_type_options,
        cors_origin,
        referrer_policy,
        permissions_policy,
    };

    Ok((row, Some(headers)))
}

fn extract_title(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();

    let start = lower.find("<title")?;
    let tag_close = lower[start..].find('>')? + start + 1;
    let end = lower[tag_close..].find("</title>")? + tag_close;

    let raw = &text[tag_close..end];
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let decoded = collapsed
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'");

    let trimmed = decoded.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}


pub(crate) fn detect_cms(
    powered_by: Option<&str>,
    body: &[u8],
    server: Option<&str>,
) -> Option<String> {
    if let Some(pb) = powered_by {
        let pb_lc = pb.to_ascii_lowercase();
        if pb_lc.contains("wordpress") { return Some("WordPress".into()); }
        if pb_lc.contains("drupal")    { return Some("Drupal".into()); }
        if pb_lc.contains("joomla")    { return Some("Joomla".into()); }
        if pb_lc.contains("typo3")     { return Some("TYPO3".into()); }
        if pb_lc.contains("wix")       { return Some("Wix".into()); }
        if pb_lc.contains("php/") || pb_lc.starts_with("php") {
            return Some("php".into());
        }
    }
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    if let Some(start) = lower.find(r#"name="generator""#).or_else(|| lower.find(r#"name='generator'"#)) {
        let mut end = std::cmp::min(start + 500, lower.len());
        while !lower.is_char_boundary(end) { end -= 1; }
        let search_area = &lower[start..end];
        if search_area.contains("wordpress") { return Some("WordPress".into()); }
        if search_area.contains("drupal")    { return Some("Drupal".into()); }
        if search_area.contains("joomla")    { return Some("Joomla".into()); }
        if search_area.contains("typo3")     { return Some("TYPO3".into()); }
        if search_area.contains("wix")       { return Some("Wix".into()); }
    }
    // body fingerprints
    if lower.contains("wp-content/") || lower.contains("wp-includes/") {
        return Some("WordPress".into());
    }
    if lower.contains("drupal.settings") || lower.contains("/sites/default/files/") {
        return Some("Drupal".into());
    }
    if lower.contains("/components/com_") {
        return Some("Joomla".into());
    }
    if lower.contains("typo3conf/") || lower.contains("typo3temp/") {
        return Some("TYPO3".into());
    }
    // Server header: Apache/nginx
    if let Some(srv) = server {
        let srv_lc = srv.to_ascii_lowercase();
        if srv_lc.contains("apache") { return Some("apache".into()); }
        if srv_lc.contains("nginx")  { return Some("nginx".into()); }
    }
    // X-Powered-By: PHP (fallback)
    if let Some(pb) = powered_by {
        if pb.to_ascii_lowercase().contains("php") {
            return Some("php".into());
        }
    }
    None
}

async fn save_html_zip(base: &std::path::Path, domain: &str, body: Vec<u8>) {
    let zip_path = base.join(format!("{domain}.html.zip"));
    if zip_path.exists() { return; }
    let base = base.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        std::fs::create_dir_all(&base)?;
        let file = std::fs::File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("index.html", opts)?;
        use std::io::Write as _;
        zip.write_all(&body)?;
        zip.finish()?;
        Ok(())
    }).await;
}

fn classify_reqwest_error(e: &reqwest::Error) -> ErrorKind {
    if e.is_timeout() {
        return ErrorKind::Timeout;
    }
    let mut msg = e.to_string().to_ascii_lowercase();
    let mut src: Option<&(dyn std::error::Error + 'static)> = e.source();
    while let Some(err) = src {
        msg.push_str(" | ");
        msg.push_str(&err.to_string().to_ascii_lowercase());
        src = err.source();
    }

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
        if msg.contains("refused") || msg.contains("connection refused") {
            return ErrorKind::Refused;
        }
        return ErrorKind::Other;
    }

    ErrorKind::Other
}
