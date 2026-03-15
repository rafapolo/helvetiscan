use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{anyhow, Context, Result};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{ResolveError, TokioResolver};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

use crate::shared::{
    build_default_resolver, classify_dns_error, dedupe_sorted, progress_reporter,
    sanitize_domain, sql_bool, sql_bool_opt, sql_int_opt, sql_string, sql_string_list,
    sql_string_opt, DnsRow, ErrorKind, Progress, ScanStatus,
    DISPATCH_BATCH_SIZE, DISPATCH_BATCH_SLEEP,
};
use crate::email_security::{analyze_email_security, flush_email_security_batch, EmailSecurityRow};
use crate::DnsArgs;

pub(crate) fn load_scan_targets(
    conn: &duckdb::Connection,
    domain: Option<&str>,
    table: &str,
    timestamp_col: &str,
    rescan: bool,
    retry_errors: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(domain) = domain {
        return Ok(vec![sanitize_domain(domain).ok_or_else(|| anyhow!("invalid domain: {domain}"))?]);
    }
    if let Some(kind) = retry_errors {
        let sql = format!("SELECT domain FROM {table} WHERE error_kind = ? ORDER BY domain");
        let mut stmt = conn.prepare(&sql)?;
        let domains: Vec<String> = stmt
            .query_map([kind], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        return Ok(domains);
    }
    let sql = if rescan {
        "SELECT domain FROM domains ORDER BY domain".to_string()
    } else {
        format!(
            "SELECT d.domain
             FROM domains d
             LEFT JOIN {table} t ON t.domain = d.domain
             WHERE t.domain IS NULL OR t.{timestamp_col} IS NULL
             ORDER BY d.domain"
        )
    };
    let mut stmt = conn.prepare(&sql)?;
    let domains: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(domains)
}

pub(crate) async fn cmd_dns(args: DnsArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    if args.retry_errors.is_some() && args.rescan {
        return Err(anyhow!("--retry-errors and --rescan are mutually exclusive"));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    let pending = load_scan_targets(&conn, args.domain.as_deref(), "dns_info", "resolved_at", args.rescan, args.retry_errors.as_deref())?;
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
    let (result_tx, result_rx) = mpsc::channel::<DnsRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = args.write_batch_size;
        let progress = progress.clone();
        move || writer_loop_dns(db_path, result_rx, progress, done_tx, batch_size)
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

    let dispatcher_handle = tokio::spawn(dispatcher_loop_dns(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        resolver,
        args.concurrency,
    ));

    reader_handle
        .await
        .context("dns reader task panicked")?
        .context("dns reader failed")?;
    dispatcher_handle
        .await
        .context("dns dispatcher task panicked")?
        .context("dns dispatcher failed")?;
    writer_handle
        .await
        .context("dns writer task panicked")?
        .context("dns writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

pub(crate) async fn dispatcher_loop_dns(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<DnsRow>,
    sem: Semaphore,
    resolver: TokioResolver,
    max_concurrency: usize,
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
            let resolver = resolver.clone();
            let tx = result_tx.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_dns_info(&resolver, domain).await;
                let _ = tx.send(row).await;
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
        let permit = sem.clone().acquire_owned().await.context("semaphore closed")?;
        let resolver = resolver.clone();
        let tx = result_tx.clone();

        joinset.spawn(async move {
            let _permit = permit;
            let row = fetch_dns_info(&resolver, domain).await;
            let _ = tx.send(row).await;
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

pub(crate) async fn fetch_dns_info(resolver: &TokioResolver, domain: String) -> DnsRow {
    let dmarc_host = format!("_dmarc.{domain}");
    let wildcard_host = format!("*.{domain}");
    let (
        a_result, aaaa_result, ns_result, mx_result, cname_result,
        txt_result, dmarc_result, caa_result, wildcard_result,
    ) = tokio::join!(
        collect_ip_strings(resolver, &domain, RecordType::A),
        collect_ip_strings(resolver, &domain, RecordType::AAAA),
        collect_lookup_strings(resolver, &domain, RecordType::NS),
        collect_lookup_strings(resolver, &domain, RecordType::MX),
        collect_lookup_strings(resolver, &domain, RecordType::CNAME),
        collect_txt_records(resolver, &domain),
        collect_txt_records(resolver, &dmarc_host),
        collect_caa_records(resolver, &domain),
        resolver.lookup_ip(wildcard_host.as_str()),
    );

    let mut status = ScanStatus::Ok;
    let mut error_kind = None;
    let primary_errors = [
        a_result.as_ref().err(),
        aaaa_result.as_ref().err(),
        ns_result.as_ref().err(),
        mx_result.as_ref().err(),
    ];
    if primary_errors.iter().all(|err| err.is_some()) {
        status = ScanStatus::Error;
        error_kind = primary_errors
            .into_iter()
            .flatten()
            .map(classify_dns_error)
            .next()
            .or(Some(ErrorKind::Dns));
    }

    let a = a_result.unwrap_or_default();
    let aaaa = aaaa_result.unwrap_or_default();
    let ns = ns_result.unwrap_or_default();
    let mx = mx_result.unwrap_or_default();
    let cname = cname_result.unwrap_or_default().into_iter().next();
    let txt_all = txt_result.unwrap_or_default();
    let txt_spf = txt_all
        .iter()
        .find(|txt| txt.to_ascii_lowercase().starts_with("v=spf1"))
        .cloned();
    let txt_dmarc = dmarc_result.unwrap_or_default().into_iter().next();
    let dnssec_signed = Some(has_dnssec_material(resolver, &domain).await);
    let ptr = first_ptr_record(resolver, &a, &aaaa).await;
    let caa = caa_result.unwrap_or_default();
    let wildcard = wildcard_result.is_ok();

    let email_security = Some(analyze_email_security(&domain, txt_spf.as_deref(), txt_dmarc.as_deref(), resolver).await);

    DnsRow {
        domain,
        status,
        error_kind,
        ns,
        mx,
        cname,
        a,
        aaaa,
        txt_spf,
        txt_dmarc,
        ttl: None,
        ptr,
        dnssec_signed,
        dnssec_valid: None,
        caa,
        wildcard,
        txt_all,
        email_security,
    }
}

pub(crate) async fn collect_lookup_strings(
    resolver: &TokioResolver,
    domain: &str,
    record_type: RecordType,
) -> std::result::Result<Vec<String>, ResolveError> {
    let lookup = resolver.lookup(domain, record_type).await?;

    let values = lookup
        .iter()
        .map(|record| match record {
            RData::NS(v) => v.to_utf8(),
            RData::CNAME(v) => v.to_utf8(),
            RData::MX(v) => v.exchange().to_utf8(),
            _ => record.to_string(),
        })
        .collect::<Vec<_>>();
    Ok(dedupe_sorted(values))
}

pub(crate) async fn collect_ip_strings(
    resolver: &TokioResolver,
    domain: &str,
    record_type: RecordType,
) -> std::result::Result<Vec<String>, ResolveError> {
    let lookup = resolver.lookup(domain, record_type).await?;

    let mut values = Vec::new();
    for record in lookup.iter() {
        match record {
            RData::A(v) => values.push(v.0.to_string()),
            RData::AAAA(v) => values.push(v.0.to_string()),
            _ => {}
        }
    }
    Ok(dedupe_sorted(values))
}

async fn collect_txt_records(
    resolver: &TokioResolver,
    domain: &str,
) -> std::result::Result<Vec<String>, ResolveError> {
    let lookup = resolver.lookup(domain, RecordType::TXT).await?;

    let mut values = Vec::new();
    for record in lookup.iter() {
        if let RData::TXT(txt) = record {
            let joined = txt
                .txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).to_string())
                .collect::<String>();
            if !joined.is_empty() {
                values.push(joined);
            }
        }
    }
    Ok(dedupe_sorted(values))
}

async fn collect_caa_records(
    resolver: &TokioResolver,
    domain: &str,
) -> std::result::Result<Vec<String>, ResolveError> {
    let lookup = resolver.lookup(domain, RecordType::CAA).await?;
    let values = lookup
        .iter()
        .filter_map(|record| {
            if let RData::CAA(caa) = record {
                let value = String::from_utf8_lossy(caa.raw_value()).to_string();
                Some(format!("{} {} {}", caa.issuer_critical() as u8, caa.tag(), value))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    Ok(values)
}

async fn has_dnssec_material(resolver: &TokioResolver, domain: &str) -> bool {
    let (dnskey, ds) = tokio::join!(
        resolver.lookup(domain, RecordType::DNSKEY),
        resolver.lookup(domain, RecordType::DS),
    );
    dnskey.is_ok() || ds.is_ok()
}

async fn first_ptr_record(
    resolver: &TokioResolver,
    ipv4: &[String],
    ipv6: &[String],
) -> Option<String> {
    for candidate in ipv4.iter().chain(ipv6.iter()) {
        let Ok(ip) = candidate.parse::<IpAddr>() else {
            continue;
        };
        let Ok(lookup) = resolver.reverse_lookup(ip).await else {
            continue;
        };
        if let Some(name) = lookup.iter().next() {
            return Some(name.to_utf8());
        }
    }
    None
}

pub(crate) async fn resolve_first_ip(resolver: &TokioResolver, domain: &str) -> std::result::Result<IpAddr, ErrorKind> {
    let lookup = resolver.lookup_ip(domain).await.map_err(|e| classify_dns_error(&e))?;
    lookup.iter().next().ok_or(ErrorKind::NotFound)
}

fn writer_loop_dns(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<DnsRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = duckdb::Connection::open(&db_path)
        .with_context(|| format!("dns writer: open duckdb {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            flush_dns_and_email_batch(&conn, &mut batch)?;
        }
    }
    if !batch.is_empty() {
        flush_dns_and_email_batch(&conn, &mut batch)?;
    }
    let _ = done_tx.send(());
    Ok(())
}

fn flush_dns_and_email_batch(conn: &duckdb::Connection, batch: &mut Vec<DnsRow>) -> Result<()> {
    // Extract email security rows before mutating batch
    let mut es_batch: Vec<EmailSecurityRow> = batch
        .iter()
        .filter_map(|r| r.email_security.clone())
        .collect();
    flush_dns_batch(conn, batch)?;
    if !es_batch.is_empty() {
        flush_email_security_batch(conn, &mut es_batch)?;
    }
    Ok(())
}

fn flush_dns_batch(conn: &duckdb::Connection, batch: &mut Vec<DnsRow>) -> Result<()> {
    let mut sql = String::from("BEGIN;\n");
    for row in batch.iter() {
        sql.push_str(&format!(
            "INSERT INTO dns_info (
                domain, status, error_kind, ns, mx, cname, a, aaaa,
                txt_spf, txt_dmarc, ttl, ptr,
                dnssec, dnssec_signed, dnssec_valid, caa, wildcard, txt_all,
                resolved_at
             ) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {},
                       {}, {}, {}, {}, {}, {},
                       NOW())
             ON CONFLICT(domain) DO UPDATE SET
                status        = excluded.status,
                error_kind    = excluded.error_kind,
                ns            = excluded.ns,
                mx            = excluded.mx,
                cname         = excluded.cname,
                a             = excluded.a,
                aaaa          = excluded.aaaa,
                txt_spf       = excluded.txt_spf,
                txt_dmarc     = excluded.txt_dmarc,
                ttl           = excluded.ttl,
                ptr           = excluded.ptr,
                dnssec        = excluded.dnssec,
                dnssec_signed = excluded.dnssec_signed,
                dnssec_valid  = excluded.dnssec_valid,
                caa           = excluded.caa,
                wildcard      = excluded.wildcard,
                txt_all       = excluded.txt_all,
                resolved_at   = NOW();\n",
            sql_string(row.domain.as_str()),
            sql_string(row.status.as_str()),
            sql_string_opt(row.error_kind.map(|v| v.as_str())),
            sql_string_list(&row.ns),
            sql_string_list(&row.mx),
            sql_string_opt(row.cname.as_deref()),
            sql_string_list(&row.a),
            sql_string_list(&row.aaaa),
            sql_string_opt(row.txt_spf.as_deref()),
            sql_string_opt(row.txt_dmarc.as_deref()),
            sql_int_opt(row.ttl),
            sql_string_opt(row.ptr.as_deref()),
            sql_bool_opt(row.dnssec_signed), // write to legacy 'dnssec' col too
            sql_bool_opt(row.dnssec_signed),
            sql_bool_opt(row.dnssec_valid),
            sql_string_list(&row.caa),
            sql_bool(row.wildcard),
            sql_string_list(&row.txt_all),
        ));
    }
    sql.push_str("COMMIT;");
    conn.execute_batch(&sql)?;
    batch.clear();
    Ok(())
}
