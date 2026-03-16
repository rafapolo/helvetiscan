use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use hickory_resolver::TokioResolver;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
use chrono::NaiveDate;

use crate::shared::{
    build_default_resolver, classify_io_error, non_empty, progress_reporter,
    sql_bool_opt, sql_int_opt, sql_string, sql_string_list, sql_string_opt,
    ErrorKind, Progress, TlsRow, ScanStatus,
    DISPATCH_BATCH_SIZE, DISPATCH_BATCH_SLEEP,
};
use crate::dns_scan::resolve_first_ip;
use crate::TlsArgs;

pub(crate) fn build_tls_connector() -> TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

pub(crate) async fn cmd_tls(args: TlsArgs) -> Result<()> {
    if args.concurrency == 0 {
        return Err(anyhow!("--concurrency must be > 0"));
    }
    if args.retry_errors.is_some() && args.rescan {
        return Err(anyhow!("--retry-errors and --rescan are mutually exclusive"));
    }

    let conn =
        duckdb::Connection::open(&args.db).with_context(|| format!("open duckdb {:?}", args.db))?;
    let pending = crate::dns_scan::load_scan_targets(&conn, args.domain.as_deref(), "tls_info", "scanned_at", args.rescan, args.retry_errors.as_deref())?;
    drop(conn);

    if pending.is_empty() {
        eprintln!("Nothing to do.");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let tls_connector = build_tls_connector();
    let progress = Arc::new(Progress::new(pending.len() as u64, "valid TLS", "errors"));
    let work_buf = (args.concurrency * 2).clamp(1_000, 100_000);
    let result_buf = (args.concurrency * 2).clamp(1_000, 100_000);

    let (work_tx, work_rx) = mpsc::channel::<String>(work_buf);
    let (result_tx, result_rx) = mpsc::channel::<TlsRow>(result_buf);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer_handle = tokio::task::spawn_blocking({
        let db_path = args.db.clone();
        let batch_size = args.write_batch_size;
        let progress = progress.clone();
        move || writer_loop_tls(db_path, result_rx, progress, done_tx, batch_size)
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

    let dispatcher_handle = tokio::spawn(dispatcher_loop_tls(
        work_rx,
        result_tx,
        Semaphore::new(args.concurrency),
        tls_connector,
        resolver,
        args.clone(),
    ));

    reader_handle
        .await
        .context("tls reader task panicked")?
        .context("tls reader failed")?;
    dispatcher_handle
        .await
        .context("tls dispatcher task panicked")?
        .context("tls dispatcher failed")?;
    writer_handle
        .await
        .context("tls writer task panicked")?
        .context("tls writer failed")?;

    if let Some(h) = progress_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}

async fn dispatcher_loop_tls(
    mut work_rx: mpsc::Receiver<String>,
    result_tx: mpsc::Sender<TlsRow>,
    sem: Semaphore,
    connector: TlsConnector,
    resolver: TokioResolver,
    args: TlsArgs,
) -> Result<()> {
    let sem = Arc::new(sem);
    let connector = Arc::new(connector);
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
            let connector = connector.clone();
            let resolver = resolver.clone();
            let tx = result_tx.clone();
            let args_task = args.clone();

            joinset.spawn(async move {
                let _permit = permit;
                let row = fetch_tls_info(&connector, &resolver, domain, &args_task).await;
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
        let connector = connector.clone();
        let resolver = resolver.clone();
        let tx = result_tx.clone();
        let args_task = args.clone();

        joinset.spawn(async move {
            let _permit = permit;
            let row = fetch_tls_info(&connector, &resolver, domain, &args_task).await;
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

async fn fetch_tls_info(connector: &TlsConnector, resolver: &TokioResolver, domain: String, args: &TlsArgs) -> TlsRow {
    let mut row = TlsRow {
        domain: domain.clone(),
        status: ScanStatus::Error,
        error_kind: None,
        cert_issuer: None,
        cert_subject: None,
        valid_from: None,
        valid_to: None,
        days_remaining: None,
        expired: None,
        self_signed: None,
        tls_version: None,
        cipher: None,
        san: vec![],
        key_algorithm: None,
        key_size: None,
        signature_algorithm: None,
        cert_fingerprint: None,
        ct_logged: None,
        ocsp_must_staple: None,
    };

    let Ok(server_name) = ServerName::try_from(domain.clone()) else {
        row.error_kind = Some(ErrorKind::ParseFailed);
        return row;
    };

    let Ok(ip) = resolve_first_ip(resolver, &domain).await
    else {
        row.error_kind = Some(ErrorKind::Dns);
        return row;
    };

    let Ok(stream) = tokio::time::timeout(
        args.connect_timeout,
        TcpStream::connect(SocketAddr::new(ip, 443)),
    )
    .await
    else {
        row.error_kind = Some(ErrorKind::Timeout);
        return row;
    };
    let Ok(stream) = stream else {
        row.error_kind = Some(classify_io_error(&stream.unwrap_err()));
        return row;
    };

    let Ok(tls_stream) = tokio::time::timeout(
        args.handshake_timeout,
        connector.connect(server_name, stream),
    )
    .await
    else {
        row.error_kind = Some(ErrorKind::Timeout);
        return row;
    };
    let Ok(tls_stream) = tls_stream else {
        row.error_kind = Some(ErrorKind::Tls);
        return row;
    };

    let (_, session) = tls_stream.get_ref();
    row.tls_version = session.protocol_version().map(|v| format!("{v:?}"));
    row.cipher = session
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()));

    let Some(peer_cert) = session
        .peer_certificates()
        .and_then(|certs| certs.first())
    else {
        row.error_kind = Some(ErrorKind::ParseFailed);
        return row;
    };

    let fingerprint = format!("{:x}", Sha256::digest(peer_cert.as_ref()));
    if let Ok((_, cert)) = X509Certificate::from_der(peer_cert.as_ref()) {
        populate_tls_cert_fields(&mut row, &cert, fingerprint);
        row.status = ScanStatus::Ok;
        row.error_kind = None;
    } else {
        row.error_kind = Some(ErrorKind::ParseFailed);
    }

    row
}

fn populate_tls_cert_fields(row: &mut TlsRow, cert: &X509Certificate<'_>, cert_fingerprint: String) {
    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();
    let valid_from = asn1_date(cert.validity().not_before.timestamp());
    let valid_to = asn1_date(cert.validity().not_after.timestamp());

    row.cert_issuer = non_empty(issuer);
    row.cert_subject = non_empty(subject);
    row.valid_from = valid_from;
    row.valid_to = valid_to;
    row.self_signed = Some(cert.issuer() == cert.subject());
    row.cert_fingerprint = Some(cert_fingerprint);

    if let Some(valid_to) = valid_to {
        let today = Utc::now().date_naive();
        let days = valid_to.signed_duration_since(today).num_days();
        row.days_remaining = Some(days.clamp(i32::MIN as i64, i32::MAX as i64) as i32);
        row.expired = Some(valid_to < today);
    } else {
        row.expired = None;
    }

    // SAN
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        row.san = ext.value.general_names.iter().filter_map(|name| match name {
            GeneralName::DNSName(s) => Some(s.to_string()),
            GeneralName::IPAddress(b) => {
                if b.len() == 4 {
                    let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                    Some(ip.to_string())
                } else if b.len() == 16 {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(b);
                    Some(std::net::Ipv6Addr::from(bytes).to_string())
                } else {
                    None
                }
            }
            _ => None,
        }).collect();
    }

    // key algorithm + size
    let pkey = cert.public_key();
    let key_alg_oid = pkey.algorithm.algorithm.to_id_string();
    match key_alg_oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            row.key_algorithm = Some("RSA".into());
            if let Ok(x509_parser::public_key::PublicKey::RSA(rsa)) = pkey.parsed() {
                row.key_size = Some(rsa.key_size() as i32);
            }
        }
        "1.2.840.10045.2.1" => {
            let (name, bits) = pkey.algorithm.parameters.as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| match oid.to_id_string().as_str() {
                    "1.2.840.10045.3.1.7" => ("P-256", 256i32),
                    "1.3.132.0.34"        => ("P-384", 384i32),
                    "1.3.132.0.35"        => ("P-521", 521i32),
                    _                     => ("EC", 0i32),
                })
                .unwrap_or(("EC", 0));
            row.key_algorithm = Some(name.into());
            if bits > 0 { row.key_size = Some(bits); }
        }
        "1.3.101.112" => { row.key_algorithm = Some("Ed25519".into()); row.key_size = Some(256); }
        "1.3.101.113" => { row.key_algorithm = Some("Ed448".into());   row.key_size = Some(448); }
        _ => {}
    }

    // signature algorithm
    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    row.signature_algorithm = Some(match sig_oid.as_str() {
        "1.2.840.113549.1.1.11" => "SHA256withRSA".into(),
        "1.2.840.113549.1.1.12" => "SHA384withRSA".into(),
        "1.2.840.113549.1.1.13" => "SHA512withRSA".into(),
        "1.2.840.10045.4.3.2"   => "SHA256withECDSA".into(),
        "1.2.840.10045.4.3.3"   => "SHA384withECDSA".into(),
        "1.2.840.10045.4.3.4"   => "SHA512withECDSA".into(),
        "1.3.101.112"           => "Ed25519".into(),
        "1.3.101.113"           => "Ed448".into(),
        other                   => other.into(),
    });

    // CT logged: SCT list extension OID 1.3.6.1.4.1.11129.2.4.2
    row.ct_logged = Some(cert.extensions().iter().any(|ext| {
        ext.oid.to_id_string() == "1.3.6.1.4.1.11129.2.4.2"
    }));

    // OCSP must-staple: TLS Feature extension OID 1.3.6.1.5.5.7.1.24
    // contains a SEQUENCE of INTEGER; feature 5 (status_request) = DER 02 01 05
    row.ocsp_must_staple = cert.extensions().iter()
        .find(|ext| ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.24")
        .map(|ext| ext.value.windows(3).any(|w| w == [0x02, 0x01, 0x05]));
}

fn asn1_date(ts: i64) -> Option<NaiveDate> {
    DateTime::from_timestamp(ts, 0).map(|dt| dt.date_naive())
}

fn writer_loop_tls(
    db_path: PathBuf,
    mut result_rx: mpsc::Receiver<TlsRow>,
    progress: Arc<Progress>,
    done_tx: tokio::sync::oneshot::Sender<()>,
    batch_size: usize,
) -> Result<()> {
    let conn = duckdb::Connection::open(&db_path)
        .with_context(|| format!("tls writer: open duckdb {:?}", db_path))?;

    let mut batch = Vec::with_capacity(batch_size);
    while let Some(row) = result_rx.blocking_recv() {
        if row.error_kind.is_none() {
            progress.ok.fetch_add(1, Ordering::Relaxed);
        } else {
            progress.errors.fetch_add(1, Ordering::Relaxed);
        }
        batch.push(row);
        progress.completed.fetch_add(1, Ordering::Relaxed);
        if batch.len() >= batch_size {
            flush_tls_batch(&conn, &mut batch)?;
        }
    }
    if !batch.is_empty() {
        flush_tls_batch(&conn, &mut batch)?;
    }
    conn.execute_batch("CHECKPOINT")?;
    let _ = done_tx.send(());
    Ok(())
}

fn flush_tls_batch(conn: &duckdb::Connection, batch: &mut Vec<TlsRow>) -> Result<()> {
    let mut sql = String::from("BEGIN;\n");
    for row in batch.iter() {
        sql.push_str(&format!(
            "INSERT INTO tls_info (
                domain, status, error_kind,
                cert_issuer, cert_subject, valid_from, valid_to,
                days_remaining, expired, self_signed, tls_version, cipher,
                san, key_algorithm, key_size, signature_algorithm,
                cert_fingerprint, ct_logged, ocsp_must_staple,
                scanned_at
             ) VALUES ({}, {}, {},
                       {}, {}, {}, {},
                       {}, {}, {}, {}, {},
                       {}, {}, {}, {},
                       {}, {}, {},
                       NOW())
             ON CONFLICT(domain) DO UPDATE SET
                status              = excluded.status,
                error_kind          = excluded.error_kind,
                cert_issuer         = excluded.cert_issuer,
                cert_subject        = excluded.cert_subject,
                valid_from          = excluded.valid_from,
                valid_to            = excluded.valid_to,
                days_remaining      = excluded.days_remaining,
                expired             = excluded.expired,
                self_signed         = excluded.self_signed,
                tls_version         = excluded.tls_version,
                cipher              = excluded.cipher,
                san                 = excluded.san,
                key_algorithm       = excluded.key_algorithm,
                key_size            = excluded.key_size,
                signature_algorithm = excluded.signature_algorithm,
                cert_fingerprint    = excluded.cert_fingerprint,
                ct_logged           = excluded.ct_logged,
                ocsp_must_staple    = excluded.ocsp_must_staple,
                scanned_at          = NOW();\n",
            sql_string(row.domain.as_str()),
            sql_string(row.status.as_str()),
            sql_string_opt(row.error_kind.map(|v| v.as_str())),
            sql_string_opt(row.cert_issuer.as_deref()),
            sql_string_opt(row.cert_subject.as_deref()),
            sql_string_opt(row.valid_from.map(|d| d.to_string()).as_deref()),
            sql_string_opt(row.valid_to.map(|d| d.to_string()).as_deref()),
            sql_int_opt(row.days_remaining),
            sql_bool_opt(row.expired),
            sql_bool_opt(row.self_signed),
            sql_string_opt(row.tls_version.as_deref()),
            sql_string_opt(row.cipher.as_deref()),
            sql_string_list(&row.san),
            sql_string_opt(row.key_algorithm.as_deref()),
            sql_int_opt(row.key_size),
            sql_string_opt(row.signature_algorithm.as_deref()),
            sql_string_opt(row.cert_fingerprint.as_deref()),
            sql_bool_opt(row.ct_logged),
            sql_bool_opt(row.ocsp_must_staple),
        ));
    }
    sql.push_str("COMMIT;");
    conn.execute_batch(&sql)?;
    batch.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use crate::shared::{TlsRow, ScanStatus};

    #[test]
    fn asn1_date_epoch() {
        assert_eq!(asn1_date(0), Some(NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()));
    }

    #[test]
    fn asn1_date_known_timestamp() {
        // 1_700_000_000 seconds after epoch = 2023-11-14
        assert_eq!(asn1_date(1_700_000_000), Some(NaiveDate::from_ymd_opt(2023, 11, 14).unwrap()));
    }

    #[test]
    fn asn1_date_negative_is_before_epoch() {
        // -86400 = 1969-12-31
        assert_eq!(asn1_date(-86400), Some(NaiveDate::from_ymd_opt(1969, 12, 31).unwrap()));
    }

    #[test]
    fn flush_tls_batch_roundtrip() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        crate::schema::ensure_schema(&conn).unwrap();

        let mut batch = vec![TlsRow {
            domain: "test.ch".into(),
            status: ScanStatus::Ok,
            error_kind: None,
            cert_issuer: Some("Let's Encrypt".into()),
            cert_subject: Some("CN=test.ch".into()),
            valid_from: Some(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap()),
            valid_to: Some(NaiveDate::from_ymd_opt(2025, 1, 1).unwrap()),
            days_remaining: Some(90),
            expired: Some(false),
            self_signed: Some(false),
            tls_version: Some("TLSv1_3".into()),
            cipher: None,
            san: vec!["test.ch".into(), "www.test.ch".into()],
            key_algorithm: Some("RSA".into()),
            key_size: Some(2048),
            signature_algorithm: Some("SHA256withRSA".into()),
            cert_fingerprint: Some("deadbeef".into()),
            ct_logged: Some(true),
            ocsp_must_staple: Some(false),
        }];

        // Pre-insert into domains to satisfy any FK if needed; tls_info has no FK
        flush_tls_batch(&conn, &mut batch).unwrap();
        assert!(batch.is_empty());

        let issuer: Option<String> = conn
            .query_row("SELECT cert_issuer FROM tls_info WHERE domain='test.ch'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(issuer.as_deref(), Some("Let's Encrypt"));

        let san_len: i64 = conn
            .query_row("SELECT len(san) FROM tls_info WHERE domain='test.ch'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(san_len, 2);
    }

    #[test]
    fn flush_tls_batch_upserts() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        crate::schema::ensure_schema(&conn).unwrap();

        let make_row = |issuer: &str| TlsRow {
            domain: "upsert.ch".into(),
            status: ScanStatus::Ok,
            error_kind: None,
            cert_issuer: Some(issuer.into()),
            cert_subject: None,
            valid_from: None,
            valid_to: None,
            days_remaining: None,
            expired: None,
            self_signed: None,
            tls_version: None,
            cipher: None,
            san: vec![],
            key_algorithm: None,
            key_size: None,
            signature_algorithm: None,
            cert_fingerprint: None,
            ct_logged: None,
            ocsp_must_staple: None,
        };

        flush_tls_batch(&conn, &mut vec![make_row("OldCA")]).unwrap();
        flush_tls_batch(&conn, &mut vec![make_row("NewCA")]).unwrap();

        let issuer: Option<String> = conn
            .query_row("SELECT cert_issuer FROM tls_info WHERE domain='upsert.ch'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(issuer.as_deref(), Some("NewCA"));
    }
}
