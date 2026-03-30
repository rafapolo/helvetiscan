use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::Value;

// ---- Structs ----

#[allow(dead_code)]
pub(crate) struct CveCatalogRow {
    pub cve_id: String,
    pub technology: String,
    pub affected_from: Option<String>,
    pub affected_to: Option<String>,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub in_kev: bool,
    pub summary: Option<String>,
    pub published_at: Option<String>,
}

#[allow(dead_code)]
pub(crate) struct CveMatchRow {
    pub domain: String,
    pub technology: String,
    pub version: Option<String>,
    pub cve_id: String,
    pub severity: Option<String>,
    pub cvss_score: Option<f64>,
    pub in_kev: Option<bool>,
    pub published_at: Option<String>,
}

// ---- Hardcoded seed CVEs (technology, cve_id, severity, cvss_score, affected_from, affected_to, summary) ----

const SEED_CVES: &[(&str, &str, &str, f64, &str, &str, &str)] = &[
    // WordPress
    ("wordpress", "CVE-2023-2745", "HIGH", 8.8, "6.0", "6.2.9", "WordPress core authenticated stored XSS via block editor"),
    ("wordpress", "CVE-2022-21661", "HIGH", 8.8, "5.6", "5.8.3", "WordPress SQL injection via WP_Query"),
    ("wordpress", "CVE-2021-44223", "CRITICAL", 9.8, "0", "5.8", "WordPress Gutenberg plugin arbitrary file upload"),
    ("wordpress", "CVE-2019-17671", "HIGH", 7.5, "0", "5.2.3", "WordPress unauthenticated view of private posts"),
    // Drupal
    ("drupal", "CVE-2018-7600", "CRITICAL", 9.8, "7.0", "8.5.1", "Drupalgeddon2 — remote code execution"),
    ("drupal", "CVE-2018-7602", "CRITICAL", 9.8, "7.0", "7.59", "Drupalgeddon2 SA-CORE-2018-004 follow-up"),
    ("drupal", "CVE-2019-6340", "CRITICAL", 9.8, "8.6", "8.6.9", "Drupal REST API remote code execution"),
    // Joomla
    ("joomla", "CVE-2023-23752", "MEDIUM", 5.3, "4.0.0", "4.2.7", "Joomla improper API access leading to info disclosure"),
    ("joomla", "CVE-2015-8562", "CRITICAL", 9.8, "1.5", "3.4.5", "Joomla PHP object injection via session data"),
    ("joomla", "CVE-2017-8917", "CRITICAL", 9.8, "3.7.0", "3.7.0", "Joomla SQL injection in com_fields"),
    // Apache
    ("apache", "CVE-2021-41773", "CRITICAL", 9.8, "2.4.49", "2.4.49", "Apache HTTP Server path traversal and RCE"),
    ("apache", "CVE-2021-42013", "CRITICAL", 9.8, "2.4.49", "2.4.50", "Apache HTTP Server path traversal follow-up"),
    ("apache", "CVE-2017-7679", "CRITICAL", 9.8, "2.2.0", "2.2.32", "Apache mod_mime buffer overread"),
    ("apache", "CVE-2022-31813", "HIGH", 7.5, "2.4.0", "2.4.53", "Apache HTTP Server request smuggling"),
    // nginx
    ("nginx", "CVE-2021-23017", "HIGH", 7.7, "0.6.18", "1.20.0", "nginx DNS resolver off-by-one heap write"),
    ("nginx", "CVE-2019-9511", "HIGH", 7.5, "1.0.7", "1.17.2", "nginx HTTP/2 DoS (Data Dribble attack)"),
    ("nginx", "CVE-2019-9513", "HIGH", 7.5, "1.0.7", "1.17.2", "nginx HTTP/2 DoS (Resource Loop attack)"),
    // PHP
    ("php", "CVE-2023-3824", "CRITICAL", 9.8, "8.0.0", "8.1.22", "PHP buffer overread in PHAR parsing"),
    ("php", "CVE-2022-31628", "HIGH", 7.8, "7.4.0", "8.1.11", "PHP phar wrapper stack buffer overflow"),
    ("php", "CVE-2021-21706", "MEDIUM", 4.3, "5.3.0", "7.4.25", "PHP ZipArchive::extractTo path traversal"),
    ("php", "CVE-2019-11043", "CRITICAL", 9.8, "7.1.0", "7.3.10", "PHP-FPM buffer underflow in env_path_info"),
    // TYPO3
    ("typo3", "CVE-2023-24814", "CRITICAL", 9.8, "9.0.0", "12.1.1", "TYPO3 SQL injection in page tree"),
    ("typo3", "CVE-2022-36020", "HIGH", 8.8, "9.0.0", "11.5.16", "TYPO3 improper access control in backend"),
    ("typo3", "CVE-2019-12747", "CRITICAL", 8.8, "8.0.0", "9.5.7", "TYPO3 Extbase deserialization attack"),
    // OpenSSL
    ("openssl", "CVE-2022-0778", "HIGH", 7.5, "1.0.2", "3.0.1", "OpenSSL BN_mod_sqrt infinite loop DoS"),
    ("openssl", "CVE-2022-3602", "HIGH", 7.5, "3.0.0", "3.0.6", "OpenSSL X.509 punycode buffer overflow"),
    ("openssl", "CVE-2014-0160", "HIGH", 7.5, "1.0.1", "1.0.1f", "Heartbleed — OpenSSL memory disclosure"),
    // Craft CMS
    ("craft cms", "CVE-2024-56145", "CRITICAL", 9.8, "3.0.0", "5.5.2", "Craft CMS code injection via template rendering"),
    ("craft cms", "CVE-2025-23209", "HIGH", 8.8, "4.0.0", "5.5.5", "Craft CMS code injection via improper input validation"),
    ("craft cms", "CVE-2025-35939", "HIGH", 8.0, "3.0.0", "5.6.2", "Craft CMS external control of assumed-immutable web parameter"),
    // LiteSpeed
    ("litespeed", "CVE-2022-0073", "HIGH", 8.8, "5.0", "6.0.12", "LiteSpeed Web Server privilege escalation via dashboard"),
    ("litespeed", "CVE-2022-0074", "HIGH", 8.8, "5.0", "6.0.12", "LiteSpeed Web Server RCE via log injection"),
    ("litespeed", "CVE-2020-36641", "CRITICAL", 9.8, "5.0", "5.4.12", "LiteSpeed Cache Plugin path traversal"),
    // Tomcat
    ("tomcat", "CVE-2025-24813", "CRITICAL", 9.8, "9.0.0", "11.0.2", "Apache Tomcat path equivalence RCE"),
    ("tomcat", "CVE-2020-1938", "CRITICAL", 9.8, "7.0.0", "9.0.30", "Apache Tomcat AJP Ghostcat file read/inclusion"),
    ("tomcat", "CVE-2017-12617", "HIGH", 8.1, "7.0.0", "9.0.1", "Apache Tomcat JSP upload via HTTP PUT"),
    ("tomcat", "CVE-2016-8735", "CRITICAL", 9.8, "6.0.0", "9.0.0", "Apache Tomcat RCE via JMX listener"),
    // MySQL / MariaDB (port 3306 banner)
    ("mysql", "CVE-2016-6662", "CRITICAL", 9.8, "0", "5.7.15", "MySQL/MariaDB config file injection leading to RCE as root"),
    ("mysql", "CVE-2016-6664", "HIGH", 7.0, "0", "5.7.15", "MySQL/MariaDB privilege escalation via unsafe file handling"),
    ("mysql", "CVE-2012-2122", "HIGH", 7.5, "0", "5.6.5", "MySQL auth bypass via timing attack on memcmp"),
    ("mysql", "CVE-2023-21980", "CRITICAL", 9.8, "8.0.0", "8.0.32", "MySQL optimizer RCE"),
    // Microsoft SQL Server (port 1433 banner)
    ("mssql", "CVE-2022-23276", "HIGH",     8.8, "15.0.0",  "15.0.4197", "SQL Server 2019 on Linux container elevation of privilege"),
    ("mssql", "CVE-2020-0618",  "HIGH",     8.8, "0",       "14.0.9999", "SQL Server Reporting Services deserialization RCE"),
    ("mssql", "CVE-2019-1068",  "HIGH",     8.8, "0",       "15.0.2000", "SQL Server Machine Learning Services remote code execution"),
    ("mssql", "CVE-2018-8273",  "CRITICAL", 9.8, "0",       "14.0.3030", "SQL Server 2016/2017 buffer overflow via crafted request"),
    ("mssql", "CVE-2021-1636",  "HIGH",     8.8, "0",       "15.0.4102", "SQL Server remote code execution via linked server"),
    // ProFTPD (port 21 banner)
    ("proftpd", "CVE-2015-3306", "CRITICAL", 10.0, "0", "1.3.5", "ProFTPD mod_copy unauthenticated arbitrary file read/write"),
    ("proftpd", "CVE-2019-12815", "CRITICAL", 9.8, "0", "1.3.6b", "ProFTPD mod_copy arbitrary file copy without auth"),
    ("proftpd", "CVE-2011-4130", "CRITICAL", 9.0, "0", "1.3.3g", "ProFTPD use-after-free in response pool"),
    // vsftpd (port 21 banner)
    ("vsftpd", "CVE-2011-2523", "CRITICAL", 10.0, "2.3.4", "2.3.4", "vsftpd 2.3.4 backdoor command execution"),
    // RDP (port 3389 presence — no banner, matched by port alone)
    ("rdp", "CVE-2019-0708", "CRITICAL", 9.8, "0", "999", "BlueKeep — pre-auth wormable RCE in Windows RDP (KEV)"),
    ("rdp", "CVE-2019-1181", "CRITICAL", 9.8, "0", "999", "DejaBlue — pre-auth RCE in Windows RDP (KEV)"),
    ("rdp", "CVE-2019-1182", "CRITICAL", 9.8, "0", "999", "DejaBlue variant — pre-auth RCE in Windows RDP (KEV)"),
    // Redis (port 6379 banner)
    ("redis", "CVE-2022-0543",  "CRITICAL", 10.0, "0",     "6.2.6",  "Redis Lua sandbox escape RCE via Debian/Ubuntu package"),
    ("redis", "CVE-2021-32761", "HIGH",      7.5,  "2.2.0", "6.2.5",  "Redis integer overflow in GETDEL/COPY leading to heap corruption"),
    ("redis", "CVE-2023-28425", "MEDIUM",    5.5,  "0",     "7.0.10", "Redis malformed LMPOP command crash"),
    ("redis", "CVE-2023-41056", "HIGH",      8.1,  "7.0.0", "7.2.3",  "Redis integer overflow in listTypeSetTypeAt heap corruption"),
    // Elasticsearch (port 9200 banner)
    ("elasticsearch", "CVE-2014-3120", "CRITICAL", 9.8, "0",     "1.3.0",  "Elasticsearch Groovy sandbox escape leading to RCE"),
    ("elasticsearch", "CVE-2015-1427", "CRITICAL", 9.8, "0",     "1.4.2",  "Elasticsearch Groovy/MVEL sandbox escape RCE"),
    ("elasticsearch", "CVE-2021-22145", "MEDIUM",  6.5, "7.0.0", "7.13.3", "Elasticsearch sensitive info disclosure via error reporting"),
    // Memcached (port 11211 banner)
    ("memcached", "CVE-2021-37519", "HIGH",     7.5, "0",     "1.6.9",  "Memcached heap buffer overflow in binary protocol"),
    ("memcached", "CVE-2022-48571", "HIGH",     7.5, "0",     "1.6.17", "Memcached NULL pointer dereference in UDP stats command"),
    ("memcached", "CVE-2016-8705",  "CRITICAL", 9.8, "0",     "1.4.33", "Memcached SASL auth multiple integer overflows leading to RCE"),
    // Docker API (port 2375 — unauthenticated remote socket)
    ("docker", "CVE-2024-41110", "CRITICAL", 10.0, "0", "27.1.0", "Docker Engine AuthZ plugin bypass allowing unauthenticated API RCE"),
    ("docker", "CVE-2019-13139", "HIGH",      8.4, "0", "18.9.3", "Docker build command injection via malicious Dockerfile"),
    // OpenSSH (port 22 banner)
    ("openssh", "CVE-2024-6387", "HIGH", 8.1, "8.5p1", "9.7p1", "regreSSHion — OpenSSH unauthenticated RCE via race in SIGALRM handler (KEV)"),
    ("openssh", "CVE-2023-38408", "CRITICAL", 9.8, "0", "9.3p1", "OpenSSH ssh-agent forwarding RCE via remote library loading"),
    ("openssh", "CVE-2023-51385", "MEDIUM", 6.5, "0", "9.6", "OpenSSH OS command injection via shell metacharacters in host or username"),
    // Microsoft IIS (server header: Microsoft-IIS/x.x)
    ("iis", "CVE-2017-7269", "CRITICAL", 9.8, "6.0", "6.0", "Microsoft IIS 6.0 WebDAV buffer overflow RCE"),
    ("iis", "CVE-2015-1635", "CRITICAL", 9.8, "7.5", "8.5", "Microsoft IIS HTTP.sys remote code execution"),
    ("iis", "CVE-2021-31166", "CRITICAL", 9.8, "10.0", "10.0", "Microsoft IIS HTTP Protocol Stack RCE"),
    // Microsoft Exchange
    ("exchange", "CVE-2021-26855", "CRITICAL", 9.8, "15.0.0", "15.2.792", "Microsoft Exchange Server SSRF leading to pre-auth RCE (ProxyLogon, KEV)"),
    ("exchange", "CVE-2021-34473", "CRITICAL", 9.8, "15.0.0", "15.2.858", "Microsoft Exchange Server remote code execution (ProxyShell, KEV)"),
    ("exchange", "CVE-2022-41082", "HIGH", 8.8, "15.0.0", "15.2.1118", "Microsoft Exchange Server remote code execution (ProxyNotShell, KEV)"),
    // Magento / Adobe Commerce (CMS detection)
    ("magento", "CVE-2022-24086", "CRITICAL", 9.8, "2.3.0", "2.4.2", "Magento/Adobe Commerce pre-auth RCE via template injection (KEV)"),
    ("magento", "CVE-2022-24087", "CRITICAL", 9.8, "2.3.0", "2.4.2", "Magento/Adobe Commerce pre-auth RCE follow-up (KEV)"),
    ("magento", "CVE-2025-24434", "CRITICAL", 9.1, "2.4.0", "2.4.7", "Magento/Adobe Commerce authorization bypass allowing code read/execution"),
    // PrestaShop (CMS detection)
    ("prestashop", "CVE-2023-30839", "CRITICAL", 10.0, "0", "8.0.4", "PrestaShop SQL injection via crafted HTTP request body"),
    ("prestashop", "CVE-2022-36408", "HIGH", 7.2, "0", "1.7.8", "PrestaShop SQL injection via BO invoice module"),
    // Roundcube (webmail — common in European hosting)
    ("roundcube", "CVE-2023-5631", "HIGH", 8.8, "0", "1.6.3", "Roundcube stored XSS via HTML-formatted email (KEV)"),
    ("roundcube", "CVE-2023-43770", "MEDIUM", 6.1, "0", "1.4.14", "Roundcube XSS via plaintext email linkreference"),
    ("roundcube", "CVE-2024-37383", "MEDIUM", 6.1, "0", "1.5.7", "Roundcube XSS via SVG animate attributes in HTML email"),
];

// ---- Version helpers ----

/// Extract a version string from a service banner for a known technology.
/// Returns None if the technology is unrecognised or the banner has no version.
pub(crate) fn extract_version(banner: &str, technology: &str) -> Option<String> {
    let lower = banner.to_ascii_lowercase();
    match technology {
        "mysql" => {
            let pos = lower.find("mysql")?;
            let after = &banner[pos + 5..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let token: String = after[ver_start..]
                .chars()
                .take_while(|c| !c.is_ascii_whitespace())
                .collect();
            // Strip MariaDB compatibility prefix "5.5.5-"
            let version: String = if token.starts_with("5.5.5-") {
                token[6..]
                    .split('-')
                    .next()
                    .unwrap_or(&token[6..])
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect()
            } else {
                token.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect()
            };
            if version.is_empty() { None } else { Some(version) }
        }
        "openssh" => {
            let pos = lower.find("openssh_")?;
            let after = &banner[pos + 8..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let token: String = after[ver_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == 'p')
                .collect();
            // Strip patch suffix "p<N>" (e.g. "9.3p1" → "9.3")
            let version = if let Some(p_pos) = token.find('p') {
                if token[p_pos + 1..].chars().next().map_or(false, |c| c.is_ascii_digit()) {
                    token[..p_pos].to_string()
                } else {
                    token
                }
            } else {
                token
            };
            if version.is_empty() { None } else { Some(version) }
        }
        "proftpd" => {
            let pos = lower.find("proftpd")?;
            let after = &banner[pos + 7..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let version: String = after[ver_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if version.is_empty() { None } else { Some(version) }
        }
        "vsftpd" => {
            let pos = lower.find("vsftpd")?;
            let after = &banner[pos + 6..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let version: String = after[ver_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if version.is_empty() { None } else { Some(version) }
        }
        "redis" => {
            // Banner format: "Redis 6.2.6"
            let pos = lower.find("redis ")?;
            let after = &banner[pos + 6..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let version: String = after[ver_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if version.is_empty() { None } else { Some(version) }
        }
        "elasticsearch" => {
            // Banner format: "Elasticsearch 7.13.3"
            let pos = lower.find("elasticsearch ")?;
            let after = &banner[pos + 14..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let version: String = after[ver_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if version.is_empty() { None } else { Some(version) }
        }
        "memcached" => {
            // Banner format: "VERSION 1.6.9"
            let upper = banner.to_ascii_uppercase();
            let pos = upper.find("VERSION ")?;
            let after = &banner[pos + 8..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let version: String = after[ver_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if version.is_empty() { None } else { Some(version) }
        }
        "mssql" => {
            // Banner: "MSSQL 15.0 build 2000" → "15.0.2000"
            let upper = banner.to_ascii_uppercase();
            let pos = upper.find("MSSQL ")?;
            let after = &banner[pos + 6..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let major_minor: String = after[ver_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if major_minor.is_empty() { return None; }
            let lower_b = banner.to_ascii_lowercase();
            if let Some(b_pos) = lower_b.find(" build ") {
                let build: String = banner[b_pos + 7..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if !build.is_empty() {
                    return Some(format!("{major_minor}.{build}"));
                }
            }
            Some(major_minor)
        }
        _ => None,
    }
}

/// Compare dotted-numeric version strings. Ignores non-digit suffixes on each component
/// (e.g. "9.3p1" treats the "p1" component as "3", "8.5p1" as "8.5").
fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|p| {
                let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
                digits.parse::<u64>().unwrap_or(0)
            })
            .collect()
    };
    let pa = parts(a);
    let pb = parts(b);
    let len = pa.len().max(pb.len());
    for i in 0..len {
        let va = pa.get(i).copied().unwrap_or(0);
        let vb = pb.get(i).copied().unwrap_or(0);
        match va.cmp(&vb) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Returns true if `version` falls within [from, to] (inclusive).
/// - Both None → always matches (no range constraint)
/// - Unparseable version (no digits) → matches (fail open)
/// - "0" from and "999" to are natural sentinels handled by numeric comparison
fn version_in_range(version: &str, from: Option<&str>, to: Option<&str>) -> bool {
    if from.is_none() && to.is_none() {
        return true;
    }
    if !version.chars().any(|c| c.is_ascii_digit()) {
        return true; // fail open
    }
    if let Some(f) = from {
        if cmp_version(version, f) == std::cmp::Ordering::Less {
            return false;
        }
    }
    if let Some(t) = to {
        if cmp_version(version, t) == std::cmp::Ordering::Greater {
            return false;
        }
    }
    true
}

// ---- List services ----

pub(crate) fn cmd_list_services(db: std::path::PathBuf) -> Result<()> {
    let conn = crate::shared::open_db(&db)
        .with_context(|| format!("open db {:?}", db))?;

    let mut stmt = conn.prepare(
        "SELECT domain, port, banner FROM ports_info WHERE banner IS NOT NULL ORDER BY port, domain",
    )?;

    // (port, technology) → (versions set, domain count)
    let mut map: std::collections::BTreeMap<(i64, String), (std::collections::BTreeMap<String, usize>, usize)> = std::collections::BTreeMap::new();

    let rows: Vec<(String, i64, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .filter_map(|r| r.ok())
        .collect();

    for (domain, port, banner) in &rows {
        let lower = banner.to_ascii_lowercase();
        let technology = match *port {
            3306 if lower.contains("mysql")         => "mysql",
            21   if lower.contains("proftpd")       => "proftpd",
            21   if lower.contains("vsftpd")        => "vsftpd",
            21                                      => "ftp",
            22   if lower.contains("openssh")       => "openssh",
            22                                      => "ssh",
            25 | 587                                => "smtp",
            6379 if lower.contains("redis")         => "redis",
            9200 if lower.contains("elasticsearch") => "elasticsearch",
            11211                                   => "memcached",
            2375                                    => "docker",
            6443                                    => "kubernetes",
            5900                                    => "vnc",
            1433 if lower.contains("mssql")         => "mssql",
            _                                       => "unknown",
        };
        let entry = map.entry((*port, technology.to_string())).or_default();
        entry.1 += 1;
        let _ = domain; // counted via entry.1
        if let Some(ver) = extract_version(banner, technology) {
            *entry.0.entry(ver).or_insert(0) += 1;
        }
    }

    println!("{:<6} {:<16} {:<24} {}", "PORT", "SERVICE", "VERSION(S)", "DOMAINS");
    println!("{}", "-".repeat(70));
    for ((port, tech), (versions, domain_count)) in &map {
        if versions.is_empty() {
            println!("{:<6} {:<16} {:<24} {}", port, tech, "(unknown)", domain_count);
        } else {
            for (i, (ver, _)) in versions.iter().enumerate() {
                if i == 0 {
                    println!("{:<6} {:<16} {:<24} {}", port, tech, ver, domain_count);
                } else {
                    println!("{:<6} {:<16} {:<24}", "", "", ver);
                }
            }
        }
    }

    Ok(())
}

// ---- CISA KEV fetcher ----

pub(crate) async fn cmd_update_cves(db: PathBuf) -> Result<()> {
    let conn = crate::shared::open_db(&db)
        .with_context(|| format!("open db {:?}", db))?;

    crate::schema::ensure_schema(&conn)?;

    // Seed hardcoded entries first
    let seeded = seed_hardcoded_cves(&conn)?;
    eprintln!("cve: seeded {seeded} hardcoded CVE entries");

    // Fetch CISA KEV feed
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    eprintln!("cve: fetching {url}");

    let fetch_result = async {
        let resp = client.get(url).send().await
            .context("fetching CISA KEV feed")?;
        let bytes = resp.bytes().await.context("reading CISA KEV response body")?;
        let json: Value = serde_json::from_slice(&bytes).context("parsing CISA KEV JSON")?;
        Ok::<Value, anyhow::Error>(json)
    }.await;

    let json = match fetch_result {
        Ok(j) => j,
        Err(e) => {
            eprintln!("cve: WARNING — could not fetch CISA KEV feed ({e:#}); using hardcoded entries only");
            run_cve_matching(&conn)?;
            return Ok(());
        }
    };

    let vulnerabilities = json["vulnerabilities"]
        .as_array()
        .context("missing vulnerabilities array")?;

    let relevant_vendors = &["wordpress", "drupal", "joomla", "apache", "nginx", "openssl", "php", "typo3", "craft cms", "tomcat", "litespeed", "mysql", "mariadb", "proftpd", "openssh", "iis", "exchange", "magento", "prestashop", "roundcube", "mssql", "sql server"];

    let mut inserted = 0usize;
    for entry in vulnerabilities {
        let vendor = entry["vendorProject"].as_str().unwrap_or("").to_ascii_lowercase();
        let product = entry["product"].as_str().unwrap_or("").to_ascii_lowercase();
        let combined = format!("{vendor} {product}");

        let matched_tech = relevant_vendors.iter().find(|&&v| combined.contains(v));
        let Some(&technology) = matched_tech else { continue };
        let technology = if technology == "sql server" { "mssql" } else { technology };

        let cve_id = entry["cveID"].as_str().unwrap_or("").to_string();
        if cve_id.is_empty() { continue; }

        let summary: Option<String> = entry["shortDescription"].as_str().map(|s: &str| s.to_string());
        let published_at: Option<String> = entry["dateAdded"].as_str().map(|s: &str| s.to_string());

        conn.execute(
            "INSERT INTO cve_catalog (cve_id, technology, severity, in_kev, summary, published_at)
             VALUES (?1, ?2, 'CRITICAL', 1, ?3, ?4)
             ON CONFLICT(cve_id) DO UPDATE SET
                severity     = excluded.severity,
                in_kev       = excluded.in_kev,
                summary      = excluded.summary,
                published_at = excluded.published_at",
            rusqlite::params![
                cve_id.as_str(),
                technology,
                summary.as_deref(),
                published_at.as_deref(),
            ],
        )?;
        inserted += 1;
    }

    eprintln!("cve: inserted/updated {inserted} KEV entries");

    let matched = run_cve_matching(&conn)?;
    eprintln!("cve: {matched} domain-CVE matches recorded");

    Ok(())
}

fn seed_hardcoded_cves(conn: &rusqlite::Connection) -> Result<usize> {
    let mut count = 0usize;
    for &(technology, cve_id, severity, cvss_score, affected_from, affected_to, summary) in SEED_CVES {
        conn.execute(
            "INSERT INTO cve_catalog (cve_id, technology, affected_from, affected_to, severity, cvss_score, in_kev, summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
             ON CONFLICT(cve_id) DO UPDATE SET
                technology    = excluded.technology,
                affected_from = excluded.affected_from,
                affected_to   = excluded.affected_to,
                severity      = excluded.severity,
                cvss_score    = excluded.cvss_score,
                summary       = excluded.summary",
            rusqlite::params![
                cve_id,
                technology,
                affected_from,
                affected_to,
                severity,
                cvss_score,
                summary,
            ],
        )?;
        count += 1;
    }
    Ok(count)
}

pub(crate) fn run_cve_matching(conn: &rusqlite::Connection) -> Result<usize> {
    conn.execute("DELETE FROM cve_matches", [])?;
    conn.execute_batch(
        "INSERT INTO cve_matches (domain, technology, version, cve_id, severity, cvss_score, in_kev, published_at)
         -- CMS / server / powered_by header matching
         SELECT d.domain, c.technology,
                -- Extract version from server header: e.g. 'Apache/2.4.58 (FreeBSD)' → '2.4.58'
                CASE
                  WHEN lower(coalesce(d.server, '')) LIKE '%' || c.technology || '/%'
                  THEN (
                    WITH after_slash(s) AS (
                      SELECT substr(lower(d.server),
                               instr(lower(d.server), c.technology || '/') + length(c.technology) + 1)
                    )
                    SELECT CASE
                             WHEN instr(s, ' ') > 0 THEN substr(s, 1, instr(s, ' ') - 1)
                             ELSE s
                           END
                    FROM after_slash
                  )
                  ELSE NULL
                END,
                c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM domains d
         JOIN cve_catalog c ON lower(coalesce(d.cms, '')) = c.technology
                            OR lower(coalesce(d.server, '')) LIKE '%' || c.technology || '%'
                            OR lower(coalesce(d.powered_by, '')) LIKE '%' || c.technology || '%'
         WHERE d.cms IS NOT NULL OR d.server IS NOT NULL OR d.powered_by IS NOT NULL
         UNION
         -- MySQL / MariaDB banner on port 3306
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'mysql'
         WHERE p.port = 3306 AND lower(coalesce(p.banner, '')) LIKE '%mysql%'
         UNION
         -- ProFTPD banner on port 21
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'proftpd'
         WHERE p.port = 21 AND lower(coalesce(p.banner, '')) LIKE '%proftpd%'
         UNION
         -- vsftpd banner on port 21
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'vsftpd'
         WHERE p.port = 21 AND lower(coalesce(p.banner, '')) LIKE '%vsftpd%'
         UNION
         -- OpenSSH banner on port 22
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'openssh'
         WHERE p.port = 22 AND lower(coalesce(p.banner, '')) LIKE '%openssh%'
         UNION
         -- RDP presence-only on port 3389 (no readable banner)
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'rdp'
         WHERE p.port = 3389
         UNION
         -- Redis banner on port 6379
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'redis'
         WHERE p.port = 6379 AND lower(coalesce(p.banner, '')) LIKE '%redis%'
         UNION
         -- Elasticsearch banner on port 9200
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'elasticsearch'
         WHERE p.port = 9200 AND lower(coalesce(p.banner, '')) LIKE '%elasticsearch%'
         UNION
         -- Memcached banner on port 11211
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'memcached'
         WHERE p.port = 11211 AND lower(coalesce(p.banner, '')) LIKE '%memcached%'
         UNION
         -- Docker API presence on port 2375 (unauthenticated socket)
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'docker'
         WHERE p.port = 2375
         UNION
         -- MSSQL banner on port 1433
         SELECT p.domain, c.technology, NULL, c.cve_id, c.severity, c.cvss_score, c.in_kev, c.published_at
         FROM ports_info p
         JOIN cve_catalog c ON c.technology = 'mssql'
         WHERE p.port = 1433 AND lower(coalesce(p.banner, '')) LIKE '%mssql%'
         ON CONFLICT (domain, cve_id) DO UPDATE SET matched_at = datetime('now')",
    )?;

    apply_port_versions(conn)?;
    apply_version_filter(conn)?;

    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM cve_matches",
        [],
        |r| r.get(0),
    )?;

    Ok(count as usize)
}

/// For each port banner that carries a version string, update `cve_matches.version`
/// so the version filter has something to compare against.
fn apply_port_versions(conn: &rusqlite::Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT p.domain,
            CASE
                WHEN p.port = 3306  AND lower(p.banner) LIKE '%mysql%'         THEN 'mysql'
                WHEN p.port = 21    AND lower(p.banner) LIKE '%proftpd%'        THEN 'proftpd'
                WHEN p.port = 21    AND lower(p.banner) LIKE '%vsftpd%'         THEN 'vsftpd'
                WHEN p.port = 22    AND lower(p.banner) LIKE '%openssh%'        THEN 'openssh'
                WHEN p.port = 6379  AND lower(p.banner) LIKE '%redis%'          THEN 'redis'
                WHEN p.port = 9200  AND lower(p.banner) LIKE '%elasticsearch%'  THEN 'elasticsearch'
                WHEN p.port = 11211 AND lower(p.banner) LIKE '%memcached%'      THEN 'memcached'
                WHEN p.port = 1433  AND lower(p.banner) LIKE '%mssql%'          THEN 'mssql'
            END AS technology,
            p.banner
         FROM ports_info p
         WHERE p.banner IS NOT NULL
           AND (   (p.port = 3306  AND lower(p.banner) LIKE '%mysql%')
                OR (p.port = 21    AND lower(p.banner) LIKE '%proftpd%')
                OR (p.port = 21    AND lower(p.banner) LIKE '%vsftpd%')
                OR (p.port = 22    AND lower(p.banner) LIKE '%openssh%')
                OR (p.port = 6379  AND lower(p.banner) LIKE '%redis%')
                OR (p.port = 9200  AND lower(p.banner) LIKE '%elasticsearch%')
                OR (p.port = 11211 AND lower(p.banner) LIKE '%memcached%')
                OR (p.port = 1433  AND lower(p.banner) LIKE '%mssql%'))",
    )?;

    let rows: Vec<(String, String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .filter_map(|r| r.ok())
        .collect();

    for (domain, technology, banner) in rows {
        if let Some(version) = extract_version(&banner, &technology) {
            conn.execute(
                "UPDATE cve_matches SET version = ?1 WHERE domain = ?2 AND technology = ?3",
                rusqlite::params![version, domain, technology],
            )?;
        }
    }
    Ok(())
}

/// Delete `cve_matches` rows whose extracted version falls outside the CVE's affected range.
fn apply_version_filter(conn: &rusqlite::Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT cm.domain, cm.cve_id, cm.version, cc.affected_from, cc.affected_to
         FROM cve_matches cm
         JOIN cve_catalog cc ON cc.cve_id = cm.cve_id
         WHERE cm.version IS NOT NULL
           AND (cc.affected_from IS NOT NULL OR cc.affected_to IS NOT NULL)",
    )?;

    let candidates: Vec<(String, String, String, Option<String>, Option<String>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?
        .filter_map(|r| r.ok())
        .collect();

    for (domain, cve_id, version, from, to) in candidates {
        if !version_in_range(&version, from.as_deref(), to.as_deref()) {
            conn.execute(
                "DELETE FROM cve_matches WHERE domain = ?1 AND cve_id = ?2",
                rusqlite::params![domain, cve_id],
            )?;
        }
    }
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

    #[test]
    fn seed_inserts_all_hardcoded_cves() {
        let conn = in_memory_db();
        let count = seed_hardcoded_cves(&conn).unwrap();
        assert_eq!(count, SEED_CVES.len());

        let in_db: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve_catalog", [], |r| r.get(0))
            .unwrap();
        assert_eq!(in_db as usize, SEED_CVES.len());
    }

    #[test]
    fn seed_is_idempotent() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        seed_hardcoded_cves(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve_catalog", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count as usize, SEED_CVES.len());
    }

    #[test]
    fn run_cve_matching_matches_wordpress_domain() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();

        conn.execute_batch(
            "INSERT INTO domains (domain, status, cms) VALUES ('wp-site.ch', 'ok', 'WordPress')",
        )
        .unwrap();

        let matched = run_cve_matching(&conn).unwrap();
        assert!(matched > 0, "expected at least one WordPress CVE match");

        let domain_match: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cve_matches WHERE domain='wp-site.ch'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(domain_match > 0);
    }

    #[test]
    fn run_cve_matching_no_match_for_unknown_cms() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();

        conn.execute_batch(
            "INSERT INTO domains (domain, status, cms) VALUES ('unknown.ch', 'ok', 'SomeCMS')",
        )
        .unwrap();

        let matched = run_cve_matching(&conn).unwrap();
        assert_eq!(matched, 0);
    }

    #[test]
    fn run_cve_matching_matches_mysql_port_banner() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();

        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('db.ch');
             INSERT INTO ports_info (domain, port, service, banner) VALUES ('db.ch', 3306, 'mysql', 'MySQL 8.0.32');",
        )
        .unwrap();

        let matched = run_cve_matching(&conn).unwrap();
        assert!(matched > 0, "expected MySQL CVE match from port 3306 banner");

        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cve_matches WHERE domain='db.ch' AND technology='mysql'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(n > 0);
    }

    #[test]
    fn run_cve_matching_matches_mariadb_banner() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();

        // Use an old MariaDB version (5.5.60) that is within the range of legacy MySQL CVEs
        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('maria.ch');
             INSERT INTO ports_info (domain, port, service, banner) VALUES ('maria.ch', 3306, 'mysql', 'MySQL 5.5.5-5.5.60-MariaDB-log');",
        )
        .unwrap();

        let matched = run_cve_matching(&conn).unwrap();
        assert!(matched > 0, "expected mysql CVE match from MariaDB 5.5.60 banner");
    }

    #[test]
    fn run_cve_matching_matches_rdp_presence() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();

        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('rdp.ch');
             INSERT INTO ports_info (domain, port, service) VALUES ('rdp.ch', 3389, 'rdp');",
        )
        .unwrap();

        run_cve_matching(&conn).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cve_matches WHERE domain='rdp.ch' AND technology='rdp'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(n > 0, "expected RDP CVE matches from port 3389 presence");
    }

    #[test]
    fn run_cve_matching_matches_openssh_banner() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();

        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('ssh.ch');
             INSERT INTO ports_info (domain, port, service, banner) VALUES ('ssh.ch', 22, 'ssh', 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6');",
        )
        .unwrap();

        run_cve_matching(&conn).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cve_matches WHERE domain='ssh.ch' AND technology='openssh'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(n > 0, "expected OpenSSH CVE match from port 22 banner");
    }

    #[test]
    fn all_seed_cves_have_valid_cve_ids() {
        for &(_, cve_id, _, _, _, _, _) in SEED_CVES {
            assert!(
                cve_id.starts_with("CVE-"),
                "expected CVE ID format for: {cve_id}"
            );
        }
    }

    #[test]
    fn all_seed_cves_have_known_severity() {
        let valid = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
        for &(_, _, severity, _, _, _, _) in SEED_CVES {
            assert!(
                valid.contains(&severity),
                "unexpected severity '{severity}'"
            );
        }
    }

    // ---- extract_version ----

    #[test]
    fn extract_version_mysql_plain() {
        assert_eq!(extract_version("MySQL 8.0.40", "mysql"), Some("8.0.40".into()));
    }

    #[test]
    fn extract_version_mysql_mariadb_prefix() {
        assert_eq!(
            extract_version("MySQL 5.5.5-10.6.20-MariaDB-log", "mysql"),
            Some("10.6.20".into())
        );
    }

    #[test]
    fn extract_version_openssh() {
        assert_eq!(
            extract_version("SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6", "openssh"),
            Some("9.3".into())
        );
    }

    #[test]
    fn extract_version_proftpd() {
        assert_eq!(
            extract_version("220 ProFTPD 1.3.6 Server (example.ch)", "proftpd"),
            Some("1.3.6".into())
        );
    }

    #[test]
    fn extract_version_vsftpd() {
        assert_eq!(extract_version("220 (vsFTPd 3.0.5)", "vsftpd"), Some("3.0.5".into()));
    }

    #[test]
    fn extract_version_unknown_tech_returns_none() {
        assert_eq!(extract_version("Apache/2.4.52", "apache"), None);
    }

    // ---- cmp_version ----

    #[test]
    fn cmp_version_greater() {
        assert_eq!(cmp_version("8.0.42", "8.0.32"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn cmp_version_less() {
        assert_eq!(cmp_version("5.7.14", "5.7.15"), std::cmp::Ordering::Less);
    }

    #[test]
    fn cmp_version_equal() {
        assert_eq!(cmp_version("9.3", "9.3p1"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn cmp_version_handles_patch_suffix() {
        // "8.5p1" should be treated as "8.5" for the p-suffix component
        assert_eq!(cmp_version("9.3", "8.5p1"), std::cmp::Ordering::Greater);
    }

    // ---- version_in_range ----

    #[test]
    fn version_in_range_no_bounds() {
        assert!(version_in_range("8.0.42", None, None));
    }

    #[test]
    fn version_in_range_within() {
        assert!(version_in_range("8.0.30", Some("8.0.0"), Some("8.0.32")));
    }

    #[test]
    fn version_in_range_above_upper() {
        assert!(!version_in_range("8.0.42", Some("8.0.0"), Some("8.0.32")));
    }

    #[test]
    fn version_in_range_at_upper_bound() {
        assert!(version_in_range("8.0.32", Some("8.0.0"), Some("8.0.32")));
    }

    #[test]
    fn version_in_range_unparseable_fails_open() {
        assert!(version_in_range("unknown", Some("1.0"), Some("2.0")));
    }

    // ---- Integration: version filtering ----

    #[test]
    fn version_filter_removes_false_positive_mysql_cve_2016_6662() {
        // CVE-2016-6662 affects 0–5.7.15; MySQL 8.0.42 should NOT match
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('db.ch');
             INSERT INTO ports_info (domain, port, service, banner)
             VALUES ('db.ch', 3306, 'mysql', 'MySQL 8.0.42');",
        )
        .unwrap();

        run_cve_matching(&conn).unwrap();

        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cve_matches WHERE domain='db.ch' AND cve_id='CVE-2016-6662'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "CVE-2016-6662 must not match MySQL 8.0.42");
    }

    #[test]
    fn version_filter_keeps_cve_2023_21980_for_mysql_8_0_30() {
        // CVE-2023-21980 affects 8.0.0–8.0.32; MySQL 8.0.30 should match
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('db.ch');
             INSERT INTO ports_info (domain, port, service, banner)
             VALUES ('db.ch', 3306, 'mysql', 'MySQL 8.0.30');",
        )
        .unwrap();

        run_cve_matching(&conn).unwrap();

        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cve_matches WHERE domain='db.ch' AND cve_id='CVE-2023-21980'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "CVE-2023-21980 must match MySQL 8.0.30");
    }

    #[test]
    fn version_filter_removes_cve_2023_21980_for_mysql_8_0_33() {
        // CVE-2023-21980 upper bound is 8.0.32; 8.0.33 should NOT match
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('db.ch');
             INSERT INTO ports_info (domain, port, service, banner)
             VALUES ('db.ch', 3306, 'mysql', 'MySQL 8.0.33');",
        )
        .unwrap();

        run_cve_matching(&conn).unwrap();

        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cve_matches WHERE domain='db.ch' AND cve_id='CVE-2023-21980'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "CVE-2023-21980 must not match MySQL 8.0.33");
    }

    #[test]
    fn version_filter_removes_regressing_openssh_false_positive() {
        // CVE-2024-6387 affects 8.5–9.7; OpenSSH 9.8 should NOT match
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('ssh.ch');
             INSERT INTO ports_info (domain, port, service, banner)
             VALUES ('ssh.ch', 22, 'ssh', 'SSH-2.0-OpenSSH_9.8p1 Ubuntu-3ubuntu0.7');",
        )
        .unwrap();

        run_cve_matching(&conn).unwrap();

        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cve_matches WHERE domain='ssh.ch' AND cve_id='CVE-2024-6387'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "CVE-2024-6387 must not match OpenSSH 9.8");
    }
}
