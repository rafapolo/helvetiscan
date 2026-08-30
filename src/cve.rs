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
    ("wordpress", "CVE-2026-60137", "HIGH", 8.8, "6.8.0", "7.0.1", "WordPress WP2Shell facilitated SQL injection via author__not_in in WP_Query — combined with batch-route confusion leads to RCE"),
    ("wordpress", "CVE-2026-63030", "CRITICAL", 9.8, "6.9.0", "7.0.1", "WordPress WP2Shell REST API batch-route confusion + SQLi leading to pre-auth RCE — actively exploited in the wild"),
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
    // MongoDB (port 27017 — presence/exposure based, no readable version)
    ("mongodb", "CVE-2019-2386", "MEDIUM", 5.9, "0", "4.0.9", "MongoDB user session not invalidated after user deletion"),
    ("mongodb", "CVE-2021-20329", "MEDIUM", 6.5, "0", "3.6.13", "MongoDB BSON type confusion allowing injection"),
    ("mongodb", "CVE-2020-7921", "MEDIUM", 5.3, "0", "4.4.0", "MongoDB improper serialization of authorization info"),
    // PostgreSQL (port 5432)
    ("postgresql", "CVE-2019-9193", "HIGH", 8.8, "9.3", "11.2", "PostgreSQL COPY TO/FROM PROGRAM arbitrary command execution"),
    ("postgresql", "CVE-2018-1058", "HIGH", 8.8, "0", "10.2", "PostgreSQL search_path schema hijacking"),
    ("postgresql", "CVE-2021-23214", "HIGH", 8.1, "0", "13.5", "PostgreSQL processes unencrypted bytes from man-in-the-middle"),
    // VNC / RFB (port 5900 — presence based)
    ("vnc", "CVE-2018-7225", "CRITICAL", 9.8, "0", "999", "LibVNCServer rfbProcessClientNormalMessage out-of-bounds access"),
    ("vnc", "CVE-2019-15681", "HIGH", 7.5, "0", "999", "LibVNC server memory leak information disclosure"),
    ("vnc", "CVE-2019-8287", "HIGH", 8.8, "0", "999", "TightVNC heap buffer overflow in HandleCoRREBBP"),
    // JavaScript libraries (detected from page assets, versioned)
    ("jquery", "CVE-2020-11022", "MEDIUM", 6.1, "1.2", "3.5.0", "jQuery cross-site scripting via HTML from untrusted sources"),
    ("jquery", "CVE-2019-11358", "MEDIUM", 6.1, "0", "3.4.0", "jQuery prototype pollution via jQuery.extend"),
    ("jquery", "CVE-2015-9251", "MEDIUM", 6.1, "0", "3.0.0", "jQuery cross-site scripting via cross-domain ajax"),
    ("bootstrap", "CVE-2019-8331", "MEDIUM", 6.1, "0", "3.4.1", "Bootstrap XSS in tooltip/popover data-template"),
    ("bootstrap", "CVE-2018-14041", "MEDIUM", 6.1, "4.0.0", "4.1.2", "Bootstrap XSS in data-target property of scrollspy"),
    ("angular", "CVE-2020-7676", "MEDIUM", 6.1, "0", "1.8.0", "AngularJS XSS via SVG usage in ng-bind-html"),
    ("angular", "CVE-2019-10768", "HIGH", 7.5, "0", "1.7.9", "AngularJS prototype pollution in merge"),
    ("lodash", "CVE-2019-10744", "CRITICAL", 9.1, "0", "4.17.12", "Lodash prototype pollution via defaultsDeep"),
    ("lodash", "CVE-2021-23337", "HIGH", 7.2, "0", "4.17.21", "Lodash command injection via template"),
    ("moment", "CVE-2022-31129", "HIGH", 7.5, "0", "2.29.4", "Moment.js ReDoS in string-to-date parsing"),
    // Web frameworks (detected from headers/cookies, presence based)
    ("laravel", "CVE-2021-3129", "CRITICAL", 9.8, "0", "8.4.2", "Laravel Ignition debug-mode remote code execution"),
    ("express", "CVE-2024-29041", "MEDIUM", 6.1, "0", "4.19.1", "Express open redirect via malformed URLs in response.location"),
    // WordPress plugins (detected from /wp-content/plugins/<slug>/)
    ("contact-form-7", "CVE-2020-35489", "CRITICAL", 9.8, "0", "5.3.1", "Contact Form 7 unrestricted file upload"),
    ("elementor", "CVE-2022-1329", "HIGH", 8.8, "0", "3.6.3", "Elementor authenticated remote code execution via file upload"),
    // Apache Struts (detected via response patterns / .action/.do endpoints)
    ("apache-struts", "CVE-2017-5638", "CRITICAL", 9.8, "0", "2.3.32", "Apache Struts2 RCE via Content-Type header (Equifax breach)"),
    ("apache-struts", "CVE-2018-11776", "CRITICAL", 9.8, "0", "2.3.34", "Apache Struts2 RCE via namespace/result with no namespace"),
    ("apache-struts", "CVE-2017-9805", "CRITICAL", 9.8, "0", "2.3.33", "Apache Struts2 REST plugin XStream deserialization RCE"),
    ("apache-struts", "CVE-2017-9791", "CRITICAL", 9.8, "0", "2.3.32", "Apache Struts2 devMode OGNL injection"),
    ("apache-struts", "CVE-2013-2251", "CRITICAL", 9.8, "0", "2.3.15", "Apache Struts2 DMI method invocation RCE"),
    ("apache-struts", "CVE-2012-0394", "HIGH", 8.8, "0", "2.3.8", "Apache Struts2 ParameterInterceptor class loader manipulation"),
    ("apache-struts", "CVE-2006-1547", "HIGH", 7.5, "0", "1.2.9", "Apache Struts form validation bypass"),
    ("apache-struts", "CVE-2020-17530", "CRITICAL", 9.8, "0", "2.5.25", "Apache Struts2 forced double OGNL evaluation"),
    // Apache Log4j (detected via JNDI injection probe or Server header patterns)
    ("apache-log4j", "CVE-2021-44228", "CRITICAL", 10.0, "2.0", "2.14.1", "Log4Shell — JNDI injection RCE via logged user input (KEV)"),
    ("apache-log4j", "CVE-2021-45046", "CRITICAL", 10.0, "2.0", "2.16.0", "Log4j2 incomplete fix for CVE-2021-44228 — RCE via thread context map pattern lookup"),
    // Apache Shiro (detected via rememberMe cookie)
    ("apache-shiro", "CVE-2016-4437", "CRITICAL", 10.0, "1.2.4", "1.2.5", "Apache Shiro default AES key allows deserialization RCE via rememberMe cookie (KEV)"),
    // Apache Solr (port 8983 HTTP API)
    ("apache-solr", "CVE-2019-0193", "CRITICAL", 9.8, "5.0", "5.5.5", "Apache Solr DataImportHandler RCE via custom request parameters"),
    ("apache-solr", "CVE-2019-17558", "CRITICAL", 9.8, "5.0", "8.3.1", "Apache Solr velocity template injection RCE via params.resource.loader.enabled"),
    // Apache ActiveMQ (port 8161 admin console)
    ("apache-activemq", "CVE-2023-46604", "CRITICAL", 10.0, "5.0", "5.18.2", "Apache ActiveMQ RCE via ClassInfo in OpenWire protocol (KEV)"),
    ("apache-activemq", "CVE-2016-3088", "CRITICAL", 10.0, "5.0", "5.13.2", "Apache ActiveMQ file-based message store RCE via web console"),
    ("apache-activemq", "CVE-2026-34197", "CRITICAL", 9.8, "0", "6.1.6", "Apache ActiveMQ unauthorized Jolokia endpoint access leading to RCE"),
    // Apache RocketMQ
    ("apache-rocketmq", "CVE-2023-33246", "CRITICAL", 9.8, "0", "5.1.1", "Apache RocketMQ remote command execution via broker configuration update"),
    // Apache Spark
    ("apache-spark", "CVE-2022-33891", "CRITICAL", 9.8, "0", "3.2.1", "Apache Spark shell command injection via Spark-Submit UI"),
    // Apache Flink
    ("apache-flink", "CVE-2020-17519", "CRITICAL", 9.8, "0", "1.12.0", "Apache Flink SQL client OS command injection via JAR upload"),
    // Apache Superset
    ("apache-superset", "CVE-2023-27524", "CRITICAL", 9.8, "0", "2.0.0", "Apache Superset default SECRET_KEY allows admin session takeover"),
    // Apache OfBiz
    ("apache-ofbiz", "CVE-2024-32113", "CRITICAL", 9.8, "0", "18.12.14", "Apache OFBiz pre-auth RCE via deserialization vulnerability"),
    ("apache-ofbiz", "CVE-2024-38856", "CRITICAL", 9.8, "0", "18.12.15", "Apache OFBiz view-entity SQL injection leading to RCE"),
    ("apache-ofbiz", "CVE-2024-45195", "CRITICAL", 9.8, "0", "18.12.16", "Apache OFBiz screen rendering SSRF to RCE"),
    // Apache CouchDB (port 5984)
    ("apache-couchdb", "CVE-2022-24706", "CRITICAL", 10.0, "0", "3.2.2", "Apache CouchDB default admin password in setup wizard leading to RCE (KEV)"),
    // Apache HugeGraph
    ("apache-hugegraph", "CVE-2024-27348", "CRITICAL", 9.8, "0", "1.3.0", "Apache HugeGraph Groovy script injection RCE via Gremlin API"),
    // Apache Kylin
    ("apache-kylin", "CVE-2020-1956", "CRITICAL", 9.8, "0", "3.0.1", "Apache Kylin command injection via diagnostic API"),
    // Apache Airflow
    ("apache-airflow", "CVE-2020-11978", "CRITICAL", 9.8, "0", "1.10.10", "Apache Airflow command injection via example DAGs"),
    ("apache-airflow", "CVE-2020-13927", "CRITICAL", 9.8, "0", "1.10.10", "Apache Airflow unauthenticated REST API allowing remote command execution"),
    // Apache APISIX
    ("apache-apisix", "CVE-2022-24112", "CRITICAL", 9.8, "0", "2.13.0", "Apache APISIX batch-requests plugin RCE via SSRF"),
    // Magento additional CVEs
    ("magento", "CVE-2024-34102", "CRITICAL", 9.8, "2.4.0", "2.4.6", "Magento/Adobe Commerce XML external entity injection leading to RCE"),
    // Roundcube additional CVEs
    ("roundcube", "CVE-2024-42009", "CRITICAL", 9.8, "0", "1.6.9", "Roundcube XSS via crafted HTML email leading to session hijack"),
    ("roundcube", "CVE-2025-49113", "CRITICAL", 9.8, "0", "1.6.11", "Roundcube server-side template injection via email body rendering"),
    // Drupal additional
    ("drupal", "CVE-2026-9082", "CRITICAL", 9.8, "0", "999", "Drupal SQL injection via filter module leading to privilege escalation"),
    ("drupal", "CVE-2020-13671", "CRITICAL", 9.8, "0", "9.0.15", "Drupal sanitization bypass allowing file extension exploitation"),
    // Joomla additional
    ("joomla", "CVE-2026-48907", "CRITICAL", 9.8, "0", "6.0.0", "Joomla Widget Factory plugin access control bypass"),
    ("joomla", "CVE-2026-56290", "CRITICAL", 9.8, "0", "6.0.0", "Joomla Page Builder access control bypass"),
    // Litespeed additional
    ("litespeed", "CVE-2026-48172", "CRITICAL", 9.8, "0", "6.6", "LiteSpeed Web Server path traversal RCE via .htaccess bypass"),
    ("litespeed", "CVE-2026-54420", "CRITICAL", 9.8, "0", "6.7", "LiteSpeed Web Server HTTP request smuggling leading to RCE"),
    // WordPress additional
    ("wordpress", "CVE-2026-41940", "CRITICAL", 9.8, "0", "999", "WebPros cPanel/WHM and WP2 authentication bypass via login flow"),
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
            // Banner format: "Elasticsearch 7.13.3" or "Elasticsearch 8.14.0"
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
        "solr" => {
            // Banner format: "Solr/Lucene 9.3.0" or "Solr 9.3.0"
            let pos = lower.find("solr").or_else(|| lower.find("lucene"))?;
            let after = &banner[pos..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let version: String = after[ver_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if version.is_empty() { None } else { Some(version) }
        }
        "activemq" => {
            // Banner format: "ActiveMQ 5.18.2" or "Apache ActiveMQ 5.18.2"
            let pos = lower.find("activemq")?;
            let after = &banner[pos + 8..];
            let ver_start = after.find(|c: char| c.is_ascii_digit())?;
            let version: String = after[ver_start..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if version.is_empty() { None } else { Some(version) }
        }
        "couchdb" => {
            // Banner format: "CouchDB 3.2.2"
            let pos = lower.find("couchdb")?;
            let after = &banner[pos + 7..];
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

/// Find the first dotted-numeric version that appears *after* a marker substring
/// (case-insensitive). Used by both banner and HTTP-header parsers, e.g.
/// `dotted_version_after("Server: nginx/1.20.1", "nginx/")` -> `Some("1.20.1")`.
pub(crate) fn dotted_version_after(haystack: &str, marker: &str) -> Option<String> {
    let hay_lower = haystack.to_ascii_lowercase();
    let marker_lower = marker.to_ascii_lowercase();
    let pos = hay_lower.find(&marker_lower)?;
    let rest = &haystack[pos + marker.len()..];
    let start = rest.find(|c: char| c.is_ascii_digit())?;
    let v: String = rest[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    // Reject a bare number with no dot when it is obviously not a version (single digit
    // like "nginx/1" is still valid, so only reject empty).
    if v.is_empty() { None } else { Some(v.trim_end_matches('.').to_string()) }
}

/// Extract a version from an HTTP `Server` / `X-Powered-By` header value for a known
/// technology tag (e.g. "apache" from "Apache/2.4.58 (Ubuntu)").
pub(crate) fn extract_http_version(header: &str, technology: &str) -> Option<String> {
    let marker = match technology {
        "apache" => "apache/",
        "nginx" => "nginx/",
        "iis" => "microsoft-iis/",
        "tomcat" => "tomcat/",
        "php" => "php/",
        "litespeed" => "litespeed/",
        "openssl" => "openssl/",
        _ => return None,
    };
    dotted_version_after(header, marker)
}

/// Generic fallback version parser: returns the first dotted-numeric token in a banner
/// (at least `major.minor`). Used when no technology-specific parser applies.
pub(crate) fn extract_version_generic(banner: &str) -> Option<String> {
    let bytes: Vec<char> = banner.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == '.') {
                i += 1;
            }
            let token: String = bytes[start..i].iter().collect();
            let token = token.trim_end_matches('.');
            if token.contains('.') && token.split('.').all(|p| !p.is_empty()) {
                return Some(token.to_string());
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Compare dotted-numeric version strings. Ignores non-digit suffixes on each component
/// (e.g. "9.3p1" treats the "p1" component as "3", "8.5p1" as "8.5").
pub(crate) fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
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
pub(crate) fn version_in_range(version: &str, from: Option<&str>, to: Option<&str>) -> bool {
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

/// Map Apache product names from the CISA KEV feed to specific technology tags.
/// HTTP Server products keep the bare `"apache"` tag so they match Server headers.
/// All other Apache products get scoped tags (e.g. `"apache-struts"`) so they
/// only fire when that specific product is detected.
fn map_apache_product(product: &str) -> Option<&'static str> {
    let p = product;
    if p.contains("http server") || p == "apache" {
        Some("apache")
    } else if p.contains("struts") {
        Some("apache-struts")
    } else if p.contains("tomcat") {
        Some("tomcat")
    } else if p.contains("log4j") {
        Some("apache-log4j")
    } else if p.contains("activemq") {
        Some("apache-activemq")
    } else if p.contains("ofbiz") {
        Some("apache-ofbiz")
    } else if p.contains("solr") {
        Some("apache-solr")
    } else if p.contains("airflow") {
        Some("apache-airflow")
    } else if p.contains("flink") {
        Some("apache-flink")
    } else if p.contains("spark") {
        Some("apache-spark")
    } else if p.contains("rocketmq") {
        Some("apache-rocketmq")
    } else if p.contains("superset") {
        Some("apache-superset")
    } else if p.contains("couchdb") {
        Some("apache-couchdb")
    } else if p.contains("apisix") {
        Some("apache-apisix")
    } else if p.contains("kylin") {
        Some("apache-kylin")
    } else if p.contains("shiro") {
        Some("apache-shiro")
    } else if p.contains("hugegraph") {
        Some("apache-hugegraph")
    } else {
        None
    }
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
            populate_domain_technologies(&conn)?;
            run_cve_matching(&conn)?;
            return Ok(());
        }
    };

    let vulnerabilities = json["vulnerabilities"]
        .as_array()
        .context("missing vulnerabilities array")?;

    let relevant_vendors = &["wordpress", "drupal", "joomla", "apache", "nginx", "openssl", "php", "typo3", "craft cms", "tomcat", "litespeed", "mysql", "mariadb", "proftpd", "openssh", "iis", "exchange", "magento", "prestashop", "roundcube", "mssql", "sql server", "mongodb", "postgresql", "postgres", "vnc"];

    let mut inserted = 0usize;
    for entry in vulnerabilities {
        let vendor = entry["vendorProject"].as_str().unwrap_or("").to_ascii_lowercase();
        let product = entry["product"].as_str().unwrap_or("").to_ascii_lowercase();
        let combined = format!("{vendor} {product}");

        let matched_tech = relevant_vendors.iter().find(|&&v| combined.contains(v));
        let Some(&technology_base) = matched_tech else { continue };
        let technology = match technology_base {
            "apache"   => map_apache_product(&product).unwrap_or("apache"),
            "sql server" => "mssql",
            "postgres" => "postgresql",
            t          => t,
        };

        let cve_id = entry["cveID"].as_str().unwrap_or("").to_string();
        if cve_id.is_empty() { continue; }

        let summary: Option<String> = entry["shortDescription"].as_str().map(|s: &str| s.to_string());
        let published_at: Option<String> = entry["dateAdded"].as_str().map(|s: &str| s.to_string());

        conn.execute(
             "INSERT INTO cve_catalog (cve_id, technology, severity, in_kev, summary, published_at)
              VALUES (?1, ?2, 'CRITICAL', 1, ?3, ?4)
              ON CONFLICT(cve_id) DO UPDATE SET
                 technology   = excluded.technology,
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

    match fetch_and_apply_epss(&conn).await {
        Ok(n) => eprintln!("cve: applied EPSS scores to {n} catalog entries"),
        Err(e) => eprintln!("cve: WARNING — could not apply EPSS scores ({e:#})"),
    }

    populate_domain_technologies(&conn)?;
    let matched = run_cve_matching(&conn)?;
    eprintln!("cve: {matched} domain-CVE matches recorded");

    Ok(())
}

/// Parse the FIRST EPSS CSV. Lines are `cve,epss,percentile`; a leading `#model_version`
/// comment line and the `cve,epss,percentile` header are skipped. Malformed rows are
/// ignored. Returns `(cve_id, epss, percentile)` triples.
pub(crate) fn parse_epss_csv(text: &str) -> Vec<(String, f64, f64)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("cve,") {
            continue;
        }
        let mut cols = line.split(',');
        let (Some(cve), Some(epss), Some(pct)) = (cols.next(), cols.next(), cols.next()) else {
            continue;
        };
        if !cve.starts_with("CVE-") {
            continue;
        }
        let (Ok(epss), Ok(pct)) = (epss.trim().parse::<f64>(), pct.trim().parse::<f64>()) else {
            continue;
        };
        out.push((cve.to_string(), epss, pct));
    }
    out
}

/// Fetch the current EPSS score set and write scores onto catalog entries we already know
/// about. Only existing `cve_catalog` rows are updated — we do not import the full ~250k
/// EPSS corpus. Returns the number of catalog rows updated.
async fn fetch_and_apply_epss(conn: &rusqlite::Connection) -> Result<usize> {
    use std::io::Read;

    let known: std::collections::HashSet<String> = {
        let mut stmt = conn.prepare("SELECT cve_id FROM cve_catalog")?;
        let ids: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        ids.into_iter().collect()
    };
    if known.is_empty() {
        return Ok(0);
    }

    let url = "https://epss.cyentia.com/epss_scores-current.csv.gz";
    eprintln!("cve: fetching EPSS scores from {url}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("building EPSS HTTP client")?;
    let bytes = client.get(url).send().await.context("fetching EPSS feed")?
        .bytes().await.context("reading EPSS body")?;

    let mut gz = flate2::read::GzDecoder::new(&bytes[..]);
    let mut text = String::new();
    gz.read_to_string(&mut text).context("gunzip EPSS csv")?;

    let rows = parse_epss_csv(&text);
    apply_epss_rows(conn, &rows, &known)
}

/// Write EPSS scores onto existing catalog rows. Only CVEs present in `known` are touched.
pub(crate) fn apply_epss_rows(
    conn: &rusqlite::Connection,
    rows: &[(String, f64, f64)],
    known: &std::collections::HashSet<String>,
) -> Result<usize> {
    let mut updated = 0usize;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(
            "UPDATE cve_catalog SET epss_score = ?1, epss_percentile = ?2 WHERE cve_id = ?3",
        )?;
        for (cve, epss, pct) in rows {
            if known.contains(cve) {
                updated += stmt.execute(rusqlite::params![epss, pct, cve])?;
            }
        }
    }
    tx.commit()?;
    Ok(updated)
}

pub(crate) fn seed_hardcoded_cves(conn: &rusqlite::Connection) -> Result<usize> {
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

/// Register SQLite scalar functions backing the version parsing/comparison logic, so the
/// filter steps run set-based in the engine instead of as millions of per-row round-trips
/// from Rust (which, at full scale with version-ranged CVEs, generated a multi-GB WAL).
fn register_match_functions(conn: &rusqlite::Connection) -> Result<()> {
    use rusqlite::functions::FunctionFlags;
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;

    conn.create_scalar_function("hs_ver_in_range", 3, flags, |ctx| {
        let version: Option<String> = ctx.get(0)?;
        let from: Option<String> = ctx.get(1)?;
        let to: Option<String> = ctx.get(2)?;
        let ok = match version {
            Some(v) => version_in_range(&v, from.as_deref(), to.as_deref()),
            None => true,
        };
        Ok(if ok { 1i64 } else { 0i64 })
    })?;

    conn.create_scalar_function("hs_http_version", 2, flags, |ctx| {
        let header: Option<String> = ctx.get(0)?;
        let tech: Option<String> = ctx.get(1)?;
        let (Some(header), Some(tech)) = (header, tech) else { return Ok(None) };
        Ok(extract_http_version(&header, &tech).or_else(|| extract_version_generic(&header)))
    })?;

    conn.create_scalar_function("hs_banner_version", 2, flags, |ctx| {
        let banner: Option<String> = ctx.get(0)?;
        let tech: Option<String> = ctx.get(1)?;
        let (Some(banner), Some(tech)) = (banner, tech) else { return Ok(None) };
        Ok(extract_version(&banner, &tech))
    })?;
    Ok(())
}


/// Populate `domain_technologies` from all available scan data sources.
/// Replaces the old per-technology LIKE-scan pattern with a single scan that
/// stores one row per (domain, technology, version). Safe to re-run:
/// uses INSERT OR REPLACE to update the version/last_seen on re-detection.
pub(crate) fn populate_domain_technologies(conn: &rusqlite::Connection) -> Result<usize> {
    conn.execute("DELETE FROM domain_technologies", [])?;

    // 1. HTTP server/powered_by headers (domains table)
    conn.execute_batch(
        "INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT domain, 'apache',
                CASE WHEN lower(coalesce(server, '')) LIKE 'apache/%'
                     THEN substr(lower(server), instr(lower(server), 'apache/') + 7) END,
                'http_header'
         FROM domains WHERE lower(coalesce(server, '')) LIKE '%apache%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT domain, 'nginx',
                CASE WHEN lower(coalesce(server, '')) LIKE 'nginx/%'
                     THEN substr(lower(server), instr(lower(server), 'nginx/') + 6) END,
                'http_header'
         FROM domains WHERE lower(coalesce(server, '')) LIKE '%nginx%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT domain, 'tomcat', NULL, 'http_header'
         FROM domains WHERE lower(coalesce(server, '')) LIKE '%coyote%' OR lower(coalesce(server, '')) LIKE '%tomcat%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT domain, 'iis',
                CASE WHEN lower(coalesce(server, '')) LIKE 'microsoft-iis/%'
                     THEN substr(lower(server), instr(lower(server), 'microsoft-iis/') + 14) END,
                'http_header'
         FROM domains WHERE lower(coalesce(server, '')) LIKE '%microsoft-iis%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT domain, 'litespeed',
                CASE WHEN lower(coalesce(server, '')) LIKE 'litespeed/%'
                     THEN substr(lower(server), instr(lower(server), 'litespeed/') + 10) END,
                'http_header'
         FROM domains WHERE lower(coalesce(server, '')) LIKE '%litespeed%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT domain, 'php',
                CASE WHEN lower(coalesce(powered_by, '')) LIKE 'php/%'
                     THEN substr(lower(powered_by), instr(lower(powered_by), 'php/') + 4)
                     WHEN lower(coalesce(server, '')) LIKE 'apache/%' THEN NULL END,
                'http_header'
         FROM domains WHERE lower(coalesce(powered_by, '')) LIKE '%php%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT domain, 'openssl',
                CASE WHEN lower(coalesce(server, '')) LIKE 'apache/%'
                     THEN NULL
                     WHEN lower(coalesce(server, '')) LIKE 'nginx/%'
                     THEN NULL END,
                'http_header'
         FROM domains WHERE lower(coalesce(server, '')) LIKE 'apache%' OR lower(coalesce(server, '')) LIKE 'nginx%';")?;

    // 2. CMS detections from domains.cms column
    let cms_techs = ["wordpress", "drupal", "joomla", "typo3", "exchange",
                      "magento", "prestashop", "roundcube", "craft cms", "laravel"];
    for tech in &cms_techs {
        let sql = format!(
            "INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
             SELECT domain, '{tech}', NULL, 'cms_tag'
             FROM domains WHERE lower(coalesce(cms, '')) = '{tech}'",
            tech = tech
        );
        conn.execute_batch(&sql)?;
    }

    // 3. Port banners
    conn.execute_batch(
        "INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT p.domain, 'mysql', NULL, 'port_banner'
         FROM ports_info p WHERE lower(coalesce(p.banner, '')) LIKE '%mysql%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT p.domain, 'proftpd',
                CASE WHEN lower(coalesce(p.banner, '')) LIKE 'proftpd %'
                     THEN substr(lower(p.banner), 9) END,
                'port_banner'
         FROM ports_info p WHERE lower(coalesce(p.banner, '')) LIKE '%proftpd%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT p.domain, 'vsftpd',
                CASE WHEN lower(coalesce(p.banner, '')) LIKE '%vsftpd%'
                     THEN substr(lower(p.banner), instr(lower(p.banner), 'vsftpd') + 7) END,
                'port_banner'
         FROM ports_info p WHERE lower(coalesce(p.banner, '')) LIKE '%vsftpd%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT p.domain, 'openssh',
                CASE WHEN lower(coalesce(p.banner, '')) LIKE 'ssh-%'
                     THEN substr(lower(p.banner), 5) END,
                'port_banner'
         FROM ports_info p WHERE lower(coalesce(p.banner, '')) LIKE '%ssh%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT p.domain, 'redis', NULL, 'port_banner'
         FROM ports_info p WHERE lower(coalesce(p.banner, '')) LIKE '%redis%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT p.domain, 'elasticsearch', NULL, 'port_banner'
         FROM ports_info p WHERE p.port = 9200 AND (lower(coalesce(p.banner, '')) LIKE '%elasticsearch%' OR lower(coalesce(p.banner, '')) LIKE '%lucene%');

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT p.domain, 'memcached', NULL, 'port_banner'
         FROM ports_info p WHERE p.port = 11211 AND (lower(coalesce(p.banner, '')) LIKE 'version %' OR lower(coalesce(p.banner, '')) LIKE '%memcached%');

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT p.domain, 'mssql', NULL, 'port_banner'
         FROM ports_info p WHERE lower(coalesce(p.banner, '')) LIKE '%mssql%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT p.domain, 'docker', NULL, 'port_detection'
         FROM ports_info p WHERE p.port = 2375;
    ")?;

    // 4. Known port-based detections (no banner needed)
    conn.execute_batch(
        "INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT p.domain, 'rdp', NULL, 'port_detection'
         FROM ports_info p WHERE p.port = 3389;

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT p.domain, 'mongodb', NULL, 'port_detection'
         FROM ports_info p WHERE p.port = 27017;

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT p.domain, 'postgresql', NULL, 'port_detection'
         FROM ports_info p WHERE p.port = 5432;

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT p.domain, 'vnc', NULL, 'port_detection'
         FROM ports_info p WHERE p.port = 5900;

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT p.domain, 'tomcat', NULL, 'port_detection'
         FROM ports_info p WHERE p.port = 8009 AND lower(coalesce(p.banner, '')) LIKE '%ajp%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT p.domain, 'apache-solr', NULL, 'port_detection'
         FROM ports_info p WHERE p.port = 8983 AND (lower(coalesce(p.banner, '')) LIKE '%solr%' OR lower(coalesce(p.banner, '')) LIKE '%lucene%');

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT p.domain, 'apache-activemq', NULL, 'port_detection'
         FROM ports_info p WHERE p.port = 8161 AND lower(coalesce(p.banner, '')) LIKE '%activemq%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT p.domain, 'apache-couchdb', NULL, 'port_detection'
         FROM ports_info p WHERE p.port = 5984 AND lower(coalesce(p.banner, '')) LIKE '%couchdb%';"
    )?;

    // 5. Java frameworks detection (from server headers indicating Java runtime)
    conn.execute_batch(
        "INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT d.domain, 'apache-struts', NULL, 'java_runtime'
         FROM domains d
         WHERE lower(coalesce(d.server, '')) LIKE '%coyote%'
            OR lower(coalesce(d.server, '')) LIKE '%tomcat%'
            OR lower(coalesce(d.server, '')) LIKE '%jboss%'
            OR lower(coalesce(d.server, '')) LIKE '%wildfly%'
            OR lower(coalesce(d.server, '')) LIKE '%java%'
            OR lower(coalesce(d.powered_by, '')) LIKE '%java%'
            OR lower(coalesce(d.powered_by, '')) LIKE '%servlet%'
            OR lower(coalesce(d.powered_by, '')) LIKE '%jsp%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT d.domain, 'apache-log4j', NULL, 'java_runtime'
         FROM domains d
         WHERE lower(coalesce(d.server, '')) LIKE '%coyote%'
            OR lower(coalesce(d.server, '')) LIKE '%tomcat%'
            OR lower(coalesce(d.powered_by, '')) LIKE '%java%';

         INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT DISTINCT d.domain, 'apache-shiro', NULL, 'java_runtime'
         FROM domains d
         WHERE lower(coalesce(d.server, '')) LIKE '%coyote%'
            OR lower(coalesce(d.server, '')) LIKE '%tomcat%'
            OR lower(coalesce(d.powered_by, '')) LIKE '%java%';"
    )?;

    // 6. Software detections
    conn.execute_batch(
        "INSERT OR REPLACE INTO domain_technologies (domain, technology, version, source)
         SELECT sd.domain, sd.name, sd.version, 'software_detection'
         FROM software_detections sd;"
    )?;

    // 7. Merge version from port banners into existing rows (fill in missing versions)
    conn.execute_batch(
        "UPDATE domain_technologies SET version = (
            SELECT CASE WHEN lower(coalesce(p.banner, '')) LIKE '%' || domain_technologies.technology || '/%'
                        THEN substr(lower(p.banner),
                             instr(lower(p.banner), domain_technologies.technology || '/')
                             + length(domain_technologies.technology) + 1)
                        ELSE NULL END
            FROM ports_info p
            WHERE p.domain = domain_technologies.domain
              AND lower(coalesce(p.banner, '')) LIKE '%' || domain_technologies.technology || '/%'
            LIMIT 1
        ) WHERE version IS NULL AND source = 'port_banner';"
    )?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM domain_technologies", [], |r| r.get(0))?;
    Ok(count as usize)
}

pub(crate) async fn cmd_populate_technologies(db: PathBuf) -> Result<()> {
    let conn = crate::shared::open_db(&db)
        .with_context(|| format!("open db {:?}", db))?;
    crate::schema::ensure_schema(&conn)?;
    let n = populate_domain_technologies(&conn)?;
    eprintln!("domain_technologies: populated {n} rows");
    let m = run_cve_matching(&conn)?;
    eprintln!("cve_matches: rebuilt with {m} rows");
    Ok(())
}

/// Rebuild `cve_matches` from `domain_technologies` + `cve_catalog`, then apply version
/// filtering. This replaces 20+ per-technology LIKE scans with a single JOIN — the old
/// approach required a separate INSERT per technology and scanned 8M domain rows 20+ times.
/// Now `populate_domain_technologies` scans the data sources once, then this function
/// uses the compact `domain_technologies` table to derive CVE matches in a single pass.
pub(crate) fn run_cve_matching(conn: &rusqlite::Connection) -> Result<usize> {
    register_match_functions(conn)?;

    conn.execute("DELETE FROM cve_matches", [])?;

    // Per-technology INSERTs: bake in the version-filter logic so we don't insert rows that
    // apply_version_filter would immediately delete.  For VERSIONED_TECHS (apache, nginx, php,
    // openssh, etc.) unversioned non-KEV CVEs are skipped — they were generating ~100M+ rows
    // per technology that got immediately deleted, causing the INSERT to timeout.
    let mut total = 0usize;
    let mut stmt = conn.prepare("SELECT DISTINCT technology FROM domain_technologies ORDER BY technology")?;
    let techs: Vec<String> = stmt.query_map([], |r| r.get(0))?.filter_map(|r| r.ok()).collect();
    drop(stmt);
    let insert_sql = format!(
        "INSERT OR IGNORE INTO cve_matches (domain, technology, version, cve_id, severity, cvss_score, in_kev, published_at)
         SELECT dt.domain, dt.technology, dt.version, cc.cve_id, cc.severity, cc.cvss_score, cc.in_kev, cc.published_at
         FROM domain_technologies dt
         JOIN cve_catalog cc ON cc.technology = dt.technology
         WHERE dt.technology = ?1
           AND (
             (cc.affected_from IS NULL
              AND (dt.technology NOT IN {vt} OR cc.in_kev = 1))
             OR (cc.affected_from IS NOT NULL
                 AND dt.technology NOT IN {vt})
             OR (dt.version IS NOT NULL
                 AND cc.affected_from IS NOT NULL
                 AND hs_ver_in_range(dt.version, cc.affected_from, cc.affected_to) = 1)
           )",
        vt = VERSIONED_TECHS
    );
    let mut insert_stmt = conn.prepare(&insert_sql)?;
    let mut checkpoint_n = 0usize;
    for tech in &techs {
        let rows = insert_stmt.execute([tech])?;
        total += rows;
        eprintln!("  {}: +{rows} rows", tech);
        checkpoint_n += 1;
        if checkpoint_n % 5 == 0 {
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)");
        }
    }
    drop(insert_stmt);
    eprintln!("cve_matches: inserted {total} rows across {} technologies", techs.len());

    // Remove client‑only CVEs
    conn.execute_batch("DELETE FROM cve_matches WHERE cve_id IN ('CVE-2016-1908','CVE-2023-28531')")?;
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");

    apply_port_versions(conn)?;
    apply_http_versions(conn)?;
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
    apply_version_filter(conn)?;
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");

    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM cve_matches",
        [],
        |r| r.get(0),
    )?;

    Ok(count as usize)
}

/// For each port banner that carries a version string, update `cve_matches.version`
/// so the version filter has something to compare against.
/// Set the version on port-banner matches from `ports_info`, using the `hs_banner_version`
/// SQL function. One statement — no per-row round-trips.
fn apply_port_versions(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "UPDATE cve_matches
         SET version = (
           SELECT hs_banner_version(p.banner, cve_matches.technology)
           FROM ports_info p
           WHERE p.domain = cve_matches.domain
             AND p.banner IS NOT NULL
             AND lower(p.banner) LIKE '%' || cve_matches.technology || '%'
           ORDER BY p.port
           LIMIT 1
         )
         WHERE cve_matches.version IS NULL
           AND cve_matches.technology IN
               ('mysql','proftpd','vsftpd','openssh','redis','elasticsearch','memcached','mssql',
                'solr','activemq','couchdb');",
    )?;
    Ok(())
}

/// Set the version on HTTP-detected matches from the `Server` / `X-Powered-By` headers, so
/// the version filter applies to web-server/PHP CVEs too. One statement via `hs_http_version`.
fn apply_http_versions(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "UPDATE cve_matches
         SET version = (
           SELECT hs_http_version(
                    CASE WHEN cve_matches.technology = 'php'
                         THEN COALESCE(d.powered_by, d.server, '')
                         ELSE COALESCE(d.server, '') END,
                    cve_matches.technology)
           FROM domains d WHERE d.domain = cve_matches.domain
         )
         WHERE cve_matches.version IS NULL
           AND cve_matches.technology IN ('apache','nginx','iis','tomcat','php','litespeed','openssl');",
    )?;
    Ok(())
}

/// The `cve_matches.technology` values that advertise a concrete version in a banner or HTTP
/// header. For these, a match is only asserted when a live version was read *and* falls in a
/// CVE's affected range. Everything else (CMS, port-only, and presence/behaviour services such
/// as wordpress, redis, mongodb, rdp, vnc, ...) matches on presence and is always kept.
const VERSIONED_TECHS: &str =
    "('apache','nginx','iis','tomcat','php','litespeed','openssl',\
      'mysql','openssh','proftpd','vsftpd','mssql',\
      'elasticsearch','memcached','solr','activemq','couchdb')";

/// SQL predicate (over aliases `cm` = cve_matches, `cc` = cve_catalog) that is true for a row
/// the version filter should **drop**. Two independent reasons:
///
///   1. **Out-of-range known version, any technology.** If we read a concrete version and the
///      CVE has a real range that excludes it, it is not vulnerable — e.g. a patched jQuery/
///      lodash from `software_detections`.
///   2. **Unconfirmed match on a version-advertising product** (`technology IN VERSIONED_TECHS`).
///      Those products only count when a live version was read *and* is in range; unknown-version
///      hosts and range-less KEV entries on them are dropped. This is what prevents the ~300M-row
///      blow-up. Presence-based services (CMS, ports, RDP/VNC/Mongo, ...) are not in the set and
///      match on presence.
///
/// Requires `hs_ver_in_range` to be registered and `cc` to come from a LEFT JOIN so range-less /
/// uncatalogued rows are covered.
fn version_filter_drop_predicate() -> String {
    format!(
        "(cm.version IS NOT NULL
          AND cc.affected_to IS NOT NULL AND cc.affected_to <> '999'
          AND hs_ver_in_range(cm.version, cc.affected_from, cc.affected_to) = 0)
         OR (cm.technology IN {V}
             AND (cc.in_kev IS NULL OR cc.in_kev = 0)
             AND NOT (
               cm.version IS NOT NULL
               AND cc.affected_to IS NOT NULL AND cc.affected_to <> '999'
               AND hs_ver_in_range(cm.version, cc.affected_from, cc.affected_to) = 1
             ))",
        V = VERSIONED_TECHS
    )
}

/// Preview what the version filter ([`apply_version_filter`]) would remove from an existing
/// `cve_matches` table, **without mutating anything**. Prints the keep/drop split. Read-only:
/// no writes, no WAL growth. Use this before `refilter-cves` to see the resulting size up front.
pub(crate) fn cmd_refilter_cves_preview(db: PathBuf) -> Result<()> {
    let conn = crate::shared::open_db(&db)
        .with_context(|| format!("open db {:?}", db))?;
    register_match_functions(&conn)?;
    let drop = version_filter_drop_predicate();

    let before: i64 = conn.query_row("SELECT COUNT(*) FROM cve_matches", [], |r| r.get(0))?;
    let dropped: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM cve_matches cm
             LEFT JOIN cve_catalog cc ON cc.cve_id = cm.cve_id
             WHERE {drop}"
        ),
        [],
        |r| r.get(0),
    )?;

    eprintln!("cve: refilter preview (no changes written)");
    eprintln!("  total rows : {before}");
    eprintln!("  would drop : {dropped}");
    eprintln!("  would keep : {}", before - dropped);
    Ok(())
}

/// Shrink an existing `cve_matches` table by applying the version filter
/// ([`apply_version_filter`]) to data generated before that filter existed (the ~300M-row
/// blow-up). Copies only the *kept* rows into a fresh table and swaps it in, so the WAL only
/// holds the surviving set rather than the whole rewrite of a giant in-place `DELETE`. No
/// network, no re-matching; run `VACUUM` afterwards to return freed pages to the filesystem.
pub(crate) fn cmd_refilter_cves(db: PathBuf) -> Result<()> {
    let conn = crate::shared::open_db(&db)
        .with_context(|| format!("open db {:?}", db))?;
    register_match_functions(&conn)?;
    let drop = version_filter_drop_predicate();

    let before: i64 = conn.query_row("SELECT COUNT(*) FROM cve_matches", [], |r| r.get(0))?;
    eprintln!("cve: refilter starting from {before} rows");

    conn.execute_batch("DROP TABLE IF EXISTS cve_matches_refiltered;")?;
    conn.execute_batch(
        "CREATE TABLE cve_matches_refiltered (
            domain        TEXT NOT NULL,
            technology    TEXT NOT NULL,
            version       TEXT,
            cve_id        TEXT NOT NULL,
            severity      TEXT,
            cvss_score    REAL,
            in_kev        INTEGER,
            published_at  TEXT,
            matched_at    TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (domain, cve_id)
        );",
    )?;

    // Keep every row the filter would not drop. LEFT JOIN so range-less / uncatalogued rows are
    // evaluated by the same predicate the DELETE uses.
    conn.execute_batch(&format!(
        "INSERT INTO cve_matches_refiltered
            (domain, technology, version, cve_id, severity, cvss_score, in_kev, published_at, matched_at)
         SELECT cm.domain, cm.technology, cm.version, cm.cve_id, cm.severity, cm.cvss_score,
                cm.in_kev, cm.published_at, cm.matched_at
         FROM cve_matches cm
         LEFT JOIN cve_catalog cc ON cc.cve_id = cm.cve_id
         WHERE NOT ({drop});"
    ))?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

    // `legacy_alter_table=ON` stops the RENAME from validating dependent objects mid-swap: the
    // `risk_score` view references `cve_matches`, which is momentarily absent between the DROP
    // and the RENAME, and the modern ALTER path would otherwise abort on it.
    conn.execute_batch(
        "PRAGMA legacy_alter_table=ON;
         DROP TABLE cve_matches;
         ALTER TABLE cve_matches_refiltered RENAME TO cve_matches;
         PRAGMA legacy_alter_table=OFF;",
    )?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

    let after: i64 = conn.query_row("SELECT COUNT(*) FROM cve_matches", [], |r| r.get(0))?;
    eprintln!(
        "cve: refilter kept {after} rows (removed {}); run `VACUUM` to reclaim disk space",
        before - after
    );
    Ok(())
}

/// Version filtering. A match against a version-advertising product (web servers, PHP, SSH, DB
/// banners — see [`VERSIONED_TECHS`]) is asserted only when a live version was read *and* falls
/// inside a CVE's affected range. Out-of-range versions, unknown versions, and range-less KEV
/// entries on those products are all dropped — otherwise every host matched every KEV CVE for
/// its product regardless of version, which blew the table up to ~300M rows. CMS, port-only,
/// and presence/behaviour services (wordpress, redis, mongodb, rdp, vnc, ...) are not in the
/// version-advertising set and match on presence. One set-based DELETE via `hs_ver_in_range`.
fn apply_version_filter(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "DELETE FROM cve_matches
         WHERE rowid IN (
           SELECT cm.rowid FROM cve_matches cm
           LEFT JOIN cve_catalog cc ON cc.cve_id = cm.cve_id
           WHERE {}
         );",
        version_filter_drop_predicate()
    ))?;
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
    fn run_cve_matching_matches_and_filters_detected_software() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('shop.ch');
             -- vulnerable jQuery (3.4.1 is within CVE-2020-11022 range 1.2..3.5.0)
             INSERT INTO software_detections (domain, kind, name, version) VALUES ('shop.ch','js_lib','jquery','3.4.1');
             -- patched lodash (4.17.21 is above CVE-2019-10744 upper bound 4.17.12)
             INSERT INTO software_detections (domain, kind, name, version) VALUES ('shop.ch','js_lib','lodash','4.17.21');
             -- WP plugin, presence based (no version)
             INSERT INTO software_detections (domain, kind, name, version) VALUES ('shop.ch','wp_plugin','contact-form-7',NULL);",
        ).unwrap();
        run_cve_matching(&conn).unwrap();

        let jq: i64 = conn.query_row("SELECT COUNT(*) FROM cve_matches WHERE domain='shop.ch' AND cve_id='CVE-2020-11022'", [], |r| r.get(0)).unwrap();
        assert_eq!(jq, 1, "vulnerable jQuery 3.4.1 must match");
        let lodash: i64 = conn.query_row("SELECT COUNT(*) FROM cve_matches WHERE domain='shop.ch' AND cve_id='CVE-2019-10744'", [], |r| r.get(0)).unwrap();
        assert_eq!(lodash, 0, "patched lodash 4.17.21 must be filtered out");
        let cf7: i64 = conn.query_row("SELECT COUNT(*) FROM cve_matches WHERE domain='shop.ch' AND cve_id='CVE-2020-35489'", [], |r| r.get(0)).unwrap();
        assert_eq!(cf7, 1, "contact-form-7 plugin must match on presence");
    }

    #[test]
    fn run_cve_matching_matches_new_service_ports() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain) VALUES ('svc.ch');
             INSERT INTO ports_info (domain, port, service) VALUES ('svc.ch', 27017, 'mongodb');
             INSERT INTO ports_info (domain, port, service) VALUES ('svc.ch', 5432, 'postgresql');
             INSERT INTO ports_info (domain, port, service) VALUES ('svc.ch', 5900, 'vnc');",
        ).unwrap();
        run_cve_matching(&conn).unwrap();
        for tech in ["mongodb", "postgresql", "vnc"] {
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM cve_matches WHERE domain='svc.ch' AND technology=?1", [tech], |r| r.get(0))
                .unwrap();
            assert!(n > 0, "expected {tech} CVE matches from port presence");
        }
    }

    // ---- EPSS ----

    #[test]
    fn parse_epss_csv_skips_comments_and_header() {
        let csv = "#model_version:v2024.01.01,score_date:2024-07-01T00:00:00Z\n\
                   cve,epss,percentile\n\
                   CVE-2021-44228,0.97544,0.99995\n\
                   CVE-2018-7600,0.94210,0.99900\n\
                   garbage,line,here\n\
                   CVE-2020-0000,notanumber,0.5\n";
        let rows = parse_epss_csv(csv);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "CVE-2021-44228");
        assert!((rows[0].1 - 0.97544).abs() < 1e-9);
        assert!((rows[1].2 - 0.99900).abs() < 1e-9);
    }

    #[test]
    fn apply_epss_rows_only_updates_known_cves() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        let known: std::collections::HashSet<String> = {
            let mut stmt = conn.prepare("SELECT cve_id FROM cve_catalog").unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0)).unwrap().filter_map(|r| r.ok()).collect()
        };
        let rows = vec![
            ("CVE-2018-7600".to_string(), 0.942, 0.999),   // known (Drupalgeddon2)
            ("CVE-9999-0001".to_string(), 0.5, 0.5),        // unknown → ignored
        ];
        let n = apply_epss_rows(&conn, &rows, &known).unwrap();
        assert_eq!(n, 1);
        let score: f64 = conn
            .query_row("SELECT epss_score FROM cve_catalog WHERE cve_id='CVE-2018-7600'", [], |r| r.get(0))
            .unwrap();
        assert!((score - 0.942).abs() < 1e-9);
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

    // ---- generic / HTTP version parsing ----

    #[test]
    fn generic_version_parser_finds_dotted_token() {
        assert_eq!(extract_version_generic("Server v1.2.3 ready"), Some("1.2.3".into()));
        assert_eq!(extract_version_generic("build 2019 patch"), None); // no dot → not a version
        assert_eq!(extract_version_generic("nothing here"), None);
    }

    #[test]
    fn http_version_extractor_handles_common_headers() {
        assert_eq!(extract_http_version("Apache/2.4.58 (Ubuntu)", "apache"), Some("2.4.58".into()));
        assert_eq!(extract_http_version("nginx/1.20.1", "nginx"), Some("1.20.1".into()));
        assert_eq!(extract_http_version("Microsoft-IIS/10.0", "iis"), Some("10.0".into()));
        assert_eq!(extract_http_version("PHP/8.1.2", "php"), Some("8.1.2".into()));
        assert_eq!(extract_http_version("nginx/1.20.1", "apache"), None);
    }

    #[test]
    fn dotted_version_after_marker() {
        assert_eq!(dotted_version_after("redis_version:6.2.6\r\n", "redis_version:"), Some("6.2.6".into()));
        assert_eq!(dotted_version_after("\"number\" : \"7.13.3\"", "\"number\""), Some("7.13.3".into()));
        assert_eq!(dotted_version_after("no version", "marker"), None);
    }

    #[test]
    fn http_version_filter_removes_out_of_range_apache() {
        // CVE-2021-41773 affects only 2.4.49; a live Apache/2.4.58 must not match.
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain, server) VALUES ('web.ch', 'Apache/2.4.58 (Ubuntu)');",
        ).unwrap();
        run_cve_matching(&conn).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve_matches WHERE domain='web.ch' AND cve_id='CVE-2021-41773'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "Apache 2.4.58 must not match a 2.4.49-only CVE");
    }

    #[test]
    fn http_version_filter_keeps_in_range_apache() {
        let conn = in_memory_db();
        seed_hardcoded_cves(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO domains (domain, server) VALUES ('web.ch', 'Apache/2.4.49 (Unix)');",
        ).unwrap();
        run_cve_matching(&conn).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM cve_matches WHERE domain='web.ch' AND cve_id='CVE-2021-41773'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "Apache 2.4.49 must match CVE-2021-41773");
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
