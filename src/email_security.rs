use anyhow::Result;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};

// ---- Data structures ----

pub(crate) struct SpfAnalysis {
    pub present: bool,
    pub policy: Option<String>,
    pub too_permissive: bool,
    pub dns_lookups: i32,
    pub over_limit: bool,
}

pub(crate) struct DmarcAnalysis {
    pub present: bool,
    pub policy: Option<String>,
    pub subdomain_policy: Option<String>,
    pub has_reporting: bool,
    pub pct: Option<i32>,
}

#[derive(Debug, Clone)]
pub(crate) struct EmailSecurityRow {
    pub domain: String,
    pub spf_present: bool,
    pub spf_policy: Option<String>,
    pub spf_too_permissive: bool,
    pub spf_dns_lookups: i32,
    pub spf_over_limit: bool,
    pub dmarc_present: bool,
    pub dmarc_policy: Option<String>,
    pub dmarc_subdomain_policy: Option<String>,
    pub dmarc_has_reporting: bool,
    pub dmarc_pct: Option<i32>,
    pub dkim_default: bool,
    pub dkim_google: bool,
    pub dkim_found: bool,
}

// ---- SPF parsing ----

pub(crate) fn parse_spf(txt: &str) -> SpfAnalysis {
    if txt.is_empty() {
        return SpfAnalysis {
            present: false,
            policy: None,
            too_permissive: false,
            dns_lookups: 0,
            over_limit: false,
        };
    }

    // Find the `all` mechanism qualifier
    let lower = txt.to_ascii_lowercase();
    let mut policy: Option<String> = None;

    // Find the last token matching [+~?-]?all
    for token in lower.split_whitespace() {
        let t = token.trim_start_matches(|c| c == '+' || c == '-' || c == '~' || c == '?');
        if t == "all" {
            policy = Some(token.to_string());
        }
    }

    let qualifier = policy.as_deref().and_then(|p| {
        let first = p.chars().next()?;
        if "+-~?".contains(first) {
            Some(first)
        } else {
            Some('+') // default is + when no prefix
        }
    });

    let too_permissive = matches!(qualifier, Some('+') | Some('?'));

    // Count DNS lookups
    let mut dns_lookups: i32 = 0;
    for token in lower.split_whitespace() {
        if token.starts_with("include:") {
            dns_lookups += 1;
        } else if token.starts_with("redirect=") {
            dns_lookups += 1;
        } else if token.starts_with("exists:") {
            dns_lookups += 1;
        } else if token == "a" || token.starts_with("a:") || token.starts_with("a/") {
            dns_lookups += 1;
        } else if token == "mx" || token.starts_with("mx:") || token.starts_with("mx/") {
            dns_lookups += 1;
        } else if token == "+a" || token.starts_with("+a:") || token.starts_with("+a/")
            || token == "-a" || token.starts_with("-a:") || token.starts_with("-a/")
            || token == "~a" || token.starts_with("~a:") || token.starts_with("~a/")
            || token == "?a" || token.starts_with("?a:") || token.starts_with("?a/")
        {
            dns_lookups += 1;
        } else if token == "+mx" || token.starts_with("+mx:") || token.starts_with("+mx/")
            || token == "-mx" || token.starts_with("-mx:") || token.starts_with("-mx/")
            || token == "~mx" || token.starts_with("~mx:") || token.starts_with("~mx/")
            || token == "?mx" || token.starts_with("?mx:") || token.starts_with("?mx/")
        {
            dns_lookups += 1;
        }
    }

    let over_limit = dns_lookups > 10;

    SpfAnalysis {
        present: true,
        policy,
        too_permissive,
        dns_lookups,
        over_limit,
    }
}

// ---- DMARC parsing ----

pub(crate) fn parse_dmarc(txt: &str) -> DmarcAnalysis {
    let present = txt.to_ascii_lowercase().starts_with("v=dmarc1");

    if !present {
        return DmarcAnalysis {
            present: false,
            policy: None,
            subdomain_policy: None,
            has_reporting: false,
            pct: None,
        };
    }

    let mut policy: Option<String> = None;
    let mut subdomain_policy: Option<String> = None;
    let mut has_reporting = false;
    let mut pct: Option<i32> = None;

    for part in txt.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("p=").or_else(|| part.strip_prefix("P=")) {
            policy = Some(val.trim().to_ascii_lowercase());
        } else if let Some(val) = part.strip_prefix("sp=").or_else(|| part.strip_prefix("SP=")) {
            subdomain_policy = Some(val.trim().to_ascii_lowercase());
        } else if part.to_ascii_lowercase().starts_with("rua=") {
            has_reporting = true;
        } else if let Some(val) = part.strip_prefix("pct=").or_else(|| part.strip_prefix("PCT=")) {
            if let Ok(n) = val.trim().parse::<i32>() {
                pct = Some(n);
            }
        }
    }

    DmarcAnalysis {
        present,
        policy,
        subdomain_policy,
        has_reporting,
        pct,
    }
}

// ---- DKIM probing ----

pub(crate) async fn probe_dkim(domain: &str, resolver: &TokioResolver) -> (bool, bool) {
    let default_host = format!("default._domainkey.{domain}");
    let google_host = format!("google._domainkey.{domain}");

    let (default_res, google_res) = tokio::join!(
        resolver.lookup(&default_host, RecordType::TXT),
        resolver.lookup(&google_host, RecordType::TXT),
    );

    let dkim_default = default_res.is_ok_and(|lookup| {
        lookup.iter().any(|record| {
            if let RData::TXT(txt) = record {
                let joined = txt.txt_data().iter()
                    .map(|c| String::from_utf8_lossy(c).to_string())
                    .collect::<String>();
                joined.contains("v=DKIM1")
            } else {
                false
            }
        })
    });

    let dkim_google = google_res.is_ok_and(|lookup| {
        lookup.iter().any(|record| {
            if let RData::TXT(txt) = record {
                let joined = txt.txt_data().iter()
                    .map(|c| String::from_utf8_lossy(c).to_string())
                    .collect::<String>();
                joined.contains("v=DKIM1")
            } else {
                false
            }
        })
    });

    (dkim_default, dkim_google)
}

// ---- Analyze email security ----

pub(crate) async fn analyze_email_security(
    domain: &str,
    txt_spf: Option<&str>,
    txt_dmarc: Option<&str>,
    resolver: &TokioResolver,
) -> EmailSecurityRow {
    let spf = parse_spf(txt_spf.unwrap_or(""));
    let dmarc = parse_dmarc(txt_dmarc.unwrap_or(""));
    let (dkim_default, dkim_google) = probe_dkim(domain, resolver).await;
    let dkim_found = dkim_default || dkim_google;

    EmailSecurityRow {
        domain: domain.to_string(),
        spf_present: spf.present,
        spf_policy: spf.policy,
        spf_too_permissive: spf.too_permissive,
        spf_dns_lookups: spf.dns_lookups,
        spf_over_limit: spf.over_limit,
        dmarc_present: dmarc.present,
        dmarc_policy: dmarc.policy,
        dmarc_subdomain_policy: dmarc.subdomain_policy,
        dmarc_has_reporting: dmarc.has_reporting,
        dmarc_pct: dmarc.pct,
        dkim_default,
        dkim_google,
        dkim_found,
    }
}

// ---- DB flush ----

pub(crate) fn flush_email_security_batch(
    conn: &duckdb::Connection,
    batch: &mut Vec<EmailSecurityRow>,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO email_security (
                domain, spf_present, spf_policy, spf_too_permissive, spf_dns_lookups,
                spf_over_limit, dmarc_present, dmarc_policy, dmarc_subdomain_policy,
                dmarc_has_reporting, dmarc_pct, dkim_default, dkim_google, dkim_found,
                scanned_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NOW())
             ON CONFLICT(domain) DO UPDATE SET
                spf_present            = excluded.spf_present,
                spf_policy             = excluded.spf_policy,
                spf_too_permissive     = excluded.spf_too_permissive,
                spf_dns_lookups        = excluded.spf_dns_lookups,
                spf_over_limit         = excluded.spf_over_limit,
                dmarc_present          = excluded.dmarc_present,
                dmarc_policy           = excluded.dmarc_policy,
                dmarc_subdomain_policy = excluded.dmarc_subdomain_policy,
                dmarc_has_reporting    = excluded.dmarc_has_reporting,
                dmarc_pct              = excluded.dmarc_pct,
                dkim_default           = excluded.dkim_default,
                dkim_google            = excluded.dkim_google,
                dkim_found             = excluded.dkim_found,
                scanned_at             = excluded.scanned_at",
        )?;
        for row in batch.iter() {
            stmt.execute(duckdb::params![
                row.domain.as_str(),
                row.spf_present,
                row.spf_policy.as_deref(),
                row.spf_too_permissive,
                row.spf_dns_lookups,
                row.spf_over_limit,
                row.dmarc_present,
                row.dmarc_policy.as_deref(),
                row.dmarc_subdomain_policy.as_deref(),
                row.dmarc_has_reporting,
                row.dmarc_pct,
                row.dkim_default,
                row.dkim_google,
                row.dkim_found,
            ])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    batch.clear();
    Ok(())
}
