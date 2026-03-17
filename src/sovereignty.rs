use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
use hickory_resolver::TokioResolver;

use crate::shared::{build_default_resolver, sql_string, sql_string_opt};
use crate::SovereigntyArgs;

const EU_COUNTRIES: &[&str] = &[
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
    "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT",
    "NL", "PL", "PT", "RO", "SE", "SI", "SK",
];

fn country_to_jurisdiction(code: &str) -> &'static str {
    match code {
        "CH" => "CH",
        "US" => "US",
        c if EU_COUNTRIES.contains(&c) => "EU",
        _ => "OTHER",
    }
}

fn normalize_ns_to_operator(ns: &str) -> String {
    let h = ns.trim_end_matches('.').to_lowercase();

    const RULES: &[(&str, &str)] = &[
        ("ns.infomaniak.ch",      "Infomaniak"),
        ("cloudflare.com",        "Cloudflare"),
        ("infomaniak.ch",         "Infomaniak"),
        ("hostpoint.ch",          "Hostpoint"),
        ("hetzner.com",           "Hetzner"),
        ("hetzner.de",            "Hetzner"),
        ("registrar-servers.com", "Namecheap"),
        ("ui-dns.biz",            "IONOS"),
        ("ui-dns.com",            "IONOS"),
        ("ui-dns.de",             "IONOS"),
        ("ui-dns.org",            "IONOS"),
        ("domaincontrol.com",     "GoDaddy"),
        ("azure-dns.com",         "Azure DNS"),
        ("azure-dns.net",         "Azure DNS"),
        ("azure-dns.org",         "Azure DNS"),
        ("azure-dns.info",        "Azure DNS"),
        ("googledomains.com",     "Google"),
        ("google.com",            "Google"),
        ("nsone.net",             "NS1"),
        ("ultradns.net",          "UltraDNS"),
        ("ultradns.com",          "UltraDNS"),
        ("ultradns.org",          "UltraDNS"),
        ("worldnic.com",          "Network Solutions"),
        ("name.com",              "Name.com"),
        ("dnsmadeeasy.com",       "DNS Made Easy"),
        ("dnsimple.com",          "DNSimple"),
        ("he.net",                "Hurricane Electric"),
        ("bind.ch",               "Switch"),
        ("switch.ch",             "Switch"),
        ("metaname.net",          "Metaname"),
        ("stackpathdns.com",      "Stackpath"),
        ("dynect.net",            "Dyn/Oracle"),
        ("nine.ch",               "Nine"),
        ("hosteurope.de",         "HostEurope"),
        ("eurodns.com",           "EuroDNS"),
        ("active24.com",          "Active24"),
        ("mydomain.com",          "MyDomain"),
        ("netsolcorp.com",        "Network Solutions"),
        ("verisigndns.com",       "Verisign"),
        ("akamaiedge.net",        "Akamai"),
        ("akam.net",              "Akamai"),
    ];

    for (suffix, op) in RULES {
        if h.ends_with(suffix) {
            return op.to_string();
        }
    }

    if h.contains("awsdns") {
        return "AWS Route53".to_string();
    }

    // Fallback: SLD.TLD
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        h
    }
}

fn parse_json_array(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

/// Rebuild ns_staging from dns_info and return a map of operator → sample NS hostname.
fn rebuild_ns_staging(conn: &rusqlite::Connection) -> Result<HashMap<String, String>> {
    conn.execute_batch("DELETE FROM ns_staging;")?;

    let mut stmt = conn.prepare(
        "SELECT domain, ns FROM dns_info WHERE ns IS NOT NULL AND ns != '[]'",
    )?;
    let rows: Vec<(String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut operator_sample: HashMap<String, String> = HashMap::new();

    for (domain, ns_str) in &rows {
        for ns_host in parse_json_array(ns_str) {
            let operator = normalize_ns_to_operator(&ns_host);
            pairs.push((domain.clone(), operator.clone()));
            operator_sample.entry(operator).or_insert_with(|| ns_host.clone());
        }
    }

    pairs.sort();
    pairs.dedup();

    for chunk in pairs.chunks(500) {
        let values: String = chunk
            .iter()
            .map(|(d, o)| format!("({}, {})", sql_string(d), sql_string(o)))
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute_batch(&format!(
            "INSERT INTO ns_staging (domain, operator) VALUES {values}"
        ))?;
    }

    eprintln!(
        "sovereignty: {} (domain, operator) pairs in ns_staging",
        pairs.len()
    );
    Ok(operator_sample)
}

async fn resolve_first_a(resolver: &TokioResolver, hostname: &str) -> Option<IpAddr> {
    if hostname.is_empty() {
        return None;
    }
    let fqdn = if hostname.ends_with('.') {
        hostname.to_string()
    } else {
        format!("{hostname}.")
    };
    resolver.lookup_ip(fqdn).await.ok()?.iter().next()
}

pub(crate) async fn cmd_sovereignty(args: SovereigntyArgs) -> Result<()> {
    // Phase 1: sync — schema + rebuild ns_staging
    let to_resolve: Vec<(String, String)> = {
        let conn = crate::shared::open_db(&args.db)
            .with_context(|| format!("open db {:?}", args.db))?;
        crate::schema::ensure_schema(&conn)?;

        eprintln!("sovereignty: rebuilding ns_staging from dns_info...");
        let operator_samples = rebuild_ns_staging(&conn)?;
        eprintln!(
            "sovereignty: {} distinct operators found",
            operator_samples.len()
        );

        let mut stmt = conn.prepare("SELECT operator FROM ns_operators")?;
        let existing: std::collections::HashSet<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        operator_samples
            .into_iter()
            .filter(|(op, _)| !existing.contains(op))
            .collect()
    }; // conn dropped here

    // Phase 2: async DNS + mmdb resolution
    type OperatorRow = (
        String,         // operator
        String,         // sample_ns
        Option<String>, // resolved_ip
        Option<String>, // asn
        Option<String>, // asn_org
        Option<String>, // country_code
        String,         // jurisdiction
    );

    let resolved: Vec<OperatorRow> = if to_resolve.is_empty() {
        eprintln!("sovereignty: all operators already resolved, skipping DNS/GeoLite2 step");
        vec![]
    } else {
        eprintln!(
            "sovereignty: resolving {} operators via DNS + GeoLite2...",
            to_resolve.len()
        );

        let asn_reader = maxminddb::Reader::open_readfile(&args.asn_mmdb)
            .with_context(|| format!("open ASN mmdb {:?}", args.asn_mmdb))?;
        let country_reader = maxminddb::Reader::open_readfile(&args.country_mmdb)
            .with_context(|| format!("open Country mmdb {:?}", args.country_mmdb))?;
        let resolver = build_default_resolver();

        let mut results: Vec<OperatorRow> = Vec::with_capacity(to_resolve.len());

        for (i, (operator, sample_ns)) in to_resolve.iter().enumerate() {
            if i > 0 && i % 50 == 0 {
                eprintln!("  {i}/{} ...", to_resolve.len());
            }

            let ip = resolve_first_a(&resolver, sample_ns).await;

            let (resolved_ip, asn_num, asn_org, country_code) = match ip {
                Some(ip) => {
                    let (asn_num, asn_org) =
                        match asn_reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                            Ok(a) => (
                                a.autonomous_system_number.map(|n| format!("AS{n}")),
                                a.autonomous_system_organization.map(str::to_owned),
                            ),
                            Err(_) => (None, None),
                        };
                    let cc = match country_reader.lookup::<maxminddb::geoip2::Country>(ip) {
                        Ok(c) => c.country.and_then(|c| c.iso_code).map(str::to_owned),
                        Err(_) => None,
                    };
                    (Some(ip.to_string()), asn_num, asn_org, cc)
                }
                None => (None, None, None, None),
            };

            let jurisdiction =
                country_to_jurisdiction(country_code.as_deref().unwrap_or("")).to_string();

            results.push((
                operator.clone(),
                sample_ns.clone(),
                resolved_ip,
                asn_num,
                asn_org,
                country_code,
                jurisdiction,
            ));
        }

        results
    };

    // Phase 3: sync — write ns_operators, update sovereignty_score, print summary
    {
        let conn = crate::shared::open_db(&args.db)
            .with_context(|| format!("open db {:?}", args.db))?;

        for (operator, sample_ns, resolved_ip, asn_num, asn_org, country_code, jurisdiction) in
            &resolved
        {
            let sql = format!(
                "INSERT INTO ns_operators \
                    (operator, sample_ns, resolved_ip, asn, asn_org, country_code, jurisdiction) \
                 VALUES ({}, {}, {}, {}, {}, {}, {}) \
                 ON CONFLICT (operator) DO UPDATE SET \
                     sample_ns    = excluded.sample_ns, \
                     resolved_ip  = excluded.resolved_ip, \
                     asn          = excluded.asn, \
                     asn_org      = excluded.asn_org, \
                     country_code = excluded.country_code, \
                     jurisdiction = excluded.jurisdiction, \
                     updated_at   = CURRENT_TIMESTAMP",
                sql_string(operator),
                sql_string(sample_ns),
                sql_string_opt(resolved_ip.as_deref()),
                sql_string_opt(asn_num.as_deref()),
                sql_string_opt(asn_org.as_deref()),
                sql_string_opt(country_code.as_deref()),
                sql_string(jurisdiction),
            );
            conn.execute_batch(&sql)?;
        }

        eprintln!("sovereignty: computing per-domain sovereignty scores...");
        conn.execute_batch(
            "UPDATE domains SET sovereignty_score = (
                SELECT MAX(
                    CASE o.jurisdiction
                        WHEN 'US'    THEN 3
                        WHEN 'OTHER' THEN 2
                        WHEN 'EU'    THEN 1
                        ELSE 0
                    END
                )
                FROM ns_staging ns
                JOIN ns_operators o ON ns.operator = o.operator
                WHERE ns.domain = domains.domain
            )",
        )?;

        print_summary(&conn)?;
    }

    Ok(())
}

fn print_summary(conn: &rusqlite::Connection) -> Result<()> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM domains", [], |r| r.get(0))?;

    println!();
    println!("=== DNS Jurisdiction Distribution ===");
    println!("{:<12} {:>10} {:>9}", "Jurisdiction", "Domains", "%");
    println!("{}", "-".repeat(36));

    let mut stmt = conn.prepare(
        "SELECT o.jurisdiction, COUNT(DISTINCT ns.domain) AS cnt
         FROM ns_staging ns
         JOIN ns_operators o ON ns.operator = o.operator
         GROUP BY o.jurisdiction
         ORDER BY cnt DESC",
    )?;
    let jur_rows: Vec<(String, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;

    for (jur, cnt) in &jur_rows {
        let pct = if total > 0 {
            cnt * 100 / total
        } else {
            0
        };
        let warn = if jur == "US" || jur == "OTHER" { " ⚠" } else { "" };
        println!("{:<12} {:>10} {:>8}%{}", jur, cnt, pct, warn);
    }

    println!();
    println!("=== Top NS Operators (by domain count) ===");
    println!("{:<26} {:>8} {:>7}  {}", "Operator", "Domains", "%", "Jurisdiction");
    println!("{}", "-".repeat(60));

    let mut stmt2 = conn.prepare(
        "SELECT o.operator, COUNT(DISTINCT ns.domain) AS cnt, o.jurisdiction
         FROM ns_staging ns
         JOIN ns_operators o ON ns.operator = o.operator
         GROUP BY o.operator, o.jurisdiction
         ORDER BY cnt DESC
         LIMIT 20",
    )?;
    let op_rows: Vec<(String, i64, String)> = stmt2
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;

    for (op, cnt, jur) in &op_rows {
        let pct = if total > 0 { cnt * 100 / total } else { 0 };
        let warn = if jur == "US" || jur == "OTHER" { " ⚠" } else { "" };
        println!("{:<26} {:>8} {:>6}%  {}{}", op, cnt, pct, jur, warn);
    }

    println!();
    println!("=== Per-Domain Sovereignty Scores ===");
    println!("{:>5}  {:>10}  description", "Score", "Domains");
    println!("{}", "-".repeat(40));

    let mut stmt3 = conn.prepare(
        "SELECT sovereignty_score, COUNT(*) AS cnt
         FROM domains
         WHERE sovereignty_score IS NOT NULL
         GROUP BY sovereignty_score
         ORDER BY sovereignty_score",
    )?;
    let score_rows: Vec<(i32, i64)> = stmt3
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;

    for (score, cnt) in &score_rows {
        let desc = match score {
            0 => "CH (fully Swiss DNS)",
            1 => "EU-controlled DNS  (−1 pt)",
            2 => "Non-EU foreign DNS (−3 pts)",
            3 => "US-controlled DNS  (−5 pts)",
            _ => "unknown",
        };
        println!("{:>5}  {:>10}  {}", score, cnt, desc);
    }

    let unscored: i64 = conn.query_row(
        "SELECT COUNT(*) FROM domains WHERE sovereignty_score IS NULL",
        [],
        |r| r.get(0),
    )?;
    if unscored > 0 {
        println!("  N/A  {:>10}  no NS data", unscored);
    }

    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- country_to_jurisdiction ----

    #[test]
    fn jurisdiction_ch() {
        assert_eq!(country_to_jurisdiction("CH"), "CH");
    }

    #[test]
    fn jurisdiction_us() {
        assert_eq!(country_to_jurisdiction("US"), "US");
    }

    #[test]
    fn jurisdiction_eu_members() {
        for code in &["DE", "FR", "IT", "AT", "NL", "PL", "SE"] {
            assert_eq!(country_to_jurisdiction(code), "EU", "expected EU for {code}");
        }
    }

    #[test]
    fn jurisdiction_other() {
        for code in &["JP", "CN", "BR", "IN", "AU"] {
            assert_eq!(country_to_jurisdiction(code), "OTHER", "expected OTHER for {code}");
        }
    }

    #[test]
    fn jurisdiction_empty_is_other() {
        assert_eq!(country_to_jurisdiction(""), "OTHER");
    }

    // ---- normalize_ns_to_operator ----

    #[test]
    fn ns_operator_cloudflare() {
        assert_eq!(normalize_ns_to_operator("ns1.cloudflare.com"), "Cloudflare");
        assert_eq!(normalize_ns_to_operator("ns2.cloudflare.com."), "Cloudflare");
    }

    #[test]
    fn ns_operator_infomaniak() {
        assert_eq!(normalize_ns_to_operator("ns1.infomaniak.ch"), "Infomaniak");
        assert_eq!(normalize_ns_to_operator("ns.infomaniak.ch"), "Infomaniak");
    }

    #[test]
    fn ns_operator_aws_route53() {
        assert_eq!(normalize_ns_to_operator("ns-123.awsdns-45.com"), "AWS Route53");
        assert_eq!(normalize_ns_to_operator("ns-42.awsdns-07.org"), "AWS Route53");
    }

    #[test]
    fn ns_operator_azure() {
        assert_eq!(normalize_ns_to_operator("ns1-01.azure-dns.com"), "Azure DNS");
    }

    #[test]
    fn ns_operator_switch() {
        assert_eq!(normalize_ns_to_operator("ns.switch.ch"), "Switch");
    }

    #[test]
    fn ns_operator_fallback_sld_tld() {
        // Unknown NS falls back to SLD.TLD
        assert_eq!(normalize_ns_to_operator("ns1.example.net"), "example.net");
        assert_eq!(normalize_ns_to_operator("ns1.example.net."), "example.net");
    }

    #[test]
    fn ns_operator_single_label_fallback() {
        // Single label with no dot → returned as-is
        assert_eq!(normalize_ns_to_operator("localhost"), "localhost");
    }

    // ---- parse_json_array ----

    #[test]
    fn parse_array_empty() {
        assert!(parse_json_array("[]").is_empty());
        assert!(parse_json_array("").is_empty());
    }

    #[test]
    fn parse_array_single_element() {
        let result = parse_json_array(r#"["ns1.example.com"]"#);
        assert_eq!(result, vec!["ns1.example.com"]);
    }

    #[test]
    fn parse_array_multiple_elements() {
        let result = parse_json_array(r#"["ns1.example.com","ns2.example.com"]"#);
        assert_eq!(result, vec!["ns1.example.com", "ns2.example.com"]);
    }

    #[test]
    fn parse_array_with_spaces() {
        let result = parse_json_array(r#"["a.com", "b.com"]"#);
        assert_eq!(result, vec!["a.com", "b.com"]);
    }
}
