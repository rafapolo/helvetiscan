use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{Context, Result};
use serde_json::json;

use crate::sovereignty::country_to_jurisdiction;
use crate::HubExportArgs;

#[derive(Clone)]
struct HubMeta {
    kind: &'static str,
    label: String,
    jurisdiction: Option<String>,
    asn_org: Option<String>,
    domains: std::collections::HashSet<String>,
    risk_sum: f64,
    risk_count: u32,
}

impl HubMeta {
    fn new(kind: &'static str, label: String, jurisdiction: Option<String>, asn_org: Option<String>) -> Self {
        Self {
            kind,
            label,
            jurisdiction,
            asn_org,
            domains: std::collections::HashSet::new(),
            risk_sum: 0.0,
            risk_count: 0,
        }
    }
}

// ---------- entity resolution ----------
// NS-operator names (from sovereignty.rs's hardcoded hostname rules, e.g. "Hostpoint") and
// hosting-ASN org names (from MaxMind, e.g. "Hostpoint AG") come from independent sources
// and often name the same real company differently. Left unmerged, the same provider shows
// up as two separate top hubs. This pass merges hubs whose normalized labels match.

const LEGAL_SUFFIXES: &[&str] = &[
    "ag", "gmbh", "sa", "sarl", "sagl", "ltd", "inc", "llc", "corp", "bv", "nv", "kg", "kgaa",
    "se", "plc", "oy", "srl", "spa", "pty", "co",
];

/// Lowercased, punctuation-stripped tokens with a single trailing legal-entity suffix removed.
fn canonical_tokens(label: &str) -> Vec<String> {
    let lower = label.to_lowercase();
    let cleaned: String = lower
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' })
        .collect();
    let mut tokens: Vec<String> = cleaned.split_whitespace().map(str::to_string).collect();
    if tokens.len() > 1 {
        if let Some(last) = tokens.last() {
            if LEGAL_SUFFIXES.contains(&last.as_str()) {
                tokens.pop();
            }
        }
    }
    tokens
}

/// Strips one trailing ".tld"-shaped segment (e.g. "infomaniak.com" -> "infomaniak").
/// Only applies to simple two-part dotted labels, to avoid mangling anything more complex.
fn strip_simple_tld(label: &str) -> String {
    let parts: Vec<&str> = label.rsplitn(2, '.').collect();
    if parts.len() == 2 && parts[0].len() <= 4 && parts[0].chars().all(|c| c.is_ascii_alphabetic()) {
        parts[1].to_string()
    } else {
        label.to_string()
    }
}

fn is_token_prefix(a: &[String], b: &[String]) -> bool {
    !a.is_empty() && a.len() <= b.len() && a == &b[..a.len()]
}

fn uf_find(parent: &mut [usize], x: usize) -> usize {
    if parent[x] != x {
        parent[x] = uf_find(parent, parent[x]);
    }
    parent[x]
}

fn uf_union(parent: &mut [usize], a: usize, b: usize) {
    let ra = uf_find(parent, a);
    let rb = uf_find(parent, b);
    if ra != rb {
        parent[ra] = rb;
    }
}

fn merge_duplicate_entities(
    hubs: HashMap<String, HubMeta>,
    edges: HashMap<(String, String), u64>,
    risk_scores: &HashMap<String, f64>,
) -> (HashMap<String, HubMeta>, HashMap<(String, String), u64>) {
    let hub_ids: Vec<String> = hubs.keys().cloned().collect();
    let mut parent: Vec<usize> = (0..hub_ids.len()).collect();

    // An ns_operator label is "trusted" (a real company name, not a raw hostname fallback)
    // iff it doesn't contain a dot — sovereignty.rs's explicit rules table never emits dots;
    // only its SLD.TLD fallback does. hosting_asn labels are always trusted (from MaxMind).
    let mut trusted_indices: Vec<usize> = Vec::new();
    for (i, id) in hub_ids.iter().enumerate() {
        let h = &hubs[id];
        let trusted = match h.kind {
            "hosting_asn" => true,
            "ns_operator" => !h.label.contains('.'),
            _ => false,
        };
        if trusted {
            trusted_indices.push(i);
        }
    }

    let mut trusted_tokens: HashMap<usize, Vec<String>> = HashMap::new();
    for &i in &trusted_indices {
        trusted_tokens.insert(i, canonical_tokens(&hubs[&hub_ids[i]].label));
    }

    // Merge trusted hubs whose canonical names prefix-match each other (e.g.
    // "Hostpoint" / "Hostpoint AG", or "Infomaniak" / "Infomaniak Network SA").
    for (pos, &i) in trusted_indices.iter().enumerate() {
        for &j in &trusted_indices[pos + 1..] {
            let ti = &trusted_tokens[&i];
            let tj = &trusted_tokens[&j];
            if is_token_prefix(ti, tj) || is_token_prefix(tj, ti) {
                uf_union(&mut parent, i, j);
            }
        }
    }

    // Untrusted (dotted, fallback-derived) ns_operator hubs may only merge into a trusted
    // hub via EXACT canonical-token equality after stripping a simple TLD — never against
    // each other — to avoid false-positive merges across the long tail of unrelated names.
    for (i, id) in hub_ids.iter().enumerate() {
        let h = &hubs[id];
        if h.kind != "ns_operator" || !h.label.contains('.') {
            continue;
        }
        let toks = canonical_tokens(&strip_simple_tld(&h.label));
        if toks.is_empty() {
            continue;
        }
        for &j in &trusted_indices {
            if trusted_tokens[&j] == toks {
                uf_union(&mut parent, i, j);
                break;
            }
        }
    }

    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..hub_ids.len() {
        let root = uf_find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }

    let mut merged_hubs: HashMap<String, HubMeta> = HashMap::new();
    let mut id_remap: HashMap<String, String> = HashMap::new();

    for members in groups.into_values() {
        if members.len() == 1 {
            let id = hub_ids[members[0]].clone();
            id_remap.insert(id.clone(), id.clone());
            merged_hubs.insert(id.clone(), hubs[&id].clone());
            continue;
        }

        // Representative id: prefer a hosting_asn member (ASN numbers are stable, canonical
        // identifiers), else the shortest ns_operator id.
        let rep_idx = members
            .iter()
            .copied()
            .find(|&i| hubs[&hub_ids[i]].kind == "hosting_asn")
            .unwrap_or_else(|| *members.iter().min_by_key(|&&i| hub_ids[i].len()).unwrap());
        let rep_id = hub_ids[rep_idx].clone();

        let mut domains: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut kinds: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut label: Option<String> = None;
        let mut jurisdiction: Option<String> = None;
        let mut asn_org: Option<String> = None;

        for &i in &members {
            let h = &hubs[&hub_ids[i]];
            domains.extend(h.domains.iter().cloned());
            kinds.insert(h.kind);
            if h.kind == "hosting_asn" {
                label.get_or_insert_with(|| h.label.clone());
                asn_org = asn_org.or_else(|| h.asn_org.clone());
                jurisdiction = jurisdiction.or_else(|| h.jurisdiction.clone());
            }
        }
        if label.is_none() {
            // No hosting_asn member — prefer a trusted (non-dotted) ns_operator label.
            label = members
                .iter()
                .map(|&i| &hubs[&hub_ids[i]])
                .find(|h| !h.label.contains('.'))
                .map(|h| h.label.clone())
                .or_else(|| Some(hubs[&hub_ids[members[0]]].label.clone()));
        }
        if jurisdiction.is_none() {
            jurisdiction = members.iter().find_map(|&i| hubs[&hub_ids[i]].jurisdiction.clone());
        }
        if asn_org.is_none() {
            asn_org = members.iter().find_map(|&i| hubs[&hub_ids[i]].asn_org.clone());
        }
        let kind: &'static str = if kinds.len() > 1 {
            "provider"
        } else if kinds.contains("hosting_asn") {
            "hosting_asn"
        } else {
            "ns_operator"
        };

        // Recompute risk over the de-duplicated domain union — summing each member's
        // pre-computed risk_sum would double-count domains shared across merged hubs.
        let mut risk_sum = 0.0;
        let mut risk_count = 0u32;
        for d in &domains {
            if let Some(score) = risk_scores.get(d) {
                risk_sum += score;
                risk_count += 1;
            }
        }

        for &i in &members {
            id_remap.insert(hub_ids[i].clone(), rep_id.clone());
        }

        merged_hubs.insert(
            rep_id,
            HubMeta {
                kind,
                label: label.unwrap(),
                jurisdiction,
                asn_org,
                domains,
                risk_sum,
                risk_count,
            },
        );
    }

    let mut merged_edges: HashMap<(String, String), u64> = HashMap::new();
    for ((a, b), w) in edges {
        let ra = id_remap.get(&a).cloned().unwrap_or(a);
        let rb = id_remap.get(&b).cloned().unwrap_or(b);
        if ra == rb {
            continue; // self-loop created by merging the edge's own two endpoints
        }
        let key = if ra < rb { (ra, rb) } else { (rb, ra) };
        *merged_edges.entry(key).or_insert(0) += w;
    }

    let merged_count = hub_ids.len() - merged_hubs.len();
    if merged_count > 0 {
        eprintln!(
            "export-hubs: merged {merged_count} duplicate-entity hub(s) ({} -> {} total hubs before filtering)",
            hub_ids.len(),
            merged_hubs.len()
        );
    }

    (merged_hubs, merged_edges)
}

pub(crate) fn cmd_export_hubs(args: HubExportArgs) -> Result<()> {
    let conn = crate::shared::open_db(&args.db)
        .with_context(|| format!("open db {:?}", args.db))?;

    // --- load NS operator metadata (populated by `sovereignty`) ---
    let mut operators: HashMap<String, (Option<String>, Option<String>, String)> = HashMap::new();
    {
        let mut stmt = conn.prepare("SELECT operator, asn, asn_org, jurisdiction FROM ns_operators")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (operator, asn, asn_org, jurisdiction) = row?;
            operators.insert(operator, (asn, asn_org, jurisdiction));
        }
    }
    if operators.is_empty() {
        eprintln!("export-hubs: ns_operators is empty — run `sovereignty` first for NS operator data");
    }

    // --- load domain -> NS operator(s), from ns_staging (populated by `sovereignty`) ---
    let mut domain_operators: HashMap<String, Vec<String>> = HashMap::new();
    {
        let mut stmt = conn.prepare("SELECT domain, operator FROM ns_staging")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (domain, operator) = row?;
            domain_operators.entry(domain).or_default().push(operator);
        }
    }

    // --- load per-domain risk_score ---
    let mut risk_scores: HashMap<String, f64> = HashMap::new();
    {
        let mut stmt = conn.prepare("SELECT domain, score FROM risk_score")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?)))?;
        for row in rows {
            let (domain, score) = row?;
            risk_scores.insert(domain, score);
        }
    }

    // --- load domain -> ip ---
    // Note: registrar hubs were dropped — .ch RDAP/WHOIS is centralized and rate-limit-blocks
    // bulk scans, so registrar data was never reliably populated (see docs/SCHEMA.md).
    let domains: Vec<(String, Option<String>)> = {
        let mut stmt = conn.prepare("SELECT domain, ip FROM domains")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        })?;
        rows.collect::<Result<_, _>>()?
    };

    eprintln!("export-hubs: resolving hosting ASN for distinct hosting IPs...");
    let asn_reader = maxminddb::Reader::open_readfile(&args.asn_mmdb)
        .with_context(|| format!("open ASN mmdb {:?}", args.asn_mmdb))?;
    let country_reader = maxminddb::Reader::open_readfile(&args.country_mmdb)
        .with_context(|| format!("open Country mmdb {:?}", args.country_mmdb))?;

    // Cache ASN/country lookups per unique hosting IP — many domains share one IP.
    let mut ip_cache: HashMap<String, Option<(String, Option<String>, Option<String>)>> = HashMap::new();

    let mut hubs: HashMap<String, HubMeta> = HashMap::new();
    // undirected pair key -> weight
    let mut edges: HashMap<(String, String), u64> = HashMap::new();

    for (domain, ip) in &domains {
        let mut touched: Vec<String> = Vec::with_capacity(2);

        // NS operator hub(s)
        if let Some(ops) = domain_operators.get(domain) {
            for op in ops {
                let hub_id = format!("ns:{op}");
                hubs.entry(hub_id.clone()).or_insert_with(|| {
                    let (_, asn_org, jurisdiction) = operators
                        .get(op)
                        .cloned()
                        .unwrap_or((None, None, "OTHER".to_string()));
                    HubMeta::new(
                        "ns_operator",
                        op.clone(),
                        Some(jurisdiction),
                        asn_org.or_else(|| Some(op.clone())),
                    )
                });
                touched.push(hub_id);
            }
        }

        // Hosting ASN hub
        if let Some(ip_str) = ip {
            let resolved = ip_cache.entry(ip_str.clone()).or_insert_with(|| {
                let addr = IpAddr::from_str(ip_str).ok()?;
                let (asn_num, asn_org) = match asn_reader.lookup::<maxminddb::geoip2::Asn>(addr) {
                    Ok(a) => (
                        a.autonomous_system_number.map(|n| format!("AS{n}")),
                        a.autonomous_system_organization.map(str::to_owned),
                    ),
                    Err(_) => (None, None),
                };
                let cc = match country_reader.lookup::<maxminddb::geoip2::Country>(addr) {
                    Ok(c) => c.country.and_then(|c| c.iso_code).map(str::to_owned),
                    Err(_) => None,
                };
                let asn_num = asn_num?;
                Some((asn_num, asn_org, cc))
            });

            if let Some((asn_num, asn_org, cc)) = resolved {
                let hub_id = format!("asn:{asn_num}");
                hubs.entry(hub_id.clone()).or_insert_with(|| {
                    let jurisdiction = country_to_jurisdiction(cc.as_deref().unwrap_or("")).to_string();
                    HubMeta::new(
                        "hosting_asn",
                        asn_org.clone().unwrap_or_else(|| asn_num.clone()),
                        Some(jurisdiction),
                        asn_org.clone().or_else(|| Some(asn_num.clone())),
                    )
                });
                touched.push(hub_id);
            }
        }

        touched.sort();
        touched.dedup();

        for hub_id in &touched {
            let hub = hubs.get_mut(hub_id).expect("hub was just inserted");
            hub.domains.insert(domain.clone());
            if let Some(score) = risk_scores.get(domain) {
                hub.risk_sum += score;
                hub.risk_count += 1;
            }
        }

        for i in 0..touched.len() {
            for j in (i + 1)..touched.len() {
                let key = if touched[i] < touched[j] {
                    (touched[i].clone(), touched[j].clone())
                } else {
                    (touched[j].clone(), touched[i].clone())
                };
                *edges.entry(key).or_insert(0) += 1;
            }
        }
    }

    let (hubs, edges) = merge_duplicate_entities(hubs, edges, &risk_scores);

    // Filter long-tail noise: keep only hubs with domain_count >= min_domains.
    let kept: std::collections::HashSet<String> = hubs
        .iter()
        .filter(|(_, h)| h.domains.len() as u32 >= args.min_domains)
        .map(|(id, _)| id.clone())
        .collect();

    let node_list: Vec<_> = hubs
        .into_iter()
        .filter(|(id, _)| kept.contains(id))
        .map(|(id, h)| {
            let avg_risk = if h.risk_count > 0 {
                Some(h.risk_sum / h.risk_count as f64)
            } else {
                None
            };
            json!({
                "id": id,
                "kind": h.kind,
                "label": h.label,
                "domain_count": h.domains.len(),
                "jurisdiction": h.jurisdiction,
                "asn_org": h.asn_org,
                "avg_risk_score": avg_risk,
            })
        })
        .collect();

    let edge_list: Vec<_> = edges
        .into_iter()
        .filter(|((a, b), _)| kept.contains(a) && kept.contains(b))
        .map(|((source, target), weight)| json!({ "source": source, "target": target, "weight": weight }))
        .collect();

    eprintln!(
        "export-hubs: {} hubs kept (of {} candidates), {} edges, min_domains={}",
        node_list.len(),
        kept.len(),
        edge_list.len(),
        args.min_domains
    );

    std::fs::write(&args.nodes_out, serde_json::to_string(&node_list)?)
        .with_context(|| format!("write {:?}", args.nodes_out))?;
    std::fs::write(&args.edges_out, serde_json::to_string(&edge_list)?)
        .with_context(|| format!("write {:?}", args.edges_out))?;

    eprintln!(
        "export-hubs: wrote {:?} and {:?}",
        args.nodes_out, args.edges_out
    );

    Ok(())
}
