use std::path::PathBuf;

use anyhow::{Context, Result};

// Keyword rules: (keyword, sector, subsector, confidence)
// More specific rules must come before less specific ones (e.g. "kantonalbank" before "bank").
const KEYWORD_RULES: &[(&str, &str, &str, f64)] = &[
    ("kantonalbank",  "finance",    "banking",   0.9),
    ("sparkasse",     "finance",    "banking",   0.8),
    ("bank",          "finance",    "banking",   0.7),
    ("credit",        "finance",    "banking",   0.65),
    ("finanz",        "finance",    "banking",   0.65),
    ("versicherung",  "finance",    "insurance", 0.75),
    ("insurance",     "finance",    "insurance", 0.7),
    ("pharma",        "pharma",     "",          0.7),
    ("biotech",       "pharma",     "",          0.7),
    ("klinik",        "healthcare", "",          0.75),
    ("spital",        "healthcare", "",          0.8),
    ("hospital",      "healthcare", "",          0.75),
    ("medizin",       "healthcare", "",          0.6),
    ("anwalt",        "legal",      "",          0.65),
    ("advokat",       "legal",      "",          0.75),
    ("notariat",      "legal",      "",          0.8),
    ("law",           "legal",      "",          0.5),
    ("schule",        "education",  "",          0.65),
    ("hochschule",    "education",  "",          0.8),
    ("universitaet",  "education",  "",          0.85),
    ("eth.ch",        "education",  "",          0.95),
    ("shop",          "retail",     "",          0.5),
    ("boutique",      "retail",     "",          0.55),
    ("news",          "media",      "",          0.5),
    ("zeitung",       "media",      "",          0.7),
    ("gemeinde",      "government", "",          0.8),
    ("kanton",        "government", "",          0.8),
    ("admin.ch",      "government", "",          0.95),
];

const CANTONAL_DOMAINS: &[&str] = &[
    "bs.ch", "zh.ch", "be.ch", "ag.ch", "sg.ch", "lu.ch", "ti.ch", "vd.ch",
    "ge.ch", "vs.ch", "fr.ch", "so.ch", "tg.ch", "gr.ch", "ne.ch", "sz.ch",
    "zg.ch", "gl.ch", "nw.ch", "ow.ch", "ur.ch", "ai.ch", "ar.ch", "sh.ch",
    "bl.ch", "ju.ch",
];

/// Returns (sector, subsector, confidence) for a domain+title combination.
pub(crate) fn classify_by_keywords(
    domain: &str,
    title: Option<&str>,
) -> Option<(&'static str, &'static str, f64)> {
    let domain_lc = domain.to_ascii_lowercase();
    let title_lc = title.unwrap_or("").to_ascii_lowercase();
    let combined = format!("{domain_lc} {title_lc}");

    // Government domain patterns take highest priority
    if domain_lc == "admin.ch" || domain_lc.ends_with(".admin.ch") {
        return Some(("government", "", 0.95));
    }
    for &cd in CANTONAL_DOMAINS {
        if domain_lc == cd || domain_lc.ends_with(&format!(".{cd}")) {
            return Some(("government", "", 0.90));
        }
    }

    // Keyword matching — return the first match (rules are ordered by priority)
    for &(keyword, sector, subsector, confidence) in KEYWORD_RULES {
        if combined.contains(keyword) {
            return Some((sector, subsector, confidence));
        }
    }

    None
}

pub(crate) async fn cmd_classify(db: PathBuf) -> Result<()> {
    let conn = duckdb::Connection::open(&db)
        .with_context(|| format!("open duckdb {:?}", db))?;

    crate::schema::ensure_schema(&conn)?;

    // Fetch unclassified domains
    let mut stmt = conn.prepare(
        "SELECT d.domain, d.title
         FROM domains d
         LEFT JOIN domain_classification dc ON dc.domain = d.domain
         WHERE dc.domain IS NULL"
    )?;

    struct DomainTitle {
        domain: String,
        title: Option<String>,
    }

    let rows: Vec<DomainTitle> = stmt.query_map([], |row| {
        Ok(DomainTitle {
            domain: row.get(0)?,
            title: row.get(1)?,
        })
    })?
    .collect::<std::result::Result<_, _>>()?;

    if rows.is_empty() {
        eprintln!("classify: all domains already classified");
        return Ok(());
    }

    let total = rows.len();
    let mut classified = 0usize;
    let mut by_sector: std::collections::HashMap<&'static str, usize> = std::collections::HashMap::new();

    conn.execute_batch("BEGIN")?;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO domain_classification (domain, sector, subsector, source, confidence)
             VALUES (?1, ?2, ?3, 'keyword', ?4)
             ON CONFLICT(domain) DO UPDATE SET
                sector        = excluded.sector,
                subsector     = excluded.subsector,
                source        = excluded.source,
                confidence    = excluded.confidence,
                classified_at = CURRENT_TIMESTAMP"
        )?;

        for row in &rows {
            if let Some((sector, subsector, confidence)) = classify_by_keywords(&row.domain, row.title.as_deref()) {
                stmt.execute(duckdb::params![
                    row.domain.as_str(),
                    sector,
                    subsector,
                    confidence,
                ])?;
                classified += 1;
                *by_sector.entry(sector).or_insert(0) += 1;
            }
        }
    }
    conn.execute_batch("COMMIT")?;

    eprintln!("classify: {classified}/{total} domains classified");
    let mut sectors: Vec<_> = by_sector.iter().collect();
    sectors.sort_by(|a, b| b.1.cmp(a.1));
    for (sector, count) in sectors {
        eprintln!("  {sector}: {count}");
    }

    Ok(())
}
