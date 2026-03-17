use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use rusqlite::Connection;

pub(crate) struct GeoCodeArgs {
    pub(crate) db: PathBuf,
    pub(crate) country_mmdb: PathBuf,
}

pub(crate) fn cmd_geocode(args: GeoCodeArgs) -> Result<()> {
    let conn = Connection::open(&args.db)
        .with_context(|| format!("opening {:?}", args.db))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

    let reader = maxminddb::Reader::open_readfile(&args.country_mmdb)
        .with_context(|| format!("opening {:?}", args.country_mmdb))?;

    let total: u64 = conn.query_row(
        "SELECT COUNT(*) FROM domains WHERE ip IS NOT NULL AND country_code IS NULL",
        [],
        |r| r.get(0),
    )?;

    if total == 0 {
        eprintln!("geocode: all IPs already have a country_code, nothing to do");
        return Ok(());
    }

    eprintln!("geocode: enriching {total} domains with country_code…");

    let mut stmt = conn.prepare(
        "SELECT domain, ip FROM domains WHERE ip IS NOT NULL AND country_code IS NULL",
    )?;

    let rows: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();

    const BATCH: usize = 10_000;
    let mut done: u64 = 0;
    let mut skipped: u64 = 0;

    for chunk in rows.chunks(BATCH) {
        let tx = conn.unchecked_transaction()?;
        {
            let mut upd = tx.prepare_cached(
                "UPDATE domains SET country_code = ?1 WHERE domain = ?2",
            )?;
            for (domain, ip_str) in chunk {
                let cc: Option<String> = IpAddr::from_str(ip_str).ok().and_then(|ip| {
                    reader
                        .lookup::<maxminddb::geoip2::Country>(ip)
                        .ok()
                        .and_then(|c| c.country.and_then(|c| c.iso_code).map(str::to_owned))
                });
                match cc {
                    Some(code) => {
                        upd.execute(rusqlite::params![code, domain])?;
                        done += 1;
                    }
                    None => {
                        skipped += 1;
                    }
                }
            }
        }
        tx.commit()?;

        let pct = (done + skipped) * 100 / total;
        eprint!("\r  {}/{total} ({pct}%)  ", done + skipped);
    }

    eprintln!("\ngeocoding: {done} updated, {skipped} IPs not in database");
    Ok(())
}
