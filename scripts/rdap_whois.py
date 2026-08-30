#!/usr/bin/env python3
"""Slow, conservative RDAP scraper for .ch domains. Respects 429s."""

import sqlite3, json, time, sys, os
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

DB = os.environ.get("DB", "data/domains.db")
DOMAINS_FILE = os.path.join(os.path.dirname(DB), "domains.txt")
BASE = "https://rdap.nic.ch/domain"
SLEEP = 0.3          # ~3 req/s base
BACKOFF = 5          # seconds to wait on 429
MAX_BACKOFF = 300    # max backoff (5 min)
BATCH = 500          # commit interval

def ensure_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS whois_info (
            domain           TEXT PRIMARY KEY,
            registrar        TEXT,
            whois_created    TEXT,
            expires_at       TEXT,
            status           TEXT,
            dnssec_delegated INTEGER,
            queried_at       TEXT
        )
    """)

def fetch(domain):
    url = f"{BASE}/{domain}"
    req = Request(url, headers={"User-Agent": "helvetiscan-research/1.0 (security research; +https://github.com/rafapolo/helvetiscan)"})
    resp = urlopen(req, timeout=15)
    return json.loads(resp.read())

def parse(data):
    reg_date = ""
    for e in data.get("events", []):
        if e.get("eventAction") == "registration":
            reg_date = e.get("eventDate", "")
            break
    status = data.get("status", [None])[0]
    registrar = ""
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vcard = ent.get("vcardArray", [[],[]])[1]
            if vcard:
                for item in vcard:
                    if item[0] == "org":
                        registrar = item[3]
    dnssec = 1 if data.get("secureDNS", {}).get("delegationSigned") else 0
    return registrar, reg_date, status, dnssec

def main():
    conn = sqlite3.connect(DB)
    ensure_table(conn)
    done = set(r[0] for r in conn.execute("SELECT domain FROM whois_info WHERE registrar IS NOT NULL AND registrar != ''"))
    total_queried = set(r[0] for r in conn.execute("SELECT domain FROM whois_info"))
    with open(DOMAINS_FILE) as f:
        all_domains = [line.strip() for line in f if line.strip() not in total_queried]
    # If none pending, retry failed ones (NULL registrar)
    if not all_domains:
        all_domains = [r[0] for r in conn.execute("SELECT domain FROM whois_info WHERE registrar IS NULL OR registrar = '' ORDER BY domain")]
    print(f"Pending: {len(all_domains)} domains", flush=True)

    backoff = SLEEP
    count = 0
    for i, domain in enumerate(all_domains):
        try:
            data = fetch(domain)
            registrar, reg_date, status, dnssec = parse(data)
            queried_at = time.strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("""
                INSERT INTO whois_info (domain, registrar, whois_created, status, dnssec_delegated, queried_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    registrar=excluded.registrar, whois_created=excluded.whois_created,
                    status=excluded.status, dnssec_delegated=excluded.dnssec_delegated,
                    queried_at=excluded.queried_at
            """, (domain, registrar, reg_date, status, dnssec, queried_at))
            backoff = SLEEP  # reset on success
            count += 1
            if count % BATCH == 0:
                conn.commit()
                print(f"  {count}/{len(all_domains)} - last: {domain} → registrar={registrar}", flush=True)
        except HTTPError as e:
            if e.code == 429:
                print(f"  429 on {domain}, backing off {backoff}s...", flush=True)
                time.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
                # Don't advance i — retry after backoff
                # Actually, we need to re-insert this domain into the loop
                # Let's just record it with NULL and retry later
                conn.execute("""
                    INSERT INTO whois_info (domain, queried_at)
                    VALUES (?, ?) ON CONFLICT(domain) DO NOTHING
                """, (domain, time.strftime("%Y-%m-%d %H:%M:%S")))
                if count % BATCH == 0:
                    conn.commit()
                continue
            else:
                print(f"  HTTP {e.code} on {domain}: {e}", flush=True)
                conn.execute("""
                    INSERT INTO whois_info (domain, queried_at)
                    VALUES (?, ?) ON CONFLICT(domain) DO NOTHING
                """, (domain, time.strftime("%Y-%m-%d %H:%M:%S")))
        except (URLError, OSError, json.JSONDecodeError) as e:
            print(f"  Error on {domain}: {e}", flush=True)
            conn.execute("""
                INSERT INTO whois_info (domain, queried_at)
                VALUES (?, ?) ON CONFLICT(domain) DO NOTHING
            """, (domain, time.strftime("%Y-%m-%d %H:%M:%S")))

        time.sleep(backoff)
        backoff = SLEEP  # reset to base after non-429

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM whois_info").fetchone()[0]
    with_data = conn.execute("SELECT COUNT(*) FROM whois_info WHERE registrar IS NOT NULL AND registrar != ''").fetchone()[0]
    print(f"Done. Total: {total}, with data: {with_data}", flush=True)
    conn.close()

if __name__ == "__main__":
    main()
