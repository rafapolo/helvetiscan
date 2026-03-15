## HelvetiScan - Mapping Swiss Cyberspace

Scan, map and visualize the entire Swiss `.ch` namespace — over 2.5 million domains. A complete map of Switzerland's digital surface - unpatched software, expired certificates, exposed databases, foreign dependencies, fakeable emails, weak or no encryptions and other uncharted vulnerabilities.

This public visualization exposes the DNS dependency structure as an interactive force graph. See it online [here](https://xn--2dk.xyz/dataviz/swiss/?maxPoints=50000&sim=1).

<div align="center">

![50k nodes sample](50knodes.jpg)

</div>

 50k domains shown. Adjust `maxPoints` URL to load more — full dataset (2.5M nodes) requires a good GPU.

---

## How we use it?

```
Swiss internet scanner - HTTP, DNS, TLS and port intelligence for the .ch namespace

Usage: helvetiscan [OPTIONS] [COMMAND]

Commands:
  init         Populate domains.duckdb from a plain-text domain list (one domain/line)
  scan         HTTP scan: fetch status, title, server headers for all pending domains
  dns          Resolve DNS metadata for all domains missing a dns_info row
  tls          Scan TLS metadata for all domains missing a tls_info row
  ports        Scan a small fixed set of TCP ports for all domains missing a ports_info row
  subdomains   Discover subdomains via DNS zone transfer (AXFR) and NS/MX record harvest
  whois        Fetch WHOIS registrar and registration date for all domains
  update-cves  Fetch/refresh the CVE catalog from CISA KEV and seed built-in entries
  classify     Classify domains by industry sector using keyword heuristics
  benchmark    Compute sector-level risk benchmarks across classified domains
  help         Print this message or the help of the given subcommand(s)

Options:
      --domain <DOMAIN>  Scan only this single domain
      --all              Run HTTP, DNS, TLS, and ports scans together
      --db <DB>          [default: data/domains.duckdb]
      --full <FULL>      Full rescan shortcut using default arguments 
                         [possible values: domain, dns, tls, ports, subdomains, whois, all]
  -h, --help             Print this help
```

---

## What do we scan?

Seven modules, each covering a different layer of exposure:

| Module | What it checks |
|---|---|
| **TLS & Certificates** | Expiration, chain validity, key strength, TLS version, CT logs |
| **DNS & DNSSEC** | DNSSEC adoption, CAA records, zone transfers, open resolvers |
| **HTTP Security Headers** | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| **Open Ports** | Exposed databases, RDP, SMB, FTP, management interfaces |
| **Email Security** | SPF, DKIM, DMARC — spoofing readiness across the namespace |
| **Technology Fingerprinting** | CMS/framework detection, version extraction, CVE correlation |
| **Domain Protection** | WHOIS expiry, typosquats, homoglyphs, orphaned subdomains |

---


## Research directions

The final database can answer questions such as:[^1]

- How many .ch domains depend on foreign infrastructure?
- Which .ch domains expose databases to the open internet?
- How many Swiss companies can have their email spoofed?
- How many .ch sites run software with known vulnerabilities?
- Which Swiss industries have the weakest security posture?
- How many Swiss domains expire in the next 30 days without auto-renewal?
- Which open ports appear most frequently across .ch?
- What's the most common CMS running on .ch domains?
- How many .ch mail servers use weak DKIM keys?
- Which Swiss cantons have the most exposed infrastructure?
- How many .ch domains have orphaned subdomains vulnerable to takeover?

#### → Read our [preliminary analyses](analyses/analyse_domains.md).

## Planned Analyses

- **Sector patterns** — Which Swiss industries have the weakest security posture?
- **Attack surface clustering** — Do domains sharing infrastructure share vulnerabilities?
- **Supply chain exposure** — How many .ch sites are affected by a single vulnerable plugin?
- **Cascade modeling** — If the top 3 providers go down, how many domains go dark?
- **Trend detection** — Is DMARC adoption growing? Is DNSSEC adoption stalling?
- **Threat prediction** — Can new typosquat registrations signal incoming phishing campaigns?

[^1]: Raw datasets are not published. Consider only processed edges.arrow and nodes.arrow for dataviz.
