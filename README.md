## HelvetiScan - Mapping Swiss Cyberspace

Scan, map and visualize the entire Swiss `.ch` namespace — over 2.5 million domains. A complete map of Switzerland's digital surface - unpatched software, expired certificates, exposed databases, foreign dependencies, fakeable emails, weak or no encryptions and other previously uncharted vulnerabilities.


<div align="center">

![50k nodes sample](docs/50knodes.jpg)

</div>

This public visualization exposes the DNS dependency structure as an interactive force graph. See it online [here](https://xn--2dk.xyz/dataviz/swiss/?maxPoints=50000&sim=1).

50 thousand domains shown in this graph, just 2%. Adjust `maxPoints` in the URL to load more.[^2]
 
 

---

## The Tool

```
Swiss Cyberspace scanner - HTTP, DNS, TLS, HTTP, ports, WHOIS, MX and CVEs

Usage: helvetiscan [OPTIONS] [COMMAND]

Commands:
  init         Populate domains.db from a plain-text domain list (one domain/line)
  scan         HTTP scan: fetch status, title, server headers for all pending domains
  dns          Resolve DNS metadata for all domains missing a dns_info row
  tls          Scan TLS metadata for all domains missing a tls_info row
  ports        Scan a small fixed set of TCP ports for all domains missing a ports_info row
  subdomains   Discover subdomains via DNS zone transfer (AXFR) and NS/MX record harvest
  whois        Fetch WHOIS registrar and registration date for all domains
  update-cves  Fetch/refresh the CVE catalog from CISA KEV and seed built-in entries
  classify     Classify domains by industry sector using keyword heuristics
  benchmark    Compute sector-level risk benchmarks across classified domains
  sovereignty  Map NS operators by jurisdiction and compute per-domain sovereignty scores
  help         Print this message or the help of the given subcommand(s)

Options:
      --domain <DOMAIN>              Scan only this single domain
      --retry-errors <RETRY_ERRORS>  Re-scan domains whose error_kind matches this value (e.g. 'timeout')
```

The full HTTP scan completes in under four hours on a 1 Gbps connection.

---

## The Mapping

→ [Scan Modules and Security Scoring](docs/README.md)

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

## The Findings (preliminary)

-  76.4% has a live HTTP response; 1 in 4 is dead
-  DNS failure accounts for 74.9% of errors (450,916 domains) — registered but no server
-  Apache 38.3% and nginx 34.0% cover 72% of .ch web servers; Cloudflare proxies 10.2%
-  WordPress holds 71.5% of identifiable CMS installs (376,098 domains, ~19% of all live .ch)
-  43,473 live sites advertise EOL PHP — 40.6% of 107K installs with version exposed; PHP 7.4.33 most common
-  22.1% redirect cross-domain — parking services, CDN edges, or brand consolidation
-  12.6% of live flagged as parked or abandoned — no title or generic placeholder
-  130,937 IPs host 1,816,085 live domains — mean 13.9 per IP, heavily skewed toward shared hosting
-  Single IP (Hostpoint 217.26.48.101) hosts 133,425 domains (6.9%); top 10 IPs cover ~21% of live .ch
-  147,983 share a single Hostpoint parking page
-  71.7% end on HTTPS; 28.3% still serve over plain HTTP
-  40.6% of .ch domains hosted abroad; Germany leads at 17.3%, US at 11.6%
-  49.1% send zero security headers; only 30.2% use HSTS despite 71.7% serving HTTPS
-  TLS 1.3 at 92.9%; Let's Encrypt issues 83.1% of certs; 60,171 expire within 30 days
-  43.3% of scanned domains fully spoofable; DKIM only 6.8%; 24.7% of DMARC adopters on p=none
-  313,472 domains (16% of live) expose MySQL; 87,292 expose SMB; 1,742 expose Docker API
-  86.7% of .ch hosting stays within Europe; North America (US cloud) accounts for 13.0%
-  Largest foreign IP concentrations (Wix 77K, Register.it 35K, Shopify 15K)
-  Domains in weak-jurisdiction countries (501 in RU/BY/IR/CN/SY)
-  US cloud exposure via server header (Cloudflare 181K, Vercel 10K, AWS 6K = 10.1%)
-  TLS key sizes (no RSA <2048; ECDSA at 15.4%; 1,091 certs expiring in 7 days)
-  Email spoofing exposure (305K domains = 43.3% fully spoofable)
-  AXFR zone transfer leaks (2,300 parent domains, 27K subdomains exposed)
-  Most common ports beyond 80/443 (FTP open on 688K = 42% of scanned)

→ [See more](docs/FINDINGS.md)[^1]

[^1]: Raw datasets are not published. Consider only processed edges.arrow and nodes.arrow for dataviz.
[^2]: Full dataset visualiaztion requires more than 16GB RAM for a proper WebGPU processing.
