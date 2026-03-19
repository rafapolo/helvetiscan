## HelvetiScan - Mapping Swiss Cyberspace

Scan, map and visualize the entire Swiss `.ch` namespace — over 2.5 million domains. A complete map of Switzerland's digital surface - unpatched software, expired certificates, exposed databases, foreign dependencies, fakeable emails, weak or no encryptions and other previously uncharted vulnerabilities.


<div align="center">

![50k nodes sample](docs/graph-50k.jpg)

</div>

This public visualization exposes the DNS dependency structure as an interactive force graph with 50 thousand domains shown by default, just 2%. Adjust `maxPoints` param in the URL to load as many you can.[^1] 

Explore it online [here](https://xn--2dk.xyz/dataviz/swiss/?maxPoints=50000&sim=1). 

---

## The Tool

The full HTTP scan completes in under 3 hours with high parallelization on a single machine with a 1 Gbps connection.

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

---

## The Mapping[^2]

-  76.4% has a live HTTP response; 1 in 4 is dead
-  Top 10 IPs cover ~21% of live .ch
-  FTP plaintext file transfer open on 688K domains — 42% of scanned .ch
-  Apache 38.3% and nginx 34.0% cover 72% of .ch web servers; Cloudflare proxies 10.2%
-  WordPress holds 71.5% of identifiable CMS installs; ~19% of all live .ch
-  22.1% redirect cross-domain — parking services, CDN edges, or brand consolidation
-  12.6% of live flagged as parked or abandoned — no title or generic placeholder
-  130,937 IPs host 1,816,085 live domains — mean 13.9 per IP; heavy shared hosting
-  Single IP (Hostpoint 217.26.48.101) hosts 133,425 domains (6.9%); 
-  147,983 share a single Hostpoint parking page
-  71.7% end on HTTPS; 28.3% still serve over plain HTTP
-  40.6% of .ch domains hosted abroad; Germany leads at 17.3%, US at 11.6%
-  207,977 .ch domains fully offshored — foreign NS operator AND hosting combined
-  49.1% send zero security headers; only 30.2% use HSTS despite 71.7% serving HTTPS
-  TLS 1.3 at 92.9%; Let's Encrypt issues 83.1% of certs; 71,767 expire within 30 days
-  1,091 certs expiring within 7 days
-  45.0% fully spoofable MX; DKIM only 6.8%; 25.5% of DMARC adopters on p=none
-  16% of live .ch expose MySQL; 87,292 expose SMB; 1,742 expose Docker API
-  38.4% match at least one potential CISA Known Exploited Vulnerability entry
-  86.7% of .ch hosting stays within Europe; US cloud accounts for 13.0%
-  Pharma lowest Swiss-hosting rate at 49.9%; government highest at 75.1%
-  Largest foreign IP concentrations (Wix 77K, Register.it 35K, Shopify 15K)
-  501 domains served in weak-jurisdiction countries (RU/BY/IR/CN/SY)
-  US cloud exposure via server header (Cloudflare 181K, Vercel 10K, AWS 6K = 10.1%)

→ Read the [KEY FINDINGS](docs/FINDINGS.md) / [PDF REPORT](docs/helvetiscan-findings.pdf)

---

→ [RESEARCH & ROADMAP](docs/RESEARCH.md) / [SCAN OVERVIEW](docs/README.md) / [REGULATORY PRESSURE](docs/REGULATORY.md) / [LEGAL](docs/LEGAL.md) / [LICENSE](LICENSE)

[^1]: Full dataset visualization requires ~32GB RAM for a proper WebGPU processing.
[^2]: Raw datasets are not published. Consider only processed edges.arrow and nodes.arrow for dataviz.
