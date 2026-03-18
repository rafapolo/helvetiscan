# Key Findings

→ See also [Research Questions](RESEARCH.md)

---

## 1. How many .ch domains are alive vs dead?

| Status | Count     | Share |
|--------|-----------|-------|
| ok     | 1,947,451 | 76.4% |
| error  |   601,830 | 23.6% |

The dataset is fully scanned — no pending entries. **3 in 4** registered .ch domains serves a live HTTP response.

---

## 2. What are the most common ways a .ch domain fails?

| Error kind | Count   | Share of errors |
|------------|---------|-----------------|
| dns        | 450,916 | 74.9%           |
| timeout    |  93,913 | 15.6%           |
| tls_failed |  30,925 |  5.1%           |
| refused    |  14,482 |  2.4%           |
| other      |  11,594 |  1.9%           |

**DNS failures dominate at 75%** — domains registered but with no A record. TLS failures at 5.1% represent sites reachable but with a broken certificate.

---

## 3. What are the most common HTTP status codes?

| Status code | Meaning         | Count     | Share of live |
|-------------|-----------------|-----------|---------------|
| 200         | OK              |   861,942 | 44.3%         |
| 206         | Partial Content |   784,791 | 40.3%         |
| 403         | Forbidden       |    93,814 |  4.8%         |
| 404         | Not Found       |    84,678 |  4.3%         |
| 500         | Server Error    |    40,313 |  2.1%         |
| 429         | Rate Limited    |    21,457 |  1.1%         |
| 503         | Unavailable     |    21,437 |  1.1%         |

The **206 Partial Content** at 40% is a scanner artifact — the HTTP client sends a `Range` header and many servers honour it literally. The real "content served" population is 200 + 206 combined (~85%). The 93K `403` responses are domains that connect but actively block the scanner.

---

## 4. What's the most popular web server software in Switzerland?

*Based on 1,779,967 domains with a `Server:` header (91.4% of live domains).*

| Server family     | Count     | Share |
|-------------------|-----------|-------|
| Apache            |   682,437 | 38.3% |
| nginx / OpenResty |   605,026 | 34.0% |
| Cloudflare        |   181,451 | 10.2% |
| Other             |   126,980 |  7.1% |
| Pepyaka (Wix)     |   102,701 |  5.8% |
| LiteSpeed         |    35,038 |  2.0% |
| Squarespace       |    19,853 |  1.1% |
| Microsoft IIS     |    16,525 |  0.9% |
| Vercel            |     9,956 |  0.6% |

Apache leads at 38% with nginx close behind at 34%. Cloudflare proxies 10% of live .ch sites. Wix (Pepyaka) at 5.8% reflects strong hosted-platform adoption.

---

## 5. What's the most common CMS running on .ch?

*Actual CMS installs among live domains.*

| CMS       | Count   | Share of CMS installs |
|-----------|---------|-----------------------|
| WordPress |  376,098 | 71.5% |
| Wix       |   83,246 | 15.8% |
| TYPO3     |   26,372 |  5.0% |
| Joomla    |   23,202 |  4.4% |
| Drupal    |   10,028 |  1.9% |
| Other     |    7,382 |  1.4% |

**WordPress dominates at 71.5%** of identifiable CMS installs and represents ~19% of all live .ch domains. TYPO3 — common in German-speaking enterprise — holds 3rd ahead of Joomla.

---

## 6. How many .ch domains still run PHP, and which version?

*Based on 174,706 domains with an `X-Powered-By` header (9% of live domains).*

| `X-Powered-By` | Count  |
|----------------|--------|
| PHP/7.4.33     | 18,738 |
| PHP/8.3.30     | 14,965 |
| PleskLin       | 14,864 |
| PHP/8.2.30     | 12,669 |
| ASP.NET        | 11,986 |
| PHP/5.6.40     | 11,496 |
| PHP/8.1.34     |  7,450 |
| Next.js        |  7,334 |
| PHP/8.4.18     |  4,942 |

**EOL PHP breakdown** (107,234 total PHP installs with version exposed):

| PHP branch          | Count  | EOL date    |
|---------------------|--------|-------------|
| PHP 5.x             | 16,839 | Dec 2018    |
| PHP 7.0–7.3         |  6,190 | Dec 2019–22 |
| PHP 7.4             | 20,444 | Nov 2022    |
| **Total EOL**       | **43,473** |         |
| PHP 8.x (supported) | 61,961 | —           |

**43,000+ live .ch sites advertise end-of-life PHP** — outnumbering supported PHP 8.x installs. PHP 7.4.33 is the single most common version and has been EOL since November 2022.

---

## 7. What does the average .ch response time look like?

*Based on 1,947,451 successful scans.*

| Percentile | Response time |
|------------|---------------|
| min        |         4 ms  |
| p25        |       633 ms  |
| median     |     1,102 ms  |
| p75        |     1,676 ms  |
| p95        |     5,532 ms  |
| p99        |    10,774 ms  |
| max        |   106,288 ms  |
| mean       |     1,685 ms  |

Median of **1.1 seconds**. The p99 at 10.8 s flags slow shared-hosting tails. The slowest recorded response exceeded 106 seconds.

---

## 8. How many .ch domains redirect to a different domain entirely?

| Redirect type         | Count     | Share of live |
|-----------------------|-----------|---------------|
| Same-domain final URL | 1,545,839 | 79.4%         |
| Cross-domain redirect |   401,612 | 20.6%         |

**20.6% of live .ch domains redirect to a completely different domain** — parking services, CDN edges, or brand consolidation.

---

## 9. How many .ch websites are parking pages or abandoned?

| Category                | Count   | Share of live |
|-------------------------|---------|---------------|
| No `<title>` tag        | 221,512 | 11.4%         |
| Generic/default title   |  23,535 |  1.2%         |
| **Total likely parked** | **245,047** | **12.6%** |

Over **1 in 8 live .ch domains** shows no title or a generic placeholder.

---

## 10. How many distinct IPs host all live .ch domains?

**130,937 distinct IP addresses** serve 1,816,085 live domains (with IP data) — average of **13.9 domains per IP**, but extremely skewed.

---

## 11. Which single IP address hosts the most .ch domains?

| IP              | Domains hosted | Provider           |
|-----------------|----------------|--------------------|
| 217.26.48.101   |    133,425     | Hostpoint AG       |
| 217.26.63.20    |     43,708     | Hostpoint AG       |
| 81.88.58.216    |     35,747     | Register S.p.A     |
| 185.230.63.107  |     35,031     | Wix Ltd (US)       |
| 128.65.195.180  |     32,764     | Swisscom AG        |
| 84.16.66.164    |     29,854     | Infomaniak Network |
| 185.101.158.113 |     28,322     | Hosttech GmbH      |
| 162.159.128.70  |     28,171     | Cloudflare         |
| 185.230.63.171  |     21,538     | Wix Ltd (US)       |
| 185.230.63.186  |     21,107     | Wix Ltd (US)       |

**A single IP hosts 133,425 domains** — 6.9% of all live .ch sites. The top 10 IPs account for ~410K domains (21% of live .ch).

---

## 12. How many unique .ch websites exist vs clones sharing the same body?

| Metric                               | Count     |
|--------------------------------------|-----------|
| Domains with body hash               | 1,917,250 |
| Unique body hashes                   | 1,302,466 |
| Truly unique bodies (hash seen once) | 1,204,305 |
| Domains sharing a body               |   712,945 |
| Distinct shared-body groups          |    98,161 |
| Domains with no body hash            |    30,201 |

**712,945 domains (36.6%)** share their page body with at least one other domain.

| Sites sharing | Title                                                |
|---------------|------------------------------------------------------|
|    147,983    | "Hello, this domain has been purchased at Hostpoint" |
|     37,464    | *(no title)*                                         |
|     25,101    | "Seite nicht verfügbar"                              |
|     13,844    | "415 Unsupported Media Type"                         |
|      8,554    | "403 Forbidden"                                      |

**147,983 Hostpoint parking pages** (7.6% of live .ch) share a single body hash — the largest clone group.

---

## 13. How many .ch domains redirect from HTTP to HTTPS?

| Protocol outcome  | Count     | Share of live |
|-------------------|-----------|---------------|
| Ends on HTTPS     | 1,397,073 | 71.7%         |
| Stays on HTTP     |   550,378 | 28.3%         |

**71.7% of live .ch domains** serve their final content over HTTPS. **550,000 sites still deliver content over plain HTTP**.

---

## 14. Where are .ch domains hosted?

*Based on 1,739,441 live domains with a resolved IP in GeoLite2 (89.3% of live domains).*

| Country | Count     | Share |
|---------|-----------|-------|
| CH      | 1,033,304 | 59.4% |
| DE      |   300,707 | 17.3% |
| US      |   202,562 | 11.6% |
| FR      |    52,720 |  3.0% |
| IT      |    41,992 |  2.4% |
| CA      |    22,713 |  1.3% |
| NL      |    22,181 |  1.3% |
| DK      |     9,788 |  0.6% |
| GB      |     9,247 |  0.5% |
| IE      |     8,204 |  0.5% |
| AT      |     7,810 |  0.4% |
| other   |    18,213 |  1.1% |

**40.6% of .ch domains are hosted outside Switzerland.** Germany (17.3%) is the leading foreign host, largely driven by Wix (DE infrastructure) and Register.it. The US at 11.6% reflects AWS, Cloudflare, and Vercel. Ireland (0.5%) is almost entirely AWS/Cloudflare EU endpoints.

---

## 15. HTTP security headers

*Based on 1,947,451 live domains — complete coverage.*

| Header                  | Count   | Share of live |
|-------------------------|---------|---------------|
| HSTS                    | 588,872 | 30.2%         |
| X-Content-Type-Options  | 470,434 | 24.2%         |
| X-Frame-Options         | 460,142 | 23.6%         |
| Content-Security-Policy | 149,180 |  7.7%         |
| **None of the above**   | 955,764 | **49.1%**     |

**49% of live .ch domains send zero security headers.** Only 30% use HSTS despite 72% serving HTTPS. CSP adoption at 7.7% is weakest.

---

## 16. TLS certificate landscape

*Based on 1,158,482 domains with a successful TLS scan (full scan: 2,549,281 domains attempted).*

**Protocol versions:**

| TLS version | Count     | Share  |
|-------------|-----------|--------|
| TLSv1.3     | 1,076,502 | 92.9%  |
| TLSv1.2     |    81,980 |  7.1%  |

TLS 1.0/1.1 appear extinct in the dataset. **93% of TLS-enabled .ch domains run TLS 1.3.**

**Certificate issuers:**

| CA             | Count   | Share  |
|----------------|---------|--------|
| Let's Encrypt  | 962,746 | 83.1%  |
| Other          | 145,398 | 12.5%  |
| DigiCert       |  25,477 |  2.2%  |
| Sectigo/Comodo |  19,465 |  1.7%  |
| ZeroSSL        |   4,126 |  0.4%  |
| SwissSign      |   1,270 |  0.1%  |

**Let's Encrypt issues 83% of all certificates.** SwissSign (Swiss national CA) covers only 1,270 domains. **71,767 certificates expire within 30 days.**

---

## 17. Email security posture

*Based on 2,549,281 domains — complete coverage.*

| Signal                | Count     | Share  |
|-----------------------|-----------|--------|
| SPF present           | 1,365,991 | 53.6%  |
| DMARC present         |   714,725 | 28.0%  |
| DKIM found            |   174,388 |  6.8%  |
| SPF too permissive    |    74,477 |  2.9%  |

Of domains with DMARC:

| DMARC policy  | Count   | Share of DMARC |
|---------------|---------|----------------|
| reject        | 297,927 | 41.7%          |
| quarantine    | 234,348 | 32.8%          |
| none          | 182,089 | 25.5%          |

**46.4% of .ch domains have no SPF record**, leaving them open to spoofing. Of those with DMARC, 25.5% are on `p=none` — monitoring only, no enforcement. Only 6.8% have a discoverable DKIM key.

---

## 18. Exposed ports — databases and dangerous services

*Based on 1,633,972 distinct domains with port scan data.*

| Port  | Service       | Domains exposed | Risk     |
|-------|---------------|-----------------|----------|
| 3306  | MySQL         |       313,472   | Critical |
| 445   | SMB/CIFS      |        87,292   | Critical |
| 5432  | PostgreSQL    |        17,976   | High     |
| 3389  | RDP           |         3,718   | Critical |
| 9200  | Elasticsearch |         2,378   | Critical |
| 6379  | Redis         |         2,045   | High     |
| 5900  | VNC           |         1,910   | High     |
| 2375  | Docker API    |         1,742   | Critical |
| 23    | Telnet        |         1,440   | High     |
| 27017 | MongoDB       |         1,399   | High     |
| 11211 | Memcached     |         1,109   | High     |

**313,472 domains have port 3306 (MySQL) open** — 16% of all live .ch domains. **87,292 expose SMB (445)** and **3,718 expose RDP** — both common ransomware entry vectors. **1,742 expose Docker API (port 2375)**, which commonly runs unauthenticated.

---

## 19. DNSSEC adoption

*Based on 2,549,281 domains — complete coverage.*

| Metric        | Count     | Share  |
|---------------|-----------|--------|
| DNSSEC signed | 1,075,048 | 42.2%  |
| Not signed    | 1,474,233 | 57.8%  |

**42% of .ch domains have DNSSEC signing** — high compared to global averages, likely driven by SWITCH actively promoting DNSSEC for .ch registrations.

---

## 20. Hosting sovereignty — continental breakdown

*Based on 1,739,441 live domains with IP geolocation data (89.3% of live domains).*

| Continent     | Count     | Share |
|---------------|-----------|-------|
| Europe (all)  | 1,509,878 | 86.8% |
| — Switzerland | 1,033,304 | 59.4% |
| — Rest of EU  |   476,574 | 27.4% |
| North America |   225,284 | 13.0% |
| Asia-Pacific  |     3,277 |  0.2% |
| Other         |     1,002 |  0.1% |

**86.8% of .ch domain hosting stays within Europe.** The 13% North America share is nearly entirely US cloud services (Cloudflare, Wix US infrastructure, AWS, Vercel). Asia-Pacific and other jurisdictions combined represent under 0.3% of all live domains.

---

## 21. Swiss hosting providers — domestic dominance

*Top individual IPs where the hosting country resolves to Switzerland (GeoLite2).*

| IP              | Domains hosted | Provider         |
|-----------------|----------------|------------------|
| 217.26.48.101   |    133,425     | Hostpoint AG     |
| 217.26.63.20    |     43,708     | Hostpoint AG     |
| 128.65.195.180  |     32,764     | Swisscom AG      |
| 84.16.66.164    |     29,854     | Infomaniak Network |
| 185.101.158.113 |     28,322     | Hosttech GmbH    |
| 185.67.193.93   |     11,085     | (CH provider)    |
| 2a00:d70:0:a::166 |    9,738     | (CH provider)    |
| 92.43.216.100   |      8,040     | (CH provider)    |
| 185.117.169.155 |      5,202     | (CH provider)    |

Hostpoint AG alone accounts for the two largest domestic IPs — **177,133 domains (17.1% of Swiss-hosted)** on just two addresses.

---

## 22. Largest foreign IP concentrations

*Top individual IPs with country_code ≠ CH.*

| IP              | Country | Domains | Provider         |
|-----------------|---------|---------|------------------|
| 81.88.58.216    | IT      |  35,747 | Register S.p.A   |
| 185.230.63.107  | US      |  35,031 | Wix.com Ltd.     |
| 185.230.63.171  | US      |  21,538 | Wix.com Ltd.     |
| 185.230.63.186  | US      |  21,107 | Wix.com Ltd.     |
| 64.190.63.222   | DE      |  16,296 | (DE provider)    |
| 23.227.38.65    | CA      |  15,329 | Shopify          |
| 213.186.33.5    | FR      |  11,536 | OVH SAS          |
| 198.49.23.144   | US      |  10,470 | Squarespace      |
| 213.239.221.71  | DE      |   9,946 | Hetzner Online   |
| 18.197.248.23   | DE      |   8,259 | AWS eu-central-1 |

Wix concentrates **77,676 .ch domains across three US IPs**. The top 10 foreign IPs alone account for ~185K domains (~9.5% of all live .ch).

---

## 23. Domains in weak-jurisdiction countries

*Live .ch domains hosted in jurisdictions with weak or hostile data-protection laws.*

| Country | Domains |
|---------|---------|
| RU      |     473 |
| BY      |      16 |
| IR      |       7 |
| CN      |       4 |
| SY      |       1 |
| **Total** | **501** |

**501 .ch domains** — Swiss-registered web presence — have their infrastructure in Russia, Belarus, Iran, China, or Syria. Small in absolute terms but notable given Swiss data-protection obligations.

---

## 24. US cloud infrastructure exposure

*Share of live .ch domains served via major US cloud providers, identified by `Server:` header.*

| Provider    | Count   | Share of live |
|-------------|---------|---------------|
| Cloudflare  | 181,451 |  9.3%         |
| Vercel      |   9,956 |  0.5%         |
| AWS (ELB/S3)|   6,180 |  0.3%         |
| **Total**   | **197,587** | **10.1%** |

**10% of all live .ch domains route through US-based cloud infrastructure** identifiable via server headers alone. The real figure is higher since AWS CloudFront and similar services often suppress or replace the `Server:` header.

---

## 25. TLS certificate health

*Based on 1,158,482 domains with status='ok' TLS scans.*

**Key size distribution:**

| Algorithm   | Key size | Count   | Share  |
|-------------|----------|---------|--------|
| RSA         | 2048     | 844,699 | 72.9%  |
| ECDSA P-256 | 256      | 164,373 | 14.2%  |
| RSA         | 4096     | 129,671 | 11.2%  |
| ECDSA P-384 | 384      |  13,907 |  1.2%  |
| RSA         | 3072     |   5,831 |  0.5%  |

No RSA keys below 2048 bits were found — the 2048-bit floor appears universal. ECDSA (P-256 + P-384) covers **15.4%** of certs.

**Certificates expiring within 7 days:** 1,091.

---

## 26. Email spoofing exposure

*Based on 2,549,281 domains — complete coverage.*

| Condition | Count     | Share of total |
|-----------|-----------|----------------|
| No SPF AND no DMARC | 1,038,992 | 40.8% |
| Fully spoofable (no/permissive SPF + no/none DMARC) | 1,146,818 | 45.0% |
| SPF lookup limit exceeded | 25 | <0.1% |

**1,146,818 .ch domains (45.0%) can have their email impersonated without technical barriers** — either because they publish no SPF at all, or their SPF is too permissive and their DMARC policy provides no enforcement.

---

## 27. Open CORS headers

*Based on 1,947,451 live domains — complete coverage.*

| Signal | Count | Share of live |
|--------|-------|---------------|
| `Access-Control-Allow-Origin: *` | 28,891 | 1.5% |

**28,891 .ch domains broadcast an open CORS policy**, meaning any website can make authenticated cross-origin requests to them. `*` on endpoints that also set cookies or handle sensitive data creates cross-site data exfiltration risk.

---

## 28. DNS hygiene

*Based on 2,549,281 domains — complete coverage.*

| Signal | Count | Share of total |
|--------|-------|----------------|
| Wildcard DNS enabled (`*.domain` resolves) | 771,104 | 30.2% |
| No CAA record (any CA may issue) | 2,511,838 | 98.5% |
| No MX but publishes SPF | 350,229 | 13.7% |

**98.5% of .ch domains have no CAA record**, leaving certificate issuance unrestricted — any CA in the world can issue a certificate for those domains without the domain owner's consent. **30% enable wildcard DNS**, which broadens the attack surface for subdomain takeovers. **350,000 domains publish SPF records but have no MX**, likely holdovers from migrated mail infrastructure.

---

## 29. Zone transfer (AXFR) leaks

*Based on 394,928 discovered subdomains across 234,062 parent domains.*

| Metric | Count |
|--------|-------|
| Total subdomains discovered | 394,928 |
| Subdomains via AXFR (zone transfer) | 164,117 |
| Parent domains leaking via AXFR | 14,316 |
| Subdomains via MX/NS record harvest | 230,709 |
| Subdomains via Certificate Transparency | 102 |

**14,316 .ch domains allow unauthenticated DNS zone transfers (AXFR)**, exposing their complete internal subdomain map to any querying host. The single largest AXFR leak exposes 23,850 subdomains from one ISP-scale domain. The next four largest expose between 1,200 and 3,647 subdomains each.

The scale of AXFR leakage has grown significantly: 14,316 leaking domains (up from 2,300 in earlier measurements), with 164,117 subdomains exposed via zone transfer alone.

---

## 30. Most common open ports beyond 80/443

*Based on 1,633,972 distinct domains with port scan data.*

| Port  | Service           | Open on (domains) | Notes |
|-------|-------------------|-------------------|-------|
| 21    | FTP               |   688,489         | Plaintext file transfer |
| 22    | SSH               |   430,272         | Remote access |
| 8443  | HTTPS alternate   |   340,464         | Admin panels / proxies |
| 587   | SMTP submission   |   335,755         | Mail sending |
| 3306  | MySQL             |   313,472         | See §18 |
| 8080  | HTTP alternate    |   117,060         | Dev/proxy panels |
| 445   | SMB/CIFS          |    87,292         | See §18 |
| 6443  | Kubernetes API    |     2,057         | High risk if unauthenticated |

**FTP (port 21) is open on 688,489 domains** — 42% of all scanned domains — making it by far the most common non-web service. FTP transmits credentials in cleartext. SSH (port 22) at 430K is expected for managed hosting but represents a large brute-force attack surface. **2,057 domains expose the Kubernetes API (6443)**, typically requiring authentication but representing a high-value target if misconfigured.

---

## 31. WordPress version currency

*Based on 3,475 WordPress installs with a detectable version (out of 376,098 total WordPress sites).*

| WordPress status | Count | Share of versioned |
|------------------|-------|--------------------|
| Current (6.8–6.9) | 2,668 | 76.8% |
| Minor outdated (6.0–6.7) | 501 | 14.4% |
| Major outdated (<6.0) | 245 | 7.1% |

Top versions: `6.9.4` (2,140), `6.8.5` (203), `6.9.1` (101), `6.7.5` (82).

**21.5% of versioned WordPress installs run outdated releases.** 56.6% of WP sites conceal their version entirely — the real outdated count is likely higher. With 376K WP installs representing the largest single technology surface in .ch, even a conservative outdated rate implies tens of thousands of unpatched sites.

---

## 32. CVE exposure at scale — maximum vulnerable population

*Dataset: 2,549,281 .ch domains. CVE catalog: 74 high-severity entries. These figures represent the **maximum exposed population** — domains running a technology to which at least one cataloged CVE applies. Treat all matches as "possibly vulnerable, requires verification."*

| Technology | .ch domains | CRITICAL CVEs | HIGH CVEs | Notes |
|---|---|---|---|---|
| Apache | ~682,000 | 39 | 1 | 38% of live .ch domains |
| nginx | ~516,000 | 0 | 3 | |
| WordPress | ~376,000 | 4 | 3 | 71% of CMS installs |
| PHP (with version) | ~109,000 | 9 | 1 | all exposed installs |
| PHP (EOL branch) | ~43,000 | 9 | 1 | EOL PHP 5.x–7.4 only |
| TYPO3 | ~26,000 | 2 | 1 | Strong in CH enterprise |
| Joomla | ~23,000 | 3 | 0 | |
| Drupal | ~10,000 | 4 | 0 | All CRITICAL |
| OpenSSL | ~7,800 | 1 | 2 | |

- **Apache has 39 CRITICAL CVEs in the catalog** and covers 682,000 .ch domains — the highest combined risk surface in the dataset.
- **43,000+ domains expose end-of-life PHP** (branches 5.x, 7.0–7.4), all of which have unpatched RCE-class CVEs in their version range.
- **Drupal has the highest CRITICAL ratio** — all four seeded CVEs are CRITICAL, including the widely-exploited Drupalgeddon2.
- **WordPress with 376K installs and 4 CRITICAL CVEs** is the largest managed-software attack surface in .ch.

**How matching works:** The scanner maintains a `cve_catalog` table seeded with 74 high-severity CVEs plus entries from the CISA Known Exploited Vulnerabilities (KEV) feed. Technologies are fingerprinted from `Server:` header, `X-Powered-By:` header, CMS body patterns, and TCP port banners. Matching is **version-unaware** — any domain running a covered technology is flagged regardless of installed version.

**Exclusions:** Cloudflare (181K), Wix/Pepyaka (103K), Squarespace (20K), and Vercel (10K) are intentionally excluded — operators of sites behind these platforms cannot patch the underlying infrastructure.

---

## 33. Sector risk benchmarks

*Based on 103,814 classified domains across 8 sectors. Benchmark computed via `risk_score` view.*

| Sector     | Domains | Risk score (mean) | HSTS adoption | DMARC coverage | DNSSEC signing |
|------------|---------|-------------------|---------------|----------------|----------------|
| Finance    |  13,761 |  66.6             | 55.4%         | 18.5%          | 36.8%          |
| Retail     |  38,230 |  66.2             | 58.8%         | 17.5%          | 37.8%          |
| Legal      |   8,539 |  65.2             | 53.5%         | 17.9%          | 42.4%          |
| Media      |   6,060 |  64.5             | 52.2%         | 18.9%          | 39.6%          |
| Pharma     |   3,296 |  64.9             | 52.4%         | 19.8%          | 34.0%          |
| Education  |  16,110 |  63.6             | 56.7%         | 17.8%          | 42.8%          |
| Healthcare |   9,925 |  62.1             | 54.2%         | 15.1%          | 39.6%          |
| Government |   7,893 |  61.9             | 60.5%         | 21.0%          | 40.7%          |

Risk score is 0–100 (higher = better). Government scores lowest despite leading on HSTS adoption, driven by DMARC weakness (79% of government domains have weak or absent DMARC enforcement). Finance leads on absolute score. Healthcare has the weakest DMARC coverage at 15.1% of classified domains.

---

## 34. DNS namespace concentration

*Based on 2,146,728 (domain, NS operator) pairs across 18,985 distinct operators.*

| Operator | Domains | Share | Cumulative |
|---|---|---|---|
| Hostpoint | 314,457 | 14.6% | 14.6% |
| Infomaniak (infomaniak.com) | 136,225 | 6.3% | 21.0% |
| Infomaniak (legacy) | 105,864 | 4.9% | 25.9% |
| cyon.ch | 72,060 | 3.4% | 29.3% |
| wixdns.net | 61,715 | 2.9% | 32.2% |
| GoDaddy | 54,348 | 2.5% | — |

**If Hostpoint's nameservers went offline, 14.6% of .ch domains would stop resolving.** Infomaniak appears under two operator names; combined it controls ~11.2% (242,089 domains). The top 3 distinct providers (Hostpoint + Infomaniak + cyon.ch) collectively serve **29.3% of all .ch domain-operator pairs** — a single incident at any one of them constitutes a national-scale DNS outage.

---

## 35. Fully offshored domains — foreign DNS and foreign hosting

*Domains with both a non-CH/EU NS operator jurisdiction AND a non-CH hosting IP.*

**207,977 .ch domains are fully offshored** — their DNS is controlled by a foreign (non-EU) operator and their web server is hosted outside Switzerland. This represents ~8.2% of all live .ch domains.

---

## 36. Hosting sovereignty by sector

*Share of classified domains with CH-hosted IP vs US-hosted IP (GeoLite2).*

| Sector | Domains | CH-hosted | US-hosted |
|---|---|---|---|
| Government | 6,887 | 75.1% | 6.7% |
| Education | 13,392 | 69.8% | 8.9% |
| Legal | 6,721 | 68.0% | 9.4% |
| Healthcare | 8,257 | 60.9% | 9.3% |
| Finance | 10,451 | 60.0% | 11.3% |
| Media | 4,696 | 59.1% | 7.7% |
| Retail | 30,563 | 51.0% | 7.0% |
| Pharma | 2,526 | 49.9% | 13.5% |

Government and education are the most domestically hosted sectors. **Pharma has the lowest Swiss-hosting rate at 49.9%** and the highest US exposure at 13.5%. Retail — the largest sector — has only half its domains on Swiss infrastructure.

---

## 37. US cloud infrastructure by sensitive sector

*Finance, government, and healthcare domains using Cloudflare, Vercel, or AWS (identified via Server: header).*

| Sector | Cloudflare | Vercel | AWS |
|---|---|---|---|
| Finance | 944 | 121 | 39 |
| Healthcare | 601 | 71 | 14 |
| Government | 273 | 26 | 14 |

**944 Swiss finance domains and 601 healthcare domains route through Cloudflare** — a US-incorporated company subject to US legal process. These figures are a lower bound; domains behind Cloudflare often suppress or rewrite the Server: header.

---

## 38. Database port exposure by sector

*Open database ports (MySQL 3306, PostgreSQL 5432, Redis 6379, Elasticsearch 9200, MongoDB 27017) per classified sector.*

| Sector | MySQL | PostgreSQL | Redis | Elasticsearch | MongoDB | Total domains |
|---|---|---|---|---|---|---|
| Retail | 5,102 | 427 | 34 | 35 | 23 | 38,230 |
| Education | 2,967 | 97 | 5 | 14 | 6 | 16,110 |
| Finance | 1,723 | 97 | 34 | 37 | 20 | 13,761 |
| Healthcare | 1,666 | 92 | 18 | 18 | 5 | 9,925 |
| Legal | 1,598 | 37 | 1 | 0 | 2 | 8,539 |
| Government | 1,488 | 82 | 0 | 2 | 2 | 7,893 |
| Media | 763 | 71 | 10 | 9 | 3 | 6,060 |
| Pharma | 329 | 40 | 7 | 7 | 2 | 3,296 |

**Finance has 37 Elasticsearch instances and 34 Redis instances exposed** — both commonly run unauthenticated. Healthcare exposes 1,666 MySQL ports. Government exposes zero Redis (only sector to do so) but 1,488 MySQL and 82 PostgreSQL.

---

## 39. Email spoofing exposure by sector

*Based on classified domains with email_security data.*

| Sector | SPF % | DMARC % | DMARC enforced % | Fully spoofable % |
|---|---|---|---|---|
| Pharma | 51.0% | 25.9% | 19.8% | 48.5% |
| Finance | 48.6% | 25.0% | 18.5% | 48.5% |
| Media | 50.5% | 27.8% | 18.9% | 48.1% |
| Retail | 50.8% | 25.8% | 17.4% | 47.7% |
| Healthcare | 53.7% | 24.4% | 15.1% | 44.3% |
| Legal | 55.3% | 23.9% | 17.8% | 43.0% |
| Education | 57.9% | 27.8% | 17.7% | 40.0% |
| Government | 60.5% | 30.0% | 21.0% | 37.0% |

**Finance and pharma lead the spoofing risk table at 48.5% fully spoofable** — nearly half of classified finance domains can have their email impersonated without technical barriers. Government performs best at 37% but still has 79% of its DMARC-covered domains on weak or absent enforcement.

---

## 40. CISA Known Exploited Vulnerabilities (KEV) exposure

*Based on cve_matches with in_kev=1 across 2,549,281 domains.*

**977,666 .ch domains match at least one CISA KEV entry** — 38.4% of the entire dataset. The six technologies carrying KEV entries in the catalog:

| Technology | Domains with KEV match | Distinct CVEs |
|---|---|---|
| Apache | 682,438 | 40 |
| WordPress | 376,098 | 7 |
| PHP | 108,926 | 11 |
| Joomla | 23,202 | 3 |
| Drupal | 10,028 | 4 |
| OpenSSL | 7,805 | 3 |

Apache alone accounts for the majority — 682K domains match a technology with CISA-confirmed exploited vulnerabilities. The overlap between technologies means 977K unique domains carry at least one KEV match.

---

## 41. CVE exposure by technology

*All severity levels, distinct CVE IDs per technology across full dataset.*

| Technology | Domains affected | Distinct CVEs |
|---|---|---|
| Apache | 682,438 | 40 |
| nginx | 516,211 | 3 |
| WordPress | 376,098 | 7 |
| PHP | 108,926 | 11 |
| TYPO3 | 26,372 | 3 |
| Joomla | 23,202 | 3 |
| Drupal | 10,028 | 4 |
| OpenSSL | 7,805 | 3 |

Apache has the widest CVE catalog at 40 distinct CVEs covering 682K domains. nginx has only 3 CVEs but reaches 516K domains. PHP carries 11 CVEs including RCE-class entries for EOL branches.

---

## 42. Critical CVE exposure — finance and healthcare sectors

*CRITICAL-severity cve_matches for domains classified in finance or healthcare.*

| Sector | Technology | CRITICAL CVE domains |
|---|---|---|
| Finance | Apache | 3,945 |
| Finance | WordPress | 2,017 |
| Finance | PHP | 698 |
| Finance | Drupal | 258 |
| Finance | TYPO3 | 229 |
| Finance | OpenSSL | 178 |
| Finance | Joomla | 74 |
| Healthcare | Apache | 2,954 |
| Healthcare | WordPress | 2,575 |
| Healthcare | PHP | 631 |
| Healthcare | TYPO3 | 493 |
| Healthcare | Drupal | 133 |
| Healthcare | Joomla | 114 |
| Healthcare | OpenSSL | 27 |

**3,945 finance domains and 2,954 healthcare domains run Apache with at least one CRITICAL CVE match.** Healthcare has proportionally more TYPO3 exposure (493 domains, 7.3% of classified healthcare) than finance (229, 1.7%). These are maximum-exposed populations — version-level verification required to confirm vulnerability.

---

## 43. Domains with the highest CVE count

*Domains matching the most distinct CVE IDs (combination of Apache + PHP + OpenSSL + WordPress stacks).*

The maximum observed CVE count is **61 distinct CVEs** per domain — reached by domains running Apache + PHP + OpenSSL + WordPress simultaneously. At least 10 domains carry this maximum.

---

## 44. Sectors with most domains scoring below 50/100

*Share of classified domains with risk_score < 50.*

| Sector | Domains | Below 50 | % below 50 |
|---|---|---|---|
| Healthcare | 9,925 | 2,672 | 26.9% |
| Government | 7,893 | 2,022 | 25.6% |
| Education | 16,110 | 3,853 | 23.9% |
| Legal | 8,539 | 1,789 | 21.0% |
| Media | 6,060 | 1,214 | 20.0% |
| Pharma | 3,296 | 653 | 19.8% |
| Retail | 38,230 | 6,549 | 17.1% |
| Finance | 13,761 | 2,177 | 15.8% |

**Healthcare and government have the worst tail risk** — more than 1 in 4 classified domains scores below the midpoint. Finance performs best despite having the highest absolute risk score mean, suggesting a bimodal distribution.

---

## 45. Government vs retail — full security flag comparison

| Flag | Government | Retail |
|---|---|---|
| HTTPS final URL | 86.0% | 69.2% |
| HSTS | 38.0% | 27.7% |
| DNSSEC | 40.7% | 37.8% |
| SPF present | 60.5% | 50.8% |
| DMARC enforced | 21.0% | 17.4% |
| X-Frame-Options | 27.3% | 29.3% |
| CSP | 9.3% | 14.6% |

Government leads retail on every metric except **X-Frame-Options** and **CSP**. The CSP gap is notable: retail at 14.6% vs government at 9.3% — retail's higher e-commerce and Shopify/platform adoption likely drives this. Government's HTTPS rate of 86% is the highest of any sector but still leaves 14% of government domains serving content over plain HTTP.

---

## 46. Security header adoption by sector

*Share of classified domains with each header present (all classified, not just live).*

| Sector | HSTS | CSP | X-Frame-Options | XCTO | None of above |
|---|---|---|---|---|---|
| Legal | 23.6% | 6.0% | 19.1% | 18.5% | 61.6% |
| Media | 27.5% | 8.7% | 19.9% | 23.0% | 58.3% |
| Pharma | 30.6% | 9.5% | 18.8% | 22.5% | 58.0% |
| Finance | 29.0% | 12.7% | 24.5% | 22.2% | 57.7% |
| Healthcare | 31.2% | 7.7% | 18.4% | 24.3% | 55.9% |
| Education | 29.9% | 7.3% | 19.6% | 28.0% | 54.5% |
| Retail | 27.7% | 14.6% | 29.3% | 27.8% | 48.2% |
| Government | 38.0% | 9.3% | 27.3% | 33.8% | 47.8% |

**Legal is the weakest sector — 61.6% of legal domains send zero security headers.** Pharma and finance follow at ~58%. Government performs best at 47.8% with no headers, but that still means nearly half of all government domains are completely unprotected at the HTTP layer.

---

## 47. CMS popularity by sector

*Top CMS per sector among classified domains with a detected CMS.*

| Sector | #1 CMS | Share | #2 CMS | Share |
|---|---|---|---|---|
| Healthcare | WordPress | 38.1% | Apache (raw) | 18.6% |
| Government | WordPress | 35.0% | nginx (raw) | 19.9% |
| Education | WordPress | 34.6% | nginx (raw) | 22.9% |
| Legal | WordPress | 34.9% | Apache (raw) | 23.4% |
| Pharma | WordPress | 34.5% | Apache (raw) | 29.2% |
| Retail | Apache (raw) | 29.5% | WordPress | 27.1% |
| Finance | Apache (raw) | 34.3% | WordPress | 26.4% |
| Media | Apache (raw) | 28.7% | WordPress | 28.4% |

WordPress dominates as the top CMS in 5 of 8 sectors. Finance and media are the only sectors where raw Apache deployments edge out WordPress. **TYPO3 is notable in healthcare (7.3%) and government (5.6%)**, consistent with its strong adoption in German-speaking enterprise and public-sector environments.

---

## 48. TLS key inventory — no sub-2048-bit RSA found

*Based on 1,158,482 domains with status='ok' TLS scans.*

| Algorithm | Key size | Domains |
|---|---|---|
| RSA | 2048 | 844,699 |
| RSA | 3072 | 5,831 |
| RSA | 4096 | 129,671 |
| RSA | 8192 | 1 |
| ECDSA P-256 | 256 | 164,373 |
| ECDSA P-384 | 384 | 13,907 |

**No RSA key below 2048 bits was found in the entire dataset.** The 2048-bit floor is universal across .ch TLS deployments. There is one RSA-8192 certificate — notably oversized. ECDSA (P-256 + P-384) covers 15.4% of all certificates. Expired and self-signed certificate flags are not populated by the current scanner.

---

## 49. TLS without CAA — certificate issuance unrestricted

*Domains with a valid TLS certificate but no CAA DNS record restricting which CA may issue.*

| Condition | Count |
|---|---|
| Active TLS + no CAA record | 1,137,037 |
| Active TLS + CAA record present | 21,445 |

**1,137,037 .ch domains have a live TLS certificate but publish no CAA record** — 98.2% of all TLS-enabled domains. Without CAA, any CA in the world may issue a certificate for these domains without the owner's consent, leaving them exposed to certificate misissuance. Only 21,445 domains — 1.8% — restrict issuance via CAA.

---
