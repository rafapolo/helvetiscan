# Domain Analysis
*Dataset: 2,549,281 domains — data/domains.db*

Key findings:
  - §01: 1,947,451 of 2,549,281 domains (76.4%) serve a live HTTP response; 1 in 4 is dead
  - §02: DNS failure accounts for 74.9% of errors (450,916 domains) — registered but no A record
  - §03: HTTP 200+206 combined cover 84.6% of live responses; 93,814 (4.8%) actively block the scanner
  - §04: Apache 38.3% and nginx 34.0% cover 72% of .ch web servers; Cloudflare proxies 10.2%
  - §05: WordPress holds 71.5% of identifiable CMS installs (376,098 domains, ~19% of all live .ch)
  - §06: 43,473 live sites advertise EOL PHP — 40.6% of 107K installs with version exposed; PHP 7.4.33 most common
  - §07: Median response time 1,102 ms; p99 reaches 10,774 ms; slowest domain times out at 106 s
  - §08: 430,233 live domains (22.1%) redirect cross-domain — parking services, CDN edges, or brand consolidation
  - §09: 245,047 domains (12.6% of live) flagged as parked or abandoned — no title or generic placeholder
  - §10: 130,937 IPs host 1,816,085 live domains — mean 13.9 per IP, heavily skewed toward shared hosting
  - §11: Single IP (Hostpoint 217.26.48.101) hosts 133,425 domains (6.9%); top 10 IPs cover ~21% of live .ch
  - §12: 712,945 domains (36.6%) share a page body hash; 147,983 share a single Hostpoint parking page
  - §13: 1,397,073 domains (71.7%) end on HTTPS; 550,378 (28.3%) still serve over plain HTTP
  - §14: 40.6% of .ch domains hosted abroad; Germany leads at 17.3%, US at 11.6%
  - §15: 955,764 domains (49.1%) send zero security headers; only 30.2% use HSTS despite 71.7% serving HTTPS
  - §16: TLS 1.3 at 92.9%; Let's Encrypt issues 83.1% of certs; 60,171 expire within 30 days [59.5% scanned]
  - §17: 43.3% of scanned domains fully spoofable; DKIM only 6.8%; 24.7% of DMARC adopters on p=none [36.2% scanned]
  - §18: 313,472 domains (16% of live) expose MySQL; 87,292 expose SMB; 1,742 expose Docker API [83.9% scanned]
  - §19: DNSSEC signed on 46.2% of scanned domains — above global averages [32.2% scanned]
  - §20: 86.7% of .ch hosting stays within Europe; North America (US cloud) accounts for 13.0%
  - §21: Top Swiss domestic hosting IPs (Hostpoint, Swisscom, Infomaniak)
  - §22: Largest foreign IP concentrations (Wix 77K, Register.it 35K, Shopify 15K)
  - §23: Domains in weak-jurisdiction countries (501 in RU/BY/IR/CN/SY)
  - §24: US cloud exposure via server header (Cloudflare 181K, Vercel 10K, AWS 6K = 10.1%)
  - §25: TLS key sizes (no RSA <2048; ECDSA at 15.4%; 1,091 certs expiring in 7 days)
  - §26: Email spoofing exposure (305K domains = 43.3% fully spoofable)
  - §27: Open CORS (*) on 28,891 domains
  - §28: DNS hygiene (98.4% no CAA, 33% wildcard, 86K no-MX-with-SPF)
  - §29: AXFR zone transfer leaks (2,300 parent domains, 27K subdomains exposed)
  - §30: Most common ports beyond 80/443 (FTP open on 688K = 42% of scanned)

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
| nginx / OpenResty |   605,029 | 34.0% |
| Cloudflare        |   181,448 | 10.2% |
| Other             |   126,975 |  7.1% |
| Pepyaka (Wix)     |   102,701 |  5.8% |
| LiteSpeed         |    35,038 |  2.0% |
| Squarespace       |    19,853 |  1.1% |
| Microsoft IIS     |    16,530 |  0.9% |
| Vercel            |     9,956 |  0.6% |

Apache leads at 38% with nginx close behind at 34%. Cloudflare proxies 10% of live .ch sites. Wix (Pepyaka) at 5.8% reflects strong hosted-platform adoption.

---

## 5. What's the most common CMS running on .ch? *(RESEARCH.md)*

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

## 6. How many .ch domains still run PHP, and which version? *(RESEARCH.md)*

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

Median of **1.1 seconds**. The p99 at 10.8 s flags slow shared-hosting tails.

**Slowest domains:** `tiger-cards.ch` (106 s), `tiertraining-angipinth.ch` (94 s), `tile-art-gmbh.ch` (92 s).

---

## 8. How many .ch domains redirect to a different domain entirely?

| Redirect type         | Count     | Share of live |
|-----------------------|-----------|---------------|
| Same-domain final URL | 1,517,218 | 77.9%         |
| Cross-domain redirect |   430,233 | 22.1%         |

**22% of live .ch domains redirect to a completely different domain** — parking services, CDN edges, or brand consolidation.

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

| IP              | Domains hosted | Notes              |
|-----------------|----------------|--------------------|
| 217.26.48.101   |    133,425     | Hostpoint AG       |
| 217.26.63.20    |     43,708     | Hostpoint AG       |
| 81.88.58.216    |     35,747     | Register S.p.A     |
| 185.230.63.107  |     35,031     | Wix Ltd            |
| 128.65.195.180  |     32,764     | Swisscom AG        |
| 84.16.66.164    |     29,854     | Infomaniak Network |
| 185.101.158.113 |     28,322     | Hosttech GmbH      |
| 162.159.128.70  |     28,171     | Cloudflare         |
| 185.230.63.171  |     21,538     | Wix.com Ltd.       |
| 185.230.63.186  |     21,107     | Wix.com Ltd.       |

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

| Body hash (truncated) | Sites sharing | Title                                                |
|-----------------------|---------------|------------------------------------------------------|
| `bbd490ba...`         |    147,983    | "Hello, this domain has been purchased at Hostpoint" |
| `459468d3...`         |     37,464    | *(no title)*                                         |
| `6d25a865...`         |     25,101    | "Seite nicht verfügbar"                              |
| `4a3a54aa...`         |     13,844    | "415 Unsupported Media Type"                         |
| `5290b851...`         |      8,554    | "403 Forbidden"                                      |

**147,983 Hostpoint parking pages** (7.6% of live .ch) share a single body hash — the largest clone group.

---

## 13. How many .ch domains redirect from HTTP to HTTPS?

| Protocol outcome  | Count     | Share of live |
|-------------------|-----------|---------------|
| Ends on HTTPS     | 1,397,073 | 71.7%         |
| Stays on HTTP     |   550,378 | 28.3%         |

**71.7% of live .ch domains** serve their final content over HTTPS. **550,000 sites still deliver content over plain HTTP**.

---

## 14. Where are .ch domains hosted? *(RESEARCH.md)*

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

## 15. HTTP security headers *(RESEARCH.md)*

*Based on 1,947,451 live domains — complete coverage.*

| Header                  | Count   | Share of live |
|-------------------------|---------|---------------|
| HSTS                    | 588,872 | 30.2%         |
| X-Content-Type-Options  | 470,434 | 24.2%         |
| X-Frame-Options         | 460,142 | 23.6%         |
| Content-Security-Policy | 149,180 |  7.7%         |
| **None of the above**   | 955,764 | **49.1%**     |

**49% of live .ch domains send zero security headers.** Only 30% use HSTS despite 72% serving HTTPS. CSP adoption at 7.7% is weakest. Of HSTS adopters: 162,455 include `includeSubDomains`, 82,989 are `preload`-eligible.

---

## 16. TLS certificate landscape **[preliminary — 59.5% scanned]**

*Based on 1,158,482 domains with a TLS scan (out of 1,947,451 live).*

**Protocol versions:**

| TLS version | Count     | Share  |
|-------------|-----------|--------|
| TLSv1.3     | 1,076,502 | 92.9%  |
| TLSv1.2     |    81,980 |  7.1%  |

TLS 1.0/1.1 appear extinct in the current sample. **93% of TLS-enabled .ch domains run TLS 1.3.**

**Certificate issuers:**

| CA             | Count   | Share  |
|----------------|---------|--------|
| Let's Encrypt  | 962,746 | 83.1%  |
| Other          | 145,022 | 12.5%  |
| DigiCert       |  25,477 |  2.2%  |
| Sectigo/Comodo |  19,465 |  1.7%  |
| ZeroSSL        |   4,126 |  0.4%  |
| SwissSign      |   1,270 |  0.1%  |

**Let's Encrypt issues 83% of all certificates.** SwissSign (Swiss national CA) covers only 1,270 domains. **60,171 certificates expire within 30 days.**

---

## 17. Email security posture *(RESEARCH.md)* **[preliminary — 36.2% scanned]**

*Based on 704,584 domains with email security data.*

| Signal                | Count   | Share  |
|-----------------------|---------|--------|
| SPF present           | 393,820 | 55.9%  |
| DMARC present         | 207,915 | 29.5%  |
| DKIM found            |  47,655 |  6.8%  |
| SPF too permissive    |  24,235 |  3.4%  |

Of domains with DMARC:

| DMARC policy  | Count  | Share of DMARC |
|---------------|--------|----------------|
| reject        | 89,572 | 43.1%          |
| quarantine    | 66,965 | 32.2%          |
| none          | 51,272 | 24.7%          |

**44% of scanned domains have no SPF record**, leaving them open to spoofing. Of those with DMARC, 24.7% are on `p=none` — monitoring only, no enforcement. Only 6.8% have a discoverable DKIM key.

---

## 18. Exposed ports — databases and dangerous services *(RESEARCH.md)* **[preliminary — 83.9% scanned]**

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

## 19. DNSSEC adoption *(RESEARCH.md)* **[preliminary — 32.2% scanned]**

*Based on 626,255 domains with DNS data.*

| Metric        | Count   | Share  |
|---------------|---------|--------|
| DNSSEC signed | 289,540 | 46.2%  |
| Not signed    | 336,715 | 53.8%  |

**46% of scanned .ch domains have DNSSEC signing** — high compared to global averages, likely driven by SWITCH actively promoting DNSSEC for .ch registrations.

---

## 20. Hosting sovereignty — continental breakdown *(RESEARCH.md)*

*Based on 1,739,441 live domains with IP geolocation data (89.3% of live domains).*

| Continent     | Count     | Share |
|---------------|-----------|-------|
| Europe        | 1,508,189 | 86.7% |
| North America |   225,275 | 13.0% |
| Asia-Pacific  |     3,277 |  0.2% |
| Other         |     2,700 |  0.2% |

**86.7% of .ch domain hosting stays within Europe.** The 13% North America share is nearly entirely US cloud services (Cloudflare, Wix US infrastructure, AWS, Vercel). Asia-Pacific and other jurisdictions combined represent under 0.4% of all live domains.

---

## 21. Swiss hosting providers — domestic dominance *(RESEARCH.md)*

*Top individual IPs where the hosting country resolves to Switzerland.*

| IP              | Domains hosted | Provider         |
|-----------------|----------------|------------------|
| 217.26.48.101   |    133,425     | Hostpoint AG     |
| 217.26.63.20    |     43,708     | Hostpoint AG     |
| 128.65.195.180  |     32,764     | Swisscom AG      |
| 84.16.66.164    |     29,854     | Infomaniak Network |
| 185.101.158.113 |     28,322     | Hosttech GmbH    |
| 185.67.193.93   |     11,085     | (CH provider)    |
| 92.43.216.100   |      8,040     | (CH provider)    |
| 185.117.169.155 |      5,202     | (CH provider)    |
| 5.148.169.160   |      4,570     | (CH provider)    |

Hostpoint AG alone accounts for the two largest domestic IPs — **177,133 domains (17.1% of Swiss-hosted)** on just two addresses.

---

## 22. Largest foreign IP concentrations *(RESEARCH.md)*

*Top individual IPs with country_code ≠ CH.*

| IP              | Country | Domains | Provider         |
|-----------------|---------|---------|------------------|
| 81.88.58.216    | IT      |  35,747 | Register S.p.A   |
| 185.230.63.107  | US      |  35,031 | Wix.com Ltd.     |
| 185.230.63.171  | US      |  21,538 | Wix.com Ltd.     |
| 185.230.63.186  | US      |  21,107 | Wix.com Ltd.     |
| 64.190.63.222   | DE      |  16,296 | (DE provider)    |
| 23.227.38.65    | CA      |  15,329 | Shopify           |
| 213.186.33.5    | FR      |  11,536 | OVH SAS           |
| 198.49.23.144   | US      |  10,470 | Squarespace       |
| 213.239.221.71  | DE      |   9,946 | Hetzner Online    |
| 18.197.248.23   | DE      |   8,259 | AWS eu-central-1  |

Wix concentrates **77,676 .ch domains across three US IPs**. The top 10 foreign IPs alone account for ~185K domains (~9.5% of all live .ch).

---

## 23. Domains in weak-jurisdiction countries *(RESEARCH.md)*

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

## 24. US cloud infrastructure exposure *(RESEARCH.md)*

*Share of live .ch domains served via major US cloud providers, identified by `Server:` header.*

| Provider   | Count   | Share of live |
|------------|---------|---------------|
| Cloudflare |  181,451 |  9.3%        |
| Vercel     |    9,956 |  0.5%        |
| AWS (ELB/S3)|   6,180 |  0.3%        |
| **Total**  | **197,587** | **10.1%** |

**10% of all live .ch domains route through US-based cloud infrastructure** identifiable via server headers alone. The real figure is higher since AWS CloudFront and similar services often suppress or replace the `Server:` header.

---

## 25. TLS certificate health **[preliminary — 59.5% scanned]**

*Based on 1,158,482 domains with status='ok' TLS scans.*

**Key size distribution:**

| Algorithm | Key size | Count   | Share  |
|-----------|----------|---------|--------|
| RSA       | 2048     | 844,699 | 72.9%  |
| ECDSA P-256 | 256    | 164,373 | 14.2%  |
| RSA       | 4096     | 129,671 | 11.2%  |
| ECDSA P-384 | 384    |  13,907 |  1.2%  |
| RSA       | 3072     |   5,831 |  0.5%  |

No RSA keys below 2048 bits were found — the 2048-bit floor appears universal in the current sample. ECDSA (P-256 + P-384) covers **15.4%** of certs, offering equivalent security with smaller key sizes.

**Certificates expiring within 7 days:** 1,091 (across the preliminary sample).

Expired and self-signed certificates surface in the `tls_failed` error class from §2 (30,925 domains) rather than as 'ok' TLS records — those domains never reach the certificate extraction stage.

---

## 26. Email spoofing exposure *(RESEARCH.md)* **[preliminary — 36.2% scanned]**

*Based on 704,584 domains with email security data.*

| Condition | Count   | Share of scanned |
|-----------|---------|------------------|
| No SPF AND no DMARC | 272,956 | 38.7% |
| Fully spoofable (no/permissive SPF + no/none DMARC) | 305,164 | 43.3% |
| SPF lookup limit exceeded | 10 | <0.1% |

**305,164 scanned domains (43.3%) can have their email impersonated without technical barriers** — either because they publish no SPF at all, or their SPF is too permissive and their DMARC policy provides no enforcement. SPF lookup limit overflows (which silently break SPF validation) affect only 10 domains in the current sample.

---

## 27. Open CORS headers *(RESEARCH.md)*

*Based on 1,947,451 live domains — complete coverage.*

| Signal | Count | Share of live |
|--------|-------|---------------|
| `Access-Control-Allow-Origin: *` | 28,891 | 1.5% |

**28,891 .ch domains broadcast an open CORS policy**, meaning any website can make authenticated cross-origin requests to them. While CORS is not a standalone critical issue, `*` on endpoints that also set cookies or handle sensitive data creates cross-site data exfiltration risk.

---

## 28. DNS hygiene *(RESEARCH.md)* **[preliminary — 32.2% scanned]**

*Based on 626,255 domains with DNS data.*

| Signal | Count | Share of scanned |
|--------|-------|------------------|
| Wildcard DNS enabled (`*.domain` resolves) | 208,049 | 33.2% |
| No CAA record (any CA may issue) | 616,160 | 98.4% |
| No MX but publishes SPF | 85,996 | 13.7% |

**98.4% of scanned .ch domains have no CAA record**, leaving certificate issuance unrestricted — any CA in the world can issue a certificate for those domains without the domain owner's consent. **33% enable wildcard DNS**, which broadens the attack surface for subdomain takeovers. **86,000 domains publish SPF records but have no MX**, likely holdovers from migrated mail infrastructure — the SPF protects a mail flow that no longer exists.

---

## 29. Zone transfer (AXFR) leaks *(RESEARCH.md)* **[preliminary — partial coverage]**

*Based on 62,724 discovered subdomains.*

| Metric | Count |
|--------|-------|
| Total subdomains discovered | 62,724 |
| Subdomains via AXFR (zone transfer) | 27,220 |
| Parent domains leaking via AXFR | 2,300 |

**2,300 .ch domains allow unauthenticated DNS zone transfers (AXFR)**, exposing their complete internal subdomain map to any querying host. The top leakers:

| Domain | Subdomains exposed |
|--------|-------------------|
| ajoie-net.ch | 3,647 |
| arcanite-infra.ch | 1,586 |
| abahost.ch | 1,190 |
| abaservices.ch | 488 |
| aeropers.ch | 284 |

**Top domains by total discovered subdomains** (all sources):

| Domain | Subdomains |
|--------|-----------|
| ajoie-net.ch | 3,647 |
| arcanite-infra.ch | 1,586 |
| abahost.ch | 1,190 |
| abaservices.ch | 488 |
| aeropers.ch | 284 |
| 21shops.ch | 240 |
| avarix.ch | 236 |
| arcanite.ch | 206 |

---

## 30. Most common open ports beyond 80/443 *(RESEARCH.md)* **[preliminary — 83.9% scanned]**

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
