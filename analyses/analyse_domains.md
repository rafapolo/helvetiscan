# Preliminary / Domain Analysis 
*Dataset: 2,549,282 domains — data/domains.duckdb*

---

## 1. How many .ch domains are alive vs dead?

| Status  | Count     | Share |
|---------|-----------|-------|
| error   | 1,554,866 | 61.0% |
| ok      |   638,652 | 25.1% |
| pending |   355,764 | 14.0% |

Only **1 in 4** registered .ch domains serves a live HTTP response. Over 60% fail outright. 355,764 have not yet been scanned.

---

## 2. What are the most common ways a .ch domain fails?

| Error kind  | Count     | Share |
|-------------|-----------|-------|
| timeout     | 859,916   | 55.3% |
| dns         | 680,691   | 43.8% |
| tls_failed  |   4,976   |  0.3% |
| refused     |   4,685   |  0.3% |
| other       |   4,598   |  0.3% |

Two failure modes dominate: **connection timeouts** (parked/abandoned servers that accept TCP but never respond) and **DNS failures** (domains with no A record — registered but not deployed). Together they account for 99.1% of all failures.

---

## 3. What's the most popular web server software in Switzerland?

*Based on 566,419 domains with a `Server:` header (88.7% of live domains).*

| Server family     | Count   | Share |
|-------------------|---------|-------|
| Apache            | 211,709 | 37.4% |
| nginx / OpenResty | 183,434 | 32.4% |
| Cloudflare        |  61,747 | 10.9% |
| Other             |  47,068 |  8.3% |
| Pepyaka (Wix)     |  33,775 |  6.0% |
| LiteSpeed         |  13,144 |  2.3% |
| Squarespace       |   7,331 |  1.3% |
| Microsoft IIS     |   5,006 |  0.9% |
| Vercel            |   3,205 |  0.6% |

**Apache** leads, but **nginx** is close behind. Cloudflare proxies ~11% of all live .ch sites. Pepyaka (Wix's proprietary server) at 6% reflects strong Wix adoption. Microsoft IIS is a distant 8th at under 1%.

---

## 4. What's the most common CMS running on .ch?

*Based on 10,582 domains with a recognized CMS (1.7% of live domains).*

| CMS       | Count | Share |
|-----------|-------|-------|
| WordPress | 8,013 | 75.7% |
| Wix       | 1,489 | 14.1% |
| Joomla    |   457 |  4.3% |
| TYPO3     |   427 |  4.0% |
| Drupal    |   196 |  1.9% |

**WordPress is overwhelmingly dominant** at 3 in 4 identifiable CMS installs. TYPO3 — popular in German-speaking enterprise environments — edges out Drupal. Note: CMS fingerprinting covers only sites that expose telltale markers; the true total is higher.

---

## 5. How many .ch domains leak their software version in HTTP headers?

| Metric                              | Count  | Share of live |
|-------------------------------------|--------|---------------|
| `X-Powered-By` header present       | 57,359 | 9.0%          |
| PHP exposing full version           | 35,668 | 5.6%          |
| PHP 5.x (EOL since 2018)            |  4,772 | —             |
| PHP 7.0–7.3 (EOL since 2022)        |  2,215 | —             |
| PHP 7.4 (EOL Dec 2022)              |  7,012 | —             |
| **Total EOL PHP installs**          | **13,999** | **2.2%**  |

Top `X-Powered-By` values: `PHP/7.4.33` (6,286), `PHP/8.3.30` (6,195), `PleskLin` (4,940), `PHP/5.6.40` (3,028).

**~14,000 live .ch sites advertise end-of-life PHP versions** in their response headers, making them trivially fingerprints for exploit targeting.

---

## 6. What does the average .ch response time look like? 

*Based on 638,652 successful scans from a 5G connection.*

| Percentile | Response time |
|------------|---------------|
| min        |        32 ms  |
| p25        |     1,241 ms  |
| median     |     8,397 ms  |
| p75        |    20,950 ms  |
| p95        |    47,342 ms  |
| p99        |    90,518 ms  |
| max        |   179,406 ms  |
| mean       |    14,665 ms  |

The median of **8.4 seconds** is extremely slow — nearly all of this is scanner-side wait time from a single connection following redirects. The p95 at 47 seconds indicates many sites run on slow shared hosting or have very high latency.

**Slowest domains:** `3380.ch` (179s), `aesthee.ch` (160s), `4results.ch` (157s).

---

## 7. How many .ch domains redirect to a different domain entirely?

| Redirect type           | Count   | Share of live |
|-------------------------|---------|---------------|
| Same-domain final URL   | 376,924 | 59.0%         |
| Cross-domain redirect   | 261,728 | 41.0%         |

**41% of live .ch domains redirect to a completely different domain** — pointing to parking services, CDN edges, hosting redirectors, or brand consolidation (e.g. `example.ch` → `www.example.com`).

---

## 8. How many .ch websites have no title — parking pages or abandoned?

| Category             | Count  | Share of live |
|----------------------|--------|---------------|
| No `<title>` tag     | 89,299 | 14.0%         |
| Generic/default title| 13,576 |  2.1%         |
| **Total likely parked** | **102,875** | **16.1%** |

Over **1 in 6 live .ch domains** shows either no title or a generic placeholder — consistent with parking pages, default hosting pages, or abandoned installations.

---

## 9. How many distinct IPs host all live .ch domains?

**52,923 distinct IP addresses** serve 638,652 live domains.

That is an average of **12 domains per IP**, but the distribution is extremely skewed (see Q10). The actual median is far lower — most IPs host 1–2 domains while a handful of hosting providers concentrate tens of thousands.

---

## 10. Which single IP address hosts the most .ch domains?

| IP              | Domains hosted | Notes             |
|-----------------|----------------|-------------------|
| 217.26.48.101   | 30,790         | Hostpoint AG      |
| 128.65.195.180  | 11,161         | Swisscom  AG      |
| 185.230.63.107  |  9,972         | Wix Ltd           |
| 81.88.58.216    |  9,248         | Register S.p.A    |
| 217.26.63.20    |  9,199         | Hostpoint AG      |
| 162.159.128.70  |  8,454         | Cloudflare        |
| 3.33.130.190    |  8,316         | AWS Global Accel. |
| 84.16.66.164    |  6,659         |Infomaniak Network |
| 185.101.158.113 |  6,315         | Hosttech GmbH     |
| 185.230.63.171  |  6,159         | Wix.com Ltd.      |

**A single IP hosts 30,790 domains** — nearly 5% of all live .ch sites on one address. This illustrates extreme concentration in Swiss shared hosting, with the top 10 IPs accounting for ~106,000 domains (16.6% of all live .ch).

---

## 11. How many .ch domains still run on end-of-life PHP versions?

| PHP branch | Count  | EOL date     |
|------------|--------|--------------|
| PHP 5.x    |  4,772 | Dec 2018     |
| PHP 7.0–7.3|  2,215 | Dec 2019–22  |
| PHP 7.4    |  7,012 | Nov 2022     |
| **Total EOL** | **13,999** |         |
| PHP 8.x (supported) | 21,576 | —   |

**14,000 live .ch domains advertise EOL PHP** in their `X-Powered-By` header. PHP 7.4 (EOL Nov 2022) is the single largest EOL cohort. These versions no longer receive security patches and are exposed to all post-EOL CVEs.

---

## 12. How many unique .ch websites exist vs clones sharing the same body?

> "only ~18% have any distinct page body at all"

| Metric                              | Count   |
|-------------------------------------|---------|
| Domains with body hash              | 624,606 |
| Unique body hashes                  | 458,243 |
| Truly unique bodies (hash seen once)| 435,431 |
| Domains on a shared body            | 189,175 |
| Distinct shared hashes              |  22,812 |
| Domains with no body hash           |  14,046 |

**189,175 domains** (30.3%) share their body hash with at least one other domain — these are clones, mirrors, or parking pages with identical content. There are 22,812 distinct "clone groups".

| Body hash (truncated) | Sites sharing | Title                                              |
|-----------------------|---------------|----------------------------------------------------|
| `bbd490ba...`         | 41,478        | "Hello, this domain has been purchased at Hostpoint" |
| `6d25a865...`         |  7,145        | "Seite nicht verfügbar"                            |
| `b8115086...`         |  1,818        | "Error 404 (Not Found)!!1" *(Google 404)*          |

The dominant cluster — **41,478 Hostpoint parking pages** — accounts for 22% of all cloned domains on its own. The two 12k+ clusters with no title are likely blank or minimal holding pages from other registrars. The 403/404 clusters reveal thousands of domains that respond successfully but serve error bodies.



---

## 13. Which WordPress version is most common — and how many are outdated?

*Based on 3,475 WordPress installs with a detectable version (out of 8,013 total WordPress sites).*

| WordPress status | Count | Share of versioned |
|------------------|-------|--------------------|
| Current (6.8–6.9)| 2,668 | 76.8%              |
| Minor outdated (6.0–6.7) | 501 | 14.4%        |
| Major outdated (<6.0) | 245 |  7.1%           |

Top versions: `6.9.4` (2,140), `6.8.5` (203), `6.9.1` (101), `6.7.5` (82).

**21.5% of versioned WordPress installs are running outdated releases.** With 4,538 installs concealing their version (56.6%), the real outdated count is likely higher.

---

## 14. How many .ch domains redirect from HTTP to HTTPS vs stay on HTTP?

*Scanner starts from `http://` and follows redirects. `final_url` shows the landing protocol.*

| Protocol outcome       | Count   | Share of live |
|------------------------|---------|---------------|
| Ends on HTTPS          | 467,353 | 73.2%         |
| Stays on HTTP          | 171,299 | 26.8%         |

**73% of live .ch domains serve their final content over HTTPS**, meaning they redirect or run natively on HTTPS. However, **171,299 sites still deliver content over plain HTTP** — no encryption, no HSTS — exposing user traffic to interception.
