# CVE Matching — How It Works and What We Found

*Dataset: 2,549,281 .ch domains*
---

## Exposure Stats in the .ch Dataset

These figures represent the **maximum exposed population** — domains running a technology to which at least one cataloged CVE applies. Actual vulnerable count depends on software version, which is not yet compared.

| Technology | .ch domains | CRITICAL CVEs | HIGH CVEs | Notes |
|---|---|---|---|---|
| Apache | ~682,000 | 3 | 1 | 38% of live .ch domains |
| nginx / OpenResty | ~605,000 | 0 | 3 | Includes ~35K OpenResty via alias |
| WordPress | ~376,000 | 1 | 3 | 71% of CMS installs |
| PHP (EOL branch) | ~43,000 | 2 | 1 | EOL PHP 5.x–7.4 only |
| LiteSpeed | ~35,000 | 1 | 2 | Previously uncovered |
| Plesk | ~15,000 | 1 | 0 | Via `X-Powered-By: PleskLin` |
| Microsoft IIS | ~16,500 | 3 | 0 | Previously uncovered |
| TYPO3 | ~26,000 | 2 | 1 | Strong in CH enterprise |
| Joomla | ~23,000 | 2 | 0 | |
| ASP.NET | ~12,000 | 0 | 2 | Previously uncovered |
| Drupal | ~10,000 | 3 | 0 | All CRITICAL |

### Key findings

- **Apache and nginx together cover 72% of live .ch domains** and have cataloged CVEs. Even if only a fraction run unpatched versions, the absolute numbers are large.
- **43,000+ domains expose end-of-life PHP** (branches 5.x, 7.0–7.4), all of which have unpatched RCE-class CVEs in their version range.
- **LiteSpeed (35K), IIS (16.5K), Plesk (15K), and ASP.NET (12K)** were previously unmatched. Adding coverage for these four technologies exposes ~79,000 additional domains to CVE matching.
- **Drupal has the highest CRITICAL ratio** in the catalog — all three seeded CVEs are CRITICAL 9.8, including the widely-exploited Drupalgeddon2.
- **IIS is the highest-risk newly-added technology**: all three seeded CVEs are CRITICAL 9.8, one (CVE-2017-7269) is in the CISA KEV and targets IIS 6.0 which is still detectable in the dataset.

---

## How CVE Matching Works

### CVE Catalog

The scanner maintains a `cve_catalog` table populated from two sources:

**Hardcoded seed CVEs** — 34 hand-picked, high-severity CVEs covering technologies prevalent in the .ch dataset. Each entry records the technology name, CVE ID, severity, CVSS score, affected version range, and a summary. These are always present regardless of network access.

**CISA Known Exploited Vulnerabilities (KEV) feed** — fetched from `cisa.gov` on each `update-cves` run. Only entries matching covered technologies are imported (marked `in_kev = 1`). KEV status is a strong signal: these are vulnerabilities confirmed to be actively exploited in the wild, not just theoretical.

### Technology Detection

The scanner fingerprints technologies from three HTTP response fields and TCP port banners:

| Field | Examples detected |
|---|---|
| `Server:` header | Apache, nginx, OpenResty, LiteSpeed, Microsoft-IIS |
| `X-Powered-By:` header | PHP version, ASP.NET, PleskLin/PleskWin |
| CMS fingerprint | WordPress, Drupal, Joomla, TYPO3 (via body pattern matching) |
| Port banner (port 22) | OpenSSH (e.g. `SSH-2.0-OpenSSH_8.9`) |
| Port banner (ports 25, 587) | Postfix (e.g. `220 host ESMTP Postfix`), Exim (e.g. `220 host Exim 4.96`) |


The port + keyword combination prevents cross-technology false matches (e.g. an SMTP banner containing "postfix" will not match OpenSSH CVEs).

Matching is conservative and **version-unaware**: if a domain runs WordPress and a WordPress CVE exists in the catalog, it is flagged — regardless of the installed version. This avoids false negatives (missing a vulnerable site because version parsing failed) at the cost of some false positives (flagging a patched version). Operators should verify actual versions before acting on matches.

### Covered Technologies

| Technology | Detection field | .ch domain population |
|---|---|---|---|
| WordPress | `cms` | ~376,000 |
| TYPO3 | `cms` | ~26,000 |
| Joomla | `cms` | ~23,000 |
| Drupal | `cms` | ~10,000 |
| Apache | `Server:` | ~682,000 |
| nginx / OpenResty | `Server:` + alias | ~605,000 |
| LiteSpeed | `Server:` | ~35,000 |
| Microsoft IIS | `Server:` | ~16,500 |
| PHP | `X-Powered-By:` | ~107,000 (with version) |
| ASP.NET | `X-Powered-By:` | ~12,000 |
| Plesk | `X-Powered-By:` | ~15,000 |

---

## Limitations

- **Version-unaware**: matching flags any domain running a technology regardless of installed version. The affected version ranges are stored in `cve_catalog.affected_from`/`affected_to` but are not yet compared. Treat all matches as "possibly vulnerable, requires verification."
- **Header-dependent**: ~9% of live domains have no `Server:` header; ~91% lack `X-Powered-By`. Many more installations exist than are detected.
- **SaaS exclusions**: Cloudflare (181K), Wix/Pepyaka (103K), Squarespace (20K), and Vercel (10K) are intentionally excluded — operators of sites behind these platforms cannot patch the underlying infrastructure, so matches would only create noise.
- **KEV severity override**: KEV-sourced entries default to severity `CRITICAL`. This may not match the official CVSS score for every entry.

---

## Future CVE Coverage: Port/Service Banner Expansion

The `risk_score` view already flags ports 3306, 5432, 6379, 9200, 27017, 11211, and 2375 as `exposed_db_port` (−10 pts) and 3389, 445, 23, 5900 as `exposed_risky_port` (−10 pts). These are binary presence signals — they do not identify which software or version is running, so no CVE can be attached. The services behind these ports carry some of the highest-severity publicly-known CVEs (CVSS 9.8–10.0), several in the CISA KEV catalog.

Expanding to CVE-level matching requires first solving a banner capture problem per service, then seeding the catalog.

### Banner capture constraints

| Port | Service | Server speaks first? | Capture approach |
|---|---|---|---|
| 21 | FTP (ProFTPD / vsftpd) | Yes — `220 ProFTPD 1.3.6 Server ...` | Add to `BANNER_PORTS`; `grab_banner` works as-is |
| 3306 | MySQL / MariaDB | Yes — greeting embeds ASCII version string | Add to `BANNER_PORTS`; version readable in first line |
| 5432 | PostgreSQL | Yes — binary `AuthenticationRequest` packet | Binary; needs protocol-aware parsing, skip for now |
| 6379 | Redis | No | Send `INFO server\r\n`; parse `redis_version:x.y.z` |
| 9200 | Elasticsearch | No | Send `GET / HTTP/1.0\r\n\r\n`; parse JSON `version.number` |
| 27017 | MongoDB | No | Binary BSON `isMaster`; skip for now |
| 11211 | Memcached | No | Send `version\r\n`; parse `VERSION x.y.z` |
| 2375 | Docker API | No | Send `GET /version HTTP/1.0\r\n\r\n`; parse JSON `Version` |
| 3389 | RDP | No readable banner | Match by port presence only |

### CVE candidates

**FTP / ProFTPD (port 21)**

| CVE | Severity | CVSS | Description |
|---|---|---|---|
| CVE-2015-3306 | CRITICAL | 10.0 | mod_copy unauthenticated arbitrary file read/write (ProFTPD < 1.3.6) — in CISA KEV |
| CVE-2019-12815 | CRITICAL | 9.8 | mod_copy arbitrary file copy without auth (ProFTPD < 1.3.6b) |
| CVE-2011-4130 | CRITICAL | 9.0 | Use-after-free in response pool (ProFTPD < 1.3.3g) |

Detection: banner contains `proftpd` or `vsftpd` or `filezilla server`.

**MySQL / MariaDB (port 3306)**

| CVE | Severity | CVSS | Description |
|---|---|---|---|
| CVE-2016-6662 | CRITICAL | 9.8 | Config file injection → RCE as root (MySQL < 5.7.15, MariaDB < 10.1.17) |
| CVE-2016-6664 | HIGH | 7.0 | Privilege escalation via unsafe file handling (same range) |
| CVE-2012-2122 | HIGH | 7.5 | Auth bypass via timing attack on `memcmp` (many versions) |
| CVE-2023-21980 | CRITICAL | 9.8 | Optimizer RCE (MySQL ≤ 8.0.32) |

Detection: MySQL banner embeds version verbatim — `5.7.39-log`, `8.0.32`, `10.6.12-MariaDB`. Match `mysql` or `mariadb` in banner.

**Redis (port 6379)**

| CVE | Severity | CVSS | Description |
|---|---|---|---|
| CVE-2022-0543 | CRITICAL | 10.0 | Lua sandbox escape → arbitrary code execution (Debian/Ubuntu Redis < 6.0.16) |
| CVE-2021-32762 | CRITICAL | 9.8 | Heap overflow in integer handling (< 6.2.6) |
| CVE-2021-32687 | HIGH | 8.8 | Integer overflow via intset type (< 6.2.6) |
| CVE-2021-29477 | HIGH | 8.8 | Integer overflow in STRALGO LCS (< 6.2.4) |

Detection: send `INFO server\r\n`, parse `redis_version:` line. Requires active probe.

**Elasticsearch (port 9200)**

| CVE | Severity | CVSS | Description |
|---|---|---|---|
| CVE-2015-1427 | CRITICAL | 9.8 | Groovy sandbox escape RCE (< 1.6.1) — in CISA KEV |
| CVE-2014-3120 | CRITICAL | 9.8 | MVEL/MVFLEX sandbox escape RCE (< 1.2) — in CISA KEV |
| CVE-2021-22145 | MEDIUM | 6.5 | Sensitive info disclosure in error messages (< 7.14.0) |

Detection: `GET / HTTP/1.0\r\n\r\n`, parse `version.number` from JSON. Requires active probe.

**Memcached (port 11211)**

| CVE | Severity | CVSS | Description |
|---|---|---|---|
| CVE-2016-8705 | CRITICAL | 9.8 | RCE via binary protocol `update` command (< 1.4.33) |
| CVE-2016-8706 | HIGH | 8.1 | Integer overflow in `sasl_auth` (< 1.4.33) |
| CVE-2018-1000115 | MEDIUM | 5.3 | UDP amplification DDoS (1.5.5) |

Detection: send `version\r\n`, parse `VERSION x.y.z`. Requires active probe.

**Docker API (port 2375)**

Open unauthenticated Docker API is itself a CRITICAL finding — trivial container escape to host root. CVE matching adds report completeness. Also consider a dedicated `exposed_docker_api` risk flag (more severe than generic `exposed_db_port`).

| CVE | Severity | CVSS | Description |
|---|---|---|---|
| CVE-2019-5736 | HIGH | 8.6 | runc container escape overwriting host binary (Docker < 18.09.2) — in CISA KEV |
| CVE-2014-9357 | CRITICAL | 10.0 | RCE via crafted Docker image (Docker < 1.3.2) |

Detection: `GET /version HTTP/1.0\r\n\r\n`, parse `Version` from JSON. Requires active probe.

**RDP (port 3389)** — already tracked as `exposed_risky_port`

RDP does not expose a readable software version. Match on port presence alone — justified by severity.

| CVE | Severity | CVSS | Description |
|---|---|---|---|
| CVE-2019-0708 | CRITICAL | 9.8 | BlueKeep — pre-auth wormable RCE (Windows XP–Server 2008 R2) — in CISA KEV |
| CVE-2019-1181 | CRITICAL | 9.8 | DejaBlue — pre-auth RCE (Windows 7–Server 2019) — in CISA KEV |
| CVE-2019-1182 | CRITICAL | 9.8 | DejaBlue variant — in CISA KEV |

### Implementation path

**Phase 1 — passive banner wins (minimal change)**
1. Add ports 21 and 3306 to `BANNER_PORTS` in `src/shared.rs`
2. Seed FTP and MySQL/MariaDB CVEs in `SEED_CVES`
3. Extend `run_cve_matching` UNION branch for port 21 (`proftpd`/`vsftpd`) and port 3306 (`mysql`/`mariadb`)
4. Seed RDP CVEs; add port-presence UNION branch for port 3389 → `rdp` technology

No protocol changes required. FTP and MySQL send readable text banners immediately on connect.

**Phase 2 — active probing**
Add a `probe_banner(ip, port, probe: &[u8]) -> Option<String>` helper to `src/ports_scan.rs` that sends a fixed payload before reading. Wire probes for Redis (6379), Elasticsearch (9200), Memcached (11211), Docker API (2375). Results stored in the existing `banner` column — no schema change.

**Phase 3 — risk score refinement**
Extract Docker API (2375) out of the generic `exposed_db_port` flag into a dedicated `exposed_docker_api` flag in the `risk_score` view with a higher deduction (−15 or −20), reflecting the trivial-RCE nature of an unauthenticated Docker socket.

### Priority

| Service | Effort | Top CVE severity | Recommendation |
|---|---|---|---|
| FTP port 21 | Minimal | CRITICAL 10.0 (KEV) | Phase 1 |
| MySQL/MariaDB port 3306 | Minimal | CRITICAL 9.8 | Phase 1 |
| RDP CVE attach | Small | CRITICAL 9.8 (KEV) | Phase 1 |
| Redis active probe | Medium | CRITICAL 10.0 | Phase 2 |
| Elasticsearch active probe | Medium | CRITICAL 9.8 (KEV) | Phase 2 |
| Memcached active probe | Medium | CRITICAL 9.8 | Phase 2 |
| Docker API probe + risk flag | Medium | HIGH 8.6 (KEV) | Phase 2 |
| PostgreSQL | High (binary protocol) | — | Skip |
| MongoDB | High (BSON protocol) | — | Skip |
