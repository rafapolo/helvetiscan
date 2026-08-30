# Critical, Unverified, Remote-Exploitable CVEs

Snapshot from `data/domains.db`, restricted to CRITICAL severity, still missing a `cve_verifications`
row, and limited to technologies whose exploit class is genuinely unauthenticated/server-side
(WordPress, Joomla, TYPO3, Drupal, Apache, PHP, nginx, ProFTPD, Tomcat, IIS, Exchange, Craft CMS,
Express, Laravel, Elementor, PrestaShop, plus CVE-2024-6387 regreSSHion). OpenSSH's other CVEs are
excluded — they're client-side, auth-gated, enumeration/DoS-only, or noise from overly broad
"before 10.4" 2026 catalog entries that match almost the entire OpenSSH population regardless of
real exploitability.

**24 CVEs, 7,966 distinct domains.**

Remote status (checked 2026-07-15): the `verify-all --aggressive` screen session on the `finland`
VPS has finished (3.70M confirmed, 671k refuted, 2.56M unreachable; 44 domains confirmed via real
Apache path-traversal exploit). **That result has not been synced to local `data/domains.db` yet**
— local's last `checked_at` is 17:18, the remote run continued to 20:12. No export db was staged on
remote this time; syncing means exporting the delta and rsyncing it back, same as the earlier
`cve_verify_agg.db` pattern.

## Craft CMS (3,867 domains each — presence-only, no version data)

| CVE | KEV | EPSS | What it does |
|---|---|---|---|
| CVE-2025-32432 | ✅ | 0.998 | Code injection, unauthenticated RCE |
| CVE-2024-56145 | ✅ | 0.974 | Code injection RCE |
| CVE-2025-35939 | ✅ | 0.012 | Improper param control |
| CVE-2025-23209 | ✅ | 0.047 | Code injection (needs security key leak) |

## Drupal (5 domains each)

| CVE | KEV | EPSS | What it does |
|---|---|---|---|
| CVE-2018-7600 (Drupalgeddon2) | ✅ | 0.9999 | Unauth RCE |
| CVE-2018-7602 (Drupalgeddon3) | ✅ | 0.992 | Unauth RCE |
| CVE-2019-6340 | ✅ | 0.919 | REST module RCE |
| CVE-2026-9082 | ✅ | 0.846 | SQLi, priv escalation |
| CVE-2020-13671 | ✅ | 0.043 | File-extension sanitization bypass |

## Joomla (3 domains each)

| CVE | KEV | EPSS | What it does |
|---|---|---|---|
| CVE-2023-23752 | ✅ | 0.998 | Unauth API access-control bypass |
| CVE-2017-8917 | — | 0.998 | SQLi in com_fields |
| CVE-2015-8562 | — | 0.983 | PHP object injection RCE |
| CVE-2026-48907 | ✅ | 0.804 | Widget Factory plugin access control |
| CVE-2026-56290 | ✅ | 0.029 | Page Builder access control |

## Apache

| CVE | Domains | KEV | EPSS | What it does |
|---|---|---|---|---|
| CVE-2010-0425 (mod_isapi) | 61 | — | 0.942 | CVSS 10 — RCE via ISAPI module unload |
| CVE-2009-3555 (TLS renegotiation) | 3,738 | — | 0.873 | MITM plaintext injection |

## Laravel

| CVE | Domains | KEV | EPSS | What it does |
|---|---|---|---|---|
| CVE-2021-3129 (Ignition debug RCE) | 180 | — | 0.999 | Essentially guaranteed hit if debug mode is on |

## WordPress (176 domains each — the 376k-domain population is HIGH, not CRITICAL)

| CVE | KEV | EPSS | What it does |
|---|---|---|---|
| CVE-2020-11738 (Duplicator) | ✅ | 0.978 | File download RCE |
| CVE-2020-25213 (File Manager) | ✅ | 0.973 | Unauth RCE |
| CVE-2019-9978 (Social Warfare) | ✅ | 0.735 | XSS |
| CVE-2021-44223 (Gutenberg) | — | 0.290 | Arbitrary file upload |
| CVE-2026-41940 | ✅ | 0.981 | ⚠️ data-quality flag: catalog summary describes cPanel/WHM + "WP2", not core WordPress — likely mistagged, verify before probing |

## TYPO3 (1 domain each — low priority)

| CVE | KEV | EPSS | What it does |
|---|---|---|---|
| CVE-2023-24814 | — | 0.008 | SQLi in page tree |
| CVE-2019-12747 | — | 0.015 | Extbase deserialization |

## Update (2026-07-16): Craft CMS + Drupal probed

Ran the local `verify-cves` binary (rebuilt from the latest `src/cve_verify.rs`, which had two
compile errors left mid-edit from the prior session — fixed: a stray `?` on an `Option` inside
`verify_mongodb`, and a missing `aggressive` arg on `verify_docker`) scoped to exactly the 3,872
Craft CMS + Drupal domains above, via the `cve_pending_local` staging table. **Non-aggressive** —
`active_http_poc` (the only code path that sends real exploit payloads) only covers
apache/nginx/tomcat/litespeed path-traversal and PHP-CGI source leak; Craft CMS and Drupal have no
PoC implemented, so this was a single ordinary HTTPS/HTTP GET per domain, fingerprinting CMS
markers + version-in-range — the same "version-confirmed" tier already used for hundreds of
thousands of other domains, not exploitation. `cve_pending_local` was cleared again after the run.

**Craft CMS** (3,867 domains, applies uniformly across all 4 CVEs since it's one fingerprint check
per domain): **2,831 confirmed**, 408 refuted, 628 unreachable.

**Drupal** (5 domains):
- CVE-2018-7600, CVE-2018-7602, CVE-2019-6340: 2 confirmed, 3 refuted (version outside range)
- CVE-2020-13671, CVE-2026-9082: 5 confirmed (no affected-version ceiling in the catalog entry)

None of this proves live RCE — it's presence + version-range confirmation only. Craft CMS has no
safe non-destructive PoC in `poc-exploits.md` either, so "proven exploitable" for these would
require the per-host, CERT-coordinated path the doc describes, not a mass automated run.

## Recommended next move

With Craft CMS + Drupal now fingerprint-confirmed, the next highest-value unverified gaps are
**Apache's CVE-2010-0425** (mod_isapi, CVSS 10, 61 domains) and **Laravel's CVE-2021-3129**
(Ignition debug RCE, 180 domains, EPSS 0.999) — both small populations, both fingerprint-only
(no PoC exists for Laravel; Apache's traversal PoC only fires for CVE-2021-41773/42013, not
mod_isapi). WordPress's KEV-listed plugin CVEs (176 domains each) are the next tier after that.
