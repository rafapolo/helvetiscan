## Research Questions

Questions answerable from a populated helvetiscan database. Each maps to one or more tables listed above.

### Infrastructure sovereignty
- How many .ch domains depend on foreign DNS infrastructure? → `ns_operators.jurisdiction`
- Which domains have both foreign DNS and foreign hosting — fully offshored? → `ns_operators` + `domains.country_code`
- How concentrated is .ch DNS? If the top 3 NS operators went down, how many domains would be affected? → `ns_staging` + `ns_operators`
- Which US-based cloud providers host the most .ch government or finance domains? → `ns_operators` + `domain_classification`
- How does hosting sovereignty differ across industry sectors? → `domains.country_code` + `domain_classification`

### Exposed services
- Which .ch domains expose databases (MySQL, PostgreSQL, Redis, Elasticsearch, MongoDB, Memcached) to the open internet? → `ports_info`
- Which industries have the most exposed database ports? → `ports_info` + `domain_classification`

### Email spoofing
- Which sectors have the worst email authentication posture? → `email_security` + `domain_classification`

### Known vulnerabilities
- How many .ch sites run software with known exploited vulnerabilities (CISA KEV)? → `cve_matches.in_kev`
- Which CMS/server technology accounts for the most CVE matches? → `cve_matches.technology`
- How many critical CVEs are matched to finance or healthcare domains? → `cve_matches` + `domain_classification`
- Which domains have the highest CVE count? → `cve_matches`

### Industry benchmarks
- Which Swiss industries have the weakest overall security posture? → `sector_benchmarks` + `risk_score`
- What percentage of finance domains have HSTS? DNSSEC? DMARC enforcement? → `risk_score` + `domain_classification`
- Which sector has the most domains scoring below 50/100? → `risk_score` + `domain_classification`
- How does the government sector compare to retail on every risk flag? → `risk_score` + `domain_classification`

### Domain lifecycle
- How many .ch domains expire in the next 30 days? → `whois_info.expires_at`
- Which registrar has the most domains about to expire? → `whois_info`
- Are there high-value domains (many subdomains, classified sector) expiring soon? → `whois_info` + `subdomains` + `domain_classification`
- What is the average age of .ch domains by registrar? → `whois_info.whois_created`

### CMS and server landscape
- Which CMS is most popular in each industry sector? → `domains.cms` + `domain_classification`

### TLS and certificates
- Which domains use RSA keys smaller than 2048 bits? → `tls_info.key_algorithm`, `tls_info.key_size`
- How many certificates are expired or self-signed (distinct from tls_failed errors)? → `tls_info.expired`, `tls_info.self_signed`

### Subdomains and takeover risk
- How many .ch domains have orphaned subdomains (CNAME pointing to nothing)? → `subdomains` + `dns_info`

### Security headers
- Which sectors have the lowest security header adoption? → `http_headers` + `domain_classification`

### DNS hygiene
- Which .ch domains lack CAA records but have active TLS certificates? → `dns_info.caa` + `tls_info`

### Registrar landscape
- Which registrars hold the most .ch domains? → `whois_info.registrar`
- Is there a correlation between registrar and security posture? → `whois_info` + `risk_score`
- Which registrars have the most domains with DNSSEC delegated? → `whois_info.dnssec_delegated`

---

## Findings gap analysis
*What's missing or underrepresented in key-findings.md (§1–§30) — assessed 2026-03-17*

### Already computed, not yet a finding

**CVE exposure at scale** — the biggest omission. `preliminary-exposure.md` has the numbers: Apache (682K domains, 3 CRITICAL CVEs), nginx (605K, 3 HIGH), WordPress (376K, 1 CRITICAL), EOL PHP (43K, 2 CRITICAL). The combined "maximum exposed population" across those four technologies alone exceeds 1M .ch domains. This is the most actionable security finding in the dataset and has no slot in the 30. Belongs as §31 or folded into a new "CVE exposure" section.

**FTP cleartext exposure** — §30 buries it in a ports table. "FTP open on 688K domains — 42% of scanned .ch — transmitting credentials in cleartext" deserves its own finding, not a row in a survey.

**WordPress version lag** — `domains-overview.md` §13 (partial scan, now removed): 21.5% of versioned WP installs are outdated, and 56.6% hide their version entirely. Given 376K WP installs, the absolute outdated count is significant. Ported to key-findings §31.

### Existing findings weaker than they could be

**§20 (continental breakdown)** is a restatement of §14 (country breakdown) — both say the same thing about Switzerland vs abroad at different granularities. Could be merged to free a slot.

**§21 and §22** (Swiss domestic IPs, foreign IP concentrations) are supporting tables for §10/§11, not standalone headline findings. Could be collapsed into §10/§11 notes.

### High-value findings not yet computed (require DB queries)

**DNS namespace concentration** (→ task 19 / `dns_concentration` table): which NS operators control what fraction of .ch, and what happens if the top few fail? "If provider X goes offline, Y% of .ch domains stop resolving" is the kind of systemic risk finding that resonates with NCSC and enterprise audiences. Feeds directly into hub resilience.

**Hub resilience** (→ task 21 / `hub_resilience` table): cascading failure scenarios — minimum operator set whose removal takes 10%/25%/50% of .ch offline. Extends DNS concentration into a quantified infrastructure risk statement.

**Sector-differentiated risk** (→ `domain_classification` + `risk_score`): healthcare vs finance vs government security posture. Which sector has the most domains below 50/100? Which has the worst DMARC enforcement? High publication value.

**Domain expiry risk** (→ `whois_info.expires_at`): how many .ch domains expire in the next 30/90 days, and are any high-value (many subdomains, classified sector)?

**Subdomain takeover surface** (→ `subdomains` + DNS): orphaned CNAMEs pointing to decommissioned services. Not yet computed.
