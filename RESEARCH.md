## Research Questions

Questions answerable from a populated helvetiscan database. Each maps to one or more tables listed above.

### Infrastructure sovereignty
- How many .ch domains depend on foreign DNS infrastructure? → `ns_operators.jurisdiction`
- What share of .ch sites are hosted outside Switzerland? → `domains.country_code`
- Which domains have both foreign DNS and foreign hosting — fully offshored? → `ns_operators` + `domains.country_code`
- How concentrated is .ch DNS? If the top 3 NS operators went down, how many domains would be affected? → `ns_staging` + `ns_operators`
- Which US-based cloud providers host the most .ch government or finance domains? → `ns_operators` + `domain_classification`

### Exposed services
- Which .ch domains expose databases (MySQL, PostgreSQL, Redis, Elasticsearch, MongoDB, Memcached) to the open internet? → `ports_info`
- How many .ch domains have RDP (3389), Telnet (23), or VNC (5900) open? → `ports_info`
- Which open ports appear most frequently across .ch, beyond 80/443? → `ports_info`
- Which industries have the most exposed database ports? → `ports_info` + `domain_classification`
- How many Docker API endpoints (2375) are publicly reachable? → `ports_info`

### Email spoofing
- How many Swiss companies can have their email spoofed (no SPF or permissive + weak/no DMARC)? → `email_security`
- What fraction of .ch domains have DMARC set to `none` (monitor only, no enforcement)? → `email_security.dmarc_policy`
- How many .ch domains exceed the SPF 10-DNS-lookup limit, breaking their own email auth? → `email_security.spf_over_limit`
- Which sectors have the worst email authentication posture? → `email_security` + `domain_classification`
- How many .ch domains publish no DKIM selector at all? → `email_security.dkim_found`

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
- What's the most common CMS running on .ch domains? → `domains.cms`
- What's the server software distribution (Apache, nginx, IIS, etc.)? → `domains.server`
- Which CMS is most popular in each industry sector? → `domains.cms` + `domain_classification`
- How many .ch domains still run PHP, and which version? → `domains.powered_by`

### TLS and certificates
- How many .ch domains still negotiate TLSv1.0 or TLSv1.1? → `tls_info.tls_version`
- How many certificates are expired or self-signed? → `tls_info.expired`, `tls_info.self_signed`
- Which domains use RSA keys smaller than 2048 bits? → `tls_info.key_algorithm`, `tls_info.key_size`
- Who are the top certificate issuers for .ch? → `tls_info.cert_issuer`
- How many certificates lack Certificate Transparency SCTs? → `tls_info.ct_logged`
- How many certs expire within 7 days? → `tls_info.days_remaining`

### Subdomains and takeover risk
- How many .ch domains have orphaned subdomains (CNAME pointing to nothing)? → `subdomains` + `dns_info`
- Which domains leak their entire zone via AXFR? → `subdomains.source = 'axfr'`
- Which parent domains have the most discovered subdomains? → `subdomains`

### Security headers
- What percentage of .ch domains implement HSTS? CSP? X-Frame-Options? → `http_headers`
- How many domains are missing every security header? → `http_headers`
- How many .ch domains set `Access-Control-Allow-Origin: *`? → `http_headers.cors_origin`
- Which sectors have the lowest security header adoption? → `http_headers` + `domain_classification`

### DNS hygiene
- How many .ch domains have DNSSEC enabled? → `dns_info.dnssec_signed`
- How many .ch domains have wildcard DNS enabled (*.domain resolves)? → `dns_info.wildcard`
- Which domains lack CAA records, allowing any CA to issue certificates? → `dns_info.caa`
- How many domains have no MX record but still publish SPF? → `dns_info.mx` + `email_security`

### Registrar landscape
- Which registrars hold the most .ch domains? → `whois_info.registrar`
- Is there a correlation between registrar and security posture? → `whois_info` + `risk_score`
- Which registrars have the most domains with DNSSEC delegated? → `whois_info.dnssec_delegated`
