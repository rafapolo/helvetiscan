# Scan Module: DNS & DNSSEC

**Component ID:** dns-dnssec-001
**Criticality:** HIGH
**ISG/DORA/NIS2 Alignment:** ISG §4, DORA 16, NIS2 Article 21
**Risk Contribution:** 12–18% of overall risk score

---

## What We Scan

### DNS Record Hygiene

| Record Type | What We Check | Why It Matters |
|---|---|---|
| **A / AAAA Records** | IPv4 and IPv6 resolution | Verify legitimate IP ranges, detect rogue DNS answers |
| **MX Records** | Mail exchange priority and validity | Identify email routing paths, detect spoofing risk |
| **CNAME Records** | Canonical name aliases | Detect subdomain takeover, zone apex abuse |
| **TXT Records** | All TXT records (SPF, DKIM, DMARC, etc.) | Email authentication policy parsing |
| **NS Records** | Authoritative nameservers | Detect DNS takeover, nameserver misconfiguration |
| **SOA Record** | Start of Authority metadata | Serial number, TTL, refresh intervals |

### DNSSEC Configuration

| Element | What We Check | Why It Matters |
|---|---|---|
| **DNSSEC Signing** | Domain signed with DNSKEY records | Prevents DNS poisoning and man-in-the-middle |
| **Key Rotation** | DNSKEY versions and age | Expired keys disable DNSSEC verification |
| **DS Records** | Delegation Signer chain to parent zone | Proves key authenticity in DNSSEC chain of trust |
| **NSEC/NSEC3** | Authenticated denial of existence | Prevents zone enumeration attacks |
| **RRSIG Validity** | Signature expiration dates | Expired signatures break DNSSEC validation |
| **Trust Anchor** | Root zone trust validation | Whether .ch TLD validates domain's DNSSEC chain |

### DNS Configuration Issues

| Issue | Detection | Risk |
|---|---|---|
| **Open DNS Resolver** | Responds to recursive queries from internet | DDoS amplification attack vector |
| **DNS Amplification** | Large response size to small query | Used in DDoS attacks |
| **Zone Transfer (AXFR)** | Anyone can request full zone dump | Zone enumeration, subdomain discovery |
| **Wildcard Records** | \*.domain.ch matches any subdomain | Masks legitimate infrastructure, enables subdomain takeover |
| **TTL Misconfiguration** | TTL too low (< 300s) or too high (> 86400s) | Performance vs flexibility trade-off |
| **Missing CAA Records** | No Certificate Authority Authorization | Any CA can issue certificate for domain |

---

## Why This Matters

### Regulatory Compliance

**ISG §4 (Technical Security):** "DNS must be secured against poisoning and unauthorized modification. Organizations must implement DNSSEC where applicable to Swiss critical infrastructure."

**DORA 16:** "Financial institutions must ensure DNS resilience and prevent unauthorized delegation changes. Monitoring nameserver validity is mandatory."

**NIS2 Article 21 (Supply chain security):** "DNS infrastructure of suppliers must be auditable. DNSSEC implementation expected for regulated entities."

### Attack Vectors

1. **DNS Spoofing / Poisoning**
   - Attacker intercepts DNS query, responds with malicious IP
   - User visits attacker's website thinking it's legitimate
   - DNSSEC prevents this, but only if enabled and validated

2. **Zone Takeover via Nameserver Compromise**
   - Attacker gains access to domain registrar account
   - Changes NS records to attacker-controlled nameserver
   - All subsequent DNS queries answered by attacker
   - Can redirect traffic, intercept email, steal credentials

3. **DNS Amplification DDoS**
   - Attacker spoofs victim's IP, queries open DNS resolver
   - Resolver returns large response directed at victim
   - Attacker controls multiple resolvers = massive bandwidth attack

4. **Subdomain Takeover**
   - Subdomain points to deleted cloud service (S3, GitHub Pages, etc.)
   - Attacker registers same cloud resource
   - Attacker now controls subdomain
   - Can phish users, steal credentials, inject malware

---

## How We Detect It

### DNS Query Chain

```rust
// Pseudocode: DNS enumeration and DNSSEC validation
async fn scan_dns(domain: &str) -> DNSResult {
    // Resolve authoritative nameservers
    let ns_records = resolve_ns(domain).await?;

    // Query each nameserver for standard records
    for ns in &ns_records {
        let a_records = query_dns(domain, "A", ns).await?;
        let mx_records = query_dns(domain, "MX", ns).await?;
        let txt_records = query_dns(domain, "TXT", ns).await?;
        let caa_records = query_dns(domain, "CAA", ns).await?;

        // Check DNSSEC enablement
        let dnssec_enabled = check_dnssec_enabled(domain, ns).await?;

        if dnssec_enabled {
            // Validate DNSKEY signatures
            let dnskey = query_dns(domain, "DNSKEY", ns).await?;
            let validate = validate_dnssec_chain(domain, &dnskey, ns).await?;
        }

        // Test for zone transfer vulnerability
        let axfr_result = attempt_zone_transfer(domain, ns).await;

        // Test for open resolver
        let recursion_test = query_dns("8.8.8.8", "A", ns).await;
    }

    // Subdomain enumeration (brute force common subdomains)
    let subdomains = enumerate_subdomains(domain).await?;

    Ok(DNSResult {
        domain,
        ns_records,
        a_records,
        mx_records,
        txt_records,
        caa_records,
        dnssec_enabled,
        zone_transfer_vulnerable: axfr_result.is_ok(),
        open_resolver: recursion_test.is_ok(),
        subdomains,
    })
}
```

### Subdomain Discovery

```bash
# Brute-force common subdomain patterns
subdomains = [
    "www", "mail", "ftp", "admin", "api", "test", "staging",
    "dev", "prod", "vpn", "remote", "webmail", "smtp", "pop3",
    "ntp", "dns", "git", "docker", "jenkins", "grafana",
    "prometheus", "elasticsearch", "kibana", "redis", "mysql",
    ...
]

for subdomain in subdomains {
    result = resolve(f"{subdomain}.{domain}");
    if result.is_some() {
        discovered_subdomains.push({
            name: subdomain,
            ip: result.ip,
            cname: result.cname,
            ttl: result.ttl,
        });
    }
}
```

---

## Risk Scoring Model

```
Base Risk = 15 (DNS is critical infrastructure)

DNSSEC Status:
  - DNSSEC not enabled:       +25 points (HIGH - vulnerable to poisoning)
  - DNSSEC enabled:           0 points
  - DNSSEC validation failing: +35 points (CRITICAL - broken trust chain)

CAA Records:
  - Missing CAA:              +15 points (any CA can issue cert)
  - Overly permissive CAA:    +8 points (multiple CAs allowed)
  - Restrictive CAA:          -5 points (bonus)

Nameserver Configuration:
  - Open resolver:            +20 points (DDoS amplification)
  - AXFR allowed:             +20 points (zone enumeration)
  - Fewer than 2 NS:          +10 points (no redundancy)
  - Healthy NS (2–4):         0 points

Wildcard Records:
  - Unrestricted wildcard:    +12 points (subdomain masking)
  - Controlled wildcard:      0 points

Subdomain Hygiene:
  - Orphaned subdomain:       +15 points per (takeover risk)
  - Valid subdomain:          0 points

TTL Configuration:
  - TTL < 300s:               +5 points (performance risk)
  - TTL > 86400s:             +3 points (flexibility risk)
  - TTL 300–3600s:            0 points (optimal)

NS Record Age:
  - Unchanged > 2 years:      +5 points (stale config)
  - Recent changes:           0 points

MAX RISK: 100 points
```

---

## Example Findings from .ch Scans

### Finding 1: Missing DNSSEC (High Risk)

```
Domain: fintech-startup.ch
Status: ⚠️ HIGH
DNSSEC Status: NOT ENABLED
Impact: Vulnerable to DNS cache poisoning attacks
Attacker Scenario:
  1. Intercept DNS query for fintech-startup.ch
  2. Respond with malicious IP (attacker-controlled server)
  3. User redirected to phishing site collecting credentials
  4. Bank accounts compromised

Recommended Action:
  - Enable DNSSEC signing at registrar
  - Publish DS records to .ch TLD registry
  - Verify DNSSEC validation chain with dnsviz.net

Timeline: 24 hours to implement
```

### Finding 2: Missing CAA Records (Medium Risk)

```
Domain: pharma-supplier.ch
Status: ⚠️ MEDIUM
CAA Records: MISSING
Impact: Any Certificate Authority can issue certificates for this domain
Attacker Scenario:
  1. Attacker opens account with cheap CA (e.g., Sectigo)
  2. Issues certificate for pharma-supplier.ch
  3. Hosts phishing site at HTTPS://pharma-supplier.ch (valid cert)
  4. Customers see green lock, enter credentials

Recommended Action:
  dns ADD CAA entry:
  pharma-supplier.ch IN CAA 0 issue "letsencrypt.org"
  pharma-supplier.ch IN CAA 0 issuewild "letsencrypt.org"
  pharma-supplier.ch IN CAA 0 iodef "mailto:security@pharma-supplier.ch"

Cost: FREE (DNS record update)
Timeline: Immediate
```

### Finding 3: Open DNS Resolver (High Risk)

```
Domain: bank-api.ch
Status: ⚠️ HIGH
Finding: DNS resolver responds to recursive queries from internet
Impact: Your nameserver is being used in DDoS amplification attacks
Attacker Usage:
  1. Attacker spoofs victim's IP in DNS query
  2. Your resolver responds with large answer directed at victim
  3. Amplification factor: 1 KB query → 5 KB response = 5x amplification
  4. With 100k compromised resolvers: 500 Gbps DDoS attack generated

Recommended Action:
  - Configure nameserver to ONLY accept recursive queries from your network
  - Implement rate limiting (max 10 queries/sec from external IPs)
  - Consider managed DNS service (AWS Route 53, Cloudflare, etc.)

Severity: CRITICAL - could result in ISP suspension for DDoS abuse
```

### Finding 4: Zone Transfer Allowed (High Risk)

```
Domain: internal-api.ch
Status: ⚠️ HIGH
Finding: AXFR (zone transfer) allowed from any IP
Impact: Complete zone file can be dumped, exposing all infrastructure
Exposed Information:
  - All A records: reveals internal IP ranges
  - All CNAME records: reveals infrastructure partners
  - All MX records: reveals email infrastructure
  - All TXT records: exposes SPF, DKIM, DMARC policies
  - Subdomain discovery: staging, test, admin, dev servers all enumerated

Recommended Action:
  - Restrict AXFR to specific IPs only (secondary DNS providers)
  - Disable AXFR entirely if zone is not distributed
  - Use NOTIFY mechanism instead of full zone transfers
  - Monitor zone transfer attempts in DNS logs

Attacker Value: Reconnaissance saves weeks of enumeration
```

### Finding 5: Orphaned Subdomain (Medium Risk)

```
Domain: company.ch
Subdomain: api-old.company.ch
Status: ⚠️ MEDIUM (SUBDOMAIN TAKEOVER RISK)
Current State: CNAME points to api.herokuapp.com (deleted)
Vulnerability: No server occupies api.herokuapp.com anymore
Attacker Action:
  1. Register new Heroku app named api
  2. Attacker now controls api-old.company.ch
  3. Can serve malware, phishing, steal credentials
  4. Users trust company.ch → subdomain appears legitimate

Recommended Action:
  - Delete CNAME record immediately
  - Or point to valid, owned endpoint
  - Audit all subdomains for orphaned DNS entries

Risk Window: Until CNAME deleted (URGENT)
```

### Finding 6: Wildcard Record Masking (Medium Risk)

```
Domain: hosting-platform.ch
Status: ⚠️ MEDIUM
Finding: *.hosting-platform.ch resolves to 203.0.113.45 (catch-all)
Impact: Any subdomain (real or fake) resolves to same IP
Legitimate Use: Customer domain routing (each customer gets subdomain)
Attacker Use:
  - anyone.hosting-platform.ch → resolved to platform
  - phishing-site.hosting-platform.ch → resolved to platform
  - Attacker uploads malware to /phishing-site/ directory
  - Users click link, see hosting-platform.ch in URL (trusted domain)
  - Malware served from legitimate domain

Recommended Action:
  - If wildcard is necessary: implement strict subdomain validation
  - Only allow registered customer subdomains
  - Monitor for suspicious subdomain patterns
  - Implement WHOIS blocking to prevent attacker registration

Risk Level: Medium (requires app-level validation)
```

---

## Compliance Reporting

### ISG §4 Report

```
DNS SECURITY ASSESSMENT
Domain: company.ch
Scan Date: 2026-03-15
Report Type: ISG §4 DNS Infrastructure

DNSSEC Status: ✓ ENABLED (Valid chain)
CAA Records: ✓ CONFIGURED (Restricts issuers)
Zone Transfer: ✓ RESTRICTED (Secondary DNS only)
Open Resolver: ✓ NOT OPEN (recursive disabled)
Nameserver Redundancy: ✓ 2 nameservers active

ISG COMPLIANT: YES

Risk Assessment: LOW
Recommendations: None — infrastructure meets ISG baseline
```

### NIS2 Supply Chain Assessment

```
NIS2 Article 21 — Supply Chain Security
Domain: supplier.ch
Assessment Date: 2026-03-15

DNS Configuration:
  - Authoritative NS: dns1.supplier.ch, dns2.supplier.ch
  - DNSSEC: Enabled, validated
  - CAA: Restricts to Let's Encrypt
  - Audit Trail: Available (syslog enabled)

Supplier Security Status: ✓ COMPLIANT
Access Controls: ✓ VERIFIED
Change Log: ✓ AVAILABLE

Recommended Action: Approved for supply chain partnership
```

---

## Integration with Other Modules

- **TLS & Certificates:** CAA records control certificate issuance
- **Email Security:** MX records determine email routing, SPF/DKIM/DMARC are TXT records
- **Domain Protection:** Subdomain enumeration feeds into takeover detection
- **HTTP Security Headers:** May be served per-subdomain (DNS points to different IPs)

---

## Roadmap: Advanced Detections (Future)

- [ ] NSEC3 walking detection (zone enumeration via DNSSEC)
- [ ] DNS query anomaly detection (DGA detection)
- [ ] Nameserver geographic analysis (latency, uptime)
- [ ] BGP hijacking detection (IP route analysis)
- [ ] DNS-over-HTTPS (DoH) endpoint security scanning
- [ ] SOCKSv5 proxy detection via DNS leakage

---

## Customer Value

**For SMEs:**
> "You worry about your business, not DNS infrastructure. We monitor your DNS for misconfigurations, missing DNSSEC, and orphaned subdomains. One customer discovered they could accept zone transfers from anyone — potential data breach of their entire infrastructure."

**For Pharma/Finance:**
> "DNSSEC compliance report for auditors. CAA records prove certificate issuance is controlled. We continuously monitor for unauthorized nameserver changes — any attempt is logged and alerted."
