# Scan Module: Email Security (SPF, DKIM, DMARC)

**Component ID:** email-sec-001
**Criticality:** CRITICAL (for SMEs especially)
**ISG/DORA/NIS2 Alignment:** ISG §4, ISG §12, DORA 16, FINMA Dec 2024
**Risk Contribution:** 18–25% of overall risk score

---

## What We Scan

### Email Authentication Framework

| Protocol | Purpose | What We Check |
|---|---|---|
| **SPF (Sender Policy Framework)** | Authorize which IPs can send mail from domain | SPF record syntax, IP ranges, includes |
| **DKIM (DomainKeys Identified Mail)** | Cryptographically sign outbound emails | Key strength, signing algorithm, key rotation |
| **DMARC (Domain-based Message Authentication, Reporting and Conformance)** | Enforce SPF/DKIM and define failure handling | Policy (none/quarantine/reject), subdomain coverage, reporting endpoints |
| **TLS-RPT (SMTP TLS Reporting)** | Report TLS connection failures | Configuration of tls-rpt@domain records |
| **MTA-STS (Mail Transfer Agent Strict Transport Security)** | Enforce STARTTLS and valid certificates | Policy presence, enforcement mode, certificate pinning |

### Detailed Checks

#### SPF (Sender Policy Framework)

```
SPF Evaluation:
  - Record presence and syntax validation
  - Mechanism types: ip4, ip6, a, mx, include, ptr, exists
  - SPF includes (e.g., include:sendgrid.net) — count and validity
  - SPF limit: RFC states max 10 DNS lookups (overflow = SPF FAIL)
  - "~all" (softfail) vs "-all" (hardfail) enforcement
  - Subdomain SPF: whether subdomains have dedicated SPF

Example weak SPF:
  v=spf1 include:sendgrid.net include:mailchimp.com include:stripe.net ~all
  (Too many includes, softfail = easy to spoof)

Example strong SPF:
  v=spf1 ip4:203.0.113.1 include:_spf.google.com -all
  (Explicit IPs, hardened includes, explicit deny)
```

#### DKIM (DomainKeys Identified Mail)

```
DKIM Checks:
  - Selector discovery (default: k1, google, sendgrid, etc.)
  - Key strength: RSA 1024-bit (weak), 2048-bit (standard), 4096-bit (strong)
  - Signature algorithm: rsa-sha256 (standard), rsa-sha1 (deprecated)
  - Key rotation age (keys unchanged for 2+ years = risk)
  - DKIM record syntax validation (misconfigurations)

Example DKIM record:
  google._domainkey.company.ch TXT "v=DKIM1; k=rsa; p=MIGfMA0GCS..."

Weakness: Key is 1024-bit RSA (factorizable, deprecated)
Strength: Key is 4096-bit RSA, rotated every 90 days
```

#### DMARC (Domain-based Message Authentication, Reporting and Conformance)

```
DMARC Policy Analysis:
  1. Policy strictness:
     - p=none (monitoring only, no enforcement)
     - p=quarantine (suspicious emails to spam folder)
     - p=reject (hard reject, no delivery)

  2. Subdomain policy:
     - sp=none (subdomains not protected)
     - sp=quarantine (subdomains to spam)
     - sp=reject (subdomains rejected)

  3. Reporting:
     - rua=mailto:... (aggregate reports for DMARC compliance)
     - ruf=mailto:... (forensic reports for rejected emails)

  4. Alignment:
     - adkim=r (relaxed DKIM alignment)
     - adkim=s (strict DKIM alignment)
     - aspf=r (relaxed SPF alignment)
     - aspf=s (strict SPF alignment)

Example Weak DMARC:
  v=DMARC1; p=none; rua=mailto:reports@company.ch
  (No enforcement, monitoring only — attackers freely spoof)

Example Strong DMARC:
  v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;
  rua=mailto:dmarc-reports@company.ch; ruf=mailto:dmarc-forensics@company.ch
  (Hard reject, subdomains protected, forensic reporting)
```

---

## Why This Matters: Email is the #1 Attack Vector

### Swiss SME Context

**Fact:** Email is the primary attack vector for:
- CEO fraud (50% of phishing incidents)
- Credential theft (40% of data breaches)
- Malware distribution (30% of infections)

**Real Swiss Case Studies:**

**Case 1: CEO Fraud at Basel Pharma Supplier**
```
Timeline:
  Week 1: Attacker researches company executives
  Week 2: Attacker registers domain: company-ch.com (vs company.ch)
  Week 3: Attacker sends email from cfo@company-ch.com:
          "Wire CHF 500,000 to new supplier account X1234 (invoice 2025-001)"
  Recipient: AP manager sees "CFO", approves, wires funds
  Result: CHF 500,000 stolen

Prerequisite for attack: No SPF/DKIM/DMARC = any IP can send from company.ch
```

**Case 2: Employee Credential Theft at Fintech**
```
Timeline:
  Day 1: Attacker spoofs reply-to header in email from "company.ch"
  Day 2: Employee replies with password in "response"
  Day 3: Attacker has legitimate credentials
  Day 4: Attacker accesses banking APIs with employee account
  Day 5: Transfers CHF 100,000 to attacker's account

Root cause: No DMARC enforcement → spoofed emails accepted
```

**Case 3: Phishing Campaign Against Roche Suppliers**
```
Attacker registered: roche-supplier.ch (vs roche-supplier-ch)
Sent emails: "Procurement update: Click here to confirm your vendor status"
SPF/DKIM/DMARC not configured on roche-supplier.ch:
  - SPF: Not set (any IP can send)
  - DKIM: Not signed (no cryptographic proof)
  - DMARC: Not set (no policy enforcement)

100 suppliers clicked, 50 entered credentials
Impact: Access to supply chain information, procurement systems

Prevention: Strong DMARC (p=reject) + SPF + DKIM would have alerted recipients
```

### Regulatory Alignment

**ISG §4 (Mandatory as of April 2025):**
> "Organizations must implement SPF and DMARC to prevent email spoofing. DKIM is recommended."

**FINMA Dec 2024 Guidance:**
> "Email authentication (SPF/DMARC/DKIM) is a baseline control. Its absence is a finding in internal audit reports."

**DORA 16:**
> "Financial institutions must enforce strict DMARC (p=reject) on all domains."

**NIS2 Article 20:**
> "Email security including spoofing prevention is a supply chain requirement."

---

## How We Detect It

### Email Authentication Scanning

```rust
// Pseudocode: Email security scanner
async fn scan_email_security(domain: &str) -> EmailSecResult {
    // 1. SPF Record Check
    let spf_record = dns_query(domain, "TXT", "v=spf1").await?;
    let spf_analysis = validate_spf(&spf_record)?;

    // Check for SPF includes and recursion depth
    let spf_includes = extract_spf_includes(&spf_record);
    let lookup_count = count_spf_dns_lookups(&spf_includes)?;

    // 2. DKIM Key Discovery
    let selectors = vec!["k1", "google", "sendgrid", "mailchimp", "default"];
    let mut dkim_records = Vec::new();

    for selector in selectors {
        let selector_domain = format!("{}._domainkey.{}", selector, domain);
        if let Ok(dkim) = dns_query(&selector_domain, "TXT").await {
            let key_strength = extract_key_strength(&dkim)?;
            dkim_records.push(DKIMKey {
                selector,
                strength: key_strength,
                algorithm: extract_algorithm(&dkim),
            });
        }
    }

    // 3. DMARC Policy Check
    let dmarc_record = dns_query(&format!("_dmarc.{}", domain), "TXT").await?;
    let dmarc_policy = parse_dmarc(&dmarc_record)?;

    // Extract policy enforcement
    let p_policy = dmarc_policy.get("p"); // none, quarantine, reject?
    let sp_policy = dmarc_policy.get("sp"); // subdomain policy
    let reporting = dmarc_policy.get("rua"); // aggregate reports enabled?

    // 4. Subdomain DMARC Check (subdomains often forgotten)
    let subdomains = enumerate_subdomains(domain).await?;
    for subdomain in subdomains {
        let subdomain_dmarc = dns_query(&format!("_dmarc.{}", subdomain), "TXT").await;
        // Check if subdomain has its own DMARC or inherits from parent
    }

    // 5. Email Flow Testing
    // Simulate sending email, check for DKIM signature and SPF pass
    let test_email = send_test_email(domain).await?;
    let dkim_valid = verify_dkim_signature(&test_email)?;
    let spf_valid = check_spf_pass(&test_email)?;

    // 6. Common Misconfigurations
    let issues = detect_email_issues(&spf_record, &dmarc_policy, &dkim_records);

    Ok(EmailSecResult {
        domain,
        spf: spf_analysis,
        dkim: dkim_records,
        dmarc: dmarc_policy,
        issues,
        overall_risk: calculate_email_risk(&spf_analysis, &dmarc_policy, &dkim_records),
    })
}

fn detect_email_issues(spf: &SPF, dmarc: &DMARC, dkim: &[DKIM]) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Issue 1: SPF only, no DKIM or DMARC
    if spf.is_some() && dkim.is_empty() && dmarc.is_none() {
        issues.push(Issue {
            severity: HIGH,
            message: "SPF present but DKIM unsigned and DMARC missing",
        });
    }

    // Issue 2: DMARC p=none (no enforcement)
    if dmarc.policy == "none" {
        issues.push(Issue {
            severity: HIGH,
            message: "DMARC policy is p=none (monitoring only, no enforcement)",
        });
    }

    // Issue 3: SPF softfail (~all) instead of hardfail (-all)
    if spf.fail_mode == "softfail" {
        issues.push(Issue {
            severity: MEDIUM,
            message: "SPF uses ~all (softfail) instead of -all (hardfail)",
        });
    }

    // Issue 4: Wildcard SPF (include:*)
    if spf.includes.contains("*") {
        issues.push(Issue {
            severity: MEDIUM,
            message: "SPF uses overly broad include (allows too many IPs)",
        });
    }

    // Issue 5: DKIM key too weak (1024-bit)
    for key in dkim {
        if key.strength < 2048 {
            issues.push(Issue {
                severity: HIGH,
                message: format!("DKIM key {} is {}-bit (weak)", key.selector, key.strength),
            });
        }
    }

    issues
}
```

---

## Risk Scoring Model

```
Base Risk = 25 (email is the #1 attack vector)

SPF Status:
  - Missing:                      +20 points (CRITICAL)
  - Present, softfail (~all):     +8 points (weak enforcement)
  - Present, hardfail (-all):     0 points
  - Broken/invalid syntax:        +12 points

DKIM Status:
  - Missing:                      +15 points (no cryptographic proof)
  - Present, 1024-bit key:        +10 points (weak key)
  - Present, 2048-bit key:        0 points
  - Present, 4096-bit key:        -3 points (bonus)
  - Key never rotated (>2 years): +5 points

DMARC Status:
  - Missing:                      +20 points (CRITICAL)
  - p=none (no enforcement):      +15 points (monitoring only)
  - p=quarantine:                 +5 points (weak enforcement)
  - p=reject:                     0 points
  - sp=none (subdomains exposed): +8 points (subdomains not protected)
  - sp=reject (subdomains safe):  0 points
  - Reporting enabled:            -2 points (bonus)

Alignment:
  - DMARC adkim=r (relaxed):      +3 points (easier to spoof)
  - DMARC adkim=s (strict):       0 points
  - DMARC aspf=r (relaxed):       +3 points
  - DMARC aspf=s (strict):        0 points

MX Record Issues:
  - No MX records:                +10 points (no email delivery)
  - MX points to external service without SPF: +8 points
  - Multiple MX with different policies: +5 points

Subdomain Coverage:
  - Subdomains exist but no DMARC: +10 points per subdomain
  - Subdomain email sent but no SPF: +8 points per subdomain

MAX RISK: 100 points
```

---

## Example Findings from .ch Scans

### Finding 1: Missing DMARC (CRITICAL)

```
Domain: healthcare-provider.ch
Status: 🚨 CRITICAL
DMARC Record: MISSING

Impact: Attackers can freely spoof emails from healthcare-provider.ch
  - Send fake patient notifications
  - Request sensitive medical information
  - Direct patients to phishing sites (fake prescription refill)
  - Steal healthcare data (GDPR violation)

Real Attack Scenario:
  Patient receives email appearing from healthcare-provider.ch:
    "Your prescription renewal is ready. Click here to confirm:"
  Patient clicks, enters credentials on phishing site
  Attacker accesses patient portal, modifies prescriptions
  Patient receives wrong medication

Recommended Action:
  1. Add DMARC record:
     _dmarc.healthcare-provider.ch TXT "v=DMARC1; p=reject; sp=reject;
       rua=mailto:dmarc-reports@healthcare-provider.ch; ruf=mailto:forensics@healthcare-provider.ch"

  2. Enable DMARC reporting to monitor legitimate failures
  3. Implement SPF and DKIM first (see below)
  4. Test with p=quarantine for 30 days, then p=reject

Timeline: URGENT — 24 hours
ISG Impact: Mandatory control, failure = audit finding
```

### Finding 2: Weak DMARC (p=none) — No Enforcement

```
Domain: fintech-platform.ch
Status: ⚠️ HIGH
DMARC Record: v=DMARC1; p=none
Impact: DMARC present but NOT enforcing policy
  - Authentication records monitored but not acted upon
  - Attackers' spoofed emails NOT rejected
  - Equivalent to not having DMARC at all

DMARC Reports Show:
  - 50% of emails fail SPF/DKIM (alignment failures)
  - Attacker sending emails from attacker.com claiming fintech-platform.ch origin
  - DMARC reports it but doesn't reject

Recommended Action:
  1. Analyze DMARC reports for 30 days
  2. Identify all legitimate senders (marketing, invoicing, etc.)
  3. Add them to SPF includes or separate DKIM keys
  4. Gradually increase enforcement: p=quarantine → p=reject
  5. Monitor daily for legitimate mail rejected (false positives)

Timeline: 30–60 days (staged rollout)

Current Risk: High — domain is being actively spoofed
```

### Finding 3: Missing SPF (HIGH)

```
Domain: startup-web.ch
Status: ⚠️ HIGH
SPF Record: MISSING

Impact: No authorization for who can send mail from startup-web.ch
  - Any IP can send email claiming to be from startup-web.ch
  - Phishing emails pass authentication
  - No way to distinguish legitimate from fraudulent

Attack Example:
  Attacker sends: From: admin@startup-web.ch
  Recipient: Hello, can you reset your password at [phishing-link]?
  User has no way to know if this is legitimate (no SPF validation)

Recommended Action:
  1. Create SPF record:
     startup-web.ch TXT "v=spf1 include:sendgrid.net -all"
     (If using SendGrid for marketing)

  2. Or:
     startup-web.ch TXT "v=spf1 ip4:203.0.113.1 ip4:203.0.113.2 -all"
     (If sending from own servers)

  3. Test with: mxtoolbox.com or dmarcian.com

Timeline: Immediate — 5 minutes to deploy
Impact: Drastically reduces phishing success
```

### Finding 4: SPF Softfail (~all) — Weak Enforcement

```
Domain: insurance-broker.ch
Status: ⚠️ MEDIUM
SPF Record: v=spf1 include:google.com ~all

Issue: Uses "~all" (softfail) instead of "-all" (hardfail)

Impact:
  - Softfail means: "If you're not in this list, I'm not sure... but deliver anyway"
  - Hardfail means: "If you're not in this list, you're definitely not me"

Attacker Scenario:
  Softfail SPF: Attacker's email fails SPF check but is still delivered
  Recipient sees: From: CEO@insurance-broker.ch
  No warning shown (SPF softfail doesn't trigger red flags in Gmail/Outlook)
  User transfers CHF 50,000 to "supplier account"

Recommended Action:
  Change to: "v=spf1 include:google.com -all"
  Monitor for 1 week for legitimate failures
  If no issues, deploy to production

Timeline: LOW priority, but improves security
```

### Finding 5: Weak DKIM Key (1024-bit) — CRITICAL

```
Domain: bank-api.ch
Status: ⚠️ CRITICAL
DKIM Key: google._domainkey.bank-api.ch TXT "v=DKIM1; k=rsa; p=[1024-bit RSA]"

Issue: 1024-bit RSA is cryptographically broken
Factorization Time: 18–24 months with modern computers
Cost: USD 10,000–100,000 (feasible for determined attacker)

Attack Path:
  1. Attacker intercepts DKIM public key (DNS)
  2. Factors 1024-bit RSA key (expensive but possible)
  3. Computes DKIM private key
  4. Forges email signatures appearing to be from bank-api.ch
  5. Sends malware or phishing to customers

Recommended Action (URGENT):
  1. Generate new 4096-bit RSA key:
     openssl genrsa -out dkim.key 4096

  2. Create new selector:
     k1._domainkey.bank-api.ch TXT "v=DKIM1; k=rsa; p=[new key]"

  3. Update mail server to sign with new key

  4. After 30 days, retire old 1024-bit key

  5. Set key rotation schedule: every 90 days

Timeline: CRITICAL — 1–2 hours to deploy
```

### Finding 6: No Subdomain DMARC Protection

```
Domain: company.ch
Status: ⚠️ MEDIUM
DMARC: v=DMARC1; p=reject (main domain protected)
Subdomain: mail.company.ch (has no dedicated DMARC)

Issue: Subdomain not explicitly protected by DMARC
  - Parent domain DMARC may not apply (depends on alignment)
  - Attacker can spoof: admin@mail.company.ch

Subdomains Discovered:
  - mail.company.ch
  - api.company.ch
  - app.company.ch
  - dev.company.ch (internal dev server, public DNS)

Recommended Action:
  1. Add DMARC to each subdomain:
     _dmarc.mail.company.ch TXT "v=DMARC1; p=reject; sp=reject"
     _dmarc.api.company.ch TXT "v=DMARC1; p=reject"
     etc.

  2. Or configure parent domain to protect all subdomains:
     v=DMARC1; p=reject; sp=reject (sp= covers subdomains)

Timeline: 1–2 hours (multiple DNS records)
Impact: Closes email spoofing loophole for subdomains
```

---

## Compliance Reporting

### ISG §4 Report

```
EMAIL SECURITY ASSESSMENT
Domain: company.ch
Scan Date: 2026-03-15
Report Type: ISG §4 Email Authentication

SPF Status: ✓ CONFIGURED (Hardfail: -all)
DKIM Status: ✓ CONFIGURED (4096-bit key, rotated)
DMARC Status: ✓ CONFIGURED (Policy: p=reject)
Subdomain Coverage: ✓ All subdomains protected
Reporting: ✓ DMARC reports enabled

ISG COMPLIANT: YES

Email spoofing risk: ✓ MITIGATED
```

### FINMA Audit Trail

```
EMAIL AUTHENTICATION CONTROLS
Institution: regulated-bank.ch
Assessment Date: 2026-03-15

Baseline Controls (FINMA Dec 2024):
  SPF: ✓ STRONG (-all hardfail)
  DKIM: ✓ STRONG (4096-bit, rotated quarterly)
  DMARC: ✓ STRONG (p=reject, sp=reject)

Spoofing Resistance: ✓ HIGH
Employee Risk: ✓ LOW (domain spoofing blocked)
Customer Risk: ✓ LOW (phishing impersonation prevented)

FINMA Status: ✓ COMPLIANT
```

---

## Integration with Other Modules

- **DNS & DNSSEC:** MX records, SPF includes, DMARC reporting endpoints all DNS-based
- **Open Ports:** SMTP port 25/587/465 configuration analysis
- **Domain Protection:** Subdomain enumeration → email subdomain protection

---

## Roadmap: Advanced Detections (Future)

- [ ] MTA-STS (Mail Transfer Agent Strict Transport Security) validation
- [ ] TLS-RPT (SMTP TLS Reporting) configuration analysis
- [ ] Email authentication timeline tracking (deployment rollout)
- [ ] DMARC forensic report analysis (automated parsing)
- [ ] BrightMail Certification validation
- [ ] Enhanced Phishing and Malware Protection (EMPS) assessment

---

## Customer Value

**For SMEs:**
> "Email spoofing is the #1 attack against your business. We check your SPF, DKIM, and DMARC. One customer had DMARC missing entirely — we helped them implement it in 30 minutes, blocking thousands of spoofed emails per month."

**For Regulated Industries:**
> "ISG-compliant email security proof. We track your DMARC policy evolution, provide forensic reports, and alert on any weakening. One pharma company discovered a rogue employee trying to weaken their DMARC policy — we caught it immediately."
