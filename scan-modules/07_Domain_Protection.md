# Scan Module: Domain Protection & Brand Security

**Component ID:** domain-protection-001
**Criticality:** MEDIUM-HIGH
**ISG/DORA/NIS2 Alignment:** ISG §4 (domain security), DORA 16, NIS2 Article 20
**Risk Contribution:** 12–18% of overall risk score

---

## What We Scan

### Domain Lifecycle Management

| Check | What We Monitor | Risk if Missed |
|---|---|---|
| **WHOIS Expiry** | Domain registration renewal date | Domain expires → lapses → squatter re-registers → loss of brand |
| **Grace Period** | Post-expiration recovery window (30 days) | If grace period expires, domain permanently lost |
| **Auto-Renewal Status** | Domain auto-renewal configuration | Oversight can let critical domain expire |
| **WHOIS Privacy** | Who can see registrant information | Exposed WHOIS = privacy leak, targeted attacks |
| **Registrant Contact** | Email address for renewal notifications | Undelivered renewal notice = accidental expiry |
| **Registry Lock** | Domain locked to prevent unauthorized transfer | Unprotected domain vulnerable to hijacking |

### Typosquat & Brand Impersonation Detection

| Check | Examples | Risk |
|---|---|---|
| **Homoglyphs** | company.ch vs compаny.ch (Cyrillic 'а') | Visual spoofing, phishing |
| **Lookalike domains** | companyname.ch vs companyname-ch.com | Customer confusion, brand damage |
| **Typosquat domains** | compnay.ch, companny.ch | Typo-based phishing |
| **Country-code alternatives** | company.de, company.fr | Customer misdirection |
| **Soundalike domains** | kompany.ch | Audio confusion (phone referrals) |
| **Subdomain variations** | mail-company.ch (instead of mail.company.ch) | Spoofing attempts |

### Subdomain Enumeration & Orphan Detection

| Check | What We Find | Risk |
|---|---|---|
| **Active subdomains** | mail.domain.ch, api.domain.ch, admin.domain.ch | Legitimate infrastructure |
| **Orphaned subdomains** | cdn.domain.ch → points to deleted CloudFront | Subdomain takeover |
| **Dangling CNAME** | api.domain.ch → api.herokuapp.com (deleted) | Attacker re-registers service |
| **DNS spoofing** | Subdomains with wrong IP → attacker's server | DNS hijacking |

---

## Why This Matters

### Real-World Swiss Case: Domain Expiry

**Scenario:**
```
Company: Basel-based software startup
Domain: innovativetech.ch
Registrar: Namecheap
WHOIS Expiry: 2025-03-15
Renewal Notification: Sent to cto@company.ch (old email, CTO left company)
Status: Nobody checked email for renewal

Timeline:
  March 15: Domain expires
  March 16–April 15: Grace period (30 days, still recoverable)
  April 16: Domain leaves grace period, enters DROP state
  April 16: Squatter buys domain for CHF 15 at auction
  April 17: Squatter sets up fake innovativetech.ch
  April 18: Squatter emails customers: "Our website moved, update payment method"
  April 19: Customers wire money to squatter's bank account

Impact:
  - CHF 500k stolen from customers
  - Company reputation destroyed
  - ISG reporting requirement (as of April 2025)
  - Customers switch to competitors
  - Company effectively ceases to exist (brand stolen)
```

**Recovery Timeline:**
```
If caught during grace period (within 30 days):
  - Cost: CHF 500–2000 to recover domain
  - Restore: 24–48 hours

If caught after grace period:
  - Highly unlikely to recover (must buy from squatter)
  - Cost: CHF 5000–50,000 (ransom)
  - May never recover if squatter refuses
```

### Subdomain Takeover: Heroku Example

**Real Incident:**
```
Company: Zurich fintech startup
Subdomain: api.startup.ch
Heroku App: api-staging-123.herokuapp.com (deleted in 2022)
DNS: api.startup.ch → CNAME api-staging-123.herokuapp.com

Timeline:
  2022: Heroku app deleted, nobody updates DNS
  2025: Attacker discovers api.startup.ch DNS points to unclaimed Heroku
  2025: Attacker registers api-staging-123.herokuapp.com
  2025: Attacker can now serve from api.startup.ch

Attack Options:
  - Serve malware
  - Phish API credentials from mobile apps using this endpoint
  - Intercept API requests

Prevention:
  - Would have required: Regular subdomain audit
  - Find orphaned CNAME pointers
  - Delete or redirect to valid endpoint
```

### Typosquat Case Study: Swiss Bank Impersonation

**Scenario:**
```
Legitimate: zurichbank.ch (Swiss bank)
Typosquat: zurichbnk.ch (missing 'a')
Lookalike: zurich-bank.ch (hyphenated)

Attacker Action:
  - Register typosquat domain zurichbnk.ch
  - Copy legitimate bank website layout
  - Set up HTTPS (Let's Encrypt, free)
  - Send phishing emails: "Renew your credentials here: https://zurichbnk.ch/login"
  - Victims mistype or click email link
  - 50% don't notice missing 'a' or extra hyphen
  - Credentials stolen
  - Bank accounts compromised

Prevention:
  - Brand monitoring (continuous scanning for typosquats)
  - WHOIS monitoring (track who registers similar domains)
  - Trademark registration (can force ICANN takedowns)
```

---

## How We Detect It

### Domain Monitoring Engine

```
function scan_domain_protection(domain):
    // 1. WHOIS
    whois          = query_whois(domain)
    days_to_expiry = whois.expiry_date - today()

    // 2. Subdomain enumeration + orphan detection
    subdomains = enumerate_subdomains(domain)
    orphaned   = []
    for subdomain in subdomains:
        cname = get_cname(subdomain)
        if cname exists and target_is_unreachable(cname):
            orphaned.append({ subdomain, cname, risk: "subdomain takeover" })

    // 3. Typosquat detection
    typosquats = detect_typosquats(domain)
    // e.g. zurichbnk.ch, zurich-bank.ch, zurichbank.com ...

    // 4. Homoglyph detection
    homoglyphs = detect_homoglyphs(domain)
    // e.g. zurichbank.сh (Cyrillic 'с'), zür1chbank.ch (digit '1') ...

    return DomainProtectionResult {
        days_to_expiry,
        auto_renewal:    whois.auto_renewal_enabled,
        registry_lock:   whois.registry_lock,
        whois_privacy:   whois.privacy_protection_enabled,
        registrant_email: whois.registrant_email,
        orphaned_subdomains: orphaned,
        typosquats,
        homoglyph_risks: homoglyphs
    }

function enumerate_subdomains(domain):
    PATTERNS = ["www", "mail", "ftp", "admin", "api", "test", "staging",
                "dev", "prod", "vpn", "cdn", "static", "blog", "shop",
                "git", "jenkins", "docker", "k8s", "grafana", ...]
    discovered = []
    for pattern in PATTERNS:
        fqdn = pattern + "." + domain
        if dns_resolves(fqdn):
            discovered.append(fqdn)
    return discovered

function detect_typosquats(domain):
    name       = domain.split(".")[0]
    candidates = []

    // Single-character substitutions
    for each position i in name:
        for each letter in a-z:
            candidates.append(replace_char(name, i, letter) + ".ch")

    // Adjacent transpositions (common typing errors)
    for each position i in 0..len(name)-2:
        candidates.append(swap_chars(name, i, i+1) + ".ch")

    // Common lookalike substitutions
    candidates.append(name.replace('l', '1') + ".ch")
    candidates.append(name.replace('o', '0') + ".ch")

    return candidates
```

### WHOIS Monitoring

```
function check_expiry(domain):
    whois           = query_whois(domain)
    days_remaining  = whois.expiry_date - today()

    if days_remaining < 7:   alert(CRITICAL, domain + " expires in " + days_remaining + " days")
    else if days_remaining < 30:  alert(HIGH,     domain + " expires in " + days_remaining + " days")
    else if days_remaining < 90:  alert(MEDIUM,   domain + " expires in " + days_remaining + " days")
```

---

## Risk Scoring Model

```
Base Risk = 12 (domain is core infrastructure)

WHOIS Expiry:
  - Expires within 7 days:        +25 points (CRITICAL)
  - Expires within 30 days:       +15 points (HIGH)
  - Expires within 90 days:       +5 points
  - Expires > 1 year:             0 points
  - Auto-renewal enabled:         -3 points (bonus)

Grace Period:
  - In grace period (expiry passed): +20 points (emergency)
  - Outside grace period:         +35 points (CRITICAL, unrecoverable)

Registry Lock:
  - Not enabled:                  +5 points (takeover risk)
  - Enabled:                      0 points

WHOIS Privacy:
  - Privacy protection disabled:  +3 points (privacy leak)
  - Privacy protection enabled:   0 points

Subdomain Issues:
  - Orphaned/dangling CNAME:      +12 points per subdomain (takeover)
  - Total orphaned subdomains:    Max +30 points

Typosquat/Brand Risk:
  - Identical typosquat registered: +15 points per domain
  - Homoglyph registered:          +15 points per domain
  - Lookalike registered:          +10 points per domain
  - No typosquats detected:        0 points

Subdomain Certificate Risk:
  - HTTPS cert for orphaned subdomain: +10 points (legit-looking takeover)

Registrant Contact:
  - Invalid/outdated email:       +8 points (won't receive alerts)
  - Valid contact:                0 points

MAX RISK: 100 points
```

---

## Example Findings from .ch Scans

### Finding 1: Domain Expiring Soon (HIGH)

```
Domain: swiss-startup.ch
Status: ⚠️ HIGH
WHOIS Expiry: 2026-03-20 (5 days from scan)
Registrar: Namecheap
Registrant Email: founder@company.ch
Auto-Renewal: NOT ENABLED

Risk: If domain expires:
  1. Legitimate users can't access website
  2. Email bounces (domain-based MX records)
  3. Domain enters grace period (30 days)
  4. After grace period: domain goes to auction
  5. Squatter buys at discount → brand stolen

Timeline:
  March 20: EXPIRY DATE (5 days)
  March 20–April 19: Grace period (30 days)
  April 20: Domain is dropped, public auction begins
  April 21+: Squatter can register

Recommended Action (URGENT):
  1. Enable auto-renewal immediately at registrar
  2. Verify registrant email is monitored
  3. Add secondary contact to renewal notifications
  4. Set phone number reminder 7 days before next expiry

Timeline: Immediate (5 minutes)
Impact: Domain restoration cost = CHF 500–2000 if missed
```

### Finding 2: Orphaned Subdomain / Dangling CNAME (CRITICAL)

```
Domain: company.ch
Subdomain: cdn.company.ch
Status: 🚨 CRITICAL
Current DNS: cdn.company.ch CNAME → cdn-123456.cdn.jsdelivr.net (deleted)
Discovered: CDN service was deprovisioned 6 months ago, DNS not cleaned

Vulnerability:
  - Attacker can re-register cdn-123456.cdn.jsdelivr.net
  - Will then serve from cdn.company.ch (legitimate domain)
  - Can inject malware, steal credentials, phishing

Worst Case Scenario:
  cdn.company.ch serves JavaScript to all pages
  Attacker injects: fetch('/api/credentials') → steals API keys
  Application API compromised

Recommended Action (URGENT):
  1. Delete dangling CNAME immediately:
     dns DELETE cdn.company.ch CNAME

  2. If CDN still needed:
     Point to valid CDN: cdn.company.ch CNAME → d111111abcdef8.cloudfront.net

  3. Audit all subdomains for similar issues:
     dig +nocmd *.company.ch +noall +answer

Timeline: CRITICAL — fix within 1 hour
Recovery Window: Until attacker registers the service (could be any time)
```

### Finding 3: Registered Typosquats (HIGH)

```
Domain: pharmaco.ch
Status: ⚠️ HIGH
Discovered Typosquats:
  [1] pharmaca.ch - REGISTERED (single char swap)
  [2] pharmaco-ch.com - REGISTERED (country code variant)
  [3] pharamco.ch - REGISTERED (transposition)
  [4] pharmacc.ch - REGISTERED (double letter)

WHOIS Lookup:
  pharmaca.ch: Registered to "Domain Investor Ltd" (Privacy protected)
  Registrar: NameCheap
  Renewal: 2026-06-15

Risk Analysis:
  - 4 typosquats actively registered
  - Likely used for phishing customers
  - Difficult to recover (owned by competitor or squatter)

Customer Impact:
  - Email typos: customer types pharamco.ch → wrong site
  - Phishing campaign: "Renew license at pharmacc.ch"
  - Revenue loss: Customers misrouted to competitors

Recommended Action:
  1. Monitor traffic to typosquat domains (likely phishing)
  2. Register typosquats yourself to protect brand:
     - Cost: CHF 12 × 4 = CHF 48/year for each
     - Redirect all to legitimate pharmaco.ch

  3. Trademark registration (Switzerland):
     - Cost: CHF 500–1000
     - Allows ICANN takedown of confusing domains
     - Covers .ch and international TLDs

  4. Employee/customer awareness:
     - Train staff on typosquat risks
     - Add anti-phishing banner to emails

Timeline: 2–4 weeks (trademark + typosquat registration)
Impact: HIGH (active phishing infrastructure against customers)
```

### Finding 4: Homoglyph Attack (MEDIUM)

```
Domain: zurichbank.ch
Status: ⚠️ MEDIUM
Homoglyph Variant: zurichbank.сh (Cyrillic 'с' instead of Latin 'c')

Visual Appearance:
  Legitimate: zurichbank.ch (Latin c)
  Homoglyph: zurichbank.сh (Cyrillic c) — IDENTICAL TO HUMAN EYES

Attack Scenario:
  1. Attacker registers zurichbank.сh (Cyrillic domain)
  2. Sets up phishing page identical to zurichbank.ch
  3. Sends emails with link: https://zurichbank.сh/login
  4. Users don't notice Cyrillic c, enter credentials
  5. Bank accounts compromised

Prevention:
  - Modern browsers (Chrome, Firefox) show IDN/homoglyph warnings
  - Still vulnerable in some contexts (emails, QR codes)

Recommended Action:
  1. Register homoglyph variants:
     zurichbank.сh (Cyrillic c)
     zurichbank.͡ (lookalike dot)
     (Other Unicode variants)

  2. Set all homoglyphs to redirect to legitimate site

  3. Monitor brand mentions (some squatter may register)

Timeline: 1 week (register variants, set redirects)
Priority: Medium (browser warnings reduce risk)
```

### Finding 5: Registrant Email Invalid (MEDIUM)

```
Domain: company.ch
Status: ⚠️ MEDIUM
Registrant Email: cto@company.ch
Current Status: BOUNCE (CTO left company 2 years ago)

Issue:
  - Renewal notifications sent to bouncing email
  - Founder never sees renewal reminder
  - Domain may accidentally expire

2 Year History:
  - 4 renewal notices sent to cto@company.ch
  - All bounced (no delivery notifications sent)
  - Current expiry: 2026-03-20
  - Renewal notice likely bounced again

Recommended Action:
  1. Update WHOIS contact to valid email:
     registrant_email = founder@company.ch

  2. Add secondary contact (backup):
     admin_email = founder+domain@company.ch

  3. Enable registrar alerts (SMS or Slack)

  4. Calendar reminder (every year): 30 days before expiry

Timeline: 15 minutes (registrar update)
Impact: Prevents accidental expiry
```

### Finding 6: No Registry Lock (LOW-MEDIUM)

```
Domain: valuablecompany.ch
Status: ℹ️ INFO
Registry Lock: NOT ENABLED

Risk:
  - Attacker gains access to registrar account
  - Unauthorized transfer to different registrar
  - Loss of domain

Attack Likelihood: Low (requires account compromise)
Prevention: Registry Lock (prevents unauthorized transfer)

Recommended Action:
  1. Enable Registry Lock at registrar:
     Contact Namecheap support → "Enable Registry Lock"
  2. Store recovery password in secure location (1Password, Bitwarden)
  3. Set up two-factor authentication on registrar account

Timeline: 15 minutes (enable + 2FA)
Impact: Defense-in-depth against account takeover
```

---

## Compliance Reporting

### ISG §4 Report

```
DOMAIN SECURITY ASSESSMENT
Domain: company.ch
Scan Date: 2026-03-15
Report Type: ISG §4 Domain & Brand Protection

DOMAIN LIFECYCLE:
✓ Expiry Date: 2027-03-15 (1 year away)
✓ Auto-Renewal: ENABLED
✓ Registry Lock: ENABLED
✓ Registrant Contact: Valid and current

SUBDOMAIN AUDIT:
✓ Subdomains: 12 total discovered
✓ All subdomains: Active and valid
✗ Orphaned subdomains: 0

BRAND PROTECTION:
⚠️ Typosquats registered: 2 (low-value domains, minimal risk)
✓ Homoglyph variants: Not found in WHOIS (acceptable)
✓ Lookalike domains: Monitored via brand protection service

ISG COMPLIANT: YES

Recommendations:
  - Consider registering 2 typosquats for brand protection (CHF 24/year)
  - Maintain quarterly subdomain audits
```

### DORA Asset Management

```
CRITICAL INFRASTRUCTURE ASSET: DOMAIN
Asset: regulated-bank.ch
Assessment Date: 2026-03-15

Domain Renewal Status: ✓ SAFE (2+ years)
Backup Domain: backup-bank.ch (also registered) ✓
Disaster Recovery: Domain redirect configured ✓

DORA Requirement: Business continuity in case of domain loss
Status: ✓ COMPLIANT

Recovery Plan: If primary domain compromised, switchover to backup within 1 hour
```

---

## Integration with Other Modules

- **Email Security:** MX records point to mail infrastructure (subdomain enumeration)
- **TLS & Certificates:** Certificates issued for domain and subdomains
- **DNS & DNSSEC:** Domain delegation, nameserver security
- **Open Ports:** Subdomains may have different services on open ports

---

## Roadmap: Advanced Detections (Future)

- [ ] Certificate Transparency (CT) log monitoring (detect unauthorized certs)
- [ ] WHOIS changes tracking (automated alerts)
- [ ] Brand monitoring (mentions of domain on dark web, forums)
- [ ] Real-time phishing site detection (feeds from URLhaus, PhishTank)
- [ ] ICANN UDRP dispute assistance (automated trademark enforcement)
- [ ] Subdomain takeover bug bounty integration

---

## Customer Value

**For SMEs:**
> "You think you own your domain forever. Not without auto-renewal. We found a customer whose domain was going to expire in 5 days — nobody had checked. We enabled auto-renewal and added a secondary contact. Domain is safe now."

**For Regulated Industries:**
> "Domain is your brand. We continuously monitor subdomain orphans, typosquats, and expiry dates. ISG/DORA auditors see that your digital brand is protected and documented."
