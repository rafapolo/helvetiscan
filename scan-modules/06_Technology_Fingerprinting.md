# Scan Module: Technology Fingerprinting & CVE Correlation

**Component ID:** tech-fingerprint-001
**Criticality:** MEDIUM-HIGH
**ISG/DORA/NIS2 Alignment:** ISG §4 (software asset inventory), DORA 16, NIS2 Article 20
**Risk Contribution:** 10–15% of overall risk score

---

## What We Scan

### Web Server & CMS Detection

| Category | Detection Methods | Examples |
|---|---|---|
| **Web Servers** | HTTP headers, error pages, response fingerprints | Apache, nginx, IIS, Tomcat, Caddy |
| **CMS & Frameworks** | HTML comments, admin endpoints, cookies | WordPress, Joomla, Drupal, Magento, Django, Ruby on Rails |
| **Programming Languages** | Stack traces, file extensions (.php, .jsp, .aspx) | PHP, Java, C#/.NET, Python, Node.js |
| **JavaScript Frameworks** | HTML attributes, script paths, bundle signatures | React, Vue.js, Angular, Svelte |
| **Databases** | Default ports, error messages, connection strings | MySQL, PostgreSQL, MongoDB, Oracle, MSSQL |
| **Cache Layers** | Port fingerprints, response patterns | Redis, Memcached, Varnish |
| **API Gateways** | X-Powered-By headers, API response formats | Kong, AWS API Gateway, Azure API Management |
| **SSL/TLS Libraries** | Certificate issuer, cipher negotiation | OpenSSL, BoringSSL, LibreSSL |
| **Monitoring & APM** | Script fingerprints, collector domains | Datadog, New Relic, Sentry, Grafana |

### CVE Correlation

**Detection Process:**
```
1. Fingerprint technology version (e.g., WordPress 5.8.1)
2. Query vulnerability database (NVD, GitHub Security Advisory, Exploit-DB)
3. Extract CVEs affecting that version
4. Classify by severity (CVSS, exploitability)
5. Report with remediation guidance
```

### Detection Techniques

```
DETECTION_ENDPOINTS = ["/wp-admin/", "/administrator/", "/admin/",
                        "/api/version", "/.env", "/composer.json"]

function fingerprint_technologies(domain):
    response = http_get("https://" + domain)
    html     = response.body
    headers  = response.headers

    // 1. HTTP header fingerprinting
    server    = headers["Server"]           // e.g. "Apache/2.4.41"
    x_powered = headers["X-Powered-By"]    // e.g. "PHP/7.4"
    aspnet    = headers["X-AspNet-Version"]

    // 2. HTML analysis
    cms        = detect_cms(html)
    frameworks = detect_js_frameworks(html)
    generator  = extract_meta(html, "generator")

    // 3. Script source analysis
    for each script_src in extract_script_sources(html):
        framework = identify_framework(script_src)

    // 4. Probe known detection endpoints
    for endpoint in DETECTION_ENDPOINTS:
        if http_get(domain + endpoint).status == 200:
            // Endpoint exposed — extract version info

    // 5. CVE lookup per detected software + version
    detected = [(cms.name, cms.version), (server.name, server.version), ...]
    cves = []
    for (software, version) in detected:
        cves += query_cve_db(software, version)

    cves.sort_by(cvss_score, descending)

    return TechResults {
        detected_software: detected,
        cms, frameworks, cves,
        risk: calculate_cve_risk(cves)
    }

function detect_cms(html):
    if "wp-content" or "wp-includes"  in html:  return WordPress
    if "//Joomla"   or "com_"          in html:  return Joomla
    if "Drupal"     or "sites/default" in html:  return Drupal
    if "mage/"      or "skin/"         in html:  return Magento
    return null
```

---

## Why This Matters

### The Knowledge Problem

**Scenario 1: Unpatched WordPress**
```
Discovered: WordPress 5.8.0 (from wp-includes/version.php)
CVE-2021-39200: WordPress < 5.8.1 → XSS injection in admin panel
Impact: Attacker injects malicious JavaScript
Delivery: Every page loads attacker's script, steals admin credentials
Remediation: Update to WordPress 5.8.1 (5 minutes)
Status: 90% of WordPress sites are outdated
```

**Scenario 2: Vulnerable PHP Version**
```
Discovered: PHP 7.2.26 (from error page)
CVE-2019-11024: PHP 7.2 < 7.2.26-1 → Local code execution
CVE-2019-9024: PHP type juggling vulnerability
Impact: PHP deserialization → RCE (remote code execution)
Status: PHP 7.2 reached EOL in November 2020 (4+ years old)
Risk: Attacks automated, exploit code freely available
```

**Scenario 3: Vulnerable Library (Supply Chain)**
```
Detected: jQuery 1.11.0 (from script src)
CVE-2016-10506: jQuery < 3.0 → DOM manipulation XSS
Impact: Attacker injects <script> via vulnerable jQuery
Status: jQuery 1.11.0 released 2014 (10+ years old)
Why it's there: Likely bundled with CMS/framework, never updated
```

### Regulatory Alignment

**ISG §4:** "Organizations must maintain an inventory of software and perform timely updates. Known vulnerable software is a finding."

**DORA 16:** "Financial institutions must track their software asset inventory and remediate known vulnerabilities within defined timelines."

**NIS2 Article 20:** "Supply chain: Suppliers must prove their software is patched against known CVEs."

---

## Risk Scoring Model

```
Base Risk = 10 (software inventory assessment)

For each detected software with known CVEs:

CVSS Score Mapping:
  - CVSS 9.0–10.0 (CRITICAL):    +30 points
  - CVSS 7.0–8.9 (HIGH):         +20 points
  - CVSS 5.0–6.9 (MEDIUM):       +10 points
  - CVSS 0.1–4.9 (LOW):          +3 points

Exploitability Factor:
  - Unpatched for 1+ year:        +15 points
  - Public exploit code available: +10 points
  - In active exploitation:        +20 points
  - Requires authentication:       -5 points
  - Local only (no remote):        -10 points

Software Age:
  - Unsupported/EOL version:      +10 points
  - Minor version outdated (1–2 releases): +3 points
  - Fully patched:                0 points

Version Discovery Method:
  - Directly exposed (HTTP header): +5 points (easy to identify)
  - Hidden in HTML/JS:             +0 points (harder to find)

Accumulator:
  Total Risk = Sum of all detected CVEs + Software Age
  MAX: 150+ points (multiple critical vulnerabilities)
```

---

## Example Findings from .ch Scans

### Finding 1: Outdated WordPress (CRITICAL)

```
Domain: small-business.ch
Status: 🚨 CRITICAL
Detected: WordPress 5.0.0 (Core version string exposed)
Current: WordPress 6.4.3 (as of 2025)
Versions Behind: 8 major releases, 35+ months old

Vulnerabilities (Top 10):
  [1] CVE-2021-24566 - File upload to RCE (CVSS 7.8)
  [2] CVE-2021-24497 - SQL injection (CVSS 9.8) ⭐
  [3] CVE-2021-39200 - XSS in admin (CVSS 6.5)
  [4] CVE-2021-39201 - Parameter tampering (CVSS 5.7)
  [5] CVE-2020-28032 - Plugin bypass (CVSS 9.1) ⭐
  ... and 20+ more

Attack Scenario:
  1. Attacker finds WordPress version via wp-includes/version.php
  2. Exploits CVE-2021-24497 (SQL injection)
  3. Extracts admin credentials from wp_users table
  4. Logs into admin panel with stolen password
  5. Uploads malicious plugin → RCE
  6. Modifies website, injects phishing forms
  7. Steals customer credit cards

Active Exploitation: YES (these CVEs are weaponized in 2025)

Recommended Action (URGENT):
  1. Backup database and files immediately
  2. Update to WordPress 6.4.3
  3. Audit access logs for suspicious admin logins
  4. Check for unknown plugins/users
  5. Scan files for malware with Wordfence/MalCare
  6. Notify customers if payment data exposed

Timeline: 1–2 hours (full update + audit)
ISG Impact: CRITICAL unpatched software finding
```

### Finding 2: Vulnerable PHP Version (HIGH)

```
Domain: ecommerce-platform.ch
Status: ⚠️ HIGH
Detected: PHP 7.2.26 (from error page)
Latest: PHP 8.3.x (current)
Status: PHP 7.2 reached EOL November 2020 (4+ years ago)

Vulnerabilities:
  - CVE-2019-11024: Type juggling (CVSS 7.5)
  - CVE-2019-9024: Deserialization RCE (CVSS 8.1) ⭐
  - CVE-2019-7314: XML parser (CVSS 9.8) ⭐
  - CVE-2018-19935: Null pointer dereference (CVSS 9.1)

Attack Path:
  1. Attacker sends crafted serialized object
  2. PHP deserializes with vulnerable gadget chain
  3. RCE as www-data user
  4. Attacker reads database.php (credentials)
  5. Accesses customer database, credit cards
  6. Plants backdoor for persistence

Exploitation: EASY (gadget chains publicly available on GitHub)

Why It's Dangerous:
  - PHP 7.2 is 4+ versions behind
  - No security patches available
  - Vulnerable to modern automated scanning
  - Attacker can use: python exploit.py target.ch

Recommended Action:
  1. Plan PHP upgrade path: 7.2 → 7.4 → 8.0 → 8.3
  2. Test application compatibility with PHP 8.0
  3. Upgrade to PHP 8.2 minimum (current LTS)
  4. Update all dependencies (Composer)
  5. Run security scanner post-upgrade

Timeline: 1–2 weeks (testing + deployment)
ISG Impact: HIGH finding — mandatory remediation
```

### Finding 3: Unpatched CMS Plugin (HIGH)

```
Domain: company-website.ch
Status: ⚠️ HIGH
CMS: WordPress 6.0 (up-to-date)
Vulnerable Plugin: Contact Form 7 (v5.5.0 — January 2022)
Current: Contact Form 7 (v5.7.4)
Versions Behind: 8 minor versions, 3 years old

CVE: CVE-2023-39999 - File upload arbitrary access (CVSS 7.5)

Impact:
  - Users can upload files to arbitrary directory
  - Attacker uploads .php file to wp-content/uploads/
  - Visits uploaded PHP file → Code execution
  - Contacts table (email addresses) exposed

Why It's There:
  - Plugin updates are manual in WordPress
  - Admin hasn't updated in 3 years
  - No automatic security update notifications

Recommended Action:
  1. Update Contact Form 7 to v5.7.4+
  2. Audit uploaded files for suspicious PHP
  3. Check access logs for file upload activity
  4. Enable automatic plugin updates in WordPress
  5. Review other plugins for outdated versions

Timeline: 1 hour (update plugin, check logs)
Risk: Moderate (requires user to submit form)
```

### Finding 4: Outdated JavaScript Library (MEDIUM)

```
Domain: startup-web.ch
Status: ⚠️ MEDIUM
Detected: jQuery 1.11.0 (from <script src>)
Current: jQuery 3.7.0
Age: 11 years old (released November 2014)

CVE: CVE-2016-10506 - XSS vulnerability via HTML parsing (CVSS 6.1)

Attack Scenario:
  1. Attacker injects: <img src=x onerror="alert('XSS')">
  2. jQuery 1.11.0 processes HTML unsafely
  3. JavaScript executes attacker's code
  4. Attacker steals user session token from localStorage
  5. Attacker impersonates user

Why It's Not Critical:
  - Requires DOM manipulation (not reflected XSS)
  - Limited scope (page only)
  - Depends on application code using jQuery

Recommended Action:
  1. Update jQuery to 3.6.0+ (LTS)
  2. Review all jQuery usage for deprecations
  3. Consider migrating away from jQuery (most modern apps don't need it)
  4. Run security scanner for XSS

Timeline: 1–2 hours (test compatibility)
Priority: Medium (consolidate with other updates)
```

### Finding 5: Exposed Version Strings (Information Disclosure)

```
Domain: api-platform.ch
Status: ℹ️ INFO
Exposed Information:
  HTTP Header: Server: nginx/1.18.0
  HTTP Header: X-Powered-By: Express/4.17.1
  HTTP Header: X-AspNet-Version: 4.0.30319
  HTTP Header: X-MVC-Version: 5.2

Impact: Attackers immediately know software versions
  - Can target known vulnerabilities
  - Automated scanning becomes more accurate
  - Reconnaissance is trivial

Recommended Action:
  Remove/obfuscate version strings:

  nginx:
    server_tokens off;

  Express.js:
    app.disable('x-powered-by');

  IIS:
    <system.webServer>
      <security>
        <requestFiltering removeServerHeader="true" />
      </security>
    </system.webServer>

Impact: Defense-in-depth (slows attackers)
Timeline: LOW priority, easy fix
```

---

## Compliance Reporting

### ISG §4 Report

```
SOFTWARE ASSET INVENTORY & VULNERABILITY ASSESSMENT
Domain: company.ch
Scan Date: 2026-03-15
Report Type: ISG §4 Software Security

DETECTED SOFTWARE:
✓ Apache 2.4.41 (current stable)
✗ WordPress 5.0.0 (35 months behind)
✗ PHP 7.2.26 (EOL, no security support)
⚠️ jQuery 1.11.0 (minor XSS risk)

CRITICAL VULNERABILITIES: 3
HIGH VULNERABILITIES: 8
MEDIUM VULNERABILITIES: 12

REMEDIATION PLAN:
[1] Update WordPress to 6.4.3 (1–2 hours)
[2] Upgrade PHP to 8.2 LTS (2–4 weeks, test first)
[3] Update jQuery to 3.6 LTS (1 hour)
[4] Schedule automatic updates (30 minutes)

ISG COMPLIANT: NO (critical vulnerabilities present)
Timeline to Compliance: 4 weeks
```

### DORA Risk Assessment

```
SOFTWARE VULNERABILITY ASSESSMENT
Institution: regulated-bank.ch
Assessment Date: 2026-03-15

CRITICAL UNPATCHED SOFTWARE: NONE ✓
EXPLOITABLE CVES: NONE ✓
EOL SOFTWARE: NONE ✓

DORA COMPLIANT: YES

Patch Management:
  - Critical patches: Applied within 3 days ✓
  - Security patches: Applied within 30 days ✓
  - Regular patches: Applied within 60 days ✓

Last Vulnerability Assessment: 2026-03-15
Next Assessment: 2026-04-15
```

---

## Integration with Other Modules

- **Open Ports:** Services discovered on open ports feed into fingerprinting
- **HTTP Security Headers:** Framework detection helps identify web technology stack
- **Email Security:** Mail server software version detection (exim, postfix, etc.)

---

## Roadmap: Advanced Detections (Future)

- [ ] Supply chain dependency scanning (package.json, requirements.txt)
- [ ] Container image scanning (Docker, Kubernetes)
- [ ] Configuration file discovery (.env, .git, etc.)
- [ ] SBOM (Software Bill of Materials) generation
- [ ] Exploit database integration (Exploit-DB, Metasploit)
- [ ] AI-based vulnerability prediction

---

## Customer Value

**For SMEs:**
> "You don't always know what's running on your website. We found a customer running WordPress 5.0.0 with 35 known vulnerabilities. We helped them update in one afternoon — they didn't even know they were at risk."

**For Regulated Industries:**
> "Automated software inventory + vulnerability correlation. We track every version change, alert on new CVEs, and provide remediation guidance. ISG auditors see your patch management is systematic and documented."
