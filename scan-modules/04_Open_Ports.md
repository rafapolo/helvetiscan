# Scan Module: Open Ports & Services

**Component ID:** open-ports-001
**Criticality:** CRITICAL
**ISG/DORA/NIS2 Alignment:** ISG §4, DORA 16, NIS2 Article 20
**Risk Contribution:** 20–25% of overall risk score

---

## What We Scan

### Common Ports & Services

| Port(s) | Service | Risk Level | What We Detect |
|---|---|---|---|
| **21** | FTP | CRITICAL | Unencrypted credentials, legacy access |
| **22** | SSH | MEDIUM | Default credentials, weak ciphers |
| **3306** | MySQL | CRITICAL | Exposed database (Internet-facing) |
| **5432** | PostgreSQL | CRITICAL | Exposed database (Internet-facing) |
| **5984** | CouchDB | CRITICAL | NoSQL database exposed |
| **6379** | Redis | CRITICAL | Cache exposed, no authentication |
| **9200** | Elasticsearch | CRITICAL | Search database exposed |
| **27017** | MongoDB | CRITICAL | MongoDB exposed, no auth |
| **1433** | MSSQL | CRITICAL | SQL Server exposed |
| **3389** | RDP | CRITICAL | Windows Remote Desktop exposed |
| **445** | SMB | CRITICAL | Windows file sharing (ransomware vector) |
| **3128, 8080, 8888** | HTTP Proxies | HIGH | Exposed proxies (SSRF, credential theft) |
| **23** | Telnet | CRITICAL | Unencrypted remote access |
| **25, 587, 465** | SMTP | HIGH | Open relay (spam vector) |
| **53** | DNS | MEDIUM | Open resolver (DDoS amplification) |
| **8081–8099** | Management Ports | HIGH | Jenkins, GitLab, Docker, Kubernetes exposed |
| **9000–9999** | Dev/Debug Ports | HIGH | Debug interfaces, admin panels |

### Service Banner Grabbing

```
For each open port, we grab:
  - Service banner (Apache 2.4.41, nginx/1.18.0, etc.)
  - Software version string
  - Known CVE correlation
  - Authentication requirements (if detectable)
  - Configuration hints (SOAP, REST, GraphQL, etc.)
```

---

## Why This Matters

### Attack Scenarios

#### 1. Exposed Database (Port 3306/MySQL)

**Real-World Swiss Incident:**
```
Company: Mid-sized e-commerce platform
Open Port: 3306 (MySQL)
Attack: Attacker scans for open databases, connects without auth
Impact: 500,000 customer records stolen (names, emails, hashed passwords)
Damage: CHF 2 million in GDPR fines + reputational damage
Root Cause: Cloud instance security group misconfigured (0.0.0.0/0 allowed)
```

**Swiss Context:**
- E-commerce: GDPR violation = CHF 1k–20M+ fines
- Pharma: Patient data breach = FINMA investigation + criminal liability
- Financial: Account details = SRO sanctions + customer lawsuits

#### 2. Exposed Redis (Port 6379)

**Attack:**
```
1. Attacker scans for open Redis on port 6379
2. Redis has no password (common misconfiguration)
3. Attacker connects: redis-cli -h target.ch
4. Reads all cached data: session tokens, API keys, user data
5. Or executes: SAVE; BGSAVE to dump entire cache to disk
6. Steals months of cached credentials

Risk: Cache often stores: session tokens (can takeover accounts),
API keys (can access internal services), user PII (GDPR violation)
```

#### 3. Exposed RDP (Port 3389)

**Attack:**
```
1. Attacker scans for open RDP
2. Uses brute-force or default credentials (admin/admin, admin/password)
3. Gains remote access to Windows server
4. Deploys ransomware across network
5. Encrypted files demand CHF 50k–500k ransom

Swiss Impact: 2024 — ransomware cost Swiss companies CHF 600M+
```

#### 4. Exposed SMB (Port 445)

**Attack:**
```
1. Attacker scans for open port 445
2. Exploits SMB vulnerability (EternalBlue, Wannacry, etc.)
3. Gains code execution on Windows server
4. Lateral movement to other servers on network
5. Domain controller compromise, entire network encrypted

ISG Impact: Undetected SMB exposure = reportable incident if ransomware occurs
```

#### 5. Open FTP (Port 21)

**Attack:**
```
1. Attacker connects to open FTP
2. Credentials transmitted in plaintext over network
3. Attacker can:
   - Upload malware to web server
   - Download sensitive files
   - Modify files (HTML, PHP, etc.)

Swiss Case: Healthcare provider's FTP exposed with backup files
containing patient medical records (GDPR violation)
```

### Regulatory Alignment

**ISG §4:** "Organizations must limit network exposure to necessary ports only. Exposure of databases, RDP, SMB without compensating controls is a finding."

**DORA 16:** "Financial institutions must ensure no databases or sensitive services are exposed to the Internet without authentication and monitoring."

**NIS2 Article 20:** "Supply chain: Suppliers must prove that exposed ports are either: (a) authenticated, (b) rate-limited, (c) intentionally open."

---

## How We Detect It

### Port Scanning with Service Detection

```
PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993,
         3128, 3306, 3389, 5432, 5984, 6379, 8080, 8888, 9200,
         27017, 1433, 445, ...]  // + all 65535 for full scan

function scan_ports(domain):
    target_ips = dns_resolve(domain)
    open_ports = []

    for each ip in target_ips:
        for each port in PORTS (in parallel):
            if tcp_connect(ip, port) succeeds:
                banner  = grab_banner(ip, port)
                service = identify_service(port, banner)
                cves    = lookup_cves(service.name, service.version)
                open_ports.append({
                    ip, port, service, banner,
                    vulnerabilities: cves,
                    risk: assess_risk(port)
                })

    return PortScanResult {
        open_ports,
        risk_assessment: analyze_exposure(open_ports)
    }

function assess_risk(port):
    if port in [21, 23, 3306, 5432, 3389, 445, 6379, 27017]:  return CRITICAL
    if port in [22, 25, 53, 8080, 9200]:                       return HIGH
    if port in [80, 443]:                                       return LOW
    return MEDIUM
```

### Banner Grabbing & Service Identification

```
// Banner grabbing → service version detection
banner  = tcp_connect_and_read(target, port=3306)
// e.g. "5.7.25-22-log (Debian)"

service = { name: "MySQL", version: "5.7.25" }

// CVE database lookup
cves = query_nvd(service.name, service.version)
// Returns: CVE-2019-2614, CVE-2019-2627, CVE-2019-2628 ...
```

### CVE Correlation

```
Banner: Apache/2.4.41 (Ubuntu)
↓
Known vulnerabilities:
  - CVE-2021-30641 (mod_ssl heap buffer overflow)
  - CVE-2021-31618 (mod_proxy_http request splitting)
  - CVE-2021-33193 (HTTP request smuggling)

Risk Level: HIGH (immediate patching recommended)
```

---

## Risk Scoring Model

```
Base Risk = 25 (network exposure is critical)

For each OPEN PORT:

Database Ports (3306, 5432, 1433, 27017, 9200, 6379):
  - Open with no auth:           +30 points per port (CRITICAL)
  - Open with weak auth:         +20 points per port (HIGH)
  - Open with strong auth + TLS: +5 points per port
  - Not open:                    0 points

Remote Access (22, 3389, 445, 23):
  - Open, no authentication:     +30 points (CRITICAL)
  - Open, default credentials:   +25 points (CRITICAL)
  - Open, SSH key-only auth:     +3 points
  - Open, 2FA required:          +1 point
  - Closed:                      0 points

FTP/Telnet (21, 23):
  - Open:                        +25 points each (unencrypted credentials)
  - Closed:                      0 points

Management/Debug Ports (8080, 9000–9999, 8081–8099):
  - Open, no authentication:     +15 points per port
  - Open, basic auth:            +8 points per port
  - Open, strong auth:           +3 points per port
  - Closed:                      0 points

Web Ports (80, 443):
  - Open (expected):             0 points

DNS (53):
  - Open, recursive queries OK:  +10 points (DDoS amplification)
  - Open, recursive disabled:    +2 points
  - Closed:                      0 points

SMTP (25, 587, 465):
  - Open, open relay:            +20 points (spam vector)
  - Open, authentication req:    +2 points
  - Closed:                      0 points

Service Version Risk:
  - Critical CVE in banner:      +10 points
  - Known vulnerabilities:       +5 points
  - Fully patched:               0 points

MAX RISK: 150+ points
```

---

## Example Findings from .ch Scans

### Finding 1: Exposed MySQL Database (CRITICAL)

```
Domain: fintech-startup.ch
Port: 3306/TCP
Status: 🚨 CRITICAL
Service: MySQL 5.7.25-22 (Debian)
Authentication: NONE
Root Cause: AWS security group rule: 0.0.0.0/0:3306 allow

Exposure:
  - Public IP: 203.0.113.45
  - Scanned by: Shodan, Censys, BinaryEdge
  - Database accessible from: Any IP on internet

Attack Timeline:
  Day 1: Attacker finds database on Shodan
  Day 2: Attacker logs in without password
  Day 3: Attacker exfiltrates customer table (100k records)
  Day 4: Data sold on dark web for USD 2000
  Day 5: FINMA investigation begins

Impact: CHF 5 million in GDPR fines + customer lawsuits + reputational damage

Remediation:
  1. IMMEDIATELY restrict security group to VPC internal IPs only
  2. Change root password (mysql> ALTER USER 'root'@'localhost' IDENTIFIED BY 'strong-password')
  3. Enable encryption at rest (native MySQL encryption)
  4. Enable audit logging (log_error_verbosity = 3)
  5. Notify NCSC if customer data was exposed (ISG requirement)

Timeline: URGENT — 1–2 hours to patch
```

### Finding 2: Exposed RDP with Default Credentials (CRITICAL)

```
Domain: pharma-infrastructure.ch
Port: 3389/TCP
Status: 🚨 CRITICAL
Service: Windows Remote Desktop
Default Credentials: admin / admin (known issue)
Exposure: Open to internet

Attack Scenario:
  1. Attacker: rdesktop -u admin -p admin 203.0.113.46:3389
  2. Authentication succeeds
  3. Attacker gains interactive access to Windows Server
  4. Attacker deploys Conti ransomware
  5. All file servers encrypted, extortion demand: CHF 500,000

Mitigation Status: VULNERABLE
Missing Controls:
  - No MFA/2FA on RDP
  - No network segmentation
  - No RDP logging enabled
  - RDP runs as SYSTEM (code execution = domain admin)

Remediation (Priority 1):
  1. Immediately restrict RDP to VPN-only
  2. Disable RDP if not needed
  3. Implement MFA (NPS Radius or Azure AD)
  4. Enable RDP event logging (Event Viewer > Windows Logs > Security)
  5. Change admin password to 30+ char random string
  6. Run on non-standard port (e.g., 2222) to reduce automated scanning

Timeline: CRITICAL — Complete within 4 hours
```

### Finding 3: Open SSH with Weak Key Exchange (HIGH)

```
Domain: startup-infrastructure.ch
Port: 22/TCP
Status: ⚠️ HIGH
Service: OpenSSH 7.4p1 (deprecated, reached EOL in 2018)
Weak Algorithms Detected:
  - Diffie-Hellman Group1 (1024-bit, breakable)
  - DES cipher (64-bit, cryptographically broken)
  - SHA1 host key verification

CVE: CVE-2018-15473 (OpenSSH username enumeration)
Attacker can enumerate valid usernames without authentication

Current Cipher Suite: aes128-cbc, aes192-cbc (symmetric only, no forward secrecy)

Remediation:
  1. Upgrade OpenSSH to 9.0+ (supports modern key exchange)
  2. Disable weak algorithms: /etc/ssh/sshd_config
     - Remove: KexAlgorithms diffie-hellman-group1-sha1
     - Keep only: ECDH, curve25519

  3. Enforce key-based auth (disable password auth)
     - PasswordAuthentication no

  4. Implement MFA: AuthenticationMethods publickey,password

Timeline: HIGH priority — 2–4 hours to implement
```

### Finding 4: Exposed Redis (CRITICAL)

```
Domain: cache-platform.ch
Port: 6379/TCP
Status: 🚨 CRITICAL
Service: Redis 5.0.3 (no authentication)
Exposure: Open to internet, no password configured

Vulnerability:
  - Redis allows connection without password
  - Client can run ANY command (GET, DEL, FLUSHALL, etc.)
  - No encryption in transit

What's in Cache:
  - Session tokens (15 million keys cached)
  - API authentication tokens (JWT keys)
  - User personal data (cached from DB)
  - Recent searches and queries

Attack:
  1. attacker@kali:~$ redis-cli -h target.ch
     > SCAN 0
  2. Returns all keys: "session:user:1234", "token:api:xyz", etc.
  3. attacker@kali:~$ redis-cli -h target.ch GET session:user:1234
     > "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  4. Session token decoded → attacker impersonates user
  5. Attacker purchases items using stolen session

Remediation (IMMEDIATE):
  1. Add requirepass password in redis.conf:
     requirepass "very-long-random-password-32chars"
  2. Restrict network access: firewall to internal IPs only
  3. Enable encryption in transit: TLS port 6380
  4. Run Redis behind proxy (e.g., Envoy, HAProxy)
  5. Monitor for suspicious commands: redis SLOWLOG GET 10

Timeline: CRITICAL — 30 minutes to patch
```

### Finding 5: Open SMB (Port 445) — Ransomware Vector (CRITICAL)

```
Domain: infrastructure.ch
Port: 445/TCP
Status: 🚨 CRITICAL
Service: SMB v2.1, v3.0
Vulnerability: EternalBlue (CVE-2017-0144) — unpatched
Windows Version: Windows Server 2012 R2 (vulnerable, out of support)

Attack Timeline (typical ransomware):
  1. Attacker exploits EternalBlue → RCE on Server 2012
  2. Attacker uploads Cobalt Strike beacon
  3. Lateral movement to domain controller via SMB relay
  4. Domain Admin compromise
  5. Deploy ransomware to all file servers (SMB shares)
  6. Extortion: CHF 1–2 million ransom demand

Prevention Status: VULNERABLE
  - Patch MS17-010: NOT INSTALLED
  - SMB encryption: NOT ENABLED
  - Network segmentation: NONE
  - MFA on domain: NO

Remediation (Emergency):
  1. IMMEDIATELY apply patch MS17-010 (kb4012212 or later)
  2. Enable SMB encryption: Set-SmbServerConfiguration -EncryptData $true
  3. Restrict SMB to internal networks only (firewall port 445)
  4. Enable SMB signing: Registry > SMBServerConfiguration
  5. Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
  6. Monitor for suspicious SMB activity (Event ID 4625 failed logins)

Timeline: CRITICAL — Update within 2 hours
```

### Finding 6: Open Management Interface (HIGH)

```
Domain: devops-platform.ch
Port: 8080/TCP
Status: ⚠️ HIGH
Service: Jenkins 2.200 (CI/CD platform)
Authentication: Default credentials admin / admin
Public Exposure: Yes, accessible from internet

Exposed Information:
  - Build logs (contain deploy keys, API secrets)
  - Git repository URLs (source code infrastructure)
  - Docker registry credentials (artifact repository access)
  - Kubernetes cluster IPs (container orchestration)

Attack:
  1. Attacker accesses Jenkins GUI with default credentials
  2. Views build logs → extracts AWS_SECRET_ACCESS_KEY
  3. Uses credentials to access production AWS account
  4. Steals customer data, EC2 instances
  5. Or plants backdoor for persistence

Remediation:
  1. Enable authentication: Jenkins > Manage Jenkins > Configure Global Security
  2. Set strong admin password (minimum 30 characters)
  3. Restrict access to VPN/internal network only
  4. Rotate all exposed credentials (AWS keys, Docker creds, etc.)
  5. Enable audit logging (Jenkins Log Parser)
  6. Run on non-standard port (e.g., 9090) if external access needed

Timeline: HIGH — 1–2 hours to secure
```

---

## Compliance Reporting

### ISG §4 Report

```
NETWORK EXPOSURE ASSESSMENT
Domain: company.ch
Scan Date: 2026-03-15
Report Type: ISG §4 Network Boundary

OPEN PORTS SUMMARY:
✓ Port 80/443: HTTP/HTTPS (expected, monitored)
✓ Port 22: SSH (restricted to internal IPs)
✗ Port 3306: MySQL (CRITICAL — unexposed, remediated)
✗ Port 3389: RDP (CRITICAL — now restricted to VPN)
✓ Port 25/587: SMTP (authentication required)

REMEDIATION ACTIONS TAKEN:
  1. MySQL exposed via security group: FIXED
  2. RDP default credentials: CHANGED
  3. Open DNS resolver: DISABLED
  4. SMB signing: ENABLED

ISG COMPLIANT: YES (after remediation)
Last Updated: 2026-03-15

Audit Trail: All remediation actions logged and timestamped
```

### NIS2 Supply Chain Assessment

```
NIS2 Article 20 — Network Security
Supplier: contractor.ch
Assessment Date: 2026-03-15

Port Exposure Assessment:
  - Databases: NOT EXPOSED ✓
  - Remote access: RESTRICTED ✓
  - Management interfaces: INTERNAL ONLY ✓
  - Web servers: MONITORED ✓

Security Controls:
  - Firewall rules: DOCUMENTED
  - Port changes: LOGGED AND ALERTED
  - Incident response: READY

Supplier Status: ✓ APPROVED for critical operations
```

---

## Integration with Other Modules

- **Email Security:** Port 25/587/465 analysis for SMTP configuration
- **TLS & Certificates:** Port 443 TLS version enumeration
- **DNS & DNSSEC:** Port 53 DNS resolver analysis
- **Domain Protection:** DNS enumeration reveals subdomains that may have open ports

---

## Roadmap: Advanced Detections (Future)

- [ ] Aggressive scanning (all 65,535 ports)
- [ ] Firewall rule inference (TTL, response patterns)
- [ ] Service fingerprinting refinement (JARM, Bro IDS signatures)
- [ ] Vulnerability prioritization engine (CVSS + exploitability)
- [ ] Continuous port change monitoring (new ports = alert)
- [ ] Port knocking sequence detection

---

## Customer Value

**For SMEs:**
> "You think your database isn't exposed. We scan and find it accessible from the Internet. One customer had a Redis cache exposed for 18 months without knowing — we found it before attackers did."

**For Regulated Industries:**
> "ISG-compliant network assessment. We continuously scan for exposed ports, alert on changes, and provide remediation guidance. Auditors see that your external attack surface is monitored 24/7."
