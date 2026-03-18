# Regulatory Alignment

Switzerland's ISG (Informationssicherheitsgesetz) came into force in 2024, mandating baseline security controls for federal suppliers and critical infrastructure operators — with cantonal adoption cascading to SMEs in regulated sectors. Simultaneously, EU frameworks DORA (effective January 2025) and NIS2 (transposed across member states through 2024–2025) extend compliance obligations to financial entities and essential service providers operating across Swiss-EU borders. Non-compliance carries fines, mandatory breach disclosure, and personal liability for executives.

Most Swiss SMEs have no visibility into their own external attack surface. They don't know which services they're exposing, whether their certificates are expiring, or that their email domain can be spoofed today. Regulators increasingly require documented evidence of security posture — not just intent.

Helvetiscan turns passive exposure into actionable evidence. By scanning the full `.ch` namespace, it provides the first ground-truth baseline of Swiss digital hygiene at scale: which sectors are compliant, where the systemic gaps are, and what remediation looks like in practice. For a compliance consultant, an insurer pricing cyber risk, or a regulator assessing sector readiness — this dataset answers questions that no self-reported survey can.

---

### ISG §4 (Information Security Act, Switzerland)

**Mandatory Controls:**
- ✓ TLS certificates valid & strong (TLS & Certificates module)
- ✓ DNSSEC enabled (DNS module)
- ✓ HTTP security headers (HTTP Headers module)
- ✓ No exposed databases (Open Ports module)
- ✓ Email spoofing prevention (Email Security module)
- ✓ Software patching (Technology Fingerprinting module)

### DORA 16 (Digital Operational Resilience Act, EU)

**Requirements:**
- ✓ Software asset inventory (Technology module)
- ✓ Vulnerability tracking (Technology module)
- ✓ Certificate lifecycle management (TLS module)
- ✓ Network security (Open Ports module)

### NIS2 (Network & Information Security Directive 2, EU)

**Supply Chain Requirements:**
- ✓ Network segmentation assessment (Open Ports)
- ✓ Email authentication (Email Security)
- ✓ Vulnerability tracking (Technology)
- ✓ Domain ownership proof (Domain Protection)

---

## Usage Examples

### For a Healthcare Provider (GDPR-sensitive)

```
helvetiscan scan: hospital.ch

Results:
  1. Email Security: DMARC p=none (HIGH RISK)
     → Patient data vulnerable to spoofing
     → Recommendation: Implement DMARC p=reject within 30 days

  2. Open Ports: 3306 exposed (MySQL)
     → Patient database visible on Internet
     → Recommendation: URGENT — restrict to VPN within 1 hour

  3. TLS: Certificate expires in 60 days
     → Recommendation: Schedule renewal 30 days before

Compliance Status: FAILING
Timeline to ISG Compliance: 30 days (if recommendations followed)
```

### For a Fintech Company (DORA-regulated)

```
helvetiscan scan: paymentbank.ch

Results:
  1. Technology: WordPress 5.0.0 (35 months behind, 25+ CVEs)
     → Critical unpatched software
     → DORA Finding: Remediate within 30 days

  2. Domain: Typosquats registered (paymentbnk.ch)
     → Brand impersonation detected
     → Recommendation: Monitor and register variants

  3. Ports: SSH open, TLS 1.1 enabled
     → Legacy encryption, DORA requires TLS 1.2+
     → Recommendation: Upgrade TLS baseline

DORA Compliance: PARTIALLY COMPLIANT
Actions Required: 3 (all with clear timelines)
```

### For an SME (General Security)

```
helvetiscan scan: startup.ch

Results:
  1. Email Security: SPF present, DKIM weak (1024-bit), DMARC missing
     → Email spoofing risk: MEDIUM
     → Quick fix: Add DMARC p=reject (5 minutes)

  2. Domain: Auto-renewal disabled, expires in 90 days
     → Risk: Domain loss if renewal notification missed
     → Quick fix: Enable auto-renewal (2 minutes)

  3. Ports: No databases exposed (good!)
     → No critical findings

  4. HTTP Headers: CSP missing, HSTS present
     → XSS risk: MEDIUM
     → Recommendation: Add CSP rule

Overall Risk: MEDIUM
Quick Wins (Today): Email (DMARC), Domain (auto-renewal)
Medium-term: HTTP headers CSP
```
