# Security Audit & Verification Report

## Executive Summary
- **Project Name:**
- **Audit Date:**
- **Audit Type:** Full / Differential (if differential, prior audit date: YYYY-MM-DD)
- **Initial Risk Posture:**
- **Post-Remediation Risk Posture:**
- **Machine-Readable Findings:** Exported to `.security-audit/security-findings.json` (SARIF compatible)

## CVSS v4.0 Risk Metrics Summary

| Severity | Initial Count | Confirmed Exploitable | Remediated | Unresolved / Manual Review |
|---|---|---|---|---|
| **Critical** | | | | |
| **High** | | | | |
| **Medium** | | | | |
| **Low** | | | | |
| **Informational** | | | | |
| **Total** | | | | |

## Confidence Distribution

| Confidence Level | Count | Description |
|---|---|---|
| **High** | | Verified via CLI tool output or successful PoC execution |
| **Medium** | | Code pattern matches vulnerability signature, but untested dynamically |
| **Low** | | Theoretical risk based on architecture; requires human expert review |

---

## Attack Chain Analysis

<!-- Document composite multi-finding exploit paths. These are often the most critical items
     because the combined impact exceeds any individual finding. -->

### [CHAIN-01] Chain Title
- **Composed Findings:** SEC-XXX → SEC-YYY → SEC-ZZZ
- **Narrative:** Step-by-step description of how an attacker chains these vulnerabilities
- **Composite Impact:** What the attacker achieves at the end of the chain
- **Composite CVSS v4.0:** Score reflecting the combined impact
- **Remediation Priority:** Which finding in the chain is cheapest to fix to break the entire chain

---

## Detailed Audit Findings & Remediation Log

### [SEC-001] Finding Title
- **File/Line:** `path/to/file.ext:123-145`
- **CVSS v4.0:** `CVSS:4.0/...` (Score: X.X)
- **Severity:** Critical | High | Medium | Low | Informational
- **Confidence:** High | Medium | Low
- **CWE:** CWE-XXX
- **STRIDE Category:** Spoofing | Tampering | Repudiation | Info Leak | DoS | Elevation of Privilege
- **Detected By:** LLM Analysis | CLI Scanner | Both
- **Triage Evidence:**
  - Source-to-Sink Trace: [verified path description]
  - Production Context: Yes/No
  - Mitigating Controls: None / [description of existing controls]
  - Exploit Feasibility: [prerequisites required]
- **Explanation:**
- **Exploit Scenario:**
- **Phase 2 Dynamic PoC Verification:** `.security-audit/security-tests/test_sec001_poc.py` (Verdict: ...)
- **Applied Fix Diff:**
```diff
- vulnerable_code()
+ secure_code()
```
- **Final Status:** Resolved | Requires Manual Review

---

## Compliance Mapping (Optional)

_Include this section if compliance framework mapping was requested during Phase 0._

| Finding ID | CWE | PCI-DSS | SOC 2 | HIPAA | GDPR | ISO 27001 |
|---|---|---|---|---|---|---|
| SEC-001 | CWE-89 | 6.5.1 | CC6.1 | §164.312(a) | Art. 32 | A.14.2.5 |

---

## Differential Audit Delta (for Re-Audits)

_Include this section only for differential re-audits._

| Metric | Prior Audit | This Audit | Delta |
|---|---|---|---|
| Total Findings | | | |
| Critical/High | | | |
| Resolved (carried forward) | | | |
| New Findings | | | |
| Regressions Detected | | | |
| Accepted Risk (unchanged) | | | |

### Regression Analysis
<!-- List any previously-resolved findings that regressed, with the git commit that re-introduced the vulnerability. -->

---

## Phase 6 — Continuous Security & CI/CD Guardrail Summary
- **Custom Semgrep Rules:** Generated in `.semgrep/` directory
- **CI/CD Security Workflow:** Installed at `.github/workflows/security-audit.yml`
- **Git Audit Tag:** Recommend running `git tag -a security-audit-vN -m "Audit YYYY-MM-DD"`

---

## Phase 7 — Infrastructure & Operational Hardening Recommendations
_Actionable external checklist exported to `.security-audit/hardening-recommendations.md`._

| Priority | Category | Action Item | Target Provider / Layer | Status |
|---|---|---|---|---|
| **High** | WAF & Edge | Deploy WAF with OWASP Top 10 ruleset | Cloudflare / AWS WAF | Pending User Action |
| **High** | Transport | Enforce TLS 1.2+ & HSTS preload | Reverse Proxy / CDN | Pending User Action |
| **Medium** | DNS & Email | Publish SPF, DKIM, DMARC (`p=quarantine`) records | Domain Registrar / DNS | Pending User Action |
| **Medium** | Secrets | Migrate `.env` files to managed vault | AWS Secrets Mgr / HashiCorp Vault | Pending User Action |
| **Low** | Compliance | Deploy `/.well-known/security.txt` (RFC 9116) | Public Web Root | Pending User Action |

---

## Residual Risk & Ongoing Hygiene Recommendations
1.
2.
3.
