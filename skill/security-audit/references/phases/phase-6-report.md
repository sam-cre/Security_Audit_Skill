# Phase 5 — Final Reports & Machine Exports

_Load this after Phase 4 is complete. Load all Phase 0 context documents to produce the final comprehensive report._

---

## Objectives

1. Produce a comprehensive human-readable security audit report
2. Export machine-readable findings in JSON and SARIF formats
3. Write for a reviewer who wasn't in the room — the report must stand alone

---

## Deliverable 1: Human-Readable Report

Write `.security-audit/security-audit-report.md` using template `references/templates/final-report-template.md`.

### Required Sections

1. **Executive Summary**
   - Project name, audit date, audit type (Full/Differential)
   - Initial risk posture vs. post-remediation risk posture
   - Key statistics: total findings, critical/high counts, resolution rate

2. **CVSS v4.0 Risk Metrics Summary**
   - Table: Severity × (Initial Count | Confirmed | Remediated | Unresolved)

3. **Confidence Distribution**
   - Table: Confidence Level × Count with descriptions

4. **Attack Chain Analysis**
   - Each composed chain: findings involved, step-by-step narrative, composite impact, CVSS, priority fix

5. **Detailed Findings & Remediation Log**
   - Every finding with full schema (file/line, CVSS, CWE, STRIDE, triage evidence, explanation, exploit scenario, PoC result, fix diff, final status)

5b. **Verified-Safe / Assurance** — what you checked that held up
   - On a well-hardened codebase, *confirming controls work* is most of the audit's value; capture it as a first-class result, not an afterthought. For each significant attack surface or control you examined and found sound, record one line: **the surface, what you verified, and how** (e.g. "Payment integrity — prices resolved server-side from catalog, qty clamped, webhook signature-verified; client cannot tamper price/qty"). This tells the reader what has coverage, distinguishes "checked and solid" from "not looked at," and turns a zero/low-finding audit into evidence of assurance rather than an empty report. Keep it evidence-based — only list surfaces you actually traced.

6. **Compliance Mapping** (if requested in Phase 0)
   - Finding → CWE → compliance control cross-reference table

7. **Differential Audit Delta** (if this is a re-audit)
   - Prior vs. current metrics, regression analysis

8. **Phase 6 Summary** (CI/CD guardrails installed)

9. **Phase 7 Summary** (infrastructure hardening recommendations)

10. **Residual Risk & Ongoing Hygiene**
    - Outstanding manual review items
    - Recommended next audit timeline
    - Security hygiene practices

---

## Deliverable 2: Machine-Readable JSON

Write `.security-audit/security-findings.json` following schema `references/templates/security-findings-schema.json`.

Ensure the JSON includes:
- All individual findings with complete metadata
- Attack chains with composition details
- Audit metadata (date, version, mode, tools used)
- SBOM reference

---

## Deliverable 3: SARIF Export

Write `.security-audit/security-findings.sarif` using template `references/templates/security-findings-sarif-template.json`.

### SARIF Mapping Rules

1. **Rule ID Mapping:** Map each finding ID (`SEC-001`) to a SARIF rule object with CWE tags and CVSS properties

2. **Location Precision:** Include exact `artifactLocation.uri`, `startLine`, and `endLine` for inline IDE highlighting

3. **Level Mapping:**
   | Severity | SARIF Level |
   |---|---|
   | Critical / High | `error` |
   | Medium / Low | `warning` |
   | Informational | `note` |

4. **Integration Targets:**
   - GitHub Code Scanning (upload via `github/codeql-action/upload-sarif`)
   - VS Code SARIF Viewer extension
   - JetBrains Qodana
   - Azure DevOps Advanced Security

---

## Writing Quality Standards

The report must:
- **Stand alone.** A reader with no prior context should understand every finding
- **Be evidence-based.** Every claim is backed by code references, tool output, or PoC results
- **Be actionable.** Every finding includes specific remediation steps
- **Be honest about uncertainty.** Low-confidence findings are clearly labeled as such
- **Include visual aids.** Mermaid diagrams for attack chains, tables for metrics

---

## Gate to Proceed

Do not advance to Phase 6 until:
- [ ] `.security-audit/security-audit-report.md` is complete
- [ ] `.security-audit/security-findings.json` is valid JSON matching the schema
- [ ] `.security-audit/security-findings.sarif` is valid SARIF v2.1.0
