# Phase 6 - Final Reports & Machine Exports

_Load after Phase 5, with the Phase 0 context documents._

**Objectives:** a human-readable report that stands alone for a reviewer who wasn't in the room; machine-readable JSON and SARIF exports.

---

## Step 0: Verify the Audit Trail

The report claims each phase ran. Check the workspace, not memory:

```bash
find .security-audit -type f -exec ls -l {} +
```
```powershell
Get-ChildItem .security-audit -Recurse -File | Select-Object Length, FullName
```

| Phase | Expected output | Required when |
|---|---|---|
| 0 | `project-profile.md`, `threat-model.md`, `data-flow-inventory.md` | Always |
| 0 | `dependency-cve-report.md`, `sbom.cdx.json` | Project has dependencies |
| 1 | `audit-checklist.md`, `security-findings.json` | Always |
| 2 | `pentest-methodology.md`, every trust boundary covered or marked reviewed | `standard`, `deep` |
| 3 | One script in `security-tests/` per Confirmed or Partially Mitigated finding | `standard`, `deep` |
| 4 | Remediation plan and recorded user approval in `audit-checklist.md` | Always (`quick`: plan without fixes) |
| 5 | Status and Regression-Guard on every approved finding | Fixes were approved |

Also check `security-findings.json` parses and has one entry per finding in `audit-checklist.md`. A missing or empty file means that phase didn't finish: complete it, or name the gap in the methodology section. Never summarize a phase with no output.

---

## Deliverable 1: Report

Write `.security-audit/security-audit-report.md` from `references/templates/final-report-template.md`. Required sections:

1. **Executive Summary:** project, date, type (Full/Differential), risk posture before and after remediation, totals (findings, critical/high, resolution rate)
2. **CVSS v4.0 Risk Metrics:** severity x (Initial | Confirmed | Remediated | Unresolved)
3. **Confidence Distribution:** confidence x count
4. **Attack Chains:** per chain, the findings involved, step-by-step narrative, composite impact, priority fix
5. **Detailed Findings & Remediation Log:** full schema per finding (`rules.md` section 6) plus PoC result, fix diff, final status
   - **5b. Verified-Safe / Assurance:** what you checked that held up. On a hardened codebase, confirming controls is most of the value. One line per surface: what you verified and how (e.g. "Payment integrity: prices resolved server-side, qty clamped, webhook signature-verified"). Distinguishes "checked and solid" from "not looked at". List only surfaces you actually traced.
6. **Compliance Mapping** (if requested in Phase 0): finding to CWE to control
7. **Differential Delta** (re-audits): prior vs current metrics, regressions
8. **Phase 7 Summary:** `deep` only. Phase 7 runs after this report, so write "Not run" and update later
9. **Phase 8 Summary:** same
10. **Residual Risk & Hygiene:** outstanding manual review items, next audit timing, practices

Standards: stands alone; every claim backed by code, tool output, or PoC; every finding actionable; low confidence labeled; Mermaid for attack chains, tables for metrics.

---

## Deliverable 2: JSON

`.security-audit/security-findings.json` per `references/templates/security-findings-schema.json`: all findings with complete metadata, attack chains with composition, audit metadata (date, version, mode, tools), SBOM reference.

## Deliverable 3: SARIF

`.security-audit/security-findings.sarif` from `references/templates/security-findings-sarif-template.json`.

- One SARIF rule per finding ID (`SEC-001`) with CWE tags and CVSS properties
- Exact `artifactLocation.uri`, `startLine`, `endLine`
- Levels: Critical/High = `error`, Medium/Low = `warning`, Informational = `note`
- Targets: GitHub Code Scanning (`github/codeql-action/upload-sarif`), VS Code SARIF Viewer, JetBrains Qodana, Azure DevOps Advanced Security

---

## Gate to Proceed

- [ ] `security-audit-report.md` complete
- [ ] `security-findings.json` valid and matches the schema
- [ ] `security-findings.sarif` valid SARIF v2.1.0
