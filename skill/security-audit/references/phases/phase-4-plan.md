# Phase 4 - Remediation Plan & Attack Chain Composition (Approval Gate)

_Load this after Phase 3 is complete. Also load `.security-audit/audit-checklist.md` and `.security-audit/security-findings.json`._

---

## Objectives

1. Compose multi-step attack chain narratives from individual findings
2. Produce a prioritized remediation plan with minimal fix diffs
3. Map findings to compliance controls (if requested in Phase 0)
4. **Obtain explicit user approval before any code modifications**

---

## Step 1: Attack Chain Composition

After individual findings are scored, attempt to compose multi-step attack narratives.

### How to Compose Chains
1. List all findings with status "Confirmed Exploitable" or "Partially Mitigated"
2. For each finding, ask: "If an attacker succeeds here, what does it give them access to?"
3. Check if that access enables exploitation of another finding
4. Common chain patterns:
   - **SSRF → Internal Service Access → Data Exfiltration**
   - **Information Disclosure → Credential Theft → Privilege Escalation**
   - **Mass Assignment → Role Elevation → Admin Access**
   - **Open Redirect → Phishing → Session Hijack**
   - **Prompt Injection → Tool Calling → Arbitrary Code Execution**
   - **SQL Injection → Data Dump → Credential Reuse → Account Takeover**
   - **Dependency Vulnerability → RCE → Lateral Movement**
   - **Misconfiguration → Information Leak → Targeted Attack**

### Chain Scoring
- A chain's composite severity is determined by its **end impact**, not the average of individual findings
- An SSRF (Medium) that enables admin access (Critical) is a **Critical** chain
- The chain's CVSS v4.0 vector should be **freshly composed** reflecting the end-to-end attack path

### Chain Confidence
- If **all links** are `Confidence: High`, the chain is `Confidence: High`
- If **any link** is `Confidence: Medium`, the chain is `Confidence: Medium`
- If **any link** is `Confidence: Low`, the chain is `Confidence: Low` → goes to "Requires Manual Review" section

### Priority Identification
For each chain, identify the **cheapest link to break** - the single finding whose fix disrupts the entire chain. This becomes the highest-priority remediation item.

Document chains in `.security-audit/security-findings.json` under `attackChains` and in the remediation plan.

---

## Step 2: Prioritized Remediation Plan

Produce a remediation plan ordered **Critical → High → Medium → Low → Informational**.

### For Each Finding
```markdown
### [SEC-XXX] Finding Title - Severity: Critical/High/Medium/Low

**File/Line:** `path/to/file.ext:123-145`
**CVSS v4.0:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H` (Score: 8.7)
**Confidence:** High | Medium | Low
**Phase 3 PoC Result:** Confirmed Exploitable | Partially Mitigated | Inconclusive

**Risk Explanation:**
[Tied to Phase 3 PoC evidence - what was proven and what the impact is]

**Proposed Fix:**
```diff
- vulnerable_code()
+ secure_code()
```

**Regression Risk:**
[What could break if this fix is applied - dependency changes, behavior changes, performance impact]

**Remediation SLA:**
[Based on severity - see references/threat-intel.md for SLA guidelines]
```

### Separation of Auto-Remediable vs Manual Review

Clearly separate findings into two groups:

**Group A: Approved for Auto-Remediation** (Confidence: High or Medium)
- Listed with full fix diffs
- Ordered by severity

**Group B: Requires Manual Expert Review** (Confidence: Low)
- Listed separately with reasoning for why auto-remediation is not appropriate
- Includes suggested investigation steps for the human reviewer
- These findings are EXCLUDED from Phase 5 auto-remediation

---

## Step 3: Compliance Mapping (If Requested)

If compliance framework mapping was requested during Phase 0, load `references/compliance/compliance-matrix.md` and map each finding:

```markdown
| Finding ID | CWE | PCI-DSS 4.0 | SOC 2 | HIPAA | GDPR | ISO 27001 | NIST CSF | ASVS 5.0 |
|---|---|---|---|---|---|---|---|---|
| SEC-001 | CWE-89 | 6.5.1 | CC6.1 | §164.312(a) | Art. 32 | A.14.2.5 | PR.DS-1 | V5.3.4 |
```

---

## Step 4: Approval Gate

Present the complete remediation plan to the user, then **stop and ask verbatim**:

> Do you approve this remediation plan? Type YES to proceed with automated fixes, or provide feedback to revise the plan.

### Hard Rules
- **Do not touch project source files before this approval.** This is a hard gate, not a suggestion.
- Low-confidence findings are excluded from auto-remediation and listed separately
- If the user provides feedback, revise the plan and ask again
- If the user approves partially, only proceed with approved items

---

## Gate to Proceed

Do not advance to Phase 5 until:
- [ ] Attack chains have been composed and documented
- [ ] Remediation plan is prioritized by severity
- [ ] Compliance mappings are included (if requested)
- [ ] **Explicit user approval has been received** (YES response)
- [ ] The plan and the approval (date, and which findings were approved) are recorded in `.security-audit/audit-checklist.md`, so Phase 6 can verify them
