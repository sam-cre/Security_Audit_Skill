# Phase 4 - Remediation Plan & Attack Chains (Approval Gate)

_Load after Phase 3, plus `.security-audit/audit-checklist.md` and `security-findings.json`._

**Objectives:** compose attack chains; produce a prioritized plan with minimal fix diffs; map to compliance if requested; **get explicit approval before touching any code.**

---

## Step 1: Attack Chains

1. List findings that are Confirmed Exploitable or Partially Mitigated.
2. For each: if an attacker succeeds here, what does it reach? Does that enable another finding?
3. Common chains:
   - SSRF, internal service access, data exfiltration
   - Information disclosure, credential theft, privilege escalation
   - Mass assignment, role elevation, admin access
   - Open redirect, phishing, session hijack
   - Prompt injection, tool calling, arbitrary code execution
   - SQL injection, data dump, credential reuse, account takeover
   - Dependency vulnerability, RCE, lateral movement
   - Misconfiguration, information leak, targeted attack

**Severity:** set by the chain's **end impact**, not the average. A Medium SSRF that yields admin access is a Critical chain. Compose a fresh CVSS v4.0 vector for the end-to-end path (`rules.md` section 4).

**Confidence:** the lowest link wins. All High gives High; any Medium gives Medium; any Low gives Low and goes to "Requires Manual Review".

**Priority:** find the cheapest link to break, the one finding whose fix disrupts the whole chain. It becomes the top remediation item.

Record chains in `security-findings.json` under `attackChains` and in the plan.

---

## Step 2: Remediation Plan

Order Critical, High, Medium, Low, Informational. Per finding:

````markdown
### [SEC-XXX] Title - Severity: Critical/High/Medium/Low
**File/Line:** `path/to/file.ext:123-145`
**CVSS v4.0:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H` (Score: not computed | calculator-verified)
**Confidence:** High | Medium | Low
**Phase 3 PoC Result:** Confirmed Exploitable | Partially Mitigated | Inconclusive
**Risk Explanation:** what the PoC proved and the impact
**Proposed Fix:**
```diff
- vulnerable_code()
+ secure_code()
```
**Regression Risk:** what the fix could break (dependencies, behavior, performance)
**Remediation SLA:** by severity, per `references/threat-intel.md`
````

Split into two groups:
- **Group A, auto-remediation** (High or Medium confidence): full diffs, ordered by severity.
- **Group B, manual expert review** (Low confidence): reasons auto-fix is inappropriate plus investigation steps. Excluded from Phase 5.

---

## Step 3: Compliance Mapping (if requested)

Load `references/compliance/compliance-matrix.md` and map each finding:

```markdown
| Finding | CWE | PCI-DSS 4.0 | SOC 2 | HIPAA | GDPR | ISO 27001 | NIST CSF | ASVS 5.0 |
|---|---|---|---|---|---|---|---|---|
| SEC-001 | CWE-89 | 6.5.1 | CC6.1 | §164.312(a) | Art. 32 | A.14.2.5 | PR.DS-1 | V5.3.4 |
```

---

## Step 4: Approval Gate

Present the full plan, then **stop and ask verbatim**:

> Do you approve this remediation plan? Type YES to proceed with automated fixes, or provide feedback to revise the plan.

- Touch no project source file before approval. Hard gate.
- Feedback: revise and ask again. Partial approval: proceed with approved items only.

---

## Gate to Proceed

- [ ] Chains composed and documented
- [ ] Plan prioritized by severity
- [ ] Compliance mapping included (if requested)
- [ ] **Explicit user approval received** (YES)
- [ ] Plan and approval (date, approved findings) recorded in `audit-checklist.md` for Phase 6 to verify
