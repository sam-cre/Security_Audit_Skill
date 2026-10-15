# Core Rules - Loaded Once, Applies to Every Phase

Single source of truth for confidence, scoring, evidence, and safety. Phase files cite sections by number. If a phase contradicts this file, this file wins.

---

## 1. Authorization & Scope

Before Phase 0, confirm the user owns or is authorized to test the target. Record scope in `project-profile.md`.

- **In scope:** local codebase, local dev instances, sandboxed containers.
- **Out of scope by default:** production, staging, shared environments, third-party APIs, any domain or IP the user has not confirmed they control.

Send no traffic outside confirmed scope. For a domain, ask the user to confirm ownership first. "It's my client's" is not enough; ask for confirmation that testing is authorized.

---

## 2. Confidence Calibration

Every finding carries a `Confidence`.

| Confidence | Criteria | Auto-remediate? |
|---|---|---|
| **High** | Scanner output, a successful PoC, or a full source-to-sink trace you read in the code | Yes |
| **Medium** | Matches a known vulnerable pattern; trace plausible but has an unread gap; no dynamic confirmation | Yes, gap stated in the diff comment |
| **Low** | Theoretical; depends on architecture or runtime config you cannot see | **No.** Mark `Requires Manual Review` |

Raise confidence only on new evidence. Lower it freely.

### Anti-Fabrication

1. Never invent a CVE ID. Unverifiable: `"Suspected vulnerability in PKG vX.Y.Z - CVE unverified."`
2. Never call a version vulnerable without scanner or advisory-database confirmation. Cite which.
3. Never describe an exploit you cannot ground in code you read. An SQLi claim in an ORM codebase must show the line where the ORM is bypassed.
4. Never report a line you did not read. If you grepped, read the surrounding function first.
5. "I don't know" is a valid finding: `Confidence: Low, Status: Requires Manual Review`, with honest reasoning.

---

## 3. The 4-Point Triage Gate

Run every candidate (scanner or reasoned) through all four. Fail any: discard, or downgrade to Informational and record why.

1. **Source-to-Sink.** Can untrusted input reach the sink? Trace the real call chain, e.g. `req.body.name` -> `handler()` -> `buildQuery()` -> `db.raw()` unsanitized. "Looks dangerous" is not a trace.
2. **Production Context.** Is the code reachable in production? Exclude tests, fixtures, mocks, examples, benchmarks, build tooling, generated code, unless the generator or build pipeline is the target or the user asked for test review.
3. **Mitigating Controls.** Does something upstream handle it (ORM parameterization, auto-escaping, CSRF middleware, validation, types)? If so, show a **specific bypass** or mark Mitigated.
4. **Exploit Feasibility.** Is there a realistic path? Record prerequisites: network position, auth level, non-default config, timing, user interaction. Admin + race window + non-default flag is real but not Critical.

---

## 4. Severity & CVSS

**You cannot compute a CVSS v4.0 number.** v4.0 uses MacroVector lookup tables. Never print an invented decimal.

1. Emit the vector string, which you can derive by reasoning: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`
   Metrics: AV N/A/L/P, AC L/H, AT N/P, PR N/L/H, UI N/P/A, VC/VI/VA and SC/SI/SA H/L/N.
2. Assign severity by judgment, checked against the bands below.
3. Mark provenance: `Score: 9.3 (calculator-verified)` (tool or FIRST calculator) or `Score: not computed`.

If a scanner emitted a score, use it and cite the scanner.

| Band | Score | Meaning |
|---|---|---|
| Critical | 9.0-10.0 | Unauthenticated remote compromise, or mass data exposure |
| High | 7.0-8.9 | Serious impact, but needs auth, interaction, or a precondition |
| Medium | 4.0-6.9 | Real but constrained, or meaningful prerequisites |
| Low | 0.1-3.9 | Minor exposure, defense-in-depth gap |
| Informational | 0.0 | Hygiene, no direct security impact |

---

## 5. CVE Verification

1. **Preferred:** scanner output (`trivy`, `osv-scanner`, `pip-audit`, `npm audit`, `cargo audit`). Cite the tool.
2. **Fallback:** query OSV.dev:
   ```bash
   curl -s -X POST https://api.osv.dev/v1/query \
     -d '{"package":{"name":"PACKAGE","ecosystem":"PyPI"},"version":"VERSION"}'
   ```
   Ecosystems: `PyPI`, `npm`, `Go`, `crates.io`, `Maven`, `NuGet`, `RubyGems`, `Packagist`, `Hex`, `Pub`.
3. Never recall a CVE ID from memory.
4. Unverifiable: `"Suspected vulnerability - CVE unverified."`, `Confidence: Low`.

### Reachability Rubric

Do not rate every advisory at the scanner's headline severity.

| Situation | Treat as |
|---|---|
| Direct dependency, called on a path handling untrusted input | Scanner severity |
| Direct dependency, vulnerable function or flag never invoked | Down one band; name the unused sink |
| Transitive, reached only by internal use, no attacker input into the vulnerable code | Usually Low; name the parent and why the trigger is unreachable |
| Advisory needs a config or API you don't use | Informational; name the unmet precondition |
| `devDependency`, never shipped | Informational, unless the build pipeline is the target (Gate 2) |

For transitive hits, give the chain (`A -> B -> vulnerable C`) and say whether the fix needs a breaking major bump.

---

## 6. Finding Schema

Write every finding to both `.security-audit/audit-checklist.md` (human) and `.security-audit/security-findings.json` (machine, schema at `references/templates/security-findings-schema.json`).

```markdown
### [SEC-XXX] Short imperative title
- **File/Line:** path/to/file.ext:123-145
- **CVSS v4.0:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H
- **Score:** 9.3 (calculator-verified) | not computed
- **Severity:** Critical | High | Medium | Low | Informational
- **Confidence:** High | Medium | Low
- **CWE:** CWE-XXX
- **OWASP:** A0X:2025 (see the domain guide headings)
- **STRIDE:** Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation of Privilege
- **Detected By:** Reasoned Review | Scanner (<name>) | Both | DAST | Adversarial Review
- **Triage Evidence:**
  - Source-to-Sink: <actual trace>
  - Production Context: Yes/No - <why>
  - Mitigating Controls: None | <what exists and how it is bypassed>
  - Prerequisites: <auth, network position, config, timing>
- **Explanation:** What is wrong, in plain language.
- **Exploit Scenario:** Concrete attacker narrative grounded in this code.
- **Remediation:** Specific change with a code-level example.
- **Regression-Guard:** The concrete check that stops the fix reverting (Semgrep rule, test, CI assertion; Phase 7 installs it), or `None (manual)`. `N/A` for unfixed or Low findings.
- **Status:** Unconfirmed -> Confirmed Exploitable | Partially Mitigated | Fully Mitigated | Inconclusive -> Resolved | Requires Manual Review
```

---

## 7. Noise Control - Do Not Report

Skip unless genuinely exploitable in context:

- Missing security headers on an API serving no HTML
- "Weak" crypto in non-security use (MD5 as a cache key or ETag)
- Dev-only dependency CVEs that never ship (unless the build pipeline is the target)
- Hardcoded credentials in test fixtures pointing at localhost
- `Math.random()` outside a security decision
- Missing rate limits where an authenticated gateway already limits
- Generic "use a WAF" advice with no finding behind it
- Anything with no concrete exploit scenario

Worth a mention but failing the Gate: put it in an **Informational** section at the end of the report, not in findings.

---

## 8. Safety Constraints

- **Local only.** Local project or sandbox. Nothing outside confirmed scope.
- **Confirm before any network test.** State target, port, plan; get an explicit yes.
- **Non-destructive PoCs.** Prove presence with canaries, timing, or error-based detection. Never `DROP TABLE`.
- **Zero exfiltration.** Nothing leaves the machine. Redact secrets: record location and type, never the value.
- **Bounded resources.** Cap race-test concurrency. Cap DAST to ~5 concurrent requests with delay.
- **Small wordlists.** Weak or default credential checks only. No large-scale brute force.
- **No evasion.** Write no detection-evasion or anti-forensics logic.

---

## 9. Cross-Cutting Rules

- Write `.security-audit/` files live at every phase transition. A crashed session must be resumable.
- Modify no project file before Phase 4 approval, however safe the fix looks.
- Something wrong that matches no named class: file it for human review, don't drop it.
- Secrets in code or history: record file, line, type. Never write the value into any artifact.
- A fix that fails twice: stop and roll back.
- Say what you could not verify. An audit that overstates coverage is worse than a short one.
