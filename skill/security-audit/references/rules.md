# Core Rules - Loaded Once, Applies to Every Phase

_This is the single source of truth for confidence, scoring, evidence, and safety. Phase files do **not** restate these rules; they reference them. If a phase seems to contradict this file, this file wins._

---

## 1. Authorization & Scope

Before Phase 0, confirm the user owns or is authorized to test the target. State the scope explicitly in `project-profile.md`:

- **In scope:** the local codebase, local dev instances, sandboxed containers.
- **Out of scope by default:** production hosts, staging, shared environments, third-party APIs, any IP or domain you did not confirm the user controls.

Never scan, probe, or send traffic to a host outside the confirmed scope. If the user asks you to test a domain, ask them to confirm they own it before any network activity. "It's my client's" is not sufficient on its own - ask for confirmation that testing is authorized.

---

## 2. Confidence Calibration

Every finding carries a `Confidence`. Non-negotiable.

| Confidence | Criteria | Auto-remediate? |
|---|---|---|
| **High** | Verified by scanner output, a successful PoC run, or a complete source-to-sink trace you actually read in the code | Yes |
| **Medium** | Matches a known vulnerable pattern, trace is plausible but has an unread gap, no dynamic confirmation | Yes, with the gap stated in the diff comment |
| **Low** | Theoretical; depends on architecture or runtime config you cannot see from the code | **No** - mark `Requires Manual Review` |

Escalate confidence only on new evidence. Downgrade freely.

### Anti-Fabrication Rules

1. **Never invent a CVE ID.** Unverifiable → `"Suspected vulnerability in PKG vX.Y.Z - CVE unverified."`
2. **Never assert a version is vulnerable** without scanner or advisory-database confirmation. Cite which.
3. **Never describe an exploit you cannot ground in code you read.** Claiming SQLi in an ORM codebase requires showing the exact line where the ORM is bypassed.
4. **Never report a line number you did not read.** If you grepped, read the surrounding function before filing.
5. **"I don't know" is a valid finding.** File as `Confidence: Low, Status: Requires Manual Review` with honest reasoning. This is always better than a confident guess.

---

## 3. The 4-Point Triage Gate

Run every candidate finding - scanner-sourced or reasoned - through all four. Fail any gate → discard, or downgrade to Informational with the reason recorded.

**Gate 1 - Source-to-Sink.** Can untrusted input actually reach the sink? Trace the real call chain. Not "this function looks dangerous" but "`req.body.name` flows into `handler()` → `buildQuery()` → `db.raw()` unsanitized."

**Gate 2 - Production Context.** Is this code reachable in production? Exclude tests, fixtures, mocks, examples, benchmarks, build tooling, and generated code - *unless* the generator or the build pipeline is itself the target, or the user asked for test coverage review.

**Gate 3 - Mitigating Controls.** Is something upstream already handling it? ORM parameterization, template auto-escaping, framework CSRF middleware, a validation layer, type enforcement. If a control exists, you must demonstrate a **specific bypass** or the finding is Mitigated.

**Gate 4 - Exploit Feasibility.** Does a realistic path exist? Record the prerequisites: network position, auth level required, non-default config needed, timing window, user interaction. A vuln needing admin access plus a race window plus a non-default flag is real but is not Critical.

---

## 4. Severity & CVSS

**You cannot compute a CVSS v4.0 numeric score.** v4.0 scoring uses MacroVector lookup tables, not a formula you can evaluate reliably. Do not print an invented decimal.

Instead:

1. **Emit the vector string.** This is derivable by reasoning and is the useful artifact:
   `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`
2. **Assign severity by judgment**, using the band table below as a sanity check.
3. **Mark the number's provenance.** Either `Score: 9.3 (calculator-verified)` when a tool or the FIRST calculator produced it, or `Score: not computed` - never a bare invented decimal.

If a scanner already emitted a score, use the scanner's and cite it.

### Metrics

| Metric | Values |
|---|---|
| AV - Attack Vector | Network (N), Adjacent (A), Local (L), Physical (P) |
| AC - Attack Complexity | Low (L), High (H) |
| AT - Attack Requirements | None (N), Present (P) |
| PR - Privileges Required | None (N), Low (L), High (H) |
| UI - User Interaction | None (N), Passive (P), Active (A) |
| VC/VI/VA - Vulnerable system C/I/A | High (H), Low (L), None (N) |
| SC/SI/SA - Subsequent system C/I/A | High (H), Low (L), None (N) |

### Severity Bands

| Band | Score | Rough meaning |
|---|---|---|
| Critical | 9.0–10.0 | Unauthenticated remote compromise, or mass data exposure |
| High | 7.0–8.9 | Serious impact, but needs auth, interaction, or a precondition |
| Medium | 4.0–6.9 | Real but constrained impact or meaningful prerequisites |
| Low | 0.1–3.9 | Minor exposure, defense-in-depth gap |
| Informational | 0.0 | Hygiene; no direct security impact |

---

## 5. CVE Verification Protocol

1. **Preferred** - scanner output (`trivy`, `osv-scanner`, `pip-audit`, `npm audit`, `cargo audit`) is authoritative. Cite the tool.
2. **Fallback** - query OSV.dev directly:
   ```bash
   curl -s -X POST https://api.osv.dev/v1/query \
     -d '{"package":{"name":"PACKAGE","ecosystem":"PyPI"},"version":"VERSION"}'
   ```
   Ecosystems: `PyPI`, `npm`, `Go`, `crates.io`, `Maven`, `NuGet`, `RubyGems`, `Packagist`, `Hex`, `Pub`.
3. **Never** recall a CVE ID from memory. Training-data CVE recall is unreliable and the failure is silent.
4. **Unverifiable** → `"Suspected vulnerability - CVE unverified."` and `Confidence: Low`.

Reachability matters: a CVE in a dependency you never call is lower priority than a CVE on a hot path. Note reachability when you can determine it.

### Dependency Reachability Rubric

Standardize the reachability judgment - don't rate every advisory at the scanner's headline severity:

| Situation | Treat as |
|---|---|
| Direct dependency, called on a path that handles untrusted input | Scanner severity (High/Critical stays) |
| Direct dependency, but the vulnerable function/flag is never invoked | Down one band; state the unused sink |
| **Transitive** dependency, reached only via internal library usage (no attacker-controlled input into the vulnerable code) | Low, usually - say which parent pulls it and why the trigger is unreachable |
| Advisory requires a config/API you don't use (e.g. `uuid` bounds check only when a caller-supplied `buf` is passed) | Informational - name the precondition you don't meet |
| `devDependency`, never shipped or run in prod | Informational, unless the build pipeline itself is the target (see Gate 2) |

Always name the parent chain for transitive hits (`A → B → vulnerable C`) and whether the fix requires a breaking major bump - the user needs that to plan the upgrade.

---

## 6. Finding Schema

Every finding goes in **both** `.security-audit/audit-checklist.md` (human) and `.security-audit/security-findings.json` (machine, schema at `references/templates/security-findings-schema.json`).

```markdown
### [SEC-XXX] Short imperative title
- **File/Line:** path/to/file.ext:123-145
- **CVSS v4.0:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H
- **Score:** 9.3 (calculator-verified) | not computed
- **Severity:** Critical | High | Medium | Low | Informational
- **Confidence:** High | Medium | Low
- **CWE:** CWE-XXX
- **STRIDE:** Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation of Privilege
- **Detected By:** Reasoned Review | Scanner (<name>) | Both | DAST | Adversarial Review
- **Triage Evidence:**
  - Source-to-Sink: <the actual trace>
  - Production Context: Yes/No - <why>
  - Mitigating Controls: None | <what exists and how it is bypassed>
  - Prerequisites: <auth level, network position, config, timing>
- **Explanation:** What is wrong, in plain language.
- **Exploit Scenario:** Concrete attacker narrative, grounded in this code.
- **Remediation:** Specific change, with a code-level example.
- **Regression-Guard:** The check that keeps this fix from silently reverting - a Semgrep rule, a unit/integration test, a security-rules test, a CI assertion. Name the concrete guard (Phase 7 installs it) or `None (manual)` if one isn't feasible. For an unfixed/Low finding, `N/A`.
- **Status:** Unconfirmed → Confirmed Exploitable | Partially Mitigated | Fully Mitigated | Inconclusive → Resolved | Requires Manual Review
```

The **Regression-Guard** is the bridge from Phase 5 (fix) to Phase 7 (guardrails): every fix you apply should name the artifact that detects its regression, and Phase 7 turns those into committed rules/tests. A fix with no guard is one refactor away from silently coming back.

---

## 7. Noise Control - Do Not Report

These waste the user's attention. Skip them unless they are genuinely exploitable in context:

- Missing security headers on an API that serves no HTML
- "Weak" crypto in non-security contexts (MD5 as a cache key or ETag is fine)
- Dependency CVEs in `devDependencies` that never ship, unless the build pipeline is the target
- Hardcoded credentials in test fixtures pointing at localhost
- `Math.random()` outside a security decision
- Rate limiting on endpoints that are already behind an authenticated gateway that rate-limits
- Generic "use a WAF" advice with no specific finding behind it
- Any finding you cannot state a concrete exploit scenario for

If it fails the Gate but is still worth a mention, put it in an **Informational** section at the end of the report - not in the findings list.

---

## 8. Safety Constraints

- **Local only.** Run against the local project or a sandboxed instance. No traffic to any host outside confirmed scope.
- **Confirm before any network test.** State target, port, and test plan; get an explicit yes.
- **Non-destructive PoCs.** Prove presence, don't cause damage. Detection payloads (canary values, timing, error-based), never `DROP TABLE`.
- **Zero exfiltration.** Nothing leaves the machine. Redact secrets you discover - record location and type, never the value.
- **Bounded resources.** Cap concurrency in race-condition tests. Cap DAST to ~5 concurrent requests with delay.
- **Small wordlists.** Weak/default-credential checks only. No large-scale brute force, ever.
- **No evasion.** Do not write detection-evasion or anti-forensics logic.

---

## 9. Cross-Cutting Rules

- Write `.security-audit/` files **live at every phase transition** - they are working state, not a final deliverable. A crashed session should be resumable.
- **Never modify project files before Phase 4 approval**, no matter how safe the fix looks.
- Anything that looks wrong but matches no named class → file it for human review rather than dropping it.
- Secrets found in code or history: record file, line, and type. **Never** write the value into any artifact.
- If a fix fails twice, stop and roll back rather than iterating blindly.
- If you could not verify something, say so in the report. An audit that overstates its coverage is worse than a short one.
