# Phase 2 — Dynamic Analysis & Executable PoC Harnesses

_Load this after Phase 1.5 is complete. Also load the language-specific PoC template(s) matching the project's language(s)._

---

## Objectives

1. Write executable PoC test harnesses for every confirmed finding
2. Run DAST scanning against live service endpoints (if applicable)
3. Produce a structured verdict per test
4. Update finding statuses and confidence levels based on dynamic evidence

---

## Step 1: PoC Harness Creation

For each finding in `.security-audit/audit-checklist.md`, write a structured executable test harness.

### File Naming Convention
```
.security-audit/security-tests/test_secXXX_poc.<ext>
```

### Template Selection
Choose the PoC template matching the project's primary language:

| Language | Template File | Test Patterns Available |
|---|---|---|
| **Python** | `references/templates/poc-test-harness-template.py` | SQLi, Command Injection, JWT, Crypto, TOCTOU, Deserialization, Path Traversal, Password Hashing, XSS |
| **JavaScript/TypeScript** | `references/templates/poc-test-harness-template.js` | Prototype Pollution, DOM XSS, JWT, Async Race Conditions, Command Injection |
| **Go** | `references/templates/poc-test-harness-template.go` | Unparameterized SQL, Command Injection, Path Traversal, Goroutine Race Conditions |
| **Rust** | `references/templates/poc-test-harness-template.rs` | Unsafe Block Safety, Shell Command Injection, Path Traversal |
| **C/C++** | `references/templates/poc-test-harness-template.c` | Buffer Bounds, Format String, Integer Safety |

### PoC Rules
1. **Non-Destructive:** Test for vulnerability presence without causing permanent data destruction
2. **Sandboxed:** Run locally against mock targets or sandboxed project instances. Never make external network requests without explicit user confirmation
3. **Self-Contained:** Each test should be runnable independently
4. **Race Conditions:** Use concurrent execution (`ThreadPoolExecutor`, `Promise.all`, goroutines) to test state-changing operations under load

---

## Step 2: DAST — Live Service Testing (If Applicable)

When the project under audit is a **running web service**, supplement static PoC harnesses with live endpoint testing.

### When to Use DAST
- The project has HTTP/WebSocket endpoints that can be started locally
- Phase 0 identified network-facing entry points as the primary attack surface
- Static analysis found potential vulnerabilities that can only be confirmed by sending actual HTTP requests

### Pre-Flight Requirements
1. **User confirmation required** before any DAST execution. Present the target URL, port, and test plan, then ask verbatim:

   > This will send test HTTP requests to [target]. Proceed?

2. **Local only.** Run against `localhost` or a sandboxed Docker instance. Never target production, staging, or any shared environment without explicit user approval.

### DAST Execution
1. Start the local dev server (`npm run dev`, `python manage.py runserver`, `docker-compose up`, etc.)
2. Run available DAST tools:
   ```bash
   # Nuclei (template-based scanning)
   nuclei -u http://localhost:PORT -t cves/ -t misconfigurations/ -o .security-audit/nuclei-raw.json -j
   
   # Nikto (web server misconfiguration)
   nikto -h http://localhost:PORT -o .security-audit/nikto-raw.json -Format json
   ```
3. Manual endpoint probing with curl/httpie for finding-specific payloads
4. **Rate-limited:** Cap concurrent requests to 5 max, 100ms delay between requests

### DAST Findings
DAST-discovered findings use the same finding schema as Phase 1, with `detectedBy: "DAST Scanner"` or `detectedBy: "Both"` if also found statically. Include the full HTTP request/response in the `exploitScenario` field.

---

## Step 3: Record Test Verdicts

For each test, record a structured verdict:

```markdown
### Test: test_sec001_poc.py — targets SEC-001
- **Payload/Method:** [what was sent/executed]
- **Expected if Secure:** [what should happen if the vulnerability is fixed]
- **Observed:** [what actually happened]
- **Verdict:** Confirmed Exploitable | Partially Mitigated | Fully Mitigated | Inconclusive
```

### Verdict Definitions
| Verdict | Meaning | Impact on Finding |
|---|---|---|
| **Confirmed Exploitable** | PoC successfully demonstrates the vulnerability | Finding status → "Confirmed Exploitable", Confidence → High |
| **Partially Mitigated** | Some controls exist but can be bypassed under specific conditions | Finding status → "Partially Mitigated", document bypass conditions |
| **Fully Mitigated** | Controls prevent exploitation in all tested scenarios | Finding status → "Fully Mitigated", consider downgrading severity |
| **Inconclusive** | Test could not definitively prove or disprove exploitability | Finding status → "Inconclusive", Confidence remains or lowers |

### SARIF Output (Optional)
If the project uses GitHub Code Scanning or VS Code SARIF Viewer, generate `.security-audit/security-tests/poc-results.sarif` alongside the test output. Map verdict to SARIF level:
- Confirmed Exploitable → `error`
- Partially Mitigated → `warning`
- Inconclusive → `note`

---

## Step 4: Update Findings

Update `.security-audit/audit-checklist.md` and `.security-audit/security-findings.json` with:
- Test result and verdict per finding
- Updated confidence levels based on dynamic evidence
- Updated status (Unconfirmed → Confirmed/Mitigated/Inconclusive)

---

## Environment Safety Constraints

- **Zero Remote Exfiltration:** All tests execute locally against mock data or isolated local targets
- **No Production Side-Effects:** Use detection payloads (canary tokens, timing, error-based) not destructive ones
- **Network Boundaries:** No external network requests during testing without explicit approval
- **Resource Constraints:** Cap concurrent threads/goroutines to prevent local resource exhaustion

---

## Gate to Proceed

Do not advance to Phase 3 until:
- [ ] Every finding has a test result and verdict
- [ ] All test scripts exist in `.security-audit/security-tests/`
- [ ] `audit-checklist.md` and `security-findings.json` are updated with verdicts
- [ ] Findings that were "Fully Mitigated" have been downgraded or annotated accordingly
