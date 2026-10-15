# Phase 3 - Dynamic Analysis & Executable PoC Harnesses

_Load after Phase 2, plus the PoC template(s) matching the project's language(s)._

**Objectives:** an executable PoC per confirmed finding; DAST against live endpoints if applicable; a structured verdict per test; findings updated with dynamic evidence. Safety rules: `rules.md` section 8.

---

## Step 1: PoC Harnesses

For each finding in `.security-audit/audit-checklist.md`, write `.security-audit/security-tests/test_secXXX_poc.<ext>`.

| Language | Template (`references/templates/`) | Patterns |
|---|---|---|
| **Python** | `poc-test-harness-template.py` | SQLi, command injection, JWT, crypto, TOCTOU, deserialization, path traversal, password hashing, XSS |
| **JS/TS** | `poc-test-harness-template.js` | Prototype pollution, DOM XSS, JWT, async races, command injection |
| **Go** | `poc-test-harness-template.go` | Raw SQL, command injection, path traversal, goroutine races |
| **Rust** | `poc-test-harness-template.rs` | Unsafe blocks, shell injection, path traversal |
| **C/C++** | `poc-test-harness-template.c` | Buffer bounds, format string, integer safety |

No template for the language (Java, C#, PHP, Ruby, Kotlin, Swift)? Load the closest in style, keep its structure (setup, exploit attempt, an assertion separating vulnerable from fixed, cleanup), write it in the language's own test framework (JUnit, xUnit, PHPUnit, RSpec, XCTest), and name the source template in the header. A finding a test cannot exercise (a cloud setting) gets a scripted or manual check, and the verdict says so.

**Rules:** non-destructive; sandboxed (no external network without explicit confirmation); each test runs independently; races use concurrency (`ThreadPoolExecutor`, `Promise.all`, goroutines) within the caps in `rules.md` section 8.

---

## Step 2: DAST (only for a running web service)

Use when the project has HTTP/WebSocket endpoints runnable locally, Phase 0 found network-facing entry points as the main surface, or static findings need real requests to confirm.

**Pre-flight:** get user confirmation, presenting target, port, and test plan, then ask verbatim:

> This will send test HTTP requests to [target]. Proceed?

Run against `localhost` or a sandboxed container only.

1. Start the local server (`npm run dev`, `python manage.py runserver`, `docker-compose up`).
2. Run available tools:
   ```bash
   nuclei -u http://localhost:PORT -t cves/ -t misconfigurations/ -o .security-audit/raw/nuclei.json -j
   nikto -h http://localhost:PORT -o .security-audit/raw/nikto.json -Format json
   ```
3. Probe with curl/httpie using finding-specific payloads. Max 5 concurrent requests, 100ms delay.

DAST findings use the Phase 1 schema with `detectedBy: "DAST Scanner"` (or `"Both"`), and the full request/response in `exploitScenario`.

---

## Step 3: Verdicts

Per test:

```markdown
### Test: test_sec001_poc.py - targets SEC-001
- **Payload/Method:** what was sent or run
- **Expected if Secure:** what happens once fixed
- **Observed:** what happened
- **Verdict:** Confirmed Exploitable | Partially Mitigated | Fully Mitigated | Inconclusive
```

| Verdict | Meaning | Finding update |
|---|---|---|
| Confirmed Exploitable | PoC demonstrates the flaw | Status Confirmed Exploitable, Confidence High |
| Partially Mitigated | Controls exist but are bypassable | Status Partially Mitigated; document bypass conditions |
| Fully Mitigated | Controls hold in all tested cases | Status Fully Mitigated; consider downgrading |
| Inconclusive | Test could not prove or disprove | Status Inconclusive; confidence stays or drops |

**SARIF (optional)** for GitHub Code Scanning or the VS Code viewer: `.security-audit/security-tests/poc-results.sarif`, with Confirmed = `error`, Partially Mitigated = `warning`, Inconclusive = `note`.

---

## Step 4: Update Findings

Write the test result, verdict, updated confidence, and updated status to `audit-checklist.md` and `security-findings.json`.

---

## Gate to Proceed

- [ ] Every finding has a test result and verdict
- [ ] All scripts exist in `.security-audit/security-tests/`
- [ ] Both findings files updated with verdicts
- [ ] "Fully Mitigated" findings downgraded or annotated
