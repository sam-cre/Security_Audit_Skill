# Phase 1 - Static Analysis

_Prerequisite: Phase 0 done. Hold `references/rules.md` and the Phase 0 domain guides. Release `phase-0-recon.md`._

Confidence, scoring, triage, and schema rules live in `rules.md`; this file covers only what is specific to Phase 1.

**Objectives:** run every Phase 0 scanner and normalize output; walk the data-flow inventory with reasoned review (where the real findings come from); triage through the 4-Point Gate; record findings.

---

## Step 1: Run the Scanners

Run each tool the Phase 0 matrix marked available; raw output goes to `.security-audit/raw/`.

```bash
mkdir -p .security-audit/raw
# SAST
semgrep scan --config=auto --json -o .security-audit/raw/semgrep.json .
bandit -r . -f json -o .security-audit/raw/bandit.json             # Python
gosec -fmt=json -out=.security-audit/raw/gosec.json ./...          # Go
npx eslint . --format json -o .security-audit/raw/eslint.json      # JS/TS
brakeman -f json -o .security-audit/raw/brakeman.json              # Rails
dotnet list package --vulnerable --include-transitive              # .NET
# SCA
trivy fs . --format json --output .security-audit/raw/trivy.json
osv-scanner --format json --output .security-audit/raw/osv.json -r .
pip-audit --format json --output .security-audit/raw/pip-audit.json
npm audit --json > .security-audit/raw/npm-audit.json
cargo audit --json > .security-audit/raw/cargo-audit.json
# Secrets
gitleaks detect --source . --report-path .security-audit/raw/gitleaks.json --report-format json
trufflehog filesystem . --json > .security-audit/raw/trufflehog.json
# IaC (if Docker/K8s/Terraform found)
checkov -d . -o json --output-file-path .security-audit/raw/checkov.json
trivy config . --format json --output .security-audit/raw/trivy-config.json
```

Missing tools: use the Phase 0 fallback matrix and note the gap in Coverage.

**Scanner output is a lead, not a finding.** Every hit goes through the Gate in Step 3. Semgrep `--config=auto` has a high false-positive rate on framework code. Never paste scanner output into the report.

---

## Step 2: Reasoned Code Review

Scanners find known patterns; you find broken logic. Walk `.security-audit/data-flow-inventory.md`. For every source-to-sink flow:

1. Does untrusted input reach the sink without validation?
2. Is the validation **effective**? Look for encoding tricks, type confusion, second-order flows, canonicalization gaps.
3. Is there an **alternate path** to the sink that skips the control?
4. Does the framework protect this by default, and is that default still on?

**Domain guides:** walk every pattern in the selected guides and check each off explicitly. Do not skim.

**Always check, any domain:**
- Hardcoded secrets (location and type, **never the value**)
- Weak crypto in security contexts: MD5/SHA1 passwords, static IVs, ECB, RSA < 2048
- Unsafe deserialization of untrusted data (Python binary object loaders, `yaml.load`, Java `ObjectInputStream`, Ruby `Marshal.load`)
- Missing authorization on state-changing operations
- Error handling that leaks internals (traces, paths, DB errors, hostnames)
- TOCTOU and races on shared mutable state
- Sensitive data in logs (passwords, tokens, PII, cards)
- Non-CSPRNG randomness for tokens, session IDs, resets, nonces
- Fail-open paths (does auth succeed if the auth service throws?)

**Business logic** (scanners are blind here). For this application:
- Walk the **money path** or **privilege path** end to end.
- Which sequence of individually valid operations yields an invalid state? (Refund twice, coupon after checkout, change email then use the old reset link.)
- What can be replayed? What lacks idempotency?
- What is checked in the UI but not server-side?
- Which client-supplied value should be derived server-side (price, role, `user_id`, quantity, discount)?
- What happens at zero, negative, unicode, huge, empty array, null?

---

## Step 3: Triage

Apply the 4-Point Gate (`rules.md` section 3) to every candidate, scanner or reasoned. Record the gate evidence; no real source-to-sink trace, no finding. Apply the noise list (`rules.md` section 7); gate failures worth mentioning go to Informational.

---

## Step 4: Score and Record

Assign Confidence, CVSS vector, severity, CWE, OWASP category, and STRIDE per `rules.md` sections 2, 4, 6. Emit the vector string, not an invented score. For exploit-likelihood prioritization, enrich dependency findings per `references/threat-intel.md`.

Write to `.security-audit/audit-checklist.md` (schema in `rules.md` section 6) and `.security-audit/security-findings.json` (`references/templates/security-findings-schema.json`).

---

## Step 5: Coverage (mandatory)

Add to `audit-checklist.md`:

```markdown
## Coverage
- Files reviewed in full: <n> / <total>
- Files skipped and why: <vendored, generated, binary>
- Scanners run: semgrep, trivy, gitleaks
- Scanners unavailable: nuclei, checkov (those categories rely on reasoned review only)
- Areas NOT covered: <e.g. no DAST, no cloud IAM visibility>
```

An audit that hides its gaps is worse than a small one that names them.

---

## Gate to Proceed

- [ ] Every `data-flow-inventory.md` entry walked
- [ ] All scanner outputs processed and triaged
- [ ] Every domain-guide pattern checked
- [ ] Business-logic review done
- [ ] Every finding has gate evidence, confidence, vector, CWE
- [ ] `audit-checklist.md` and `security-findings.json` populated
- [ ] Coverage section written
