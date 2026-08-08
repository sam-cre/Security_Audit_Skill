# Phase 1 - Static Analysis

_Prerequisite: Phase 0 complete. Hold `references/rules.md` and the domain guides selected in Phase 0. Release `phase-0-recon.md`._

All confidence, scoring, triage, and schema rules live in `references/rules.md`. This file covers only what is specific to Phase 1.

---

## Objectives

1. Run every scanner discovered in Phase 0 and normalize the output
2. Walk the data-flow inventory with reasoned review - this is where the real findings come from
3. Triage everything through the 4-Point Gate
4. Record findings in human and machine formats

---

## Step 1: Run the Scanners

Execute each tool the Phase 0 matrix marked available. Write raw output to `.security-audit/raw/` so results are auditable.

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

# Secrets - filesystem and full history
gitleaks detect --source . --report-path .security-audit/raw/gitleaks.json --report-format json
trufflehog filesystem . --json > .security-audit/raw/trufflehog.json

# IaC (if Phase 0 found Docker/K8s/Terraform)
checkov -d . -o json --output-file-path .security-audit/raw/checkov.json
trivy config . --format json --output .security-audit/raw/trivy-config.json
```

Missing tools are not a blocker - apply the Phase 0 fallback matrix and note the gap in the report's coverage section.

### Scanner Output Is a Lead, Not a Finding

Scanner hits are **candidates**. Every one goes through the 4-Point Gate in Step 3 before it becomes a finding. Semgrep's `--config=auto` in particular has a high false-positive rate on framework code. Do not copy scanner output into the report.

---

## Step 2: Reasoned Code Review

This is the part scanners cannot do, and where the highest-value findings live. Scanners find known patterns; you find broken logic.

Walk `.security-audit/data-flow-inventory.md`. For every source→sink flow:

1. Does untrusted input reach the sink without validation?
2. Is the validation actually **effective**? Look for bypasses - encoding tricks, type confusion, second-order flows, canonicalization gaps.
3. Is there an **alternate path** to the same sink that skips the control?
4. Does the framework protect this by default, and is that default still on?

### Then check the domain guides

Systematically walk every pattern in the domain guide(s) Phase 0 selected. Check them off explicitly - do not skim.

### Always check, regardless of domain

- Hardcoded secrets, keys, tokens (record location and type, **never the value**)
- Weak crypto **in security contexts** - MD5/SHA1 for passwords, static IVs, ECB, RSA <2048
- Unsafe deserialization of untrusted data - Python `loads` on binary object streams, `yaml.load`, Java `ObjectInputStream`, Ruby `Marshal.load`
- Missing authorization checks on state-changing operations
- Error handling that leaks internals - stack traces, paths, DB errors, internal hostnames
- TOCTOU and race conditions on shared mutable state
- Sensitive data in logs - passwords, tokens, PII, card numbers
- Non-CSPRNG randomness used for tokens, session IDs, password resets, nonces
- Fail-open error paths - does auth succeed if the auth service throws?

### Business-Logic Review

Scanners are blind here. Ask, for this specific application:

- What is the **money path** or the **privilege path**? Walk it end to end.
- What sequence of individually-valid operations produces an invalid state? (Refund twice, apply a coupon after checkout, change email then use the old reset link.)
- What can be replayed? What is missing idempotency?
- What is checked at the UI layer but not re-checked server-side?
- Where does the code trust a client-supplied value it should derive server-side - price, role, `user_id`, quantity, discount?
- What happens at boundaries - zero, negative, unicode, very large, empty array, null?

---

## Step 3: Triage

Apply the **4-Point Triage Gate** from `references/rules.md` §3 to every candidate - scanner-sourced and reasoned alike. Record the gate evidence in the finding; a finding without a real source-to-sink trace does not get filed.

Then apply the **noise control list** in `rules.md` §7. Findings that fail the gate but are still worth mentioning go to an Informational section, not the findings list.

---

## Step 4: Score and Record

Assign Confidence, CVSS vector, severity, CWE, and STRIDE per `references/rules.md` §2, §4, §6. Remember: **emit the vector string, not an invented numeric score.**

Enrich dependency findings with EPSS and CISA KEV data if the user wants exploit-likelihood prioritization - see `references/threat-intel.md`.

Write to:
- `.security-audit/audit-checklist.md` - the schema in `rules.md` §6
- `.security-audit/security-findings.json` - schema at `references/templates/security-findings-schema.json`

---

## Step 5: Record Coverage Honestly

In `audit-checklist.md`, add a **Coverage** section stating what you actually reviewed:

```markdown
## Coverage
- Files reviewed in full: <n> / <total>
- Files skipped and why: <vendored deps, generated code, binary assets>
- Scanners run: semgrep, trivy, gitleaks
- Scanners unavailable: nuclei, checkov - those categories rely on reasoned review only
- Areas NOT covered: <e.g. no runtime/DAST, no cloud IAM config visibility>
```

This section is mandatory. An audit that hides its gaps is worse than a small audit that names them.

---

## Gate to Proceed

- [ ] Every entry in `data-flow-inventory.md` walked
- [ ] All available scanner outputs processed and triaged
- [ ] Every domain-guide pattern explicitly checked
- [ ] Business-logic review done
- [ ] Every finding has gate evidence, confidence, vector, CWE
- [ ] `audit-checklist.md` and `security-findings.json` populated
- [ ] Coverage section written
