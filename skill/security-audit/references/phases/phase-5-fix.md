# Phase 4 - Automated Remediation & Re-Testing

_Load this only after explicit Phase 3 user approval. Also load `.security-audit/audit-checklist.md`._

---

## Objectives

1. Apply minimal targeted code fixes for each approved finding
2. Re-run Phase 2 PoC harnesses to verify fixes
3. Automatically roll back any fix that fails twice
4. Never leave broken code in the project

---

## Pre-Fix Checklist

Before applying any fix:

1. **Verify approval:** Confirm Phase 3 approval was received. If not, STOP.
2. **Git status check:** Ensure working directory is clean or stash uncommitted changes:
   ```bash
   git status
   git stash  # if needed
   ```
3. **Identify fix scope:** Only fix findings in "Group A: Approved for Auto-Remediation" (Confidence: High or Medium). Skip ALL `Confidence: Low` findings.

---

## Fix-Test-Verify Loop

For each approved finding:

### Attempt 1
1. **Apply minimal fix:** Make the smallest possible code change that addresses the vulnerability
   - Prefer library/framework-provided security features over custom implementations
   - Preserve existing behavior and API contracts
   - Add defensive checks rather than restructuring code
   - Comment the fix with the finding ID: `// FIX: SEC-XXX - [brief description]`

2. **Re-run PoC harness:**
   ```bash
   # Python
   python -m pytest .security-audit/security-tests/test_secXXX_poc.py -v
   
   # JavaScript
   node .security-audit/security-tests/test_secXXX_poc.js
   
   # Go
   go test -run TestSecXXX -v ./.security-audit/security-tests/
   ```

3. **Evaluate result:**
   - ✅ **PoC now shows "Fully Mitigated"** → Mark finding as `Resolved`, proceed to next finding
   - ❌ **PoC still shows vulnerability** → Proceed to Attempt 2

### Attempt 2 (Only if Attempt 1 Failed)
1. **Revise the fix:** Analyze why the first fix didn't work and apply a revised patch
2. **Re-run the same PoC harness**
3. **Evaluate result:**
   - ✅ **Fixed** → Mark as `Resolved`
   - ❌ **Still failing** → **IMMEDIATELY execute Git Rollback**

### Git Rollback on Double Failure

If a fix fails twice:

```bash
# Restore the file to its clean state
git checkout -- <path/to/modified-file>
```

Then:
1. Mark the finding as `"Requires Manual Review"` in `security-findings.json`
2. Document why the automated fix failed
3. **NEVER leave broken, incomplete, or failing code in the project**
4. Move on to the next finding

---

## Post-Fix Verification

After all fixes have been applied:

1. **Run the project's existing test suite** to check for regressions:
   ```bash
   npm test          # Node.js
   pytest            # Python
   go test ./...     # Go
   cargo test        # Rust
   ```

2. **If tests fail** due to a security fix:
   - Evaluate whether the test was testing insecure behavior (it may need updating)
   - If the fix genuinely broke functionality, rollback and mark as "Requires Manual Review"

3. **Run a quick build check:**
   ```bash
   npm run build     # Node.js
   go build ./...    # Go
   cargo build       # Rust
   ```

---

## Finding Status Updates

Keep `.security-audit/audit-checklist.md` and `.security-audit/security-findings.json` updated live as fixes land:

| Status | Meaning |
|---|---|
| `Resolved` | Fix applied and PoC harness confirms vulnerability is closed |
| `Requires Manual Review` | Fix failed twice (rolled back) or Confidence: Low - needs human expert |
| `Partially Mitigated` | Fix reduces but doesn't eliminate the risk |
| `Accepted Risk` | User explicitly accepted the risk (documented in Phase 3) |

---

## Gate to Proceed

Do not advance to Phase 5 until:
- [ ] All approved findings have been attempted (fix or skip)
- [ ] No broken/partial fixes remain in the codebase
- [ ] All rollbacks have been executed where needed
- [ ] `audit-checklist.md` and `security-findings.json` reflect final statuses
- [ ] Project test suite passes (if it existed before the audit)
