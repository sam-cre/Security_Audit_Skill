# Differential Re-Audit Protocol

This document defines how to conduct a re-audit efficiently when `.security-audit/` already exists from a prior run. A re-audit should not repeat the full audit - it should focus on what changed, verify fixes hold, and catch new instances of known vulnerability patterns.

---

## When This Applies

- `.security-audit/` directory exists with files from a prior audit
- The project has a git history showing changes since the last audit
- A prior `security-findings.json` exists with resolved findings

---

## Step 1: Establish the Diff Scope

### Tag-Based Scoping (Preferred)
If the prior audit left a git tag (e.g., `security-audit-v1`):
```bash
git diff --name-only security-audit-v1..HEAD
```

### Date-Based Scoping (Fallback)
Use the `auditDate` from the prior `security-findings.json`:
```bash
git log --after="YYYY-MM-DD" --name-only --pretty=format: | sort -u
```

### Output
Produce a `.security-audit/diff-scope.md` listing:
- Files added since last audit (full scan required)
- Files modified since last audit (targeted re-scan)
- Files deleted since last audit (check if they contained findings that are now orphaned)
- Files unchanged (skip unless regression testing)

---

## Step 2: Read Prior Audit Context

Before scanning changed files, read and internalize:

0. **Schema Version Check:** Compare the `skillVersion` field in the prior `security-findings.json` against the current skill version. If the schema has changed (e.g., new required fields like `complianceMappings` or `triageEvidence` were added), migrate the prior findings to the current schema before merging. Log any fields that were absent in the prior version and backfill with sensible defaults or `null`.
1. **Prior `security-findings.json`** - understand what was found before, what was fixed, and what was accepted-risk
2. **Prior `threat-model.md`** - check whether new code introduces new trust boundaries or entry points
3. **Prior Phase 7 Semgrep rules** - these encode the exact vulnerability patterns previously fixed

### Carry-Forward Rules
- **Accepted-risk findings** from the prior audit keep their status unless the code they reference has changed
- **Resolved findings** are presumed still-resolved unless their code has changed - but they get regression-tested in Step 4
- **Prior threat model** is updated only if new entry points, dependencies, or auth mechanisms have been added

---

## Step 3: Targeted Phase 1 on Changed Files

Run Phase 1 analysis only on files identified in `diff-scope.md`:

1. **New files:** Full vulnerability class scan as if auditing from scratch
2. **Modified files:** 
   - Re-check the specific lines that changed (use `git diff` hunk context)
   - Check whether the modification introduces a new instance of a previously-found vulnerability pattern
   - If the file had prior findings, verify the fixes are still intact
3. **Run prior Phase 7 Semgrep rules** against changed files only:
   ```bash
   semgrep --config .semgrep/ --include <changed-files>
   ```

### New Finding IDs
Continue the ID sequence from the prior audit's highest ID. If the prior audit ended at SEC-042, new findings start at SEC-043.

---

## Step 4: Regression Testing

For every finding marked "Resolved" in the prior `security-findings.json`:

1. Check whether the file/function containing the fix has been modified
2. If yes: re-run the original Phase 3 PoC harness from `.security-audit/security-tests/`
3. If the PoC now fails (vulnerability has regressed): 
   - Create a new finding with status "Regression" 
   - Escalate severity by one level (a fix that was undone is a process failure, not just a code bug)
4. If the file is unchanged: mark as "Regression-Verified (unchanged)" without re-running the test

---

## Step 5: Update All Reference Documents

- Update `project-profile.md` if stack, dependencies, or entry points changed
- Update `threat-model.md` if trust boundaries shifted
- Update `audit-checklist.md` with new findings appended, prior findings preserved
- Update `security-findings.json` with merged prior + new findings
- Update `data-flow-inventory.md` if new source-to-sink paths exist

---

## Step 6: Differential Report

The final report (`security-audit-report.md`) for a re-audit includes an additional section:

### Audit Delta Summary
| Metric | Prior Audit | This Audit | Delta |
|---|---|---|---|
| Total Findings | | | |
| Critical/High | | | |
| Resolved (carried forward) | | | |
| New Findings | | | |
| Regressions Detected | | | |
| Accepted Risk (unchanged) | | | |

### Regression Analysis
List any resolved findings that regressed, with the git commit that re-introduced the vulnerability.

---

## Git Tagging

After the re-audit completes, recommend the user tag the current commit:
```bash
git tag -a security-audit-v2 -m "Security audit completed YYYY-MM-DD"
```
This establishes the baseline for the next differential audit.
