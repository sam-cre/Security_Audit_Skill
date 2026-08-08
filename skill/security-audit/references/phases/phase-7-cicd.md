# Phase 6 - Continuous Security & Regression Prevention

_Load this after Phase 5 is complete. Also load `.security-audit/audit-checklist.md`._

---

## Objectives

1. Generate custom static analysis rules targeting the exact vulnerability patterns found and fixed
2. Generate CI/CD security workflows for the project's platform
3. Generate pre-commit hooks for developer-local catching
4. Tag the audit baseline for future differential audits

---

## Step 1: Custom Semgrep Rules

Generate rules in the `.semgrep/` directory targeting the exact code patterns remediated during Phase 4.

### Rule Generation
For each resolved finding, create a Semgrep rule that would catch the same pattern:

```yaml
# .semgrep/sec-001-sql-injection.yml
rules:
  - id: sec-001-sql-injection-string-concat
    message: >
      String concatenation in SQL query detected. This pattern was identified
      and fixed during security audit (SEC-001). Use parameterized queries instead.
      See .security-audit/security-audit-report.md for details.
    severity: ERROR
    languages: [python]
    patterns:
      - pattern: |
          cursor.execute("..." + $VAR + "...")
      - pattern-not-inside: |
          # Exemption for test files
          def test_...(...):
              ...
    metadata:
      cwe: CWE-89
      finding-id: SEC-001
      owasp: A05:2025
```

### Rule Quality Standards
- Each rule must reference the original finding ID in its message
- Include the CWE and OWASP category in metadata
- Exclude test files from matching (unless the pattern is dangerous even in tests)
- Test rules against the project to verify they don't produce false positives on the fixed code

---

## Step 2: CI/CD Security Workflow

Generate a security workflow for the project's CI/CD platform. Auto-detect the platform:

| Indicator | Platform | Template to Use |
|---|---|---|
| `.github/` directory exists | GitHub Actions | `references/templates/cicd-guardrail-template.yml` |
| `.gitlab-ci.yml` exists | GitLab CI | `references/templates/cicd-gitlab-template.yml` |
| `azure-pipelines.yml` exists | Azure DevOps | `references/templates/cicd-azure-template.yml` |
| None detected | Default to GitHub Actions | Ask user which platform they use |

### Workflow Components
The generated workflow should include:
1. **Secret scanning** (Gitleaks)
2. **SAST scanning** (Semgrep with OWASP Top 10 + custom `.semgrep/` rules)
3. **SCA scanning** (Trivy for dependency vulnerabilities)
4. **SARIF upload** (for inline PR annotations)

Install the workflow file at the appropriate location:
- GitHub: `.github/workflows/security-audit.yml`
- GitLab: Include in `.gitlab-ci.yml` (or as a child pipeline)
- Azure: Include in `azure-pipelines.yml`

---

## Step 3: Pre-Commit Hooks

Generate a `.pre-commit-config.yaml` (or equivalent) to catch security issues before they're committed:

Use template: `references/templates/pre-commit-config-template.yml`

Key hooks:
- Secret detection (gitleaks/detect-secrets)
- Large file prevention
- Merge conflict markers
- Custom Semgrep rules from Step 1

If the project doesn't already use pre-commit, recommend installation:
```bash
pip install pre-commit
pre-commit install
```

---

## Step 4: Git Audit Tag

Recommend the user tag the current commit as a baseline for future differential audits:

```bash
git tag -a security-audit-v1 -m "Security audit completed YYYY-MM-DD - N findings, M resolved"
```

If this is a re-audit, increment the version number (`security-audit-v2`, etc.).

Explain: This tag enables efficient future re-audits by providing a clean diff baseline (see `references/differential-audit-protocol.md`).

---

## Step 5: Automated Dependency Updates

If not already configured, recommend setting up:

### GitHub (Dependabot)
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"  # or pip, cargo, gomod, etc.
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
```

### GitLab (Renovate)
Recommend Renovate Bot configuration with security-focused auto-merge for patch versions.

---

## Gate to Proceed

Do not advance to Phase 7 until:
- [ ] Custom Semgrep rules are generated in `.semgrep/`
- [ ] CI/CD workflow is generated for the project's platform
- [ ] Pre-commit hooks are configured (or recommended)
- [ ] Git audit tag is recommended to the user
- [ ] Dependency update automation is configured (or recommended)
