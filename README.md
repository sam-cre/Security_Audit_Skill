# Security Audit Skill

A multi-phase security audit skill for Claude Code, Codex, and Cursor. Combines SAST/SCA/DAST scanners with code review, adversarial re-checking, proof-of-concept exploits, and a remediation plan.

Covers web apps, APIs, CLIs, mobile, desktop, browser extensions, IaC/cloud, LLM/agent systems, smart contracts, embedded/IoT, data pipelines, games, and CMS/low-code platforms.

## Quick setup with your AI agent

Paste this into Claude Code, Codex, or Cursor:

```
Install the security-audit skill from https://github.com/sam-cre/Security_Audit_Skill.
Clone it, run the installer for my OS (install.ps1 on Windows, install.sh otherwise), confirm
~/.claude/skills/security-audit/SKILL.md exists, then tell me to restart. Ask before anything else.
```

For Codex or Cursor, which do not auto-install, use this instead:

```
Clone https://github.com/sam-cre/Security_Audit_Skill, then for every security audit I ask for,
follow skill/security-audit/SKILL.md and load the references it points to.
```

## Manual install

**Windows**
```powershell
.\install.ps1
```

**macOS / Linux**
```bash
./install.sh
```

Add `-Link` (Windows) or `--link` (Mac/Linux) to symlink instead of copy, so edits to this repo apply immediately.

Installs to `~/.claude/skills/security-audit/`. Available in every project after. Restart Claude after installing.

Updating: `git pull` and re-run the installer, or install once with `-Link` / `--link` and just `git pull`.

## Usage

```
/security-audit          standard audit, phases 0-6
/security-audit quick    read-only triage, phases 0, 1, 4, 6
/security-audit deep     full audit plus CI/CD guardrails and hardening, phases 0-8
/security-audit setup    guided install of scanning tools
/security-audit diff     re-audit only what changed since last run
```

Also triggers on plain language: "audit this for vulnerabilities," "review my auth flow," "am I leaking secrets," "check my dependencies for CVEs."

Output goes to `.security-audit/` in the audited project. Already excluded via `.gitignore`.

## Phases

| # | Phase | Output |
|---|---|---|
| 0 | Recon | Project profile, tool discovery, git-history scan, threat model, SBOM, CVE check |
| 1 | Static analysis | Scanner output + manual code review, including logic flaws scanners miss |
| 2 | Adversarial review | Re-checks phase 1 for false negatives |
| 3 | Dynamic testing | Runnable proof-of-concept per finding |
| 4 | Remediation plan | Attack chains, prioritized fixes. Requires user approval to proceed |
| 5 | Apply fixes | Applies approved fixes, re-runs PoCs, rolls back on failure |
| 6 | Reports | Markdown, JSON, SARIF |
| 7 | CI/CD guardrails | Semgrep rules, pre-commit hooks, pipeline config |
| 8 | Infra hardening | Guided walkthrough: TLS, DNS, headers, secrets, WAF, monitoring |

Phases 0-3 are read-only. Nothing in the audited project is modified before phase 4 approval.

## Domain routing

Phase 0 identifies the project type and loads only the matching guides:

`web-api` `auth-identity` `firebase-baas` `cli` `iac-cloud` `llm-ai` `library-sdk` `mobile-desktop` `browser-extension` `microservices` `cms-lowcode` `blockchain` `data-pipeline` `embedded-iot` `game`

Most projects load two to four.

## OWASP coverage

Web and API checks follow OWASP Top 10:2025, plus classes that older editions (2004 to 2021) listed separately: XXE, CSRF, open redirect, path traversal, file upload, insecure deserialization, request smuggling, and cache poisoning. LLM and agent checks follow the OWASP LLM and Agentic Top 10. Each finding records its OWASP category.

The skill text is kept lean on purpose, so each run feeds the model fewer tokens without dropping checks.

## Findings policy

- No invented CVEs. Sourced from scanner output or OSV.dev only.
- No invented CVSS scores. CVSS v4.0 requires MacroVector lookup tables; the skill emits the vector string and marks the score as calculator-verified or not computed.
- Every finding requires a source-to-sink trace and a concrete exploit scenario. Confidence is rated High/Medium/Low; Low is never auto-fixed.
- Reports state what was reviewed, what was skipped, and which scanners were unavailable.

For auditing code you own or are authorized to test. Phase 0 confirms scope before proceeding. Network testing is limited to local/sandboxed targets unless confirmed otherwise.

`AGENTS.md` and `.cursorrules` mirror the same instructions for Codex and Cursor. Those tools don't auto-install; point them at `skill/security-audit/SKILL.md` directly.
