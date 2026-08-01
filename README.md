# Security Audit Skill

A multi-phase security audit skill for Claude Code, Codex, and Cursor. Combines SAST/SCA/DAST scanners with code review, adversarial re-checking, proof-of-concept exploits, and a remediation plan.

Covers web apps, APIs, CLIs, mobile, desktop, browser extensions, IaC/cloud, LLM/agent systems, smart contracts, embedded/IoT, data pipelines, games, and CMS/low-code platforms.

## Install

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

If none of that works, you can simply ask the agent to access the skill by prompting to run the security audit with reference to the workflow in (x) location (where you downloaded this repository).

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

## Findings policy

- No invented CVEs. Sourced from scanner output or OSV.dev only.
- No invented CVSS scores. CVSS v4.0 requires MacroVector lookup tables; the skill emits the vector string and marks the score as calculator-verified or not computed.
- Every finding requires a source-to-sink trace and a concrete exploit scenario. Confidence is rated High/Medium/Low; Low is never auto-fixed.
- Reports state what was reviewed, what was skipped, and which scanners were unavailable.

## Layout

```
skill/security-audit/          the portable skill (what gets installed)
├── SKILL.md                   entry point: modes, phases, domain router
└── references/
    ├── rules.md          confidence, CVSS, CVE, safety rules
    ├── phases/           9 phase files
    ├── domains/          14 vulnerability guides
    ├── templates/        report, threat model, SBOM, SARIF, PoC harnesses
    ├── setup/            scanner installation
    ├── scripts/          git-history secret scanning
    └── compliance/       PCI/SOC2/HIPAA/GDPR/ISO mappings
install.ps1 / install.sh       installers
```

`AGENTS.md` and `.cursorrules` mirror the same instructions for Codex and Cursor. Those tools don't auto-install; point them at `skill/security-audit/SKILL.md` directly.

## Scope

For auditing code you own or are authorized to test. Phase 0 confirms scope before proceeding. Network testing is limited to local/sandboxed targets unless confirmed otherwise.
