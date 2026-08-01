# Security Audit Skill — Agent Instructions

Multi-phase security audit skill. When the user asks for a security audit, pentest, threat model, or hardening review, follow `skill/security-audit/SKILL.md`.

## Path resolution

All `references/...` paths are relative to **`skill/security-audit/`**, not to the project being audited. Audit output goes to `.security-audit/` in the audited project. These are different trees — never conflate them.

## Entry points

- **Workflow:** `skill/security-audit/SKILL.md` — modes, phases, domain router
- **Core rules:** `skill/security-audit/references/rules.md` — confidence, CVSS, CVE verification, safety. Load once; it applies to every phase and the phase files do not restate it.
- **Phases:** load one file at a time from `references/phases/`. Do not pre-load.
- **Domains:** in Phase 0, identify the project type and load only the matching guides from `references/domains/`.

## Modes

- `quick` — phases 0, 1, 4, 6. Read-only triage.
- `standard` — phases 0–6. Default.
- `deep` — phases 0–8. Adds CI/CD guardrails and guided infrastructure hardening.
- `setup` — guided scanner installation only.
- `diff` — re-audit of a previously audited project.

## Phases

0 recon · 1 static · 2 adversarial · 3 dynamic · 4 plan · 5 fix · 6 report · 7 CI/CD · 8 hardening

## Non-negotiable rules

1. Never modify project files before **Phase 4** approval. Phases 0–3 write only to `.security-audit/`.
2. Never fabricate a CVE. Scanner output or OSV.dev API only.
3. Never print an invented CVSS numeric score — emit the vector string and mark the score as calculator-verified or not computed.
4. Every finding needs a confidence rating. Low confidence is never auto-remediated.
5. Every finding needs a real source-to-sink trace and a concrete exploit scenario, or it is not filed.
6. State coverage honestly — what was reviewed, skipped, and not visible.
7. If a fix fails twice, roll back rather than iterating.
