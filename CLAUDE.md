# Security Audit Skill

This repo **is** a skill. `skill/security-audit/` is the portable unit; `install.ps1` / `install.sh` copy or symlink it to `~/.claude/skills/security-audit/` so it works in every project.

## Working on this repo

- The skill's source of truth is `skill/security-audit/`. Edit there.
- After editing, re-run the installer to sync (or install once with `-Link` / `--link` and edits apply immediately).
- `_deprecated/` holds the pre-restructure layout. Nothing references it. Safe to delete.

## Structure

```
skill/security-audit/
├── SKILL.md                 always loaded - keep it lean
└── references/
    ├── rules.md             single source of truth: confidence, CVSS, CVE, safety
    ├── phases/              9 files, phase-0-recon .. phase-8-hardening
    ├── domains/             14 vulnerability guides, loaded by project type
    ├── templates/           report/threat-model/SBOM/SARIF/PoC harnesses
    ├── setup/               guided scanner installation
    ├── scripts/             git-history secret scanning
    └── compliance/          framework mappings
```

## Invariants - do not break these

**Paths.** Every `references/...` path is relative to the skill directory. This works only because the skill is installed as a *skill*, not as a `.claude/commands/` slash command - commands resolve relative to the CWD, which silently breaks every reference and leaves the model improvising an audit that looks correct. Do not reintroduce a command file.

**No duplication.** Confidence calibration, CVSS guidance, the finding schema, CVE verification, and safety constraints live in `references/rules.md` **only**. Phase files cite sections by number; they must never restate the content. The previous version duplicated all of it inside phase 1, doubling token cost and letting the copies drift.

**Output directory.** Artifacts go to `.security-audit/` in the audited project - never `References/`, which collides case-insensitively with the skill's own `references/` on Windows and macOS.

**Context discipline.** `SKILL.md` and `rules.md` are the only always-resident files. Every phase file states what to hold and what to release. Content added to `SKILL.md` costs tokens on every invocation - put it in a phase or domain file instead.

**Scoring integrity.** CVSS v4.0 numeric scores use MacroVector lookup tables and cannot be computed by a language model. The skill emits vector strings and marks scores as calculator-verified or not computed. Do not reintroduce invented decimals.

## Adding a domain guide

1. Write `references/domains/<name>.md` following the existing shape: numbered categories of concrete patterns, then a short "Reviewing X well" section covering review strategy.
2. Add a row to the domain router in `SKILL.md` keyed on the **detection signal** - what in the project indicates the guide applies - not just the project type.
3. Re-run the installer.
4. Verify the router matches disk:
   ```bash
   diff <(grep -oE 'references/domains/[a-z-]+\.md' SKILL.md | sort) <(ls references/domains | sed 's|^|references/domains/|' | sort)
   ```

## Other assistants

`AGENTS.md` (Codex) and `.cursorrules` (Cursor) mirror the same rules with repo-relative paths. Keep all three in sync when changing modes, phase numbering, or core rules.
