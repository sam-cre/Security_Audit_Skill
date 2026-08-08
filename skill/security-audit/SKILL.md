---
name: security-audit
description: >-
  Multi-phase security audit and penetration test for any codebase - web apps, APIs, CLIs,
  mobile, desktop, browser extensions, microservices, IaC/cloud, LLM/AI agents, smart contracts,
  embedded/IoT, data pipelines, games, CMS and low-code. Combines SAST/SCA/DAST scanners with
  reasoned code review, adversarial false-negative hunting, executable proof-of-concept
  verification, and guided infrastructure hardening. Use when the user asks to audit, pentest,
  security-review, threat-model, or harden a project; asks "is this secure", "find
  vulnerabilities", "check for CVEs", "OWASP review", "review my auth", "am I leaking secrets";
  or asks to install security scanning tools.
allowed-tools: Read, Grep, Glob, Write, Edit, Bash, WebFetch, Task, TodoWrite
---

# Security Audit

Evidence-based hybrid security audit. Adapt to what the project actually **is** - do not assume a web app, language, or framework until Phase 0 confirms it.

## Path Resolution - read this first

Every `references/...` path below is **relative to this skill's own directory** (the folder containing this SKILL.md), *not* the project being audited. If a Read fails, locate this SKILL.md and resolve from there. Never guess at file contents you could not load - say the load failed.

Audit artifacts are written to **`.security-audit/`** in the *audited project's* root. These two trees are different things; never conflate them.

## Non-Negotiable Guardrails

1. **Reason, don't pattern-match.** Every finding passes the 4-Point Triage Gate and carries a concrete exploit scenario.
2. **Calibrate confidence.** Every finding is High/Medium/Low. Low is never auto-remediated. Never invent a CVE.
3. **Read-only until approval.** Phases 0–4 modify nothing in the project. Only `.security-audit/` is written.
4. **Executable evidence.** Confirmed vulnerabilities get a runnable PoC; fixes get regression rules.

**Read `references/rules.md` now.** It is the single source of truth for confidence calibration, CVE verification, CVSS v4.0 scoring, the finding schema, and safety constraints. It is loaded once and applies to every phase - later phases do not restate it.

## Modes

Determine the mode before Phase 0. Default is `standard`.

| Mode | Phases | Use For |
|---|---|---|
| `quick` | 0, 1, 4, 6 | Read-only triage. PR review, single scripts, small services. No fixes applied. |
| `standard` | 0–6 | Full audit: analysis, PoC verification, approved fixes, reports. |
| `deep` | 0–8 | Everything + CI/CD guardrails + guided infrastructure hardening. Production systems. |
| `setup` | - | Guided security-tool installation only. Read `references/setup/tool-install.md`. |
| `diff` | - | Re-audit of a previously audited project. Read `references/differential-audit-protocol.md`. |

## Phases

Work in order. Findings are queued, not fixed on sight.

| # | Phase | File | Gate |
|---|---|---|---|
| 0 | Recon: profile, tooling, threat model, SBOM | `references/phases/phase-0-recon.md` | Profile docs written |
| 1 | Static analysis: scanners + code review + triage | `references/phases/phase-1-static.md` | All sources reviewed |
| 2 | Adversarial self-review: hunt false negatives | `references/phases/phase-2-adversarial.md` | Every trust boundary covered |
| 3 | Dynamic: executable PoC per finding | `references/phases/phase-3-dynamic.md` | Every finding has a verdict |
| 4 | Remediation plan + attack chains | `references/phases/phase-4-plan.md` | **User approval required** |
| 5 | Apply fixes, re-run PoCs, roll back on failure | `references/phases/phase-5-fix.md` | Only after approval |
| 6 | Reports: human + JSON + SARIF | `references/phases/phase-6-report.md` | Reports generated |
| 7 | CI/CD guardrails: Semgrep rules, hooks, workflows | `references/phases/phase-7-cicd.md` | Guardrails installed |
| 8 | Guided infrastructure hardening (interactive) | `references/phases/phase-8-hardening.md` | Each item verified |

**Load ONLY the current phase file.** Do not pre-load future phases. Release the previous phase file when you advance.

## Domain Router

In Phase 0, identify the project type and load **only** the matching guides for Phase 1. Most projects match 2–4; load all that apply.

| Signal in the project | Load |
|---|---|
| HTTP routes, REST/GraphQL, SSR, templates | `references/domains/web-api.md` |
| Login, sessions, JWT, OAuth/OIDC/SAML, RBAC, password reset | `references/domains/auth-identity.md` |
| Firebase (Firestore/RTDB/Auth/Storage/App Check), Supabase, AppWrite, `firestore.rules`, client-direct DB access | `references/domains/firebase-baas.md` |
| argv parsing, stdin, shell scripts, terminal tools | `references/domains/cli.md` |
| Dockerfile, k8s manifests, Terraform, CloudFormation, CI configs | `references/domains/iac-cloud.md` |
| LLM calls, prompts, agents, RAG, tool/function calling, MCP | `references/domains/llm-ai.md` |
| Published package, exported API, semver surface | `references/domains/library-sdk.md` |
| Android/iOS, React Native, Electron, Tauri | `references/domains/mobile-desktop.md` |
| `manifest.json` with `content_scripts`, WebExtension APIs | `references/domains/browser-extension.md` |
| Multiple services, gRPC, message bus, service mesh, k8s east-west | `references/domains/microservices.md` |
| WordPress, Drupal, Shopify, Salesforce, Retool, n8n, Zapier | `references/domains/cms-lowcode.md` |
| Solidity/Vyper/Rust contracts, chain RPC, wallets | `references/domains/blockchain.md` |
| ETL/ELT, Spark, Airflow, dbt, warehouses, notebooks | `references/domains/data-pipeline.md` |
| Firmware, RTOS, MCU, serial/JTAG, OTA updates | `references/domains/embedded-iot.md` |
| Game client/server, matchmaking, virtual economy, anti-cheat | `references/domains/game.md` |

## Context Discipline

Each phase file opens with what to hold and what to release - follow it. Never hold more than one phase file at a time. Release domain guides after Phase 1.

For codebases over ~50 files or 3+ languages, read `references/multi-agent-strategy.md` and parallelize Phase 1 by module.

## Output Workspace

Create `.security-audit/` in the audited project root; Phase 0 lists the files. Offer to add it to `.gitignore` - it contains exploit detail. If it already exists from a prior run, use `references/differential-audit-protocol.md` instead of starting over.

## Load Only If Needed

`references/threat-intel.md` (EPSS/KEV enrichment) · `references/compliance/compliance-matrix.md` (framework named in Phase 0) · `references/compliance/privacy-audit.md` (GDPR/CCPA) · `references/setup/tool-install.md` (scanners missing)
