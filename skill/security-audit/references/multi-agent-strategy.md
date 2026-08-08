# Multi-Agent Parallel Scanning Strategy

This document defines when and how to decompose a security audit across multiple subagents for large or polyglot codebases. Read this during Phase 0 after completing project profiling.

---

## When to Parallelize

Parallelization adds coordination overhead. Only invoke it when at least one of these is true:

- **>50 source files** in the project (excluding vendored/generated code)
- **≥3 distinct languages** requiring different vulnerability knowledge (e.g., Python backend + TypeScript frontend + Terraform IaC)
- **Clearly decoupled modules** with separate entry points and minimal shared state (e.g., microservices, monorepo packages)

If the project is small or monolithic, run the full audit single-threaded - parallelization will add confusion without saving time.

---

## Decomposition Strategy

### Step 1: Identify Natural Boundaries

Split along **module/package/service boundaries**, not along arbitrary file counts. Each subagent should own a coherent unit that has its own:
- Entry points (routes, CLI commands, event handlers)
- Dependencies
- Trust boundaries

Good splits:
- `frontend/` vs `backend/` vs `infra/`
- Individual microservices in a monorepo
- Core library vs. CLI wrapper vs. web API layer

Bad splits:
- Alphabetical file grouping
- Splitting a single module across agents
- Separating test files from their source files (tests provide context for understanding the code)

### Step 2: Assign Finding ID Ranges

Each subagent gets a pre-allocated ID range to avoid collisions:

| Subagent | Scope | Finding ID Range |
|---|---|---|
| Agent A (Coordinator) | Cross-cutting concerns, auth flow, shared config | SEC-001 – SEC-099 |
| Agent B | Module/service 1 | SEC-100 – SEC-199 |
| Agent C | Module/service 2 | SEC-200 – SEC-299 |
| Agent D | Module/service 3 | SEC-300 – SEC-399 |
| Agent E | IaC / Deployment / CI-CD | SEC-400 – SEC-499 |

### Step 3: Shared Context Distribution

Before launching subagents, the coordinator must complete Phase 0 and distribute these read-only context files to every subagent:
- `project-profile.md` (full project context)
- `threat-model.md` (trust boundaries and STRIDE matrix)
- `data-flow-inventory.md` (source-to-sink map)

Each subagent receives the full context but only audits its assigned scope.

---

## Merge & Deduplication Protocol

After all subagents complete Phase 1, the coordinator merges findings:

### Dedup Rules
1. **Exact duplicate:** Same file, same line range, same CWE → keep the one with the more detailed exploit scenario
2. **Cross-boundary duplicate:** Same vulnerability pattern in shared utility code found by multiple agents → merge into one finding, cite all call sites
3. **Related but distinct:** Same CWE but different files/functions → keep both as separate findings

### Cross-Module Attack Chain Discovery
After merging, the coordinator must specifically look for **cross-boundary attack chains** - vulnerabilities in module A that become exploitable because of a weakness in module B. These chains are invisible to individual subagents.

Example: Agent B finds an SSRF in the API layer. Agent C finds an unprotected internal admin endpoint. Neither flags the combination - the coordinator must compose: "SEC-103 (SSRF) enables unauthenticated access to SEC-201 (unprotected admin endpoint)."

### Merge Output
The coordinator produces the unified `audit-checklist.md` and `security-findings.json`, re-numbering findings into a clean sequential order if needed, and proceeds to Phase 2 as a single-threaded process (dynamic tests must run sequentially to avoid interference).

---

## Subagent Invocation Template

When invoking subagents, use this pattern:

```
Role: "Security Auditor - [Module Name]"
Prompt: |
  You are conducting Phase 1 static analysis on [module scope].
  
  Read these context files first:
  - .security-audit/project-profile.md
  - .security-audit/threat-model.md
  - .security-audit/data-flow-inventory.md
  - references/rules.md (the skill's methodology reference)
  
  Your assigned finding ID range: SEC-[start] through SEC-[end].
  Your assigned scope: [directory/module paths]
  
  Apply the 4-Point Triage Gate to every potential finding.
  Assign CVSS v4.0 vectors to confirmed findings.
  Include a Confidence field (High/Medium/Low) for each finding.
  
  Output your findings as a JSON array following the schema in
  references/templates/security-findings-schema.json.
  
  Do NOT modify any project files. This is a read-only analysis.
```

---

## Coordinator Responsibilities

The coordinator (parent agent) owns:
- Phase 0 (recon) - always single-threaded
- Subagent dispatch and context distribution
- Finding merge and deduplication
- Cross-module attack chain composition
- Phases 2–6 - always single-threaded after merge
