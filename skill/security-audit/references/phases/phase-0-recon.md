# Phase 0 - Recon & Scoping

_The foundation. Everything downstream depends on getting this right. Hold `references/rules.md`._

---

## Create the Workspace

`.security-audit/` in the audited project root. Built up across phases:

```
project-profile.md        threat-model.md          security-findings.json
data-flow-inventory.md    audit-checklist.md       security-findings.sarif
dependency-cve-report.md  pentest-methodology.md   security-tests/
sbom.cdx.json             raw/                     security-audit-report.md
                                                   hardening-recommendations.md
```

Offer to add `.security-audit/` to `.gitignore` - it records exploit detail and secret locations.

**Create directories lazily, not up front.** Don't `mkdir` `raw/` or `security-tests/` in Phase 0 "just in case" - create each one the moment you're about to write its first file, and only if that phase actually produces something (no scanners installed → nothing lands in `raw/`; no PoC scripts needed → nothing lands in `security-tests/`). A workspace left with empty subfolders reads as unfinished work to the user; every folder present should have something in it.

---

## Step 0: Confirm Scope and Authorization

Before anything else, establish what you are allowed to touch. Record it at the top of `project-profile.md`.

- Confirm the user owns or is authorized to test this code.
- **In scope by default:** the local codebase, local dev instances, sandboxed containers.
- **Out of scope by default:** production, staging, shared environments, third-party APIs, any host you did not confirm the user controls.
- If the audit will involve network traffic to any hostname or IP, ask the user to confirm they control it *before* Phase 3.

State the scope back to the user in one line and proceed. Do not block on this unless the user has asked you to test a remote target.

---

## Step 1: Profile the Project

Walk the tree. Do not assume - read the manifests and the entry points.

| Dimension | What to determine |
|---|---|
| **Type** | Web app, API, CLI, library, agent, IaC, embedded, contract, pipeline, game, daemon, mobile, desktop, extension. Be specific. |
| **Languages/frameworks** | Every one present, with versions from the manifests |
| **Package managers** | package.json, requirements.txt/pyproject, Cargo.toml, go.mod, pom.xml, build.gradle, Gemfile, composer.json, *.csproj |
| **Architecture** | Monolith, monorepo, multi-service, serverless, static. Count deployable units. |
| **Build & deploy** | How it compiles, bundles, ships. CI config present? |
| **Privilege model** | Runs as user, root, container root, cloud IAM role, kernel, device firmware |
| **Network exposure** | Public HTTP, internal only, outbound only, air-gapped, local IPC, none |
| **Data sensitivity** | PII, payment data, health data, credentials, crypto keys, nothing sensitive |
| **AuthN/AuthZ model** | None, session, JWT, OAuth/OIDC, SAML, mTLS, API key. What are the roles? |

Write to `.security-audit/project-profile.md` using `references/templates/project-profile-template.md`.

**Sensitive-data note:** if the project handles payment, health, or EU personal data, flag it now - it changes severity weighting and may pull in `references/compliance/`.

---

## Step 2: Discover Scanners

Probe availability. Record results in the tooling matrix inside `project-profile.md`.

```bash
# SAST
semgrep --version; bandit --version; gosec --version
eslint --version; brakeman --version; phpstan --version
# SCA
trivy --version; osv-scanner --version; pip-audit --version
cargo audit --version
# Secrets
gitleaks version; trufflehog --version
# IaC / containers
checkov --version; tfsec --version; kube-score version; hadolint --version
# DAST
nuclei -version; nikto -Version
# SBOM
syft version; cdxgen --version
```

Missing tools do **not** halt the audit. Apply this fallback matrix and record the degradation:

| Category | Fallback |
|---|---|
| SAST | Reasoned review against the domain guides, walking `data-flow-inventory.md` |
| SCA | Parse manifests, verify each package against the OSV.dev API (`rules.md` section 5) |
| Secrets | `references/scripts/git-history-scan.ps1` / `.sh` plus a high-entropy regex sweep |
| IaC | Manual structural review against `references/domains/iac-cloud.md` |
| DAST | Manual endpoint probing with curl in Phase 3 |
| SBOM | Manual manifest enumeration into CycloneDX via `references/templates/sbom-template.json` |

If several tools are missing and the user wants real scanner coverage, offer the guided installer at `references/setup/tool-install.md`. Ask before installing anything.

---

## Step 3: Git History Forensics

Secrets deleted from HEAD still live in history.

```bash
gitleaks detect --source . --log-opts="--all" --report-path .security-audit/raw/gitleaks-history.json --report-format json
```

Or the bundled script: `references/scripts/git-history-scan.ps1` (Windows) / `.sh` (POSIX).

Fallback:
```bash
git log -p -G"(?i)(password|secret|api[_-]?key|token|private[_-]?key|BEGIN RSA)" --all -n 500
```

Also check whether these were ever committed: `.env` variants, cloud credential files, `.pem` / `.p12` / `.keystore`, CI config with inline secrets.

**Record location and secret type only - never the value.** If a live secret is found, tell the user immediately and recommend rotation. Rewriting history is not sufficient once a secret has been pushed.

---

## Step 4: Map Entry Points and Data Flows

This is the attack-surface contract Phase 1 walks. Every source must trace to the sinks it can reach.

**Sources (untrusted input):** HTTP bodies, params, headers, cookies · WebSocket frames · CLI args, stdin, env vars · file uploads and reads · DB reads of user-origin data · queue payloads (Kafka, SQS, RabbitMQ) · LLM prompts and RAG retrievals · tool/function-call results · IPC and sockets · webhooks · chain calldata · sensor and radio input · game client packets · browser-extension message passing

**Sinks (dangerous operations):** SQL and NoSQL execution · OS command execution · filesystem writes and path construction · template rendering · HTTP response construction · deserialization · outbound HTTP (SSRF) · crypto operations · authn/authz decisions · contract state changes · memory operations in unsafe code · reflection and dynamic dispatch · LLM tool invocation

Build `.security-audit/data-flow-inventory.md` from `references/templates/data-flow-inventory-template.md`. Each row: source → path → sink → controls present.

**Prioritize.** Rank flows by reachability x sink danger x data sensitivity. Phase 1 works this list top-down, so a truncated audit still covers what matters most.

---

## Step 5: Threat Model

Build `.security-audit/threat-model.md` from `references/templates/threat-model-template.md`:

1. **Mermaid data-flow diagram** matching the real architecture
2. **Trust boundaries** - every point where trusted meets untrusted
3. **Assets** - what is actually worth stealing or breaking here
4. **Threat actors** - unauthenticated internet, authenticated low-privilege user, insider, supply chain, compromised dependency. Which are realistic for *this* project?
5. **STRIDE matrix** across all six categories

Keep it proportional. A CLI tool does not need a twelve-actor threat model.

---

## Step 6: SBOM

```bash
syft . -o cyclonedx-json > .security-audit/sbom.cdx.json
```

Fallback: parse manifests into CycloneDX using `references/templates/sbom-template.json`.

---

## Step 7: Dependency CVE Check

Run available SCA tools, then apply the **CVE Verification Protocol** in `rules.md` section 5. Never recall a CVE from memory.

Note **reachability** where you can. A CVE in a package you import but never call on a reachable path is real but lower priority - say so rather than inflating severity.

If the user wants exploit-likelihood prioritization, enrich with EPSS and CISA KEV via `references/threat-intel.md`.

Write to `.security-audit/dependency-cve-report.md`.

---

## Step 8: Compliance Scoping (optional)

Ask once whether any framework applies: PCI-DSS 4.0, SOC 2, HIPAA, GDPR, ISO 27001, NIST CSF 2.0, OWASP ASVS 5.0, FedRAMP. If yes, record it and load `references/compliance/compliance-matrix.md` during Phase 4. Do not volunteer compliance work nobody asked for.

---

## Step 9: Select Domain Guides

Match the profile against the router in SKILL.md and record the selection in `project-profile.md`. Load **only** the matching guides in Phase 1.

Most real projects match several. A typical SaaS web app is `web-api` + `auth-identity` + `iac-cloud`. Add `llm-ai` if it calls a model, `microservices` if there is more than one deployable service.

---

## Gate to Proceed

**Proportional, not all-or-nothing.** Per `rules.md` §9, an audit that overstates its coverage is worse than a short one - so scale these artifacts to the target. The first two are always required; the rest are strong defaults you may compress for a small, single-service, low-sensitivity codebase **as long as you record what you compressed and why** (one line in `project-profile.md`). A CLI tool does not need a formal `threat-model.md` with a mermaid diagram; a payment system does. Skipping an artifact silently is the failure mode - noting "SBOM: single manifest, enumerated inline; no separate sbom.cdx.json" is fine.

- [ ] Scope and authorization recorded - **required**
- [ ] `project-profile.md` complete, including the tooling matrix - **required**
- [ ] Entry points and data flows mapped (`data-flow-inventory.md`, or inline for a tiny surface)
- [ ] `threat-model.md` written - proportional; compress for simple targets
- [ ] `dependency-cve-report.md` written
- [ ] `sbom.cdx.json` generated - or manifest enumerated inline for a single-manifest project
- [ ] Domain guides selected and recorded
- [ ] Anything compressed above is recorded with a one-line reason
