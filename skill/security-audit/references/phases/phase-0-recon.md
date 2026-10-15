# Phase 0 - Recon & Scoping

_Everything downstream depends on this. Hold `references/rules.md`._

---

## Workspace

`.security-audit/` in the audited project root, built up across phases:

```
project-profile.md        threat-model.md          security-findings.json
data-flow-inventory.md    audit-checklist.md       security-findings.sarif
dependency-cve-report.md  pentest-methodology.md   security-tests/
sbom.cdx.json             raw/                     security-audit-report.md
                                                   hardening-recommendations.md
```

Offer to add it to `.gitignore` (it holds exploit detail and secret locations). Create subfolders lazily, only when about to write their first file. Empty folders read as unfinished work.

---

## Step 0: Scope

Apply `rules.md` section 1. Record scope at the top of `project-profile.md`, state it back in one line, and proceed. Block only if the user asked to test a remote target. Any network traffic needs host ownership confirmed before Phase 3.

---

## Step 1: Profile the Project

Read manifests and entry points. Assume nothing.

| Dimension | Determine |
|---|---|
| **Type** | Web app, API, CLI, library, agent, IaC, embedded, contract, pipeline, game, daemon, mobile, desktop, extension. Be specific. |
| **Languages/frameworks** | Every one, with versions from manifests |
| **Package managers** | package.json, requirements/pyproject, Cargo.toml, go.mod, pom.xml, build.gradle, Gemfile, composer.json, *.csproj |
| **Architecture** | Monolith, monorepo, multi-service, serverless, static. Count deployable units. |
| **Build & deploy** | How it ships; CI config? |
| **Privilege model** | User, root, container root, cloud IAM role, kernel, firmware |
| **Network exposure** | Public HTTP, internal, outbound only, air-gapped, local IPC, none |
| **Data sensitivity** | PII, payment, health, credentials, keys, none |
| **AuthN/AuthZ** | None, session, JWT, OAuth/OIDC, SAML, mTLS, API key; roles |

Write `.security-audit/project-profile.md` from `references/templates/project-profile-template.md`. If the project handles payment, health, or EU personal data, flag it now: it changes severity weighting and may pull in `references/compliance/`.

---

## Step 2: Discover Scanners

Probe and record in the tooling matrix in `project-profile.md`.

```bash
semgrep --version; bandit --version; gosec --version; eslint --version; brakeman --version; phpstan --version   # SAST
trivy --version; osv-scanner --version; pip-audit --version; cargo audit --version                              # SCA
gitleaks version; trufflehog --version                                                                          # secrets
checkov --version; tfsec --version; kube-score version; hadolint --version                                      # IaC
nuclei -version; nikto -Version                                                                                 # DAST
syft version; cdxgen --version                                                                                  # SBOM
```

Missing tools do not halt the audit. Use the fallback and record the degradation:

| Category | Fallback |
|---|---|
| SAST | Reasoned review per domain guides, walking `data-flow-inventory.md` |
| SCA | Parse manifests, verify against OSV.dev (`rules.md` section 5) |
| Secrets | `references/scripts/git-history-scan.ps1` / `.sh` plus a high-entropy regex sweep |
| IaC | Manual review against `references/domains/iac-cloud.md` |
| DAST | Manual curl probing in Phase 3 |
| SBOM | Enumerate manifests into `references/templates/sbom-template.json` |

If many tools are missing and the user wants scanner coverage, offer `references/setup/tool-install.md`. Ask before installing.

---

## Step 3: Git History Forensics

Secrets deleted from HEAD still live in history.

```bash
gitleaks detect --source . --log-opts="--all" --report-path .security-audit/raw/gitleaks-history.json --report-format json
```

Or `references/scripts/git-history-scan.ps1` / `.sh`. Fallback:
```bash
git log -p -G"(?i)(password|secret|api[_-]?key|token|private[_-]?key|BEGIN RSA)" --all -n 500
```

Also check for ever-committed `.env` variants, cloud credential files, `.pem`/`.p12`/`.keystore`, and CI config with inline secrets. Record location and type only (`rules.md` section 9). For a live secret, tell the user at once and recommend rotation; rewriting history is not enough once pushed.

---

## Step 4: Entry Points and Data Flows

The attack-surface contract Phase 1 walks. Every source traces to the sinks it can reach.

**Sources:** HTTP bodies, params, headers, cookies · WebSocket frames · CLI args, stdin, env · file uploads/reads · DB reads of user-origin data · queue payloads · LLM prompts and RAG retrievals · tool-call results · IPC/sockets · webhooks · chain calldata · sensor/radio input · game packets · extension messages

**Sinks:** SQL/NoSQL execution · OS commands · filesystem writes and path building · template rendering · response construction · deserialization · outbound HTTP (SSRF) · crypto operations · authn/authz decisions · contract state changes · unsafe-code memory ops · reflection/dynamic dispatch · LLM tool invocation

Build `.security-audit/data-flow-inventory.md` from `references/templates/data-flow-inventory-template.md`; rows are source, path, sink, controls. Rank by reachability x sink danger x data sensitivity so a truncated audit still covers what matters.

---

## Step 5: Threat Model

Build `.security-audit/threat-model.md` from `references/templates/threat-model-template.md`: Mermaid data-flow diagram matching the real architecture; trust boundaries; assets worth attacking; realistic threat actors (unauthenticated internet, low-privilege user, insider, supply chain, compromised dependency); STRIDE matrix. Keep it proportional: a CLI does not need twelve actors.

---

## Step 6: SBOM

```bash
syft . -o cyclonedx-json > .security-audit/sbom.cdx.json
```
Fallback: `references/templates/sbom-template.json`.

---

## Step 7: Dependency CVE Check

Run SCA tools, then `rules.md` section 5 (verification and reachability rubric). Optional EPSS/KEV enrichment: `references/threat-intel.md`. Write `.security-audit/dependency-cve-report.md`.

---

## Step 8: Compliance (optional)

Ask once whether a framework applies: PCI-DSS 4.0, SOC 2, HIPAA, GDPR, ISO 27001, NIST CSF 2.0, OWASP ASVS 5.0, FedRAMP. If yes, record it and load `references/compliance/compliance-matrix.md` in Phase 4. Do not volunteer it.

---

## Step 9: Select Domain Guides

Match the profile to the router in SKILL.md; record the selection in `project-profile.md`. Phase 1 loads only those. A typical SaaS web app is `web-api` + `auth-identity` + `iac-cloud`; add `llm-ai` if it calls a model, `microservices` if more than one deployable service.

---

## Gate to Proceed

Scale artifacts to the target (`rules.md` section 9: overstating coverage is worse than a short audit). The first two are required; compress the rest for a small, single-service, low-sensitivity codebase, but record what you compressed and why in one line in `project-profile.md`. Silent skipping is the failure mode; "SBOM: single manifest, enumerated inline" is fine.

- [ ] Scope and authorization recorded - **required**
- [ ] `project-profile.md` complete with tooling matrix - **required**
- [ ] Entry points and data flows mapped (inline for a tiny surface)
- [ ] `threat-model.md` written (compress for simple targets)
- [ ] `dependency-cve-report.md` written
- [ ] SBOM generated, or manifest enumerated inline
- [ ] Domain guides selected and recorded
- [ ] Anything compressed is recorded with a reason
