# Guided Security Tool Installation

_Read when scanners are missing and the user wants real coverage, or when invoked as `/security-audit setup`._

Scanners raise audit quality substantially — they catch known-pattern bugs cheaply, freeing reasoning for logic flaws they cannot see. But an audit without them is still valid; it just carries a coverage caveat.

---

## How to Run This

1. **Detect first.** Run the probes in `phase-0-recon.md` Step 2 and show the user what is present versus missing.
2. **Recommend a tier, don't dump the list.** Most people need the Core Four, not fifteen tools.
3. **Ask before installing.** Installing software is the user's call. Present the exact command and let them approve it.
4. **Verify each install** before moving to the next.
5. **If an install fails, move on.** Note the gap and use the fallback. Never let tool setup consume the session.

---

## Tiers

**Core Four — covers ~80% of automated value. Recommend these unless the user wants more.**

| Tool | Catches | Why it earns its place |
|---|---|---|
| `semgrep` | Injection, XSS, SSRF, crypto misuse, auth patterns | Multi-language, high signal with curated rulesets |
| `trivy` | Dependency CVEs, container CVEs, IaC misconfig, secrets | Four tools in one binary |
| `gitleaks` | Committed secrets across full git history | Finds what HEAD-only review misses |
| `osv-scanner` | Dependency CVEs from the OSV database | Authoritative, cross-ecosystem, complements Trivy |

**Language add-ons — only for languages actually in the project:** `bandit` (Python), `gosec` (Go), `cargo-audit` (Rust), `brakeman` (Rails), `npm audit` (built in), `hadolint` (Dockerfiles).

**Deep tier — only for `deep` mode or dedicated infra work:** `checkov` (IaC), `syft` (SBOM), `nuclei` (DAST), `trufflehog` (deeper secret verification).

---

## Windows

Prefer **winget** (built into Windows 11). Fall back to **Scoop** for tools winget lacks.

```powershell
# Core Four
winget install --id Semgrep.Semgrep -e
winget install --id AquaSecurity.Trivy -e
winget install --id Gitleaks.Gitleaks -e
winget install --id Google.OSVScanner -e
```

If a package ID is not found, use Scoop:

```powershell
# One-time Scoop setup
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
scoop bucket add main

scoop install trivy gitleaks osv-scanner syft
```

Python- and Go-based tools:

```powershell
# Python-based (needs Python 3.9+)
pip install semgrep bandit checkov pip-audit

# Go-based (needs Go 1.21+)
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Windows caveats worth stating up front:**
- **Semgrep** has limited native Windows support. If it misbehaves, run it under WSL2 or Docker: `docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep scan --config=auto /src`
- **PATH** — after `go install`, ensure `%USERPROFILE%\go\bin` is on PATH. After `pip install --user`, ensure the Python Scripts directory is too.
- **Restart the shell** after any PATH change or the tool will appear missing.
- Some scanners emit CRLF-sensitive output; prefer JSON output flags everywhere.

---

## macOS

```bash
brew install semgrep trivy gitleaks osv-scanner syft trufflehog hadolint
pip install bandit checkov pip-audit
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

## Linux (Debian/Ubuntu)

```bash
# Trivy
sudo apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy

# Others
pip install semgrep bandit checkov pip-audit
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
go install github.com/gitleaks/gitleaks/v8@latest
go install github.com/google/osv-scanner/cmd/osv-scanner@v1
```

---

## Docker-Only Path

If the user cannot or will not install anything, every core scanner runs containerized. This is also the cleanest option on Windows.

```bash
docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep scan --config=auto /src
docker run --rm -v "${PWD}:/src" aquasec/trivy fs /src
docker run --rm -v "${PWD}:/path" zricethezav/gitleaks:latest detect --source=/path
docker run --rm -v "${PWD}:/src" anchore/syft:latest /src -o cyclonedx-json
```

---

## Verify

Run after installing. Every line should print a version.

```bash
semgrep --version && trivy --version && gitleaks version && osv-scanner --version
```

The bundled scripts `references/setup/bootstrap-tools.ps1` (Windows) and `bootstrap-tools.sh` (POSIX) automate the Core Four plus verification. **Read the script to the user before running it** — never execute an install script they have not seen.

---

## Recording the Result

Update the tooling matrix in `.security-audit/project-profile.md`:

| Tool | Status | Version | Fallback in use |
|---|---|---|---|
| semgrep | Installed | 1.x | — |
| trivy | Installed | 0.x | — |
| gitleaks | Missing | — | git-history-scan script + entropy sweep |

Whatever remains missing goes in the report's Coverage section. Never imply coverage you did not have.
