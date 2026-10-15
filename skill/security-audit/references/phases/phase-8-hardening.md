# Phase 8 - Guided Infrastructure Hardening

_Prerequisite: Phase 7 done. Hold `.security-audit/project-profile.md` for deployment context. Release source files._

Covers what source code cannot fix: TLS, DNS, headers, secrets storage, WAF, monitoring. These live in hosting dashboards, registrars, and cloud consoles. Run it as a guided walkthrough, one item at a time, not a checklist dump.

---

## How to Run

1. **Establish the real stack.** Ask: where does this run (host/PaaS, DNS provider, CDN/WAF, where secrets live now) and does the user have console access? Tailor everything to the answers.
2. **Order by risk.** For an internet-facing app with PII: Secrets, TLS, Headers, Auth surface, Monitoring, DNS, Email.
3. **Per item:** **Why** (risk, tied to a Phase 1 finding if any), **Do** (exact commands or clicks for their provider), **Verify** (a command proving it worked), **Record** (`Applied` / `Skipped` / `N/A` / `Blocked (reason)` in `.security-audit/hardening-recommendations.md`).
4. An item is done only when its verify command passes. If you cannot verify, mark `Pending verification`.
5. The user applies DNS, TLS, WAF, and vault changes. You write the exact config and verify. The user enters any credentials; you never do.
6. Stop when the user has had enough. Ten verified items beat forty unread. The checklist file is the resume point.

**Deliverable:** `.security-audit/hardening-recommendations.md` from `references/templates/hardening-recommendations-template.md`, a status on every row, and a top line like:
`Applied: 12 · Pending verification: 3 · Skipped (accepted risk): 2 · N/A: 7`

---

## Track A - Secrets (usually first)

A leaked credential defeats every other control.

| Item | Do | Verify |
|---|---|---|
| Out of source | Move `.env` values to a secret store (platform env vars, AWS/GCP/Azure secret managers, Doppler, Vault) | `gitleaks detect --source . --log-opts="--all"` clean |
| Rotate anything ever committed | Rotate at the provider. Rewriting history is not enough; assume public | New credential works, old returns 401 |
| Stop the next leak | Enable push protection; install the Phase 7 pre-commit hook | Commit a dummy key; it is blocked |
| Scope down | Least-privilege scoped credentials; OIDC federation over static keys in CI | IAM policy has no wildcards |
| Rotation | 90-day rotation, reminders or automated | Date recorded |

## Track B - TLS

| Item | Do | Verify |
|---|---|---|
| TLS 1.2 min, 1.3 preferred | Set at LB, CDN, or proxy | `openssl s_client -connect HOST:443 -tls1_1` fails |
| Weak ciphers | Remove RC4, 3DES, CBC suites, NULL, EXPORT | `nmap --script ssl-enum-ciphers -p 443 HOST` |
| HSTS | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` | `curl -sI https://HOST \| grep -i strict-transport` |
| HSTS preload | hstspreload.org, **only after** every subdomain is HTTPS. Hard to undo | Domain in the list |
| Auto-renewal | ACME/ACM plus expiry alert at 15 days | Forced staging renewal succeeds |
| HTTP redirect | 301 to HTTPS at the edge | `curl -sI http://HOST` |

## Track C - Security Headers

Build the CSP **from the codebase**: scan real script, style, font, image, and connect origins, then write the narrowest policy that works.

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
```

**CSP rollout** (a bad CSP is an outage): 1) `Content-Security-Policy-Report-Only` with `report-uri`; 2) collect violations for a full traffic cycle (about a week); 3) widen only for legitimate violations, prefer nonces over `'unsafe-inline'`; 4) enforce.

Skip headers for APIs that never return HTML (`rules.md` section 7). `frame-ancestors` supersedes `X-Frame-Options`; set the latter only for legacy browsers.

**Verify:** `curl -sI https://HOST`, each header present with the intended value.

## Track D - Edge, WAF, Rate Limiting

Recommend a WAF only with a specific reason.

| Item | Do | Verify |
|---|---|---|
| Managed ruleset | Enable OWASP core rules at the CDN | Benign probe `?q=<script>` is blocked or logged |
| Rate limit | Login, signup, reset, token refresh, expensive search/export | N+1 requests return 429 |
| Origin lockdown | Allow only CDN IPs or authenticated origin pulls | Direct origin request refused |
| Body size | Cap at edge and app | Oversized post returns 413 |
| Timeouts | Every layer, against slowloris | Slow-drip request is cut |

## Track E - DNS

| Item | Do | Verify |
|---|---|---|
| DNSSEC | Enable at registrar | `dig +dnssec HOST` shows RRSIG |
| CAA | `HOST. IN CAA 0 issue "letsencrypt.org"` | `dig CAA HOST` |
| Dangling records | Audit every CNAME for takeover (deprovisioned cloud targets) | Each target is a resource you own |
| Registrar lock | Transfer lock plus 2FA | Confirm in console |

## Track F - Monitoring & Response

| Item | Do | Verify |
|---|---|---|
| Central logs | Ship app, access, auth logs off-host | Logs arrive in expected time |
| Auth events | Log login success/failure, privilege, password/email changes. Never log credentials | Trigger each, confirm it lands |
| Alerts | 401/403 spike, admin login from new ASN/country, IAM or secret anomaly, bulk export, exception rate | Fire a test per alert |
| Retention | 90 days minimum unless compliance says more | Policy confirmed |
| `security.txt` | `/.well-known/security.txt` per RFC 9116, real contact, future `Expires` | `curl` it |
| Runbook | Who to call, revoke sessions, rotate every secret, roll back | Exists and names real people |

## Track G - Email Authentication (only if the domain sends mail)

Stage DMARC; jumping to `p=reject` drops legitimate mail.
1. SPF: `v=spf1 include:PROVIDER ~all`, under 10 lookups
2. DKIM: enable signing, publish key
3. DMARC: `v=DMARC1; p=none; rua=mailto:dmarc@DOMAIN`
4. Read reports 2-4 weeks, fix legitimate failing senders
5. `p=quarantine`, then `p=reject`

**Verify:** `dig TXT DOMAIN`, `dig TXT _dmarc.DOMAIN`, and a test mail to a mailbox that shows auth results.

## Track H - Platform-Specific

Run only the block matching the Phase 0 deployment model.

**Containers / Kubernetes:** non-root (`USER 10001`), `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`; drop all capabilities; seccomp `RuntimeDefault`; minimal base image scanned in CI; resource limits; default-deny NetworkPolicy. Verify: `trivy image IMAGE`, `kube-score score manifest.yaml`.

**Serverless:** one least-privilege role per function; strict timeouts and concurrency caps; private networking to data stores; no unintended public URLs. Verify: no wildcard IAM actions or resources.

**Desktop (Electron/Tauri):** signing and notarization; `contextIsolation: true`, `nodeIntegration: false`; strict Tauri capability config and validated IPC; signed auto-update over HTTPS; no debug symbols in release. Verify: signature on a built artifact.

**Mobile:** certificate pinning; no secrets in the bundle (always extractable); Keychain/Keystore for tokens, not `SharedPreferences`/`UserDefaults`; no backup of sensitive data; obfuscated release. Verify: unzip the package and grep for secret patterns.

**Embedded / IoT:** signed firmware with rollback and anti-downgrade; JTAG/UART/debug off in production; secure boot; encrypted credential storage; unique per-device keys. Verify: flashing an unsigned image is rejected.

## Track I - Supply Chain & Repo

| Item | Do | Verify |
|---|---|---|
| Least-privilege CI | Default `permissions: read-all`, grant per job | Review workflows |
| Pin actions/images | Pin third-party actions to a commit SHA | Grep `@v` in workflows |
| Branch protection | Require review, passing checks, signed commits | Direct push rejected |
| Artifact signing | Sigstore/Cosign for releases and images | `cosign verify` |
| SBOM | Attach CycloneDX SBOM to each release | Present on release |
| Dependency updates | Dependabot or Renovate, auto-merge patch security updates | Test PR raised |

---

## Closing the Audit

1. Every row in `hardening-recommendations.md` has a status
2. Add the hardening summary to `security-audit-report.md`
3. State plainly what remains unverified and why
4. Recommend a re-audit in 3-6 months or after major change; `references/differential-audit-protocol.md` makes it cheap
