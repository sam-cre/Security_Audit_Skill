# Phase 8 — Guided Infrastructure Hardening

_Prerequisite: Phase 7 complete. Hold `.security-audit/project-profile.md` for deployment context. Release source files._

This phase covers what **cannot be fixed in source code** — TLS, DNS, headers, secrets storage, WAF, monitoring. These live in hosting dashboards, DNS registrars, and cloud consoles.

**This is a guided walkthrough, not a checklist dump.** The failure mode of a checklist is that the user reads it, nods, and applies none of it. Work one item at a time and verify each before moving on.

---

## How to Run This Phase

1. **Establish the real stack.** Ask, don't assume:
   > Before I generate hardening steps — where does this actually run? (host/PaaS, DNS provider, CDN/WAF if any, where secrets live today, and whether you have console access.)

   Everything below is tailored to those answers. Generic advice is worthless here.

2. **Order by risk**, not by section number. Run the tracks in the order the project's threat model justifies. For an internet-facing app handling PII, that is usually: Secrets → TLS → Headers → Auth surface → Monitoring → DNS → Email.

3. **One item at a time.** For each:
   - **Why** — the concrete risk, tied to a Phase 1 finding where one exists
   - **Do** — exact commands or exact dashboard clicks for *their* provider
   - **Verify** — a command that proves it worked
   - **Record** — mark `Applied` / `Skipped` / `N/A` / `Blocked (reason)` in `.security-audit/hardening-recommendations.md`

4. **Never claim an item is done because you gave instructions.** It is done when the verify command passes. If you cannot verify (no console access, DNS not propagated), mark it `Pending verification` and say so.

5. **Do not perform these changes yourself.** DNS records, TLS certs, WAF rules, and vault migrations are the user's to apply — you write the exact config and verify the result. If a step needs credentials, the user enters them; you never do.

6. **Stop when the user has had enough.** Ten verified items beat forty unread ones. Offer to resume later; the checklist file is the resume point.

---

## Deliverable

`.security-audit/hardening-recommendations.md`, built from `references/templates/hardening-recommendations-template.md`. Each row carries a status. Add a summary line at the top:

```
Applied: 12  ·  Pending verification: 3  ·  Skipped (accepted risk): 2  ·  N/A: 7
```

---

## Track A — Secrets (usually first)

**Why first:** a leaked credential defeats every other control.

| Item | Do | Verify |
|---|---|---|
| Get secrets out of source | Move `.env` values into the platform's secret store (Vercel/Netlify env vars, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Doppler, HashiCorp Vault) | `gitleaks detect --source . --log-opts="--all"` returns clean |
| Rotate anything ever committed | Rotate at the provider. History rewriting alone does not help — assume it is public | New credential works; old one returns 401 |
| Stop the next leak | Enable GitHub/GitLab push protection; install the pre-commit hook from Phase 7 | Test-commit a dummy key and confirm it is blocked |
| Scope down | Replace long-lived root keys with least-privilege scoped credentials; prefer OIDC federation over static keys in CI | Review the IAM policy for wildcards |
| Rotation schedule | Set 90-day rotation with calendar reminders or automated rotation | Rotation date recorded |

---

## Track B — Transport (TLS)

| Item | Do | Verify |
|---|---|---|
| TLS 1.2 minimum, 1.3 preferred | Set the minimum version at the load balancer, CDN, or reverse proxy | `openssl s_client -connect HOST:443 -tls1_1` must **fail** |
| Disable weak ciphers | Remove RC4, 3DES, CBC-mode suites, anything with `NULL` or `EXPORT` | `nmap --script ssl-enum-ciphers -p 443 HOST` shows A-grade only |
| HSTS | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` | `curl -sI https://HOST \| grep -i strict-transport` |
| HSTS preload | Submit at hstspreload.org — **only after** confirming every subdomain is HTTPS. This is hard to undo. | Domain appears in the preload list |
| Cert auto-renewal | ACME / Let's Encrypt / ACM, plus an expiry alert at 15 days | Force a renewal in staging and confirm it succeeds |
| Redirect HTTP | 301 all HTTP to HTTPS at the edge | `curl -sI http://HOST` returns 301 to `https://` |

---

## Track C — Security Headers

Generate a CSP **from the codebase**, not from a template. Scan for actual script, style, font, image, and connect origins, then build the narrowest policy that does not break the app.

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
```

**CSP rollout order** — do not skip this, a bad CSP is an outage:
1. Deploy as `Content-Security-Policy-Report-Only` with a `report-uri`
2. Collect violations for at least one full traffic cycle (a week for most apps)
3. Widen only for legitimate violations; prefer nonces over `'unsafe-inline'`
4. Flip to enforcing

Skip header work entirely for APIs that never return HTML — see `rules.md` section 7. `X-Frame-Options` is superseded by `frame-ancestors`; set it only for legacy browser support.

**Verify:** `curl -sI https://HOST` and check each header is present with the intended value.

---

## Track D — Edge, WAF, Rate Limiting

Only recommend a WAF if there is a specific reason. "Deploy a WAF" with no finding behind it is noise.

| Item | Do | Verify |
|---|---|---|
| Managed ruleset | Enable OWASP core rules at the CDN (Cloudflare, AWS WAF, Azure Front Door, Fastly) | Send a benign probe such as `?q=<script>` and confirm it is blocked or logged |
| Rate limit auth endpoints | Login, signup, password reset, token refresh, and any expensive search or export | Script N+1 requests and confirm a 429 |
| Origin lockdown | Restrict origin to CDN IP ranges or authenticated origin pulls, so the WAF cannot be bypassed | Request the origin IP directly; it must refuse |
| Body size limits | Cap request body size at the edge and in the app | Post an oversized body and confirm 413 |
| Timeouts | Set request timeouts at every layer to prevent slowloris and cascading stalls | Slow-drip a request and confirm it is cut |

---

## Track E — DNS

| Item | Do | Verify |
|---|---|---|
| DNSSEC | Enable at the registrar | `dig +dnssec HOST` shows RRSIG records |
| CAA records | Restrict issuance to your CAs: `HOST. IN CAA 0 issue "letsencrypt.org"` | `dig CAA HOST` |
| Dangling records | Audit every CNAME for subdomain takeover — records pointing at deprovisioned cloud resources | Each CNAME target resolves to a resource you still own |
| Registrar lock | Enable transfer lock and 2FA on the registrar account | Confirm in the registrar console |

---

## Track F — Monitoring & Response

Detection is what turns a breach into an incident instead of a disaster.

| Item | Do | Verify |
|---|---|---|
| Centralized logs | Ship app, access, and auth logs off-host (CloudWatch, Datadog, Loki, ELK) | Logs appear within the expected delay |
| Auth event logging | Log every login success, failure, privilege change, and password/email change — **never** log the credentials | Trigger each event and confirm it lands |
| Alerts | 401/403 spike · admin login from a new ASN or country · IAM or secret access anomaly · bulk data export · unhandled-exception rate | Fire a test event per alert |
| Log retention | Retain long enough to investigate (90 days minimum for most; compliance may require more) | Confirm the retention policy |
| `security.txt` | Publish `/.well-known/security.txt` per RFC 9116 with a real contact and a future `Expires` | `curl https://HOST/.well-known/security.txt` |
| Response runbook | Write down: who to call, how to revoke sessions, how to rotate every secret, how to roll back | The runbook exists and names real people |

---

## Track G — Email Authentication (only if the domain sends mail)

Roll out DMARC in stages — jumping straight to `p=reject` will drop legitimate mail.

1. SPF: `v=spf1 include:PROVIDER ~all` — keep under 10 DNS lookups
2. DKIM: enable signing at the provider, publish the public key
3. DMARC monitoring: `v=DMARC1; p=none; rua=mailto:dmarc@DOMAIN`
4. Read reports for 2–4 weeks, fix legitimate senders that fail
5. Tighten to `p=quarantine`, then `p=reject`

**Verify:** `dig TXT DOMAIN`, `dig TXT _dmarc.DOMAIN`, and send a test to a mailbox that reports authentication results.

---

## Track H — Platform-Specific

Run only the block matching the Phase 0 deployment model.

**Containers / Kubernetes**
- Non-root user (`USER 10001`), `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`
- Drop all capabilities, add back only what is needed
- Seccomp `RuntimeDefault`; AppArmor or SELinux where available
- Distroless or minimal base image; scan images in CI
- Resource limits on every container; NetworkPolicy default-deny east-west
- Verify: `trivy image IMAGE`, `kube-score score manifest.yaml`

**Serverless**
- One least-privilege execution role per function, never a shared role
- Strict timeouts and concurrency caps (runaway-bill protection)
- Private networking to data stores; no public function URLs unless intended
- Verify: review each function's IAM policy for wildcard actions or resources

**Desktop / Electron / Tauri**
- Code signing and notarization; `contextIsolation: true`, `nodeIntegration: false`
- Strict `allowlist`/capability config in Tauri; validate all IPC input
- Auto-update over HTTPS with signature verification
- Strip debug symbols from release builds
- Verify: confirm the signature on a built artifact

**Mobile**
- Certificate pinning; no secrets in the bundle (they are extractable, always)
- Keychain/Keystore for tokens, never `SharedPreferences`/`UserDefaults`
- Disable backup of sensitive data; obfuscate release builds
- Verify: unzip the built package and grep for known secret patterns

**Embedded / IoT**
- Signed firmware with rollback protection and anti-downgrade
- Disable JTAG/UART/debug in production images
- Secure boot chain; encrypted credential storage
- Per-device unique keys — never a shared factory key
- Verify: attempt to flash an unsigned image; it must be rejected

---

## Track I — Supply Chain & Repo

| Item | Do | Verify |
|---|---|---|
| Least-privilege CI | Default `permissions: read-all`, grant per job | Review workflow files |
| Pin actions/images | Pin third-party CI actions to a commit SHA, not a tag | Grep for `@v` in workflow files |
| Branch protection | Require PR review, passing checks, and signed commits on the default branch | Try to push directly; it must be rejected |
| Artifact signing | Sign releases and container images (Sigstore/Cosign) | `cosign verify` succeeds |
| Publish SBOM | Attach the CycloneDX SBOM to each release | SBOM present on the release |
| Dependency updates | Enable Dependabot or Renovate with auto-merge for patch-level security updates | A test PR is raised |

---

## Closing the Audit

1. Ensure `.security-audit/hardening-recommendations.md` has a status on every row
2. Update `.security-audit/security-audit-report.md` with the hardening summary
3. State plainly what remains unverified and why
4. Recommend a re-audit in 3–6 months, or after any major change — `references/differential-audit-protocol.md` makes the re-run cheap
