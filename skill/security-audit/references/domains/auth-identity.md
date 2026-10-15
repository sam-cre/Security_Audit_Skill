# Domain: Authentication, Session & Authorization

_Load when the project has login, sessions, tokens, SSO, roles, or multi-tenancy. Pairs with `web-api.md`._

Auth bugs are usually the highest-severity findings and scanners miss them, because the flaw is a **missing** check, not a dangerous call. Read the code; don't just grep.

---

## 1. Password Storage

- MD5, SHA-1, SHA-256, or any fast hash for passwords (need **argon2id**, **scrypt**, **bcrypt**)
- No per-user salt, or a shared/static salt
- Low work factor (bcrypt cost < 12, argon2 memory < 19 MiB) or unchanged since 2015; no rehash-on-login when raised
- Hand-rolled key derivation
- Password compared with `==`, not constant-time
- bcrypt 72-byte truncation unhandled
- Password or hash in logs, errors, or analytics

## 2. Login Flow

- No rate limit, or limit keyed on IP only (proxy pools bypass it)
- **User enumeration** via message, status code, or response time (existence check short-circuits before the hash)
- No lockout or progressive delay; no credential-stuffing defense (breached-password check, anomaly detection)
- Login over plaintext HTTP anywhere; credentials in a query string
- "Remember me" token that is long-lived with no rotation or revocation

## 3. Session Management

- Session ID not regenerated on login (**fixation**)
- Session not invalidated on logout, password change, email change, MFA enrollment
- Cookies missing `HttpOnly`, `Secure`, `SameSite`; `SameSite=None` without need; broad `Domain` across untrusted subdomains
- Session IDs from a non-CSPRNG or under 128 bits
- No absolute lifetime (idle timeout only, or none)
- Client-side sessions without integrity protection
- No way to list or revoke active sessions; no concurrent-session limit where the threat model needs one

## 4. JWT

- `alg: none` accepted
- **Algorithm confusion**: RS256 verifier accepts HS256, so the public key becomes the HMAC secret
- Weak, default, or cross-environment HMAC secret
- Signature unverified (`decode` where `verify` was meant)
- `exp` missing, unchecked, or months long
- `aud`/`iss` unvalidated (tokens from another service or tenant accepted)
- No revocation path (no denylist, no short-lived token plus refresh)
- Sensitive data in the payload (base64, not encryption)
- JWT in `localStorage` (XSS reads it); prefer `HttpOnly` cookies
- `kid` used to select a key without validation (path traversal, SQLi in key lookup)
- JWKS fetched over HTTP or uncached/unpinned (key substitution)

## 5. OAuth 2.0 / OIDC

- Missing or unvalidated `state` (callback CSRF)
- No PKCE on public clients; `plain` method accepted
- `redirect_uri` matched by prefix or substring, not exact (**open redirect, token theft**)
- Implicit flow still used (use code + PKCE)
- Auth code not bound to client, or reusable
- `nonce` unvalidated in OIDC (ID token replay)
- ID token used as access token, or accepted unverified
- Over-broad scopes; no server-side per-scope enforcement
- Client secret in a mobile app or SPA bundle
- Refresh tokens never rotated, or rotated without reuse detection
- Account linking by unverified email (**pre-account-takeover**)

## 6. SAML

- Signature unverified, or only the assertion verified, not the response
- **XML Signature Wrapping**: unsigned assertion added beside the signed one
- XXE in the SAML parser
- `NotBefore`/`NotOnOrAfter`/`Recipient`/`Audience` unvalidated
- Assertion replay (no `InResponseTo` check, no one-time-use tracking)
- IdP cert not pinned, or rotation unhandled

## 7. Multi-Factor Authentication

- MFA enforced in the UI, not the API; post-MFA endpoint callable directly
- OTP reusable or no attempt limit (6-digit brute force)
- TOTP window too wide; no replay tracking
- Backup codes few, reusable, or unhashed
- SMS as sole factor on high-value accounts
- MFA not required to disable MFA or change recovery email
- "Trust this device" tokens that never expire or aren't device-bound
- WebAuthn: origin, RP ID, challenge, or user-verification flag unvalidated; sign counter ignored

## 8. Password Reset & Recovery

The most commonly broken flow. Walk it end to end.

- Token predictable, sequential, or non-CSPRNG
- Token lifetime too long (use 15-60 min), reusable, or valid after a successful reset
- Token not bound to the requesting user
- **Host header injection**: reset link built from `Host`
- Reset link leaked via `Referer` to third-party scripts
- In-session password change without the old password
- Sessions survive a reset
- Endpoint reveals whether an account exists
- Email change with no confirmation to the **old** address
- Security questions as sole factor
- No rate limit on reset requests (mail flooding, token grinding)

## 9. Registration & Verification

- Email verification not enforced before privileged actions; verification tokens share section 8 weaknesses
- Case, unicode, or `+`-alias normalization differs between registration and login (duplicate or hijackable accounts)
- Homograph or confusable usernames allowed
- No mass-registration defense where it matters

## 10. Authorization

- **IDOR/BOLA**: object fetched by user-supplied ID with no ownership check. Test every `:id` route.
- **BFLA**: admin function reachable by low roles because the check is UI-only
- Check at the controller but bypassable via a second route, GraphQL resolver, batch endpoint, or internal API
- Role taken from a client-supplied value (body, client-settable JWT claim, header)
- **Mass assignment**: `User.update(req.body)` allowing `role`, `is_admin`, `tenant_id`, `balance`
- Default-allow: a new route with no decorator is public
- No re-authorization on step-up actions (payment, role change, export)
- Privilege escalation via self-service roles or invitations
- Ownership checked on read but not write, or the reverse
- Authorization cached past a role change

## 11. Multi-Tenancy Isolation

- Tenant ID from the request, not the session
- Queries missing the tenant filter (one omission leaks the table)
- Shared cache keys with no tenant prefix
- Background jobs, exports, webhooks, search indexes unscoped
- File paths not tenant-isolated
- Database row-level security available but off
- Admin impersonation with no audit trail, consent, or time limit

## 12. Service & API Credentials

- API keys with no scope, expiry, or rotation
- Keys compared non-constant-time or logged on error
- Service calls trusting a spoofable header (`X-User-Id`) through the gateway
- Internal endpoints assumed unreachable instead of authenticated (see `microservices.md`)
- Webhook receivers not verifying HMAC, or comparing non-constant-time; no timestamp or nonce (replay)
- Static cloud credentials in CI where OIDC federation exists

## 13. Account Lifecycle

- Deactivated or deleted accounts keep valid sessions and tokens
- Offboarding leaves API keys, OAuth grants, SSH keys
- No audit log for privilege changes, impersonation, admin actions
- Soft-delete only where erasure was promised (see `compliance/privacy-audit.md`)

---

## Reviewing Auth Well

1. **Enumerate every route mechanically from the router, then ask what protects each.** Don't trust code that looks protected.
2. **Find the default.** Is an unannotated route public or private? Default-allow is one systemic finding, not per-route.
3. **Walk each flow end to end** (signup, login, refresh, reset, email change, role change, delete). Bugs hide in the seams.
4. **Everything the client sends is attacker-controlled**, including gateway-added headers if the gateway can be bypassed.
5. **Check both halves:** read authorized, write authorized, same object, same user.
