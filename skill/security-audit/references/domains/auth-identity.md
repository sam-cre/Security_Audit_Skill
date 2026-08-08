# Domain: Authentication, Session & Authorization

_Load when the project has login, sessions, tokens, SSO, roles, or multi-tenancy. Pairs with `web-api.md` for most apps._

Auth bugs are the highest-severity findings in most applications and scanners are nearly blind to them, because the flaw is usually a **missing** check rather than a dangerous call. Read the code; don't grep for it.

---

## 1. Password Storage

- MD5, SHA-1, SHA-256, or any fast hash used for passwords - must be **argon2id**, **scrypt**, or **bcrypt**
- Missing per-user salt, or a shared/static salt
- Work factor too low (bcrypt cost < 12, argon2 memory < 19 MiB) or unchanged since 2015
- Hand-rolled key derivation instead of a vetted library
- Password compared with `==` instead of a constant-time comparison
- bcrypt's 72-byte truncation not handled - long passwords silently equivalent
- No rehash-on-login when the work factor is raised
- Password or hash written to logs, error messages, or analytics

## 2. Login Flow

- No rate limiting, or rate limiting keyed only on IP (trivially bypassed with a proxy pool)
- **User enumeration:** different message, status code, or *response time* for unknown user versus wrong password
- No account lockout or progressive delay after repeated failures
- No credential-stuffing defense - no breached-password check, no anomaly detection
- Login over plaintext HTTP anywhere in the flow
- Credentials passed in a URL query string (they land in logs, history, and `Referer`)
- "Remember me" implemented as a long-lived token with no rotation or revocation
- Timing side channel: user-existence check short-circuits before the hash comparison

## 3. Session Management

- Session ID not regenerated on login → **session fixation**
- Session not invalidated on logout, password change, email change, or MFA enrollment
- Cookies missing `HttpOnly`, `Secure`, or `SameSite`
- `SameSite=None` without a justified cross-site need
- Overly broad cookie `Domain` sharing sessions across untrusted subdomains
- Session IDs from a non-CSPRNG, or with insufficient entropy (< 128 bits)
- No absolute session lifetime - only idle timeout, or no timeout at all
- Sessions stored client-side without integrity protection
- No way for a user to view or revoke active sessions
- Concurrent-session limits absent where the threat model requires them

## 4. JWT

- `alg: none` accepted
- **Algorithm confusion** - an RS256 verifier that accepts HS256, letting the public key be used as an HMAC secret
- Weak, guessable, or default HMAC secret; secret shared across environments
- Signature not verified at all (`decode` used where `verify` was meant)
- `exp` missing or not checked; expiry measured in months
- `aud` and `iss` not validated → token from another service or tenant accepted
- No revocation path - a stolen token stays valid until expiry, with no denylist or short-lived-token-plus-refresh design
- Sensitive data in the payload (it is base64, not encryption)
- JWT in `localStorage` where any XSS reads it - prefer `HttpOnly` cookies
- `kid` header used to select a key without validating the value → path traversal or SQL injection into key lookup
- JWKS fetched over HTTP, or without pinning/caching, allowing key substitution

## 5. OAuth 2.0 / OIDC

- Missing or unvalidated `state` → CSRF on the callback
- Missing PKCE on public clients (mobile, SPA); `plain` challenge method accepted
- `redirect_uri` matched by prefix or substring instead of exact match → **open redirect → token theft**
- Implicit flow still in use (deprecated; use authorization code + PKCE)
- Authorization code not bound to the client, or accepted more than once
- `nonce` not validated in OIDC → ID token replay
- ID token used as an access token, or accepted without signature verification
- Overly broad scopes requested or granted; no per-scope enforcement server-side
- Client secret embedded in a mobile app or SPA bundle
- Refresh tokens never rotated, or rotation without reuse detection
- Account linking by unverified email → **pre-account-takeover** (attacker registers with the victim's email before they sign up via SSO)

## 6. SAML

- Signature not verified, or only the assertion verified while the response is not
- **XML Signature Wrapping** - attacker adds an unsigned assertion alongside the signed one
- XXE in the SAML parser (external entities enabled)
- `NotBefore` / `NotOnOrAfter` / `Recipient` / `Audience` not validated
- Assertion replay - no `InResponseTo` check, no one-time-use tracking
- IdP certificate not pinned, or rotation unhandled

## 7. Multi-Factor Authentication

- MFA enforced in the UI but not on the API
- Verification step skippable by calling the post-MFA endpoint directly
- OTP not invalidated after use; no attempt limit → 6-digit brute force
- TOTP window too wide; no replay tracking of used codes
- Backup codes: too few, not single-use, stored unhashed
- SMS as the only factor, with no SIM-swap consideration for high-value accounts
- MFA not required to disable MFA, or to change the recovery email
- "Trust this device" tokens that never expire or are not device-bound
- WebAuthn: origin, RP ID, challenge, or user-verification flag not validated; sign counter ignored

## 8. Password Reset & Account Recovery

The most commonly broken flow in any application. Walk it end to end.

- Reset token predictable, sequential, or non-CSPRNG
- Token does not expire, or expires far too late (hours to days is too long - 15–60 min)
- Token reusable, or not invalidated after a successful reset
- Token not bound to the requesting user → use one account's token on another
- **Host header injection** - reset link built from the `Host` header, letting an attacker point it at their own domain
- Reset link leaked via `Referer` to third-party scripts on the landing page
- Old password not required for an in-session password change
- Sessions not invalidated after a reset - attacker keeps their session
- Reset endpoint reveals whether an account exists
- Email change: no confirmation sent to the **old** address, so a takeover is silent
- Security questions used as a sole factor (answers are usually public)
- No rate limiting on reset requests → mailbox flooding, token grinding

## 9. Registration & Verification

- Email verification not enforced before privileged actions
- Verification token sharing the weaknesses listed in section 8
- Case, unicode, or `+`-alias normalization inconsistent between registration and login → duplicate or hijackable accounts
- Homograph or confusable usernames permitted
- No defense against automated mass registration where that matters

## 10. Authorization

- **IDOR / BOLA** - object fetched by user-supplied ID without an ownership check. Test every `:id` route.
- **BFLA** - admin function reachable by a low-privilege role because the check lives only in the UI
- Authorization checked at the controller but bypassable via a second route, GraphQL resolver, batch endpoint, or internal API
- Role read from a client-supplied value (request body, JWT claim the client can set, header)
- **Mass assignment** - `User.update(req.body)` allowing `role`, `is_admin`, `tenant_id`, `balance`
- Default-allow authorization: a new route with no decorator is public
- Missing re-authorization on step-up actions (payment, role change, data export)
- Privilege escalation via self-service role assignment or invitation flows
- Ownership checked on read but not on write, or vice versa
- Authorization decision cached and not invalidated on role change

## 11. Multi-Tenancy Isolation

- Tenant ID taken from the request instead of derived from the session
- Queries missing a tenant filter - one omission leaks the whole table
- Shared cache keys without a tenant prefix → cross-tenant cache poisoning
- Background jobs, exports, webhooks, and search indexes running without tenant scoping
- File storage paths not tenant-isolated
- Row-level security available in the database but not enabled
- Admin/support impersonation with no audit trail, no consent, and no time limit

## 12. Service & API Credentials

- API keys with no scope, no expiry, and no rotation path
- Keys compared non-constant-time, or logged on error
- Service-to-service calls trusting a header (`X-User-Id`) that a client can spoof through the gateway
- Internal endpoints assumed unreachable rather than authenticated (see `microservices.md`)
- Webhook receivers not verifying HMAC signatures, or verifying non-constant-time
- Webhook replay possible - no timestamp check, no nonce
- Long-lived static cloud credentials in CI where OIDC federation is available

## 13. Account Lifecycle

- Deactivated or deleted accounts retain valid sessions and tokens
- Offboarding does not revoke API keys, OAuth grants, or SSH keys
- No audit log for privilege changes, impersonation, or admin actions
- Deletion is soft-only where the user was promised erasure (see `compliance/privacy-audit.md`)

---

## Reviewing Auth Well

1. **Enumerate every route, then ask what protects it.** Build the list mechanically from the router; do not rely on the code looking protected.
2. **Find the default.** Is an unannotated route public or private? Default-allow is a systemic finding, not a per-route one.
3. **Walk each flow end to end** - signup, login, refresh, reset, email change, role change, delete. Bugs hide in the seams between steps.
4. **Ask what the client controls.** Anything the client sends is attacker-controlled, including headers your gateway adds if the gateway can be bypassed.
5. **Check both halves of every check.** Read authorized. Write authorized. Same object. Same user.
