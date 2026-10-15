# Vulnerability Reference: Firebase & Backend-as-a-Service (BaaS)

_Load in Phase 1 when the project uses Firebase (Firestore, Realtime DB, Auth, Storage, App Check, Cloud Functions) or a comparable BaaS (Supabase, AppWrite) where **the client talks directly to the database** and security rules, not server middleware, are the main authorization boundary. Pairs with `auth-identity.md`, and `web-api.md` for Cloud Functions._

The browser is a first-class database client. Any control a server would enforce (rate limiting, field projection, input shape, business invariants) is absent unless a rule, App Check, or a server endpoint provides it. Assume the attacker speaks the raw SDK/REST protocol, not your UI.

---

## 1. Security-Rules Semantics

These are model properties that decide what a fix can look like. Get them wrong and you recommend an impossible fix.

- **Rules cannot project fields on read.** If `allow read` is `true`, the client gets the **whole document**. You cannot hide `userId` but show `userName` with a rule.
  - Secrets, PII, and authz-key fields in a readable doc are exposed to every reader (CWE-200). Common leaks: UID (often the authz key), email, `stripeCustomerId`, moderation flags, `costPrice`, `isBanned`.
  - Real fixes: (a) don't store the field in the readable doc, (b) move it to a sibling doc/collection that is not client-readable, or (c) set read to `false` and serve reads through a server endpoint that projects safe fields. A rule tweak cannot fix field exposure.
- **`create` is not `update` is not `write`.** `write` = create + update + delete. `create` fires only when the doc does not exist; `set()` on an existing doc is an update and is denied under create-only rules. A create-only public collection can be proliferated but not overwritten. Don't overstate it as "arbitrary write".
- **`request.resource.data` vs `resource.data`.** `request.resource` is the incoming, attacker-controlled write; `resource` is the existing doc. Checking `request.resource.data.ownerId == request.auth.uid` is a classic hole: the attacker sets `ownerId` in the same write. Check the **existing** `resource.data`, or make the field immutable (`request.resource.data.ownerId == resource.data.ownerId`).
- **Validation covers only the keys you name.** A rule that types four fields but ends in `keys().size() <= N` still lets the attacker add other unlisted keys with any type and size. Enumerate every field the client writes (read the SDK calls) and confirm each is validated or provably unused.
- **`read` = `get` + `list`.** Read can allow enumeration of a whole collection. Split `get` from `list`; sensitive collections often want `get` only.
- **Timestamps.** `request.time` is trustworthy; a client `createdAt` is not unless pinned (`request.resource.data.createdAt == request.time`). `serverTimestamp()` in the SDK does not stop REST calls with any value.
- **Default-deny is necessary, not sufficient.** `match /{document=**} { allow read, write: if false; }` is good hygiene, but every explicit `match` below it widens it. Audit each widening.

---

## 2. Authentication & Authorization

- **Email is not an identity key.** Email/password sign-ups are not verified by default and released emails can be re-registered. Auth on `token.email`/`email_verified` is spoofable. Key on the immutable **UID**. Check that `isAdmin()` in rules and server middleware both use UID and that the lists match.
- **Custom claims vs UID allowlists.** A UID list duplicated in `firestore.rules` and server code will drift; flag it. Custom claims (`request.auth.token.admin == true`) centralize this but must be set only by a trusted server.
- **Backend token verification.** Functions and servers must call `verifyIdToken()` (signature, expiry, revocation). Never trust a decoded-but-unverified JWT or a `uid` in the request body.
- **`request.auth != null`** means any signed-in user, including a fresh attacker account, not "the owner". Confirm it also constrains to the owner (`request.auth.uid == userId`).

---

## 3. Abuse, Cost & Integrity (client-direct writes)

- **No rate limit exists on direct SDK/REST writes.** Your Express/Function limiter is bypassed. An unauthenticated writable collection (analytics, contact form, waitlist) is a cost-amplification and data-pollution vector, since each write bills and aggregates feed dashboards the operator trusts. Mitigate with **App Check** enforcement, tighter rules (auth, field bounds), or a rate-limited server endpoint. Rules cannot rate-limit.
- **App Check works only when enforced.** Client SDK wiring does nothing until enforcement is on for Firestore/Storage/Functions. Verify enforcement, and that debug tokens don't ship to production.
- **Unbounded aggregated fields.** If a dashboard sums or renders an attacker-writable field (`duration_seconds`, `product_name`), the attacker corrupts metrics or injects oversized strings. Bound it: `is number && >= 0 && <= MAX`, or `is string && size() <= N`, using `!('f' in request.resource.data) || (<constraint>)` so events omitting the field still pass.
- **Public counters** (likes, views, referral clicks) can be inflated. Use server-mediated increments or dedup on an authenticated identity.

---

## 4. Storage

- Storage rules are separate from Firestore rules and frequently opened to `if true`. Check content-type and size limits (`request.resource.size`, `request.resource.contentType`), UID path scoping, and that uploads can't be served as active content (HTML/SVG/JS) from a same-origin path (stored XSS).
- Signed URLs and download tokens in client-readable docs are public credentials. Treat as a secret in a readable doc (section 1).

---

## 5. Client Config & Secrets

- The web config (`apiKey`, `projectId`, `appId`) is **public by design**. It is an identifier, not a secret; do not report it. The real boundary is rules plus App Check.
- **Do** report: a service-account JSON (private key) committed or shipped to the client, Admin SDK credentials in client-reachable code, `FIREBASE_SERVICE_ACCOUNT_*` or `.env` values bundled by the front-end build. Confirm the service account is gitignored, absent from git history, and absent from the hosting `public` output. (Vite/CRA expose only `VITE_`/`REACT_APP_` vars; check no secret carries such a prefix.)
- Confirm the deployed directory (e.g. `dist`) has no service account, `.env`, or `.firebaserc` secrets, and that the hosting `ignore` globs exclude them.

---

## 6. Cloud Functions / custom backend

Audit under `web-api.md`, plus:
- The Admin SDK **bypasses all rules**: every Function is root on the database. Enforce authorization in the Function code.
- Callable functions verify the Auth context automatically; raw HTTP functions must verify the ID token and set CORS themselves.
- Webhooks (Stripe, etc.) must verify signatures on the **raw** body before parsing.

---

## Triage priorities

1. **Field exposure in client-readable docs** (section 1): compare each readable collection's full document shape to what the UI needs; the delta is the leak.
2. **Ownership checks on `request.resource` instead of `resource`** (section 1): privilege escalation / IDOR.
3. **`request.auth != null` where owner-only was intended** (section 2).
4. **Unauthenticated or unbounded writable collections** (section 3): cost and integrity, gated only by App Check enforcement you must verify.
5. **Service-account or Admin credentials reachable by clients** (section 5): full compromise.
