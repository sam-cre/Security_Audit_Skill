# Vulnerability Reference: Firebase & Backend-as-a-Service (BaaS)

_Load this during Phase 1 when the project uses Firebase (Firestore, Realtime Database, Firebase Auth, Storage, App Check, Cloud Functions) or a comparable BaaS (Supabase, AppWrite) where a **client talks directly to the database** and security rules - not server middleware - are the primary authorization boundary. Pairs with `auth-identity.md` and, for Cloud Functions, `web-api.md`._

The defining property of BaaS: **the browser is a first-class database client.** Any control you expect a server to enforce (rate limiting, field projection, input shape, business invariants) is absent unless a security rule, an App Check gate, or a server endpoint provides it. Audit from the assumption that an attacker speaks the raw SDK/REST protocol, not your UI.

---

## 1. Security-Rules Semantics - the gotchas that change remediation

These are not "misconfigurations" - they are model properties that dictate what a fix can even look like. Get them wrong and you will recommend an impossible fix.

- **Rules cannot project fields on read.** If `allow read` is `true`, the client receives the **entire document**, every field. You cannot "hide `userId` but show `userName`" with a rule. Consequences:
  - Any secret/PII/authz-key field stored in a client-readable doc is **exposed to every reader** (CWE-200). Common leaks: internal `userId`/UID (often also the authz key), email, `stripeCustomerId`, moderation flags, `costPrice`/margin fields, soft-delete `isBanned` state.
  - The only real fixes are: (a) don't store the sensitive field in the readable doc, (b) split sensitive fields into a sibling doc/collection that is *not* client-readable, or (c) set the collection read to `false` and mediate reads through a server endpoint (Cloud Function / your own API) that projects safe fields. A rule tweak alone cannot fix a field-exposure finding.
- **`create` ≠ `update` ≠ `write`.** `allow write` grants create + update + delete. `allow create` fires only when the doc does **not** exist; `set()` on an existing doc is an update and is denied under create-only rules. Use this when judging severity: a create-only public collection can be *proliferated* (new docs) but existing docs cannot be *overwritten*. Don't overstate an "arbitrary write" finding that is actually create-only.
- **`request.resource.data` vs `resource.data`.** `request.resource` is the incoming write (attacker-controlled on writes); `resource` is the existing doc. Authorizing a write against `request.resource.data.ownerId == request.auth.uid` is a classic hole - the attacker sets `ownerId` in the same write. Ownership checks must read the **existing** `resource.data`, or the field must be immutable (`request.resource.data.ownerId == resource.data.ownerId`).
- **Validation only covers the keys you name.** A rule that checks four fields' types/sizes but ends with `keys().size() <= N` still lets the attacker add *other* unlisted keys (up to N) with arbitrary type and size. Any field the app later reads/aggregates/renders - but the rule doesn't bound - is attacker-controlled and unbounded. Enumerate every field the client actually writes (read the client SDK calls) and confirm each is either validated or provably unused.
- **`allow read` is `get` + `list`.** Granting read can enable **enumeration** of a whole collection, not just single-doc fetch, unless you split `allow get` from `allow list`. Sensitive collections often want `get` but not `list`.
- **Timestamps/authenticity.** `request.time` is trustworthy; a client-supplied `timestamp`/`createdAt` field is not, unless the rule pins it (`request.resource.data.createdAt == request.time`). Server-side `serverTimestamp()` in the SDK does not stop an attacker hitting the REST API with any value.
- **Default-deny is necessary but not sufficient.** `match /{document=**} { allow read, write: if false; }` is correct hygiene, but each explicit `match` below it *widens* it. Audit every widening, not the default.

---

## 2. Authentication & Authorization

- **Email is not an identity key.** Firebase email/password sign-ups are **not email-verified by default**, and a released email can be re-registered. Authorization keyed on `token.email` / `email_verified` is spoofable/takeover-prone. Authorization should key on the **UID** (immutable, never reused). Verify both the rules' `isAdmin()` and any server middleware use UID, and that the two lists match.
- **Custom claims vs. hardcoded UID allowlists.** Small admin sets are often a UID list duplicated in `firestore.rules` and server code - flag drift between the two copies as a real risk (one gets updated, the other doesn't). Custom claims (`request.auth.token.admin == true`) centralize this but require the claim to be set only by a trusted server.
- **ID token verification on the backend.** Cloud Functions / custom servers must call `verifyIdToken()` (which checks signature + expiry + revocation) - never trust a decoded-but-unverified JWT, and never trust a `uid` passed in the request body.
- **`allow read: if request.auth != null`** means *any signed-in user*, including a freshly self-registered attacker account - not "the owner." Confirm the rule also constrains to the owner (`request.auth.uid == userId`).

---

## 3. Abuse, Cost & Data Integrity (client-direct writes)

- **No rate limit exists on direct SDK/REST writes.** Your Express/Cloud-Function rate limiter is bypassed entirely when the client writes straight to Firestore. An unauthenticated writable collection (analytics/telemetry/"contact form"/"waitlist") is a **cost-amplification and data-pollution** vector: each write bills, and aggregated fields feed dashboards the operator trusts. Mitigations: **App Check** enforcement on the collection, tighter rules (auth required, field bounds), or routing the write through a rate-limited server endpoint. Firestore rules cannot rate-limit by themselves.
- **App Check is only real if enforced.** Wiring reCAPTCHA/App Check on the client does nothing until enforcement is enabled for the resource (Firestore/Storage/Functions). Confirm enforcement, not just SDK initialization. Debug tokens must not ship to production.
- **Aggregation of unbounded fields.** When an admin dashboard sums/renders a field an attacker can write (e.g. `duration_seconds`, `product_name`), an attacker corrupts metrics or injects oversized strings. Bound the field in the rule (`is number && >= 0 && <= MAX`, or `is string && size() <= N`) using the optional-field pattern `!('f' in request.resource.data) || (<constraint>)` so legitimate events that omit the field still pass.
- **`increment()` / counters.** Publicly writable counters (like/view/referral-click counts) can be inflated. Prefer server-mediated increments or dedup keyed on an authenticated identity.

---

## 4. Storage

- **Storage rules are separate from Firestore rules** and default to requiring auth - but are frequently opened to `if true` for "public" buckets. Check: content-type/size limits (`request.resource.size`, `request.resource.contentType`), path-scoping to the owner's UID, and that user-uploaded files can't be served as active content (HTML/SVG/JS) from a same-origin path (stored-XSS).
- **Signed URLs / download tokens** in client-readable docs are effectively public credentials - treat as secret-in-readable-doc (§1).

---

## 5. Client Config & Secrets

- **The Firebase web config (`apiKey`, `projectId`, `appId`) is public by design** - it is an identifier, not a secret. Do **not** report it as a leaked credential. The real boundary is rules + App Check.
- **Do** report: a **service-account JSON** (private key) committed or shipped to the client, Admin SDK credentials in client-reachable code, or `FIREBASE_SERVICE_ACCOUNT_*` / `.env` values bundled by the front-end build. Confirm the service account is gitignored **and** absent from git history and the hosting `public` output. (With Vite/CRA, only `VITE_`/`REACT_APP_`-prefixed vars are exposed - verify no secret carries such a prefix.)
- **Hosting `public` dir.** Confirm the deployed directory (e.g. `dist`) does not contain the service account, `.env`, or `.firebaserc` secrets, and that the `ignore` globs actually exclude them.

---

## 6. Cloud Functions / custom backend (if present)

Audit under `web-api.md`, plus BaaS-specific notes:
- The Admin SDK **bypasses all security rules** - every Function is implicitly "root" on the database. Authorization must be enforced *in the Function code*, not assumed from rules.
- Callable vs. HTTP functions: callable functions verify the Firebase Auth context automatically; raw HTTP functions do not - they must verify the ID token themselves and set CORS.
- Webhook endpoints (Stripe, etc.) must verify signatures on the **raw** body before any parsing.

---

## Triage priorities for this domain

1. **Field exposure in client-readable docs** (§1) - trace every readable collection's full document shape against what the UI needs; the delta is the leak.
2. **Ownership checks against `request.resource` instead of `resource`** (§1) - privilege escalation / IDOR.
3. **`request.auth != null` used where owner-only was intended** (§2).
4. **Unauthenticated/unbounded writable collections** (§3) - cost + integrity, gated only by App Check enforcement you must verify.
5. **Service-account / Admin credentials reachable by clients** (§5) - full compromise if present.
