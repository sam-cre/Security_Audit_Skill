# Vulnerability Reference: Web & API Applications

_Load this during Phase 1 when auditing Web Applications, REST/GraphQL APIs, microservices, or SSR frameworks. Aligned with **OWASP Top 10:2025**._

---

## A01:2025 - Broken Access Control

_If `auth-identity.md` is also loaded, record access-control findings there and keep this section for the SSRF and mass-assignment patterns below. Do not file the same issue twice._

### Object-Level Authorization (BOLA / IDOR)
- Unprotected object keys (`/api/users/:id`) exposed without checking ownership or session identity
- Sequential/predictable IDs enabling enumeration (`/api/orders/1001`, `/api/orders/1002`)
- GraphQL queries returning objects without authorization middleware

### Function-Level Authorization (BFLA)
- Admin/privileged API endpoints accessible by low-privilege roles without middleware checks
- Missing role verification on state-changing operations (DELETE, PUT, PATCH)
- Horizontal privilege escalation via shared resource endpoints

### Mass Assignment / Object Property Overwrite
- Binding user JSON directly to database models (`User.create(req.body)`, `Model.objects.create(**request.data)`)
- Allowing property overrides (e.g., `is_admin: true`, `role: "admin"`, `balance: 999999`)

### SSRF (Server-Side Request Forgery)
- Server making HTTP requests to user-supplied URLs without validation
- Missing local IP blocking (`127.0.0.1`, `169.254.169.254`, `10.x.x.x`, `fd00::`)
- Missing scheme restriction (allowing `file://`, `gopher://`, `dict://`)
- Cloud metadata endpoint access (`http://169.254.169.254/latest/meta-data/`)

---

## A02:2025 - Security Misconfiguration

### Server & Framework Misconfig
- Debug mode enabled in production (`DEBUG=True`, `NODE_ENV=development`)
- Default credentials on admin panels, databases, or middleware
- Verbose error pages leaking stack traces, file paths, or database schema
- Directory listing enabled on web servers
- Unnecessary HTTP methods enabled (TRACE, OPTIONS returning sensitive info)

### CORS Misconfiguration
- `Access-Control-Allow-Origin: *` with credentials
- Dynamic origin reflection without whitelist validation
- Missing origin checks on WebSocket upgrade requests

### Security Headers Missing
- No `Content-Security-Policy` header
- No `X-Frame-Options` or `frame-ancestors` in CSP
- No `Strict-Transport-Security` (HSTS)
- No `X-Content-Type-Options: nosniff`

---

## A03:2025 - Software Supply Chain Failures

### Dependency Vulnerabilities
- Known CVEs in direct or transitive dependencies
- Unpinned dependency versions allowing silent upgrades to compromised packages
- Missing lockfile integrity verification (`package-lock.json`, `yarn.lock`, `poetry.lock`)

### Supply Chain Attack Vectors
- Typosquatting risk on package names (check for common misspellings)
- Post-install scripts in npm/pip packages that execute arbitrary code
- Dependency confusion (internal package name collision with public registry)
- Compromised maintainer accounts on critical dependencies

### Build Pipeline Integrity
- Unsigned build artifacts
- CI/CD pipelines with overly permissive permissions
- Missing SBOM (Software Bill of Materials) generation

---

## A04:2025 - Cryptographic Failures

### Weak Hashing
- MD5/SHA1 for password hashing (use bcrypt, scrypt, argon2id)
- Missing salt or shared/static salt across users
- Insufficient work factor / iteration count

### Encryption Weaknesses
- ECB mode for block ciphers (use GCM or CBC with HMAC)
- Static/hardcoded initialization vectors (IVs)
- Insecure random number generators (`Math.random()`, `random.random()`) for security purposes (use CSPRNG)
- Weak key sizes (RSA < 2048, AES < 128)

### TLS & Certificate Issues
- TLS verification disabled (`verify=False`, `rejectUnauthorized: false`)
- Hardcoded certificates or certificate pinning bypass

---

## A05:2025 - Injection

### SQL Injection
- String concatenation or format strings in query execution (`f"SELECT * FROM users WHERE id = {user_input}"`)
- ORM raw query methods with unsanitized input
- Verify parameterized queries (`?`, `$1`, `:param`)

### Command Injection
- `os.system()`, `subprocess.Popen(..., shell=True)`, `exec.Command("sh", "-c", ...)`, `child_process.exec()` with user input
- Missing input validation before shell execution

### Template Injection (SSTI)
- Unescaped user input in Jinja2, EJS, Handlebars, Twig, ERB (`{{ user_input }}`, `Markup()`, `|safe`)

### Header / CRLF Injection
- User input injected into HTTP response headers → response splitting, session fixation

### NoSQL Injection
- MongoDB query operator injection (`{"$gt": ""}`, `{"$ne": null}`) via unvalidated JSON input

---

## A06:2025 - Insecure Design

### Business Logic Flaws
- Missing rate limiting on expensive operations (login, search, export)
- No validation of business rules (negative prices, skipping checkout steps)
- Replay attacks on non-idempotent operations (double payment, double vote)
- Missing anti-automation controls (CAPTCHA, proof-of-work)

---

## A07:2025 - Authentication Failures

**Covered in depth by `references/domains/auth-identity.md`.** Load it whenever the project has login, sessions, tokens, SSO, roles, or multi-tenancy - which is nearly every web app. It covers password storage, login flow, sessions, JWT, OAuth/OIDC, SAML, MFA, password reset, and the authorization model.

Do not duplicate those findings here. If the project genuinely has no authentication, record that as an architectural observation and move on.

---

## A08:2025 - Software & Data Integrity Failures

### Deserialization
- Unsafe deserialization of untrusted data (`pickle.loads()`, `yaml.load()`, `JSON.parse()` + `eval()`)
- Missing integrity checks on serialized data

### Code Integrity
- Auto-update mechanisms without signature verification
- CDN-loaded scripts without Subresource Integrity (SRI) hashes

---

## A09:2025 - Security Logging & Alerting Failures

- Sensitive data logged (passwords, tokens, PII, credit cards)
- Authentication failures not logged
- Missing audit trail for admin actions
- No alerting on suspicious patterns (brute force, mass data access)

---

## A10:2025 - Mishandling of Exceptional Conditions

- Unhandled exceptions exposing internal state (stack traces, DB errors, file paths)
- Fail-open behavior on error (auth succeeds if auth service is down)
- Resource exhaustion via malformed input (ReDoS, billion laughs XML, zip bombs)
- Missing timeout on external service calls → cascading failures
- Panic/crash on unexpected input types or null values

---

## Client-Side & Framework-Specific

### XSS (Cross-Site Scripting)
- Reflected, stored, or DOM XSS
- `innerHTML`, `document.write`, `dangerouslySetInnerHTML` with user input
- Template engines with escaping disabled (`|safe`, `{!! !!}`, `<%- %>`)

### Prototype Pollution (JavaScript/TypeScript)
- Unsafe recursive object merge/extend without key sanitization
- `__proto__`, `constructor.prototype` injection via user-controlled JSON

### Next.js / React Server Components
- Server Action authorization bypasses
- Leaking server-only env vars to client bundles
- Missing authentication on API routes

### GraphQL-Specific
- Introspection enabled in production
- No query depth/complexity limiting → denial of service via nested queries
- Batching attacks (multiple mutations in single request bypassing rate limits)
- Field-level authorization missing (users can query fields they shouldn't see)

### WebSocket Security
- Missing origin validation on WebSocket upgrade
- No authentication on WebSocket connection
- No message rate limiting
- Injection via WebSocket messages
