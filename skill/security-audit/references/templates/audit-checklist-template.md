# Audit Checklist

_Tailored to this project from threat-model.md and references/rules.md. Only include vulnerability classes that are actually plausible given the attack surface — mark others explicitly N/A with a one-line reason rather than omitting them silently._

## Checklist

### Core Web & System Vulnerabilities
- [ ] **Injection** (SQL / Command / LDAP / XML-XPath / Template / Header)
- [ ] **Broken Authentication & Session Flaws** (JWT confusion, session fixation, weak hashing)
- [ ] **Insecure Deserialization** (Unsafe pickle, PyYAML load, Java gadget chains)
- [ ] **Sensitive Data Exposure & Secret Leaks** (Hardcoded keys, committed secrets in git log)
- [ ] **Cryptographic Failures** (MD5/SHA1 usage, ECB mode, static IV, predictable RNG)
- [ ] **Path Traversal / Unvalidated File Inclusion** (`../` sequences, symlink bypass)
- [ ] **Cross-Site Scripting (XSS)** (Reflected / Stored / DOM-based)
- [ ] **Cross-Site Request Forgery (CSRF)**
- [ ] **Security Misconfiguration** (Debug endpoints, CORS, missing security headers)
- [ ] **Race Conditions & TOCTOU** (Non-atomic database/file operations)
- [ ] **Memory Safety & Integer Flaws** (Buffer overflows, uninitialized memory, Rust `unsafe`)
- [ ] **Supply Chain & Dependency Risks** (Malicious packages, typosquatting, unpinned versions)

### Modern & Emerging Surfaces
- [ ] **API Security Flaws** (BOLA / IDOR, BFLA, Mass Assignment, Rate Limit bypass)
- [ ] **LLM & AI Application Flaws** (Prompt injection, unsafe tool execution, vector DB access leak)
- [ ] **Infrastructure as Code (IaC) & Container Risks** (Dockerfile root user, open S3, weak IAM/RBAC)
- [ ] **Modern Web & SSR Flaws** (Next.js Server Actions bypass, RSC leaks, Prototype Pollution)
- [ ] **Logging & Monitoring Gaps** (Missing audit trails, sensitive data over-logging)
- [ ] **Git History Secret Scan** (`gitleaks` or manual commit log scan)

---

## Findings Summary Table

| ID | Title | File & Line Range | CVSS v4.0 Vector | Severity | CWE | Status |
|---|---|---|---|---|---|---|
| SEC-001 | Example Finding | `src/auth.js:45-50` | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H` | Critical | CWE-89 | Unconfirmed |

---

## Detailed Findings

<!-- Phase 1 appends detailed findings here as they're discovered using the schema in references/rules.md.
     Append-only during Phase 1; statuses, CVSS metrics, and PoCs are updated during Phase 2 and Phase 4. -->
