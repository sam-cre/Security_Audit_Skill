# Phase 2 - Adversarial Self-Review

_Load this after Phase 1 is complete. Also load `.security-audit/threat-model.md` and `.security-audit/audit-checklist.md`._

---

## Objective

Systematically hunt for **false negatives** - vulnerabilities that Phase 1 missed. Phase 1 finds what it's looking for; Phase 2 finds what nobody was looking for.

---

## Lens 1: Trust Boundary Coverage Audit

For every trust boundary identified in `.security-audit/threat-model.md`:

1. Check whether at least one finding targets it OR an explicit "reviewed, secure" annotation exists
2. If a trust boundary has zero coverage, it indicates a gap - investigate that boundary specifically
3. Pay special attention to:
   - Boundaries between different privilege levels (user → admin, service → database)
   - Boundaries between different environments (client → server, internal → external)
   - Boundaries between different teams/codebases (microservice A → microservice B)

Document coverage status for each boundary:
```markdown
| Trust Boundary | Finding(s) | Coverage Status |
|---|---|---|
| Client → API Gateway | SEC-001, SEC-003 | Covered |
| API → Database | (none) | ⚠️ GAP - Investigating |
| API → External Service | SEC-007 | Covered |
```

---

## Lens 2: Human Pentester Simulation

Walk through the application as an attacker would. This is not a code review - this is a **behavioral** review.

### Authentication Flow Walk-through
- [ ] Register a new account - what validation exists? Can you register with `admin@company.com`?
- [ ] Login flow - is brute-force protected? Account lockout? Rate limiting?
- [ ] Password reset - is the token predictable? Does it expire? Can it be reused?
- [ ] Session management - are sessions invalidated on password change? On logout?
- [ ] Token handling - are JWTs validated properly (algorithm, expiry, signature)?

### Authorization Flow Walk-through
- [ ] Access another user's data by modifying IDs in URLs/API requests (IDOR/BOLA)
- [ ] Access admin endpoints with a regular user token (BFLA)
- [ ] Privilege escalation via parameter manipulation (mass assignment, role parameter)
- [ ] Horizontal escalation (user A accessing user B's resources)
- [ ] Vertical escalation (regular user → admin capabilities)

### Hidden Surface Discovery
- [ ] Are there routes/endpoints not linked from any UI? (admin panels, debug endpoints, health checks with sensitive data)
- [ ] Are there API endpoints that accept methods (PUT, DELETE, PATCH) not documented?
- [ ] Are there GraphQL introspection queries enabled in production?
- [ ] Are there WebSocket endpoints without authentication?
- [ ] Are there file upload endpoints without type/size validation?

### Business Logic Abuse
- [ ] Can negative values be submitted where positive is expected? (prices, quantities, transfers)
- [ ] Can steps in a multi-step process be skipped? (checkout, verification, approval)
- [ ] Can requests be replayed for duplicate effect? (payments, votes, claims)
- [ ] Are there time-based operations vulnerable to race conditions?
- [ ] Can coupon codes, referral codes, or reward systems be abused?

---

## Lens 3: Implicit Security Assumptions

Find places where security depends on conditions that aren't explicitly enforced:

### Environment Variable Dependencies
- Security-critical env vars with no fallback - what happens if `JWT_SECRET` is empty?
- Env vars that change behavior between dev/prod - is `DEBUG=true` possible in production?
- Env vars that hold secrets but are logged or exposed in error messages

### Middleware & Configuration Order
- Is authentication middleware registered before route handlers? Could registration order change?
- Are CORS headers set before or after authentication checks?
- Is rate limiting applied before or after expensive operations?

### Insecure Defaults
- Are security features opt-in rather than opt-out?
- Do configuration templates ship with permissive defaults? (`CORS: *`, `DEBUG: true`, `ALLOW_ALL: true`)
- Are example/demo configurations used in production?

### Fail-Open vs Fail-Closed
- What happens when an external auth service is unreachable? (Does the app let everyone in or lock everyone out?)
- What happens when the database connection fails? (Are cached credentials used? Are they stale?)
- What happens when rate limiting storage (Redis) is down? (Are requests unlimited?)

---

## Recording Results

Document the adversarial review in `.security-audit/pentest-methodology.md` using template `references/templates/pentest-methodology-template.md`.

Any new findings discovered go into `.security-audit/audit-checklist.md` and `.security-audit/security-findings.json` with the same schema as Phase 1 findings, noting `"Detected By": "Adversarial Self-Review"`.

---

## Gate to Proceed

Do not advance to Phase 3 until:
- [ ] Every trust boundary has either a finding or an explicit "reviewed, secure" annotation
- [ ] All three adversarial lenses have been documented
- [ ] `.security-audit/pentest-methodology.md` is complete
- [ ] Any new findings are recorded in `audit-checklist.md` and `security-findings.json`
