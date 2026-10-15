# Phase 2 - Adversarial Self-Review

_Load after Phase 1, plus `.security-audit/threat-model.md` and `.security-audit/audit-checklist.md`._

Hunt **false negatives**. Phase 1 finds what it looked for; Phase 2 finds what nobody looked for.

---

## Lens 1: Trust Boundary Coverage

For every boundary in `threat-model.md`, require at least one finding or an explicit "reviewed, secure" note. Zero coverage is a gap: investigate it. Watch boundaries between privilege levels (user to admin, service to database), environments (client to server, internal to external), and teams or codebases (service A to service B).

```markdown
| Trust Boundary | Finding(s) | Coverage |
|---|---|---|
| Client -> API Gateway | SEC-001, SEC-003 | Covered |
| API -> Database | (none) | GAP - investigating |
```

---

## Lens 2: Human Pentester Simulation

Behavioral review: walk the app as an attacker.

**Authentication**
- [ ] Register: what validation exists? Can you register `admin@company.com`?
- [ ] Login: brute-force protection, lockout, rate limits?
- [ ] Reset: predictable, expiring, reusable token?
- [ ] Sessions invalidated on password change and logout?
- [ ] JWTs validated for algorithm, expiry, signature?

**Authorization**
- [ ] Change IDs in URLs/requests to reach another user's data (IDOR/BOLA)
- [ ] Call admin endpoints with a regular token (BFLA)
- [ ] Escalate via parameters (mass assignment, role field)
- [ ] Horizontal (user A to user B) and vertical (user to admin)

**Hidden surface**
- [ ] Unlinked routes: admin panels, debug endpoints, health checks with sensitive data
- [ ] Undocumented methods (PUT, DELETE, PATCH)
- [ ] GraphQL introspection on in production
- [ ] WebSocket endpoints without auth
- [ ] Upload endpoints without type/size validation

**Business logic**
- [ ] Negative values where positive expected (prices, quantities, transfers)
- [ ] Skippable steps (checkout, verification, approval)
- [ ] Replayable requests (payments, votes, claims)
- [ ] Race conditions in time-based operations
- [ ] Coupon, referral, and reward abuse

---

## Lens 3: Implicit Security Assumptions

**Environment variables:** security-critical vars with no fallback (empty `JWT_SECRET`?); vars that change dev/prod behavior (`DEBUG=true` in production?); secrets logged or shown in errors.

**Middleware order:** is auth registered before route handlers, and could order change? CORS before or after auth? Rate limiting before or after expensive work?

**Insecure defaults:** security opt-in rather than opt-out; config templates with permissive defaults (`CORS: *`, `DEBUG: true`, `ALLOW_ALL: true`); demo configs used in production.

**Fail-open vs fail-closed:** auth service unreachable (everyone in or everyone out)? Database down (stale cached credentials)? Rate-limit store (Redis) down (unlimited requests)?

---

## Recording

Document in `.security-audit/pentest-methodology.md` from `references/templates/pentest-methodology-template.md`. New findings go to `audit-checklist.md` and `security-findings.json` in the Phase 1 schema with `"Detected By": "Adversarial Review"`.

---

## Gate to Proceed

- [ ] Every trust boundary has a finding or a "reviewed, secure" note
- [ ] All three lenses documented
- [ ] `pentest-methodology.md` complete
- [ ] New findings recorded in both findings files
