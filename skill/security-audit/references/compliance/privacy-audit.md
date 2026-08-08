# Privacy & Data Protection Audit Guide

_Load this when privacy audit or GDPR/HIPAA data protection review is requested during Phase 0._

---

## PII / PHI Data Classification

During Phase 0 data flow mapping, classify all data elements by sensitivity:

### Classification Levels

| Level | Examples | Handling Requirements |
|---|---|---|
| **Restricted** | Passwords, private keys, payment card numbers (PAN), SSN, health records (PHI) | Encrypted at rest + in transit, access logging, minimal retention |
| **Confidential** | Email addresses, phone numbers, physical addresses, date of birth, government IDs | Encrypted in transit, access-controlled, purpose-limited |
| **Internal** | User IDs, usernames, internal URLs, session tokens | Access-controlled, not publicly exposed |
| **Public** | Published content, public profiles, open-source code | No special handling required |

### Data Element Inventory

For each data element in the application:
```markdown
| Data Element | Classification | Storage Location | Encrypted at Rest? | Encrypted in Transit? | Retention Period | Access Controls |
|---|---|---|---|---|---|---|
| user.email | Confidential | PostgreSQL users table | Yes (column-level) | Yes (TLS) | Account lifetime + 30d | Role-based |
| user.password | Restricted | PostgreSQL users table | Yes (bcrypt hash) | Yes (TLS) | Account lifetime | No direct access |
```

---

## GDPR Article 35 - Data Protection Impact Assessment (DPIA)

If the project processes EU personal data, conduct a DPIA:

### Step 1: Processing Activity Description
- What personal data is collected?
- What is the legal basis for processing? (consent, contract, legitimate interest)
- Who are the data subjects? (customers, employees, public)
- How long is data retained?
- Who has access to the data?

### Step 2: Necessity & Proportionality
- Is the data collection necessary for the stated purpose? (data minimization)
- Could the same purpose be achieved with less data?
- Is there a less privacy-invasive alternative?

### Step 3: Risk Assessment

| Risk Category | Risk Description | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| Unauthorized access | Data breach exposing PII | | | |
| Excessive collection | Collecting more data than needed | | | |
| Lack of transparency | Users not informed of data processing | | | |
| Cross-border transfer | Data sent outside EU without safeguards | | | |
| Third-party sharing | Data shared with processors without DPA | | | |

### Step 4: Technical Controls Audit
- [ ] **Encryption at rest:** All PII/PHI encrypted in database
- [ ] **Encryption in transit:** TLS 1.2+ for all data transmission
- [ ] **Access logging:** All access to PII/PHI is logged with timestamp and actor
- [ ] **Data minimization:** Only necessary data fields are collected
- [ ] **Purpose limitation:** Data used only for stated purposes
- [ ] **Right to erasure:** Mechanism exists to delete all user data on request
- [ ] **Right to portability:** Mechanism exists to export user data in machine-readable format
- [ ] **Consent management:** Consent recorded, revocable, and version-tracked
- [ ] **Data breach notification:** Process exists to notify authorities within 72 hours
- [ ] **Privacy by design:** Security controls built into the architecture, not bolted on

---

## Data Retention Policy Audit

Check for:

### Retention Issues
- [ ] Is there a defined retention period for each data category?
- [ ] Are expired records automatically purged? (or is data kept indefinitely?)
- [ ] Are backups included in the retention policy? (backup data often outlives primary data)
- [ ] Are audit logs retained appropriately (long enough for investigations, not indefinitely)?
- [ ] Are soft-deleted records truly purged after the grace period?

### Deletion Verification
- [ ] When a user requests deletion, is ALL their data removed? (not just the primary record)
- [ ] Are references in logs, analytics, caches, and search indices also cleaned?
- [ ] Is deletion from backups addressed? (note: backup deletion is often deferred - document the policy)
- [ ] Are third-party data processors notified of deletion requests?

---

## Privacy-Specific Vulnerability Patterns

### Data Exposure
- PII in URL parameters (logged by web servers, proxies, browser history)
- PII in error messages or stack traces
- PII in client-side JavaScript bundles or API responses
- Analytics/tracking pixels transmitting PII to third parties
- Email addresses or usernames exposed in password reset flows

### Tracking & Consent
- Third-party cookies set without consent
- Fingerprinting techniques used without disclosure
- Analytics SDKs transmitting data before consent is granted
- Dark patterns in consent UI (pre-checked boxes, confusing language)

### Cross-Border Data Flows
- Data stored in regions outside the user's jurisdiction
- Third-party services (CDN, analytics, payment) processing data in non-adequate countries
- Missing Standard Contractual Clauses (SCCs) or Data Processing Agreements (DPAs)

---

## HIPAA-Specific Checks (Healthcare)

If the project handles Protected Health Information (PHI):

- [ ] **Access controls:** Role-based, unique user IDs, automatic logoff
- [ ] **Audit trail:** All PHI access logged with who, what, when, where
- [ ] **Transmission security:** PHI encrypted in transit
- [ ] **Integrity controls:** Mechanisms to detect unauthorized PHI modification
- [ ] **Emergency access:** Procedure for emergency PHI access documented
- [ ] **Business Associate Agreements (BAAs):** In place for all third parties handling PHI
- [ ] **Minimum necessary:** Access limited to the minimum PHI needed for each role
