# Compliance Framework Cross-Reference Matrix

_Load this during Phase 3 when compliance framework mapping is requested. Maps CWE categories to specific compliance controls._

---

## OWASP ASVS 5.0 Level Mapping

Use ASVS levels to determine the required depth of security verification:

| ASVS Level | Target Applications | Verification Depth |
|---|---|---|
| **Level 1 (Basic)** | Low-risk apps, marketing sites, internal tools | Automated scanning + basic code review |
| **Level 2 (Standard)** | Most business apps handling PII or sensitive data | Full code review + dynamic testing + threat model |
| **Level 3 (Advanced)** | Financial, healthcare, critical infrastructure, government | Formal threat model + full penetration test + formal verification |

### Key ASVS 5.0 Chapters

| Chapter | Topic | Relevant CWEs |
|---|---|---|
| V1 | Architecture, Design & Threat Modeling | CWE-1059, CWE-250 |
| V2 | Authentication | CWE-287, CWE-384, CWE-521, CWE-640 |
| V3 | Session Management | CWE-384, CWE-613, CWE-614 |
| V4 | Access Control | CWE-285, CWE-639, CWE-862, CWE-863 |
| V5 | Validation, Sanitization & Encoding | CWE-20, CWE-79, CWE-89, CWE-116 |
| V6 | Stored Cryptography | CWE-310, CWE-326, CWE-327, CWE-328 |
| V7 | Error Handling & Logging | CWE-209, CWE-532, CWE-778 |
| V8 | Data Protection | CWE-311, CWE-312, CWE-319 |
| V9 | Communication | CWE-295, CWE-319, CWE-523 |
| V10 | Malicious Code | CWE-506, CWE-507, CWE-511 |
| V11 | Business Logic | CWE-799, CWE-837, CWE-841 |
| V12 | Files & Resources | CWE-22, CWE-73, CWE-434 |
| V13 | API & Web Services | CWE-346, CWE-352, CWE-598 |
| V14 | Configuration | CWE-2, CWE-16, CWE-388 |

---

## CWE → Compliance Control Mapping

### Injection (CWE-78, CWE-79, CWE-89, CWE-94)

| Framework | Control Reference | Requirement Summary |
|---|---|---|
| PCI-DSS 4.0 | 6.2.4 | Prevent common software attacks including injection |
| SOC 2 | CC6.1 | Logical and physical access controls |
| HIPAA | §164.312(a)(1) | Access control - unique user identification |
| GDPR | Article 32(1)(b) | Ensure confidentiality and integrity of processing |
| ISO 27001 | A.8.26 | Application security requirements |
| NIST CSF 2.0 | PR.DS-1 | Data-at-rest protection |
| ASVS 5.0 | V5.3 | Output Encoding and Injection Prevention |

### Broken Authentication (CWE-287, CWE-384, CWE-521)

| Framework | Control Reference | Requirement Summary |
|---|---|---|
| PCI-DSS 4.0 | 8.3 | Strong authentication for all access |
| SOC 2 | CC6.1, CC6.2 | Logical access, credentials management |
| HIPAA | §164.312(d) | Person or entity authentication |
| GDPR | Article 32(1)(b) | Ability to ensure integrity |
| ISO 27001 | A.8.5 | Secure authentication |
| NIST CSF 2.0 | PR.AA-1 | Identity management and authentication |
| ASVS 5.0 | V2 | Authentication Verification |

### Broken Access Control (CWE-285, CWE-639, CWE-862)

| Framework | Control Reference | Requirement Summary |
|---|---|---|
| PCI-DSS 4.0 | 7.2 | Access control system configured properly |
| SOC 2 | CC6.3 | Role-based access control |
| HIPAA | §164.312(a)(1) | Access control - minimum necessary |
| GDPR | Article 25 | Data protection by design and default |
| ISO 27001 | A.8.3 | Access restriction |
| NIST CSF 2.0 | PR.AA-5 | Access permissions management |
| ASVS 5.0 | V4 | Access Control Verification |

### Cryptographic Failures (CWE-310, CWE-326, CWE-327)

| Framework | Control Reference | Requirement Summary |
|---|---|---|
| PCI-DSS 4.0 | 3.5, 4.2 | Protect stored data, encrypt transmissions |
| SOC 2 | CC6.1, CC6.7 | Data encryption in transit and at rest |
| HIPAA | §164.312(a)(2)(iv) | Encryption and decryption |
| GDPR | Article 32(1)(a) | Pseudonymization and encryption |
| ISO 27001 | A.8.24 | Use of cryptography |
| NIST CSF 2.0 | PR.DS-1, PR.DS-2 | Data-at-rest and in-transit protection |
| ASVS 5.0 | V6 | Stored Cryptography Verification |

### Security Misconfiguration (CWE-2, CWE-16, CWE-388)

| Framework | Control Reference | Requirement Summary |
|---|---|---|
| PCI-DSS 4.0 | 2.2 | Secure configuration standards |
| SOC 2 | CC6.1 | Security configuration management |
| HIPAA | §164.312(c)(1) | Integrity controls |
| GDPR | Article 32(1)(d) | Regular testing and evaluation |
| ISO 27001 | A.8.9 | Configuration management |
| NIST CSF 2.0 | PR.PS-1 | Configuration management |
| ASVS 5.0 | V14 | Configuration Verification |

### Logging & Monitoring Failures (CWE-778, CWE-223)

| Framework | Control Reference | Requirement Summary |
|---|---|---|
| PCI-DSS 4.0 | 10.2, 10.3 | Audit trail, log review |
| SOC 2 | CC7.2 | Monitoring for anomalies |
| HIPAA | §164.312(b) | Audit controls |
| GDPR | Article 33 | Breach notification (requires detection capability) |
| ISO 27001 | A.8.15 | Logging |
| NIST CSF 2.0 | DE.CM | Continuous monitoring |
| ASVS 5.0 | V7 | Error Handling and Logging Verification |

---

## NIST Cybersecurity Framework 2.0 Mapping

| NIST Function | Relevant Audit Phases | Key Controls |
|---|---|---|
| **Govern (GV)** | Phase 0 | Risk management, roles, policy |
| **Identify (ID)** | Phase 0 | Asset inventory, risk assessment, SBOM |
| **Protect (PR)** | Phase 1, 4, 6, 7 | Access control, encryption, configuration, training |
| **Detect (DE)** | Phase 1, 1.5, 7 | Anomaly detection, monitoring, logging |
| **Respond (RS)** | Phase 3, 4, 7 | Incident response, mitigation, communication |
| **Recover (RC)** | Phase 7 | Recovery planning, improvements |

---

## Using This Matrix

During Phase 3 remediation planning:

1. For each finding, look up its CWE in the tables above
2. Map the CWE to the relevant compliance controls
3. Include the mapping in the remediation plan and final report
4. For ASVS, note which level requires the finding to be addressed
5. Highlight any findings that impact multiple compliance frameworks (higher priority)
