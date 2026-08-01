# Threat Intelligence Enrichment Protocol

_Read this during Phase 1 when you need to enrich vulnerability findings with exploit likelihood data, or during Phase 3 for remediation prioritization._

---

## EPSS — Exploit Prediction Scoring System

EPSS provides a probability score (0.0 to 1.0) indicating how likely a CVE is to be exploited in the wild in the next 30 days. Use this to prioritize remediation.

### When to Use
- After identifying dependency CVEs in Phase 0/1
- To prioritize remediation order in Phase 3 (break ties between same-severity findings)

### How to Query
```bash
# Query EPSS score for a specific CVE
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-XXXXX" | jq '.data[0]'
```

### Interpretation
| EPSS Score | Interpretation | Remediation Priority |
|---|---|---|
| > 0.7 | Very high exploit probability | **Immediate** — treat as if actively exploited |
| 0.4 – 0.7 | High exploit probability | **Urgent** — fix within 7 days |
| 0.1 – 0.4 | Moderate exploit probability | **Standard** — fix within 30 days |
| < 0.1 | Low exploit probability | **Scheduled** — fix within 90 days |

### Integration with CVSS
EPSS complements CVSS — a Medium-severity CVE with high EPSS (> 0.7) should be prioritized above a High-severity CVE with low EPSS (< 0.1). CVSS measures theoretical impact; EPSS measures real-world likelihood.

---

## CISA KEV — Known Exploited Vulnerabilities Catalog

The CISA KEV catalog lists vulnerabilities **actively being exploited** in the wild. Any CVE on this list is a critical finding regardless of CVSS score.

### When to Use
- After dependency enumeration in Phase 0/1
- Cross-reference every confirmed CVE against KEV

### How to Check
```bash
# Download KEV catalog
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | \
  jq '.vulnerabilities[] | select(.cveID == "CVE-2024-XXXXX")'
```

### If a CVE is in KEV
1. **Escalate to Critical** regardless of CVSS score
2. Mark as `"kevListed": true` in `security-findings.json`
3. Move to top of remediation priority in Phase 3
4. Note the CISA-mandated remediation deadline (if applicable to federal systems)

---

## Remediation SLA Recommendations

Based on combined CVSS + EPSS + KEV data, recommend these remediation timelines:

| Severity | EPSS | KEV Listed | Recommended SLA |
|---|---|---|---|
| Critical | Any | Yes | **24 hours** |
| Critical | > 0.4 | No | **72 hours** |
| Critical | < 0.4 | No | **7 days** |
| High | Any | Yes | **72 hours** |
| High | > 0.4 | No | **7 days** |
| High | < 0.4 | No | **14 days** |
| Medium | Any | No | **30 days** |
| Low | Any | No | **90 days** |
| Informational | Any | No | **Next release cycle** |

---

## Threat Actor Profiling

During Phase 0 threat modeling, consider the likely attackers for the project type:

| Project Type | Primary Threat Actors |
|---|---|
| Public web app | Anonymous internet users, automated scanners, script kiddies |
| SaaS platform | Authenticated malicious users, competitor espionage |
| Internal tool | Malicious insiders, compromised employee accounts |
| Open-source library | Supply chain attackers, package hijackers |
| Financial service | Organized crime, state-sponsored actors |
| Healthcare system | Ransomware operators, data brokers |
| IoT / Embedded | Physical attackers, nation-state (critical infrastructure) |
| Smart contract / DeFi | MEV bots, flash loan attackers, white-hat bounty hunters |
| Game | Cheat developers, account sellers, currency farmers |
| AI / LLM app | Prompt injection researchers, data poisoners |

---

## Post-Audit Security Maintenance

### Recommended Cadence
| Audit Type | Frequency | Trigger |
|---|---|---|
| **Full audit** (Deep mode) | Every 6 months | Major version releases, compliance deadlines |
| **Differential audit** | Every 3 months | Feature branches, quarterly reviews |
| **Quick scan** | Every sprint / PR | Pull request reviews, pre-merge checks |
| **Dependency scan** | Weekly (automated) | CI/CD pipeline, Dependabot/Renovate |

### Security Champion Program
Recommend the team designate a **security champion** who:
- Reviews security-relevant PRs
- Monitors dependency vulnerability alerts
- Coordinates audit scheduling
- Maintains the `.semgrep/` custom rules
- Manages the `.security-audit/` audit artifacts
