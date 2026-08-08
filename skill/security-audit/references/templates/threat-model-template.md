# Threat Model (STRIDE Methodology)

_Reasoned from project-profile.md - keep these two documents consistent with each other. Select or adapt the Data Flow Diagram (DFD) matching the project's architecture._

---

## Data Flow Diagrams (Architecture Examples)

### Architecture 1: Web Application / API Gateway
```mermaid
graph TD
    User["Untrusted User / Client"] -->|HTTPS / REST API| API["API Gateway / Controller"]
    API -->|Internal IPC / Auth Check| Auth["Auth Service"]
    API -->|Parameterized Queries| DB[("Production Database")]
    API -->|Async Job Payload| Queue["Message Queue"]
    API -->|RAG Query / Context| VectorDB[("Vector DB / LLM Pipeline")]

    subgraph Trust Boundary 1: Public Internet
        User
    end

    subgraph Trust Boundary 2: Application Tier
        API
        Auth
        Queue
        VectorDB
    end

    subgraph Trust Boundary 3: Data Store
        DB
    end
```

### Architecture 2: CLI Tool / Local Utility
```mermaid
graph TD
    User["Terminal User / Shell Script"] -->|Args, Flags, Stdin| Parser["CLI Argument Parser"]
    Parser -->|Parsed Config| Core["Core Application Logic"]
    Core -->|Read / Write| LocalFS[("Local File System")]
    Core -->|Subprocess Exec| Subshell["System Shell / Tools"]
    Core -->|HTTP Requests| RemoteAPI["External APIs / Registries"]

    subgraph Trust Boundary 1: Untrusted Input
        User
    end

    subgraph Trust Boundary 2: Process Boundary
        Parser
        Core
    end

    subgraph Trust Boundary 3: System & Network
        LocalFS
        Subshell
        RemoteAPI
    end
```

### Architecture 3: Library / Framework / SDK
```mermaid
graph TD
    HostApp["Consuming Application"] -->|Public API Methods| SDK["SDK / Library Interface"]
    SDK -->|Data Processing| Engine["Internal Engine / Helpers"]
    Engine -->|I/O Calls| Network[("Remote Endpoint / Service")]
    Engine -->|Cache / Storage| LocalCache[("Disk / Memory Cache")]

    subgraph Trust Boundary 1: Host Application Space
        HostApp
    end

    subgraph Trust Boundary 2: SDK Sandbox / Boundary
        SDK
        Engine
    end

    subgraph Trust Boundary 3: External Systems
        Network
        LocalCache
    end
```

### Architecture 4: System Daemon / Background Service
```mermaid
graph TD
    Client["Local Process / User"] -->|Unix Domain Socket / IPC| Daemon["Daemon Process (Privileged)"]
    Daemon -->|Privilege Check| Policy["Access Policy Engine"]
    Daemon -->|System Call| Kernel["OS Kernel / Device Drivers"]
    Daemon -->|Log Entry| Syslog[("System Logger / Journal")]

    subgraph Trust Boundary 1: Unprivileged Userspace
        Client
    end

    subgraph Trust Boundary 2: Service Boundary
        Daemon
        Policy
    end

    subgraph Trust Boundary 3: Privileged Kernel Space
        Kernel
        Syslog
    end
```

### Architecture 5: Data Pipeline / ETL Processing
```mermaid
graph TD
    Ingest["Untrusted Data Source (S3, Kafka, Webhook)"] -->|Raw Stream / Batch| Parser["Data Parser & Schema Validator"]
    Parser -->|Validated Records| Transform["ETL Processing Engine"]
    Transform -->|Aggregated Data| Storage[("Data Warehouse / Lake")]
    Transform -->|Pipeline Metric/Log| Monitoring["Monitoring & Alerts"]

    subgraph Trust Boundary 1: External Data Sources
        Ingest
    end

    subgraph Trust Boundary 2: Processing Infrastructure
        Parser
        Transform
    end

    subgraph Trust Boundary 3: Secure Data Tier
        Storage
        Monitoring
    end
```

---

## Assets Worth Protecting
<!-- Sensitive customer data, authentication credentials, cryptographic keys, availability of critical endpoints, AI model prompts/weights, integrity of database records, system file integrity. -->

## STRIDE Threat Matrix

| STRIDE Category | Threat Description | Affected Asset / Component | Mitigation Status |
|---|---|---|---|
| **Spoofing** | Attacker impersonates valid user via stolen JWT, session fixation, or spoofed IPC identity | Auth Service / API / Socket | Pending Audit |
| **Tampering** | Parameter manipulation, SQL/Command injection, or file modification | DB / File System / API | Pending Audit |
| **Repudiation** | Lack of audit logging for administrative actions or critical operations | Audit Log Store / Journal | Pending Audit |
| **Information Disclosure** | Leakage of sensitive PII, API tokens, verbose stack traces, or debug outputs | HTTP Responses / Logs / Temp files | Pending Audit |
| **Denial of Service** | Resource exhaustion via oversized payload, regex backtracking, or unbounded memory allocation | Application Gateway / Parser | Pending Audit |
| **Elevation of Privilege** | IDOR, BFLA, SUID abuse, or missing authorization check leading to escalation | Admin Endpoints / Privileged Daemon | Pending Audit |

## Likely Threat Actors
<!-- Reasoned from project type: anonymous internet users, authenticated low-privilege users, local non-root users, malicious insiders, supply-chain package hijackers. -->

## Trust Boundaries
<!-- Where does trusted code/data meet untrusted input? List explicitly - Phase 1 findings cluster here. -->

## Out of Scope
<!-- Anything genuinely inapplicable with explicit technical justification (e.g., "No network attack surface: pure offline CLI tool"). -->
