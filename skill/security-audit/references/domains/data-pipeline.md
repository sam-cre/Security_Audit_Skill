# Vulnerability Reference: Data Pipelines, ETL & Data Warehouses

_Load this during Phase 1 when auditing ETL pipelines, data ingestion services, streaming processors, data lakes, or data warehouse configurations._

---

## 1. Data Ingestion Poisoning

### Untrusted Source Injection
- External data sources (S3 buckets, webhooks, Kafka topics, FTP drops) ingested without schema validation
- CSV/JSON/XML parsing without sanitization — injection of formulas in CSV (`=SYSTEM("cmd")` in Excel contexts)
- XML External Entity (XXE) in XML pipeline parsers
- Malformed data crashing parsers (null bytes, oversized fields, nested structures)

### Schema Injection
- Dynamic schema inference from untrusted data allowing new columns/fields to appear
- Schema evolution without validation gate (new fields auto-accepted)
- Type confusion between string and executable types in dynamic languages

---

## 2. Credential & Secret Exposure

### Pipeline Credentials
- Database connection strings hardcoded in pipeline configuration files (Airflow DAGs, dbt profiles, Luigi configs)
- Cloud service account keys embedded in ETL scripts or environment variables
- Shared credentials across pipeline stages (same service account for read and write)

### Data-Layer Credentials
- Warehouse admin credentials used for ETL jobs instead of least-privilege service accounts
- Missing credential rotation for long-running pipeline service accounts
- Credentials logged in pipeline execution logs or error messages

---

## 3. Access Control & Data Isolation

### Warehouse ACL Bypass
- Overpermissive warehouse roles (ETL service account with `SYSADMIN` or `ACCOUNTADMIN`)
- Missing row-level security on multi-tenant data
- Cross-schema access allowing ETL jobs to read/modify unrelated datasets
- Missing column-level masking on PII/PHI fields

### Pipeline Execution Privileges
- Pipeline orchestrator (Airflow, Dagster, Prefect) running with elevated OS privileges
- Worker processes inheriting orchestrator's full IAM permissions
- Missing task-level permission scoping

---

## 4. PII & Sensitive Data Leakage

### Logging & Monitoring Leaks
- PII/PHI appearing in pipeline execution logs (names, SSNs, medical records)
- Sensitive data in error messages or stack traces sent to monitoring systems
- Intermediate pipeline outputs containing unmasked sensitive data persisted to shared storage

### Intermediate Storage Exposure
- Temporary files in `/tmp` or shared S3 buckets containing unencrypted PII
- Failed pipeline runs leaving sensitive data in staging tables indefinitely
- Missing data retention policies on intermediate/staging data

---

## 5. Data Integrity & Tampering

### Pipeline Tampering
- Missing checksums or signatures on data in transit between pipeline stages
- No idempotency guarantees — re-running a pipeline produces different results
- Race conditions in concurrent pipeline execution (two jobs writing to same table)

### Data Quality as Security
- Missing row count / schema validation between pipeline stages
- Silent data loss (rows dropped without alerting)
- Data duplication without deduplication checks

---

## 6. Infrastructure & Orchestration

### Orchestrator Security
- Airflow web UI exposed without authentication
- DAG code injection via user-controlled DAG definitions
- Missing RBAC on pipeline trigger/modify operations
- Insecure deserialization in task serialization (pickle in Celery/Airflow)

### Compute Isolation
- Pipeline tasks sharing compute resources without isolation (container, VM, or process-level)
- Untrusted code execution in user-defined transformations (UDFs)
- Missing resource quotas allowing a single pipeline to exhaust cluster resources

---

## 7. Compliance & Governance

### Data Lineage
- Missing data lineage tracking (where did each record come from?)
- No audit trail for data transformations
- Inability to trace a specific output record back to its source

### Regulatory
- Cross-border data transfers without GDPR/HIPAA compliance checks
- Missing data classification labels on pipeline outputs
- No automated PII detection in ingested data
