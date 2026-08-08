# Vulnerability Reference: Infrastructure as Code, Cloud & CI/CD

_Load this during Phase 1 when auditing Dockerfiles, Kubernetes manifests, Terraform scripts, CloudFormation templates, CI/CD pipelines, or serverless configurations._

---

## 1. Container Security (Dockerfiles)

### Image Security
- **Root User:** Missing `USER` instruction - container process running as `root`
- **Unpinned Images:** Using `:latest` tags without SHA256 digests (`FROM node:latest` → `FROM node:20-slim@sha256:...`)
- **Bloated Images:** Using full OS images instead of slim/distroless/scratch
- **Secrets in Build Layers:** Hardcoding API keys, private keys, or passwords in `ENV`, `ARG`, or `RUN` instructions (persist in layer history even if deleted in later layers)
- **Multi-Stage Leaks:** Secrets from build stages leaking into final image via `COPY --from`

### Runtime Security
- **Sensitive Mounts:** Mounting host Docker socket (`/var/run/docker.sock`) or host root filesystem
- **Privileged Mode:** `--privileged` flag or `privileged: true` in compose/K8s
- **Missing Health Checks:** No `HEALTHCHECK` instruction for orchestrator liveness detection
- **Writable Root Filesystem:** Missing `--read-only` flag for runtime filesystem protection

---

## 2. Kubernetes & Cluster Security

### RBAC & Authorization
- Service accounts bound to `cluster-admin` or cluster roles with `verbs: ["*"]`
- Default service account used instead of dedicated per-workload accounts
- Missing `automountServiceAccountToken: false` on pods that don't need API access
- Namespace-level isolation not enforced (pods can access cross-namespace services)

### Pod Security
- Missing `securityContext` configuration:
  - `readOnlyRootFilesystem: true`
  - `allowPrivilegeEscalation: false`
  - `runAsNonRoot: true`
  - `capabilities: drop: ["ALL"]`
- Missing Seccomp / AppArmor profiles
- `hostNetwork: true`, `hostPID: true`, or `hostIPC: true` without justification
- Missing resource limits (`resources.limits.cpu`, `resources.limits.memory`) - DoS risk

### Network Policies
- Missing NetworkPolicy resources (all pods can communicate by default)
- Overly permissive ingress/egress rules
- Missing egress restrictions (pods can reach internet, cloud metadata)

### Secrets Management
- Kubernetes Secrets stored as base64 (not encrypted) - readable by anyone with API access
- Missing encryption at rest for etcd
- Secrets mounted as environment variables (visible in process listing) instead of volume files

---

## 3. Terraform / CloudFormation / IaC

### Cloud Resource Misconfig
- **Open Storage:** S3/GCS buckets with public read/write permissions or missing default encryption
- **Overpermissive IAM:** Policies using `"Action": "*"` or `"Resource": "*"`
- **Unencrypted Storage:** EBS volumes, RDS instances, or data stores without encryption at rest
- **Public Endpoints:** Databases, caches (Redis, Memcached), or internal services exposed to `0.0.0.0/0`

### State & Secrets
- **State File Exposure:** Terraform state files stored unencrypted, containing plaintext secrets
- **Remote State Without Locking:** Concurrent modifications causing state corruption
- **Hardcoded Secrets:** API keys, passwords in `.tf` files instead of using `sensitive = true` variables or vault references

### Drift & Governance
- Missing state drift detection (manual changes not tracked)
- No policy-as-code (Sentinel, OPA/Rego, Checkov) enforcement
- Missing tagging requirements for cost allocation and ownership

---

## 4. CI/CD Pipeline Security

### Pipeline Poisoning
- **Poisoned Pipeline Execution (PPE):** Untrusted PRs triggering CI/CD with modified pipeline definitions
- **Dependency Confusion in CI:** Internal package names resolvable from public registries during build
- **Artifact Tampering:** Build artifacts modifiable between build and deploy stages
- **Secret Exposure in Logs:** CI/CD variables printed in build output

### GitHub Actions Specific
- `pull_request_target` with `actions/checkout` of PR head (code injection from forks)
- Overly broad `permissions` (should use `permissions: read-all` + explicit per-job grants)
- Unpinned action versions (`uses: actions/checkout@main` instead of `@v4` or SHA pinning)
- `${{ github.event.issue.title }}` or similar in `run:` blocks (command injection)
- Self-hosted runners without proper isolation

### GitLab CI Specific
- Shared runners executing untrusted code without isolation
- Missing protected branch/tag restrictions on deployment jobs
- CI/CD variables not marked as protected or masked

### Secrets in CI/CD
- Secrets accessible to all jobs/stages instead of scoped to specific environments
- Missing secret rotation for CI/CD service accounts
- Secrets persisted in CI/CD logs or artifacts

---

## 5. Serverless Security

### Function Configuration
- Overpermissive IAM execution roles (Lambda/Cloud Function accessing all S3 buckets)
- Missing function timeout limits (runaway execution → cost attack)
- Missing concurrency limits (DDoS → massive cost)
- Environment variables containing secrets without KMS encryption

### Event Injection
- Untrusted event payloads (API Gateway, S3 events, SQS messages) processed without validation
- Missing input validation on event trigger data
- Cross-function invocation without authorization checks

### Cold Start & Timing
- Sensitive initialization in cold start path (loading secrets, establishing connections) timing leaks
- VPC cold start delays exploitable for timing attacks

---

## Tooling

Check for availability of:
```bash
checkov -d .                # IaC scanner (Terraform, K8s, Dockerfile, CloudFormation)
tfsec .                     # Terraform security scanner
kube-score score deploy.yml # Kubernetes manifest analysis
trivy config .              # IaC misconfiguration scanning
kubeaudit all               # Kubernetes cluster audit
hadolint Dockerfile         # Dockerfile linting
```
