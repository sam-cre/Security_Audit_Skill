# Vulnerability Reference: Infrastructure as Code, Cloud & CI/CD

_Load in Phase 1 for Dockerfiles, Kubernetes manifests, Terraform, CloudFormation, CI/CD pipelines, or serverless configs._

---

## 1. Containers (Dockerfiles)

**Image**
- Missing `USER` (runs as root)
- `:latest` or unpinned tags, no digest (`node:20-slim@sha256:...`)
- Full OS image instead of slim/distroless/scratch
- Secrets in `ENV`, `ARG`, or `RUN` (persist in layer history even if later deleted)
- Build-stage secrets leaking via `COPY --from`

**Runtime**
- Host Docker socket (`/var/run/docker.sock`) or host root mounted
- `--privileged` / `privileged: true`
- No `HEALTHCHECK`; writable root filesystem (no `--read-only`)

## 2. Kubernetes

**RBAC**
- ServiceAccounts bound to `cluster-admin` or `verbs: ["*"]`
- Default ServiceAccount instead of per-workload accounts
- No `automountServiceAccountToken: false` on pods that don't need the API
- No namespace isolation (cross-namespace access)

**Pod security**
- Missing `securityContext`: `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true`, `capabilities: drop: ["ALL"]`
- No Seccomp/AppArmor profile
- `hostNetwork`, `hostPID`, `hostIPC` without justification
- No CPU/memory limits (DoS)

**Network**
- No NetworkPolicy (all pods talk by default); overly permissive rules
- No egress limits (internet and cloud metadata reachable)

**Secrets**
- Secrets are base64, not encrypted, and readable by anyone with API access
- No etcd encryption at rest
- Secrets as env vars (visible in process listing) rather than volume files

## 3. Terraform / CloudFormation

**Resources**
- Public S3/GCS buckets, or no default encryption
- IAM with `"Action": "*"` or `"Resource": "*"`
- Unencrypted EBS, RDS, or data stores
- Databases, caches (Redis, Memcached), internal services open to `0.0.0.0/0`

**State & secrets**
- Unencrypted Terraform state containing plaintext secrets
- Remote state without locking
- Hardcoded secrets in `.tf` files instead of `sensitive = true` variables or vault references

**Governance**
- No drift detection; no policy-as-code (Sentinel, OPA/Rego, Checkov); no ownership tagging

## 4. CI/CD Pipelines

**Pipeline poisoning**
- Untrusted PRs running modified pipeline definitions (PPE)
- Internal package names resolvable from public registries during build (dependency confusion)
- Artifacts modifiable between build and deploy
- CI variables printed in build output

**GitHub Actions**
- `pull_request_target` checking out the PR head (fork code injection)
- Broad `permissions` (use `read-all` plus per-job grants)
- Unpinned actions (`@main` instead of `@v4` or a SHA)
- `${{ github.event.issue.title }}` or similar inside `run:` (command injection)
- Self-hosted runners without isolation

**GitLab CI**
- Shared runners executing untrusted code unisolated
- No protected branch/tag rules on deploy jobs
- Variables not protected or masked

**Secrets in CI/CD**
- Secrets visible to all jobs, not scoped to environments
- No rotation for CI service accounts
- Secrets persisted in logs or artifacts

## 5. Serverless

- Overpermissive execution roles (a function reaching all S3 buckets)
- No timeout or concurrency limits (runaway cost, DDoS bills)
- Env-var secrets without KMS encryption
- Untrusted event payloads (API Gateway, S3, SQS) processed without validation
- Cross-function invocation without authorization
- Timing leaks from secret loading in the cold-start path, and VPC cold-start delays

---

## Tooling

```bash
checkov -d .                # Terraform, K8s, Dockerfile, CloudFormation
tfsec .                     # Terraform
kube-score score deploy.yml # K8s manifests
trivy config .              # IaC misconfiguration
kubeaudit all               # cluster audit
hadolint Dockerfile         # Dockerfile lint
```
