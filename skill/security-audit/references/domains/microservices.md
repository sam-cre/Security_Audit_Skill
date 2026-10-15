# Domain: Microservices & Distributed Systems

_Load when the project has more than one deployable service, gRPC, a message bus, a service mesh, or east-west traffic in a cluster._

The core failure is **assuming the network is trusted**. Once one service is compromised or the gateway is bypassed, every internal call is attack surface.

---

## 1. Service-to-Service Authentication

- Internal endpoints with no auth because they are "not exposed" (SSRF or a pod compromise exposes them)
- Trusting a gateway-set header (`X-User-Id`, `X-Roles`, `X-Tenant`) without verifying the request came from the gateway
- One shared static API key for all services
- mTLS at the mesh, but the app also accepts plaintext on another port
- Service identity from source IP or DNS name (spoofable on a flat network)
- No cert rotation, or one wildcard cert for every service
- SPIFFE/SPIRE or mesh identity available but not enforced in policy

## 2. Token Propagation

- User JWT forwarded downstream but **not re-validated** at each hop
- Token exchanged for a more privileged internal token with no scope narrowing
- Downstream trusting claims an intermediate service could have altered
- Long-lived internal tokens with no audience restriction
- Token accidentally forwarded to an external service
- User identity not recorded with downstream actions (audit cannot attribute)

## 3. Gateway & Perimeter

- Routes reachable on the service port directly, bypassing gateway authn, rate limits, and WAF
- Gateway rate and body-size limits not replicated at the service
- Path normalization mismatch (`/admin/..;/`, double-encoded paths) defeating gateway ACLs
- Gateway allowlist by path prefix while the service exposes more routes under it
- Admin/actuator/debug endpoints (`/actuator`, `/metrics`, `/debug/pprof`, detailed `/health`) without auth
- Mesh sidecar bypass via `hostNetwork` or ports the mesh doesn't capture

## 4. Network Policy & Segmentation

- Default-allow east-west traffic; no or overly broad `NetworkPolicy`; namespaces not isolated
- Databases and caches reachable from every service, not just the owner
- Redis, Elasticsearch, Kafka, etcd, RabbitMQ admin bound to `0.0.0.0` with default or no auth
- Unrestricted egress (exfiltration, payload download)

## 5. Message Queues & Event Streams

- No auth or ACLs on Kafka, RabbitMQ, NATS, SQS, or Pub/Sub topics
- Any service can publish to any topic (a low-privilege service forges high-privilege events)
- Payloads not integrity-protected (broker compromise rewrites them)
- Consumers trusting content as pre-validated because it came from inside
- Unsafe deserialization (language-native object formats instead of a schema)
- No replay protection or idempotency key (duplicate side effects)
- Poison messages retried forever (self-DoS)
- Dead-letter queues with weaker access control than the source
- PII in events fanned out to consumers that don't need it

## 6. gRPC & RPC

- Server reflection on in production
- TLS off on internal gRPC
- Authn/authz interceptors on some services only, or missing on streaming methods
- No message size limit
- Internal detail in `Status` errors
- Protobuf `Any` deserialized into arbitrary types

## 7. SSRF as a Pivot

In a cluster SSRF is far worse than on a monolith.

- User-controlled URLs reach internal services, the cloud metadata endpoint, and the Kubernetes API
- Metadata not blocked: `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`
- No outbound allowlist; redirects followed without re-validating
- DNS rebinding (validation and fetch resolve twice)
- Link-local, loopback, RFC1918 not blocked, including IPv6

## 8. Discovery & Configuration

- Service registry (Consul, etcd, Eureka) writable without auth (traffic redirection)
- Config server serving secrets to any asker
- Env-injected secrets visible in `/proc`, crash dumps, debug endpoints
- Secrets in `ConfigMap` not `Secret`, or `Secret` without encryption at rest
- Images baked with credentials
- Sidecar or init container with broader RBAC than the workload

## 9. Kubernetes Workload Identity

- Default ServiceAccount token auto-mounted in pods that never call the API
- RBAC with `cluster-admin`, wildcard verbs, or `secrets: list` across namespaces
- Privileged pods, root, `hostPID`, `hostPath`
- No Pod Security admission enforcement
- Cloud IAM bound to the node, so every pod inherits it

## 10. Observability Leaks

- Traces capturing full bodies, headers, tokens, PII
- Central logs with weaker access control than the source data
- Metrics exposing user identifiers or sensitive cardinality
- Client-supplied correlation IDs trusted for audit attribution
- Profiling and heap-dump endpoints reachable in production

## 11. Resilience & Consistency

- No timeout on inter-service calls (cascading stalls)
- Retries without backoff or budget (self-DoS); no circuit breaker
- Saga compensation that can be skipped, leaving an attacker-profitable state
- Non-idempotent operations under at-least-once delivery
- Authorization decided on stale data under eventual consistency

## 12. Multi-Tenancy Across Services

- Tenant context set at the edge but not propagated, so downstream queries are unscoped
- Caches, search indexes, object storage keyed without tenant
- Async jobs losing tenant context
- No per-tenant quota (one tenant starves another)

---

## Reviewing a Distributed System Well

1. **Draw the real call graph:** who calls whom, over what protocol, with what credential. Findings live in the edges.
2. **Assume one service is already owned.** What can an attacker inside it reach? That is the blast radius.
3. **Try to bypass the gateway.** If a service answers on its own port, gateway controls are advisory.
4. **Follow one user request end to end,** noting where identity is re-verified versus believed.
5. **Check async paths.** Consumers and scheduled jobs get less scrutiny than HTTP handlers and usually hold more privilege.
