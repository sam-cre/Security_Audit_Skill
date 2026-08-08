# Domain: Microservices & Distributed Systems

_Load when the project has more than one deployable service, gRPC, a message bus, a service mesh, or east-west traffic inside a cluster._

The defining failure of microservice security is **assuming the network is trusted**. Every internal call is an attack surface once one service is compromised or the gateway is bypassed.

---

## 1. Service-to-Service Authentication

- Internal endpoints with no authentication because they are "not exposed" - an SSRF or a pod compromise makes them exposed
- Trusting a header the gateway sets (`X-User-Id`, `X-Roles`, `X-Tenant`) without verifying the request came from the gateway - a client that reaches the service directly spoofs it
- Shared static API key across all services, so compromising one grants all
- mTLS terminated at the mesh but the application also accepting plaintext on another port
- Service identity derived from source IP or DNS name, both spoofable inside a flat network
- Certificates with no rotation, or a single wildcard cert used by every service
- SPIFFE/SPIRE or mesh identity available but not actually enforced in policy

## 2. Token Propagation

- Original user JWT forwarded downstream but **not re-validated** at each hop
- Token exchanged for a more privileged internal token with no scope narrowing
- Downstream service trusting claims that an intermediate service could have modified
- Long-lived internal tokens with no audience restriction - usable against any service
- Token forwarded to a third-party or external service by accident
- No correlation between the user identity and the action recorded downstream, so audit logs cannot attribute

## 3. Gateway & Perimeter

- Routes reachable directly on the service port, bypassing the gateway's authn, rate limiting, and WAF
- Gateway rate limits and body-size limits not replicated at the service
- Path normalization mismatch between gateway and service - `/admin/..;/` or double-encoded paths routed differently by each, defeating gateway ACLs
- Gateway allowlist by path prefix while the service exposes additional routes under it
- Admin/actuator/debug endpoints (`/actuator`, `/metrics`, `/debug/pprof`, `/health` with detail) exposed without auth
- Service mesh sidecar bypassable via `hostNetwork`, or traffic to ports the mesh does not capture

## 4. Network Policy & Segmentation

- Default-allow east-west traffic - any pod can reach any service
- No `NetworkPolicy` or an overly broad one; namespaces not isolated
- Databases and caches reachable from every service rather than only their owner
- Management planes (Redis, Elasticsearch, Kafka, etcd, RabbitMQ admin) bound to `0.0.0.0` with default or no auth
- Egress unrestricted, so a compromised pod can exfiltrate freely or pull attacker payloads

## 5. Message Queues & Event Streams

- No authentication or ACLs on Kafka, RabbitMQ, NATS, SQS, or Pub/Sub topics
- Any service able to publish to any topic - a compromised low-privilege service forges high-privilege events
- Message payloads not integrity-protected, so a broker compromise lets messages be rewritten
- Consumers trusting message content as pre-validated because "it came from inside"
- Unsafe deserialization of message payloads (language-native object formats rather than a schema)
- No replay protection or idempotency key, so redelivery causes duplicate side effects
- Poison-message handling that retries forever, causing self-inflicted denial of service
- Dead-letter queues holding sensitive payloads with weaker access control than the source
- PII in event payloads that fan out to consumers with no need for it

## 6. gRPC & RPC Surfaces

- Server reflection enabled in production, publishing the full service schema
- TLS disabled on internal gRPC
- Interceptors for authn/authz applied to some services but not all, or not to streaming methods
- No message size limit, allowing memory exhaustion
- Errors returning internal detail in `Status` messages
- Protobuf `Any` fields deserialized into arbitrary types

## 7. SSRF as a Pivot

In a cluster, SSRF is far more severe than on a monolith.

- Any user-controlled URL fetched by a service reaches internal services, the cloud metadata endpoint, and the Kubernetes API
- Metadata endpoints not blocked: `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`
- No allowlist on outbound destinations; redirects followed without re-validating the target
- DNS rebinding not considered - validation and fetch resolve the name twice
- Link-local, loopback, and RFC1918 ranges not blocked, including IPv6 equivalents

## 8. Service Discovery & Configuration

- Service registry (Consul, etcd, Eureka) writable without auth → traffic redirection
- Config server serving secrets to any client that asks
- Environment-injected secrets visible in `/proc`, crash dumps, or debug endpoints
- Secrets in Kubernetes `ConfigMap` rather than `Secret`, or `Secret` without encryption at rest
- Container images baked with credentials
- Sidecar or init container with broader RBAC than the workload needs

## 9. Kubernetes Workload Identity

- Default ServiceAccount token auto-mounted into pods that never call the API
- RBAC granting `cluster-admin`, wildcard verbs, or `secrets: list` across namespaces
- Pods running privileged, as root, or with `hostPID` / `hostPath` mounts
- No Pod Security admission enforcement
- Cloud IAM bound to a node rather than a workload, so every pod inherits node permissions

## 10. Observability Leaks

- Distributed traces capturing full request bodies, headers, tokens, or PII
- Logs aggregated centrally with weaker access control than the source data
- Metrics endpoints exposing user identifiers or business-sensitive cardinality
- Correlation IDs supplied by the client and trusted for audit attribution
- Profiling and heap-dump endpoints reachable in production

## 11. Resilience & Consistency

- No timeout on inter-service calls, causing cascading stalls and thread exhaustion
- Retries without backoff or a budget, amplifying a partial outage into a self-DoS
- No circuit breaker, so one slow dependency takes down the fleet
- Distributed transaction or saga with a compensating action that can be skipped, leaving the system in a profitable-to-attacker state
- Non-idempotent operations exposed to at-least-once delivery
- Eventual consistency used for an authorization decision - check on stale data, act on fresh

## 12. Multi-Tenancy Across Services

- Tenant context established at the edge but not propagated, so downstream services query unscoped
- Caches, search indexes, and object storage keyed without a tenant component
- Async jobs losing tenant context and running with elevated or wrong scope
- One tenant's load able to starve another (no per-tenant quota)

---

## Reviewing a Distributed System Well

1. **Draw the real call graph.** Which service calls which, over what protocol, with what credential. Findings live in the edges, not the nodes.
2. **Assume one service is already owned.** For each service, ask what an attacker inside it reaches. That is the blast radius, and it is the core question.
3. **Try to bypass the gateway.** If a service can be reached on its own port, every gateway control is advisory.
4. **Follow one user request end to end**, watching where identity is re-verified and where it is merely believed.
5. **Check the async paths.** Queue consumers and scheduled jobs are consistently less scrutinized than HTTP handlers, and they usually run with more privilege.
