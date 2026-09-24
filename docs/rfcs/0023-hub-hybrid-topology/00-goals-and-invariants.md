# Goals and invariants

## Scope

This RFC adds a **hybrid runtime mode** to AOS Hub. It determines which
runtime handles a request and which runtime owns durable state. It does not
change the logical surfaces, placements, endpoint identities, route policy, or
write-authority model specified by [RFC-0012](../0012-hub-surface-topology/README.md).
A placement may use R2, S3, or another supported storage binding in any
runtime mode. The runtime mode is a deployment choice for one Hub instance,
not a property of a registry, cache, tenant, or placement.

The existing [RFC-0004 unified runtime](../0004-registry-hub/10-unified-runtime.md)
and shared Hub service/router remain the application model. Hybrid adds a
Worker ingress and storage-compute tier around a Native Hub, rather than a
second copy of Hub business logic. RFC-0004's proposed
[colocated Durable Object data architecture](../0004-registry-hub/14-colocated-storage-architecture.md)
does not define the hybrid mode's database placement.

## Intended deployment modes

| Mode | Public request entry | SQL authority | Application and indexing authority | Object work |
| --- | --- | --- | --- | --- |
| Native-only | Native Hub, or an ordinary ingress in front of it | Native SQLite by default; another supported native SQL backend may be configured | Native Hub | Native storage adapters or direct object-store delivery |
| Worker-only | Cloudflare Worker | HubDb SQLite Durable Object | Shared Hub service in Workers and Worker jobs | Worker storage adapters |
| Hybrid | Cloudflare Worker on every Hub public authority | One PostgreSQL database used by one logical Native Hub service | Native Hub | Workers near bound object storage, with direct storage delivery when appropriate |

The hybrid baseline is a Native Hub on GCP with Cloud SQL PostgreSQL. One
*logical* Native service means one deployment identity, one set of signing and
sealing keys, one SQL authority, and one coordinated job domain. It may have
several stateless request replicas. Replicas do not each create independent
Hub state, scheduler ownership, or publication authority. A single process is
not a scalability requirement.

Worker-only remains a complete deployment mode. Its resource-affine request
Durable Objects may spread execution, but their calls into `HubDb` do not
shard the relational data. Hybrid does not put relational tables into those
request objects or into object-scoped caches.

## Goals

1. **Keep SQL and application decisions close.** An authenticated page or
   control API call executes in Native against nearby PostgreSQL. It does not
   make a sequence of cross-colo Durable Object-to-HubDb SQL calls. Native
   owns sessions, IAM, topology, publication, anti-rollback floors, indexing
   commits, and other transactional decisions.
2. **Keep object bytes away from Native.** Uploads, downloads, replication,
   and storage inspection use Worker storage adapters or direct object-store
   paths. Native exchanges bounded plans and derived results with Workers.
   Indexing may fetch a small, explicitly bounded slice when a parser requires
   it; a full object cannot become an implicit fallback.
3. **Make the Worker an effective front door.** It serves static assets and
   eligible cached public responses, terminates public requests, enforces
   ingress limits, and shields the Native origin from avoidable traffic.
   Authenticated HTML and control APIs still use Native's canonical router.
4. **Scale object work independently of SQL and Native CPU.** Native can fan
   out typed, bounded storage operations across Workers while retaining the
   final verification and database commit. Object-scoped Durable Objects are
   optional, reconstructable parse caches, not the system of record.
5. **Keep deployment modes behaviorally aligned.** Shared authorization,
   routing, wire formats, and business rules have one implementation or a
   tested common contract. Runtime adapters may differ; API semantics do not.
6. **Make the topology observable and cost-bounded.** Operators can identify
   time spent at the edge, origin, SQL, and storage executor and measure
   cross-cloud bytes by direction and workflow.

## Invariants

### Authority and consistency

- Exactly one database is authoritative for a Hub instance. Hybrid Workers
  have no writable copy or general SQL proxy. PostgreSQL transactions decide
  whether work is committed; Worker results are untrusted evidence until
  Native verifies their object identity, binding generation, and digest.
- Every request reaches a single authoritative path. A Worker may serve a
  response locally only when the route's cache or storage policy permits it;
  it cannot infer authorization or publication state from a stale cache.
- A storage work plan names an immutable object version or content identity,
  a binding/placement generation, permitted operations, limits, and an expiry.
  Worker execution cannot silently substitute a new placement or credential
  revision. Changes to RFC-0012 write authority are committed by Native.
- Worker and Native versions must negotiate a compatible storage-work
  protocol. An incompatible deployment fails the operation closed; it cannot
  reinterpret an old plan under new parser or binding semantics.

### Byte movement and egress

- No normal hybrid path routes complete NARs, images, bundles, OCI layers,
  uploads, or mirrored objects through Native. Native's outbound traffic is
  limited to bounded storage plans and API/HTML responses. Inbound derived
  storage results are also bounded so indexing cannot exhaust Native memory or
  network capacity.
- A public or authorized private download is delivered by a Worker or a
  scoped direct-storage URL. Private delivery requires authorization evidence
  issued or validated by Native, scoped to the exact object and short lived;
  cache keys and response policy must preserve that privacy boundary.
- Storage work uses bounded batches and projections. A generic remote `fetch`
  returning arbitrary bytes is not an acceptable implementation of hybrid
  indexing. A full-object read is a named exceptional operation with an
  explicit byte cap and an operational signal.
- Cloud egress accounting distinguishes Native-to-Worker, Native-to-client
  through the Worker, and object-store-to-Worker traffic. The practical target
  is that GCP outbound bytes are application responses and small plans, not
  proportional to object bytes inspected or transferred. Non-GCP provider
  egress, especially for S3 bindings, is measured separately.

### Failure and scaling

- Edge cache loss and object-cache eviction affect latency, not correctness.
  Native SQL and immutable storage evidence remain sufficient to reconstruct
  them. Cache invalidation is tied to committed state or bounded freshness.
- Worker storage operations are retryable or explicitly idempotent. A timeout
  cannot imply that Native committed a publication, and a retry cannot create
  a second logical commit. Native controls job leases and commit sequencing
  across replicas.
- The Native origin accepts only authenticated edge ingress and explicit
  operator access. It does not trust browser-supplied forwarding headers.
  Public availability during a Native or SQL outage is limited to responses
  whose cache and authorization policy explicitly allows it.

## Performance and cost acceptance

Before rollout, record the current staging baseline for authenticated page
loads, representative Connect-JSON calls, parallel uploads, indexing, and
large downloads. Measure at least edge-to-origin time, Native handler time,
SQL time, storage-executor time, cache hit rate, origin request rate, and bytes
crossing the GCP boundary. The implementation plan sets numeric service
targets against that baseline before a production cutover.

Acceptance requires all of the following, rather than a faster anonymous
landing page alone:

- Warm authenticated page and control API latency no longer grows with the
  number of remote HubDb round trips; traces show local Native-to-PostgreSQL
  calls for their SQL work.
- Increasing parallel uploads and object inspections increases Worker and
  object-store work without serializing all transfers through one Native
  process or database object. Native job concurrency and SQL connection pools
  remain bounded.
- Transfer-size tests show that GCP outbound bytes do not scale with bytes
  uploaded, downloaded, mirrored, or parsed. Any full-object exception is
  visible and separately counted.
- Authenticated responses never enter a shared public cache. An origin outage
  cannot expose private content through a stale edge entry.

This RFC does not require an online migration from an existing Worker-only or
Native-only Hub. A deployment may be reset and initialized in hybrid mode.
The optional portable export/restore facility and its manual workflow are
specified separately in this RFC; they are not a prerequisite to the runtime
architecture.
