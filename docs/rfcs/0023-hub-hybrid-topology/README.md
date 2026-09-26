# RFC-0023: AOS Hub hybrid runtime topology

- **Status:** Proposed (implementation in progress). Portable whole-Hub
  snapshots remain a later phase.
- **Date:** 2026-09-24.
- **Audience:** AOS Hub, Cloudflare Worker, GCP application platform, storage,
  security, and operations implementers.

## Summary

AOS Hub supports Native-only and Cloudflare Workers-only deployments today.
This RFC adds a third mode: a Cloudflare Worker fronts every public Hub
authority, while one logical Native Hub service on GCP owns the canonical API,
authenticated website, indexing decisions, and PostgreSQL system of record.
The Worker shields and caches eligible public traffic, serves bulk object bytes,
and exposes an authenticated storage-work API that lets Native fan out bounded
inspection and mutation jobs over R2 or S3 bindings. Native receives compact
results and commits authoritative state; it does not carry uploads, downloads,
entire store objects, or mirrored bytes through GCP.

```text
  browser / CLI / Nix / OCI client
                |
                v
       Cloudflare Worker (public edge)
        /           |             \
  safe cache   object bytes    API / HTML proxy
                  |                  |
             R2 or S3         Native Hub on GCP
                                  |       |
                           PostgreSQL   indexing/jobs
                                           |
                                           v
                              authenticated storage-work API
                                           |
                                   Worker object executor
                                           |
                                        R2 or S3
```

The Worker and Native service are one Hub deployment, not two independently
authoritative Hubs. “One Native service” means one logical application and
database authority; multiple stateless request replicas are allowed. The
storage executor can initially live in the public Worker deployment and later
be separated behind the same versioned protocol if placement or load warrants
it. An object-scoped Durable Object may cache a verified parse or coalesce
work for one immutable object, but it never owns relational Hub data.

## Decisions

| Question | Intended state |
| --- | --- |
| Who serves the website and primary API? | Native's shared Hub router renders authenticated pages and handles the canonical API. The Worker is the public ingress, serves static assets and eligible cache entries, and proxies other control requests. |
| Where is relational state? | Native uses one Cloud SQL PostgreSQL system of record in the hybrid baseline. Workers-only retains HubDb SQLite; Native-only retains its local SQLite default. |
| Where do large bytes travel? | Between clients, Worker storage adapters, and the selected R2/S3 placement. They do not transit Native in hybrid mode. |
| Where does indexing run? | Native schedules work, applies trust and anti-rollback rules, and commits the index. Worker storage compute parses, filters, and verifies objects and returns bounded projections or signed payloads required for Native verification. |
| How are uploads and GC controlled? | Native owns admission, policy, durable jobs, and SQL commits. Worker storage compute handles bytes, inventory, conditional mutations, and evidence. |
| Is an online topology migration required? | No. The first hybrid staging instance may be reset and initialized. A portable whole-Hub snapshot/import is a later phase in this RFC, with an optional admin UI workflow. |

## Boundaries and invariants

The hybrid runtime is a deployment topology, not a new kind of RFC-0012
surface placement. Existing surface identity, binding revisions, write
authority, access policy, and route generations remain authoritative. The
Native-to-Worker storage protocol accepts only typed, bounded operations
fenced to those revisions. It is not a remote SQL interface or arbitrary
compute service. Every Worker result is checked before it changes SQL state.

Hybrid must preserve Native-only and Workers-only as complete modes. Shared
business rules and wire protocols retain one implementation or a tested common
contract. Public cache entries and object-scoped parse caches are disposable;
neither may authorize a private read or a publication. A stale edge, Native,
database, or object-store component fails the affected operation closed.

Performance and cost are design constraints. The implementation must measure
authenticated page latency during parallel uploads, storage-work call counts,
object bytes by network boundary, Worker execution, PostgreSQL pool pressure,
and provider-specific egress. A hybrid deployment is successful only if the
large-object paths stay off GCP and the logged-in experience improves under
representative load. The exact staging gates are in
[implementation and validation](06-implementation-and-validation.md).

## Documents

| File | Contents |
| --- | --- |
| [`00-goals-and-invariants.md`](00-goals-and-invariants.md) | Runtime modes, authority, byte movement, performance goals |
| [`01-runtime-routing-and-authority.md`](01-runtime-routing-and-authority.md) | Worker ingress, Native API/Web origin, cache/shield, trusted proxy, failure behavior |
| [`02-storage-work-protocol.md`](02-storage-work-protocol.md) | Bounded plans, results, authorization, binding fences, storage adapters |
| [`03-object-compute-and-lifecycle.md`](03-object-compute-and-lifecycle.md) | Parsing and queries near objects, optional object-scoped Durable Object cache, expiration and GC |
| [`04-workflows.md`](04-workflows.md) | Indexing, upload, download, OCI, inventory, GC, mirror, and parity data paths |
| [`05-state-deployment-and-portability.md`](05-state-deployment-and-portability.md) | PostgreSQL ownership, first deployment/reset, later portable snapshot/import and admin workflow |
| [`06-implementation-and-validation.md`](06-implementation-and-validation.md) | Code boundaries, delivery phases, measurable gates, and failure tests |
| [`07-decisions-and-considerations.md`](07-decisions-and-considerations.md) | Alternatives, costs, risks, and bounded open decisions |

## Relationship to existing designs

This RFC extends [RFC-0004's Hub](../0004-registry-hub/README.md) and shared
Native/Worker runtime. For **hosted hybrid** deployments it supersedes the
proposed relational-data placement in RFC-0004's
[colocated storage chapter](../0004-registry-hub/14-colocated-storage-architecture.md);
that chapter remains historical context and does not change the complete
Workers-only mode. It composes with [RFC-0012's logical surface
topology](../0012-hub-surface-topology/README.md),
[RFC-0019's OCI contracts](../0019-oci-containers/README.md), and
[RFC-0017's canonical publishing and production gates](../0017-canonical-hub-publishing/README.md).
The current [hosted backup runbook](../../maintainers/aos-hub-backup-recovery.md)
describes what can be recovered today; this RFC's portable snapshot is an
intended capability, not a claim that the current Hub already has one.
