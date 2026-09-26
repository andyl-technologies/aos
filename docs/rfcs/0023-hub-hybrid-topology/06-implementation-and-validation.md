# Implementation and validation

## Delivery sequence

Each phase must keep Native-only and Worker-only modes buildable and tested.
Hybrid is a third, explicit deployment mode with one canonical Hub API; it
must not fork business rules or database queries into the edge Worker.

1. **Measure the current paths.** Capture cold and warm logged-in page traces,
   concurrent upload impact, index byte flows, request hop counts, and costs in
   staging. Record the client region, Worker colo, Durable Object location,
   request class, dataset, and test window. This is the baseline for the later
   acceptance gates.
2. **Enable Native PostgreSQL serving.** Wire the existing PostgreSQL backend
   into Native `serve` and administrative commands, add connection and migration
   controls, and qualify the Hub schema and critical transactions against a
   real PostgreSQL service. Keep local SQLite as the Native-only default.
3. **Add the hybrid edge.** Add a Worker mode whose public routes distinguish
   cacheable delivery, Worker-owned byte paths, and Native-owned control/API/Web
   paths. Implement private-origin authentication, canonical public origin and
   client context forwarding, bounded body and response handling, release
   compatibility probes, and cache invalidation after authoritative commits.
4. **Add the storage-work protocol.** Introduce typed inspection, query,
   upload, inventory, and conditional-delete contracts with bounded plans and
   results. Connect Native orchestration to the Worker executor; retain local
   adapters for Native-only and Worker-only. Validate R2 first and S3 through
   the same binding contract before claiming S3 support.
5. **Move bulk workflows.** Update indexing and publication first, then
   downloads, OCI, inventory, mirroring, and GC. Ensure each workflow's SQL
   commit checks the relevant surface and binding revisions. Add object-scoped
   parse caches only after the uncached protocol is correct and measured.
6. **Qualify and deploy staging.** Provision a fresh hybrid instance, initialize
   it, republish needed data, and run the real browser, API, CLI, Nix-cache,
   image, and OCI paths under simultaneous bulk work. Add deployment automation
   and an operator runbook for the GCP and Cloudflare halves.
7. **Add portability.** Implement the whole-Hub snapshot format and CLI restore
   checks described in [state and portability](05-state-deployment-and-portability.md).
   This phase can follow initial staging qualification. An admin UI wizard can
   follow the command and restore protocol.

## Code boundaries

The shared router and domain services in `aos-hub-core` remain the source of
API and authorization behavior. Native `aos-hub` owns PostgreSQL connection,
background orchestration, and the trusted origin server. `aos-hub-worker` owns
public ingress, safe cache and shielding, object byte paths, and the storage
executor. The storage-work request and result schemas belong in a shared,
runtime-neutral crate or protocol module. The Native caller uses a client
adapter; Worker-only can call an in-process adapter rather than HTTP to itself.

The existing `SurfaceProvider`/`SurfaceFetch` and `SurfaceWriteProvider` seams
can support local and remote adapters, but the indexer cannot remain a sequence
of full-object `fetch` calls in hybrid. Add a typed inspection/query port for
the narrow data the indexer needs, with local implementations for the existing
modes. Keep signature, trust-root, monotonic-floor, and database-commit
decisions in the canonical Hub code. Remote parse results are untrusted inputs
that Native validates before committing authoritative state.

The GCP application platform in `infra` should own the Native service and
database deployment. AOS Hub should publish the runtime configuration and
health/compatibility contracts that platform needs, without making provider
provisioning part of the request path. The Cloudflare deployment code gains a
hybrid profile for the public Worker and its object bindings. The two artifacts
carry compatible protocol versions and one deployment identity; a mismatched
pair fails readiness rather than serving partially.

## Acceptance gates

The initial staging test must exercise a simple logged-in page, parallel
multipart uploads to the same registry and to several registries, large
immutable downloads, indexing a full release, inventory, and GC. At minimum,
record p50/p95/p99 time to first byte, throughput, errors, SQL pool usage,
cross-cloud request count, bytes on each hop, cache hits, Worker CPU and
duration, and object-store requests. Compare with the current Worker-only and
Native-only baselines under the same data and client region.

- A simple warm authenticated page should reach p95 time to first byte below
  500 ms and p99 below 1 second from the primary test region. A parallel upload
  run should not raise its p95 by more than 25% over the no-upload baseline.
  If the target is missed, the measured stage and hop must be identified before
  hybrid is promoted.
- No complete bulk object body (NAR, image, bundle, OCI layer, upload, or
  mirror copy) may transit Native in hybrid. An explicitly bounded signed
  metadata payload or object slice needed for Native verification is allowed
  and measured. GCP outbound storage traffic consists of bounded plans and
  control responses; inbound storage traffic consists of bounded projections
  and verification inputs. Measure response-size distributions and alert on
  unexpectedly large storage-work payloads.
- Indexing must show bounded, batched cross-cloud work; the number of
  Native-to-Worker calls and bytes must be recorded per release. Large bundles
  must be parsed or projected on the storage side. The same signed fixtures
  must produce identical authoritative indexes across all runtime modes.
- Concurrent uploads must not serialize through a single Durable Object or
  database transaction while bytes are moving. A publication or inventory
  pointer changes only after object verification and an authoritative commit.
- Public immutable cache hits may survive a Native outage if their identity
  and authorization are independently valid. Authenticated control and private
  reads fail closed when Native or its authorization state is unavailable.
  Storage-work plans with expired or stale binding generations are rejected.
- Native-only and Worker-only retain their existing public API semantics, URL
  shapes, authorization behavior, and storage integrity checks. Cross-mode
  contract tests run from the same fixtures and compare observable results.

The byte budget is a launch gate, not a promise that another provider's egress
is free. R2 and S3 have different transfer and request economics; the measured
report must attribute each provider and each cloud boundary separately.

## Failure and recovery tests

Inject a Native origin outage, PostgreSQL outage, Worker storage executor
outage, R2/S3 timeout, stale placement revision, expired work plan, partial
multipart upload, duplicate result delivery, cache eviction, and Worker
revision mismatch. Verify that retries use idempotency keys, stale results do
not commit, GC cannot delete a newly rooted object, private content does not
fall through a public cache, and operators can identify the stalled job and
resume or abandon it. Trace one request or job across the edge, Native,
PostgreSQL, storage executor, and object store without logging credentials or
private object contents.
