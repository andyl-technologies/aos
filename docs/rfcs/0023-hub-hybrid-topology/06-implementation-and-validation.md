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
pair fails readiness rather than serving partially. Infrastructure registration
also owns the Cloudflare buckets, upload CORS, lifecycle rules, verification
queues, and automated credential bootstrap described in the
[deployment contract](05-state-deployment-and-portability.md#cloudflare-resource-provisioning).
Provider module tests and emulated fleet tests qualify configuration and local
behavior separately from the final hosted provider and performance gates.

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

### External admission scale and safety

Managed external execution is a separate launch gate. Metadata publication,
Watermark, SQL acknowledgement or the fixed-ledger foundation alone cannot pass
it. Declare the execution policy, protocol/key boundaries and each workload's
accepted throughput/latency/error envelope before qualification.

For bounded leases, record configured TTL `T` and actual renewal interval `R`,
minimum/maximum allowed TTL, qualified clock/dispatch uncertainty, maximum active
exact renewal cohorts `C`, cache/region/isolate cold-start fanout,
refresh retry bounds and a measured issuer RPC/CPU/durable-commit budget with
headroom. Steady renewal is approximately `C/R` calls per second, not a request
per object. The ideal `C/T` model applies only to expiry-spaced renewal; early
renewal/jitter can make `R < T`. Duplicate caches and cold starts increase calls.
The cohort includes
association, purpose, executor, prefix and effect restrictions. Test:

- Steady traffic at the declared maximum `C`, using the shortest configured TTL;
  renewal coalescing/jitter must fit the measured issuer budget and preserve
  concurrent control/cutoff latency. Also test the largest TTL and attestation
  expiry cap to establish the actual longest revocation window.
- Simultaneous cold cohorts, regional/isolate startup and retry storms at the
  declared fanout. Record actual renewal calls, queue time and p50/p95/p99,
  signature CPU, bytes and commits. No assumed fleet-wide shared cache; no
  unbounded refresh retries or issuance from a cached/unsigned epoch.
- Many independent keys plus declared worst per-key/session bursts, tiny-object
  writes and parallel multipart parts. Trace actual stage latency and RPCs:
  ordinary leased effects have no global identity or per-effect issuer round
  trip, and no gate holds streaming bodies serially. Bound each hot guard/session
  and record backpressure/errors rather than claiming unlimited bucket scale.
- An issuer outage through token expiry, verifier/key rotation, lagging or rolled
  back clocks, and executor pause at the final expiry check. New dispatch fails
  closed when time/continuation bounds or renewed tokens cannot be established.

Correctness qualification injects denial before/after issuance, lost issuance
replies, old lease use at unseen and advanced keys, same-generation forks,
cutoff/reopen and credential rotation while an old key has unknown late provider
I/O. The recorded cutoff must include every issued token; it never reports drain.
Prove other eligible keys resume only after cutoff and reviewed exclusivity,
while unknown keys, incarnations and receipts survive. Exercise duplicate part
attempts, session freeze against in-flight parts, unknown create/abort/completion,
receipt-persistence failure, byte-identical recreation, SQL restore and actual
runtime restart/persistence. A provider HEAD or TTL must settle no unknown effect.

Audit every Native-only, Worker-only and Hybrid producer, retained writer,
alternate alias and presigned path at actual dispatch. Uncoordinated writers and
already issued bypass capabilities must be excluded before managed activation.
Prove issuer private-key isolation, verifier-only object execution, exact ordinary
application authorization and all immutable input projections. Direct final-key
presigned PUT and unqualified staged/part alternatives must reject. Preserve
permanent namespace/identity/key history through partition migration; empty
journal adoption must reject. A full drain claim additionally requires complete
partitioned guard-directory settlement, never SQL/provider listing alone.

Qualify immediate reservation separately for any strict purpose, including its
Begin/Settle rate, unresolved accounting and generation rollover costs. Neither
policy enables external DELETE until every visible writer, frozen stamp/grant/
claim/receipt chain and actual provider deletion semantics are qualified. Publish
measurements by configured policy and purpose; no successful metadata fixture
or performance model substitutes for these runtime/provider gates.

The byte budget is a launch gate, not a promise that another provider's egress
is free. R2 and S3 have different transfer and request economics; the measured
report must attribute each provider and each cloud boundary separately.
Application accounting must retain offered plans and observed response-body
bytes when an exchange is cancelled or its result is rejected. Keep this
accounting separate from validated-result and storage-source counters, mark
HTTP error bodies that were discarded unread, and use provider telemetry for
framing, internal prefetch, and actual billed wire usage. Offered request bytes
are not proof that the destination received them.

## Direct-upload launch gates

Qualify the actual managed R2 and external S3/R2 provider independently. The
common staged client/server path must transfer parallel out-of-order parts,
resume a sparse session after process/runtime restart, preserve exact operation
replay, and reject changed source/geometry/revision. Test checksum corruption,
full-SHA/composite-checksum confusion, embedded completion errors, lost create,
close, promotion and abort acknowledgments, receipt-persistence failure and
same-number part replacement. Retained unknown state must survive clock expiry,
SQL restore, credential rotation and provider HEAD/listing.

Exercise the actual signed UploadPart capability after successful completion and
abort, including an already started request racing completion. Prove completed
staging/final bytes remain immutable under the selected materialization contract;
an S3 emulator or another provider's documentation cannot qualify R2. Distinguish
upload-ID closure and exact final publication from eventual resource reclamation
and account for acknowledged abort with still-running part uploads. Do not enable
external final-key DELETE solely because staged upload tests pass.

Use the real publisher command with thousands of small independent metadata
files and large multipart objects. Record active transfers, source spool memory,
aggregate grant/control bytes, RPC/provider request count, batch refusals,
p50/p95/p99 stage latency and dependency visibility ordering. Demonstrate batched
control rather than per-file/per-part serial Native calls. Browser gates cover
exact-origin CORS, required checksum headers, ETag exposure and expired grants;
CLI gates cover interruption/checkpoint resume and redacted failures. A Native
body that fails if polled must be refused before consumption even with forged
phase headers. Captured Worker-origin requests contain bounded metadata only;
verify actual GCP ingress/egress stays metadata-sized through upload, hash and
promotion. No unavailable-capability test may pass by proxying bulk bytes to
Native. Report configured direct-provider readiness separately from intended
RFC state and preserve all failed qualification artifacts.

Qualify foreground and queued verification separately on the actual Worker
runner and each intended provider. For queued work, include an object above the
measured foreground budget, a consumer restart, lost enqueue and completion
acknowledgments, conditional-read source replacement, Native authorization
revocation, and expired machine delegation. Measure the whole consumer
invocation's wall and CPU time, memory, bytes read from storage, and bytes sent
to Native. Prove that a pending status never starts another provider upload or
crosses the publication barrier. A platform time limit alone does not qualify
an object size or authorize a retry after an unknown read effect.

For thousands of small metadata objects, measure bounded queue send batches and
Native read-evidence pages alongside actual object concurrency. A one-object
consumer setting for large archives is not evidence of metadata throughput.

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
