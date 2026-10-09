# 4. Runtime execution protocol

## 4.1. Ownership by deployment mode

| Mode | Coordinator/evaluator | Durable application state | Provider/object executor |
| --- | --- | --- | --- |
| Local | Current machine | Local journal/cache | In-process adapters |
| Native | Native shared application | Configured Native SQL | In-process Native adapters |
| Worker | Worker shared application | HubDb SQLite | Worker adapters/jobs |
| Hybrid | Native shared application | PostgreSQL | Scoped Worker executors |

There is one coordinator contract and one evaluator. Runtime adapters do not
implement independent source selection, candidate policy, advisory matching,
or result schemas. Worker-only MAY split long evaluation into resumable chunks
but MUST preserve the exact pinned inputs and final canonical result.

Hybrid Native owns schedules, inventory, provider budgets, task leases, policy,
assessment pointers, alerts, events, and SQL commits. Worker invocation state
and reconstructable caches MUST NOT become logical scan authority. Existing
Hybrid refusal of Worker logical maintenance jobs MUST remain effective.

## 4.2. Placement of computation

Workers perform lightweight provider requests, streaming downloads/hashing,
per-object parsing, bounded projection/filtering, and delivery fanout. Native
performs CPU-intensive matching, compatible-vector selection, graph joins,
global prioritization, and policy evaluation over compact admitted evidence.

The coordinator SHOULD batch related requests and deduplicate common upstream
projects. It MUST NOT send the complete package inventory to every executor
or make one cross-cloud RPC per provider record. Workers MUST NOT return full
archives, images, NARs, or aggregate advisory feeds as an implicit fallback.

A supported operation MAY return bounded metadata required for Native
verification. Its limit is independent of source size. Larger derived records
require a defined paged operation. Unsupported projections remain unsupported;
they do not become generic raw fetches.

## 4.3. Provider work route and authentication

Hybrid introduces `/_internal/assessment/v1/provider/execute` and
`/_internal/assessment/v1/capabilities`. These routes are handled before the
general Native proxy fallback. The public path is reachable but accepts only
authenticated service work. End-user tokens and browser sessions MUST NOT
authorize these routes.

Requests use a separate provider-work authentication domain and audience from
ingress and storage-work. Following RFC-0023's authenticated-plan pattern, the
signature binds method, route, canonical body hash, deployment, issuer,
audience, validity window, and nonce. TLS is REQUIRED. Replay/deduplication
uses the stable task identity; a duplicate MUST NOT acquire a fresh provider
budget reservation automatically.

The capability response is authenticated and contains protocol version,
deployment identity, executor build identity, supported adapter/profile
versions, and effective limits. Native MUST check required capabilities before
issuing work. Missing scan capabilities make scanning unavailable, not all
unrelated Hub delivery routes unavailable. A mandatory promotion dependency
remains blocked until its required scanning capability is restored.

## 4.4. ProviderWorkPlan

`aos.provider-work-plan/v1` is a closed record:

| Field | Constraint and meaning |
| --- | --- |
| `schema` | Exact identifier |
| `deploymentId`, `issuer`, `audience` | Installed paired-service identities |
| `planId`, `scanId`, `taskId` | Opaque execution references |
| `generation`, `claimToken` | SQL-issued fence and unguessable current claim |
| `issuedAt`, `expiresAt` | Validity window of at most 60 seconds |
| `nonce` | Unique request nonce bound to the authenticated body |
| `inventoryDigest`, `policyDigest` | Frozen context; no inventory body required |
| `operation` | Closed operation variant and exact adapter version |
| `authorizationPartition` | Public or tenant-scoped execution identity |
| `credentialRef` | Optional immutable permitted credential reference |
| `budgetReservation` | Source budget identity, reservation ID, request allowance and deadline |
| `cacheRef` | Optional exact prior response/validator reference |
| `continuation` | Optional source-bound continuation from an earlier result |
| `limits` | Effective source, result, item, request, duration and concurrency limits |

Operation variants initially are `observe-releases`, `observe-tags`,
`observe-go-releases`, `observe-repology`, `query-osv`, `retrieve-advisories`,
and `refresh-advisory-source`. Each variant permits only its typed source
configuration. Endpoint selection comes from the installed provider profile.
Arbitrary URLs, request headers, uploaded programs, and unrestricted predicates
are rejected before credentials are resolved or a network request begins.

Provider plans are read-observation authority, not storage-write authority.
An operation retaining raw bytes MUST use an independently scoped evidence
write admission under the existing object-storage contract. Its result binds
that receipt. Possessing a provider plan cannot select a bucket or overwrite
evidence at an arbitrary key.

## 4.5. Execution and result

The executor validates authentication, version, scope, limits, expiry, adapter
and budget before effects. It fetches an admitted page/query, parses using
shared code, retains evidence where authorized, and returns a canonical
`aos.provider-work-result/v1`:

| Field | Meaning |
| --- | --- |
| `schema`, `planDigest`, `taskId`, `generation` | Exact request/result association |
| `executorBuild`, `adapterVersion` | Actual execution and parser identities |
| `outcome` | `observed`, `not-modified`, `partial`, or typed failure |
| `observationRefs` | Ordered normalized observation/evidence references |
| `normalizedObjects` | Digest-bound canonical observations and required payload/record projections, within the result byte ceiling |
| `coverage` | Complete, through-boundary, partial, or unknown with basis |
| `continuation` | Optional exact next unreturned position/source identity |
| `usage` | Requests, compressed/decompressed source bytes, result bytes, duration |
| `completedAt` | Executor observation time, separately validated |
| `diagnostics` | Bounded sanitized errors and retry information |

Results are service-authenticated with the provider-result domain. Native
verifies exact plan binding, build/profile compatibility, source/project
identity, bounds, continuation monotonicity, and current claim before accepting
them. An expected response digest supplied in a plan is not proof that the
executor observed those bytes. Actual observed identity must be recorded.

Native receives the bounded normalized objects needed to admit and evaluate
observations into nearby SQL. A cold cache MUST NOT turn an evidence reference
into an unbounded raw-object read by Native. Missing projections require a
new admitted paged projection/retrieval operation, with explicit continuation
and the same result ceiling. Shard manifests identify the complete normalized
record set; committing a snapshot waits for all required shards. Raw feeds,
archives, and provider response bodies stay on the admitted evidence path.
An executor's object-storage receipt proves custody, while its authenticated
projection and source provenance establish the claimed observation; neither
receipt alone proves advisory truth.

Each bounded invocation can finish under one validity window. Longer work is
split into new Native-issued plans. Workers MUST NOT extend authority, choose
a different source, or independently schedule a new logical refresh.
Executor queue continuations MAY carry admitted work, but each dispatched
provider request needs valid scope and budget at execution time.

Native commits validated observations and schedules evaluation in short
transactions. No transaction is held open while a Worker makes provider calls.
Duplicate result delivery is idempotent by task/input/result identity. A
changed payload for the same completion identity is a conflict, not a retry.

## 4.6. Limits and error classes

The initial provider profile has these hard ceilings; deployments MAY tighten
them. Raising a ceiling requires a negotiated profile revision and tests.

| Resource | Ceiling |
| --- | --- |
| Encoded plan | 256 KiB |
| Encoded result page | 256 KiB |
| Queries/items in a work plan | 64 |
| Normalized entries in a result page | 128, also subject to byte ceiling |
| One normalized advisory record | 64 KiB; oversized records yield a diagnostic |
| One decompressed upstream response | 8 MiB |
| Aggregate decompressed source bytes per task | 64 MiB |
| Provider page requests per task | 10 |
| Concurrent upstream requests per task | 4, further constrained by reservations |
| Connect timeout / request timeout | 10 seconds / 45 seconds |
| Plan lifetime / executor duration | 60 seconds / no later than plan expiry |
| Identifier / ordinary string / detailed diagnostic | 128 bytes / 8 KiB / 4 KiB |

Compressed and decompressed byte counters are enforced while reading. Counts
and bytes are independent limits. An item that cannot fit alone is rejected;
it is not truncated into a valid-looking advisory. CPU/memory admission uses
runtime-specific measured budgets advertised in capabilities; exhaustion
returns `resource-exhausted` and partial coverage.

Errors distinguish `invalid-plan`, `unauthenticated`, `expired`, `superseded`,
`unsupported`, `rate-limited`, `provider-unavailable`, `source-changed`,
`malformed-source`, `resource-exhausted`, and `evidence-unavailable`.
Only documented transient classes are automatically retried. A response
timeout retains uncertain request-budget consumption; it does not release a
reservation as though no request occurred.

## 4.7. Storage inspection, evidence delivery, and cache

Stored scan metadata and SBOM inspection use RFC-0023's frozen placement,
object identity, parser, and generation fencing. New inspection operations
MUST negotiate explicit capability names and result bounds. A generic HTTP
fetch MUST NOT be added to `StorageWorkOperation` for provider convenience.

Per-object parse caches MAY coalesce repeated work, keyed by deployment,
authorization namespace, object identity, parser version, and projection.
They do not own scan history or prove that an object still exists. Cache loss
causes bounded recomputation or unknown evidence, never stale success.

Large evidence and handoff bundles are delivered through authorized Worker
or direct-storage paths. Native supplies compact manifests/grants and receives
receipts. Its data store owns semantic evidence references and status; object
storage owns admitted bulk bytes under the existing lifecycle contract.

## 4.8. Compatibility and failure

Local, Native-only, and Worker-only adapters implement equivalent task/result
contracts in process where possible. They need not serialize internal calls,
but MUST enforce the same semantic limits and conformance behavior.

Incompatible executors reject work without provider dispatch. A rolling
upgrade MUST preserve issued plans until expiry or stop issuing affected work.
Parser changes create new projections and cannot reinterpret retained evidence
under an old adapter identity.

A Native/SQL outage permits only already admitted bounded Worker work; it
does not permit new logical scans, alerts, or promotion. A Worker outage leaves
durable Native work pending/retryable. Hybrid MUST NOT route bulk reads through
Native as an automatic fallback. Last known assessments remain inspectable
with their freshness and service-health state.
