# Storage work protocol

Hybrid mode gives the Native Hub one system of record and gives Workers the
object-store data plane. The Native Hub decides what work is authorized, which
physical placement to use, and what the result means. A Worker opens the
selected R2 or S3-compatible object, performs bounded storage-local work, and
returns a compact result or serves the bytes to their final consumer. This
boundary is a versioned protocol, not a second Hub database or an invitation to
run arbitrary code beside the bucket.

## Boundary and execution model

The public edge and storage executor may initially be one Worker deployment.
Their routes are nevertheless separate: public delivery requests go through
the edge router, while `/_internal/storage/v1/*` reaches an authenticated
storage executor before any Native proxy fallback. The endpoint is reachable
over HTTPS so the Native Hub can call it from GCP, but possession of the URL
does not authorize a request. A deployment may later run multiple storage
executor Workers with the same protocol and storage bindings. No executor
requires an affinity to a particular Native replica.

The Native Hub owns reviewed desired admission, authorization, quotas, the index
generation, anti-rollback floors, jobs, durable claims, and SQL commits.
The executor owns
provider I/O, byte verification, parsing of supported storage formats, and
bounded filtering or aggregation. It cannot update Hub SQL. Each result names
the exact plan, operation, selected placement, physical object identity,
parser version, and bytes observed. Native accepts a result only for the
generation and placement it issued, then applies existing policy and commits
the result transactionally.

The protocol permits three kinds of output:

1. **Small semantic result:** selected fields, matches, counts, hashes, and
   proof metadata needed for an index or inventory decision. Result size is
   capped independently of the source object size.
2. **Bounded page:** an ordered page and opaque continuation token for a list
   or a large result set. Native explicitly asks for subsequent pages.
3. **Byte delivery:** a stream to an authorized client, another object store,
   or an explicitly selected destination. Native receives the final receipt,
   never the stream body in hybrid mode.

No operation may silently return a whole source object to Native when its
projection is too large or unsupported. It returns a typed limit or unsupported
error, allowing the caller to choose a narrower plan, split the work, or report
that the workflow needs implementation. This is the enforcement point for the
hybrid GCP egress budget.

## Direct upload control and delegated capabilities

Public GetCapabilities distinguishes direct-required upload support from legacy
transport, including the exact supported providers, negotiated checksums and
control limits. An unavailable, invalid or expired capability response stops
direct-required publication with an actionable configuration error; the client
does not silently switch to a Native body route.

DirectUploadService uses closed, versioned bounded batches for session admission,
status, part grants/reports, completion and abort. Public callers authenticate
through the ordinary Hub authorization contract. Native resolves scope, quota,
required placements, full expected digest/length, dependency phase and immutable
binding revisions. A signed storage admission binds the deployment/executor
identity, public method/path, request nonce/body hash, issue/expiry times, logical
session and immutable intent fingerprint before the Worker creates provider
state. Reauthorization or a narrowly scoped session capability is explicit;
possessing an unsigned session ID never authorizes part grants or completion.

Grant responses name the exact PUT method, provider URL, required headers, part
number/offset/length, grant fingerprint and expiry. Bearer URLs and provider
credentials stay request-local and are redacted from errors, Debug, checkpoints
and durable records. Signing credentials live only at storage execution; a
Native primary API does not need them. Deployment R2 S3 credentials must be
qualified against the actual R2 binding, while external credentials must resolve
the approved authority/association and immutable revision. A request cannot
supply a new bucket, endpoint or physical namespace. Each per-session coordinator
retains compact effect/grant/part records; no upload body enters its journal.

Signed completion evidence binds the logical request and frozen manifest, exact
placement/binding revisions, independently observed full digest/size and guarded
final incarnation/promotion operation. Native rechecks every item before SQL
commit. Batch limits bound item count, aggregate encoded bytes, provider fanout
and response bytes separately. Controls accept at most 64 sessions/items and
256 KiB of encoded data; grant/report/status pages contain at most 64 actual
part descriptors after required-placement fanout, with at most 16 placements
per session. Count limits do not imply that every maximum-length combination
fits the byte limit. Completion carries compact per-placement part counts and
domain-bound canonical manifest digests rather than an unbounded full part
list; sparse status/receipt pages preserve that same 64-descriptor bound.
Per-item unknown/refused results cannot advance
another item's visibility barrier or manufacture a batch success. Direct mode
has no per-part Native admission/completion RPC and no bulk-body origin fallback.
Delegated staging remains governed by the capability and unknown-outcome
requirements in the object lifecycle chapter; an admission signature is not a
claim that the provider enforces a fresh issuer lease at URL use.

## Native-issued work plans

`StorageWorkPlan` is a closed, versioned request body authenticated with a
short-lived Native service credential. A canonical encoding binds the signature
to the HTTP method, route, request body hash, audience, issuer, issue and expiry
times, nonce, and deployment identity. The Worker validates the caller and plan
before opening storage. Clock skew allowance and maximum lifetime are small;
neither a browser session nor a public API token may call these routes.

```text
StorageWorkPlan v1
  plan_id, operation_id, idempotency_key
  issuer, audience, deployment_id, issued_at, expires_at
  org_id, surface_id, registry_id (where applicable)
  placement_id, placement_resource_version, observation_version
  binding_id, binding_resource_version, binding_revision
  binding_snapshot_revision, credential_references (purpose and generation)
  placement_prefix, operation_kind, object_selector
  expected_object_identity, parser_schema_version
  projection, filters, page_cursor
  limits: objects, source_bytes, result_bytes, CPU, duration, fanout
```

`object_selector` is a canonical surface-relative path or a restricted prefix
and range, never an arbitrary URL. The executor joins it to the frozen
placement prefix using the same normalized key rules as public delivery. It
rejects path traversal, encoded separators, another tenant's prefix, and a
selector outside the operation's admitted namespace. A plan cannot select the
current writer implicitly or substitute a healthier placement.

The placement and binding fields carry the [RFC-0012](../0012-hub-surface-topology/01-domain-model.md)
resource fences. A binding snapshot is a signed, revisioned, nonsecret
description of provider kind, endpoint, bucket, prefix, capabilities, and the
exact credential reference that the executor may resolve. Workers receive
these snapshots and purpose-scoped secrets through an authenticated control
channel or deployment bindings; they do not query the Native SQL database on
each object read. A plan naming a missing, expired, or different snapshot or
credential revision fails closed. The Worker never receives a storage secret
inside a work plan or returns one in a result. `deployment_r2` resolves to its
bound R2 bucket; portable `r2` and `s3` bindings resolve to an admitted
S3-compatible endpoint and exact purpose-scoped credential revisions. A
compound read/write operation names both revisions in canonical purpose order.

Snapshot distribution is part of topology reconciliation. Native publishes a
new immutable snapshot before issuing plans for its revision, waits for the
executor to acknowledge availability, and withdraws retired or revoked
revisions from future use. For managed external storage, coordinate, prefix,
writer and credential changes also close execution admission under the reviewed
policy below. A SQL head change or snapshot withdrawal alone cannot revoke a
previously issued lease or settle provider I/O. Execution cutoff and terminal
settlement are separate results; waiting for a plan or lease to expire establishes
neither settlement nor safe receipt retirement. A binding snapshot alone never
provides execution authority.
External S3 storage may be far from Cloudflare compute and may
charge provider egress. Such placements remain supported, but their read
location, transfer cost, and latency must be measured; the protocol does not
promise R2-like locality for every binding.

The Native Hub rechecks the relevant placement, binding, authority, and job
generation before accepting a result. Worker-side validation prevents
unauthorized provider I/O; Native-side validation prevents an old result from
changing current state. Existing `FrozenSurfaceAccess` and conditional-delete
claims are the model for destructive operations. A delete plan additionally
requires the reviewed inventory identity, strong provider condition, and
durable claim ID. The executor never turns a conditional mismatch into an
unconditional retry.

Deployment R2 executors advertise `r2_gc_incarnation_v1` in the authenticated
capability reply. Native requires this capability before pairing with a Worker
for versioned GC. Inventory hashing, pagination and reuse retain the provider
upload version observed with the source bytes; Native carries that same version
through SQL inventory, reviewed actions, claims and signed execution plans.
Matching bytes, size and ETag alone do not identify a particular upload.

The `expected_provider_version` member is always present in both the outer
destructive operation and its inner claim, including an explicit JSON `null`
when no version is recorded. Older closed schemas reject that member instead
of executing a weakened request during a mixed-version deployment. A fresh R2
delete requires a recorded version. An existing terminal receipt is replayed
before that requirement is checked, so legacy completed actions remain
recoverable without repeating provider effects.

## Managed external execution admission

Managed external effects use a separately negotiated, closed admission protocol.
The execution policy is part of the reviewed authority/executor contract:
`bounded_lease` with a maximum TTL and qualified clock/dispatch uncertainty, or
`immediate_reservation` for an explicitly selected purpose. Missing, unknown or
incompatible policy fails closed. Current signed publication and nonce-bound
Watermark replies deliver metadata; they are not reusable execution permits.
The current fixed ledger is a metadata implementation foundation and does not
activate this intended execution protocol or qualify existing direct adapters.

A bounded lease names its protocol version and issuer key, deployment audience,
permanent physical authority and guard namespace, exact executor, admission
generation/digest and publication digest, immutable association/address/prefix
projection, selected purpose and credential-member identity, allowed effect
kinds, issuance time, absolute expiry and monotonic issuance sequence. Credential
identity includes its exact reference, generation and fingerprint, never secret
bytes. The DTO/envelope is closed, canonically signed and byte-bounded; it admits
no unconstrained purpose/executor privilege, arbitrary URL or Native SQL lease
token.

Only the durable per-authority issuer can sign. It checks its current admitted
head, fresh exclusivity time and exact selected cohort, caps expiry by both the
reviewed TTL and attestation expiry, and atomically retains the largest issued
expiry and sequence before returning a token. Lost replies cannot hide a token
from denial accounting. The signing key is issuer-only; object executors hold
verifier material. Native's metadata HMAC key, a restored SQL image, cached
publication or an offline signer cannot mint fresh execution authority. Isolate
the issuer deployment when a shared script would expose its secret to ingress
or object code; a DO class name alone is no key isolation boundary. Lease,
issuance-response and denial-event signatures use separate domains. Key rotation
preserves verifier history for retained leases/receipts without creating a new
empty journal or extending an old token's validity.

Reuse a token only within its exact association/purpose/executor/prefix/effect
cohort. Trusted caches may coalesce issuance and serve a still-valid older token
within the explicit bounded policy; they cannot extend expiry or turn cached
metadata into fresh admission. Every effect still requires application-authorized
canonical full-key selection, the retained binding/credential projection and the
operation's own plan, ticket or reviewed delete grant. A cohort lease alone is
not user permission for arbitrary Hub resources. Object guards independently
validate these inputs and their permanent address. Terminal result replay precedes
new lease admission and performs no provider I/O.

Under `bounded_lease`, denial atomically stops new issuance and records the
largest prior expiry. Previously issued valid tokens can admit local dispatch
until the conservative recorded cutoff, including qualified clock/dispatch
uncertainty. A signed denial event can raise an individual guard's durable floor
earlier, but cutoff correctness cannot depend on fanout reaching every key.
"Lease admission cutoff reached" does not mean "provider execution drained";
an already invoked request can arrive or complete later. Lease expiry never
clears pending effects. Without a qualified time/continuation bound, bounded
revocation cannot be enabled. The immediate policy and object-local rules are
specified in [object lifecycle](03-object-compute-and-lifecycle.md#scalable-external-execution).

### Retained external cleanup grants

Applying OCI GC claims use a separate signed cleanup envelope when their
original delete credential is no longer the current binding generation.
Native validates the SQL claim, credential hold, frozen placement and binding
revision, and observed provider capability before issuing it. This does not
republish the retained credential or restore ordinary read/write authority.

The version 1 envelope admits only HEAD or conditional DELETE for one canonical
OCI blob key. It carries the stable action identity, current claim token and
lease, frozen access fence, reviewed digest, size and strong ETag, and exactly
one retained delete credential through private transport. The envelope is
limited to 16 KiB and 30 seconds, cannot outlive the claim lease, and uses a
separate HMAC domain from ordinary storage work. Workers must not cache its
secret material or pass it to binding publication. No list, body download,
alternate key, write or multipart operation is admitted.

The stable receipt fingerprint excludes request IDs, claim tokens, validity
times and secret bytes, so renewing a lease cannot repeat a settled physical
deletion. It retains the frozen address, reviewed object identity and credential
reference. Reusing an action identity with a changed fingerprint fails closed.
Wire validation proves request scope and integrity; it does not replace Native
claim checks or positive observation of provider deletion semantics. Persistent
pending mutations and terminal receipts still coordinate every visible writer
for the same physical key.

External S3 conditional deletion requires an actual non-null provider version,
strong ETag and exact size. The version selector and `If-Match` header are both
signed; ordinary current HEAD metadata must still match before DELETE. An
identical ETag on another version cannot substitute for the reviewed version.
Unversioned providers and external R2 endpoints without these semantics refuse
this operation. Managed R2 keeps its existing guard-backed deletion protocol.

The executor additionally selects an independently configured delete cohort
from `HUB_EXTERNAL_OBJECT_CONSUMER` and its matching issuer installation from
`HUB_EXTERNAL_DELETE_CONSUMER`. That latter closed configuration retains
`versioned_conditional_delete_evidence_digest`; it grants no provider capability
by itself. The existing renewal service and independent keys are required, with
no automatic credential, binding or issuer creation. Used physical guard
configuration remains immutable; adding a cohort cannot rewrite old journals.

The capability probe uses only its reserved key and at most four KiB. Its
negative case targets the current version with the previous ETag, so providers
that ignore `If-Match` cannot pass through a HEAD-only check. Positive cleanup
can remove the two exact probe versions, and must then observe absence. Hashing
runs beside storage; Native receives metadata, never the probe read body.
Read/write probe cohorts must separately cover these bounded operations.

Frozen deletion uses the closed `frozen-delete-custody` wrapper over the existing
SQL claim, adding its actual provider version. Exact terminal lookup precedes
renewal or retained-material resolution. An unresolved turn rejects even a
renewed claim; no timeout, HEAD, mismatch or transport retry clears it. Provider
qualification remains a separate launch gate from these implementation and
fixture contracts.

## Closed operation set

The first protocol version has explicit operation families. Each has a schema,
purpose-specific capability, source and result limits, and a documented
idempotency rule.

| Operation | Worker execution | Native result |
| --- | --- | --- |
| `head` and `list_page` | Inspect provider metadata or enumerate a placement prefix in bounded pages | Exact object version, size, presence, and ordered keys |
| `inspect_registry` | Fetch and verify selected Git loose objects, bundle entries, channel partitions, or signed semantic files | Typed fields needed by the shared indexer, with source digest and parser evidence |
| `inspect_metadata_objects` | Read up to 32 ordered, unique admitted metadata paths beside storage | An ordered page of exact bounded documents and provider identities, with explicit absent entries |
| `inspect_oci` and `inspect_cache` | Parse admitted OCI descriptors, manifests, closure metadata, narinfo, or other versioned small semantic formats | Typed, bounded catalog or index projections |
| `inspect_documentation_content` | Read and verify one signed single-file documentation NAR, then parse its canonical document once | Closed documentation model of at most 4 MiB plus a 1 KiB result envelope; Native rechecks signed content identity, with no NAR bytes or generic source fallback |
| `filter_object` | Apply an admitted schema-specific predicate and field projection to one verified object | Matching records or an ordered page, not source bytes |
| `verify_object` | Stream source bytes locally while hashing and checking expected identity | Digest, size, version, and placement evidence |
| `copy_object` | Stream from a selected source placement to an authorized destination | Destination identity and verification receipt |
| `put_metadata` | Write a Native-authored Nix base32 narinfo of at most 128 KiB through the object-scoped storage guard after checking its exact SHA-256 | Bounded acknowledgment; Native verifies the stored object before committing its write ticket |
| `delete_if_matches` | Use the reviewed conditional-delete capability and exact object condition | Provider acknowledgment and independently observed evidence |

Client upload bodies enter through Worker upload routes or separately qualified
staged direct-storage grants, using Native-issued tickets. Managed direct
presigned final-key PUT and unqualified part URLs fail closed; see
[multipart coordination](03-object-compute-and-lifecycle.md#multipart-and-presigned-paths).
They are not sent from
Native in a `StorageWorkPlan`. The executor's write, multipart completion,
abort, and final verification operations use those ticket constraints and
return receipts to Native before any SQL publication commit. Their wire
schemas and idempotency rules are part of the storage protocol even though
the client supplies the bytes on a separate route.

The operation names describe intended state, not a claim that all parsers or
provider combinations exist today. The first implementation should cover the
actual indexer's object classes and its largest data-transfer paths, then add
formats deliberately. Predicates are a typed, schema-specific expression such
as selected package names or Git OIDs; there is no general SQL, JavaScript,
Wasm upload, regular-expression program, unrestricted field path, or arbitrary
HTTP fetch. An unsupported predicate fails rather than forcing a full-object
return.

### Indexer integration

Today `aos_hub_core::indexer` consumes `SurfaceFetch`, whose `fetch` and
`fetch_bounded` methods return bytes. `ObjectReader::preload_bundles` can read
an aggregate bundle or up to 256 shard bundles before a walk. Simply placing
an HTTP implementation of `SurfaceFetch` between Native and R2 would send
those bundles into GCP and retain the cross-cloud round trips this topology is
meant to remove.

Introduce a typed `SurfaceInspection` port alongside `SurfaceFetch`, with
local adapters for Native-only and Workers-only modes and a remote adapter for
hybrid mode. Refactor the indexer's object reader and semantic loaders to ask
for verified objects or projections by identity in batches. In hybrid mode,
the executor selects bundle entries and parses them beside storage; it returns
only the requested decoded objects or narrower index fields. The Native Hub
continues to resolve trust anchors, verify signed claims where the compact
inputs permit it, enforce the rollback floor, choose the index snapshot, and
commit SQL. Where a large object cannot be cryptographically checked from its
projection, the Worker performs the byte-level hash and parser checks using
shared code and returns authenticated observed evidence. Native does not infer
verification from a filename or a claimed expected digest.

Batch plans amortize cross-cloud latency. A plan may contain several explicit
selectors within one placement and one parser family, subject to per-plan
limits. The executor may fan out storage reads within its own subrequest and
CPU budgets or enqueue bounded follow-on work with durable results. Native
does not make one GCP-to-Worker call per package or per channel partition.
Results preserve deterministic order so retries produce the same logical
snapshot. Existing index caps, including branch, release, package, listing,
and semantic-object limits, remain upper bounds rather than being replaced by
larger remote limits.

Channel refresh uses `SurfaceFetch::fetch_metadata_batch`. Local adapters read
the batch concurrently; the hybrid adapter issues `inspect_metadata_objects`
plans instead of one cross-cloud call per partition. Each plan names a sorted,
unique set of at most 32 admitted metadata paths and a cursor into that set.
The Worker returns a nonempty contiguous prefix of the remaining observations,
including explicit absence, and the exact first unreturned position. Native
rejects omitted or reordered positions, nonadvancing cursors, another source
key, malformed bodies, and inconsistent byte counts before retaining a page.
It restores the caller's input order after assembling all pages.

Individual documents and the aggregate decoded bodies in one page are bounded
at 128 KiB; the serialized result, including provider identities and base64
encoding, is bounded at 256 KiB. Pagination preserves the existing maximum
document size. The Worker may read the remaining batch concurrently before
packing a page, so source-byte accounting includes documents deferred to the
next page; a later page may reread those documents. Fanout and retries remain
bounded, and this work does not return bulk storage objects to Native. Mutable
channel documents retain their existing per-object observation semantics;
batching does not claim an atomic snapshot across partitions. Native verifies
each channel signature, name binding, tag target, and anti-rollback floor
before committing the complete refresh.

The executor advertises this operation in its authenticated capability reply.
A hybrid Native Hub requiring metadata batching remains unready when the
paired Worker lacks that capability.

## Idempotency, failures, and compatibility

Read and inspection plans are safe to retry against the exact object version.
Mutating plans require a durable Native operation ID and an executor-side
idempotency receipt or a provider condition sufficient to prove a repeated
attempt safe. A retry may resume a page or operation but must not select a new
object version under the old plan. Native verifies receipts before marking a
job complete. Expired plans are reissued from current SQL state; they are not
extended by Workers.

Results distinguish absence, version mismatch, authorization failure, quota
or limit exhaustion, unsupported operation, transient provider failure,
verified corruption, and an uncertain mutation outcome. Native may retry only
the documented transient classes and only while the placement and object
fences still match. A partial page or response cannot be committed as a
complete inventory. A placement change, key rotation, credential revocation or
executor protocol mismatch stops Native issuance/commit of affected work until
a compatible new plan is issued. Previously admitted external dispatch remains
subject to its physical lease cutoff and permanent pending fence; stopping SQL
orchestration does not establish provider settlement.

The Native and Worker deployments exchange supported protocol and parser
versions at startup and expose them in health status. The Native Hub issues
only operations supported by the deployed executor; the Worker rejects
unknown fields and newer incompatible versions. Rolling a Worker independently
must preserve already issued plan versions until their short expiry, or the
Native Hub must stop issuing work during that window. Each work call records
plan ID, operation class, placement and object identity, source bytes read,
result bytes sent to Native, duration, cache status, and error class without
logging credentials or sensitive payloads.
