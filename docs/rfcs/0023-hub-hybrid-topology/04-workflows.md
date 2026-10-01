# Workflows and data movement

Hybrid mode gives the Native Hub authority over users, policy, SQL state,
publication, indexing decisions, and durable jobs. The public Worker handles
client-facing object bytes and invokes a storage executor near each supported
binding. The executor can be part of the public Worker deployment or a separate
Worker service; that choice does not change the ownership contract. Native sends
bounded, authenticated work requests and receives bounded evidence or query
results. It does not relay entire objects, upload bodies, or object copies
through GCP.

Native-only and Workers-only remain complete deployment modes. They run the
same shared Hub policy and format code with local implementations of the storage
ports. Hybrid mode supplies remote implementations of those ports. A feature is
enabled only where its selected binding and runtime have the required storage
capabilities; hybrid mode does not silently fall back to a bulk Native transfer.

## Common execution contract

Every storage operation names a surface, exact placement and binding revision,
restricted object selector, operation, result limit, deadline, and idempotency
key. Reads name an immutable content identity or a provider version where
available. Mutable pointers are read with an observed version and checked
again before Native commits a result. The Worker resolves the binding through
its R2 or S3 adapter, enforces the operation's limits, and reports observed
content identity, size, provider version, and whether the result is complete.
It never chooses a new write authority or interprets a missing object as
permission to use another placement. Native checks the returned evidence
against its pinned topology and SQL generation before applying it.

The Worker may split a bounded request into parallel object tasks, subject to
per-binding concurrency and byte budgets. Native batches independent tasks so
the cross-cloud hop is per batch or job checkpoint, rather than per Git object,
channel partition, or multipart chunk. Large result sets are paged with stable
cursors and explicit completeness; an exhausted budget resumes from a durable
checkpoint rather than returning a plausible partial answer. Backpressure at
the Worker limits store concurrency without requiring more Native instances.

This split follows RFC-0012's surface, placement, read selection, write
authority, and binding revision rules. A storage executor cannot authorize a
new placement, grant a client access, or publish a pointer merely because it can
read or write the underlying object store.

## Registry indexing

Native claims an index job and selects a reconciled read placement. It obtains
`HEAD`, `info/refs`, signed commits, tags, channel partitions, and the bounded
canonical metadata needed to apply registry trust policy. It drives the
existing indexer's anti-rollback checks, release and channel resolution,
retention snapshots, catalog updates, and transactional SQL commit. A failed or
incomplete inspection leaves the last good index intact under the existing
stale/failed distinction.

The Worker reads and parses storage objects for Native's requested projection.
It can inspect loose Git objects and bundle shards, enumerate a tree, fetch
selected package or closure records, filter channel partitions, and return
small canonical signed payloads or typed parsed results with their object-ID
and version evidence. One Worker bundle read may answer many requested Git
object IDs. Native retains signature verification, trust-anchor selection,
name binding, anti-rollback floors, and the decision to commit an index. The
Worker's parser must use the same versioned registry format libraries as the
Native and Workers-only indexers; Native rejects unknown parser versions and
unbounded results. Native receives the exact bounded signed payloads it needs
to verify signatures. For larger content, it checks signed expected digests
against the Worker's authenticated full-object verification evidence, never
against an unbound parsed summary.

The Worker also computes full-object hashes and exact lengths for large signed
disk images and other immutable artifacts in bounded, resumable object-store
reads. Native compares that evidence with the signed catalog and provider
version before recording verification. The current indexer streams these bytes
through `SurfaceFetch::fetch_stream`; hybrid mode must replace that path with a
typed remote verification operation. It must never run a full-object
`SurfaceFetch` fallback on the Native Hub.

`aos-hub-core::indexer` currently couples its Git walk to `SurfaceFetch`, and
`ObjectReader` hydrates bundle bytes in its own process. Introduce a
`SurfaceInspection` port for bounded, batchable object and metadata queries,
plus a versioned result type carrying completeness and object evidence. Adapt
the shared indexer to use the port for its expensive reads, with an in-process
adapter over `SurfaceFetch` for Native-only and Workers-only and a storage-work
client for hybrid. Keep the existing `SurfaceFetch` streaming port for HTTP
delivery and bounded compatibility reads; its availability must not imply that
the hybrid indexer may download a bundle or image to Native. Package
documentation tree extraction and OCI sidecar inspection use the same
inspection port when they need object parsing.

Canonical package documentation is another concrete bulk read in the current
indexer: `fetch_package_documentation` retrieves a narinfo and complete
single-file NAR, verifies the signed locator and hashes, decodes canonical
JSON, and builds search/options projections. In hybrid mode the Worker performs
the NAR read, hash, decode, and schema validation. It returns bounded search
and option projections plus exact signed-locator evidence for Native to check
against the release metadata before writing the SQL documentation index. Search
and navigation then run against Native SQL. Authorized detail and artifact
requests use the closed `inspect_documentation_content` query. The Worker
reads and parses the signed NAR once and returns only the canonical document
model, bounded by the existing 4 MiB document limit plus a 1 KiB result
envelope. Native reconstructs canonical JSON and rechecks its exact signed
digest, size, package selection and semantic schema. Source NAR and narinfo
bytes remain beside storage. Every other semantic result retains its 256 KiB
limit; generic Native object fetch and streaming remain unavailable.

Parsed object caches are optional and disposable. A Worker may address a
Durable Object by immutable store-object identity plus parser version to
single-flight a parse and cache its bounded projection. It does not hold the
registry index, user state, or authoritative object presence. Cache expiry,
parser upgrades, object deletion, and placement GC invalidate or age out the
entry. An object that changes under the same key cannot reuse an earlier parse.

## Parallel uploads and publication

Native authenticates the producer, checks scope and quota, selects the
reconciled writer and required placements, and creates a durable upload ticket
or OCI session in SQL. The response gives the client a Worker upload endpoint
or a narrowly scoped direct-to-store URL when the binding and access policy
permit it. Upload bodies and multipart parts go from the client to the Worker
or object store. A Worker can coordinate many parts concurrently while its
storage adapter enforces key, size, hash, expiration, and binding revision
constraints. Native sees admission, progress summaries, and completion
evidence, not each chunk's bytes.

Finalization verifies the exact object bytes, expected digest and length,
required placement presence, and upload session generation before Native
commits quota and publication state. The Worker may hash or assemble staged
parts near storage. Native remains the sole authority for pointer writes,
release visibility, OCI tag changes, audit, and indexing triggers. Immutable
objects are durable before mutable discoverability is advanced. Failed or
expired tickets leave recoverable staging work for bounded cleanup.

The current shared `SurfaceWrite` and `SurfaceWriteProvider` ports, cache write
tickets, OCI upload sessions, multipart methods, and presigned URLs provide the
starting seams. Hybrid adapters must route body-bearing operations to storage
compute and keep Native's SQL ticket lifecycle intact. The public Worker must
admit an authenticated upload before consuming or forwarding its body; a
control request can reach Native without sending the body there. A client
retry uses the existing ticket and idempotency key rather than creating a
second publication.

### Direct multipart, resume and independent metadata

A direct-required client sends object bytes only through exact provider
UploadPart grants on private session staging keys. The storage Worker owns
create/close/abort, whole-object hash verification and guarded storage-side
promotion; Native sees bounded batch admission, normalized index projections
and signed results. Missing signing credentials, unqualified provider closure,
expired admission or an unavailable storage executor rejects direct mode. The
client does not silently select a Native body endpoint. Native rejects body
routes before polling/buffering the body, including misleading phase headers.

Resume retains the same logical session and immutable source digest, length and
geometry. Status returns sparse part observations and explicit unknown states;
new grants cover only eligible exact parts. Clients use bounded positional
source reads or private disk spools, share global byte/request concurrency
budgets, and persist no bearer URLs. File mutation, different immutable inputs
or unresolved provider control effects refuse resume. Part observations and
expiry are never substituted for settlement.

Small files use parallel independently scoped sessions and bounded batched
Begin/Status/Grant/Report/Complete operations. HTTP cache mutability is distinct
from publication dependency order: independent narinfos/leaf metadata can run
concurrently under their own key guards and expected revisions after their
referenced immutable objects are verified. Final release/root/channel/tag
visibility waits for its complete dependency barrier. Existing content-addressed
object layout and HTTP cache-control are preserved; coalescing requires an
explicit compatible versioned format. The Worker parses uploaded narinfos and
returns the bounded validated index projection rather than routing the original
file upload through Native. Provider request counts, control RPCs and per-phase
latency for large metadata sets are measured, not hidden by file size totals.

When foreground verification is unqualified, small metadata objects use a
separately qualified queued profile. Queue sends and Native read-evidence
controls are batched within fixed message, item and invocation budgets; each
object retains its own attempt, evidence and publication dependency.

Completion may remain in `CompletingStaging` while a storage-local queue job
verifies a large closed object. The client retains and polls its exact original
Complete; it does not resend parts, create a replacement Complete, or publish a
root from a pending or merely staged reply. The verified final placement and
current Native authorization must be present before the same publication
barrier can advance.

Native terminal publication holds the exact current actor, granting membership,
credential head, writer, binding, placement, catalogue and immutable dependency
rows through its checked transaction. Parent organization/quota/usage and
registry rows precede topology, retained Direct source receipts and copy rows.
This order applies under PostgreSQL's ordinary transaction isolation; an
unlocked `EXISTS` observation alone does not fence a concurrent revocation.
Shared cache parent/state locks also fence first signing-usage and ticket
insertions whose absence matters to metadata admission.

A final Direct registry copy carries the exact committed source session ID.
Canonical original Complete, source evidence, original baseline and independently
verified final guard establish that link. A nonversioned guard stamp is never
serialized as a provider version. Inventory observations clear the source link,
even when hash, size and ETag remain equal. Visibility checks validate and lock
that exact source; bounded copy/source plans retain compact digests and versions,
with one full source document at a time.

Verified registry publication charges the durable logical object ledger in the
same transaction as copy presence and terminal receipt. A new generation-7
publication/mirror insertion records its accounting origin; existing conflicts,
inventory and OCI rows do not acquire it. A known ledger controls resize and
reimport deltas. A legacy object without a ledger or known origin refuses new
publication effects until explicit manual reconciliation or reset, rather than
inferring prior billing from storage presence.

An expired, previously valid acceptance can be loaded only for recovery after
its independent signature, closed facts, audience, source/script/guard issuer
and clock policy pass historical verification at the actual current clock.
Future or malformed windows remain invalid. This loader grants no producer
profile: admission, baseline permission and new storage effects still require
current qualification. Exact held-positive Freeze/Commit instead requires fresh
independently authenticated original stage/final readback and current Native
IAM, target and SQL fences. Neither configured pins nor old HEAD/stage visibility
prove a final publication. SQL execution is bounded by the original lookup
context deadline and current JWT expiry (also the baseline witness deadline
for baseline retention). A timeout returns no success acknowledgement and makes
no settlement claim; exact original replay resolves
the retained result without repeating a provider effect.

Standard OCI PATCH clients may keep authenticated Worker byte ingress because
PATCH is not a presigned UploadPart PUT. AOS direct OCI producers must use the
explicit staged-session contract. Neither compatibility path sends OCI layer
bytes to Native or redirects an authenticated PATCH to an incompatible grant.

## Downloads and machine paths

The public Worker serves static assets and immutable public object paths from
its cache or selected object placement. It supports conditional requests and
byte ranges while preserving the existing registry, Nix cache, disk-image,
and OCI machine-path contracts. Native supplies route policy and authorization
decisions for dynamic or private requests. A private request receives a
short-lived, exact-path delivery grant or remains streamed through the Worker
after its access check; knowing a storage key or OCI digest alone never grants
access. The Worker fetches from R2 or S3 and streams directly to the client.

Native serves dynamic HTML, authenticated APIs, catalog queries, and control
RPC. Worker caching of those responses is limited to explicitly safe public
responses with a revision or freshness contract; authenticated responses are
not shared across users. Native may return small query results through the
Worker. It does not proxy NARs, OCI layers, raw images, or other bulk bodies.
External direct routes remain governed by RFC-0012's declared access posture
and route semantics.

OCI Distribution keeps RFC-0019's digest, repository authorization, manifest,
tag, and descriptor-graph semantics. Native checks repository scope and owns
OCI catalog, upload session, quota, tag, and retention transactions. Worker
storage compute handles blob upload, exact digest verification, blob existence,
range delivery, and physical cleanup. A public pull can be served entirely at
the Worker when its grant and publication state are current; private pulls
must check the repository link and token scope. OCI manifests are bounded and
may be served from Native or a revisioned Worker cache, but immutable blob
bytes stay on the storage path.

Manifest and index PUTs retain the same 4 MiB limit in every runtime. In Hybrid,
these bounded documents use a Worker-local upload path. The Worker hashes and
parses the exact client bytes, while Native reserves quota and persists the
original staging operation, placement and immutable binding write revision
before admitting a provider write. The client retains the original proved OCI
actor and provider profile for document, index and tag writes, including
credential renewal; a shared credential cache cannot substitute another actor.

The Worker stores the document beside R2 through the retained object mutation
guard, then sends only a closed, signed metadata projection and positive storage
evidence to Native. The projection binds the document digest, byte size, media
type and descriptor graph to the original reservation and current registered
OCI delivery authority. Native validates that evidence and the closed graph,
checks current repository authority, and commits materialization and catalog
state. Neither a raw manifest nor blob bytes enter Native on this path. A direct
request to Native refuses raw bodies before polling; it cannot become a proxy
fallback when Worker storage or provider readiness fails.

Lost acknowledgements replay the original operation and receipt. Expiry alone
does not settle unknown provider effects or release quota and mutation fences.
Final index and tag visibility follows verified object closure and the Native
publication barrier. Bulk archives and OCI layers use signed provider uploads;
the bounded manifest path does not authorize bulk Worker uploads.

## Inventory, reconciliation, and GC

Native owns the durable inventory generation, leases, root graph, policy,
reviewed GC plan, mutation epoch, and deletion jobs. It asks the Worker to
enumerate bounded provider pages and produce exact object evidence, including
content hash, size, and strong provider version where required. The Worker
hashes large objects locally with bounded ranged reads and resumable
checkpoints. Native imports pages only when their cursor, topology fence, and
completeness agree; stale or partial inventory cannot authorize deletion.

Native derives logical deletion or placement eviction using RFC-0012's
retention roots and RFC-0019's OCI descriptor graph. It then dispatches
placement-scoped conditional deletes to the Worker with the exact reviewed
object identity and preconditions. The Worker reports deleted, already absent,
or precondition mismatch. Native records the outcome and advances tombstones
or quota only after the required placements are accounted for. A mismatch
never triggers an unconditional retry. The existing `oci_inventory_controller`,
`oci_gc_controller`, `gc_controller`, and `placement_scan` are the orchestration
seams; their provider reads, hashing, and conditional write/delete calls need
remote storage-work adapters in hybrid mode.

Object-scoped parse caches are removed or allowed to expire when their object
is collected. Cache cleanup is best effort and cannot gate the correctness of
SQL GC or physical deletion; every cache hit remains tied to immutable object
identity and parser version.

## Mirroring, replication, and repair

Native selects the source, verifies trust and the destination's write
authority, records a bounded copy plan, and controls publication order. The
Worker fetches upstream bytes or a source placement and writes the destination
placement without routing the copy through Native. It may fan out independent
immutable objects, but commits registry pointers last and cache NARs before
narinfos. Each destination reports hash, size, provider version, and presence
before Native marks a replica complete or makes it eligible for serving.

The current native full-mirror implementation in `mirror.rs` writes only to a
local filesystem, while `placement_scan` can copy through the shared
`SurfaceFetch` and `SurfaceWrite` ports. Hybrid mode needs a remote copy/job
port that lets the Worker perform the byte movement, with bounded progress and
retry evidence returned to Native. If source and destination stores cannot be
accessed by one Worker executor, a storage-to-storage transfer service may
relay the bytes outside GCP; Native still receives only progress and evidence.
The protocol must preserve upstream URL safety, mirror trust checks,
immutable-first ordering, and the completion and fail-closed placement rules
from RFC-0012.

## Runtime parity

The same policy, validation, and state transitions are exercised in all three
modes. Native-only uses local filesystem, HTTP, or S3 adapters and can perform
storage work in process. Workers-only uses R2 or supported binding adapters
and its existing database runtime. Hybrid uses remote storage-work adapters
and one Native SQL authority. Capability checks are explicit per operation:
missing conditional delete, strong object version, multipart support, or
remote inspection blocks only the workflow that requires it. Parity tests run
the same representative registry, cache, image, and OCI fixtures through all
supported adapters and compare SQL outcomes and client-visible bytes.
