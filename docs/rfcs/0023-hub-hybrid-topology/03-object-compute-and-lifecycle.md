# Object compute and lifecycle

Storage-local compute reduces bytes and round trips while Native SQL remains
the system of record for Hub accounts, indexes, placement authority, retention
policy and authoritative inventory. A Worker may parse, verify, filter and page
an object-store result. An optional Durable Object (DO) may coordinate and cache
a *derived result for one physical store object*. Permanent admission and
object-effect journals are separate correctness authorities; they cannot be
reconstructed from a parse cache, SQL backup or current provider HEAD. The
optional/reconstructable cache goal applies only to derivatives; managed storage
requires its permanent admission and effect journals.

## Physical identity and cache keys

An object-scoped cache key includes the Hub deployment and tenant namespace,
binding and placement IDs, exact storage key, a provider-observed immutable
version or verified content digest, operation and parser schema versions, and
the projection class. This separates identical keys in different buckets and
different versions at the same key. It also separates a new parser's output
from old cached data. Credentials are not part of the key or cached value.

For an immutable Git or OCI object, the Worker verifies the content identity
against its OID or digest before admitting a parsed result. For a mutable
pointer, channel partition, narinfo, or other overwritten object, the Worker
first obtains a strong provider version and reads that exact version with a
conditional request. A provider that cannot give the necessary version or
conditional read does not get a persistent parse cache for that object. A
cache hit is *not* proof that the physical object still exists: operations
that depend on current presence or publication eligibility revalidate
against the provider and the [RFC-0012](../0012-hub-surface-topology/02-delivery-and-auth.md)
placement and publication rules. A deleted object can leave a harmless
derivative until expiry, but it cannot be served or reintroduced into Native
state from that derivative alone.

## Worker execution path

The storage executor validates the work plan, resolves its frozen binding,
and checks the source object's exact identity. It may then:

1. return a bounded cached parse result for the same identity and parser
   version, after any required live-presence check;
2. coordinate one in-flight parse through the object-scoped DO, so concurrent
   callers share the work; or
3. parse in an ordinary Worker invocation when caching would cost more than
   recomputation.

All three paths return the same canonical typed result and evidence. DO use is
an optimization chosen for hot or expensive objects, not a correctness
dependency or a required hop for every file. Worker invocations remain
horizontally independent; a cold, evicted, or unavailable cache can be rebuilt
from the object store. The executor applies per-object byte, memory, CPU,
fanout, and result-size limits before allocation and during streaming. If one
invocation cannot process the admitted object, it reports a typed limit or
partitions work into bounded storage-local tasks. It never sends the raw
object to Native as a fallback.

The present registry format illustrates why the cache must be selective.
`ObjectReader` currently preloads `objects/aos-index-v1/all` (up to 32 MiB) or
256 shard bundles (up to 2 MiB each), then pulls loose objects by OID. A
hybrid Worker can read one bundle once and return only the OIDs or parsed
fields needed by a batch of index requests. A bundle DO may cache a bounded
directory of entry offsets or selected hot derivatives. It must not replicate
an entire 32 MiB bundle into every object DO or retain every decoded package
indefinitely. If the format does not support efficient ranged extraction,
the Worker may parse the bounded bundle locally for that batch and return a
typed size or time error when it exceeds its execution budget. Changing the
bundle format to add a range-friendly index is a possible later optimization,
not a prerequisite for preserving the network boundary.

## Which computations belong here

The Worker may decode and hash Git objects and bundles, parse versioned
registry manifests, select channel partitions, inspect OCI manifests and
descriptors, parse narinfo, compute bounded inventory pages, and verify large
objects by streaming their bytes from the provider. Parsers and validators
that exist in `aos-registry-surface`, `aos-oci-types`, and
`aos_hub_core::indexer` should be extracted into shared, deterministic
functions rather than reimplemented in Worker request handlers. For a
schema-specific filter, the request names admitted fields and operators; the
result contains only requested fields and their observed source identity.

Native retains the trust decisions and graph-wide joins: trust-anchor
selection, signed release acceptance, anti-rollback floors, release and
channel relationships, package visibility, retention roots, and SQL index
commit. A Worker can return the compact signed material needed for Native to
verify a claim. When the underlying object is too large for that, the Worker
verifies bytes using shared code and returns an authenticated digest and
canonical parsed projection. The RFC's validation plan must test that the
same invalid input is rejected in all three runtime modes. A Worker result is
trusted service evidence, not a replacement for a signature or a provider
condition where the Hub protocol requires one.

## Expiration and cleanup

Each cached derivative has an absolute expiry and a maximum idle age, both
bounded by deployment policy. The object DO schedules cleanup when it writes
state. An alarm deletes expired entries and releases any temporary work
metadata; expiration never depends on another request arriving. The DO does
not own a permanent copy of the source object. Workers also bound total
entries and bytes per DO and evict least-recently-used derivatives within
those limits. Cache admission can be disabled by operation, object class, or
deployment.

Object deletion and storage GC send a best-effort invalidation for the exact
binding, placement, key, and version. A confirmed delete also makes that
version ineligible for future cache hits even if the invalidation message is
delayed: every presence-sensitive hit checks current provider identity. A
replacement at the same key has a different identity and therefore a
different cache key. Placement removal or binding retirement marks its
namespace ineligible for new cache admission and queues cleanup; TTL and alarms
eventually reclaim unreachable derivatives. This logical binding readiness does
not cancel issued physical execution leases, whose cutoff is enforced separately.
Credential rotation may change
access authority without changing content identity, so new work must still
pass the plan's exact credential and binding fence before using old parsed
content.

The Native Hub owns object lifecycle decisions. It issues a reviewed,
conditional deletion plan only after SQL retention and inventory checks. The
Worker performs provider I/O and reports the exact outcome. A cache entry
cannot authorize deletion, serve as sole proof of absence, or keep an object
alive. For S3-compatible backends, conditional-delete support must be
positively observed for the exact binding revision as required by existing
`FrozenSurfaceAccess` and OCI GC flows; unsupported backends fail closed for
that workflow.

Deployment R2 uses a separate object-scoped Durable Object for visible
mutations. Its identity is the deployment and physical R2 key. Every hybrid
visible put and multipart completion for that key passes through this guard,
as does each reviewed physical deletion. Nonempty request bodies are staged
as multipart parts in R2 by the ingress Worker; only compact completion
metadata crosses to the guard. R2's Worker API has no atomic conditional
delete operation, so the guard serializes HEAD, identity comparison, and
DELETE with writes to the same key. A deletion plan carries the SQL claim ID,
strong ETag, size, reviewed hash, and provider upload version. The guard compares
the reviewed upload version with the current R2 object before issuing DELETE;
an identical replacement with the same bytes and ETag still fails that check.
The identity is the upload-specific `version` from Cloudflare's
[R2Object API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/#r2object-definition).
Inventory and cache scans persist the observed version through their reviewed
digests, frozen actions, jobs and immutable attempt receipts. Existing
versionless candidates require a new scan before a first R2 deletion; a
terminal legacy receipt remains replayable without provider I/O.

The guard persists the claim before
deleting and retains its outcome indefinitely; a retried claim cannot delete
a replacement at the same key. A crash or lost provider response before outcome
persistence leaves the key fenced by the pending claim. Neither a subsequent
HEAD reporting absence nor lease expiry proves that the original request has
settled. The guard refuses a second physical deletion and keeps writes blocked
until provider settlement is established and its terminal receipt is persisted.
The initial implementation retains this ambiguous state for operator recovery;
it does not automatically clear it on a timer. This guard is a correctness dependency for hybrid R2,
distinct from the optional parsed-result cache above. Other backends need
their own positively observed atomic condition or an equivalent serialized
mutation boundary before physical GC can run.

An already absent object is confirmed through signed HEAD in the same guard.
Native accepts that observation only for the reviewed claim and records bounded
absence evidence; a pending mutation prevents confirmation. A provider upload
version does not establish settlement of an already dispatched DELETE.

The deployment and guard namespace must remain stable for the lifetime of a
reused bucket and prefix. Resetting SQL or rotating credentials cannot retire
pending fences or terminal receipts. A topology reset that reuses storage must
preserve this authority; safe receipt retirement needs a separate protocol
that proves old requests can no longer take effect.

### External physical storage authority

An external S3 guard is owned by a permanent physical authority, rather than
a logical binding, placement, credential generation or current SQL deployment.
Root operators review its bucket identity, immutable guard namespace, canonical
endpoint aliases and exact binding revisions. An approved endpoint/bucket alias
remains reserved after revocation. DNS resolution, matching ETags and shared
credentials do not establish that two addresses refer to one physical resource.
Two active guard domains cannot be merged merely because an alias is later
discovered. The namespace and prior effects must first be reconciled explicitly.

Authority creation freezes the initially qualified managed prefix in its
canonical specification. An explicitly empty prefix qualifies the entire
bucket; an absent prefix is invalid. Renewed exclusivity attestations may narrow
or reopen within that immutable ceiling, using complete path components, but
cannot expand it. The first published attestation does not choose the ceiling.
Neither a prefix change nor restored SQL settles existing effects or receipts.

SQL records reviewed identity, credential exclusivity evidence and monotonically
versioned desired admission. A separately durable executor ledger enforces that
admission. Restoring an older database cannot reduce its remote generation or
reopen a revoked authority: a fresh authenticated watermark and explicit reviewed
reconciliation are required. Root `StorageManage` permission is checked both
when creating a plan and when applying it. Organization binding permissions do
not authorize physical equivalence or executor adoption.

The typed `StorageAuthorityService` exposes `PlanStorageAuthorityDecision`, `StorageAuthorityDecision` and
`GetAuthority` at instance root. Plans bind the exact actor, typed decision,
confirmation and request/apply keys. Plans return the canonical
`TopologyPlanResponse`. Apply requests contain only `plan_id`,
`confirmation_hash` and `idempotency_key`; the exact typed intent is loaded from
the immutable stored plan. Apply and durable result replay require fresh root
permission.

The plan's `expected_resource_version` is empty for new permanent identities,
the immutable creation digest exposed by `GetAuthority.resource_version` for
aliases/attestations, the exact binding resource version for associations, and
the desired admission generation for admission decisions. Association and
admission versions must equal their typed decision fields. Admission plans also
bind the exact predecessor digest. New plans check current mutable versions;
exact request replay preserves its original reviewed intent after the target
advances. A closed version-1 plan envelope persists the explicit expected version
and typed decision together, and its complete canonical bytes determine the
confirmation. The canonical API rejects bare legacy intent; the trusted DB
primitive retains deliberate bare-plan compatibility for historical internal
records. Offline classification admits both known closed formats and preserves
the exact original private JSON cell and confirmation without rewriting either.

Atomic apply retains all current binding, credential and admission fences. SQL
projections distinguish desired admission from
authenticated executor agreement; a committed decision alone admits no provider
operation.

Each acknowledged visible mutation advances a guard-issued incarnation for the
full physical object key, including an identical-byte replacement. The frozen
identity is the explicit pair `(physical_authority_id, incarnation)` and remains
separate from an R2 provider upload version. Inventory, reviewed actions, jobs,
claims and receipts carry that exact pair. A later HEAD cannot fill a missing
stamp or settle an unknown provider effect.

Every managed Native-only, Worker-only and Hybrid writer must use the approved
issuer/object-guard protocol or reject the operation, including retained writers
and alternate aliases. Required coverage includes OCI staging/final blobs and
manifests; cache bodies, narinfo and publication PUT; Git loose objects, refs and
registry/draft metadata; consumer transactions; replication and placement scans;
credential/conditional-delete probes and cleanup; multipart create, parts,
completion and abort; GC, migration and every retry/recovery path. Enforce this
at factories and actual provider dispatch, rather than only new writer creation.
A completion HEAD fallback cannot settle an unknown provider result.
Already issued direct provider capabilities and other
provider credentials must be covered by the exclusivity decision. A fresh unused
namespace with exclusive executor access is the initial adoption path; an
existing unmanaged namespace requires actual prior-effect settlement. Deletion
is enabled only after every visible writer and the provider's physical deletion
semantics are qualified. A versioned S3 delete marker alone does not prove that
historical object bytes were reclaimed.

## Scalable external execution

Separate rare permanent identity decisions from upload-frequency admission.
A global registry reserves canonical aliases, physical identities and immutable
executor/namespace links. Each permanent physical authority has its own issuer,
full reviewed publications/receipts, current generation and issuance cutoff.
Each full physical key has its own persistent guard. Logical binding IDs,
credential generations, aliases and SQL restores cannot select another journal.
Many authorities use one class with separate object IDs; one bucket does not
require one class. The global registry and issuer never carry bulk bodies.
Lease renewal reads the current head and selected keyed association/purpose
projection linked atomically to the full publication and receipt, rather than
scanning the complete member bundle. Full publication and receipt validation
remain on the control path.

Global reservation and per-authority installation are distinct transactions.
Install only after exact signed reservation receipts are available; partial
failure may leave unused permanent reservations, never ownership rollback or
execution without the required evidence. Partitioning the current fixed ledger
requires [lifetime-preserving initialization](05-state-deployment-and-portability.md#permanent-journal-lifetime-and-partitioning),
not adoption of an empty object for previously used physical storage.

### Object-local dispatch and settlement

Under the bounded lease policy, an object guard authenticates the work and
exact application-authorized canonical key, pins its permanent authority/scope,
replays only an exact terminal receipt, and rejects unknown or differing pending
effects. It verifies the
[closed lease](02-storage-work-protocol.md#managed-external-execution-admission),
its exact cohort/purpose, absolute expiry and durable generation/digest floor.
Same-generation forks and older generations fail closed. A verified later denial
or admission raises the local floor; an older lease cannot follow a newer-epoch
visible mutation at that key.

Persist exact stable intent and admitted lease identity before provider I/O.
PUT/part commitments derive from actual validated bytes, not an unchecked client
hash. Recheck expiry in the actual dispatch adapter immediately before invoking
the provider, with no intervening application await. Qualify runtime pause and
continuation uncertainty around that check; this is an executor admission and
invocation bound, not a provider-arrival/completion deadline. Only the live
continuation can persist definite pre-invocation no-dispatch evidence. Expiry,
restart, HEAD, matching bytes or credential revocation cannot supply it.

Validate the actual provider terminal acknowledgement and persist the exact
receipt and guard-issued visible incarnation before clearing only its matching
intent. Network ambiguity or failed receipt persistence retains the unknown
fence indefinitely. There is no central Begin/Settle call per leased effect;
terminal authority remains at the permanent key guard. A lease alone never
permits GC: the reviewed frozen action/claim, exact guard incarnation, absence
of unknown work at that key and qualified provider condition remain required.
An unknown effect at another key does not freeze all uploads or GC. External
DELETE stays disabled until the complete path and provider semantics are
actually qualified.

### Denial, reopening and strict purposes

Denial stops issuer renewal immediately; authentic existing leases may still
admit new dispatch until their recorded expiry plus conservative qualified
uncertainty. Expose issuance closure, lease admission cutoff and per-key unknown
state separately. Never report TTL-based execution drain or discard an old
receipt. Signed denial fanout can stop touched guards earlier, but unseen keys
may use an old valid token within the explicitly accepted window.

After confirming cutoff, root-reviewed renewed exclusivity may reopen other
eligible keys in a new admitted generation while old unknown keys remain fenced.
Binding/coordinate/prefix/writer/credential mutation APIs must close issuance and
confirm the previous cutoff before new execution admission. SQL credential-head
changes alone do not revoke tokens. The review must account for retained managed
effects and exclude old direct writers, binaries and provider capabilities; it
cannot claim physical quiescence. Retired authority cannot reopen. Namespace
transfer, destruction of old guards or unqualified storage reuse still requires
actual prior-effect settlement or a fresh never-reused physical namespace.

A purpose requiring an immediate admission reservation cutoff can instead use
per-authority atomic BeginDispatch/SettleDispatch. Denial then stops new
reservations in that serialization order; prior reservations may invoke or
complete later. Its durable accounting and generation rollover/drain rules must
be qualified, and its roughly two authority RPCs per effect and hotspot cost
are disclosed. A reusable lease must not silently weaken this policy. Neither
policy's denial acknowledgement alone proves that all provider work stopped.

Under bounded leases, authority-wide drain additionally needs an immutable
partitioned directory of all guards, with acknowledged registration before a key's first provider I/O,
then exact settlement from every partition/guard after cutoff. SQL inventory or
provider listing can miss pending creation. Missing pages, guards or unknown
effects prevent drain. Until that extra protocol is qualified, expose cutoff
and individual key eligibility only.

### Multipart and presigned paths

Do not hold one final-key gate while every body part streams. A persistent
upload-session coordinator is permanently linked to its final authority/key;
short session/part admission sections permit independent parts to transfer
concurrently using exact purpose leases. Each part attempt has its own immutable
identity and unknown fence, so concurrent retries cannot overwrite one part.
Whether parts use local records or separate part guards requires an explicit
persistence/concurrency contract.

For server-executed parts, freeze admitted parts before completion: stop new
part admission and require exact terminal outcomes for every earlier admitted
part. Under the final-key
guard, verify the immutable settled-part/ETag commitment and a freshly valid
completion lease before persisting final-visible intent and invoking completion.
Unknown server-executed parts block that session; unknown completion blocks
the final key.
Create/abort uncertainty retains provider resource accounting even without a
visible final object. HEAD and URL/lease expiry settle none of these effects.

The delegated staging protocol below substitutes qualified upload-ID closure
for settlement of reusable part capabilities; it cannot reinterpret a client
report as one of those exact server-executed part receipts.

Direct presigned final-key PUT cannot enforce this guard and fails closed for
managed storage. Direct uploads instead use a fresh private staging key and a
permanently retained upload session. The client receives only exact UploadPart
capabilities naming one provider upload ID, part number, immutable part geometry,
required checksum headers and bounded expiry. It receives no create, complete,
abort or final-key write capability. One-part small objects use the same staged
protocol unless a separately qualified attempt-specific PUT/materialization
contract is selected. An ordinary cohort lease is not a provider-side check at
the later invocation of a presigned URL: delegated staging is a distinct purpose
with an explicit capability tail and provider qualification.

Before provider creation, reserve the original immutable admission in a
permanently retained coordinator addressed by deployment, authenticated stable
principal and client operation ID. The address excludes SQL session/owner IDs,
restored database labels and mutable placement coordinates; those belong to the
original admission fingerprint. A reconstructed or changed admission cannot
select a fresh coordinator to escape an unknown effect or prior receipt.

Grant issuance and renewal validate the exact application admission, physical
authority, immutable session, binding/credential revisions and staging scope.
Grant batching and independent part transfers do not occupy a final-key gate or
make per-part Native control round trips. Each grant and its original input
fingerprint is retained; a client part report is an observation, not terminal
settlement. A content-bound retry of the same private upload ID and part is
allowed while active with the original checksum, length and source fingerprint;
packet loss need not permanently block that part. Changed content and new
control identities cannot reset an unknown create/close/promote/abort. Freeze stops new grants and commits the canonical ordered part/ETag
manifest. Previously issued grants remain reusable; a late part replacement can
invalidate that manifest. URL expiry and provider listing do not settle queued
or unknown work. Unknown create, completion or abort remains fenced and retains
provider resource accounting across SQL restore, expiration and rotation.

The server alone completes staging. It parses the complete provider response,
including errors carried in a success HTTP status. Before enabling a provider,
qualify that a successful canonical close prevents old part grants, including
requests started before close, from modifying the completed staging object or
creating its replacement. Lost completion acknowledgment does not prove close.
The storage executor then streams an exact completed-stage snapshot, verifies
full SHA-256 and length, and materializes only those verified bytes under the
final-key retained intent and a freshly valid promotion-purpose lease. Native
receives signed compact incarnation/hash evidence and commits discoverability
only for the original logical admission and required placements. No bulk bytes
or verification read may fall back through Native.

Verification uses an explicit, provider-qualified execution profile. Foreground
work is bounded by the original public invocation and its fixed deadline. A
queued profile must be reserved by the original Begin, with its exact placement,
before provider creation. Objects exceeding the measured foreground budget use
that qualified queue profile. Small objects may use it too when foreground
verification is unavailable; neither mode is selected after provider creation.

A successful provider Complete response establishes closed staging, not a
verified whole object digest. The client may observe `CompletingStaging` and
poll its original operation while the storage Worker verifies the object
asynchronously.

The queue carries only a bounded job reference. A consumer obtains a fresh,
scoped machine read permission for the retained original session, placement and
staging incarnation, then hashes an exact conditional read beside storage. Its
durable receipt records the bytes actually read and the immutable attempt; a
client checksum, HEAD response or declared length cannot replace that receipt.
Native checks the current original actor and publication authority before
promotion, and the final-key guard admits only the selected placement under a
separate signed authorization. A lost queue acknowledgment cannot start a
second read for the same attempt; retries use distinct bounded attempts under
the retained job. Neither polling nor a later private credential refresh renews
an expired foreground invocation or creates queue authority retroactively.
Provider object-size eligibility follows measured Worker and queue capacity,
including the whole consumer invocation budget, and fails closed otherwise.

Direct staging requires a provider-qualified private bucket or reviewed
prefix-private policy. Unguessable names and facade denial alone do not make a
public provider binding private. Publicly readable bindings refuse direct-required
uploads until a qualified private policy or separately approved private staging
authority/materialization path exists. Public delivery and ordinary inventory
exclude the reserved staging namespace before provider reads.

Exclude already issued bypass capabilities and uncoordinated writers before
managed authority activation. Staging qualification does not prove whole-domain
drain or external deletion readiness. Abort acknowledgment, acknowledged upload
closure, logical ticket cancellation and eventual provider resource reclamation
are separate states. Lifecycle expiry is only a resource leak backstop; it
cannot discard an unknown fence or terminal receipt. Unsupported or unqualified
direct capabilities reject before granting a URL, rather than selecting a
Native body transport.

## Failure and cost controls

DO alarms, cache reads, and provider reads are observable separately. Metrics
include cache hit and rebuild rates, source bytes read, parse CPU, result
bytes returned to Native, per-object fanout, eviction/expiry counts, and
invalidation lag. A parse cache should be enabled for an object class only
when measured storage reads or CPU saved justify its DO requests and stored
bytes. Workers enforce concurrency and per-plan limits so one large upload or
index walk cannot monopolize a cache object or saturate the object store.

If a parse-cache DO is unavailable, the executor may recompute in a stateless Worker
when the plan's limits allow it. A provider outage or an unverifiable object
returns an error; it does not produce a result from stale cache. Native keeps
its last accepted index with the appropriate stale or failed state and retries
only according to the storage-work error contract. A partial fanout never
appears as a complete scan or index generation.

An unavailable permanent guard never permits stateless mutation fallback. An
issuer outage prevents renewal; cached leases admit only their exact scope until
expiry under the reviewed bounded policy. Ordinary indexed queries stay close
to Native SQL and do not consult an issuer/guard. Storage inspection can reuse
read-purpose leases, while HEAD/inventory retains pending checks and coherent
stamp capture. Strict read revocation selects its policy explicitly.
