# Object compute and lifecycle

Storage-local compute is useful only if it reduces bytes and round trips
without becoming another system of record. A Worker may parse, verify, filter,
and page an object-store result. An optional Durable Object (DO) may coordinate
and cache a *derived result for one physical store object*. Neither holds Hub
accounts, indexes, placement authority, retention policy, or authoritative
inventory. The Native SQL database remains authoritative for those records.

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
namespace inaccessible immediately and queues cache cleanup; TTL and alarms
eventually reclaim unreachable derivatives. Credential rotation may change
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

SQL records reviewed identity, credential exclusivity evidence and monotonically
versioned desired admission. A separately durable executor ledger enforces that
admission. Restoring an older database cannot reduce its remote generation or
reopen a revoked authority: a fresh authenticated watermark and explicit reviewed
reconciliation are required. Root `StorageManage` permission is checked both
when creating a plan and when applying it. Organization binding permissions do
not authorize physical equivalence or executor adoption.

Each acknowledged visible mutation advances a guard-issued incarnation for the
full physical object key, including an identical-byte replacement. The frozen
identity is the explicit pair `(physical_authority_id, incarnation)` and remains
separate from an R2 provider upload version. Inventory, reviewed actions, jobs,
claims and receipts carry that exact pair. A later HEAD cannot fill a missing
stamp or settle an unknown provider effect.

Managed Native-only, Workers-only and Hybrid writers use the same authority
ledger or reject the operation. This includes ordinary PUT, multipart completion,
metadata publication, replication, credential probes, recovery writes and
presigned upload issuance. Already issued direct provider capabilities and other
provider credentials must be covered by the exclusivity decision. A fresh unused
namespace with exclusive executor access is the initial adoption path; an
existing unmanaged namespace requires actual prior-effect settlement. Deletion
is enabled only after every visible writer and the provider's physical deletion
semantics are qualified. A versioned S3 delete marker alone does not prove that
historical object bytes were reclaimed.

## Failure and cost controls

DO alarms, cache reads, and provider reads are observable separately. Metrics
include cache hit and rebuild rates, source bytes read, parse CPU, result
bytes returned to Native, per-object fanout, eviction/expiry counts, and
invalidation lag. A parse cache should be enabled for an object class only
when measured storage reads or CPU saved justify its DO requests and stored
bytes. Workers enforce concurrency and per-plan limits so one large upload or
index walk cannot monopolize a cache object or saturate the object store.

If the DO is unavailable, the executor may recompute in a stateless Worker
when the plan's limits allow it. A provider outage or an unverifiable object
returns an error; it does not produce a result from stale cache. Native keeps
its last accepted index with the appropriate stale or failed state and retries
only according to the storage-work error contract. A partial fanout never
appears as a complete scan or index generation.
