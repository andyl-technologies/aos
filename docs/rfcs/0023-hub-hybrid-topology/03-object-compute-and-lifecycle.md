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
