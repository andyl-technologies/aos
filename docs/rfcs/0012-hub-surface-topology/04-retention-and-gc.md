# Retention and garbage collection

## Correct source data

Retention by release requires an immutable artifact snapshot for each verified
release tag. The current registry index describes the current catalog and
records release tag/commit metadata, but it does not retain the package
artifact set read from each release commit.

Indexing therefore gains an immutable snapshot header and artifact rows:

```text
RegistryRelease
  registry_id
  semver/tag oid/commit oid/tagged at

ReleaseArtifactSnapshot
  snapshot id
  release_id
  source commit
  verified tag oid / verification record
  manifest digest
  state = building | complete | failed
  expected / actual artifact count
  completed at / error

ReleaseArtifact
  snapshot_id
  package
  package version
  platform
  kind = output | image | source_derivation
  store_path
  store_hash
```

The indexer verifies the release tag, reads the registry tree at its target
commit, derives a manifest digest, and records the snapshot header and artifact
rows before publishing that snapshot as complete in one transaction. At most
one complete snapshot exists for an immutable release. A complete zero-artifact
snapshot is different from a release that has never been indexed. Existing complete
snapshots are immutable and remain intact when a later index or verification
attempt fails; failed attempts are separate snapshot rows and never replace the
complete pointer. A selector that needs a release without a complete snapshot
is not safe for destructive GC.

The canonical digest covers the ordered full artifact identity and metadata,
not only store hashes. Completion requires source commit and verified tag oid to
match the immutable release, expected and actual row counts to match, and a
recomputed digest to equal the header. The only snapshot transition is
`building -> complete|failed`; terminal headers and their artifact rows cannot
be updated or deleted by steady-state runtime methods. The release's complete
snapshot pointer may advance only once from null to that validated complete
row.

Channel partitions resolve to release ids. Every distinct release targeted by
any live partition is a live channel target during a rollout. A single
frontier string is insufficient.

## Retention subscriptions

Retention policy belongs to a cache/registry subscription, not only to the
cache, because shared-cache consumers need different policies.

Selectors are composable union terms:

```text
RetentionSelector
  current_catalog
  channel_targets { channels = all | names }
  recent_releases { count, include_prereleases = false }
  releases { exact tags }
  semver { requirement, include_prereleases = false }
  all_releases
```

The recommended initial default is:

```text
current_catalog
union all channel partition targets
union latest 5 verified releases
```

The count is editable per subscription. Organizations may define a different
default, and archival caches may select all releases.

`recent_releases.count` is an integer from 1 through 100. It considers only
verified releases with a complete artifact snapshot and a valid SemVer 2.0.0
version. Unless `include_prereleases` is true, a version with a prerelease
component is excluded. Eligible releases sort by this stable tuple:

```text
tagged_at DESC,
SemVer precedence DESC,
canonical SemVer UTF-8 bytes ASC,
verified tag OID bytes ASC,
stable release id bytes ASC
```

`tagged_at` is the immutable verified tag timestamp recorded by the registry
indexer. Re-index time and snapshot completion time never participate. Exact
tag selectors remain the way to retain a non-SemVer release tag.

SemVer requirements use one RFC-owned grammar rather than host-library
shorthand:

```text
requirement = OWS conjunction *( OWS "||" OWS conjunction ) OWS
conjunction = comparator *( OWS "," OWS comparator )
comparator  = ( ">=" | "<=" | "=" | ">" | "<" ) version
version     = SemVer-2.0.0-version-without-build-metadata
OWS         = *( SP | HTAB )
```

Tokens use longest-match lexing. Leading/trailing OWS is accepted and removed
by canonicalization. Caret, tilde, wildcard, partial, implicit-equality, hyphen-range, and bare-space
conjunction syntax are rejected. Parsing enforces SemVer 2.0.0 numeric and
identifier rules. Canonicalization normalizes whitespace away, renders numeric
identifiers without leading zeroes, deduplicates comparators, sorts comparators
within each conjunction by `(operator, canonical version bytes)`, sorts
conjunctions by their canonical bytes, and joins with `,` and `||`. With
`include_prereleases = false`, candidates containing a prerelease component are
filtered before evaluation. With it true, all candidates use ordinary SemVer
precedence. Native and Worker store the canonical expression and selector flag
in the refresh digest and share the same parser and ordering vectors.

`current_catalog` deliberately preserves the current safe behavior: every
package-output and image store path still published at the registry's current
indexed commit is rooted. Release selectors add historical correctness rather
than replacing current-catalog safety.

## Root reasons

Selectors materialize provenance-bearing root reasons:

```text
CacheRootReason
  id
  cache_id
  store_hash
  source_kind = manual | lease | registry_catalog | release | channel
  retention_subscription_id
  registry_id
  release_id
  channel and partition provenance
  source_revision
  expires_at
  refreshed_at
```

Uniqueness includes the reason identity, not merely `(cache_id, store_hash)`.
One store hash may have many reasons. The root inspector can therefore answer:

```text
why retained?
  andyl/main current catalog: hello 2.1 x86_64-linux
  andyl/main stable partition 00-7f: release 2.1.0
  andyl/main latest-5 policy: release 2.0.3
  manual pin by dylan@example, expires 2026-09-01
```

Refresh is transactional per subscription. A refresh header captures the
subscription, cache, registry, selector digest, registry indexed revision, its
current parent refresh, and the expected reason count. Reasons staged under it
are immutable and carry source-specific provenance: current-catalog reasons
name the indexed registry revision; release reasons name the complete release
snapshot and manifest digest; channel reasons additionally name the channel,
partition, and channel source revision.

The refresh remains unreachable while building. Commit verifies the exact
reason count, every source reference, and the unchanged subscription version,
parent pointer, selector digest, source revision, and cache GC epoch. One atomic
batch marks it complete, sets activation and parent-grace times, advances the
subscription's `current_refresh_id`, and advances the cache epoch. A failed
refresh records its error but never becomes current. The active root query
starts only at each subscription's current complete refresh and follows parent
links only while the child generation's `parent_grace_until` exceeds the GC
cutoff. A retired subscription contributes that lineage only through its
explicit retirement grace. No query treats every historical reason row as
active.

Manual roots have stable ids and are logically deleted rather than overwritten.
A root is either indefinite, contributing a manual reason, or lease-governed,
contributing no separate indefinite reason. A lease-governed root stores one
`current_lease_id`. The active lease reason exists only when that exact lease is
the current head, is not revoked or superseded, and contains the GC cutoff in
`[begins_at, expires_at)`. Renewal atomically creates a successor linked by
`renewed_from_lease_id`, marks the prior head superseded, advances the root
pointer/version, and advances the cache epoch. Revocation marks the current
head revoked, clears the pointer, and advances the same versions; it cannot
revoke a historical predecessor. Wall-clock expiry is derived and needs no
unsafe background rewrite. Root deletion clears either form of protection and
is likewise epoch-guarded. Ordinary unreferenced grace still begins before the
object becomes eligible for collection.

## Cache object identity

A Nix store path, its narinfo, and its NAR are related but not identical:

```text
CacheObject(cache, store hash)
  -> NarinfoSurfaceObject(<store-hash>.narinfo)
  -> NarSurfaceObject(nar URL/content identity)
  -> CacheObjectReference(referenced store hash) ...
```

Several store paths may reference the same NAR. Every narinfo and NAR has
placement-scoped presence, while closure edges belong to the logical cache
object. Physical authority therefore never comes from a cache-global binding
and prefix, an embedded JSON reference list, or a cache-wide NAR refcount.
Refcounts are computed per placement from active narinfo-to-NAR mappings.

Publishing and replication use NAR-first, narinfo-last order. A cache object's
logical metadata becomes active only after its reference edges and required NAR
presence are durable. The cache object-graph generation advances in that same
control-plane transition.

## Marking the closure

Root reasons name top-level store hashes. GC walks the transitive closure using
normalized, indexed narinfo `References`. Missing root objects or reference
metadata are reported as coverage failures but do not stop other roots from
being explained and marked. They do block destructive apply because their
unknown closure cannot be proven safe.

Cycles are harmless. Rooted objects and every reachable reference remain live.
An object remains live if any active reason reaches it.

### Mark generations and unreferenced time

GC never mixes a live root query with an independently changing object graph.
It builds an immutable mark generation containing:

- the exact root reasons and root-generation version;
- object-graph and complete-inventory generations;
- GC-policy and placement/topology versions;
- every marked cache object; and
- missing-root, missing-reference, or stale-inventory coverage errors.

The generation is unreachable while building and becomes usable only after a
complete validation and one compare-and-set publication. A failed generation
does not replace the last complete one.

`unreferenced_since` is set when an object is first absent from a complete
successful mark, not when it was uploaded. Later absent marks preserve that
original time. A later root, lease, upload, repair, or population that makes the
object live clears it. An object becomes age-eligible only after
`unreferenced_since + unreferenced grace`; subscription removal grace is
applied before this cache-wide clock starts.

### Portable cache epoch

Each binary cache owns one monotonic GC epoch in its GC state row. Every
mutation that can invalidate collection advances that row in the same atomic
batch as its domain change:

- retention current-pointer, subscription retirement, manual-root, or lease
  mutation;
- cache object, narinfo/NAR mapping, reference-edge, tombstone, resurrection,
  upload, or population publication;
- complete logical/presence inventory publication;
- cache placement, placement-policy, replication, repair, or drain state that
  can change physical targets; and
- creation, completion, or cancellation of an object-mutation fence.

Routes that only change delivery do not affect logical membership and do not
advance the epoch. A desired/observed write-authority CAS alone also does not
change membership, inventory, or deletion targets and retains its portable
single-row contract. Reconciliation that can publish bytes creates an object-
mutation fence first; that fence, its publication, and any placement lifecycle
or presence change advance the epoch. GC never changes or derives write
authority.
Informational root, graph, inventory, and topology generation fields remain in
plans for explanation, but the single epoch is the portable race arbiter.

Native SQL transactions and Worker D1 atomic batches implement the same rule.
A one-row mutation combines its domain and epoch CAS in one statement and sets
`epoch_owner_token` to its operation token. A multi-row mutation first creates
a claim unique on `(cache_id, expected_epoch)`, advances the epoch while setting
that claim as `epoch_owner_token`, and gates every write and final assertion on
both the claim and matching owner token. It uses the final `CHECK (ok = 1)`
pattern defined for GC apply below and never assumes that a zero affected-row
statement aborts a D1 batch. A root refresh and GC apply, or two applies, racing
from one epoch therefore have exactly one winner.

## Logical GC and placement GC

Multiple placements introduce two distinct operations.

### Logical cache GC

Logical GC decides whether an object belongs in the binary cache namespace.
Once all root reasons and grace periods expire, the object becomes logically
collectable. Logical deletion removes the narinfo and NAR from every placement
according to a durable deletion job.

The logical metadata is retained as a tombstone until all required placement
deletions are confirmed or administratively abandoned. This makes partial
backend failures recoverable and auditable.

The target set comes from a complete observed physical inventory, not only
from desired placement policy. Complete replicas, shard members that actually
contain the object, archives, partial tiers, and off-policy extra copies all
receive actions. An archival or legal hold must be represented as a retention
reason that prevents logical collection; archive kind is not an implicit
exception after the namespace object is tombstoned.

### Placement repair and eviction

Placement policy decides where a logically live object must be present:

- The placement derived as primary from observed write authority, and every
  complete replica placement, retain every logically live object.
- Shards retain live objects selected by their `hash_range_v1` interval.
- Archive placements follow their own archival replication policy.
- A complete placement may not evict a logically live object merely to satisfy
  a local byte cap; it becomes over-cap or loses its complete designation.
- A partial read-through tier may evict live objects only if its route has a
  guaranteed fallback to another complete placement.

Thus “GC from the cache” and “evict from one tier” are separate operations.
The former changes namespace membership; the latter changes physical presence.
Authority-free or write-blocked state does not make live objects collectable,
and a pending desired authority does not transfer GC responsibility before its
observed generation reconciles.

## Replication and deletion ordering

Replication is immutable-first and idempotent. For registries, mutable pointers
advance only after required immutable presence. For binary caches, narinfo is
published only after its referenced NAR is present on the placement.

Deletion reverses publication ordering:

1. stop selecting the object/placement for new responses;
2. delete narinfo or mutable discoverability at each observed placement;
3. confirm its absence, then delete the NAR/object only after that placement's
   active narinfo refcount reaches zero; and
4. confirm presence-state deletion.

A durable action records its plan/operation, object and placement, phase,
dependencies, expected content hash/ETag and inventory generation, attempt
count, next retry, and terminal result. Retries use bounded exponential backoff
with jitter. Backend not-found is success only when the expected object version
has not been republished; an ETag or generation mismatch is stale, not deleted.
A failed deletion retains evidence that bytes may exist. Administrative
abandonment records leaked bytes and permits tombstone lifecycle completion,
but never reports them as reclaimed. Database state must not claim storage was
freed until the backend confirms it.

An abandoned narinfo action never satisfies a NAR dependency. Its possible
discoverability keeps the placement-scoped NAR refcount nonzero, so the
dependent NAR action becomes blocked and cannot run. Completing the logical
operation then requires a separate reviewed abandonment of that blocked NAR
action, recording its possible bytes as leaked. “All prerequisites terminal”
is insufficient; every NAR prerequisite must be `succeeded`.

At most one active deletion job exists globally for one surface object and
placement, independent of plan. Job ids are deterministic from the action, and
retry/apply reuses the existing preparing, pending, running, or failed row
rather than creating parallel deletes. Confirmed reclaimed bytes are recorded
once by the terminal success CAS from the observed placement size. Operation
totals are sums of unique successful jobs; retry, not-found reconciliation, and
shared-NAR fan-in cannot count the same placement object twice. Abandoned and
blocked jobs contribute only to the separate leaked-byte total.

Logical collection and physical deletion are decoupled by a durable operation.
A crash before or after a backend delete is safe to retry, and one failed
placement does not erase successful progress at the others.

## Capacity and age policy

Global cache policy carries:

- unreferenced grace/TTL;
- soft logical byte and object caps;
- GC schedule;
- deletion concurrency and retry policy; and
- tombstone retention.

Placement policy carries physical quotas and tiering behavior. Retention
selectors do not live in the global cache policy.

Rooted closures are never logically evicted to satisfy a soft cap. A cache
whose live closure exceeds its cap reports a quota breach with the contributing
subscriptions and root sizes.

## Immutable plan and guarded apply

`PlanCacheGc` first creates a complete mark, then records an immutable,
expiring candidate manifest. For every candidate it includes eligibility
reason, `unreferenced_since`, logical object version, projected bytes, and every
placement action and dependency. Estimated NAR bytes distinguish shared bytes
from bytes that become reclaimable only after the last placement-scoped
reference disappears.

The plan captures the cache epoch plus root, object-graph, inventory, policy,
and topology versions.
`RunCacheGc(plan_id)` never recomputes a more destructive set. Its one
control-plane compare-and-set verifies the plan identity, actor/scope,
confirmation hash, expiry, every input version and candidate state, and the
absence of population, replication, repair, or publication work touching those
candidates. Any mismatch rejects the whole logical apply as stale with zero new
tombstones or deletion jobs.

Successful apply uses one guarded statement batch inside a native transaction
or D1 atomic batch. In order it:

1. inserts a unique apply claim with one `INSERT ... SELECT` whose predicate
   includes the expected epoch, unused/unexpired plan, actor/scope,
   confirmation, manifest counts, every candidate version,
   `unreferenced_since`, active-root absence, placement observation, and
   mutation-fence absence;
2. advances the cache epoch, stores the winning claim as `epoch_owner_token`,
   and performs every later write only when the state row still identifies that
   claim at the expected successor epoch;
3. tombstones the logical cache objects and affected narinfo/NAR surface
   objects, incrementing their versions and the graph generation;
4. creates one deterministic operation and deterministic initial jobs in
   non-runnable preparation state;
5. exposes only dependency-ready narinfo jobs as pending; and
6. inserts an always-attempted final assertion row whose `CHECK (ok = 1)`
   verifies the claim and every expected final count.

Every mutation is claim-gated. A missing claim or partial result makes the final
portable constraint fail, so D1 rolls back without needing to inspect an
intermediate affected-row count. Retrying the same applied plan returns its
existing operation and jobs. A root refresh, manual-root mutation, lease
renewal, completed population, changed reference
edge, complete scan, placement change, fence mutation, or second apply racing
that transaction has one epoch-guarded winner. New roots that encounter an
existing tombstone fail closed and request repair or proven resurrection; they
never silently make an in-flight deletion safe.

## Access telemetry

Hub-proxied reads update access time directly with debouncing. Direct routes
may import CDN/gateway logs. Without an access signal, physical eviction uses
upload/observation age and says so in the console; it never weakens logical
retention correctness.

Access telemetry affects eviction preference only. It never creates or removes
a root reason.

## Standalone caches

A standalone cache has no registry retention subscriptions. It may still have:

- manual indefinite pins;
- expiring leases for CI/build outputs;
- population from `nix copy` or Hub cache upload APIs;
- several placements and routes; and
- ordinary TTL/capacity collection of unrooted objects.

Standalone does not mean unmanaged or non-GC. It means no registry-derived
root source exists. An empty registry-root set is valid, but the same complete
object/presence inventory, immutable mark, unreferenced grace, plan/apply, and
first-sweep acknowledgement rules still apply.

## Safety gates

Before destructive GC is enabled for a migrated cache:

1. object and presence inventories complete a full scan;
2. release-artifact snapshots exist for every selector that depends on them;
3. retention subscriptions have completed at least one successful refresh;
4. an immutable unapplied plan reports root provenance and per-placement
   deletions;
5. no required placement is stale or unknown; and
6. an operator acknowledges the first real sweep.

Migration defaults to retain-all or current safe-superset behavior. The rewrite
must never turn schema migration into implicit reclamation.

Destructive apply is also blocked while a required subscription has not
refreshed to the registry's current indexed source revision, while population
or copying touches a candidate, or while any input version captured by the plan
has changed. These are safety failures, not warnings that `--yes` can bypass.
