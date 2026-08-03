# Retention and garbage collection

## Correct source data

Retention by release requires an immutable artifact snapshot for each verified
release tag. The current registry index describes the current catalog and
records release tag/commit metadata, but it does not retain the package
artifact set read from each release commit.

Indexing therefore gains:

```text
RegistryRelease
  registry_id
  semver/tag oid/commit oid/tagged at

ReleaseArtifact
  release_id
  package
  package version
  platform
  kind = output | image | source_derivation
  store_path
  store_hash
```

The indexer verifies the release tag, reads the registry tree at its target
commit, and records the artifact set transactionally. Existing release
artifact snapshots remain intact when a later refresh fails.

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
  recent_releases { count }
  releases { exact tags }
  semver { requirement }
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

`current_catalog` deliberately preserves the current safe behavior: every
primary and image store path still published at the registry's current indexed
commit is rooted. Release selectors add historical correctness rather than
replacing current-catalog safety.

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

Refresh is transactional per subscription. A successful refresh inserts the
new desired set and retires stale reasons from that subscription. Failure keeps
the prior successful set and marks the subscription stale.

## Marking the closure

Root reasons name top-level store hashes. GC walks the transitive closure using
the binary cache's indexed narinfo `References`. Missing root objects are
reported as coverage failures but do not make other roots unsafe.

Cycles are harmless. Rooted objects and every reachable reference remain live.
An object remains live if any active reason reaches it.

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

### Placement repair and eviction

Placement policy decides where a logically live object must be present:

- Primary and complete replica placements retain every logically live object.
- Shards retain live objects selected by their partition rule.
- Archive placements follow their own archival replication policy.
- A complete placement may not evict a logically live object merely to satisfy
  a local byte cap; it becomes over-cap or loses its complete designation.
- A partial read-through tier may evict live objects only if its route has a
  guaranteed fallback to another complete placement.

Thus “GC from the cache” and “evict from one tier” are separate operations.
The former changes namespace membership; the latter changes physical presence.

## Replication and deletion ordering

Replication is immutable-first and idempotent. For registries, mutable pointers
advance only after required immutable presence. For binary caches, narinfo is
published only after its referenced NAR is present on the placement.

Deletion reverses publication ordering:

1. stop selecting the object/placement for new responses;
2. delete narinfo or mutable discoverability;
3. delete the NAR/object after per-placement refcount reaches zero; and
4. confirm presence-state deletion.

A failed deletion is retried. Database state must not claim storage was freed
until the backend confirms it.

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
root source exists.

## Safety gates

Before destructive GC is enabled for a migrated cache:

1. object and presence inventories complete a full scan;
2. release-artifact snapshots exist for every selector that depends on them;
3. retention subscriptions have completed at least one successful refresh;
4. a dry run reports root provenance and per-placement deletions;
5. no required placement is stale or unknown; and
6. an operator acknowledges the first real sweep.

Migration defaults to retain-all or current safe-superset behavior. The rewrite
must never turn schema migration into implicit reclamation.
