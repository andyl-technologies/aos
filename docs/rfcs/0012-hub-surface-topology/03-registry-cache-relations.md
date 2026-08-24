# Registry and binary-cache relationships

## Independent resources

A binary cache is an organization- or instance-scoped Nix substituter whether
or not it is associated with a registry. It has its own identity, signing key,
placements, routes, object inventory, retention policy, and GC history.

A registry is likewise independently servable. Its own URL remains
Nix-cache-compatible and may be the client's fallback when its signed consumer
cache stack is empty.

The topology supports:

- a standalone binary cache used only by stock Nix;
- one registry using several caches on different bindings;
- several registries sharing one cache;
- a registry publishing an external cache it does not control;
- a cache retaining registry artifacts without being published to clients;
- an archival cache populated and retained but not ordinarily served; and
- a public cache shared by public and private registries, subject to explicit
  content-exposure acknowledgement.

## Three registry/cache relationships

### Consumer publication

Direction:

```text
Registry -> cache endpoint
```

Meaning: clients resolving this registry should use this endpoint according to
the signed consumer cache stack.

The stack is committed registry content. Managed cache selection in the
console drafts a signed config change; applying ordinary SQL state cannot
silently alter the stack.

Stack nodes retain the existing semantics:

```text
endpoint(url)
try [node, ...]       ordered fall-through; union coverage
mirror [node, ...]    equivalent replicas; every member must be complete
```

A managed endpoint is indexed with a stable `binary_cache_id` and
`route_id` in addition to the committed URL. External entries have no
managed identity. Managed identity is never inferred solely from current URL
string equality.

The portable signed representation continues to contain an HTTP URL. New
changes should prefer the cache's stable canonical URL. At cutover, every
committed URL must either name a normal route in the new topology or
be replaced through a signed registry change before the old route is removed.
There is no legacy URL-alias subsystem.

### Retention subscription

Direction:

```text
Binary cache <- registry artifact source
```

Meaning: selected registry artifact closures are GC roots in this cache.

Retention is per cache/registry pair and carries selectors such as current
catalog, channel targets, recent releases, exact tags, or all releases. It has
no client-publication or upload effect.

Several registries sharing a cache contribute independent root reasons. The
cache retains their union. Removing one subscription removes only the reasons
derived from that subscription. A successful refresh publishes an immutable
retention generation for that subscription; a failed refresh leaves its
preceding generation authoritative. Removal grace keeps the prior generation
live long enough for rollout and operator recovery.

Logical GC also snapshots a cache-wide root generation. A subscription refresh,
manual-root change, or lease renewal that commits after a GC plan was created
makes that plan stale. This is deliberate: a reviewed candidate set is never
silently expanded or applied against newer retention state.

### Population target

Direction:

```text
Registry release/build workflow -> binary cache
```

Meaning: matching artifacts should be uploaded into this cache during or after
publication.

Population policy defines required versus best-effort destinations, placement
write policy, validation gates, and repair behavior. It has no client
publication or GC effect.

An upload may satisfy a retention subscription, but the two records stay
independent: retention describes desired survival; population describes how
bytes arrive.

Population publishes NAR presence before narinfo discoverability and advances
the cache object-graph generation only after both metadata and reference edges
are durable. GC plans capture that generation. Population and GC therefore do
not coordinate by timing assumptions: a concurrent completed population makes
the older plan stale, while an in-flight population fences any object it may
publish from destructive apply.

## Coverage is a fourth, derived fact

Coverage is measured, not configured:

```text
configured -> reachable -> covered -> retained
```

- **Configured:** the endpoint is present in signed registry configuration.
- **Reachable:** representative endpoint requests succeed.
- **Covered:** the cache contains the required selected artifact closure.
- **Retained:** active root reasons protect that closure from GC.

Population is an automation status alongside these facts, not proof of
coverage. A failed upload can leave a configured population target uncovered.

For `try`, the union of members must satisfy the configured coverage policy.
For `mirror`, every member must independently satisfy it. A managed binary
cache with several complete placements is internally validated before its
route is counted as covered.

## Visibility

Consumer publication validates that every intended registry reader can use the
selected route. A public registry cannot publish a route requiring private Hub
credentials. A private registry may publish a public cache, but the console
warns that its NARs are publicly retrievable by hash.

Retention performs a separate exposure assessment. Rooting a private
registry's artifacts in a public cache may preserve otherwise undiscoverable
content in a public namespace. This requires an explicit acknowledgement or an
organization policy allowing public build outputs.

Population validates write authority without using read visibility as a proxy.
A public-read cache commonly has authenticated writes; the storage and
credential model must support that normal case.

## Shared caches

A shared cache is not a special subtype. It is a binary cache with multiple
independent integrations:

```text
Registry A --consumer entry-------> Shared cache route advertisement
Registry A --retention selector---> Shared cache
Registry A --population target----> Shared cache

Registry B --consumer entry-------> Shared cache route advertisement
Registry B --retention selector---> Shared cache

Registry C --retention selector---> Shared cache
```

Registry C may use the cache only for archival retention and never publish it.
Registry B may populate through an external builder rather than a Hub rule.

Cache ownership and authorization remain with the cache's organization. A
cross-organization integration requires explicit permission from both sides:
the registry principal may select its artifacts, and the cache principal may
accept reads, writes, or retention obligations as applicable.

Logical collection remains cache-wide. It marks the union of every active
subscription, manual root, and lease before selecting candidates. Removing
Registry A's subscription cannot collect an object still reachable from
Registry B, even when their reasons name different top-level store paths that
share part of a closure or a physical NAR.

## Registries spanning caches and bindings

A registry spans bindings by composing binary caches in its consumer
stack, not by attaching cache bindings directly to the registry:

```text
try
  mirror
    cache-us route advertisement -> cache-us placements on R2 and S3
    cache-eu route advertisement -> cache-eu placement on R2
  upstream public cache
  registry's own route advertisement
```

This separates client fallback from the internal placement topology of any one
cache. A cache may itself have multiple placements, but the client consumes a
logical endpoint rather than storage coordinates.

## User actions

The console may provide an “Integrate binary cache” workflow with independent
choices:

1. **Use for clients** — draft a change to the signed consumer cache stack.
2. **Protect artifacts** — create a retention subscription and selector.
3. **Upload releases** — create a population target.

Review shows three separate effects and audit entries. Unchecking one does not
silently undo either of the others.

There is no persisted generic “linked” state. A cache and registry are related
when one or more of these concrete records exists.
