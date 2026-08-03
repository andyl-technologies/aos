# Domain model

## Surfaces

`Registry` and `BinaryCache` are the two surface kinds. They share placement,
delivery, domain, health, and visibility machinery but retain distinct payload
and lifecycle schemas.

```text
Surface
  id
  kind = registry | binary_cache
  org_id
  stable_name
  visibility
  canonical_route_id

Registry
  surface_id
  project_id
  trust/signing/index fields

BinaryCache
  surface_id
  narinfo_signing_key_id
  nix_priority
  compression
  mass_query
```

This is a conceptual supertype. Implementations may retain separate
`registries` and `caches` tables if foreign-key and one-of constraints remain
enforceable.

A registry's Git layout and its Nix-compatible paths are one logical registry
surface. A binary cache is a separate Nix namespace even when a registry uses
it as its preferred substituter.

## Storage bindings

A storage binding describes how the Hub reaches an origin:

```text
StorageBinding
  id
  org_id or instance scope
  kind = local_fs | s3 | r2
  bucket/root
  API endpoint
  region
  read credential reference
  write credential reference
  mint/admin credential references
  conditional-write and presign capabilities
  health
```

The API endpoint is never a consumer URL. Public readability is a capability
of an origin or external gateway, not a substitute for an explicit delivery
route.

Read, write, credential-minting, and administrative authority remain separate
because their blast radii differ. Credentials should be scoped to a placement
prefix whenever the backend permits it.

## Placements

A placement maps one surface into one binding prefix:

```text
Placement
  id
  surface
  storage_binding_id
  prefix
  role = primary | replica | shard | archive
  read_enabled
  write_enabled
  state = provisioning | syncing | ready | degraded | draining | offline
  completeness = complete | partial | unknown
  partition_rule
  read_priority
  write_priority
```

A surface may have several placements immediately. Prefix uniqueness is
enforced per binding unless an explicit placement-equivalence record says two
read-only placement views intentionally address the same bytes.

### Roles

**Primary** is an authoritative upload destination. A surface normally has one
primary placement. A controlled multi-writer mode may be added only for
backends and payload classes with proven conflict-free conditional writes.

**Replica** is expected to contain the complete advertised namespace. It may
serve directly and participate in failover. Replication is immutable-first and
pointer-last.

**Shard** contains only the objects selected by a stable partition rule. It may
be selected behind a Hub route but cannot independently claim to be a complete
surface.

**Archive** is a retention or recovery copy not selected for ordinary reads.
It may be restored or used as a repair source.

### Placement groups and selection

A route either pins a placement or names a placement policy:

```text
PlacementPolicy
  ordered_failover [placement ids]
  latency_preferred [placement ids]
  hash_partition { rule, shard placement ids }
  local_then_remote [placement ids]
```

Selection is per request but stable where the protocol requires related reads
to observe a consistent generation. Mutable registry pointers may be served
only from placements that have completed the corresponding immutable phase.

`ordered_failover` is the baseline portable policy. Latency and sharding are
additive strategies, not implicit behavior hidden in placement priority.

## Logical objects and physical presence

Multiple placements require separate logical inventory from physical presence:

```text
SurfaceObject
  surface_id
  object_key or store_hash
  immutable identity/metadata

ObjectPresence
  surface_object_id
  placement_id
  state = present | copying | missing | corrupt | deleting
  size/hash/etag
  observed_at
```

For binary caches, logical `CacheObject` rows contain narinfo metadata and the
closure-reference graph. Presence records say where the narinfo and NAR bytes
exist. A content-addressed NAR shared by several narinfos is refcounted per
placement before physical deletion.

For registries, the same split tracks Git objects, packs, releases, channels,
and mutable pointer generations. The existing surface remains readable from a
single placement while presence indexing is introduced.

## Domains and routes

A domain owns hostname lifecycle independently of any route:

```text
Domain
  id
  org_id or instance scope
  hostname
  verification state
  TLS provider/state
  DNS provider/state
  access provider
  health
```

A delivery route maps a path on that domain to a surface:

```text
DeliveryRoute
  id
  domain_id
  base_path
  surface
  mode
  access_policy
  placement_id or placement_policy_id
  capabilities = git | nix_cache | web
  canonical
  enabled
  health
```

`(domain_id, normalized_base_path)` is globally unique. Longest-prefix matching
is deterministic. Route creation validates that the selected placement or
policy can implement every declared capability.

A surface may have any number of routes. Exactly one route may be canonical
for each protocol audience when setup snippets require a single URL. Other
routes remain simultaneously usable.

## Storage gateways

A storage gateway is a reusable direct mapping over a binding:

```text
StorageGateway
  id
  org_id or instance scope
  domain_id
  base_path
  storage_binding_id
  origin_path rewrite
  access policy
  enabled
  desired/observed generation and reconciliation state
```

A placement on that binding can derive a direct route by appending its prefix.
The derived route is still represented and validated as a delivery route and
records its source gateway/generation; it is not an invisible inheritance side
effect.

This replaces the current combination of a binding-targeted frontend and a
resource-level `advertise_storage_frontend` toggle. Operators see the concrete
derived URL, eligibility, access posture, and route health on the surface.

Instance and organization topology defaults may nominate a storage binding,
domain, and gateway for creation workflows. Organization values override
instance values. Defaults never retarget an existing placement or route; that
always requires its own impact plan and apply.
