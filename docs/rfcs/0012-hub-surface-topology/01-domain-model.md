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
  current_write_revision
  health

StorageBindingWriteRevision
  storage_binding_id
  revision
  write credential version reference
  write and conditional-write capability declaration
  immutable revision fingerprint
  capability fingerprint

StorageBindingWriteObservation
  storage_binding_id
  revision
  state = unknown | validating | valid | invalid
  validated_at
  error
```

The API endpoint is never a consumer URL. Public readability is a capability
of an origin or external gateway, not a substitute for an explicit delivery
route.

Read, write, credential-minting, and administrative authority remain separate
because their blast radii differ. Credentials should be scoped to a placement
prefix whenever the backend permits it.

A binding write revision is immutable. Rotation or a capability declaration
change creates and validates a new revision, then advances the binding's
default pointer; it never edits the revision that an authority currently uses.
Revision identity includes the binding, credential-version reference, and
canonical capability declaration. The capability-only fingerprint is retained
for equivalence/display but is not unique, so rotating to a new credential with
unchanged capabilities still creates a distinct revision.
Validity is observed separately because a provider may revoke a credential or
lose a capability without a control-plane mutation. An invalid observation
makes effective writes fail closed but does not silently select another
revision or placement.

## Placements

A placement maps one surface into one binding prefix:

```text
Placement
  id
  surface
  storage_binding_id
  prefix
  kind = complete | shard | archive
  desired_state = active | draining | offline
  desired_read_enabled
  partition_rule
  read_priority
  write_spec_version

PlacementWriteCapability
  placement_id
  placement_write_spec_version
  storage_binding_id
  binding_write_revision

PlacementObservation
  placement_id
  state = provisioning | syncing | ready | degraded | offline
  completeness = complete | partial | unknown
  observed_at
  observation_version

RegistryPlacementPublicationWatermark
  placement_id
  registry_id
  mutable_publication_id
  observed_at
```

A surface may have several placements immediately. Prefix uniqueness is
enforced per binding unless an explicit placement-equivalence record says two
read-only placement views intentionally address the same bytes.

Placement kind describes intended coverage and service purpose. A **complete**
placement is expected to contain the whole advertised namespace and may serve
directly, participate in failover, or become the writer. A **shard** contains
only objects selected by a stable partition rule and cannot independently
claim to be a complete surface. An **archive** is a retention or recovery copy
excluded from ordinary reads, but may be restored or used as a repair source.

Desired state is operator intent. Observation is evidence reported by probes,
replication, and publication. A complete placement may therefore be observed
as partial or unknown while it is provisioning; kind does not manufacture a
claim that bytes are present. Observation changes remain possible when a
placement is the writer, including reporting that it has degraded or gone
offline.

The publication watermark is a registry-only observation. Composite
placement/registry and publication/registry references prevent a cache
placement or another registry's publication from being recorded. It advances
only after the placement has the publication's required immutable objects and
mutable pointers; request-relative read eligibility requires an exact
watermark match for mutable registry paths.

`write_spec_version` changes only when a writer-critical property changes,
such as kind, binding/prefix, required capability class, or desired lifecycle.
Credential rotation selects a new binding write revision under the same
topology write-spec version. Read ordering and health observations do not
change it. Write-authority references pin this version so promotion cannot race
a drain, delete, or incompatible placement change on PostgreSQL or MySQL.

Each immutable placement-write-capability row binds one topology write-spec
version to one immutable binding write revision. Several capability rows may
exist for the same placement write-spec during credential rotation. Authority
pins one exact row, so a one-placement surface can reconcile from an old
credential revision to a new one without mutating the pinned placement or
creating a fake second placement.

### Write authority and derived roles

Write selection belongs to one per-surface authority resource rather than to
each placement:

```text
SurfaceWriteAuthority
  surface
  mode = single_writer
  desired_placement_id
  desired_write_spec_version
  desired_binding_write_revision
  desired_generation
  observed_placement_id
  observed_write_spec_version
  observed_binding_write_revision
  observed_generation
  reconciliation_state = pending | ready | failed
  reconciliation_error
  resource_version
```

The desired placement is the reviewed control-plane intent. The observed
placement and generation identify the writer for which routing and any
required fencing have completed. A promotion either updates both halves in
one authority-row compare-and-swap when the switch is synchronous, or updates
desired state first and lets a reconciler complete the observed half with a
second authority-row compare-and-swap. It never edits roles on two placement
rows. A pending or failed promotion is retried or explicitly cancelled through
the same generation-guarded reconciliation; cancellation restores the old
observed writer only after the candidate is fenced.

Public placement role is a derived presentation:

- the observed authority placement is **primary**, including when its health
  is degraded;
- any other complete placement is a **replica**;
- shard and archive roles follow placement kind; and
- a desired candidate not yet observed is shown separately as **promotion
  pending**, not as a second primary.

Effective write eligibility is true only for the observed authority placement
when desired and observed generations agree, reconciliation is ready, the
placement is active and complete, and its observation is ready and complete.
The pinned binding write revision must also declare the required write
capabilities and have a `valid` observation. Generation disagreement, invalid
credentials, or uncertain health fails Hub writes closed. There is no stored
`write_enabled` or `write_order` field.

An arbitrary number of complete placements may coexist, but the initial mode
allows one reconciled writer. A future controlled multi-writer mode requires
an explicit immutable policy revision and member set for payload classes with
proven conditional-write and conflict behavior; it is not represented by
enabling several placements independently.

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
