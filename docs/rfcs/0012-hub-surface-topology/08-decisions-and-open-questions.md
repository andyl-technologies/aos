# Decisions and open questions

## Locked decisions

### D1: registries and binary caches are logical surfaces

Their identity is independent of storage and URL. They share topology
machinery without collapsing their payload models.

### D2: multiple placements ship in the first topology implementation

Placement roles and object presence are first-class. The migration creates one
primary placement for every existing surface before adding replicas or shards.

### D3: routes and placements are different layers

A route maps an HTTP path to a surface. It may pin a placement or invoke a
placement policy. Storage coordinates never appear in signed consumer config.

### D4: several routes operate simultaneously

Canonical selects stable references and generated snippets. It does not make
alternate routes inactive.

### D5: private direct serving requires declared external enforcement

Private surfaces normally use Hub auth. A direct route is permitted only when
an external identity provider, gateway, or private network is explicitly
modeled. A private origin alone is not client authentication.

### D6: publication, retention, and population are separate

There is no generic registry/cache link in the target model. A workflow may
create several relations, but each persists and audits independently.

### D7: signed registry configuration owns consumer publication

SQL topology may generate a change request but cannot silently change the
consumer cache stack. The legacy `advertised` link bit is removed.

### D8: stable canonical URLs decouple signed config from topology

Managed caches and registries have canonical Hub-controlled endpoints. Direct
routes remain available for explicit use, but ordinary signed cache entries
prefer stable endpoints.

### D9: retention is per cache/registry subscription

The cache-global GC policy controls sweep mechanics and quotas. Registry
release/channel selectors belong to the subscription.

### D10: historical retention uses release artifact snapshots

Latest-N and channel policies are not considered implemented until the indexer
records artifact sets from verified release commits. Current-catalog rooting
continues as a safe union member.

### D11: logical deletion differs from placement eviction

Logical GC removes namespace membership. Placement eviction/tiering changes
physical presence while preserving a guaranteed read path.

### D12: order is structural

Consumer stacks and placement policies use explicit list order. Nix cache
`Priority` retains its protocol meaning, lower preferred. No ambiguous generic
priority is shared across them.

### D13: production performs a complete cutover

Implementation may be developed in phases, but there is no production
dual-read period. The cutover transforms all data under maintenance, drops the
old schema, and deploys Web UI, CLI, API, native, and Worker together. Rollback
restores the pre-cutover database and deployment; it is not a permanent legacy
mode in the new runtime.

### D14: the public API becomes `aos.hub.v1`

The complete `aos.registry.v1` package is renamed, not extended indefinitely.
Old methods and generated client names are removed. The final server mounts
only the Hub namespace.

### D15: names are corrected during the cutover

The system-of-record object is `binary_caches`, signed consumer projections are
`registry_cache_stack_entries`, HTTP mappings are delivery routes, and storage
copies are placements. The final schema/API/source does not retain ambiguous
`frontends`, `cache_registry_links`, `advertised`, or storage-switch concepts.

### D16: retained URLs are ordinary routes

An existing public URL may survive only because the migration imports it as a
normal delivery route that satisfies all new invariants. There is no historical
URL alias table or special compatibility handler.

### D17: one settings shell and hierarchy serves every scope

Instance administration, organizations, registries, and binary caches use the
same grouped navigation, page anatomy, topology components, responsive
behavior, and default-first ordering. Overview is always the first item and the
scope root. Pages own one primary mutation domain; inventories, creation,
topology, policy, operations, and danger are not combined merely to reduce
route count.

## Rejected conflations

- Storage binding endpoint as consumer URL.
- Physical bucket equality as logical binding identity.
- Binding frontend inheritance as invisible route creation.
- A direct route as proof that a private resource is protected.
- Cache publication as a flag on a GC relationship.
- Retention as proof that bytes are present.
- Population as proof of coverage.
- URL string equality as managed-cache identity.
- A complete replica and a partial shard as the same placement role.
- Logical cache GC and local tier eviction as one operation.

## Bounded open questions

### O1: one primary or controlled multi-writer?

The baseline is one primary writer plus replicas. A future multi-writer policy
requires per-payload conflict analysis and conditional-write support. The
schema does not prevent adding it, but this RFC does not authorize it.

### O2: initial shard function

The first shard rule should be portable and immutable, likely a fixed prefix of
the store hash with a versioned rule id. The exact hash/range encoding is chosen
during Phase 6 and becomes persistent data; changing it requires resharding.

### O3: canonical Hub proxy versus redirect default

Public canonical endpoints may proxy, redirect, or select based on object size.
The choice affects cost, observability, and cache behavior but not identity.
Benchmarks in Phase 2 choose the default; private routes retain policy control.

### O4: external access-provider verification depth

Some providers expose APIs the Hub can verify; a private VPN may offer only an
operator assertion and an in-network probe. The UI must distinguish verified,
probed, and declared-only states. Exact provider adapters are incremental.

### O5: canonical managed identity in portable registry config

The required wire value remains a URL. A future optional stable cache-id hint
could improve imports and mirrors, but clients must not require Hub-specific
identity metadata to use a standard Nix cache.

### O6: release snapshot storage growth

Artifact rows may be deduplicated by commit/tree digest or stored as compact
content-addressed artifact sets. The logical contract is immutable release to
artifact mapping; physical database optimization is implementation work.

### O7: default recent-release count

This RFC recommends five for new subscriptions, subject to observed closure
sizes and operator feedback. The selector and UI must remain explicit so this
default can change without altering existing subscriptions.
