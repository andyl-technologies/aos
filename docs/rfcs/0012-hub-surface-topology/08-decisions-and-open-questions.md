# Decisions and open questions

## Locked decisions

### D1: registries and binary caches are logical surfaces

Their identity is independent of storage and URL. They share topology
machinery without collapsing their payload models.

### D2: multiple placements ship in the first topology implementation

Placement kind, desired lifecycle, observed condition, and object presence are
first-class. The migration creates one complete placement for every existing
surface and a separate single-writer authority only for each proven writable,
validated, unambiguous legacy surface before adding more complete placements,
shards, or archives.

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
mode in the new runtime. Only an explicitly writable legacy surface with one
validated, unambiguous destination receives authority; explicitly read-only
surfaces remain authority-free and unproven declared writability aborts.

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

### D18: write authority is one per-surface resource

Placements do not store primary role, write enablement, write order, or nullable
primary-discriminator columns. One authority row records desired and observed
placement revisions and generations. Primary role and effective write
eligibility are read projections. Promotion is a compare-and-swap on that one
row, guarded by authority, current-writer, and candidate versions; no API or
runtime swaps flags between placement rows.

Desired authority may reconcile synchronously or through an explicit pending
generation. Generation disagreement and uncertain candidate health fail Hub
writes closed. Writer-critical placement revisions are pinned by same-surface
composite foreign keys so concurrent drain, delete, or kind changes cannot
commit around promotion on any supported database.

### D19: placement intent and observation are separate records

Placement kind, desired lifecycle, and desired read selection are operator
intent. Readiness, completeness, health, and publication progress are observed
state and remain writable while authority is pinned. A degraded primary stays
the authority until an explicit promotion; health never silently elects a
writer.

Generic placement observation owns health/completeness and cascades with its
placement. Registry mutable-publication watermark is a separate registry-only
record with same-registry composite foreign keys. Effective read eligibility
is request-relative and requires desired selection, observed health/coverage,
policy or shard membership, object presence, and publication watermark.

### D20: binding write capability is immutable, versioned, and pinned

Each binding write/credential capability is an immutable revision with a
separate validation observation. A placement topology write-spec maps to one or
more binding revisions, and desired/observed authority pin one exact mapping.
Rotation fans out authority CAS operations while old and new validated
revisions coexist. Immediate `ON DELETE/UPDATE RESTRICT` foreign keys prevent a
Hub-managed revision from disappearing under a concurrent promotion; external
invalidation blocks writes without moving authority.

### D21: route resolution is canonical and shared

Native Hub and Worker classify control paths first, then use one hostname/path
normalizer, segment-boundary longest match, typed route result, capability and
authorization checks, immutable policy selector, and exact presence/publication
predicate. Encoded separators and ambiguous paths are rejected. A direct route
that reaches Hub is not silently proxied.

### D22: the initial placement selectors are deterministic

The supported immutable policy revisions are ordered failover, trusted-access-
class local-then-remote, and `hash_range_v1`. The shard selector is domain-
separated SHA-256 over canonical immutable object identity with a 16-bit
big-endian bucket. Each range is stored once with an ordered replica group;
distinct ranges cannot overlap, and uncovered ranges require a complete
fallback. Shards do not serve mutable pointers.
Latency-preferred selection is not shipped without a separate observation and
anti-flapping design.

### D23: direct delivery is one reconciled concrete mapping

A direct route pins one complete placement through one immutable, reconciled
storage-gateway revision. Its external component enforces access; it does not
perform AOS placement selection. Mixed direct and Hub paths on one endpoint origin
require declared layer-7 ingress. Hub-authorized redirects run the complete
authorization and eligibility pipeline before minting a short-lived,
path-specific capability.

### D24: client URL origins are typed delivery endpoints

`Domain` remains DNS-name ownership/certificate lifecycle. `DeliveryEndpoint`
owns scheme, DNS or canonical IP host, effective port, ingress/network realm,
and observed listener/TLS posture. Routes and gateway revisions reference an
endpoint; they do not store opaque URLs or overload Domain with IP literals.
Instance endpoint grants make shared Hub origins available to organizations
without transferring ownership. Plain HTTP is explicit and never carries Hub
or origin secrets over unprotected cleartext.

### D25: network boundaries are revisioned security resources

`NetworkBoundary` has immutable scoped realm identity derived from a typed
public, provider-resource, stable allowlist-resource, or trusted-listener
specification. Its immutable desired revisions pin protected-transport
requirements, trusted-ingress verification references, probe location, and
source-allowlist CIDR membership. Reconciliation records verification per
exact revision, allowing overlapping active revisions during consumer moves.
Endpoints pin an exact boundary and
revision, and cross-scope use requires exact materialized grants. Unknown,
stale, mismatched, or degraded observation fails closed for credential-bearing
HTTP, local access classification, and private redirect eligibility. A CLI or
Web form cannot assert protection as an endpoint-local flag.
The public realm is the deployment-provisioned, instance-owned,
non-revisable `instance:public@1` singleton with eagerly materialized exact
organization grants; public endpoint creation still references it explicitly.

## Rejected conflations

- Storage binding endpoint as consumer URL.
- Physical bucket equality as logical binding identity.
- Binding frontend inheritance as invisible route creation.
- Domain name as a full URL, listener, access policy, or IP-literal container.
- A direct route as proof that a private resource is protected.
- Cache publication as a flag on a GC relationship.
- Retention as proof that bytes are present.
- Population as proof of coverage.
- URL string equality as managed-cache identity.
- A complete replica and a partial shard as the same placement role.
- Primary role or write enablement as independently mutable placement fields.
- Desired lifecycle and observed placement health as one state column.
- Logical cache GC and local tier eviction as one operation.

## Bounded open questions

### O1: controlled multi-writer policy details

The locked baseline is one desired/observed writer authority plus any number of
complete replicas. A future controlled multi-writer mode uses immutable
write-policy revisions and explicit members selected by the authority row; it
does not restore placement write booleans or write order. Payload eligibility,
conditional-write capabilities, fencing, quorum, and conflict semantics remain
open and require a separate authorization before widening the `single_writer`
mode constraint.

### O2: canonical Hub proxy versus redirect default

Public canonical endpoints may proxy, redirect, or select based on object size.
The choice affects cost, observability, and cache behavior but not identity.
Benchmarks in Phase 2 choose the default; private routes retain policy control.

### O3: external access-provider verification depth

Some providers expose APIs the Hub can verify; a private VPN may offer only an
operator assertion and an in-network probe. The UI must distinguish verified,
probed, and declared-only states. Exact provider adapters are incremental.

### O4: canonical managed identity in portable registry config

The required wire value remains a URL. A future optional stable cache-id hint
could improve imports and mirrors, but clients must not require Hub-specific
identity metadata to use a standard Nix cache.

### O5: release snapshot storage growth

Artifact rows may be deduplicated by commit/tree digest or stored as compact
content-addressed artifact sets. The logical contract is immutable release to
artifact mapping; physical database optimization is implementation work.

### O6: default recent-release count

This RFC recommends five for new subscriptions, subject to observed closure
sizes and operator feedback. The selector and UI must remain explicit so this
default can change without altering existing subscriptions.
