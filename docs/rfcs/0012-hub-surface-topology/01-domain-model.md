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
`registries` and `binary_caches` tables if foreign-key and one-of constraints remain
enforceable.

A registry's Git layout and its Nix-compatible paths are one logical registry
surface. A binary cache is a separate Nix namespace even when a registry uses
it as its preferred substituter.

## Bindings

A binding describes how the Hub reaches an origin:

```text
Binding
  id
  org_id or instance scope
  kind = local_fs | s3 | r2 | deployment_r2
  bucket/root
  API endpoint
  region
  read credential reference
  write credential reference
  mint/admin credential references
  conditional-write and presign capabilities
  current_write_revision
  health

BindingWriteRevision
  binding_id
  revision
  write credential version reference
  write and conditional-write capability declaration
  immutable revision fingerprint
  capability fingerprint

BindingWriteObservation
  binding_id
  revision
  state = unknown | validating | valid | invalid
  validated_at
  error
```

The API endpoint is never a consumer URL. Public readability is a capability
of an origin or external gateway, not a substitute for an explicit delivery
route.

`deployment_r2` names a Cloudflare Worker R2 binding and has no HTTP endpoint
or object-store credential. It is the Worker-native storage path. `r2` names
the same storage class reached through its S3-compatible API and therefore has
the ordinary endpoint, signing-region, access-mode, and purpose-scoped
credential lifecycle. Native and Worker runtimes accept both portable API
bindings and their runtime-native optional bindings; choosing one never changes
the placement, route, retention, or consumer-cache model above it.

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
  binding_id
  prefix
  kind = complete | shard | archive
  desired_state = active | draining | offline
  desired_read_enabled
  hash_range_v1 = half-open start/end (shard only)
  read_priority
  write_spec_version

PlacementWriteCapability
  placement_id
  placement_write_spec_version
  binding_id
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
only objects selected by its typed `hash_range_v1` interval and cannot
independently claim to be a complete surface. An **archive** is a retention or
recovery copy excluded from ordinary reads, but may be restored or used as a
repair source.

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
PlacementPolicyRevision
  id
  surface
  revision
  kind = ordered_failover | local_then_remote | hash_partition
  immutable selector configuration

OrderedFailover
  ordered complete-placement ids

LocalThenRemote
  ordered { placement id, access_class = local | remote }
  local_boundary id + immutable revision
  allow_remote_fallback

HashPartition
  rule = hash_range_v1
  ordered { half-open range, ordered replica placement ids }
  ordered complete fallback placement ids

PolicyFailureContract
  retry = connect_failure | timeout_before_headers | origin_429 |
          origin_502 | origin_503 | origin_504 | presence_mismatch |
          verified_corruption
  never_retry = every other origin status or client/auth/protocol failure
```

Policies are immutable revisions so a route never observes half of an edit.
Changing membership, order, access class, or a partition range creates a new
revision and moves routes through their ordinary generation-guarded update.
Selection is per request but stable where the protocol requires related reads
to observe a consistent generation. Mutable registry pointers are selected
only from complete placements that have published the exact referenced
generation; shards never serve mutable pointers.

For a mutable registry request, route resolution snapshots the surface's
committed publication-head id before placement selection. Every candidate must
carry that exact publication watermark and all required presence records.
Selection and failover retain the snapshot for the request even if a newer head
commits concurrently; a retry never re-resolves to a different head.

`ordered_failover` is the baseline portable policy. `local_then_remote` is the
same deterministic ordering with an explicit request access class; geography
is never inferred from untrusted forwarding headers. `hash_partition` uses the
versioned rule below. A latency-preferred strategy is deliberately absent until
portable, trustworthy latency observations and anti-flapping semantics exist.

`hash_range_v1` operates on the required 32-byte `partition_key` stored on each
immutable `SurfaceObject`; routers never derive it independently from an HTTP
path. Indexing computes that key as SHA-256 over this exact byte sequence:

```text
"aos-hub-surface-object-v1\0" || kind:u8 || key_length:u32be || canonical_key
```

The kind tags and canonical keys are: `0x01`, Git object algorithm byte plus
raw object digest; `0x02`, Git pack algorithm byte plus raw pack checksum;
`0x03`, release artifact content-hash algorithm byte plus raw digest; `0x11`,
raw 20-byte Nix store hash for a narinfo; and `0x12`, NAR hash algorithm byte
plus raw digest. Release paths and mutable Git/channel/release pointers are not
partition identities. New object kinds require a new assigned tag in this RFC
before they can join this selector.

Digest algorithm bytes are `0x00` MD5, `0x01` SHA-1, `0x02` SHA-256, and
`0x03` SHA-512. Git objects and packs accept only their repository's declared
SHA-1 or SHA-256 object format. An unsupported algorithm is ineligible rather
than mapped to a string spelling.

The selector digest is SHA-256 over
`"aos-hub-hash-range-v1\0" || partition_key`; its first two bytes are one
unsigned big-endian bucket in `[0, 65535]`. Ranges are half-open,
non-wrapping integer intervals `[start, end)` with
`0 <= start < end <= 65536`. Bounds use an unsigned 32-bit wire/storage type so
the exclusive full-range end is representable. Each range owns an ordered replica group. Distinct ranges
must not overlap; identical ranges are represented once with several replicas.
The union of ranges must cover the whole bucket space unless the policy has at
least one complete fallback. Native Hub and Worker use the shared stored key,
this exact encoding, and these normative selector vectors:

| `partition_key` bytes | selector SHA-256 hex | bucket |
| --- | --- | ---: |
| 32 `00` bytes | `c84df95b5544ccded87876f4a24fc63445f48af7dcddac6af26f2a7a7742abda` | 51277 |
| `00 01 ... 1f` | `5266775ea5f5297e717cfd66abe696828282822c7793ad0d5c5ab0b0fc5f0cbc` | 21094 |
| 32 `ff` bytes | `5de6f7beb4067b866bc9835b476fd57f583f208dd247679ef8098bfd65aa4b01` | 24038 |

Partition-key derivation has these additional normative vectors:

| Logical object identity | `partition_key` SHA-256 hex | selector bucket |
| --- | --- | ---: |
| Git object, SHA-1, 20 zero digest bytes | `53966266be3ec6639ef217cb4e16996fc1e69833512df48ba9e091f7f1b147d8` | 52736 |
| Narinfo, 20 zero store-hash bytes | `9cda12e164949c4166f051e41f7103f66fa097c380c333263b73a0bc2f58f939` | 22494 |
| NAR, SHA-256, digest bytes `00` through `1f` | `0a5e8e4a54ac17e4130754a6b3d2c2328994bba50864aed8b53e670aaf1f6529` | 20101 |

## Logical objects and physical presence

Multiple placements require separate logical inventory from physical presence:

```text
SurfaceObject
  surface_id
  object_key or store_hash
  immutable identity/metadata
  partition_key (32 bytes, immutable objects only)

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

## Domains, endpoints, and routes

A domain owns DNS-name lifecycle independently of any endpoint or route:

```text
Domain
  id
  org_id or instance scope
  hostname
  verification state
  DNS provider/state
  certificate provider/state
```

One domain can back several client-facing origins. IP literals and custom ports
are endpoints, not fake domains or opaque URL strings:

The domain's canonical hostname and owner scope are immutable. Changing the
DNS name creates a replacement domain and then replacement endpoints; DNS and
certificate-provider posture remains revisioned lifecycle configuration.

```text
Endpoint
  id
  owner scope
  scheme = https | http
  host = domain id | canonical IPv4 bytes | canonical IPv6 bytes
  effective port
  immutable network policy id
  desired/observed endpoint generation

EndpointRevision
  endpoint id + immutable generation
  network policy revision
  ingress kind = hub | external | layer7
  desired listener, TLS, and probe posture

NetworkPolicy
  stable scoped realm identity and kind
  immutable desired protection/trusted-ingress revision
  per-revision verification and staged/active/retiring lifecycle
```

DNS hosts are IDNA A-labels. IPv4 and IPv6 are stored as 4 or 16 canonical
bytes; IPv4-mapped IPv6 and zone ids are rejected, and IPv6 is bracketed only
when rendering a URL. Default ports 443/80 remain explicit identity fields but
are omitted in rendered origins. An HTTPS DNS endpoint requires SNI and Host to
agree; an HTTPS IP endpoint requires a matching IP subject alternative name.
The network-boundary component distinguishes repeated private addresses in
different VPN/VPC realms. An endpoint owner explicitly grants the consumer
scopes that may attach routes; organization creation never inherits endpoint
access or pretends the organization owns the DNS name. Origin/realm identity is
immutable. Ingress and listener changes
create a new endpoint generation, while an origin or realm change creates a
replacement endpoint and an impact-planned route/gateway move.

A route maps a path on that endpoint to a surface:

```text
Route
  id
  endpoint id + immutable generation
  base_path
  surface
  mode
  access_policy
  gateway_id and gateway_generation (direct only)
  placement_id or placement_policy_revision_id
  capabilities = git | nix_cache | web
  canonical
  enabled
  health
```

`(endpoint_id, normalized_base_path)` is globally unique. A direct route requires
one complete placement plus one gateway on that placement's binding and pins
the gateway's observed generation and the gateway-derived client path. It
cannot select a policy. Hub proxy and
redirect routes select one placement or one immutable policy revision and
cannot reference a gateway. Composite foreign keys make the route,
target, gateway, and any canonical-route row belong to the same surface and
scope.

Longest-prefix matching is deterministic and matches only on a path-segment
boundary. Routing uses the raw request target before any framework decoding and
excludes the query. The HTTP/2 `:authority` or HTTP/1.1 `Host` must normalize to
the endpoint's exact host and effective port. Userinfo, fragments, trailing-dot
aliases, invalid IDNA, zone ids, IPv4-mapped IPv6, missing/mismatched custom
ports, and disagreement with TLS SNI or the actual listener scheme are
rejected. Scheme/authority/host forwarding headers are honored only from the
endpoint's configured mutually authenticated ingress and replace, rather than
merge with, untrusted client headers.

Base paths have one leading slash and no trailing slash except `/`. The raw
path scanner rejects invalid percent escapes and any encoded ASCII byte,
including encoded or double-encoded percent, slash, backslash, dot, or NUL.
Percent encoding is accepted only for non-ASCII octets that decode once to
valid UTF-8; matching then uses decoded Unicode normalized to NFC. Literal
backslash, NUL, `.`/`..` segments, and empty interior segments are rejected.
The stored route path uses the same canonical form.

On configured Hub control endpoints, an exact `-` path segment and the leading
`/_assets`, `/login`, `/logout`, and `/aos.hub.v1.*` namespaces are classified
before tenant delivery and cannot be route bases. On delivery-only custom
endpoints those reserved requests return not found and never fall through to a
surface. Native Hub, Worker, and declared layer-7 ingress share this parser and
fixed routing vectors.

Route resolution returns a typed result containing the matched route, surface,
capability, access contract, and pinned placement or immutable policy revision.
It does not rewrite the request into a legacy slug path. Route creation
validates that the selected placement or policy can implement every declared
capability.

A surface may have any number of routes. Exactly one route may be canonical
for each protocol audience when setup snippets require a single URL. Other
routes remain simultaneously usable.

## Gateways

A gateway is a reusable direct mapping over a binding:

```text
Gateway
  id
  org_id or instance scope
  enabled
  desired/observed generation and reconciliation state

GatewayRevision
  gateway id + immutable generation
  endpoint id + immutable generation
  client base path
  binding_id
  origin prefix
  access policy
  content digest
```

A complete placement on that binding is eligible for a user-owned direct route
whose base path is exactly
`join_segments(gateway.client_base_path, placement.prefix)`. The route is
explicitly created, represented, and validated as a route and pins its
exact source gateway revision; gateway reconciliation never creates or mutates
it. Revisions remain immutable while routes reference
them, so an external gateway cannot change path or access behavior underneath a
live route.

Gateway path composition has one definition:

```text
route.base_path = join_segments(gateway_revision.client_base_path,
                                placement.prefix)

origin_path = join_segments(gateway_revision.origin_prefix,
                            placement.prefix,
                            request.path relative to route.base_path)

gateway client base /cache + origin /objects + placement acme/cache produces
route /cache/acme/cache; request /cache/acme/cache/nar/abc.nar maps to
/objects/acme/cache/nar/abc.nar
```

Every component is stored in the canonical segment form above;
`join_segments` performs no second decoding and proves the result remains below
`gateway_revision.origin_prefix`. A direct route records the gateway
and endpoint generations, client base, placement prefix, and binding that
produced this mapping; composite constraints validate the exact gateway and
placement inputs. Arbitrary client-path-to-prefix mapping is not supported in
this revision. Gateway reconciliation configures and probes only the selected
external generation and atomically advances its observed state; it never
enables, disables, creates, updates, replaces, or deletes a route. A route is
not enabled, advertised, or reported healthy until its explicitly pinned
gateway generation is reconciled. A gateway revision cannot retire while any
route pins it.

This replaces the current combination of a binding-targeted frontend and a
resource-level `advertise_storage_frontend` toggle. Operators see the concrete
derived URL, eligibility, access posture, and route health on the surface.

Instance and organization topology defaults may nominate a binding,
endpoint, and gateway for creation workflows. Organization values
override instance values. Defaults never retarget an existing placement or
route; that always requires its own impact plan and apply. Defaults affect only
proposal construction: creating a registry or cache never creates a placement,
and every placement remains an independently planned and applied object.
