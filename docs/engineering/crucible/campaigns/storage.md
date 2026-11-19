# Campaign storage

Campaign storage is one content-addressed object model implemented by a
validated graph of small storage components. Memory, directory, SQLite, packed,
and S3-compatible storage are leaf drivers, not campaign concepts. Routing,
tiering, packing, verification, compression, encryption, quotas, write-back,
and eviction are composable layers whose physical choices never enter campaign
or configuration identity.

The contracts live in `crucible_store::content_store` and
`crucible_store::content_envelope`; the AWS SDK transport for the S3 leaf
lives in `crucible-store-s3`. Daemon-side composition, GC, retention, and
transfer live in `crucible-daemon` (`campaign_store_composition`,
`campaign_store_quota`, `campaign_gc`, `campaign_retention`,
`exact_pin_retention`, `campaign_transfer`).

One campaign namespace has one authoritative mutable ref backend. Immutable
content may occupy any number of tiers. Archival transfer and offline
maintenance transfer are supported; concurrent multi-host execution and
multi-writer convergence are not.

## Content envelope

```text
ContentId = H(object-kind domain tag, canonical schema version,
              canonical plaintext length, canonical plaintext bytes)
```

Structured objects use a generic, bounded, versioned envelope below campaign
semantics:

```text
"CRUCOBJE" | envelope-version
schema-name | schema-version
sorted-set(role, child-ContentId)
body-length | record-specific canonical body
```

The full envelope bytes are what `ContentId` hashes; the body has no second
identity. Child roles and IDs are part of identity. The parser rejects
duplicate or out-of-order children, noncanonical ID text, unknown framing,
trailing bytes, and oversized objects. Generic storage, transfer, retention,
and GC code walk closures with only this parser, while record-owning crates
additionally verify that the advertised children exactly match the references
decoded from the body.

Closure verification is iterative, duplicate-aware, and bounded. Deliberately
opaque leaves (RAM and disk extents, VMState, trace segments) are streamed and
authenticated to end-of-file but not parsed. A missing child, wrong record
subtype, malformed ancestry transition, cycle, or traversal-limit breach rejects
publication or import rather than producing a partially readable head.

Compression, encryption, sparse representation, pack membership and offsets,
paths, buckets, multipart layout, tier, cache state, and copy count are
physical placement and can change without changing the logical ID.

| Class | Examples | Requirement |
| --- | --- | --- |
| Canonical semantic state | Policy, configuration, branch request, proposal, attempt, observation, finding, snapshot | Reachable from the campaign ref and durable before ref publication |
| Durable acceleration | Exact closures, RAM and disk extents, retained indexes | Required only when named by a durable retention root |
| Rebuildable projection | Frontier, statistics, coverage indexes | May be evicted and recomputed |
| Ephemeral operation | Reservations, PIDs, sockets, hot templates, host paths, placement receipts | Never campaign state |

A campaign stays semantically readable when every ephemeral record and every
unpinned acceleration or projection is absent.

## Blob and ref interfaces

```rust,ignore
pub trait ImmutableBlobBackend: Send + Sync {
    fn capabilities(&self) -> BackendCapabilities;
    fn contains(&self, id: ContentId) -> Result<bool, StoreError>;
    fn read(&self, id: ContentId, range: Option<ByteRange>)
        -> Result<BlobHandle, StoreError>;
    fn put_if_absent(&self, id: ContentId, source: &BlobHandle)
        -> Result<PutReceipt, StoreError>;
}

pub trait MutableRefBackend: Send + Sync {
    fn capabilities(&self) -> RefBackendCapabilities;
    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError>;
    fn compare_exchange(&self, name: &RefName,
                        expected: Option<ContentId>, next: ContentId)
        -> Result<RefCasOutcome, StoreError>;
}
```

- A `BlobSource` is finite and reopenable: every `open` returns the same bytes
  and exactly the declared length, so mirrors, retries, and promotion can
  reread it without holding a RAM-sized buffer.
- A read returns a handle promptly; whole-object authentication completes when
  a stream reaches end-of-file. Consumers drain the stream and observe its
  result before publishing, restoring, or executing the bytes, and atomic
  consumers stage before publishing. Reading into memory requires an explicit
  maximum.
- Authentication evidence inside a handle is private, so routing and mirroring
  layers can preserve it, and a routed, mirrored write costs one streaming pass
  per physical placement rather than one hash pass per wrapper.
- The traits are synchronous and object-safe; the daemon runs blocking drivers
  on its bounded storage I/O pool.

Mutable refs are separate. Blob caches and mirrors compose freely, but refs are
never mirrored, cached, or reconciled by last-writer-wins, and a write-back
cache never acknowledges head durability before the authoritative conditional
update succeeds. The durable daemon profile requires a blob side that
advertises durable conditional creation and a ref side that advertises durable
comparison state; memory implementations are for tests and ephemeral use.

Administration is a separate capability. `BlobStoreAdmin` acquires a
`BlobInventoryFence` that excludes cooperating puts and repacks, streams exact
`(ContentId, length)` placements, returns a backend-instance-bound
`InventoryGeneration`, and permits deletion only of caller-selected candidates.
`RefStoreAdmin` similarly streams `(RefName, ContentId)` bindings under a
`RefInventoryFence` with a persistent generation that advances on every
accepted replacement, so delete-and-restore cannot recreate an earlier
generation. `S3MultipartCleanupAdmin` can only reclaim unfinished multipart
uploads. None of these computes reachability; the daemon combines them with
authenticated root reachability.

Store errors keep stable classes across drivers: missing, corrupt,
unauthorized, incompatible, quota, unavailable, conditional conflict,
unsupported capability, and `DurabilityUnsatisfied`. Errors never expose
credentials or sensitive host paths through the campaign API.

## Leaves

| Leaf | Notes |
| --- | --- |
| Memory | Bounded test or read cache; never sole durable storage |
| Directory | Same-filesystem staging, authentication, flush, atomic install, directory flush |
| Compressed, encrypted, compressed-encrypted directory | The same with physical encoding outside logical identity |
| SQLite | The default immutable leaf of the built-in campaign store |
| Packed | Many small logical objects in immutable physical packs with a durable resolution index |
| S3 | Immutable objects and multipart streaming through an S3-compatible API |
| Directory ref | Expected-value check under an advisory lock and atomic same-filesystem replacement |
| S3 ref | Conditional ref backend, admitted only when the service passes strong compare-and-swap conformance |

Directory durability flushes staged bytes, authenticates them, installs the
object atomically, and flushes the containing directory (and every newly
created ancestor). An idempotent put that finds an existing object still
flushes the directory. An error after a ref replacement may be an
indeterminate commit, so the coordinator re-reads the ref before retrying.
Directory read handles pin the opened inode, so unlink or replacement cannot
retarget an in-flight read.

The directory blob and ref leaves keep a persistent inventory state record
(`.inventory-admin` and `.ref-admin/state-v1`):

```text
version=1
instance=<64 lowercase hex>
generation=<canonical unsigned decimal u64>
checksum=<64 lowercase hex>
```

The checksum is BLAKE3 over the first three lines with a schema-specific
domain prefix, and the record is at most 256 bytes. `generation` advances
durably before every cooperating physical mutation, making delete-and-reinsert
distinguishable across restart. The directory root is operator-owned: a writer
that bypasses the lock invalidates the admission contract.

The S3 leaf binds graph configuration to a non-secret endpoint-policy
identifier; credentials, regions, retry policy, and HTTP details never enter
graph bytes. Objects live below `<prefix>/objects/<ContentId>`. Multipart
parts are 5 to 64 MiB and at most 10,000 parts are admitted. Every source is
authenticated before upload completes.

## Composition graph

`StoreNodeSpec` is a closed set of leaves and layers:

```text
Verified          authenticate logical bytes and envelopes
Routed            choose a child by authenticated object kind
Tiered            ordered reads, optional promotion, explicit write policy
ReadThrough       cache verified reads in a faster child
WriteThrough      require configured children before success
WriteBack         stage locally and expose archival progress
DurabilityPolicy  enforce per-kind durable placement requirements
LogicalQuota      bounded aggregate logical accounting
PhysicalQuota     require an authenticated kernel-enforced leaf quota
Metrics           counters and latencies without changing results
Namespaced        isolate deployments and authorization domains
ProfileValidated  derive and validate object profiles at the graph root
```

The configured graph is acyclic and built from these built-in layers only. A
route is selected from the authenticated envelope, never a caller hint.
Verification is against canonical plaintext, compression precedes encryption,
packing owns a durable index, and refs never enter the blob graph. A write-back
layer is valid only with a durable transfer journal whose pending IDs are GC
roots. Graph construction fails before campaign access when any route,
durability policy, or layer requires a capability its child lacks.

`crucible serve --campaign-store PATH` loads a
`crucible.campaign-repository-store` TOML deployment
(parsed in `crucible-cli/src/cli/verify_serve/campaign_store.rs`): an absolute, normalized,
exact-owner mode-`0600` regular file of at most 256 KiB with a closed schema.

```toml
schema = "crucible.campaign-repository-store"
version = 2
root = "profile"
admitted_kinds = [
  "campaign-fact", "campaign-snapshot", "merkle-node", "scenario",
  "configuration", "policy", "exact-manifest", "ram-extent",
  "disk-extent", "device-state", "observation", "finding", "projection",
  "trace",
]
ref_directory = "/var/lib/crucible/campaign-refs"
physical_quota_policies = []

[[keys]]
id = "campaign-key"
path = "/etc/crucible/campaign-store-key.bin"

[[nodes]]
id = "leaf"
[nodes.spec]
kind = "encrypted-directory"
root = "/var/lib/crucible/campaign-objects"
maximum_logical_object_bytes = 67108864
key_id = "campaign-key"

[[nodes]]
id = "profile"
[nodes.spec]
kind = "profile-validated"
child = "leaf"
policy = "crucible.campaign.object-profile.v1"
```

`admitted_kinds` must list every campaign object kind exactly once, so startup
cannot defer an unsupported repository operation. Node kinds are the
kebab-case spellings of the layers and leaves above, except that memory nodes
are rejected because they cannot satisfy durable daemon admission. Exactly one
of `ref_directory` or a remote `[s3_ref]` is required. Every physical,
journal, quota-state, and ref path must already exist, be absolute and
normalized, exact-owner, and not group- or other-writable. Key files are exact
32-byte, nonzero, mode-`0600` files; key bytes never enter graph identity.
`namespaces` entries grant `contains`, `read`, and `put` over the object
kinds. Graph construction returns the administration capabilities separately,
and the daemon never lends them to the campaign service, planner, runtime, or
executor. Operator commands for inspecting and collecting a composed store are
in [the user guide](../../../users/crucible/campaigns.md#inspect-and-collect-a-composed-store).

### Object profiles and durability

After envelope authentication the store derives an operational profile:

```text
SensitivityClass   := Metadata | Evidence | GuestState
Reconstructibility := Canonical | Rebuildable
RetentionRole      := CampaignMetadata | Evidence | ExactState | ProjectionCache
```

Configuration artifacts and opaque exact manifests, RAM, disk, and
device-state extents are `GuestState / Canonical / ExactState`. Measurement,
property, observation, objective, reproduction, finding, and trace records are
`Evidence / Canonical / Evidence`. Expansion, continuation, guidance, coverage,
and ranking projections are `Rebuildable / ProjectionCache`. Other campaign
records are `Metadata / Canonical / CampaignMetadata`. Profiles are derived
from the authenticated object, never trusted from a hint, and the
`ProfileValidated` and `Namespaced` boundaries may only sit at the root of the
graph.

A `PutReceipt` records which nodes verified an object and which durability
conditions hold. A `DurabilityPolicy` node requires, per object kind, a minimum
number of distinct durable backend placements (1 to 256) and whether deferred
writes are acceptable. A shortfall returns a typed failure after the immutable
write but before the caller may publish a ref; a write-back queue alone is
never durable completion.

## Publication and transfer

Publishing a snapshot:

1. persist new immutable facts and artifacts;
2. persist changed Merkle collection paths;
3. satisfy the required durability through the store graph;
4. persist the immutable snapshot;
5. read and verify the authoritative current ref;
6. compare-and-swap it from the expected parent to the new snapshot.

A conflict means stale command input or an ownership defect; concurrent writer
histories are never merged.

Archival transfer (`campaign_transfer`) walks missing objects from a snapshot
or closure ID, copies only missing logical content, verifies every object, and
then creates or advances the destination ref. Source and destination journals
record the same direct object inventory before copying, so transfer is
idempotent and resumable without either side holding both GC fences. Closure
policies are `metadata`, `findings`, `debug`, `executable`, and `mirror`; a
metadata archive can be inspected without downloading RAM. Exact restore
requires every execution-required object to be locally readable and
authenticated; there is no remote demand paging.

## Retention and garbage collection

Retention roots include every campaign ref, scenario and image roots, semantic
pins, finding and corpus pins, in-progress publication and transfer roots,
durable assignment-ledger checkpoint roots, hot-checkpoint fallbacks, and
pending write-back journal entries. A pin declares thin or exact retention.

- **Semantic pins.** Within a snapshot the pin projection is keyed by
  `ConfigurationId` and holds the latest accepted pin command; `None` is a
  tombstone. A paged, snapshot-bound inventory resolves each pinned
  configuration through the graph and emits the thin replay roots. An `Exact`
  pin additionally requires one complete portable exact closure.
- **Exact-pin selection.** `exact_pin_retention` keeps a single-writer journal
  that binds each exact pin to a concrete authenticated checkpoint root whose
  modeled configuration equals the pin target, choosing the
  content-address-least retained root. It is operational state and never
  advances the campaign ref.
- **Hot-checkpoint fallbacks.** A fixed 65,536-slot catalog records the exact
  or thin fallback of each retained hot source.

`campaign_gc` builds a canonical plan header, a logical-root manifest, and a
physical-candidate manifest, bound to every administrative generation (refs,
blob inventory, assignment ledger, journals, catalogs). Planning is
non-destructive. Apply reacquires every fence, requires the exact manifest
identities, and keeps the fences through candidate deletion, so a concurrent
pin, demotion, or publication cannot be raced into deletion. Apply is recorded
in a durable external journal and is interruption safe.

## Confidentiality

Content authentication protects integrity, not confidentiality or
authorization. Deployments use filesystem or bucket ACLs, encryption at rest,
and credential rotation appropriate to retained guest state. Encrypted leaves
wrap canonical plaintext, and replicas verify the plaintext digest after
decryption; key IDs and nonces are physical metadata. Content hash paths reveal
object equality and should not be exposed in untrusted namespaces.
