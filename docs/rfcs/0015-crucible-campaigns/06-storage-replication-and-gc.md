# 06 — Composable content stores, durability, retention, and garbage collection

Campaign storage is one content-addressed object model implemented by a
validated graph of small storage components. Directory, memory, NVMe, and
S3-compatible storage are leaf drivers, not campaign concepts. Routing,
tiering, packing, verification, compression, encryption, mirroring, promotion,
and eviction are composable layers whose physical choices never enter campaign
or configuration identity.

The supported deployment has one authoritative mutable ref backend per
campaign namespace. Immutable content may occupy any number of tiers. This RFC
supports archival transfer and offline maintenance transfer, not concurrent
multi-host campaign execution or multi-writer campaign convergence.

## 06.1 Logical objects and physical placement

```text
ContentId = H(
  object-kind domain tag,
  canonical schema version,
  canonical plaintext byte length,
  canonical plaintext bytes
)
```

Canonical structured objects use a generic, bounded, versioned plaintext
envelope below campaign semantics:

```text
"CRUCOBJE" | envelope-version
schema-name | schema-version
sorted-set(role, child-ContentId)
body-length | record-specific canonical body
```

The full envelope bytes are the plaintext bytes hashed by `ContentId`; the
record body does not receive a second identity. Child roles and IDs are part of
identity. The envelope parser rejects duplicate or out-of-order children,
noncanonical content-ID text, unknown framing, trailing bytes, and objects over
the hard size bound. A generic closure walker needs only this envelope parser;
record-owning crates additionally verify that the advertised children exactly
match references decoded from the body.

Logical object kinds include campaign facts and snapshots, scenario and policy
objects, page or extent bytes, exact-closure manifests, opaque VMState, disk
objects, logs, traces, coverage projections, and findings. A kind-specific ID
such as `PageId`, `ExactClosureId`, or `CampaignSnapshotId` is a typed
`ContentId`, not a storage location.

Record-typed API/CLI text uses `schema-name@kind.version.digest`; canonical
record bodies encode the same exact schema tag before the generic content ID.
This is a type-confusion boundary, not a second identity: the suffix is still
the sole content address, and loading it must authenticate an envelope with the
claimed registered schema.

Closure verification is iterative, duplicate-aware, and bounded. Structured
campaign objects and Merkle nodes are parsed and their role-tagged children are
walked; owner codecs additionally prove body/child correspondence and
cross-record constraints. Non-campaign structured kinds such as exact
manifests, observations, findings, and projections are still parsed as generic
envelopes so their children remain walkable; their owning crate performs the
stronger body validation. Scenario and configuration artifacts are owned
campaign envelopes with exact semantic cross-links; legacy raw forms must be
migrated explicitly before import. Deliberately opaque leaves such as RAM/disk
extents, VMState, and trace segments are drained through their authenticated
stream to EOF but are not parsed as envelopes. A missing child, wrong record
subtype, malformed ancestry transition, cycle, or traversal-limit breach
rejects publication/import rather than yielding a partially readable head.

Compression, encryption, sparse representation, pack membership, pack byte
range, local path, bucket, multipart layout, tier, cache state, and copy count
are physical placement. They may change without changing the logical ID.

| Class | Examples | Required behavior |
| --- | --- | --- |
| Canonical semantic state | Policy, configuration, branch request, proposal, attempt, observation, finding, snapshot | Reachable from campaign ref and durable before ref publication |
| Durable acceleration | Exact closure, RAM/disk extents, retained indexes | Required only when named by a durable retention root |
| Rebuildable projection | Frontier/statistics/coverage indexes | May be evicted and recomputed from canonical facts |
| Ephemeral operation | Reservations, PIDs, sockets, hot templates, RSS, host paths, placement receipts | Never campaign state |

- **[CSTORE-1]** A campaign MUST remain semantically readable when every
  ephemeral placement record and every unpinned acceleration or projection is
  absent.
- **[CSTORE-2]** Logical object identity MUST be domain-separated by object
  kind and schema and MUST be independent of backend, encoding, packing,
  encryption, and tier placement.

## 06.2 Immutable blob and mutable ref traits

The leaf interfaces are intentionally smaller than campaign storage:

```rust,illustrative
pub trait BlobSource: Send + Sync {
    fn logical_length(&self) -> u64;
    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError>;
}

pub trait ImmutableBlobBackend: Send + Sync {
    fn capabilities(&self) -> BackendCapabilities;
    fn contains(&self, id: ContentId) -> Result<bool, StoreError>;
    fn read(
        &self,
        id: ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError>;
    fn put_if_absent(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError>;
}

pub trait MutableRefBackend: Send + Sync {
    fn read_ref(&self, name: &RefName)
        -> Result<Option<ContentId>, StoreError>;
    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError>;
}

pub trait StoreAdmin: Send + Sync {
    fn inventory(&self) -> Result<InventoryGeneration, StoreError>;
    fn verify(&self, scope: VerifyScope) -> Result<VerifyReport, StoreError>;
    fn plan_gc(&self, roots: RootSetId) -> Result<GcPlanId, StoreError>;
    fn apply_gc(&self, plan: GcPlanId) -> Result<GcReport, StoreError>;
    fn repack(&self, plan: RepackPlanId) -> Result<RepackReport, StoreError>;
}
```

`StoreAdmin` above is the complete maintenance target, not authority granted to
a campaign repository. The current leaf checkpoint implements its physical
foundation as a separate `BlobStoreAdmin` capability on the memory, directory,
and packed blob leaves. An acquired `BlobInventoryFence` excludes cooperating
puts and repacks, streams exact `(ContentId, logical_length)` placements with
checked terminal counts, returns a backend-instance-bound
`InventoryGeneration`, and permits only exact caller-selected logical-candidate
deletion. A visitor can fail early when its own work bound is exhausted. Prefix
output is tentative until terminal enumeration succeeds, and the visitor cannot
reenter the exclusively fenced backend.

The same capability separation applies to authoritative names. `RefStoreAdmin`
is not part of `MutableRefBackend`; its `RefInventoryFence` excludes every
cooperating read and compare-and-swap in that namespace, streams exact
`(RefName, ContentId)` bindings, and returns a persistent
`RefInventoryGeneration`. Memory and directory implementations advance their
monotonic generation on every accepted replacement. A failed expected-value
comparison does not advance it. Delete-and-restore or change-and-restore ABA
therefore cannot recreate an earlier generation.

This primitive does not compute reachability or confer deletion authority on
`ImmutableBlobBackend`. The single-host daemon composes it with authenticated
root reachability, the canonical store-graph identity, ref and operational-root
generations, and the interruption-safe external journal specified below.
Policy-aware tier eviction, transform/S3 administration, and the complete
operator flight remain mandatory before T-CAM-8.3 is complete.

`BlobSource` is finite and reopenable: every `open` returns the same byte stream
and exactly `logical_length` bytes. Reopenability lets mirrors, retries, and
promotion reread a source without retaining a RAM-sized extent. Every leaf
still authenticates the particular stream it stores. `BlobHandle` implements
the same source contract, so verified reads can flow directly into another
backend. Reading a handle into a `Vec` requires an explicit caller-provided
maximum. A handle captures the source's declared length once; subsequent
changes to a source's length declaration cannot change an in-flight operation.

Authentication evidence inside a `BlobHandle` is private and cannot be forged
by a caller. A wrapper that has authenticated a source may preserve that
evidence through routing and mirroring, while every physical leaf still
authenticates the stream it publishes or relies on a child handle that
authenticates every complete open. Thus a normal verified, routed, mirrored
write performs one routing proof and one streaming pass per physical placement,
not one full-object hash pass per composition wrapper.

A backend read returns promptly with a handle; whole-object authentication may
finish only when a stream opened from that handle reaches EOF. Consumers MUST
drain the stream and observe its final result before publishing, restoring, or
executing the bytes. The public complete-copy helper does this with bounded
memory; the full-buffer helper additionally requires an explicit size limit.
Bytes may already have reached a destination before a deferred authentication
failure, so atomic consumers use staging and publish only after success.

The initial Rust storage trait is synchronous and object-safe. The daemon runs
potentially blocking drivers on its bounded storage I/O pool; asynchronous RPC
and S3 adapters translate streaming bodies at the service boundary. This is an
implementation scheduling choice, not a wire contract and not campaign state.
Production implementations may add batched existence queries, delete-by-plan,
and repair enumeration. Object reachability never depends on backend listing.
`put_if_absent` authenticates logical bytes against the expected ID before
success; `read` verifies the logical object after all physical decoding layers.

Mutable refs are deliberately separate. Blob caches and mirrors may be
composed freely, but one campaign namespace has one configured authoritative
`MutableRefBackend`. A tiered read must never return a cached stale ref, and a
write-back cache must never acknowledge campaign-head durability before the
authoritative conditional update succeeds.

- **[CSTORE-3]** Every immutable backend and composition layer MUST implement
  one conformance contract for idempotent put, authenticated get, bounded range
  read, missing/corrupt distinction, and explicit durability capability.
- **[CSTORE-4]** One campaign namespace MUST have exactly one authoritative ref
  backend. Mutable refs MUST NOT be naively mirrored, cached, or reconciled by
  last-writer-wins.

## 06.3 Backend capabilities and error model

Capabilities are operational and include:

```text
conditional create       bounded range read       streaming read/put
durable flush semantics  multipart/resume         atomic conditional ref
delete support           repair enumeration       maximum object/part sizes
physical encryption      sparse-file support      pack-index durability
deferred downstream transfer
```

Layers declare both requirements of their children and capabilities they
synthesize. Store-graph construction fails before campaign access when a child
cannot satisfy a required operation. Store errors distinguish missing,
corrupt, unauthorized, incompatible, quota, unavailable, conditional conflict,
and unsupported-capability outcomes.

- **[CSTORE-5]** Store-graph validation MUST fail closed when any route,
  durability policy, ref backend, or composition layer requires an unsupported
  child capability.
- **[CSTORE-6]** Backend errors MUST preserve stable semantic classes across
  drivers and MUST NOT expose credentials or sensitive host paths through the
  campaign API.

## 06.4 Leaf backends

Initial leaf drivers are:

| Driver | Purpose |
| --- | --- |
| `MemoryBlobBackend` | Bounded test or read cache; never sole durable storage |
| `DirectoryBlobBackend` | Local immutable objects using same-filesystem staging, authentication, flush, and atomic publication |
| `DirectoryRefBackend` | Expected-value verification under an advisory lock and atomic same-filesystem ref replacement |
| `S3BlobBackend` | Immutable object and multipart streaming through an S3-compatible API |
| `S3RefBackend` | Optional conditional ref backend only when the configured service passes strong CAS conformance |

The campaign model never contains a driver name, endpoint, bucket, region,
credential, or local root. An S3 driver does not receive special campaign APIs.
It is configured under an operational store name such as `archive` and is
tested through the same traits as a directory driver.

Directory durable publication flushes staged bytes, authenticates them,
atomically installs the object, and flushes the containing directory. Ref
publication likewise flushes replacement bytes, performs expected-value
verification and atomic replacement under the local lock, then flushes the ref
directory. Rename without the required file and directory durability steps is
not a successful durable put.

If publication creates directory ancestors, it flushes every new directory and
the first pre-existing ancestor that contains the new chain before reporting
durability. An idempotent put that finds an existing authenticated object still
flushes its containing directory before returning a durable receipt; this
matters when a prior attempt installed the name but failed its directory flush.
An error after a ref replacement may be an indeterminate commit, so the sole
coordinator re-reads the authoritative ref before deciding whether to retry.

The directory blob leaf serializes every cooperating put and administrative
deletion through `<root>/.inventory-admin/lock`. Its registered
`crucible.content-store.directory-inventory-state` schema v1 is canonical UTF-8
text:

```text
version=1
instance=<64 lowercase hexadecimal digits>
generation=<canonical unsigned decimal u64>
checksum=<64 lowercase hexadecimal digits>
```

`checksum` is BLAKE3 over the exact first three newline-terminated lines,
prefixed by the ASCII domain
`crucible.content-store.directory-inventory-state.v1`. `instance` is generated
once when the state is first durably created. A reader retains at most 257
bytes and rejects the record when it exceeds the 256-byte schema limit.
`generation` advances durably before every attempted cooperating physical
mutation; conservative advancement without a resulting object change is valid,
but a physical change under an old generation is not. The persistent state
makes delete-and-reinsert ABA distinct across restart. The configured directory
root is operator-owned: an uncooperating writer that bypasses this lock
invalidates the backend admission contract and MUST be excluded before
administrative deletion is enabled.

The directory ref backend uses the identical 256-byte field grammar at
`<ref-root>/.ref-admin/state-v1`, registered as
`crucible.content-store.directory-ref-inventory-state` v1. Its checksum domain
is `crucible.content-store.directory-ref-inventory-state.v1`. Every cooperating
read takes the namespace lock shared; every compare-and-swap takes it exclusive
and durably advances the state before publishing an accepted replacement. The
fenced inventory recursively validates every authoritative path as an exact
`RefName`, bounds each value record to 256 bytes, rejects symlinks and malformed
records, and treats a complete staging-named record conservatively as a root
rather than silently omitting a valid name with the same spelling.

Generation digests are language-neutral:

```text
InventoryGeneration = BLAKE3(
    "crucible.content-store.persistent-inventory-generation.v1" ||
    LE64(byte_length(backend_name_utf8)) || backend_name_utf8 ||
    instance_32 || LE64(counter)
)
RefInventoryGeneration = BLAKE3(
    "crucible.content-store.ref-inventory-generation.v1" ||
    instance_32 || LE64(counter)
)
```

The domain strings are the exact ASCII bytes shown and `||` is concatenation.

Directory read handles pin an already-opened inode rather than reopening its
path. Unlink or atomic path replacement therefore cannot retarget an in-flight
handle. Each complete open scans and authenticates the whole logical object,
including bytes outside a requested range; in-place mutation is reported as
corruption at EOF. This initial whole-object range verification is deliberately
simple and bounded in memory. Packed or Merkle-authenticated layouts may later
provide sub-object proofs without scanning unrelated bytes while preserving the
same logical read contract.

- **[CSTORE-7]** The directory backend MUST leave either no object or a complete
  authenticated object after interruption; same-filesystem staging debris is
  unreachable and reclaimable.
- **[CSTORE-8]** The S3-compatible backend MUST tolerate interrupted multipart
  upload, authenticate downloaded logical bytes, and use conditional ref
  operations only after the concrete service passes the ref conformance suite.

## 06.5 Store composition graph

Every composition node implements the logical immutable-store interface and
wraps one or more child nodes. Initial compositions are:

```text
VerifiedStore       authenticate logical bytes and envelopes
RoutedStore         select a child policy from authenticated ObjectKind
TieredStore         ordered read, optional promotion, explicit write policy
ReadThroughStore    cache verified reads in a faster child
WriteThroughStore   require configured children before success
WriteBackStore      stage locally and expose archival progress without claiming it complete
PackedStore         map many logical small objects into immutable physical packs
CompressedStore     encode/decode without changing logical identity
EncryptedStore      authenticated physical encryption outside plaintext identity
QuotaStore          enforce bounded physical and logical accounting
MetricsStore        emit operational latency/bytes/errors without changing results
NamespacedStore     isolate deployments and authorization domains
```

The configured structure is an acyclic graph from a closed set of built-in Rust
layers in this RFC. Dynamic native plugins and arbitrary wrapper ordering are
not supported. A route is selected from the authenticated envelope, never an
untrusted caller-provided kind hint. Verification is against canonical
plaintext; compression precedes encryption; physical decoding reverses the
declared order before logical verification; packing owns a durable resolution
index; mutable refs never enter the blob graph. A graph may share a leaf between
routes but must define unambiguous read, write, durability, promotion, and
eviction behavior for every admitted object kind. A write-back layer is valid
only with a durable transfer journal whose protected roots participate in GC.

The first write-back layer requires durable streaming staging and destination
children. A put authenticates its complete source, publishes the staging child,
and appends a checksummed pending record to the durable
`crucible.content-store.write-back-transfer-journal` v1 log before returning.
The returned placement receipt names only staging; an owner requiring the
destination's durability waits for explicit transfer completion rather than
treating the queue as an archival receipt. Reads prefer staging and fall back
to the destination only on exact absence. A bounded flush visits node and
`ContentId` order, idempotently publishes the destination, and durably appends
completion before the pending root disappears.

The journal has fixed pending-object and aggregate logical-byte ceilings, a
64-MiB physical log ceiling, checksummed records, durable append, and atomic
bounded compaction. Pending capacity is reserved under the journal state lock
before staging, so a quota rejection cannot publish unjournaled staging debris;
successful staging still precedes the durable pending append. Restart replays
the exact pending set and rejects a header whose BLAKE3 binding does not match
the exact node ID, staging child ID, destination child ID, and configured count
and byte limits. Node IDs are stable configured-instance identities; changing a
child's physical configuration requires a new child ID or a new journal root.

The registered v1 journal encoding is:

```text
"crucible.content-store.write-back-transfer.v1\0"
binding[32]
repeated {
  payload_length_u32_be
  operation_u8                 # 0 Pending, 1 Complete
  content_id_length_u16_be
  content_id_ascii[content_id_length]
  logical_length_u64_be
  checksum[32]
}
```

`binding = BLAKE3("crucible.content-store.write-back-transfer-binding.v1" ||
len_u64_be(node) || node || len_u64_be(staging) || staging ||
len_u64_be(destination) || destination || maximum_pending_objects_u64_be ||
maximum_pending_bytes_u64_be)`. `checksum` is
`BLAKE3("crucible.content-store.write-back-transfer-record.v1" || record bytes
before checksum)`. Each payload is at most 256 bytes. A torn final record that
was never durably acknowledged is truncated while holding the journal state
lock; malformed complete records fail closed. The journal's shared lifecycle
fence spans staging publication through pending append and spans destination
publication through completion append. Single-host GC acquires the exclusive
side, adds every pending ID to its canonical root manifest, and holds that fence
while reproducing roots and deleting planned physical placements. A changed
pending set therefore invalidates an old plan before deletion.

The initial admitted graph is a flat `StoreNodeId -> StoreNodeSpec` map with an
explicit root and exact admitted `ObjectKind` set. `StoreNodeSpec` is a closed
enum over built-in leaves and layers; child fields contain node IDs, which lets
multiple routes share a leaf without duplicating it. Startup performs a DFS and
demand propagation before constructing the root:

- at most 256 nodes, depth at most 64, bounded ASCII node IDs, and absolute
  administrative paths of at most 4,096 opaque Unix bytes;
- every child exists, the graph is acyclic, and every configured node is
  reachable;
- a router covers exactly the kinds that can reach it, including the union of
  demands when the router is shared;
- tiers and mirrors are nonempty, the write-tier index is valid, and promotion
  or mirroring children support conditional immutable creation;
- write-back staging and destination children are durable, conditional,
  streaming stores that do not themselves defer transfer, pending count/byte
  bounds are nonzero and bounded, and journal directories do not lexically
  overlap a blob directory or another journal directory;
- public introspection returns only node ID, built-in kind, and derived
  capabilities, never a directory root, endpoint, or credential.

`ReadThroughStore(cache, source)` reads the cache first and falls through only
on exact `NotFound`. Corruption, authorization, and availability failures from
the cache remain visible. A source hit is streamed through authenticated
conditional creation into the cache before the caller's requested logical range
is sliced; a quota or availability failure during that optional promotion does
not hide the authenticated source object. Ordinary puts go only to `source`, so
cache durability is never reported as source durability.

`MetricsStore(child)` retains saturating `u64` counters for synchronous
`contains`, `read`, and `put_if_absent` calls, successful declared logical bytes,
and failures. Graph introspection returns those counters by bounded node ID
without returning child paths or credentials. This initial deterministic counter
view deliberately ends when a read handle is returned: latency plus errors and
bytes observed later while consuming its deferred authenticated stream remain
open for a host-side observer boundary rather than introducing host time into
logical storage code.

Direct constructors for composition layers are private. Callers may use a leaf
alone or an admitted `StoreGraph`, so arbitrary trait-object nesting cannot
bypass these checks.

`StoreGraph::build_with_admin` returns the ordinary immutable graph and a
separate, non-cloneable `StoreGraphAdmin`. The graph does not retain or expose
physical inventory/delete authority. The administrative value retains exactly
one capability for every admitted memory, directory, or packed leaf and lends
them in canonical node-ID order to the daemon maintenance owner. Shared graph
paths therefore do not duplicate a leaf inventory, and a campaign repository
that receives only `StoreGraph` cannot construct a deletion fence. Both values
retain the same content-derived `StoreGraphConfigurationId`; GC accepts the
administrative value itself and cannot pair independently supplied leaves with
an unrelated graph hash.

The registered `crucible.content-store.graph-configuration` schema v1 freezes
that identity basis. Every persistent path is an absolute host-local Unix path;
its opaque bytes, rather than a lossy Unicode rendering, enter the identity.
Node IDs and counts use their bounds above, object-kind tags and routed entries
are ordered by ascending ASCII tag, nodes by ascending node ID, and ordered
child lists retain their configured order. The canonical body is:

```text
"crucible.content-store.graph-configuration.v1\0"
root_node_id:string_u16
admitted_kind_count:u16be
repeated admitted_kind_count times: object_kind_tag:string_u16
node_count:u16be
repeated node_count times:
    node_id:string_u16 || node_tag:u8 || node_fields

string_u16 := length:u16be || ASCII_bytes[length]
path_u32   := length:u32be || Unix_path_bytes[length]

node tag 1  Memory:      maximum_logical_bytes:u64be
node tag 2  Directory:   root:path_u32
node tag 3  Packed:      root:path_u32 || target_pack_bytes:u64be
node tag 4  Verified:    child:string_u16
node tag 5  Routed:      route_count:u16be
                         || repeated (kind:string_u16 || child:string_u16)
node tag 6  Tiered:      child_count:u16be || repeated child:string_u16
                         || write_tier:u16be || promote_reads:u8
node tag 7  ReadThrough: cache:string_u16 || source:string_u16
node tag 8  WriteThrough:child_count:u16be || repeated child:string_u16
node tag 9  WriteBack:   staging:string_u16 || destination:string_u16
                         || journal_root:path_u32
                         || maximum_pending_objects:u64be
                         || maximum_pending_bytes:u64be
node tag 10 Metrics:     child:string_u16
```

Let `D` be `crucible.content-store.graph-configuration-id.v1` and `B` the
complete body. The 32-byte configuration identity is
`BLAKE3(BE64(len(D)) || D || BE64(len(B)) || B)`. Any layer, edge, route,
limit, path, admitted kind, or root change therefore invalidates a prior GC
plan even when the physical leaf names happen to be unchanged.

Example:

```text
VerifiedStore
  `- RoutedStore
      |- metadata -> WriteThroughStore(directory, archive)
      |- RAM       -> TieredStore(memory-cache, packed-NVMe, packed-archive)
      |- disk      -> TieredStore(packed-NVMe, packed-archive)
      `- traces    -> WriteBackStore(directory, archive)
```

- **[CSTORE-9]** Store composition MUST be acyclic, bounded, introspectable,
  and deterministic for a given authenticated object profile and operational
  policy version.
- **[CSTORE-10]** Promotion, demotion, cache hits, driver choice, and physical
  transformation MUST NOT change returned logical bytes or any canonical ID.

## 06.6 Object profiles, routing, and durability

After envelope authentication, the store derives an operational profile:

```rust,illustrative
pub struct ObjectProfile {
    pub kind: ObjectKind,
    pub logical_length: u64,
    pub sensitivity: SensitivityClass,
    pub reconstructibility: Reconstructibility,
    pub retention_role: RetentionRole,
}
```

Routing and durability policy may distinguish canonical metadata, finding
artifacts, exact RAM, disk extents, opaque device state, projections, logs, and
traces. The profile and policy choose physical actions only. Sensitivity and
retention claims are validated against the canonical object and its reachable
root rather than trusted from a caller hint.

`PutReceipt` records which store nodes verified an object and which durability
conditions are satisfied. Receipts are operational and replaceable. A snapshot
publisher declares a `DurabilityRequirement`; it may advance the ref only after
every newly required reachable object has a receipt satisfying that
requirement.

- **[CSTORE-11]** Snapshot publication MUST wait for all objects required by the
  snapshot's retention roots to satisfy the requested durability policy; a
  write-back queue alone is not durable completion.
- **[CSTORE-12]** Routing policy and placement receipts MUST remain outside
  scenario, configuration, attempt, observation, and content identity.

## 06.7 Canonical envelope and Merkle collections

Canonical objects carry:

```text
magic
object kind and schema version
canonical payload length
sorted typed child content IDs
canonical payload
logical digest authentication
```

Strings use defined UTF-8 normalization, maps use canonical key order, integer
widths and byte order are explicit, and decoders reject trailing bytes,
duplicates, unknown required fields, unreasonable lengths, and unsorted
canonical collections.

Large sets and maps use bounded-fanout persistent Merkle structures. Updating
one entry writes only the changed path. Projection objects name their exact
input roots and algorithm version. Full recomputation samples and verifies
cached projections.

- **[CSTORE-13]** Decoders MUST validate declared limits and typed child
  references before allocation or use and MUST reject non-canonical encodings.
- **[CSTORE-14]** Merkle rebalancing, compaction, and insertion order MUST
  preserve logical collection identity or publish a distinct representation
  with a verified logical-root equivalence rule.

## 06.8 RAM, disk, and physical packs

Hot QEMU forks use kernel copy-on-write directly. They do not hash or publish
RAM pages merely to create a child. Pages or extents enter the content store
only when an exact closure, retained finding, hibernation image, or explicit
archive operation requires durable state.

An exact RAM manifest maps stable `(RAMBlockId, page-or-extent-index)` keys to
logical content IDs and compact zero/repeated/base/delta runs. Disk manifests
use immutable backing identities plus changed extent IDs. Opaque device VMState
remains an authenticated blob. The initial exact-checkpoint root is a generic
two-child envelope over canonical QEMU/Apache metadata and that opaque VMState
blob. Generic closure walkers can therefore retain and verify both child IDs
without interpreting QEMU bytes; the daemon owner additionally checks the
fixed root body against the decoded snapshot identity, configuration, and exact
child lengths.

Millions of logical pages must not imply millions of S3 or filesystem objects.
`PackedStore` groups logical object bodies into immutable multi-megabyte packs
and durably indexes `ContentId -> (PackId, offset, length, physical encoding)`.
The index is backend metadata, not campaign state. It must be crash-recoverable
or rebuildable from authenticated pack metadata. Repacking or garbage-
collecting sparse packs preserves every logical ID.

- **[CSTORE-15]** Logical page/extent IDs and `ExactClosureId` MUST be
  independent of pack geometry, pack identity, backend, and repacking history.
- **[CSTORE-16]** A packed backend MUST authenticate the requested logical
  object after range extraction and MUST recover safely from interruption
  between pack and index publication.

The single-host packed leaf implements the following registered canonical v1
physical formats. Every integer is unsigned big-endian, every content ID is its
canonical lowercase ASCII form preceded by a `u16` byte length, and every
literal includes the shown trailing NUL where present:

```text
PackV1 =
  "crucible.content-store.pack.v1\0"
  configuration[32]
  entry_count_u32
  manifest_length_u32
  repeated entry_count {
    content_id_length_u16
    content_id_ascii[content_id_length]
    absolute_body_offset_u64
    logical_length_u64
  }
  manifest_checksum[32]
  concatenated_logical_bodies

PackIndexV1 =
  "crucible.content-store.pack-index.v1\0"
  configuration[32]
  backend_instance[32]
  generation_u64
  last_repack_tag_u8          # 0 None, 1 Some
  [last_repack_plan_id[32]]   # present exactly when tag is 1
  entry_count_u32
  repeated entry_count {
    content_id_length_u16
    content_id_ascii[content_id_length]
    pack_id[32]
    absolute_body_offset_u64
    logical_length_u64
  }
  index_checksum[32]

PackedRepackPlanV1 =
  "crucible.content-store.pack-repack-plan.v1\0"
  configuration[32]
  backend_instance[32]
  index_generation_u64
  exact_index_digest[32]
  accounting_generation_u64
  logical_object_count_u64
  logical_bytes_u64
  referenced_pack_count_u64
  referenced_physical_bytes_u64
  plan_checksum[32]
```

`configuration = BLAKE3("crucible.content-store.packed-configuration.v1" ||
BE64(name_length) || name_utf8 || BE64(root_path_byte_length) ||
root_path_bytes || BE64(target_pack_bytes))`.
`manifest_checksum = BLAKE3("crucible.content-store.pack-manifest.v1" ||
the exact pack bytes preceding the checksum)` and
`PackId = BLAKE3("crucible.content-store.pack-id.v1" || configuration ||
the exact manifest entry bytes)`. Logical bodies are authenticated by their
manifest `ContentId`s, so physical pack identity does not become logical
identity. `index_checksum` uses the domain
`crucible.content-store.pack-index.v1` over the exact preceding index bytes.
`exact_index_digest` uses
`crucible.content-store.pack-index-digest.v1` over the complete checksummed
index. `plan_checksum` uses
`crucible.content-store.pack-repack-plan.v1`, and `PackedRepackPlanId` uses
`crucible.content-store.pack-repack-plan-id.v1` over the complete checksummed
plan.

`accounting_generation_u64` MUST equal `index_generation_u64`; count, byte, and
pack relationships are checked before a decoded plan can be applied.

One index admits at most 65,536 logical objects and 65,536 referenced packs and
is at most 16 MiB. One pack contains 1 through 4,096 entries and is at most
128 MiB including metadata and bodies. Configured target size is 64 KiB through
128 MiB. Empty logical objects are valid. Entry IDs are strictly increasing;
offsets are absolute, contiguous, overflow-checked, and cover the exact pack
length. Decoders reject unknown tags, duplicate IDs, trailing bytes,
configuration mismatch, checksum mismatch, missing referenced packs, and an
index entry that does not exactly match its pack manifest.

Ordinary puts durably publish an authenticated one-object pack before atomically
advancing the index. Repack planning is read-only and binds the exact backend
configuration, persistent instance, generation, complete index digest, and
checked logical/physical accounting. Apply accepts only that exact basis,
writes and verifies every deterministic replacement pack, atomically publishes
the next checksummed index by write-fsync-rename-directory-fsync, and then
durably removes superseded pack names. A publication error is reconciled by
reloading and re-fsyncing the visible index. The next index retains the applied
plan ID, so retry after an indeterminate switch or cleanup error is idempotent;
any later put, delete, or repack generation makes the old plan stale.

Startup removes complete unindexed pack names left by a pack-before-index
interruption, but fails closed for a missing or malformed referenced pack.
Readers retain an open pack inode before releasing the state lock and
authenticate the complete logical body, including bytes outside a requested
range; replacement and unlink therefore cannot retarget an in-flight read.
Logical deletion removes only the index entry until the final entry in that
pack is deleted. Repack is the operation that reclaims sparse physical bytes.

## 06.9 Publication, archival transfer, and offline movement

Publishing a new campaign snapshot is:

1. persist new immutable facts and artifacts;
2. persist changed Merkle collection paths;
3. satisfy required object durability through the configured store graph;
4. persist the immutable `CampaignSnapshot`;
5. read and verify the authoritative current ref;
6. compare-and-swap it from the expected parent to the new snapshot.

One coordinator serializes semantic updates. A CAS conflict means stale command
input or an ownership defect; this RFC does not merge concurrent writer
histories.

Archival transfer exchanges a snapshot or closure ID, walks missing Merkle
objects, copies only missing logical content through source and destination
stores, verifies every object, then creates or advances the destination ref.
Supported closure policies are `metadata`, `findings`, `debug`, `executable`,
and `mirror`. A metadata archive can be inspected without downloading RAM.

Offline maintenance transfer first hibernates and pins the exact closure,
ensures its complete executable closure in the destination store, verifies
compatibility, restores on the destination during a separate operator action,
and only then permits source eviction. No two-host scheduler or live post-copy
pager is implied.

- **[CSTORE-17]** Transfer MUST operate on authenticated logical IDs and be
  idempotent and resumable without changing those IDs or requiring equal pack
  layouts at source and destination.
- **[CSTORE-18]** Initial exact restore MUST require all execution-required
  logical objects to be locally readable and authenticated before modeled
  execution resumes; remote demand paging is outside this RFC.

## 06.10 Pinning, eviction, and garbage collection

Retention roots include every campaign ref in the store namespace,
intentionally retained historical refs, scenario/image roots, user pins,
finding/corpus pins, active-continuation ancestors, in-progress publication or
transfer roots, and durable write-back journals. A pin declares
metadata, thin, or exact retention plus a durability requirement. Hot-hub
preference and placement receipts are operational.

Pending write-back IDs enter the same single-host GC root manifest as refs and
assignment-ledger roots. Planning inventories them under the transfer fence;
apply reacquires that fence, requires the exact manifest identity, and retains
the fence through candidate deletion. No separate generation field is needed
in the v1 GC plan header because the exact root-manifest identity binds the
complete active set and the held fence excludes changes during apply.

Within a campaign snapshot, the semantic pin projection is keyed by the exact
`ConfigurationId`. Its value is the latest authenticated schema-v5
`PinCommandAccepted` fact. `Thin` and `Exact` select the required logical
closure profile; `None` is a retained tombstone that removes the configuration
from the current GC pin set without erasing command replay or campaign history.
The graph membership proof is evaluated at the accepting parent snapshot, so a
backing-store object that is not authoritative campaign knowledge cannot be
pinned through this transaction.

The local repository exposes this current projection as a snapshot-bound,
10,000-entry paged retention inventory. It authenticates each projected fact,
requires the projection key to match the fact's `ConfigurationId`, resolves
that configuration through the same snapshot's graph root, and authenticates
the exact configuration and lineage scenario artifacts required for thin
replay. The lineage scenario artifact is validated once per inventory pass.
Tombstones are counted but do not emit roots. An `Exact` record emits the same thin roots and
additionally declares that the later physical retention plan must retain or
materialize one complete portable exact closure for that configuration; the
semantic pin alone does not select an arbitrary operational checkpoint.

The single-host daemon makes that physical choice through a separate,
single-writer exact-pin materialization journal. Selection admission reads and
authenticates the complete current semantic pin projection, requires the target
configuration to be `Exact`, loads the complete `ExactCheckpointId` root and
metadata through the exact-checkpoint store, and requires the checkpoint's
modeled configuration identity to equal the pin target before the first journal
write. The selected value binds the campaign name, configuration, latest
accepted pin fact, and exact-checkpoint root. It is operational owner state and
does not advance the campaign ref or alter modeled campaign identity.

The registered
`crucible.executor.exact-pin-materialization-selection` schema v1 is stored at
`<journal>/records/<first-two-key-hex>/<key-hex>`. One journal admits at most
64,000,000 records and one record admits at most 4 KiB. Its canonical body is:

```text
"crucible.executor.exact-pin-materialization-selection.v1\0"
campaign_length:u16be | campaign UTF-8
configuration:CampaignHash[32]
pin_fact_length:u16be | canonical CampaignFactId UTF-8
checkpoint_length:u16be | canonical ExactCheckpointId UTF-8
checksum:CampaignHash[32]
```

The key material is
`campaign_length:u16be || campaign || configuration[32]`. Derive `key` as
`H("crucible.executor.exact-pin-materialization-selection-key.v1", key_material)`
and the checksum as
`H("crucible.executor.exact-pin-materialization-selection.v1", body_without_checksum)`,
where `H(domain, bytes)` is `CampaignHash::derive(domain, bytes)`.
Lengths, UTF-8, typed IDs, the checksum, filename, shard, and reconstructed key
MUST all validate before the record is trusted. Replacement is
staging-file/fsync/rename/directory-fsync atomic. A lifetime nonblocking
exclusive writer lock excludes a second cooperating daemon; the journal root
MUST live outside every blob leaf inventoried by campaign GC.

GC acquires the authoritative ref fence and exact-pin journal fence together.
For each fenced `campaigns/<name>` snapshot it authenticates the snapshot-bound
pin projection without rereading the mutable ref. Every current `Exact` pin
MUST have a selection whose campaign, configuration, and latest pin fact match;
otherwise planning/apply fails closed. Its checkpoint becomes a logical GC
root. A journal record whose fact is no longer the current `Exact` projection
is stale and MUST NOT become a root, so unpin or repin cannot leak an old exact
closure. Explicit journal clear reclaims its bounded namespace but is not
required for liveness correctness. Apply reacquires both fences and recomputes
the exact root manifest before deletion. The manifest identity plus held fences
binds the complete selected checkpoint set; no additional selection-generation
field is required in the v1 GC header.

On the single-host executor, the lineage-qualified operational assignment
ledger is the owner of result-publication roots. It streams the expected
`ObservationId` from every authenticated `publishing` record and the retained
`ObservationId` from every authenticated `completed` record into the GC root
enumeration without materializing ledger history. It likewise streams the
`ExactCheckpointId` from authenticated `checkpoint-publishing` and `paused`
records. Publication state is durable before the first candidate-object write
and survives restart; completion, durable pause, or an explicit
cancellation/quarantine transition is the only way to replace it.
These operational records do not grant the executor authority to mutate a
campaign ref.

The ledger exposes this inventory only through the separate
`AssignmentRetentionAdmin` maintenance capability. Acquiring its mutable fence
excludes executor state transitions, and the directory ledger's lifetime
single-writer lock excludes another cooperating process. One pass authenticates
each canonical attempt-state path and record and streams both observation and
checkpoint roots; a consumer-visible prefix is tentative until the terminal
summary returns. The summary binds the complete root set to an
`AssignmentRetentionGeneration`.

The directory ledger persists `<ledger>/retention-state-v1` under the registered
`crucible.executor.assignment-retention-state` schema v1. Its canonical binary
body is the literal `crucible.executor.assignment-retention-state.v1\0`, a
32-byte random backend instance, and a little-endian unsigned 64-bit generation,
followed by the 32-byte `CampaignHash::derive`
`crucible.executor.assignment-retention-state.v1` checksum of that preceding
body. The generation digest is
`CampaignHash::derive("crucible.executor.assignment-retention-generation.v1",
instance || LE64(generation))`. The counter starts at one and advances durably
before every accepted attempt-state replacement, including deletion and
same-value replacement; a failed expected-state comparison does not advance it.
An error after the state advance is conservative because it only invalidates an
older plan. The memory ledger uses a process-local hash-chain generation for its
ephemeral backend instance.

The registered `crucible.campaign.gc-root-manifest` and
`crucible.campaign.gc-candidate-manifest` schemas v1 are streamed external
administrative records. Each admits at most 64,000,000 entries, matching the
complete campaign-closure work bound. A root manifest deduplicates roots and
orders them by `(ContentId.kind ASCII tag, schema version as an unsigned
integer, digest bytes)`. Its canonical binary layout is:

```text
"crucible.campaign.gc-root-manifest.v1\0"
root_count:u64be
repeated root_count times:
    content_id_length:u16be || canonical_content_id_utf8
```

A candidate manifest names exact physical
`(backend_id, ContentId, logical_length)` placements rather than ambiguous
logical IDs. Entries are unique and ordered first by backend ASCII bytes, then
by the same ContentId tuple. Its canonical layout is:

```text
"crucible.campaign.gc-candidate-manifest.v1\0"
candidate_count:u64be
repeated candidate_count times:
    backend_length:u16be || backend_utf8
    content_id_length:u16be || canonical_content_id_utf8
    logical_length:u64be
```

For either manifest, let `D` be respectively
`crucible.campaign.gc-root-manifest.v1` or
`crucible.campaign.gc-candidate-manifest.v1`, and let `M` be the complete
canonical bytes above. Its 32-byte manifest hash is
`BLAKE3(BE64(len(D)) || D || M)`. Decoders enforce the entry limit before
allocation proportional to a claimed count, bound every individual string,
require strict order and exact EOF, and recompute terminal candidate count and
logical-byte totals.

The registered `crucible.campaign.gc-plan` schema v1 is the bounded immutable
header that composes these independently fenced inputs. It does not embed the
potentially large root set or candidate list. Instead it binds their separately
authenticated canonical manifest hashes and terminal counters. Its canonical
binary layout is:

```text
"crucible.campaign.gc-plan.v1\0"
store_graph_hash[32]
root_set_manifest_hash[32]
ref_generation[32] || ref_count:u64be
ledger_generation[32] || attempt_count:u64be
    || observation_root_count:u64be || checkpoint_root_count:u64be
candidate_manifest_hash[32] || candidate_count:u64be || candidate_bytes:u64be
physical_inventory_count:u16be
repeated physical_inventory_count times:
    backend_length:u16be || backend_utf8[backend_length]
    || blob_generation[32] || object_count:u64be || logical_bytes:u64be
```

The physical list contains 1 through 256 entries in strictly increasing backend
identifier order. An identifier is 1 through 64 ASCII bytes from letters,
digits, `.`, `_`, and `-`. The complete header is at most 64 KiB. Counts are
checked for overflow; operational roots cannot outnumber attempt records, and
candidate placements/bytes cannot exceed the summed physical inventory. Its
identity is
`CampaignHash::derive("crucible.campaign.gc-plan.v1", canonical_header)`.
Changing any store-graph, root-manifest, candidate-manifest, blob, ref, or ledger
basis therefore changes the plan identity. The daemon's non-destructive
single-host planner now fences and inventories the complete ref namespace and
assignment ledger, deduplicates their logical roots, authenticates their union
through the campaign repository's semantic, generic-envelope, Merkle, and
opaque-leaf closure verifier, then inventories each named physical leaf. Every
placement whose logical ID is absent from that authenticated reachable set is
written into the candidate manifest. A physical capability must report the same
backend identifier configured by the maintenance owner, and physical inputs are
strictly ordered. Any incomplete visitor prefix is discarded. Because apply
later revalidates every generation, mutations between these non-destructive
phases only make the plan stale; they cannot authorize deletion.

The daemon now persists the exact header and both streamed manifests in an
external directory journal that is not part of any inventoried blob leaf. The
directory also contains an exclusively locked operational `lock` file and the
registered `crucible.campaign.gc-journal-state` schema v1. The canonical state
body is:

```text
"crucible.campaign.gc-journal-state.v1\0"
plan_id[32]
phase:u8  # 1 Planned, 2 Applying, 3 Complete
checksum[32]
```

`checksum` is `CampaignHash::derive(
"crucible.campaign.gc-journal-state.v1", preceding_state_bytes)`. Journal
creation writes and fsyncs `plan-v1`, `roots-v1`, and `candidates-v1`, then
publishes checksummed `state-v1` by write-fsync-rename-directory-fsync and
fsyncs the containing parent. Reopen locks the directory, re-fsyncs visible
directory metadata, strictly decodes all records, recomputes the plan/manifest
bindings, and accepts an existing journal only for the exact same inputs. A
crash before initial state publication leaves an incomplete directory that
fails closed. `Applying` means at least one deletion may have occurred, so an
interrupted journal is durable recovery evidence and requires a fresh plan
rather than reuse of its now-stale generations.

Campaign repository mutations now also acquire the ref backend's shared
publication-lifecycle fence before their first immutable child write and retain
it through the final ref comparison. Ref inventory takes the exclusive side.
The memory backend composes an in-process reader/writer lock; directory-backed
repositories sharing a root compose the same rule through
`.ref-admin/publication-lock`. This excludes the children-before-ref race before
root inventory or apply begins.

Single-host physical-leaf apply requires a `Planned` journal and the exact
construction-time `StoreGraphAdmin`. It derives and compares that capability's
configuration hash and canonical physical-backend list before taking and
retaining the exclusive ref/publication, ledger, and pending-write-back fences.
It reproduces their terminal generations, counters, and exact deduplicated root
manifest, then preflights every complete physical inventory and every
candidate's exact observed length.
Only after every basis matches does it durably publish `Applying`. It then
reacquires each physical leaf in canonical order, revalidates that exact basis
again, retains that leaf's fence through all of its deletions, and finally
publishes `Complete` while the root fences still exclude new authority. The
second physical pass makes any intervening put fail closed even though physical
leaves are not locked simultaneously; sequential acquisition also prevents a
misconfigured alias from deadlocking on the same physical lock. A complete
journal replays idempotently. Any failure after `Applying`, including an
indeterminate durable delete or final state write, retains the journal in the
recovery-required phase and never authorizes reuse of its generations.
Construction-time graph administration now supplies the exact memory,
directory, and packed leaf capabilities without granting them to the campaign
repository. Restart testing proves that two logical objects may share one pack,
planning selects only the unreachable entry, and apply removes that entry while
retaining the live object and shared physical pack. Transform/S3 leaf
administration and policy-aware eviction of extra reachable cache copies remain
open beyond this physical-leaf apply.

The single-host daemon composes these sources into one logical root inventory:
authoritative refs, current exact-pin selections, durable observation and
checkpoint publication roots, and pending write-back roots. Assignment-ledger
roots are lineage-qualified and host-local rather than campaign-name-qualified,
so a planner aggregating several campaign refs enumerates the ledger once.
Duplicate operational roots may be emitted by distinct records and are
deduplicated by content identity by the physical planner. Visitor output is
tentative until terminal enumeration succeeds. This inventory is not itself a
deletion plan: applying deletion still requires the snapshot and complete
physical inventory generation checks below.

GC is planned per logical reachability and physical tier. It reports:

- logically reachable objects;
- unreachable logical objects;
- required objects missing from a durability tier;
- cache copies safe to evict;
- packs eligible for whole deletion;
- sparse packs requiring repack before reclamation;
- bytes retained by sensitivity and pin class.

Deletion is a separate apply step. Its plan binds the complete root-set digest,
store-graph configuration and generation, active publication/transfer roots,
and physical inventory generation, and becomes stale if any changes. Cache
eviction may remove one physical copy only when policy permits reconstruction
or another verified required copy exists. A pack containing any live logical
object cannot be deleted. Repacking first writes and verifies replacement packs
and indexes, atomically switches the index generation, waits for existing
readers, then permits delayed deletion of old packs. Removing an exact
materialization never removes the semantic configuration or thin replay path.

The implemented memory, directory, and packed blob leaves now provide the
exclusive physical inventory generation/idempotent exact-candidate deletion
primitive. The memory and directory ref leaves provide the exclusive
authoritative-ref inventory generation and publication-lifecycle fence needed
by that apply step. The assignment ledger likewise provides one
exclusive, persistent generation over its combined operational root inventory.
Directory and packed generations survive restart; memory generations are
process-local and monotonic for their ephemeral backend instance. These
primitives remain held by the daemon maintenance owner. The canonical bounded
v1 plan header now binds these
generations to constructed root and candidate manifests, and the external
journal durably owns their exact bytes and apply phase. No campaign
repository, planner, executor, or ordinary store-graph handle receives the
administrative capabilities, and no deletion is safe until durable external
manifest ownership and every applicable root and physical generation have been
revalidated. The implemented single-host physical-leaf apply and exact-pin
selection fence satisfy that rule for memory, directory, and packed leaves. The
packed leaf separately provides generation-bound repack plan/apply and logical
candidate deletion under its exclusive lifecycle fence; composed transform/S3
tiers and policy-aware reachable-cache eviction still require their additional
administration before global deletion.

- **[CSTORE-19]** GC MUST derive liveness from authenticated refs, pins, and
  child references, never access time, cache temperature, or backend listing
  alone.
- **[CSTORE-20]** Physical eviction, pack compaction, and pin removal MUST be
  plan/apply operations that preserve every still-required logical object and
  leave interruption-safe recovery evidence.

## 06.11 Confidentiality and authorization

Exact RAM, disks, logs, and traffic may contain secrets; content hashes reveal
equality. Store graphs enforce deployment authorization and encryption at rest
and in transit. An encryption layer binds logical ID, object kind, physical
encoding version, and ciphertext authentication. Key IDs and nonces are
physical metadata and do not change plaintext identity.

Store administration is separate from campaign operation. Export and archive
commands report sensitive closure classes and required bytes before transfer.
Credentials never enter campaign objects, planner input, executor attempts,
logs, or placement receipts returned to ordinary operators.

- **[CSTORE-21]** Every physical decoding path MUST authenticate encryption,
  compression, pack range, logical length, kind, and final logical digest before
  returning bytes to a consumer.
- **[CSTORE-22]** Driver credentials, endpoints, local roots, bucket names,
  encryption randomness, placement latency, and cache behavior MUST remain
  operational and MUST NOT affect modeled time, guidance, or canonical identity.
