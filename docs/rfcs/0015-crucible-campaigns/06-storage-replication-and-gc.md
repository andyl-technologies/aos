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

The initial admitted graph is a flat `StoreNodeId -> StoreNodeSpec` map with an
explicit root and exact admitted `ObjectKind` set. `StoreNodeSpec` is a closed
enum over built-in leaves and layers; child fields contain node IDs, which lets
multiple routes share a leaf without duplicating it. Startup performs a DFS and
demand propagation before constructing the root:

- at most 256 nodes, depth at most 64, and bounded ASCII node IDs;
- every child exists, the graph is acyclic, and every configured node is
  reachable;
- a router covers exactly the kinds that can reach it, including the union of
  demands when the router is shared;
- tiers and mirrors are nonempty, the write-tier index is valid, and promotion
  or mirroring children support conditional immutable creation;
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

Within a campaign snapshot, the semantic pin projection is keyed by the exact
`ConfigurationId`. Its value is the latest authenticated schema-v5
`PinCommandAccepted` fact. `Thin` and `Exact` select the required logical
closure profile; `None` is a retained tombstone that removes the configuration
from the current GC pin set without erasing command replay or campaign history.
The graph membership proof is evaluated at the accepting parent snapshot, so a
backing-store object that is not authoritative campaign knowledge cannot be
pinned through this transaction.

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
