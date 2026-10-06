# 03 — Complete write tracking and incremental fingerprints

This chapter specifies how Crucible observes changes to logical RAM, captures
coherent content, and publishes cached Merkle fingerprints. The logical byte
encoding and tree shape are defined in
[chapter 02](02-logical-ram-and-merkle-format.md). Paging, exact checkpoints,
and transfer consume the same authenticated content, with independent operational
progress. None of these mechanisms requires guest kernel changes, a guest agent,
or guest cooperation.

The source baseline below is informative. Requirements carrying `TRACK` or `FP`
identifiers specify the desired implementation. They do not assert that the
current implementation already provides the specified coverage.

## 03.1 Informative source baseline

The current
[QEMU patch](../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch)
adds `DIRTY_MEMORY_CRUCIBLE_CHECKPOINT`, a fourth QEMU dirty-memory client,
and `GLOBAL_DIRTY_CRUCIBLE_CHECKPOINT`. In patched `system/memory.c`,
`memory_region_get_dirty_log_mask()` adds this client to globally tracked
migratable RAM and IOMMU regions. Patched `system/physmem.c` updates its bitmap
through dirty flags, dirty ranges, imported little-endian bitmaps, RAM remapping,
and discard operations. A checkpoint generation also detects relevant writes
and topology changes during candidate validation.

Patched `system/crucible-checkpoint.c` captures direct or delta RAM records at
an exact paused simulator boundary. Candidate capture retains exclusive
migration/raw-state authority until commit, abort, or invalidation. Commit
validates RAM generation, topology, and device state before clearing its own
bitmap. Clearing calls `physical_memory_dirty_bits_cleared()` to rearm translated
writes. A detected violation restores an all-dirty checkpoint bitmap before
refusing commit. This ordering is useful groundwork for the new tracker.

The current fingerprint path is different. Patched `plugins/api.c`
`qemu_crucible_guest_ram_sha256()` hashes complete ordinary writable RAM using
`crucible.qemu.guest-ram.v1`. It includes RAMBlock names and lengths, excludes
ROM and RAM-device blocks, and follows RAMBlock traversal order. Aggregate
fingerprint capture copies this material into a sealed memfd while holding the
authorized exact boundary. The
[plugin sampler](../../../crates/crucible-qemu-plugin/src/fingerprint_sampler.rs)
and [digest worker](../../../crates/crucible-qemu-plugin/src/runtime/live_callbacks/fingerprint_worker.rs)
then hash the detached material and publish the matching request generation.
Offloading SHA-256 does not eliminate the full RAM copy or its residency cost.

Checkpoint topology instead includes migratable RAM-backed device memory,
sorts names, and records `qemu_ram_pagesize()`. Its existing topology digest is
therefore not the new logical RAM digest. Execution, exact, and lifecycle scopes
remain explicit; they must not be collapsed into one assumed universal scope.

There is also a distinct whole-RAM hash in patched
`plugins/crucible-fault-instruction.c`, which calls
`qemu_crucible_guest_ram_sha256()` while constructing instruction-fault state.
Updating only the aggregate plugin sampler would leave this scan intact.

Lifecycle observation has a third RAM hash surface. Patched `plugins/api.c`
`qemu_crucible_ram_hash()` performs an FNV-style traversal of every RAMBlock
with a host pointer, including its ID, length, and complete bytes. Patched
`plugins/crucible-fault-lifecycle.c` combines that value with device state in
`crucible_lifecycle_snapshot()` for lifecycle preconditions. This coverage is
broader than the execution SHA-256 path. Its replacement uses the explicitly
declared lifecycle scope and participates in the coordinated cutover below;
it cannot retain the old scan merely because the plugin sample uses a new root.

Exact restore in patched `system/crucible-checkpoint-restore.c` reads directly
into `qemu_ram_get_host_addr()` before establishing checkpoint authority.
Consequently, intercepting ordinary dirty-marking calls alone cannot maintain
a correct cached tree. Restore needs an explicit content-state transition.

## 03.2 Content identities and operational state

`PageDigest` is the BLAKE3-256 content digest binding a logical page's valid
length and bytes. Repeated content can share a `PageDigest` across positions.
`RegionTreeDigest` commits ordered page content in the canonical binary tree.
`RamRootDigest` commits the selected scope, topology, and ordered region roots.
The storage `ContentId` separately authenticates canonical serialized object
bytes, independently of pack, compression, encryption, or placement. These
terms and their encodings have exactly the meanings assigned in chapter 02.

Logical pages are 4096 bytes on every host. Host pages, target dirty granules,
huge pages, backing extents, compression blocks, and transfer frames may have
different sizes. Their ranges are translated into intersecting logical pages;
they never redefine the canonical page size.

Each mutable page has operational state that may include a `page_version`,
dirty-epoch membership, a cached content identity, and a coherent backing
reference. A published root retains immutable content. A backing reference to
a mutable file range is insufficient evidence that a previous page version
remains available.

The inventory classification describes actual mutability, not a device's name
or guest access permissions. RAM exposed read-only to the guest but changed by
an emulated device belongs to the applicable mutable class. Execution may omit
truly immutable ROM only under chapter 02's authenticated launch-closure rule.
All scope roots commit the complete inventory topology even when their selected
region trees differ.

- **[TRACK-1]** Every guest-observable mutable RAM region MUST appear in the
  admitted inventory with explicit scope membership and write-tracking
  ownership. Device RAM MUST be included in that inventory. Additional read-only
  membership in exact or lifecycle scopes follows chapter 02. Omitting a writer
  or moving its bytes between scopes MUST NOT be an optimization.
- **[TRACK-2]** `page_version`, `dirty_epoch`, residency, backing location, and
  consumer acknowledgments MUST remain operational state. They MUST NOT enter
  `PageDigest`, `RegionTreeDigest`, `RamRootDigest`, guest-visible state, or
  execution identity.
- **[TRACK-3]** An implementation MUST associate a cached `PageDigest` with the
  specific coherent page version it describes. It MUST NOT reuse that digest
  after an unaccounted mutation or use host allocation geometry as logical
  identity.

Operational versions need not increment on every store. One transition from
clean to potentially changed in a tracking epoch is sufficient for later
boundary hashing, provided subsequent writes cannot be mistaken for the
immutable version being hashed or written back. Epoch rotation establishes a
new mutation interval. A separate writeback protocol prevents races during
concurrent eviction.

## 03.3 Completeness of writer coverage

QEMU's ordinary migration tracking is an input to the design, not a proof of
complete tracking. Its memory API explicitly requires dirty marking for writes
outside guest code and ROM-device flushing for internal direct writes. See
[the upstream memory API](https://www.qemu.org/docs/master/devel/memory.html).
The baseline matrix identifies review entry points in the patch; implementation
must inspect the corresponding patched source and participating devices.

| Writer or transition | Current source entry point | Required coverage evidence |
| --- | --- | --- |
| Translated CPU stores | Patched `accel/tcg/cputlb.c` and `system/physmem.c` in the [QEMU patch](../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch) | Scalar, vector, atomic, unaligned, and cross-page writes; already-dirty fast paths; rearming after epoch rotation |
| DMA through address spaces | Patched `system/physmem.c`, `flatview_write_continue_step()` | Every successful written subrange, including fault-transformed values and partial completion |
| Cached DMA and mapped buffers | Patched cached-access declarations and helpers in `include/system/memory.h`, plus address-space map/unmap users | Direct pointer writes, cached stores, bounce buffers, and delayed unmap reporting |
| Device-owned RAM and ROM backing | Migratable RAM inventory, device callbacks, and ROM-device dirty/flush APIs | CPU-inaccessible and read-only-to-guest bytes that the device can mutate; explicit scope ownership |
| Debugger and management writes | QEMU debugger/physical-memory write entry points and admitted QMP mutation commands | Dirty accounting while paused, including writes to already-dirty pages |
| Boundary memory mutations | Patched `plugins/crucible-fault-memory.c`, `memory_region_fault_commit_ram()` | Atomic prepared mutations, branch-private authoritative versions, all affected dirty consumers; suppressed writes do not manufacture content changes |
| Persistent fault-model mutations | Patched `plugins/crucible-fault-node.c` retention, rowhammer, and staged fetch paths | Cold victims and delayed physical writes; tracking and translated-code invalidation for every committed subrange |
| Modeled memory service | Patched `plugins/crucible-fault-node.c`, `qemu.memory.service.v3`, and x86 CPU memory-service tickets | Deferred stores and frozen loads preserve grant/ready coordinates, access sequence, ordering, and replay state through host faults |
| Hardware-error reporting | Admitted QEMU hardware-error delivery and guest-RAM record writers | Reporting writes such as GHES records enter tracking; reporting alone is not proof of a data mutation or guest handling |
| Instruction fault state observation | Patched `plugins/crucible-fault-instruction.c` | Observes the correct pre- or post-action root without modifying tracker state inconsistently |
| Reset, boot loading, and device post-load | System reset/load paths and participating device reset/post-load callbacks | Establishes tracked initial content and invalidates overwritten bytes before root reuse |
| Exact checkpoint restore | Patched `system/crucible-checkpoint-restore.c`, `crucible_restore_parse_layer()` | Direct restored writes explicitly install or invalidate page identities |
| Resize, removal, remap, and discard | Patched `qemu_ram_resize()`, `qemu_ram_free()`, `qemu_ram_remap()`, `ram_block_discard_range()` | Distinguishes topology changes, content changes, and content-preserving paging |
| Hot fork and child repair | [hot-fork lifecycle](06-hot-fork-and-lifecycle.md) and patched fork coordinator | Child-private metadata, inherited immutable identities, and explicit repair writes |

- **[TRACK-4]** Every mutation path MUST invalidate all intersecting logical
  pages before its new bytes can be admitted into a published state. This
  requirement applies to host-side writers and paused management operations as
  well as translated guest stores.
- **[TRACK-5]** Direct host-pointer writers MUST either participate in the
  tracking protocol or be covered by a demonstrated alternative mechanism.
  An unclassified writer MUST make the affected execution capability fail
  admission. The guest MUST NOT be asked to compensate.
- **[TRACK-6]** Tracking activation and rearming MUST cover all admitted scope
  members, including writable non-migratable regions when present. Migratability
  alone MUST NOT determine fingerprint coverage.
- **[TRACK-7]** Tracking MUST distinguish content-changing guest discard/reset
  operations from content-preserving paging. Eviction, reload, remapping for
  storage, and runtime residency-policy changes MUST NOT create logical writes.

The evidence is a maintained writer inventory plus differential tests. Adding a
device, memory backend, raw-pointer optimization, or management write command
requires updating that inventory. A source-string check showing the presence of
one dirty flag is insufficient evidence of coverage.

### 03.3.1 Fault semantics and preservation work

The integration inventory distinguishes three kinds of work. Architectural
accesses exercise the admitted guest-memory model. Simulation mutations alter
RAM under the authored fault model, including delayed retention or rowhammer
victims. Operational preservation moves or observes existing logical contents
for paging, hashing, checkpoints, transfer, and COW. A host fault during either
of the first two kinds does not create another architectural access.

- **[TRACK-17]** Operational preservation MUST NOT create modeled access
  opportunities, consume occurrence counters or random choices, refresh
  simulated retention cells, increment rowhammer counters, or consume modeled
  memory-controller service. Retry and population MUST resume the same admitted
  access or mutation without duplicating its semantic effects.
- **[TRACK-18]** A simulation mutation of a cold page MUST acquire the latest
  authoritative logical version and branch-private mutation rights before
  changing bytes. It MUST notify every affected dirty consumer and satisfy the
  existing translated-code invalidation contract. Population and copying of
  unchanged bytes MUST NOT stand in for that notification.
- **[TRACK-19]** Expanded fingerprint inventory MUST NOT expand fault-target
  authorization. A region's inclusion in a RAM scope does not admit mutation
  of device RAM, ROM/ROMD, MMIO, read-only/protected ranges, or ambiguous aliases.
  Each fault capability MUST retain its own explicit target restrictions and
  reject unsupported targets before applying effects.

Read corruption, stuck reads, poison, and modeled service delays can change
observed values or future continuation without changing physical RAM bytes.
Their fault/plugin state belongs to the enclosing complete continuation, not
to a fabricated RAM write. RAM-root equality alone does not establish their
semantic equivalence. Authored fault-service delays remain modeled time;
host population delays remain operational wall time under INV-2.

The source baseline's `MemoryService` capability is narrower than arbitrary
per-access latency or a physical controller model. Shared-dispatch non-fw_cfg
CPU service uses an explicit-vCPU one-byte range and x86_64/i386 tickets. Broad
random latency, controller failures, address aliasing, or new ECC decoding
require separately specified semantic capabilities. Before claiming the current
service profile, implementation must reconcile its host payload encoder and
GPL decoder, including the actor field, through independent codec and live
tests. The source audit alone does not establish a working admitted profile.

## 03.4 Independent epochs and consumer baselines

Fingerprint publication, checkpoint durability, transfer completion, and pager
writeback have different completion points. Clearing one shared bitmap at the
first completion would lose work for the others. The implementation may use
separate bitmaps or harvest one ingestion bitmap into per-page versions and
independent immutable baselines. The observable contract is the same.

An epoch contains pages potentially changed since its beginning. Harvesting
captures that set while all relevant writers are excluded, records ownership of
the harvested interval, and rearms the next interval. A consumer can then
retain its root or version baseline independently. Checkpoint delta selection
can compare content with the committed checkpoint root, while fingerprinting
updates the latest execution root. Dirty pages are candidate differences;
matching content identities mean there is no actual content difference.

- **[TRACK-8]** Each consumer MUST have an independently acknowledged baseline.
  Completing, aborting, or clearing fingerprint, checkpoint, paging, or transfer
  work MUST NOT clear another consumer's outstanding changes.
- **[TRACK-9]** Harvest and rearm MUST exclude concurrent writers or use an
  equivalent synchronization protocol proved to preserve every write. A write
  racing the transition MUST belong to at least one retained interval.
- **[TRACK-10]** Failed or cancelled work MUST retain its previous committed
  baseline and all required mutations. Acknowledgment MUST occur only after
  that consumer's completion condition has been satisfied.
- **[TRACK-11]** Operational counter exhaustion MUST be detected before reuse.
  The implementation MUST rotate to a fresh tracking incarnation at a coherent
  boundary or stop the affected capability; wrapping comparisons MUST NOT
  authorize stale cached content.

Checkpoint candidate authority remains transactional. Capturing a candidate
does not advance the committed checkpoint baseline. Durable host publication
and matching QEMU commit establish that transition, as specified in
[chapter 07](07-checkpoints-and-storage.md). Transfer acknowledgment establishes
destination possession of authenticated content, not permission to resume a
VM; [chapter 08](08-state-transfer.md) defines that separate authority.

## 03.5 Exact capture and publication

A request identifies its authorized aggregate instruction count and request
generation. The existing control-boundary machinery quiesces every vCPU and
participating device worker. The new tracker retains those admissions. BQL or
paused runstate alone does not prove a coherent snapshot.

Capture freezes the selected inventory and all relevant page versions. It
harvests mutations, resolves changed page content, and builds an immutable root.
Unchanged pages reuse identities only when their cached versions are valid.
Cold pages can use authenticated immutable backing for the frozen version.
Pages whose current bytes are not yet preserved require bounded copying,
write protection, or continued quiescence before hashing can leave the boundary.
No detached worker may read a mutable live page and call that an exact snapshot.

- **[FP-1]** A fingerprint capture MUST bind one admitted scope, canonical RAM
  topology, exact execution coordinate, and request generation to one coherent
  immutable RAM view. All CPU, device, fault, debugger, and management writers
  capable of changing that view MUST be excluded or versioned safely.
- **[FP-2]** The root builder MUST use the canonical page and tree encodings in
  chapter 02. It MUST read current bytes for invalid leaves, or authenticated
  immutable bytes proven to represent the same frozen version.
- **[FP-3]** Asynchronous hashing MUST consume bounded immutable work. The
  system MUST NOT create a second full resident RAM image merely to detach
  hashing. Snapshot retention, buffers, and tree metadata MUST be accounted
  under the resource policy.
- **[FP-4]** Root publication MUST precede acknowledgment of the matching
  request generation. The published sample MUST contain that request's exact
  coordinate and complete component evidence. Stale or superseded work MUST NOT
  acknowledge a newer request.
- **[FP-5]** A consumer MUST observe either the prior complete sample or the
  newly published complete sample. Partial root/component publication MUST NOT
  become comparable fingerprint evidence.

The intended ordering is: admit request; quiesce and freeze content; capture
register/RR and device evidence at the prescribed boundary; finalize the RAM
root; validate capture authority; publish complete sample; acknowledge matching
generation; release the boundary according to the control protocol. If the
control callback returns before hashing completes, guest execution remains
behind the appropriate boundary gate until the protocol permits continuation.
An optimization that allows execution earlier must retain an immutable exact
view and preserve every existing acknowledgment and scheduling guarantee.

Checkpoint device pre-save callbacks can change RAM in the baseline code.
Fingerprint projection is a separate read-only observation contract. Neither
contract may silently borrow the other's ordering. The root used by a checkpoint
must describe its state after the prescribed pre-save effects; the root used by
an execution sample must describe its authorized observation boundary.

## 03.6 Cached Merkle updates and coherent eviction

The tracker marks potential changes while execution proceeds. At a coherent
capture it hashes each invalid page version once, compares the result with its
previous `PageDigest`, and propagates actual identity changes through the binary
tree. Shared ancestors are recomputed once in a batch. Writing a page and then
restoring its old bytes produces the old identity; it does not require a new
root or transfer object solely because it was dirty.

- **[FP-6]** Stores MUST NOT trigger unconditional page hashing. Changed content
  MUST be resolved at coherent capture or another proved coherent preservation
  operation, with reuse limited to the same immutable version.
- **[FP-7]** An unchanged subtree MUST retain its `RegionTreeDigest` regardless
  of residency or physical representation. Tree updates MUST preserve ordered
  position binding and MUST NOT substitute a commutative set of page digests.

Eviction can resolve a dirty page's identity while preserving its bytes. A later
fingerprint can use that identity without faulting the page into the live guest
mapping. This is safe only when eviction obtains a coherent page version and
prevents a later write from being lost between copying and removal.

- **[TRACK-12]** Dirty eviction MUST preserve one coherent page version and
  authenticate its stored representation before discarding the only current
  copy. Concurrent writeback MUST exclude writes or detect them without losing
  their bytes or invalidation.
- **[TRACK-13]** Cached identity from eviction MUST remain associated with its
  preserved version. A later write MUST invalidate that association before a
  root can reuse it. Writeback completion MUST NOT clear fingerprint,
  checkpoint, or transfer obligations.

Kernel swap does not expose its anonymous-page backing as an application-level
content object. A kernel-swap realization can still use Merkle caching and
independent epochs, but rehashing an invalid cold leaf may fault it in. The
explicit pager in [chapter 04](04-host-paging.md) can preserve an authenticated
page identity during eviction and avoid that reload. This distinction affects
cost, not logical fingerprint semantics.

### 03.6.1 Prepared fault mutations across residency transitions

The existing range-mutation contract prepares before/after evidence for all
fragments and admits an all-or-nothing commit; see
[RFC-0014's boundary mutation contract](../0014-signal-driven-fault-model/14-qemu-fault-patches/03-memory-boundary-mutation.md).
Cold-page acquisition and COW add operational failure points to that transaction.

- **[TRACK-20]** Before the first fault-transaction write, preparation MUST
  establish coherent before bytes, the bound page versions, mutation/COW
  authority, and admitted commit resources for every affected fragment.
  Residency transitions MUST NOT change that prepared logical view or introduce
  a recoverable partial commit. Precommit refusal MUST preserve logical state.
  If an unavoidable operational failure makes commit disposition uncertain,
  the affected execution authority MUST be held or stopped, with unresolved
  resources retained; it MUST NOT acknowledge successful fault evidence or
  continue as a valid completed mutation.

Pinning, immutable staging, and temporary placement exclusion are implementation
choices. Their capacity and lifetime must be admitted, and stale I/O cannot
replace a prepared version. Independent consumers observe committed writes
without losing earlier obligations. The same before/after evidence contract
applies whether the original fragments were resident, cold, or shared by COW.

## 03.7 Fork, restore, reset, and recovery

A hot-fork child inherits immutable content roots and establishes private
operational tracking state. Shared tree nodes never receive in-place content
updates. Parent and siblings retain their original roots even when a child
changes RAM. Linux copy-on-write alone does not establish the lifetime or
immutability of external pager storage.

- **[TRACK-14]** Fork MUST establish child-private tracking incarnations and
  acknowledgments while retaining valid immutable content. Mutable backing,
  pager registration, and descriptor ownership MUST satisfy
  [chapter 06](06-hot-fork-and-lifecycle.md) before the child resumes.
- **[TRACK-15]** Restore MUST explicitly install authenticated page identities
  and roots, or invalidate affected content and rebuild it before observation.
  Direct writes, reset effects, and device post-load mutations MUST all be
  reconciled. No pre-restore dirty epoch may authorize the restored view.
- **[TRACK-16]** Reset, initial loading, and topology changes MUST establish new
  coherent tracker state. A zero-page identity may be used without reading RAM
  only when initialization proves those exact bytes and valid lengths and all
  later writers are tracked.

Partial restore failure leaves the VM unavailable for execution and root
publication. It cannot be repaired merely by retaining the old root: RAM or
devices may already have changed. Recovery authenticates an admitted closure
or reconstructs execution from a replay baseline. A missing page, digest
mismatch, or failed writeback is a host-side operational failure, never
canonical zero RAM or a guest finding.

- **[FP-8]** An invalidation, capture, or consistency failure MUST prevent
  successful fingerprint acknowledgment. Previously authenticated roots remain
  immutable historical evidence; they MUST NOT be presented as current state.
- **[FP-9]** Recovery MAY rebuild cached metadata from current bytes only after
  establishing coherent state and the required execution authority. It MUST NOT
  hide an observed root mismatch by replacing evidence and continuing the same
  successful attempt.

Rebuilding after known metadata loss is distinct from recovering lost RAM.
Version and epoch state need not be durable when the authenticated RAM closure
can establish a new incarnation. Lost current page bytes require restore or
replay, not a metadata reset.

## 03.8 Immediate versioned fingerprint cutover

RFC-0010 [DET-31](../0010-crucible/04-determinism-contract.md) requires the
fingerprint definition to be versioned. This RFC changes that definition
immediately. It does not require an old reader, converter, or dual production
hash path. The coordinated release admits only its new negotiated contract and
rejects older or mismatched fingerprint schemas.

The cutover covers the QEMU RAM digest domain and capture export, plugin capture
metadata, shared-memory semantic/layout version, the host
[black-box fingerprint combiner](../../../crates/crucible-qemu/src/mapped_quantum/fingerprint.rs),
and the harness
[definition and memory algorithm tags](../../../crates/crucible-harness/src/fingerprint/definition.rs).
It also covers instruction-fault before/after state hashes and any lifecycle
state observer that composes RAM identity. Scope-specific roots are chosen by
the observation's declared contract; similarly sized digests are not
interchangeable.

Selected-byte fault preconditions are an additional review surface. Patched
`plugins/crucible-fault-memory.c` hashes memory mutation evidence, while
`plugins/crucible-fault-node.c` reads selected guest RAM through translated
regions. Such range evidence is not interchangeable with a whole-scope root or
a `PageDigest`. The implementation inventory records its declared range,
observation boundary, and hashing contract, and routes reads through coherent
paging-aware content access. Hashes of unrelated accelerator buffers or device
protocol payloads remain their own contracts; replacing every 32-byte digest
with a RAM root would corrupt state meaning.

- **[FP-10]** Every production complete-RAM state identity observer MUST use the
  new declared scope/schema. Selected-range fault preconditions and before/after
  evidence MUST retain an independently declared, versioned range, observation
  boundary, and coherent paging-aware hashing contract; they MUST NOT be
  replaced by a whole-scope root that answers a different predicate. No unchanged
  algorithm tag may silently acquire Merkle semantics. Request producers,
  sample consumers, fault preconditions, and replay evidence MUST reject
  mismatched definitions for their respective contracts.
- **[FP-11]** The cutover MUST preserve component coverage, exact coordinates,
  register/RR evidence, and device observation ordering. Paging policy MUST NOT
  select a different fingerprint algorithm or weaker scope.

Exact storage format changes are specified in chapter 07. ABI and license
conformance remain mandatory under
[chapter 09](09-security-and-cutover.md); QEMU implementation objects and native
pointers do not cross into Apache host memory.

## 03.9 Independent oracle and performance evidence

Incremental agreement between two runs is insufficient: both may miss the same
writer. Validation reconstructs the canonical tree from a full coherent scan,
without consulting cached digests, dirty selection, or pager identity shortcuts.
It compares every scope root with the incremental result. The oracle is a test
and qualification mechanism, not a backward-compatible production digest.

- **[FP-12]** Qualification MUST include an independent full-recompute oracle
  covering every admitted writer family and scope. Root disagreement MUST fail
  qualification with localized page/region evidence.
- **[FP-13]** Tests MUST interleave independent consumer acknowledgments, failed
  captures, cancellation, eviction/writeback races, fork mutations, reset, and
  restore. They MUST include repeated writes, reverted writes, partial final
  pages, cold pages, and host allocation-geometry changes.

For 4 KiB pages and 32-byte digests, a power-of-two page count's dense binary
leaf/internal hashes consume approximately 1.56% of RAM size before allocation
overhead: about 8 MiB for a 512 MiB guest, or 1 GiB for a 64 GiB guest. Padding
can raise that cost toward 3.125%; chapter 02's dense/padded bound governs
admission. One dirty bitmap consumes 16 KiB per 512 MiB, and an eight-byte
version per page adds 1 MiB. Persistent roots,
references, retained snapshots, and fork-induced metadata copies add further
cost. Compact realization may preserve the specified binary tree while storing
its metadata more efficiently.

Sparse changes reduce hashing; a workload rewriting all pages still hashes all
RAM and pays tree overhead. Epoch rotation can also rearm TCG dirty paths.
[Chapter 10](10-validation-and-performance.md) measures bytes hashed, faults,
boundary latency, metadata sharing, writeback traffic, request frequency, and
campaign throughput. Optimization is accepted only with matching oracle roots
and preserved guest transparency.
