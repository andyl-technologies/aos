# 07. Checkpoints and storage

## 07.1 Scope and terminology

This chapter defines the proposed durable representation of paged RAM and its
integration into exact whole-world capture and restore. It does not implement
these facilities. [The baseline integration inventory](01-current-system-and-integration.md)
distinguishes existing behavior from the changes required here.

The logical identities are defined exclusively by
[the logical RAM format](02-logical-ram-and-merkle-format.md). A `PageDigest` is
the SHA-256 digest of the domain-separated logical length and canonical page
bytes. Logical pages use 4096-byte geometry independent of host page size.
`RegionTreeDigest` commits to ordered binary-tree placement. `RamRootDigest`
commits to the declared coverage scope and logical region catalog. This chapter
MUST NOT introduce a competing hash definition or let storage geometry alter
those identities.

A `PageObjectId` is an existing typed storage `ContentId` for immutable page
content, not a synonym for `PageDigest`. The storage identity independently
binds object kind, storage schema, length, and bytes through the content-store
contract. A page catalog authenticates the association between these identities.
The logical page content is shareable at different addresses; ordered trees
bind its position. Packing, compression, encryption, backend routing, and
filesystem locations remain physical representations.

A *candidate* is a coherent captured state awaiting durable publication. A
*published closure* is an immutable authenticated whole-world root whose
required children satisfy the configured durability policy. A *selection* is
the journaled operational choice of a published closure. A *lease* is retention
authority keeping required objects or physical readers available. None of these
terms implies authority to execute a guest; restore and replay-oracle admission
remain separate capabilities.

- **[CHECK-1]** Every exact checkpoint MUST name a complete logical RAM image
  for each required node, even when its physical representation shares all but
  a few pages with earlier checkpoints. Its reconstruction MUST NOT depend on
  following a chronological chain of checkpoint deltas.
- **[CHECK-2]** The checkpoint MUST bind RAM, CPU/device state, modeled disks,
  scheduler and host continuation, plugin/fault state, pending modeled I/O,
  permanently failed nodes, and provenance to one exact whole-world boundary.
  A valid RAM root alone MUST NOT authorize restore or execution.

## 07.2 Replacement of direct-plus-delta RAM chains

The current production format has a direct RAM layer followed by up to seven
parent-relative layers. A ninth capture rebases through another complete direct
image. The current constant and representation are in
[the exact-checkpoint relations](../../../crates/crucible/src/exact_checkpoint.rs);
capture selection is in
[the checkpoint capture loop](../../../crates/crucible-api/src/vm_lifecycle/quantum_loop/checkpoint_capture.rs).
Those links describe the baseline, not the new format.

Under this proposal, a checkpoint names immutable region roots and a complete
logical catalog. Unchanged page contents and metadata subtrees are reused;
changed paths receive new immutable objects. A reader can reconstruct any
checkpoint from its root and authenticated descendants without materializing
older whole-world manifests. A previous checkpoint may remain as provenance or
an independently retained recovery selection, but it is not an obligatory RAM
layer to replay.

This eliminates forced full-RAM rebasing caused solely by chronological depth.
It does not eliminate storage maintenance. Packs can accumulate obsolete
objects, placement indexes can grow, and compressed representations can have
poor locality. Repacking and garbage collection operate on authenticated
reachability and placement generations without changing logical roots.

- **[CHECK-3]** The new checkpoint format MUST use the current logical RAM
  schema for complete-image roots. No direct/delta interpretation, legacy
  fallback reader, converter, or mixed-format restore path is introduced by this
  RFC. The coordinated experimental cutover in
  [Chapter 09](09-security-and-cutover.md) applies to all publishers and readers.
- **[STORE-1]** A logical RAM root MUST commit to logical topology and content
  associations. It MUST NOT commit to pack paths, compression choices, host
  residency, host page sizes, paging-policy generations, or physical offsets.

Checkpoint coverage includes all RAM state necessary to restore an admitted
machine, including migratable RAM-backed device regions. The canonical full
topology inventory commits to each region's class and scope mask. Mutable normal
and device RAM participates in execution, exact, and lifecycle scopes;
immutable ROM and reconstruction-only regions participate in exact and
lifecycle scopes. Unknown classifications fail admission. Execution-scope
omission of immutable bytes requires their commitment by the launch closure.
Implementations share page infrastructure but MUST preserve these coverage
rules. An execution fingerprint root cannot substitute for an exact-scope root
merely because both use the same tree algorithm.

Physical restoration compatibility is a separate provenance record. For
example, alignment or host mapping requirements can constrain admission without
changing the logical page size. The baseline topology hashes
`qemu_ram_pagesize`; this proposal removes that physical property from logical
RAM identity while preserving any necessary launch checks in compatibility
metadata.

The whole-world exact manifest continues to bind required execution provenance
and restore compatibility. That manifest is a different identity from the
scoped logical RAM root; including physical compatibility in provenance does
not make it an input to `PageDigest` or `RamRootDigest`.

## 07.3 Capture boundary and candidate construction

Capture begins after the host has established the existing exact boundary:
required QEMU nodes are paused, selectable requests are drained into the
continuation, devices are flushed under their admitted contract, and all
process-bearing nodes have explicit dispositions. Permanently failed and non-VM
nodes contribute their authenticated process-free state.

Device pre-save is allowed to have documented RAM effects. The current QEMU
capture deliberately serializes final device state before collecting RAM
records. Consequently, freezing a RAM tree before device pre-save would capture
inconsistent state. The new flow is:

1. Acquire the whole-world capture owner and cancellation context.
2. Quiesce required writers and establish the declared boundary.
3. Perform device pre-save and capture final CPU/device state.
4. Flush and reconcile every RAM-writing source, then establish the RAM epoch.
5. Rehash invalidated logical leaves, construct immutable roots, and capture
   associations for the complete checkpoint scope.
6. Stage remaining whole-world objects and validate their combined candidate.

The ownership and epoch rules in
[write tracking](03-write-tracking-and-fingerprints.md) apply independently to
fingerprints, checkpoints, and paging writeback. A checkpoint cannot clear
another consumer's pending changes. A page written and returned to its prior
contents may reuse its earlier content identity after validation, even though
its dirty epoch advanced.

- **[CHECK-4]** The candidate RAM root MUST be constructed after all admitted
  device pre-save RAM effects and MUST refer to the same boundary as final
  device state. An unexpected writer or topology change MUST invalidate the
  candidate rather than silently creating a later RAM image.
- **[CHECK-5]** Candidate creation MUST leave the previously committed
  checkpoint and dirty-consumer acknowledgments intact. Failure, cancellation,
  or indeterminate publication MUST NOT acknowledge changes absent from a
  durably selected successor.

For resident pages, capture reads a coherent view under the owner. For
nonresident clean pages, it reuses an authenticated content association and its
lease. For nonresident dirty pages, it reads the latest preserved spill version
or completes bounded writeback before hashing. A cached digest for an earlier
page generation cannot validate the latest bytes.

The candidate may reference an immutable page version shared with a template or
another checkpoint. It MUST NOT reference a mutable spill slot that execution
can overwrite. While first publication persists a page, the candidate holds
the version stable until a durable receipt and retention transition are
established. This can use a pinned immutable extent or bounded staging; it
cannot rely on a path name remaining unchanged.

## 07.4 Durable publication and commit

Publication separates content persistence from operational selection. All
required immutable children become durable before the exact root is exposed.
The root commits to the complete inventory, schema, logical RAM scopes,
provenance, configuration, and boundary. The operational journal then selects
that root, and each QEMU/host dirty consumer advances through its own bound
acknowledgment.

- **[CHECK-6]** Publication MUST verify object identities, exact lengths,
  catalog completeness, and configured durability receipts before publishing
  the whole-world root. Metadata existence or a successful temporary write
  MUST NOT satisfy this condition.
- **[CHECK-7]** The checkpoint commit acknowledgment MUST bind the candidate
  identity, boundary, source epochs, node identities, and logical roots.
  Stale, duplicate, or foreign acknowledgments MUST NOT clear newer dirty
  state. Idempotent repetition of the same completed acknowledgment MAY return
  the prior receipt.
- **[CHECK-8]** A crash or ambiguous storage result MUST retain the prior
  selected root and candidate recovery authority until reconciliation can prove
  publication and selection. Recovery MUST NOT guess which root became current.

Publication progress is measured in authenticated objects, persisted bytes,
and durable transitions. Progress reports do not change semantic checkpoint
identity. The supervision policy distinguishes hashing, persistence, device
capture, commit, and cleanup operations; a storage stall is a host operational
failure, not a guest timeout or a replayable finding.

Only nodes that were running before capture are eligible to resume afterward.
Cleanup attempts every captured node and owned resource even if one cleanup
operation fails. A failed disposition transfers authority to explicit recovery
or quarantine ownership; it cannot disappear into an exception path. Published
but unselected immutable objects can later become garbage, provided no
recovery journal or runtime lease retains them.

Replay-oracle promotion continues to validate an exact realization against an
independently realized thin path. The new RAM representation neither removes
this requirement nor makes a persisted promotion boolean authoritative. A
promotion capability must bind the selected exact root and current format.

## 07.5 Immutable catalog and object layout

The logical tree representation and its canonical bytes are fixed by Chapter
02. Storage metadata provides authenticated resolution from logical digests to
typed page objects and grouped tree/catalog objects. It may contain complete
canonical zero runs, repeated-page runs, and authenticated subtree reuse where
the logical schema permits those encodings.

Canonical zero pages need not occupy stored page objects when their exact
logical length and digest can be derived. A zero run is still authenticated
placement information; an absent object is not implicitly a zero page. Final
partial pages use their declared logical length and MUST NOT admit noncanonical
padding as hidden content.

- **[STORE-2]** A reader MUST authenticate both the storage object identity and
  the logical page digest/length before exposing page bytes. Tree paths MUST
  authenticate the page's region and position. Substituting a different typed
  object with the same apparent payload length MUST fail.
- **[STORE-3]** Catalogs MUST be hierarchical and bounded per object. They
  MUST reject duplicate positions, overlaps, unsupported kinds, gaps in
  required coverage, out-of-range references, excessive depth, inconsistent
  counts, and ambiguous encodings before declaring a root ready.

Page content objects should remain individually addressable logically while
physical packs group many small objects. Tree nodes should be grouped into
bounded metadata objects instead of requiring a separate filesystem object for
every binary branch. Grouping changes physical object organization, not the
ordered binary logical digest definition.

The baseline packed backend has a 65,536-object index limit. Incompressible
512 MiB RAM has 131,072 logical 4096-byte pages before metadata or checkpoint
history. Its
[packed backend](../../../crates/crucible-cas/src/content_store/packed.rs)
therefore cannot serve as the unchanged page-object implementation. Likewise,
the current
[content envelope](../../../crates/crucible-cas/src/content_envelope.rs)
limits one envelope to 65,536 children, and production exact roots already use
bounded inventory index pages.

- **[STORE-4]** Admission MUST account for worst-case unique pages and retained
  metadata, not expected deduplication. The implementation MUST provide
  scalable placement indexes and paginated traversal before enabling page-level
  durable capture at capacities exceeding existing limits. Raising a constant
  without bounding index memory is insufficient.

A larger immutable extent can reduce request overhead, but cannot obscure page
identity or force a single changed page to change every unrelated logical page
object. If packed extraction serves a subrange, its admitted integrity contract
must establish authenticated page bytes and placement metadata. A checksum of
an unread entire pack is not evidence that the selected page is valid.

## 07.6 Temporary spill and durable content

Paging spill preserves current mutable execution bytes. Durable CAS preserves
immutable named state. They can share physical devices or storage primitives,
but their authority, quotas, lifetime, and durability differ.

Spill slots may be overwritten after their owning page version becomes
obsolete. A spill write receipt binds page ownership, generation, exact byte
count, and successful preservation under the pager's failure contract. It does
not automatically satisfy checkpoint durability. Checkpoint publication may
promote a stable spill version by independently hashing, persisting, obtaining
durable receipts, and transferring retention authority.

- **[STORE-5]** A dirty page MUST NOT be evicted until its current bytes have
  another admitted preservation source. A checkpoint MUST NOT retain mutable
  spill merely by recording its offset or a cached digest.
- **[STORE-6]** Deduplication MAY share immutable page content across admitted
  instances. It MUST NOT share writable page ownership, infer authorization
  from a digest, or allow one instance's eviction/cleanup to destroy another
  instance's retained source.

Backing-object access must remain within the authenticated storage namespace
and authority established for the instance or checkpoint. Confidential page
contents follow the storage encryption and tenant-isolation policy; using a
content digest as a name does not declassify those bytes. Spill encryption,
crash cleanup, and deletion are covered by the security and lifecycle chapters.

## 07.7 Leases, discovery, GC, and packs

Reachability and reader stability are related but different. A durable root
retains logical descendants through GC. An open pack reader pins a physical
generation or inode while extraction completes. A runtime instance may depend
on immutable pages without yet having a durable checkpoint root. It therefore
needs a runtime retention record visible to the same GC authority.

- **[STORE-7]** Every runtime page source, candidate, selected checkpoint,
  restore, template, transfer, and recovery journal MUST have an explicit
  retention owner. Ownership transfer MUST install the successor's retention
  before releasing the predecessor's. Anonymous process-local knowledge of a
  root MUST NOT be the sole protection against GC.
- **[STORE-8]** Object discovery and journal publication MUST occur under an
  admitted GC exclusion or equivalent atomic retention protocol. Objects found
  during a paginated walk MUST remain protected across subsequent pages,
  cancellation, and restart reconciliation.
- **[STORE-9]** Repacking MUST preserve logical identities, switch placement
  indexes atomically, and retain old physical sources until admitted readers
  finish. A faulting pager MUST NOT race pack deletion or depend on a stale
  unpinned byte range.

GC walks roots through bounded cursors with authenticated continuation state.
It must account for shared subtrees once without storing the entire closure in
an unbounded in-memory set. Scratch discovery indexes can be disk-backed,
quota-controlled, and restartable. Expired wall-clock leases cannot permit
deletion while a live admitted instance still has authority to fault those
pages; expiration must first revoke or reconcile that authority.

Deleting an unreachable logical object may not immediately reclaim its pack
bytes. Quotas and telemetry distinguish logical retained bytes, unique page
bytes, physical pack bytes, spill allocations, and pending reclamation.
Repacking needs temporary disk headroom for both generations and remains
cancelable before its atomic switch. Cleanup after a committed switch is
idempotent and cannot revert logical ownership.

## 07.8 Local lazy restore

The baseline restore fully copies RAM layer streams into sealed memfds before
launch, then QEMU validates and applies the direct/delta records. See
[exact restore materialization](../../../crates/crucible-qemu/src/spawn/materialization/exact_restore.rs)
and [sealed inputs](../../../crates/crucible-qemu/src/exact_checkpoint_input.rs).
This duplicates full-image staging and live RAM pressure despite bounded copy
buffers. The new path replaces that RAM contract with authenticated immutable
catalogs and leased local page sources.

Before launch, restore validates the whole-world manifest, exact provenance,
logical region geometry, complete page associations, required object
availability, byte/object budgets, and retention ownership. Device state and
other non-RAM artifacts remain subject to their admitted immutable-input
contracts. Establishing RAM source readiness does not require loading all RAM
into the destination's live mapping.

- **[CHECK-9]** Local lazy restore MUST begin with a complete authenticated
  closure and retained available local sources. It MUST NOT require arbitrary
  remote content to satisfy a guest fault. Runtime fetching from a remote store
  requires a separately admitted execution mode.
- **[CHECK-10]** Before installing a page into guest-accessible RAM, restore
  MUST validate exact length, typed object identity, logical `PageDigest`, and
  membership at the requested position under the admitted root. Failure MUST
  leave that page inaccessible and fail the affected host operation.
- **[CHECK-11]** The restore transaction MUST publish the world only after all
  nodes and continuation components are ready. Partial node readiness MUST NOT
  become executable world state. Cancellation MUST reap uncommitted processes
  and retain recovery authority until cleanup is resolved.

Prelaunch validation authenticates immutable catalogs and possession receipts
or verifies objects through the admitted store. Per-page validation still
guards later extraction, corruption, and wrong-placement errors. The store
contract must keep checked sources stable; checking a mutable filename once is
insufficient. A root and its digests provide integrity expectations, not proof
of continued physical possession.

If device restore callbacks access RAM, the pager and page-source leases must
already be operational before those callbacks execute. Such accesses populate
only the necessary pages under the restore budget. A fault during restoration
cannot advance guest-visible virtual time or invent a modeled I/O event.

## 07.9 Resource budgets, cancellation, and acceptance

Capture, publication, restore, discovery, and maintenance receive separate
operation budgets. Every path limits working buffers, metadata cache, number
of in-flight objects, temporary disk bytes, retained descriptors, and queue
depth. Budgets include staging, pack generations, tree updates, and shared
objects' physical ownership; guest RAM residency alone is not the complete
host footprint.

- **[STORE-10]** Each streamed operation MUST check cancellation between
  bounded I/O units and use storage-operation deadlines for blocked I/O.
  Cancellation MUST remain distinguishable from retryable store failure and
  MUST NOT bypass publication, ownership, or cleanup ordering.
- **[CHECK-12]** A configured residency target MUST NOT force capture or
  restore to allocate another complete RAM image in memory. Peak memory MUST
  have an admitted bound derived from working sets and bounded metadata rather
  than total serialized RAM size.

Initial capture of previously unhashed contents still reads those bytes.
Subsequent capture should perform work proportional to changed pages and
necessary metadata, including authenticated source access for cold dirty pages.
Implementation acceptance includes incompressible large RAM, sparse zero RAM,
write-and-revert, many retained roots, device pre-save writes, mid-operation
cancellation, forced storage errors, pack replacement during page reads, and
crash injection at every root/selection/epoch transition.

The decisive correctness result is equal logical roots and equal whole-world
continuation across resident, aggressively paged, restored, and forked
realizations. The decisive resource result is bounded memory during cold
capture and lazy restore, with measured temporary disk and object counts.
