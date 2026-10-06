# 06 — Hot fork and page-state lifecycle

This chapter extends the retained QEMU template transaction to include paged
RAM, immutable RAM roots, and the resources needed to resolve faults. It governs
local process descendants, their backing leases, and their retirement. The
[logical RAM format](02-logical-ram-and-merkle-format.md),
[write tracking](03-write-tracking-and-fingerprints.md), and
[host paging](04-host-paging.md) define the contents being retained. The
[runtime policy](05-runtime-policy-and-supervision.md) governs their physical
placement. These responsibilities remain distinct throughout the transaction.

The capitalized requirement words have the meanings specified by this RFC's
[conventions](README.md). Requirements in this chapter use the `FORK` and `LIFE`
prefixes. Informative descriptions of existing implementation do not establish
new admission capabilities.

## 06.1 Existing fork machinery and its limits

The current [RFC-0020 hot-fork contract](../0020-crucible-campaigns/05-hot-fork-and-checkpoints.md)
retains an exact paused boundary, frozen block sources, quiescent plugin, RCU,
and asynchronous-worker barriers, and authenticated child resources. The
coordinator executes `fork(2)` on QEMU's designated main-loop thread. Child
startup migrates into its target cgroup, establishes process containment,
reconstructs process-local runtime state, applies descriptor dispositions, and
authenticates the resulting writable shared mappings. Host continuation and
QEMU child readiness commit as one candidate world.

The [QEMU patch](../../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch)
implements `qemu_crucible_hot_fork_ram_set_forkable()` by advising each RAMBlock
with `MADV_DOFORK` or `MADV_DONTFORK`. This helper does not change a shared
writable RAM mapping into a private mapping or construct immutable file backing.
The existing child mapping-table scan rejects writable shared VMAs that do not
match the closed authenticated disposition table. The RFC-0020 description of
rejecting or converting shared RAM is therefore not evidence that conversion
exists in the implementation.

Current admission is also conservative. The
[source resource measurement](../../../crates/crucible-api/src/vm_lifecycle/hot_fork/resource_usage.rs)
charges at least full guest RAM as template bytes and another full guest-RAM
allowance in expected private dirties. The
[managed pool](../../../crates/crucible-daemon/src/managed_qemu_hot_fork_source_world_pool/pool.rs)
reserves another source profile for a child lease. Paging does not increase
admitted concurrency until those policies change explicitly.

- **[FORK-1]** A paged hot-fork capability MUST be negotiated independently of
  ordinary stopped runstate. A matching build, capability profile, and protocol
  schema MUST be admitted before a paged source or child is accepted.
- **[FORK-2]** Guest RAM MUST remain private between independently writable
  executions. `MADV_DOFORK` MUST NOT be treated as proof of private-COW
  semantics. Unknown RAM mappings MUST fail admission; any mapping conversion
  requires an implemented, authenticated transaction and conformance evidence.

This RFC uses an immediate experimental cutover. Old template reports, roots,
and checkpoint schemas are rejected under the new capability. There is no
compatibility converter or old-digest fallback. The
[cutover contract](09-security-and-cutover.md) defines that rejection.

## 06.2 The source seal binds bytes, not residency

A retained source has an immutable logical RAM view. Its seal identifies the
ordered RAM topology, canonical 4096-byte logical pages, SHA-256 `PageDigest`
values, binary ordered `RegionTreeDigest` values, and the scoped
`RamRootDigest` defined by chapter 02. Page placement, host addresses, physical
page size, compression, and backing locations are outside that root.

The source seal also binds operational authority: process and template
generations, page-state ownership, tracking boundaries, fault-service context,
and the leases that make the bytes recoverable. These fields establish who may
serve or release the image. They are not inputs to its semantic digest.

Physical residency may change while a source remains sealed. A page can move
from a private resident frame to authenticated immutable backing, or back again,
without changing its logical contents. Sealing every physical address would
prevent the intended reclamation of cold templates. Conversely, knowing a page
digest without retaining a readable realization is insufficient to serve a
fault.

- **[FORK-3]** A source seal MUST bind one coherent RAM root and an owned readable
  realization of every logical page. A realization MAY be a retained resident
  page, an authenticated backing object, or the format's canonical zero
  representation. A digest alone MUST NOT constitute a realization lease.
- **[FORK-4]** A sealed source MUST admit no modeled RAM writes. Placement changes
  MAY continue only through operations that preserve the sealed bytes and
  readable leases. A residency change MUST NOT invalidate or regenerate the
  semantic source root.
- **[FORK-5]** Operational counters, including `page_version`, dirty epochs,
  policy revisions, fault-request generations, and backing-location
  generations, MUST remain outside page, region, RAM, and configuration
  digests. They MUST still be checked wherever they guard ownership or races.

A hot source need not eagerly serialize every resident page solely to obtain
its seal. Before a resident-only source page is evicted, however, current bytes
must have a committed readable backing realization. An independently retained
exact fallback has the stronger durable-closure requirements of
[chapter 07](07-checkpoints-and-storage.md).

## 06.3 Extended retained-template transaction

The existing subsystem barriers remain mandatory. The page-state extension adds
work to their transaction; it does not permit an external host process to infer
fork safety from a RAM root or paused status.

Preparation proceeds in the following dependency order:

1. Reach the authorized deterministic boundary and complete the guest/device
   write fence. Close admission of modeled RAM mutation and placement operations
   that cannot finish independently of the barriers about to be retained.
2. Drain in-flight page replacements and writebacks that affect the source
   image. Complete pending hash invalidations and publish a coherent root.
3. Bind the source image's leases and fault-service context. Establish the
   minimal service path that remains available during retained barriers.
4. Retain the block, plugin, RCU, asynchronous-worker, and runtime barriers in
   the existing supported-profile order. Verify that their inventories and the
   page-state basis still match the selected source generation.
5. Stage the complete child-private resource set, including pager endpoints,
   fault-registration disposition, mutable backing authority, and reserved
   fault-resolution resources. Authenticate descriptors and mapping roles.
6. Execute the coordinated fork and independently authenticate parent and child
   dispositions. Pair the completed child with its cloned host continuation.

- **[FORK-6]** Preparation MUST bind the page-state seal to the exact paused
  CPU/device and host-continuation boundary. A root from an earlier instruction
  boundary MUST NOT be accepted because the process is currently stopped.
- **[FORK-7]** Template readiness MUST include positive evidence that every page
  potentially accessed under retained barriers has a live independent fault
  path. An observational pager inventory or successful prior fault MUST NOT be
  promoted into that proof.
- **[FORK-8]** Descriptor, endpoint, mapping, backing, and page-state staging MUST
  be generation-bound and complete in both directions. New pager resources
  MUST appear in the closed resource plan; they MUST NOT survive through ambient
  descriptor inheritance.
- **[FORK-9]** A preparation failure before child creation MUST retain enough
  authority for exact rollback. If rollback cannot attest released barriers and
  terminated placement operations, the source MUST be quarantined.

The initial custom eviction path runs only at proven paused boundaries. Within
a retained template, eviction is permitted only while its source seal and
minimal service proof remain valid. Fault resolution can occur during execution
without allowing an unproved concurrent eviction algorithm. Ordinary
kernel-managed reclamation has its own memory-preservation contract and does
not establish correctness of custom discard operations.

- **[FORK-10]** Initial custom eviction MUST NOT race running CPU or device RAM
  accesses. Concurrent custom eviction requires a separately admitted capability
  proving write exclusion, page-version validation, dirty preservation, and
  interaction with every fork barrier.

## 06.4 Child service and rebinding

A child inherits ordinary process COW memory, not the parent's worker threads.
Before reconstruction, the child may already need RAM for device or plugin
state inspection. Waiting until its first guest instruction to establish the
pager is therefore too late.

Linux memory locks established with `mlock` are not inherited across `fork`.
An unchanged RAM root, inherited resident pages, or a parent's successful
`resident-required` transition therefore does not establish the child's
residency guarantee. Each child needs its own admitted reservation, prefault,
locking operation, and verification before guest execution is released. Child
promotion does not exempt subsequent descendants from this requirement.

A supported fault mechanism must define the fork handoff explicitly. An
inherited fault registration, a kernel fork notification, and a new userspace
worker are different things. Capability admission must demonstrate which
registration owns each child range and which service consumes its faults. If
the selected mechanism cannot serve faults during that handoff, reconstruction
must stay within a proven resident bootstrap set until service is available.

- **[FORK-11]** The child MUST have working page-fault service before its earliest
  reconstruction access to pageable RAM. The implementation MUST prove this
  ordering with cold-page tests; a readiness flag set after reconstruction is
  insufficient.
- **[FORK-12]** Each child MUST receive an independent writable page-state context,
  fault-request namespace, tracking state, mutable backing disposition, and
  runtime policy owner. Parent and child MAY share immutable page objects and
  immutable tree nodes under explicit leases.
- **[FORK-13]** Child rebinding MUST preserve logical RAM contents, topology, and
  the source root. A writable shared RAM VMA or mutable backing alias across
  independent children MUST fail readiness, even if its descriptor is otherwise
  valid.

Dirty state requires more care than assigning an empty bitmap. The child starts
unchanged relative to its fork root, but an older checkpoint or transfer
baseline may still differ from that root. Forking clones those relationships;
it does not erase them. Tracking for fingerprint invalidation, checkpoint
capture, transfer, and backing writeback remains independent as specified by
chapter 03.

- **[FORK-14]** Child tracking MUST preserve every inherited consumer baseline
  and allocate private subsequent mutation authority. Resetting the child's
  dirty epoch MUST NOT make it falsely clean relative to an older baseline.
  One child's acknowledgment MUST NOT clear another child's changes.

Persistent tree sharing is structural. A child may inherit a root and immutable
ancestor nodes; updates produce child-owned replacements. Operational
`page_version` values may be copied at the fork boundary, but their subsequent
interpretation is scoped to the new owner. Identity and version checks must
prevent a completion from the parent context from installing bytes into a child.

- **[FORK-15]** A child MUST execute no guest instruction or emit a canonical
  event until RAM isolation, fault service, backing leases, runtime
  reconstruction, resource disposition, and host-continuation pairing all
  commit. A partial multi-node child world MUST NOT be published.

## 06.5 Barrier dependencies and minimal service

Fault service remains an operational obligation while semantic writers are
quiescent. It must not need any worker or lock parked by the transaction. The
following wait-for table is normative for capability review.

| Waiting operation | Resources it may retain | Fault service MUST NOT require | Required evidence |
| --- | --- | --- | --- |
| Main-loop template preparation or fork | BQL or coordinator ownership; retained subsystem barriers | Dispatch through that main loop or a QMP reply from the blocked operation | Cold RAM access during preparation completes independently |
| Fingerprint or source sealing | RAM write fence; plugin or fingerprint coordination | The same parked fingerprint worker; guest execution; reopening write admission | Hashing a cold page completes under the selected fence |
| Retained block snapshot | Block graph/backend ownership and drained AIO admission | Ordinary QEMU block jobs, bottom halves, or drained backend workers | Pager backing I/O uses an independent proven path |
| RCU/runtime reconstruction | Retained RCU admission; thread/mutex registry ownership | Starting an unregistered parent worker or acquiring the held registry guard | Fault path remains live while registry is frozen |
| Child descriptor disposition | Closed descriptor/signal admission; incomplete child runtime | Opening an unplanned endpoint or using a descriptor about to be closed | Pager resources are staged and survive exact disposition |
| Child fault-registration handoff | Child bootstrap ownership; source leases | Child-ready acknowledgment; an event processed only after guest release | First cold reconstruction access completes |
| Cancellation or retirement | Lifecycle ownership; stopped guest | Guest progress; released backing lease; a worker already joined | Pending faults and writebacks reach terminal dispositions |

The implementation must construct a concrete dependency graph for its selected
fault mechanism. The table does not exempt QEMU-private calls from the licensing
boundary. Calls that resolve or inspect QEMU RAM belong on the GPL side; host
policy and storage communicate through versioned public protocols.

- **[FORK-16]** The fault-service wait-for graph MUST be acyclic for preparation,
  retained templates, fork, reconstruction, hashing, and retirement. Fault
  completion MUST NOT depend on acquiring a resource held by its waiting
  caller or on resuming modeled execution.
- **[FORK-17]** The minimal fault service MUST have admitted workers, bounded
  queues, and reserved buffers before a retained barrier is entered. Its
  allocations MUST NOT depend on successful reclaim of the page currently
  faulting. Host pressure MUST leave sufficient independently accounted
  capacity to resolve, reject, or cancel the admitted outstanding faults.
- **[FORK-18]** Retained minimal service MUST be limited to preserving and serving
  the sealed image and completing authenticated operational work. It MUST NOT
  emit guest events, advance virtual time, or mutate semantic RAM to make
  progress. Background policy convergence MAY be suspended while essential
  demand faults remain serviceable.

One helper outside the frozen QEMU runtime can simplify this proof, but helper
placement alone does not prove independence. Its storage I/O, locks, buffers,
and callback dependencies still require review. A retained in-process service
must additionally prove its thread and mutex disposition across the fork.

- **[FORK-19]** Every fork child admitted with `resident-required` policy MUST
  separately reserve the required resident capacity, prefault its required RAM
  ranges, establish child-owned memory locks, and verify the resulting
  residency and locking guarantee before guest release. Parent locks or parent
  verification MUST NOT substitute for these child operations. Bootstrap ranges
  needed before this verification MUST satisfy the independently proven
  reconstruction service contract. Failure of reservation, prefaulting,
  locking, or verification MUST reject child readiness and follow the existing
  rollback or quarantine path; it MUST NOT silently weaken the selected policy.

## 06.6 Cancellation, uncertain outcomes, and containment

Cancellation closes new execution and placement work, retains the root's
readable leases, stops guest mutation, and resolves the disposition of existing
faults and writebacks. A stopped QEMU thread blocked on a missing page cannot be
joined by waiting for the same thread to perform pager cleanup.

- **[LIFE-1]** Cancellation MUST prevent new unowned fault or writeback requests
  while retaining authority for admitted requests. Storage and mapping owners
  MUST remain alive until every request either completes for the exact owner
  generation or is terminally invalidated before it can install bytes.
- **[LIFE-2]** A timeout after child creation may have occurred MUST be treated as
  an uncertain operational outcome. The source MUST reconcile retained child
  status and page-resource authority before retry, release, or reuse. A reported
  PID MUST NOT become independent process authority.
- **[LIFE-3]** Quarantine MUST retain process, page-store, mapping, and resource
  reservations until cleanup is attested. Killing QEMU alone MUST NOT release a
  helper's outstanding I/O or backing leases. Failure to reap or drain MUST
  retain the affected reservation.

The existing coordinator's fixed ten-second child cgroup-placement wait is an
informative example of an internal deadline that must be audited alongside
host QMP and readiness timeouts. Fault latency can delay placement or later
reconstruction without representing guest failure. Chapter 05 governs separate
progress and completion budgets, cancellation escalation, and host-failure
classification. Extending a deadline does not resolve a dependency cycle.

- **[LIFE-4]** Process placement, fault-service handoff, child reconstruction,
  readiness, and cleanup MUST have distinct operational supervision. Paging
  stalls MUST NOT be classified as guest crashes or replayable guest timeouts.
  Unknown post-fork disposition MUST fail closed through reconciliation or
  quarantine.
- **[LIFE-5]** Parent-death containment MUST remain effective throughout child
  bootstrap and steady operation. Backing leases MUST NOT be mistaken for
  permission to continue a process whose required ancestor authority died.
  A separately supervised promotion or ownership transfer requires its own
  authenticated containment transition.

## 06.7 Descendant leases, promotion, and fallback

Page content ownership and process ancestry serve different purposes. Linux COW
keeps physical pages readable while a process mapping references them. Custom
paging additionally needs readable page objects after those frames disappear.
A parent-local filename, an inherited descriptor number, or a reachable Merkle
digest is not a sufficient descendant lease.

- **[LIFE-6]** Each admitted child MUST own leases for the immutable tree and
  backing realizations it can reference, including nonresident pages. A source
  MAY release its own lease only after independent child or durable-checkpoint
  leases are committed. Shared backing MUST remain readable until its last
  authorized reference and outstanding I/O are retired.
- **[LIFE-7]** Garbage collection and backing relocation MUST account for running
  children, retained templates, exact checkpoints, transfers, and quarantined
  requests. A root MUST NOT be collected merely because its originating source
  was demoted. Mutable child backing MUST never be inferred as immutable
  content-addressed storage.

Promotion freezes a child at a new exact boundary and begins a fresh template
transaction. The new template may share old immutable nodes while publishing
new nodes for changed pages. It also receives fresh template and process-bound
operational authority; inherited staging plans cannot be reused for descendants.

- **[LIFE-8]** Child promotion MUST revalidate the complete page-state, fault
  service, mapping, backing, and runtime inventories. It MUST publish the
  child's current coherent root and establish fresh descendant resources.
  Ancestor staging receipts MUST NOT substitute for the promoted source seal.
- **[LIFE-9]** Source demotion MUST authenticate the selected exact or thin
  fallback, retire the complete source authority, and attest page-service
  cleanup before releasing its accounting. A partial world demotion MUST retain
  surviving source authority and completed releases without installing a
  partially admitted replacement.

A thin fallback permits replay of a configuration; it does not authorize
discarding a live dirty page from a running child. A durable exact fallback must
retain the complete RAM object closure as well as CPU, device, disk, and host
continuation state. Fallback choice remains operational placement policy and
must not alter strict semantic proposal priority.

## 06.8 Runtime policy scopes and hot-source accounting

Runtime policy applies to an authenticated operational owner. Campaign defaults,
executor defaults, source-template policy, and child-instance policy are
different scopes. Changes to a parent must not accidentally rewrite children
through shared mutable policy objects.

- **[LIFE-10]** Child admission MUST record the effective policy revision selected
  at staging. Subsequent parent changes MUST NOT modify an existing child's
  policy unless an explicit update addresses that child. A policy change during
  staging MUST be linearized before admission or explicitly deferred; mixed
  resource and policy revisions MUST fail readiness.
- **[LIFE-11]** Requested policy, admitted reservation, and measured residency MUST
  be reported separately. A lowered target MUST NOT release accounting until
  its convergence or replacement reservation is attested. A raised reservation
  MUST be admitted before resources are consumed.
- **[LIFE-12]** Operational policy changes MUST preserve the source root and child
  baseline. Updates that replace backing ownership or fault-service
  registrations MUST pass the corresponding authenticated lifecycle transition,
  even when their semantic RAM contents remain identical.

Hot-source accounting includes physical resident guest frames, shared immutable
frames, private dirty capacity, readable backing capacity, Merkle metadata,
fault queues, reserved buffers, page-cache pressure, and non-pageable runtime
overhead. Logical RAM capacity remains a separate dimension. Measuring only
`VmRSS` can double-count shared frames, while charging only child-private dirties
can omit retained source charges and file-cache memory.

- **[LIFE-13]** Admission MUST preserve conservative ownership of every physical
  and backing resource while avoiding claims that disk-backed RAM is free.
  Shared resources MUST have an accountable owner and bounded aggregate charge.
  Resource movement between source and child owners MUST NOT create an
  uncharged interval.
- **[LIFE-14]** A resident target approaching zero MUST retain independently
  admitted execution and fault-service capacity. The host MUST reject a profile
  whose reserved working resources cannot resolve its own admitted demand
  faults. Immutable sharing MUST NOT permit unbounded metadata or descriptor
  growth across descendants.

## 06.9 Required lifecycle evidence

Qualification extends the existing hot-fork equivalence, isolation, scaling,
and world-atomicity gates. It uses unmodified supported guests and a forced
resident path as the comparison realization. Mandatory cases include a cold
source, the child's first cold reconstruction read, simultaneous sibling
faults, sibling writes to one shared logical page, repeated child promotion,
runtime target changes during staging and retention, source demotion with live
backing references, storage failure, and ambiguous cancellation after fork.

- **[LIFE-15]** Admission of the paged hot-fork capability MUST require evidence
  that resident and paged realizations produce identical canonical results and
  RAM roots, preserve sibling isolation, and terminate or quarantine failed
  lifecycle operations without losing backing authority. The validation MUST
  exercise actual QEMU RAM and retained barriers; scripted endpoint tests alone
  are insufficient.

[Chapter 10](10-validation-and-performance.md) specifies reproducible failure
injection and performance measurements. More parallel processes are a benefit
only when total campaign throughput improves within the admitted host and
storage budgets.
