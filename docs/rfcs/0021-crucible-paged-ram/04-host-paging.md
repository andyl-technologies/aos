# 04 - Host paging and stable guest RAM mappings

This chapter specifies the host paging mechanism, its safety conditions, and
the qualification boundary between kernel reclaim and an explicit pager. The
logical RAM format is defined in
[Chapter 02](02-logical-ram-and-merkle-format.md); dirty tracking and coherent
fingerprints are defined in
[Chapter 03](03-write-tracking-and-fingerprints.md). Runtime policy changes and
supervision are defined together in
[Chapter 05](05-runtime-policy-and-supervision.md).

Requirements identified as `PAGER-N` are normative. References to current code
and upstream implementations describe evidence and constraints; they do not
establish that the proposed mechanism already exists.

## 04.1 Contract and backend decision

Guest RAM capacity and its logical contents are independent of host residency.
Every supported guest continues to execute without a changed kernel, guest
agent, balloon device, paging-aware driver, or cooperative workload. A host
page fault delays execution in wall time while preserving the virtual-time and
event-ordering contract. It is not a guest page fault, memory error, modeled
storage operation, or additional simulated memory latency.

- **[PAGER-1]** Paging MUST preserve the configured guest physical address
  space, every logical RAM byte, and the existing deterministic execution
  contract. Storage placement, fetch latency, reclaim decisions, and access
  sampling MUST NOT enter semantic fingerprints or guest-visible event order.
- **[PAGER-2]** The initial precise paging backend MUST retain ordinary,
  stable virtual mappings for QEMU RAM. It MUST NOT replace translated memory
  accesses with a separate file operation for every load or store.
- **[PAGER-3]** An executor MUST distinguish a qualified kernel-reclaim backend
  from an explicit pager. It MUST NOT advertise strict control of individual
  guest RAM residency from process-wide kernel limits alone.

The selected architecture is an explicit page store underneath stable,
private, forkable mappings, with fault-based population. Kernel swap is a useful
measurement baseline for approximate residency against which custom paging
must justify its complexity. It does not satisfy the precise control or
authenticated-preservation contract by itself.

- **[PAGER-22]** Kernel-managed swap MUST remain a measurement-only baseline
  unless its deployment profile independently satisfies INV-4, PAGER-8, and
  TEST-7's preserved-byte integrity and failure contract before access resumes.
  Swap availability, cgroup configuration, or Merkle verification at a later
  boundary MUST NOT count as that proof. An unqualified baseline MUST NOT be
  advertised as an admitted authenticated paging backend or used as a silent
  fallback. This edition does not introduce a weaker storage threat model.
  A custom backend MUST prevent unqualified kernel swapping of its guest arenas
  or independently qualify that additional preservation path; authenticating its
  own page store does not authenticate bytes returned through kernel swap.

The first explicit-pager stage validates preservation and population using
paused-boundary removal. That stage does not provide general low-peak execution
for arbitrary guests. Activation of the general precise low-peak backend is
blocked on the additional progress mechanism in Section 04.4; merely attaching
a fault descriptor and setting a small limit does not establish that capability.

| Backend | Preservation and sharing | Integration decision |
|---|---|---|
| Anonymous mappings with kernel swap | Kernel preserves modified bytes and fork copy-on-write | Measurement baseline; deployment additionally requires independent integrity qualification under PAGER-22 |
| Immutable file with private mappings | Clean pages reload from the file; writes become private | Useful immutable basis, but private dirty pages still require preservation |
| Writable shared file mapping | Modified bytes belong to the file | Reject direct inheritance across hot forks |
| Distinct reflink files with shared mappings | Filesystem shares extents between separate files | Candidate requiring a separate remapping and filesystem qualification |
| Private mappings with explicit fault service | Logical pages have independent backing and residency state | Required architecture for precise guest RAM policy |

`mmap` is the access surface, not the entire pager. `MAP_PRIVATE` modifications
do not update their file; `MAP_SHARED` modifications can become visible through
other mappings of that file. See the [Linux mmap manual](https://man7.org/linux/man-pages/man2/mmap.2.html).
A file backend therefore needs explicit treatment of modified contents and
fork isolation. QEMU exposes memory-backend objects, but selecting one is not
proof of Crucible capability. See
[QEMU memory-backend invocation options](https://www.qemu.org/docs/master/system/invocation.html).

Filesystem reflinks share storage extents, not writable VM address spaces.
Their use requires distinct writable files, preservation of the source basis,
and correct rebinding before child execution. They are not mandatory for this
architecture. See the
[Linux reflink interface](https://man7.org/linux/man-pages/man2/ioctl_ficlone.2.html).

This RFC adopts the coordinated cutover in
[Chapter 09](09-security-and-cutover.md). The backend comparison does not
authorize old-format fingerprints, compatibility modes, or converters.

## 04.2 Mapping identity and page ownership

The logical paging unit is the fixed 4096-byte page from Chapter 02, including
the declared valid length of a region's final page. Host page size, transparent
huge pages, and storage extent size are implementation properties. A backend
may service several logical pages in one host fault or I/O, but it must retain
their individual logical identities and mutation ownership.

A GPL-side mapping registry relates a logical page to its process-local RAM
address. Its authoritative key includes node incarnation, RAM-block identity,
topology generation, and logical page index. Host-facing storage requests use
checked identities and offsets. The registry must describe aliases and RAM
blocks that do not belong to the main `-m` allocation; placing the main block
alone under a pager is not coverage of all logical RAM.

- **[PAGER-4]** Eviction and population MUST preserve each live RAM mapping's
  virtual address and declared extent. Cached QEMU pointers remain valid
  addresses; they MUST NOT become references into a replacement allocation.
- **[PAGER-5]** Every page operation MUST bind the node incarnation, topology
  generation, page index, applicable `page_version`, and unique operation
  generation. A completion for a replaced topology or incarnation MUST NOT
  modify the new mapping.

`PageDigest`, ordered `RegionTreeDigest`, and scoped `RamRootDigest` retain the
exact definitions in Chapter 02. Mutable page versions and topology generations
belong to operation identity, not content hashes. The storage `ContentId` is
separate from logical identity. Equal bytes at distinct logical positions may
share storage without conflating their tree positions or ownership.

The runtime registry also retains state, backing location and preservation
status, residency charge, dirty obligations, and current waiter ownership.
Its implementation may partition state across QEMU and its companion, but
there must be one unambiguous authority for each transition. Replicated
observations are not independent permission to remove a page.

## 04.3 Page state machine

The state names below specify observable safety properties rather than an
in-memory enum layout. Preservation means that the complete current page can
be recovered under the retained live-operation authority. It does not imply a
durable checkpoint or a published content-addressed object.

| State | Resident bytes | Recoverable current backing | Permitted semantic access |
|---|---|---|---|
| `AbsentPreserved` | None | Complete, retained | Fault and fetch |
| `FetchPending` | Not yet published | Complete, retained | Wait |
| `ResidentPreserved` | Complete | Same current contents | Read; write invalidates preservation basis |
| `ResidentModified` | Complete | Current contents may lack backing | Read and write |
| `PreservePending` | Complete and frozen for this operation | New backing is provisional | Read only if the operation's exclusion proof allows it |
| `RemovePending` | Complete or already removed under exclusion | Complete current backing | Wait or proved read access |
| `FailedHeld` | Variable | Variable | No guest execution |

An explicit zero-page backing is a recoverable content value. Missing backing
is not a zero-page value. A backed page need not have a current cached digest
until Chapter 03's hash obligation is discharged; conversely, a cached digest
does not establish recoverability of the bytes.

- **[PAGER-6]** A page MUST NOT become `AbsentPreserved` until its complete
  current contents are preserved and the mapping's future access is covered
  by functioning fault authority. No hole, partial write, or previous version
  may stand in for the removed bytes.
- **[PAGER-7]** Logical writes MUST invalidate all applicable preservation and
  hash obligations through Chapter 03's write protocol. Moving identical bytes
  between RAM and storage MUST NOT create a logical write or change the RAM
  root.

The normal removal sequence is:

1. Acquire the qualified quiesced boundary and a page-operation claim.
2. Validate current incarnation, topology, version, and fault registration.
3. Reuse existing current backing, or copy the frozen page into a reserved
   buffer and enter `PreservePending`.
4. Finish the backing write and validate its complete length and ownership.
   Publish the preserved basis only for the claimed page version.
5. Enter `RemovePending`, release physical storage through the qualified
   mapping primitive, and confirm the resulting state.
6. Publish `AbsentPreserved`, release the claim, and wake affected waiters.

The page remains recoverable across every step. A failed backing write leaves
the resident page authoritative. A failure after physical removal leaves its
preserved backing authoritative. A completion cannot move an operation backward
to a state whose ownership was already released.

The normal population sequence claims `AbsentPreserved`, enters
`FetchPending`, reserves staging and destination memory, reads and validates the
declared backing, and installs complete bytes through the qualified fault
interface. Only then does it publish `ResidentPreserved` and permit access.
Concurrent faults on the same page join the operation. Multi-page faults and
partial progress retain exact per-page completion accounting.

- **[PAGER-8]** Population MUST authenticate backing bytes against the applicable
  retained integrity basis before waking a faulting RAM user. Missing,
  truncated, corrupt, or wrong-version backing MUST cause a host-side failure;
  the pager MUST NOT substitute zeros, poison a guest page, or expose a partial
  page.

## 04.4 Initial eviction boundary and concurrency qualification

The initial explicit pager removes pages only at existing authenticated paused
boundaries that exclude every semantic RAM writer and RAM topology mutation.
Stopping a vCPU alone does not establish that boundary. Device activity, DMA,
fault application, debugger operations, restore, reset, and host observation
must follow the chapter's ownership protocol as appropriate.

- **[PAGER-9]** Initial eviction MUST be bounded and occur under a proved RAM
  quiescence scope. The scope MUST bind the node and operation generations and
  exclude all semantic writers until current bytes are preserved and removal
  completes. Admission using paused-only removal MUST
  reserve a sound worst-case population bound until the next reachable eviction
  boundary; absent such a bound, that reservation MUST cover full guest RAM plus
  required host progress resources. A smaller unsupported peak MUST be refused
  before execution admission or policy application; fail-on-capacity admission
  is not an alternative guarantee in this edition. Unexpected resource loss
  after sound admission MUST still fail as a typed host resource failure before
  exhausting the independent progress reserve.
- **[PAGER-10]** Concurrent removal MUST remain disabled until separately
  qualified. Qualification MUST prove exclusion of writes during preservation,
  exclusion of stale accesses during removal, and correct handling of readers,
  aliases, blocked faults, and canceled operations.
- **[PAGER-23]** Paused-boundary removal MUST additionally establish physical
  access-lifetime safety for retained DMA mappings, raw-pointer borrowers,
  kernel pins, aliases, and observation readers. Every such user MUST be
  drained, held under proved exclusion, or covered by the qualified fault path
  without retaining stale physical contents. Exact semantic pause, RCU object
  lifetime, or write protection alone MUST NOT authorize removal. This proof
  MUST hold with guest fault injection disabled as well as enabled.

Write protection is useful for tracking mutations; it is not alone a complete
reader-exclusion mechanism. A reader can race mapping removal, and a writer
already executing can race an attempted protection change. The proof must
cover the selected kernel primitives and all QEMU access paths. It must not
depend on the accidental absence of a second CPU or device thread.

Demand population can operate while a guest runs because a missing-page access
is held until bytes are installed. Its progress path must remain independent
of the faulting RAM user's locks and execution thread. Initially, access to
pages selected for removal is covered by the paused boundary, not by a new
guest-visible event.

That mechanism has a specific liveness limit. A guest can touch more pages in
one execution interval than the requested resident target allows. Once its next
fault is blocked for lack of capacity, it may be unable to finish the quantum
and reach the only qualified eviction boundary. Waiting for that boundary while
holding the fault is cyclic. Small staging buffers and extra fault workers do
not resolve the cycle because completed population retains the page until
removal is allowed. Host RAM users between boundaries also belong in the bound.

Paused-only removal can therefore implement a soft target with partial
convergence at pauses while admitting sufficient peak capacity for the entire
interval. It cannot guarantee both a generally small peak and continued
execution for arbitrary unmodified guests. Policy updates remain available,
but a low target is a convergence preference in this stage, not a strict peak
guarantee. A stricter unsupported request must be rejected under Chapter 05's
capability and admission rules. Refusing an unsupported peak does not prohibit
lowering the soft target while preserving the admitted peak reservation.

General low-peak execution requires a later, separately implemented and
qualified mechanism: either fault-safe resource suspension with reclaim that
is reachable while the fault remains blocked, or concurrent removal with the
complete access-lifetime proof in PAGER-10. Resource suspension is not an
already existing exact execution boundary. It must preserve virtual time,
semantic event order, partially executing operation state, and write ownership
without requiring the blocked access to complete first. Its reclaim path must
remain live despite QEMU locks, device activity, and retained barriers. The
implementation and validation plan must treat this mechanism as a prerequisite
for general precise low-residency execution, rather than optional optimization.

- **[PAGER-24]** General low-peak qualification MUST identify the process,
  thread, kernel primitive, and retained authority that can discard a victim
  while the faulting QEMU thread is blocked. Independent fetch service alone
  MUST NOT satisfy this obligation. A local discard worker MUST have an
  explicit thread/mutex disposition and child reconstruction contract. Resource
  suspension MUST NOT introduce additional interrupt checks, vCPU rotation,
  virtual-timer dispatch, modeled idle advancement, or semantic pause
  publication. Exit-and-resume MUST be equivalent to uninterrupted execution;
  retaining icount alone MUST NOT count as that proof.

The current exact pause can revoke a quantum's unused tail and publish semantic
control state; it cannot be reused wholesale as an operational hold. Pending
timers, bottom halves, and coroutines must remain ordered rather than being
dispatched to obtain a hold. Selected retained AIO/RCU admission machinery may
be reused only with a separate physical-borrow and dependency proof.

The GPL companion's fault descriptor does not itself provide remote discard
authority. `process_madvise` does not offer remote `MADV_DONTNEED`, and
`UFFDIO_MOVE` has pinned-page and fork-COW sharing restrictions; see
[process_madvise](https://man7.org/linux/man-pages/man2/process_madvise.2.html)
and [UFFDIO_MOVE](https://man7.org/linux/man-pages/man2/UFFDIO_MOVE.2const.html).
Qualification must establish the selected primitive on the actual mapping,
including shared source pages and kernel pins. A hold requested before capacity
depletion must retain enough capacity to reach its proven safe point; a fault
already blocking that point requires independent population or safe failure.

Qualified logical reset may replace a volatile region with authenticated zero
backing and a new operation basis without loading old pages. It must preserve
reset's semantic write and translation invalidation obligations. Restore must
similarly install the authenticated target page map rather than reinterpreting
unrestored holes as zeros. See
[Chapter 06](06-hot-fork-and-lifecycle.md).

## 04.5 Access sampling is independent of dirty tracking

A write says that content may differ; it does not say whether a page is cold.
Read-mostly executable pages may be hot while never dirty. A recently modified
page may be cold and safe to preserve. Dirty epochs belong to correctness;
access sampling belongs to host placement policy.

- **[PAGER-11]** Eviction heuristics MUST NOT use a clean bit as proof of
  inactivity, or an access sample as proof of unchanged content. Sampling
  errors MAY reduce performance but MUST NOT lose writes or alter execution.

The first policy may use coarse recency, demand-fault frequency, and bounded
sampling at paused boundaries. Working-set sampling must avoid attributing
fingerprint or checkpoint scans to guest demand where possible. Sampling
overhead and scan-induced page faults require separate metrics. Selecting an
eviction victim does not grant removal authority; the state machine still
applies.

Advanced userfaultfd read/write protection and asynchronous tracking modes are
optional capabilities. Their presence in current upstream documentation is not
evidence that a deployed kernel or architecture supports them. The backend
must negotiate actual features. It must provide a qualified policy using the
selected baseline capabilities, or reject the requested capability.

## 04.6 Fault-service placement and licensing

The initial custom-pager candidate is a supervised GPL-side companion process.
QEMU owns mapping registration and logical mutation authority. The companion
services fault descriptors, reads retained page backing, and installs pages;
QEMU performs initial boundary eviction and exports frozen pages through
bounded staging. This split avoids making fault service depend on a QEMU worker
that disappears at `fork` or is parked by a retained barrier.

The companion's process-local fault addresses and mapping knowledge remain on
the GPL side. Apache host services receive only versioned public requests with
stable identifiers, checked offsets, bounded page payloads, storage identities,
and generations. A companion is not a license exemption for adding QEMU
headers, implementation objects, or callback entry points to permissive crates.

- **[PAGER-12]** Mapping interpretation, fault-address resolution, and QEMU
  mutation coordination MUST remain GPL-side. The Apache/GPL boundary MUST
  continue to use the versioned Unix-socket control and shared-memory data
  protocols. Raw process pointers MUST NOT enter those public protocols.
- **[PAGER-13]** The selected placement MUST pass a dependency proof for every
  retained barrier and lifecycle phase before explicit paging is admitted.
  No operation that may access paged RAM may depend on its own parked fault
  service, the faulting thread, or a lock held by that thread.

The companion is a concrete architectural candidate, not an established fork
capability. Qualification must establish its descriptor retention, restricted
authority, startup authentication, child endpoint binding, control cancellation,
and crash containment. It must also show that its storage service continues
while QEMU RCU, async workers, plugin workers, and block admission are held.
Storage operations must not route through a block worker barred by the same
transaction.

Failure of this proof blocks custom-pager deployment; it does not justify
quietly moving QEMU-private objects into the Apache host. Any alternate
in-process placement requires an equivalent dependency proof and child
reconstruction contract.

## 04.7 Kernel access and capability preflight

RAM reaches more than translated loads and stores. Current fingerprint
materialization writes RAM directly into a file descriptor; restore reads
directly into RAM. Kernel-side copies can therefore fault on a paged mapping.
The upstream userfaultfd interface distinguishes kernel-originated faults from
userspace-only handling. See the
[userfaultfd manual](https://man7.org/linux/man-pages/man2/userfaultfd.2.html).

- **[PAGER-14]** Preflight MUST prove support for every fault origin reachable
  under the selected profile. Userspace-only fault handling MUST NOT be used
  while kernel-originated access to missing registered pages remains possible.

An implementation may obtain authorized kernel-fault handling or eliminate
such access by staging through resident buffers. The latter requires auditing
all direct syscalls and RAM mappings; fixing fingerprint writes alone is
insufficient. In either case, capability discovery must precede guest execution
and must not grant unrelated host privileges merely for convenience.

Preflight checks the host page geometry, chosen mapping type, registration
modes, population and protection operations, fork events, remove/unmap events,
descriptor-transfer authority, storage reservations, and required kernel
configuration. It also validates the ability to retain fault registrations
through the proposed lifecycle. Huge-page configurations require their own
qualification because fault granularity, reclaim behavior, and memory
reservation differ.

- **[PAGER-15]** Every required kernel operation MUST be checked against the
  negotiated feature and ioctl sets for the actual mapping. Unsupported
  combinations MUST reject the requested backend before execution. No silent
  fallback may weaken its advertised guarantees.

The Linux kernel documents fault-descriptor transfer, fork notifications, and
mapping-specific feature negotiation. Those facilities provide building blocks
for the proof, not proof of complete Crucible integration. See
[kernel userfaultfd documentation](https://docs.kernel.org/admin-guide/mm/userfaultfd.html).

The initial anonymous-mapping candidate negotiates missing-page handling and,
where selected by the write-tracking design, write protection. Population uses
`UFFDIO_COPY` from reserved resident staging, or `UFFDIO_ZEROPAGE` only for an
explicit authenticated zero backing. The destination range is checked against
the GPL-side mapping registry before the operation; installation preserves any
required write protection before access is released. Physical population of
existing logical contents does not discharge a pending semantic dirty epoch.

Removal notifications require an operation-aware interpretation. An event
caused by eviction must retain the preserved contents; an event caused by a
semantic discard or reset must follow that operation's new logical value.
The companion must not interpret every missing range as zero merely because a
kernel removal event has occurred. Remap and unmap events revoke the affected
mapping-generation authority and reconcile pending faults before a new range
can be admitted.

## 04.8 Fork and retained-template obligations

Present private pages inherit kernel copy-on-write isolation. Absent pages
inherit their logical backing map and must populate independently in each
process. Both cases share immutable content and Merkle nodes; neither permits
sharing a writable logical page between branches.

- **[PAGER-16]** A child MUST receive a bound paging context, preserved page-map
  basis, and retained fault authority before any child RAM access outside the
  proved initialization scope. Readiness MUST authenticate these resources
  with the existing fork generation and child ownership transaction.

Fork notification can create a separate child fault context. Its delivery and
descriptor lifetime must be integrated with the existing closed descriptor
table, companion registration, and child adoption protocol. Parent and child
must not accidentally consume each other's page completions. Template eviction
must not invalidate immutable backing retained by previously created children.

Boundary code itself can read cold RAM, including when preparing device state
or evidence. Consequently, the proof must cover faults before child readiness
and while the parent remains a retained template. Disabling guest execution
does not eliminate these host accesses.

Kernel cgroup accounting and policy accounting remain distinct. Inherited
pages can retain a template's kernel charge while becoming accessible to
children. Host admission must account for shared physical pages and growing
private pages at the attempt aggregate and node scopes defined in Chapter 05;
it must not derive exclusive child residency from cgroup membership alone.
See [Linux cgroup memory ownership](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## 04.9 Authority loss, cancellation, and failure

Fault registration is safety authority. Losing its last reference can permit
default kernel handling of a missing page, which is unacceptable for logical
RAM with preserved nonzero contents. Service availability and registration
lifetime must therefore have different owners.

- **[PAGER-17]** Each admitted node MUST retain fault authority independently
  of the companion's liveness. The final registration reference MUST NOT be
  released while a live mapping contains removed logical pages. Companion
  failure MUST hold or stop the node before any default handling can expose
  replacement bytes.

For a fork child, registration retention must be proved during the interval
between fork notification and child adoption, including companion death.
Holding the child's guest gate is necessary but does not prove safety of host
initialization code. Failure to establish retention means the child is never
admitted and is terminated under retained ownership.

Cancellation requests stop new claims and identify outstanding generations.
They do not revoke backing still needed by a live page. A pending fetch may
finish into held state or be abandoned before installation. Once installation
occurs, cleanup must acknowledge that fact rather than reporting that nothing
happened. A pending preservation may be canceled while the resident page
remains authoritative. A removed page retains its recoverable basis through
termination or verified repopulation.

- **[PAGER-18]** Cancellation and retry MUST have explicit ownership of every
  in-flight buffer, backing write, install, removal, and waiter. Stale
  completions MUST NOT publish new page state. Ambiguous completion MUST
  quarantine the affected node or transaction until reconciled.
- **[PAGER-19]** Paging failures MUST use Chapter 05's host operational failure
  and supervision model. They MUST NOT become guest memory faults, guest
  crash findings, or changes to deterministic virtual-time limits.

An eviction request that fails before removing any bytes may leave the node
safely resident and report failed convergence. Unavailable backing for an
already absent page cannot be handled that way: the node remains held and its
attempt ownership is reconciled. Timeouts do not prove that a late storage
operation cannot complete. Cleanup retains the required resources until the
operation is acknowledged or the consuming process is stopped.

## 04.10 Reservations, working set, and storage preservation

Fault progress requires resident resources outside the evictable guest pool:
companion code and stacks, operation metadata, descriptors, bounded read/write
buffers, fault queues, and enough destination capacity for admitted concurrent
population. QEMU's execution and control paths also need a minimum operational
working set. A memory policy must reserve these costs before admitting a VM.

- **[PAGER-20]** The pager MUST have bounded, reserved progress capacity that
  cannot be reclaimed by its own guest eviction policy. If remaining capacity
  cannot satisfy a fault without violating a strict resource contract, the
  node MUST use a qualified independently progressing reclaim or admission
  path, or enter a typed host resource failure before exhausting its emergency
  reserve. It MUST NOT wait for an eviction boundary that depends on completing
  the same blocked fault. Any temporary hold MUST retain an independent bounded
  resolution and failure path under Chapter 05's supervision model.

A residency target of zero may describe an idle, paused VM whose pages have
all been preserved and removed. It cannot promise zero physical RAM during
execution. Strict enforcement, convergence targets, temporary headroom, and
the distinction between per-node and aggregate limits are defined in Chapter
05. Emergency population must not be mislabeled as successful convergence.

Emergency capacity reserves the ability to preserve ownership, report failure,
and stop the consuming process. It is not an unbounded extension of the guest
residency allowance. Dynamic policy changes cannot retroactively establish an
unproved between-boundary footprint bound, nor may they convert an admitted
soft target into a strict cap that creates the fault/eviction cycle. A denied
update leaves the last effective policy in force; accepted partial convergence
must report its current state explicitly.

Storage reservations cover complete preservation obligations, provisional
writes, shared immutable bases, and cleanup retention. They must not assume
every page compresses, every file is sparse, or deduplication always succeeds.
Backing-store exhaustion must fail before removing the last authoritative
resident copy. Page-cache and buffered-I/O memory remain host resource costs;
moving bytes to a file does not prove their physical memory has been reclaimed.

- **[PAGER-21]** Live preservation MUST retain recoverable bytes for the node's
  lifetime. Durable publication MUST additionally satisfy Chapter 07's object
  validation, commit, retention, and recovery contract. A completed live write
  MUST NOT be represented as a durable checkpoint acknowledgement.

Kernel reclaim is separately qualified for its actual guarantees. It may use
runtime memory pressure and proactive reclaim, but its results remain
best-effort. `MADV_PAGEOUT` preserves anonymous contents through swap or writes
dirty file-backed pages; destructive discard is not anonymous swap. See the
[Linux madvise manual](https://man7.org/linux/man-pages/man2/madvise.2.html).

## 04.11 Qualification evidence and baseline integration

The current launch supplies `-m` without an explicit backend, the cgroup guard
sets `memory.swap.max` to zero, and launch admission reserves the guest-RAM
baseline as resident memory. The QEMU patch makes RAM forkable using
`MADV_DOFORK`. These are integration points, not implementations of this chapter.
See [Chapter 01](01-current-system-and-integration.md) for the evidence map.

Initial qualification must compare fully resident and paged runs, exercise
cold-page forks and child divergence, and change runtime targets during CPU,
device, fingerprint, checkpoint, and lifecycle operations. It must deliberately
fault while retained barriers are held, destroy the companion, interrupt
storage, exhaust preservation capacity, and cancel operations before and after
installation or removal. Every test must check logical content, ownership,
failure attribution, and resource convergence independently.

The liveness test MUST include an unmodified supported guest that faults in
more pages than its low target within one quantum, before the next exact paused
boundary. Qualification must demonstrate either completion within the admitted
worst-case peak, a typed host resource failure using the emergency reserve, or
the separately qualified suspension/reclaim or concurrent-removal path. A fault
left waiting for the boundary it prevents is a blocking correctness failure.
Dynamic reduction of a target or peak during that interval must exercise the
same test rather than relying on a configuration applied only at launch.

For the initial paused-only backend, the admission-negative variant must refuse
the unsupported small peak before launch or a live update. The operational
failure variant tests unexpected resource loss after valid admission; it must
not be used to qualify deliberately undersized admission.

Acceptance also requires bounded scan behavior: a Merkle fingerprint must not
rehydrate unchanged absent pages, and direct state export must use bounded
buffers rather than materializing an additional full RAM image. Demand faults,
observation reads, preservation traffic, page cache, kernel charges, and
companion overhead require separate measurements. Campaign throughput under
storage contention, rather than the count of simultaneously launched guests,
determines whether paging improves capacity.

The complete validation matrix and performance criteria are in
[Chapter 10](10-validation-and-performance.md). Failure of precise-pager
qualification leaves that capability unavailable; it does not relax guest
transparency or authorize an undeclared weaker backend.
