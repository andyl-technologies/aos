# 14 - Common RAM contract and implementation profiles

## 14.1 Status, ownership, and admission

The common contract is canonical logical RAM, not a universal emulator runtime.
It retains chapter 02's 4096-byte pages, region ownership and aliases, unchanged
page/tree/scoped-root preimages, authenticated preservation, immutable sharing,
generation-bound operations, and owned leases. Paging contexts serve independent
mutable branches under execution and capture owners. A public node need not be
one execution owner, one capture owner, or one process.

QEMU-SIM remains the initial implementation target. The gem5 and KVM profiles
below are proposed requirements, not implemented or qualified capabilities.
The current implementation MUST reject requests for these profiles rather than
silently selecting QEMU-SIM, resident execution, or weaker capture semantics.
This chapter specifies no immediate gem5/KVM implementation.

The terminology follows proposed RFC-0025's pinned
[admission contract](https://github.com/andyl-technologies/aos/blob/9f5015bd5a1813b6c9383f64a81d763882f094c2/docs/rfcs/0025-crucible-node-contract/02-ports-capabilities-and-admission.md)
and [state contract](https://github.com/andyl-technologies/aos/blob/9f5015bd5a1813b6c9383f64a81d763882f094c2/docs/rfcs/0025-crucible-node-contract/05-state-and-replay.md).
Those documents are proposed designs reviewed at the linked revision; importing
vocabulary does not imply that their provider APIs already exist.

- **[PROFILE-1]** Admission MUST bind the actual implementation and build,
  resolved semantic configuration, execution/capture-owner graph, operating
  mode, capture fidelity and schema, and requested RAM capabilities before
  execution. Mapping types, fault origins, tracking mechanisms, safe removal
  boundaries, clock behavior, lazy restore, and branch creation MUST each be
  declared and independently qualified. Paging support MUST NOT imply
  deterministic execution, exact capture, durable restart, hot fork, concurrent
  eviction, or general low-peak execution.

CONF-1 through CONF-3 govern advertisement and release evidence. Unknown
combinations fail closed. A specified profile can exist before qualification;
only evidence for its actual build/configuration permits activation. Retained
paused-only/full-peak restrictions apply until separately discharged. Without a
proved smaller inter-boundary population bound, admission retains full guest RAM
plus independently reserved progress resources. A small target is a convergence
preference, not proof of a small guaranteed peak.

## 14.2 Requirement scope and unchanged guarantees

Existing requirement identifiers are preserved. This edition explicitly changes
the scope of INV-2 and PAGER-1 from an implicit QEMU deterministic context to the
named deterministic modes. Their original deterministic guarantee remains intact;
KVM gets a separate declared contract rather than an informal exception.
POLICY-1 and TRANSFER-2 allocate policy and destination timing to the declared
mode; TEST-1/TEST-2 allocate correctness and live evidence to the actual profile.
TEST-11/TEST-12, LIFE-15, and chapter 07's concluding equivalence criterion distinguish
deterministic equality from nondeterministic KVM conformance. No hash edition,
page preimage, coverage mask, resource limit, or deadline changes here.

CONF-1 now binds implementation/build/configuration and mode explicitly. FP-1
names the admitted coordinate and phase; FP-11 retains each profile's complete
CPU evidence, including the original QEMU register/RR evidence. PAGER-2 and
PAGER-4 use execution-owner mappings and implementation pointers without
changing their stable-address requirement. These are explicit allocations of
existing obligations, not a weaker observation or removal contract.

| Existing requirements | Common obligation and profile allocation |
| --- | --- |
| INV-1, INV-4 through INV-10; CONF-1 through CONF-3 | Transparency, authoritative bytes, coherent capture, failure separation, custody, containment, and bounded admission remain required for every profile. INV-8's QEMU-private/GPL allocation remains QEMU-specific. |
| INV-2, PAGER-1; TRACK-17 | Deterministic QEMU-SIM and qualified gem5 retain modeled-time/budget/event-order invariance and exactly-once resumption. KVM follows section 14.5's quantized clock/budget/publication contract; preservation never fabricates an additional guest access. |
| INV-3; RAM-1 through RAM-12 | Identical declared topology and contents yield identical RAM roots. Complete machine identity additionally binds the profile and state closure; this does not promise repeatable KVM execution. |
| TRACK and FP requirements | Complete writers, independent epochs, immutable views, coherent observations, and independent recomputation apply at each actual implementation boundary. |
| PAGER-4 through PAGER-11, PAGER-13 through PAGER-24 | Mapping lifetime, generations, integrity, fault progress, physical-access safety, capabilities, containment, and peak reservations require each profile's concrete proof. PAGER-12's QEMU mapping interpretation remains GPL-side. |
| FORK and LIFE requirements | Source seals, private mutation, paging contexts, leases, readiness, uncertain outcomes, and retirement apply to every claimed branch. RAMBlock/COW-process details, QEMU barriers, child repair, and designated-thread fork are QEMU-SIM mechanisms. |
| CHECK, STORE, SEC, and CUT requirements | Authentic capture bindings, full closure, storage publication, retention, compatibility refusal, and public boundary review remain required. QEMU-specific licenses and artifacts remain mandatory for QEMU-SIM. |

PROFILE requirements add the cross-implementation and mode declarations needed
to allocate those obligations. They do not replace a failed writer, kernel-fault,
physical-borrow, or progress proof with a weaker alternative.

## 14.3 Deterministic QEMU-SIM profile

The admitted QEMU TCG profile preserves its existing instruction-counted timing,
modeled memory-service behavior, event order, register/RR evidence, and exact
control boundaries. Host page preservation, fetch, reclaim, hashing, and fault
service MUST NOT consume modeled instruction or service budgets, dispatch guest
events, advance virtual time, or create simulated memory accesses. Population
resumes the original pending access or mutation exactly once.

RAMBlock inventory and aliases, migration dirty clients, translated-code
invalidation, BQL/QMP coordination, plugin workers, GPL-side mapping/fault
interpretation, retained block/RCU/AIO barriers, and process child repair belong
to this profile. Their concrete obligations remain in chapters 03, 04, 06, and
07. A stopped runstate or BQL alone is not an access-lifetime or coherence proof.
Device pre-save RAM effects keep CHECK-4's admitted ordering; no new modeled
execution is authorized to obtain a convenient capture.

QEMU-SIM paging qualification retains the existing zero CPU-time and wall-time
regression requirement against the original admitted baseline and workloads.
A generalized specification is not permission to change those baselines,
execution ceilings, pauses, resource caps, or failure classifications. The
[validation chapter](10-validation-and-performance.md) supplies the evidence;
this profile makes no measured performance claim.

## 14.4 Proposed deterministic gem5 profile

The profile binds the actual ISA/CPU model, memory hierarchy, coherence protocol,
controllers, devices, event-queue/thread arrangement, immutable inputs, and all
semantic parameters. A qualified model preserves deterministic event ordering
and budgets across resident, paged, captured, restored, and branched realizations.
A host population wait must retain the same pending modeled operation, request
identity, operands, partial progress, and ordering position until exactly-once
resumption. It must not resend an already accepted transaction or perform a new
functional access as a substitute for that transaction.

### Backing bytes and complete modeled state

A backing-region RAM root commits the declared backing bytes. A dirty modeled
cache can hold the newer architectural value while backing retains an older
value. Both can be valid parts of the reached state. Making backing current by
flushing the cache changes modeled execution and is not an exact capture.

- **[PROFILE-2]** Every future-affecting modeled state domain MUST have one
  explicit capture owner. Cache data/tags/dirty permissions/replacement state,
  coherence transients, pending requests and responses, controller queues,
  pipeline/speculation/retirement state, predictors, translations, devices,
  PRNG position, and complete event ordering MUST be captured when realized by
  the admitted model. Domains MAY be separate canonical state components or
  correctly classified inventoried RAM-backed regions. They MUST NOT be omitted
  as operational host allocations, double-owned, or joined through invented
  aliases between distinct bytes.
- **[PROFILE-3]** Exact capture MUST preserve the reached admitted continuation
  without modeled draining, cache writeback/invalidation, event advancement,
  instruction retirement, warm-up, or prefix re-execution. Host representation
  normalization requires proof of equal future modeled behavior. Unsupported
  boundaries or unpreservable modeled domains MUST refuse exact capture.
- **[PROFILE-4]** Fault preconditions, selected-byte evidence, and guest-visible
  assertions MUST name a coherent observation contract: target state domain,
  boundary, architectural/backing projection, and any admitted mutation rights.
  A backing read MUST NOT silently substitute for a newer cache-owned value.
  Observation MUST NOT change cache replacement, coherence, queues, event order,
  or modeled service counters. Unsupported coherent inspection MUST be refused.

Upstream [gem5 memory access interfaces](https://www.gem5.org/documentation/general_docs/memory_system/)
distinguish timing, atomic, and functional access. Choosing an interface by name
is not a proof that a particular model's inspection is coherent and observational.
Upstream checkpoint availability likewise does not qualify this exact profile.

### Writer and removal matrix

This matrix allocates TRACK-4 through TRACK-7, TRACK-17 through TRACK-19,
PAGER-10, PAGER-14, PAGER-15, and PAGER-23 through PAGER-24.

| Path | Required qualification |
| --- | --- |
| CPU/backing stores and cache/coherence transactions | Scalar/vector/atomic and cross-page effects, cache-owned values, writebacks, pending accepted operations, partial completion, and epoch rearm; backing and cache ownership remain distinct. |
| DMA and modeled devices/controllers | Every committed subrange, pending response, device-owned RAM, and ordering relationship with memory/coherence owners. |
| Functional/debug access, loaders, reset, restore, and faults | Coherent target/projection, mutation authorization, all dirty consumers, and explicit identity invalidation; cold pages do not skip these paths. |
| Removal and population | All retained native pointers, packet buffers, event callbacks, aliases, and kernel accesses are excluded or safely leased. Event dispatch being paused alone is insufficient. |
| Branch and reconstruction | Event/thread disposition, native graph references, independent mutable domains, page-source leases, and first cold reconstruction access; process COW is only candidate machinery. |

## 14.5 Proposed nondeterministic quantized KVM profile

This mode does not claim instruction-exact stopping, deterministic multi-vCPU
interleavings, or preservation of physical caches, predictors, pipelines, or
other unexposed hardware microstate. A frozen virtual clock does not make the
hardware execution trajectory deterministic. Capture fidelity names the exposed
architectural/device state actually preserved and explicitly identifies omitted
state; it must not claim exact detailed modeled continuation.

The baseline window policy follows proposed RFC-0025's pinned
[quantized contract](https://github.com/andyl-technologies/aos/blob/9f5015bd5a1813b6c9383f64a81d763882f094c2/docs/rfcs/0025-crucible-node-contract/04-quantized-and-physical-nodes.md).
A positive logical quantum and phase define fixed window boundaries. Complete
ordered inputs are staged and acknowledged before activation; outputs stay in
owned custody and become publishable no earlier than the window's end, after
acknowledged stopping and complete window closure. A host timer or request to
stop is not a stop receipt. Shared execution owners admit one active grant.

- **[PROFILE-5]** KVM admission MUST bind the enabled guest clock/counter and
  timer sources, logical quantum/phase, host execution-budget measure and clock
  source/measurement scope, suspension policy, stop mechanism/acknowledgment,
  qualified bounded stop overrun, and input/output publication policy. The declared
  baseline MUST hold affected vCPUs and devices during a host page fault, freeze
  their controlled guest clock progression and timer injection, and retain due
  timer/input custody until an admitted resume or window-close boundary. If an
  enabled clock, device, DMA source, or external input cannot obey that hold, the
  paged mode MUST be refused rather than partially frozen.

A resumed execution window preserves its original logical grant and start batch.
Fault completion does not activate a later quantum or admit newly arrived input
into the already active batch. Due timers retain their declared ordering and
become eligible only under the admitted resume/closure rule. Clock offsets,
rate changes, timer reconciliation, and counter behavior must be established for
all enabled sources, including clocks visible through polling, not only RTC.

- **[PROFILE-6]** The remaining host execution budget MUST retain the same
  admitted basis across population waits: active execution excludes an attested
  held interval, while an elapsed-wall budget continues to expire. Neither kind
  may be renewed or replenished by a fault. Host operational deadlines continue
  under chapter 05. Actual native work and timing MUST be reported separately
  from logical quantum duration; blocked service time MUST NOT be presented as
  additional modeled execution. A missed host operational deadline, lost fault
  service, corrupt backing, failure to obtain required stop/window closure,
  or uncertain cleanup MUST contain the operation under INV-6,
  retaining outputs and resources without publishing a guest failure or a valid
  window-close receipt.

Exhaustion of an admitted native execution slice invokes the profile's normal
stop and window-closure rules; it is not itself a paging failure. A valid closure
still requires acknowledged stopping, complete causal window closure, and the
original output-publication boundary. Failure to obtain that closure is an
operational containment case, not permission to fabricate a guest timeout.

The admitted budget measure must be enforceable while all relevant execution
owners are held. A strict wall-time request that cannot tolerate page-fault
latency must refuse paging or require separately reserved, prefaulted,
appropriately locked resident memory. Freezing clocks does not suspend the
original host deadline. No profile is permitted to promise arbitrary fault
latency or unchanged real interleavings.

### Writer and physical-access matrix

| Path | Required qualification under existing TRACK/PAGER obligations |
| --- | --- |
| Hardware CPU stores | Actual memslot dirty-log/ring mechanisms, all admitted vCPUs, atomics/cross-page writes, epoch harvest/rearm, overflow, and reconciliation at acknowledged coherence boundaries. |
| Userspace devices, DMA, debug/management, loaders, reset, restore, and faults | Independent coverage for every writer outside hardware CPU logging, including retained mappings and delayed completions. Hardware dirty logging alone is insufficient. |
| Coherent hashing and preservation | Actual writer exclusion or safe versioning across CPU, devices, DMA and host writers before a root or preserved version is selected. |
| Physical removal | Secondary translations, retained mappings, kernel pins, device accesses, and every physical reader/writer must be reconciled before removal. Stopped vCPUs alone do not authorize eviction. Unsupported passthrough or pinned-memory paths refuse admission. |
| Fault origins and service | Actual mapping/host granularity, userspace and kernel-originated faults, permission policy, negotiated features/ioctls, and independent service progress under held vCPU/device/owner locks. |
| Restoration and branching | Fresh VM/vCPU/device kernel objects, exposed state, clocks/timers, outstanding architectural I/O, independent mutable RAM and backing, and descriptor/worker retirement. Inherited descriptors or RAM COW do not prove a child. |

The [KVM API](https://docs.kernel.org/virt/kvm/api.html) supplies capability and
state interfaces with process/thread and descriptor-lifetime constraints.
Availability of those interfaces is not a reconstruction or paging proof.

## 14.6 Compatibility, provenance, and independent capabilities

- **[PROFILE-7]** A complete capture/restore binding MUST authenticate backend
  implementation/build, resolved semantic configuration, execution mode, state
  schema/fidelity, owner graph, and immutable reconstruction inputs. These
  belong to the enclosing machine/world artifact, not PageDigest or RamRootDigest.
  Equal RAM roots MUST NOT authorize cross-backend continuation. KVM-to-QEMU-SIM-
  to-gem5 testing MAY use common guest images in fresh admitted runs; continuation
  conversion requires a separate specified conversion and explicit lost guarantees.
- **[PROFILE-8]** A stateful scenario MUST retain nondeterministic provenance
  introduced by a coupled node, including effects already present in state,
  inputs, and queued outputs. Deterministic neighbors or equal RAM roots MUST
  NOT erase it. Only a separately qualified record/replay contract can establish
  its declared stronger guarantee; transcript replay does not automatically
  qualify counterfactual branches.

KVM capture also MUST preserve the coordinator continuation, not only kernel
objects: the admitted window phase (prepared, active, closing, or closed but
unpublished), original grant/owner generation, quantum grid, input/output custody,
held clock/timer state, remaining budget basis and value, and acknowledged closure
prefix. This follows the pinned quantized contract's CN-QUANT-31 and CN-QUANT-37.
A requested capture phase that cannot preserve those domains MUST be refused.
Stop overrun qualification under CN-QUANT-19 does not renew a grant or enlarge an
original host operation deadline.

Private RAM branching shares immutable pages and trees under leases while giving
each branch exclusive mutable state. It does not reconstruct CPU/device state,
workers, descriptors, or kernel objects. Persistent restore must work after the
original source has terminated; a live seed's hidden state cannot supply missing
closure. Each profile separately declares lazy restore, live branch creation,
and durable restart, refusing any requested dimension it cannot satisfy.

The common oracle, integrity, stale-completion, lease, progress, and bounded-
resource obligations remain mandatory. Deterministic gem5 evidence additionally
compares full modeled state and event traces with dirty caches and pending
transactions. KVM evidence checks coherent capture, all writers, page integrity,
branch isolation, kernel-fault progress, clock/timer suspension, and causal window
containment rather than repeated bit-identical nondeterministic execution.
[Chapter 10](10-validation-and-performance.md) owns acceptance evidence;
[chapter 11](11-implementation-plan.md) owns its implementation allocation.
