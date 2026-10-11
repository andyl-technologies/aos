# Phased implementation plan

This plan is nonnormative. [RFC-0025](../../rfcs/0025-crucible-node-contract/README.md)
defines the target contract. Task completion requires reviewable implementation
and evidence, not this checklist's existence. No tasks are reported complete by
the documentation change.

## 1. Dependency order and acceptance policy

```text
P0: audit and freeze reference artifacts
  -> P1: behavior-preserving facades and semantic extraction
  -> P2: versioned descriptions, graph, and state identity
  -> P3: owner-qualified exact scheduling and host-model nodes
       -> P5: device parity and mixed exact worlds (also requires P4)
       -> P6: quantized worlds and KVM
       -> P7: external profiles and vendor qualification
              (requires the relevant P3/P6 mode implementation)

G0: gem5 full-state feasibility starts alongside P1
  -> P4: gem5 exact owner, durable capture, and branching
  -> P5
```

Parallel work does not bypass prerequisites. In particular, G0 can investigate
gem5 state without changing admitted production profiles; P5 cannot advertise
exact gem5 support until P4's complete-state gates pass. P6 can prototype KVM
clock containment earlier, but cannot launch mixed production worlds before
node-qualified admission and boundary rules exist.

Every phase has a feature/profile boundary and a rollback path. A rollback does
not reinterpret newly emitted state as an older schema. Preserve old readers
or refuse the newer state explicitly. New features remain opt-in until their
full qualified profile passes; the existing exact QEMU path remains available.

## 2. P0 — Audit and reproducible reference

Prerequisite: accepted RFC direction and an isolated implementation branch.

**T-CN-01: Freeze source, identity, and performance references.** Inventory all
current scenario/schema/hash versions; owner and queue state; dispatch and
inventory authority; source symbols; deterministic gate routes; and production
QEMU/plugin artifact pairing. Retain reference canonical bytes and exact
execution witnesses for boot, block, 9p, network, clocks, faults, and restore.
Record the complete current crate dependency graph and runtime thread ownership.

Deliverables: reviewed audit delta from [current-state.md](current-state.md),
compact machine-readable compatibility inventory, frozen local artifact
identities, and a repeatable reference runner invocation.

Exit: reviewers can identify the owner and format of every preserved field and
reproduce the reference without an undocumented host tool. Sim versus ordinary
TCG mode comparisons use the same QEMU binary and matched clock contracts.
Implementation improvements compare separately identified parent and candidate
builds under matched workloads and semantic contracts; changing the binary is
the measured intervention, not an unreported mode-comparison confounder.

Gates: documentation link/requirement consistency; existing exact QEMU witness
qualification; selected existing scheduler and campaign tests in
[qualification-plan.md](qualification-plan.md). Performance runs are local and
unprofiled; profiling is a separate diagnostic run.

Risk: stale evidence or an artifact described as `origin/master` after local
prerequisite patches. Rollback: revise the reference and its labels before any
functional change; retain every failed attempt.

## 3. P1 — Behavior-preserving extraction

Prerequisite: T-CN-01.

**T-CN-02: Clarify source role names.** Introduce compute-specific names and
rename the host scheduling wrapper where useful. Keep universal IDs and actual
QEMU mechanisms. Preserve old bytes, domains, fault registrations, order, and
schema tags. Add temporary source aliases only when needed.

**T-CN-03: Add descriptors, facades, and owner routes.** Describe existing
compute and host-device nodes without changing their queues or execution.
Split collection dispatch from common logical participation. Wrap deterministic
I/O using its existing lifecycle; retain one authoritative native owner.

**T-CN-04: Extract shared campaign semantics.** Move materialization-neutral
frontier, choice, observation, and quantum logic behind a neutral lifecycle.
Retain QEMU marker evidence and fresh/restore/fork permissions in typed adapters.

**T-CN-05: Extract common lifecycle and debugger orchestration.** Separate world
bookkeeping from QEMU launch, VMState, fault execution, leases, and gdbstub
handling. Record public API field renames for later schema work instead of
changing requests accidentally.

Deliverables: independent source-refactor commits, descriptor tables for existing
participants, runtime routing diagram, and adapter custody review.

Exit: old canonical encodings and ordered exact traces match the reference.
Existing scenario authoring and execution still choose the same QEMU/device
paths. No new hot callbacks, synchronization, or per-instruction facet lookup.

Gates: exact execution and restore regression set, campaign core/replay tests,
crate-layer checks, application test-target compilation for Rust edits, and
head-to-head boot/device performance comparison against the parent commit.
ABI/license gates apply if an extraction crosses a process boundary; avoid such
changes in this phase.

Risk: a renamed semantic method accidentally gets native release authority;
trait-object dispatch enters hot loops; a changed Rust enum order changes
serialization. Rollback: revert the source extraction independently. Golden
formats make an unexpected behavior change a failed exit, not an accepted
migration.

## 4. P2 — Versioned admission and persisted graph bindings

Prerequisites: T-CN-03 and T-CN-05. T-CN-06 precedes new codec placement.

**T-CN-06: Define bounded capability and provider descriptions.** Implement
orthogonal role, operating mode, time resolution, pause, capture, branch, replay,
and fault support. Separate provider potential support from qualified realized
capabilities. Decide lower-layer type placement after the dependency audit;
do not introduce a reverse device/runtime dependency.

**T-CN-07: Bind every owner and introduce observed-attempt identity.** Add new
canonical implementation/configuration/profile rosters, world binding, and
capture closure version. Separate planned configuration identity from
nondeterministic observed attempts. Introduce a new executor capability schema
without erasing the old strict `ThinReplay` correctness rule. Gate deterministic
caches, minimization, and equivalence on admitted guarantees.

**T-CN-08: Implement typed ports and ownership graph.** Define protocol schemas,
directions, timing/buffering policies, directed causal dependencies, attachment
relations, execution owners, and state owners. Validate unique ownership,
compatible ports, finite resource bounds, composite closure, and zero-lookahead
cycles before activation. Add compute, host-I/O, link, and clock declarations
using explicitly versioned scenario representations.

**T-CN-09: Separate time and execution units.** Add checked exact/quantized
coordinates and conversions; distinguish retirement counts and guest clock
readings. Preserve existing QEMU raw/logical observations in adapters. Define
legacy reader/writer policy and refuse overflow or unrepresentable ceilings.

T-CN-08/T-CN-09 also implement and bind the `superdense-v1` ordering profile,
including microsteps, producer sequences, and captured pending-event keys.
The new key `(instant, microstep, phase, consumer, producer, sequence)` ensures causes
precede their zero-latency effects. Preserve old key bytes in the legacy profile;
do not change them in P1 or claim equivalence across different ordering profiles.
Initial activation, like restore activation, waits for complete all-owner and
connection readiness and a committed world activation record under the admitted
binding. Ordinary grants refer to that record and owner-ready generation; no
physical simultaneous startup is implied.

Deliverables: versioned formats and test vectors, old/new compatibility table,
whole-graph admission errors, profile manifests, and migration tests.

Exit: malformed, incomplete, unsupported, and mismatched graphs fail before
launch. Any foreign implementation or omitted state owner refuses restoration
before candidate activation. Old exact QEMU state remains restorable through
its authenticated legacy path; it is never relabeled as new implementation state.

Gates: canonical round-trip and negative codec tests, graph admission tests,
content-address/replay/campaign regressions, application test-target compilation,
and ABI/license/versioning tests for changed public protocols.

Risk: compatibility metadata remains outside identity; mode support becomes a
stringly typed claim; replay fallback is erroneously enabled for KVM. Rollback:
disable new writers and admissions; keep legacy readers and new-format refusal.
Do not downgrade emitted owner-state artifacts.

## 5. P3 — General exact-node scheduling

Prerequisites: P2. Initially use serial dispatch through qualified existing owners.

**T-CN-10: Qualify dispatch and inventory per owner.** Replace collection-global
selection with immutable realization/owner bindings. Retain native receipt,
input/cap boundary, retry, settlement, and uncertain-outcome handling. Exclusive
leases prevent concurrent mutation through aliased logical nodes.

**T-CN-11: Adapt event-driven host models.** Wrap block, 9p, and network link
models using typed ports and next-event observations. Distinguish passive idle,
known future deadlines, and unknown pending behavior. Preserve queue ordering,
backpressure, fault state, and transaction commit boundaries.

**T-CN-12: Generalize conservative causal bounds.** Apply producer frontier,
connection lookahead, pending delivery, and local deadline bounds to every port
family. Refuse unsafe or unrepresentable advances, including same-time and
zero-lookahead cases. Keep host scheduling out of canonical event ordering.

Implement explicit phase/microstep closure and boundary-settlement grants at
one physical instant. A parked tick is not proof of semantic-prefix closure.
Settlement may execute only its authorized superdense position range and may
not execute a later tick. Admitted zero-time cycles bind a finite iteration
limit and fail on nonconvergence or microstep overflow, without shifting time.

**T-CN-13: Add logical clock roles and composite routing.** Model readings,
alarms, drift, and faults independently of coordinator time. Delegate embedded
clock/cache/interrupt state into its actual implementation owner. Do not invent
a second mutable replica or let guest clock changes rewrite shared time.

**T-CN-14: Qualify exact world capture and concurrent dispatch.** Capture each
owner once together with coordinator, ports, queues, order, lifecycle, and fault
state. Prepare all restore components before activation; quarantine uncertain
partial outcomes. Then qualify deterministic parallel execution for disjoint
owners, committing completions canonically regardless of host order.

Deliverables: owner-qualified scheduler, general causal graph, passive-node
adapters, atomic world capture/restore, and serial/parallel equivalence evidence.

Exit: a fast node cannot outrun possible input from any slower producer. Waiting
nodes do not pin progress without a causal reason. Composite aliases cannot
advance twice. Boundary and restore traces remain exact for the existing QEMU
profile, including adversarial tie ordering and backpressure.

Gates: scheduler ceiling/lookahead/local-event/concurrency/liveness set; device
wire and live-I/O checks; restore and fork isolation; signal-fault integration;
negative causality and ownership tests; boot and device throughput overhead.

Risk: Ethernet-only assumptions survive in another dependency path; event-driven
nodes are treated as runnable VMs; new dispatch allocates or locks per native
instruction. Rollback: profile-gate the general scheduler and retain the old
strict path until equivalence is established.

## 6. G0 and P4 — Exact gem5 feasibility and implementation

G0 prerequisite: frozen upstream revision, reproducible source-built tools, and
an explicit machine/CPU/device model. It can begin alongside P1. P4 integration
prerequisites: P2 and owner-qualified P3 interfaces.

**T-CN-15: Prove complete nondraining capture feasibility early.** Inventory
serialization and live-fork coverage at a pinned gem5 revision. Exercise genuinely
nonempty pipeline, predictor, cache, memory-controller, event, DMA, and protocol
state. Determine what must be patched. Stock drained checkpoints, cache warm-up,
or architectural export do not satisfy exact capture. Decide durable full-state
representation separately from same-host copy-on-write branching.

**T-CN-16: Implement the native control owner and exact stops.** Build gem5
hermetically, implement versioned process control and checked time/event-ordinal
mapping, retain early outputs and pending requests, and qualify stops before
incoming delivery without executing extra simulated work.

**T-CN-17: Preserve the complete realized state graph.** Capture object identity,
pipeline and speculative state, predictor/RNG state, caches/MSHRs/transients,
memory controller queues/timing, pending requests, event ordering, devices,
transport, and adapter state. Use checked graph restoration and reject unknown
stateful objects. Do not silently drain, flush, write back, or reconstruct state
by executing warm-up instructions.

**T-CN-18: Qualify durable restore after origin death.** Restore into a fresh
process using saved artifacts after the original process exits. Compare complete
state and future event traces to uninterrupted and capture-without-restore
controls. Include unsupported-version and missing-object failures before
activation.

**T-CN-19: Qualify live branching and resource isolation.** If native COW is
offered, audit threads, locks, private/shared mappings, sockets, listeners,
writable images, output streams, and host services. Identical children reproduce
the original continuation; divergent children cannot mutate parents or siblings.
Advertise live branching only for its independently qualified configuration.

Deliverables: feasibility report, explicit full-state inventory, patched source
and matching package identity, exact control adapter, durable format, and separate
durable/live-branch certificates.

Exit: complete model-state preservation, including difficult in-flight state,
without hidden drain or simulated-time movement. A durable artifact survives
source-process death. Every advertised CPU and device configuration passes;
failure blocks the profile rather than weakening “exact.”

Gates: new complete-state qualification suite in [qualification-plan.md](qualification-plan.md),
process ABI/license review, artifact/source pairing, build reproducibility,
negative hidden-state omission tests, and independent state/event digests.

Risk: full graph serialization is substantial; COW preserves heap but not shared
external state; event tie order is omitted; profile options introduce untracked
threads. Rollback: retain research/prototype status and reject production gem5
admission. A narrower profile is allowed only if declared as a distinct qualified
configuration; it cannot satisfy the requested full-parity profile by omission.

## 7. P5 — Device parity and mixed exact worlds

Prerequisites: P3 and P4 exact qualification.

**T-CN-20: Implement required guest-facing device and platform parity.** Match
supported block/root-image, 9p, network, entropy, serial, debug transport,
accelerator, doorbell, firmware, interrupts, and clock behavior for the declared
machine profiles. Reuse authoritative host services where applicable, with new
native guest transports. Preserve frontend virtqueues, DMA, interrupts, and
host-model state in one capture closure.

**T-CN-21: Qualify x86-64 and AArch64 profiles independently.** Record CPU,
platform, devices, features, transport, clock and interrupt contracts, exact
state support, and faults. Configuration-sensitive gaps refuse admission;
capabilities cannot be used to declare missing required parity acceptable.

**T-CN-22: Exercise mixed QEMU-SIM/gem5 scenarios.** Use bidirectional guest
workloads with unequal resolutions, local timers, queued storage/network input,
zero-lookahead refusal, same-time ordering, faults, and mixed checkpoints. Start
serially, then qualify host-parallel dispatch for independent owners.

**T-CN-23: Separate fidelity performance profiles.** Add comparison workloads
with declared CPU/memory/device models. Retain the existing strict QEMU/SIM
timing comparison and its witnesses; do not relabel detailed-model runtime as
equal guest work. Measure model cost, scheduling overhead, capture, and restore
separately.

Deliverables: complete parity ledger, architecture profiles, live mixed-world
tests, stateful fault tests, and local performance summaries.

Exit: supported guest applications exercise real I/O on both implementations;
no scripted success substitutes for execution. Exact nodes retain fine event
resolution and never cross a possible incoming boundary. Mixed restore and
branching preserve all ownership and ordering state.

Gates: parity, complete-state, mixed exact causality, fault, architecture, and
performance suites. Rollback: remove the failing profile from admitted support,
while retaining earlier qualified QEMU profiles. Risk: basic boot success hides
missing guest ABI features or frontend state.

## 8. P6 — Quantized worlds and KVM

Prerequisites: P2/P3 general admission, state identity, and causal graph. P6 does
not depend on gem5 being faster or fully qualified; mixed gem5 admission still
requires P5.

**T-CN-24: Implement quantized grants and acknowledgment.** Define boundary
input sampling, authorized activity, polling/cancellation, output sealing,
idempotent acknowledgment, commit, and failure/quarantine. Explicitly represent
late or uncertain effects. Keep exact grant results a different type.

**T-CN-25: Contain KVM clocks, timers, and I/O.** Inventory x86/ARM counters,
paravirtual clocks, RTC/PIT/HPET/APIC or ARM timers/GIC, vCPU run and halt state,
DMA, storage, and device completions. Implement pause/resume continuity and
boundary policy for every advertised clock. Kernel controls alone do not make
the whole machine controller-clocked. Require complete mediation or refuse the
profile; use patches where necessary without claiming exact native stops.

Before implementation, produce an x86-64/AArch64 kernel feasibility matrix
mapping TSC/RDTSCP, ARM physical/virtual counters, paravirtual clock memory,
and every timer/interrupt source to available trapping, scaling, offsets,
emulation, mediation, required patches, or profile refusal. Qualify progress of
guests polling clocks as well as timer-driven guests. Bind the clock policy
during vCPU stop overshoot and closed-window waits; a counter adjustment alone
does not establish correct pacing or containment.

**T-CN-26: Enforce mixed-resolution no-outrun admission.** Reserve quantized
publication boundaries with exact peers and slower producers. Inputs may cross
only admitted boundaries; finer exact events retain their own resolution.
Prove how grants depend on closed producer frontiers and declared latency.
Buffering outputs cannot repair a receiver that already missed authorized input.

**T-CN-27: Qualify KVM architectural capture and smoke progression.** Capture
exposed CPU, memory, interrupt/device, disk, protocol, and clock state under the
weaker contract. Restore a fresh VM rather than inheriting unsupported kernel
VM handles. KVM-to-SIM-to-gem5 test progression starts separate realizations;
any conversion is explicitly nonexact initialization with new lineage.

**T-CN-28: Add optional conditional transcript replay.** Record accepted inputs,
output bytes, effective boundaries/order, storage effects, control outcomes, and
uncertainty. Refuse changed inbound interactions or missing transcript coverage.
Keep unrecorded KVM worlds nondeterministic, with observed-attempt identity and
deterministic cache/replay/search exclusions.

Deliverables: quantized state machine, architecture-qualified clock inventory,
KVM profile, mixed-resolution tests, capture scope, and optional replay profile.

Exit: quantized nodes cannot publish into committed history or receive inputs
after the boundary they were admitted to observe. Slow peers stall progress as
needed. Missed deadlines invoke declared policy; stop overshoot is measured but
never presented as an exact guarantee. No participant bypasses mediated I/O.

Gates: quantized lifecycle and late-output negatives; real multi-vCPU KVM boot,
clock/timer/pause/interrupt tests; connected exact/quantized causality; observed
identity/cache rules; capture isolation; conditional replay negatives; runtime
performance and deadline distributions for the qualified workload.

Risk: a guest clock or device path escapes containment; host hardware continues
after apparent pause; a signal latency measurement is mistaken for a hard bound.
Rollback: disable KVM/quantized profile admission while retaining exact support.
Do not fall back to an exact protocol or pretend the attempt was deterministic.

## 9. P7 — External implementations and public qualification

Prerequisites: P2 formats and P3/P6 relevant mode implementations.

**T-CN-29: Publish versioned integration schemas and vectors.** Provide transport
operations, bounds, ordering, lifecycle/error handling, extension registration,
and independent test vectors. A provider negotiates immutable capabilities and
receives only admitted operations. Native pointers or host Rust layouts never
cross the process boundary.

**T-CN-30: Add an external adapter reference profile.** Use a small real or
controlled external component to prove reuse beyond compute. Describe whether
physical activity pauses, how observations are buffered/timestamped, restart
and disconnect behavior, clock uncertainty, and unsupported capture guarantees.
Do not require access to particular vendor hardware for the general conformance
suite; hardware-specific qualification remains a separate profile.

**T-CN-31: Deliver vendor conformance and adversarial suites.** Cover malformed
messages, version mismatch, missing facets, stale grants, duplicates, reconnects,
resource exhaustion, boundary ordering, ownership, capture, and selected modes.
Qualification identifies exact implementation/configuration/toolchain versions
and the scope of evidence, not a product-wide blanket approval.

**T-CN-32: Integrate release, documentation, and operational migration.** Update
executor inventory, package/source manifests, profile admission, troubleshooting,
state compatibility documentation, and final requirement-to-test traceability.
Publish concise results through the change description; retain raw traces locally.

Deliverables: external profile, reusable conformance tool, negative vectors,
release integration, and migration runbook.

Exit: an independent implementation can negotiate, realize, execute, fail safely,
and preserve exactly the state it advertises using the public contract and
vectors. Required extensions are not inferred from vendor names. All production
profiles have complete requirement coverage and explicit operating limits.

Gates: vendor contract/security/resource tests, ABI/license and matching-source
publication where applicable, existing release acceptance, and final local
performance comparisons. Risk: implementation-specific assumptions leak into
the public API or an optional extension becomes implicit mandatory support.
Rollback: withdraw a profile/version from admission, retain explicit refusal and
compatible readers, and preserve previous qualified profiles.
