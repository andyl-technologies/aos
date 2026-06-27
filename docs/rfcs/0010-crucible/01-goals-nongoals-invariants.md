# 01 — Goals, Non-goals, and Invariants

This file is the contract. Everything else in the RFC exists to satisfy the goals
and uphold the invariants stated here. Requirement IDs defined here (`G-*`,
`NG-*`, `INV-*`) are referenced throughout.

## Goals

- **[G-1] Hermetic instruction-level determinism.** For a fixed
  `(ScenarioDef, seed, Schedule)`, every VM MUST produce a bit-identical
  instruction stream and architectural-state evolution, and the whole-system run
  MUST be reproducible to the instruction. Determinism is achieved by eliminating
  nondeterminism at its source, not by recording and replaying it. (Detailed
  contract: [`04-determinism-contract.md`](04-determinism-contract.md).)

- **[G-2] Any unmodified guest.** Crucible MUST run an arbitrary guest kernel and
  root image with only launch-time configuration (QEMU flags, kernel cmdline,
  seeded firmware entropy). It MUST NOT require modifications to the guest image,
  an in-guest agent, or guest kernel patches for its core function. The system
  SHOULD be guest-OS-agnostic (Linux, BSD, others) in black-box mode.

- **[G-3] Black-box by default, white-box by opt-in.** All core capabilities —
  deterministic execution, fault injection, coverage, property checking against
  observable I/O — MUST work with zero guest cooperation. Fine-grained in-guest
  assertions and markers MAY be added via an optional, explicitly-enabled
  white-box channel.

- **[G-4] One unified execution model.** Start, resume, and fork MUST be the same
  operation. A run is `reduce(ScenarioDef, Schedule)`; producing a runnable state
  from any point (including the first) is one recursive `instantiate` whose base
  case is boot. Save, resume, fork, replay, and state-space search MUST all be
  operations on a single content-addressed execution graph.

- **[G-5] Foundation-first correctness.** The determinism contract, the test
  harness, the co-simulation transport ABI, and the control-plane/API correctness
  MUST be complete and gated before any feature is built on top of them. Phase
  ordering and gates enforce this ([`32-implementation-plan.md`](32-implementation-plan.md)).

- **[G-6] Reproduce-then-explore.** A failure MUST be reproducible bit-identically
  from a self-contained artifact (seed + scenario + schedule). The system MUST
  support systematic exploration of the schedule space (fork, state-space search,
  coverage-guided fuzzing) built on that reproducibility.

- **[G-7] Hermetic, from-source build inside AOS.** Crucible and its patched QEMU,
  guest kernel, and root images MUST build hermetically within AOS's build system
  with no upstream binary dependencies, consistent with AOS build principles. The
  QEMU patch series MUST be well-tested and MUST be inert unless simulation mode is
  active, so AOS's production QEMU is unaffected.

- **[G-8] Stable, tested, versioned interfaces.** The three boundary ABIs — the
  shared-memory layout, the guest↔host channel, and the control-plane RPC — MUST
  be explicitly versioned and covered by conformance tests/golden vectors.

- **[G-9] Performance adequate for interactive use and fuzzing.** The system MUST
  meet the throughput and latency targets in [`25-performance-targets.md`](25-performance-targets.md):
  idle time fast-forwarded to zero wall-clock, multi-VM parallelism up to the
  lookahead budget, determinism overhead within budget, and a stated fuzzing
  throughput.

- **[G-10] Deterministic multi-vCPU guests.** Crucible MUST run multi-vCPU
  (`-smp N`) guests deterministically via single-threaded round-robin (RR) TCG +
  `-icount` (never MTTCG): the whole multi-vCPU interleaving MUST be a pure
  function of `(image, seed, Schedule)`. Within a VM, vCPUs are serialized on one
  host thread (determinism over intra-VM speed); cross-VM host parallelism
  ([`08-scheduling.md`](08-scheduling.md)) is unaffected. (Detail:
  [`04-determinism-contract.md`](04-determinism-contract.md),
  [`10-qemu-integration.md`](10-qemu-integration.md),
  [`11-qemu-patches.md`](11-qemu-patches.md),
  [`12-qemu-plugin.md`](12-qemu-plugin.md).)

- **[G-11] Concurrency-interleaving exploration.** The vCPU-switch and
  interrupt/preemption timing MUST be a first-class explorable `Decision`
  (`Decision::Preemption`), deterministic by default and branchable by the
  explorer ([`22-advanced-features.md`](22-advanced-features.md)), including for
  single-vCPU guests (varying when the timer interrupt preempts) — the
  highest-leverage axis for finding intra-node concurrency/ordering bugs.

## Non-goals

- **[NG-1] _(withdrawn — superseded by [G-10])._** Multi-vCPU guest determinism
  was originally out of scope (single-vCPU only) because multi-threaded TCG
  (MTTCG) is nondeterministic. It is now a goal ([G-10]), achieved **not** via
  MTTCG but via single-threaded round-robin TCG + `-icount` (all vCPUs time-share
  one host thread, switching at a deterministic icount quantum). MTTCG
  (`thread=multi`) remains forbidden ([DET-23]).

- **[NG-2] In-process testing of host Rust code.** Crucible is a QEMU-guest
  simulator. It does NOT provide an in-process harness for testing the host's own
  async Rust code (where in-process tasks stand in for services); "node" always
  means a guest VM or an I/O sub-node, never an in-process task standing in for a
  service.

- **[NG-3] A bespoke formal-methods engine.** Crucible does NOT include a model
  checker or a specification-language evaluator. Temporal properties are checked
  against the recorded event log via the assertion vocabulary; conformance against
  an external formal spec, if ever wanted, is an OPTIONAL offline step using
  existing tooling, never an in-runtime engine.

- **[NG-4] A web UI.** Crucible exposes a programmatic API and a CLI. A browser
  front-end is explicitly out of scope for this RFC.

- **[NG-5] Real-time fidelity.** Crucible models virtual time, not wall-clock
  performance of the guest. It is not a benchmarking tool; timings are the modeled
  virtual timings, not measured host timings.

- **[NG-6] Record/replay as the determinism mechanism.** A decision log is used
  for *forking and search*, but the per-VM determinism MUST come from source
  elimination of entropy, not from recording and replaying nondeterministic
  events. (QEMU's own record/replay is, at most, a diagnostic for *finding*
  residual nondeterminism — see [`30-risks-spikes.md`](30-risks-spikes.md).)

- **[NG-7] Dependency on RFC-0007 (`ratchet`).** Crucible ships standalone. Any
  shared substrate with ratchet is gated behind a later integration; this RFC does
  not depend on ratchet landing.

## Invariants

Invariants are properties that MUST hold at all times in a running or stored
system. They are the load-bearing truths the design and its tests defend.

- **[INV-1] Purity of reduction.** Execution state is a pure function of the
  scenario and the schedule: `State(t) = reduce(ScenarioDef, Schedule[0..t])`. No
  wall-clock value, host-scheduling order, host entropy, or uncontrolled external
  input may influence `State`. *Gate:* `gate:replay-oracle`.

- **[INV-2] Replay-oracle equality.** For any checkpoint, the state obtained by
  materializing it from a stored snapshot MUST equal the state obtained by
  re-reducing it from any ancestor along the same schedule, compared by content
  hash. A materialized (fat) checkpoint and its thin derivation MUST hash equal.
  *Gate:* `gate:replay-oracle`.

- **[INV-3] Total order of cross-node events.** Every interaction observable
  across nodes (frame delivery, I/O completion, fault activation) has a
  deterministic total order keyed by `(virtual_time, consumer node_id, producer node_id, sequence)`,
  independent of wall-clock and host scheduling. *Gate:* `gate:layer1-injection`.

- **[INV-4] Virtual time is instruction-count-derived.** A node's virtual time is
  a pure function of its executed instruction count; cross-node ordering uses the
  shared icount→virtual-time mapping. No node's progress depends on host real time.
  *Gate:* `gate:layer0-determinism`, `gate:single-vm-fingerprint`.

- **[INV-5] Guest non-modification.** Booting and running a guest MUST NOT mutate
  the guest's on-disk image (copy-on-write overlays only) and MUST NOT require any
  content placed inside the guest by Crucible for core operation. *Gate:*
  `gate:any-guest`.

- **[INV-6] Content addressing.** Every immutable artifact (scenario components,
  snapshots, event-log segments, schedule deltas) is identified by the hash of its
  content; equal content has equal identity, enabling sharing and deduplication
  across the temporal graph. *Gate:* `gate:content-address`.

- **[INV-7] Patch inertness.** The QEMU patch series MUST have no observable
  effect on QEMU behavior unless simulation mode is explicitly activated
  (plugin loaded + sim flags). AOS's production QEMU built from the same source
  MUST be behaviorally identical to upstream when sim mode is off. *Gate:*
  `gate:qemu-inert`.

- **[INV-8] Single authoritative scheduler.** All advancement of virtual time and
  all resolution of cross-node ordering decisions flow through one scheduler;
  there is no second source of timing truth. The scheduler is an actor that yields
  between quanta so control operations are processed at well-defined points
  (no long-held locks). *Gate:* `gate:scheduler-liveness`, `gate:control-responsive`.

- **[INV-9] Harness determinism.** Crucible's own host code MUST be deterministic:
  no unordered map iteration on ordering-significant paths, no host wall-clock or
  thread RNG in the engine, deterministic `select`. *Gate:* `gate:harness-lint`.

- **[INV-10] No silent nondeterminism.** Any code path that could introduce
  nondeterminism MUST either be eliminated, routed through the seeded decision
  source, or fail loudly. A detected divergence MUST localize to the first
  differing decision/instruction, never be smoothed over. *Gate:*
  `gate:divergence-bisect`.

- **[INV-11] Interleaving is instruction-count-derived.** A node's vCPU
  interleaving and interrupt-delivery points are a pure function of node icount,
  the fixed `rr_switch_quantum`, and the `Schedule`'s `Decision::Preemption`
  entries — never of host thread scheduling. *Gate:* `gate:layer0-determinism`,
  `gate:single-vm-fingerprint`.

## Acceptance: when is Crucible "done" to this RFC?

Crucible reaches the target state of this RFC when:

1. Every `MUST` requirement across all topic files is satisfied by a completed
   task (`[PLAN-2]` coverage is empty), and
2. Every phase gate in [`32-implementation-plan.md`](32-implementation-plan.md) is
   green, ending with `gate:e2e-determinism` (a representative multi-VM,
   fault-injected scenario runs bit-identically across adversarial host conditions
   and reproduces from its artifact), and
3. The QEMU patch series is upstreamable-quality, inert-by-default, and each patch
   has a passing micro-test (`gate:qemu-inert`, per-patch gates in 11).

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md). This file's
> requirements are satisfied transitively by the per-area tasks; there are no
> tasks whose primary area is "goals." The coverage check in 32 verifies every
> `MUST` here maps to a concrete task elsewhere.
