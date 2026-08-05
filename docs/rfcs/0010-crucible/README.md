# RFC-0010: Crucible — a hermetically deterministic multi-VM simulation harness

- **Status:** Proposed (design-only; no implementation yet). This RFC is
  written in the present tense to describe the *target* system; nothing here
  ships until the phased plan in [`32-implementation-plan.md`](32-implementation-plan.md)
  is worked through and each phase's gate is green.
- **Date:** 2026-06-18
- **PR:** [#112](https://github.com/andyl-technologies/aos/pull/112) (draft)
- **Audience:** anyone working on `crates/crucible-*`, the AOS QEMU package
  (`pkgs/emulation/qemu*`) and its patch series, the AOS kernel/rootfs builders,
  or CI determinism gates.

This is a directory RFC. This `README.md` carries the status header, the
problem statement, the whole-system overview, the reading order, and the
requirement-ID scheme that threads the spec to the implementation plan. The
topic files hold the detail.

## What Crucible is, in one paragraph

Crucible is a **hermetically deterministic, multi-VM simulation harness**: it
boots one or more unmodified guest kernels under QEMU TCG with instruction-count
virtual time, drives them through a single authoritative scheduler so that the
*entire multi-machine execution is bit-identical across runs of the same seed*,
and exposes that determinism as a controllable execution graph — checkpoint,
fork, resume, inject faults, assert properties, and search the space of
schedules. It is the substrate for deterministic distributed-systems testing:
reproduce any failure exactly from a seed, and explore the failure space
systematically rather than by luck.

## The problem

Testing distributed systems is hard because the bugs that matter are
*timing-and-order-dependent* — a partition that heals one instruction earlier, a
disk write that lands after a crash instead of before — and those orderings are
not reproducible on real hardware or under ordinary virtualization. Standard
tools give you, at best, *statistical* coverage: run it a thousand times and hope
the bad interleaving shows up, and when it does, you usually cannot reproduce it.

The root cause is nondeterminism, and it enters at many layers: the host
scheduler, wall-clock time, hardware entropy (`RDRAND`, `RDTSC`), interrupt
timing, multi-core memory ordering, and the network. Crucible's thesis is that
**all of these can be eliminated or brought under a single deterministic clock**
if you (a) run each guest under QEMU TCG with fixed instruction-count time and a
sealed entropy boundary, (b) make every cross-machine interaction flow through
one authoritative, exactly-ordered scheduler, and (c) model the entire run as a
pure reduction of an immutable scenario definition under a recorded sequence of
scheduling decisions. Once execution is a pure function of `(scenario, seed,
schedule)`, reproduction is free and exploration is a graph traversal.

The prior internal exploration of this idea proved the physics works
(instruction-count time, a shared-memory co-simulation transport, copy-on-write
device overlays, a deterministic fault taxonomy) but settled for a *weaker*
determinism contract — same delivered-message sequence, not the same instruction
stream — and grew its control plane, its synchronization granularity, and its
advanced features (fork, resume, search) reactively on top of that weaker
foundation, so they are not yet reliable. This RFC raises the contract to
**instruction-level determinism**, specifies it precisely, and rebuilds the
system around a single unified execution model with a determinism gate at every
layer.

## Non-negotiable targets (the headline contract)

These are stated formally with IDs in [`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md);
the headline four:

1. **Hermetic instruction-level determinism.** For a fixed scenario, seed, and
   schedule, every VM produces a bit-identical instruction stream and
   architectural state evolution, and the whole-system run is reproducible to the
   instruction. *Not* a record/replay log papering over nondeterminism — the
   nondeterminism is eliminated at the source.
2. **Any unmodified guest.** Determinism is achieved entirely host-side. Crucible
   boots an arbitrary guest kernel + image with only launch-time configuration;
   no guest image changes, no required in-guest agent, no guest kernel patches.
   Black-box observation is the default; in-guest instrumentation is an optional
   white-box enhancement.
3. **One execution model.** Start, resume, and fork are the *same operation*: a
   run is `state = reduce(ScenarioDef, Schedule)`, and producing a runnable state
   from any point — including the very first — is one recursive `instantiate`
   function whose base case is boot. Save/resume/fork/replay/search are all
   operations on one content-addressed execution graph.
4. **Correctness is structural and gated.** The replay oracle
   (`reduce`-from-ancestor must equal a materialized snapshot) is an invariant of
   the data model, enforced in CI, and every layer has its own determinism gate
   that must be green before anything is built on top of it.

## Whole-system overview

Crucible is organized as two orthogonal graphs joined by one reduction:

- **The spatial graph** ([`06-spatial-graph.md`](06-spatial-graph.md)) — the
  immutable, content-addressed *definition* of a scenario: the topology of nodes
  and links, per-node configuration, the fault plan, the properties to check, and
  the seed. This is the system's *structure*. It is "configuration #0."
- **The temporal graph** ([`07-temporal-graph.md`](07-temporal-graph.md)) — the
  *unfolding* of the spatial graph under scheduling decisions: a content-addressed
  DAG of checkpoints (copy-on-write, thin-or-materialized) whose edges are
  decisions. This is the system's *behavior over decision-time*. It is the closure
  of configuration #0 under the `step` reducer.
- **The reduction** ([`05-execution-model.md`](05-execution-model.md)) —
  `State(t) = reduce(ScenarioDef, Schedule[0..t])`, with `instantiate` unifying
  boot / resume / fork as one recursive function.

Underneath, the runtime is layered (L0–L4, [`27-crate-structure.md`](27-crate-structure.md)),
each layer with its own determinism gate:

```text
  L4  control plane      crucible-session (actor) · crucible-api · crucible-daemon · crucible (CLI)
  L3  engine             crucible — scenario model, scheduler, faults, assertions, temporal graph
  L2  QEMU integration   crucible-qemu (host) · crucible-qemu-plugin (in-VM cdylib) · crucible-guest
  L1  co-sim transport   crucible-shmem (ABI) · crucible-protocol · crucible-device (disk/9p/net sub-nodes)
  L0  deterministic core  crucible-sim (runtime/scheduler primitives) · crucible-assert
```

The hard determinism work concentrates at L0–L2: eliminate every entropy source
inside a single VM (L2 + the AOS QEMU patch series, [`11-qemu-patches.md`](11-qemu-patches.md)),
make cross-VM event injection a pure function of instruction-count time
(L1 + [`08-scheduling.md`](08-scheduling.md)), and prove both with a layered
determinism harness ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md))
before any feature is built on top.

## Reading order

Start here, then read in three bands:

**Band A — the contract (read first, in order):**
1. [`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md) — targets, non-goals, invariants (the requirement IDs everything else satisfies).
2. [`02-glossary.md`](02-glossary.md) — precise vocabulary.
3. [`00-conventions.md`](00-conventions.md) — requirement-ID scheme, RFC-2119 keywords, how the checkbox plan threads back to the spec.
4. [`03-architecture-overview.md`](03-architecture-overview.md) — the whole system, end to end.
5. [`04-determinism-contract.md`](04-determinism-contract.md) — the formal determinism contract (the spine of the whole RFC).
6. [`05-execution-model.md`](05-execution-model.md) — `Configuration` / `step` / `instantiate` / `bake`; start ≡ resume ≡ fork.

**Band B — the spec (the system, layer by layer):**
7. [`06-spatial-graph.md`](06-spatial-graph.md) · 8. [`07-temporal-graph.md`](07-temporal-graph.md) · 9. [`08-scheduling.md`](08-scheduling.md) · 10. [`09-virtual-time-icount.md`](09-virtual-time-icount.md)
11. [`10-qemu-integration.md`](10-qemu-integration.md) · 12. [`11-qemu-patches.md`](11-qemu-patches.md) · 13. [`12-qemu-plugin.md`](12-qemu-plugin.md)
14. [`13-shmem-abi.md`](13-shmem-abi.md) · 15. [`14-protocol.md`](14-protocol.md) · 16. [`15-io-subnodes.md`](15-io-subnodes.md) · 17. [`16-guest-host-channel.md`](16-guest-host-channel.md)
18. [`17-fault-injection.md`](17-fault-injection.md) · 18a. [`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) · 19. [`18-assertions-properties.md`](18-assertions-properties.md) · 20. [`19-observability-event-log.md`](19-observability-event-log.md)
21. [`20-session-control-plane.md`](20-session-control-plane.md) · 22. [`21-api.md`](21-api.md) · 23. [`22-advanced-features.md`](22-advanced-features.md) · 24. [`23-cli.md`](23-cli.md)

**Band C — making it real:**
25. [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) · 26. [`25-performance-targets.md`](25-performance-targets.md) · 27. [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md)
28. [`27-crate-structure.md`](27-crate-structure.md) · 29. [`28-engineering-standards.md`](28-engineering-standards.md) · 30. [`29-patterns-and-sketches.md`](29-patterns-and-sketches.md)
31. [`30-risks-spikes.md`](30-risks-spikes.md) · 32. [`31-decision-register.md`](31-decision-register.md)

**Worked examples & workloads:**
33. [`33-examples-and-workloads.md`](33-examples-and-workloads.md) — end-to-end worked scenarios covering both opaque black-box workloads and structured guest assertions (happy path, partition-recovery, crash/restart, fault campaign, determinism check), plus the in-guest workload/traffic-generation story.

**Advanced capabilities (built on the green determinism foundation):**
34. [`34-failure-triage.md`](34-failure-triage.md) — clustering/dedup of discovered failures by root-cause signature, signature-preserving minimization, per-cluster reports.
35. [`35-distributed-continuous-exploration.md`](35-distributed-continuous-exploration.md) — fleet-scaled search over the shared content-addressed store, persistent campaigns + the coverage ratchet, the reproduction-vs-scheduling determinism boundary.
36. [`36-time-travel-debugging.md`](36-time-travel-debugging.md) — gdb-stub attach to any checkpoint, reverse/time-travel via restore-nearest+replay, the non-canonical debug branch.

(Multi-vCPU determinism, concurrency-interleaving exploration, guided/adaptive search, and optional app-controlled randomness are folded into the relevant spec files above — see [01](01-goals-nongoals-invariants.md) [G-10]/[G-11], [05](05-execution-model.md) `Decision::Preemption`/`Decision::AppRandom`, and [22](22-advanced-features.md).)

**The plan (the thing an implementor works through):**
33. [`32-implementation-plan.md`](32-implementation-plan.md) — the master, phased, checkbox implementation plan. Every task references the spec requirement IDs it satisfies; every spec file carries the slice of the plan that belongs to it. Phase ordering puts **determinism, the test harness, the transport ABI, and the control-plane API correctness first**, before any feature is built on top.

## How the spec threads into the plan

Every normative statement in a topic file is a numbered **requirement** with a
stable ID (e.g. `DET-3`, `EXEC-7`, `SCHED-2`; scheme in
[`00-conventions.md`](00-conventions.md)). Every topic file ends with an
**Implementation checklist** of `- [ ]` tasks, each tagged with the requirement
IDs it satisfies. The master plan ([`32-implementation-plan.md`](32-implementation-plan.md))
aggregates all tasks into ordered phases with explicit gates. An implementor
works the master plan top to bottom; each task links back to the exact spec
section that defines "done." When every box is checked and every gate is green,
the system is at the target state this RFC specifies.

## Relationship to RFC-0007 (`ratchet`)

`ratchet` (RFC-0007, the language-agnostic Nix-evaluator engine) is a conceptual
cousin — both are content-addressed, incremental, determinism-obsessed Rust
graph-reduction systems — but it is **not a dependency**. Any shared lower-level
substrate (a content-addressed store + dependency-gated invalidation primitive
common to ratchet's incremental cache and Crucible's temporal graph) is **gated
behind a future integration** ([`26-packaging-aos-integration.md`](26-packaging-aos-integration.md) §"ratchet gate"):
RFC-0007 is still in flight, so Crucible ships standalone and the merge happens
later. Until then Crucible vendors or reimplements the small amount it needs and
marks the seam.
