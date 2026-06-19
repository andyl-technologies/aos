# 32 — Master implementation plan

This is the plan an implementor works through, top to bottom, to reach the exact
target state RFC-0010 specifies. It is the **ordering authority**: it arranges
every task defined across the topic files into phases, states the **gate** that
must be green to leave each phase, and verifies (the coverage section) that every
normative `MUST` maps to at least one task.

## How to use this plan

- The **authoritative text** of each task lives in its topic file's
  "Implementation checklist" section ([PLAN-3]). This plan owns **ordering** and
  groups tasks by area and ID range; follow the link to the topic file for the
  full task text and its requirement back-references.
- Task IDs are area-scoped and stable (`T-<AREA>-n`, [`00-conventions.md`](00-conventions.md)).
  Re-sequencing a task here never renumbers it.
- **[PLAN-4] holds**: no task depends on a later-phase task. The ordering is
  *foundation-first* — determinism, the harness, the transport ABI, and
  control-plane correctness precede everything built on them (G-5).
- A phase is **done** when all its tasks are checked and its **exit gate** (24)
  is green. Do not start a phase before the prior phase's gate is green.

## Inventory

The plan covers **497 tasks** across 33 areas, satisfying **952 numbered
requirements** (plus the goal/non-goal/invariant/decision IDs). Coverage is
**complete**: every defined requirement is cited by at least one checklist task,
and no task cites a non-existent requirement (verified by the `T-PLAN-1` lint).
Task counts by area:

```text
SCHED 30  DET 28  PERF 26  HARN 26  EXEC 25  PLUG 23  SPAT 21  SHM 21  TRIG 20
PKG 20  PATCH 20  ASRT 17  RISK 16  IO 16  FAULT 16  CLI 16  ADV 16  SESS 15
GHC 15  CRATE 15  QEMU 14  API 14  STD 13  OBS 13  TEMP 11  PROTO 11  PAT 9
TIME 8  WL 6  EX 5  ARCH 5  PLAN 3  D 3
```

## The phase ladder

```text
  Phase 0  De-risk          spikes that can reshape the design       gate: Phase-0 blockers pass
  Phase 1  Determinism core L0 runtime, decision RNG, time, harness  gate:harness-lint, gate:layer0-determinism,
                            content-addressed store, the test double        gate:content-address, gate:replay-oracle (sim),
                                                                            gate:single-vm-fingerprint (double), gate:divergence-bisect
  Phase 2  Transport+QEMU   shmem ABI, protocol, patch series,       gate:abi-conformance, gate:qemu-inert,
                            host QEMU + plugin, single-VM determinism       gate:patch-microtests, gate:single-vm-fingerprint (real QEMU)
  Phase 3  Scheduling+I/O   scheduler, I/O sub-nodes, cross-VM        gate:layer1-injection, gate:scheduler-liveness,
                            injection determinism                           gate:adversarial-determinism (2-VM)
  Phase 4  Engine           spatial+temporal graph, faults,           gate:replay-oracle (full), gate:e2e-determinism (mock)
                            assertions, event log, guest-host channel
  Phase 5  Control plane    session actor, API, CLI, daemon          gate:control-responsive
  Phase 6  Exploration      fork, save/resume, search, fuzz, coverage gate:replay-oracle (under search)
  Phase 7  Package+perf+e2e AOS packaging, performance, acceptance   gate:perf-bench, gate:e2e-determinism (acceptance)
```

Cross-cutting throughout: `T-STD-*` (engineering standards / harness-lint) apply
from the first line of code; `T-PAT-*` are realized inside the area tasks that
cite them; `T-ARCH-*` (workspace + layer skeleton) and `T-CRATE-*` land at the
very start of Phase 1.

---

## Phase 0 — De-risk (spikes)

**Goal.** Resolve the assumptions that can invalidate or reshape the design
*before* committing to it (G-5). These are cheap experiments, not production code.

**Tasks.** `T-RISK-1 … T-RISK-16` ([`30-risks-spikes.md`](30-risks-spikes.md)).

**Blockers (must pass to leave Phase 0):** the four foundational spikes —
S1 single-VM bit-identical execution under `-icount` + entropy elimination;
S2 guest HLTs during blocking I/O (else fast-forward is perf-only);
S4 producer→consumer shmem visibility is icount-not-wall-clock (Contract B);
S3 `savevm`/`loadvm` completeness (else fat checkpoints fall back to thin/replay).

**Exit gate.** All Phase-0 blocker spikes report PASS (or a documented fallback
adopted and the affected requirements amended). S1 failing with no path is a
stop-the-RFC event.

---

## Phase 1 — Determinism core, harness, and the test double

**Goal.** Build the pure-Rust deterministic substrate and prove it — *before any
QEMU*. This is where the determinism contract, the harness, the gate catalog, the
in-process test double, the content-addressed store, and the decision/time model
all land and are gated. Everything later is built on this.

**Tasks.**
- Workspace + layer skeleton: `T-ARCH-1 … T-ARCH-5` ([`03`](03-architecture-overview.md)), `T-CRATE-1 … T-CRATE-15` ([`27`](27-crate-structure.md)).
- Engineering standards + harness-lint: `T-STD-1 … T-STD-13` ([`28`](28-engineering-standards.md)).
- Determinism contract mechanisms: `T-DET-1 … T-DET-28` ([`04`](04-determinism-contract.md)).
- Time / icount model: `T-TIME-1 … T-TIME-8` ([`09`](09-virtual-time-icount.md)).
- Execution model (Configuration/step/instantiate, decision RNG): `T-EXEC-1 … T-EXEC-25` ([`05`](05-execution-model.md)).
- Temporal graph + content-addressed store (engine-independent parts): `T-TEMP-1 … T-TEMP-11` ([`07`](07-temporal-graph.md)).
- Harness, gate catalog, in-process QEMU double, fingerprint, divergence bisector: `T-HARN-1 … T-HARN-26` ([`24`](24-determinism-harness-testing.md)).
- Patterns realized here: `T-PAT-1, T-PAT-4, T-PAT-5, T-PAT-6, T-PAT-9` ([`29`](29-patterns-and-sketches.md)).

**Exit gates.** `gate:harness-lint`, `gate:layer0-determinism`,
`gate:content-address`, `gate:replay-oracle` (against the test double),
`gate:single-vm-fingerprint` (against the test double), `gate:divergence-bisect`.

---

## Phase 2 — Transport ABI and per-VM QEMU determinism

**Goal.** Stand up the co-simulation transport as a versioned ABI, the QEMU patch
series (inert-by-default), and the host+plugin integration, and prove **Contract
A** (one real VM, bit-identical) on real QEMU.

**Tasks.**
- Shmem ABI: `T-SHM-1 … T-SHM-21` ([`13`](13-shmem-abi.md)).
- Protocol: `T-PROTO-1 … T-PROTO-11` ([`14`](14-protocol.md)).
- QEMU patch series + rebase pipeline + inertness: `T-PATCH-1 … T-PATCH-20` ([`11`](11-qemu-patches.md)).
- Host QEMU integration: `T-QEMU-1 … T-QEMU-14` ([`10`](10-qemu-integration.md)).
- In-VM plugin: `T-PLUG-1 … T-PLUG-23` ([`12`](12-qemu-plugin.md)).
- Patterns realized here: `T-PAT-3, T-PAT-8` ([`29`](29-patterns-and-sketches.md)).

**Exit gates.** `gate:abi-conformance`, `gate:qemu-inert`, `gate:patch-microtests`,
`gate:single-vm-fingerprint` (real QEMU — Contract A proven), `gate:any-guest`
(an unmodified guest boots deterministically, no image mutation).

---

## Phase 3 — Scheduling, I/O sub-nodes, and cross-VM determinism

**Goal.** The single authoritative scheduler and the I/O sub-nodes, proving
**Contract B** (cross-node injection is icount-deterministic) and liveness.

**Tasks.**
- Scheduler: `T-SCHED-1 … T-SCHED-30` ([`08`](08-scheduling.md)).
- I/O sub-nodes (disk/9p/net as scheduled completion events): `T-IO-1 … T-IO-16` ([`15`](15-io-subnodes.md)).
- Patterns realized here: `T-PAT-2` ([`29`](29-patterns-and-sketches.md)).

**Exit gates.** `gate:layer1-injection` (Contract B), `gate:scheduler-liveness`,
`gate:adversarial-determinism` (a 2-VM scenario byte-identical under hostile host
conditions).

---

## Phase 4 — Engine: scenarios, faults, assertions, log, channel

**Goal.** The L3 engine: the scenario model, the full temporal graph, fault
injection, the property/assertion layer, the unified event log, and the
guest↔host channel (black-box default + optional white-box).

**Tasks.**
- Spatial graph (ScenarioDef): `T-SPAT-1 … T-SPAT-21` ([`06`](06-spatial-graph.md)).
- Temporal graph (CoW, thin/fat, GC, search-reduction): remaining `T-TEMP-*` beyond Phase 1.
- Conditions, triggers, and the event graph (the shared observable-condition predicate vocabulary + trigger graph + validator): `T-TRIG-1 … T-TRIG-20` ([`17a`](17a-conditions-and-triggers.md)).
- Faults (as trigger actions; the time-scheduled Plan lowers to `At`-triggered events): `T-FAULT-1 … T-FAULT-16` ([`17`](17-fault-injection.md)).
- Assertions / properties (incl. offline checker): `T-ASRT-1 … T-ASRT-16` ([`18`](18-assertions-properties.md)).
- Unified event log: `T-OBS-1 … T-OBS-13` ([`19`](19-observability-event-log.md)).
- Guest↔host channel + optional agent: `T-GHC-1 … T-GHC-15` ([`16`](16-guest-host-channel.md)).
- Workload / traffic-generation story (in-guest, seeded via the entropy boundary): `T-WL-1 … T-WL-6` ([`33`](33-examples-and-workloads.md)).
- Patterns realized here: `T-PAT-4, T-PAT-7` ([`29`](29-patterns-and-sketches.md)).

**Exit gates.** `gate:replay-oracle` (full, fat checkpoints over real backends),
`gate:e2e-determinism` (against the mock/double backend end to end).

---

## Phase 5 — Control plane, API, CLI

**Goal.** The session actor and the surfaces over it; responsive control with no
long-held locks.

**Tasks.**
- Session actor + backend trait + breakpoints: `T-SESS-1 … T-SESS-15` ([`20`](20-session-control-plane.md)).
- API (RPC + in-process client + conformance suite): `T-API-1 … T-API-14` ([`21`](21-api.md)).
- CLI: `T-CLI-1 … T-CLI-16` ([`23`](23-cli.md)).
- Patterns realized here: `T-PAT-1, T-PAT-6` (state machine + backend, finalized).

**Exit gate.** `gate:control-responsive` (a control op is acknowledged within a
bounded number of quanta, under a long-running step).

---

## Phase 6 — Advanced exploration

**Goal.** Fork, save/resume, state-space search, coverage-guided fuzzing — built
strictly on the now-green determinism + oracle-validated snapshot/restore (G-6).

**Tasks.** `T-ADV-1 … T-ADV-16` ([`22`](22-advanced-features.md)).

**Exit gate.** `gate:replay-oracle` continues to hold under active search (forks
and restores validated continuously), and reproduction artifacts replay
bit-identically.

---

## Phase 7 — Packaging, performance, acceptance

**Goal.** Ship it inside AOS, hit the performance targets, and pass the final
acceptance gate.

**Tasks.**
- AOS packaging (hermetic, patched QEMU pkg, fixtures, CI wiring, ratchet seam): `T-PKG-1 … T-PKG-20` ([`26`](26-packaging-aos-integration.md)).
- Performance: `T-PERF-1 … T-PERF-26` ([`25`](25-performance-targets.md)).
- Worked example scenarios as CI fixtures (happy path, partition-recovery, crash/restart, fault campaign, determinism check): `T-EX-1 … T-EX-5` ([`33`](33-examples-and-workloads.md)). These double as the `gate:e2e-determinism` corpus.
- Open-decision spikes that gate release: `T-D-1 … T-D-3` ([`31`](31-decision-register.md)).

**Exit gates.** `gate:perf-bench` (cost-model metrics meet baselines, no
regression), `gate:e2e-determinism` (final acceptance: a representative multi-VM,
fault-injected scenario runs bit-identically across adversarial host conditions
and reproduces from its self-contained artifact). When this is green and the
coverage check below is empty, Crucible is at the target state of this RFC
([`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md) §Acceptance).

---

## Requirement coverage ([PLAN-2])

Every normative `MUST` MUST be satisfied by at least one task. Coverage is
maintained two ways:

1. **By construction.** Every task in every topic file's checklist names the
   requirement IDs it satisfies (`— satisfies [X-n] …`). Every requirement names
   the gate that enforces it. The areas and their counts:

   ```text
   area   reqs  tasks    area   reqs  tasks    area   reqs  tasks
   PLUG    49    23      OBS    35    13       SESS   29    15
   SCHED   43    30      GHC    35    15       ASRT   29    16
   QEMU    42    14      IO     34    16       PERF   26    26
   PATCH   42    20      HARN   34    26       CLI    25    16
   DET     42    28      TIME   33     8       RISK   24    16
   PKG     38    20      STD    33    13       PROTO  24    11
   SHM     35    21      SPAT   33    21       CRATE  18    15
   SPAT*   ...                                  PAT    12     9
   ADV     32    16      FAULT  32    16       ARCH    9     5
   EXEC    32    25      API    31    14       TEMP   30    11
   ```

2. **By an automated coverage check** (`T-DOC-cov`, below): a doc lint parses
   every `**[X-n]**` requirement and every `**T-X-n**` task across the RFC and
   reports (a) any `MUST` requirement with no satisfying task, and (b) any task
   citing a non-existent requirement ID. **This report MUST be empty** for the
   RFC to be considered internally complete. The same lint enforces [PLAN-3]
   (per-file checklist task IDs/text match this plan) and the gate-name
   consistency (every `gate:*` referenced is in the [`24`](24-determinism-harness-testing.md) catalog).

## Implementation checklist (this file's own tasks)

- [ ] **T-PLAN-1** Implement the RFC coverage/consistency doc-lint: every `MUST`
  requirement has ≥1 satisfying task; every task cites existing requirement IDs;
  every `gate:*` is in the 24 catalog; per-file checklists match this plan; and no
  banned names (prior internal exploration / third-party commercial products)
  appear in the RFC or Crucible code/comments/docs. Wire it as a CI doc check. —
  satisfies [PLAN-1], [PLAN-2], [PLAN-3], [CONV-1]; spec §coverage.
- [ ] **T-PLAN-2** Keep the per-file checklist copies in sync with this plan's
  ordering (the lint from T-PLAN-1 fails on drift). — satisfies [PLAN-3]; spec §"How to use".
- [ ] **T-PLAN-3** Maintain the phase-gate wiring: each phase's exit gate (24) is
  a CI target that blocks the next phase. — satisfies [PLAN-4], [G-5]; spec §"The phase ladder".
