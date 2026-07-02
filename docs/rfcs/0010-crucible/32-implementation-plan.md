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
  full task text and its requirement back-references. The checklist sync digest
  below makes any drift in the ordered task text fail the doc lint.
- Task IDs are area-scoped and stable (`T-<AREA>-n`, [`00-conventions.md`](00-conventions.md)).
  Re-sequencing a task here never renumbers it.
- **[PLAN-4] holds**: no task depends on a later-phase task. The ordering is
  *foundation-first* — determinism, the harness, the transport ABI, and
  control-plane correctness precede everything built on them (G-5).
- **Multi-vCPU determinism (G-10)** is part of the determinism foundation: it
  lands in Phases 2–3 (single-threaded RR-TCG + icount, then RR sub-division in
  the scheduler), so `gate:single-vm-fingerprint` covers N-vCPU before anything
  exploratory runs. **Interleaving, guided/adaptive, distributed, triage, and
  time-travel debugging exploration (Phases 6–7)** are built strictly on the
  green determinism + oracle-validated save/restore foundation (G-5 and the
  dependency ladder in [`22`](22-advanced-features.md)).
- A phase is **done** when all its tasks are checked and its **exit gate** (24)
  is green. Do not start a phase before the prior phase's gate is green.

## Inventory

The plan covers **566 tasks** across 36 areas, satisfying **1079 numbered
requirements** (plus the goal/non-goal/invariant/decision IDs). Coverage is
**complete**: every defined requirement is cited by at least one checklist task,
and no task cites a non-existent requirement (verified by the `T-PLAN-1` lint).
Task counts by area:

```text
SCHED 30  DET 31  PERF 28  PLUG 27  PATCH 24  PKG 23  HARN 26  SPAT 21  ADV 21
EXEC 20  TRIG 20  RISK 20  ASRT 18  CLI 18  GHC 17  FAULT 16  IO 16  QEMU 16
SHM 16  CRATE 15  API 14  OBS 14  SESS 13  STD 13  TEMP 11  PROTO 11  DCE 10
TIME 9  PAT 9  TRI 8  DBG 8  WL 6  ARCH 5  EX 5  D 4  PLAN 3
```

Checklist sync digest: `rfc0010-checklist-v1:b5bb6bec8fcf4c1a`

## The phase ladder

```text
  Phase 0  De-risk          spikes that can reshape the design       gate: Phase-0 blockers pass
  Phase 1  Determinism core L0 runtime, decision RNG, time, harness  gate:harness-lint, gate:layer0-determinism,
                            content-addressed store, the test double        gate:content-address, gate:replay-oracle (sim),
                                                                            gate:single-vm-fingerprint (double), gate:divergence-bisect
  Phase 2  Transport+QEMU   shmem ABI, protocol, patch series,       gate:abi-conformance, gate:layer1-injection,
                            host QEMU + plugin, single-VM determinism       gate:patch-microtests, gate:qemu-inert,
                                                                            gate:single-vm-fingerprint (real QEMU)
  Phase 3  Scheduling+I/O   scheduler, I/O sub-nodes, cross-VM        gate:layer1-injection, gate:scheduler-liveness,
                            injection determinism                           gate:adversarial-determinism (2-VM)
  Phase 4  Engine           spatial+temporal graph, faults,           gate:replay-oracle (full), gate:e2e-determinism (mock)
                            assertions, event log, guest-host channel
  Phase 5  Control plane    session actor, API, CLI, daemon          gate:control-responsive
  Phase 6  Exploration      fork, save/resume, search, fuzz, coverage gate:replay-oracle (under search)
  Phase 7  Package+perf+e2e AOS packaging, performance, acceptance   gate:perf-bench, gate:e2e-determinism (acceptance),
                                                                            gate:fleet-equivalence, gate:campaign-continuity
```

Cross-cutting throughout: `T-STD-*` (engineering standards / harness-lint) apply
from the first line of code; `T-PAT-*` are realized inside the area tasks that
cite them; `T-ARCH-*` (workspace + layer skeleton) and `T-CRATE-*` land at the
very start of Phase 1.

---

## Phase 0 — De-risk (spikes)

**Goal.** Resolve the assumptions that can invalidate or reshape the design
*before* committing to it (G-5). These are cheap experiments, not production code.

**Tasks.** `T-RISK-1 … T-RISK-20` ([`30-risks-spikes.md`](30-risks-spikes.md)). The
later set `T-RISK-17 … T-RISK-20` de-risks the multi-vCPU goal: single-threaded
RR-TCG + icount determinism, `Decision::Preemption` interleaving, the RR quantum
boundary, and the gdbstub seam for time-travel debugging.

**Blockers (must pass to leave Phase 0):** the four foundational spikes —
S1 single-VM bit-identical execution under `-icount` + entropy elimination;
S2 guest HLTs during blocking I/O (else fast-forward is perf-only);
S4 producer→consumer shmem visibility is icount-not-wall-clock (Contract B);
S3 `savevm`/`loadvm` completeness (else fat checkpoints fall back to thin/replay).
**S11 (single-threaded RR-TCG + icount is bit-identical for multi-vCPU) is a
blocker for the multi-vCPU goal G-10**; if it fails with no path, G-10 falls back
to single-vCPU per VM.

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
- Determinism contract mechanisms (incl. the pure multi-vCPU and app-random
  determinism tasks `T-DET-29 … T-DET-31`): `T-DET-1 … T-DET-31` ([`04`](04-determinism-contract.md)).
- Time / icount model: `T-TIME-1 … T-TIME-9` ([`09`](09-virtual-time-icount.md)).
- Execution model (Configuration/step/instantiate, decision RNG; the `Decision`
  taxonomy extensions `T-EXEC-19` `Preemption` + `T-EXEC-20` `AppRandom`): `T-EXEC-1 … T-EXEC-20` ([`05`](05-execution-model.md)).
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
A** (one real VM, bit-identical) on real QEMU — including **deterministic
multi-vCPU (RR-TCG)**, where a single-threaded round-robin TCG core under icount
makes an N-vCPU guest bit-identical (G-10).

**Tasks.**
- Shmem ABI (incl. the multi-vCPU ABI task `T-SHM-16`): `T-SHM-1 … T-SHM-16` ([`13`](13-shmem-abi.md)).
- Protocol: `T-PROTO-1 … T-PROTO-11` ([`14`](14-protocol.md)).
- QEMU patch series + rebase pipeline + inertness (incl. the RR-TCG/multi-vCPU
  patches `T-PATCH-21 … T-PATCH-24`): `T-PATCH-1 … T-PATCH-24` ([`11`](11-qemu-patches.md)).
- Host QEMU integration (incl. the multi-vCPU tasks `T-QEMU-15, T-QEMU-16`): `T-QEMU-1 … T-QEMU-16` ([`10`](10-qemu-integration.md)).
- In-VM plugin (incl. the per-vCPU plugin tasks `T-PLUG-24 … T-PLUG-27`): `T-PLUG-1 … T-PLUG-27` ([`12`](12-qemu-plugin.md)).
- Patterns realized here: `T-PAT-3, T-PAT-8` ([`29`](29-patterns-and-sketches.md)).

**Exit gates.** `gate:abi-conformance`, `gate:layer1-injection` (L1 injection
preflight before L2 gates), `gate:patch-microtests`, `gate:qemu-inert`,
`gate:single-vm-fingerprint` (real QEMU — Contract A proven, now covering an
N-vCPU guest), `gate:any-guest` (an unmodified guest boots deterministically, no
image mutation).

---

## Phase 3 — Scheduling, I/O sub-nodes, and cross-VM determinism

**Goal.** The single authoritative scheduler and the I/O sub-nodes, proving
**Contract B** (cross-node injection is icount-deterministic) and liveness. This
is also where **concurrency-interleaving determinism** is proven: the scheduler's
RR sub-division and the applied `Decision::Preemption` make a chosen vCPU
interleaving exactly reproducible.

**Tasks.**
- Scheduler (incl. RR sub-division, applying `Decision::Preemption`, and the
  all-vCPUs-idle handling `T-SCHED-28 … T-SCHED-30`): `T-SCHED-1 … T-SCHED-30` ([`08`](08-scheduling.md)).
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
- Assertions / properties (incl. offline checker and assertion-proximity `T-ASRT-18`): `T-ASRT-1 … T-ASRT-18` ([`18`](18-assertions-properties.md)).
- Unified event log (incl. the proximity projection `T-OBS-14`): `T-OBS-1 … T-OBS-14` ([`19`](19-observability-event-log.md)).
- Guest↔host channel + optional agent (incl. the app-controlled randomness
  channel `T-GHC-16, T-GHC-17` — the optional white-box `Decision::AppRandom`
  source): `T-GHC-1 … T-GHC-17` ([`16`](16-guest-host-channel.md)).
- Workload / traffic-generation story (in-guest, seeded via the entropy boundary): `T-WL-1 … T-WL-6` ([`33`](33-examples-and-workloads.md)).
- Patterns realized here: `T-PAT-4, T-PAT-7` ([`29`](29-patterns-and-sketches.md)).

**Exit gates.** `gate:replay-oracle` (full, fat checkpoints over real backends),
`gate:e2e-determinism` (against the mock/double backend end to end).

---

## Phase 5 — Control plane, API, CLI

**Goal.** The session actor and the surfaces over it; responsive control with no
long-held locks.

**Tasks.**
- Session actor + backend trait + breakpoints (incl. the debug/time-travel
  control commands `T-SESS-13`): `T-SESS-1 … T-SESS-13` ([`20`](20-session-control-plane.md)).
  `T-SESS-1` is green through `checks.crucible.phase5.sessionActor`, which
  proves the live actor owns `Engine<L>` by value, keeps the actor mailbox as
  the only live-session mutation path, owns the event-log writer, carries the
  actor-owned breakpoint set, and gates against a locked/shared actor engine.
  `T-SESS-3` is green through `checks.crucible.phase5.sessionLifecycle`, which
  adds the closed lifecycle, pause-reason, outcome, and full §4 command-kind
  lifecycle model, proves the pure transition table is total and non-wedging for
  generated representative command streams, and checks realized model/engine
  pairs with typed, side-effect-free rejections.
- API (RPC + in-process client + conformance suite): `T-API-1 … T-API-14` ([`21`](21-api.md)).
- CLI (incl. the triage + debug subcommands `T-CLI-17, T-CLI-18`): `T-CLI-1 … T-CLI-18` ([`23`](23-cli.md)).
- Patterns realized here: `T-PAT-1, T-PAT-6` (state machine + backend, finalized).

**Exit gate.** `gate:control-responsive` (a control op is acknowledged within a
bounded number of quanta, under a long-running step).

---

## Phase 6 — Advanced exploration

**Goal.** Fork, save/resume, state-space search, coverage-guided fuzzing — built
strictly on the now-green determinism + oracle-validated snapshot/restore (G-6),
extended with guided/adaptive search, concurrency-interleaving exploration via
`Decision::Preemption` (G-11), app-random search, time-travel debugging, and
failure triage. Every capability here rides the green determinism + save/restore
foundation (the dependency ladder in [`22`](22-advanced-features.md)).

**Tasks.**
- Advanced features — fork/save/resume/search/fuzz plus guided/adaptive
  (pluggable signals + bandit), interleaving, and app-random search
  (`T-ADV-17 … T-ADV-21`): `T-ADV-1 … T-ADV-21` ([`22`](22-advanced-features.md)).
- Time-travel debugging (built on the checkpoint DAG + replay): `T-DBG-1 … T-DBG-8` ([`36`](36-time-travel-debugging.md)).
  `T-DBG-1` is green through `checks.crucible.phase6.debugAttach`; `T-DBG-2`
  is green through `checks.crucible.phase6.readOnlyDebugInspection`, which proves
  read-only debugger observations do not alter config, virtual time, or the
  canonical causal event-log subsequence; `T-DBG-3` is green through
  `checks.crucible.phase6.canonicalDebugBreakpoint`, which refuses memory-patch-only
  canonical breakpoints and transparently maps software breakpoint requests to
  out-of-band mechanisms when available; `T-DBG-4` is green through
  `checks.crucible.phase6.debugTimeTravel`, which proves debug `goto` uses
  restore-nearest-checkpoint-then-replay, reverse-step mirrors the forward
  `StepMode` set, and reverse-continue resolves the latest prior 17a condition
  coordinate through the same replay-oracle-checked path; `T-DBG-5` is green
  through `checks.crucible.phase6.debugScopedTimeTravel`, which proves per-node
  exact-icount travel leaves other nodes untouched, whole-world travel lands at a
  prefix/fork-minus-divergence coordinate, and `--checkpoint-stride` remains a
  performance-only cache cadence, including safe fat eviction, defaulting to
  thin/replay until S3 is green; `T-DBG-6` is green through
  `checks.crucible.phase6.debugNonCanonicalBranch`, which proves mutating/operator-
  controlled debugging records a visibly non-canonical branch from the instantiated
  attach runtime, preserves the canonical graph and canonical-run causal log, emits a
  causal catalog-kind `fork` marker flagged non-canonical, excludes the branch from
  replay-oracle and `(seed, scenario, schedule)` artifacts, and stores arbitrary guest
  edits only in a never-model-reproducible debug-edit script; `T-DBG-7` is green
  through `checks.crucible.phase6.debugTargetResolver`, which resolves `--at`,
  `--at-event`, `--at-failure`, `--at-checkpoint`, and divergence-bisection targets
  into replay-checked debug `goto` requests and centralizes the copy-pasteable
  `crucible debug <artifact> --at-failure` failure footer command; `T-DBG-8`/`T-CLI-18`
  are green through `checks.crucible.phase6.debugCliSurface`, which implements the
  `crucible debug` parser and planner as a stateless session/debugger wrapper over
  target-aware coordinate defaults, target resolution, session query/snapshot/fork
  commands, debug reverse-step/goto restore-plus-replay operations, the mediated
  gdbstub proxy, read-only default inspection, explicit non-canonical mutation
  branches, no-symbol-server ownership, coherent multi-vCPU gdb threads, and
  disabled raw gdb single-step until the S14 spike is green.
- Failure triage: `T-TRI-1` is green through `checks.crucible.phase6.failureSignature`,
  which implements the recorded-run-only `FailureSignature` tuple for property
  violations and divergence bisection points, binds checked event-log projection
  metadata, recorded coverage fingerprints, and violation records to the same
  reproduction artifact, derives coverage classes from those metadata-bound
  deterministic coverage fingerprints, and omits discovery campaign/finding-
  fingerprint state from the signature. `T-TRI-2` is green through
  `checks.crucible.phase6.failureNormalization`, which makes absolute icount
  report-only, applies symmetry-canonical `faulting_node` relabeling, and hashes
  only the normalized causal cone for `causal_slice_hash`. `T-TRI-3` is green
  through `checks.crucible.phase6.signaturePolicy`, which provides the closed,
  versioned coarse/default/fine/exact `SignaturePolicy`, policy-projected
  signature keys, exact-policy full-cone/absolute-icount keying, and triage
  result identity keyed by findings ledger plus policy. `T-TRI-4` is green
  through `checks.crucible.phase6.failureClustering`, which partitions findings
  by policy signature key, uses the key hash as the cluster id, and emits
  content-address ordered clusters and members. `T-TRI-5` is green through
  `checks.crucible.phase6.signaturePreservingMinimization`, which minimizes the
  content-address-least representative of each cluster through the existing
  replay-validated minimization pass while strengthening the accept predicate to
  active-policy signature-key equality. `T-TRI-6` is green through
  `checks.crucible.phase6.perClusterReports`, which emits content-addressed
  per-cluster reports binding the full signature, ordered member hashes, minimal
  representative, failing property or bisected first-diff detail, minimal
  reproduction tuple, causal-log excerpt, causal-cone narrative, and exact replay
  command through deterministic `json`, `jsonl`, `table`, and `markdown`
  renderings. `T-TRI-7` is green through
  `checks.crucible.phase6.triageThinDriver`, which adds content-addressed
  findings ledgers and triage result artifacts, DagStore dedup/cache-hit
  storage, per-finding offline signature recompute self-check records, content
  diffs for `--compare`, and a thin `crucible triage <findings>` runner that
  opens the local DagStore, loads stored/path ledgers, executes the
  cluster→minimize-representative→emit→store pipeline for representable
  discovery-signature evidence, and rejects bare non-empty artifact-only ledgers
  instead of fabricating signatures. `T-TRI-8` is green through
  `checks.crucible.phase6.triageCliSurface`, which resolves the forward
  reference into 23 by keeping `triage` in the closed subcommand set, aligning
  the user-facing help copy for `--policy`, `--minimize`, `--report`, global
  `--format`, `--recompute-signatures`, and `--compare`, and testing the
  uniform triage exit-code surface ([`34`](34-failure-triage.md)).

**Exit gate.** `gate:replay-oracle` continues to hold under active search (forks
and restores validated continuously), and reproduction artifacts replay
bit-identically.

---

## Phase 7 — Packaging, performance, acceptance

**Goal.** Ship it inside AOS, hit the performance targets, and pass the final
acceptance gate.

**Tasks.**
- AOS packaging (hermetic, patched QEMU pkg, fixtures, CI wiring, ratchet seam;
  incl. the new packaging tasks `T-PKG-21 … T-PKG-23`): `T-PKG-1 … T-PKG-23` ([`26`](26-packaging-aos-integration.md)).
- Performance (incl. the fleet-perf tasks `T-PERF-27, T-PERF-28`): `T-PERF-1 … T-PERF-28` ([`25`](25-performance-targets.md)).
- Distributed / continuous exploration (campaigns spanning a fleet of workers): `T-DCE-1 … T-DCE-10` ([`35`](35-distributed-continuous-exploration.md)).
- Worked example scenarios as CI fixtures (happy path, partition-recovery, crash/restart, fault campaign, determinism check): `T-EX-1 … T-EX-5` ([`33`](33-examples-and-workloads.md)). These double as the `gate:e2e-determinism` corpus.
- Open-decision spikes that gate release: `T-D-1 … T-D-4` ([`31`](31-decision-register.md)).

**Exit gates.** `gate:perf-bench` (cost-model metrics meet baselines, no
regression), `gate:e2e-determinism` (final acceptance: a representative multi-VM,
fault-injected scenario runs bit-identically across adversarial host conditions
and reproduces from its self-contained artifact), `gate:fleet-equivalence` (a
distributed campaign across workers reproduces a finding bit-identically off any
worker), `gate:campaign-continuity` (a continuous campaign resumes from its
persisted frontier without losing or re-deriving coverage). When this is green and the
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
   PLUG    52    27      OBS    37    14       PERF   28    28
   SCHED   47    30      GHC    38    17       CLI    27    18
   QEMU    43    16      IO     34    16       RISK   28    20
   PATCH   47    24      HARN   34    26       PROTO  24    11
   DET     44    31      TIME   35     9       CRATE  18    15
   PKG     45    23      STD    33    13       PAT    12     9
   SHM     37    16      SPAT   33    21       ARCH    9     5
   ADV     40    21      FAULT  34    16       TEMP   30    11
   EXEC    34    20      API    31    14       TRIG   32    20
   DBG     40     8      ASRT   33    18       TRI    19     8
   DCE     33    10      SESS   33    13       WL     12     6
                                               EX      3     5
   ```

2. **By an automated coverage check** (`T-DOC-cov`, below): a doc lint parses
   every `**[X-n]**` requirement and every `**T-X-n**` task across the RFC and
   reports (a) any `MUST` requirement with no satisfying task, and (b) any task
   citing a non-existent requirement ID. **This report MUST be empty** for the
   RFC to be considered internally complete. The same lint enforces the gate-name
   consistency (every `gate:*` referenced is in the [`24`](24-determinism-harness-testing.md)
   catalog), banned-name policy, and task-inventory/file-ownership consistency.
   The [PLAN-3] sync lint also verifies each topic checklist's order against this
   plan's phase-order projection and compares the ordered task text to the
   checklist sync digest above.

## Implementation checklist (this file's own tasks)

- [x] **T-PLAN-1** Implement the RFC coverage/consistency doc-lint: every `MUST`
  requirement has ≥1 satisfying task; every task cites existing requirement IDs;
  every `gate:*` is in the 24 catalog; per-file checklist task IDs have known
  ownership and are present in the phase inventory; and no banned names (prior
  internal exploration / third-party commercial products) appear in the RFC or
  Crucible code/comments/docs. Wire it as a CI doc check. — satisfies [PLAN-1],
  [PLAN-2], [CONV-1]; spec §coverage.
- [x] **T-PLAN-2** Keep the per-file checklist copies in sync with this plan's
  ordering: the doc lint fails if a topic checklist's task order differs from the
  master phase-order projection or if the ordered task-text digest drifts. —
  satisfies [PLAN-3]; spec §"How to use".
- [x] **T-PLAN-3** Maintain the phase-gate wiring: each phase's exit gate (24) is
  a CI target that blocks the next phase. — satisfies [PLAN-4], [G-5]; spec §"The phase ladder".
