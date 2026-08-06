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

The plan covers **592 tasks** across 37 areas, satisfying **1094 numbered
requirements** (plus the goal/non-goal/invariant/decision IDs). Coverage is
**complete**: every defined requirement is cited by at least one checklist task,
and no task cites a non-existent requirement (verified by the `T-PLAN-1` lint).
Task counts by area:

```text
PERF 34  DET 31  SCHED 30  HARN 28  PLUG 27  PATCH 24  PKG 23  ADV 21  SPAT 21
CLI 20  EXEC 20  RISK 20  TRIG 20  SHM 19  ASRT 18  GHC 17  CRATE 16  FAULT 16
IO 16  QEMU 16  API 14  DBG 14  OBS 14  SESS 14  STD 14  PROTO 11  TEMP 11
DCE 10  PAT 9  TIME 9  TRI 8  WL 6  ARCH 5  EX 5  BOUND 4  D 4  PLAN 3
```

Checklist sync digest: `rfc0010-checklist-v1:216f8037ca38a7c6`

### Adversarial completion audit (2026-07-09)

The checklist state is authoritative. An adversarial source-and-gate audit
reopened tasks whose checked evidence proved only a model, a structural source
needle, an inert callback scaffold, or identity-labelled QEMU selection rather
than the normative live behavior. In particular, the shipped plugin install
path is still inert; the production CLI's QEMU routes do not yet execute the
selected QEMU backend; scheduler RR/preemption and device sub-nodes are not
connected to live nodes; ordinary replay reconstructs embedded evidence instead
of re-executing it; and the Phase-7 e2e/performance/fleet checks explicitly run
the in-process double or modeled metrics. A "Completed by" paragraph under an
unchecked item records useful partial implementation and test coverage only; it
does not discharge that task. Re-close an item only after its full task text is
implemented and an adversarial review confirms the gate exercises that behavior.

## The phase ladder

```text
  Phase 0  De-risk          spikes that can reshape the design       gate: Phase-0 blockers pass
  Phase 1  Determinism core L0 runtime, decision RNG, time, harness  gate:harness-lint, gate:license-boundary,
                            licensing boundary                            gate:layer0-determinism,
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
- Workspace + layer skeleton: `T-ARCH-1 … T-ARCH-5` ([`03`](03-architecture-overview.md)), `T-CRATE-1 … T-CRATE-16` ([`27`](27-crate-structure.md)).
- Engineering standards + harness-lint: `T-STD-1 … T-STD-14` ([`28`](28-engineering-standards.md)).
- Licensing and process boundary: `T-BOUND-1 … T-BOUND-4`
  ([`37`](37-licensing-process-boundary.md)).
- Determinism contract mechanisms (incl. the pure multi-vCPU and app-random
  determinism tasks `T-DET-29 … T-DET-31`): `T-DET-1 … T-DET-31` ([`04`](04-determinism-contract.md)).
- Time / icount model: `T-TIME-1 … T-TIME-9` ([`09`](09-virtual-time-icount.md)).
- Execution model (Configuration/step/instantiate, decision RNG; the `Decision`
  taxonomy extensions `T-EXEC-19` `Preemption` + `T-EXEC-20` `AppRandom`): `T-EXEC-1 … T-EXEC-20` ([`05`](05-execution-model.md)).
- Temporal graph + content-addressed store (engine-independent parts): `T-TEMP-1 … T-TEMP-11` ([`07`](07-temporal-graph.md)).
- Harness, gate catalog, in-process QEMU double, fingerprint, divergence bisector: `T-HARN-1 … T-HARN-28` ([`24`](24-determinism-harness-testing.md)).
- Patterns tracked here: `T-PAT-1, T-PAT-4, T-PAT-5, T-PAT-6, T-PAT-9`;
  the backend pattern is completed by the phase-5 backend and SimDouble suite
  ([`29`](29-patterns-and-sketches.md)).

**Exit gates.** `gate:harness-lint`, `gate:license-boundary`, `gate:layer0-determinism`,
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
- Shmem ABI (incl. the multi-vCPU, coverage-ring, white-box marker-ring, and
  preemption-mailbox ABI tasks `T-SHM-16 … T-SHM-19`):
  `T-SHM-1 … T-SHM-19`
  ([`13`](13-shmem-abi.md)).
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
  control commands `T-SESS-13`): `T-SESS-1 … T-SESS-14` ([`20`](20-session-control-plane.md)).
  `T-SESS-1` is green through `checks.crucible.phase5.sessionActor`, which
  proves the live actor owns `Engine<L>` by value, keeps the actor mailbox as
  the only live-session mutation path, owns the event-log writer, carries the
  actor-owned breakpoint set, and gates against a locked/shared actor engine.
  `T-SESS-3` is green through `checks.crucible.phase5.sessionLifecycle`, which
  adds the closed lifecycle, pause-reason, outcome, and full §4 command-kind
  lifecycle model, proves the pure transition table is total and non-wedging for
  generated representative command streams, and checks realized model/engine
  pairs with typed, side-effect-free rejections.
  `T-SESS-4` is green through `checks.crucible.phase5.sessionCommandSet`, which
  adds reply-bearing command payloads for fault injection/healing,
  breakpoint insert/remove, savepoints, fork, and query, maps them into the
  session engine, scheduler control queue, and temporal graph, and verifies
  successful and rejected oneshot replies.
  `T-SESS-5` is green through `checks.crucible.phase5.sessionStepModes`, which
  adds engine-owned active-step state for quantum/event/assertion/timer/duration
  forward steps, pauses only at deterministic event-log or virtual-time stop
  points, and verifies pause/stop interruption between bounded quanta.
  `T-SESS-6` is green through `checks.crucible.phase5.sessionBoundaryControl`,
  which records accepted running boundary commands in a deterministic
  frontier/quanta-keyed session control log, verifies scheduler-backed control
  delivery and stopped-state terminal drain, and checks pause/stop take effect
  at the boundary without an extra quantum while stop invokes shutdown.
  `T-SESS-7` is completed by `checks.crucible.phase5.sessionBreakpoints`,
  which evaluates actor-owned breakpoints through the shared 17a condition
  prefix/evaluator, threads scheduler quiescence evidence into session
  breakpoint evaluation including every no-entry quantum boundary, records
  deterministic firing entries and action scheduler controls, verifies
  suspend/trace/action and OneShot/Repeatable behavior including persistent
  `Once` latches, derives `After`/`Timer` facts from the canonical trigger log,
  rejects unsupported or unrepresentable action breakpoints before applying
  scheduler controls, and evaluates step stop points through one-shot breakpoint
  conditions. Its session-visible `BreakpointHostMetadata` supplies
  virtual-time-keyed `Named` truths plus resolved code/memory symbols, and that
  metadata is inherited across resume and fork.
  `T-SESS-8` is green through `checks.crucible.phase5.sessionSaveResumeFork`,
  which keeps save/resume/fork on the temporal graph: savepoint materialization
  uses `save_checkpoint`, checkpoint resume resolves the recorded configuration
  through `resume_checkpoint`, session runtime realization goes through
  `TemporalGraph::resume`, fork commands can spawn independent children through
  an actor fork-loop factory, and fork-from-checkpoint creates an independent
  paused child actor without mutating the parent snapshot.
  `T-SESS-9` is green through `checks.crucible.phase5.sessionControlDeterminism`,
  which applies and logs inject/heal controls at running and paused boundaries,
  captures `SessionControlReplayArtifact` records keyed by virtual
  frontier/quanta plus scheduler-control batch, and replays them with
  boundary/final-snapshot mismatch guards so scheduler-owned state is reproduced
  without wall-clock timing as an input.
  `T-SESS-10` is green through `checks.crucible.phase5.sessionLockFreeObservation`,
  which keeps the live status mirror in actor-written atomics, exposes
  lock-free `LiveSnapshot::read`, `LiveSnapshot::query`, and
  `SessionActor::live_status` observation, streams retained and live event-log
  entries through the bounded cursor-backed `SessionEventLog` broadcast tail,
  and streams actor-owned full `EngineState` transitions through
  `SessionStateTransitionBus` with lag-or-drop behavior instead of subscriber
  back-pressure.
  `T-SESS-11` is completed by `checks.crucible.phase5.sessionSimulationBackend`,
  which defines the pluggable `SimulationBackend` contract, exports its
  observation/effect/snapshot/fingerprint data types, and verifies the mock,
  `SimBackend`, `SimDouble`, and QEMU `QemuNode` implementations against the
  same scheduler-supplied timing boundary, including full SimDouble
  snapshot/restore, QEMU restore-time mirror updates, and rejection of
  trait-level SimDouble outbound sends without scheduler authorization.
  `T-SESS-12` is completed by `checks.crucible.phase5.sessionSimDoubleSuite`,
  which runs the full `crucible-session` suite plus the API/daemon
  control-responsive tests under in-process `crucible::SimDouble` quantum-loop
  adapters, and runs `gate:scheduler-liveness` under `test-double` with an
  initialized and stepped `crucible::SimDouble` smoke path before the pure
  scheduler-liveness reduction. Source checks reserve real QEMU for Contract A,
  guest non-mutation, and patch inertness fidelity properties.
  `T-SESS-13` is green through `checks.crucible.phase5.sessionDebugTimeTravel`,
  which exposes the session debug command set (`attach_gdb`, `goto`,
  `reverse_step`, `reverse_continue`) over the model time-travel APIs, keeps
  debug repositioning out of the scheduler replay/control log, guards
  forward/mutating use behind a marked NON-CANONICAL branch command, and adds the
  optional backend `open_gdbstub` capability with `BackendQuantumLoop` routing to
  the live backend, QEMU binding a retained mediated listener, and SimDouble/mock
  returning typed `Unsupported`.
- API (RPC + in-process client + conformance suite): `T-API-1 … T-API-14` ([`21`](21-api.md)).
  `T-API-1` is green through `checks.crucible.phase5.apiControlClient`,
  which defines the shared async `ControlClient` trait, in-process and HTTP/2 RPC
  client handles, the `/crucible.rpc/hello` HTTP/2 negotiation path, and a shared
  `ControlWireModel` over the frozen RPC ABI encoder.
  `T-API-2` is green through `checks.crucible.phase5.apiSessionCommandMapping`,
  which freezes the thin API-to-session mapping: service methods are typed
  programmatic requests, map to session commands, lock-free mirror reads, or
  server/control-log reads, and the API command table covers
  `SessionCommandKind::ALL` exactly once.
  `T-API-3` is green through `checks.crucible.phase5.apiLifecycleUnary`, which
  implements side-effect-free discovery, scenario-ref and inline session creation
  through `SessionCommand::Start`, live-mirror session listing, and
  epoch-guarded/idempotent destroy through `SessionCommand::Stop`, exposed on the
  shared `ControlClient` trait for both in-process lifecycle and HTTP/2 RPC
  clients. Inline RPC carries scenario seed and request seed separately so the
  lifecycle mismatch guard remains transport-facing.
  `T-API-4` is green through `checks.crucible.phase5.apiStreamingEquivalence`,
  which adds the typed `Control` and `Watch`+`Send` facade, validates identical
  command capabilities from the thin mapping table, exposes the same attach/send
  paths through `ControlClient`/`RpcControlClient`, and drives lifecycle plus
  non-basic command classes from both command paths while returning
  `CommandResult` plus optional `StateUpdate`.
  `T-API-5` is green through `checks.crucible.phase5.apiOpenSetPayload`, which
  adds the dotted-kind open-set payload model, reuses the unified event-log
  catalog for event payload schemas, adapts command/fault/breakpoint kind
  sources from existing model tables, treats unknown received event kinds as
  opaque, rejects unknown or malformed send payloads with typed errors, and
  updates `Hello`/golden vectors to advertise the open-set categories.
  `T-API-6` is green through `checks.crucible.phase5.apiStreamingCursor`, which
  adds attach-tail replay metadata, log-derived snapshot summaries, API event
  frame conversion over the shared event-log stream, observational flags, and a
  cursor gate covering replay, attach-past-tail skip, pure observation, and live
  tail delivery.
  `T-API-7` is green through `checks.crucible.phase5.apiStateUpdateStream`,
  which wires `Control`/`Watch` attach to the actor state-transition bus, exposes
  monotone state-update frames separately from event-log frames, demultiplexes
  RPC `state-update-frame` messages from the shared framed stream without
  starving behind undrained event frames, and proves a Watch-only client can
  track run-state from `SendResponse` plus `StateUpdate`.
  `T-API-8` is green through `checks.crucible.phase5.apiEpochGuards`, which
  carries `expected_epoch` on attach, command, and lifecycle destroy requests,
  rejects stale session refs and expected epochs before actor dispatch, proves
  failed guards leave live state and event-log cursors unchanged, and checks
  server-monotonic epochs across creates.
  `T-API-9` is green through `checks.crucible.phase5.apiReproductionContext`,
  which publishes the session boundary-control log as a read-only reproduction
  context, exposes it through both `AttachSnapshot` and `GetReproduction`,
  includes virtual-time boundary, at-sequence, accepted result, command payload,
  and observational ordering metadata, and proves read-only retrieval, epoch
  fast-fail, attach/unary agreement, and equivalent interactive-vs-scripted
  schedules.
  `T-API-10` is green through
  `checks.crucible.phase5.apiCommandStatusTaxonomy`, which closes command
  rejections and transport errors over INVALID_STATE/NOT_FOUND/INVALID_ARGUMENT/
  UNSUPPORTED/INTERNAL, freezes the new RPC status wire vectors, and proves
  invalid commands, missing scenarios, missing sessions, and stale epochs decode
  as typed errors without stream teardown or state mutation.
  `T-API-13` is green through
  `checks.crucible.phase5.apiReferenceClientConformance`, which drives the
  reference `ControlClient` lifecycle over in-process SimDouble and an HTTP/2
  RPC server, covers scenario-ref and inline creation, both attach paths, command
  send, fault, breakpoint, savepoint, fork, `GetReproduction`, stale epoch
  rejection, destroy, idempotent destroy, and per-message RPC ABI snapshot
  coverage, and also runs the `crucible-qemu` `QemuNode`
  `SimulationBackend` contract test.
  `T-API-14` is green through `checks.crucible.phase5.apiNondeterminism`,
  which compares quiet/noisy in-process, quiet/noisy HTTP/2 RPC, and
  server-observed read-before-mutate/mutate-before-read RPC `ControlClient`
  projections for the same boundary-recorded scheduler controls, proves
  `Hello`/`List*`/`Watch`/
  `GetReproduction` and query-class traffic leave state, event-log cursor,
  causal/observational event counts, and reproduction context unchanged, compares
  a non-empty replayed causal event payload projection under quiet/noisy
  streaming observer load, and forbids wall-clock reads in the production API
  paths.
- CLI (incl. the triage + debug subcommands `T-CLI-17, T-CLI-18`): `T-CLI-1 … T-CLI-20` ([`23`](23-cli.md)).
  `T-CLI-2` is green through `checks.crucible.phase5.cliThinWrapper`, which
  enforces a pre-dispatch thin-wrapper plan for every closed subcommand, records
  the emitted session/API/driver operations, limits routed control capabilities
  to `SessionCommandKind::ALL` and actual `ControlClient` methods, treats
  CLI-held state only as daemon/content-addressed/artifact/savepoint handles, and
  rejects CLI-owned canonical state, scheduler logic, checkpoint materialization,
  fork logic, or invented control capabilities. The production-path check also
  requires resume/fork checkpoint and baked-genesis setup to delegate to
  `crucible_session::validation` and rejects direct checkpoint materialization
  in the CLI command modules.
  `T-CLI-3` is green through `checks.crucible.phase5.cliBackendSelection`, which
  records a backend-selection route for each backend-routed subcommand, sends
  `--daemon` invocations over a fakeable API command runner without local
  backend selection, resolves local `auto` through hermetic QEMU/plugin
  discovery when a valid pair is available and fails closed otherwise, omits
  the double parser variant and implementation from production builds, fails
  explicit QEMU discovery/configuration errors with exit 4, and compares recorded
  local/remote stdout/stderr, exit-code, canonical-log, and artifact projections.
  The selected local QEMU route boots the closure-owned emulator, stock AOS
  kernel/root fixture, and production plugin through the API boundary and
  records exact-icount, fingerprint, boot-barrier, and child-exit evidence.
  `T-CLI-4` is green through `checks.crucible.phase5.cliDeterminismErgonomics`,
  which resolves seed sources in explicit flag, `CRUCIBLE_SEED`, generated order
  before run-identity dispatch, prints the resolved seed unless quiet, treats
  replay/resume as artifact/savepoint-owned seed modes, threads the seed into the
  backend-routed canonical run-identity projection and failure artifacts, emits
  shell-quoted replay/debug footer commands from the artifact path, renders
  routed canonical output or `--trace` through `jsonl`/`json`/`table` from one
  event-log entry stream with `jsonl` emitted entry by entry, rejects `markdown`
  for canonical event-log traces, propagates non-passing outcomes through the
  process exit-code path after writing artifacts, and gates CLI/model/session
  canonical paths against wall-clock APIs. Failed local runs embed their exact
  compact scenario, observed canonical entries, resolved identity, and observed
  fingerprint stream rather than substituting mock gate evidence.
  `T-CLI-5` is green through `checks.crucible.phase5.cliHermeticDiscovery`,
  which resolves QEMU/plugin candidates in explicit flag,
  `CRUCIBLE_QEMU`/`CRUCIBLE_PLUGIN`, then AOS package-set order, rejects host
  `$PATH` discovery, requires the patched-QEMU sim-capability marker and matched
  plugin ABI/QEMU-build metadata, derives that plugin ABI from
  `crucible_shmem::ABI_VERSION`, fails explicit absence or mismatched candidate
  pairs with exit 4 and actionable discovery guidance, wires the packaged CLI
  with compile-time AOS store-path hints for `qemu-crucible` and
  `crucible-qemu-plugin`, and pins the selected QEMU build identity plus plugin
  ABI into replay identity checks and failure reproduction artifacts. Selected
  candidates must additionally pass executable/shared-object ELF probes: QEMU
  is process-queried with `--version`, and the plugin export surface must contain
  the QEMU install/version entrypoints; text impersonators are rejected.
  `T-CLI-6` is completed through `checks.crucible.phase5.cliRunWorkflow`, which
  covers canonical scenario file and `blake3:` store-reference parsing,
  invalid-scenario exit 5, local and daemon lifecycle session creation through
  the typed control-client workflow, production HTTP/2 RPC serving, control
  attachment, non-empty scheduler event/state stream consumption, parsed
  virtual-time/quanta budget checks from live counters, outcome-derived
  terminal status, user-visible `--watch` status lines, real terminal
  savepoint handles for `--save-on`, incremental stdin acknowledgements for
  interactive commands, and non-passing outcome exit propagation with a
  reproduction artifact.
  `T-CLI-7` is green through `checks.crucible.phase5.cliVerifyWorkflow`, which
  covers fresh local-double, local-QEMU, and remote-daemon verify reductions,
  canonical-log byte comparison, execution-fingerprint stream comparison,
  adversarial hostile profiles, divergence localization with first
  decision/sample/byte reporting, both-side reproduction artifacts,
  `verify --compare <a> <b>`, exit 0/1 deterministic/divergent outcomes, and
  local-QEMU verify output pinned to the resolved QEMU/plugin build identity.
  Each local-QEMU reduction also performs an independent production plugin boot
  and rejects non-identical live reports.
  `T-CLI-16` is green through `checks.crucible.phase5.cliCompletionsHelp`, which
  covers Bash, Elvish, Fish, PowerShell, and Zsh completion generation, exact
  long/short `--version`, normalized exact §6–§14 subcommand usage/help
  snapshots, Clap enforcement of every normative required input (including
  conditional alternatives and `serve --listen`) and the fork seed/override
  conflict,
  process-level help/version/completion and missing-input coverage for the real
  binary, hidden gate-only flag exclusion from help, and rejection of future
  flags whose command behavior is not implemented yet.
  `T-CLI-8` is completed through `checks.crucible.phase5.cliSelftest`, which covers
  a process invocation of the packaged production
  `crucible selftest --with-qemu` process, with three independent live
  QEMU/plugin boots against the unmodified stock Linux kernel and per-gate PASS
  rows carrying QEMU identity, terminal icount, and execution fingerprint.
  Supplemental feature-gated tests cover the fast test corpus, canonical
  `--gates <list>` validation, malformed/unsupported selection rejection, and
  file-backed `--corpus <path>` manifests; those test-double runners are absent
  from the packaged binary.
  `T-CLI-9` is completed through `checks.crucible.phase5.cliSaveWorkflow`, which
  covers executable `save <SCENARIO> --at quiescence` and `--at virtual-time
  --max-virtual-time <dur>` saves, parser/planner coverage for
  `--at property --property <assertion>` and `--at marker --marker <name>`, and
  typed in-process breakpoint-id plus breakpoint-firing-query plumbing for the
  future selector proof path; creates a label-bearing savepoint at the paused
  boundary, validates the returned materialized checkpoint through replay-oracle
  `fat==thin` before exporting a `.crucible-savepoint` handle, supports default
  `--artifact-dir` and explicit `--out` destinations, exercises local-double
  property saves through host assertion evaluation of scenario-declared
  properties, exercises marker saves through white-box scenario-declared guest
  marker sources, proves both selector classes with suspending breakpoints plus
  breakpoint-firing proof, rejects wrong-marker and no-source marker selectors,
  routes explicitly selected local-QEMU saves through the same create-savepoint/
  export/oracle workflow with resolved QEMU/plugin identity metadata, routes
  remote-daemon quiescence and virtual-time saves over the RPC control API and
  validates them with replay-oracle evidence, routes remote selector proof
  queries over RPC breakpoint-firing payloads, transfers arbitrary scenario
  selector sources to remote daemons as form-bearing inline `CreateSession` RPC
  payloads, derives remote guest-marker white-box policy from the transferred
  source form, and fails undeclared property selectors and marker selectors
  without a white-box source. The same gate also process-tests real-binary
  `save --backend qemu` JSONL output and handle export through marker-resolved
  QEMU/plugin identity, then runs a backend-executed patched-QEMU
  `snapshot-save` smoke over the same QMP savepoint primitive. The selected
  local-QEMU route also requires a successful packaged-QEMU/plugin boot before
  exporting the replay-oracle-validated handle.
  `T-CLI-10` is completed through `checks.crucible.phase5.cliResumeWorkflow`, which
  covers `resume <SAVEPOINT>` parser/help surface, `.crucible-savepoint` handle
  decoding with compact scenario/schedule evidence, direct `blake3:<hash>`
  checkpoint reference parsing and local DAG-store checkpoint closure loading,
  virtual-time budget validation, malformed-handle artifact errors, and
  executable handle- or store-backed local-double resume to quiescence,
  virtual-time, interactive command driving, or a declared property violation
  through the session checkpoint-resume API with breakpoint-firing proof for the
  property stop and replay-oracle validation for terminal savepoints, plus
  remote-daemon handle-backed virtual-time resume over `ResumeSession` RPC,
  remote interactive command driving, `--watch` status streaming at observed
  remote boundaries, terminal savepoint replay-oracle validation, and terminal
  remote interactive finalization through stopped snapshot query, actor-owned
  terminal savepoint validation, replay-oracle proof, and stopped-session
  cleanup, plus explicitly selected local-QEMU resumes that run the same resumed
  session workflow, invoke the `crucible-qemu` resume coordinator through an
  API-owned adapter backed by a `SimBackend`-seeded
  `QemuBackendRealizationExecutor`, and derive
  branch/runtime proof fields from that coordinator result. The API bridge now
  also accepts a caller-owned `QemuVmRealizationExecutor`, giving the CLI/API
  boundary an explicit hook for selecting the Linux real-node executor once
  launch artifacts are resolvable.
  The `crucible-qemu` realization coordinator owns baked-genesis,
  source-ancestor, and savevm policy branches, and now exposes a `Backend`-backed
  realization executor that restores exact/baked snapshots through the
  QMP-backed backend boundary and replays suffixes through backend horizon
  advances, plus a Linux real-node realization executor that launches a
  policy-authorized restored `QemuNode`, replays through shared memory, samples
  live fingerprints and icounts, and keeps generic QMP snapshot/restore closed
  after node assembly, while the CLI emits
  `materialization=qemu-vm-realization`, `operation=resume`,
  `executor=model-checkpoint`, branch, replay count, runtime/configuration
  hashes, and resolved QEMU/plugin identity in stdout and the canonical log.
  process-level `resume --backend qemu` JSONL output checks those
  coordinator-derived proof fields from that model-checkpoint executor plus
  replay-oracle validation through marker-resolved QEMU/plugin identity, then the gate runs a direct patched-QEMU
  QMP `snapshot-load` smoke that proves the load job concludes and QEMU reports
  `running` after `cont`. The selected local-QEMU path now also requires a
  successful live packaged-QEMU/plugin boot before the replay-oracle-admitted
  coordinator result is exposed.
  `T-CLI-11` is completed through `checks.crucible.phase5.cliForkWorkflow`, which
  covers `fork <SAVEPOINT>` parser/help surface, global `--seed` re-seed
  plumbing, repeatable `--override decision=value` validation, labels,
  virtual-time budget validation, `.crucible-savepoint` handle decoding, direct
  `blake3:<hash>` checkpoint references loaded from the local DAG-store
  checkpoint closure index, malformed-handle artifact errors, seed/override
  conflict usage errors, handle- and store-backed no-divergence local-double fork
  execution through an independent child session, repeatable post-fork
  `--override` decision application, explicit post-fork `--seed` execution in
  the local double by deriving the child's post-fork decision stream from the
  explicit seed while preserving the requested savepoint prefix, distinct-seed
  terminal-savepoint and exact virtual-time-boundary proof, interactive child
  command driving, CLI-replayable child reproduction artifact writing whose
  embedded seed remains the scenario-form seed plus fork-seed provenance output
  and separate model artifact/replay-state evidence, and terminal savepoint
  replay-oracle validation, plus explicitly selected local-QEMU forks through
  the same child-session materialization with resolved QEMU/plugin identity
  provenance in stdout and the canonical log, and process-level
  `fork --backend qemu` JSONL output plus child artifact creation through
  marker-resolved QEMU/plugin identity and requires an independent live
  packaged-QEMU/plugin boot before the child workflow. Production-QEMU
  `--seed` forks now re-seed scheduler, World-network, block, 9p, and
  plugin-served app-random streams at the exact saved configuration; app-random
  branch/relaunch cursors are explicit launch inputs, and the patched-QEMU
  white-box gate proves cursor-zero branch-seed service to a real guest.
  `T-CLI-12` is completed through `checks.crucible.phase5.cliReplayCheck`, which
  covers `replay --check <original-log>` parsing, pinned-identity validation
  before store access, content-addressed component payload resolution from the
  selected local DAG store, declared DAG-store reference validation against
  inline payloads, byte-identical canonical-log comparison, exit 1 on mismatch
  with deterministic first-difference byte localization, process-level
  `replay --check` success/mismatch and `replay --to <SAVEPOINT>`
  target-validation JSONL coverage with replay records plus `final_outcome`,
  artifact-to-artifact
  `--bisect <other-artifact>` over validated matching replay inputs with
  canonical-log/fingerprint divergence localization, and `replay --to
  <SAVEPOINT>` validation for savepoint handles or local DAG-store checkpoint
  hashes through savepoint evidence, scenario-identity matching, artifact
  decision-count bound checks, payload-backed typed schedule-prefix proof with
  equal-length non-prefix and missing-prefix-payload rejection, pure
  replay-oracle validation, and unified model temporal-graph replay
  materialization with runtime/reduced-state, single-VM-fingerprint, and
  fat/thin checkpoint agreement, plus host-profile machine-independent replay
  coverage in the same gate for quiet single-core vs loaded many-core artifact
  reproduction. Ordinary replay re-executes the pure
  `reduce(ScenarioDef, Schedule)` materialization and verifies the reconstructed
  canonical bytes and fingerprint evidence.
  `T-CLI-13` is completed through `checks.crucible.phase5.cliSearchFuzzWorkflow`,
  which covers `search <SCENARIO>` and `fuzz <FAMILY>` parser/help surface,
  concrete scenario resolution for search, family reference resolution for fuzz,
  search strategy/budget/violation-mode validation, seeded coverage-guided fuzz
  config construction, local-double search execution through
  `TemporalGraph::search_with_strategy_and_failure_oracle_bounded_depth_sampled`
  after deriving a prefix-safe scenario-assertion search failure oracle,
  bounded decision-depth execution for
  `--max-depth`, explicit `--on-violation`
  acceptance, deterministic `search-run` output with `failure_oracle=none` or
  `failure_oracle=scenario-assertions`, exhaustion metadata, 1/1 replay-oracle
  sampling counts over fat search materializations, RFC §13 status mapping
  for discovered failures, stop-mode budget exhaustion, collect-mode
  budgeted campaigns, engine-discovered counterexample metadata, and replayable
  CLI reproduction artifact emission with standard replay/debug footer commands;
  prefix-safe lowering of concrete schedule-derived fault-active
  safety/unreachability assertion violations plus `--schedule-named-truths`
  loading of explicit data-only oracle inputs for named host predicates keyed by
  search-reconstructed schedule facts, with schema/node/duplicate-key
  validation and source digest/payload provenance in `search-run` output and
  reproduction artifacts, while the default CLI path still excludes
  absence-based liveness/existential failures, time/timer/quiescence predicates,
  observable-event/guest-marker predicates, and named host predicates unless
  explicit schedule-named truth data is supplied; an engine trusted retained-log
  provider path can now lower prefix-safe safety/unreachability failures over
  event-log-backed predicates such as time/timers,
  network/console/I/O/node/assertion-state observables, raw guest-address
  coverage, physical-address/register memory samples, guest markers, and
  schedule fault-active facts when the caller supplies the exact
  `RecordedAssertionLog` for each reached configuration, with
  configuration-bound retained-log evidence bundles that pair logs with
  host-resolution tables and an explicit
  resolution context for symbolic coverage and virtual/symbolic memory leaves,
  plus terminal quiescence evidence
  for retained after-quiescence, `sometimes`, `eventually`, and
  expected-reachable failures, terminal `sometimes` and required `reachable`
  guest assertion marker failures, and event-backed `always` false or
  `unreachable` true guest marker failures; hidden local-double
  `crucible.search-retained-evidence.v1` retained-evidence fixture loading for
  guest-marker events, terminal quantum evaluation-boundary entries, and
  terminal-quiescence entries on root or explicitly hashed configurations,
  validation of retained guest-marker evidence against scenario nodes and
  white-box policy, rejection of blocked terminal quiescence until blocker
  evidence is modeled, local-double CLI coverage for retained
  after-quiescence and terminal `sometimes` failures, trusted retained-log
  provider wiring through configuration-bound `SearchRetainedLogAssertionEvidence`,
  and retained evidence source digest/payload provenance in `search-run` output
  and reproduction artifacts;
  file-backed `crucible.scenario-family.v1` fuzz family loading,
  local-double `ScenarioFamily::fuzz_coverage_guided` and
  `ScenarioFamily::fuzz_coverage_guided_corpus` execution, durable
  `LocalDagStore` corpus persistence, stored family-hash loading as strict
  scenario-family TOML from the configured DAG store, deterministic `fuzz-run`
  output with generated-mutant/admission/retained-entry/store-put/
  replay-validation counts, and explicit backend errors for missing/corrupt
  stored family objects and unsupported fuzz targets. The gate process-executes
  packaged production `search` and `fuzz` commands against the unmodified stock
  Linux kernel. Search queries the engine-owned live frontier and realizes child
  schedule prefixes in fresh QEMU sessions before replay-oracle admission; fuzz
  executes warm-up and guided iterations in fresh QEMU sessions and feeds
  non-empty plugin basic-block coverage into the engine policy. The gate requires
  branch-realization, coverage-feedback, pinned backend proof, and successful
  JSONL `final_outcome` records. The search and fuzz fixtures reuse the phase-2
  guest-only raw-Ethernet initramfs. Search uses shift 0, the certified
  3.999-billion-nanosecond conservative link window, and a
  12-billion-icount horizon; its single root expansion discovers the live loss
  frontier and replay-validates both children in fresh two-node QEMU sessions.
  The fuzz family excludes pre-boot faults so a real guest quantum commits
  plugin coverage before feedback is evaluated. Neither fixture modifies
  Linux.
  `T-CLI-17` is complete under `checks.crucible.phase5.cliTriageWorkflow`: the
  thin `triage <FINDINGS>` parser/planner loads empty and signed engine-owned
  property findings ledgers through the local DagStore, drives triage-engine
  clustering, representative election, signature-preserving minimization,
  deterministic report/result artifact storage, `--policy`, `--minimize`,
  `--report`, global `--format`, `--recompute-signatures`, and `--compare`,
  and explicitly rejects CLI-local `finding.*` sidecars plus artifact-only
  ledgers whose discovery-time signature evidence is not available.
  `T-CLI-14` is completed under `checks.crucible.phase5.cliServeReadOnly`,
  `checks.crucible.phase5.cliServeMaxSessions`,
  `checks.crucible.phase5.cliServeMultiClient`, and
  `checks.crucible.phase5.cliServeShutdown`: the CLI advertises and enforces
  `serve --read-only` and `serve --max-sessions <n>`, rejects invalid caps before
  binding, runs the production HTTP/2 daemon over the shared lifecycle/session
  actor path, rejects state-mutating calls in read-only mode, admits concurrent
  Watch and Query clients while Control drives the same session, propagates
  shutdown to active Control/Watch streams, maps serve bind/backend failures to
  exit 3, and proves a real process exits 0 after an external shutdown signal.
  `T-CLI-15` is completed through `checks.crucible.phase5.cliExitMachineReadable`,
  which covers the backend-routed output path appending a machine-readable
  final-outcome record to canonical `json`/`jsonl` traces, suppressing human
  summary/footer lines from machine-readable stdout, process-level local-double
  `run`, `save`, `search`, `fuzz`, marker-resolved QEMU `save`, `resume`, and
  `fork`, `replay --check` success/mismatch, and `replay --to <SAVEPOINT>`
  JSONL output with parsed command-specific canonical events plus
  `final_outcome`, and
  regression-testing the RFC §15 exit-code classes, including the live-QEMU
  run/save/resume/fork/search/fuzz routes.
- Patterns realized here: `T-PAT-1`, `T-PAT-6`.

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
- Time-travel debugging (built on the checkpoint DAG + replay): `T-DBG-1 … T-DBG-12` ([`36`](36-time-travel-debugging.md)).
  `T-DBG-1` is completed through `checks.crucible.phase6.debugAttach`; `T-DBG-2`
  is completed through `checks.crucible.phase6.readOnlyDebugInspection`, which proves
  read-only debugger observations do not alter config, virtual time, or the
  canonical causal event-log subsequence; `T-DBG-3` is completed through
  `checks.crucible.phase6.canonicalDebugBreakpoint`, which refuses memory-patch-only
  canonical breakpoints and transparently maps software breakpoint requests to
  out-of-band mechanisms when available;
  `T-DBG-4` is green through `checks.crucible.phase6.debugTimeTravel`, which
  proves debug `goto` uses restore-nearest-checkpoint-then-replay, reverse-step
  mirrors the forward `StepMode` set, and reverse-continue resolves the latest
  prior 17a condition coordinate through the same replay-oracle-checked path;
  `T-DBG-5` is green through `checks.crucible.phase6.debugScopedTimeTravel`,
  which proves per-node exact-icount travel leaves other nodes untouched,
  whole-world travel lands at a prefix/fork-minus-divergence coordinate, and
  `--checkpoint-stride` remains a performance-only cache cadence, including safe
  fat eviction, defaulting to thin/replay until S3 is green;
  `T-DBG-6` is green through `checks.crucible.phase6.debugNonCanonicalBranch`,
  which proves mutating/operator-controlled debugging records a visibly
  non-canonical branch from the instantiated attach runtime, preserves the
  canonical graph and canonical-run causal log, emits a causal catalog-kind
  `fork` marker flagged non-canonical, excludes the branch from replay-oracle and
  `(seed, scenario, schedule)` artifacts, and stores arbitrary guest edits only
  in a never-model-reproducible debug-edit script;
  `T-DBG-7` is green through `checks.crucible.phase6.debugTargetResolver`, which
  resolves `--at`, `--at-event`, `--at-failure`, `--at-checkpoint`, and
  divergence-bisection targets into replay-checked debug `goto` requests and
  centralizes the copy-pasteable
  `crucible debug <artifact> --at-failure` failure footer command;
  `T-DBG-8`/`T-CLI-18` are completed through `checks.crucible.phase6.debugCliSurface`, which implements the
  `crucible debug` parser and planner as a stateless session/debugger wrapper over
  target-aware coordinate defaults, target resolution, session query/snapshot/fork
  commands, debug reverse-step/goto restore-plus-replay operations, the mediated
  gdbstub proxy, read-only default inspection, explicit non-canonical mutation
  branches, no-symbol-server ownership, coherent multi-vCPU gdb threads, and
  disabled raw gdb single-step. The command resolves and boots the hermetic
  packaged QEMU/plugin backend before reporting the delegated debug plan. The
  remote path additionally exposes controller-leased GDB relay plus explicit
  whole-world guest-introspection fork, argv exec, PTY, and configured in-guest
  SSH byte bridging through the bounded public protocol.
  `T-DBG-9 … T-DBG-12` remain open for the production gateway/live replacement
  gates, complete authorization and peer-credential enforcement, guest-channel
  reposition teardown/resize/transcript completion, and live acceptance.
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

**Exit gates.** `gate:replay-oracle` continues to hold under active search
(forks and restores validated continuously), reproduction artifacts replay
bit-identically, and `gate:basic-block-coverage` proves the opt-in coverage path
through a loaded-QEMU callback run without affecting fingerprints.

---

## Phase 7 — Packaging, performance, acceptance

**Goal.** Ship it inside AOS, hit the performance targets, and pass the final
acceptance gate.

**Tasks.**
- AOS packaging (hermetic, patched QEMU pkg, fixtures, CI wiring, ratchet seam;
  incl. the new packaging tasks `T-PKG-21 … T-PKG-23`): `T-PKG-1 … T-PKG-23` ([`26`](26-packaging-aos-integration.md)).
- Debugger packaging and live acceptance: `T-DBG-13 … T-DBG-14`
  ([`36`](36-time-travel-debugging.md)).
- Performance (incl. the fleet-perf tasks `T-PERF-27, T-PERF-28` and the host-parallelism tasks `T-PERF-29 … T-PERF-34`): `T-PERF-1 … T-PERF-34` ([`25`](25-performance-targets.md)).
- Distributed / continuous exploration (campaigns spanning a fleet of workers): `T-DCE-1 … T-DCE-10` ([`35`](35-distributed-continuous-exploration.md)).
- Worked example scenarios as CI fixtures (happy path, partition-recovery, crash/restart, fault campaign, determinism check): `T-EX-1 … T-EX-5` ([`33`](33-examples-and-workloads.md)). These double as the `gate:e2e-determinism` corpus.
- Completed decision spikes: `T-D-1 … T-D-4` ([`31`](31-decision-register.md)).

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
   PLUG    52    27      OBS    37    14       PERF   34    34
   SCHED   47    30      GHC    38    17       CLI    27    18
   QEMU    43    16      IO     34    16       RISK   28    20
   PATCH   47    24      HARN   34    26       PROTO  24    11
   DET     44    31      TIME   35     9       CRATE  18    15
   PKG     45    23      STD    33    13       PAT    12     9
   SHM     37    16      SPAT   33    21       ARCH    9     5
   ADV     40    21      FAULT  34    16       TEMP   30    11
   EXEC    34    20      API    31    14       TRIG   32    20
   DBG     47    14      ASRT   33    18       TRI    19     8
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
  Completed by `checks.crucible.phase1.phaseGateWiring`,
  `checks.crucible.phase1.phaseGateOrdering`, and the `greenBeforeAdvance`
  wrappers in `tests/crucible/default.nix`: the checks derive the canonical gate
  inventory from §24, require every phase exit target to exist in the Nix check
  tree and master plan, enforce lower-layer/earlier-phase dependencies, and keep
  the terminal phase-7 e2e occurrence in the acceptance set.
