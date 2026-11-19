# Testing and determinism gates

Crucible proves its determinism with named, automated checks called gates. A
gate is a pure check: given the same source tree and the same seed corpus it
returns the same verdict on every machine. Gates never depend on wall-clock
thresholds, host core counts, or network access, and a flaky gate is treated
as a failing gate whose flake is a residual nondeterminism to remove at its
source. Gates are never retried or quarantined to turn green.

This page describes the canonical gate catalog, how gates are ordered and
wired into the Nix check tree, and the harness components that the gates share.
The coding rules that the gates enforce are in
[engineering-standards.md](engineering-standards.md); the crate layering they
follow is in [crate-structure.md](crate-structure.md). How to run Crucible
checks in CI from a user's point of view is in
[../../users/crucible/ci.md](../../users/crucible/ci.md).

The harness lives in `crates/crucible/crucible-test-support`, a test-only
workspace member that no runtime crate may depend on. Its module map:

| Module | Owns |
| --- | --- |
| `lib.rs` | `CANONICAL_GATES`, `canonical_gates()`, `find_gate()`, `HARNESS_COMPONENTS` |
| `gate_targets` | `GATE_TARGETS`: canonical gate name to isolable Cargo test target |
| `phase_plan` | `PHASE_GATE_ORDER`, layer precedences, the advanced-feature ladder |
| `fingerprint` | Execution-fingerprint definition, sampling, and stream comparison |
| `divergence` | First-divergence location, icount bisection, state dumps |
| `replay_oracle` | Fat-versus-thin checkpoint comparison and in-search sampling |
| `abi` | Golden-vector comparison with separate version and byte drift |
| `adversarial` | Hostile host profiles and run comparison |
| `e2e` | Mock-backend end-to-end determinism driver |
| `reproduction` | The versioned reproduction-artifact format |
| `segment_replay` | Checkpoint-segment parallel replay with ordered joining |
| `perf` | The cost-model substrate of `gate:perf-bench` |
| `assertion` | Test-only determinism assertion labels (`crucible-assert.v1`) |
| `campaign_gates` | Executable contracts of the campaign gates |
| `workspace_crates` | `crucible_crates()`: the Crucible crate list that workspace-wide lints iterate |

## Test layers

Crucible is layered L0 to L4 (see [crate-structure.md](crate-structure.md)).
Each layer has its own determinism coverage, and a higher layer's test never
stands in for a lower layer's property. Lower-layer unit suites are fast and
supplemental; the canonical execution gates run the shipped QEMU and plugin.

```text
  L4  control plane     gate:control-responsive    ops acked within a quantum bound
  L3  engine            gate:replay-oracle         fat == thin by hash
                        gate:content-address       equal content, equal id
  L2  QEMU integration  gate:single-vm-fingerprint one VM bit-identical
                        gate:layer0-determinism    exact production fingerprint stream
                        gate:scheduler-liveness    bounded production scheduler progress
                        gate:any-guest             unmodified guest, no image mutation
                        gate:qemu-inert            sim-off behavior matches upstream
  L1  co-sim transport  gate:layer1-injection      injection icount is pure
                        gate:abi-conformance       shmem/protocol/RPC golden vectors
  L0  deterministic core supplemental unit suites  RNG, ordering, digest properties
  --  cross-cutting     gate:harness-lint, gate:divergence-bisect,
                        gate:adversarial-determinism, gate:e2e-determinism
```

`DeterminismLayer` in `crates/crucible/crucible-test-support/src/phase_plan.rs`
names the same five layers.

- **L0, `crucible-determinism`.** In-process tests cover decision-RNG stability
  under entity insertion (per-entity streams are forked by name hash, so adding
  a node does not perturb other streams), total-order stability of the
  cross-node key `(virtual_time, consumer node_id, producer node_id, sequence)`,
  ordered iteration, and digest helpers. They run in milliseconds and do not
  substitute for `gate:layer0-determinism`, whose verdict comes from the
  production QEMU fingerprint stream.
- **L1, `crucible-qemu-shmem`, `crucible-qemu-protocol`, `crucible-device`.**
  The shared-memory region, SPSC frame queues, protocol codec, and I/O
  sub-nodes run without real QEMU: injection determinism, golden vectors, the
  exhaustive SPSC ordering model, and codec and wire fuzzing.
- **L2, `crucible-qemu-host`, `crucible-qemu-plugin`, `crucible-guest`.** The
  first layer that boots a guest. Single-VM fingerprints, production execution
  determinism, scheduler progress, unmodified-guest boot, patch inertness, and
  patch microtests. Fixtures are small boot-to-ready images so the cheap
  in-process layers catch most regressions first.
- **L3, `crucible-engine`.** The temporal graph, scheduler, faults, and
  assertions. The replay oracle is the load-bearing structural test.
- **L4, session, control API, client, server, daemon, CLI.** Control-plane
  responsiveness and the RPC half of ABI conformance, exercised against the
  in-process double so a full session, fork, snapshot, and inject exercise
  needs no guest boot.

## Gate catalog

`CANONICAL_GATES` in `crates/crucible/crucible-test-support/src/lib.rs` is the
canonical catalog. Every entry is a `GateSpec` with a `name`, the `GatePhase`
where it first blocks progress, an `owner` crate, and a `GateStatus`. All
catalog gates currently have status `Implemented`; `RedPlaceholder` and
`CatalogOnly` remain in the type for wired-but-failing and catalog-only
entries. The table lists the catalog in code order.

| Gate | First blocks | Owner | Pass criterion |
| --- | --- | --- | --- |
| `gate:harness-lint` | `Always` | `crucible-test-support` | The static determinism lint, the clippy tier, the crate-shape lints, and the check-reference integrity lint report zero findings. |
| `gate:license-boundary` | `Always` | `crucible-test-support` | Dependency, license-scope, protocol-shape, package-source, and corresponding-source rules hold; any violation fails closed. |
| `gate:layer0-determinism` | `Phase1` | `crucible-qemu-host` | Guarded production QEMU reproduces the same authenticated fingerprint stream at exact sample coordinates across a restart, and a one-instruction coordinate change is localized exactly. |
| `gate:single-vm-fingerprint` | `Phase1` | `crucible-qemu-host` | One unmodified VM booted twice with fixed inputs yields bit-identical fingerprint streams and final icount. |
| `gate:layer1-injection` | `Phase2` | `crucible-device` | The icount at which each frame is observed by its receiver is a pure function of the cross-node ordering key across all tested host interleavings. |
| `gate:content-address` | `Phase1` | `crucible-engine` | Equal content yields an equal id across runs; any single-byte change yields a different id. |
| `gate:campaign-model` | `Phase1` | `crucible-campaign` | Canonical campaign identities and repository lifecycle remain exact. |
| `gate:replay-oracle` | `Phase1` | `crucible-engine` | Every fat checkpoint hash equals the hash of its thin reconstruction from an ancestor. |
| `gate:divergence-bisect` | `Phase1` | `crucible-test-support` | A seeded divergence is localized to its first differing sample, icount, and node, deterministically. |
| `gate:scheduler-liveness` | `Phase3` | `crucible-qemu-host` | Packaged QEMU reaches exact bounded targets through quantum preemption, vCPU switching, interrupt delivery, all-vCPU idle, and a queued idle wake that reproduces after restart. |
| `gate:control-responsive` | `Phase5` | `crucible-session` | Pause, snapshot, fork, inject, and query are acknowledged within a bounded number of quanta, measured in quanta and never wall-clock. |
| `gate:any-guest` | `Phase2` | `crucible-qemu-host` | An unmodified guest fixture boots with deterministic fingerprints, the CoW base image stays byte-unchanged, and no in-guest agent is required. |
| `gate:qemu-inert` | `Phase2` | `crucible-qemu-host` | With sim mode off, the patched QEMU matches an unpatched reference over the checked corpus; the only migration delta is the authenticated PIT phase subsection, and the host-control QMP extension fails closed. |
| `gate:abi-conformance` | `Phase2` | `crucible-test-support` | Live shmem layout, protocol frames, and RPC encodings match frozen golden vectors byte for byte, with matching version fields. |
| `gate:typed-choice` | `Phase2` | `crucible-campaign` | Typed guest choice registrations, pending tokens, host replies, and fresh-process continuation match the frozen shared-memory and choice contracts. |
| `gate:patch-microtests` | `Phase2` | `crucible-qemu-plugin` | Every capability in the atomic QEMU patch has a focused passing test, and one pristine-QEMU negative proves the capability set is absent upstream. |
| `gate:adversarial-determinism` | `Phase3` | `crucible-test-support` | Runs under every hostile host profile produce byte-identical canonical logs and final fingerprints. |
| `gate:e2e-determinism` | `Phase4` | `crucible-test-support` | A representative multi-VM, fault-injected scenario is bit-identical across host profiles and reproduces bit-identically from its artifact. |
| `gate:campaign-statistics` | `Phase4` | `crucible-campaign` | Finite static estimation preserves exact support and weights and excludes intervention execution bases. |
| `gate:basic-block-coverage` | `Phase6` | `crucible-qemu-plugin` | An opt-in loaded-QEMU run emits the expected guest-PC and block-length stream without changing any fingerprint; off mode installs no callback. |
| `gate:checkpoint-materialization` | `Phase6` | `crucible-engine` | An exact fat checkpoint persists a complete content-addressed state closure; a thin checkpoint stays an advisory reconstruction cache. |
| `gate:state-space-search` | `Phase6` | `crucible-engine` | Search expands only authenticated runtime decisions, materializes each frontier from canonical state, and deduplicates children by configuration identity. |
| `gate:perf-bench` | `Phase7` | `crucible-test-support` | Cost-model metrics meet their baselines and none regresses beyond its threshold. |
| `gate:fleet-equivalence` | `Phase7` | `crucible-test-support` | Single-host and fleet search over the same family, seed, and budget find the same content-addressed finding set with byte-identical artifacts; discovery order may differ. |
| `gate:campaign-continuity` | `Phase7` | `crucible-test-support` | Seeding a run from a previous campaign reproduces each corpus entry, coverage never decreases, and cross-provenance reuse is refused. |
| `gate:production-rust-plugin-flight` | `Phase7` | `crucible-qemu-host` | The Rust host and plugin drive packaged QEMU through exact boundaries, fingerprints, idle wake, and timer expiry twice with identical authenticated evidence. |
| `gate:signal-fault-system` | `Phase7` | `crucible-test-support` | The closed signal-driven fault system has per-kind evidence, live-boundary coverage, replay identity, and no retired executable path. |

Two gates differ from the rest in kind. `gate:perf-bench` is a regression gate
that compares metrics against stored baselines rather than checking byte
identity; it never trades determinism for speed (see
[performance.md](performance.md)). `gate:harness-lint` and
`gate:license-boundary` are `Always` gates that run on every change before the
ordered gates. Campaign gates are described with the campaign pages, and the
signal-driven fault model with its own pages; this page lists them only
because they share the catalog.

The catalog is also a documentation contract. A test compares the set of names
in this table with `canonical_gates()`, and every gate name used anywhere in
the Crucible engineering documentation must be a catalog name (see
[engineering-standards.md](engineering-standards.md)).

## Gate targets

Each catalog gate maps to one or more addressable Cargo integration-test
targets in `GATE_TARGETS` (`crates/crucible/crucible-test-support/src/gate_targets.rs`).
A target proves its crate's contribution; it does not by itself discharge an
aggregate gate that also needs packaged processes, VM execution, or host
variation. Targets that need a feature list it in `required_features`; engine
targets that use the shared-memory double run with `--features test-double`.

| Package | Test target | Features | Gate |
| --- | --- | --- | --- |
| `crucible-test-support` | `harness_lint` | | `gate:harness-lint` |
| `crucible-test-support` | `gate_license_boundary` | | `gate:license-boundary` |
| `crucible-qemu-host` | `deterministic_launch` | | `gate:layer0-determinism` |
| `crucible-qemu-host` | `deterministic_launch` | | `gate:single-vm-fingerprint` |
| `crucible-qemu-plugin` | `gate_patch_microtests` | | `gate:single-vm-fingerprint` |
| `crucible-guest` | `gate_single_vm_fingerprint` | | `gate:single-vm-fingerprint` |
| `crucible-device` | `gate_layer1_injection` | | `gate:layer1-injection` |
| `crucible-qemu-protocol` | `gate_layer1_injection` | | `gate:layer1-injection` |
| `crucible-qemu-shmem` | `gate_layer1_injection` | | `gate:layer1-injection` |
| `crucible-test-support` | `gate_abi_conformance` | | `gate:abi-conformance` |
| `crucible-qemu-shmem` | `gate_abi_conformance` | | `gate:abi-conformance` |
| `crucible-qemu-protocol` | `gate_abi_conformance` | | `gate:abi-conformance` |
| `crucible-control-api` | `gate_abi_conformance` | | `gate:abi-conformance` |
| `crucible-qemu-plugin` | `gate_abi_conformance` | | `gate:abi-conformance` |
| `crucible-guest` | `gate_abi_conformance` | | `gate:abi-conformance` |
| `crucible-engine` | `gate_abi_conformance` | `test-double` | `gate:abi-conformance` |
| `crucible-campaign` | `gate_typed_choice` | | `gate:typed-choice` |
| `crucible-engine` | `gate_replay_oracle` | `test-double` | `gate:replay-oracle` |
| `crucible-engine` | `gate_content_address` | | `gate:content-address` |
| `crucible-determinism` | `gate_content_address` | | `gate:content-address` |
| `crucible-campaign` | `gate_campaign_model` | | `gate:campaign-model` |
| `crucible-campaign` | `gate_campaign_statistics` | | `gate:campaign-statistics` |
| `crucible-qemu-host` | `deterministic_launch` | | `gate:scheduler-liveness` |
| `crucible-session` | `gate_control_responsive` | | `gate:control-responsive` |
| `crucible-control-server` | `gate_control_responsive` | | `gate:control-responsive` |
| `crucible-daemon` | `gate_control_responsive` | | `gate:control-responsive` |
| `crucible-qemu-host` | `deterministic_launch` | | `gate:any-guest` |
| `crucible-qemu-host` | `gate_qemu_inert` | | `gate:qemu-inert` |
| `crucible-qemu-plugin` | `gate_qemu_inert` | | `gate:qemu-inert` |
| `crucible-qemu-plugin` | `gate_patch_microtests` | | `gate:patch-microtests` |
| `crucible-test-support` | `gate_divergence_bisect` | | `gate:divergence-bisect` |
| `crucible-engine` | `gate_adversarial_determinism` | | `gate:adversarial-determinism` |
| `crucible-engine` | `gate_e2e_determinism_concurrency` | `test-double` | `gate:e2e-determinism` |
| `crucible-cli` | `gate_e2e_determinism` | | `gate:e2e-determinism` |
| `crucible-engine` | `gate_basic_block_coverage` | | `gate:basic-block-coverage` |
| `crucible-qemu-host` | `gate_basic_block_coverage` | | `gate:basic-block-coverage` |
| `crucible-engine` | `gate_checkpoint_materialization` | | `gate:checkpoint-materialization` |
| `crucible-engine` | `gate_state_space_search` | | `gate:state-space-search` |
| `crucible-engine` | `gate_fleet_equivalence` | | `gate:fleet-equivalence` |
| `crucible-store` | `gate_campaign_continuity` | | `gate:campaign-continuity` |
| `crucible-engine` | `gate_signal_fault_system` | | `gate:signal-fault-system` |
| `crucible-test-support` | `gate_perf_bench` | | `gate:perf-bench` |

`gate:production-rust-plugin-flight` has no Cargo target; it exists only as
the packaged-QEMU Nix check `checks.crucible.phase7.productionRustPluginFlight`.
`GATE_TARGETS` also maps campaign-only gate labels that are outside the
canonical catalog; those are documented with the campaign pages.

The canonical adversarial target is the engine-side test that drives the real
`SingleScheduler` through the host-adversary matrix, not the harness-side mock
corpus. The engine's `gate_layer0_determinism` and `gate_scheduler_liveness`
targets and `crucible-determinism`'s `gate_layer0_determinism` remain
supplemental unit coverage.

## Gate ordering

`PHASE_GATE_ORDER` in `crates/crucible/crucible-test-support/src/phase_plan.rs`
records every ordered gate occurrence, including gates that occur more than
once, separately from the one-row-per-gate catalog. Each `PhaseGateOccurrence`
carries the `PhasePlanPhase`, the gate name, the Nix attribute path that must
be green, its `PhaseGateKind`, a purpose, whether it needs the in-process
double, and whether it is the terminal acceptance gate. The block below lists
the occurrences in code order as `phase gate attr-path`:

```text
  phase0  phase0:blockers                     checks.crucible.phase0.gates.blockers
  phase0  gate:harness-lint                   checks.crucible.phase0.gates.harnessLint
  phase1  gate:harness-lint                   checks.crucible.phase1.gates.harnessLint
  phase1  gate:license-boundary               checks.crucible.phase1.gates.licenseBoundary
  phase1  gate:layer0-determinism             checks.crucible.phase1.gates.layer0Determinism
  phase1  gate:content-address                checks.crucible.phase1.gates.contentAddress
  phase1  gate:campaign-model                 checks.crucible.phase1.gates.campaignModel
  phase1  gate:replay-oracle                  checks.crucible.phase1.gates.replayOracle
  phase1  gate:single-vm-fingerprint          checks.crucible.phase1.gates.singleVmFingerprint
  phase1  gate:divergence-bisect              checks.crucible.phase1.gates.divergenceBisect
  phase2  gate:abi-conformance                checks.crucible.phase2.gates.abiConformance
  phase2  gate:typed-choice                   checks.crucible.phase2.gates.typedChoice
  phase2  gate:layer1-injection               checks.crucible.phase2.gates.layer1Injection
  phase2  gate:patch-microtests               checks.crucible.phase2.gates.patchMicrotests
  phase2  gate:qemu-inert                     checks.crucible.phase2.gates.qemuInert
  phase2  gate:single-vm-fingerprint          checks.crucible.phase2.gates.singleVmFingerprint
  phase2  gate:any-guest                      checks.crucible.phase2.gates.anyGuest
  phase3  gate:layer1-injection               checks.crucible.phase3.gates.layer1Injection
  phase3  gate:scheduler-liveness             checks.crucible.phase3.gates.schedulerLiveness
  phase3  gate:adversarial-determinism        checks.crucible.phase3.gates.adversarialDeterminism
  phase4  gate:replay-oracle                  checks.crucible.phase4.gates.replayOracle
  phase4  gate:campaign-statistics            checks.crucible.phase4.gates.campaignStatistics
  phase4  gate:e2e-determinism                checks.crucible.phase4.gates.e2eDeterminism
  phase5  gate:control-responsive             checks.crucible.phase5.gates.controlResponsive
  phase6  gate:replay-oracle                  checks.crucible.phase6.gates.replayOracle
  phase6  gate:basic-block-coverage           checks.crucible.phase6.basicBlockCoverage
  phase6  gate:checkpoint-materialization     checks.crucible.phase6.checkpointMaterialization
  phase6  gate:state-space-search             checks.crucible.phase6.stateSpaceSearch
  phase7  gate:perf-bench                     checks.crucible.phase7.gates.perfBench
  phase7  gate:e2e-determinism                checks.crucible.phase7.gates.e2eDeterminism
  phase7  gate:fleet-equivalence              checks.crucible.phase7.gates.fleetEquivalence
  phase7  gate:campaign-continuity            checks.crucible.phase7.gates.campaignContinuity
  phase7  gate:production-rust-plugin-flight  checks.crucible.phase7.productionRustPluginFlight
  phase7  gate:signal-fault-system            checks.crucible.phase7.gates.signalFaultSystem
```

`phase0:blockers` is the only `NonCatalogAggregate`: it aggregates the
bounded-scheduler-preemption, S2, S4, and S11 blocker checks and is not a
catalog gate. Every other occurrence is a `CatalogGate`.

Repeated occurrences guard different evidence. The first
`gate:single-vm-fingerprint` and `gate:replay-oracle` occurrences and
`gate:divergence-bisect` are double-backed (`requires_sim_double`), as is the
phase4 `gate:e2e-determinism`. The phase2 fingerprint occurrence is Contract A
on real QEMU, the phase3 `gate:layer1-injection` is the full cross-node
contract, the phase6 `gate:replay-oracle` covers active search, and the phase7
`gate:e2e-determinism` is final acceptance.

The ordering is green-before-advance: no occurrence in a later phase runs until
every occurrence of every earlier phase is green, and
`gate:signal-fault-system` terminal in phase7 is the only occurrence with
`terminal_acceptance` set. `phase_plan_invariant_failures` rejects a plan with
any of these defects (`PhasePlanInvariantFailureKind`):

| Failure kind | Rule |
| --- | --- |
| `UnknownCatalogGate` | A catalog occurrence names a gate absent from `CANONICAL_GATES`. |
| `DuplicateAttrPath` | Two occurrences share a Nix attribute path. |
| `NonCatalogAggregateAfterPhase0` | A non-catalog aggregate appears after phase0. |
| `OutOfOrderPhase` | An occurrence follows one from a later phase. |
| `EmptyPhase` | A phase from phase0 to phase7 has no occurrence. |
| `MissingTerminalSignalFaultSystem` | No terminal phase7 `gate:signal-fault-system` occurrence exists. |
| `InvalidTerminalAcceptanceGate` | The terminal marker is on any other occurrence. |
| `SimDoubleUnavailable` | An occurrence needs the double before `SIM_DOUBLE_AVAILABLE_PHASE` (phase1). |

`green_before_advance_failures(green, next_phase)` returns every occurrence in
a phase before `next_phase` whose attribute path is not in the green set.

### Layer precedences

`LAYER_GATE_PRECEDENCES` makes the per-layer rule executable: a lower-layer
occurrence must precede the higher-layer occurrence it supports, so a
higher-layer gate never covers a lower layer's property.
`layer_gate_precedence_failures` reports any pair out of order.

| Lower | Higher | Lower occurrence | Higher occurrence |
| --- | --- | --- | --- |
| L0 | L1 | `phase1.gates.layer0Determinism` | `phase2.gates.abiConformance` |
| L1 | L2 | `phase2.gates.layer1Injection` | `phase2.gates.patchMicrotests` |
| L1 | L2 | `phase2.gates.layer1Injection` | `phase2.gates.qemuInert` |
| L1 | L2 | `phase2.gates.layer1Injection` | `phase2.gates.singleVmFingerprint` |
| L1 | L2 | `phase2.gates.layer1Injection` | `phase2.gates.anyGuest` |
| L2 | L3 | `phase2.gates.singleVmFingerprint` | `phase3.gates.schedulerLiveness` |
| L2 | L3 | `phase2.gates.singleVmFingerprint` | `phase3.gates.adversarialDeterminism` |
| L1 | L3 | `phase2.gates.layer1Injection` | `phase3.gates.schedulerLiveness` |
| L1 | L3 | `phase2.gates.layer1Injection` | `phase3.gates.adversarialDeterminism` |
| L3 | L4 | `phase4.gates.replayOracle` | `phase5.gates.controlResponsive` |
| L3 | L4 | `phase4.gates.e2eDeterminism` | `phase5.gates.controlResponsive` |

All paths are under `checks.crucible.`.

### Advanced-feature ladder

Exploration features build on each other in a fixed ladder, encoded by
`AdvancedFeatureRung` and `ADVANCED_FEATURE_LADDER`:

```text
exact-determinism -> save-restore -> fork -> search -> coverage-feedback -> fuzzing
```

Each `AdvancedFeatureStep` entry is keyed by the attribute path of the check
that implements it, such as `checks.crucible.phase6.coverageGuidedFuzzing`.
Every entry is scheduled in phase6 and requires a set of gate occurrences that
are green in earlier phases:

| Rung | Entries | Required green occurrences |
| --- | --- | --- |
| `exact-determinism` | 2 | fingerprint, e2e, and control-responsive |
| `save-restore` | 2 | phase4 replay oracle and e2e |
| `fork` | 2 | phase4 replay oracle and e2e |
| `search` | 5 | phase4 replay oracle and e2e |
| `coverage-feedback` | 5 | phase2 fingerprint and phase4 e2e, or replay oracle and e2e |
| `fuzzing` | 5 | phase4 replay oracle and e2e |

The coverage-guided fuzzing entry additionally requires the coverage, guidance,
and app-randomness entries. Two checks enforce the ladder.
`advanced_feature_ladder_failures` rejects a required gate that is missing or
not in an earlier phase, a prerequisite listed later, or a rung that moves
backward. `advanced_feature_schedule_failures` parses
`tests/crucible/default.nix` and rejects an entry whose check is not declared,
a check not wrapped in its own `greenBeforeAdvance` or `redBeforeAdvance`, and
a missing top-level dependency on a required gate or prerequisite check.

## Nix wiring

The gates run as Nix checks under `checks.crucible`, built from
`tests/crucible/default.nix` (imported by the repository `default.nix` as
`crucibleChecksBase`). Each phase attribute (`phase0` to `phase7`, plus
campaign phases) holds a `gates` set with one wrapped attribute per occurrence
whose `attrPath` string equals the `PhaseGateOccurrence` attribute path.

Gate checks share predicates from `tests/crucible/_lib.nix`: `hasInfix`,
`failuresFor` (needles missing from a source file), and `forbiddenFor` (needles
that must stay absent). A check reads its sources with `builtins.readFile`,
collects failures, and throws at evaluation time if any exist. A built gate
writes `$out/result` with a `PASS` line plus `gate=` and `check=` lines.

Three wrappers in `tests/crucible/default.nix` encode the ordering:

- `greenBeforeAdvance { attrPath, gate, dependencies }` builds a small
  derivation that depends on the gate and on the wrapped earlier occurrences,
  then writes `green_before_advance=<attrPath>` and the dependency count. The
  raw gate stays reachable as `rawGate`, and the raw gate itself depends on the
  earlier occurrences' `rawGate` outputs. For example, the phase1
  `singleVmFingerprint` raw gate depends on
  `[replayOracle.rawGate phase1.simDouble]` and its wrapper on
  `[replayOracle phase1.simDouble]`, so the double-backed gates cannot build
  before `checks.crucible.phase1.simDouble` is green.
- `redBeforeAdvance` wraps a gate in `red-gate-placeholder.nix`, which always
  fails and records `RED`, the gate, phase, owner, tasks, and reason. It keeps
  an unfinished occurrence wired without letting it pass.
- `qualifiedRawGate` certifies that a raw gate's result has exactly one `PASS`,
  the expected `gate=` line, and exactly one `check=` line naming its raw
  attribute path, then republishes the result under the qualified path.

The terminal `signalFaultSystem` occurrence depends on the phase2 QEMU fault and
plugin checks, the patch microtests, and the phase6 checkpoint-materialization
and replay-oracle raw gates. CI-facing aliases in the repository `default.nix`
(for example `crucible-e2e-determinism`, which builds
`phase4.gates.e2eDeterminism.rawGate`) point into the same tree.

Consistency between the code and the wiring is checked from both sides:
`tests/gate_catalog.rs` requires a `gate = "<name>";` CI target in
`tests/crucible/phase1-phase-gate-wiring.nix` for every non-`CatalogOnly` gate,
and `tests/phase_plan.rs` requires an `attrPath = "<path>";` in
`tests/crucible/default.nix` for every ordered occurrence. The Nix mirrors are
`checks.crucible.phase1.gateCatalog`, `checks.crucible.phase1.phaseGateWiring`,
and `checks.crucible.phase1.phaseGateOrdering`.

## The in-process QEMU double

Most determinism properties are about how the host orchestrates nodes, not
about a guest's instruction stream. The in-process double lets those
properties run in milliseconds without launching QEMU.

The engine provides two backends behind its `Backend` trait
(`crates/crucible/crucible-engine/src/backend.rs`), whose core operations are
`advance_to_horizon`, `fingerprint`, `deliver_input`, `snapshot`, `restore`,
and `shutdown`:

- `SimBackend` (`crates/crucible/crucible-engine/src/local_backend.rs`) is an
  always-available, safe, deterministic local backend. It advances an
  instruction counter, records delivered inputs, produces stable fingerprints,
  and snapshots and restores its small state.
- `SimDouble` (`crates/crucible/crucible-engine/src/sim_backend.rs`) is the
  plugin-side shared-memory double, compiled only with the engine's
  `test-double` feature, which also enables the optional
  `crucible-qemu-shmem` dependency.

`SimDouble` implements the plugin side of the shared-memory ABI and control
protocol with the real code, never a reimplementation: it builds its region
from `RegionAllocation`, validates setup with `validate_setup_region_header`,
moves frames through the real SPSC accessors, decodes host frames with
`control_decode_host_msg` and the `ControlLifecycle` validator, and replies
with `control_encode_plugin_msg`. It authorizes advances against the same
lookahead ceiling as the QEMU quantum path and drains inbound frames by the
canonical `FrameDeliveryKey`. Only the behavior generator is bespoke: a
`SimInstructionScript` of instruction budgets and a synthetic register and
memory fingerprint, both pure functions of the script and the received frames.

The double records a host-observable schedule (`SimDoubleHostScheduleEvent`:
`HorizonAdvance`, `FrameDelivery`, `FrameEmission`, `IoCompletion`, and
`Snapshot`) encoded by `sim_double_host_schedule_canonical_bytes` with the
versioned prefix `crucible.sim-double.host-schedule.v1`. The
`checks.crucible.phase1.gates.hostObservableSchedule` check compares that
schedule byte for byte with the plugin's projection, and the installed plugin
path replays live reached-icount sequences through the double, so a double node
and a real node are indistinguishable at the host boundary.

```text
  property under test                tested via SimDouble?   why
  ---------------------------------  ---------------------   -------------------------
  scheduler quantum ordering         yes                     pure host logic
  cross-node injection icount        yes                     injection is host-side
  SPSC queue correctness             yes                     real queue implementation
  protocol framing / versioning      yes                     real codec
  snapshot / restore round-trip      yes                     host serializes node state
  fork (CoW share with ancestor)     yes                     temporal-graph operation
  replay oracle (fat == thin)        yes                     re-reduce the double's script
  control-plane responsiveness       yes                     no boot needed
  per-VM instruction determinism     NO                      needs real QEMU
  guest non-mutation                 NO                      on-disk image behavior
  patch inertness                    NO                      QEMU behavior
```

## Execution fingerprint

The execution fingerprint is a cheap, periodic digest of one run, defined in
`crates/crucible/crucible-test-support/src/fingerprint/`. Two runs are
bit-identical when their fingerprint streams are identical.

`FingerprintDefinition::canonical()` fixes what a sample covers: the
authenticated on-demand request boundary, full guest memory, device state, and
round-robin vCPU scheduler state. The definition digest is folded into every
stream, so two runs captured under different definitions never compare equal.
The digest covers these tags:

| Constant | Value |
| --- | --- |
| `EXECUTION_FINGERPRINT_DEFINITION_VERSION` | `crucible-execution-fingerprint-v2` |
| `FINGERPRINT_HASH_ALGORITHM` | `crucible-stable-fingerprint-hash-v1` |
| `REGISTER_DIGEST_ALGORITHM` | `host-observed-architectural-register-digest-v1` |
| `MEMORY_DIGEST_ALGORITHM` | `host-observed-full-guest-memory-digest-v1` |
| `DEVICE_DIGEST_ALGORITHM` | `host-observed-device-state-digest-v1` |
| `FINGERPRINT_DIGEST_BYTES` | `32` |

A `FingerprintObserver` obtains host-observed state from a backend.
`FingerprintSampleMaterial` sorts per-vCPU register digests by vCPU id and
rejects an empty node name, an empty vCPU set, or a duplicate vCPU.
`compute_fingerprint_sample` then chains the samples:

```text
fp_0 = H("fingerprint-stream-seed", definition_digest)
fp_n = H("fingerprint-sample", definition_digest, fp_{n-1},
         seq, node, icount, "authenticated-request",
         [vcpu_id, register_digest, retired_count]*,
         rr{current_vcpu, quantum_remaining, [vcpu_id, retired]*},
         memory_digest, device_digest)
```

A `FingerprintSample` stores `seq`, `node`, `icount`, and the
`rolling_fingerprint`; a `FingerprintStream` stores the `definition_digest`,
the samples, and the `final_fingerprint` (the last rolling value, or `fp_0`
for an empty stream). The local hasher is stable and host-independent but not
cryptographic. `compare_fingerprint_streams` reports the first mismatch as a
`FingerprintMismatchKind` of `Definition`, `Sample`, `Length`, or `Final`.

Sampling is observation-only and driven by icount, never by wall-clock, so the
sample positions are themselves deterministic.
`gate:single-vm-fingerprint` boots one unmodified guest twice with a fixed
image, command line, seed, and input sequence and requires identical streams
and final icount; its negative control forces a real divergence and requires
the first differing sample and component to be identified.
`gate:layer0-determinism` runs the guarded production fingerprint authority at
five exact sample targets under bounded host-scheduler preemption, requires
the stream to be identical after restart, and requires a one-instruction
coordinate change to be localized.

`gate:any-guest` boots a generic AOS Linux kernel and initramfs fixture twice
under a diskless launch profile and twice under a guest-visible CoW-block
profile, on real QEMU with no in-guest agent. Both cadence fingerprint streams match exactly,
and the CoW profile writes through `/dev/vda` against a qcow2 overlay while the
copied base image stays byte-identical. Broader off-the-shelf guest image coverage remains outside the
fixture matrix and is not claimed by the gate.

## Divergence bisection

When two runs diverge, `crates/crucible/crucible-test-support/src/divergence.rs`
answers where they first differ. It owns the comparison core; the caller
supplies a probe that resumes a run to an icount.

1. `locate_first_divergence` walks two fingerprint streams in lock step and
   returns the first differing sample. A definition or final-only mismatch is
   not a localizable divergence.
2. `bisect_icount_window` and `bisect_first_different_icount` binary-search the
   icount window between the last agreeing and first differing samples. Each
   step resumes both sides to the midpoint and compares their fingerprints.
   Resuming is cheap and exact because any icount is reachable from the nearest
   checkpoint by replay.
3. `bisect_diverging_runs` combines both steps with a both-sides state dump
   (`DivergenceStateDump`: registers, differing memory regions, recent events)
   in a `DivergenceBisectionReport`. `locate_first_decision_mismatch` compares
   decision traces directly.

`bisect_diverging_runs_with_segment_replay` runs the same search over
checkpoint segments. `segment_replay` replays each checkpoint-to-checkpoint
segment on its own worker, validates the state at every boundary, and joins
canonical-log entries in segment order, so host completion order is never
observable.

Bisection is a pure function of the two runs' artifacts and reports the same
point every time. `gate:divergence-bisect` seeds a known divergence into one of
two identical runs and requires the tool to report exactly that icount and
node.

## Replay oracle

The replay oracle is the structural check of the temporal graph: a fat
(materialized) checkpoint must hash equal to its thin derivation, rebuilt by
re-reducing from an ancestor along the same schedule. The hash is over
canonical state and excludes observational entries. The comparison core is
`crates/crucible/crucible-test-support/src/replay_oracle.rs`:

- `check_replay_oracle` compares `ReplayOracleCase` fat and thin hashes over a
  fixed corpus.
- `check_materialized_replay_oracle` also compares the configuration,
  ancestor, and schedule-delta hashes of a `ReplayOracleMaterializedCase`.
- `check_sampled_search_replay_oracle` samples real search materializations
  (`ReplayOracleSearchMaterialization`) at a deterministic rate and returns a
  `ReplayOracleSearchSamplingReport`. `ReplayOracleSamplingConfig::new` takes a
  numerator, denominator, and seed tag and rejects a zero denominator, a zero
  numerator, a numerator above the denominator, or an empty seed tag.
- `check_sampled_search_replay_oracle_with_bisection` turns a sampled mismatch
  into a bisection request and localizes it to an exact icount or decision when
  diagnostic streams are available.

The engine runs the oracle inline during search:
`TemporalGraph::search_with_replay_oracle_sampling` with a
`SearchReplayOracleSamplingConfig` reconstructs each sampled fat
materialization thin, and a mismatch is the hard error
`EngineError::SearchReplayOracleMismatch`. The fixed corpus runs as
`checks.crucible.phase1.gates.replayOracle` against the double and again as
`checks.crucible.phase4.gates.replayOracle` and
`checks.crucible.phase6.gates.replayOracle` over the full temporal graph and
active search.

## Adversarial determinism

Determinism that holds only on a quiet host is not determinism.
`crates/crucible/crucible-test-support/src/adversarial.rs` runs a fixed scenario
corpus under hostile host conditions and requires byte-identical canonical logs
and final fingerprints. `canonical_host_adversary_matrix()` returns four
`HostAdversaryProfile`s:

| Profile | Workers | Task order | Affinity | Load | Producer/consumer skew |
| --- | --- | --- | --- | --- | --- |
| `quiet-single-core` | 1 | `Forward` | `SingleCore` | quiet | `None` |
| `loaded-single-core` | 1 | `Reverse` | `SingleCore` | spin 4096, yield every 2 | `ProducerFast` |
| `reordered-two-core` | 2 | `SeededPermutation` | `Seeded` | spin 2048, yield every 1 | `ConsumerFast` |
| `loaded-many-core` | 4 | `Strided { stride: 3 }` | `RoundRobin { logical_cores: 4 }` | spin 4096, yield every 1 | `Alternating` |

Profiles are deterministic work plans; no result depends on wall-clock time.
The comparison reports `AdversarialMismatch` for any profile-dependent log or
fingerprint and rejects empty evidence. The canonical
`checks.crucible.phase3.gates.adversarialDeterminism` gate drives the real
`SingleScheduler` through this matrix (engine target
`gate_adversarial_determinism`). It remains the fast diagnostic layer for
isolating scheduler drift, while the native profiles run inside
`gate:e2e-determinism`.

## End-to-end determinism

`gate:e2e-determinism` is the whole-system acceptance gate. The native gate
(`tests/crucible/phase4-e2e-determinism.nix`) runs a representative three-VM
workload over block and 9p sub-nodes with partition, loss, latency, and crash
faults and always, eventually, and sometimes properties, through the
closure-owned patched QEMU and plugin. It runs three host profiles on one
physical host:

```text
quiet-single-core           1 core
randomized-worker-two-core  2 cores, randomized worker scheduling
loaded-io-stall-four-core   4 cores, seeded load, launch jitter, host I/O stalls
```

All profiles must produce identical canonical event streams, identical
non-empty fingerprint streams, and identical reproduction artifacts. The
`quiet-single-core` artifact is then replayed from an empty content store under
`loaded-io-stall-four-core`, and the replay must be byte-identical. Raw profile
and replay output, canonical identities, artifact digests, and the closure
identity are retained in the gate output for diagnosis. The phase7 occurrence
(`tests/crucible/phase7-e2e-determinism.nix`) re-runs the native acceptance
together with the CLI artifact tests, and builds only after the
license-boundary, perf-bench, and release-manifest checks.

`crates/crucible/crucible-test-support/src/e2e.rs` holds the mock-backend driver
shared by the engine's `gate_e2e_determinism_concurrency` and the CLI's
`gate_e2e_determinism` targets.

## Reproduction artifacts

Every failure can emit a self-contained reproduction artifact that carries
`(seed, ScenarioDef, Schedule)` plus pinned producer identities, so a replay
that would silently use a different engine, ABI, or QEMU build fails instead.
The format is `crucible.reproduction-artifact.v4`
(`REPRODUCTION_ARTIFACT_SCHEMA`), media type
`application/vnd.crucible.reproduction+text`, defined in
`crates/crucible/crucible-test-support/src/reproduction.rs`. It is a canonical
tab-separated line format with percent-escaped string fields; large scenario
components are named by content hash and a hermetic `cas:` URI rather than
embedded:

```text
schema  crucible.reproduction-artifact.v4
seed    42
identity  0.1.0  engine-abi:v1  crucible.reproduction-artifact.v4  crucible-hash:...  ...
scenario  scenario_def  cluster.scn  crucible-hash:...  cas:crucible-hash:...  application/vnd.crucible.scenario+text  128
payload  crucible-hash:...  7363656e6172696f
schedule  crucible-hash:...  12
decision  0  1  node-a  deliver  crucible-hash:...
```

The user-facing workflow is in
[../../users/crucible/reproduction.md](../../users/crucible/reproduction.md).

## ABI conformance and fuzzing

The shared-memory layout, the host/plugin protocol, and the control-plane RPC
are versioned data contracts. `gate:abi-conformance` encodes fixed logical
values and compares them byte for byte with frozen golden vectors checked into
the repository, and verifies each version field. The runner in
`crates/crucible/crucible-test-support/src/abi.rs` reports version drift
separately from byte drift. An intentional ABI change bumps the version and
regenerates the vectors in the same change. The aggregate gate
(`checks.crucible.phase2.gates.abiConformance`) covers the shmem layout and
generated header, protocol frames, and the RPC corpus.

The SPSC frame ring is certified by a checked-in exhaustive model rather than
an external model-checking crate: `assert_spsc_ring_exhaustive_ordering_model`
enumerates every producer and consumer interleaving under the declared atomic
orderings, `assert_spsc_ring_exhaustive_trace_properties` checks no loss, no
duplication, FIFO order, full and empty behavior, and wraparound, and
deliberately weakened orderings must fail as negative controls. The model is
built entirely from the workspace, which keeps the hermetic bootstrap free of
two proc-macro-heavy dependency trees without shrinking the covered state
space. `checks.crucible.phase1.concurrencyAbiOracleStandards` emits
`spsc=exhaustive-ordering-model`.

The protocol codec and the block and 9p wire handlers are fuzzed
(the `codec_fuzz` module of `crucible-qemu-protocol` and
`crucible_qemu_plugin::io_wire_fuzz`, run by
`checks.crucible.phase2.protocolCodecFuzz`). The fuzzers assert that
decoding never panics, rejects malformed input with a typed error or decodes
deterministically, and round-trips well-formed input
(`decode(encode(x)) == x`). Findings join a seeded regression corpus.

## QEMU patch microtests and inertness

The AOS QEMU package carries one atomic patch whose simulation controls are
inert unless sim mode is active. `gate:patch-microtests` requires a focused
behavioral test for every capability in the patch, including the ordinary-TCG
picosecond timer adapters, plus one pristine-QEMU attribution negative that
proves the capability set is absent upstream.

`gate:qemu-inert` builds the patched and unpatched QEMU from the same pinned
source and runs both with sim mode off (plugin not loaded, no sim flags). The
patched build must be behaviorally identical to an unpatched reference build
over the checked corpus. The gate compares raw boot and device-I/O serial output, block, 9p, and virtio-rng
output, QMP capabilities and state, and snapshot save and load. Legacy Q35
migration state must be byte-identical apart from the authenticated PIT
picosecond-phase subsection, and patched streams, restore, and re-save must
agree. Only unordered QMP collections and transport metadata are normalized.
The enumerated terminal-lifecycle QMP extension must fail closed and leave a
stopped VM in its original run state. The reference build, patched build, and
guest images are all built from source. See [qemu-patch.md](qemu-patch.md).
