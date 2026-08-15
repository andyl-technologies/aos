# RFC-0013: Signal-driven, cross-domain fault modeling for Crucible

- **Status:** Proposed (design-only). This RFC specifies one atomic replacement
  of Crucible's fault system. No subset is a supported intermediate release;
  the new schema and runtime become authoritative only when the single
  implementation PR satisfies every merge gate in
  [`07-implementation-plan.md`](07-implementation-plan.md).
- **Date:** 2026-08-04
- **PR:** [#187](https://github.com/andyl-technologies/aos/pull/187)
- **Audience:** anyone working on `crates/crucible-*`, the AOS QEMU patch and
  plugin boundary, deterministic device models, scenario authoring, trace
  ingestion, search, replay, or fault-injection documentation.

This is a directory RFC. It generalizes Crucible's current activate/heal fault
plan into a deterministic **signal-driven fault system** shared by networking,
storage, sensors, compute, memory, clocks, power, radios, buses, and other
modeled hardware. The framework owns *when and why* an effect occurs. Strongly
typed domain adapters own *what the effect means* and how overlapping effects
compose.

The design is deliberately broader than mobile-radio simulation. Mobile motion
through a cellular city, a cut fiber conduit, a congested routed path, a
satellite contact window, vibration-induced disk errors, an overheating laptop,
and a drifting industrial sensor all use the same signal, correlation,
opportunity, decision, checkpoint, and replay machinery.

## Problem

Crucible currently represents a fault as a static typed value that is active
between exact activation and heal events. This is correct and useful for finite
partitions, crashes, fixed latency bumps, and fixed probability tables, but it
cannot directly express the important physical cases:

- link quality varying continuously as endpoints move;
- interference, heat, vibration, power, radiation, weather, or load affecting
  several devices at once;
- a sporadic error rate controlled by a recorded or generated temporal signal;
- bursty failures with memory, hysteresis, or recovery state;
- recorded measurements from physical equipment replayed against a simulated
  system;
- a hardware operation failing only at a precise opportunity such as one frame,
  block completion, sensor sample, clock read, memory access, or interrupt;
- shared-media, routed-path, handoff, contact-window, and resource-contention
  behavior that is richer than an independently faulted symmetric link.

Adding a separate scheduled fault variant for every waveform or physical source
would multiply taxonomy without solving correlation, replay, or composition.
Conversely, making faults arbitrary scripts would destroy schema exhaustiveness,
hermeticity, validation, and deterministic replay.

The missing abstraction is a small, exact, content-addressed signal language
that feeds typed fault bindings at deterministic hardware opportunities.

## Design thesis

```text
recorded traces   generated functions   modeled environment   simulation state
       \                 |                       |                    /
        +----------------+-----------------------+-------------------+
                                 |
                        typed SignalProgram
                                 |
              mapping / hysteresis / hazard / state machine
                                 |
                           FaultBinding
                    target + opportunity + effect
                                 |
       +---------------+---------+---------+--------------+
       |               |                   |              |
   networking       storage             sensors       compute/power/...
    adapter          adapter              adapter          adapters
       |               |                   |              |
  frame/path       I/O completion      measurement      typed outcome
    effects           effects             effects          effects
       +---------------+---------+---------+--------------+
                                 |
              decisions + event log + checkpoint state
                                 |
                  recomputed replay or locked replay
```

The system has four separate concepts:

1. A **signal** is a typed value, vector, state, or event over an explicit
   deterministic domain such as virtual time, spatial position, node icount, or
   operation sequence.
2. A **fault opportunity** is the stable point where a modeled operation may be
   affected: frame emission, disk admission, sensor sampling, clock read, and so
   on.
3. A **binding** maps signal output and opportunity context into one typed
   effect over selected targets.
4. A **domain adapter** validates, combines, and applies effects according to
   network, disk, sensor, compute, power, or other hardware semantics.

## Goals

- **[SFM-1]** The design MUST support static, periodic, trace-driven,
  spatiotemporal, stochastic, stateful, and opportunity-driven fault controls
  without arbitrary executable scenario code.
- **[SFM-2]** A single signal MUST be able to control multiple bindings across
  multiple hardware domains so common-cause failures are correlated by
  construction rather than by coincident independent RNG draws.
- **[SFM-3]** Every signal evaluation, probabilistic decision, state transition,
  and applied effect MUST be a pure function of content-addressed scenario
  inputs, the scenario seed, the recorded schedule, and checkpointed model
  state.
- **[SFM-4]** The framework MUST support both replaying recorded physical causes
  and replaying the exact resolved effects that those causes produced.
- **[SFM-5]** Hardware-domain effects MUST remain exhaustively typed and
  validated. The generic framework MUST NOT reduce device behavior to stringly
  typed maps or arbitrary mutation callbacks.
- **[SFM-6]** The signal/binding schema and runtime MUST be the only fault path.
  The implementation PR MUST remove the existing fault-plan entry schema,
  imperative inject/heal forms, compatibility lowering, and their runtime
  branches rather than deprecating or shadowing them.
- **[SFM-7]** The framework MUST support point-to-point, shared-medium,
  switched, routed, overlay, contact-window, and mobile network models, including
  directional behavior and shared failure domains.
- **[SFM-8]** The taxonomy MUST cover representative datacenter, IoT, wired and
  wireless networking, mobile, satellite, laptop, radio, sensor, storage,
  compute, memory, bus, environmental, and power failure modes.
- **[SFM-9]** Search and fuzzing MUST be able to branch on selected signal
  transitions and resolved opportunities without turning every trace sample into
  an unconditional schedule branch.
- **[SFM-10]** The system MUST fail before execution when a scenario requests an
  effect or opportunity that the chosen backend cannot apply deterministically.

## Non-goals

- This RFC does not require transistor-, electromagnetic-field-, fluid-,
  orbital-, or chemical-level first-principles simulation. Technology models may
  use calibrated deterministic transfer functions.
- This RFC does not make every enumerated domain executable. The implementation
  PR accepts every `Core`, `Next`, and `Advanced` effect in the network,
  storage/9p, and node/CPU/memory/interrupt/clock/accelerator sections. Domains
  without an implementation commitment are specification vocabulary only: they
  have no accepted schema variant, runtime enum, feature flag, or placeholder
  adapter.
- This RFC does not implement sensor devices or sensor fault application because
  Crucible's QEMU does not yet expose modeled sensor devices. Sensor truth,
  sampling, and effect semantics remain specified for a later complete adapter;
  the first implementation MUST reject sensor targets and effects as unknown.
- This RFC does not permit live host sensors to influence a canonical run.
  Physical observations are captured and normalized before the run, or admitted
  as explicitly non-canonical control input that forks the run.
- This RFC does not make sensor observations identical to physical truth. A
  scenario may model both, and faults may perturb the observed channel without
  changing truth.
- This RFC does not silently emulate unsupported hardware effects with an
  approximation. Approximation is allowed only under an explicit effect kind or
  declared fidelity policy included in scenario identity.
- This RFC does not replace properties, workload events, or the temporal
  execution graph with the signal program. Signals control modeled environment
  and hardware effects; properties judge behavior; the temporal graph stores
  execution states.

## Non-negotiable invariants

1. **No host nondeterminism.** Signal programs never consult host wall time,
   host scheduling, ambient filesystem state, unrecorded network state, or host
   entropy.
2. **Exact arithmetic.** Canonical evaluation uses integers, rationals, enums,
   and fixed rounding rules. Native floating point is not canonical scenario or
   schedule material.
3. **Stable opportunity identity.** Sporadic choices are keyed by stable
   operation identity, not a mutable global draw cursor whose future shifts when
   an unrelated fault is added.
4. **Explicit state.** Hysteresis, burst models, handoffs, queues, filters,
   battery state, thermal state, wear, and other memory are part of materialized
   state and checkpoints.
5. **Typed application.** A signal never edits guest or device state directly.
   It reaches hardware only through a validated binding and domain adapter.
6. **Causal scheduling.** A dynamic effect cannot move delivery or completion
   into a consumer's past or lower a conservative scheduler bound without an
   admitted boundary transition.
7. **Recorded provenance.** Imported traces retain raw-source provenance and a
   canonical normalized representation. Reproduction artifacts identify both.
8. **Two replay levels.** Recomputed replay proves model determinism; locked
   replay reproduces recorded resolved outcomes and detects incompatible effect
   application.
9. **Deterministic composition.** Overlapping bindings combine by a documented
   per-effect algebra independent of insertion, hash-map, thread, or callback
   order.
10. **Truth/observation separation.** Physical truth, environmental state,
    device internal state, and guest-observed samples are distinct unless a
    scenario explicitly binds them together.

## Existing implementation seam

The implementation uses one deterministic spine:

- [`FaultSignalPlan`](../../../crates/crucible/src/model/fault_signal/plan.rs)
  is the sole admitted fault-program representation. It owns validated signal
  programs, bindings, resource limits, and their canonical identity.
- [`TransactionalFaultAdapters`](../../../crates/crucible/src/model/fault_signal/adapter_runtime.rs)
  owns deterministic composition and transactional commit for the network,
  storage, and node domains.
- [`ResolvedBindingAction`](../../../crates/crucible/src/model/fault_signal/binding_runtime.rs)
  is the typed application contract between evaluated bindings and those
  adapters.
- The former fault-plan authoring and runtime hierarchy is removed completely;
  it creates no compatibility obligation for the replacement schema.
- [`LinkFaults`](../../../crates/crucible-device/src/netlink/fault.rs) and
  [`NetLink`](../../../crates/crucible-device/src/netlink/link.rs) already apply
  deterministic per-frame timing, capacity, loss, duplication, reordering, and
  corruption transforms.
- [`SchedulerState`](../../../crates/crucible/src/model/materialized.rs) captures
  deterministic device cursors, pending work, and finite search frontiers in
  checkpoint state; fault-runtime state is authenticated alongside it.
- The unified event log and schedule record raw decisions and resolved fault
  outcomes.

Signal-program state and the binding evaluator feed the domain-specific
combination/application seam directly. No legacy schema, lowering layer,
parallel active-fault table, or alternate execution path remains.

## Conventions and requirement IDs

The capitalized words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** have their RFC-2119/RFC-8174 meanings. Stable requirement IDs use these
prefixes:

| Prefix | Area | Primary file |
| --- | --- | --- |
| `SFM` | Whole-system goals and atomic replacement | this README |
| `SIG` | Signal values, sources, operators, state, and identity | 01 |
| `OPP` | Hardware opportunity and target identity | 02 |
| `BIND` | Bindings, effects, adapters, capabilities, and runtime | 02 |
| `NET` | Network segments, paths, media, mobility, and contacts | 03 |
| `TAX` | Cross-domain taxonomy and extension rules | 04 |
| `REP` | Recording, replay, observability, checkpoints, and calibration | 05 |
| `FX` | Closed executable effect registry and taxonomy ledger | 08 |
| `SCHEMA` | Normative v2 scenario schema and canonical encoding | 09 |
| `NTECH` | Network technology and transition contracts | 10 |
| `STORE` | Storage durability, media, controller, array, and 9p semantics | 11 |
| `SENSOR` | Complete future sensor-adapter specification | 12 |
| `LIMIT` | Admission ceilings and performance gates | 13 |
| `QFP` | QEMU patch-series boundary, licensing, and aggregate gates | 14 |

All fenced blocks are tagged `text` or `toml`. Blocks in §9 are normative schema
fragments; §6 explicitly labels its focused authoring excerpts and any
specification-only sensor syntax. Normative registries, field tables, and
requirements win if explanatory excerpts omit surrounding context.

## Reading order

1. [`01-signal-program.md`](01-signal-program.md) defines typed signals,
   evaluation domains, exact operators, stateful nodes, spatial fields, trace
   sources, and canonicalization.
2. [`02-opportunities-bindings-runtime.md`](02-opportunities-bindings-runtime.md)
   defines stable opportunities, target selectors, binding mappings, effect
   phases, composition, capabilities, checkpoint state, and search.
3. [`03-network-paths-and-media.md`](03-network-paths-and-media.md) applies the
   framework to every major network-link structure, including shared media,
   routed paths, cellular mobility, satellite contact, and correlated
   interference.
4. [`04-fault-taxonomy.md`](04-fault-taxonomy.md) enumerates the cross-domain
   fault vocabulary, implementation boundary, model tiers, targets, controls,
   and effects.
5. [`05-recording-replay-observability.md`](05-recording-replay-observability.md)
   specifies raw/normalized traces, cause versus outcome replay, provenance,
   event-log records, checkpoints, debugging, and calibration.
6. [`06-schema-and-examples.md`](06-schema-and-examples.md) provides worked
   correlated-fault examples using the normative schema.
7. [`07-implementation-plan.md`](07-implementation-plan.md) defines the parallel
   workstreams and single atomic merge gate for the implementation PR.
8. [`08-executable-effect-contracts.md`](08-executable-effect-contracts.md)
   closes the effect registry and maps every executable taxonomy row to typed
   target, opportunity, composition, state, evidence, and capability semantics.
9. [`09-normative-schema.md`](09-normative-schema.md) defines the exhaustive,
   strict v2 schema, defaults, validation, limits, and canonical material.
10. [`10-network-technology-contracts.md`](10-network-technology-contracts.md)
    specifies every executable wired, shared-medium, routed, radio, mobile, and
    satellite technology model.
11. [`11-storage-durability-and-media.md`](11-storage-durability-and-media.md)
    specifies cache, persistence, media, controller, array, and 9p state
    machines.
12. [`12-sensor-adapter-specification.md`](12-sensor-adapter-specification.md)
    fixes the complete future sensor contract without adding first-PR schema or
    code.
13. [`13-resource-and-performance-bounds.md`](13-resource-and-performance-bounds.md)
    fixes hard admission ceilings, required algorithms, and performance gates.
14. [`14-qemu-fault-patches/`](14-qemu-fault-patches/) specifies each required
    QEMU mutation as a separate ordered, licensed patch with live acceptance
    tests.

## Locked architectural decisions

| Decision | Choice | Reason |
| --- | --- | --- |
| Control/effect split | Signals and bindings are generic; effects are domain-typed. | Preserves reuse without losing validation or physical meaning. |
| Execution | Signals form a closed declarative DAG, not a script runtime. | Keeps scenarios hermetic, analyzable, bounded, and content-addressable. |
| Arithmetic | Integer/rational with named units and fixed rounding. | Avoids platform-dependent floating-point results. |
| Sporadic choices | Counter-based keyed decisions per stable opportunity. | Prevents unrelated model changes from shifting future decisions. |
| Correlation | Shared signals and explicit fault domains. | Correlation is a modeled cause, not accidental RNG alignment. |
| Trace ingestion | Raw artifact plus normalized canonical artifact. | Retains provenance while making replay parser-independent. |
| Replay | Both recomputed-cause and locked-effect modes. | Supports determinism proofs and faithful incident reproduction. |
| Dynamic networking | Directed segment/path profiles sampled at canonical boundaries. | Covers wired, wireless, routed, mobile, and contact networks uniformly. |
| Migration | The old fault schema and runtime are removed in the implementation PR. | Prevents two semantic paths and makes incomplete migration impossible to ship. |
| Backend support | Explicit capability negotiation and fail-closed validation. | Prevents silent low-fidelity substitution. |
| Delivery | One atomic implementation PR and one complete merge gate. | Prevents MVP, feature-flagged, stubbed, or partially accepted states. |

## Locked implementation choices

The first implementation does not defer these choices:

1. Canonical serialized scalars use signed or unsigned 64-bit integers with
   named units. Probabilities use unsigned millionths. Rational values use a
   signed 64-bit numerator and positive 64-bit denominator in lowest terms.
   Multiply/divide intermediates use checked signed or unsigned 128-bit
   arithmetic; overflow is an admission or evaluation error according to the
   node's declared policy.
2. Large normalized traces use a canonical manifest over independently
   content-addressed per-channel chunks of at most 4,096 samples or events.
   Chunking, byte order, coordinate bounds, and digest material are versioned.
3. Networking implements both token-bucket service and piecewise-constant
   integrated service curves, plus their shared-scheduler composition. The
   sample-at-emission behavior is not retained as a lower-fidelity runtime path.
4. The QEMU patch/plugin boundary implements and advertises every capability
   needed by the first-PR node effect set, including exact-boundary memory and
   register mutation, interrupt control, machine checks, lifecycle transitions,
   and throttling. An effect is not added to the accepted schema until its live
   QEMU gate passes.
5. The first implementation uses built-in exact transfer functions and imported
   canonical lookup tables. It introduces no external physical-model library.

## Resolved specification contracts

The RFC resolves the formerly merge-blocking design gaps before implementation:

| Contract | Normative resolution |
| --- | --- |
| Closed effect ledger | [§8](08-executable-effect-contracts.md) maps every `Core`, `Next`, and `Advanced` network, storage/9p, and node row to registered executable semantics and evidence. |
| Exhaustive schema | [§9](09-normative-schema.md) fixes the strict v2 grammar, values, defaults, validation, canonicalization, and rejection behavior. |
| QEMU ABI and mutations | [§14](14-qemu-fault-patches/) separates thirteen required patches and fixes their commands, phases, state, architecture behavior, live tests, and GPL/DCO obligations. |
| Storage state machines | [§11](11-storage-durability-and-media.md) fixes cache, persistence, atomicity, reset, power loss, media, wear, retry, controller, array, and 9p behavior. |
| Network technology models | [§10](10-network-technology-contracts.md) fixes wired, shared-medium, routed, overlay, radio, mobile, and satellite state machines and in-flight policies. |
| Future sensor adapter | [§12](12-sensor-adapter-specification.md) is complete design vocabulary but creates no accepted v2 schema or implementation path. |
| Enforceable bounds | [§13](13-resource-and-performance-bounds.md) fixes admission ceilings, algorithms, event/checkpoint/search limits, and performance gates. |

These documents are part of this RFC, not optional follow-up work. Any new
consequential choice discovered during implementation must amend and review the
relevant contract before its code lands; it cannot be hidden in a fallback,
stub, test double, or undocumented backend convention.

## Atomic completeness rule

The implementation PR MUST NOT merge with dormant feature flags, accepted but
unapplied effect variants, placeholder adapters, `todo!`/`unimplemented!`
branches, fallback approximations, or separate old/new fault engines. Every
accepted schema value must pass model, codec, canonicalization, real production
backend application, checkpoint, recomputed-replay, locked-replay, event-log,
CLI/reference, and malformed-input gates. Test-double backends are prohibited;
pure state-transition unit tests supplement but never replace production-path
evidence. Specification-only taxonomy rows are prose, not code.

## Relationship to RFC-0010

RFC-0010 establishes Crucible's determinism, scheduler, device, trigger,
event-log, checkpoint, and search contracts. RFC-0013 supersedes RFC-0010's
fault schema and execution path while retaining those surrounding determinism
contracts. It does not rewrite RFC-0010's historical text. When implemented:

- the old interval, permanent, activation, and heal schema is rejected and its
  implementation is deleted;
- typed per-device adapter state remains the final application boundary, but the
  former generic active-fault path does not;
- opportunity-keyed decisions replace variable-consumption RNG behavior for all
  operation-level fault choices;
- signal state joins the canonical state reduced and replayed by RFC-0010's
  execution model.

The canonical user documentation must describe only shipped schema and values;
this RFC remains a target design until its implementation gates pass.
