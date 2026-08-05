# 07 — Atomic implementation plan and merge gates

RFC-0012 is implemented by one large pull request. The workstreams below provide
an engineering order and review ownership; they are not independently shippable
phases, MVPs, feature flags, or accepted intermediate repository states. The PR
must remain draft until every workstream and the single final gate are complete.

## 7.1 Exact implementation boundary

The PR implements the entire generic system:

- typed signal values, domains, sources, pure and stateful operators, spatial
  fields, exact arithmetic, graph validation, canonical identity, and resource
  bounds;
- normalized trace manifests/chunks, import, seeking, provenance, alignment,
  redaction, recording, and content-addressed storage;
- stable opportunities, typed selectors, mappings, lifetime classes,
  composition, adapter contracts, and fine-grained capabilities;
- canonical runtime state, checkpoints, time travel, event logging, search,
  minimization, recomputed replay, and locked-effect replay;
- complete network, storage/9p, and node adapters for every `Core`, `Next`, and
  `Advanced` taxonomy row assigned to those domains;
- CLI/builders, exhaustive reference documentation, examples, diagnostics, and
  live-backend conformance tests.

The PR does not implement sensor devices, IoT bus/peripheral/actuator adapters,
or dedicated power/battery/cooling device models. Those domain items remain
prose only. They must not appear in Rust enums, TOML schemas, codecs, generated
references, capability manifests, runtime dispatch, feature flags, or
placeholder modules. Accelerator faults are part of the complete node scope.

Power, heat, motion, weather, vibration, radiation, interference, and load may
be signal sources that drive supported network, storage, or node effects. That
does not create a separate device adapter.

## 7.2 No legacy or partial path

- [ ] **T-ATOM-1** Remove `FaultPlanEntry`, finite/permanent fault entries,
  imperative `inject_fault`/`heal_fault`, fault activation/heal scheduler
  payloads, old fault-tag state, old random-fault configuration, and their
  builders, codecs, CLI surfaces, examples, tests, and documentation.
- [ ] **T-ATOM-2** Replace the old `Fault` execution hierarchy with the new
  signal/binding/typed-adapter representation. Existing device algorithms may
  be moved into adapters; the old dispatcher and active-fault tables may not
  remain alongside them.
- [ ] **T-ATOM-3** Bump the scenario schema version. Older scenario versions
  fail admission with a concise migration error and are not parsed, lowered, or
  replayed by a compatibility engine.
- [ ] **T-ATOM-4** Add repository guards for retired type, field, event, and CLI
  names. Historical RFC text and an explicit migration guide are the only
  allowed occurrences.
- [ ] **T-ATOM-5** Prohibit dormant feature flags, placeholder adapters,
  accepted-but-unapplied variants, fallback approximations, `todo!`,
  `unimplemented!`, and wildcard handling of effect or operator enums.

Static and interval behavior is authored directly as constant, pulse, step, or
event-sequence signals. It exercises the same evaluator, binding, composition,
checkpoint, and replay path as every other fault.

## 7.3 Signal and trace workstream

This workstream implements the closed grammar in
[`09-normative-schema.md`](09-normative-schema.md) within the ceilings and
algorithms in
[`13-resource-and-performance-bounds.md`](13-resource-and-performance-bounds.md).

- [ ] **T-SIG-1** Implement the complete typed value/unit set using validated
  `i64`/`u64` stored values, probability millionths, reduced rationals, and
  checked `i128`/`u128` intermediates with explicit rounding/overflow policy.
- [ ] **T-SIG-2** Implement virtual-time, node-counter, operation, spatial,
  event, and modeled-state domains with explicit sampling/projection nodes.
- [ ] **T-SIG-3** Implement constant, step, pulse, periodic pulse, ramp,
  event-sequence, normalized trace, spatial point/grid/zone/seeded field, and
  admitted telemetry sources.
- [ ] **T-SIG-4** Implement every pure operator in §1.4 and every stateful
  operator in §1.5, including hysteresis, debounce, filters, integration,
  counter, finite-state machine, burst process, and delay state.
- [ ] **T-SIG-5** Implement counter-based keyed stochastic choices and hazard
  integration without a shared mutable RNG cursor.
- [ ] **T-SIG-6** Implement exact next-change/crossing discovery and scheduler
  boundary admission. Continuous values are evaluated on demand and do not
  create periodic polling events.
- [ ] **T-SIG-7** Implement graph type checking, cycle detection, canonical
  topological order, semantic versioning, content identity, bounds, and complete
  malformed-input diagnostics.
- [ ] **T-TRACE-1** Specify and implement the canonical trace binary codec:
  manifest, per-channel chunks of at most 4,096 entries, byte order, integer
  widths, string normalization, digest domains, indexes, and bounds.
- [ ] **T-TRACE-2** Implement exact time alignment, piecewise clock correction,
  coordinate frames, quality channels, missing-data policies, and deterministic
  spatial redaction.
- [ ] **T-TRACE-3** Implement generic typed CSV and JSONL import/export plus
  PCAP/PCAPNG network-outcome import. These are hermetic AOS-built tools; a run
  never parses raw capture formats.
- [ ] **T-TRACE-4** Implement trace capture/provenance manifests, seekable store
  objects, dependency closure, resource limits, malformed fixtures, and
  deterministic repeated-import gates.

## 7.4 Opportunities, bindings, state, replay, and search workstream

The registries, algebras, and taxonomy mapping in
[`08-executable-effect-contracts.md`](08-executable-effect-contracts.md) are
normative inputs to generated schema, code, capabilities, evidence, and docs.

- [ ] **T-BIND-1** Implement stable opportunity schemas for every supported
  network frame/path/queue transition, block/9p operation, and node/QEMU
  boundary. Identity must be invariant under unrelated bindings and host
  scheduling.
- [ ] **T-BIND-2** Implement typed selectors, static target resolution, dynamic
  association/route/domain membership, empty-selection policy, and symbolic
  target resolution before execution.
- [ ] **T-BIND-3** Implement every mapping kind, lifetime class, persistent
  contribution, impulse record, and deterministic boundary ordering specified
  in §2.
- [ ] **T-BIND-4** Implement adapter-owned composition algebras with contributor
  attribution, conflict rejection, canonical ordering where order is physical,
  and property tests independent of TOML/map insertion order.
- [ ] **T-BIND-5** Generate versioned capability manifests from the same closed
  effect registry used by schema validation. Admission fails before guest start
  if any required production capability or declared bound is absent.
- [ ] **T-STATE-1** Add every signal, binding, adapter, queue, path, medium,
  association, storage media, durability, node, QEMU, and trace-cursor state item
  to canonical state, fingerprints, fat checkpoints, thin reconstruction, and
  savepoint dependency closure.
- [ ] **T-REPLAY-1** Implement recomputed replay with first-divergence evidence
  for signals, opportunities, decisions, composition, application, event log,
  and final fingerprints.
- [ ] **T-REPLAY-2** Implement resolved-effect recording and locked replay with
  exact target, opportunity, phase, profile, capability version, precondition,
  and final-fingerprint validation. No semantic-version compatibility shim is
  included.
- [ ] **T-SEARCH-1** Implement finite outcome/transition/parameter branching,
  bounded trace-window and mapping mutation, independence analysis, schedule
  export, and signature-preserving minimization.
- [ ] **T-OBS-1** Implement the complete typed event vocabulary in §5.6,
  JSON/JSONL rendering, configurable high-rate sample retention, causal
  explanation, provenance inspection, and sensitive-export closure reporting.

## 7.5 Complete network adapter workstream

The network adapter implements every row in §§4.2–4.4 according to the closed
ledger in [§8](08-executable-effect-contracts.md), the technology contracts in
[§10](10-network-technology-contracts.md), and the bounds in
[§13](13-resource-and-performance-bounds.md). The taxonomy table and generated
effect registry must have a checked one-to-one mapping; a row cannot be marked
executable merely because a generic loss or latency approximation exists.

- [ ] **T-NET-1** Replace the current logical-link model with directed
  interfaces, segments, forwarders, queues, paths, shared media, route and
  association state, and explicit physical/administrative fault domains.
- [ ] **T-NET-2** Implement `EffectiveLinkProfile` with attributed propagation,
  access, processing, serialization, queue, jitter, reorder, retransmission,
  service, availability, loss, duplication, corruption, MTU, and technology
  state.
- [ ] **T-NET-3** Implement integrated piecewise-constant service, token buckets,
  bounded queues, strict priority, weighted round-robin, fixed slots, overflow,
  backpressure, shared load, and checkpointed accounting. A stateless
  sample-at-emission rate path is not retained.
- [ ] **T-NET-4** Implement ordered path traversal, encapsulation/MTU behavior,
  segment-local opportunities, bounded loops, ECMP, route transition,
  convergence, asymmetry, blackhole, and in-flight/buffer treatment.
- [ ] **T-NET-5** Implement switch, router, firewall, NAT, tunnel, load-balancer,
  provider, conduit, chassis, line-card, and control-plane effects required by
  the executable taxonomy.
- [ ] **T-NET-6** Implement joint shared-medium transmission ordering,
  occupancy, arbitration, collision/capture, backoff, interference, channel
  allocation, and fair/shared service for the listed wired buses and radios.
- [ ] **T-NET-7** Implement exact truth trajectories, spatial attenuation and
  interference fields, channel-profile lookup, association, authentication,
  roaming, cellular handoff/reselection, radio reconnect, and observed network
  telemetry.
- [ ] **T-NET-8** Implement satellite/contact traces, range-varying propagation,
  acquisition, beam/gateway handover, rain/weather fade, shared transponder
  service, bounded store-and-forward queues, and contact-plan routing.
- [ ] **T-NET-9** Implement outcome, channel, and mobility/environment replay,
  including exact packet/frame alignment modes and fail-loud ambiguity.
- [ ] **T-NET-10** Provide isolated, overlap, shared-cause, mobility revisit,
  queue conservation, checkpoint, search, and both replay tests for every
  executable network effect and every supported network structure.

## 7.6 Complete storage and 9p adapter workstream

The storage adapter implements every row in §4.6 according to the closed ledger
in [§8](08-executable-effect-contracts.md), the state machines in
[§11](11-storage-durability-and-media.md), and the bounds in
[§13](13-resource-and-performance-bounds.md), including stateful durability and
media behavior rather than approximating them as completion errors.

- [ ] **T-STOR-1** Implement admission, queue, resolve, persistence, flush, reset,
  and delivery opportunities for block and 9p operations with stable IDs.
- [ ] **T-STOR-2** Implement integrated bandwidth/IOPS service, queue depth,
  latency/jitter, stall/timeout, typed errors, reorder, corruption, stale data,
  and read-only/offline/reset transitions.
- [ ] **T-STOR-3** Implement explicit volatile-cache and durable-media state so
  lost writes, torn/partial writes, reordered persistence, volatile-cache loss,
  and lying flushes have distinct testable semantics.
- [ ] **T-STOR-4** Implement persistent bad ranges, latent failures,
  program/erase failures, wear state, controller/path loss, RAID/multipath
  degraded state, and rebuild load for all executable rows.
- [ ] **T-STOR-5** Implement filesystem-facing errno, stale data/metadata, reset,
  visibility, and ordering semantics for every executable 9p row.
- [ ] **T-STOR-6** Include cache, durability, wear, bad-range, queue, retry,
  controller, and multipath state in snapshots, fingerprints, event evidence,
  search, and both replay modes.
- [ ] **T-STOR-7** Provide live shared-memory block and 9p conformance gates plus
  isolated, overlap, power/reset common-cause, checkpoint, and mismatch tests for
  every executable storage effect.

## 7.7 Complete node and QEMU adapter workstream

The node adapter implements every row in §4.5 according to the closed ledger in
[§8](08-executable-effect-contracts.md) and the patch contracts in
[`14-qemu-fault-patches/`](14-qemu-fault-patches/). This expands well beyond the
current crash/slow/clock-skew implementation and requires new patched-QEMU/plugin
APIs. Mock, fake, and test-double backends are prohibited; every effect must
produce live patched-QEMU architectural or device evidence.

- [ ] **T-NODE-1** Implement crash, hang, boot failure, power-cycle reset,
  intermittent reset, restart/recovery, and volatile-state-loss semantics at
  exact scheduler boundaries.
- [ ] **T-NODE-2** Implement CPU capacity and thermal throttling, vCPU stall and
  offline state, register bit flips, and architecture-specific machine checks
  with exact vCPU/register/exception schemas.
- [ ] **T-NODE-3** Implement dropped, delayed, duplicate, spurious, and storm
  interrupt effects with exact source, target vCPU, vector/type, phase, and
  round-robin delivery semantics.
- [ ] **T-NODE-4** Implement transient memory bit flips, persistent stuck-at,
  opportunity-specific read corruption, poison, corrected and uncorrectable ECC
  events, persistent failed ranges, and memory latency/bandwidth degradation.
- [ ] **T-NODE-5** Implement guest clock offset, exact rational drift, jump,
  freeze, jitter/wander, and synchronization-loss state without changing global
  scheduler time.
- [ ] **T-NODE-6** Implement instruction-result corruption, instruction
  skip/replay, illegal/spurious exception injection, lost/torn memory writes,
  retention decay, rowhammer-style disturbance, clock-source fallback, and all
  other `Advanced` CPU/memory/clock rows with exact architectural opportunities.
- [ ] **T-NODE-7** Implement accelerator disappearance/reset, result corruption,
  device-memory/ECC error, and thermal/power throttle for declared QEMU GPU,
  TPU, and FPGA device classes with complete device-specific capability gates.
- [ ] **T-QEMU-0047** Implement
  [`crucible-fault-command-abi`](14-qemu-fault-patches/01-command-abi.md): the
  closed command/result layouts, dispatcher, version negotiation, capability
  enumeration, failure statuses, ring ownership, and ABI microtests.
- [ ] **T-QEMU-0048** Implement
  [`crucible-fault-safe-boundary`](14-qemu-fault-patches/02-safe-boundary.md):
  exact-icount arming, all-vCPU/device quiescence, authorization, ordered commit,
  acknowledgement, past-boundary rejection, and boundary microtests.
- [ ] **T-QEMU-0049** Implement
  [`crucible-memory-boundary-mutate`](14-qemu-fault-patches/03-memory-boundary-mutation.md):
  atomic GPA/GVA impulse mutation, translation records, before/after evidence,
  dirty tracking, translation-cache handling, and x86-64/AArch64 live tests.
- [ ] **T-QEMU-0050** Implement
  [`crucible-memory-access-faults`](14-qemu-fault-patches/04-memory-access-faults.md):
  load/store/fetch/DMA transforms, stuck and failed ranges, poison, lost/torn
  writes, retention, rowhammer disturbance, memory service, state, and live
  access-path tests.
- [ ] **T-QEMU-0051** Implement
  [`crucible-register-mutate`](14-qemu-fault-patches/05-register-mutation.md):
  complete architecture register manifests, typed bit/field mutation, derived
  state repair, persistent stuck rules, evidence, and live register tests.
- [ ] **T-QEMU-0052** Implement
  [`crucible-instruction-faults`](14-qemu-fault-patches/06-instruction-faults.md):
  instruction metadata and exact result corruption, skip, replay, illegal and
  spurious exception semantics, ordering, state, and live instruction tests.
- [ ] **T-QEMU-0053** Implement
  [`crucible-interrupt-faults`](14-qemu-fault-patches/07-interrupt-faults.md):
  architecture interrupt manifests and exact drop, delay, duplicate, replace,
  and storm behavior across request, pending, selection, and delivery phases.
- [ ] **T-QEMU-0054** Implement
  [`crucible-hardware-error-inject`](14-qemu-fault-patches/08-hardware-errors.md):
  x86 machine checks, AArch64 hardware errors, corrected and uncorrectable ECC,
  platform reporting, guest acknowledgement, and architecture-specific tests.
- [ ] **T-QEMU-0055** Implement
  [`crucible-vcpu-service-control`](14-qemu-fault-patches/09-vcpu-service.md):
  rational capacity credits, thermal throttle, deterministic stall and offline
  state, multi-vCPU scheduling, VMState, and live throughput tests.
- [ ] **T-QEMU-0056** Implement
  [`crucible-node-lifecycle-faults`](14-qemu-fault-patches/10-node-lifecycle.md):
  crash, hang, boot failure, reset, power-cycle, restart/recovery, volatile-state
  policies, process lifecycle acknowledgement, and live reboot tests.
- [ ] **T-QEMU-0057** Implement
  [`crucible-guest-clock-faults`](14-qemu-fault-patches/11-guest-clocks.md): every
  guest-visible clock source, offset, rational drift, jump, freeze,
  jitter/wander, source failure/fallback, synchronization loss, timer rearming,
  VMState, and live clock tests.
- [ ] **T-QEMU-0058** Implement
  [`crucible-accelerator-fault-device`](14-qemu-fault-patches/12-accelerator-device.md):
  a real QEMU/virtio GPU, TPU, and FPGA co-simulation device and applicable
  virtio-gpu hooks with lifecycle, result, memory/ECC, service, guest driver,
  workload, VMState, and live tests; no in-memory substitute is accepted.
- [ ] **T-QEMU-0059** Implement
  [`crucible-fault-vmstate`](14-qemu-fault-patches/13-vmstate-and-final-gates.md):
  save/restore for all fault state, a cross-patch snapshot barrier, system
  evidence closure, rollback/revert-sensitive tests, inertness/performance gates,
  and final capability closure.
- [ ] **T-QEMU-LICENSE** Land every numbered patch as a separate DCO-signed
  commit, retain applicable upstream notices, update the series/catalog/license
  inventories, preserve the public shared-memory process boundary, and ship the
  identity-matched complete corresponding source required by
  [§14.2](14-qemu-fault-patches/README.md#142-process-and-license-boundary).

## 7.8 Specification-only domain guard

- [ ] **T-SPEC-1** Keep sensor truth/observation, sensor samples, IoT buses,
  actuators, power devices, batteries, and thermal/cooling devices documented in
  the taxonomy and examples only.
- [ ] **T-SPEC-2** Add negative schema tests proving every specification-only
  target and effect is rejected as unknown, plus source guards proving no
  placeholder runtime type or capability ID exists.
- [ ] **T-SPEC-3** Document the rule for a later implementation: its RFC and PR
  must add the entire domain adapter, all selected effects, live capabilities,
  state/replay/search support, exhaustive reference, and gates atomically.

## 7.9 Documentation and operability workstream

- [ ] **T-DOC-1** Generate the user reference from closed registries for every
  signal source/operator, mapping, selector, opportunity, network/storage/node
  effect, field, unit, default, composition rule, capability, and example.
- [ ] **T-DOC-2** Add beginner and advanced examples for static faults, recorded
  traces, city mobility, shared interference, routed failure domains, satellite
  contact, storage durability, memory corruption, clock drift, and correlated
  rack power/vibration causes.
- [ ] **T-DOC-3** Add CLI inspection for signal graphs, trace provenance,
  capabilities, fault-domain fan-out, opportunity/effect records, checkpoint
  dependencies, replay divergence, and sensitive export closure.
- [ ] **T-DOC-4** Publish a breaking migration guide showing how to rewrite old
  scenarios. It is documentation only; no runtime migration parser is retained.

## 7.10 Per-kind completeness matrix

One generated registry is authoritative for accepted values. For each accepted
signal node, mapping, selector, opportunity, or effect kind, CI requires links to
all applicable evidence:

| Evidence | Required |
| --- | --- |
| Strict TOML/schema and unknown-field rejection | Yes |
| Public Rust builder and documented fields | Yes |
| Canonical material, codec, and golden vector | Yes |
| Type/unit/target/phase validation | Yes |
| Composition and overlap semantics | Yes |
| Mock, fake, or test-double backend | Prohibited |
| Live production-backend application and observed-state evidence | Yes |
| Event-log and human diagnostic projection | Yes |
| Fat checkpoint and thin reconstruction | Yes |
| Recomputed and locked replay | Yes |
| Search behavior or explicit non-branching rationale | Yes |
| Malformed, bounds, and capability-negative tests | Yes |
| Exhaustive user-reference row and configuration example | Yes |

Generation fails if an accepted kind lacks an evidence record or if the docs
claim executable support for a kind absent from the registry.

## 7.11 Single merge gate

**Gate `gate:signal-fault-system`:** the implementation PR may leave draft only
when all of the following are true:

1. Every task in §§7.2–7.9 is complete in the same PR.
2. The per-kind completeness matrix has no missing cell for any accepted value.
3. Repository guards find no retired fault path, placeholder, dormant feature,
   accepted specification-only value, silent fallback, wildcard effect dispatch,
   or unfinished implementation marker.
4. All canonical and binary artifacts are byte-identical across repeated runs,
   input row orders, supported architectures, checkpoint/resume, and replay.
5. Live QEMU, network, block, and 9p gates cover every advertised production
   capability and prove exact boundary application.
6. A cross-domain fleet scenario combines shared power, vibration, movement,
   interference, routed network, satellite contact, storage durability, CPU,
   memory, interrupt, and clock effects; search minimizes a failure and ordinary
   locked replay reproduces it without the explorer.
7. Every imported artifact and dependency is hermetic, content-addressed,
   bounded, exportable, and covered by provenance/privacy inspection.
8. User documentation is exhaustive for accepted values and clearly labels all
   prose-only taxonomy items as unavailable.
9. The complete workspace test suite and all RFC-0010 determinism, live QEMU,
   checkpoint, replay, packaging, and hermetic-build gates remain green.

There is no “partially implemented” RFC status. Before this gate passes,
RFC-0012 remains design-only and none of its new schema is released. After it
passes, the old fault system is gone and the new network, storage, and node fault
system is the sole supported implementation.

## 7.12 Requirement coverage

| Requirements | Primary workstreams |
| --- | --- |
| `SFM-1`–`SFM-10` | Atomic replacement, all workstreams, and the single merge gate |
| `SIG-1`–`SIG-28` | Signal and trace workstream |
| `OPP-1`–`OPP-9` | Opportunities/bindings plus all three adapters |
| `BIND-1`–`BIND-26` | Binding/state/replay/search and legacy removal workstreams |
| `NET-1`–`NET-33` | Complete network adapter workstream |
| `TAX-1`–`TAX-9` | Exact boundary, per-kind matrix, and specification-only guard |
| `REP-1`–`REP-29` | Trace, state, replay, observability, and operability workstreams |
| `FX-1`–`FX-8` | Generated registries, all adapters, per-kind matrix, and docs |
| `SCHEMA-1`–`SCHEMA-6` | Signal/binding implementation, codecs, and admission tests |
| `NTECH-1`–`NTECH-8` | Complete network adapter and live network gates |
| `STORE-1`–`STORE-7` | Complete storage/9p adapter and live storage gates |
| `SENSOR-1`–`SENSOR-5` | Specification-only domain guard and future sensor contract |
| `LIMIT-1`–`LIMIT-6` | Admission, algorithmic, performance, and stress gates |
| `QFP-1`–`QFP-5` and `QFP-*` patch requirements | Separate QEMU patch tasks, live tests, VMState, packaging, and licensing |
