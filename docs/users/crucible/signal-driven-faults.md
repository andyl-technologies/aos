# Signal-driven faults

Crucible models a fault as a value that changes over an experiment, connected
to a precisely defined hardware or network effect. The same mechanism covers a
constant outage, a short pulse, a recorded trace, movement through a radio
field, a storage failure, and an architectural CPU or memory mutation.

This guide explains how to design those experiments. The
[reference](reference.md#plans-signals-bindings-and-faults) is the exhaustive
field and value catalog. The implementation source of truth is the
[signal model](../../../crates/crucible/src/model/fault_signal/mod.rs),
[binding model](../../../crates/crucible/src/model/fault_signal/binding.rs), and
[effect registry](../../../crates/crucible/src/model/fault_signal/effect_registry.rs).

## The four parts of a fault

Read a fault from left to right:

```text
signal graph -> binding -> target opportunity -> typed effect and evidence
```

1. A **signal graph** describes the cause over an explicit coordinate domain.
   Examples are `true` for an outage, temperature over virtual time, position
   along a route, or vibration replayed from a trace.
2. A **binding** says when to sample the signal and how to map its typed value
   to an effect. It also gives the fault a stable identity.
3. A **target and opportunity** identify the physical object and exact phase at
   which the adapter may act. Packet admission, block persistence, a memory
   load, and an interrupt delivery are different opportunities.
4. A **typed effect** declares the hardware behavior. Its adapter records the
   contributors, precondition, applied result, capability version, and replay
   evidence.

Do not encode a physical cause directly as an unrelated outcome. For example,
model rack vibration once as a signal, then bind it to a storage media effect
and a network connector effect. This preserves the common cause in replay and
lets search mutate it coherently.

## Start with the coordinate domain

Choose the domain before choosing a source:

| Domain | Use it for | Typical sampling point |
| --- | --- | --- |
| `virtual_time` | Weather, maintenance windows, motion, heat, power, contact schedules | Scheduler boundary or exact signal change |
| `node_counter` | Retired-instruction or node-local progress effects | QEMU safe boundary |
| `operation` | Per-frame, per-I/O, per-instruction, or per-access behavior | Typed adapter opportunity |
| `spatial` | Position, distance, zones, attenuation, and interference fields | Route or channel resolution |
| `event` | Reset impulses, transitions, alarms, and recorded discrete events | Stable event identity |
| `state` | Feedback-delayed modeled state and finite-state machines | Declared state transition |

Crossing domains must be explicit. Use a sampling/projection node rather than
letting host timing decide when a value is observed. Continuous sources are
evaluated at their exact next change or crossing; Crucible does not poll them
on a wall-clock timer.

## A first static fault

A static fault is still a signal-driven fault. Use a Boolean `constant` source,
an `active_when_true` mapping, a resolved target, and a persistent effect. This
ensures static faults use the same admission, composition, checkpoint, and
replay path as changing faults.

The canonical plan contains these logical fields (generated content IDs are
omitted here because the builder computes them):

```toml
[plan]
fault_model = "signal_bindings_v2"
fault_signal_semantic_version = 2

[[plan.signal]]
id = "datacenter-link-down"
semantic_version = 1
domain = "virtual_time"
value_type = "bool"
unit = "dimensionless"
scale_decimal_exponent = 0
inputs = []

[plan.signal.node]
kind = "constant"
value = true

[[plan.fault_binding]]
id = "datacenter-link-outage"
semantic_version = 1
signals = ["datacenter-link-down"]
search_policy = { kind = "fixed" }

[plan.fault_binding.sampling]
kind = "at_boundary"

[plan.fault_binding.mapping]
kind = "active_when_true"
invert = false
```

The binding also needs a typed selector, phase set, observability policy, and an
effect table. Generate the complete canonical TOML with `Plan::to_canonical_toml`
after constructing the binding; do not invent content hashes. The public
constructors validate shape, lifetime, target, phase, and capability before a
guest starts. See [`FaultBinding::new`](../../../crates/crucible/src/model/fault_signal/binding.rs)
and [`Plan::to_canonical_toml`](../../../crates/crucible/src/model/plan_properties.rs).

Use `pulse`, `step`, or `periodic_pulse` instead of `constant` when the same
effect starts or stops at known coordinates. No separate heal operation exists:
deactivation is a signal transition whose ordering is recorded.

## Recorded and sporadic behavior

Use `trace` when the experiment comes from a physical capture. Import raw data
into the normalized, content-addressed trace format before a run. A trace source
names both the normalized artifact and the raw-provenance digest, plus:

- channel and optional quality channel;
- interpolation and before/after behavior;
- missing-data policy;
- exact source-to-virtual-time alignment; and
- coordinate frame for spatial channels.

Raw CSV, JSONL, PCAP, and PCAPNG are import formats, not runtime inputs. The run
only reads the admitted normalized artifact, so parsing libraries and host file
ordering cannot change replay.

Use `bernoulli`, `uniform_integer`, `exponential_wait`, or `weibull_wait` for
synthetic sporadic failures. Their choices are keyed by a stable opportunity,
transition, or coordinate identity. They do not consume a shared random cursor,
so adding an unrelated binding does not perturb existing decisions.

Use stateful operators for correlation:

| Desired behavior | Operator |
| --- | --- |
| Ignore a noisy threshold crossing until it persists | `debounce` or `hysteresis` |
| Accumulate thermal, wear, or radiation exposure | `integrator` or `leaky_integrator` |
| Alternate between good and bad bursts | `burst_process` |
| Model a closed operating-mode graph | `finite_state_machine` |
| Track bounded queued work or events | `queue_model` or `counter` |

Every state item is included in checkpoints and fingerprints. A restored run
continues the burst, filter, trace cursor, and accumulated exposure rather than
starting them again.

## Networking examples

The network adapter models directed interfaces, segments, paths, forwarders,
queues, attachments, shared media, and scheduled contacts. Select the narrowest
physical target that explains the failure.

### Moving through a city

Represent the device's truth trajectory as a position signal. Combine it with
building/terrain zones, transmitter fields, and interference fields. Bind the
derived channel values to:

- `network.rf_channel` for geometry, attenuation, interference, and transfer
  curves;
- `network.association` for authentication, roaming, reconnect, handoff, and
  reselection;
- `network.service` and `network.queue` for shared capacity and congestion; and
- `network.profile_delta` only for explicitly attributed residual latency,
  hazard, or technology metrics.

The movement trajectory is supported network truth, not a simulated sensor
device. A recorded GPS or drive-test trace may drive it, but no guest sensor is
created.

### Shared interference

Declare one medium and its resources, then attach all participating interfaces.
Use `network.shared_medium` for joint occupancy, arbitration, collision,
capture, retry, and duty-cycle behavior. Use `network.rf_channel` for received
signal and interference power. Independent per-packet loss bindings cannot
substitute for a shared-medium model because they lose transmission ordering
and common occupancy state.

This pattern applies to Wi-Fi, cellular radio resources, Ethernet collision
domains, CAN, field buses, optical channels, acoustic links, and other shared
links. Technology-specific policy artifacts configure arbitration and transfer
curves without changing deterministic scheduling.

### Routed and datacenter failures

Use path and forwarder targets for switch, router, firewall, NAT, tunnel,
load-balancer, provider, line-card, and control-plane failures. Queue targets
model congestion and backpressure. Fault-domain selectors let one cause fan out
to every declared rack, conduit, chassis, provider, or availability-zone
member. Route changes are explicit state transitions; packets already queued or
in flight use the declared treatment rather than an implicit drop.

### Satellite and disrupted links

Declare contacts and a contact plan. Drive acquisition and handover with
`network.contact`, range-dependent delay with `network.profile_delta`, rain or
weather fade with `network.rf_channel`, and shared transponder capacity with
`network.service`. Store-and-forward queues remain bounded and checkpointed
across contact loss. A missing or ambiguous capture-to-frame alignment is an
admission error, not a best-effort match.

## Storage and 9p examples

Storage effects attach to block devices, byte ranges, controllers, arrays, or
9p devices. Choose the opportunity that matches the intended layer:

| Intent | Effect family and phase |
| --- | --- |
| Reduce throughput or IOPS | `storage.service` at admission/queue/service |
| Return latency, timeout, or errno | `storage.result` or `ninep.result` at resolve/deliver |
| Lose, tear, reorder, or falsely acknowledge a write | `storage.persistence` at persist/flush |
| Corrupt or return stale bytes | `storage.data_transform` at resolve/persist |
| Model bad ranges, wear, retention, or program/erase failure | `storage.media_state` or `storage.flash_state` |
| Reset or disconnect a controller/path | `storage.controller_lifecycle` |
| Degrade an array and add rebuild load | `storage.array_state` |
| Delay committed 9p state becoming visible | `ninep.visibility` |

Power-loss testing must declare volatile-cache state and the fate of protected
and unprotected entries. A lying flush, reordered persistence, torn sector, and
completion error are distinct effects with distinct evidence. The live block
and 9p adapters preserve their queues, durability frontier, bad ranges, wear,
controller epochs, and array state in an exact checkpoint.

## CPU, memory, interrupt, clock, and accelerator examples

Node effects are applied only through matched patched-QEMU capabilities:

| Intent | Effect |
| --- | --- |
| Crash, hang, boot failure, reset, power cycle, or recovery | `node.lifecycle`, `node.hang` |
| CPU throttling, vCPU stall, or offline state | `cpu.service`, `cpu.vcpu_state` |
| Register bit/field mutation or stuck value | `cpu.register_transform` |
| Instruction result corruption, skip, replay, or illegal exception | `cpu.instruction_transform`, `cpu.exception` |
| Drop, delay, duplicate, replace, or storm interrupts | `interrupt.disposition`, `interrupt.storm` |
| Flip memory bits at a boundary | `memory.mutation` |
| Corrupt loads/stores/fetch/DMA, lose/torn writes, or poison access | `memory.access_transform` |
| Corrected/uncorrectable ECC or machine-check evidence | `memory.ecc_event` |
| Stuck ranges, retention decay, rowhammer disturbance | `memory.region_state` |
| Memory latency/bandwidth degradation | `memory.service` |
| Offset, drift, jump, freeze, jitter, or wander a guest clock | `clock.transform` |
| Fail/fallback/synchronize a clock source | `clock.source_state` |
| Disappear, reset, corrupt, or throttle a declared accelerator | `accelerator.lifecycle`, `accelerator.result_transform`, `accelerator.memory_event`, `accelerator.service` |

Register, instruction, interrupt, memory, and clock targets include the exact
architecture-specific identity. The capability handshake rejects an
unsupported CPU model, register, exception, clock source, accelerator class, or
effect before boot. Global scheduler time never changes when a guest clock is
faulted.

## One cause, several hardware domains

A realistic rack incident can reuse one admitted trace or modeled signal graph:

```text
rack vibration trace
  -> debounced threshold -> network attachment/profile degradation
  -> accumulated exposure -> storage media/persistence failure

rack power event
  -> node lifecycle transition
  -> storage volatile-cache loss
  -> network forwarder restart
```

Movement, weather, radiation, temperature, power, and vibration are valid
causes for supported effects. They are not executable sensor, battery, power
device, or cooling-device adapters. Such device targets are rejected until a
complete production adapter and real QEMU device exist.

Put related targets in a declared fault domain when the cause should fan out
atomically. Composition remains adapter-owned: minimum service caps, outage OR,
ordered transforms, severity, and conflict rules are different physical
algebras. The event log records every contributor and the final composed value.

## Replay, search, and minimization

Use recomputed replay to reevaluate the signal graph and compare the first
divergence in samples, opportunities, decisions, composition, application,
events, or fingerprints. Use locked replay when the resolved effect trace is
the artifact under test; it validates the exact target, phase, capability,
precondition, profile, and terminal fingerprint without rerunning search.

Search can branch finite outcomes, transitions, and parameter candidates, or
mutate bounded trace windows and mapping points. Export the selected schedule
and resolved-effect trace. After minimization, replay the result with the
ordinary production replay command; a finding that only reproduces inside the
explorer is not valid.

Inspect a retained run in this order:

1. signal samples and source provenance;
2. resolved target and opportunity identity;
3. mapped value and contributing bindings;
4. adapter composition and capability version;
5. application evidence and guest-visible result;
6. checkpoint dependency closure and final fingerprint.

The [reproduction guide](reproduction.md) explains save, resume, fork, and both
replay modes. The [exploration guide](exploration.md) explains bounded search
and finding minimization. Use the [exhaustive reference](reference.md) for every
accepted source, operator, mapping, target, phase, effect, and nested field.
