# Effects and the fault taxonomy

The effect registry is the closed list of everything a binding may ask an
adapter to do. The taxonomy maps real-world fault vocabulary (a cut conduit,
rain fade, a lying flush, a machine check) onto programs over those effects.
Keeping the two separate lets one cause drive several observable outcomes
without inventing a new effect for every technology or waveform.

## The effect registry

[`effect_registry.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/effect_registry.rs)
defines `EffectKind` with 71 effects: 31 network, 20 storage (including two
9p effects), and 20 node. Every kind has an `EffectDescriptor`, which is
executable admission data rather than documentation:

| Descriptor field | Meaning |
| --- | --- |
| `key` | Stable schema key such as `network.frame_loss`. |
| `semantic_version` | `EFFECT_SEMANTIC_VERSION`, part of canonical material. |
| `adapter` | `network`, `storage`, or `node`. |
| `targets` | Accepted `FaultTargetKind`s, all owned by that adapter. |
| `phases` | Accepted `FaultPhase`s; anything else is rejected, never translated. |
| `lifetimes` | Persistent, opportunity, impulse, and/or state-machine. |
| `composition` | The `CompositionAlgebra` for simultaneous contributions. |
| `capability` | Versioned backend capability ID required at admission. |
| `replay_evidence` | Evidence fields every resolved record must carry. |

Effect parameters are closed per domain in
[`network_effect.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/network_effect.rs),
[`storage_effect.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/storage_effect.rs), and
[`node_effect.rs`](../../../../crates/crucible/crucible-engine/src/model/fault_signal/node_effect.rs).
Technology detail that does not change observable semantics stays in typed
world objects and signal inputs referenced by ID; it never becomes a hidden
effect variant.

| Domain | Effect keys |
| --- | --- |
| Network | `availability`, `flap`, `negotiated_mode`, `profile_delta`, `propagation_delay`, `access_delay`, `jitter`, `service_curve`, `token_bucket`, `queue_policy`, `frame_loss`, `burst_error_state`, `duplicate`, `reorder`, `payload_transform`, `detected_frame_error`, `mtu`, `pause_backpressure`, `recipient_subset`, `forwarder_lifecycle`, `forwarding_mutation`, `route_transition`, `control_plane_service`, `firewall_disposition`, `connection_state`, `shared_medium`, `rf_channel`, `association`, `control_result_transform`, `contact`, `custody_queue` |
| Storage | `storage.`: `availability`, `reported_capacity`, `latency`, `service`, `operation_failure`, `stall_timeout`, `completion_reorder`, `duplicate_completion`, `read_transform`, `write_disposition`, `persistence_order`, `volatile_cache`, `volatile_cache_loss`, `flush_disposition`, `media_range`, `flash_state`, `controller_lifecycle`, `array_state`; `ninep.`: `result`, `visibility` |
| Node | `node.lifecycle`, `node.hang`, `cpu.service`, `cpu.vcpu_state`, `cpu.register_transform`, `cpu.instruction_transform`, `cpu.exception`, `interrupt.disposition`, `interrupt.storm`, `memory.mutation`, `memory.access_transform`, `memory.ecc_event`, `memory.region_state`, `memory.service`, `clock.transform`, `clock.source_state`, `accelerator.lifecycle`, `accelerator.result_transform`, `accelerator.memory_event`, `accelerator.service` |

Network keys are prefixed `network.`.

## Composition algebras

| Algebra | Rule |
| --- | --- |
| `outage_or` | The target is unavailable while any contribution is active; all contributors are retained. |
| `checked_sum` | Values add in canonical binding order; overflow is an error. |
| `minimum` | The least non-null cap wins; every limiter remains observable. |
| `rational_product` | Reduced rationals multiply with checked intermediates. |
| `ordered_transform` | Transforms apply in binding order, recording each intermediate digest. |
| `severity` | A closed precedence lattice selects the greatest severity. |
| `state_machine` | Declared transition precedence, then binding ID, orders same-coordinate inputs. |
| `independent_hazards` | Every keyed hazard is evaluated; any firing outcome applies; all decisions are logged. |
| `conflict` | Distinct simultaneous contributions are invalid. |
| `composite` | Effect-specific rules combine several component algebras. |

Where physical semantics permit, composition is associative and commutative;
where order matters the order is the canonical binding order and the
intermediate evidence is recorded. Precedence never permits an adapter to drop
contributors from evidence.

## Taxonomy ledger

The executable taxonomy is a crate-owned data contract,
[`crates/crucible/crucible-engine/tests/data/fault-taxonomy.tsv`](../../../../crates/crucible/crucible-engine/tests/data/fault-taxonomy.tsv).
Each of its 226 rows names a section, area, fault, primary targets and
observable effect, model tier, and the effect program that realizes it:

| Section | Rows | Covers |
| --- | ---: | --- |
| `wired` | 76 | Physical media, Ethernet, optical, PON, DSL, cable, links, queues, switching, routing, NAT, firewall, tunnels, load balancers. |
| `radio` | 52 | Path loss, fading, interference, Wi-Fi, cellular, LPWAN/BLE/Zigbee, association, handoff, mobility. |
| `satellite` | 20 | Visibility windows, acquisition, pointing, beam and gateway handover, range delay, custody. |
| `node` | 41 | Lifecycle, throttling, vCPU state, register/instruction/exception, interrupts, memory, ECC, clocks, accelerator. |
| `storage` | 37 | Availability, capacity, latency, service, durability, cache, flush, media, flash, controller, array, 9p. |

The model tier (`Core`, `Next`, `Advanced`) describes model complexity, not
implementation status: every row in the ledger is executable. Backtick spans
in the effect-program column are registered `EffectKind` keys; a `+` joins
effects that one cause drives through separate bindings so each outcome
remains observable. The engine test
[`tests/fault_taxonomy.rs`](../../../../crates/crucible/crucible-engine/tests/fault_taxonomy.rs)
rejects duplicate, missing, or mis-sectioned rows and any unregistered effect
key, and pins the per-section cardinality.

Representative rows:

| Fault | Effect program |
| --- | --- |
| cable/fiber cut | `network.availability(down)` on every segment in the conduit domain |
| transceiver failure | `network.forwarder_lifecycle` for port/transceiver + directional `network.availability` |
| building/tunnel entry | zone signal into `network.rf_channel` + `network.association` + `network.route_transition` |
| range-varying delay | range trace into `network.propagation_delay` |
| thermal throttle | temperature signal into `cpu.service` |
| read-only transition | `storage.availability(read_only)` |
| delayed visibility | `ninep.visibility` |

## Common-cause domains

Correlated failures are modeled as one shared signal or state fanned out
through explicit bindings, typically selected with a `fault_domain` selector.
Examples: a fiber conduit taking down many segments, rack power resetting
nodes and switches, a vibration zone flapping connectors and corrupting disk
reads, an RF spectrum region sharing interference, or a satellite beam sharing
weather and gateway outage. Correlation is never faked by giving independent
hazards equal seeds. Fault-domain membership is static or changes through a
deterministic declared rule, such as an endpoint moving into a spatial zone.

## Extending the registry

A proposed effect must answer: Is it a cause, a persistent state, an
opportunity outcome, or an impulse? Can an existing effect express the
observable semantics? Which target and phase apply? Which parameters and exact
units? What composition algebra, checkpoint state, event-log evidence, and
locked-replay precondition? Which capability? How is it tested in isolation,
overlap, checkpoint, and divergence?

A new waveform is never a new effect; it belongs in signals and mappings.
Technology metrics may be added as typed telemetry without becoming effect
parameters. A new effect lands together with its descriptor, parameter schema,
production implementation record, capability, reference documentation, and
live production-backend tests; test-double backends do not count as
application evidence.
