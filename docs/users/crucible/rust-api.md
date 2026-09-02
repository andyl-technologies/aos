# Rust integration API

The packaged CLI is the normal operator interface. The public Rust crates are
also required for canonical scenario generation, raw signal import, direct
artifact injection, embedded lifecycle control, and control-plane clients.
This guide maps those surfaces and their support boundaries.

## Crate roles

| Crate | Owns | Use it when |
|---|---|---|
| `crucible` | Model types, canonical forms, scheduler contracts, stores, checkpoints, properties, traces | Building and validating scenarios or consuming typed execution data. |
| `crucible-api` | Versioned lifecycle/control API, in-process and RPC clients, streaming, daemon server, production VM lifecycle facade | Embedding sessions or writing a control-plane client. |
| `crucible-qemu` | Production patched-QEMU lifecycle implementation | Normally reached through `crucible-api`; examples/gates may use it directly. |
| `crucible-protocol` / `crucible-shmem` | Versioned process-boundary protocols | Infrastructure integration, not ordinary scenario authoring. |

Do not link QEMU implementation details into Apache-side model code. The Unix
socket and shared-memory protocols are the only Crucible/QEMU integration
surfaces.

## Scenario generation

Generate canonical TOML rather than hand-maintaining derived hashes:

```rust,no_run
use crucible::model::{Plan, Properties, ScenarioDefForm, Seed, World};

# fn build_world() -> Result<World, Box<dyn std::error::Error>> { todo!() }
# fn build_plan(world: &World) -> Result<Plan, Box<dyn std::error::Error>> { todo!() }
# fn build_properties() -> Result<Properties, Box<dyn std::error::Error>> { todo!() }
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let world = build_world()?;
let plan = build_plan(&world)?;
let properties = build_properties()?;
let form = ScenarioDefForm::from_components(
    &world,
    &plan,
    &properties,
    Seed::from_u64(0x5eed),
)?;
let canonical_toml = form.to_canonical_toml()?;
# let _ = canonical_toml;
# Ok(())
# }
```

Use `World::from_nodes_and_links` for VM-only worlds and
`World::from_node_defs_and_links` when adding block/9p sub-nodes. Attach a
validated `WorldFaultTopology`, then build `SignalProgram`, `FaultBinding`, and
`FaultSignalPlan`. Resolve the plan for that same world with
`Plan::with_fault_signals_for_world`; selector materialization is world-specific.

`ScenarioBuilder` is useful when only an immutable in-memory `ScenarioDef` is
needed. `ScenarioDefForm` is the canonical exchange form used by the CLI.

## Artifact injection and production lifecycle

`ProductionVmLifecycleConfig` configures the matched QEMU/plugin processes and
accepts world and signal artifact stores. Direct integrations use it for inputs
that ordinary `run`/`verify` do not obtain from `--store`, including normalized
recordings and spatial/sampler objects.

`build_production_vm_lifecycle_loop` constructs a fresh live session.
`build_production_vm_lifecycle_loop_from_checkpoint` realizes an exact retained
session after validating dependencies and backend identity.
`collect_signal_artifact_objects` resolves the authenticated transitive signal
closure. `production_vm_search_frontier` exposes the production search frontier
used by bounded exploration.

Production evidence snapshots expose typed network outage/queue, block, and
node evidence. These are diagnostic/API views of the same canonical execution
evidence, not a separate fault mechanism.

## Lifecycle control plane

The lifecycle API covers:

- scenario and session listing;
- create and resume session;
- session summary and destruction;
- reproduction-artifact retrieval;
- guest introspection and debug reposition dispatch; and
- resource-limit enforcement.

`LifecycleControlPlane` owns the server-side state. `InProcessLifecycleClient`
is the direct thin client. The transport-neutral `ControlClient` trait is
implemented by `InProcessControlClient` and `RpcControlClient`; both share the
same versioned wire model and method/command mapping.

Creating a session accepts only declared `CreateSessionSource` variants.
Resuming validates the savepoint/checkpoint contract. Session references carry
stable IDs, not host process IDs.

## Streaming control

The attach/watch/send facade provides:

- `AttachRequest` and an `Attached` snapshot;
- ordered state-update and event frames;
- command send/acknowledgement with typed rejection reasons;
- explicit capability discovery; and
- control/watch/send equivalence validation.

Control commands are scheduler-serialized. Receiving an acknowledgement means
the command reached its defined control boundary; effect/guest consequences
remain visible through later evidence. `validate_control_responsiveness` checks
the quantum-bounded acknowledgement contract for required operations.

The live event-log subscription uses a cursor-backed replay window plus bounded
broadcast capacity. Consumers must handle cursor expiry/lag as a typed error;
they must not infer that a missing frame never occurred.

## RPC and daemon

The RPC ABI has explicit major/minor/patch/build identity and golden vectors.
Clients perform hello/version negotiation before lifecycle calls. Status codes,
attach modes, event classes, and open-set payload envelopes use closed versioned
wire forms.

`serve_lifecycle_http2*` exposes the daemon transport. The packaged `serve`
command supports both mutual-TLS server/client configuration and an explicit
trusted-network cleartext mode; direct integrations expose the same choices.
Neither mode
turns the daemon into a distributed scheduler, and remote command fidelity is
limited as described in [Daemon operation](daemon.md).

## Open-set extensions

Open-set command, breakpoint, and event payloads use dotted kind names plus
typed attributes. The API publishes current capability categories and schema
validation helpers. “Open set” means versioned extensibility, not arbitrary
code execution: prefixes, payload category, attribute types, and negotiated
capability are validated.

Unknown extension kinds can be transported only according to the negotiated
wire rules. They do not create an unregistered fault effect; fault effects
remain the closed 71-entry registry.

## Debug integration

Debug access has an explicit authorization policy, controller acquisition, and
read-only versus mutable fork distinction. The Apache control plane talks to a
separate debugger gateway process over its versioned Unix protocol. The relay
uses bounded chunks and typed stream identity.

Guest introspection messages also use the shared control protocol version and
typed failure codes/output streams. Availability depends on guest agent and
backend capability. See [Debugging](debugging.md) before exposing a gateway.

## Checkpoint realization

`realize_model_checkpoint_vm_resume_from_savepoint` validates a model
checkpoint and returns a realization proof for production VM resume. It does
not weaken the build/protocol/scenario checks performed by ordinary `resume`.
Production plugin install types are re-exported under backend-neutral names so
control-plane clients do not depend directly on the implementation crate.

## Import APIs

Recorded CSV, JSONL, PCAP, and PCAPNG import is currently a Rust API. Importers
normalize channel schema, units, coordinates, quality, time mapping, chunking,
and provenance into the DAG store. Use the resulting manifest ID in a trace
source and provide the same store to the production lifecycle. See
[Recorded signals](recorded-signals.md).

## Integration checklist

1. Keep scenario construction in `crucible` model types and serialize through
   canonical forms.
2. Resolve fault plans against the exact admitted World.
3. Supply complete world/signal object closures through lifecycle config.
4. Negotiate protocol/build/capability before session creation.
5. Treat streaming cursors, acknowledgements, and command rejection as typed
   state, not log text.
6. Retain reproduction artifacts and canonical traces from the same session.
7. Use the CLI guides' support boundaries even when a public type exposes a
   broader certification or model surface.

Implementation-backed examples are indexed in [Certification examples](examples.md).
The two-VM network and shared-cause examples are the best starting points for a
fresh direct integration.
