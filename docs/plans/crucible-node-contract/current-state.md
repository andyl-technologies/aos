# Current implementation and target gaps

This is a nonnormative source audit at commit
`1037fd8490479ad8eeef9349dd1043bb799fc405`, dated 2026-10-07. The target is
[RFC-0025](../../rfcs/0025-crucible-node-contract/README.md).

## 1. Existing graph vocabulary is already heterogeneous

[Topology declarations](../../../crates/crucible/src/model/topology_faults.rs)
define `NodeId` at line 9 as a canonical name, without a VM restriction.
`SchedulerNodeId` at line 18 adds a scheduling kind. Its existing kinds include
VM, disk, 9p, network, and control plane. `WorldNodeDef` at line 284 includes VM
and I/O declarations. These are a foundation for the universal node graph, not
names that need to be replaced wholesale.

`WorldNode` at line 62 is specifically compute configuration: architecture,
memory, guest command line, readiness, vCPUs, kernel, root image, and initrd.
[NodeTemplate](../../../crates/crucible/src/model/family.rs), line 11, is its
compute-only authoring counterpart. Their broad names obscure that specialization.
`WorldNodeDef` is the appropriate heterogeneous layer to extend.

`WorldIoNode` in the topology declarations, line 202, has an `owner` field whose
documented meaning is the VM consuming its completions. It does not identify the
authoritative state owner. Reusing that field for capture ownership would conflate
two different relations. Current block and 9p declarations carry immutable
artifact identities and deterministic latency configurations.

`LinkDef`, line 348, connects two node IDs, but current world validation and
scheduler setup interpret those endpoints as VM network endpoints. A pair of IDs
is not yet a typed-port connection or a general causal dependency.

Target changes:

- Retain universal `NodeId`; distinguish role declarations from runtime handles.
- Give ports protocol, direction, ordering, timing, and capacity contracts.
- Represent attachments and capture/execution ownership independently.
- Generalize causal dependencies to block, filesystem, interrupts, clock alarms,
  and registered protocols rather than treating Ethernet as the only source of
  incoming lookahead.
- Preserve the existing graph's identities and ordering in the first extraction.

## 2. The backend trait is collection-shaped

[Backend contracts](../../../crates/crucible/src/backend.rs) contain two relevant
surfaces. `Backend` at line 38 has single-machine advance, input, fingerprint,
snapshot, restore, and shutdown methods. `SimulationBackend` at line 103 serves
the session and scheduler and addresses operations by `NodeId`. It includes
device receipt custody, execution admission, stepping, fingerprints, guest
introspection, and debugging. It does not require `Send`, because concrete
runtime handles can be thread-affine.

`SimulationBackend::dispatch_contract`, line 161, and
`io_inventory_authority`, line 169, return one contract for the collection.
[BackendQuantumLoop](../../../crates/crucible/src/scheduler/event_log/backend_loop.rs),
line 148, retains one selected dispatch contract and rejects later changes.
That immutability is valuable; its scope is too broad for a mixed implementation
graph. The target retains immutable negotiation per realization and uses an
owner-qualified selection for each dispatch.

`BackendDispatchContract` is an execution-authority distinction:
`PhysicalSource` requires genuine native admission, and `ControlV3` uses exact
ceilings and retained native queues. Neither value means “quantized.” Mapping
KVM to `ControlV3` because it has a controller connection would make an invalid
exactness claim.

[Concurrent dispatch](../../../crates/crucible/src/scheduler/concurrent_prepare.rs),
line 142, defines `ConcurrentSimulationBackend`. Prepared RUNs retain sealed
admission and dispatch ceilings. Results distinguish completed, input, tighter
cap, and internal dispatch boundaries. This authority and settlement structure
must survive extraction. A new generic observation struct must not collapse an
unsettled native stop into a completed scheduler boundary.

[QemuNodeSet](../../../crates/crucible-qemu/src/node_set.rs), line 463, already
holds a `BTreeMap<NodeId, QemuNode>` with per-node pending requests and retained
evidence. Keep it as the QEMU implementation collection. A mixed runtime can
route to QEMU owners without renaming native QEMU operations to generic names.

## 3. Devices already separate computation and delivery

[IoSubNode and IoCore](../../../crates/crucible-device/src/subnode.rs) provide a
useful specialized facet. `IoSubNode` at line 74 computes a response from the
request and owned state, and has rollback state for computation transactions.
`IoCore` at line 126 owns deterministic queues, local clock, sequence ordering,
and in-flight completions. Computation wall time cannot influence results, and
the core does not advance its own clock.

This is not a universal trait for external devices: it deliberately assumes
deterministic request/response computation. Preserve it as a deterministic I/O
facet and wrap it in the general node contract. Physical adapters advertise
different guarantees instead of pretending that host or hardware behavior is a
pure function.

[DeviceSchedulingSubNode](../../../crates/crucible/src/device_subnode.rs), line
313, connects that device state to scheduler participation.
[Scheduler construction](../../../crates/crucible/src/scheduler/single_scheduler_state.rs),
line 38, validates VM participants, attaches device nodes to consumers, and
instantiates world network links. [Scheduler runtime state](../../../crates/crucible/src/scheduler/runtime_state.rs),
line 416, holds the authoritative scheduler state.

The target distinguishes an event-driven node's next possible event from an
executing node's progress cursor. Otherwise a passive disk with no request, or
a link waiting for traffic, could artificially pin global progress. Unknown
future behavior is not the same as “no pending event”; neither should be
inferred from a missing queue observation.

## 4. Logical time exists, but names still conflate units

[NodeTimeMapping](../../../crates/crucible/src/node_time.rs), line 12, maps a
node-local logical counter to shared time using an anchor. It already supports
rebasing after restore. It is not a rate controller for a hardware clock, and
guest clock faults do not change this map.

`ExecutionHorizon` in [backend.rs](../../../crates/crucible/src/backend.rs), line
555, carries `Icount`; `AdvanceOutcome::Paused` also uses instruction-shaped
coordinates. Concurrent dispatch turns the admitted horizon into logical ticks.
The QEMU implementation retains raw retirement and logical time separately in
its [marker diagnostics](../../../crates/crucible-qemu/src/node_set.rs), line 488.
This is evidence for a type cleanup, not evidence that clocks can be arbitrarily
scaled without changing behavior.

Target types separate shared time, local execution coordinates, actual retired
instructions, native event ordinals, guest clock readings, and host observation
time. The first implementation stage keeps existing representations at adapter
edges. Format migrations then define checked conversions and refusal cases.

Quantized participation introduces a new state machine: admitted quantum,
authorized execution or observation, pending acknowledgment, sealed outputs, and
committed boundary. Existing exact RUN subdivision and idle fast-forwarding
cannot be relabeled to supply this contract.

## 5. Production lifecycle and campaign code remain QEMU-bound

[ProductionVmLifecycleLoop](../../../crates/crucible-api/src/vm_lifecycle.rs), line
1064, contains `BackendQuantumLoop<SingleScheduler, QemuNodeSet, ...>` and QEMU
launch configuration, fault, device, generation, debugger, and continuation
state. Its apparently broad name does not make it a provider-neutral runtime.
Extract common lifecycle orchestration while retaining actual process launch,
native receipts, VMState, and debugger implementation adapters.

[The campaign driver](../../../crates/crucible-daemon/src/qemu_campaign_driver.rs)
already declares `QemuModeledAttemptLifecycle`, line 958, as a
materialization-independent semantic surface. It contains frontier, quantum,
choice, and quiescence operations, but later methods expose QEMU marker proof.
Extract a neutral semantic core and an explicit exact compute/marker facet;
do not merely rename the whole file while leaving its types QEMU-shaped.

[CLI backend resolution](../../../crates/crucible-cli/src/cli/backend.rs), line
127, describes a resolved local QEMU implementation.
[Finding deployment](../../../crates/crucible-daemon/src/finding_production_replay/deployment.rs)
also routes through QEMU execution. Provider selection, resource admission,
attempt orchestration, and node launch need distinct seams.

## 6. Compatibility and checkpoint identity are global today

[CampaignLineage](../../../crates/crucible-campaign/src/model.rs), line 77, has
one `qemu_build`. [ExecutorCompatibilityProfile](../../../crates/crucible-campaign/src/execution.rs),
line 115, compares that build and other global facts.
[ExecutorCapabilitySet](../../../crates/crucible-campaign/src/executor_capability.rs),
line 110, carries QEMU profiles; its constructor at line 147 requires
`ThinReplay`. That requirement protects the existing deterministic campaign
path. It cannot apply to unrecorded KVM or hardware attempts, and must not simply
be deleted from the old schema.

[Checkpoint](../../../crates/crucible/src/model/materialized.rs), line 906,
includes per-node blobs and a concrete execution-closure reference.
`CheckpointMeta` is explicitly identity-irrelevant. Implementation bindings
cannot be added only to labels. [Exact checkpoint relations](../../../crates/crucible/src/exact_checkpoint.rs)
use canonical, versioned manifest, target, frontier, sparse-artifact, and
repository relations. These are a sound basis for extending binding to all state
owners, not a generic bag of optional provider metadata.

Target saved state binds every owner to implementation identity, realized
configuration, state schema, qualification, graph connections, timing policy,
and coordinator continuation. Unknown owners, missing state, different CPU
models, different devices, or a different implementation are rejected before
activation. A fresh KVM, QEMU-SIM, or gem5 realization can reuse portable guest
images and authored scenarios; it cannot reuse another implementation's exact
state by relabeling its identity.

Nondeterministic attempts need observed-attempt identity in addition to planned
configuration identity. A planned schedule cannot stand for unique physical
state. Deterministic memoization, equivalence, automatic thin replay, and branch
minimization need explicit eligibility checks. Recorded-boundary replay is
conditional on the complete accepted transcript, including its inbound requests.

## 7. Dependency placement and license boundary

At the audited revision, [crucible](../../../crates/crucible/Cargo.toml) depends
on `crucible-sim`, campaign, CAS, device, and protocol crates.
[crucible-device](../../../crates/crucible-device/Cargo.toml) depends on sim,
shmem, and codec libraries, not on `crucible`.
[crucible-qemu](../../../crates/crucible-qemu/Cargo.toml) depends on both.
[crucible-campaign](../../../crates/crucible-campaign/Cargo.toml) is lower than
the runtime and cannot acquire a dependency on the high-level `crucible` crate
merely to encode implementation identity.

Initially put descriptor facades and runtime traits in `crucible`, where QEMU
adapters can implement them and host-device wrappers can call existing device
models. Keep low-level canonical identity values in a dependency-compatible
module after a crate graph review. Do not make `crucible-device` implement a
high-level trait by adding a reverse dependency. If later independent consumers
justify a new contract-types crate, extract only stable values and codecs, with
no runtime, process, or simulator dependency.

Host traits are not cross-process objects. QEMU/plugin and future gem5 native
integration use versioned public process protocols. Do not put Rust enum layouts,
trait objects, callbacks, pointers, or simulator-private structures in shared
memory. Preserve the [license boundary](../../legal/licensing.md) and existing
package-source retention obligations.

## 8. Gap summary

| Area | Audited behavior | Target implementation work |
| --- | --- | --- |
| Node identity | Already universal names | Explicit role, port, owner, and realization bindings |
| Runtime dispatch | Node-addressed collection; collection-global contract | Owner-qualified immutable admission and dispatch |
| Timing | Exact scheduler ceilings and logical tick anchors | Independent exact and quantized contracts |
| I/O | Deterministic request/response core | General ports, external adapters, and event-driven scheduling |
| Ownership | VM consumer attachments and native process collections | Explicit execution/state closure shared by composite nodes |
| Clock nodes | Guest fault vocabulary and scheduler timeline | Modeled readings/alarms without a second coordinator timeline |
| Capture | QEMU VMState plus host/coordinator closure | Complete owner roster with implementation-specific state |
| Replay | Deterministic campaign assumptions and mandatory thin fallback | Separate strict, nondeterministic, and conditional-replay policies |
| Providers | QEMU-specific resolution and launch | Typed realized facets and provider admission |
| gem5 | No qualified implementation in this change | Complete nondraining state preservation and device parity |
| KVM | No quantized participation implemented here | Clock/interrupt/device containment and boundary acknowledgment |
| External vendors | No universal integration qualification here | Versioned protocols, schemas, extension profiles, and conformance |

## 9. gem5 checkpoint audit

The upstream gem5 audit used revision
`f5c5a6e390f55dd5984977815bf9d0bd05da6945`. Its checkpoint mechanisms do not
establish the complete-state contract required by RFC-0025's gem5 profile.

The Python checkpoint path drains and writes memory back; O3 thread
serialization preserves architectural thread context, and classic cache
serialization does not preserve cache contents. These are narrower operations
than the profile's exact continuation requirement. See the pinned
[checkpoint path][gem5-checkpoint], [O3 thread serializer][gem5-o3-state], and
[cache serializer][gem5-cache-state].

The external 9p proxy also warns that checkpointing a used device can lose
state. The integration must implement the required owned filesystem
continuation. See the pinned [9p serialization implementation][gem5-ninep-state].

T-CN-15 through T-CN-19 in the [phased implementation plan](phased-implementation.md)
investigate complete nondraining preservation, durable restoration, and live
branching independently.

[gem5-checkpoint]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/python/m5/simulate.py#L401
[gem5-o3-state]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/cpu/o3/thread_state.cc#L57
[gem5-cache-state]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/mem/cache/base.cc#L2057
[gem5-ninep-state]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/dev/virtio/fs9p.cc#L230
