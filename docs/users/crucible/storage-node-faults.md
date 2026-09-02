# Storage, node, and hardware faults

Crucible's non-network adapters distinguish request admission, service,
completion, persistence, guest-visible data, device lifecycle, and machine
state. Choose the layer that matches the failure mechanism; similar guest
symptoms at different layers intentionally produce different evidence.

## Block and 9p topology

Add block or 9p I/O sub-nodes to the `World`, then describe their fault
contracts in `WorldFaultTopology`.

A block declaration identifies its owning VM, immutable base artifact and
length, scheduler shift, and deterministic operation latencies. The fault
topology adds durability, cache, media, controller, path, array, and policy
objects as needed. A 9p declaration similarly identifies its immutable
filesystem artifact and modeled control/data latency.

Supply every referenced artifact through the world's content-addressed store.
The backend rejects missing content, length mismatches, dangling ownership, or
an effect aimed at an undeclared storage object before useful execution.

## Select a storage layer

| Failure mechanism | Effect family |
|---|---|
| Device offline, read-only, degraded, or wrong capacity | `storage.availability`, `storage.reported_capacity` |
| Latency, throughput, IOPS, queueing, stall, or timeout | `storage.latency`, `storage.service`, `storage.stall_timeout` |
| Typed operation error or abnormal completion order | `storage.operation_failure`, `storage.completion_reorder`, `storage.duplicate_completion` |
| Stale, corrupt, or misdirected read | `storage.read_transform` |
| Lost, torn, or misdirected write | `storage.write_disposition` |
| Reordered durability or lying/stalled flush | `storage.persistence_order`, `storage.flush_disposition` |
| Volatile write cache policy or power-loss event | `storage.volatile_cache`, `storage.volatile_cache_loss` |
| Bad range, latent sector, poison, or read-only media | `storage.media_range` |
| Flash wear, retention, program/erase failure, or read disturb | `storage.flash_state` |
| Controller reset, reconnect, enumeration, namespace, or path change | `storage.controller_lifecycle` |
| Member/path degradation, quorum, selection, or rebuild | `storage.array_state` |
| 9p errno/stale/misdirected result | `ninep.result` |
| 9p committed state not yet visible | `ninep.visibility` |

The exact phase matters. A completion error does not undo a write that the
persistence model already made durable. A lying flush acknowledges without
moving the declared durability frontier. A volatile-cache-loss impulse chooses
from the eligible cached writes at a boundary; it is not equivalent to
corrupting the backing artifact.

The live examples
[`crucible-qemu-live-block-io.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-live-block-io.rs),
[`crucible-qemu-live-block-node.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-live-block-node.rs),
and
[`crucible-qemu-live-ninep-io.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-live-ninep-io.rs)
show the production protocol boundaries.

## Node lifecycle and progress

Use `node.lifecycle` for boot, crash, reset, power-cycle, stop, and recovery.
Its request declares downtime, boot policy, volatile-state treatment, and
device-state treatment. Use `node.hang` when the process/device remains present
but progress stops and a watchdog or recovery policy governs resumption.

Lifecycle effects act on the complete production VM participant, not merely a
host-side model flag. The adapter records generation changes and restores only
the state the effect declares preserved. The production reference is
[`crucible-qemu-live-node-lifecycle-fault.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-live-node-lifecycle-fault.rs).

## CPU, interrupt, memory, and clock

These effects require exact `WorldNodeFaultCapabilities` that agree with the
realized patched-QEMU machine:

| Target behavior | Effects |
|---|---|
| CPU capacity, thermal throttling, or vCPU state | `cpu.service`, `cpu.vcpu_state` |
| Register mutation | `cpu.register_transform` |
| Instruction corruption, skip, replay, or exception | `cpu.instruction_transform`, `cpu.exception` |
| Interrupt loss, delay, duplication, replacement, or storm | `interrupt.disposition`, `interrupt.storm` |
| Atomic safe-boundary memory mutation | `memory.mutation` |
| Load/store/fetch/DMA transform | `memory.access_transform` |
| ECC/platform error | `memory.ecc_event` |
| Retention, rowhammer, persistent region failure, or memory service | `memory.region_state`, `memory.service` |
| Guest-visible clock offset, drift, jump, freeze, jitter, or source failure | `clock.transform`, `clock.source_state` |

Register masks, writable phases, address ranges, DRAM mapping, interrupt route,
and clock identity are capability data, not free-form selectors. The QEMU
handshake rejects an unknown target or unsupported lifetime before boot.
Faulting a guest clock never changes the authoritative scheduler's virtual
time.

## Deterministic accelerator device

Accelerator effects apply only to the declared Crucible fault device and its
advertised GPU/TPU/FPGA-class capabilities:

- `accelerator.lifecycle` changes presence, reset/reconnect, enumeration, and
  queue treatment;
- `accelerator.result_transform` changes admitted job/result fields;
- `accelerator.memory_event` emits corrected, uncorrectable, or transformed
  device-memory behavior; and
- `accelerator.service` applies compute, memory, thermal, or power service caps.

This is not a promise of deterministic arbitrary PCI passthrough or host GPU
fault injection.

## Power loss and shared-cause tests

Model the cause once and bind it to all affected domains. A rack power event
might:

- crash a node with explicit RAM/device-state policy;
- lose the eligible unprotected volatile-cache entries;
- reset a storage controller and classify pending I/O; and
- power down a network forwarder with explicit queue/table policy.

The certified shared-cause example implements this pattern and checks exact
effect evidence across fresh-process checkpoint and replay:
[`crucible-qemu-signal-shared-cause.rs`](../../../crates/crucible-api/examples/crucible-qemu-signal-shared-cause.rs).

## Assertions and replay

Assert both the physical effect and the application consequence. Adapter
evidence can prove which write was durable, which interrupt was delivered, or
which node generation restarted; a guest marker should prove the service's
semantic outcome.

Exact checkpoints retain storage queues, cache and durability frontiers, media
state, controller and array epochs, CPU/device rules, signal state, and QEMU
state. Locked replay validates target, phase, capability, precondition, applied
result, and terminal fingerprint. Consult the
[effect registry](reference.md#exhaustive-effect-registry) rather than substituting a
neighboring effect with a superficially similar guest symptom.
