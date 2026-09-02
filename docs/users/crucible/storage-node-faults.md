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

## Complete storage and 9p effect contract

All effects use semantic version `1`. **Storage targets** means block device,
block range, controller, or array; narrower rows are explicit.

| Effect | Targets; phases; lifetimes; composition | Capability | Complete top-level parameters |
|---|---|---|---|
| `storage.availability` | storage targets; `admit`; `persistent` or `state_machine`; `severity` | `storage.availability.v1` | availability `state`, admitted/queued-operation `reconnect_policy` |
| `storage.reported_capacity` | storage targets; `produce`, `admit`; `persistent`; `composite` | `storage.capacity.v1` | positive `length_bytes`, beyond-boundary `shrink_policy` |
| `storage.latency` | storage targets; `resolve`, `deliver`; `opportunity`; `checked_sum` | `storage.latency.v1` | nonempty `operations`, `extra_nanos`, maximum keyed `jitter_nanos` |
| `storage.service` | storage targets; `queue`; `persistent` or `state_machine`; `minimum` | `storage.service.v1` | positive byte rate, optional positive IOPS, positive queue depth, service policy |
| `storage.operation_failure` | storage targets; `resolve`, `persist`; `opportunity`; `severity` | `storage.failure.v1` | operations, probability, registered typed status/errno |
| `storage.stall_timeout` | storage targets; `resolve`; `opportunity` or `state_machine`; `composite` | `storage.stall.v1` | positive stall duration, optional recovery event, typed timeout result |
| `storage.completion_reorder` | storage targets; `deliver`; `opportunity`; `composite` | `storage.reorder.v1` | positive window, keyed selection |
| `storage.duplicate_completion` | storage targets; `deliver`; `opportunity`; `checked_sum` | `storage.duplicate.v1` | bounded additional copies, gap, protocol duplicate policy |
| `storage.read_transform` | storage targets; `resolve`; `opportunity`; `ordered_transform` | `storage.read-transform.v1` | typed bit/stale/misdirection `mutation` and selector |
| `storage.write_disposition` | storage targets; `persist`; `opportunity`; `conflict` | `storage.write-disposition.v1` | applied/lost/torn/misdirected `disposition`, acknowledged status |
| `storage.persistence_order` | storage targets; `persist`; `persistent` or `opportunity`; `composite` | `storage.persistence-order.v1` | ordering-group identity, registered delay/barrier rule |
| `storage.volatile_cache` | block device/range; `persist`; `persistent`; `conflict` | `storage.volatile-cache.v1` | positive byte capacity, admission/eviction policy |
| `storage.volatile_cache_loss` | block device/range; `boundary`; `impulse`; `ordered_transform` | `storage.volatile-cache-loss.v1` | deterministic eligible-entry selector, protection/loss kind |
| `storage.flush_disposition` | storage targets; `persist`; `opportunity`; `severity` | `storage.flush.v1` | honest/error/lie/stall kind, typed status; stall-only duration and optional recovery event |
| `storage.media_range` | storage targets; `resolve`, `persist`; `persistent` or `state_machine`; `ordered_transform` | `storage.media-range.v1` | byte range, media state, operations, optional access-count/time thresholds |
| `storage.flash_state` | storage targets; `persist`; `persistent` or `state_machine`; `state_machine` | `storage.flash.v1` | positive erase-block/page sizes and endurance; retention, disturb, and program/erase rule IDs |
| `storage.controller_lifecycle` | storage targets; `boundary`; `state_machine`; `severity` | `storage.controller.v1` | transition, complete transition policy, resulting namespace and path sets |
| `storage.array_state` | storage targets; `resolve`, `persist`; `state_machine`; `composite` | `storage.array.v1` | layout, member/path state, selection, rebuild, consistency, and failure-result IDs |
| `ninep.result` | 9p device; `resolve`; `opportunity`; `severity` | `ninep.result.v1` | operations, result kind; errno only for error, version only for stale, object only for misdirection |
| `ninep.visibility` | 9p device; `persist`, `visibility`, `deliver`; `state_machine`; `composite` | `ninep.visibility.v1` | update ID, exactly one of delay/event, namespace/data visibility policy |

Storage availability is `online`, `offline`, `read_only`, or `degraded`.
Transition policies classify admitted and queued work rather than silently
dropping it. Thresholded media and flash state retain counters in the
checkpoint. All result/status IDs resolve through declared typed policy
artifacts, so the guest protocol response is reproducible.

Mandatory evidence covers service and queue ledgers, keyed decisions,
before/after data digests, volatile and durable sequences/frontiers, selected
cache entries, media thresholds/counters, controller namespace/path state,
array selection/rebuild/durability, and 9p committed/visible frontiers.

### Closed storage parameter choices

| Type/field | Accepted variants and variant fields |
|---|---|
| availability | `online`, `offline`, `read_only`, `degraded` |
| transition policy | `preserve`, `fail`, `drain`, `discard` |
| selection | `keyed_uniform`, `canonical_first`, `canonical_last`, `all` |
| read mutation | `bit_flip { range, mask }`, `stale { version }`, `misdirected { source_device, source_range }` |
| write disposition | `apply`, `lost { selection }`, `torn { selection }`, `misdirected { destination_device, destination_range }` |
| flush kind | `honest`, `error`, `lie`, `stall` |
| media state | `bad`, `latent`, `poisoned`, `read_only` |
| controller transition | `reset`, `reconnect`, `enumerate` |
| volatile-cache loss kind | `power_loss`, `protection_failure` |
| volatile-cache selector | `all`, `after_sequence { sequence }`, `range_intersection { range }`, `keyed_subset { count }` |
| 9p result | `errno`, `stale`, `misdirected`, with exactly its matching top-level payload field |

`ByteRange` uses a start and positive length. Masks/replacement bytes are
canonical nonempty hexadecimal data where the selected variant requires them.

## Node lifecycle and progress

Use `node.lifecycle` for boot, crash, reset, power-cycle, stop, and recovery.
Its request declares downtime, boot policy, volatile-state treatment, and
device-state treatment. Use `node.hang` when the process/device remains present
but progress stops and a watchdog or recovery policy governs resumption.

Lifecycle effects act on the complete production VM participant, not merely a
host-side model flag. The adapter records generation changes and restores only
the state the effect declares preserved. The production reference is
[`crucible-qemu-live-node-lifecycle-fault.rs`](../../../crates/crucible-qemu/examples/crucible-qemu-live-node-lifecycle-fault.rs).

## Complete node and hardware effect contract

All effects use semantic version `1`. The target must also exist in
`WorldNodeFaultCapabilities`; target kind alone is insufficient.

| Effect | Targets; phases; lifetimes; composition | Capability | Complete top-level parameters |
|---|---|---|---|
| `node.lifecycle` | node; `boundary`; `impulse` or `state_machine`; `severity` | `qemu.node.lifecycle.v1` | transition, downtime, boot policy, volatile-state policy, device-state policy |
| `node.hang` | node/vCPU/accelerator; `boundary`, `run`; `persistent`; `outage_or` | `qemu.node.hang.v1` | hang scope, recovery event, watchdog policy |
| `cpu.service` | node/vCPU; `run`; `persistent` or `state_machine`; `minimum` | `qemu.cpu.service.v1` | vCPU set, exact capacity ratio, positive instruction quantum, service discipline |
| `cpu.vcpu_state` | vCPU; `boundary`; `state_machine`; `severity` | `qemu.cpu.vcpu-state.v1` | online/offline/stalled state, optional recovery event where required |
| `cpu.register_transform` | register; `before_instruction`, `after_instruction`, `boundary`; `persistent`, `opportunity`, or `impulse`; `ordered_transform` | `qemu.register.mutate.v1` | register ID, first bit, positive bit count, mutation, occurrence policy |
| `cpu.instruction_transform` | vCPU; `before_instruction`, `after_instruction`; `opportunity`; `conflict` | `qemu.cpu.instruction-transform.v1` | architecture instruction selector, corruption/skip/replay mutation |
| `cpu.exception` | vCPU; `before_instruction`, `after_instruction`, `boundary`; `impulse`; `severity` | `qemu.cpu.exception.v1` | architecture-specific exception payload |
| `interrupt.disposition` | interrupt; `raise`, `route`, `interrupt_deliver`; `opportunity` or `state_machine`; `ordered_transform` | `qemu.interrupt.control.v1` | drop/delay/duplicate/replace mutation |
| `interrupt.storm` | interrupt; `raise`; `state_machine`; `composite` | `qemu.interrupt.storm.v1` | source, vector, positive period, bounded burst/count, routing policy |
| `memory.mutation` | memory range; `boundary`; `impulse`; `ordered_transform` | `qemu.memory.mutate.v1` | address space, byte range, mutation, atomicity policy |
| `memory.access_transform` | memory range; `fetch`, `load`, `store`, `dma_read`, `dma_write`, `page_table_walk`; `persistent` or `opportunity`; `ordered_transform` | `qemu.memory.access-transform.v1` | range, access classes, optional DMA device, atomicity-violation flag, mutation, occurrence |
| `memory.ecc_event` | memory range; `fetch`, `load`, `store`, `dma_read`, `dma_write`, `page_table_walk`, `boundary`; `impulse` or `opportunity`; `severity` | `qemu.memory.ecc-event.v1` | target vCPU, ECC kind, address, syndrome, bank/channel/rank, guest visibility |
| `memory.region_state` | memory range; `fetch`, `load`, `store`, `dma_read`, `dma_write`, `page_table_walk`, `refresh`; `persistent` or `state_machine`; `ordered_transform` | `qemu.memory.region-state.v1` | range, failed/retention/rowhammer kind, process parameters |
| `memory.service` | memory range; `fetch`, `load`, `store`, `dma_read`, `dma_write`, `page_table_walk`, `queue`; `persistent` or `state_machine`; `composite` | `qemu.memory.service.v1` | latency, optional byte/operation rates, sharing scope |
| `clock.transform` | clock source; `clock_read`, `arm`, `fire`; `persistent` or `impulse`; `composite` | `qemu.clock.transform.v1` | source, offset/drift/jump/freeze/jitter/wander mutation, monotonicity, overdue-timer policy |
| `clock.source_state` | clock source; `source_switch`, `synchronize`; `state_machine`; `conflict` | `qemu.clock.source-state.v1` | source set, transition, synchronization policy |
| `accelerator.lifecycle` | accelerator; `boundary`, `submit`; `state_machine`; `severity` | `qemu.accelerator.lifecycle.v1` | device, transition, queue policy, memory policy |
| `accelerator.result_transform` | accelerator; `execute`, `complete`; `opportunity`; `ordered_transform` | `qemu.accelerator.result-transform.v1` | job selector, result mutation |
| `accelerator.memory_event` | accelerator; `accelerator_memory_access`, `boundary`; `opportunity` or `impulse`; `severity` | `qemu.accelerator.memory-event.v1` | range and allowed ECC kind, syndrome, or replacement bytes |
| `accelerator.service` | accelerator; `execute`, `queue`; `persistent` or `state_machine`; `minimum` | `qemu.accelerator.service.v1` | exact capacity ratio, optional memory/job rates, thermal/power contract |

The QEMU handshake proves each fine-grained capability and architecture
manifest. Register evidence retains the manifest/model digests, resolved
register, before/after values, side effects, instruction count, and execution
fingerprint. Memory evidence retains translation, bytes, dirty tracking,
access outcome, page-table walk and DRAM/ECC identity. Interrupts retain source,
route, vector, original/final deliveries and acknowledgements. Clock evidence
retains raw/transformed values and timer consequences. Accelerator evidence
retains enumeration/run state, queue treatment, job/data digests, device-memory
outcome, and service ledgers.

### Closed node and hardware parameter choices

| Type/field | Accepted variants and variant fields |
|---|---|
| lifecycle transition | `boot`, `crash`, `reset`, `power_off`, `power_cycle`, `permanent_failure` |
| state policy | `preserve`, `clear`, `device_reset` |
| boot policy | `immediate`; or `require_ready { ready_marker, maximum_attempts, retry_delay_nanos, exhausted }` |
| watchdog | `disabled`; or `transition_after { timeout_nanos, transition, downtime_nanos, boot_policy, volatile_state_policy, device_state_policy }` |
| hang scope | `node`, `vcpus` with a nonempty vCPU list, or `device` with a declared ID |
| occurrence | `every`; or `periodic { first, period, count }` using one-based match ordinals |
| CPU service/state | discipline `work_conserving` or `strict_cap`; vCPU state `online`, `offline`, `stalled` |
| register mutation | `bit_flip { mask }`, `stuck { mask, value }`, `replace { value }` |
| instruction selector | PC start/positive length, optional exact bytes/opcode class/input-state SHA-256, occurrence |
| instruction mutation | `result_corrupt { transform }`, `skip`, `replay { count }`; result transform names destination register and register mutation |
| exception | architecture `x86_64` or `aarch64`, vector, syndrome, optional fault address, before/after flag, maskability, record |
| exception record | `architecture_default`; `x86_machine_check { bank, status, global_status, address?, misc?, corrected }`; `aarch64_ras { esr, far?, disr?, asynchronous, corrected, fatal }` |
| interrupt mutation | `drop`, `delay { delay_nanos }`, `duplicate { copies, gap_nanos }`, `replace { vector }` |
| interrupt routing | nonempty target-vCPU list, priority, retain-pending flag |
| boundary memory mutation | `bit_flip { mask }`, `replace { bytes }`; address space `guest_physical` or `guest_virtual`; atomicity is only `all_or_nothing` |
| access classes | Boolean selectors for fetch, CPU load/store, DMA read/write, and page-table walk; at least one applies |
| access mutation | `stuck { mask, value }`, `read_corrupt { mask }`, `lost_write`, `torn_write { selector }`, `poison { policy }` |
| poison policy | `access_error`, `corrected { xor_mask }`, `exception { exception }` |
| ECC | kind `corrected` or `uncorrectable`; visibility `telemetry_only`, `corrected_interrupt { vector }`, or `exception` with complete exception payload |
| memory region | kind/process pair `failed { policy }`, `retention { interval_nanos, decay_mask }`, or `rowhammer { row_bytes, threshold, victim_distance, flip_mask }` |
| memory sharing scope | `node`, `range`, `controller` with realized controller ID |
| clock mutation | `offset { offset_nanos }`, `drift { ratio }`, `jump { delta_nanos }`, `freeze { value_nanos, release }`, `jitter { maximum_nanos, distribution_nanos }`, `wander { process }` |
| clock policy | freeze release `resume_from_frozen` or `catch_up_jump`; monotonicity `allow_backward`, `clamp_monotonic`, `fault_on_backward`; overdue timer `fire_at_boundary`, `drop`, `reschedule_periodic` |
| clock wander | positive update step, maximum offset/rate, nonempty ordered signed rate increments |
| clock source transition | `healthy`, `degraded`, `failed { behavior }`, `fallback { source }`; failure behavior `stop` or `read_error` |
| clock synchronization | `step`; or `slew { rate, threshold_nanos }` |
| accelerator transition | `disappear`, `reset`, `reconnect` |
| accelerator job/result | job kind, optional queue, occurrence; result byte offset, mask, value |
| accelerator thermal/power | temperature in millikelvin and power in milliwatts |

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
