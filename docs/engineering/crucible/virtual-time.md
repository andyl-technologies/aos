# Virtual time

Crucible's guests never observe host time. Every VM and every deterministic
I/O sub-node runs on one exact logical timeline whose unit is the picosecond
tick. A running VM advances that timeline only by retiring guest
instructions; an idle VM advances it only through a scheduler-authorized
jump. This page describes the units, the host and plugin types that carry
them, the shared-memory handoff, and how the scheduler moves time forward.

The determinism argument that depends on this model is in
[determinism.md](determinism.md). Horizon selection and the quantum loop are
in [scheduling.md](scheduling.md); the full node-slot layout is in
[shmem-abi.md](shmem-abi.md).

## Units

| Quantity | Value | Defined in |
| --- | --- | --- |
| Ticks per guest nanosecond | `1_000` | `SIM_TICKS_PER_NS` (`crucible-engine`), `TICKS_PER_NS` (`crucible-qemu-shmem`) |
| Ticks per retired instruction | `50` | `SIM_TICKS_PER_INSTRUCTION`, `TICKS_PER_INSTRUCTION` |
| Tick | one picosecond | `SimTick` in `crates/crucible/crucible-engine/src/model/time.rs` |
| Guest TSC period (x86 `sim`) | 250 ticks | `icount_get_tsc_ticks` in the QEMU patch |

The relations are fixed:

```text
logical_tick  = raw_retired * 50 + idle_bias        (running VM)
guest_ns      = floor(logical_tick / 1000)          (guest/API boundary only)
tick_for_ns   = checked(authored_ns * 1000)         (authored durations)
guest_tsc     = floor(logical_tick / 250)           (x86 sim mode)
```

A running `sim` VM therefore executes 50 ticks per retired instruction, a
fixed rate of 20 billion instructions per virtual second, and a thousand
consecutive ticks share one integer nanosecond. The tick, not the
nanosecond, is the coordinate used for scheduling, shared-memory ceilings,
delivery stamps, event-log stamps, and checkpoints. Rounding to nanoseconds
would merge 1,000 distinct coordinates and change horizon, timer, and
delivery ordering, so nanoseconds are only ever a projection.

The QEMU patch pins the same constants at compile time against the generated
shared-memory header:

```c
G_STATIC_ASSERT(CRUCIBLE_SIM_TICKS_PER_NS == CRUCIBLE_SHMEM_TICKS_PER_NS);
G_STATIC_ASSERT(CRUCIBLE_SIM_TICKS_PER_INSTRUCTION ==
                CRUCIBLE_SHMEM_TICKS_PER_INSTRUCTION);
G_STATIC_ASSERT(CRUCIBLE_SIM_TICKS_PER_NS %
                CRUCIBLE_SIM_TICKS_PER_INSTRUCTION == 0);
```

### Two coordinates: logical ticks and raw retirement

Idle jumps move logical time without retiring instructions, so a VM has two
separate coordinates:

- **Raw retired count**: QEMU's aggregate instruction counter across all
  vCPUs. It is architectural evidence: fingerprints, divergence bisection,
  instruction-specific fault evidence, and checkpoint `node_icounts` use it.
- **Logical tick**: the scheduling coordinate. It equals
  `raw_retired * 50 + bias`, where the bias is the accumulated sum of
  authorized idle jumps (`timers_state.crucible_sim_tick_bias` in the patch).

The invariant `raw_retired * 50 <= logical_tick` holds at every published
boundary; `NodeSlot` rejects a publication that violates it with
`NodeSlotError::RawRetirementAhead`. Code must not present a logical tick as a
raw retirement witness, and `Icount::initial_virtual_time` is documented as a
bias-free projection that a live VM must not use to reconstruct its time.

### The fixed `sim` profile

QEMU's `-icount shift=N` assigns `2^N` nanoseconds per instruction in
ordinary TCG. The patched `sim` accelerator ignores that mapping and uses its
own fixed 50 ps per instruction; it requires the internal profile
`-icount shift=0,sleep=off,align=off`. The shift is therefore not a selectable
nanosecond time scale in `sim` mode, and no scenario or user option exposes a
shift. In the patch, `icount_crucible_sim_mode()` is true only for precise
icount under the `sim` accelerator, and
`icount_crucible_sim_configuration_valid()` additionally requires
`shift == 0`, `align` off, and `sleep` off.

The host enforces the same profile before spawn in
`validate_pre_spawn_qemu_launch_args`
(`crates/crucible/crucible-qemu-host/src/launch/validation.rs`): a missing
shift, `shift=auto`, or any nonzero shift is rejected, as is any `sleep` or
`align` value other than `off`. `shift=auto` is rejected because adaptive
icount makes the number of instructions before a timer deadline depend on host
speed.

The fixed scale is part of launch identity. `scenario_hash_material` emits
`qemu_icount_shift=0`, `sim_tick=picosecond`, `sim_ticks_per_ns=1000`,
`sim_ticks_per_instruction=50`, and
`virtual_time_ns=floor(sim_tick/1000)`, and
`scenario_hash_material_for_nodes` adds one sorted
`node_sim_ticks_per_ns[<node>]=1000` line per node. Every node shares the
same scale and the same epoch; there is no per-node scale.

## Host time types

`crates/crucible/crucible-engine/src/model/time.rs` names each coordinate
separately so they cannot be confused:

| Type | Field | Meaning |
| --- | --- | --- |
| `VirtualInstant` (alias `SimInstant`) | `ticks: u64` | A point on the shared timeline, ticks since `VirtualInstant::EPOCH` |
| `VirtualTime` | `ticks: u64` | Serialized virtual-time value used in model signatures and checkpoints |
| `SimDuration` | `ticks: u64` | An unsigned span |
| `SimOffset` | `ticks: i64` | A signed offset |
| `Icount` | `retired: u64` | A raw retired-instruction count |
| `NodeCounter` | `ticks: u64` | A node-local logical counter before projection |

The operator set encodes the algebra. `VirtualInstant + SimDuration` is
defined; there is no `VirtualInstant + VirtualInstant`.
`VirtualInstant::duration_since` saturates at zero instead of producing a
negative span. `VirtualInstant::with_skew(SimOffset)` saturates at the epoch
below and `u64::MAX` above. Point and duration addition saturate rather than
wrap. Ordering, equality, and hashing are derived from the integer fields.

Conversions are checked and never lose phase silently:

- `VirtualInstant::from_nanoseconds` and `SimDuration::from_nanoseconds`
  multiply by 1,000 and fail with `TimeConversionError::NanosecondOverflow`.
- `VirtualInstant::nanoseconds_floor` is the only point-to-nanosecond
  projection.
- `SimDuration::nanoseconds_exact` fails with
  `TimeConversionError::SubNanosecondDuration` unless the span is a whole
  number of nanoseconds, so a tick span is encoded into a nanosecond field only
  when no phase would be discarded.
- `Icount::initial_virtual_time` fails with
  `TimeConversionError::VirtualTimeOverflow`.

No floating point appears on any time path.

### Mapping a backend counter onto the timeline

`NodeTimeMapping` (`crates/crucible/crucible-engine/src/node_time.rs`) anchors
one node's backend counter to scheduler time:

```rust
pub struct NodeTimeMapping {
    pub anchor_counter: NodeCounter,
    pub anchor_time: SimInstant,
}
```

`NodeTimeMapping::IDENTITY` anchors counter 0 at the epoch. A replacement
backend started from a restored checkpoint may report a different counter
origin; the scheduler re-anchors the mapping so the committed logical boundary
is preserved. `logical_time`, `counter_for_logical_time_ceil`, and
`counter_for_logical_time_floor` are checked and reject projections outside
the mapping's domain. Guest clock faults are applied by the signal-driven QEMU
adapter and never alter this map (see
[../../users/crucible/signal-driven-faults.md](../../users/crucible/signal-driven-faults.md)).

Deterministic I/O sub-nodes use `VirtualClock`
(`crates/crucible/crucible-device/src/clock.rs`), a scheduler-driven tick
cursor. Device latencies are added to the exact request tick, preserving its
sub-nanosecond phase.

## Who may move time

Only two sources move a VM's logical clock, and both are bounded by a
scheduler-published ceiling. The plugin models them as
`PluginClockAdvanceSource` in
`crates/crucible/crucible-qemu-plugin/src/time_control.rs`:

| Source | Plugin entry point | Effect |
| --- | --- | --- |
| `GuestInstructions` | `PluginVirtualClock::advance_guest_instructions` | Adds `retired * 50` ticks, rejected past the `SchedulerCeiling` |
| `SchedulerAuthorizedIdleJump` | `PluginVirtualClock::advance_authorized_idle_jump` | Moves to a scheduler-authorized target without retirement |

`PluginVirtualClock` has no wall-clock or monotonic-clock input and can only
be constructed with a `PluginTimeControlOwnership` token. An idle-jump
authorization (`SchedulerAuthorizedIdleJump`) records the tick it was issued
from; consuming it at any other tick fails with
`PluginClockError::StaleIdleJumpAuthorization`.

### Acquiring time control before guest code

The plugin requests QEMU's virtual clock through
`qemu_plugin_request_time_control` during registration, before any guest
instruction can retire. `CANONICAL_TIME_CONTROL_REGISTRATION_ORDER` fixes the
sequence:

```text
ParseArguments -> ControlHandshake -> RequestTimeControl -> ReceiveSetup
  -> MapSharedMemory -> ArmWakeFd -> RegisterCallbacks -> SendSetupAck
  -> WaitBootBarrier -> FirstVisibleInstruction
```

A fresh `NodeSlot` holds `max_advance_icount` at 0, so the guest is parked at
the boot barrier until the scheduler publishes its first ceiling. Launch
identity records `time_control_owner=crucible-qemu-plugin` and
`time_control_acquire=registration-before-first-visible-instruction`.

### No warp and no realtime budget

Two upstream behaviors would let host time leak into the virtual clock. The
QEMU patch disables both in `sim` mode only:

- **Idle warp.** Upstream icount advances `QEMU_CLOCK_VIRTUAL` by host time
  while every vCPU sleeps. Under the `sim` accelerator,
  `icount_start_warp_timer` only notifies `QEMU_CLOCK_VIRTUAL` and returns;
  clock movement is commanded by the host. The patch also exports
  `qemu_plugin_has_time_control`, the ownership predicate behind warp
  suppression while the scheduler owns idle advancement.
- **Realtime deadlines in the instruction budget.** Upstream mixes the
  nearest `QEMU_CLOCK_REALTIME` deadline into the per-TB instruction budget.
  For `sim` precise icount the budget is derived from `QEMU_CLOCK_VIRTUAL`
  deadlines only; otherwise the number of instructions retired before a TB
  exit would depend on host speed.

Launch identity records both as `idle_warp_under_time_control=suppressed`,
`icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL`, and
`realtime_deadline_in_precise_budget=false`. The host also rejects `-realtime`
and host RTC clocks before spawn.

### Guest-visible clocks

Every guest time source derives from logical ticks and a fixed epoch:

| Source | Configuration |
| --- | --- |
| RTC | `-rtc base=2026-01-01T00:00:00,clock=vm` (`DEFAULT_RTC_EPOCH_UTC`) |
| TSC (x86) | `floor(logical_tick / 250)`, uniform across vCPUs |
| Timer devices | `QEMU_CLOCK_VIRTUAL` at picosecond resolution, with nanosecond projections at public APIs |

Pre-spawn validation rejects `-rtc` with `clock` other than `vm`, a missing
`base`, `base=utc`, or `base=localtime`. On AArch64 the CPU model must set
`pmu=off` so PMU retirement timing is not guest-visible.

The engine has a signed `SimOffset` and `VirtualInstant::with_skew`, but no
scenario field configures per-node clock skew or drift. Guest clock
perturbation is a fault-model feature handled outside the scheduler map.

## The ceiling handoff

The scheduler computes an exact-tick horizon for a node, publishes that same
tick as the max-advance ceiling, and waits for the node to report the tick it
reached. No nanosecond conversion occurs anywhere in the loop.

```text
 scheduler                       NodeSlot (shmem)                 plugin / QEMU
 ---------                       ----------------                 -------------
 horizon(tick) ---------------> max_advance_icount  ---wake----> run guest up to
                                advance_stop_condition           the ceiling or
                                advance_publication_sequence     an idle park
                                                                      |
 next horizon <---------------- current_icount (tick) <---------------+
                                current_ns, idle_wake_icount
                                logical_time_raw_icount, status
```

The relevant `NodeSlot` fields are below (from
`crates/crucible/crucible-qemu-shmem/src/shmem/frame_node/layout.rs`). For
historical reasons several fields are named `*_icount`; in the current ABI
they all carry logical ticks, and only `logical_time_raw_icount` carries raw
retirement.

| Offset | Field | Direction | Meaning |
| --- | --- | --- | --- |
| 0 | `current_icount` | plugin to host | Logical tick reached |
| 8 | `current_ns` | plugin to host | `current_icount / 1000` |
| 16 | `max_advance_icount` | host to plugin | Ceiling tick |
| 24 | `idle_wake_icount` | plugin to host | Next local wake tick when idle |
| 32 | `wake_signal` | host to plugin | Non-private futex word |
| 36 | `status` | plugin to host | `STATUS_RUNNING`, `STATUS_IDLE`, `STATUS_DONE` |
| 39 | `advance_stop_condition` | host to plugin | `Ceiling` or `NextAuthenticatedIdle` |
| 48 | `device_completion_deadline_tick` | host to plugin | Pending device completion, 0 if none |
| 104 | `logical_time_raw_icount` | plugin to host | Raw retired count at the published tick |
| 208 | `advance_publication_sequence` | host to plugin | Seqlock over the ceiling tuple |

Ordering and fail-closed rules:

- The host release-stores the ceiling and stop condition under
  `advance_publication_sequence`, then increments `wake_signal` and issues a
  cross-process futex wake. Readers retry until the sequence shows a stable
  `(ceiling, stop condition)` tuple, which excludes partial transitions and a
  ceiling-to-idle-to-ceiling ABA. `load_scheduler_advance` rejects an unknown
  stop-condition byte.
- `NodeSlot::publish_scheduler_advance` refuses a ceiling behind the
  published current tick (`NodeSlotError::CeilingBeforePublishedCurrent`).
- `check_node_may_advance_to` and `publish_reached_icount` reject any tick past
  the ceiling (`NodeSlotError::NodeAdvancePastCeiling`). A node never extends
  its own authorization.
- `publish_idle` requires `idle_wake_icount >= reached tick`.
- The plugin parks without a host busy-wait: the idle callback calls QEMU's
  one-shot `qemu_plugin_crucible_wait_idle_wake`, which releases the BQL
  around one futex wait and forces a fresh all-idle rescan on return.

`AdvanceStopCondition::Ceiling` completes an advance at the ceiling or at an
idle park that cannot reach it. `AdvanceStopCondition::NextAuthenticatedIdle`
completes it at the next all-vCPU idle state, which is published without
authorizing the idle deadline; a later advance must authorize that jump.

### Exact boundaries between instructions

An exact event may fall between two retirement boundaries, because
retirements land on multiples of 50 ticks plus the current bias. In the
patched RR loop, the instruction budget toward the next exact deadline is
`floor((deadline - now) / 50)`, so the CPU stops at the last complete
retirement at or below the target. When fewer than 50 ticks remain before the
earlier of that deadline and the logical ceiling,
`rr_crucible_sim_advance_fractional_boundary` performs a time-only advance to
the exact tick and runs due virtual timers. The event is never snapped to a
neighboring retirement. `icount_advance_virtual_time_to_tick` rejects a target
outside `sim` mode, beyond `INT64_MAX`, or, once shared-memory dispatch is
registered, past the logical ceiling.

## Idle fast-forward

When every vCPU is idle the plugin computes an exact next wake instead of
guessing. `compute_idle_wake_plan`
(`crates/crucible/crucible-qemu-plugin/src/idle_loop/planning.rs`) takes the
earliest of:

| `IdleWakeCause` | Source |
| --- | --- |
| `TimerDeadline` | Next `QEMU_CLOCK_VIRTUAL` deadline from `qemu_plugin_clock_deadline_ps` |
| `InboundFrame` | Delivery tick of the head inbound frame |
| `DeviceIoCompletion` | Host-published `device_completion_deadline_tick` while device I/O is active |
| `DeviceIoFreeze` | Device I/O active with no completion deadline; timer deadlines are held |
| `SchedulerCeiling` | No local wake; the ceiling bounds the park |

Because a tick is a picosecond, the picosecond deadline from QEMU is used
directly as the wake tick (`timer_deadline_icount`). The exact-deadline export
is required: `ExactDeadlineReader::require` fails with
`ExactDeadlineError::CapabilityUnavailable` when
`qemu_plugin_clock_deadline_ps` is missing, and there is no
overshoot-and-correct fallback. The export returns `-1` for no armed timer and
`-2` for an unrepresentable deadline; `-2` and any other negative value are
errors. The deadline never consults `QEMU_CLOCK_REALTIME` or
`QEMU_CLOCK_HOST`.

For a multi-vCPU node, `aggregate_multi_vcpu_deadline` reduces per-vCPU
reports to the minimum over all vCPUs' armed virtual-clock deadlines. Per-vCPU
deadlines stay inside the plugin; only the node minimum reaches the scheduler,
where it becomes the node's `ExactLocalEvent::TimerDeadline` in horizon
computation.

Once authorized, the jump is queued through `qemu_plugin_advance_time_ticks`.
QEMU applies it from a main-loop bottom half, dispatches due virtual timers,
and then invokes the completion callback registered with
`qemu_plugin_register_time_advance_cb`.
`PendingIdleAdvance::validate_completion` rejects a nonzero status or a
completion whose echoed target differs from the requested tick.

A plugin-validated virtual-timer witness (`timer_witness_*` slot fields,
published under `publish_gen`) records the armed deadline, the tick it was
published as, and the raw icount at arm and fire. It gives the host evidence
that an idle wake corresponded to an actual `QEMU_CLOCK_VIRTUAL` callback.

## Multi-vCPU nodes: one aggregate clock

All vCPUs of a node run on one host thread under single-threaded
round-robin TCG. The node has exactly one raw retired count, the aggregate
retired-instruction count across all `N` vCPUs, and one logical tick clock
derived from it plus the idle bias. The shared-memory ABI has no
per-vCPU slots or clocks. Per-vCPU retired counts are plugin-internal and
appear only in fingerprint evidence; the scheduler orders nodes, not vCPUs.

The vCPU switch point is `rr_switch_quantum`, an integer number of retired
instructions passed as `-icount ...,rr_switch_quantum=<n>` and recorded in
launch identity with `rr_switch_quantum_units=retired-instructions` and
`rr_vcpu_rotation=ascending-vcpu-id`. The default is
`DEFAULT_RR_SWITCH_QUANTUM = 4096`; zero and values above `i32::MAX` are
rejected. The quantum is fixed, so it never adapts to wall time. 4096 was
chosen as the smallest swept quantum that met the throughput floor without
losing race discrimination.

## Restore and inactive time

Checkpoint restore must reproduce both coordinates. VMState restores QEMU's
raw icount; the logical tick is then restored through a two-step slot
transaction. The host calls `NodeSlot::arm_logical_time_restore(target)`
while the executor is stopped. The plugin answers with
`acknowledge_logical_time_restore(request, reached, raw)`, which requires
`reached == target` and `raw * 50 <= reached`, and publishes the node as idle
at that exact boundary. This preserves sub-nanosecond idle-jump phase across
restore. A stale or mismatched acknowledgement fails.

When every node is `Halted` or `Done`, the scheduler can still advance its
own frontier to a pending trigger or signal-fault wakeup without issuing a
backend RUN (`crates/crucible/crucible-engine/src/scheduler/inactive_time.rs`).
It never advances a powered-off backend counter. A reactivated node joins the
current frontier.

## Cross-node ordering

Every cross-node event retains its exact tick stamp through delivery. The
scheduler orders due events by `ScheduledEventKey`, which sorts by
`(virtual_time, consumer node, producer node, sequence)`; the consumer and
sequence come from `SharedTimelineKey`. In shared memory, inbound frames
carry their delivery tick in `FrameEntry::delivery_icount`, and the plugin
exposes due frames in `FrameDeliveryKey` order
`(delivery_icount, src_node, seq)`. Visibility depends on the stamped tick,
never on when the frame appeared in the ring. See
[determinism.md](determinism.md#contract-b-injection-determinism) and
[scheduling.md](scheduling.md).
