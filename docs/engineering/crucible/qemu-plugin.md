# The in-QEMU plugin

`crates/crucible/crucible-qemu-plugin` builds the `cdylib` that QEMU loads
with `-plugin`. It is the only Crucible code that runs inside the emulator.
It owns the guest's virtual clock, parks the guest when it goes idle,
intercepts device I/O, and injects cross-node inputs at their exact delivery
instruction counts. It talks to the host through the shared-memory region
described in [shmem-abi.md](shmem-abi.md) on the hot path and through the
control socket described in [control-protocol.md](control-protocol.md) once
at setup and once at shutdown.

The crate is GPL-2.0-only because it implements QEMU plugin entry points and
callbacks. It may depend on the dual-licensed `crucible-qemu-protocol` and
`crucible-qemu-shmem` boundary crates but never on Apache-only host crates;
see [../../legal/licensing.md](../../legal/licensing.md). The host side is in
[qemu-integration.md](qemu-integration.md), and the QEMU APIs the plugin
calls are listed in [qemu-patch.md](qemu-patch.md#plugin-api-surface).

## Module map

| Module | Owns |
| --- | --- |
| `abi` | `qemu_plugin_version`, `qemu_plugin_install`, symbol resolution, execution-model validation |
| `args` | Fail-closed `-plugin` argument parsing (`PluginArgs`) |
| `registration`, `runtime` | The fail-stop registration sequence and process-lifetime runtime ownership |
| `handshake`, `setup` | `Hello`/`HelloAck`, descriptor mapping, setup-plan authentication, `SetupAck` |
| `boot_barrier` | The initial-ceiling wait before the first guest instruction |
| `time_control`, `deadline`, `idle_loop` | Clock ownership, exact deadlines, and the idle hot loop |
| `round_robin`, `preemption`, `vcpu_introspection` | vCPU rotation, halt tracking, commanded preemption, per-vCPU reads |
| `inbound`, `network_rx`, `network_tx` | Inbound ordering, lossless RX injection, TX interception |
| `device_io`, `block_io`, `ninep_io` | The device-I/O time hold and block and 9p routing |
| `whitebox_doorbell`, `coverage` | Optional white-box doorbell and basic-block coverage |
| `teardown` | Shutdown triggers and post-trigger sealing of shared memory |
| `shmem_ordering` | The single funnel for shared-memory access |
| `inertness` | Plugin-side sim-off assertions |

## Execution model

Every simulation VM runs under `-accel sim,thread=single` with one or more
vCPUs. QEMU drives all vCPUs on one host thread, so every vCPU-thread callback
is serialized onto that thread for any vCPU count. That is what keeps the
plugin's callback state uncontended: locks exist to satisfy Rust's rules for
process-global state, not to arbitrate real contention. During install the
plugin validates `qemu_info_t` (`QEMU_PLUGIN_API_VERSION` is 7,
`MIN_SUPPORTED_VCPU_COUNT` is 1) and requires
`qemu_plugin_crucible_single_threaded_rr` to report single-threaded round
robin; multi-threaded TCG is rejected with
`QemuPluginAbiError::MultiThreadedTcg`. A vCPU count above one is not
rejected.

Callbacks can re-enter each other on the vCPU thread. An idle advance fires a
guest timer, the timer handler transmits a frame, and the TX callback runs
inside the idle path. The plugin therefore splits its state:

- a lifecycle and clock core touched only by the lifecycle callbacks, and
- device-callback state (ring pointers, slot, sequence counters) fixed at
  registration and read without taking any lock the idle path holds.

The plugin also runs a few dedicated worker threads for run-phase control
reads, teardown, and fingerprint capture. They exchange only typed messages
with the callbacks and never decide virtual time.

## Arguments

QEMU passes comma-separated `key=value` tokens after the shared-object path.
`PluginArgs::parse` is total and fail-closed: a missing required key, a
duplicate key, a malformed token, an unknown key, or an unparsable value is a
`PluginArgsParseError`, and registration stops before any side effect.

| Key | Required | Meaning |
| --- | --- | --- |
| `simfd=N` | yes | Control socket descriptor (fd 3 in production) |
| `slot=N` | yes | Zero-based node slot; the only key used to find this node's cells |
| `fault_node_hash` | yes | 32-byte lowercase hex fault-target identity |
| `process_generation` | yes | Nonzero host-supervised process generation |
| `network_tx_next_seq` | yes | Authenticated next TX sequence for this process |
| `storage_completed_history_epochs`, `storage_completed_history_gaps` | yes | Block history limits, capped by compiled maxima |
| `shmemfd=N`, `wakefd=N` | no | Pre-inherited descriptors; both or neither |
| `whitebox=on\|off` | no, default `off` | Enables the doorbell trap |
| `whitebox_setup` | with `whitebox=on` | Collision-validation attestation (`x86-port-00e7-unclaimed-v1` or `aarch64-hint-4c-inert-v1`) |
| `campaign_marker_parking=on` | no | Requires `whitebox=on` |
| `app_random_*` | no | Seeded app-random configuration; requires `whitebox=on` |
| `coverage=on\|off` | no, default `off` | Enables basic-block coverage |
| `fingerprint=on\|off` | no, default `off` | Enables single-VM fingerprint sampling |

The canonical source of the shared-memory and wake descriptors is the
`Setup` frame, not the command line. `PluginArgs::validate_slot_index`
rejects a slot outside `0..node_count` once the node count is known.

## Install and registration order

`qemu_plugin_install` copies QEMU's info and argv, reserves the
process-lifetime runtime, runs the install, and publishes the runtime only
on success. A panic is caught and turned into `QEMU_PLUGIN_INSTALL_ERROR`
with a stderr diagnostic. Before the handshake, a production preflight
resolves every QEMU export and callback registration the selected launch mode
needs. A missing capability fails the install before any socket traffic.

`PluginRegistrationSequence` accepts only the steps of
`CANONICAL_TIME_CONTROL_REGISTRATION_ORDER`, in this fixed order:

```text
ParseArguments
ControlHandshake          Hello -> HelloAck, slot cross-check
RequestTimeControl        qemu_plugin_request_time_control
ReceiveSetup              three SCM_RIGHTS descriptors
MapSharedMemory           mmap exactly region_len, validate header
ArmWakeFd                 authenticate the setup plan, arm the eventfd
RegisterCallbacks         device, vCPU, coverage, white-box callbacks
SendSetupAck              SetupAck(0)
WaitBootBarrier           park until the first ceiling
FirstVisibleInstruction
```

A failure at any step records a diagnostic and blocks every later step.
Time control is requested before setup, so no warp or real-time advance can
occur before the plugin owns the clock. If QEMU reports that another plugin
already holds time control, registration fails; one VM has exactly one
time-controlling plugin.

Failure handling depends on how far registration got. Before any callback is
stored, the install returns an error and QEMU unloads the plugin. Once
callback registration has begun, Crucible's QEMU callback slots are not
transactionally tied to QEMU's uninstall path, so a failure writes a
diagnostic and aborts the process. A callback-registration failure is first
reported to the host as a nonzero `SetupAck`.

## Handshake and setup completion

`perform_plugin_handshake` sends `Hello` with the compiled
`CONTROL_PROTOCOL_VERSION` and shared-memory `ABI_VERSION`, waits for
`HelloAck`, and requires an exact match of both versions and
`slot_index < node_count`. The authoritative slot is the handshake's, and it
must equal the launch argument; a difference is
`PluginHandshakeError::LaunchSlotMismatch`. The handshake happens before any
byte of shared memory is mapped.

On `Setup` the plugin requires exactly three descriptors via `SCM_RIGHTS`
(`SETUP_DESCRIPTOR_COUNT`), in fixed order:

1. the shared-memory memfd, mapped for exactly the advertised `region_len`
   and validated for magic, ABI version, node count, and slot;
2. the wake eventfd, armed and registered with QEMU through
   `qemu_plugin_register_wake_fd` before readiness;
3. the plugin setup plan: a regular memfd sealed with `F_SEAL_SHRINK`,
   `F_SEAL_GROW`, `F_SEAL_WRITE`, and `F_SEAL_SEAL`, read up to
   `PLUGIN_SETUP_PLAN_MAX_BYTES`, and strictly decoded as the `CRUCSUP2`
   composite carrying the app-random branch plan and the selectable catalog.

Any other descriptor count, a short region, a mutable or malformed plan, or
a failed header check is a setup failure. `SetupAck` reports
`SETUP_ACK_STATUS_READY` (0) only after the region is mapped and validated,
the wake fd registered, and every required callback registered. On any other
status the plugin never reads its clock cell, polls its rings, or advances
time.

## Boot barrier

After `SetupAck(0)` and before the guest retires its first
architecturally visible instruction, `PluginBootBarrier` publishes an idle
wait for `BOOT_BARRIER_FIRST_GUEST_ICOUNT` (1) and parks on the slot's
`wake_signal` futex until the scheduler publishes a nonzero
`max_advance_icount`. The slot's ceiling starts at zero, so the plugin cannot
advance before the barrier releases. The futex is the only wait primitive
for the barrier: the eventfd is a separate QEMU main-loop nudge, and the
barrier has no wall-clock timeout or sleep fallback.

Without the barrier the guest would start at QEMU's default instruction
budget and run past the boot rendezvous by a host-dependent amount before
its first idle. With it, the first run is deterministic from instruction
zero; there is no golden first run.

## Time control

Once time control is acquired, the plugin is the only authority that
advances its node's virtual time. Virtual time moves only when the guest
retires instructions up to the scheduler-published ceiling, or when the
plugin makes an explicit idle jump to a scheduler-authorized target. No
plugin path that influences virtual time, frame delivery, or I/O completion
reads host wall-clock time, host monotonic time, or host entropy. The plugin
never extends its own ceiling.

Virtual time is a picosecond logical clock. The shared-memory "icount" fields
the plugin reads and publishes are in these ticks, 50 per retired
instruction; see [virtual-time.md](virtual-time.md).

### Exact deadlines

`ExactDeadlineReader::require` takes the patched
`qemu_plugin_clock_deadline_ps` export and fails registration with
`ExactDeadlineError::CapabilityUnavailable` if it is missing. Each read
returns `ExactDeadlineReport::NoArmedTimer` or
`ExactDeadlineReport::Armed { deadline_ps }` from `QEMU_CLOCK_VIRTUAL`; the
export's `-2` sentinel becomes
`ExactDeadlineError::UnrepresentableDeadline`. Because the deadline is
already in picoseconds, `timer_deadline_icount` uses it directly as a tick
after a range check. There is no overshoot-and-correct fallback: guessing a
jump and backing off cannot be made bit-deterministic.

### The idle hot loop

The node is idle only when every vCPU is halted. `VcpuHaltTracker` maintains
per-vCPU halt state from QEMU's idle and resume callbacks, so the all-halted
predicate is exact. A vCPU that un-halts (interrupt, IPI, or commanded
preemption) clears node idleness. When the last vCPU halts,
`PluginIdleHotLoop` runs one turn:

1. **Publish.** Read the current count and publish `current_icount`,
   `current_ns`, and a new `publish_gen`.
2. **Plan.** `compute_idle_wake_plan` merges three candidates and picks the
   earliest, breaking ties in device, timer, inbound order:
   - a host-published device completion deadline
     (`device_completion_deadline_tick`, only while device I/O holds);
   - the exact timer deadline, the minimum over all vCPUs, suppressed while
     device I/O holds without a completion deadline;
   - the head inbound frame's `delivery_icount`, peeked without consuming.

   With no candidate, the wake is the scheduler ceiling. The plan records
   its `IdleWakeCause`: `TimerDeadline`, `InboundFrame`,
   `DeviceIoCompletion`, `DeviceIoFreeze`, or `SchedulerCeiling`. A ceiling
   behind the current count is an error.
3. **Park.** Publish `idle_wake_icount` and `STATUS_IDLE`, then wait until
   the ceiling reaches the desired wake or shutdown is requested. The wait
   uses `qemu_plugin_crucible_wait_idle_wake`, which releases QEMU's BQL
   around one raw non-private futex wait on `wake_signal` with the exact
   expected value. Each return is rechecked against the acquire-loaded
   control flags and ceiling, and QEMU rescans its round-robin state before
   doing anything else. There is no busy spin and no wall-clock timeout; a
   liveness watchdog, if any, belongs to the host.
4. **Advance.** Enqueue one authorized target with
   `qemu_plugin_advance_time_ticks` and return from the callback without
   changing plugin clock or injection state. QEMU advances the clock and runs
   due timers from queued main-loop work, then calls the completion callback
   registered with `qemu_plugin_register_time_advance_cb` after the
   timer-produced bottom halves. If QEMU returns `-EBUSY` because a
   preceding advance still owns its barrier, the plugin rolls back, re-arms
   the all-halted edge, and recomputes after QEMU's completion kick instead
   of keeping the stale pre-input publication.
5. **Commit.** `complete_after_time_advance` validates that the completion
   names the pending target before the plugin advances its clock, consumes
   inbound rings, or injects frames. No new quantum starts while completion
   is pending.
6. **Inject.** Inject every inbound frame with
   `delivery_icount <= current_icount` in deterministic order (see below).
7. **Resume.** Republish `current_icount` and `current_ns` and set the status
   to running.

The resume callback marks the vCPU running in `VcpuHaltTracker`; it neither
blocks nor advances time. QEMU must not resume a vCPU while a queued idle
advance is pending: outside a requested control boundary that is the fatal
`LiveVcpuTimeCallbackError::ResumeWhileIdleAdvancePending`.

This two-stage advance is what makes idle fast-forward exact. A long idle gap
collapses to one jump, and every timer due in the gap fires at its exact
count, in the same order, on every run, without the plugin recursively
running QEMU's main loop.

## Round robin and commanded preemption

Between idle transitions the single-threaded round-robin loop rotates vCPUs
after each `rr_switch_quantum` retired instructions, in ascending vCPU order.
The plugin's `RoundRobinRunState` models the same rotation for planning and
evidence, and `compute_all_halted_idle_wake_plan` applies the minimum
deadline over all vCPUs through `aggregate_multi_vcpu_deadline`. A node with
one vCPU is the degenerate case: the rotation never switches, and a
preemption reduces to an interrupt at a commanded count.

The scheduler's preemption decisions arrive through a shared-memory mailbox
(`SchedulerPreemptionCommand`). The plugin checks that the commanded count
lies in the authorized `[deadline, ceiling]` window, encodes the command
(`QEMU_PREEMPTION_KIND_VCPU_SWITCH` is 1, `QEMU_PREEMPTION_KIND_INTERRUPT_AT`
is 2), applies it through `qemu_plugin_inject_preemption`, and acknowledges
the mailbox sequence only after QEMU accepts it. An out-of-window command is
a loud `PreemptionError`, never clamped, deferred, or applied at a different
count. The interleaving and any applied preemption are a pure function of
the instruction count and the decision. Exploration of these decisions is
described in [scheduling.md](scheduling.md).

## Inbound frames and network RX

The plugin reads inbound SPSC rings through `InboundFrameRing`. It peeks the
head `delivery_icount` without consuming when planning a wake, and it makes a
frame architecturally visible if and only if
`frame.delivery_icount <= current_icount`. When the bytes arrived in the
ring is irrelevant. Simultaneously deliverable frames from all rings are
injected in the total order `(delivery_icount, src_node, seq)`, independent
of which producer stored first or which ring was polled first.

A frame whose `delivery_icount` is already behind the guest's count is a
loud `InboundFrameError::DeliveryAlreadyPassed` carrying the frame key and
the current count. The one exception is the ring head after a real QEMU
backpressure result: its ABI-versioned consumer state (`FrameDeliveryState`)
records the prior attempt, and while it blocks, its same-ring FIFO
successors are authorized behind it. A retained head does not pin the next
guest wake to its already-attempted count, because guest progress is what
releases backpressure.

`PluginNetworkRx` injects from the idle context after the advance, so a frame
due inside the jumped-over window becomes visible at the deterministic wake
count. It calls `qemu_plugin_net_inject`:

| Return | Meaning | Plugin action |
| --- | --- | --- |
| `0` | Complete guest delivery | Dequeue the frame and continue |
| `1` | Guest backpressure, ownership not taken | Stop; record the retained head; leave it and its successors in the ring |
| negative | Permanent capability or link failure | Fail loudly |

Retained frames live only in the bounded shared-memory ring, which is part
of the exact checkpoint transport state, never in a QEMU-private packet
queue. Retries are spaced by `NETWORK_RX_RETRY_INTERVAL_ICOUNT` and capped by
`NETWORK_RX_DELIVERY_ATTEMPT_LIMIT` (1024). Each retry is a fresh device
probe.

## Network TX

`qemu_plugin_register_net_tx_cb` installs the TX callback. Each guest frame
becomes a `FrameEntry` in the `(slot -> SLOT_NET_ROUTER)` ring with the
emitting guest's count in `delivery_icount`, the node's slot as `src_node`,
and the next per-ring sequence starting at `network_tx_next_seq`. The host
router adds link latency and fault effects and re-stamps the delivery count;
see [io-subnodes.md](io-subnodes.md).

The TX path reads its ring and slot from registration-time state, so it is
safe to enter from inside an idle advance. A payload larger than
`MAX_FRAME_DATA` (4608 bytes) is `NetworkTxError::PayloadTooLarge`, a full
ring is a `QueueFull` ring error, and sequence exhaustion is
`SequenceOverflow`. None of them truncates, drops, or advances the sequence.
Under conservative scheduling a full outbound ring indicates a scheduling
defect, not normal backpressure.

## Device I/O and the time hold

A block or 9p round trip is submitted at one count and answered later. If
guest timer ticks could advance virtual time freely in between, the count at
which the completion became visible would depend on how many idle passes the
host happened to interleave. `PluginDeviceIoFreeze` prevents that:

- Each submit sets the slot's `device_io_active` flag, increments a local
  pending counter, and returns a non-`Copy` `DeviceIoRequestToken`. The token
  must be consumed by exactly one completion or failure, regardless of
  status, so the counter cannot drift.
- While device I/O holds, the idle plan suppresses guest timer deadlines. If
  the host has published `device_completion_deadline_tick`, the node jumps
  directly to that completion (`IdleWakeCause::DeviceIoCompletion`);
  otherwise it holds at the ceiling (`IdleWakeCause::DeviceIoFreeze`).
- The hold is released when the last request of the burst completes.

The hold does not freeze virtual time at the submit instant. The completion
becomes visible at the executor-computed delivery count, and the requester
advances to it through the exact local-event jump. Only the host-dependent
extra timer ticks between submit and completion are removed.

**Block.** `PluginBlockIo` encodes each guest request in the versioned block
wire format (`BLOCK_WIRE_VERSION` 4) into the `(slot -> SLOT_BLK_IO)` ring,
starts the hold, and returns. Poll peeks `(SLOT_BLK_IO -> slot)`, exposes a
response only after its `delivery_icount` has been reached (returning "not
ready" until then), and consumes the matching token. Registration uses
`qemu_plugin_register_blk_cb`, `qemu_plugin_register_blk_event_cb`, and
`qemu_plugin_register_blk_wait_cb`.

**9p.** `ninep_io` routes raw 9p messages through `(slot -> SLOT_9P_IO)` and
back with the same gate, allows up to 256 requests in flight, and adds a
burst-done callback. One 9p device invocation can fan out to several
requests, and the hold covers the whole burst. Registration uses
`qemu_plugin_register_9p_cb`.

The executors and wire formats are described in
[io-subnodes.md](io-subnodes.md).

## White-box doorbell

Black-box operation is the default and supports the whole determinism
contract; every fingerprint is computable with zero guest cooperation. With
`whitebox=off` the plugin installs no trap, and the reserved instruction
behaves exactly as under unmodified QEMU.

With `whitebox=on` the plugin recognizes only the frozen encodings `out
0xe7, al` (x86_64, port `0x00e7`) and `hint #0x4c` (AArch64). It reads the
payload registers and guest memory only through the QEMU plugin API
(`qemu_plugin_read_memory_vaddr`) and stamps each marker with the exact
retirement coordinate. That coordinate is the translation-block entry count
cached by the TB-entry callback plus the instruction's index within the
block; stale or missing TB metadata fails closed. Any host-to-guest reply,
such as an app-controlled random value drawn from the seeded decision
stream, is written through `qemu_plugin_crucible_write_memory_vaddr` at the
trap count and recorded as evidence, so enabling white-box cannot reorder
the instruction stream. A node that never rings the doorbell behaves exactly
like a black-box node. Frame formats, marker kinds, and the setup-time
collision validation are in
[guest-host-channel.md](guest-host-channel.md).

## Coverage

Coverage is a registration-time opt-in. With `coverage=off` the plugin
registers no translation-block callback, so the execution hot path carries no
per-block branch. With `coverage=on` it registers QEMU's stock TB
translation, conditional execution, and flush callbacks. At translation it
folds each block's guest PC into one of `DEFAULT_COVERAGE_MAP_ENTRIES`
(65,536) slots. QEMU's per-vCPU scoreboard condition invokes the
exact-count callback only while that slot is unseen, and the callback marks
the slot before publishing the novelty, so repeated execution stays on
QEMU's conditional fast path. Each novel entry is release-published into a
dedicated per-VM SPSC ring whose capacity equals the map size; the host
drains it at quantum boundaries.

Coverage is observational. It never influences scheduling, virtual time, or
injection, and enabling it does not change the execution fingerprint.
Translated-block callback userdata is reclaimed after QEMU's exclusive TB
flush. See [exploration.md](exploration.md) and
[../../users/crucible/coverage.md](../../users/crucible/coverage.md).

## Fingerprint sampling

With `fingerprint=on`, the plugin samples the node's black-box state at a
scheduler boundary into the shared-memory `FingerprintSample` slot.
`PluginVcpuIntrospector::read_nvcpu_fingerprint_inputs` reads every vCPU's
register file in ascending order through `qemu_plugin_read_vcpu_regs`, plus
the round-robin cursor through `qemu_plugin_rr_cursor`. The sampler adds RAM
and device projections from
`qemu_plugin_crucible_capture_fingerprint_material`. Every read is
side-effect-free with respect to the instruction stream and architectural
state, so sampling does not perturb the run it measures.

## Teardown

The plugin accepts exactly three shutdown triggers (`PluginTeardownTrigger`):

- `ShutdownRequested`: the region header's `shutdown_requested` flag,
  acquire-observed by a callback or a parked wait;
- `HostQuit`: a `Quit` frame read by the run-control worker;
- `RunControlFault`: an unsolicited, malformed, or closed control stream
  during the run, which selects fail-loud shutdown.

The single teardown worker takes the first trigger, publishes the node as
done, seals further shared-memory access through `PluginTeardown`, and asks
QEMU for an orderly exit through `qemu_plugin_request_shutdown`. After a
trigger the plugin never advances time or injects again. Orderly exit lets
the host's escalation ladder finish at its first rung without leaking the
child.

## Shared-memory ordering

The plugin side is single-threaded, but the scheduler, router, and executors
are other processes. All shared-memory access goes through
`PluginShmemOrdering`, whose named operations wrap `crucible_qemu_shmem`
methods carrying the ABI's ordering: acquire loads for the ceiling, control
flags, and ring write indices, and release stores for published counts, ring
frees, and status. Relaxed atomics appear only for plugin-local counters
that are never stored in the region and never publish data to another
process. The ABI's ordering rules are in [shmem-abi.md](shmem-abi.md).

## Unsafe boundary

The plugin is one of the few Crucible crates that is inherently unsafe: it
exports C ABI entry points, maps shared memory, and registers C callbacks.
The discipline is:

- Unsafe code is confined to the QEMU ABI, setup and mapping, coverage,
  fingerprint, runtime, and device callback adapters. Every `unsafe` block
  carries a nearby `// SAFETY:` comment and every unsafe function a
  `# Safety` section.
- Soundness rests on four invariants: vCPU callbacks are serialized on one
  thread; the mapped region lives for the process lifetime once setup
  succeeds; the setup descriptors are the ones handed over by `SCM_RIGHTS`;
  and registered C callbacks receive only the pinned, process-lifetime
  userdata the registrar passed. `unsafe` never papers over a data race.
- Guest memory is read and written only through the QEMU plugin memory API;
  guest addresses are opaque handles, never dereferenced as host pointers.
- Every payload copied between the guest and a ring is bounds-checked against
  `MAX_FRAME_DATA` and the request's declared length before copying.

## Fail-loud behavior

Determinism-critical failures stop the node with a distinct diagnostic and
never degrade to a best-effort or wall-clock-dependent fallback:

| Failure | Where |
| --- | --- |
| Malformed arguments | `PluginArgsParseError`, before any side effect |
| Missing QEMU capability | Install preflight, `ExactDeadlineError::CapabilityUnavailable`, symbol resolvers |
| Version, ABI, or slot mismatch | `PluginHandshakeError`, setup validation |
| Wrong descriptor count, short region, unsealed plan | `PluginSetupError`, nonzero `SetupAck` |
| Full outbound ring, oversized frame | `NetworkTxError`, block and 9p errors |
| Passed delivery count | `InboundFrameError::DeliveryAlreadyPassed` |
| Out-of-window preemption | `PreemptionError` |
| Broken run-phase control stream | `RunControlFault` teardown |

A failure inside a live callback writes `crucible-qemu-plugin: fatal live
callback failure: ...` to stderr and aborts. The host observes an unexpected
child exit and reports a crashed node for localization rather than retrying
it (see [qemu-integration.md](qemu-integration.md#crash-detection) and
[failure-triage.md](failure-triage.md)).

## Inertness

When simulation mode is off the plugin is not loaded at all: no `-plugin`
argument, no install call, no control socket, no shared-memory mapping, no
callback registration, and no call into a patched QEMU capability. Its
existence has zero effect on a QEMU process launched without it. The
`inertness` module expresses that plugin half as
`PluginInertnessObservation::sim_off`, whose counters
(`time_control_requests`, `coverage_callback_registrations`,
`whitebox_trap_registrations`, and the rest) must all be zero. The real-QEMU
corpus that proves patched QEMU matches upstream with sim mode off is
described in [qemu-patch.md](qemu-patch.md#inertness).

## Tests

Plugin behavior is covered by the crate's unit tests, the build-time
`cargo test` in `pkgs/emulation/crucible-qemu-plugin.nix`, and loaded-QEMU
checks such as `checks.crucible.phase2.qemuLivePluginInstall` (handshake,
setup, boot barrier, silent run, `Quit`, natural exit),
`checks.crucible.phase2.qemuPluginRegistrationOrder`,
`checks.crucible.phase2.qemuPluginTimeControl`,
`checks.crucible.phase2.qemuPluginSynchronousIdleAdvance`,
`checks.crucible.phase2.qemuPluginUnsafeBoundary`,
`checks.crucible.phase2.qemuPluginFailLoud`,
`checks.crucible.phase2.qemuLiveWhiteboxDoorbell`,
`checks.crucible.phase2.qemuPreemptionInject`, and
`checks.crucible.phase6.basicBlockCoverage`. See
[testing-and-gates.md](testing-and-gates.md) for the complete list.
