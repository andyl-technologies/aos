# 0088/0090 - Deterministic host-kick boundary

## Purpose

Patch `0087` removes the forced-RCU notifier as one source of host-timed
translation-block exits, but QEMU's generic single-threaded TCG kick entry point
is shared by host work, main-loop notifications, stop requests, and device
control. Its upstream implementation calls `cpu_exit()` for every RR vCPU as
soon as the host request arrives. Under load, that arrival coordinate changes
where a pending guest interrupt becomes architecturally visible.

Patch `0088`, refined by patch `0090`, prevents generic host latency hints from choosing a guest
instruction boundary while a bounded Crucible sim execution slice is active.
Already-committed stop, unplug, halted, stopped, and interrupt-request states,
plus an admitted exact terminal-pause request, retain an immediate exit request
for the shared RR execution thread. The first four cannot rely on further guest
retirement for progress; an interrupt request is already guest-visible modeled
state, and the admitted terminal pause is a deterministic observer action at a
proven instruction boundary.

## Admission and progress contract

`rr_kick_vcpu_thread` skips the immediate all-vCPU `cpu_exit()` loop only when
all five predicates hold:

1. the active accelerator is `sim`;
2. precise icount is active; and
3. `icount_crucible_rr_switch_quantum()` is nonzero; and
4. `icount_get_raw_observed()` reports at least one retired instruction;
5. more than one vCPU exists, so host timing could select an RR owner; and
6. the serialized RR loop has atomically published
   `rr_tcg_exec_active = true` immediately before entering
   `tcg_cpu_exec()` or `cpu_exec_step_atomic()`.

Patch `0088` originally used a non-null `rr_current_cpu` for the fifth
predicate. That pointer is published before `cpu_can_run()` is evaluated, so it
also describes startup and other non-executing RR-loop intervals. Patch `0090`
removes that approximation. Only the explicit execution flag proves that guest
code is inside a bounded TCG slice.

The raw observer is mandatory here. `icount_get_observed()` includes QEMU's
virtual-clock bias and can therefore be nonzero before the first guest
instruction, which would suppress the startup kick.

Every other configuration, including every single-vCPU guest, executes the
upstream loop unchanged. A single-vCPU loop has no alternate RR owner for a
host kick to select, while retaining the kick is required for startup and
main-loop progress. In the guarded
configuration, the active vCPU does not receive `cpu_exit()` merely because a
host latency hint arrived. The remaining serialized RR budget is finite and no
larger than the pinned quantum. Between slices, the RR loop clears
`rr_current_cpu`; a generic kick then retains upstream behavior so an idle or
waiting thread receives the exit request needed to re-enter its run loop. If an
exact terminal pause is pending, or any
vCPU is already stopping, unplugging, halted, stopped, or has a published
interrupt request, the guarded path calls `cpu_exit()` for every vCPU. All RR
vCPUs share one host execution thread, so a stateful transition targeting a
non-current vCPU must also return the current TCG slice. Native pause, shutdown,
hot-unplug, terminal observation, and interrupt wakeups thereby preserve their
established guest-visible semantics.

At icount zero, QEMU retains upstream immediate-kick behavior. `cpu_resume()`
clears the initial stop flags before issuing the kick that starts the RR thread.
Because no guest instruction has executed, this startup kick cannot select an
architectural coordinate. Single-vCPU execution retains upstream kicks at every
icount because no alternate guest CPU exists. During each later multi-vCPU
active slice, the pinned finite quantum supplies the deterministic return
boundary.
The execution flag is cleared immediately after TCG returns, before icount
processing and exact-boundary callbacks, so generic kicks retain upstream
liveness throughout every between-slice interval.

The host request's arrival time is not recorded and does not alter the RR
owner, cursor, translation-block endpoint, interrupt window, or architectural
execution. This patch does not drop work and does not turn a condition signal
into the source of truth.

## Interaction with other scheduler exits

Deterministic preemption commands, exact fault boundaries, terminal horizon
stops, guest exceptions, and guest-generated interrupts retain their existing
modeled exit paths. Patch `0087` separately covers the forced-RCU notifier;
patch `0088` covers the generic host kick callback registered by the RR
accelerator. QEMU's virtual-time RR kick timer remains disabled in sim mode by
the earlier deterministic scheduler patches.

## Files and license scope

The patch modifies MIT-licensed `accel/tcg/tcg-accel-ops-rr.c` and
GPL-compatible internal plugin declarations and implementation in
`include/qemu/plugin.h` and `plugins/api.c`. It creates no QEMU source file and
adds no cross-process field, callback, or shared-memory representation.

## Required gates

1. Run the production four-vCPU fingerprint workload twice through the exact
   3,700,000,000-instruction horizon.
2. Apply sustained host CPU contention only to the second run, causing host
   work and notification schedules to differ.
3. Require identical canonical all-vCPU registers, RAM, device state, RR
   cursor/switch events, and deterministic-IPI evidence at every sample.
4. Require QMP topology, terminal stop, exact checkpoint pause, and process
   teardown to complete within their existing bounds, proving state-aware kicks
   preserve control liveness.
5. Run the production single-vCPU fingerprint workload with the pinned quantum
   and require it to boot from icount zero, reach its exact horizon, checkpoint,
   and compare identically, proving startup progress and post-genesis boundary
   determinism are both preserved.
6. Prove stock QEMU retains the immediate generic kick and that configurations
   outside the six-part admission predicate, including single-vCPU guests and
   between-slice waits,
   retain that path.
7. Rebuild every patch prefix and pass regeneration, ABI, license, inertness,
   and corresponding-source gates.

- **[QFP-KICK-1]** While a bounded sim execution slice is active, generic host
  kicks MUST NOT choose translation-block or interrupt-visibility coordinates.
- **[QFP-KICK-2]** Deferred host work MUST remain level triggered; an admitted
  exact terminal observation and committed control and interrupt state MUST
  retain an immediate exit request for the shared RR execution thread.
