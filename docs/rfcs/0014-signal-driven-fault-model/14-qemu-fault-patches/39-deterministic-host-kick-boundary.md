# 0088/0090 - Deterministic host-kick boundary

## Purpose

Patch `0087` removes the forced-RCU notifier as one source of host-timed
translation-block exits, but QEMU's generic single-threaded TCG kick entry point
is shared by host work, main-loop notifications, stop requests, and device
control. Its upstream implementation calls `cpu_exit()` for every RR vCPU as
soon as the host request arrives. Under load, that arrival coordinate changes
where a pending guest interrupt becomes architecturally visible.

Patch `0088`, refined by patch `0090`, prevents generic host latency hints from
asynchronously choosing a guest instruction boundary in bounded Crucible sim
mode. State-free kicks take effect at the end of the current deterministic
translation block.
Already-committed stop, unplug, halted, stopped, and interrupt-request states,
plus an admitted exact terminal-pause request, retain an immediate exit request
for the shared RR execution thread. The first four cannot rely on further guest
retirement for progress; an interrupt request is already guest-visible modeled
state, and the admitted terminal pause is a deterministic observer action at a
proven instruction boundary.

## Admission and progress contract

`rr_kick_vcpu_thread` replaces the immediate all-vCPU `cpu_exit()` loop with a
soft all-vCPU exit request only when all three predicates hold:

1. the active accelerator is `sim`;
2. precise icount is active; and
3. `icount_crucible_rr_switch_quantum()` is nonzero.

Patch `0088` originally used a non-null `rr_current_cpu` as an execution
predicate. That pointer is published before `cpu_can_run()` is evaluated, so it
also describes startup and other non-executing RR-loop intervals. Patch `0090`
removes that approximation; wake liveness comes from the condition broadcast,
not from host-timed translation-block interruption.

Patch `0088` also used positive raw observed icount to distinguish startup from
execution. That value is not updated until TCG returns, so it remains zero for
the entire first active slice. Patch `0090` removes this proxy together with the
RR pointer approximation. Neither is needed because the soft request is safe
whether the RR thread is executing a block or waiting.

Every other configuration executes the upstream loop unchanged. In the guarded
configuration, a state-free kick atomically sets `exit_request` without setting
`icount_decr.high`. A running vCPU completes its current deterministic
translation block, then `cpu_exec` observes the request before starting the
next block. An idle or waiting RR thread is awakened by the condition broadcast
that `qemu_cpu_kick()` performs before invoking the accelerator hook. If an
exact terminal pause is pending, or any
vCPU is already stopping, unplugging, halted, stopped, or has a published
interrupt request, the guarded path calls `cpu_exit()` for every vCPU. All RR
vCPUs share one host execution thread, so a stateful transition targeting a
non-current vCPU must also return the current TCG slice. Native pause, shutdown,
hot-unplug, terminal observation, and interrupt wakeups thereby preserve their
established guest-visible semantics.

Before the first TCG entry, `qemu_cpu_kick()` broadcasts the halt condition that
starts the RR thread before invoking the accelerator hook. Until the RR thread
publishes completion of its initial stopped wait, the hook suppresses only the
asynchronous decrementer side effect; committed stop, unplug, halt,
terminal-pause, and interrupt state still forces an immediate exit. QEMU may
enter TCG while raw observed icount is still zero and QMP reports the machine
runstate as `shutdown`; neither is a reliable execution predicate. The
translation-block endpoint is deterministic for both single- and multi-vCPU
execution.

The host request's arrival time is not recorded and does not alter the RR
owner, cursor, translation-block endpoint, interrupt window, or architectural
execution. The condition-variable broadcast performed by `qemu_cpu_kick()` and
the soft request observed between translation blocks preserve wake and
scheduler progress. This
patch therefore neither drops work nor turns host timing into an architectural
source of truth.

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
6. Prove stock QEMU retains the immediate generic kick, configurations outside
   the three-part admission predicate retain that path, and bounded sim uses a
   soft request that does not write the asynchronous icount decrementer.
7. Rebuild every patch prefix and pass regeneration, ABI, license, inertness,
   and corresponding-source gates.

- **[QFP-KICK-1]** In bounded sim execution, generic host kicks MUST NOT
  asynchronously choose an instruction or interrupt-visibility coordinate;
  state-free requests take effect at deterministic translation-block ends.
- **[QFP-KICK-2]** Deferred host work MUST remain level triggered; an admitted
  exact terminal observation and committed control and interrupt state MUST
  retain an immediate exit request for the shared RR execution thread.
