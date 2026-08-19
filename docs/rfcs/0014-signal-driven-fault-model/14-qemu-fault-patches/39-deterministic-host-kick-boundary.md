# 0088 - Deterministic host-kick boundary

## Purpose

Patch `0087` removes the forced-RCU notifier as one source of host-timed
translation-block exits, but QEMU's generic single-threaded TCG kick entry point
is shared by host work, main-loop notifications, stop requests, and device
control. Its upstream implementation calls `cpu_exit()` for every RR vCPU as
soon as the host request arrives. Under load, that arrival coordinate changes
where a pending guest interrupt becomes architecturally visible.

Patch `0088` prevents generic host kicks from choosing a guest instruction
boundary in bounded Crucible sim mode. Pending host work remains level
triggered and is drained when the deterministic RR run returns to the BQL.

## Admission and progress contract

`rr_kick_vcpu_thread` skips the immediate all-vCPU `cpu_exit()` loop only when
all three predicates hold:

1. the active accelerator is `sim`;
2. precise icount is active; and
3. `icount_crucible_rr_switch_quantum()` is nonzero.

Every other configuration executes the upstream loop unchanged. In the guarded
configuration, the remaining serialized RR budget is finite and no larger than
the pinned quantum. Stop, unplug, queued vCPU work, QMP control, and main-loop
notifications therefore wait at most one deterministic vCPU budget before the
RR thread re-enters the BQL and services their level-triggered state.

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

The patch modifies `accel/tcg/tcg-accel-ops-rr.c`, preserving that file's MIT
license. It creates no QEMU source file and adds no process-boundary field,
callback, or shared-memory representation.

## Required gates

1. Run the production four-vCPU fingerprint workload twice through the exact
   3,700,000,000-instruction horizon.
2. Apply sustained host CPU contention only to the second run, causing host
   work and notification schedules to differ.
3. Require identical canonical all-vCPU registers, RAM, device state, RR
   cursor/switch events, and deterministic-IPI evidence at every sample.
4. Require QMP topology, terminal stop, and process teardown to complete within
   their existing bounds, proving deferred host work remains live.
5. Prove stock QEMU retains the immediate generic kick and that configurations
   outside the three-part admission predicate retain that path.
6. Rebuild every patch prefix and pass regeneration, ABI, license, inertness,
   and corresponding-source gates.

- **[QFP-KICK-1]** Generic host kicks MUST NOT choose translation-block or
  interrupt-visibility coordinates in bounded sim mode.
- **[QFP-KICK-2]** Deferred host work MUST remain level triggered and MUST be
  serviced no later than the next bounded RR scheduler return.
