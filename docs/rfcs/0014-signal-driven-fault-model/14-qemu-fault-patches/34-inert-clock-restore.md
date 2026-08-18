# Patch 0083: preserve inert clocks across restore

## Capability

An exact checkpoint restores device clocks as one transaction. While QEMU is
deserializing VMState, device callbacks use the native clock coordinate and
cannot observe either the pre-load Crucible state or a partially restored
state. After the successful outermost load completes, Crucible reprojects
device deadlines only when the restored clock source has an effective
transform or source-state fault. This keeps an empty fault plan observationally
inert across a fresh-process restore without weakening checkpoint
authentication or active clock-fault replay.

An effective source includes any source with a bound transform rule, a bound
source-state rule, a nonzero accumulated offset, nonidentity drift, a frozen
value, a non-healthy source state, or an in-progress synchronization. Those
sources continue through the existing deterministic rearm callback after their
authenticated clock state commits.

## Failure closed by this patch

QEMU device `post_load` callbacks and the aggregate Crucible fault section are
separate entries in the VMState stream. Their load order means a timer callback
can run after native device fields change but before the authenticated Crucible
clock state commits. Transforming at that point combines state from two
different executions. In the production two-node world, the CMOS RTC observed
that mixed coordinate and entered the clock subsystem's fail-closed terminal
state before the first restored quantum.

Skipping all restore-time clock maintenance would be incorrect. A source with
an effective transform must reproject its guest deadline into the restored
scheduler coordinate. In addition, the internal wander timer must always be
rearmed or deleted so same-process rollback cannot retain a pending transition
from state newer than the loaded checkpoint. The patch therefore defers both
operations until the entire outermost VMState load succeeds. A failed load
clears the transaction guard without rearming partially restored state.

HPET has an additional inert-state invariant. Native HPET timers do not advance
the Crucible arm sequence, so an empty-plan checkpoint legitimately omits the
optional Crucible HPET timer subsection even though QEMU's native timer remains
pending. After restore, HPET therefore requires its Crucible `armed` marker only
when a nonzero transform generation says that the deadline was fault-managed.
It still enters the terminal state if either that active marker is missing or
the authenticated timer-fire transition fails.

## QEMU changes

`migration/migration.c` brackets every entry into the central VMState
deserialization loop, including nested packaged streams. The clock subsystem
tracks that nesting depth and a transaction-wide failure latch. While the depth
is nonzero, `qemu_crucible_fault_clock_source_active()` returns false so device
`post_load` code uses native QEMU coordinates. The outermost successful exit
then calls `crucible_clock_rearm_source()` only for an effective transform and
calls `crucible_clock_wander_timer_rearm()` for every source. A nested or outer
failure suppresses both operations.

`hw/timer/hpet.c` distinguishes a native pending timer from a fault-managed
timer using the restored transform generation. A zero generation follows the
ordinary QEMU callback path; a nonzero generation requires the serialized arm
marker and the existing authenticated fire transition.

Live reads outside VMState loading continue to layer the subsystem-terminal
condition over the effective-transform predicate so they fail closed after a
clock error. Restore deliberately does not treat that terminal latch as a
transform requiring device reprojection: doing so would invoke every device
callback while handling the very state that made further clock calculations
invalid.

The change adds no process ABI, shared-memory field, VMState version, QAPI
command, or new QEMU file. It modifies existing QEMU-side migration, internal
header, and clock implementation files and does not change the
corresponding-source license inventory.

## Acceptance

The per-patch contract consumes the production live-network gate rather than a
mock timer. That gate boots two real x86 QEMU nodes, exchanges packets, captures
an exact checkpoint with an empty fault plan, cleanly terminates both original
processes, restores both nodes into fresh processes, and requires the first
restored quantum and the remaining exchange to complete deterministically. Its
failure path also remains bounded: a QEMU exit is reported as a typed node crash
rather than an unbounded scheduler wait.

The aggregate patch-series and regeneration gates additionally require the
isolated patch to apply at the recorded stack position, the signed patch-branch
commit and tree to match `_series.nix`, and the corresponding-source bundle to
regenerate byte-for-byte. Existing live guest-clock mutation gates remain the
positive control for active source rearming. The implementation task is
`T-QEMU-0083`.
