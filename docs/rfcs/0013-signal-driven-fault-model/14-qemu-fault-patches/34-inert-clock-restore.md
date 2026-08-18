# Patch 0083: preserve inert clocks across restore

## Capability

An exact checkpoint whose guest-clock fault state is inert restores the native
QEMU timer state recorded by each device. Crucible reprojects device deadlines
only when the restored clock source has an effective transform or source-state
fault. This keeps an empty fault plan observationally inert across a
fresh-process restore without weakening checkpoint authentication or active
clock-fault replay.

An effective source includes any source with a bound transform rule, a bound
source-state rule, a nonzero accumulated offset, nonidentity drift, a frozen
value, a non-healthy source state, or an in-progress synchronization. Those
sources continue through the existing deterministic rearm callback after their
authenticated clock state commits.

## Failure closed by this patch

QEMU device VMState loads timer deadlines before the aggregate Crucible fault
section commits. Patch 0068 nevertheless invoked every registered device rearm
callback, including callbacks for clock sources with no fault state. That
second reconstruction was unnecessary for an inert source and could observe a
transient restore coordinate while several timer devices were being committed.
In the production two-node world this caused the clock subsystem to enter its
terminal state before the first restored quantum; the CMOS RTC transform error
was the visible downstream failure.

Skipping all restore-time clock maintenance would be incorrect. A source with
an effective transform must reproject its guest deadline into the restored
scheduler coordinate. In addition, the internal wander timer must always be
rearmed or deleted so same-process rollback cannot retain a pending transition
from state newer than the loaded checkpoint. The patch therefore guards only
the device callback and leaves wander-timer maintenance unconditional.

## QEMU changes

`plugins/crucible-fault-clock.c` evaluates
`qemu_crucible_fault_clock_source_active()` for each fully restored source. It
calls `crucible_clock_rearm_source()` only for an active source, then calls
`crucible_clock_wander_timer_rearm()` for every source. The active predicate is
the same closed predicate used by live clock reads and mutations, so restore
does not introduce a second definition of fault activity.

The change adds no ABI, shared-memory field, VMState version, QAPI command, or
new QEMU file. It modifies an existing GPL-side implementation file and does
not change the corresponding-source license inventory.

## Acceptance

The per-patch contract consumes the production live-network gate rather than a
mock timer. That gate boots two real x86 QEMU nodes, exchanges packets, captures
an exact checkpoint with an empty fault plan, cleanly terminates both original
processes, restores both nodes into fresh processes, and requires the first
restored quantum and the remaining exchange to complete deterministically.

The aggregate patch-series and regeneration gates additionally require the
isolated patch to apply at the recorded stack position, the signed patch-branch
commit and tree to match `_series.nix`, and the corresponding-source bundle to
regenerate byte-for-byte. Existing live guest-clock mutation gates remain the
positive control for active source rearming. The implementation task is
`T-QEMU-0083`.
