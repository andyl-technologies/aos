# Patch 0079: stopped-state control progress

## Responsibility

`0079-crucible-stopped-state-control-progress.patch` closes the last lost-wake
window in QEMU's serialized round-robin thread while an exact Crucible
checkpoint or restore holds the VM in the native paused runstate. Guest
instructions must remain stopped, but queued host control work must still be
drained so QEMU can acknowledge `CPUState::stop`, publish the requested exact
state, and complete the QMP stop or restore transaction.

This patch does not add a polling execution mode. It hardens the existing
native-stop parking loop whose only entry condition is an authenticated exact
boundary request under precise-icount `-accel sim`.

## Lost-wake model

The RR thread services `qemu_wait_io_event_common()` for every vCPU before it
parks. Two producers can race with the subsequent condition wait:

1. the main loop can set `CPUState::stop` or `CPUState::unplug`; and
2. a non-BQL producer can enqueue vCPU work needed by the stop or restore
   handshake.

A condition variable signal is only a latency hint. If either producer signals
between the drain and the sleep, an unconditional wait can consume no further
wake and leave QEMU paused forever. The patch makes readiness level-triggered:

- `rr_crucible_sim_stop_or_unplug_pending()` detects pending lifecycle work;
- `rr_crucible_sim_vcpu_work_pending()` scans every vCPU work list; and
- the RR thread sleeps only while the exact VM-stop request remains pending and
  both readiness predicates are false.

The final wait is `qemu_cond_timedwait_bql(first_cpu->halt_cond, 1)`. The
one-millisecond host timeout cannot advance guest virtual time, choose a guest
schedule, or make a fault decision. It only bounds how long the stopped host
control loop can miss a racing non-BQL enqueue. After every return, the loop
drains all vCPU work and re-evaluates the level-triggered predicates under the
BQL.

## Ordering and safety invariants

- Guest execution remains disabled for the entire parking loop.
- The RR thread never calls a guest TCG execution path to make control progress.
- Stop/unplug and queued-work predicates are checked while the BQL is held.
- Work is drained before sleeping and again after every signal or timeout.
- A pending stop/unplug request prevents sleep and is acknowledged through
  QEMU's normal `qemu_wait_io_event_common()` path.
- A queued work item prevents sleep even if its condition signal raced with the
  preceding check.
- The bounded wait is not part of canonical evidence and cannot change the
  fingerprint, RR cursor, event log, or replay choice stream.

## Verification

The focused patch microtest requires the stop/unplug recheck, all-vCPU queued-
work scan, and bounded BQL wait in the isolated patch, while pristine QEMU must
contain none of them. Reverting only patch 0079 therefore makes its microtest
red.

The live exact-snapshot gate supplies the integration proof. It stops a running
multi-vCPU guest at a nonzero RR position, captures exact state, destroys the
old process, starts a fresh QEMU process, restores while guest execution remains
paused, and requires the restored fingerprint plus replay suffix to match. That
path exercises the control-boundary callback and native stop handshake that
would hang if the queued-work wake were lost.

Non-sim and unarmed executions never enter the Crucible VM-stop parking loop;
their upstream wait behavior is byte-for-byte unchanged by this patch.

## Boundary and licensing

The change modifies only QEMU's GPL-side RR scheduler source and introduces no
file or ABI. No QEMU object, callback, or host condition crosses the process
boundary. The Apache host observes only the existing authenticated checkpoint
and restore results. The patch is retained as a separate DCO-signed commit in
the corresponding-source bundle.
