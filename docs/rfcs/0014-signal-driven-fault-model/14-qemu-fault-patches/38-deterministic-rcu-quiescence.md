# 0087 - Deterministic RCU quiescence

## Purpose

QEMU's single-threaded TCG loop registers a forced-RCU notifier that normally
calls `cpu_exit()` from a host thread. That is safe for ordinary emulation, but
the exact host instant of the kick can terminate a translation block at a
different guest instruction. If an architectural interrupt is pending, the
new translation-block boundary can change the instruction at which QEMU makes
that interrupt visible.

Patch `0087` makes forced RCU progress deterministic under `-accel sim`.
Ordinary accelerators keep the upstream kick. Sim mode instead relies on its
already bounded round-robin execution budget to leave the RCU read-side
critical section at the next deterministic scheduler boundary.

## Execution contract

The forced-RCU notifier has exactly two branches:

1. outside Crucible sim mode, call the existing `rr_kick_next_cpu()` path
   unchanged; and
2. in Crucible sim mode with precise icount, return without asynchronously
   changing `CPUState::exit_request` or the active translation-block budget.

This is not an unbounded RCU deferral. Sim mode requires a nonzero pinned
`rr_switch_quantum`, and `icount_percpu_budget()` caps the current vCPU run by
the remaining serialized quantum. The vCPU thread therefore reaches a natural
quiescent state after a finite, guest-coordinate-defined amount of work.

No timer, wall-clock duration, host thread identity, host CPU load, or RCU
callback arrival coordinate becomes modeled state. RCU changes memory
reclamation timing only; it does not select a new guest execution boundary.

## Interaction with interrupts and scheduling

Deferred inter-vCPU interrupts remain drained in their canonical FIFO order at
the existing RR scheduler points. A pending interrupt is observed according to
guest state and deterministic RR progress, never because a host RCU worker
happened to request a grace period. Serialized RR owner, cursor position, and
quantum accounting are unchanged.

The patch does not suppress guest interrupts, postpone a deterministic
preemption command, or modify the QEMU main-loop wake protocol. It removes only
the host-originated forced exit from sim execution.

## Files and license scope

The patch modifies `accel/tcg/tcg-accel-ops-rr.c`, preserving that file's MIT
license. It creates no QEMU source file, so `LICENSES.md` does not gain a row.
The change remains wholly inside the GPL-side QEMU process and adds no process
boundary field or callback.

## Required gates

1. Run the real four-vCPU QEMU fingerprint workload twice to the exact
   3,700,000,000-instruction horizon.
2. Apply sustained host CPU contention only to the second run.
3. Require byte-identical canonical sample, RR-switch, deterministic-IPI, RAM,
   device-state, and all-vCPU architectural-register evidence.
4. Require the guest to exercise real inter-vCPU interrupts and every vCPU to
   retire instructions.
5. Prove stock QEMU retains its ordinary forced-RCU kick and that the added
   branch is gated by Crucible sim mode.
6. Rebuild every QEMU patch prefix, regenerate the deterministic patch stack,
   and pass ABI, license-boundary, source-retention, and non-sim inertness
   gates.

- **[QFP-RCU-1]** Host-originated RCU progress MUST NOT choose a guest
  instruction boundary in sim mode.
- **[QFP-RCU-2]** Sim-mode RCU deferral MUST remain bounded by the nonzero
  deterministic RR quantum; ordinary QEMU execution MUST retain its existing
  forced-kick behavior.
