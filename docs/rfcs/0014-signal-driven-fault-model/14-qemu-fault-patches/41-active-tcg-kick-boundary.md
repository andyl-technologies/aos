# 0090 - Active TCG kick boundary

## Purpose

Patch `0090` makes the active-slice admission rule from patch `0088`
executable rather than inferential. The RR scheduler publishes
`rr_current_cpu` before checking whether that vCPU can run. A non-null pointer
therefore cannot distinguish guest execution from startup, stopped, or
between-slice scheduler work.

The patch introduces one process-local atomic boolean,
`rr_tcg_exec_active`. The RR thread sets it immediately before releasing the
big QEMU lock and entering `tcg_cpu_exec()` or `cpu_exec_step_atomic()`, then
clears it immediately after guest execution returns. No protocol, shared-memory
layout, VMState field, or migration representation changes.

## Determinism and liveness contract

`rr_kick_vcpu_thread()` may defer a state-free generic host kick only for a
multi-vCPU guest while all of the patch `0088` mode and raw-icount predicates
hold and `rr_tcg_exec_active` is true. The finite RR quantum remains the
deterministic return boundary. A single-vCPU guest has no alternate RR owner
for host timing to select and retains upstream kick behavior for liveness.

At startup, after TCG returns, during icount accounting, in exact-boundary
callbacks, and while the RR loop is parked or between slices, the flag is false.
Generic kicks in those intervals retain upstream `cpu_exit()` behavior. The
stateful stop, unplug, halt, terminal-pause, and interrupt exceptions from patch
`0088` remain unchanged and still force the shared RR thread out immediately.

## Files and license scope

The patch modifies only MIT-licensed
`accel/tcg/tcg-accel-ops-rr.c`. It creates no QEMU file and does not cross the
Apache/GPL process boundary.

## Required gates

1. The single-vCPU S1 workload must leave startup, reach the exact horizon,
   pause, checkpoint, and reproduce under host load.
2. The production multi-vCPU fingerprint must remain byte-identical under its
   host-load adversary.
3. The live network workload must retain deterministic delivery and
   acknowledgement coordinates.
4. Patch microtests must prove that both TCG entry paths bracket guest execution
   with the atomic flag and that the generic-kick predicate consumes the flag
   instead of `rr_current_cpu`.
5. Patch regeneration, ABI, license-boundary, inertness, and complete
   corresponding-source gates must pass.

- **[QFP-KICK-3]** Active TCG execution MUST be proven by an explicit
  process-local ownership flag; scheduler pointers published before runnable
  admission MUST NOT serve as execution proof.
