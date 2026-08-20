# 0090 - Deterministic TCG kick boundary

## Purpose

Patch `0090` replaces the active-slice inference from patch `0088` with a
boundary-safe exit primitive. The RR scheduler publishes `rr_current_cpu`
before checking whether that vCPU can run, so a non-null pointer cannot
distinguish guest execution from startup, stopped, or between-slice scheduler
work.

For a state-free kick in bounded sim mode, the patch atomically sets each RR
vCPU's `exit_request` without setting `icount_decr.high`. If TCG is executing,
the current translation block completes at its deterministic endpoint and
`cpu_exec` observes the request before another block starts. If the RR thread
is idle, `qemu_cpu_kick()` has already broadcast its halt condition. No
protocol, shared-memory layout, VMState field, or migration representation
changes.

Patch [`0106`](57-defer-active-slice-host-wakes.md) subsequently tightens this
mechanism: the production multi-vCPU adversary demonstrated that even the soft
request could let host arrival choose which translation block ended a slice.
The soft request remains the between-slice liveness mechanism. Multi-vCPU
active TCG execution defers state-free wakes to the finite RR boundary, while
single-vCPU active execution retains the soft request for bounded main-loop
service because no alternate RR allocation can be perturbed.

The patch also publishes the process-local `rr_initial_wait_complete` flag
immediately after leaving the RR thread's initial stopped wait. Before that
point, `qemu_cpu_kick()` has already broadcast the condition needed for
startup, so the initialization-time `stopped` bit is not misclassified as a
committed lifecycle transition. Committed control state still receives an
immediate exit.

## Determinism and liveness contract

`rr_kick_vcpu_thread()` supplies the soft request outside active TCG execution
while all of the patch `0088` mode predicates hold. Immediate `cpu_exit()`
remains mandatory for
an admitted terminal pause and committed stop, unplug, halted, stopped, or
interrupt state. Host arrival changes neither the current translation-block
endpoint nor the architectural coordinate within that block.

QEMU may begin TCG execution while QMP still reports the machine runstate as
`shutdown`, and raw observed icount remains zero until the first slice returns.
Neither value is execution proof or part of the admission predicate. The soft
request is safe before execution, between blocks, during accounting, in exact
callbacks, and while the RR loop is parked because the condition broadcast
provides wake liveness. The stateful stop, terminal-pause, and interrupt
exceptions from patch `0088` remain unchanged and still force the shared RR
thread out immediately.

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
4. Patch microtests must prove that the state-free path publishes an atomic
   `exit_request` without writing `icount_decr.high`, does not use
   `rr_current_cpu`, raw icount, runstate, or a deferred host latch, and that
   the initial wait publishes its completion.
5. Patch regeneration, ABI, license-boundary, inertness, and complete
   corresponding-source gates must pass.

- **[QFP-KICK-3]** State-free generic kicks MUST be observed at deterministic
  translation-block boundaries without requiring an execution-ownership proxy;
  scheduler pointers, runstate, and pre-return raw icount MUST NOT serve as
  execution proof.
