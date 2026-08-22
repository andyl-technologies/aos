# 0106 - Defer state-free host wakes in multi-vCPU bounded TCG

## Purpose

Patch `0106` closes the host-arrival race left by patch `0090`. A soft
`exit_request` avoids QEMU's asynchronous decrementer, but the host can still
choose which translation block observes that request. Under adversarial CPU
load, that changed the four-vCPU RR allocation and every later architectural
fingerprint component.

In multi-vCPU mode, an atomic idle/active/pending handshake owns state-free
host wakes without modifying any `CPUState`. Active covers the entire partial
RR turn, not one translation block: a wake remains pending across adjacent TCG
slices until the RR thread reaches a complete pinned handoff, an authorized
scheduler ceiling, or a guest halt/idle boundary. An idle-to-pending compare-
exchange also closes the interval immediately before the next slice starts.
The handshake therefore never turns an arbitrary between-block gap into a
host-selected service point and never drops a wake. In single-vCPU mode, patch
`0090`'s soft between-block request remains available because there is no
alternate RR allocation to perturb and bounded main-loop service is required
for startup and device liveness.

## Determinism and liveness contract

The terminal-pause request publishes its level-triggered pending state before
issuing an explicit vCPU kick. Admitted terminal pause, committed stop, unplug,
halted, stopped, and interrupt state therefore still call `cpu_exit()` for
every vCPU. Initialization remains live through the existing
condition-variable broadcast. A state-free kick in single-vCPU execution
publishes the soft request. Multi-vCPU execution latches the request across an
active slice and services it at the next canonical handoff, authorized ceiling,
or idle boundary. Stateful exits and the initial boot wait clear the process-
private handshake. An idle-to-pending claimant also publishes an exit request:
the atomic claim prevents TCG from starting, while the exit request closes the
condition broadcast-before-wait window. No host timeout or arrival order
chooses an instruction boundary.

## Files and license scope

The patch modifies MIT-licensed `accel/tcg/tcg-accel-ops-rr.c` and
GPL-2.0-or-later `plugins/api.c`. It creates no QEMU file and does not cross the
Apache/GPL process boundary.

## Required gates

1. The production four-vCPU fingerprint streams are byte-identical when the
   second run executes under bounded scheduler preemption.
2. S1 reaches its exact horizon and preserves checkpoint/replay liveness.
3. Production live networking retains exact delivery and acknowledgement
   coordinates.
4. Structural microtests require the single-vCPU-only soft request, the atomic
   idle/active/pending handshake, and consumption only at full RR handoff, scheduler-ceiling,
   idle-service, stateful-exit, and initial-boot boundaries.
5. Patch regeneration, ABI, licensing, inertness, and corresponding-source
   gates pass.

- **[QFP-KICK-4]** State-free host wake arrival MUST NOT choose a translation
  block endpoint or subsequent RR allocation within a finite multi-vCPU sim RR
  slice, including the race between adjacent slices. Single-vCPU execution MUST
  retain bounded main-loop liveness without changing the asynchronous icount
  decrementer.
