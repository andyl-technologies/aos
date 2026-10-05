# Capability task 0110 — Bound RR spin and release halted turns

The atomic QEMU patch keeps a serialized RR owner across partial turns while
allowing an all-halted guest to reach its idle deadline. For precise `sim`, x86
`PAUSE` is a counted processor hint: it does not itself end a translation block
or transfer the RR owner.

## Problem

A vCPU can execute `HLT` before consuming its RR quantum. If it is the last
runnable vCPU, re-entering its retained partial turn at the same instruction
count prevents the all-vCPU-idle callback and its timer advance. Separately,
turning every guest `PAUSE` into a host-side TB exit makes a spin loop return
to the RR scheduler every few instructions even when every peer is halted.

## Contract

The selector first gives another runnable vCPU its turn. If the selected owner
is halted with no pending work and no peer can run, the RR execution loop
returns to its normal idle path without consuming or resetting the serialized
partial cursor. The all-halted callback can then advance to the earliest armed
virtual deadline.

In `sim`, x86 `PAUSE` remains one decoded and retired guest instruction. Its
ordinary SVM intercept, single-step, plugin instruction markers, and icount
accounting still apply. It does not establish a special zero-instruction
handoff. The existing RR quantum bounds how long a runnable peer waits; exact
virtual timer, campaign dispatch, fault, and preemption budgets can stop the
owner sooner. Ordinary QEMU accelerators retain the upstream PAUSE helper and
its normal TB exit.

A guest-authored cross-vCPU APIC IPI is queued with its source sequence and
routing generation, then requests the source vCPU to leave translated
execution at the next TB boundary. The RR loop drains the queue before
selecting another vCPU. Requesting an exit does not abort the APIC MMIO/MSR
instruction after it has staged the IPI. IPI delivery and peer eligibility
must not depend on host signal timing.

An exhausted quantum still advances the serialized owner and publishes the
usual RR handoff callback. HLT, reset, plugin stop, and exact control
boundaries retain their independent checks; no PAUSE-specific transient marker
or control fence remains.

## Evidence required

The four-vCPU S11 contention guest executes `PAUSE` in its lock-spin loop and
must reproduce the same aggregate fingerprint, per-vCPU trace, and RR cursor
on repeated runs of one build. The live `qemuPauseIpiLive` gate starts an AP
through directed INIT/SIPI, records each SIPI MMIO write and AP entry at raw
icount, bounds the first IPI-to-AP interval, and proves that both vCPUs execute
`PAUSE` before the BSP reaches HLT and the RR loop observes all-vCPU idle. Its
complete event and serial streams must match across two launches of the same
build. The existing S2 LAPIC companion covers exact virtual timer advancement
and interrupt delivery. Exact-checkpoint, control-boundary, and replay gates
must agree within that build. A one-instruction handoff between PAUSE and the
next guest instruction is not a release requirement.
