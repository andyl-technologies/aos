# Patch 0110: release halted partial RR turns

Patch `0110-crucible-release-halted-rr-turn.patch` closes a scheduler-progress
regression introduced by preserving a serialized RR cursor across partial
turns.

## Problem

A guest can execute `HLT` before consuming the configured RR switch quantum.
The serialized cursor correctly retains the unused part of that vCPU's turn.
When no other vCPU is runnable, however, the RR selector returns the same
halted cursor owner. Treating that return as ordinary partial-turn execution
re-enters `tcg_cpu_exec()` indefinitely at one icount and prevents the existing
all-vCPU-idle callback from running.

The same cursor retention can starve a runnable peer at a guest-authored
`PAUSE`. SeaBIOS exposes this during SMP bring-up: the boot CPU releases its
AP-startup lock and executes `PAUSE`, but retaining that boot CPU's partial turn
lets it reacquire the lock before an application processor can run. QEMU reports
`PAUSE` as `EXCP_INTERRUPT`, so it must be distinguished from a host kick before
committing the deterministic early handoff.

## Contract

The selector still gets the first opportunity to hand the partial turn to a
different runnable vCPU. If it returns the same owner and that vCPU is halted
without pending work, the RR execution loop exits to its normal idle path. The
cursor remains serialized at its nonzero position; leaving the execution loop
does not consume or reset it.

The x86 `PAUSE` helper marks its own TCG exit in transient private `CPUState`.
The RR loop consumes and clears that marker immediately after `tcg_cpu_exec()`
returns, before any control callback or checkpoint boundary. Generic
`EXCP_INTERRUPT` exits therefore cannot masquerade as a guest yield, and the
marker is never VMState.

In multi-vCPU precise sim mode, a marked `PAUSE` return with no asynchronous
exit request, stop, unplug, or queued CPU work is a guest-authored scheduler
yield. When ordinary instruction accounting has not already completed the
turn, QEMU advances the serialized owner to the next vCPU and resets the cursor
to zero. A yield coincident with full-quantum completion is already represented
by ordinary accounting and is not applied twice. Single-vCPU execution retains
its prior cursor because no peer can be starved.

The corresponding exact completed-turn handoff is also a safe register-capture
boundary after the serialized owner advances. Single-threaded RR excludes
concurrent vCPU execution, the committed cursor must be zero at the next owner,
and `current_cpu` must still name the vCPU whose turn just finished. All other
owner-mismatch contexts remain rejected.

Runnable partial turns continue immediately with a newly clamped budget.
Ordinary accelerators never enter this sim-only RR branch.

## Evidence

The one-vCPU and four-vCPU diskless quantum guests finish boot with `HLT` at a
nonzero RR cursor position. The live gates require the real patched QEMU and
plugin to publish an all-halted boundary, advance to the exact PIT deadline,
and reproduce the result under bounded scheduler preemption. The patch
micro-test also requires the halted-owner escape to precede partial-turn
continuation, requires `PAUSE` to set a dedicated marker that is consumed and
cleared immediately on return, and requires the guest-yield branch to exclude
unmarked interrupts, single-vCPU, host-kick, and already-completed-turn cases.
The four-vCPU guest emits the exact output-only sequence `AAABPPPR`. Each AP
publishes `A` before the BSP releases it with `B`, then publishes `P` only after
that release; the BSP emits `R` only after all three post-release publications.
The BSP and AP wait loops execute `PAUSE`, so the final all-halted boundary is
unreachable unless the helper-marked zero-instruction RR turn hands off to the
next vCPU. INIT/SIPI delivery or an unrelated interrupt cannot false-green this
evidence.
