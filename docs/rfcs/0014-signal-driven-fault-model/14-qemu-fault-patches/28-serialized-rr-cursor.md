# Patch 0077: authoritative serialized round-robin cursor

## Responsibility

`0077-crucible-serialize-rr-cursor.patch` makes the deterministic
single-threaded TCG scheduler's inter-vCPU position explicit state. The cursor
contains the selected vCPU and the number of retired instructions within its
pinned `rr_switch_quantum`. It is the cursor exported to the fingerprint plugin
and the cursor restored with VMState.

This position is QEMU's authoritative precise-icount value, not the trace
plugin's per-vCPU instruction-callback counter. Both streams are deterministic
and are fingerprinted, but exception and assist execution may advance precise
icount before the observation plugin receives the same number of callbacks on a
newly runnable vCPU. Import therefore validates the cursor against its own
closed domain (`current_vcpu < vcpu_count` and `position < quantum`) and does
not compare it numerically with `register_retired`.

The earlier introspection helper derived its answer from `current_cpu` and the
temporary budget of one `tcg_cpu_exec` call. That representation is unavailable
while a freshly restored VM is stopped and resets at every host scheduler
ceiling, so it cannot describe checkpoint continuation state.

## State transitions

- The first runnable vCPU initializes `(current_vcpu, position) = (cpu, 0)`.
- Retired instructions advance `position` after icount accounting and before
  the exact-boundary plugin callback publishes a fingerprint.
- Each CPU budget is clamped to
  `rr_switch_quantum - position`; host ceilings may split a turn but cannot
  restart or overrun it.
- Reaching the quantum selects the next vCPU in ascending QEMU CPU-list order,
  wraps at the end, resets `position` to zero, and makes that selection
  authoritative for the next RR-loop iteration.
- A scheduler-authorized early switch, halted-vCPU skip, or service-control
  transition selects the actual next vCPU and starts its new turn at zero.
- A restored or rotated pending selection remains authoritative across
  zero-instruction control boundaries. It is consumed only when that vCPU
  actually retires an instruction; if the selected vCPU is halted, observing
  the following CPU is the explicit deterministic skip that starts a new turn.
- The plugin read is side-effect-free and remains valid while QEMU is stopped;
  it never consults the thread-local `current_cpu` pointer.

## VMState contract

The cursor is required state in version 2 of QEMU's `timer/icount` VMState
section. Version 1 state is intentionally rejected rather than accepted through
a compatibility path. When a nonzero Crucible RR quantum is configured, load
rejects a missing or invalid selected vCPU and a position at or beyond the
quantum. A successful load marks the serialized selection for
the RR thread to consume before any guest instruction can execute. The
subsection is included in QEMU's non-RAM VMState schema and device-state digest,
so incompatible state fails the checkpoint fingerprint rather than silently
restarting at vCPU zero.

## Verification

Patch microtests must prove partial turns survive multiple host ceilings,
quantum completion rotates exactly once, and invalid/missing cursor VMState is
rejected. The live gate uses at least two vCPUs, checkpoints at a nonzero
intra-turn position, destroys QEMU, restores into a fresh process, and requires
the same cursor plus identical all-vCPU register, RAM, device-state, and schema
digests before continuation. A negative control that resets the nonzero
intra-turn position to zero recomputes the black-box fingerprint and must be
rejected by the same production fingerprint admission used during fault-runtime
restore.

## Boundary and licensing

The cursor and its VMState subsection are QEMU scheduler implementation and
remain in the applicable GPL scope. Only fixed-width cursor values cross the
versioned plugin/shared-memory boundary; no QEMU pointer or private structure
does. The patch commit requires the QEMU-series DCO sign-off and is included in
the retained corresponding-source bundle.
