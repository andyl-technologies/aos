# Capability task 0094 — Retention virtual-time origin

## Purpose

Capability task `0094` keeps memory-retention duration arithmetic in one coordinate
domain. A node-boundary result is stamped in raw retired instructions, while a
retention interval is expressed in virtual nanoseconds. Treating the result's
instruction coordinate as the initial virtual timestamp lets QEMU's clock bias
make a positive interval due at the installation instruction.

The atomic patch initializes `last_exposure_tick` from QEMU's authoritative
picosecond virtual clock. The configured nanosecond interval is converted to
exact ticks before it is added to that origin, and the scheduler deadline clamp
reaches the exact virtual expiry.

## Canonicality contract

Retention installation samples virtual time once while QEMU holds the exact
node boundary. All initial and refreshed cell deadlines use that same clock
domain. Raw icount remains the event-order and evidence coordinate; it is not
reinterpreted as elapsed nanoseconds.

Under the patched `sim` clock, a one-nanosecond interval spans 1,000 ticks.
Each further retirement advances 50 ticks, so it takes 20 retirements to reach
that expiry without an authorized idle jump. The interval must not decay at
the installation instruction, even when the virtual clock carries a nonzero
bias.

## Files and license scope

The atomic patch modifies GPL-side `plugins/crucible-fault-node.c`. It changes no
shared-memory or control wire format and adds no QEMU file.

## Required gates

1. The complete live memory-access matrix must pass on x86_64 and AArch64.
2. The retention case must observe exactly one boundary event at the exact
   virtual deadline, after the installation instruction coordinate.
3. Atomic-patch source attribution, regeneration, pristine-QEMU negative, ABI,
   and license-boundary gates must pass.

- **[MEM-RET-TIME-1]** Retention exposure and expiry MUST use authoritative
  exact virtual ticks after converting the authored nanosecond interval.
- **[MEM-RET-TIME-2]** A positive retention interval MUST NOT expire at its
  installation instruction coordinate because of virtual-clock bias.
