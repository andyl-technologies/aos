# 0094 - Retention virtual-time origin

## Purpose

Patch `0094` keeps memory-retention duration arithmetic in one coordinate
domain. A node-boundary result is stamped in raw retired instructions, while a
retention interval is expressed in virtual nanoseconds. Treating the result's
instruction coordinate as the initial virtual timestamp lets QEMU's clock bias
make a positive interval due at the installation instruction.

The patch initializes `last_exposure_ns` from QEMU's authoritative virtual
clock. The configured nanosecond interval is then added to a nanosecond origin,
and the existing scheduler deadline clamp reaches that exact virtual expiry.

## Canonicality contract

Retention installation samples virtual time once while QEMU holds the exact
node boundary. All initial and refreshed cell deadlines use that same clock
domain. Raw icount remains the event-order and evidence coordinate; it is not
reinterpreted as elapsed nanoseconds.

With precise icount at shift zero, a one-nanosecond interval expires after one
additional retired instruction even when the virtual clock carries a nonzero
bias. It must not decay at the installation instruction.

## Files and license scope

The patch modifies GPL-side `plugins/crucible-fault-node.c`. It changes no
shared-memory or control wire format and adds no QEMU file.

## Required gates

1. The complete live memory-access matrix must pass on x86_64 and AArch64.
2. The retention case must observe exactly one boundary event at the exact
   virtual deadline, after the installation instruction coordinate.
3. Patch-prefix provenance, attribution, regeneration, drop-one, ABI, and
   license-boundary gates must pass.

- **[MEM-RET-TIME-1]** Retention exposure and expiry MUST use authoritative
  virtual nanoseconds end to end.
- **[MEM-RET-TIME-2]** A positive retention interval MUST NOT expire at its
  installation instruction coordinate because of virtual-clock bias.
