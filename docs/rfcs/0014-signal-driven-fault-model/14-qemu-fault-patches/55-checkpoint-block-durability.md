# 0104 - Checkpoint block durability preservation

## Purpose

Patch `0104` prevents QEMU's synthetic native-stop flush from changing the
storage state selected for an exact checkpoint. QEMU normally calls
`bdrv_flush_all()` while entering paused state. For the Crucible shared-memory
backend, that operation would submit a new production flush after the host had
proved the transport quiescent, deadlock the stop handshake waiting for host
service, and incorrectly force volatile cache state toward durable media.

## Durability contract

The Crucible block backend treats its flush callback as already complete only
while an exact Crucible VM stop is pending. The paired Apache checkpoint retains
the accepted cache, controller, media, and fault continuations as canonical
state. Guest-issued flushes and ordinary QEMU stop paths continue through the
real shared-memory request and response transport.

## Files and license scope

The patch modifies GPL-side `block/crucible-shmem.c`. It changes no
shared-memory or control wire format and adds no QEMU file.

## Required gates

1. The pending-durability exact snapshot scenario must stop without a synthetic
   block request and restore the same Apache storage continuation twice.
2. Ordinary guest flush and block fault matrices must retain their production
   request behavior.
3. Patch-prefix provenance, regeneration, ABI, and license-boundary gates must
   pass.

- **[QFP-CHECKPOINT-DURABILITY-1]** Native exact stop MUST NOT flush or otherwise
  mutate checkpointed Crucible durability state.
- **[QFP-CHECKPOINT-DURABILITY-2]** Suppression MUST require a pending exact
  Crucible VM stop and MUST NOT affect guest or ordinary QEMU flushes.
