# 0101 - Canonical snapshot RR resume

## Purpose

Patch `0101` makes source execution resume from the same serialized RR
coordinate that a fresh process selects after loading the snapshot. Snapshot
creation drains and resumes QEMU internally; without an explicit one-shot
selection, the source RR loop can replace the serialized owner with its local
loop cursor and discard a nonzero intra-turn position.

## Continuation contract

After a successful deterministic snapshot, QEMU arms the existing serialized
owner selection whenever the pinned RR quantum is nonzero and the serialized
cursor is valid. The next RR selection consumes that state exactly once. The
operation does not modify the owner or cursor, and non-Crucible and non-RR
execution remain unchanged.

## Files and license scope

The patch modifies GPL-side `accel/tcg/icount-common.c`,
`include/system/cpu-timers.h`, and `migration/savevm.c`. It changes no
shared-memory or control wire format and adds no QEMU file.

## Required gates

1. Exact snapshot source continuation and both fresh-process restores must
   converge at the same canonical RR coordinate and guest-state fingerprint.
2. A nonzero intra-turn cursor must survive snapshot creation on the source.
3. Patch-prefix provenance, regeneration, ABI, and license-boundary gates must
   pass.

- **[QFP-SNAPSHOT-RR-1]** Successful snapshot creation MUST preserve the
  serialized RR owner and intra-turn cursor used by fresh-process restore.
- **[QFP-SNAPSHOT-RR-2]** Source continuation MUST consume the restored-owner
  selection exactly once and MUST NOT mutate serialized scheduler state while
  arming it.
