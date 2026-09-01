# 0097 - Canonical memory retry identity

## Purpose

Patch `0097` removes the translation-block-local instruction ordinal from
memory retry identity. A faulted instruction can be retranslated with a
different local ordinal even though its architectural PC, memory target, and
page-walk coordinates are unchanged. Treating that local ordinal as semantic
identity resets the retry counter and breaks ordered retry evidence.

## Canonicality contract

Instruction-backed retries are identified independently of translation-block
shape. The internal checkpoint field remains present for layout compatibility
but new state always serializes it as zero, and lookup neither hashes nor
compares it. Older retained values therefore do not prevent an otherwise
identical retry from matching after restore.

Accesses without decoded instruction identity continue to use their observed
clock coordinate as the execution-episode discriminator.

## Files and license scope

The patch modifies GPL-side `plugins/crucible-fault-node.c`. It changes no
shared-memory or control wire format and adds no QEMU file.

## Required gates

1. The x86_64 and AArch64 page-table retry cases must publish error ordinal
   zero followed by applied ordinal one.
2. The complete memory-access matrix must remain green.
3. Checkpoint/restore, patch-prefix provenance, ABI, and license-boundary gates
   must pass.

- **[MEM-RETRY-ID-1]** Retry identity MUST NOT depend on a TB-local instruction
  ordinal.
- **[MEM-RETRY-ID-2]** The retained checkpoint field MUST serialize at
  canonical zero and MUST NOT participate in retry lookup.
