# Capability task 0097 — Canonical memory retry identity

## Purpose

Capability task `0097` removes the translation-block-local instruction ordinal
from the memory retry key and its checkpoint encoding. A faulted instruction
can be retranslated with a different local ordinal even though its
architectural PC, memory target, and page-walk coordinates are unchanged.
Treating that local ordinal as semantic identity resets the retry counter and
breaks ordered retry evidence.

## Canonicality contract

Instruction-backed retries are identified independently of translation-block
shape. Their retry key and checkpoint record omit the TB-local instruction
ordinal. The live memory transaction and its evidence retain the ordinal as an
observed instruction coordinate, but retry lookup does not hash or compare it.

Accesses without decoded instruction identity continue to use their observed
clock coordinate as the execution-episode discriminator.

## Files and license scope

The atomic patch modifies GPL-side `plugins/crucible-fault-node.c`. It changes no
shared-memory or control wire format and adds no QEMU file.

## Required gates

1. The x86_64 and AArch64 page-table retry cases must publish error ordinal
   zero followed by applied ordinal one.
2. The complete memory-access matrix must remain green.
3. Checkpoint/restore, atomic-patch source attribution and regeneration,
   pristine-QEMU negative, ABI, and license-boundary gates must pass.

- **[MEM-RETRY-ID-1]** Retry identity MUST NOT depend on a TB-local instruction
  ordinal.
- **[MEM-RETRY-ID-2]** The retry key and checkpoint record MUST omit the
  TB-local instruction ordinal while the live transaction and evidence retain
  it.
