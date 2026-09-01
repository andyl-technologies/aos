# 0100 - AArch64 memory exception vectors

## Purpose

Patch `0100` corrects the production admission check for AArch64 exceptions
attached to memory-access rules. QEMU identifies an instruction abort with
vector `2` and a data abort with vector `3`; the old check instead required
vectors `3` and `4`, respectively, before calling the architecture validator.
That made every architecturally valid memory exception impossible to prepare.

## Execution contract

A fetch-only rule may carry only instruction-abort vector `2`. A non-fetch
memory rule may carry only data-abort vector `3`. Mixed fetch and non-fetch
classes remain inadmissible, and the architecture-specific validator still
checks the syndrome, address, record, and maskability after this classification.

## Files and license scope

The patch modifies GPL-side `plugins/crucible-fault-node.c`. It changes no
shared-memory layout or control wire format and adds no QEMU file.

## Required gates

1. The focused AArch64 poison-exception and retry cases must prepare, commit,
   and deliver canonical evidence.
2. Invalid memory-exception combinations must continue to reject atomically.
3. The complete memory-access matrix, patch-prefix provenance, regeneration,
   ABI, and license-boundary gates must pass.

- **[MEM-A64-VECTOR-1]** AArch64 fetch and non-fetch memory exceptions MUST use
  instruction-abort vector `2` and data-abort vector `3`, respectively.
- **[MEM-A64-VECTOR-2]** Vector admission MUST precede architecture validation
  without weakening syndrome, address, or atomic rejection checks.
