# 0096 - Physical page-table region fixture

## Purpose

Patch `0096` makes the live persistent-region page-table scenario target the
descriptor's guest physical address. Page-table mutation opportunities carry
the initiating guest virtual address and descriptor GPA as distinct
coordinates. Declaring the descriptor address as virtual therefore indexes the
wrong coordinate and leaves the intended persistent fault unmatched.

Ordinary failed-region, retention, rowhammer, and invalid-geometry scenarios
continue to target guest virtual memory. Only the page-table descriptor region
uses physical targeting.

## Evidence contract

The live failed-region walk must match the descriptor GPA, emit exactly one
canonical error event, and produce the architecture-defined guest-visible
fault result. The fixture may not substitute the initiating virtual address for
descriptor storage identity.

## Files and license scope

The patch modifies GPL-side
`tests/tcg/plugins/crucible-memory-access.c`. It changes no production QEMU
code, shared-memory layout, or control wire format and adds no QEMU file.

## Required gates

1. The x86_64 and AArch64 failed-region page-table cases must pass alone.
2. The complete memory-access matrix must remain green.
3. Patch-prefix provenance, attribution, regeneration, drop-one, ABI, and
   license-boundary gates must pass.

- **[MEM-PTE-REGION-1]** Persistent page-table descriptor regions MUST be
  matched by descriptor GPA.
- **[MEM-PTE-REGION-2]** Ordinary guest-memory region fixtures MUST retain
  their declared GVA semantics.
