# 0099 - Valid AArch64 abort fixture

## Purpose

Patch `0099` gives the live AArch64 poison-exception and retry scenarios a valid
same-EL data-abort syndrome. The production exception validator rejects a zero
syndrome because it does not identify a data-abort exception class, so the old
fixtures stopped at command preparation and never exercised delivery.

The fixture now uses vector `3`, QEMU's AArch64 data-abort vector, with syndrome
`0x96000000`: the AArch64 same-EL data-abort exception class with the
instruction-length bit set and no invalid implementation-defined fields. Its
fault address remains the selected guest memory address.

## Evidence contract

Preparation and commit must each return canonical evidence before the selected
load reaches QEMU's production poison-exception path. The immediate scenario
must publish the architecture-defined `0xe1` result exactly once, and the retry
scenario must resume and complete after its one authorized abort.

## Files and license scope

The patch modifies GPL-side
`tests/tcg/plugins/crucible-memory-access.c`. It changes no production QEMU
code, shared-memory layout, or control wire format and adds no QEMU file.

## Required gates

1. The focused AArch64 poison-exception and retry live cases must pass.
2. The complete x86_64 and AArch64 memory-access matrix must remain green.
3. Patch-prefix provenance, regeneration, ABI, and license-boundary gates must
   pass.

- **[MEM-A64-EXC-1]** A live AArch64 data-abort fixture MUST use the data-abort
  vector and a syndrome accepted by the production architecture validator.
- **[MEM-A64-EXC-2]** The fixtures MUST prove guest-visible delivery and retry
  rather than treating preparation rejection as execution evidence.
