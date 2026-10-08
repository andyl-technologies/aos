# Capability task 0081: deferred-result evidence validation

## Purpose

The atomic patch `crucible-qemu-11.1.1.patch` keeps the live instruction
fault matrix aligned with the canonical deferred-result contract completed by
capability task 0074. A deferred `APPLY` completion carries the same typed node-result
evidence as a synchronous completion; it is not an empty intermediate result.

The atomic patch changes only QEMU's GPL-side live test plugin. It does not add a new
runtime API, compatibility path, or fault behavior.

## Required change

For every deferred instruction mutation completion, the live plugin must:

1. require a complete `CRUCIBLE_NODE_FAULT_EVIDENCE_V1_BYTES` payload;
2. validate the evidence magic, version, command kind, `APPLY` operation,
   target kind, model phase, and generation;
3. bind the evidence request digest to the command payload that produced the
   completion, including the second payload in a composed two-command case;
4. hash the complete evidence and compare it with the result's
   `evidence_hash`; and
5. retain the existing status and icount checks for applied and fail-closed
   completions.

The obsolete assertion that deferred results have empty evidence must be
removed. Empty deferred evidence would discard the authenticated command-result
binding required for exact replay and is therefore a test failure.

## Verification

`checks.crucible.phase2.gates.patchMicrotests` validates the capability source evidence
and runs the complete live instruction-fault matrix against patched QEMU. The
stock-QEMU and non-`sim` negative controls remain part of that matrix. Exact
atomic-patch regeneration additionally proves that the atomic patch is the DCO-signed
commit in the pinned QEMU bundle.

## License boundary

The modified `tests/tcg/plugins/crucible-instruction.c` file remains
GPL-2.0-or-later. No process-boundary layout or Apache-side dependency changes.
