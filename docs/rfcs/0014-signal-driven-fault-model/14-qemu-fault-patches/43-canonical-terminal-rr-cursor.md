# 0092 - Canonical terminal RR cursor

## Purpose

Patch `0092` makes live RR cursor observation agree with the scheduler's
serialized state when an instruction retires exactly at the end of a quantum.
Before the scheduler accounts the returning translation block, a plugin can
observe the transient terminal position `rr_switch_quantum`. The serialized
cursor never retains that value: accounting advances ownership to the next
vCPU and resets its position to zero.

`qemu_plugin_rr_cursor()` therefore projects that transient live observation
onto the same next-vCPU, position-zero coordinate that scheduler accounting
will commit. The projection reads the existing CPU order and does not mutate
`TimersState`, select a CPU, or relax rejection of other out-of-range cursors.

## Canonicality contract

The projection is admitted only for the current serialized owner in a live
vCPU context, with a nonzero pinned quantum and an observed position exactly
equal to that quantum. Exact control boundaries continue to report their
already committed cursor. Genesis remains governed by patch `0091`.

This closes a boundary race in canonical execution fingerprints: instruction
and exception mutations can retire on the last instruction of a quantum
without receiving a spurious invalid-cursor result.

## Files and license scope

The patch modifies MIT-licensed `include/qemu/qemu-plugin.h` and
`plugins/api.c`. It creates no QEMU file, changes no wire or shared-memory ABI,
and does not cross the Apache/GPL process boundary.

## Required gates

1. The complete live instruction and exception mutation matrix must pass,
   including instruction completion on a terminal quantum coordinate.
2. Patch-prefix provenance, attribution, regeneration, and drop-one checks
   must cover patch `0092`.
3. ABI, license-boundary, inertness, and corresponding-source gates must pass.

- **[QFP-RR-TERMINAL-1]** A live terminal observation MUST report the next
  scheduler-owned vCPU at position zero without mutating scheduler state.
- **[QFP-RR-TERMINAL-2]** Every nonterminal out-of-range or unowned cursor MUST
  remain an error.
