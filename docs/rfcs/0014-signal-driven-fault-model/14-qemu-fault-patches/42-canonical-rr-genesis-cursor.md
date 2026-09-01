# 0091 - Canonical RR genesis cursor

## Purpose

Patch `0091` makes the formal round-robin cursor API total at the unique exact
genesis observation boundary. Before QEMU selects the first runnable vCPU, the
serialized RR cursor intentionally has no owner. Canonical fingerprint capture
still needs a concrete next scheduler coordinate, and at raw icount zero that
coordinate is uniquely vCPU 0 at position 0.

`qemu_plugin_rr_cursor()` reports that coordinate only when QEMU is inside its
exact deterministic plugin boundary, the serialized owner is invalid, raw
observed icount and cursor position are both zero, a nonzero pinned quantum is
active, and at least one vCPU exists. It does not write `TimersState` or select
a CPU. Every post-genesis invalid owner and every ordinary unowned plugin call
remains rejected.

## Canonicality contract

The returned coordinate describes the next deterministic scheduler position,
not a fabricated active owner. Raw zero alone is insufficient: exact-boundary
ownership and position zero are both mandatory. This keeps checkpoint
observation side-effect-free and prevents stale or malformed restored state
from being normalized into an apparently valid cursor.

The case is additive to patch `0089`. Live serialized-owner reads and exact
committed-cursor reads continue unchanged after the first vCPU selection.

## Files and license scope

The patch modifies MIT-licensed `include/qemu/qemu-plugin.h` and
`plugins/api.c`. It creates no QEMU file, changes no wire or shared-memory ABI,
and does not cross the Apache/GPL process boundary.

## Required gates

1. A fresh production live-world lifecycle must capture its genesis
   fingerprint and execute the selected network branch.
2. Branch decisions in the fresh lifecycle must match the production branch
   discovered before checkpoint.
3. Durable exact restore must reproduce the next complete quantum.
4. Patch microtests must pin exact-boundary, raw-zero, position-zero, and
   vCPU-zero behavior and prove that later invalid owners remain rejected.
5. Patch regeneration, ABI, license-boundary, inertness, and complete
   corresponding-source gates must pass.

- **[QFP-RR-GENESIS-1]** At exact raw-zero preselection, the formal RR cursor
  MUST report vCPU 0 at position 0 without mutating scheduler state.
- **[QFP-RR-GENESIS-2]** An invalid RR owner outside that unique boundary MUST
  remain an error.
