# 0107 - Anchor the RR cursor at guest genesis

## Purpose

Patch `0107` makes the serialized round-robin cursor authoritative before the
first execution budget. Previously, the cursor was initialized lazily when the
RR loop selected or accounted its first vCPU. Host-driven startup work could
therefore move aggregate icount before position zero was established, causing
identical fresh processes to report different intra-turn positions at the same
later aggregate icount.

The loop-local CPU iterator could also restart after servicing host control
work and suggest a different vCPU during a partial turn. The old fallback
treated that suggestion as authority and reset the serialized cursor, allowing
host service timing to discard a deterministic prefix of the current turn.

## Determinism and restore contract

After QEMU's initial stopped wait completes and before the first per-vCPU budget
is calculated, the RR thread initializes the fresh sim guest to vCPU 0 at
position 0. The raw instruction count must still be zero. Initialization is
idempotent: incoming VMState that already carries a valid cursor is never
overwritten, so restored owner and intra-turn position remain authoritative.
During execution, a valid serialized owner overrides a mismatching loop-local
suggestion. Only a guest halt or completed quantum performs the canonical
handoff to the next runnable vCPU. Both outer-loop restarts and inner-loop
`CPU_NEXT` transitions pass through that selector. Accounting rejects an owner
mismatch instead of silently resetting the cursor, and each repeated partial
turn returns directly to the outer timer/budget loop without publishing an idle
RR state. The next slice therefore retains both the serialized owner and the
active-slice host-wake guard, including when a partial turn belongs to the last
CPU in the loop-local list. Live plugin observation accepts the terminal
instruction's projected next-owner coordinate so a completed turn emits the
canonical RR-switch event instead of temporarily invalidating observation. A
same-CPU selection is classified as partial only while the serialized position
is nonzero; a completed single-vCPU wrap reaches the ordinary control-service
boundary instead of starving host completion work.

This patch changes scheduler state rather than merely projecting an observation.
Patch `0091` continues to define the exact raw-zero observation returned before
the RR thread owns the cursor.

## Files and license scope

The patch modifies MIT-licensed `accel/tcg/icount-common.c`,
`accel/tcg/tcg-accel-ops-rr.c`, `include/system/cpu-timers.h`, and
`plugins/api.c`. It creates no QEMU file and does not cross the Apache/GPL
process boundary.

## Required gates

1. Independent exact-snapshot builds produce byte-identical capture and suffix
   fingerprints at a fixed aggregate icount with a nonzero intra-turn cursor.
2. Fresh execution starts from vCPU 0 at position 0, while loaded VMState keeps
   its serialized cursor.
3. Structural microtests require initialization before the first RR budget,
   the raw-zero assertion, serialized-owner authority across inner and outer
   partial-turn transitions, and fail-loud accounting mismatch detection.
4. N-vCPU fingerprint, patch regeneration, ABI, licensing, inertness, and
   corresponding-source gates pass.

- **[QFP-RR-5]** A fresh bounded sim RR schedule MUST establish its serialized
  owner and intra-turn position at aggregate guest icount zero, before any
  execution budget is computed. Restore MUST NOT replace a valid loaded cursor.
  A loop-local CPU suggestion MUST NOT replace that owner during a partial turn;
  only a canonical quantum completion or guest halt may hand off ownership.
