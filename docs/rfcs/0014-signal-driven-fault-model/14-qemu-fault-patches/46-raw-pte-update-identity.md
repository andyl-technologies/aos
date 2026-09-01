# 0095 - Raw PTE update identity

## Purpose

Patch `0095` separates the transient value consumed by x86 page translation
from the canonical backing value used for page-table accessed and dirty
updates. A corrected-poison fault may alter software-visible PTE bits without
changing RAM. Using that corrected word as the cmpxchg expectation against the
unchanged backing entry fails every time and restarts the walk forever.

The page walker now records the raw low word before invoking the Crucible
page-table callback. Translation and protection checks continue to consume the
corrected value. If hardware bookkeeping must set an accessed or dirty bit,
the cmpxchg compares the raw backing word and writes only that raw word plus
the hardware-owned bits.

## Canonicality contract

Corrected fault bits are transient: they affect the current translation but
are never persisted by incidental accessed/dirty bookkeeping. Concurrent
guest page-table writes still cause the cmpxchg to fail and restart normally,
because the expected value remains the exact word originally read from RAM.

Without a matching corrected page-table fault, the raw and effective low words
are identical and the operation is equivalent to the upstream update path.

## Files and license scope

The patch modifies GPL-side `target/i386/tcg/system/excp_helper.c`. It changes
no shared-memory or control wire format and adds no QEMU file.

## Required gates

1. The live x86 corrected-poison page-table case must terminate and publish one
   corrected event instead of retrying the walk.
2. The complete x86_64 and AArch64 memory-access matrices must remain green.
3. Patch-prefix provenance, attribution, regeneration, drop-one, ABI, and
   license-boundary gates must pass.

- **[MEM-PTE-RAW-1]** Accessed and dirty updates MUST compare against the raw
  backing PTE observed before transient fault transformation.
- **[MEM-PTE-RAW-2]** Hardware PTE bookkeeping MUST NOT persist corrected fault
  bits into guest RAM.
