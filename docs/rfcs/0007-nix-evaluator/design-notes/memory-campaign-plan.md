# Memory campaign — implementation plan (design-only)

Owner: fv5. Status: DESIGN-ONLY (implementation of the top lever when a lane
frees). Task #15. **Target: wide-eval post-run RSS ≤38 MiB — half of C++ Nix's
~77 MiB.** Today: 140-190 MiB (FV-6 measured 140.6 cold / 156.9 warm, *before*
mimalloc; mimalloc default now pushes warm-wide to ~189).

This note **consolidates + verifies + sequences** the levers whose designs
already live across the RFC (docs 06/29/30), anchored to **today's tree** with
file:line, with honest per-lever MiB and a credible path to 38. It is not new
design where the campaign log already has it; it is the executable ordering.

Measurement per landing is the **scoreboard** defined in
[doc 15 §5.4](../docs/rfcs/0007-nix-evaluator/15-differential-testing-and-benchmarking.md):
`wide_mem_ratio` = median native
`rss_after_bytes_max` / oracle `child_peak_rss_bytes_max` on `bench.wide`, cold
and warm (goal ≤0.5), plus `arena_peak_live_mapped_bytes_max` for
arena-vs-non-arena attribution.

---

## 0. The load-bearing finding: we cannot yet attribute the 140-190 MiB

`AOS_NIX_EVAL_STATS` tracks **allocation traffic and object counts, not live
bytes per holder at peak** (`eval/tree_walk/eval_stats.rs:181-239`,
`eval/heap/alloc_counters.rs`, `campaign_counters.rs`). The **only** measured
retained-at-peak holder is the arena:

- **Arena live-mapped peak = 67.5 MiB** (measured; `docs/.../30-flat-value-architecture.md:1967`;
  gauge `ratchet-value/src/heap/gauges.rs:24-92`,
  `PEAK_LIVE_MAPPED_BYTES`; read by nix-bench at
  `crates/aos/src/commands/nix_bench/memory.rs:53` → `NativeSampleArena` →
  `arena_peak_live_mapped_bytes_max`). The arena is munmapped **only at end**
  (`ratchet-value/src/heap/arena.rs:945-953` `impl Drop for Chunk`), so it grows
  monotonically to peak.

Everything else in the **~73-90 MiB malloc-backed residual** (retained RSS minus
arena) is **inferred, not gauged**: the surviving record table + address map,
the 691,617 thunk-state sidecar `Arc`s, symbol tables + retained module IR,
allocator overhead, and — post-task-#5 — **mimalloc's retained-but-freed pages**
(measured +34 MiB warm-wide, the `MADV_FREE` residency from the allocator
landing). We cannot honestly ladder to 38 MiB without first measuring where the
140 sits. **So increment 0 is instrumentation** (§2), and the per-lever MiB in §4
are explicitly flagged measured vs estimated.

Two facts sharpen the target immediately:

1. **The default wide-eval never garbage-collects.** Both B1 sweep triggers are
   no-ops unless `AOS_NIX_GC=sweep` is set: end/quiescence
   (`eval/tree_walk/api.rs:161-165 maybe_sweep_heap_at_quiescence`) and mid-eval
   stress (`eval/tree_walk/eval_raw.rs:365
   maybe_sweep_heap_at_registered_safepoint`, `runtime/alloc.rs:955-995
   GcStressPolicy` default `Disabled`) — confirmed at
   `docs/.../06-memory-management-and-gc.md:432-434`. So the 140-190 MiB retains
   **all** of the measured **54% dead-at-end** worker heap
   (`30-...:518-521`, `9422a34c8`). Half the worker heap is garbage that is
   never reclaimed.
2. **B1 alone cannot return that memory.** B1 is non-moving; a swept object goes
   to a free list but the bump arena's mapping does not shrink (munmap only at
   end, §0 above). Converting "54% dead" into an **RSS drop** requires either
   `madvise(MADV_DONTNEED)` on swept ranges or **Tier-B B2 copying** (compact
   survivors, munmap the freed tail). B2 is therefore the decisive lever, and it
   is **already unblocked** by the landed FV-2.4 relocation substrate
   (`30-...:249-320`, the payload-identity audit + `relocation_identity.rs`).

---

## 1. Attribution breakdown (measured vs inferred)

**L0 MEASURED (2026-07-12, commit landing symbol_table_resident_bytes; bench.wide,
default cache-less, JIT=1):** arena WORKER 44.9 MiB (mapped; B2-attackable, holds
the 54%-dead) + arena PERMANENT 16.5 MiB (immortal hash-cons floor) = arena TOTAL
61.4 MiB; symbols 2.2 MiB (7,414); `record_table_records` **0** (confirmed — the
pre-flat 51 MiB table is gone post-FV-3); `flat_objects` 369,361 live; thunk-state
Arc traffic 697,236. **Cold RSS 152.0 MiB (1.53x oracle 99.3), warm 188.2 MiB
(1.89x).** => **non-arena malloc residual ~= 90 MiB, i.e. ~60% of RSS is malloc,
not arena.** This REORDERS the ladder: B2 attacks only the worker arena's 54%-dead
(~24 MiB of the 61), so it is not the single biggest lever — the ~90 MiB residual
(mimalloc retained-free ~34 MiB Linux-purgeable + thunk-state Arcs ~26 MiB +
alloc overhead) outranks it. Elevate the mimalloc purge (Linux) + L4 (arena-own
thunk state) ahead of B2 by measured yield; B2 still recovers the arena's dead
half but waits for cutover S4 regardless. The estimated table below is retained
as the pre-L0 record; the measured line above supersedes it where they differ.

| Holder | Size | M/E | Freed | Counter at HEAD |
| --- | --- | --- | --- | --- |
| Arena mapped peak (flat worker payloads + immortal hash-cons) | **67.5 MiB** | **Measured** (`30-...:1967`) | munmap at end only (`arena.rs:945-953`) | EXISTS (`gauges.rs`, `permanent_heap_*_bytes` `eval_stats.rs:63-70`) |
| — worker (sweepable) vs permanent (immortal) split | unknown | **must measure** | worker: end (no default sweep); permanent: immortal one-shot (`30-...:788-793`) | `permanent_heap_used_bytes` exists; worker split MISSING |
| Record `Vec` + address map | pre-flat 38.7+12.3 MiB; **~0 at HEAD** (FV-3 made `record_table_records`=0 in production, `30-...:1381-1388`) | **stale/est** | end | count only; bytes MISSING |
| Thunk-state sidecar `Arc`s | ~26 MiB est (691,617 × ~40 B `Arc<ThunkCell>`, `eval/thunk.rs:187-190`) | **Estimated** (count measured `30-...:1959`) | survive re-entry → end (`30-...:1949-1952`) | traffic only (`thunk_state_arc_clones` `deref_counters.rs:143`); retained MISSING |
| Symbols + retained module IR | unmeasured | **Estimated** | whole-eval, never evicted (`aos-nix-syntax/src/ast.rs:108-122`; IR-eviction unimplemented `30-...:706-709`) | `SymbolTable::len()` only; bytes MISSING |
| mimalloc retained-free pages | ~34 MiB warm est (task #5 measured `MADV_FREE` residency) | **Estimated** | OS pressure / `MIMALLOC_PURGE_DELAY` (Linux) | none (allocator-internal) |
| Eval-cache DCG | **~0 in default cache-less run** (enum defaults `Disabled` `cache/runtime/eval_cache_runtime.rs:6-13`, `aos-nix/src/native/mod.rs:142`) | **Measured-by-gating** | end (cache-on only) | MISSING (cache-on only) |
| Cache-on transient churn (per-force payload build + write-behind buffer) | ~0 default; cache-on only | **est** | per-force alloc discarded immediately; buffer flushed at run boundary | see `persist-write-batching-plan.md` §3.1/§3.2 |
| Env-capture frame retention | part of "54% dead-at-end" | **Measured share** | end (no default sweep) | traffic (`env_frame_slot_bytes`) |
| Allocator overhead / fragmentation / stacks | residual | **Estimated** | — | none |

**Read of the residual:** the pre-flat record table (51 MiB) is essentially
**gone** at HEAD (production-empty after FV-3), so it is *not* where today's
residual lives. The residual is dominated by (a) mimalloc retained-free (~34 MiB
warm, reclaimable via purge tuning on Linux), (b) thunk-state sidecar `Arc`s
(~26 MiB est), and (c) symbols/IR (unmeasured) — plus the arena's own 54%-dead
worker portion, which is *inside* the 67.5 MiB and reclaimable only by a moving
collector.

---

## 2. Increment 0 — retained-bytes attribution counters (measure first)

Spec and land the four missing retained-at-peak gauges, dumped in
`AOS_NIX_EVAL_STATS`, so every subsequent lever's MiB is measured not guessed:

1. **Arena worker-vs-permanent split** — the arena already knows its domains
   (`heap/flat/backing.rs`); add `worker_heap_used_bytes` alongside the existing
   `permanent_heap_used_bytes` (`eval_stats.rs:67-70`). This alone tells us how
   much of the 67.5 MiB B2 can attack.
2. **Live thunk-state-Arc retained bytes** — live-snapshot count ×
   `size_of::<ThunkCell>()` + Arc header, at peak (not clone traffic). Site:
   the closure store (`eval/heap/flat_values/closures.rs`).
3. **Symbol-table + retained module-IR resident bytes** — sum over `by_text` +
   `text` + `rank_by_symbol` (`aos-nix-syntax/src/ast.rs:62-66`) + lowered IR.
4. **(cache-on only) DCG node resident bytes** — over `EvalCache` node/inline/
   persist maps (`cache/runtime/eval_cache.rs`).

Gate: the four counters sum (plus arena non-attributed remainder) reconciles to
within ~10% of measured `rss_after_bytes_max` on `bench.wide`. Until they do,
the ladder's MiB targets are estimates.

---

## 3. Note on already-closed / externally-owned levers

- **Store-path segment interning — REJECTED by measurement.** The probe found
  eligible store-path string payloads total **1,250,076 bytes**; even 100%
  elimination is below the multi-MiB gate (`30-...:760-764`). Do **not** build
  it. (Listed in the task for completeness; already closed.)
- **Candidate-C container narrowing — owned by task #12, referenced not
  duplicated.** 16→8-byte values halve container slot mass. Measured slot
  populations to narrow (`30-...:1421-1424`): 145,557 list slots (~2.33 MB→~1.17),
  295,810 flat-capture slots (~4.73 MB→~2.37), 4,148,192 env-slot bytes (~2 MB
  saved). Expected arena saving **~5-8 MiB**. This campaign consumes #12's result
  as an arena-shrink lever; it does not re-plan the value ABI.
- **mimalloc purge tuning** — the `MIMALLOC_PURGE_DELAY=0` knob (documented in
  `crates/aos/src/main.rs` beside the allocator + task #5 report) returns freed
  pages on the Linux deploy target (`MADV_DONTNEED`); on darwin it's a no-op
  (`MADV_FREE`). Reclaims the ~34 MiB warm-wide mimalloc residency. A config
  lever, not a code campaign, but it is on the critical path to 38 and must be
  set in the deploy/CI config; the wide_mem_ratio scoreboard must be measured on
  Linux for it to show.

---

## 4. The ladder — dependency order, per-lever MiB (honest)

Ordering is by (a) prerequisite dependency and (b) measured yield. MiB are
estimates except where marked **measured**; increment 0 replaces the estimates.

**L0. Attribution counters (§2).** 0 MiB directly; unlocks honest sizing of all
below. *Prerequisite for everything.*

**L1. Default/budget-triggered mid-eval sweep, moved before the RSS peak.**
Today the sweep is off by default and, when on, fires post-peak at quiescence
(`api.rs:161-165`). Drive it from the memory budget escalation
(`EvalHeapMemoryBudget*`, `outcome.rs:104-125`, today measurement-only) so it
fires mid-eval when a threshold is crossed. **B1 alone reclaims logically but
does not drop RSS** (non-moving, munmap-at-end) — so L1's *direct* RSS win is ~0
until L2/madvise; its value is (i) proving the 54%-dead is collectable live, and
(ii) feeding free ranges to L2. *Depends on L0 (to see the effect).*

**L2. Tier-B B2 copying GC — the decisive lever.** Compact live survivors into a
fresh region and munmap the freed tail, converting the **measured 54%
dead-at-end** (`30-...:518-521`) into an actual RSS drop. Unblocked by the landed
relocation substrate (FV-2.4 identity audit + `relocation_identity.rs`,
`30-...:249-320`); doc 06 §4 names value-rep flattening (done, FV-1..6) as B2's
gate. Expected: the **sweepable-worker portion of the 67.5 MiB arena drops
toward its live half.** If increment-0 shows worker ≈ 45 MiB of the 67.5 with
54% dead, B2 yields **~20-24 MiB arena reduction** (arena → ~43-47 MiB). *Depends
on L0 (worker/permanent split) + L1 (sweep liveness).* **Single biggest lever.**

**L3. Last-use capture shedding.** Cardinality-fact-driven eager release, before
the force completes and before the peak — extends `SingleEntry`
(`EvalThunkForceStorageMode`, `eval/heap/mod.rs`; `30-...:779-786`). Sheds
captured frames (the "all frames in scope" retention that made 54% dead) ahead
of the peak, so the peak itself is lower (not just reclaimed after). Depends on
Chunk-D facts (landed). Expected **~5-15 MiB peak reduction** (estimate; the
env-capture share of the 54% is unmeasured — L0 sizes it). *Depends on L0.*

**L4. Thunk-state sidecar `Arc` → arena-owned.** Kill the 691,617
`Arc<ThunkCell>` (~26 MiB est malloc) by moving the thunk state into the arena
object (the FV-6 follow-up the doc names: "the payload `Arc` dies in FV-6 …
thunk force state is the only independently live portion" `30-...:1917-1926`).
Expected **~15-26 MiB malloc reduction** (est; L0 measures the live retained
bytes). *Independent; sequence after L2 so the arena is the reclamation owner.*

**L5. Eviction ladder (doc 29 §5 / doc 30 §7.2 rungs 3-4).** Under budget
pressure: evict memo L0/L1 records, then cold module IR (parse cache
re-materializes in ms — `30-...:706-709`), then (research) thunk
drop-and-recompute. Attacks the symbols/IR holder (L0-sized). Expected **~5-20
MiB** (est). *Depends on L0 + the budget trigger from L1.*

**L6. Candidate-C container narrowing (task #12).** ~5-8 MiB arena (§3).
*Reference #12; sequence when #12 lands.*

**L7. Per-kind arena segmentation + inline forced results (doc 30 §7.4).**
Segregate sweepable worker vs immortal permanent pages so L1/L2 scan/compact
only sweepable pages and immortal pages need no mark bits. Enables L2 to be
cheap and precise; also the natural home for making `allocation_domain`
positional. Small direct MiB but a **multiplier on L2's effectiveness**.
*Sequence with/after L2.*

**Config lever (parallel): mimalloc purge tuning** — ~34 MiB warm-wide reclaim
on Linux (§3). Set in deploy/CI config; measure the scoreboard on Linux.

---

## 5. Does it sum to 38? (honest arithmetic)

Starting point (Linux, mimalloc default, wide warm ≈ the high end ~189 MiB;
cold ≈ 140):

```text
  cold ~140 MiB
  - mimalloc purge tuning (Linux)          ~ -20..34   (retained-free returned)
  - L2 B2 copying (54%-dead worker arena)  ~ -20..24   (biggest single lever)
  - L4 arena-own thunk state (Arc kill)    ~ -15..26
  - L3 last-use shedding (lower the peak)  ~ -5..15
  - L5 memo/IR eviction                    ~ -5..20
  - L6 Candidate-C narrowing               ~ -5..8
  => plausible landing ~35-50 MiB, i.e. AT or NEAR the 38 target
```

This is a **credible-but-uncertain** path. The honest caveats: the ranges
overlap holders (L2 and L3 both attack the dead-worker mass; don't double-count),
several inputs are estimated pending L0, and the arena's **immortal permanent
(hash-cons) floor** is a hard lower bound B2 cannot touch — if that floor is
large, 38 needs the hash-cons domain shrunk too (weak tables are daemon-only;
in one-shot the floor is the real working set). **L0 (attribution) decides
whether 38 is reachable or whether a residual must be decomposed and attributed
to a named holder** (the doc-30 §9.3 "≤2x or decompose the residual" discipline).

---

## 6. Staged landing order + gates

1. **L0 attribution counters** — reconcile-to-±10% gate on `bench.wide`; this is
   the measure-first foundation and the first thing to land.
2. **L1 mid-eval budget-triggered sweep** — sweep/shed counters; parity-green;
   prove 54%-dead is collectable live (RSS may not drop yet — expected).
3. **L2 Tier-B B2 copying** — the big one; the FV-2.4 identity audit's B2
   worklist is the repair checklist; loom/miri on the relocation protocol;
   scoreboard `wide_mem_ratio` must drop materially. Gate: byte-parity across the
   16-package legs + wide in 4 modes (the doc-30 §9.2 battery).
4. **L4 arena-own thunk state** — the FV-6 follow-up; `thunk_state_arc_clones`→
   retained bytes drop; parity-green.
5. **L3 last-use shedding**, **L5 eviction ladder**, **L7 arena segmentation** —
   each independently gated, ordered by L0's measured yield.
6. **L6 Candidate-C** — consumed when #12 lands.
7. **Re-measure the scoreboard on Linux** (mimalloc purge on) after each; the
   campaign exits when `wide_mem_ratio ≤ 0.5` cold+warm, or the residual is
   decomposed and attributed.

**Every landing pastes the scoreboard line** ([doc 15
§5.4](../docs/rfcs/0007-nix-evaluator/15-differential-testing-and-benchmarking.md)):
`wide_mem_ratio cold=<x> warm=<x> (goal <=0.50; native <MiB> vs C++
<MiB>)` + `arena_peak=<MiB>`, so the ladder's progress is one comparable number.

## 7. Gate on the product decision

The 0.5x-of-C++ memory goal and the default-cache-root decision
(`persist-write-batching-plan.md` §8) interact: turning the persist cache on by
default adds the DCG + persist residency to every eval, which this campaign's
budget must account for. Keep the two campaigns' scoreboards on the same axis so
neither regresses the other.
