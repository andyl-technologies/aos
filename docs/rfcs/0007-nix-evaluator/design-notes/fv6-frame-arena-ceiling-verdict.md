# FV-6 frame-arena — verdict: residual frame alloc/free is ~3% of the toplevel wall

Owner: p1a-env. Task #19. **Question: is arena-owning the remaining
`Arc<EvalFrame>` allocations worth a spec for cold toplevel parity?**

> **STATUS 2026-07-14 — CLOSED, ceiling-gated. No spec.** FV-6's payload arena
> ownership already landed (doc 30 §FV-6). The only remaining arena-ownership
> candidate the toplevel actually churns — the `Arc<EvalFrame>` alloc/free — is
> now empirically bounded at **~2.8-3.4% of the cold toplevel wall** by a direct
> builder measurement, inside the predicted 2-4% band and below the 10% gate.
> The thunk-state half was already done (I1/I2) and measured wall-neutral.
> Re-entry only if a future sampling profile shows `EvalFrame` alloc/drop as a
> top-3 line item.
>
> **2026-07-23 memory correction:** the original post-run RSS comparison below
> was not a peak measurement. Fresh child-process watermarks show the current
> native toplevel at approximately 828-835MiB versus 337MiB for C++ Nix
> (roughly 2.46x), so the claimed 0.03x memory advantage and the resulting
> "independent kill condition" are retracted. The measured 2.8-3.4% speed
> ceiling remains valid; any future arena prototype must measure peak memory
> rather than assuming its direction.

Mirrors the L2 close: a lever ruled out by direct measurement so it is not
re-explored.

## What was already done (not this measurement)

- **FV-6 payloads (doc 30 §FV-6, checked box):** `EvalThunk`/`EvalLambda`/
  `EvalPrimOp` payloads are stored by value in the arena, payload `Arc`s
  removed, sweep reclaims. Measured ~6% cold + RSS win on the wide workload.
  Banked.
- **Thunk force-state `Arc` (I1/I2, `cd6bdfa7a`/`df0bf4b23`):** −93%/−61%
  `thunk_state_arc_clones`, and an interleaved server-toplevel A/B measured
  **wall-neutral** (17.37 vs 17.43s). "An `Arc` clone is an uncontended atomic
  increment; 8.6M is tens of ms, not seconds" (doc 15 §5.5).

So the toplevel's post-FV-6 flat-tail profile (`EvalFrame::new_linked` ~2.1%,
`Arc` drops ~3.5% mixed across kinds) already excludes the payload and
thunk-state work. The one unconverted class the toplevel churns is `EvalFrame`
itself (`Arc<EvalFrame>`, `env.rs`), 3.45M per eval.

## The measurement (frame probe `95a1af09b`, builder tip `20dd35cf7`)

Cache-off cold `systems.server.build.toplevel`, `AOS_NIX_FRAME_PROBE=1`:

```text
aos_nix_frame_probe {"frame_allocs":10355769,"frame_alloc_nanos":259180490,
  "frame_slots_total":11509479,"calib_slot_count":1,"calib_iters":1048576,
  "calib_alloc_drop_nanos":20578777}
clean-wall reference: native_mean = 2.504778 s
```

`frame_allocs` is cumulative across the bench's ~3 evals (≈3× the 3.45M/eval
attribution count — consistent).

- **Full alloc+drop lifecycle** (calibration, accurate over 1.05M tight-loop
  iterations with a single timing bracket): `20578777 / 1048576` = **19.6
  ns/frame** — a lower bound (a tight loop reuses freed memory warmer than the
  real eval).
- **In-eval alloc half** (in-context, per-sample timed): `259180490 / 10355769`
  = **25.0 ns/alloc**, including the per-sample `Instant` overhead. The honest
  per-frame range is **~20-25 ns**.
- **Per eval:** `3.45M × 20-25 ns` ≈ **69-86 ms** = **2.8-3.4% of the 2.50 s
  wall.**

## Why it is already this low

P3a inlines small frames (≤`INLINE_SLOT_CAPACITY` = 2 slots — the dominant
class) directly into the `Arc<EvalFrame>` box (`FrameSlots::Inline`), so there
is no separate slot allocation to remove; the residual is only the `Arc` box
`malloc`/`free` itself. Arena ownership would replace that box alloc+free with a
bump + wholesale sweep — recovering most of ~3%, minus the bump and sweep-mark
cost it still pays. Net recoverable is a fraction of ~3%: sub-noise against the
±5% builder floor.

## Memory coupling — corrected peak measurement

The earlier 28MiB native versus approximately 1GiB C++ comparison sampled
retained RSS after evaluation in one process; it did not measure either
evaluator's true high-water mark. Fresh child-process measurements reverse the
conclusion: the current native toplevel peaks around 828-835MiB while pinned
C++ Nix peaks around 337MiB. The production-GC TODO in doc 22 records the
underlying permanent-flat-store retention gap.

Arena-owning frames could increase retention, but that is now a hypothesis to
measure, not an independent reason to reject the lever. The direct allocation
ceiling still rejects it as a speed priority: even eliminating the entire
measured frame allocation/drop cost cannot materially close a roughly 3.9x
instruction gap.

## Re-entry condition

Revisit frame arena ownership only if a future sampling profile shows
`EvalFrame` allocation or drop as a **top-3 wall line item** (which would
contradict this ~3% bound), *and* a sweep policy is found that captures the
alloc savings without worsening the measured native peak. Absent both, the
cold-parity weight stays on the levers §5.5 names as load-bearing: JIT coverage
of the module-fixpoint shape class (task #20) and the heap-image prelude
snapshot.
