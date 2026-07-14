# L2 parallel — verdict: fan-out does not fit the toplevel shape

Owner: p1a-env. Task #14. **Target was: `systems.server.build.toplevel`
cache-off cold eval at parity-or-faster via L2 parallel evaluation.**

> **STATUS 2026-07-14 — CLOSED with evidence. L2 need-only fan-out CANNOT reach
> parity on the toplevel, and no bounded tax fix changes that.** The measured
> parallelizable mass of the toplevel is ≤~4%, so the Amdahl ceiling — even with
> the shared-mode coordination tax deleted entirely — is ~1.04x vs serial,
> inside the ±5% builder noise floor. The toplevel is one deep module-fixpoint
> dependency chain; it is structurally ~serial. The recorded re-entry condition
> (intra-spine decomposition) is a major redesign, not an increment. The
> shared-mode tax reduction is a real lever but belongs to the WIDE-eval case
> (parked, task #16), not here.

This mirrors the env-flatten lever close: a direction ruled out by direct
measurement so it is not re-explored. Numbers from the builder at tip
`fea4a1b19`, cache-off cold `systems.server.build.toplevel`, JIT off.

## The measurement

PASS 1 — wall (clean, `AOS_NIX_EVAL_STATS` off):

```text
serial   2.528s
K=1      5.084s   (2.01x SLOWER than serial)
K=2      5.249s
K=4      5.254s
K=8      4.894s
```

PASS 2 — scheduler + K-tax counters (`aos_nix_parallel_demand` eprintln line,
`AOS_NIX_EVAL_STATS=1`):

```text
K=2  published 25679  dropped 0  executed 25679  values 26964
     task_nanos 3.03e9  loop_nanos 5.40e9  helper_busy_permille 561
     claim_wait_nanos 3.00e9  claim_waits 1592  queue_peak 7175  speculated 0
     thunk_state_arc_clones 6030180  payload_arc_clones 0  env_frame_allocs 3451903
K=4  ... task 8.47e9  loop 15.7e9  busy 538  claim_wait 8.29e9/973  arc_clones 5824118
K=8  ... task 15.0e9  loop 33.4e9  busy 449  claim_wait 14.8e9/864  arc_clones 3090070
```

## Finding 1 — there is no parallelizable mass (~4%, tax aside)

Isolate the coordination tax by comparing *within* parallel mode (both legs
carry the identical shared-heap machinery): K=1 runs zero helpers, K=8 runs
seven. K=1 = 5.084s, K=8 = 4.894s — seven helpers removed **0.19s = 3.7%** of the
K=1 wall. So the parallelizable fraction of the toplevel is **≤~4%**.

The PASS 2 counters say the same thing directly: the helpers' `task_nanos`
(3.03e9 at K=2) is almost entirely `claim_wait_nanos` (3.00e9). Helpers do
~30ms of real work and spend the rest **blocked on claims** for spine thunks the
main worker already owns. They execute 25,679 task values against a toplevel of
~20M resolutions (~0.13%). The `derivationStrict`-entry fan-out
(`publish_derivation_entry_fanout`, `eval_derivation/demand_fanout.rs:74`) is
working exactly as designed — it just finds no independent mass on a module
fixpoint. Publishing more or earlier demand only enqueues more of the same
contended spine values.

## Finding 2 — the K=1 tax is real (2x) but is not the blocker

The shared-heap backend engages at any `Some(K)` including K=1
(`eval_core.rs:72` `shared_parallel_heap(workers)`), while helpers spawn only at
K>=2 (`pool.rs:49`). So K=1 measures pure coordination overhead: **2.01x**.
Decomposition:

- `thunk_state_arc_clones` = 6.03M at K=2. At ~20ns/clone that is **~120ms** —
  the sidecar `Arc<ThunkCell>` the shared backend mints per parked cell (the
  slice P3b's inline cells do NOT cover in shared mode).
- The remaining **~2.4s** of the ~2.5s K=1 tax is the atomic claim protocol +
  atomic slot cells applied to every one of ~14.6M forces: the shared backend
  routes every force through the CAS-claim path even with one worker.

The tell that the tax is protocol+contention, not the sidecar: at K=8
`thunk_state_arc_clones` DROPS to 3.09M (the counter is main-heap-only, so more
helpers offload clones off the main worker) while the wall stays ~2x. Removing
the sidecar attacks the small slice.

## Why no bounded fix rescues the toplevel

Grant a *perfect* shared-mode tax removal (unreachable — the candidate only
inlines the sidecar). Best-case K=8 ≈ `2.528 × (1 − 0.037) ≈ 2.43s = 1.04x` vs
serial — sub-noise. With ≤4% parallelizable mass, no coordination-cost fix and
no fan-out change can make the toplevel win. This is the decision tree's third
branch: not helper-starved (queue peak 7175, work available), not
helper-saturated (busy ~450–560 permille, and that "busy" time is ~all
claim-wait) — **the workload has no parallel mass.**

## Re-entry condition (recorded)

Toplevel parallelism requires **intra-spine decomposition**, not fan-out:
publish demand at the module-fixpoint / option level (force independent
`lib.evalModules` options concurrently) rather than at the `derivationStrict`
level, where by definition you are already serializing one derivation's attrs.
That needs an option-dependency model to know which forces are independent — a
major redesign, out of scope for an increment. Revisit only with that model in
hand.

## Not closed: the WIDE case

The shared-mode tax reduction (inline the shared-record state cell; and the
larger prize, a serial-fast-path claim that skips the CAS protocol when a thunk
is uncontended) IS a real lever — on the wide pkgset, where parallel already
nets ~1.26x @K=4 *despite* the 2x K=1 tax, so the tax is capping a real win.
That work is parked as **task #16** and must be measured against the WIDE
benchmark (interleaved serial-vs-K=1 A/B), not the toplevel, before shipping.
