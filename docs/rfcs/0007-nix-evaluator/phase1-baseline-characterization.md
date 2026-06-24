# Phase 1 Baseline Characterization

This is the Phase 1.5 characterization over the committed Phase 1 measurement
record in [`phase1-baseline.jsonl`](phase1-baseline.jsonl). The record was
captured on 2026-06-24 at 13:12:12 UTC with `aos nix-measure` against the
pinned C++ `nix-instantiate` baseline. It contains four explicit real AOS
workloads:

- `pkgs.linux`
- `pkgs.firecracker`
- `pkgs.gcc-libs`
- `pkgs.zlib`

The measurement is the opening representative slice for P1.5. It is not the
full future CI distribution; Q-C remains the place where the cold-vs-warm mix
of real CI traffic is quantified.

## Summary

| Metric | Value |
|---|---:|
| Workloads | 4 |
| Total cold `nix-instantiate` time | 1.986269 s |
| Total warm `nix-instantiate` time | 0.581437 s |
| Mean cold eval time | 0.496567 s |
| Median cold eval time | 0.531680 s |
| Mean warm eval time | 0.145359 s |
| Median warm eval time | 0.088299 s |
| Mean warm saving | 67.4% |
| Median warm saving | 68.8% |
| Total build time measured | 390.502105 s |
| Build-time-weighted eval fraction | 0.5% |
| Unweighted mean eval/build fraction | 50.2% |

The weighted and unweighted fractions say different things because the workload
classes are different:

- Long uncached builds (`pkgs.linux`, `pkgs.firecracker`) are dominated by build
  realization. Eval is below 1% of wall time there.
- Short or already-realized build actions (`pkgs.gcc-libs`, `pkgs.zlib`) are
  dominated by evaluation and process/setup overhead. Eval is the whole visible
  cost once the build action itself is effectively a cache hit.

The actionable conclusion is therefore not "eval dominates every AOS build."
It is that eval dominates no-op, already-built, and repeated developer/CI
queries, while long first realizations remain build-bound. That is exactly the
profile where an incremental evaluator can pay off without claiming to make a
full Linux compile faster.

## Workloads

| Attr | Cold eval | Warm eval | Build | Eval/build | Warm saving | Thunks | Calls | Lookups | Primops | GC bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `pkgs.linux` | 0.483298 s | 0.094622 s | 281.338103 s | 0.2% | 80.4% | 21,990 | 15,917 | 23,609 | 13,793 | 5.61 MiB |
| `pkgs.firecracker` | 0.775374 s | 0.331384 s | 108.993705 s | 0.7% | 57.3% | 34,555 | 28,102 | 37,031 | 21,320 | 9.05 MiB |
| `pkgs.gcc-libs` | 0.147535 s | 0.081976 s | 0.091650 s | 100.0% | 44.4% | 10,841 | 5,304 | 11,928 | 7,283 | 3.01 MiB |
| `pkgs.zlib` | 0.580062 s | 0.073455 s | 0.078647 s | 100.0% | 87.3% | 10,911 | 5,434 | 12,018 | 7,343 | 2.99 MiB |

`pkgs.firecracker` is the hottest measured eval workload by cold wall time and
by `NIX_SHOW_STATS` pressure: 34,555 thunks, 37,031 lookups, 28,102 function
calls, 21,320 primop calls, and 9.05 MiB of reported GC bytes.

## Counter Breakdown

Average cold `NIX_SHOW_STATS` counters across the four workloads:

| Counter | Mean |
|---|---:|
| `nrThunks` | 19,574 |
| `nrAvoided` | 26,980 |
| `nrExprs` | 39,245 |
| `nrFunctionCalls` | 13,689 |
| `nrLookups` | 21,147 |
| `nrPrimOpCalls` | 12,435 |
| `nrOpUpdates` | 1,567 |
| `nrOpUpdateValuesCopied` | 21,329 |
| `gc.totalBytes` | 5.17 MiB |
| Tracked env/set/list/value bytes | 1.65 MiB |

Every measured workload reports one GC cycle and `time.gc = 0.0`. This first
baseline does not show C++ Nix GC pause time as the headline cost. It does show
substantial allocation and thunk/update churn, so the allocator/GC work remains
important, but its first validation target should be allocation volume and
arena high-water movement rather than an assumed Boehm pause win.

## Workstream Order

P2 stays first. The cold-to-warm drop is large on every measured workload
(44.4% to 87.3%), and the short/already-realized workloads are eval dominated.
That is opening evidence for early cutoff, parse/eval reuse, and hash-consing.
It does not prove that the cache alone clears the end-to-end build-time goal;
that remains Q-A and must be answered after the P2 cache exists.

P3 and P4 should be prepared in parallel once the P2 interfaces are settled.
P3 owns the allocation path and can use `gc.totalBytes`, heap high-water, and
arena counters as the validation budget. P4 owns strictness/cardinality/escape
analysis and has direct pressure from `nrThunks`, `nrAvoided`, and
`nrOpUpdateValuesCopied`.

P5 should start with profiling hooks and shape-data collection, then land after
the analysis prerequisites. The measured `nrLookups` counts make attr access a
real target, but the current data is not enough to prioritize shape/PIC work
ahead of the cache or allocation/laziness work.

P6, P7, and the AOT tier stay later in the sequence. Function and primop call
counts are visible, but the measured cold eval wall times are subsecond and the
one-shot CLI warmup risk is still the dominant JIT question.

P3.5 parallel evaluation remains a correctness and throughput workstream, but
this baseline does not make it the immediate performance bet: the measured
single-derivation eval slices are small, so protocol design and `loom`/Miri
preparation can proceed while P2/P3/P4 supply better data.

## Decision Status

- `M-1`: opening data recorded. The cache is plausible for repeated/no-op
  workloads, but "cache alone clears the goal" is not answered until P2.
- `M-3`: first cold-vs-warm read recorded. The measured slice has a large warm
  drop; the real CI cold/warm distribution remains Q-C.
- `Q-B`: resolved for the committed representative P1 slice. The cold eval
  baseline is now anchored by this artifact instead of an estimate.
- `Q-A` and `Q-C`: informed but still open.

## Phase 1.5 Exit

P1.5 is complete for its scoped deliverable: a written characterization exists,
grounded in the P1 baseline, and it feeds the P2-P8 ordering without cancelling
any later phase.
