# Ready-plan stable-negative filter census

## Question

EMPTY_ONLY local Ready probes used to consult the sparse `ReadyCellPlanCache`
before rejecting a def-site whose static classification can never produce a
capture-free result. A report-only simulator measured whether a tiny
direct-mapped negative front filter could remove enough sparse-map work to
justify a serving implementation.

The 1,024-entry filter is now active whenever the local Ready plan cache
exists. `AOS_NIX_READY_STABLE_NEGATIVE_FILTER_CENSUS=1` enables optional
terminal counters; it is independent of `AOS_NIX_EVAL_STATS`, so it can run
with `AOS_NIX_TYPED_THUNK_HEADS=apply`.

## Stable-negative boundary

The key is the exact module-qualified `EvalNodeRef`. A resident plan is
stable-negative only when its classification is one of:

- `EffectOrUnsafe`;
- `NonSlot`;
- `BelowFloor`;
- `Unavailable`; or
- `Eligible` with a non-empty capture plan.

An `Eligible` empty plan observed with a different captured-frame count is not
negative-cached. A later thunk instance can carry the planned frame count and
must still reach the resident plan. This distinction is both a simulator
correctness rule and a prerequisite for any future serving filter.

Each direct-mapped slot stores the complete `EvalNodeRef`. An occupied
non-matching slot is a collision and falls through to the authoritative sparse
map. An exact hit returns `Ineligible` before that map lookup. Inserting or
replacing an authoritative plan first invalidates a matching filter slot;
publishing or clearing an empty Ready value needs no coherence operation
because eligible empty plans never enter the negative filter.

## Simulator result and promotion

The exact nixpkgs system-toplevel simulator run, with typed thunk heads and
same-run local Ready enabled, produced the exact expected derivation and:

| Counter | Count |
|---|---:|
| probes | 7,152,740 |
| stable-negative observations | 7,041,909 |
| stable-negative inserts | 1,005,129 |
| exact filter hits | 6,036,780 |
| collisions | 1,113,912 |
| fallbacks | 1,115,960 |
| invalidations | 0 |

Exact hits covered 84.4% of all EMPTY_ONLY plan probes. This is the measured
upper bound now converted into active sparse-map bypasses. Complete-key
comparison retains collision safety, and every empty or colliding slot still
uses the old authoritative path.

## Report

The terminal line is strict JSON:

```text
aos_nix_ready_stable_negative_filter_census {"version":2,"slots":1024,"active":true,"probes":...,"stable_negative_observations":...,"stable_negative_inserts":...,"exact_filter_hits":...,"collisions":...,"fallbacks":...,"invalidations":...}
```

`exact_filter_hits / probes` is the actual sparse-map avoidance rate.
`collisions` identifies occupied-slot fallbacks; `fallbacks` includes both
collisions and empty slots. Stable-negative observations include both
authoritative negative classifications and exact active-filter hits, while
inserts show replacement pressure in the bounded table.

Focused tests prove that exact hits bypass the authoritative map, complete-key
collisions fall back, eligible-empty frame mismatches never become negative,
and replacing a negative plan with an eligible empty plan invalidates the
matching slot.

## Promotion gate

The filter is promoted on the simulator's 84.4% bypass rate and exact output.
Retain it only if the active exact system-toplevel A/B preserves byte-identical
output and shows a repeatable instruction or wall-time improvement larger than
the direct slot probe and rare insertion cost.
