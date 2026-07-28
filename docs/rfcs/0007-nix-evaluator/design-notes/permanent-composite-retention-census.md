# Permanent composite retention census

`AOS_NIX_PERMANENT_RETENTION_CENSUS=1` enables a default-off, report-only
terminal probe. It attributes suspended thunks to either the evaluator's true
terminal roots or to lists and attrsets that are themselves unreachable from
those roots.

The probe computes two graph closures:

```text
T = transitive closure from the complete terminal evaluator root set
P = transitive closure from edges of permanent lists and attrsets not in T
```

A suspended thunk in `T` is true-root live. A suspended thunk outside `T` but
in `P` is reported as `dead_composite_only`. A thunk in neither set remains
unattached. Objects in both sets are charged only to true roots.
The implementation seeds `P` with worker-domain edges only. This is equivalent
to seeding every edge because every weak-unreachable permanent composite is
inventoried independently, and avoids copying millions of redundant permanent
object edges into the diagnostic worklist.

The output includes array-order metadata. List and attr tallies are
`[total_count, true_root_count, total_inline_bytes,
true_root_inline_bytes]`. Suspended-thunk tallies additionally report the
dead-composite-only and unattached counts and inline bytes. Direct outgoing
suspended-thunk edge counts preserve multiplicity, while thunk counts are
address-deduplicated. Reservation pages are the exact initialized arena-page
projection already used by the weak-liveness census.

The measurement does not force thunks, alter memoization, reclaim objects, or
retain a production per-thunk identity map. Captured `EvalEnv` frame bytes are
not included, so byte values are inline allocation bytes rather than full
retained-size estimates. "Dead" means unreachable under hypothetical
collectible-permanent semantics: lists and attrsets are currently immortal and
their worker edges intentionally retain objects.

## Prior terminal evidence

The exact weak-liveness probe on the nixpkgs system-toplevel workload reported
4,889 of 559,927 lists reachable, 5,783 of 1,572,087 attrsets reachable, and
35,950 of 5,228,985 typed thunk heads reachable. Its reservation projection
found 408,645 zero-live pages, approximately 1.56 GiB. Those numbers motivate
the attribution probe but do not by themselves prove that unreachable
composites retain the unreachable thunk heads; this census supplies that
missing graph split.

Import-milestone weak scans are not a substitute for this terminal result.
Root sets legitimately contain immediate values as well as heap references;
the shared weak traversal ignores those immediates just as normal edge scanning
does. The terminal seam first verifies continuation quiescence and adds the
result through `EvalRootSet`, so it is the authoritative measurement point.

This probe is terminal-only. The peak-ordinal probe records process and arena
watermarks, not a historical heap graph, so an exact peak-time ownership split
cannot be reconstructed at termination. Producing one would require retaining
or rescanning graph state at sampled peaks, which is deliberately outside this
bounded report-only increment.

## Exact system-toplevel result

The Candidate-C typed-head run of the pinned nixpkgs system-toplevel fixture
remained exact at
`/nix/store/g3lcf1mzgvi8k1gpynbalc6gn130qaxp-nixos-system-aos-evaluator-bench-25.11.19700101.dirty.drv`.
At terminal quiescence it reported:

```text
permanent lists:                  559,916 total / 4,889 true-root live
permanent attrsets:             1,572,081 total / 5,783 true-root live
direct suspended-thunk edges:  12,113,194 total
  from true-root composites:       28,949
  from dead composites:        12,084,245
suspended thunks:               4,335,701 total
  true-root live:                  30,699
  dead-composite-only:          3,438,570
  unattached:                     866,432
inline suspended-thunk bytes:  226,576,480 total
  true-root live:                 598,016
  dead-composite-only:        164,611,056
  unattached:                  61,367,408
reservation pages:                416,404 total / 7,763 true-root live
zero-live reservation bytes: 1,673,793,536
```

Thus 79.3% of terminal suspended thunks are retained only through permanent
composites that are unreachable from the evaluator's true roots. Their
164.6 MB of inline thunk storage is a strict lower bound: it excludes captured
frames and separately reserved typed-work storage. This clears the evidence
gate for a collectible-permanent cohort or equivalent retirement mechanism.
The next implementation must preserve the current strong-edge semantics while
a composite is live, prove complete roots at every collection point, and avoid
turning hash-cons indexes into accidental owners.
