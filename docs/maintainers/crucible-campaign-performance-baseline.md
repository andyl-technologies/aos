# Crucible campaign performance baseline

The RFC-0020 §10.4 planner/guest overhead ratio and the absolute no-regression
comparison are separate requirements. Increasing guest elapsed time can improve
that ratio while making execution slower. The performance gate therefore keeps
its strict ratio below 5% and its reviewed ratio ceiling, and independently
requires authenticated equal-work paired timing evidence.

`gate:campaign-performance` returns `BLOCKED` until reviewed v2 comparison and
decision-plan artifacts have pinned SHA-256 values. The ratio-only v1 baseline
is unsupported. Never populate measured values or approvals from an estimate,
a parser control, or an unrelated source revision.

## Fix the comparison before collecting data

Review both actual source revisions and the affected paths first. A decision
plan fixes eight sequential matched pairs in alternating AB/BA order, matching
semantic inputs, toolchain, native configuration, cache conditions and CPU
configuration. Each revision authenticates its own production source manifest;
intended implementation changes must not be erased or required byte-identical.
Record explicit source-backed reasons for paths outside the required vector.
This campaign-case vector cannot qualify a changed native implementation: the
validator refuses changed native patch/header or plugin bodies until separate
authenticated None-path and equal-byte console timing metrics are integrated.
A planner median or faster guest aggregate cannot replace those observations.

For each required metric, the decision uses the arithmetic mean of the fourth
and fifth sorted candidate/reference ratios. Every required paired median must
be at most 1.00, using exact integer/rational comparisons. Acceptance also
requires every fixed marginal upper limit below to be at most 1.00. A faster
aggregate cannot hide a slower required path, and there is no positive slowdown
tolerance. The exact decision method is
`paired-median-eight-marginal-upper-at-most-one-v2`; old median-only approvals
are refused. The method, vector and thresholds are fixed before measurements.

Retain every absolute timing and paired ratio. The seventh order statistic is
reported separately as a marginal one-sided 96.484375% population-median upper
limit under independent stationary pairs; the extrema give a conservative
99.21875% two-sided interval. These are not simultaneous-vector, mean, tail or
universal guarantees. A slower required median is `REFUSED`; a passing median
with any required upper limit above one is `INCONCLUSIVE`. Both outcomes exit
nonzero and cannot populate or pass the gate's accepted comparison. Acceptance
requires both limits at most one for every required metric, with these explicit
marginal and stationarity limits. Unsuitable host conditions invalidate
the interpretation; they are not an excuse to replace the method after seeing
data.

Coordinate an exclusive quiet window for CPU 0 on the host named by
`tests/crucible/fixtures/campaign-performance-reference-host-v1.env`. Record
source revisions, actual kernel/microcode, affinity, boot identity, UTC time,
cache conditions and interfering load. Do not run competing correctness or
performance flights during collection. A host-profile match alone does not
prove quiet or stationary conditions; review those collection records too.

## Retain genuine independent samples

`tests/crucible/phase9-campaign-performance-sample.nix` wraps the existing real
performance case. Its required sample ID and measured revision reach the inner
VM constructor, not merely an outer wrapper. Use a separately reviewed immutable
collection recipe; repeated realization of one unchanged VM derivation is not
independent sampling. Every sample preserves the original supervisor, SQLite
planner/queue, guest continuation, resource ownership, deadlines and assertions.

The sample path excludes the independent 10,000-lifecycle stress cases. Qualify
full native scaling and the million-admission gate separately through their
original public targets; do not repeat full stress sixteen times just to sample
timing:

```sh
nix develop -c aos-dev --release build check crucible.phase7.gates.hotForkScaling.rawGate --no-out-link
nix develop -c aos-dev --release build check crucible.phase9.gates.campaignMetadataMillion --no-out-link
```

Each actual sample output retains `result`, `serial.log`, `host-reference.env`,
`performance-source-manifest.json`, and three `corpus-N-work.json` records. Work
records are emitted outside the timing windows from accepted original proposal,
queue, configuration, ordered event identities, fingerprints and replay traces.
Raw segment bytes are addressed without normalization. The source manifest covers all seventeen local dependency owners and workspace
build policy. It binds the actual guest derivation and native configure flags.
It is separate from canonical work and includes the physical sample identity; random
owner identifiers never enter the work comparison.

A v2 comparison names all sixteen immutable outputs and the exact SHA-256 of
their retained artifacts. Approved member roots become actual Nix build/runtime dependencies and remain
referenced by the gate evidence; JSON path strings alone are insufficient
sandbox and closure custody. The validator opens those bytes, verifies actual VM
sample identity, refuses duplicate outputs, authenticates revision-specific
sources and shared conditions, checks equal work across all samples, recomputes
original per-corpus totals, and enforces the strict ratio and ceiling for every
sample. The validator consumes one bounded final completed-report frame; original live
output remains retained separately. Missing, duplicate or incomplete frames are
refused rather than deduplicated. The frame sample ID must match independent VM
provenance. The complete-case timer is an actual observed elapsed difference,
separate from the sum of selected phases. Equal-work guest throughput is reported
from actual completed quantum counts and elapsed times.

## Review and pin authenticated evidence

Use the AOS-built Python interpreter to validate a proposed comparison and
retain its full decision report:

```sh
python3 tests/crucible/campaign-performance-baseline.py \
  retained-comparison-v2.json retained-decision-v2.json \
  --report retained-paired-decision.json \
  > campaign-performance-reference-comparison-v2.json
```

This validates artifacts; it does not collect timings or approve a baseline.
Review the actual source manifests, equal work, raw samples, host conditions,
uncertainty and affected-path scope. Store the approved comparison and decision
plan under `tests/crucible/fixtures/` with the names referenced by
`phase9-campaign-performance.nix`, then pin both exact hashes there. No v1
fallback is available. A later consumer must match the measured candidate's
actual production bodies and comparison conditions; a fixture-only approval
commit does not justify retagging measurements to changed production code.

Run the original public performance gate after approval:

```sh
nix develop -c aos-dev --release build check crucible.phase9.gates.campaignPerformance --no-out-link
```

Inspect its result and retained paired decision, current source, full scaling
and million evidence. Performance acceptance does not replace native scaling,
metadata budgets, Envoy, determinism, the mode matrix, ABI, license or release
qualification. Acceptance establishes only the predeclared paired median and
marginal-upper criterion under its stated assumptions; it is never a blanket
guarantee that every path is at least as fast.
