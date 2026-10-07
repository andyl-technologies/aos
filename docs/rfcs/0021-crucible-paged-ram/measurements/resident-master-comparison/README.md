# Resident execution comparison with merged master

The predeclared zero-margin evaluator returned **`regression_detected`**. All
480 execution observations passed the original drivers' independent arithmetic,
register, retired-count, logical-tick, and physical-memory-window checks. Passing
those checks does not satisfy the performance requirement.

POST cold process CPU time had a current/baseline geometric ratio of
1.002425073, with an individual normal approximate 95% interval of
[1.000104737, 1.004750793]. This interval triggers the fixed verdict. Other
primary results are unresolved, except POST restored wall time, whose interval
supports no increase. The receipt contains every primary and checkpoint-producer
interval, classification, raw median, minimum, and maximum.

## Retained evidence

- `measurements.csv` contains every observation in execution order: 320 primary
  cold/restored observations and 160 checkpoint producers. CPU observations retain
  the original user/system tick readings and deltas, at 100 ticks per second.
- `receipt.json` binds the plan, tools, both source-built packages and plugins,
  ROMs, original boundary drivers, native source, raw manifest, raw JSONL, and
  evaluated summary by their exact hashes. It contains the complete verdict,
  compact metrics, and the original execution witnesses. Host process IDs,
  private source paths, and repeated JSON arrays are omitted from this published
  projection; the original diagnostic files remain unchanged.
- The earlier independent 40-pair confirmation also failed the no-regression
  requirement. Its retained manifest and sample hashes are recorded. No earlier
  observation is pooled into this result.

The native baseline is `33343f63cb5e8749caadcb251c6b8a90ed0482cf`, from AOS
`ee8712f2a6bfb2e63748720068f215a44f293522`. The measured current native source is
`0bc0488b5f2aae1a7404a8b42eedfadd97eba10d`. Each variant uses its own matching
source-built plugin and original boundary driver. Both ROM byte streams and
normalized guest commands are identical.

## Fixed method and interpretation

The plan fixed 40 pairs for each BIOS/POST workload and cold/restored mode on
CPU 511. Baseline runs first in even pairs; current runs first in odd pairs.
Each variant runs cold execution, a checkpoint producer, and execution restored
from that producer. The stop is 240,000,000 retired instructions; the producer
stops at 120,000,000. All 480 observations are retained. There is no exclusion,
optional stopping, pooling, changed margin, or timing-based retry.

The wall interval is the original QMP continue to authenticated exact stop.
Register/memory observations, checkpoint transfer, and cleanup occur outside that
wall interval. The diagnostic reads of process CPU counters straddle the original
wall interval; their collection times remain in the original receipt. Runqueue
accounting was disabled. Raw scheduling readings are retained there, with
availability explicitly false and interpreted scheduling totals null. No global
kernel policy was changed.

An increase is detected when any primary wall/CPU paired log-ratio interval has
its lower endpoint greater than 1. Support for no regression requires every
primary interval's upper endpoint at most 1, plus every current raw median and
maximum at most its corresponding baseline value. Otherwise, no regression is
not demonstrated. These are individual normal approximate intervals, without a
multiple-comparison adjustment. CPU readings are quantized; a raw maximum alone
does not establish a CPU cause.

## Reproduction

Use the exact package/tool hashes in `receipt.json`, source-built with the AOS
toolchain. The matching fixture target is
`aos-dev --release build check crucible.phase2.tcgPerformanceFixtures --no-out-link`.
Preserve each variant's original `tests/crucible/tcg-performance.py` from its
source snapshot. Bind a fresh `crucible.resident.confirmation-plan.v1` plan to
those paths, hashes, normalized commands, kernel, available CPU affinity, and
the unchanged method before executing it. A fresh plan must name a new output
directory; it must not overwrite or append to these observations.

After a coordinated quiet window, run the source-built Python interpreter with:

```sh
python3 -B tests/crucible/resident-performance-profile.py \
  --baseline-source "$BASELINE_SOURCE" --baseline-qemu "$BASELINE_QEMU" \
  --baseline-fixtures "$BASELINE_FIXTURES" \
  --current-source "$CURRENT_SOURCE" --current-qemu "$CURRENT_QEMU" \
  --current-fixtures "$CURRENT_FIXTURES" \
  --cpu 511 --pairs 40 --stop 240000000 --checkpoint 120000000 \
  --timeout 120 --plan "$NEW_BOUND_PLAN" --output "$NEW_RECEIPT"

python3 -B tests/crucible/resident-performance-summary.py \
  --plan "$NEW_BOUND_PLAN" --receipt "$NEW_RECEIPT" --output "$NEW_SUMMARY"
```

The tools refuse changed bindings or incomplete/reordered observations. The
summary repeats the independent original-driver oracle checks before applying
the fixed verdict. The current command writes the complete summary and exits
unsuccessfully for both a detected regression and unproved parity; only support
for no regression returns success. Bind that evaluator's hash in each new plan.
Historical plans and their retained evaluator identities remain unchanged.
The CSV is a compact projection of the unchanged raw receipt;
the raw receipt is the input to the evaluator.

## Scope

This is a resident component execution comparison. Its RAM witness is the
existing 256-byte physical window at `0x7000`, including an independent
eight-byte arithmetic prefix. It is not a canonical whole-RAM identity. It does
not qualify managed campaign execution, kernel paging, whole-RAM identity or
checkpoint costs, or deployment behavior. No broader performance or
no-regression claim follows from these measurements.
