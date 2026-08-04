# Exploration

Exploration is useful only after an ordinary run is deterministic. If repeated
reductions disagree, investigate with `verify --bisect` before expanding the
schedule space; otherwise search results mix system behavior with harness drift.

## State-space search

`search` expands the temporal graph under a bounded policy:

```sh
./result/bin/crucible \
  --format table \
  --seed 0x2a \
  search scenario.toml \
  --strategy bfs \
  --max-depth 64 \
  --max-states 1000 \
  --on-violation stop
```

The strategies are:

- `bfs` — breadth-first expansion; this is the default.
- `dfs` — depth-first expansion.
- `guided` — coverage-guided frontier selection.

`--max-states` defaults to `1`, which is intentionally conservative but rarely
useful for a real campaign. Set both state and depth bounds explicitly in CI.

`--on-violation` defaults to `stop`; `collect` is the alternate policy value.
The current production QEMU loop still explores its supplied bound after a
failure under either value and exports only the first discovered counterexample,
so do not use `collect` as a multiple-artifact retention mechanism yet. A
counterexample exits with status `1` and produces a normal reproduction artifact.

Advanced searches may load schedule-named assertion truths:

```sh
--schedule-named-truths truths.toml
```

The retained-evidence input visible in source is an internal gate surface and
is hidden from production help. Do not build operator workflows around it.

Search is currently local. `--daemon` search is rejected.

## Coverage-guided fuzzing

`fuzz` samples a `ScenarioFamily`, runs concrete pinned scenarios, and feeds
basic-block coverage back into later selection:

```sh
./result/bin/crucible \
  --format table \
  --seed 0x2a \
  fuzz builtin:fault-campaign \
  --runs 100 \
  --coverage basic-block \
  --corpus .crucible/corpus
```

The family may be supplied as a positional argument or with `--family`, but not
both. Accepted sources are:

- `builtin:fault-campaign`;
- a family TOML file; or
- a `blake3:<hash>` in `--store`.

Only `basic-block` coverage is currently exposed. `--runs` defaults to `1`.
Use an explicit seed for the campaign identity and an explicit corpus directory
if accepted cases must survive between invocations.

The production QEMU driver currently treats this command as a coverage and
corpus campaign. It does not promote a failed or timed-out iteration to a
non-passing `fuzz` outcome or emit a failure artifact. Use bounded `search`, or
run retained scenarios directly, when failure classification and artifact
capture are required.

The built-in fault campaign also has a deterministic proof path used by the
repository gates. It is useful as a workflow smoke test, not as evidence that a
user family exercises every live-QEMU exploration path.

Fuzzing is currently local. `--daemon` fuzz is rejected.

## Findings and triage

`triage` is offline: it loads a findings ledger, groups failures by signature,
optionally minimizes representatives, stores the result, and writes reports.

```sh
./result/bin/crucible \
  --format markdown \
  triage findings.crucible-findings \
  --policy default \
  --minimize representative \
  --report .crucible/triage
```

Signature policies are `coarse`, `default`, `fine`, and `exact`. Finer policies
split more findings; coarser policies are more aggressive about grouping.

Minimization modes are:

- `none` — report representatives unchanged;
- `representative` — minimize one deterministic representative per cluster;
- `all` — minimize every selected representative.

Use `--recompute-signatures` when auditing a retained ledger. It recomputes
signatures and fails if discovery-time signature bytes drift.

Compare a result with another content-addressed triage result using:

```sh
--compare <blake3:result-hash>
```

By default, triage reports go to `--artifact-dir`, and triage objects use the
same default `<artifact-dir>/store` as other offline operations.

The current implementation requires an engine-owned signed findings ledger with
discovery-time signature evidence. Although the input loader accepts a
directory or one reproduction artifact, a non-empty artifact-only input is
rejected because it cannot reconstruct those signatures. No installed CLI
command currently assembles a signed ledger from ordinary `search` or `fuzz`
output; the example above therefore assumes a ledger produced by repository
checks or internal campaign orchestration.

## Distributed campaigns

The repository contains a shared DAG-store implementation and extensive fleet
campaign invariants, but the installed `crucible-fleet-store` binary currently
exposes a conformance `probe` rather than a complete campaign administration
CLI. Operate distributed campaigns through repository checks and internal
orchestration for now; do not infer a stable public workflow from the lower-level
libraries or conformance checks.
