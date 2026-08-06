# Reproduction and branching

Crucible's central operating rule is to preserve the scenario, seed, and
recorded schedule together. A seed can reproduce deterministic choices made
from that seed, but a failure artifact is the stronger handoff: it also pins the
resolved schedule and producer build identity.

## Verify repeated execution

`verify` runs independent reductions and compares their canonical logs and
fingerprint streams:

```sh
./result/bin/crucible \
  --seed 0x2a \
  verify scenario.toml \
  --runs 5
```

Add `--adversarial` to exercise the hostile host-condition matrix and `--bisect`
to identify the first divergent state if reductions disagree:

```sh
./result/bin/crucible \
  --seed 0x2a \
  verify scenario.toml \
  --runs 8 \
  --adversarial \
  --bisect
```

A divergence exits with status `1`. When producer provenance is available,
Crucible writes side artifacts for the disagreeing executions.

To compare two existing artifacts without running the scenario again:

```sh
./result/bin/crucible verify --compare run-a.crucible run-b.crucible
```

## Failure artifacts

A non-passing `run`, `search`, or `fuzz` result normally writes a self-contained
`.crucible` artifact below `--artifact-dir`; collect-mode exploration writes one
artifact per retained finding, and `verify` writes paired side artifacts when
both divergent reductions carry producer provenance. It records:

- the resolved seed;
- engine, protocol, QEMU, patch-series, and plugin identity;
- canonical scenario material;
- the recorded decision schedule;
- canonical log and fingerprint evidence; and
- embedded model-reproduction material where the producer supplied it.

In table mode, the failure footer prints copy-pasteable `replay` and `debug`
commands. JSON/JSONL records the artifact digest in the final outcome but does
not add the host path to the canonical log; locate the matching `repro-*.crucible`
file below `--artifact-dir`.

Search and fuzz also emit a signed `.crucible-findings` ledger that can be passed
directly to `triage`. Use `--findings-out <path>` for a fixed ledger location;
otherwise it is content-addressed below `<artifact-dir>/findings`.

## Replay

Replay validates the artifact schema and requires an exact producer/consumer
build-identity match. Current production artifacts use the v3 schema; v2
artifacts are rejected instead of falling back to model-only replay. A v3 QEMU
artifact contains the compact scenario, typed schedule, pure model proof, live
replay recipe, canonical QEMU event bytes, and typed execution-fingerprint
evidence. Run, verify, and fuzz artifacts retain the full sample stream. Search
and fork artifacts retain a declared terminal snapshot containing exactly one
sample for every VM node:

```sh
./result/bin/crucible replay .crucible/repro-failed-<digest>.crucible
```

Replay first executes the required pure `reduce(ScenarioDef, Schedule)`
preflight. It then launches fresh guest VMs through the packaged QEMU/plugin
backend, reapplies recorded branch, fault, and network inputs, executes the
recorded non-interactive startup and initial controls, and
requires the terminal tuple, event stream, and fingerprint stream to match the
producer byte-for-byte. There is no production model-only success path.

Interactive failure-artifact capture is not supported yet. Crucible rejects it
instead of recording command names without the exact decision/frontier timing
needed to replay them.

Compare the artifact's canonical log with a retained log file:

```sh
./result/bin/crucible \
  replay failure.crucible \
  --check original.jsonl
```

The comparison is byte-for-byte. The file must use the canonical JSONL entry
encoding written by `--trace`, not a table rendering. The live QEMU replay and
its embedded event/fingerprint comparisons still run before this retained-log
check.

Bisect two artifacts:

```sh
./result/bin/crucible \
  replay failing.crucible \
  --bisect passing.crucible
```

Both artifacts are independently replayed through fresh QEMU sessions before
bisection compares their canonical evidence. A `--check` mismatch or bisection
divergence exits with status `1`.

With `--to <savepoint>`, Crucible completes the same live artifact replay, then
proves that the requested savepoint is a typed schedule prefix and validates its
materialization through the replay oracle. The savepoint handle or checkpoint
object must remain available in the selected store. A v3 artifact's own
terminal checkpoint hash is self-contained: Crucible reconstructs that target
from the embedded scenario, schedule, and recorded frontier when the store does
not contain a separate checkpoint object.

## Savepoints

`save` runs to a deterministic boundary, materializes a checkpoint, validates
it against the replay oracle, and exports a `.crucible-savepoint` handle.

Save at virtual time:

```sh
./result/bin/crucible \
  save scenario.toml \
  --at virtual-time \
  --max-virtual-time 20s \
  --label before-election
```

Other boundaries are:

```sh
--at quiescence
--at property --property <assertion-name>
--at marker --marker <guest-marker-name>
```

Use `--out <path>` to choose the handle path. Otherwise it is written below
`--artifact-dir`. Crucible does not export a handle if replay-oracle validation
fails.

## Resume

Resume accepts a savepoint handle or a direct `blake3:<checkpoint>` reference:

```sh
./result/bin/crucible \
  resume .crucible/savepoint-before-election-<digest>.crucible-savepoint
```

Direct checkpoint hashes require the same `--store` used when the checkpoint
was created. A savepoint handle carries scenario and schedule evidence, but its
referenced store objects must still be resolvable when they were not embedded.

`resume` supports the same `--until`, `--max-virtual-time`, `--interactive`, and
`--watch` controls as `run`.

## Fork

Fork creates an independent child from a validated execution prefix:

```sh
./result/bin/crucible \
  --seed 0x2b \
  fork .crucible/savepoint-before-election-<digest>.crucible-savepoint \
  --label alternate-seed
```

Alternatively, override recorded decisions with repeatable
`--override decision=value` arguments:

```sh
./result/bin/crucible \
  fork savepoint.crucible-savepoint \
  --override 'delivery-order=db-3-first' \
  --label alternate-delivery
```

An explicit fork seed and decision overrides are mutually exclusive. Override
keys and values are interpreted by the decision being replaced; inspect the
recorded schedule before constructing them.

Fork writes a child `.crucible` artifact below `--artifact-dir`. It is currently
a local workflow; remote daemon fork is not implemented. An unchanged fork
records an explicit resume recipe from the retained base. Reseeded and override
forks record their branch coordinates, and replay forces only decisions owned by
the post-branch suffix.

## Artifact portability

Reproduction deliberately fails on a build-identity mismatch. Move the matching
Crucible package closure with an artifact, or rebuild the exact revision that
produced it. A newer binary is not automatically a valid replay consumer even
when its artifact schema is compatible.
