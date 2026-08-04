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

A non-passing `run` or `search` result normally writes a self-contained
`.crucible` artifact below `--artifact-dir`; `verify` writes paired side
artifacts when both divergent reductions carry producer provenance. It records:

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

The current production `fuzz` driver records coverage and corpus admissions but
does not yet promote a failing iteration into a non-passing command outcome or
export its reproduction artifact. Do not rely on `fuzz` alone as a failure
retention boundary.

## Replay

Replay validates the artifact schema and requires an exact producer/consumer
build-identity match before reducing embedded scenario and schedule material:

```sh
./result/bin/crucible replay .crucible/repro-failed-<digest>.crucible
```

This command currently performs a pure model reduction from embedded artifact
components. It does not relaunch the guest VMs under QEMU. Treat it as an
identity-checked schedule and state reproduction proof, not yet as live VM
record/replay.

Compare the artifact's canonical log with a retained log file:

```sh
./result/bin/crucible \
  replay failure.crucible \
  --check original.jsonl
```

The comparison is byte-for-byte. The file must use the canonical entry encoding
captured by the artifact, not a table rendering.

Bisect two artifacts:

```sh
./result/bin/crucible \
  replay failing.crucible \
  --bisect passing.crucible
```

A `--check` mismatch or bisection divergence exits with status `1`.

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
a local workflow; remote daemon fork is not implemented.

## Artifact portability

Reproduction deliberately fails on a build-identity mismatch. Move the matching
Crucible package closure with an artifact, or rebuild the exact revision that
produced it. A newer binary is not automatically a valid replay consumer even
when its artifact schema is compatible.
