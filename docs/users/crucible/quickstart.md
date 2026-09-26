# Quickstart

This walkthrough creates the current representative scenario, installs its
content-addressed I/O objects, and runs it with the packaged QEMU backend.

## Build Crucible

From the repository root:

```sh
nix build .#pkg-crucible
```

The package includes `crucible` and the scenario generator used by the
end-to-end determinism checks.

## Generate the canonical scenario

```sh
./result/bin/crucible-e2e-determinism-scenario \
  --emit-scenario > representative.scenario.toml
```

The generator uses the typed Rust model and computes every content identity.
Inspect the emitted TOML before running it; unknown fields and invalid closed
vocabularies fail closed.

## Populate the object store

The scenario references immutable block and 9p objects. Install them into a
local content-addressed store:

```sh
mkdir -p .crucible/store
./result/bin/crucible-e2e-determinism-scenario \
  --populate-store .crucible/store
```

## Run the scenario

Production QEMU execution requires a durable run-state root:

```sh
mkdir -p .crucible/run-state
CRUCIBLE_RUN_STATE_ROOT="$PWD/.crucible/run-state" \
  ./result/bin/crucible \
  --store .crucible/store \
  --artifact-dir .crucible/artifacts \
  run representative.scenario.toml \
  --until property \
  --save-on fail
```

Crucible discovers the matched packaged QEMU and plugin, admits one guarded
process generation, and evaluates the scenario properties from the canonical
event log. A failed run retains evidence beneath `.crucible/artifacts`.

## Verify determinism

Run the same scenario twice and compare canonical fingerprints and logs:

```sh
CRUCIBLE_RUN_STATE_ROOT="$PWD/.crucible/run-state" \
  ./result/bin/crucible \
  --store .crucible/store \
  --artifact-dir .crucible/artifacts \
  verify representative.scenario.toml \
  --runs 2
```

Continue with [scenario authoring](scenarios.md), [signal-driven faults](signal-driven-faults.md),
and the complete [command reference](reference.md).
