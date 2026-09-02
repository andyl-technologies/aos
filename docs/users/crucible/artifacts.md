# Stores, artifacts, checkpoints, and findings

Crucible uses content-addressed objects for experiment inputs and exact
continuations. Several files are colloquially called “artifacts,” but they have
different portability and retention contracts. This guide separates them.

## Object types

| Object | Contains | Primary consumer | Portable by itself? |
|---|---|---|---|
| Canonical scenario | World, plan, properties, seed references, derived IDs | `run`, `verify`, `save`, `search` | Only when all referenced external objects are available. |
| DAG store object | Scenario forms, schedules, checkpoints, imported signal/spatial objects and chunks | lifecycle, continuation, search | No; retain its reachable closure. |
| Canonical trace | Ordered machine-readable execution/evidence records | CI, debugging, `replay --check` | Diagnostic evidence, not a continuation by itself. |
| Checkpoint | Exact scheduler, VM, adapter, signal, property, and object-closure state | `resume`, `fork`, replay/debug | Addressed through the store or embedded artifact. |
| Savepoint handle | Typed selector and proof naming a checkpoint | `resume`, `fork`, `debug`, `replay --to` | No; referenced store closure must remain available. |
| Reproduction artifact v3 | Authenticated inputs, schedule, live recipe, evidence scope, terminal checkpoint and reachable signal objects | `replay`, compare, bisect | Yes within its declared backend/build requirements. |
| Findings ledger | Signed search/fuzz findings and identities | `triage`, replay/minimize | Findings carry or reference self-contained reproduction material. |
| Triage report | Human/machine cluster, comparison, minimization output | operator/CI | Preserve alongside source ledgers and artifacts. |

Content hashes use `blake3:<64 lowercase hexadecimal digits>`. A hash proves
content identity; it does not fetch missing content from a remote service.

## Directory roles

`--artifact-dir` defaults to `./.crucible` and controls generated failure
artifacts, handles, ledgers, and reports. `--store` selects the DAG-store root
for commands that attach one. `--trace` writes the canonical event stream to a
chosen file. These paths may be placed under the same parent but are not
interchangeable.

Ordinary packaged `run` and `verify` do not currently attach `--store` as a
production lifecycle signal-artifact store. Direct Rust lifecycle integrations
provide world/signal artifacts explicitly. `search`, continuation, and replay
have their documented store/embedded-object paths. See
[Support boundaries](support.md) before designing trace-driven CLI automation.

## Scenario and external input closure

Canonical TOML includes content identities for kernel/root/initrd inputs,
block and 9p base data, normalized recordings, sampler tables, spatial data,
and policy artifacts. Admission resolves every required reference before useful
execution. A dangling object, wrong length, wrong schema, or hash mismatch is an
invalid-input failure, not a best-effort omission.

When creating a scenario through Rust:

- place immutable world objects in the world artifact store;
- import raw recordings into normalized content-addressed objects and retain raw
  provenance;
- pass world and signal stores through the lifecycle configuration;
- serialize the scenario only after all derived IDs are computed; and
- retain the reachable closure, not just the top-level manifest.

## Checkpoint contents

An exact checkpoint covers more than guest RAM and registers:

- scheduler coordinate, queues, decision frontier, timers, and RNG/key history;
- every VM process generation and QEMU/plugin identity;
- network frames, queues, routes, forwarding and association/contact state;
- storage requests, queues, cache and durability frontiers, media/controller/
  array/9p state;
- node lifecycle, CPU rules, interrupt/memory/clock/accelerator state;
- signal histories, state machines, stochastic state, and imported-object IDs;
- binding lifetime/composition state and search provenance; and
- property witnesses, deadlines, assertion phases, and observation cursors.

Checkpoint restoration validates the admitted scenario, closure, protocol
versions, scheduler semantics, and backend build identities. It fails closed on
mismatch instead of partially restoring.

## Savepoint handles

`save` stops at `virtual-time`, `quiescence`, `property`, or `marker` boundaries
and writes a v3 handle. The handle records the selected boundary, exact proof,
content-addressed predicate payload, scenario/frontier identity, and checkpoint
hash. Property and marker misses exit 3 without a handle; an explicit trace
still ends with `save_boundary_failure`.

The handle is a reference, not an archive. Preserve every store object reachable
from its checkpoint. Older v2 handles can be read but do not carry selector
provenance.

Use:

```sh
./result/bin/crucible --store .crucible/store save scenario.toml \
  --at marker --marker ready --out ready.savepoint

./result/bin/crucible --store .crucible/store resume ready.savepoint \
  --until quiescence
```

## Reproduction artifacts

A v3 failure artifact is the preferred portable handoff. It records the live
recipe and fingerprint evidence scope, scenario and schedule identity, backend
requirements, terminal outcome/checkpoint, and authenticated transitive signal
closure. If search mutated a trace or mapping, it also records the exact ordered
mutation recipe.

Restore verifies each embedded object into an isolated store. Production replay
then requires the matching packaged QEMU/plugin identity and re-executes the
recipe. Interactive command timing is not yet a reproducible live recipe and is
rejected where exact timing cannot be represented.

Useful operations:

```sh
./result/bin/crucible replay finding.crucible
./result/bin/crucible replay finding.crucible --check original.jsonl
./result/bin/crucible replay finding.crucible --to terminal-checkpoint
./result/bin/crucible replay finding-a.crucible --bisect finding-b.crucible
./result/bin/crucible verify --compare finding-a.crucible finding-b.crucible
```

`--check` requires byte-identical canonical JSONL after live replay. `--to`
validates a typed prefix; a v3 artifact can resolve its embedded terminal
checkpoint without an external store object. Compare and bisect distinguish
input, schedule, evidence, and terminal-fingerprint divergence.

## Search and fuzz findings

`search` and `fuzz` always write the requested signed findings ledger, including
an empty ledger. Each retained finding identifies the property/timeout outcome,
scenario materialization, schedule, coverage/evidence, and replay recipe.
`triage` authenticates ledgers, clusters equivalent failures, compares evidence,
and can minimize within declared budgets.

Do not treat arbitrary JSONL logs as findings ledgers. The signature and typed
identity are part of the input contract.

## Retention policy

For every CI failure retain:

1. canonical scenario TOML and root seed;
2. CLI version and QEMU/plugin build identities;
3. canonical JSONL trace;
4. reproduction artifact or savepoint plus its entire store closure;
5. findings ledger and triage report for search/fuzz; and
6. human diagnostics only as supplemental context.

Verify an exported reproduction artifact in a fresh process before expiring the
campaign store. A successful replay is the practical portability check.

## Integrity and failure behavior

Readers reject unknown versions, malformed content addresses, hash/length
mismatches, missing closure members, scenario/frontier disagreement, unsupported
backend identity, stale process generation, invalid boundary proof, and replay
evidence mismatch. Never repair these by editing hashes or handles. Recover the
original object or regenerate the complete canonical form.

Exit status 5 covers invalid scenario/artifact/store input; status 3 covers
replay-oracle or build-identity failure; status 1 covers a replay comparison
mismatch. Automation should preserve those distinctions.

See [Reproduction and branching](reproduction.md) for command workflows,
[Recorded signals](recorded-signals.md) for import objects, and
[Running Crucible](running.md#artifacts-and-store-layout) for global paths.

