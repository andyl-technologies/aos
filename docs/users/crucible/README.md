# Operating Crucible

Crucible is AOS's deterministic multi-VM simulation harness for testing systems
whose failures depend on timing and event order. It runs guest machines under a
patched QEMU TCG build, advances them under one authoritative scheduler, and
records the decisions needed to reproduce and explore an execution.

Crucible is currently an experimental developer tool. The local packaged-QEMU
path is the primary supported operating mode. Remote execution, distributed
campaigns, and some debugging workflows have narrower implementations than
their command surfaces suggest; this guide calls those differences out
explicitly.

## The model

A scenario has four independent inputs:

```text
ScenarioDef = World + Plan + Properties + Seed
```

- **World** declares VM nodes, links, and their fixed configuration.
- **Plan** declares faults and actions that may affect the world.
- **Properties** grade the observed execution.
- **Seed** is the root of every deterministic choice.

A run adds a recorded schedule of decisions:

```text
Configuration = ScenarioDef + Schedule
State(t) = reduce(ScenarioDef, Schedule[0..t])
```

This distinction matters operationally. A `Plan` says what may happen; a
`Schedule` records what did happen. A checkpoint is a position in that recorded
execution. Save, resume, fork, replay, and search all operate on the same
content-addressed execution graph.

## When to use it

Crucible is a good fit when you need to:

- reproduce a distributed-systems failure from the same scenario and schedule;
- test partitions, loss, reordering, crashes, restarts, or deterministic I/O;
- compare repeated executions for canonical-log or fingerprint divergence;
- branch from a known execution point to test an alternate decision; or
- search a bounded schedule space and retain self-contained findings.

It is not a real-time benchmark, a model checker, a unit-test framework, or a
general-purpose VM manager. Application traffic originates in the guests.
Crucible observes and schedules it; it is not a host-side load generator.

## Prerequisites

- A Linux host supported by the repository flake (`x86_64-linux` or
  `aarch64-linux`).
- Nix with flakes enabled.
- Enough CPU, memory, and storage for the guest topology.

Crucible uses QEMU TCG, not KVM. KVM is not required. The packaged production
path is currently wired to `qemu-system-x86_64`; treat AArch64 guest support in
the scenario schema as an implementation surface, not a documented operator
support guarantee.

## Build and smoke-test the package

Build the complete hermetic closure from the repository root:

```sh
nix build .#pkg-crucible
```

The result includes the `crucible` CLI, patched QEMU, matching plugin, Crucible
kernel, and fixture root image. The CLI has compile-time paths to the matching
artifacts, so a packaged invocation normally needs no discovery flags.

Run the live QEMU self-test before authoring or investigating a scenario:

```sh
./result/bin/crucible selftest
```

The production command runs the live QEMU gates by default. It fails closed if
it cannot discover and validate a matched QEMU/plugin pair.

## First run

Run the built-in happy-path scenario with an explicit seed:

```sh
./result/bin/crucible \
  --seed 0x2a \
  run builtin:happy-path.scn
```

When standard output is a terminal, the default rendering is a human-readable
table. When output is redirected or piped, the default is newline-delimited JSON
for automation. Pass `--format` when a command must use a fixed representation
regardless of its output destination.

Other built-in inputs are:

```text
builtin:partition-recovery.scn
builtin:crash-restart.scn
builtin:fault-campaign
```

The first three are scenarios. `builtin:fault-campaign` can also identify the
built-in family used by `fuzz`.

## Operational workflow

The usual progression is:

1. Run `selftest` to validate the packaged backend.
2. Run a scenario with an explicit seed and bounded terminal condition.
3. Inspect the event log and branch on the process exit code.
4. Use `verify` to compare independent reductions.
5. Replay any emitted failure artifact before changing the scenario.
6. Save, resume, or fork when investigating a particular execution prefix.
7. Use bounded `search` or `fuzz` only after ordinary runs are deterministic.
8. Cluster retained findings with `triage`.

## Guide map

Start with the [Nginx/Curl tutorial](quickstart.md). It builds the runtime and a
workload guest, generates a two-node scenario through the public Rust API, and
runs that scenario on the live QEMU backend.

For deeper work:

- [Scenarios](scenarios.md) explains scenario identity, authoring, and input
  resolution.
- [Running Crucible](running.md) is the command reference for backend discovery,
  seeds, terminal conditions, output, and exit codes.
- [CI](ci.md) shows a bounded, reproducible pipeline with retained failure
  artifacts.
- [Reference](reference.md) summarizes commands and the canonical scenario
  schema.
- [Signal-driven faults](signal-driven-faults.md) explains how to model static,
  recorded, spatial, sporadic, shared-cause, network, storage, and node faults.
- [Fault-model migration](fault-model-migration.md) explains the required
  one-way move to the signal-driven schema and why old plans are not translated.
- [Reproduction and branching](reproduction.md) explains `verify`, artifacts,
  `replay`, `save`, `resume`, and `fork`.
- [Exploration](exploration.md) covers bounded search, fuzzing, and triage.
- [Lazy campaigns](campaigns.md) covers the single-host campaign repository,
  verified import, lifecycle control, authenticated inspection, and current
  executor-attachment boundary.
- [Interactive control and debugging](debugging.md) covers the current
  interactive and debugger surfaces.
- [Daemon operation](daemon.md) documents the remote control plane and its
  current fidelity limitation.
- [Troubleshooting](troubleshooting.md) maps common failures to corrective
  action.

## Stability and source of truth

Crucible is experimental, and its command surfaces may evolve. For current
command syntax, `crucible --help`, `crucible <command> --help`, and the Rust CLI
implementation are authoritative. This guide describes shipped behavior and
labels incomplete surfaces rather than silently promising future functionality.
