# Operating Crucible

Crucible is AOS's deterministic multi-VM simulation harness for testing systems
whose failures depend on timing and event order. It runs guest machines under a
patched build of QEMU's software emulator (TCG, the Tiny Code Generator),
advances them under one authoritative scheduler, and
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
execution. Save, resume, replay, and search all operate on the same
content-addressed execution graph.

## Terms

These terms recur throughout the guide:

- **Content-addressed**: named by the BLAKE3 hash of its bytes, written
  `blake3:<64 lowercase hexadecimal digits>`.
- **Admission**: the validation a scenario, plan, or checkpoint must pass
  before any guest starts.
- **Fail closed**: refuse the operation instead of continuing with missing,
  mismatched, or unverified state.
- **Scheduler quantum**: one bounded slice of execution between two points at
  which the scheduler pauses the world; `--max-quanta` counts these.
- **Reduction**: one independent execution of a scenario and schedule, as in
  `reduce(ScenarioDef, Schedule)` above. `verify` compares reductions.
- **Fingerprint**: a digest of deterministic machine and modeled state taken
  at an admitted boundary and compared between executions.
- **Frontier**: the alternate choices reachable from an execution prefix that
  search or a campaign may still explore.
- **Adapter**: the component that applies fault effects in one domain, such
  as network, storage, or node.
- **White-box channel**: the optional guest-host channel through which a
  guest reports typed markers and requests application randomness.
- **Reproduction artifact**: the self-contained `.crucible` file that `replay`
  consumes. One written for a non-passing result is also called a failure
  artifact.

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

From the repository root, enter the development shell with `nix develop`
(or use the repository's direnv configuration), then build the complete suite:

```sh
aos-dev build package crucible
```

The result includes the `crucible` CLI, patched QEMU, matching plugin, Crucible
kernel, and fixture root image. The CLI has compile-time paths to the matching
artifacts, so a packaged invocation normally needs no discovery flags.
`aos-dev` is the repository's source-built development entry point at
`tools/dev/aos-dev`. The command above creates `./result`; omitting the output
link with `--no-out-link` requires using the returned store path instead.

Run the live QEMU self-test before authoring or investigating a scenario:

```sh
./result/bin/crucible selftest
```

The production command runs the live QEMU gates by default. It fails closed if
it cannot discover and validate a matched QEMU/plugin pair. Its live probes
also load the provisioned campaign-executor deployment described under
[First run](#first-run), so the self-test passes only on a provisioned host.

## First run

Local QEMU runs require a durable `CRUCIBLE_RUN_STATE_ROOT` and a provisioned
campaign-executor deployment. An administrator must supply the dedicated
cgroup-v2 and ext4 project-quota roots described in
[campaign setup](campaigns.md#start-the-single-host-owner). Building the package
does not provision these host resources. Select the owner-only deployment file
with `--campaign-deployment`, `CRUCIBLE_CAMPAIGN_DEPLOYMENT`, or the default
`/etc/crucible/packaged-executor.toml`.

After provisioning, set the paths for this shell:

```sh
mkdir -p .crucible/run-state
export CRUCIBLE_RUN_STATE_ROOT="$PWD/.crucible/run-state"
export CRUCIBLE_CAMPAIGN_DEPLOYMENT=/path/to/campaign-executor.toml
```

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
fault-campaign.fam
```

The `.scn` names identify built-in scenarios. `fault-campaign.fam` identifies
the built-in family used by `fuzz`.

## Operational workflow

The usual progression is:

1. Run `selftest` to validate the packaged backend.
2. Run a scenario with an explicit seed and bounded terminal condition.
3. Inspect the event log and branch on the process exit code.
4. Use `verify` to compare independent reductions.
5. Replay any emitted failure artifact before changing the scenario.
6. Save or resume when investigating a particular execution prefix; use
   `campaign branch` for an authenticated alternate Campaign decision.
7. Use bounded `search` or `fuzz` only after ordinary runs are deterministic.
8. Cluster findings retained by a campaign snapshot with `triage`.

## Guide map

Start with the [representative-scenario quickstart](quickstart.md). It builds
the suite, generates a three-VM nginx, curl, and I/O-probe scenario through the
public Rust API, and installs its content-addressed I/O objects before execution.

After the quickstart, the remaining pages are grouped by task.

**Start here**

- [Support boundaries](support.md) distinguishes packaged operator features,
  public APIs, repository certification surfaces, model-only behavior, and
  deliberately rejected device concepts.
- [Scenarios](scenarios.md) explains scenario identity, authoring, and input
  resolution.
- [Running Crucible](running.md) covers backend discovery, seeds, terminal
  conditions, output, and exit codes.

**Author**

- [Authoring fault scenarios](authoring.md) walks through the complete
  World/topology/signal/binding/property/artifact pipeline.
- [Signal-driven faults](signal-driven-faults.md) explains how to model static,
  recorded, spatial, sporadic, shared-cause, network, storage, and node faults.
- [Signal programs](signals.md) documents all source, pure, and stateful signal
  families, their typing rules, bounds, checkpoint state, and replay contract.
- [Fault bindings](bindings.md) documents sampling, selectors, mappings,
  opportunity filters, phases, lifetimes, composition, search, and evidence.
- [Fault topology reference](topology.md) documents every fault-domain,
  network, storage, policy, and node-capability declaration.
- [Network faults](network-faults.md) covers route topology, directional
  outages, loss, delay, queues, forwarders, shared media, assertions, and
  replay.
- [Storage, node, and hardware faults](storage-node-faults.md) covers block,
  9p, lifecycle, CPU, interrupt, memory, clock, and accelerator effects.
- [Recorded signal inputs](recorded-signals.md) documents deterministic CSV,
  JSONL, PCAP, and PCAPNG import, provenance, storage, and runtime attachment.
- [Properties, observations, and verdicts](properties-and-evidence.md) explains
  the complete assertion vocabulary and how effect evidence becomes a verdict.
- [Fault experiment cookbook](cookbook.md) provides end-to-end patterns for
  outages, hazards, congestion, corruption, power loss, recordings, hardware,
  arrays, contacts, and bounded exploration.
- [Rust integration API](rust-api.md) maps scenario generation, production
  lifecycle, control clients, streaming, RPC, debug, and import surfaces.

**Run and reproduce**

- [Reproduction and branching](reproduction.md) explains `verify`, artifacts,
  `replay`, `save`, and `resume`.
- [Stores and artifacts](artifacts.md) distinguishes scenarios, DAG objects,
  checkpoints, handles, reproduction artifacts, findings, and reports.
- [Interactive control and debugging](debugging.md) covers the current
  interactive and debugger surfaces.
- [CI](ci.md) shows a bounded, reproducible pipeline with retained failure
  artifacts.
- [Troubleshooting](troubleshooting.md) maps common failures to corrective
  action.

**Explore**

- [Exploration](exploration.md) covers bounded search, fuzzing, and triage.
- [Lazy campaigns](campaigns.md) covers the single-host campaign repository,
  verified import, lifecycle control, authenticated inspection, and current
  executor-attachment boundary.

**Operate**

- [Daemon operation](daemon.md) documents the remote control plane and its
  current fidelity limitation.
- [Lazy campaigns](campaigns.md#start-the-single-host-owner) also describes
  the host resources and deployment file that local QEMU runs require.

**Reference**

- [Reference](reference.md) lists every command and option and the canonical
  scenario schema.
- [Feature coverage](coverage.md) inventories every packaged command, model
  surface, topology family, signal family, effect adapter, evidence path, and
  continuation workflow.
- [Certification examples](examples.md) maps supported domains to executable
  examples and named repository checks.

## Feature coverage map

| Goal | Start here | Exhaustive details |
|---|---|---|
| Audit whether a feature is documented | [Feature coverage](coverage.md) | Implementation registry and coverage tests |
| Decide whether a surface is operationally supported | [Support boundaries](support.md) | [Reference](reference.md) |
| Build and run a first workload | [Representative-scenario quickstart](quickstart.md) | [Running Crucible](running.md) |
| Generate a signal-driven scenario | [Authoring fault scenarios](authoring.md) | [Signals and bindings](reference.md#plans-signals-bindings-and-faults) |
| Declare fault-addressable objects | [Fault topology reference](topology.md) | [Canonical scenario reference](reference.md#canonical-scenario-document) |
| Simulate network failures | [Network faults](network-faults.md) | [Effect registry](reference.md#exhaustive-effect-registry) |
| Simulate storage, VM, or hardware failures | [Storage, node, and hardware faults](storage-node-faults.md) | [Effect registry](reference.md#exhaustive-effect-registry) |
| Use recorded physical or packet data | [Recorded signal inputs](recorded-signals.md) | [Trace API](../../../crates/crucible/crucible-engine/src/model/fault_signal/trace_import.rs) |
| Reproduce or explore a failure | [Reproduction and branching](reproduction.md), [Exploration](exploration.md) | [Command reference](reference.md#command-line-interface) |
| Find a production-backed example | [Certification examples](examples.md) | Repository Nix checks and crate rustdoc |

## Stability and source of truth

Crucible is experimental, and its command surfaces may evolve. For current
command syntax, `crucible --help`, `crucible <command> --help`, and the Rust CLI
implementation are authoritative. This guide describes shipped behavior and
labels incomplete surfaces rather than silently promising future functionality.
