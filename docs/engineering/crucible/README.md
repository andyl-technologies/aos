# Crucible engineering

Crucible is AOS's hermetically deterministic multi-VM simulation harness. It
boots unmodified guest kernels under a patched QEMU TCG build with
instruction-count virtual time, drives every machine from one authoritative
scheduler, and records the decisions that make a run reproducible. A run is a
pure reduction of an immutable scenario definition under a recorded schedule:

```text
ScenarioDef   = World + Plan + Properties + Seed
Configuration = ScenarioDef + Schedule
State(t)      = reduce(ScenarioDef, Schedule[0..t])
```

Start, resume, and fork are therefore the same operation, and save, replay,
search, and debugging all operate on one content-addressed execution graph.

These pages describe how the implementation under `crates/crucible/`,
`pkgs/emulation/`, `pkgs/tools/crucible*`, and `tests/crucible/` works and why.
Operator and user documentation lives in [`docs/users/crucible/`](../../users/crucible/README.md);
the license and process-boundary policy lives in
[`docs/legal/licensing.md`](../../legal/licensing.md).

## Layers

```text
  L4  control plane       crucible-session, crucible-control-api,
                          crucible-control-client, crucible-control-server,
                          crucible-daemon, crucible-cli (command: crucible),
                          crucible-store-s3
  L3  engine              crucible-engine: scenario model, scheduler, faults,
                          assertions, event log, temporal graph;
                          crucible-store, crucible-campaign
  L2  QEMU integration    crucible-qemu-host (host), crucible-qemu-plugin
                          (loaded into QEMU), crucible-guest,
                          crucible-qemu-debug-gateway
  L1  co-sim transport    crucible-qemu-shmem (ABI), crucible-qemu-protocol,
                          crucible-device (disk, 9p, and network sub-nodes)
  L0  deterministic core  crucible-determinism
```

Each layer has its own determinism gate, and higher layers build only on
lower layers whose gates are green. See [crate structure](crate-structure.md)
for the complete crate map and dependency rules.

## Reading order

For a first pass through the code, read these five pages in order:

1. [Architecture](architecture.md) for the processes, crates, and data flow.
2. [Glossary](glossary.md) for the vocabulary; keep it open while reading
   the rest.
3. [Execution model](execution-model.md) for the state type and the reduction
   every other page builds on.
4. [Scheduling](scheduling.md) for how a quantum advances the system.
5. [Testing and gates](testing-and-gates.md) for what to run before sending a
   change.

After that, go to the page for the crate you are changing;
[crate structure](crate-structure.md) maps each crate to its page.

## Pages

Foundations:

- [Architecture](architecture.md): processes, layers, and data flow.
- [Glossary](glossary.md): vocabulary used throughout the code.
- [Determinism contract](determinism.md): what is bit-identical, and how
  each entropy source is eliminated.
- [Virtual time](virtual-time.md): instruction-count clocks and ceilings.
- [Execution model](execution-model.md): `Configuration`, `step`,
  `instantiate`, and `bake`.
- [Scenario model](scenario-model.md): the immutable scenario definition.
- [Execution graph](execution-graph.md): the content-addressed checkpoint DAG.
- [Scheduling](scheduling.md): the single authoritative scheduler.

QEMU integration and transport:

- [QEMU integration](qemu-integration.md): host-side launch and supervision.
- [QEMU patch](qemu-patch.md): the atomic QEMU integration patch.
- [QEMU plugin](qemu-plugin.md): the in-QEMU plugin.
- [Shared-memory ABI](shmem-abi.md): the public data-plane layout.
- [Control protocol](control-protocol.md): the host/plugin socket protocol.
- [I/O sub-nodes](io-subnodes.md): deterministic disk, 9p, and network devices.
- [Guest/host channel](guest-host-channel.md): the optional guest doorbell.

Semantics:

- [Conditions and triggers](conditions-and-triggers.md): the event graph and
  fault injection.
- [Fault model](fault-model/README.md): the signal-driven fault model.
- [Assertions](assertions.md): properties and their evaluation.
- [Event log](event-log.md): the canonical observable record of a run.

Control plane:

- [Session](session.md): the session actor and its command set.
- [Control API](control-api.md): RPC ABI, clients, server, and daemon.
- [CLI internals](cli.md): how the `crucible` command routes work.

Exploration and debugging:

- [Exploration](exploration.md): fork, replay, search, and fuzzing.
- [Failure triage](failure-triage.md): signatures, clustering, minimization.
- [Distributed exploration](distributed-exploration.md): the shared store and
  fleet execution.
- [Campaigns](campaigns/README.md): persistent, multi-run exploration
  campaigns.
- [Time-travel debugging](time-travel-debugging.md): gdb attach and reverse
  execution.

Building and qualifying:

- [Testing and gates](testing-and-gates.md): the layered determinism harness.
- [Engineering standards](engineering-standards.md): Crucible-specific checks.
- [Crate structure](crate-structure.md): crates, layers, and dependencies.
- [Performance](performance.md): the cost model and measured checks.
- [Packaging](packaging.md): the Nix packages and release components.
- [Workloads](workloads.md): in-guest workloads and worked examples.
