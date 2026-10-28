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
                          crucible-daemon, crucible-cli (command: crucible)
  L3  engine              crucible-engine: scenario model, scheduler, faults,
                          assertions, event log, temporal graph
  L2  QEMU integration    crucible-qemu-host (host), crucible-qemu-plugin
                          (loaded into QEMU), crucible-guest
  L1  co-sim transport    crucible-qemu-shmem (ABI), crucible-qemu-protocol,
                          crucible-device (disk, 9p, and network sub-nodes)
  L0  deterministic core  crucible-determinism
```

Each layer has its own determinism gate, and higher layers build only on
lower layers whose gates are green. See [crate structure](crate-structure.md)
for the complete crate map and dependency rules.

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
- [Time-travel debugging](time-travel-debugging.md): gdb attach and reverse
  execution.

Building and qualifying:

- [Testing and gates](testing-and-gates.md): the layered determinism harness.
- [Engineering standards](engineering-standards.md): Crucible-specific checks.
- [Crate structure](crate-structure.md): crates, layers, and dependencies.
- [Performance](performance.md): the cost model and measured checks.
- [Packaging](packaging.md): the Nix packages and release components.
- [Workloads](workloads.md): in-guest workloads and worked examples.
