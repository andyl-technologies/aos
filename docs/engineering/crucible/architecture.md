# Crucible architecture

Crucible is a deterministic multi-VM simulation harness. It boots unmodified
guest kernels under QEMU TCG with instruction-count virtual time, drives every
cross-machine interaction through one authoritative scheduler, and records the
run as a content-addressed graph of checkpoints. For a fixed scenario and
schedule, the whole multi-machine execution is reproducible, so a failure can
be replayed exactly and the space of schedules can be searched systematically.

This page is the map: the model the code implements, the processes and crates,
how data flows through a run, and the design decisions that shape the layout.
Each topic links to the page that owns its detail.

## The model in one paragraph

A run is a pure reduction of an immutable definition under a recorded sequence
of decisions:

```text
State(t) = reduce(ScenarioDef, Schedule[0..t])
```

The `ScenarioDef` is the spatial definition: World (nodes and links), Plan,
Properties, and Seed, content-addressed as one value. The `Schedule` is the
ordered list of `Decision`s the scheduler resolved. A `Configuration` is the
pair `(ScenarioDef, Schedule)` and is the only identity-bearing execution
state; live QEMU processes, memory images, and scheduler queues are caches of
it. The code organizes this as two graphs joined by one reduction:

```text
  SPATIAL GRAPH (what the system is)      TEMPORAL GRAPH (what it does)
  immutable, content-addressed            content-addressed checkpoint DAG

  ScenarioDef ---- genesis ---> c0 --d0--> c1 --d1--> c2 --> ...
    World                        \
    Plan                          `--d0'--> c1' --d1'--> ...
    Properties
    Seed                          nodes = Checkpoints, edges = Decisions
  ---------------------------------------------------------------------
                 step / reduce / instantiate (the join)
```

- [scenario-model.md](scenario-model.md) owns the spatial graph.
- [execution-graph.md](execution-graph.md) owns the temporal graph.
- [execution-model.md](execution-model.md) owns the reduction:
  `Configuration`, `try_step`, `reduce`, `instantiate`, and `bake`.

## System diagram

```text
 operator / CI
   crucible (crucible-cli)  --- scenario TOML, commands
        |
        |  authenticated HTTP/2 control API (crucible-control-api types)
        v
 +---------------------------------------------------------------------+
 | HOST PROCESS (Apache-2.0)        crucible-daemon                    |
 |                                                                     |
 |   crucible-control-server  -->  crucible-session (SessionActor)     |
 |                                   owns Engine: Configuration,       |
 |                                   TemporalGraph, QuantumLoop        |
 |                                        |                            |
 |   crucible-engine                      v                            |
 |     model/      ScenarioDef, Configuration, Decision, Checkpoint,   |
 |                 TemporalGraph, DagStore, instantiate, bake          |
 |     scheduler/  SingleScheduler: PICK/RUN/RESOLVE/EMIT/STEP          |
 |     trigger/    event graph, conditions, assertions                 |
 |     device_subnode/ block, 9p, network-link sub-nodes               |
 |                                        |                            |
 |   crucible-qemu-host  (SimulationBackend for QemuNode/QemuNodeSet)  |
 |   crucible-store / crucible-campaign (content store, campaigns)     |
 +-----------------|----------------------------|----------------------+
                   | Unix socket control        | shared memory region
                   | protocol + descriptor      | (crucible-qemu-shmem ABI)
                   | handover                   | + futex / eventfd wakes
                   | (crucible-qemu-protocol)   |
 +-----------------v----------------------------v----------------------+
 | QEMU PROCESS per VM (GPL-2.0)                                       |
 |   patched QEMU, TCG `sim` accelerator, -icount shift=0              |
 |   crucible-qemu-plugin (cdylib): time control, delivery at exact    |
 |   icount, observation callbacks, doorbell decoding                  |
 |      +-----------------------------------------------------------+  |
 |      | GUEST (unmodified kernel + root image)                    |  |
 |      |   optional crucible-guest white-box emitter (doorbell)    |  |
 |      +-----------------------------------------------------------+  |
 +---------------------------------------------------------------------+

 outputs: totally ordered event log -> property verdicts
          temporal graph (checkpoint DAG) -> resume / fork / search
          reproduction artifact (scenario form + schedule) -> exact re-run
```

## Process boundaries

Crucible runs as several cooperating processes. The boundaries are part of the
design, not packaging accidents.

| Boundary | Mechanism | Owner |
| --- | --- | --- |
| Operator to daemon | Authenticated HTTP/2 control API | `crucible-control-api`, `crucible-control-client`, `crucible-control-server` |
| Host to QEMU, control | Versioned Unix socket framing, setup descriptor handover | `crucible-qemu-protocol` |
| Host to QEMU, data | Versioned `#[repr(C)]` shared-memory region with SPSC frame queues and a per-node advance ceiling | `crucible-qemu-shmem` |
| Guest to plugin | Trapped-instruction doorbell, decoded by the plugin | `crucible-qemu-protocol` (doorbell ABI), `crucible-guest` |
| Debugger to QEMU | Standalone GPL-side gateway process | `crucible-qemu-debug-gateway` |

The host-to-QEMU boundary is also a license boundary. The Apache-licensed host
and the GPL-side QEMU and plugin are separate processes whose only integration
surfaces are the socket protocol and the shared-memory protocol. The shared
region holds only fixed-width values, byte arrays, checked offsets, and shared
atomics; it never contains native pointers, callback tables, or QEMU-private
types. `crucible-qemu-protocol` and `crucible-qemu-shmem` are dual-licensed
`MIT OR Apache-2.0` and depend on no QEMU code. The normative policy is in
[../../legal/licensing.md](../../legal/licensing.md); the wire formats are in
[control-protocol.md](control-protocol.md) and [shmem-abi.md](shmem-abi.md).

The setup frame of the control protocol carries three descriptors in a fixed
order: the shared-memory region, the wake descriptor, and the immutable
version-matched plugin plan. After setup, per-quantum traffic is shared-memory
writes plus wakes. A wake carries no timing decision or payload; every input
carries its delivery icount in-band, so the plugin makes it visible at that
icount regardless of when the bytes arrived.

## Layers and crates

The runtime crates are layered L0 to L4. Each layer owns one determinism
concern and depends only on its own layer or lower ones.

| Layer | Crates | Owns |
| --- | --- | --- |
| L0 deterministic core | `crucible-determinism` | Seeded decision streams (`DecisionRng`, `DecisionStream`, splitmix64), stable hashing, the isolated single-VM driver in `contract_a` |
| L1 co-simulation transport | `crucible-qemu-shmem`, `crucible-qemu-protocol`, `crucible-device` | Shared-memory ABI, host/plugin protocol, deterministic block, 9p, and network-link sub-node models |
| L2 QEMU integration | `crucible-qemu-host`, `crucible-qemu-plugin` (in-VM), `crucible-guest` (in-VM), `crucible-qemu-debug-gateway` | Launch validation and QEMU supervision, the in-QEMU plugin, the optional guest emitter, the debugger gateway |
| L3 engine | `crucible-engine`, `crucible-store`, `crucible-campaign` | Execution model, scheduler, triggers and assertions, temporal graph, content-addressed storage, campaign vocabulary |
| L4 control plane | `crucible-session`, `crucible-control-api`, `crucible-control-client`, `crucible-control-server`, `crucible-daemon`, `crucible-cli`, `crucible-store-s3` | Session actors, control API and transport, the long-lived daemon, the `crucible` command, the S3 store transport |

`crates/crucible/crucible-test-support/tests/crate_layer_graph.rs` enforces the
dependency graph:

- A runtime crate depends only on crates in its own layer or below.
- The one sanctioned upward edge is `crucible-qemu-host` to `crucible-engine`:
  the host-side QEMU adapter implements the engine's `SimulationBackend`.
- The in-VM crates `crucible-qemu-plugin` and `crucible-guest` depend directly
  only on L1 crates, which keeps engine code out of QEMU and out of the guest.
- No runtime crate depends on the test-only `crucible-test-support`.

The crate-by-crate inventory, including test-only and packaging crates, is in
[crate-structure.md](crate-structure.md).

## Data flow through one run

```text
 1 define      TOML or ScenarioBuilder -> ScenarioDefForm
               validate, canonicalize, content-address
 2 bake        boot each VM once to its ready point, capture the genesis
               checkpoint
 3 instantiate realize Configuration(def, schedule) from the temporal graph:
               exact checkpoint, else nearest cached ancestor + replay,
               else baked genesis + replay
 4 schedule    one quantum at a time:
                 PICK    minimum-horizon node
                 RUN     SimulationBackend::step_to(ceiling)
                 RESOLVE due frames, I/O completions, signal effects in
                         (virtual_time, consumer, producer, sequence) order
                 EMIT    content-addressed event-log segment
                 STEP    append decisions, advance the frontier
 5 observe     triggers and assertions evaluate over the event log
 6 checkpoint  decisions extend the temporal graph; hot nodes are
               materialized, cold nodes stay thin
 7 reproduce   ReproductionArtifact = scenario form + schedule
```

1. **Define.** A scenario arrives as canonical TOML or is built with
   `ScenarioBuilder`. Construction validates every well-formedness rule and
   canonicalizes collections before any identity is computed. See
   [scenario-model.md](scenario-model.md) and the operator view in
   [../../users/crucible/scenarios.md](../../users/crucible/scenarios.md).
2. **Bake.** Each VM is booted once to its declared `ReadyPoint`, and the
   resulting state becomes the genesis checkpoint. The first run of a scenario
   is therefore a restore, and the cold-boot path never runs in the hot loop.
3. **Instantiate.** The session engine asks the temporal graph for a runnable
   `RuntimeState`. Start, resume, and fork differ only in which configuration
   they request. See [execution-model.md](execution-model.md).
4. **Schedule.** The single scheduler advances virtual time in quanta. Only
   the scheduler advances a node's clock or delivers a cross-node event;
   backends report what they observed while stepping toward the ceiling they
   were given. See [scheduling.md](scheduling.md) and
   [virtual-time.md](virtual-time.md).
5. **Observe.** Every happening is appended to one totally ordered event log.
   Assertions and triggers evaluate over it. See [event-log.md](event-log.md),
   [assertions.md](assertions.md), and
   [conditions-and-triggers.md](conditions-and-triggers.md).
6. **Checkpoint.** The temporal graph records each configuration as a node.
   Fat checkpoints cache materialized state; thin checkpoints are the parent
   edge plus its schedule delta. See [execution-graph.md](execution-graph.md).
7. **Reproduce.** A `ReproductionArtifact` carries the validated scenario form
   and the schedule, which is everything needed to reduce the run again. See
   [../../users/crucible/reproduction.md](../../users/crucible/reproduction.md).

The session actor drives steps 3 to 6. It owns its `Engine`, services control
commands only between quanta, and publishes a lock-free `LiveSnapshot` so
observers never wait on a running quantum. See [session.md](session.md) and
[control-api.md](control-api.md).

## Determinism strategy

Nondeterminism is eliminated at its source rather than recorded and replayed.
The strategy decomposes into three independently gated parts; the formal
contract is in [determinism.md](determinism.md).

- **Intra-VM hermeticity.** One VM produces a bit-identical instruction stream
  for fixed inputs. `crucible-qemu-host` refuses to spawn QEMU unless the argv
  selects the TCG-derived `sim` accelerator, fixed `-icount` with `shift=0`, a
  pinned round-robin switch quantum, no KVM or MTTCG `thread=multi`, no host
  CPU entropy, and no host-timing devices (`validate_pre_spawn_qemu_launch_args`
  in `crates/crucible/crucible-qemu-host/src/launch/validation.rs`). The patch
  and plugin are described in [qemu-patch.md](qemu-patch.md) and
  [qemu-plugin.md](qemu-plugin.md).
- **Injection determinism.** The icount at which an external input reaches a
  VM is a pure function of virtual time. A frame is delivered at its emission
  time plus link latency; an I/O completion at the time the sub-node model
  computes. Simultaneous events break ties by the fixed key
  `(virtual_time, consumer, producer, sequence)` carried in `EventKey`.
- **Harness determinism.** The engine is a reduction island:
  `crucible-engine` forbids `unsafe`, reads no wall clock or host RNG on
  ordering paths, and iterates ordered collections. Intended randomness comes
  only from `DecisionRng` forks rooted at the scenario `Seed` and is recorded
  as `Decision`s.

A detected divergence is localized to its first differing decision or
instruction rather than smoothed over; see
[failure-triage.md](failure-triage.md) and
[testing-and-gates.md](testing-and-gates.md).

## Design decisions

These decisions explain why the code is shaped the way it is.

**QEMU TCG, never KVM.** Determinism needs instruction execution, interrupt
boundaries, timestamp counters, and floating point to be functions of the
inputs. Under TCG with `-icount`, the TSC derives from the instruction counter,
interrupts land at translation-block boundaries, and soft-float is
host-independent. KVM puts the host CPU's TSC, `RDRAND`, feature set, and
interrupt timing in the loop, and no host-side seam can make that interior
bit-identical.

**One execution model.** Start, resume, and fork are one recursive
`instantiate` over one state type. Separate boot, restore, and fork paths
drift (a field saved on resume but not on fork) and each drift is a silent
determinism break. Baking removes the last special case, cold boot, from the
hot loop. Details in [execution-model.md](execution-model.md).

**Two orthogonal graphs.** Structure (the immutable `ScenarioDef`) and
behavior (the checkpoint DAG) are separate content-addressed data. The spatial
graph is hashed once and shared; the temporal graph only grows by appending
decisions, so a re-derived state and a stored snapshot of the same point have
the same identity. The Plan stays in the spatial definition because it is
reproducible structure; only resolved choices enter the Schedule.

**Conservative PDES with exact local horizons.** A node advances only into
virtual time no peer can still affect, so nothing is ever rolled back; rolling
back a full VM image would be expensive and a determinism hazard. Timers and
I/O completions are computed host-side and give exact horizons, so only
guest-to-guest network traffic pays the conservative lookahead bound, which is
the minimum inbound link latency. That is why `MIN_LINK_LATENCY` is strictly
positive. Details in [scheduling.md](scheduling.md).

**I/O as scheduled sub-nodes.** Disk, 9p, and network links are scheduling
nodes with modeled completion times, not a "freeze the clock during host I/O"
shortcut. Modeled latency becomes part of the timeline, completions become
exact local events, and all cross-node events share one ordering mechanism.
Details in [io-subnodes.md](io-subnodes.md).

**One scheduler, realized as an actor.** A single source of timing truth is
required for one total order; a second component that could advance a clock
would turn ordering into a host-timing race. The scheduler and the session are
actors that mutate state on their own task and yield between quanta, so
control is serviced at well-defined boundaries without long-held locks.

**Shared-memory data plane.** The transport's key property is that a payload's
presence on a queue never decides its visibility; the in-band delivery icount
does. A shared-memory region expresses that directly and avoids socket round
trips per quantum. The region layout is the single versioned public schema for
the data plane, declared by
`crates/crucible/crucible-qemu-shmem/interface/crucible-shmem-abi.toml`; the
Rust crate and the generated C header are peer views of it.

**Black-box by default.** Crucible observes guests through their I/O and
needs no guest changes. The white-box channel (guest assertions, markers,
agent ready points, app-requested randomness) is opt-in per node through
`WhiteBoxPolicy::Enabled`. See
[guest-host-channel.md](guest-host-channel.md).

**Simulation control is inert unless sim mode is active.** The same patched
QEMU also runs ordinary TCG. Simulation mechanisms engage only when the plugin
and sim flags select them, so ordinary emulation keeps upstream behavior. See
[qemu-patch.md](qemu-patch.md).

## Where to read next

| Concern | Page |
| --- | --- |
| Vocabulary | [glossary.md](glossary.md) |
| Scenario definition, identity, validation | [scenario-model.md](scenario-model.md) |
| `Configuration`, `instantiate`, `bake`, replay oracle | [execution-model.md](execution-model.md) |
| Checkpoint DAG, DAG store, GC | [execution-graph.md](execution-graph.md) |
| Quantum loop, horizons, total order | [scheduling.md](scheduling.md) |
| Picosecond ticks and icount | [virtual-time.md](virtual-time.md) |
| QEMU launch and supervision | [qemu-integration.md](qemu-integration.md) |
| Session actor and control plane | [session.md](session.md), [control-api.md](control-api.md), [cli.md](cli.md) |
| Search and exploration | [exploration.md](exploration.md), [distributed-exploration.md](distributed-exploration.md) |
| Packaging and gates | [packaging.md](packaging.md), [testing-and-gates.md](testing-and-gates.md) |
