# 03 — Architecture Overview

This file is the map. It explains how Crucible works end to end — from "a user
writes a scenario" to "a bit-identical multi-VM run with checked properties and a
reproduction artifact" — and how the parts fit together so the detailed topic
files that follow have a shared frame. It is deliberately broad and light on
normative statements: the deep contracts live in their own files and are
forward-referenced here. The few architecture-level MUSTs that genuinely belong
at this altitude are stated with `ARCH-*` IDs; everything else is descriptive and
defers to the file that owns it.

Read [`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md) and
[`02-glossary.md`](02-glossary.md) first — this file uses their vocabulary and
invariant IDs (`INV-*`) without redefining them.

## 1. The system in one diagram and one walkthrough

Crucible turns an immutable test definition into a reproducible distributed-systems
run. The user writes a **ScenarioDef** (a topology of nodes and links, per-node
configuration, a fault **Plan**, the **Properties** to check, and a **Seed**);
Crucible boots the guests under QEMU TCG with instruction-count virtual time,
drives every cross-machine interaction through a single authoritative scheduler,
checks the properties against a totally-ordered **event log**, and emits a
self-contained **reproduction artifact** that re-runs the execution to the
instruction.

```text
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  USER                                                                      │
  │    scenario.rs / scenario.toml  ──►  ScenarioDef  (immutable, hashed)      │
  │      World (nodes, links)  ·  Plan (faults)  ·  Properties  ·  Seed        │
  └─────────────────────────────────────┬────────────────────────────────────┘
                                         │  build + content-address (INV-6)
                                         ▼
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  CONTROL PLANE  (L4)                                                       │
  │    crucible-cli ─► crucible-api ─► crucible-daemon ─► crucible-session     │
  │    Session is an actor: owns one live run, yields between quanta (INV-8).  │
  └─────────────────────────────────────┬────────────────────────────────────┘
                                         │  instantiate(Configuration)
                                         ▼
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  ENGINE  (L3)  crucible                                                    │
  │    ┌───────────────┐   reduce(ScenarioDef, Schedule)                       │
  │    │  Scheduler    │── single authoritative source of virtual time ───────│
  │    │  (the one     │   pick min-horizon node ─ run a quantum ─ deliver     │
  │    │   clock)      │   due events in total order ─ emit event-log entries  │
  │    └───────┬───────┘                                                       │
  │    faults · assertions · temporal graph (checkpoint DAG, CoW)             │
  └────┬─────────────────────────────────┬───────────────────────────────────┘
       │  per-node control                │  cross-node events (frames, I/O,
       ▼                                  ▼  fault activation) — total order
  ┌─────────────────────────┐     ┌──────────────────────────────────────────┐
  │  QEMU INTEGRATION (L2)   │     │  CO-SIM TRANSPORT (L1)                    │
  │  crucible-qemu (host)    │◄───►│  crucible-shmem (ABI)                     │
  │  crucible-qemu-plugin    │     │  crucible-protocol                        │
  │    (in-VM cdylib)        │     │  crucible-device (disk / 9p / net         │
  │  crucible-guest (opt.)   │     │    I/O sub-nodes)                         │
  └───────────┬─────────────┘     └──────────────────────────────────────────┘
              │  -plugin, -icount shift=N, sealed entropy boundary
              ▼
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  QEMU TCG  (patched, from-source; patches inert unless sim mode, INV-7)    │
  │   VM #0 (-smp 1)   VM #1 (-smp 1)   …   VM #k (-smp 1)                      │
  └──────────────────────────────────────────────────────────────────────────┘
              │  observed I/O + (optional white-box markers)
              ▼
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  OUTPUTS                                                                   │
  │   event log (totally ordered, content-addressed) ─► properties verdict    │
  │   temporal graph (checkpoint DAG) ─► fork / resume / search                │
  │   reproduction artifact (seed + scenario + schedule) ─► bit-identical re-run│
  └──────────────────────────────────────────────────────────────────────────┘
```

### The walkthrough, step by step

1. **Define.** The user expresses a scenario in the API
   ([`21-api.md`](21-api.md)) or a declarative file consumed by the CLI
   ([`23-cli.md`](23-cli.md)). It is lowered to a **ScenarioDef** — the spatial
   graph, "configuration #0" ([`06-spatial-graph.md`](06-spatial-graph.md)).
   Every component is content-addressed (`INV-6`): equal inputs yield equal
   identity, so two scenarios that share a kernel, image, or sub-plan share
   storage.

2. **Bake.** Before the first decision, Crucible **bakes** the World: each VM is
   booted once to a defined ready point and snapshotted, producing the **genesis
   checkpoint** ([`05-execution-model.md`](05-execution-model.md) §bake). Baking
   means even the very first run is a *resume*, not a special boot path — one code
   path serves all cases.

3. **Instantiate.** The session asks the engine to produce a runnable
   **RuntimeState** for the current **Configuration** = `(ScenarioDef, Schedule)`.
   `instantiate` is recursive: a cached snapshot loads directly; otherwise it
   replays from the nearest cached ancestor; otherwise (the base case) it boots.
   Start, resume, and fork are the *same* operation (`INV` for one execution
   model, `G-4`).

4. **Schedule.** The engine's single authoritative scheduler (`INV-8`) advances
   virtual time. Each **quantum** picks the global-minimum-**horizon** node, runs
   it under `-icount` to its next sync point, then processes every due cross-node
   event — frame delivery, I/O completion, fault activation — in the deterministic
   total order keyed by `(virtual_time, consumer node_id, producer node_id, sequence)` (`INV-3`). See §5 and
   [`08-scheduling.md`](08-scheduling.md).

5. **Observe and check.** Every observable happening is appended to the single
   totally-ordered, content-addressed **event log**
   ([`19-observability-event-log.md`](19-observability-event-log.md)). The
   assertion engine ([`18-assertions-properties.md`](18-assertions-properties.md))
   reads the log and evaluates Properties (Always / Sometimes / Eventually /
   AfterQuiescence / Reachable).

6. **Checkpoint and branch.** Scheduling decisions extend the **temporal graph**
   — a content-addressed DAG of checkpoints
   ([`07-temporal-graph.md`](07-temporal-graph.md)). Fork, resume, and state-space
   search ([`22-advanced-features.md`](22-advanced-features.md)) are traversals and
   expansions of this graph.

7. **Reproduce.** When the run ends (quiescence, a failed Always property, a
   budget) Crucible can emit a **reproduction artifact**: the self-contained
   `(seed, scenario, schedule)` bundle that re-derives the run bit-identically
   (`G-6`). Because state is a pure function of these inputs (`INV-1`),
   reproduction is free and exploration is graph traversal.

- **[ARCH-1]** The end-to-end pipeline MUST be expressible as a single pure
  reduction `State(t) = reduce(ScenarioDef, Schedule[0..t])` with no hidden
  inputs; every stage above either constructs `ScenarioDef`, appends to
  `Schedule`, or materializes/queries `State`. *Satisfies* `INV-1`. *Spec:* §3,
  [`05-execution-model.md`](05-execution-model.md).

## 2. The two orthogonal graphs

Crucible is organized as two graphs joined by one reduction. Keeping them
orthogonal is what makes the whole system tractable: *structure* and *behavior*
are separate, content-addressed data, and the engine is the pure function between
them.

```text
        SPATIAL GRAPH                          TEMPORAL GRAPH
        (what the system IS)                   (what the system DOES)
        immutable, content-addressed           content-addressed checkpoint DAG

        ScenarioDef  ── config #0 ──►  genesis ──D0──► c1 ──D1──► c2 ──┐
          World                            │                          │
          Plan                             └──D0'──► c1' ──D1'──► …    │
          Properties                                                  ▼
          Seed                              edges = Decisions     frontier
                                            nodes = Checkpoints   (search)
        ──────────────────────────────────────────────────────────────────
                       reduce / step / instantiate  (the join)
```

### The spatial graph (immutable, content-addressed `ScenarioDef`)

The spatial graph is the **definition** of a run: the topology of nodes and
links, per-node static configuration (kernel, root image, memory, link
latency/loss), the fault **Plan**, the **Properties**, and the **Seed**. It is
immutable and content-addressed — "configuration #0." It says nothing about
*time*; it is pure structure. Full schema, addressing, and lowering rules are in
[`06-spatial-graph.md`](06-spatial-graph.md).

### The temporal graph (its closure under `step`)

The temporal graph is the **unfolding** of the spatial graph under scheduling
decisions: a content-addressed DAG whose **nodes are checkpoints** (complete
execution states at a `(virtual_time / per-node icount)` point) and whose **edges
are Decisions**. It is the closure of the genesis checkpoint under the `step`
reducer. Checkpoints are **thin** (`(parent, schedule_delta)`, reconstructed by
replay — always correct) or **fat** (carrying a materialized snapshot — fast to
resume, validated against its thin derivation by the replay oracle, `INV-2`).
Copy-on-write sharing means a fork costs only its delta. Full model in
[`07-temporal-graph.md`](07-temporal-graph.md).

### Why orthogonal matters

The spatial graph never changes during a run, so it can be hashed once and shared.
The temporal graph is the only thing that grows, and it grows only by appending
Decisions — never by mutating state in place. Identity is content; a re-derived
state and a stored snapshot of the same point are *the same object* (`INV-2`,
`INV-6`). This separation is what makes resume, fork, and search uniform: they are
all positions in, and expansions of, one DAG over one fixed definition.

## 3. The unified execution model in brief

The headline simplification of Crucible is that there is **one** way to make a
runnable state, and **one** way to advance it. Detail in
[`05-execution-model.md`](05-execution-model.md); the shape:

```text
  Configuration   = (ScenarioDef, Schedule)        -- the only state identity
  genesis         = (ScenarioDef, [])              -- configuration #0, baked
  step            : Configuration × Decision → Configuration   -- append one Decision
  reduce          : (ScenarioDef, Schedule[0..t]) → State      -- pure function
  instantiate     : Configuration → RuntimeState   -- recursive; base case = boot
  bake            : World → genesis_checkpoint      -- boot once, snapshot, so the
                                                       first run is itself a resume
```

- **`State = reduce(ScenarioDef, Schedule)`.** The entire multi-VM execution is a
  pure function of the immutable definition and the totally-ordered sequence of
  decisions. No wall-clock, no host scheduling order, no host entropy enters
  (`INV-1`).
- **`instantiate` unifies boot / resume / fork.** To get a runnable state at any
  point: if a snapshot is cached, load it; else replay from the nearest cached
  ancestor along the schedule; else boot (the base case). Boot is not a separate
  feature — it is the leaf of one recursion. This is what makes start, resume, and
  fork the *same operation* (`G-4`).
- **`bake` makes even the first run a resume.** Booting each VM once to a defined
  ready point and snapshotting it produces the genesis checkpoint. Thereafter every
  `instantiate` — including the very first — is a resume from a checkpoint, so there
  is no privileged "cold start" path to get subtly wrong.

- **[ARCH-2]** There MUST be exactly one function that produces a runnable state
  from a `Configuration` (`instantiate`), and exactly one function that extends a
  `Configuration` (`step`); boot, resume, and fork MUST NOT have independent code
  paths. *Satisfies* `G-4`. *Spec:* [`05-execution-model.md`](05-execution-model.md).

## 4. The L0–L4 layering and the crate map

Crucible is layered so that each layer owns one determinism concern and is gated
before anything is built on top of it (`G-5`). The crate-by-crate detail and the
dependency rules are in [`27-crate-structure.md`](27-crate-structure.md); this is
the orientation.

```text
  L4  control plane     crucible-session (actor) · crucible-api · crucible-daemon · crucible-cli
       owns: turning user intent into Configurations; live control; reproduction artifacts
       determinism concern: control operations land at well-defined quanta, never mid-quantum

  L3  engine            crucible
       owns: scenario model, the single scheduler, faults, assertions, temporal graph, event log
       determinism concern: harness determinism (INV-9) — pure reduction, ordered iteration,
                            deterministic select, no host RNG/wall-clock in the engine

  L2  QEMU integration  crucible-qemu (host) · crucible-qemu-plugin (in-VM cdylib) · crucible-guest
       owns: launching/controlling QEMU; the plugin that owns virtual-time control and callbacks
       determinism concern: intra-VM hermeticity (Contract A) — seal every entropy source so one
                            VM is bit-identical for fixed inputs (INV-4)

  L1  co-sim transport  crucible-shmem (ABI) · crucible-protocol · crucible-device (disk/9p/net)
       owns: the shared-memory layout, IPC protocol, and I/O sub-nodes
       determinism concern: injection determinism (Contract B) — the icount at which any external
                            input is delivered is a pure function of virtual time (INV-3)

  L0  deterministic core crucible-sim (runtime/scheduler primitives) · crucible-assert
       owns: the deterministic-execution primitives and the assertion vocabulary types
       determinism concern: the determinism substrate itself — seeded decision source, ordered
                            collections, the building blocks every higher layer must use
```

The hard determinism work concentrates at **L0–L2**. L0 supplies the
deterministic primitives; L2 (with the AOS QEMU patch series,
[`11-qemu-patches.md`](11-qemu-patches.md)) eliminates entropy inside one VM; L1
makes cross-VM injection a pure function of instruction-count time. L3 stays
deterministic by construction (`INV-9`), and L4 only ever issues control at
quantum boundaries.

- **[ARCH-3]** Each layer MUST depend only on layers at or below it; there MUST be
  no upward dependency (e.g. the engine MUST NOT depend on the daemon, the
  transport MUST NOT depend on the engine). *Satisfies* `G-5`, `G-8`. *Spec:*
  [`27-crate-structure.md`](27-crate-structure.md).
- **[ARCH-4]** Each layer MUST have a determinism gate that is green before any
  higher layer is built on it (`gate:layer0-determinism`,
  `gate:single-vm-fingerprint`, `gate:layer1-injection`, `gate:harness-lint`,
  `gate:control-responsive`). *Satisfies* `G-5`, `INV-9`. *Spec:*
  [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md).

## 5. The anatomy of one scheduling quantum

The scheduler is the single source of timing truth (`INV-8`). It advances the
system one **quantum** at a time. A quantum is the unit of `step`: advance the
node that can advance furthest-soonest, then resolve everything that becomes due.
Full algorithm, horizon/lookahead derivation, and edge cases are in
[`08-scheduling.md`](08-scheduling.md); the shape of one quantum:

```text
  QUANTUM(config):
    1. PICK     choose the node with the global-minimum horizon, where
                  horizon(n) = min( next exact local event of n,          -- timer, I/O completion
                                    n.virtual_time + lookahead(n) )        -- conservative CMB bound
                lookahead(n) = minimum inbound link latency to n
                                 (a peer cannot deliver to n sooner than this)

    2. RUN      run that node under -icount until it reaches its horizon
                  (its next sync point): a TB boundary at/after the horizon,
                  an idle (HLT) with no earlier wakeup, or an emitted output.
                Idle is fast-forwarded to the wake time at zero wall-clock cost.

    3. RESOLVE  process every cross-node event now DUE (delivery_time ≤ frontier),
                in the deterministic total order keyed by (virtual_time, consumer node_id, producer node_id, sequence):
                  · frame delivery        (T_emit + link_latency, fault table applied)
                  · I/O completion        (disk / 9p sub-node deterministic completion)
                  · fault activation      (Plan entry whose virtual time has arrived)
                Probabilistic choices (does this lossy link drop?) are resolved by the
                seeded decision RNG and recorded as Decisions.

    4. EMIT     append an ordered, content-addressed entry to the event log for every
                resolved happening (and for each Decision taken).

    5. STEP     config' = step(config, decisions_taken); advance the frontier.
                Between quanta the scheduler yields, so control ops are serviced
                at this well-defined point (INV-8) — never mid-quantum.
```

Because virtual time is icount-derived (`INV-4`) and the resolution order is the
fixed key `(virtual_time, consumer node_id, producer node_id, sequence)` (`INV-3`), the sequence of quanta —
and therefore the whole run — is a pure function of `(ScenarioDef, Seed,
Schedule)`. Lookahead is the parallelism budget: nodes whose horizons do not
constrain each other may execute concurrently up to the lookahead window, but the
*resolution* of due events is always serialized through the one scheduler so the
total order is never a host-timing race.

- **[ARCH-5]** All advancement of virtual time and all resolution of cross-node
  ordering MUST flow through the single scheduler; no component may advance a
  node's clock or deliver a cross-node event out of band. *Satisfies* `INV-8`,
  `INV-3`. *Spec:* [`08-scheduling.md`](08-scheduling.md).

## 6. Determinism strategy at a high level

Crucible's determinism is **hermetic**: nondeterminism is eliminated at the
source, not recorded and replayed (`NG-6`). The formal contract is
[`04-determinism-contract.md`](04-determinism-contract.md); the layered proof is
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md). At this
altitude the strategy is two contracts plus per-layer gates.

### Contract A — intra-VM hermeticity

A single VM MUST produce a bit-identical instruction stream and architectural
state for fixed inputs `(image, kernel cmdline, seed, injected-input sequence)`.
This is achieved host-side (`G-2`): run under QEMU TCG with a fixed
`-icount shift=N` (never `auto`), suppress wall-clock warp, seal every entropy
source (`RDRAND`/`RDSEED`/`RDTSC`, firmware entropy, any device that samples the
host), and drive virtual time from the instruction counter (`INV-4`). The AOS
QEMU patch series ([`11-qemu-patches.md`](11-qemu-patches.md)) supplies the
sealing; the plugin ([`12-qemu-plugin.md`](12-qemu-plugin.md)) owns time control.
*Gate:* `gate:single-vm-fingerprint` (periodic icount + register/memory hash
matches across runs).

### Contract B — injection determinism

The icount at which any external input (a delivered frame, an I/O completion, a
fault activation) reaches a VM MUST be a pure function of virtual time, not a
host-timing race. Delivery time is `T_emit + link_latency` (or the sub-node's
deterministic completion time); the conservative CMB lookahead guarantees no node
can advance past a delivery point before the producing side has made the input
visible, so the same inputs land at the same icount every run. Simultaneous events
break ties by the fixed total order `(virtual_time, consumer node_id, producer node_id, sequence)` (`INV-3`).
*Gate:* `gate:layer1-injection`.

### Per-layer gates and "no silent nondeterminism"

Each layer has a gate (§4); the foundation gates must be green before features are
built on top (`G-5`). The engine itself is held deterministic by `INV-9`
(`gate:harness-lint`: no unordered map iteration on ordering-significant paths, no
host wall-clock or thread RNG, deterministic `select`). And `INV-10` makes
divergence loud, not smooth: any residual nondeterminism MUST be eliminated,
routed through the seeded decision source, or fail — and a detected divergence
MUST localize to the first differing decision/instruction (`gate:divergence-bisect`,
divergence bisection). Crucible never papers over a difference.

- **[ARCH-6]** The system's determinism MUST decompose into Contract A (intra-VM
  hermeticity) and Contract B (injection determinism), each independently testable
  by its own gate, with no determinism property depending on an ungated layer.
  *Satisfies* `G-1`, `G-5`, `INV-4`, `INV-3`. *Spec:*
  [`04-determinism-contract.md`](04-determinism-contract.md),
  [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md).

## 7. Data flow: I/O as uniform sub-nodes, and the guest↔host channel

### I/O sub-nodes (disk / 9p / net)

Crucible models disk, 9p, and network-link I/O not as a special side path but as
first-class **I/O sub-nodes** in the same scheduling graph as VMs. Each sub-node
has its own clock and emits **deterministic completion events** that the scheduler
resolves in the same total order as frame deliveries
([`15-io-subnodes.md`](15-io-subnodes.md)). This uniformity is a determinism
lever: a disk read does not "finish whenever the host disk finishes"; it finishes
at a virtual time the sub-node computes from the request and a fixed model, so its
completion is an **exact local event** that gives the requesting node an exact
horizon. The same total order (`INV-3`) covers frame delivery, I/O completion, and
fault activation, so all three are scheduled by one mechanism.

```text
  VM node ──issues read──►  disk sub-node ──computes completion @ virtual time──►
       ◄── completion event resolved by the one scheduler, in (vt, node, seq) order ──┘

  VM node ──emits frame──►  net link sub-node ──delivery @ T_emit + latency, fault-filtered──►
       ◄── frame delivery resolved by the one scheduler, in (vt, node, seq) order ─────────┘
```

Disk overlays are copy-on-write over a read-only base image (`INV-5`: the guest's
on-disk image is never mutated); the 9p server is read-only with deterministic
(path-hashed) QIDs and sorted directory enumeration so its observable behavior is
a pure function of its inputs.

### The guest↔host channel

The default observation mode is **black-box** (`G-3`): Crucible observes a guest
only through its I/O (frames, block/9p requests, console) and needs zero guest
cooperation. An **optional, explicitly-enabled white-box** channel
([`16-guest-host-channel.md`](16-guest-host-channel.md)) lets a cooperating guest
emit fine-grained assertions and markers — e.g. via a trapped instruction
(a **doorbell**) that signals the plugin synchronously. White-box is strictly
additive: it MUST NOT be required for any core capability, and enabling it MUST
NOT change the deterministic execution of the guest (its markers are
**observational** event-log entries, excluded from determinism comparison).

- **[ARCH-7]** All cross-node I/O (disk, 9p, network) MUST be modeled as
  scheduling sub-nodes whose completions are resolved by the single scheduler in
  the same total order as all other cross-node events; no I/O path may complete on
  host-timing. *Satisfies* `INV-3`, `INV-8`. *Spec:*
  [`15-io-subnodes.md`](15-io-subnodes.md).
- **[ARCH-8]** Black-box observation MUST be sufficient for every core capability;
  the white-box channel MUST be optional and MUST NOT perturb deterministic guest
  execution when enabled. *Satisfies* `G-2`, `G-3`. *Spec:*
  [`16-guest-host-channel.md`](16-guest-host-channel.md).

## 8. Control, the API, and advanced features on top

The deterministic engine is a pure reduction; everything interactive sits on top
of it as **L4 control plane**, talking to it only at quantum boundaries.

- **Session as actor.** A live, controllable run is a **session** modeled as an
  actor that owns its `RuntimeState` and the engine
  ([`20-session-control-plane.md`](20-session-control-plane.md)). The scheduler
  yields between quanta (`INV-8`), so the session can service control messages —
  pause, resume, step, snapshot, fork, query — at well-defined points without
  long-held locks or mid-quantum races (`gate:control-responsive`). Control is
  *messages to an actor*, never shared-state mutation.
- **API.** A versioned programmatic surface ([`21-api.md`](21-api.md), `G-8`)
  exposes session lifecycle, stepping modes, the event-log query interface, and
  the temporal-graph operations. The CLI ([`23-cli.md`](23-cli.md)) is a thin
  client over the same API; the daemon hosts long-lived sessions.
- **Advanced features.** Fork, resume, state-space search, and coverage-guided
  fuzzing ([`22-advanced-features.md`](22-advanced-features.md)) are not bolted-on
  subsystems — they are operations on the temporal graph. **Resume** is
  `instantiate` at a chosen checkpoint; **fork** is `instantiate` of a sibling
  Configuration sharing a parent via CoW; **search** enumerates Decisions at
  frontier checkpoints and expands the DAG; **fuzzing** samples the schedule space
  guided by basic-block coverage harvested from the plugin's TCG-exec hook (no
  guest instrumentation). All of them inherit reproducibility for free, because
  every position is a `Configuration` and every Configuration reduces purely
  (`G-6`, `INV-1`).

- **[ARCH-9]** Control operations MUST be delivered to the engine only at quantum
  boundaries via the session actor; no control path may mutate engine state
  concurrently with a running quantum. *Satisfies* `INV-8`. *Spec:*
  [`20-session-control-plane.md`](20-session-control-plane.md).

## 9. Map of the RFC

Each subsystem and the file that owns it. This is the index of the spec; the
reading order is in the [`README.md`](README.md).

| Subsystem / concern | File |
| --- | --- |
| Status, problem, whole-system overview, ID scheme | [`README.md`](README.md) |
| Requirement-ID & task scheme, normative keywords, plan threading | [`00-conventions.md`](00-conventions.md) |
| Goals, non-goals, invariants (the contract) | [`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md) |
| Glossary / vocabulary | [`02-glossary.md`](02-glossary.md) |
| **Architecture overview (this file)** | `03-architecture-overview.md` |
| Determinism contract (Contract A + Contract B, formal) | [`04-determinism-contract.md`](04-determinism-contract.md) |
| Execution model (`Configuration`/`step`/`instantiate`/`bake`) | [`05-execution-model.md`](05-execution-model.md) |
| Spatial graph (ScenarioDef = config #0) | [`06-spatial-graph.md`](06-spatial-graph.md) |
| Temporal graph (checkpoint DAG, CoW, replay oracle) | [`07-temporal-graph.md`](07-temporal-graph.md) |
| Cross-node scheduling (quantum, horizon, lookahead, total order) | [`08-scheduling.md`](08-scheduling.md) |
| Virtual time / icount (shift mapping, fixed N) | [`09-virtual-time-icount.md`](09-virtual-time-icount.md) |
| QEMU integration (host side) | [`10-qemu-integration.md`](10-qemu-integration.md) |
| QEMU patch series (sim mode, inertness) | [`11-qemu-patches.md`](11-qemu-patches.md) |
| QEMU plugin (in-VM cdylib, time control, callbacks) | [`12-qemu-plugin.md`](12-qemu-plugin.md) |
| Shared-memory co-sim ABI | [`13-shmem-abi.md`](13-shmem-abi.md) |
| IPC protocol | [`14-protocol.md`](14-protocol.md) |
| I/O sub-nodes (disk / 9p / net devices) | [`15-io-subnodes.md`](15-io-subnodes.md) |
| Guest↔host channel (black-box / white-box) | [`16-guest-host-channel.md`](16-guest-host-channel.md) |
| Fault injection (taxonomy, tags, Plan) | [`17-fault-injection.md`](17-fault-injection.md) |
| Assertions & properties | [`18-assertions-properties.md`](18-assertions-properties.md) |
| Observability / event log | [`19-observability-event-log.md`](19-observability-event-log.md) |
| Session / control plane (actor) | [`20-session-control-plane.md`](20-session-control-plane.md) |
| API surface (versioned) | [`21-api.md`](21-api.md) |
| Advanced features (fork / resume / search / fuzz) | [`22-advanced-features.md`](22-advanced-features.md) |
| CLI | [`23-cli.md`](23-cli.md) |
| Determinism harness & testing (gates) | [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) |
| Performance targets | [`25-performance-targets.md`](25-performance-targets.md) |
| Packaging / AOS integration (ratchet gate) | [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md) |
| Crate structure (L0–L4 map, dependency rules) | [`27-crate-structure.md`](27-crate-structure.md) |
| Engineering standards (doc lint, Rust standard) | [`28-engineering-standards.md`](28-engineering-standards.md) |
| Patterns & sketches | [`29-patterns-and-sketches.md`](29-patterns-and-sketches.md) |
| Risks & spikes | [`30-risks-spikes.md`](30-risks-spikes.md) |
| Decision register | [`31-decision-register.md`](31-decision-register.md) |
| Master phased implementation plan | [`32-implementation-plan.md`](32-implementation-plan.md) |

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are tracked
> here per [`00-conventions.md`](00-conventions.md) `[PLAN-3]`. These tasks scaffold
> the architecture itself (workspace, layers, dependency rules) so the
> per-subsystem tasks in later files have a frame to land in.

- [x] **T-ARCH-1** Create the Cargo workspace skeleton with the L0–L4 crates
  (`crucible-sim`, `crucible-assert`; `crucible-shmem`, `crucible-protocol`,
  `crucible-device`; `crucible-qemu`, `crucible-qemu-plugin`, `crucible-guest`;
  `crucible`; `crucible-session`, `crucible-api`, `crucible-daemon`,
  `crucible-cli`) as empty, compiling crates with their `//!` crate docs. —
  satisfies [ARCH-3]; spec §4,
  [`27-crate-structure.md`](27-crate-structure.md).
- [x] **T-ARCH-2** Encode the layer dependency rule as an enforced check (a CI
  lint that forbids any upward dependency between layers). — satisfies [ARCH-3];
  spec §4, [`27-crate-structure.md`](27-crate-structure.md).
- [x] **T-ARCH-3** Define the core type spine — `Configuration`, `ScenarioDef`
  handle, `Schedule`, `Decision`, `Checkpoint` — and the `step` / `reduce` /
  `instantiate` / `bake` signatures in L3 so every later subsystem builds against
  fixed shapes. — satisfies [ARCH-1], [ARCH-2]; spec §1, §3,
  [`05-execution-model.md`](05-execution-model.md).
- [x] **T-ARCH-4** Stand up the per-layer determinism-gate harness skeleton
  (`gate:layer0-determinism`, `gate:single-vm-fingerprint`, `gate:layer1-injection`,
  `gate:harness-lint`, `gate:control-responsive`) as red placeholder gates wired
  into CI, to be turned green by their owning subsystems; make black-box
  observation sufficient for every core capability with the white-box channel
  optional and non-perturbing when enabled. — satisfies [ARCH-4], [ARCH-6],
  [ARCH-8]; spec §4, §6, [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md),
  [`16-guest-host-channel.md`](16-guest-host-channel.md).
- [x] **T-ARCH-5** Establish the single-scheduler boundary: a quantum-loop trait
  in L3 that is the sole owner of virtual-time advancement and cross-node event
  resolution, with the session actor (L4) as its only driver; model all cross-node
  I/O (disk/9p/network) as scheduling sub-nodes resolved in the one total order,
  never on host timing. — satisfies [ARCH-5], [ARCH-7], [ARCH-9]; spec §5, §8,
  [`08-scheduling.md`](08-scheduling.md), [`15-io-subnodes.md`](15-io-subnodes.md),
  [`20-session-control-plane.md`](20-session-control-plane.md).
