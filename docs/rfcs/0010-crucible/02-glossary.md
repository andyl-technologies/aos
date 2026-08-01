# 02 — Glossary

Precise definitions for the vocabulary used across the RFC. Where a term has a
formal model, the defining file is named.

## Core model

- **Scenario** — informal name for a complete test definition. Formally the
  **ScenarioDef** (06).
- **ScenarioDef** — the immutable, content-addressed *definition* of a run:
  `(World, Plan, Properties, Seed)`. The "spatial graph," configuration #0. (06)
- **World** — the topology: the set of nodes and links and their per-entity static
  configuration (kernel, root image, memory, link latency/loss). (06)
- **Plan** — the declarative schedule of injected faults/events over virtual time.
  Part of the ScenarioDef; distinct from the **Schedule**. (06, 17)
- **Properties** — the assertions to check (always/sometimes/eventually/…), part of
  the ScenarioDef. (18)
- **Seed** — the root entropy from which all deterministic randomness is derived. (04)
- **Schedule** — the totally-ordered sequence of **Decisions** the scheduler made
  during a run. The thing that varies between runs of one ScenarioDef; the input,
  with the ScenarioDef, to `reduce`. (05, 08)
- **Decision** — one resolved nondeterministic choice at a scheduling point:
  delivery order on simultaneous events, whether a probabilistic fault fires, a
  draw from the decision RNG. Edges of the temporal graph. (05, 08)
- **Configuration** — `(ScenarioDef, Schedule)`; the only state type. Genesis is
  `(ScenarioDef, [])`. Its materialized runtime is a cache, not part of identity. (05)
- **reduce** — the pure function `State(t) = reduce(ScenarioDef, Schedule[0..t])`. (05)
- **step** — `Configuration × Decision → Configuration`; appends one decision. (05)
- **instantiate** — `Configuration → RuntimeState`; recursive, base case is boot;
  cached snapshot → load, else replay from nearest cached ancestor, else boot. (05)
- **bake** — `World → genesis_checkpoint`; boot each VM once to a defined ready
  point and snapshot, so even the first run is a resume. (05)

## Graphs

- **Spatial graph** — the immutable structure of the system: nodes + links + config
  = the ScenarioDef. (06)
- **Temporal graph** — the unfolding of the spatial graph under decisions: a
  content-addressed DAG of **Checkpoints** whose edges are Decisions; the closure
  of genesis under `step`. (07)
- **Checkpoint** — a node of the temporal graph: a complete execution state at a
  `(virtual_time / per-node icount)` point, identified by `hash(parent,
  schedule_delta)`, optionally carrying a **materialized** snapshot. (07)
- **Thin checkpoint** — a checkpoint stored as `(parent, schedule_delta)` only;
  always correct, reconstructed by replay. (07)
- **Fat checkpoint** — a checkpoint with a materialized snapshot (VM state, device
  overlays, scheduler state); fast to resume, validated against its thin
  derivation by the replay oracle. (07)
- **Copy-on-write (CoW)** — sharing of unchanged state (memory pages, device blocks,
  log prefixes) between a checkpoint and its ancestors so forks don't copy. (07, 15)
- **Replay oracle** — the structural correctness check: a fat checkpoint must hash
  equal to its replay-from-ancestor reconstruction (INV-2). (07, 24)

## Determinism

- **Hermetic determinism** — determinism achieved by eliminating entropy sources,
  not by recording/replaying nondeterministic events. (04)
- **Intra-VM hermeticity (Contract A)** — same inputs ⇒ same icount stream for one
  VM. (04)
- **Injection determinism (Contract B)** — the icount at which an external input is
  delivered to a VM is a pure function of virtual time, not a host-timing race. (04)
- **Execution fingerprint** — a cheap, deterministic digest of a VM's execution
  (periodic icount + register/memory hash) used to detect divergence. (24)
- **Divergence bisection** — automatically localizing the first differing
  decision/instruction between two runs. (24)
- **Decision RNG** — the seeded RNG that resolves probabilistic Decisions;
  per-entity streams are forked by name-hash so adding a node doesn't perturb
  others. (04, 08)

## Time and scheduling

- **icount** — QEMU's executed-instruction count; Crucible's canonical per-VM clock. (09)
- **Virtual time** — the shared simulated timeline; derived from icount via the
  shift mapping (`ns = icount × 2^shift` semantics). (09)
- **Shift** — the fixed `-icount shift=N` value mapping instructions to virtual ns;
  fixed, never `auto`. (09, 10)
- **Horizon** — the furthest virtual time a node may advance to before it must
  synchronize: `min(next exact local event, conservative network lookahead)`. (08)
- **Lookahead** — the conservative bound from CMB PDES: the minimum inbound link
  latency to a node; a peer cannot deliver to it sooner than this. (08)
- **Exact local event** — a host-computed, predictable next wakeup (timer, disk/9p
  I/O completion) that gives a node an exact horizon with no conservative bound. (08, 15)
- **Quantum** — one `step` of the scheduler: advance the minimum-horizon node, then
  process due cross-node events. (08)
- **Quiescence** — all nodes idle, no pending deliveries, no timers, no faults due. (08)
- **Conservative PDES / CMB** — Chandy–Misra–Bryant conservative parallel
  discrete-event simulation: advance a node only when no earlier event can arrive. (08)

## QEMU & transport

- **TCG** — QEMU's Tiny Code Generator (binary translation); the execution mode
  Crucible uses for determinism (vs KVM). (10)
- **Plugin** — `crucible-qemu-plugin`, the in-VM cdylib loaded via `-plugin`; owns
  virtual-time control and the device/channel callbacks. (12)
- **Time control** — the plugin's ownership of QEMU's virtual clock via
  `qemu_plugin_request_time_control`, overriding warp. (12)
- **Warp** — QEMU's default behavior of advancing virtual time by wall-clock while
  idle; suppressed under Crucible. (10, 11)
- **Sim mode** — the activated state in which the patch series and plugin take
  effect; off by default (INV-7). (11)
- **Shmem region** — the `#[repr(C)]` shared-memory area between host and each VM's
  plugin carrying per-node clocks, status, and SPSC frame queues. (13)
- **SPSC queue** — single-producer/single-consumer lock-free ring used for frame
  delivery between a node and the executor. (13)
- **FrameEntry** — one queued payload (delivery time, source, seq, length, data). (13)
- **Doorbell** — the trapped instruction (e.g. reserved port I/O) the guest agent
  uses to signal the plugin synchronously in white-box mode. (16)

## Nodes & devices

- **Node** — a participant in the simulation graph: a VM or an I/O sub-node. (06, 15)
- **VM node** — a QEMU guest. (10)
- **I/O sub-node** — disk, 9p, or network-link participant modeled as a first-class
  scheduling node with its own clock and deterministic completion events. (15)
- **CoW overlay** — a block device's in-memory copy-on-write page set over a
  read-only base image. (15)
- **9p server** — a read-only Plan 9 filesystem node with deterministic
  (path-hashed) QIDs and sorted directory enumeration. (15)

## Faults, properties, observation

- **Fault** — an injected perturbation (partition, crash, loss, latency,
  corruption, …); taxonomy in 17.
- **Tag** — a handle for an active fault, used to heal it. (17)
- **Assertion** — a checked property: **Always** (invariant), **Sometimes**
  (liveness witness), **Eventually** (bounded liveness after a trigger),
  **AfterQuiescence** (end-state), **Reachable** (coverage marker). (18)
- **Event log** — the single, totally-ordered, content-addressed record of
  everything that happened; the determinism oracle, assertion input, debugging
  artifact, fork index, and coverage record. (19)
- **Observational entry** — an event-log entry that may legitimately vary between
  equivalent runs (and is excluded from determinism comparison); distinguished in
  the schema, not by a side flag. (19)
- **Coverage** — basic-block coverage harvested from the plugin's TCG-exec hook,
  with no guest instrumentation; feeds fuzzing. (22)

## Control plane & exploration

- **Session** — a live, controllable run, modeled as an actor owning its state. (20)
- **State-space search** — systematic expansion of the temporal graph by
  enumerating Decisions at frontier checkpoints. (22)
- **Fuzzing** — coverage-guided sampling of the schedule space. (22)
- **Reproduction artifact** — the self-contained `(seed, scenario, schedule)`
  bundle that reproduces a run bit-identically. (06, 23)

## Build & integration

- **AOS QEMU package** — the patched, from-source QEMU shipped by AOS that Crucible
  uses; patches inert unless sim mode is on. (11, 26)
- **ratchet** — RFC-0007's language-agnostic Nix-evaluator engine; a conceptual
  cousin, not a dependency; shared substrate gated for later. (26, README)
- **Gate** — a named CI check that must be green to advance a phase. (00, 24)
