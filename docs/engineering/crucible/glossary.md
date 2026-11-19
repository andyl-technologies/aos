# Glossary

This page defines the vocabulary used in Crucible's code and engineering
documentation. Each entry names the type, constant, or module that carries
the concept so the term can be traced to the implementation. Paths are
relative to `crates/crucible/` unless they start with `pkgs/` or `tests/`.

## Model

- **ScenarioDef**: The immutable, content-addressed definition of a run,
  composed from a `World`, a `Plan`, `Properties`, and a `Seed`
  (`World::scenario_def_with_plan_properties_and_seed`). The type in
  `crucible-engine/src/model/scenario/definition.rs` carries the content
  address `id`, the `seed`, and `app_random_draw_cap`. See
  [scenario-model.md](scenario-model.md).

- **World**: The static topology: VM nodes, I/O sub-nodes, and links with their
  per-entity configuration. `World::static_topology` derives the participants,
  scheduling nodes, decision-RNG streams, lookahead graph, and bake set from
  the world alone.

- **Plan**: The declarative event graph and signal-driven fault plan layered
  over a world (`crucible-engine/src/model/plan_properties.rs`). Distinct from
  the Schedule.

- **Properties**: The assertion bundle of a scenario: named `AssertionDef`s
  over `Property` quantifiers. See [assertions.md](assertions.md).

- **Seed**: The 256-bit root entropy of a scenario (`Seed`). All intended
  randomness derives from it through the decision RNG.

- **Decision**: One resolved choice at a scheduling point (`Decision` in
  `crucible-engine/src/model/configuration.rs`): `DeliveryOrder`, `RngDraw`,
  `Override`, `Preemption`, or `Selection`.

- **Schedule**: The totally ordered sequence of decisions taken in a run
  (`Schedule`). It is the thing that varies between runs of one ScenarioDef.

- **Configuration**: `(def, schedule)` (`Configuration`), the only state
  identity. `Configuration::genesis` has an empty schedule. Its materialized
  runtime is a cache, not part of identity.

- **reduce**: `reduce(def, schedule) -> State`, the pure function whose purity
  is the determinism contract (`crucible-engine/src/model/runtime.rs`).

- **try_step**: Appends one decision to a configuration without materializing
  runtime state.

- **instantiate**: Materializes a configuration into a live runtime: load an
  exact cached snapshot if present (checked against the replay oracle),
  otherwise replay from the nearest cached ancestor, otherwise start from the
  baked genesis.

- **bake**: `bake(world) -> GenesisCheckpoint`: boot each VM once to its ready
  point and save it, so every run, including the first, is a resume.

- **Reproduction artifact**: A self-contained `(seed, scenario, schedule)`
  bundle (`ReproductionArtifact` in
  `crucible-engine/src/model/family/instances.rs`) that replays a run
  bit-identically. The CLI's failure artifacts are `.crucible` files that also
  pin the producer build identity. See
  [../../users/crucible/reproduction.md](../../users/crucible/reproduction.md).

## Graphs and checkpoints

- **Spatial graph**: The immutable structure of the system: the World's nodes,
  links, and configuration.

- **Temporal graph**: The content-addressed DAG of checkpoints whose edges are
  schedule deltas. See [execution-graph.md](execution-graph.md).

- **Checkpoint**: A temporal-graph node (`Checkpoint` in
  `crucible-engine/src/model/materialized.rs`) with `parent`, `schedule_delta`,
  `virtual_time`, per-node raw `node_icounts`, and optional materialized
  `state`.

- **Thin checkpoint**: A checkpoint with `state == None`, reconstructed by
  replay from its parent.

- **Fat checkpoint**: A checkpoint with a `MaterializedState` (VM snapshots,
  device overlay deltas, scheduler state). Fast to resume; validated against
  its thin derivation.

- **Genesis checkpoint**: The root checkpoint produced by `bake`
  (`GenesisCheckpoint`).

- **Replay oracle**: The structural check that a materialized checkpoint equals
  the replay of the same schedule from an ancestor, compared by content hash
  (`crucible-test-support/src/replay_oracle.rs`).

- **Content addressing**: Identifying every immutable artifact by the hash of
  its canonical content (`ContentHash`), so equal content has equal identity.

## Determinism

- **Hermetic determinism**: Determinism obtained by eliminating every entropy
  source at its origin, not by recording and replaying nondeterministic events.
  See [determinism.md](determinism.md).

- **Contract A**: Intra-VM hermeticity: fixed image, cmdline, seed, vCPU count,
  RR quantum, and stamped inputs produce a bit-identical instruction stream and
  state trajectory. Modeled by `ContractADriver` in
  `crucible-determinism/src/contract_a.rs`.

- **Contract B**: Injection determinism: the tick at which an input becomes
  visible is a pure function of virtual time and the scheduler's total order,
  never of host arrival time.

- **Sim mode**: The active simulation state: the patched `sim` accelerator
  under precise icount, with the Crucible plugin owning time
  (`icount_crucible_sim_mode()` in the QEMU patch). Simulation control is inert
  outside it.

- **Launch profile**: The validated QEMU configuration
  (`DeterministicLaunchProfile`, produced by
  `LaunchProfileCandidate::try_into_deterministic`) whose canonical
  `crucible.launch.v3` text enters the scenario hash.

- **Decision RNG**: The single seeded source of intended randomness
  (`DecisionRng`, algorithm `splitmix64-v1`). Per-entity `DecisionStream`s are
  forked by `seed ^ stable_domain_name_hash(domain, name)` so adding an entity
  never perturbs another.

- **Ambient guest entropy**: The `fw_cfg` seed at `opt/crucible/seed` and the
  seeded `virtio-rng` that initialize the guest CSPRNG. Opaque to Crucible and
  not explorable.

- **App-requested randomness**: Optional white-box draws requested by a
  cooperating guest, served from the decision RNG and recorded as decisions,
  capped by `app_random_draw_cap`.

- **Execution fingerprint**: A digest of a VM's architectural state at an exact
  aggregate icount: per-vCPU register digests, RR cursor, RAM digest, and
  projected device-state digest
  (`crucible-qemu-shmem/src/shmem/fingerprint_sample.rs`). Computed black-box
  on authenticated request.

- **Time fingerprint**: `ContractATimeFingerprint`: a digest over only the
  time-derived fields of a Contract A run.

- **Divergence bisection**: Localizing the first differing decision and then
  the first differing instruction between two runs
  (`crucible-test-support/src/divergence.rs`).

- **Adversarial host profile**: A deliberately hostile host condition (load,
  core count, reordering, producer/consumer skew) under which determinism
  checks rerun (`crucible-test-support/src/adversarial.rs`).

- **Build identity**: `qemu_build_id`, the hash of the QEMU source, packaging,
  configure flags, atomic patch, and shared-memory ABI
  (`pkgs/emulation/qemu.nix`). Replay is valid only against the same build.

## Time

- **Tick**: One exact picosecond on the shared timeline (`SimTick`). 1,000
  ticks make a guest nanosecond (`SIM_TICKS_PER_NS`, `TICKS_PER_NS`). See
  [virtual-time.md](virtual-time.md).

- **Logical tick**: A node's canonical scheduling coordinate: `raw_retired * 50
  + idle_bias` for a running VM.

- **Raw retired count**: QEMU's aggregate executed-instruction count across all
  vCPUs (`Icount`). Kept separately from logical ticks because idle jumps
  advance time without retiring instructions.

- **Retirement step**: The 50 ticks a retired instruction adds
  (`SIM_TICKS_PER_INSTRUCTION`, `TICKS_PER_INSTRUCTION`).

- **Virtual time**: The shared logical-tick timeline (`VirtualInstant`, alias
  `SimInstant`; serialized as `VirtualTime`). Guest-visible nanoseconds are
  `floor(ticks / 1000)`.

- **SimDuration, SimOffset**: An unsigned tick span and a signed tick offset.
  There is no point-plus-point operation.

- **NodeCounter**: A node-local logical counter before projection onto the
  shared timeline by `NodeTimeMapping`.

- **Idle jump**: A scheduler-authorized advance of an idle VM's logical time to
  an exact tick without retiring instructions (`SchedulerAuthorizedIdleJump`).
  The accumulated jumps are the node's idle bias.

- **Ceiling**: The max-advance logical tick the scheduler publishes in a node's
  shared memory slot (`max_advance_icount`); a node never runs past it.

- **Exact local event**: A host-known next wakeup for a node
  (`ExactLocalEvent`): an armed guest timer deadline, a device completion, or a
  scheduled signal-fault or trigger evaluation.

- **Lookahead**: The conservative bound on how soon a peer can deliver to a
  node: the minimum inbound live-link latency (`NetworkLookahead`). Links have
  a minimum latency of `MIN_LINK_LATENCY`, one nanosecond.

- **Horizon**: The furthest tick a node may run to before synchronizing:
  `min(exact local event, current time + lookahead)`
  (`horizon_from_network_lookahead`). See [scheduling.md](scheduling.md).

- **Quantum**: One scheduler step: advance a node to its horizon, then process
  due cross-node events at that boundary.

- **Quiescence**: No scheduler-state blocker remains: no runnable node, pending
  delivery, timer, or scheduled evaluation (`SchedulerQuiescence`).

- **Conservative PDES (CMB)**: Chandy-Misra-Bryant conservative parallel
  discrete-event simulation: a node advances only when no earlier event can
  still reach it.

- **Delivery tick**: The exact tick at which an input becomes visible to its
  consumer (`FrameEntry::delivery_icount`, `IoCompletion::delivery_tick`).

- **Total order**: The deterministic event order `(virtual_time, consumer node,
  producer node, sequence)` (`ScheduledEventKey`).

- **Warp**: Upstream QEMU's advance of the virtual clock by host time while the
  guest is idle. Disabled in sim mode.

- **Time control**: The plugin's ownership of QEMU's virtual clock, acquired
  through `qemu_plugin_request_time_control` before the first guest
  instruction.

- **RR switch quantum**: `rr_switch_quantum`, the fixed number of retired
  instructions between vCPU switches on the single round-robin TCG thread.
  Default 4096.

## QEMU and transport

- **TCG**: QEMU's Tiny Code Generator. Crucible runs guests only under TCG,
  never KVM.

- **`sim` accelerator**: The TCG-derived accelerator added by the atomic patch
  and selected with `-accel sim,thread=single`. MTTCG and stock `-accel tcg`
  are rejected for Crucible runtimes.

- **Atomic patch**: The single integration patch applied to QEMU 11.1.1
  (`pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch`). See
  [qemu-patch.md](qemu-patch.md).

- **Plugin**: `crucible-qemu-plugin`, the GPL `cdylib` loaded into QEMU with
  `-plugin`; owns time control, device callbacks, and the white-box channel.
  See [qemu-plugin.md](qemu-plugin.md).

- **Shared-memory region**: The versioned process ABI between host and plugins
  (`crucible-qemu-shmem`, magic `CRUCSHM1`, `ABI_VERSION` 30). It holds only
  fixed-width values, byte arrays, offsets, and atomics. See
  [shmem-abi.md](shmem-abi.md).

- **Node slot**: The per-node `NodeSlot` carrying current tick, ceiling, idle
  wake, status, and handoff words.

- **SPSC ring**: A single-producer, single-consumer ring carrying `FrameEntry`
  payloads.

- **FrameEntry**: One queued payload: `delivery_icount` (a tick), `src_node`,
  `seq`, `len`, and data up to `MAX_FRAME_DATA` (4608) bytes.

- **Control protocol**: The versioned Unix-socket protocol used for setup and
  shutdown (`crucible-qemu-protocol`). See
  [control-protocol.md](control-protocol.md).

- **Doorbell**: The trapped instruction a white-box guest uses to signal the
  plugin: an unclaimed x86 I/O port (`x86-port-00e7-unclaimed-v1`) or an inert
  AArch64 `HINT` (`aarch64-hint-4c-inert-v1`). See
  [guest-host-channel.md](guest-host-channel.md).

## Nodes and devices

- **Node**: A participant in the scheduling graph (`SchedulingNodeKind`): a
  `Vm`, a `Disk`, `NineP`, or `Network` sub-node, or the `ControlPlane`
  boundary.

- **VM node**: A QEMU guest.

- **I/O sub-node**: A disk, 9p, or network-link participant scheduled as a
  first-class node with its own exact-tick clock and deterministic completion
  events. See [io-subnodes.md](io-subnodes.md).

- **CoW overlay**: Copy-on-write storage over a read-only base image; the only
  place guest writes land.

- **9p server**: The deterministic Plan 9 filesystem sub-node, with path-hashed
  QIDs and sorted directory enumeration (`crucible-device/src/ninep.rs`).

## Observation and control

- **Event log**: The single, totally ordered, content-addressed record of a
  run. Entries are `Causal` or `Observational` (`SchedulerEventLogClass`); only
  the causal projection takes part in determinism comparison. See
  [event-log.md](event-log.md).

- **Property quantifiers**: `Always` (invariant), `Sometimes` (liveness
  witness), `Eventually` (bounded liveness after a trigger), `AfterQuiescence`
  (end state), and `Reachable` (coverage-style).

- **Coverage**: Basic-block coverage harvested from the plugin's TCG execution
  hook without guest instrumentation; observational only.

- **Session**: A live, controllable run owned by the `SessionActor` in
  `crucible-session`, which accepts control requests at quantum boundaries. See
  [session.md](session.md).

- **State-space search**: Systematic expansion of the temporal graph by
  enumerating decisions at frontier checkpoints. See
  [exploration.md](exploration.md).

- **Gate**: A named Nix check (`checks.crucible.<phase>.gates.<name>`) that
  must pass before dependent checks run. See
  [testing-and-gates.md](testing-and-gates.md).
