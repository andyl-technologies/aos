# 05 — Execution model: `Configuration`, `step`, `instantiate`, `bake`

This file specifies the conceptual spine of Crucible: the single execution model
that makes **start, resume, and fork the same operation**. Everything else in the
RFC — the spatial graph (06), the temporal graph (07), scheduling (08), QEMU
integration (10–12), and the session control plane (20) — is an implementation of
the small algebra defined here.

The thesis is one sentence: *a run is a pure reduction of an immutable definition
under a recorded sequence of decisions, and producing a runnable state from any
point in that reduction — including the very first — is one recursive function
whose base case is boot.* When that holds, save/resume/fork/replay/search stop
being four hand-written code paths with four lifecycle-bug surfaces and become
four call sites of the same function. This file makes that precise.

It satisfies the headline goal [G-4] (one unified execution model) and the
invariants [INV-1] (purity of reduction), [INV-2] (replay-oracle equality), and
[INV-6] (content addressing). It depends on, and is the consumer of, the
determinism contract in [`04-determinism-contract.md`](04-determinism-contract.md):
this file assumes Contract A (intra-VM hermeticity) and Contract B (injection
determinism) hold, and defines the model that those contracts make sound.

## 1. The shape of the model in one breath

There is exactly **one state type** — a `Configuration` — and exactly **one
state-producing operation** — `instantiate`. Everything is expressed in terms of
them:

```text
  ScenarioDef        immutable definition of the run                (file 06)
  Decision           one resolved nondeterministic choice           (this file, §3)
  Schedule = [Decision]   totally-ordered list of decisions          (this file, §3)
  Configuration = (ScenarioDef, Schedule)   the ONLY state type      (this file, §2)

  step:        Configuration × Decision → Configuration   (append a decision)
  reduce:      (ScenarioDef, Schedule)  → State           (pure semantics, INV-1)
  instantiate: Configuration            → RuntimeState     (recursive; base case = boot)
  bake:        World                    → genesis_checkpoint (boot once, snapshot)
```

`reduce` is the *meaning* of a configuration (its abstract state); `instantiate`
is the *realization* of that meaning as a live, controllable QEMU runtime backed
by the temporal-graph cache. The two are tied together by the replay oracle
[INV-2]: realizing a configuration two different ways (from a stored snapshot vs.
by re-reducing from an ancestor) MUST yield the same state.

- **[EXEC-1]** The execution state of a Crucible run MUST be modeled as a
  `Configuration = (ScenarioDef, Schedule)` and nothing else. The materialized
  QEMU runtime, device overlays, and scheduler memory that exist while a run is
  live are a **cache** of `reduce(ScenarioDef, Schedule)`, not part of the run's
  identity. *Gate:* `gate:replay-oracle`. *Spec:* §2.

- **[EXEC-2]** Two configurations are equal if and only if their `ScenarioDef`
  content hash and their `Schedule` are equal. A configuration's identity MUST
  NOT depend on whether, where, or how its runtime has been materialized.
  *Gate:* `gate:content-address`. *Spec:* §2.

## 2. `Configuration`: the only state type

A `Configuration` is the pair of *what the run is* (the `ScenarioDef`, the spatial
graph, "configuration #0," defined in [`06-spatial-graph.md`](06-spatial-graph.md))
and *which decisions have been taken* (the `Schedule`). It is the node identity in
the temporal graph (07): the temporal graph is the closure of the genesis
configuration `(def, [])` under `step`.

The critical design choice — and the one that the rest of the system leans on — is
that **identity is `(def, schedule)`, not the materialized runtime**. A 4 GiB VM
memory image, the CoW disk overlays, and the scheduler's in-flight queues are all
*derived* from `(def, schedule)` by `reduce`. They are expensive to compute, so we
cache them as fat checkpoints (07), but they are never the source of truth. This is
what lets a checkpoint be stored "thin" — as just `(parent, schedule_delta)` — and
reconstructed on demand, and it is what makes the replay oracle even *expressible*:
"the cache must agree with the recomputation."

```rust,illustrative
/// The immutable definition of a run: topology, fault plan, properties, seed.
/// Content-addressed; see file 06. This is "configuration #0."
// NOTE: `world`/`plan`/`properties` are shown inline here for readability;
// canonically they are content-addressed `Ref<_>` values and `id` is BLAKE3 over
// the component hashes plus the Seed — see 06 §2 [SPAT-3]/[SPAT-4], which is
// authoritative.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ScenarioDef {
    /// BLAKE3 over the tuple of component hashes (World, Plan, Properties) plus
    /// the Seed (06 §2 [SPAT-4], authoritative). Two `ScenarioDef`s are equal iff
    /// their `id` is equal.
    pub id: ContentHash,
    pub world: Ref<World>,         // nodes + links + per-node static config (file 06)
    pub plan: Ref<Plan>,           // declarative fault/event schedule over v-time (06, 17)
    pub properties: Ref<Properties>, // assertions to check (file 18)
    pub seed: Seed,           // root entropy for all decision RNG (file 04)
}

/// The ONLY state type. Identity is `(def, schedule)`; the runtime is a cache.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Configuration {
    pub def: ScenarioDef,
    pub schedule: Schedule,
}

impl Configuration {
    /// Content address of this configuration: `hash(def.id, schedule)`.
    /// This is the temporal-graph node id and the checkpoint cache key.
    pub fn id(&self) -> ContentHash {
        ContentHash::of((&self.def.id, &self.schedule))
    }

    /// The genesis configuration of a scenario: the empty schedule.
    pub fn genesis(def: ScenarioDef) -> Self {
        Self { def, schedule: Schedule::empty() }
    }

    /// Whether this configuration is the genesis (no decisions taken).
    pub fn is_genesis(&self) -> bool {
        self.schedule.is_empty()
    }
}
```

- **[EXEC-3]** The genesis configuration of a scenario MUST be exactly
  `Configuration::genesis(def) = (def, [])`. Genesis is not a special-cased
  initial object; it is the configuration with the empty schedule, and the spatial
  graph (06) is its `ScenarioDef`. *Spec:* §2.

- **[EXEC-4]** `Configuration::id()` MUST be `hash(def.id, schedule)` and MUST be
  the node identity used by the temporal graph (07) and the checkpoint cache key.
  Equal content MUST produce equal ids ([INV-6]); unequal schedules MUST produce
  unequal ids. *Gate:* `gate:content-address`. *Spec:* §2.

- **[EXEC-5]** A `Configuration` MUST be cheap to construct, clone, and hash
  independently of whether its runtime has ever been materialized. Constructing a
  configuration MUST NOT boot a VM, allocate guest memory, or touch the temporal
  graph cache; those happen only in `instantiate` (§5). *Spec:* §2, §5.

## 3. `Decision` and `Schedule`: the recorded nondeterminism

The whole point of Crucible is that *intra-VM execution is deterministic at the
source* (Contract A, file 04) — so the only nondeterminism left in the system is
**cross-node ordering and probabilistic choice**, and that nondeterminism is
finite, enumerable, and recorded. A `Decision` is one resolved such choice; a
`Schedule` is the totally-ordered list of all decisions taken so far.

A `Decision` is *not* a guest instruction, a delivered byte, or a wall-clock
event. It is the resolution of a *scheduling point*: a moment where the
authoritative scheduler ([INV-8], file 08) had a genuine choice and resolved it.
The taxonomy of decisions is fixed and small:

```rust,illustrative
/// One resolved nondeterministic choice at a scheduling point.
///
/// A `Decision` is the edge of the temporal graph (07). It is the *only*
/// place nondeterminism enters the model; intra-VM execution between
/// decisions is a pure function of state (Contract A, file 04).
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Tie-break: when two cross-node events are due at the identical
    /// `(virtual_time, ...)` key, the order they are delivered in.
    /// Resolved by the deterministic total order (INV-3) or, on a true
    /// tie, by a decision-RNG draw recorded here.
    DeliveryOrder { at: VirtualTime, order: SmallVec<EventKey> },

    /// Whether a *probabilistic* fault (a loss/latency/corruption with a
    /// per-event probability) fires at this point. The boolean outcome is
    /// recorded so replay reproduces it without re-rolling.
    FaultFires { at: VirtualTime, fault: FaultId, fired: bool },

    /// A raw draw from the seeded decision RNG (file 04), recorded by the
    /// stream it came from so adding a node doesn't perturb other streams.
    RngDraw { stream: RngStreamId, value: u64 },

    /// A schedule-space-search or fuzzing choice that *overrides* the
    /// default resolution at a scheduling point (file 22). Carries the
    /// same shape as the choice it replaces so replay is uniform.
    Override { point: SchedulingPoint, choice: ChoiceTag },

    /// A vCPU-switch or interrupt-injection point chosen by the scheduler
    /// (file 08). The DEFAULT sequence is deterministic engine behavior —
    /// recomputable from `rr_switch_quantum` plus armed deadlines, hence
    /// audit-only (EXEC-8). A NON-DEFAULT, explorer-supplied preemption
    /// carries information that cannot be recomputed and therefore MUST be
    /// stored (EXEC-33). For a single-vCPU node, `InterruptAt` varies
    /// *when* the periodic timer/external interrupt preempts the one vCPU.
    Preemption { node: NodeId, at: Icount, kind: PreemptionKind },

    /// A served app-requested random draw (white-box, optional). Reproducible:
    /// on canonical replay it is re-derived from the seeded `stream`; an
    /// OVERRIDDEN `AppRandom` MUST be served from the recorded `value`, never
    /// re-rolled (mirrors how `FaultFires` replays). Forkable per stream so
    /// adding a node does not perturb unrelated streams. See EXEC-34.
    AppRandom {
        node: NodeId,
        stream: RngStreamId,
        request_id: u64,
        width: u8,
        value: u64,
    },
}

/// The kind of a `Decision::Preemption` point.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum PreemptionKind {
    /// A multi-vCPU round-robin switch from one vCPU to another. The default
    /// is round-robin at `rr_switch_quantum` (file 08); an explorer may move
    /// the switch point to vary interleavings.
    VcpuSwitch { from_vcpu: VcpuId, to_vcpu: VcpuId },

    /// A timer or external interrupt taken at a chosen `at: Icount` on the
    /// target vCPU. Works for N = 1 to vary *when* the periodic timer
    /// preempts the single vCPU.
    InterruptAt { target_vcpu: VcpuId, irq: IrqVector },
}

/// A totally-ordered list of decisions. The thing that varies between
/// runs of one `ScenarioDef`; the input, with the def, to `reduce`.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Schedule(Vec<Decision>);

impl Schedule {
    pub fn empty() -> Self { Self(Vec::new()) }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
    pub fn len(&self) -> usize { self.0.len() }

    /// The prefix `Schedule[0..t]` — the schedule up to (not including)
    /// decision `t`. Used by `reduce` to define `State(t)`.
    pub fn prefix(&self, t: usize) -> Self { Self(self.0[..t].to_vec()) }

    /// Append one decision, producing a new schedule. Pure; does not mutate.
    pub fn appended(&self, d: Decision) -> Self {
        let mut v = self.0.clone();
        v.push(d);
        Self(v)
    }
}
```

- **[EXEC-6]** A `Decision` MUST capture exactly one resolved nondeterministic
  choice at a scheduling point and MUST be one of the closed taxonomy in §3
  (delivery order on a tie, whether a probabilistic fault fires, a decision-RNG
  draw, a search/fuzz override, a vCPU-switch/interrupt preemption, or a served
  app-requested random draw). Intra-VM execution between two consecutive
  decisions MUST contain no recorded nondeterminism, because Contract A (file 04)
  has eliminated it at the source. *Gate:* `gate:single-vm-fingerprint`.
  *Spec:* §3.

- **[EXEC-7]** A `Schedule` MUST be a *totally ordered* sequence of `Decision`s.
  The order is the order in which the authoritative scheduler resolved the
  decisions ([INV-8]); it is independent of host wall-clock and host thread
  scheduling ([INV-1]). *Gate:* `gate:replay-oracle`. *Spec:* §3.

- **[EXEC-8]** `Decision` values that are *resolved by content* (a delivery order
  fully determined by [INV-3]'s `(virtual_time, consumer node_id, producer node_id, sequence)` total order,
  with no genuine tie) MAY be recorded for audit but MUST be reproducible from the
  `ScenarioDef` and the preceding schedule alone. Only *genuine* choices
  (true ties broken by RNG, probabilistic fault outcomes, draws, overrides) carry
  information that cannot be recomputed and therefore MUST be stored. *Spec:* §3.

- **[EXEC-9]** Adding, removing, or renaming a node in the `World` MUST NOT
  perturb the decision-RNG streams of unrelated nodes: per-entity RNG streams are
  forked by name-hash (file 04). A `Decision::RngDraw` MUST record its
  `RngStreamId` so a schedule remains interpretable after the def changes only in
  unrelated parts. *Spec:* §3; cross-ref file 04 (Decision RNG).

### `step`: append one decision

`step` is the temporal-graph edge constructor. It is pure and total: given a
configuration and a decision, it returns the child configuration. It does **not**
run anything.

```rust,illustrative
/// Append one decision to a configuration, producing its child.
///
/// This is the temporal-graph edge constructor (07). Pure and cheap:
/// it constructs identity, it does not execute. Running is `instantiate`.
pub fn step(config: &Configuration, decision: Decision) -> Configuration {
    Configuration {
        def: config.def.clone(),
        schedule: config.schedule.appended(decision),
    }
}
```

- **[EXEC-10]** `step(config, d)` MUST return `(config.def, config.schedule ++
  [d])` and MUST NOT execute, boot, or materialize anything. `step` constructs
  identity; `instantiate` (§5) constructs runtime. Keeping these separate is what
  lets the temporal graph (07) be built, hashed, and traversed without running.
  *Spec:* §3.

## 4. `reduce`: the pure meaning, and the reduction identity

`reduce` is the denotational semantics of the model: it maps a `(ScenarioDef,
Schedule)` to the abstract `State` it denotes. It is the function [INV-1] is
about.

```rust,illustrative
/// The pure reduction: the abstract state denoted by a configuration.
///
/// `State(t) = reduce(def, schedule.prefix(t))` (INV-1). No wall-clock,
/// host scheduling order, host entropy, or uncontrolled input may
/// influence the result. `reduce` is the *meaning*; `instantiate` is the
/// *realization* of that meaning as a live runtime.
pub fn reduce(def: &ScenarioDef, schedule: &Schedule) -> State {
    let mut state = State::genesis(def); // boot-ready state of every node
    for decision in schedule.iter() {
        // Advance every node by Contract A (deterministic intra-VM exec)
        // up to the next scheduling point, then apply `decision`.
        state = advance_to_next_point_then_apply(state, def, decision);
    }
    state
}
```

The reduction identity is the load-bearing equation of the whole RFC, restated
here from [INV-1] with its execution-model consequences:

```text
  State(t) = reduce(ScenarioDef, Schedule[0..t])                 (INV-1)
```

Two consequences that this file is responsible for:

1. **Resume + continue is bit-identical to an uninterrupted run.** Because the
   scheduler state and every RNG stream's position live *inside* the configuration
   (they are functions of `(def, schedule)`, recomputed by `reduce`), stopping at
   `t`, persisting the configuration, and continuing later cannot diverge from
   never stopping. There is no "live-only" state to lose. (Contrast: a design that
   kept scheduler/RNG state only in the live process would have to serialize it
   perfectly on every pause — a classic lifecycle-bug surface this model deletes.)

2. **The reduction is prefix-closed.** `State(t)` depends only on `Schedule[0..t]`,
   so any prefix of a schedule is itself a valid configuration with a well-defined
   state — which is exactly what makes *fork from a non-tip configuration* (§6) a
   first-class operation rather than a special case.

- **[EXEC-11]** `reduce(def, schedule)` MUST be a pure function of its arguments:
  for fixed `(def, schedule)` it MUST return content-equal `State` on every host,
  in any process, regardless of wall-clock, host load, or host thread scheduling
  ([INV-1]). Any code path inside `reduce` that could read host nondeterminism
  MUST be eliminated or routed through the seeded decision source ([INV-10]).
  *Gate:* `gate:replay-oracle`, `gate:harness-lint`. *Spec:* §4.

- **[EXEC-12]** The reduction MUST be prefix-closed: for all `t ≤ schedule.len()`,
  `reduce(def, schedule.prefix(t))` MUST equal the state Crucible would have at
  decision `t` of an uninterrupted run of `(def, schedule)`. This is the property
  that makes every prefix a valid fork point (§6). *Gate:* `gate:replay-oracle`.
  *Spec:* §4.

- **[EXEC-13]** Resuming a configuration and continuing MUST be bit-identical to
  an uninterrupted run of the same configuration, because scheduler state and RNG
  stream positions are functions of `(def, schedule)` and live inside the
  configuration, not in ephemeral process memory. *Gate:* `gate:replay-oracle`,
  `gate:single-vm-fingerprint`. *Spec:* §4, §5.

## 5. `instantiate`: one recursive function, base case is boot

`instantiate` turns a configuration into a *live, controllable runtime* — booted
QEMU processes, mapped guest memory, attached CoW device overlays, a primed
scheduler. It is the only function that materializes runtime, and it is
**recursive, with boot as its base case**:

```text
instantiate(config):
    if cached_snapshot(config.id):                 # FAT checkpoint exists
        loadvm(cached_snapshot(config.id))         #   warm resume / fork target
    elif (anc := nearest_cached_ancestor(config)): # some prefix is materialized
        rt = instantiate(anc)                       #   recurse to that ancestor
        replay(rt, schedule[anc.len .. config.len])#   partial replay forward
    else:                                           # nothing cached on this path
        instantiate(genesis(config.def))            #   recurse to genesis...
        # ...whose own base case is the baked genesis snapshot (§7),
        # so the ONLY true boot in the system is `bake`.
```

In words: to make a configuration runnable, prefer a stored snapshot of *exactly
it*; failing that, find the nearest stored ancestor on its path and replay forward
the missing schedule suffix; failing even that, recurse toward genesis — and
genesis's base case is the **baked** genesis checkpoint (§7), which is a `loadvm`
of a snapshot, not a cold boot. The cold boot path is reached **only** inside
`bake`, run once per `World`, never in the hot loop.

```rust,illustrative
/// Materialize a configuration into a live, controllable runtime.
///
/// Recursive; base case is the baked genesis snapshot (§7). Prefers an
/// exact cached snapshot, else replays from the nearest cached ancestor,
/// else recurses toward genesis. The replay oracle (INV-2) guarantees
/// every branch yields the same `RuntimeState`.
pub fn instantiate(graph: &TemporalGraph, config: &Configuration) -> Result<RuntimeState> {
    // Base/warm case: an exact snapshot of this configuration exists.
    if let Some(snap) = graph.cached_snapshot(config.id()) {
        return RuntimeState::loadvm(snap);          // warm resume / fork target
    }
    // Partial-replay case: the nearest materialized prefix on this path.
    if let Some(anc) = graph.nearest_cached_ancestor(config) {
        let mut rt = instantiate(graph, &anc)?;     // recurse to the ancestor
        let suffix = config.schedule.range(anc.schedule.len()..);
        rt.replay(&config.def, suffix)?;            // step forward over the suffix
        return Ok(rt);
    }
    // Cold case: only genesis can reach here, and its base case is the
    // *baked* snapshot (§7) — a loadvm, not a boot. The single true boot
    // in the whole system lives inside `bake`.
    debug_assert!(config.is_genesis());
    let genesis_snap = graph.genesis_snapshot(&config.def)?; // baked once, §7
    RuntimeState::loadvm(genesis_snap)
}
```

### Start ≡ resume ≡ fork — the same call

The headline of this file. Each of the operations the prior generation of such
tools implemented as a *separate code path* is, here, one call to `instantiate`
distinguished only by which configuration it is handed:

```text
  start  config  = instantiate( (def, [])               )   # genesis
  resume config  = instantiate( (def, schedule)         )   # the tip
  fork   config  = instantiate( (def, schedule[0..k])   )   # a non-tip prefix
```

- **start** is `instantiate` of the genesis configuration `(def, [])`.
- **resume** is `instantiate` of a configuration whose schedule is the full run so
  far (the tip of a temporal-graph path).
- **fork** is `instantiate` of a configuration whose schedule is a *prefix* of an
  existing run (a non-tip node) — from which exploration appends *different*
  decisions.

There is no `boot()` distinct from `loadvm()` distinct from `fork()`. There is
`instantiate`, and the recursion picks the cheapest correct realization. This is
the elimination of the lifecycle-bug class the prior exploration suffered:
separate boot/resume/fork paths inevitably drift (a field saved on resume but not
on fork, a counter reset on boot but not on loadvm), and every such drift is a
silent determinism break. With one path, "it resumes correctly" and "it forks
correctly" are *the same test* (§8).

- **[EXEC-14]** `instantiate(config)` MUST be the single entry point that produces
  a runnable `RuntimeState` from any configuration. `start`, `resume`, and `fork`
  MUST be implemented as calls to `instantiate` differing only in the
  configuration argument (genesis, tip, and non-tip prefix respectively). No
  separate boot/resume/fork realization paths may exist. *Gate:*
  `gate:replay-oracle`. *Spec:* §5, §6.

- **[EXEC-15]** `instantiate` MUST be recursive with boot as its base case, and
  MUST resolve in this priority order: (1) `loadvm` an exact cached snapshot of
  `config.id()`; else (2) `instantiate` the nearest cached ancestor and replay the
  missing schedule suffix; else (3) recurse toward genesis. The recursion MUST
  terminate at the baked genesis snapshot (§7). *Gate:* `gate:replay-oracle`.
  *Spec:* §5, §7.

- **[EXEC-16]** The *only* cold-boot of a guest in the entire system MUST occur
  inside `bake` (§7). The hot loop — every `start`, `resume`, `fork`, replay, and
  search step — MUST reach a runtime via `loadvm` of a snapshot (genesis or a
  descendant) plus zero-or-more replay steps, never via cold boot. *Gate:*
  `gate:replay-oracle`. *Spec:* §5, §7.

- **[EXEC-17]** Every branch of `instantiate` (exact-snapshot load, ancestor
  replay, genesis load) MUST yield a `RuntimeState` whose state is content-equal
  for the same `config` ([INV-2], the replay oracle). The choice of branch is a
  performance decision; it MUST NOT be observable in the resulting state.
  *Gate:* `gate:replay-oracle`. *Spec:* §5.

## 6. `bake`: genesis-as-checkpoint, and why there is no boot path in the hot loop

A cold boot of a guest — firmware, kernel decompression, init, userspace coming up
to a steady state — is the single least-deterministic, slowest, and least
interesting phase of a run. Crucible refuses to put it in the hot loop. Instead,
`bake` runs it **once per `World`**: it boots each VM to a defined *ready point*,
snapshots, and content-addresses the result as the **genesis checkpoint**. After
`bake`, the genesis configuration `(def, [])` is realized by a `loadvm` of that
snapshot — so even the *first* run is, mechanically, a resume.

```rust,illustrative
/// Boot each VM in `world` once to its defined ready point, snapshot, and
/// content-address the result as the genesis checkpoint. Runs ONCE per
/// `World`; its output is cached and shared (INV-6). This is the only
/// cold-boot path in Crucible.
pub fn bake(world: &World) -> Result<GenesisCheckpoint> {
    let mut node_snaps = Vec::new();
    for node in world.nodes_sorted() {              // deterministic order
        let mut rt = cold_boot(node)?;              // the ONE boot
        rt.run_to_ready_point(node.ready_point)?;   // §6 "ready point"
        node_snaps.push(rt.snapshot()?);            // content-addressed blob
    }
    Ok(GenesisCheckpoint::content_addressed(world, node_snaps))
}
```

- **[EXEC-18]** `bake(world)` MUST boot each VM exactly once to its defined ready
  point, snapshot it, and content-address the bundle as the genesis checkpoint of
  every `ScenarioDef` whose `World` it is. The genesis checkpoint MUST be cached
  and shared across all scenarios and forks with the same `World` ([INV-6]).
  *Gate:* `gate:content-address`. *Spec:* §6.

- **[EXEC-19]** After `bake`, the genesis configuration `(def, [])` MUST be
  realized by `loadvm` of the genesis checkpoint, never by a cold boot. The first
  run of a scenario MUST therefore be, mechanically, a resume. *Gate:*
  `gate:replay-oracle`. *Spec:* §6.

### The one fuzzy bit: defining the deterministic "ready point"

Everything after `t = 0` is determinism-pinned by Contracts A and B. But *where is
`t = 0`?* The ready point is the one genuinely fuzzy design choice in the model,
because "the system has finished booting" is not a crisp predicate. The ready
point determines *where* `t = 0` sits; it does **not** affect determinism *after*
`t = 0` (that is the contract's job). The candidate definitions, in increasing
order of fidelity and guest-cooperation cost:

- **Fixed icount.** Run to a constant instruction count (e.g. boot for exactly N
  instructions). Maximally simple and black-box, but brittle: a kernel/image
  change shifts where steady state lands relative to N.
- **First network-idle.** Snapshot at the first virtual-time point where no node
  has pending inbound/outbound link activity for a defined quiescence window.
  Black-box, robust to small image changes, but requires a quiescence definition
  (file 08).
- **Console marker (black-box).** Snapshot when a configured marker string appears
  on the guest console/serial. Black-box, guest-agnostic, but depends on the
  guest's boot output being stable.
- **Agent signal (white-box).** Snapshot when an optional in-guest agent signals
  "ready" via the guest↔host channel (file 16). Highest fidelity ("ready" means
  what the workload says it means), but requires the white-box opt-in ([G-3]).

The ready-point policy is part of the per-node `World` config (06); the mechanism
for the white-box signal is the doorbell on the guest↔host channel (16). The
determinism harness (24) pins, for a given `World`, that `bake` reaches a
content-identical genesis snapshot across runs — so whichever policy is chosen,
the ready point itself is deterministic.

- **[EXEC-20]** Each VM's ready point MUST be defined by an explicit, deterministic
  policy in the `World` (06): fixed icount, first network-idle (08), a black-box
  console marker, or an OPTIONAL white-box agent signal (16). The chosen policy
  MUST yield a content-identical genesis snapshot across `bake` runs of the same
  `World`. The ready point fixes *where* `t = 0` is; it MUST NOT affect determinism
  after `t = 0` (Contracts A/B, file 04). *Gate:* `gate:content-address`,
  `gate:any-guest`. *Spec:* §6; forward-ref file 16 (guest↔host channel).

## 7. Homogeneity: a VM's state is always a content-addressed blob reference

A corollary of "the runtime is a cache" is that there is **no type-level
distinction between an initial VM state and a materialized one**. In every
configuration — genesis or deep in the temporal graph — a VM's state is *a
content-addressed blob reference*. At genesis it references the **baked** blob
(§6); at a later node it references a **copy-on-write delta** layered over its
parent's blob (07, 15). The type is the same; only the referent differs.

```rust,illustrative
/// A VM's state inside any configuration: ALWAYS a content-addressed blob
/// reference. No "initial vs materialized" dichotomy — genesis references
/// the baked blob; later nodes reference CoW deltas over their parent.
pub enum NodeBlobRef {
    /// Genesis: the baked snapshot for this node's `World` entry (§6).
    Baked(ContentHash),
    /// A copy-on-write delta over a parent blob, plus the resolved state hash.
    CowDelta {
        parent: ContentHash,
        delta: ContentHash,
        resolved: ContentHash,
    },
}
```

This homogeneity is what keeps `instantiate` uniform: it never has to ask "is this
the special initial state or a real one?" — it always resolves a blob reference,
whether by `loadvm` of a baked blob or by stacking CoW deltas. It is also what lets
the replay oracle compare a fat checkpoint to its thin derivation by hash: both are
just blob references, and equal content is equal identity ([INV-6]).

- **[EXEC-21]** A VM's state within a `Configuration` MUST be represented uniformly
  as a content-addressed blob reference. There MUST NOT be a type-level or code
  path distinction between an "initial" VM state and a "materialized" one: genesis
  references the baked blob (§6); descendants reference CoW deltas (07, 15).
  *Gate:* `gate:content-address`. *Spec:* §7; forward-ref files 07, 13, 15.

- **[EXEC-22]** Two configurations that denote content-equal VM state MUST have
  content-equal blob references for that VM, regardless of whether one was reached
  by `loadvm` of a fat checkpoint and the other by replay producing a thin
  checkpoint ([INV-2], [INV-6]). *Gate:* `gate:replay-oracle`,
  `gate:content-address`. *Spec:* §7.

## 8. The replay oracle: structural correctness as an invariant

The model's correctness is not a property of careful coding — it is a *structural
invariant of the data model, enforced as a gate*. The replay oracle [INV-2] says:
for any configuration, the state obtained by materializing a stored snapshot MUST
equal the state obtained by re-reducing from any ancestor along the same schedule,
compared by content hash; and a fat checkpoint MUST hash-equal its thin
derivation.

In execution-model terms, the oracle is the statement that **the two ways of
realizing a configuration agree**:

```text
  loadvm(snapshot(config))  ≡  replay(instantiate(ancestor), suffix)   (INV-2)
```

This is checked by re-instantiating the same configuration via different
`instantiate` branches and comparing the resulting `RuntimeState` fingerprints
(24). It is a CI gate (`gate:replay-oracle`), not an aspiration. Because every
operation in §6 is a call to `instantiate`, the oracle simultaneously validates
save, resume, fork, and snapshot completeness — they are the same operation, so a
single equality check covers all four (§9).

- **[EXEC-23]** For every configuration, `loadvm` of its stored snapshot MUST
  produce a `RuntimeState` content-equal to replay-from-ancestor of the same
  configuration ([INV-2], the replay oracle). A fat checkpoint MUST hash-equal its
  thin derivation. This MUST be enforced as a CI gate, not left to convention.
  *Gate:* `gate:replay-oracle`. *Spec:* §8; forward-ref file 24
  (`gate:replay-oracle`).

- **[EXEC-24]** A detected oracle violation MUST localize to the first differing
  decision or instruction (divergence bisection, file 24) rather than be smoothed
  over ([INV-10]). The model MUST NOT contain any path that "repairs" a divergence
  silently. *Gate:* `gate:divergence-bisect`. *Spec:* §8.

## 9. The five operations, all reduced to this model

Every user-facing operation is expressible as production and consumption of
`Configuration`s and `Checkpoint`s. The point of the table is that the left column
is what a user thinks they are doing and the right column is the *same small
algebra* underneath.

```text
  operation     in terms of the model
  ──────────    ───────────────────────────────────────────────────────────
  start         instantiate( genesis(def) )                       (§5, §6)
  resume        instantiate( (def, schedule) )  at the tip        (§5)
  fork          instantiate( (def, schedule[0..k]) )  k < len     (§5, §6)
                then step(...) with *different* decisions
  replay        reduce( def, schedule )  and assert fingerprint   (§4, §8)
                equals a stored checkpoint's (the oracle)
  save          materialize instantiate(config) → fat checkpoint  (§5, §7)
                keyed by config.id(); thin = (parent, delta)
  search /      enumerate Decisions at a frontier configuration,
  state-space   step(...) each → child configs, instantiate the   (§3, §5)
                interesting ones; the temporal graph is the work-list (07, 22)
```

- **start / resume / fork** are `instantiate` of genesis / tip / prefix
  configurations (§5).
- **replay** is `reduce` (or, operationally, a fresh `instantiate` via the replay
  branch) followed by a fingerprint comparison against a stored checkpoint — i.e.
  it *is* the replay oracle, run on demand.
- **save** is materializing `instantiate(config)` into a fat checkpoint keyed by
  `config.id()`, with the thin form `(parent, schedule_delta)` always available as
  the source of truth (07).
- **state-space search / fuzzing** is enumerating candidate `Decision`s at a
  frontier configuration, `step`-ping each to a child configuration, and
  `instantiate`-ing the ones worth exploring; the temporal graph (07) is the
  work-list and the dedup index (a configuration reached two ways is one node, by
  content address). Details in file 22.

- **[EXEC-25]** Every user-facing operation (start, resume, fork, replay, save,
  state-space search, fuzzing) MUST be expressed purely as construction of
  `Configuration`s (via `step`), realization via `instantiate`, and content-keyed
  caching of `Checkpoint`s. No operation may introduce a state representation
  outside the `(ScenarioDef, Schedule)` model. *Gate:* `gate:replay-oracle`,
  `gate:content-address`. *Spec:* §9; forward-ref files 07, 22.

- **[EXEC-26]** A configuration reached by two different decision paths that
  denote the same `(def, schedule)` MUST be a single node in the temporal graph,
  identified by content address ([INV-6]); state-space search MUST deduplicate
  against it rather than re-materialize. *Gate:* `gate:content-address`.
  *Spec:* §9; forward-ref file 07.

## 10. The async/state-machine realization

The model above is pure; realizing it as a live, controllable QEMU runtime needs a
host-side driver. Crucible realizes it as an **explicit async state machine** — an
`Engine` owned by a `Session` actor (file 20) — that owns the runtime, processes
control commands and execution steps in **bounded quanta**, and yields between
quanta so that control operations (pause, inspect, fork, save) are serviced at
well-defined points with **no long-held locks** ([INV-8], `gate:control-responsive`).

The design rule is: *the engine never blocks the control plane for an unbounded
time.* A "step" advances the minimum-horizon node by one scheduler quantum (08),
applies due decisions, appends to the event log, and returns — then the actor loop
checks its command mailbox before stepping again. State that an external observer
needs while a long run is in progress (current virtual time, event-log length, run
state) is mirrored lock-free so a `Watch`-style RPC never has to take the engine
lock to read it.

```rust,illustrative
/// Explicit run-state of the engine. Control operations are only valid at
/// well-defined transitions, and the actor loop yields between quanta so
/// the control plane (file 20) is always responsive (INV-8).
pub enum EngineState {
    /// Configuration loaded, runtime not yet instantiated.
    Loaded,
    /// Actively stepping the scheduler in bounded quanta.
    Running,
    /// Paused at a quantum boundary: inspect, step, fork, save are valid here.
    Paused { reason: PauseReason },
    /// Terminal: quiescent, property-violated, or stopped.
    Stopped { outcome: Outcome },
}

/// The host-side driver: owns the runtime, drives `instantiate`/step, and
/// processes commands between bounded quanta. Lives inside the `Session`
/// actor (file 20); never holds a lock across a quantum.
pub struct Engine {
    config: Configuration,        // the source of truth (§2)
    runtime: Option<RuntimeState>, // the cache, produced by `instantiate` (§5)
    state: EngineState,
    graph: TemporalGraph,         // checkpoint cache + work-list (07)
}

impl Engine {
    /// Advance exactly one scheduler quantum, then return control. A
    /// quantum: pick the minimum-horizon node (08), advance it under
    /// Contract A, apply due decisions, append to the event log (19).
    ///
    /// # Errors
    /// Returns an error if the runtime diverges from the replay oracle
    /// (INV-2) or a node fails to advance.
    pub fn step_quantum(&mut self) -> Result<StepOutcome> {
        // ... advance min-horizon node by one quantum; apply Decisions ...
        // Bounded work, then yield: the actor loop checks its mailbox.
        Ok(StepOutcome::Advanced)
    }

    /// Realize this engine's configuration into a live runtime via
    /// `instantiate` (§5). Idempotent: start, resume, and fork all land here.
    pub fn instantiate(&mut self) -> Result<()> {
        self.runtime = Some(instantiate(&self.graph, &self.config)?);
        self.state = EngineState::Paused { reason: PauseReason::Instantiated };
        Ok(())
    }
}

/// The actor loop: poll the command mailbox, then step one quantum, then
/// repeat. Commands are serviced at quantum boundaries — never mid-quantum,
/// never under a long-held lock (INV-8, gate:control-responsive).
async fn run_engine(mut engine: Engine, mut commands: CommandRx) -> Result<()> {
    loop {
        match engine.state {
            EngineState::Running => {
                // Service any pending control command first, then step.
                if let Ok(cmd) = commands.try_recv() {
                    engine.apply_command(cmd)?;        // pause/fork/save/inspect
                    continue;
                }
                if engine.step_quantum()?.is_terminal() {
                    engine.state = EngineState::Stopped { /* outcome */ };
                }
                tokio::task::yield_now().await;        // bounded; cooperative
            }
            EngineState::Paused { .. } | EngineState::Loaded => {
                // Block ONLY on the mailbox — control is fully responsive.
                let cmd = commands.recv().await.ok_or(EngineError::ChannelClosed)?;
                engine.apply_command(cmd)?;
            }
            EngineState::Stopped { .. } => return Ok(()),
        }
    }
}
```

- **[EXEC-27]** The host-side driver MUST realize the execution model as an
  explicit async state machine: an `Engine` (owned by the `Session` actor, file
  20) with a closed set of run-states (loaded / running / paused / stopped) and a
  poll-then-step actor loop. Run-state transitions MUST be the only points at which
  control operations take effect. *Gate:* `gate:control-responsive`. *Spec:* §10;
  forward-ref file 20.

- **[EXEC-28]** The engine MUST advance execution in bounded quanta and MUST yield
  to its command mailbox between quanta. It MUST NOT hold a lock across a quantum
  and MUST NOT block the control plane for an unbounded time ([INV-8]). Control
  commands (pause, inspect, fork, save) MUST be serviced at quantum boundaries.
  *Gate:* `gate:control-responsive`, `gate:scheduler-liveness`. *Spec:* §10.

- **[EXEC-29]** State an external observer needs while a run is in progress
  (current virtual time, event-log length, run-state) MUST be readable without
  acquiring the engine lock (e.g. a lock-free mirror updated at each quantum), so a
  long-running `step`/`resume` never starves observers ([INV-8]). *Gate:*
  `gate:control-responsive`. *Spec:* §10; forward-ref file 20.

- **[EXEC-30]** The `Engine` MUST treat the `Configuration` as the source of truth
  and the `RuntimeState` as a rebuildable cache: it MUST be able to drop and
  re-`instantiate` its runtime from `config` at any quantum boundary without
  changing observable state ([INV-1], [INV-2]). This is what makes pause→fork→
  resume safe and what lets memory pressure evict warm runtimes. *Gate:*
  `gate:replay-oracle`. *Spec:* §10, §2, §5.

## 11. Determinism testing of the model itself

Because start, resume, fork, and snapshot-load are *the same operation*
(`instantiate`), one test validates all four: **instantiate the same configuration
twice and assert identical execution fingerprints** (24). If the two realizations
agree, then — since the second realization may have come through a *different*
`instantiate` branch (exact snapshot vs. ancestor-replay vs. genesis) — the test
has simultaneously shown that:

- **start** is deterministic (genesis → fingerprint is stable),
- **resume** is faithful (load-from-snapshot ≡ run-through),
- **fork** is faithful (prefix-instantiate ≡ run-to-prefix), and
- **snapshot completeness** holds (nothing live-only was lost on save).

This is the execution-model face of the determinism harness (24): the same-
configuration-twice test is the cheapest possible total coverage of the four
operations, *precisely because the model collapsed them into one*.

- **[EXEC-31]** Instantiating the same configuration twice — by any combination of
  `instantiate` branches — MUST yield identical execution fingerprints (24). This
  single check MUST be used to validate start, resume, fork, and snapshot
  completeness together, since they are the same operation. *Gate:*
  `gate:single-vm-fingerprint`, `gate:replay-oracle`. *Spec:* §11; forward-ref
  file 24.

- **[EXEC-32]** The model's determinism tests MUST run under adversarial host
  conditions (host load, reordered task scheduling, varied core counts) and MUST
  still produce identical fingerprints, demonstrating [INV-1] holds against host
  nondeterminism. *Gate:* `gate:single-vm-fingerprint`, `gate:harness-lint`.
  *Spec:* §11; forward-ref file 24.

## 12. Preemption and app-requested randomness as decisions

The two `Decision` variants added in §3 — `Preemption` and `AppRandom` —
extend the closed taxonomy to cover *when a vCPU is preempted* and *which
random value an in-guest workload is served*, while preserving the
default-recomputable / override-stored discipline of [EXEC-8]. Trigger and
default preemptions are deterministic engine behavior (file 08), not a search
`Decision`, until an explorer overrides them; only the override carries
information that cannot be recomputed.

- **[EXEC-33]** A `Decision::Preemption { node, at, kind }` MUST follow the
  default-recomputable / override-stored discipline ([EXEC-8]): the DEFAULT
  preemption sequence (round-robin vCPU switches at `rr_switch_quantum` and
  interrupts taken at armed deadlines, file 08) MUST be a pure function of
  `(ScenarioDef, Seed, Schedule)` and is therefore audit-only — recomputable
  from the def and preceding schedule, recorded only as a witness. A
  NON-DEFAULT, explorer-supplied preemption (a `VcpuSwitch` or `InterruptAt`
  at a chosen `at: Icount`) carries information that is not recomputable and
  MUST be stored in the `Schedule`. For a single-vCPU node (N = 1), an
  `InterruptAt` MUST be able to vary *when* the periodic timer or external
  interrupt preempts the one vCPU. Trigger/default preemptions MUST NOT be
  recorded as search decisions. *Gate:* `gate:scheduler-liveness`,
  `gate:single-vm-fingerprint`. *Spec:* §3, §12; forward-ref file 08, file 22.

- **[EXEC-34]** A `Decision::AppRandom { node, stream, request_id, width, value }`
  MUST record the serving `RngStreamId`, the per-stream `request_id`, the draw
  `width`, and the served `value` for every app-requested random draw served
  through the optional white-box path. On canonical replay an `AppRandom` that
  was *not* overridden MUST be re-derived from the seeded `stream` (so adding a
  node does not perturb unrelated streams, per [EXEC-9]); an OVERRIDDEN
  `AppRandom` MUST be served from the recorded `value`, never re-rolled
  (mirroring `FaultFires`, [INV-2]). *Gate:* `gate:replay-oracle`,
  `gate:single-vm-fingerprint`. *Spec:* §3, §12; cross-ref file 04 (Decision RNG).

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md). The copies below are
> the tasks whose primary area is this file ([PLAN-3]); they are kept in
> sync with the master plan's order/digest by the doc lint ([`28-engineering-standards.md`](28-engineering-standards.md)).

- [x] **T-EXEC-1** Define `ScenarioDef`, `Configuration`, `Schedule`, and
  `Decision` types with content-addressed `Configuration::id()` and the genesis
  constructor; property-test that equal `(def, schedule)` ⇒ equal id and unequal
  schedule ⇒ unequal id. — satisfies [EXEC-1], [EXEC-2], [EXEC-3], [EXEC-4],
  [EXEC-5]; spec §2.
- [x] **T-EXEC-2** Implement the closed `Decision` taxonomy and `Schedule`
  (prefix/appended) with per-stream RNG draw recording; test that unrelated
  `World` edits don't perturb other streams' draws. — satisfies [EXEC-6],
  [EXEC-7], [EXEC-8], [EXEC-9]; spec §3.
- [x] **T-EXEC-3** Implement `step` as the pure temporal-graph edge constructor
  and prove (test) it performs no I/O, boot, or materialization. — satisfies
  [EXEC-10]; spec §3.
- [x] **T-EXEC-4** Implement `reduce` as the pure reduction and the prefix-closure
  property; add a `gate:harness-lint` check that `reduce` reads no host
  nondeterminism. — satisfies [EXEC-11], [EXEC-12]; spec §4.
- [x] **T-EXEC-5** Prove resume+continue ≡ uninterrupted run by fingerprint over a
  representative scenario (scheduler/RNG state lives in the configuration). —
  satisfies [EXEC-13]; spec §4.
- [x] **T-EXEC-6** Implement recursive `instantiate` with the three-branch
  resolution (exact snapshot / ancestor-replay / genesis) and termination at the
  baked snapshot. — satisfies [EXEC-15], [EXEC-16], [EXEC-17]; spec §5.
  - Completed by `crates/crucible/src/model.rs`: `instantiate` now resolves exact
    cached snapshots, recursively materializes the nearest cached ancestor and
    explicitly replays the suffix, and terminates at a registered baked genesis
    checkpoint.
    `crates/crucible/src/lib.rs` covers exact-snapshot, ancestor-replay,
    baked-genesis, missing-genesis, cached-checkpoint, and baked-genesis
    checkpoint validation cases;
    `checks.crucible.phase1.executionInstantiate` gates the surface.
- [x] **T-EXEC-7** Wire `start`, `resume`, and `fork` as call sites of
  `instantiate` (genesis / tip / prefix) and delete any separate
  boot/resume/fork realization paths. — satisfies [EXEC-14], [G-4]; spec §5, §6.
  - Completed by `crates/crucible-qemu/src/realization.rs`: `start_qemu_vm`,
    `resume_qemu_vm`, and `fork_qemu_vm` are lifecycle wrappers over the shared
    `instantiate_qemu_vm` coordinator, differing only in the configuration they
    pass (genesis, tip, or schedule prefix). `crates/crucible-qemu/src/lib.rs`
    exports that API, `crates/crucible-qemu/src/realization.rs` tests wrapper
    equivalence against direct instantiate calls and rejects out-of-range fork
    prefixes, and `checks.crucible.phase1.executionStartResumeFork` gates the
    surface.
- [x] **T-EXEC-8** Implement `bake`: cold-boot each node once to its ready point,
  snapshot, content-address as the shared genesis checkpoint; assert it is the
  only cold-boot in the codebase (lint). — satisfies [EXEC-18], [EXEC-19];
  spec §6.
  - Completed by `crates/crucible/src/model.rs`: `bake` now derives the model
    genesis definition from `World::scenario_def()`, content-addresses a fat
    genesis checkpoint from the world and genesis configuration ids, and feeds
    `TemporalGraph::with_baked_genesis` without weakening checkpoint/configuration
    validation. `crates/crucible/src/lib.rs` covers deterministic sharing for the
    same world-derived model definition, different checkpoint ids for different
    worlds, and first-run genesis realization through baked checkpoint load. The
    full `ScenarioDef = (World, Plan, Properties, Seed)` schema will broaden this
    bridge from the current opaque `ScenarioDef::id` scaffold. The QEMU bake
    coordinator remains the only production cold-boot executor call site, and
    `checks.crucible.phase1.executionBake` runs both bake and hot-genesis tests
    plus the production cold-boot lint.
- [x] **T-EXEC-9** Implement the ready-point policy set (fixed icount /
  network-idle / console marker / agent signal) in `World` config and pin that
  `bake` reaches a content-identical genesis snapshot per policy. — satisfies
  [EXEC-20]; spec §6.
  - Completed by `crates/crucible/src/model.rs`: `World::from_nodes` builds
    canonical `WorldNode` ready-point configuration, exposes the fixed-icount,
    network-idle, console-marker, and agent-signal `ReadyPoint` variants, and
    validates that `AgentSignal` requires `WhiteBoxPolicy::Enabled`. `bake` and
    `crates/crucible-qemu/src/realization.rs` QEMU bake both validate the world;
    model bake hashes canonical ready-point material into the genesis checkpoint
    input. `crates/crucible/src/lib.rs` covers canonical node ordering,
    ready-point material sensitivity, white-box opt-in rejection, and
    content-identical repeated bake output for each ready-point policy;
    `checks.crucible.phase1.executionReadyPoint` gates the task.
- [x] **T-EXEC-10** Implement the homogeneous `NodeBlobRef` (baked vs CoW-delta)
  so no code path distinguishes initial from materialized VM state. — satisfies
  [EXEC-21], [EXEC-22]; spec §7.
  - Completed by `crates/crucible/src/model.rs`: `NodeBlobRef` now represents
    both baked ready-point blobs and CoW deltas with an explicit resolved
    content hash, normalizes both shapes through `content_hash()`, and is
    carried by every `Checkpoint` in the same `node_blobs` map. Model bake and
    QEMU bake populate baked per-node refs for worlds with ready-point nodes,
    QEMU baked-genesis validation rejects missing baked node refs, and the sim
    backend, replay-oracle test double, and QEMU cached-checkpoint helpers
    materialize `CowDelta` refs via `Checkpoint::with_node_blobs`.
    `crates/crucible/src/lib.rs` covers baked-genesis refs and uniform baked/CoW
    content comparison; `checks.crucible.phase1.executionNodeBlobRef` gates the
    task.
- [ ] **T-EXEC-11** Implement the replay-oracle equality check
  (`loadvm(snapshot) ≡ replay-from-ancestor`) and wire it as `gate:replay-oracle`
  in CI. — satisfies [EXEC-23]; spec §8.
  - Completed by `crates/crucible-qemu/src/realization.rs`:
    `check_qemu_replay_oracle` restores the exact fat snapshot with
    snapshot-completeness probe authorization, independently realizes the same
    configuration through the ancestor/genesis replay path, and records
    `QemuReplayOracleValidation::{Match, Mismatch}` from the resulting runtime
    fingerprints. `checks.crucible.phase1.gates.replayOracle` now runs both the
    existing materialized model oracle and the QEMU `loadvm(snapshot) ≡
    replay-from-ancestor` checker tests.
- [x] **T-EXEC-12** Implement divergence bisection on oracle failure (localize to
  first differing decision/instruction) and the `gate:divergence-bisect` check;
  assert no silent-repair path exists. — satisfies [EXEC-24]; spec §8.
  - Completed by `crates/crucible-harness/src/divergence.rs` and
    `crates/crucible-harness/src/replay_oracle.rs`: the strict sampled
    replay-oracle path now calls `localize_replay_oracle_mismatch`, which
    compares the fat/materialized path against the thin replay path through the
    divergence bisector and reports the first differing schedule decision and
    exact icount. `gate:divergence-bisect` covers seeded first-difference
    localization, replay-oracle fat/thin mismatch localization, and
    matching-stream rejection so oracle failures cannot be repaired, retried, or
    smoothed over silently.
- [x] **T-EXEC-13** Express save/replay/search as model operations
  (fat-checkpoint materialization keyed by `config.id()`, on-demand oracle replay,
  frontier `step` enumeration) with content-addressed temporal-graph dedup. —
  satisfies [EXEC-25], [EXEC-26], [G-6]; spec §9.
  - Completed by `crates/crucible/src/model.rs`: `TemporalGraph::save_checkpoint`
    materializes non-genesis configurations as fat checkpoints keyed by
    `Configuration::id`, `TemporalGraph::replay_checkpoint` performs on-demand
    thin replay and reports `ReplayOracleMismatch` when the fat oracle diverges,
    and `TemporalGraph::enumerate_frontier` applies candidate `Decision`s with
    `step` while deduplicating recorded configurations by content address.
    `checks.crucible.phase1.executionGraphOperations` gates the model APIs,
    focused temporal-graph tests, and RFC linkage.
- [x] **T-EXEC-14** Implement the `Engine` async state machine (closed run-states,
  poll-then-step actor loop) inside the `Session` actor with bounded quanta and
  inter-quantum yields. — satisfies [EXEC-27], [EXEC-28]; spec §10.
  - Completed by `crates/crucible-session/src/lib.rs`: `Engine` now owns the
    source-of-truth `Configuration`, rebuildable `RuntimeState` cache,
    `TemporalGraph`, closed `EngineState` set, and the `QuantumLoop` boundary.
    `SessionActor::run` consumes a Tokio mailbox, services pending commands
    before stepping while running, advances exactly one scheduler quantum per
    loop iteration, and calls `tokio::task::yield_now().await` after each
    quantum. `checks.crucible.phase1.executionEngineStateMachine` gates the
    state-machine surface and focused session actor tests.
- [x] **T-EXEC-15** Implement the lock-free run-state mirror so observers read
  virtual time / log length / run-state without the engine lock; add a
  `gate:control-responsive` latency check. — satisfies [EXEC-29]; spec §10.
  - Completed by `crates/crucible-session/src/lib.rs`: `LiveSnapshot`
    publishes `LiveStateKind`, virtual time, event-log length, and monotone
    quanta counters through atomics written by the `SessionActor` after command
    transitions and scheduler quanta, while observers read through
    `LiveSnapshot::read` without entering the mailbox. The session-side
    `gate_control_responsive` integration test observes monotone progress from
    the live mirror without issuing query commands, and
    `checks.crucible.phase1.executionLiveSnapshot` gates the mirror API,
    metadata, RFC linkage, and latency check.
- [x] **T-EXEC-16** Make the `Engine` able to drop and re-`instantiate` its
  runtime at any quantum boundary with no observable change (cache-eviction
  safety). — satisfies [EXEC-30]; spec §10.
  - Completed by `crates/crucible-session/src/lib.rs`: `Engine::evict_runtime_cache`
    drops only the rebuildable `RuntimeState`, `Engine::reinstantiate_runtime_cache`
    rebuilds it from the source-of-truth `Configuration` and `TemporalGraph`
    without changing the boundary snapshot, and `Engine::refresh_runtime_cache`
    performs an atomic drop-and-rebuild refresh for cache pressure. Focused
    tests cover paused and running quantum boundaries, never-instantiated
    guards, and refresh failure atomicity, and
    `checks.crucible.phase1.executionCacheEviction` gates the API, no-observable
    change assertions, RFC linkage, and replay-oracle cache semantics.
- [x] **T-EXEC-17** Implement the same-configuration-twice fingerprint test as the
  unified validator of start/resume/fork/snapshot-completeness and wire it to
  `gate:single-vm-fingerprint`. — satisfies [EXEC-31]; spec §11.
  - Completed by `crates/crucible/tests/gate_single_vm_fingerprint.rs`: the
    model-side `gate:single-vm-fingerprint` target instantiates the same
    `Configuration` twice through start/genesis, resume exact-snapshot vs
    no-fallback ancestor-replay, fork prefix, and saved-checkpoint
    snapshot-completeness paths, then compares the resulting execution
    fingerprints while replay-checking the saved checkpoint's fat/thin identity.
    The canonical gate target map now includes the `crucible` model target, and
    `checks.crucible.phase1.gates.singleVmFingerprint` runs it alongside the
    existing QEMU run-twice evidence.
- [x] **T-EXEC-18** Run the model determinism tests under adversarial host
  conditions (load, task reordering, varied core counts) and assert identical
  fingerprints. — satisfies [EXEC-32]; spec §11.
  - Completed by `crates/crucible/tests/gate_single_vm_fingerprint.rs`:
    `gate_single_vm_fingerprint_model_determinism_survives_adversarial_host_profiles`
    runs the same representative model configurations under quiet single-core,
    loaded single-core, reordered two-worker, and loaded many-worker profiles,
    injecting deterministic host load/yields and reordering task execution while
    asserting identical canonical execution fingerprints.
    `checks.crucible.phase1.gates.singleVmFingerprint` runs this matrix with
    the model same-configuration validator.
- [x] **T-EXEC-19** Implement the `Decision::Preemption` variant
  (`VcpuSwitch` / `InterruptAt`, `PreemptionKind`) with the
  default-recomputable / override-stored discipline: prove the default RR/timer
  preemption sequence is recomputable from `(def, Seed, schedule)` and
  audit-only, and that an explorer-supplied preemption (including `InterruptAt`
  at N = 1) is stored and replayed. — satisfies [EXEC-33], [G-11]; spec §12.
  - Completed by `crates/crucible/src/decision.rs`: `default_rr_preemption`
    derives nonzero RR-boundary default switches without appending a schedule
    entry, while `record_preemption_override` stores explorer-supplied
    `VcpuSwitch` and single-vCPU `InterruptAt` choices as
    `Decision::Preemption`. The coverage floor now requires default derivation,
    invalid-boundary/overflow coverage, and override-recording markers.
- [x] **T-EXEC-20** Implement the `Decision::AppRandom` variant: record
  `stream`/`request_id`/`width`/`value` for each served app draw; on replay
  re-derive a non-overridden draw from the seeded stream and serve an overridden
  draw from the recorded value (never re-roll); test stream isolation under
  unrelated `World` edits. — satisfies [EXEC-34]; spec §12.
  - Completed by `crates/crucible/src/decision.rs`: `serve_app_random` records
    the seeded `RngDraw` plus `Decision::AppRandom`, `serve_app_random_request`
    preserves a caller-supplied request id for doorbell/protocol requests,
    hydrated replay resumes stream positions from the recorded schedule, and
    `serve_app_random_override` serves recorded values without advancing or
    re-rolling the seeded stream. The coverage floor now requires the app-random
    request-id, resume, override, and invalid override-value tests.
