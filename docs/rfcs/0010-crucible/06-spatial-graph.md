# 06 — Spatial graph: the `ScenarioDef`, "configuration #0"

This file specifies the **spatial graph**: the immutable, content-addressed
*definition* of a Crucible run. Where the execution model (05) specifies *how* a
run unfolds — `State(t) = reduce(ScenarioDef, Schedule[0..t])` — this file
specifies *what* is reduced. The `ScenarioDef` is the structure; the temporal
graph (07) is its behavior over decision-time; the reduction (05) joins them.

The spatial graph is "configuration #0": the genesis configuration of the
execution model is exactly `(def, [])`, and that `def` is the `ScenarioDef`
defined here ([EXEC-3], [EXEC-15]). Everything downstream — the baked genesis
checkpoint (05 §6), the scheduler's lookahead bounds (08), the fault timeline
(17), the property checks (18), and the reproduction artifact (23) — reads its
inputs from this definition. Getting the spatial graph right is therefore a
foundation-first obligation ([G-5]): a leaky, imprecise, or non-content-addressed
definition poisons determinism everywhere above it.

This file satisfies the headline goals [G-1] (a fixed `(ScenarioDef, seed,
Schedule)` reduces deterministically — the `ScenarioDef` half is defined here),
[G-2] (any unmodified guest — the per-node config carries only launch-time
inputs), and [G-6] (reproduce-then-explore — the `ScenarioDef` is half of the
reproduction artifact and the parameter space of a `ScenarioFamily`). It upholds
[INV-6] (content addressing) for every component it defines, and feeds [INV-1]
(purity of reduction) by being immutable once content-addressed.

## 1. What the spatial graph is, and what it is not

A `ScenarioDef` is a **value**, not a program. It is a frozen, content-addressed
tuple that *describes* a multi-machine world and the perturbations and properties
that define a test over it. It contains no live state, no host paths that vary
between machines beyond content-addressed references, no wall-clock, and no
mutable handles. Two `ScenarioDef`s with equal content are the same scenario,
everywhere, forever.

```text
  ScenarioDef = (World, Plan, Properties, Seed)         immutable, content-addressed
    World      = (nodes[], links[])                      the topology + per-entity config
    Plan       = declarative fault/event schedule        over virtual time (17)
    Properties = assertions to check                     always/sometimes/eventually/… (18)
    Seed       = root entropy                            forks all decision-RNG streams (04)
```

The four components are **orthogonal layers**. The `World` says *what machines
exist and how they are wired*; the `Plan` says *what is done to them and when*;
the `Properties` say *what must be true*; the `Seed` says *how every residual
choice is resolved*. None of the four is folded into another. In particular,
links are part of the `World` (they are topology, not events), faults are part of
the `Plan` (they are scheduled perturbations, not topology), and assertions are
part of the `Properties` (they are observations, not actions). This separation is
deliberate and load-bearing — §10 explains why a design that folds links and
assertions into a single boot "entrypoint" event sacrifices exactly the
reusability and analyzability content-addressing is supposed to buy.

- **[SPAT-1]** A `ScenarioDef` MUST be the immutable 4-tuple
  `(World, Plan, Properties, Seed)` and nothing else. It MUST be a pure value:
  it MUST NOT contain live handles, host-varying absolute paths (only
  content-addressed references, §8), wall-clock values, or mutable state. Once
  constructed and content-addressed it MUST NOT be mutated; a change produces a
  new `ScenarioDef` with a new identity. *Gate:* `gate:content-address`.
  *Spec:* §1, §2.

- **[SPAT-2]** The four components `World`, `Plan`, `Properties`, and `Seed`
  MUST be orthogonal layers: links belong to the `World`, faults/events belong
  to the `Plan`, assertions belong to the `Properties`, and root entropy is the
  `Seed`. No component may be folded into another (e.g. links MUST NOT be
  represented as boot-time events, and assertions MUST NOT be represented as
  actions). *Gate:* `gate:content-address`. *Spec:* §1, §10.

## 2. Decomposition, composition, and content-addressing

Each of the four components is **independently hashed and independently
reusable**, and a `ScenarioDef` instance is a tuple of references plus a seed.
This is the same content-addressing discipline the execution model (05) and
temporal graph (07) lean on, pushed all the way down into the definition: a
`World` is a content-addressed value that can be shared across hundreds of
scenarios; a `Plan` (a fault campaign) can be applied to many different `World`s;
a `Properties` bundle (a correctness suite) can be checked against many
`(World, Plan)` pairs.

```rust,illustrative
/// The immutable definition of a run: topology, Plan, properties, and seed.
/// "Configuration #0" — the genesis configuration of the execution model (05)
/// is exactly `(this, [])`. Content-addressed; equal content ⇒ equal `id`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ScenarioDef {
    /// BLAKE3 of the canonical serialization of `(world, plan, properties, seed)`.
    /// Two `ScenarioDef`s are equal iff their `id` is equal ([EXEC-2]).
    pub id: ContentHash,
    pub world: Ref<World>,           // §3; independently hashed and reusable
    pub plan: Ref<Plan>,             // §6, file 17; independently hashed and reusable
    pub properties: Ref<Properties>, // §7, file 18; independently hashed and reusable
    pub seed: Seed,                  // §7, file 04; a 256-bit root key
}

/// A content-addressed reference to an immutable component. Equal content has
/// equal `hash`; the referent is fetched from the content store on demand.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ref<T> {
    pub hash: ContentHash,
    _ty: core::marker::PhantomData<T>,
}
```

The hash is **BLAKE3 over a canonical serialization** (§8) of each component, and
the `ScenarioDef::id` is BLAKE3 over the tuple of component hashes plus the seed.
Canonicalization (sorted node lists, sorted link lists, sorted property lists,
fixed field order, no floating ambiguity — §8) is what makes the hash a function
of *meaning* rather than of *spelling*: two authoring sessions that describe the
identical world in a different statement order produce the identical hash.

- **[SPAT-3]** Each of `World`, `Plan`, and `Properties` MUST be independently
  content-addressed by BLAKE3 over its canonical serialization (§8), and MUST be
  independently reusable: the same `World` hash MUST be shareable across many
  `ScenarioDef`s, and the same `Plan` or `Properties` hash MUST be applicable
  across many `World`s. *Gate:* `gate:content-address`. *Spec:* §2, §8.

- **[SPAT-4]** `ScenarioDef::id` MUST be BLAKE3 over the tuple of its component
  hashes and its `Seed`. Equal component content and equal seed MUST produce an
  equal `id`; any difference in any component or the seed MUST produce a
  different `id` ([INV-6]). The `id` MUST be the value the execution model uses
  as the `def.id` half of `Configuration::id()` ([EXEC-4]). *Gate:*
  `gate:content-address`. *Spec:* §2; cross-ref 05 §2.

- **[SPAT-5]** Content addressing MUST be over *meaning*, not spelling: the
  canonical serialization (§8) MUST be insensitive to authoring order (node
  declaration order, link declaration order, property declaration order) and to
  any other accidental, semantics-preserving variation. Two authoring sessions
  that describe the same scenario MUST produce the same `ScenarioDef::id`.
  *Gate:* `gate:content-address`. *Spec:* §2, §8.

## 3. `World`: nodes and links

The `World` is the topology and the per-entity static configuration. It is the
input to `bake` (05 §6) — `bake(world)` boots each node once to its ready point
and content-addresses the genesis checkpoint — and the input to the scheduler's
conservative-lookahead bounds (08), which read the link latencies. It has exactly
two collections: `nodes` and `links`.

```rust,illustrative
/// The topology: the set of nodes and the set of links between them, plus each
/// entity's static configuration. Independently content-addressed (§2); the
/// input to `bake` (05 §6) and to the scheduler's lookahead bounds (08).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct World {
    /// Nodes, canonically sorted by `NodeId` (§8). The *logical* topology;
    /// no physical/shmem layout or participant count is encoded here (§5).
    nodes: Vec<NodeDef>,
    /// Links, canonically sorted by `(endpoint_a, endpoint_b)` (§8). The
    /// logical graph edges; decoupled from any physical transport (§5).
    links: Vec<LinkDef>,
}

impl World {
    /// Returns this world's immutable node topology.
    pub fn nodes(&self) -> &[NodeDef] {
        &self.nodes
    }

    /// Returns this world's immutable logical links.
    pub fn links(&self) -> &[LinkDef] {
        &self.links
    }
}
```

### 3.1 Per-node configuration

A `NodeDef` carries everything `bake` needs to bring one node to its ready point
deterministically, and nothing that would vary between hosts (so the hash is
portable) or that would require modifying the guest (so [G-2] holds). All image
and kernel references are **content-addressed blob references** (§8), not host
paths.

```rust,illustrative
/// One node in the world: a VM, or an I/O sub-node (15). Carries only
/// launch-time inputs — no guest modification is implied ([G-2], INV-5).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NodeDef {
    /// Stable, author-assigned identity, unique within the `World`. The key
    /// for links, faults, properties, and per-entity RNG-stream forking (04).
    pub id: NodeId,
    /// What kind of node this is and its kind-specific configuration.
    pub kind: NodeKind,
    /// The deterministic ready-point policy for `bake` (05 §6, [EXEC-20]).
    pub ready_point: ReadyPoint,
}

/// The kind of a node and its configuration.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum NodeKind {
    /// A QEMU guest VM (10). The common case.
    Vm(VmDef),
    /// A first-class I/O participant: disk, 9p server, or net link endpoint,
    /// modeled as a scheduling node with its own clock (15). Defined in 15;
    /// referenced here so the `World` can hold a heterogeneous node set.
    IoSubNode(IoSubNodeDef),
}

/// Static configuration of a VM node. Everything `bake` needs to reach the
/// ready point; all references are content-addressed (§8), never host paths.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VmDef {
    /// Target architecture; selects the QEMU system binary and TCG target.
    pub arch: Arch,                  // e.g. X86_64, Aarch64
    /// Content-addressed reference to the guest kernel image (bzImage/vmlinux).
    pub kernel: BlobRef,
    /// Content-addressed reference to the read-only root image. Booting it
    /// uses CoW overlays only; the base blob is never mutated (INV-5).
    pub root_image: BlobRef,
    /// Optional content-addressed reference to an initramfs.
    pub initrd: Option<BlobRef>,
    /// Kernel command line. Part of the determinism input ([DET-3]); fixed
    /// per scenario, hashed verbatim.
    pub cmdline: String,
    /// Guest RAM, in mebibytes. Fixed; part of the hashed config.
    pub memory_mib: u32,
    /// Fixed vCPU count. `N >= 1`; multi-vCPU nodes use single-threaded RR-TCG
    /// with a content-addressed RR switch quantum (10/[QEMU-5], 10/[QEMU-43]).
    pub smp_vcpus: u16,
    /// The fixed `-icount shift=N` for this node (09, 10); never `auto`.
    /// Hashed so a shift change is a different scenario ([TIME] cross-ref).
    pub icount_shift: u8,
    /// Optional white-box agent opt-in: enables the guest↔host channel (16)
    /// for agent-signal ready points and in-guest markers. Default off ([G-3]).
    pub white_box: WhiteBoxPolicy,
}

/// The deterministic ready point: where `t = 0` sits for this node (05 §6).
/// All variants MUST yield a content-identical genesis snapshot across `bake`
/// runs of the same `World` ([EXEC-20]).
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ReadyPoint {
    /// Run for exactly `n` instructions, then snapshot. Black-box, brittle.
    FixedIcount { n: u64 },
    /// Snapshot at first network-idle for a quiescence window (08). Black-box.
    NetworkIdle { window: VirtualDuration },
    /// Snapshot when `marker` appears on the guest console/serial. Black-box.
    ConsoleMarker { marker: ConsoleMarker },
    /// Snapshot when an in-guest agent signals ready (16). White-box opt-in.
    AgentSignal,
}
```

The fields are exactly the launch-time inputs to QEMU plus the determinism knobs:
architecture, kernel/root/initrd blobs, command line, memory, the fixed vCPU
count, the fixed icount
shift, the ready-point policy, and the white-box opt-in. Note what is *absent*:
no host paths, no "snapshot path" (genesis snapshots are derived by `bake`, not
authored — 05 §6), no participant count, no shmem geometry, no per-run scratch
directories. The `NodeDef` is portable because it contains only content and
content-addressed references.

- **[SPAT-6]** A `World` MUST consist of exactly two collections, `nodes` and
  `links`, each canonically ordered (§8). Every node MUST have a `NodeId` unique
  within the `World`; a duplicate `NodeId` MUST be rejected at build time (§9).
  *Gate:* `gate:content-address`. *Spec:* §3.

- **[SPAT-7]** A VM node's configuration MUST carry only launch-time inputs:
  architecture, content-addressed kernel/root/initrd references, kernel command
  line, memory size, the fixed vCPU count, the fixed icount shift, the ready-point
  policy, and the white-box opt-in. It MUST NOT carry host-varying absolute
  paths, an authored genesis-snapshot path (genesis snapshots are produced by
  `bake`, 05 §6), or any content that Crucible places inside the guest for core
  operation ([G-2], [INV-5]). *Gate:* `gate:any-guest`. *Spec:* §3.1.

- **[SPAT-8]** Each VM node MUST request a fixed vCPU count `N >= 1`; `N` MUST be
  part of the hashed configuration, so a vCPU-count change is a different
  scenario. A multi-vCPU node (`N > 1`) MUST use the single-threaded RR-TCG
  launch contract from 10/[QEMU-5] and 10/[QEMU-43], never MTTCG. The
  `icount_shift` MUST be a fixed value (never `auto`) and MUST also be part of
  the hashed configuration, so a shift change is a different scenario. *Gate:*
  `gate:content-address`. *Spec:* §3.1; cross-ref 09, 10.

- **[SPAT-9]** Each node MUST declare a `ReadyPoint` policy ([EXEC-20]); the
  policy is part of the hashed `World`. A white-box ready point (`AgentSignal`)
  MUST require the node's `white_box` opt-in to be enabled, and MUST NOT be the
  default ([G-3]). *Gate:* `gate:any-guest`. *Spec:* §3.1; cross-ref 05 §6, 16.

### 3.2 Per-link configuration and the minimum link-latency floor

A `LinkDef` is a logical edge between two node endpoints with its transport
characteristics: latency, jitter, loss, and bandwidth. The latency is special: it
is the **conservative-lookahead bound** the scheduler (08) uses to advance nodes
in parallel without violating causality (the minimum inbound link latency to a
node is the soonest a peer can deliver to it). For that reason, **zero latency is
forbidden**: a link MUST have a strictly positive latency at or above a minimum
floor.

```rust,illustrative
/// One logical link between two node endpoints, with transport characteristics.
/// Latency is also the conservative-lookahead bound for the scheduler (08).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LinkDef {
    /// The two endpoints, canonically ordered so `(a, b)` and `(b, a)` hash
    /// equal for a symmetric link (§8). Both MUST reference declared nodes (§9).
    pub endpoints: (NodeId, NodeId),
    /// One-way base latency. MUST be `>= MIN_LINK_LATENCY` (the floor below).
    /// Zero latency is forbidden (08 explains why: it collapses lookahead to
    /// zero, serializing the simulation and breaking the CMB safety bound).
    pub latency: VirtualDuration,
    /// Latency jitter, resolved deterministically per-frame from the seeded
    /// decision RNG (04). The *jittered* latency MUST still be `>= the floor`.
    pub jitter: VirtualDuration,
    /// Frame loss probability in `[0.0, 1.0]`. Resolved per-frame as a
    /// `Decision::FaultFires`-style draw (05 §3) from the seeded RNG (04).
    pub loss: Probability,
    /// Optional bandwidth cap, in bits per virtual second. `None` = unbounded.
    pub bandwidth_bps: Option<u64>,
}

/// The non-negotiable minimum one-way link latency. A link at or below zero
/// would give the scheduler zero lookahead to the destination node (08),
/// forcing full serialization and breaking the conservative PDES safety
/// argument. The floor guarantees a strictly positive lookahead horizon.
pub const MIN_LINK_LATENCY: VirtualDuration = VirtualDuration::from_nanos(1);
```

The latency floor is a **modeling invariant**, not a performance tunable. Under
the conservative parallel discrete-event scheme (CMB, 08), a node may advance its
virtual time only up to the soonest moment a peer could deliver an event to it;
that soonest moment is bounded below by the minimum inbound link latency. If any
inbound link has zero latency, the lookahead horizon collapses to the node's
current time, the node cannot advance ahead of its peers at all, and the
conservative safety argument degenerates. Worse, a zero-latency cycle in the
topology admits an instantaneous event loop with no well-defined order. Forbidding
zero latency — and requiring a positive floor even after jitter is applied —
keeps every node's lookahead strictly positive, which is what lets the scheduler
advance nodes in parallel and what makes the total event order (INV-3)
well-founded. File 08 carries the full derivation; this file enforces the floor
at the definition boundary so an ill-formed `World` never reaches the scheduler.

- **[SPAT-10]** A `LinkDef` MUST reference exactly two declared nodes by
  `NodeId` as its endpoints; a link referencing an undeclared node MUST be
  rejected at build time (§9). The endpoint pair MUST be canonically ordered so a
  symmetric link hashes identically regardless of authoring direction (§8).
  *Gate:* `gate:content-address`. *Spec:* §3.2, §9.

- **[SPAT-11]** Every link's one-way `latency` MUST be greater than or equal to
  `MIN_LINK_LATENCY` (a strictly positive floor); zero or negative latency MUST
  be rejected at build time (§9). The floor exists because the link latency is
  the scheduler's conservative-lookahead bound (08): a zero-latency link
  collapses lookahead and breaks the conservative PDES safety argument. *Gate:*
  `gate:e2e-determinism`. *Spec:* §3.2; forward-ref 08.

- **[SPAT-12]** When jitter is applied to a link, the resulting effective
  latency MUST remain greater than or equal to `MIN_LINK_LATENCY`; a `LinkDef`
  whose `latency - jitter` could fall below the floor MUST be rejected at build
  time (§9). Jitter MUST be resolved deterministically from the seeded decision
  RNG (04), never from host entropy. *Gate:* `gate:e2e-determinism`. *Spec:*
  §3.2; cross-ref 04, 08.

- **[SPAT-13]** Link `loss` MUST be a probability in `[0.0, 1.0]`; a value
  outside that range MUST be rejected at build time (§9). Per-frame loss
  decisions MUST be resolved from the seeded decision RNG and recorded as
  `Decision`s (05 §3) so replay reproduces them without re-rolling. *Gate:*
  `gate:e2e-determinism`. *Spec:* §3.2; cross-ref 04, 05 §3.

### 3.3 The logical topology is decoupled from any physical layout

A first-class design rule: the `World` describes the **logical** topology only —
which nodes exist, which links connect them, and their characteristics. It says
**nothing** about how the co-simulation transport is physically laid out. There
is no participant count baked into the model, no shared-memory region geometry, no
ring-buffer sizing, no slot indices — none of the physical transport's shape
leaks into the definition. The mapping from "node `db-2` has an inbound link from
`db-1` with latency 5 ms" to "shared-memory region #3, SPSC queue #7, slot
0x40..." is the transport's job (13), computed at instantiation time from the
logical `World`, and is *not* part of the scenario's identity.

This decoupling matters for three reasons. First, **portability of identity**: a
scenario's hash must not change because the host laid the shmem out differently,
or because a transport revision changed a buffer size; if physical layout leaked
in, the same logical test would hash differently on different machines, breaking
content addressing ([SPAT-5]) and reproduction ([G-6]). Second, **reuse**: the
same logical `World` must be usable by any transport implementation, present or
future; embedding a fixed participant count or slot map would freeze it to one
transport generation. Third, **analyzability**: tools that read topology (for the
scheduler's lookahead graph, for visualization, for property scoping) want the
logical graph, not a memory map. The discipline is therefore: *the model is
logical; the layout is derived; the derivation is not identity.*

- **[SPAT-14]** The `World` MUST encode only the *logical* topology (nodes,
  links, and their characteristics). It MUST NOT encode any physical
  co-simulation-transport layout: no participant count, shared-memory region
  geometry, queue sizing, slot indices, or any other artifact of how the
  transport (13) is physically arranged. The logical→physical mapping MUST be
  computed at instantiation time from the logical `World` and MUST NOT be part of
  the `ScenarioDef`'s identity. *Gate:* `gate:content-address`. *Spec:* §3.3;
  forward-ref 13.

- **[SPAT-15]** A scenario's `ScenarioDef::id` MUST be invariant under any change
  to physical transport layout, transport buffer sizing, or host memory geometry:
  the same logical `World` MUST hash identically across hosts and across transport
  revisions. *Gate:* `gate:content-address`, `gate:e2e-determinism`. *Spec:*
  §3.3; cross-ref 13.

## 4. Static topology with fault-modeled membership dynamics

The `World`'s topology is **static**: the set of nodes and the set of links are
fixed for the life of a `ScenarioDef`. There is no `add_node` or `remove_node`
that mutates the world mid-run, and no `create_link`/`destroy_link` event that
changes the graph's vertex/edge set. Membership *dynamics* — a node that crashes,
a partition that splits the cluster, a node that rejoins — are modeled entirely
as **faults in the `Plan`** (17) over the static topology, not as mutations of
the topology itself.

A crash is `Fault::Crash` over a still-declared node; a partition is
`Fault::Partition` that suppresses delivery on still-declared links; a heal
removes the fault and restores the declared link's behavior. The node and link
never leave the `World`; what changes is whether they are *active*, expressed as
fault state layered over the static graph and resolved deterministically by the
scheduler.

This is a determinism decision, not a capability limitation. Dynamic membership —
genuinely adding a node to the `World` at virtual time `t` — would mean the set of
participants, the set of per-entity RNG streams (04), the scheduler's lookahead
graph (08), and the genesis-bake set (05 §6) all change *during* a run. That
makes the `ScenarioDef` no longer a fixed value reduced under a schedule; it makes
the world a function of decision-time, which (a) breaks `bake` (you cannot boot a
node "once per `World`" if the `World` grows mid-run), (b) perturbs unrelated RNG
streams (a new participant shifts stream allocation unless every stream is
name-hashed *and* the new node's stream is defined a priori — at which point the
node was effectively in the `World` all along), and (c) makes the lookahead graph
time-varying, complicating the conservative PDES safety argument. The static-world
+ fault-modeled-membership design keeps the `ScenarioDef` a fixed value, keeps the
participant set and RNG-stream set fixed, keeps `bake` a once-per-`World`
operation, and still expresses every membership scenario that matters for
distributed-systems testing (crash/restart, partition/heal, asymmetric
partitions, isolated minorities) — because those *are* faults, not topology
edits. A node that is "not yet joined" is simply a declared node held in a crashed
or partitioned state until a `Plan` event heals it.

- **[SPAT-16]** The topology of a `World` (its set of nodes and set of links)
  MUST be static for the life of a `ScenarioDef`. There MUST be no operation that
  adds or removes a node or changes the link set mid-run. *Gate:*
  `gate:content-address`. *Spec:* §4.

- **[SPAT-17]** Membership dynamics — crash, restart, partition, heal,
  isolation, rejoin — MUST be modeled as faults in the `Plan` (17) layered over
  the static topology and resolved deterministically by the scheduler (08), not
  as mutations of the `World`. A "not-yet-joined" participant MUST be a declared
  node held inactive by a fault until a `Plan` event activates it. *Gate:*
  `gate:e2e-determinism`. *Spec:* §4; cross-ref 17, 08.

- **[SPAT-18]** Because the node set and link set are static, the participant
  set, the per-entity decision-RNG-stream set (04), the scheduler lookahead graph
  (08), and the `bake` node set (05 §6) MUST all be fully determined by the
  `World` alone and MUST NOT vary with the `Schedule`. This is what keeps the
  `ScenarioDef` a fixed value reduced under a schedule ([INV-1]) and `bake` a
  once-per-`World` operation ([EXEC-18]). *Gate:* `gate:e2e-determinism`.
  *Spec:* §4; cross-ref 04, 05 §6, 08.

## 5. `Plan`, `Properties`, `Seed`: the other three layers

The `World` is defined above; the other three components of the tuple are defined
in detail by their own files, and referenced here so the `ScenarioDef`'s shape is
complete and its layering is explicit.

### 5.1 `Plan` — event choreography and fault signals

The `Plan` carries declarative event choreography and the signal-driven fault
program. It is the scenario's *what changes modeled behavior and when* layer.
The executable fault taxonomy and binding semantics are defined by
[`RFC-0013`](../0013-signal-driven-fault-model/README.md); the trigger/condition vocabulary
(timer-fired, event-fired, assertion-satisfied/violated, compound all-of/any-of)
and the event-graph model the `Plan` is an instance of are defined in
[`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) — the real home
of the trigger taxonomy this section forward-references. The event graph emits
referenced occurrences that event-domain signal sources may consume. Known-time
fault behavior uses time-domain signal nodes directly; fault effects are not
event actions. What matters here is the Plan's place
in the tuple: the `Plan` is a content-addressed component, orthogonal to the
`World` and reusable across worlds, and it is part of the `ScenarioDef`'s identity
(a different fault campaign is a different scenario).

```rust,illustrative
/// The declarative fault/event schedule over virtual time. Orthogonal to the
/// `World`; independently content-addressed (§2) and reusable across worlds.
/// Full taxonomy in file 17; referenced here as a `ScenarioDef` component.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Plan {
    /// Canonical event choreography.
    pub events: EventGraph,
    /// Canonical signal programs, typed bindings, and resource limits.
    pub fault_signals: FaultSignalPlan,
}
```

- **[SPAT-19]** The `Plan` MUST carry the event graph defined in
  [`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md) and the sole
  `FaultSignalPlan` defined by RFC-0013. It MUST be carried as an independently
  content-addressed component of the `ScenarioDef` (§2), MUST be orthogonal to the
  `World` (faults are not topology) and reusable across worlds, and all node/link
  references in it MUST be validated against the `World` at build time (§9).
  *Gate:* `gate:content-address`. *Spec:* §5.1; forward-ref 17, 17a.

- **[SPAT-20]** The `Plan` MUST evaluate events and signals against canonical
  domains such as virtual time and stable opportunities, never host wall-clock.
  Evaluation MUST be a function of authenticated scenario and continuation state
  only ([INV-1]). *Gate:* `gate:e2e-determinism`.
  *Spec:* §5.1; cross-ref 09, 04, 17.

### 5.2 `Properties` — the assertions

The `Properties` are the assertions checked against the run: the **Always**
(invariant), **Sometimes** (liveness witness), **Eventually** (bounded liveness
after a trigger), **AfterQuiescence** (end-state), and **Reachable** (coverage
marker) vocabulary, defined in [`18-assertions-properties.md`](18-assertions-properties.md).
Like the `Plan`, the `Properties` are a content-addressed component, orthogonal to
both `World` and `Plan` (a correctness suite is not a topology and not a fault
campaign), and part of the `ScenarioDef`'s identity.

```rust,illustrative
/// The assertions to check against the run (always/sometimes/eventually/
/// after-quiescence/reachable). Orthogonal to `World` and `Plan`; independently
/// content-addressed (§2). Full vocabulary in file 18.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Properties {
    /// Named assertions, canonically ordered by name (§8). Predicates reference
    /// the `World`'s nodes by `NodeId`; references validated at build time (§9).
    pub assertions: Vec<AssertionDef>,
}
```

- **[SPAT-21]** The `Properties` MUST be the assertion bundle defined in
  [`18-assertions-properties.md`](18-assertions-properties.md), carried as an
  independently content-addressed component of the `ScenarioDef` (§2). It MUST be
  orthogonal to `World` and `Plan` (assertions are not actions and not topology)
  and reusable across both. All node references in predicates MUST be validated
  against the `World` at build time (§9). *Gate:* `gate:content-address`. *Spec:*
  §5.2; forward-ref 18.

### 5.3 `Seed` — the root entropy

The `Seed` is the single root of all deterministic randomness in the run: a
256-bit root key from which every per-entity decision-RNG stream is forked by
name-hash, defined in [`04-determinism-contract.md`](04-determinism-contract.md).
It is part of the `ScenarioDef`'s identity (a different seed is a different
scenario), and it is the parameter a `ScenarioFamily` (§6) varies most often.
Forking streams by name-hash (rather than by allocation order) is what lets
adding or renaming an unrelated node leave other streams' draws unchanged
([EXEC-9]) — a property the static-world rule (§4) and the stable `NodeId` (§3.1)
together guarantee.

```rust,illustrative
/// The root entropy for all deterministic randomness (04). A 256-bit root key;
/// every per-entity RNG stream is forked from it by name-hash so unrelated
/// `World` edits don't perturb other streams ([EXEC-9]). Part of identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seed(pub [u8; 32]);
```

- **[SPAT-22]** The `Seed` MUST be the root entropy from which all decision-RNG
  streams are derived, as defined in
  [`04-determinism-contract.md`](04-determinism-contract.md). It MUST be part of
  the `ScenarioDef`'s identity (a different seed is a different scenario). Per-entity
  streams MUST be forked from the seed by name-hash (not allocation order), so the
  seed plus a stable `NodeId` (§3.1) plus the static-world rule (§4) together
  guarantee that unrelated `World` edits do not perturb other streams' draws
  ([EXEC-9]). *Gate:* `gate:e2e-determinism`. *Spec:* §5.3; forward-ref 04.

## 6. Authoring: code-first builder with a serializable content-addressed form

Scenarios are authored **code-first**, with a Rust builder that constructs a
`ScenarioDef` and validates it (§9) before it is hashed. Code-first authoring
gives the author the host language's type checking, refactoring, abstraction
(helper functions that emit common sub-topologies), and composition (reusing a
`World` value across scenarios) — the things a string-templated config format
cannot. The builder is the canonical front door; the serializable form (below) is
for storage, exchange, and reproduction, not the primary authoring surface.

```rust,illustrative
/// Code-first scenario authoring. Builds and validates (§9) a `ScenarioDef`,
/// then content-addresses it (§2). Orthogonal layers are set independently:
/// the `World` (nodes + links), the `Plan` (faults/events), the `Properties`
/// (assertions), and the `Seed` — never folded together (§10).
let scenario = ScenarioBuilder::new()
    // ── World: nodes (logical; no physical layout, §3.3) ──────────────────
    .node("db-0", VmDef::x86_64()
        .kernel(kernel_blob)
        .root_image(root_blob)
        .cmdline("console=ttyS0 quiet")
        .memory_mib(512)
        .icount_shift(7)
        .ready_point(ReadyPoint::ConsoleMarker { marker: "crucible-ready".into() }))
    .node("db-1", VmDef::x86_64().like("db-0"))   // reuse a node template
    .node("db-2", VmDef::x86_64().like("db-0"))
    // ── World: links (latency >= MIN_LINK_LATENCY, [SPAT-11]) ─────────────
    .link("db-0", "db-1", LinkDef::lan().latency_ms(5).jitter_ms(1).loss(0.0))
    .link("db-1", "db-2", LinkDef::lan().latency_ms(5))
    .link("db-0", "db-2", LinkDef::lan().latency_ms(5))
    // ── Plan: faults/events over virtual time (orthogonal layer, file 17) ─
    .plan(Plan::builder()
        .at_virtual_secs(10).inject(Fault::partition("db-0", "db-1").tag("split"))
        .at_virtual_secs(40).heal("split"))
    // ── Properties: assertions (orthogonal layer, file 18) ────────────────
    .properties(Properties::builder()
        .always("no_split_brain", Predicate::AtMostOneLeader)
        .eventually("converges", Predicate::AllAgree, /* deadline */ secs(60)))
    // ── Seed: root entropy (orthogonal layer, file 04) ────────────────────
    .seed(Seed::from_u64(42))
    .build()?;   // validates (§9), canonicalizes (§8), and content-addresses (§2)
```

The builder enforces the orthogonality of the four layers *structurally*: links
go through `.link(...)` (the `World`), faults through `.plan(...)` (the `Plan`),
assertions through `.properties(...)` (the `Properties`), and the seed through
`.seed(...)`. There is no `.boot_event(...)` into which links and assertions are
folded; the layers are independent because the API makes them independent (§10).

### 6.1 The serializable, content-addressed form

A `ScenarioDef` (and each component independently) has a **canonical serialized
form** — a deterministic TOML schema for human authoring/inspection and a compact
binary form for storage and exchange — both of which serialize to the *same*
canonical bytes for hashing (§8). The serialized form is what is stored in the
content store, exchanged between machines, and embedded in the reproduction
artifact (§7, 23). It is round-trippable: serialize-then-parse yields an equal
`ScenarioDef`, and the parse step runs the same validation (§9) and produces the
same `id` (§2).

```toml
# A canonical TOML rendering of the scenario above (illustrative). Tables are
# emitted in canonical order (§8) so the file is byte-stable for a given def.
# This form is for storage/exchange/repro; the builder (§6) is the front door.

[scenario]
seed = "0x000000000000002a00000000000000000000000000000000000000000000000000"  # 256-bit

[[world.node]]
id = "db-0"
arch = "x86_64"
kernel = "blake3:9f86d0..."        # content-addressed blob ref (§8)
root_image = "blake3:2c26b4..."
cmdline = "console=ttyS0 quiet"
memory_mib = 512
icount_shift = 7
ready_point = { kind = "console_marker", marker = "crucible-ready" }

# ... db-1, db-2 emitted in canonical (sorted) order ...

[[world.link]]
endpoints = ["db-0", "db-1"]       # canonically ordered pair (§8)
latency = "5ms"                    # >= MIN_LINK_LATENCY ([SPAT-11])
jitter = "1ms"
loss = 0.0

[[plan.entry]]                     # the Plan layer (file 17), orthogonal to world
at = "10s"                         # virtual time (09), never wall-clock
inject = { fault = "partition", a = "db-0", b = "db-1", tag = "split" }

[[plan.entry]]
at = "40s"
heal = { tag = "split" }

[[properties.assertion]]           # the Properties layer (file 18), orthogonal
name = "no_split_brain"
kind = "always"
predicate = "at_most_one_leader"
```

- **[SPAT-23]** The primary authoring surface MUST be a code-first Rust builder
  that constructs, validates (§9), canonicalizes (§8), and content-addresses (§2)
  a `ScenarioDef`. The builder MUST enforce the orthogonality of the four layers
  structurally: distinct entry points for `World` nodes/links, the `Plan`, the
  `Properties`, and the `Seed`, with no entry point that folds links or assertions
  into a boot/entry event (§10). *Gate:* `gate:content-address`. *Spec:* §6, §10.

- **[SPAT-24]** A `ScenarioDef`, and each of its components independently, MUST
  have a serializable content-addressed form for storage, exchange, and
  reproduction: a deterministic TOML rendering for human authoring/inspection and
  a compact binary rendering for storage, both serializing to the same canonical
  bytes for hashing (§8). The form MUST be round-trippable: serialize-then-parse
  MUST yield an equal `ScenarioDef` with the same `id`, and the parse step MUST
  run the same validation (§9). *Gate:* `gate:content-address`. *Spec:* §6.1, §8,
  §9.

- **[SPAT-25]** The serialized form MUST contain only content-addressed
  references for images/kernels/initrds (never host paths), so it is portable
  across machines and embeddable in a self-contained reproduction artifact (§7).
  *Gate:* `gate:content-address`, `gate:any-guest`. *Spec:* §6.1, §7.

## 7. `ScenarioFamily`: parametric scenarios for fuzzing and search

A single `ScenarioDef` pins one concrete world, plan, properties, and seed. For
fuzzing and state-space search ([G-6], file 22) the author needs not one scenario
but a **family**: a parametric generator over a space of scenarios, varying the
seed, the fault density, and the topology size. A `ScenarioFamily` is a function
from a point in its parameter space to a concrete `ScenarioDef`; a run **pins one
instance** by sampling (or enumerating) a parameter point, producing a fixed
`ScenarioDef` whose `id` goes into the run's reproduction artifact (§7.1, 22).

```rust,illustrative
/// A parametric generator over a space of `ScenarioDef`s, for fuzzing and
/// state-space search (file 22). Sampling/enumerating a `FamilyParams` point
/// pins ONE concrete `ScenarioDef` (with a fixed `id`); a run never executes a
/// family, only a pinned instance.
pub struct ScenarioFamily {
    /// Deterministic instantiation: params → a concrete, validated `ScenarioDef`.
    pub instantiate: Box<dyn Fn(&FamilyParams) -> Result<ScenarioDef, BuildError>>,
    /// The parameter space the family ranges over.
    pub space: FamilySpace,
}

/// The axes a family ranges over. Sampling is itself seeded and deterministic.
pub struct FamilySpace {
    /// Seeds to range over (a set, a range, or "draw N from the meta-seed").
    pub seeds: SeedSpace,
    /// Fault density: faults-per-virtual-second, scaling the generated `Plan`.
    pub fault_density: RangeInclusive<f64>,
    /// Topology size: node count (and a topology shape: ring/star/mesh/random).
    pub topology_size: RangeInclusive<u32>,
}

/// One sampled point in the family's space; deterministically maps to a def.
pub struct FamilyParams {
    pub seed: Seed,
    pub fault_density: f64,
    pub topology_size: u32,
    pub topology_shape: TopologyShape,
}
```

The family is the unit of *exploration*; the pinned `ScenarioDef` is the unit of
*execution and reproduction*. Search and fuzzing (22) walk the family's parameter
space, instantiate concrete `ScenarioDef`s, and run them; any failing run carries
a fully concrete `ScenarioDef` (with its `id`) and a `Schedule`, so a discovered
failure reduces to a self-contained reproduction artifact (§7.1) that needs no
reference to the family that generated it.

- **[SPAT-26]** Crucible MUST support a `ScenarioFamily`: a deterministic,
  parametric generator over a space of `ScenarioDef`s ranging at least over seed,
  fault density, and topology size (with a topology shape), for fuzzing and
  state-space search (22). Instantiating a family at a parameter point MUST
  produce a concrete, validated (§9) `ScenarioDef`. *Gate:* `gate:content-address`.
  *Spec:* §7; forward-ref 22.

- **[SPAT-27]** A run MUST pin exactly one concrete `ScenarioDef` instance; it
  MUST NOT execute a family directly. A run discovered by family search/fuzzing
  MUST reduce to a self-contained reproduction artifact (§7.1) carrying the
  concrete `ScenarioDef` (with its `id`), requiring no reference to the generating
  family to reproduce. *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`.
  *Spec:* §7, §7.1; forward-ref 22, 23.

### 7.1 The reproduction artifact

A failure is reproducible bit-identically from a **self-contained bundle**:
`(seed, scenario, schedule)` (the `seed` here is the `ScenarioDef`'s own `Seed`,
not a separate third field). The bundle is self-contained in the strong sense —
it contains (by content-addressed reference, dereferenceable from the content
store, or inlined for fully offline transport) everything needed to reduce the
run again to the same state: the `Seed`, the complete `ScenarioDef` (its `World`
with content-addressed kernel/root images, its `Plan`, its `Properties`), and the
`Schedule` (the recorded decision sequence, 05 §3). Because `State(t) =
reduce(ScenarioDef, Schedule[0..t])` ([INV-1]) and the artifact carries the
`ScenarioDef` and the `Schedule`, replaying the artifact MUST land at the same
state, verified by the replay oracle ([INV-2], 05 §8). The artifact's own
identity is content-addressed, so an artifact can be shared, deduplicated, and
referenced durably. The full on-disk format and the `crucible repro` flow are in
[`23-cli.md`](23-cli.md) and the temporal-graph storage in
[`07-temporal-graph.md`](07-temporal-graph.md); this file fixes the *contract*:
the artifact is `(seed, scenario, schedule)` and it is self-contained.

```rust,illustrative
/// A self-contained reproduction bundle: everything needed to reduce a run to
/// the same state ([INV-1]). Content-addressed; portable; offline-replayable.
/// On-disk format in file 23; storage in file 07. The contract is here.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReproArtifact {
    /// The pinned scenario definition (carries its own `Seed`, §5.3). Its
    /// `World` references images/kernels by content hash (§8), inlinable for
    /// fully offline transport.
    pub scenario: ScenarioDef,
    /// The recorded decision sequence (05 §3) that, with `scenario`, reduces
    /// to the run's state.
    pub schedule: Schedule,
    /// Content address of this artifact, for durable sharing/dedup ([INV-6]).
    pub id: ContentHash,
}
```

- **[SPAT-28]** A reproduction artifact MUST be the self-contained tuple `(seed,
  scenario, schedule)` and MUST contain (by content-addressed reference or inlined
  for offline transport) everything needed to reduce the run to the same state:
  the `Seed`, the complete `ScenarioDef` (with content-addressed images), and the
  `Schedule`. Replaying the artifact MUST land at the same state, verified by the
  replay oracle ([INV-2]). *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`.
  *Spec:* §7.1; forward-ref 23, 07.

- **[SPAT-29]** A reproduction artifact MUST be content-addressed by BLAKE3 over
  its canonical serialization, so it can be shared, deduplicated, and referenced
  durably ([INV-6]). The artifact MUST be portable across hosts (no host-varying
  paths) and replayable fully offline when images are inlined. *Gate:*
  `gate:content-address`. *Spec:* §7.1; cross-ref 23.

## 8. Canonicalization and content addressing (the hashing contract)

Content addressing is only meaningful if the serialization is **canonical**:
deterministic and a function of meaning, not of authoring accident. The hashing
contract is:

- **Algorithm.** BLAKE3 over the canonical byte serialization of each component,
  and BLAKE3 over the tuple of component hashes plus the seed for the
  `ScenarioDef::id` (§2).
- **Sorted collections.** `nodes` sorted by `NodeId`; `links` sorted by their
  canonically-ordered endpoint pair; `Plan` entries sorted by `(virtual_time,
  stable_tie_break)`; `Properties` assertions sorted by name. Sets, not authored
  order.
- **Canonical endpoint ordering.** A symmetric link's endpoint pair `(a, b)` is
  ordered by `NodeId` so `(a, b)` and `(b, a)` hash equal.
- **Fixed field order and encoding.** Struct fields serialized in a fixed schema
  order; integers in fixed-width little-endian; durations in a fixed unit
  (virtual nanoseconds); strings length-prefixed UTF-8.
- **No floating-point ambiguity in hashes.** Probabilities and densities that
  participate in the hash MUST be serialized in a canonical, exactly-representable
  form (e.g. a fixed-point or rational encoding), never a host-dependent float
  print, so the same probability hashes the same on every host.
- **Content-addressed references only.** Image/kernel/initrd references are
  BLAKE3 blob hashes, never host paths, so the hash is portable ([SPAT-25]).

This is what makes [SPAT-5] hold (meaning, not spelling) and what makes a
`World`, `Plan`, or `Properties` independently reusable by hash ([SPAT-3]).

- **[SPAT-30]** Every content-addressed component MUST have a single canonical
  byte serialization, hashed with BLAKE3, that is a function of meaning, not
  authoring order: collections sorted by a stable key, symmetric pairs canonically
  ordered, fixed field order and integer/duration encoding, and a canonical
  exactly-representable encoding for any probability/density that participates in a
  hash (no host-dependent float printing). Equal meaning MUST produce equal bytes
  and therefore equal hash on every host. *Gate:* `gate:content-address`,
  `gate:e2e-determinism`. *Spec:* §8.

## 9. Validation at parse/build time (fail early, not at runtime)

Every well-formedness condition of a `ScenarioDef` MUST be checked at **parse or
build time** — when the builder calls `.build()` or the parser parses the
serialized form — and an ill-formed scenario MUST be rejected with a precise error
*before* it is hashed or runs. The contract is "fail early, not at runtime": a
scenario that reaches the scheduler is already known well-formed, so the runtime
never has to defend against (or silently paper over) a malformed definition.

The required checks:

| Check | Condition | Requirement |
| --- | --- | --- |
| Node identity | `NodeId`s unique within the `World` | [SPAT-6] |
| Link endpoints | both endpoints are declared nodes | [SPAT-10] |
| Latency floor | every link `latency >= MIN_LINK_LATENCY` | [SPAT-11] |
| Jitter floor | `latency - jitter >= MIN_LINK_LATENCY` | [SPAT-12] |
| Loss range | every link `loss ∈ [0.0, 1.0]` | [SPAT-13] |
| Plan refs | every `Plan` node/link reference is declared | [SPAT-19] |
| Fault params | fault rates ∈ [0.0, 1.0]; counts/windows valid; directions known | [SPAT-31] |
| Heal tags | every heal references a tag injected somewhere in the `Plan` | [SPAT-31] |
| Plan time | every `Plan` entry is scheduled in virtual time, non-negative | [SPAT-20] |
| Property refs | every predicate's node reference is declared | [SPAT-21] |
| Ready point | white-box ready point requires the node's white-box opt-in | [SPAT-9] |
| vCPU count | a fixed count `N >= 1`; `N > 1` uses single-threaded RR-TCG | [SPAT-8] |
| Icount shift | a fixed, in-range shift (never `auto`) | [SPAT-8] |

```rust,illustrative
/// Build-time validation failures. Every variant is a well-formedness error
/// caught before hashing/running ([SPAT-32]); none is deferred to runtime.
#[derive(Debug)]
pub enum BuildError {
    DuplicateNodeId { id: NodeId },
    UndeclaredNode { referenced_by: RefSite, id: NodeId },
    LatencyBelowFloor { link: (NodeId, NodeId), latency: VirtualDuration },
    JitterBelowFloor { link: (NodeId, NodeId) },
    LossOutOfRange { link: (NodeId, NodeId), loss: f64 },
    FaultParamOutOfRange { entry: PlanEntryId, detail: String },
    HealWithoutInject { entry: PlanEntryId, tag: FaultTag },
    NegativePlanTime { entry: PlanEntryId },
    WhiteBoxReadyPointWithoutOptIn { node: NodeId },
    InvalidIcountShift { node: NodeId, shift_was_auto: bool },
    // ... one variant per row of the validation table ...
}
```

- **[SPAT-31]** Fault and event parameters in the `Plan` MUST be validated at
  build time: rates/probabilities in `[0.0, 1.0]`, counts and windows in valid
  ranges, partition directions among the known set, and every `heal` tag MUST
  reference a tag injected somewhere in the `Plan`. An out-of-range or dangling
  reference MUST be rejected with a precise error before hashing/running. *Gate:*
  `gate:e2e-determinism`. *Spec:* §9; cross-ref 17.

- **[SPAT-32]** All well-formedness checks (the §9 table) MUST run at parse/build
  time and MUST reject an ill-formed `ScenarioDef` with a precise, localized error
  *before* it is content-addressed or executed. No well-formedness condition may
  be deferred to runtime; a `ScenarioDef` that reaches the scheduler MUST already
  be known well-formed. *Gate:* `gate:content-address`. *Spec:* §9.

## 10. Why the layers stay orthogonal (untangling the entrypoint anti-pattern)

A tempting shortcut — and one an earlier generation of such tools fell into — is
to collapse the four layers into one: make the scenario a flat list of *events*,
make the first event a triggerless "boot"/"entrypoint" event, and **fold** the
links and the assertions into that boot event's action list (a boot event whose
actions are "create link A↔B, create link B↔C, register assertion X, start all
nodes"). It parses; it runs; and it quietly destroys the three properties this
file is built to provide.

It destroys **reuse**. When links live inside a boot event's action list, the
topology is not a value you can hash and share — it is tangled with start-node
actions, timer arms, and whatever else the boot event happens to do. You cannot
take "the 3-node ring `World`" and apply a different fault campaign to it, because
the campaign and the ring are the same blob. Orthogonal layers ([SPAT-2]) make the
`World` a standalone content-addressed value ([SPAT-3]) that any `Plan` and any
`Properties` can be paired with — which is exactly what a `ScenarioFamily` (§7)
and a correctness suite need.

It destroys **analyzability**. The scheduler needs the topology to compute the
conservative-lookahead graph (08); visualization and property scoping want the
node/link set directly. If links are buried in event-action lists, every such
consumer must *interpret events* to recover the graph — re-deriving structure that
should have been declared structure. With orthogonal layers the topology is read
directly from `World.links`.

It destroys **content-addressing of meaning** ([SPAT-5]). Folding makes the hash
depend on the boot event's action *order* and on incidental co-location of
unrelated actions, so semantically identical scenarios authored slightly
differently hash differently — the opposite of what content addressing is for.

Crucible therefore keeps the layers orthogonal at every level: in the type
(`ScenarioDef = (World, Plan, Properties, Seed)`, [SPAT-1]), in the builder API
(distinct entry points, no boot-event folding, [SPAT-23]), in the serialized form
(separate `[world]`, `[plan]`, `[properties]` sections, [SPAT-24]), and in the
hash (each component independently addressed, [SPAT-3]). A scenario *may* still
have triggerless `Plan` entries that fire at virtual time 0 (a fault that is
active from the start is fine); what it MUST NOT do is express *topology* or
*assertions* as *events*. Links are topology (the `World`); assertions are
observations (the `Properties`); faults are the only things that are events (the
`Plan`).

- **[SPAT-33]** Topology (links) MUST be expressed in the `World` and assertions
  MUST be expressed in the `Properties`; neither may be expressed as `Plan` events
  or folded into a boot/entrypoint event. Only faults/events belong in the `Plan`.
  This orthogonality MUST hold in the type ([SPAT-1]), the builder API
  ([SPAT-23]), the serialized form ([SPAT-24]), and the hash ([SPAT-3]), so that a
  `World` is independently reusable, the topology is directly analyzable, and the
  hash is a function of meaning ([SPAT-5]). *Gate:* `gate:content-address`.
  *Spec:* §10; cross-ref §1, §2.

## Cross-file assumptions this file fixes

Files 05, 07, 17, 18, and 23 reference the `ScenarioDef`; this file is the
authority for its shape. The contract those files may rely on:

- `ScenarioDef = (World, Plan, Properties, Seed)`, content-addressed by BLAKE3,
  with `ScenarioDef::id` = BLAKE3 over component hashes + seed ([SPAT-1],
  [SPAT-4]). This is the `def` of `Configuration = (def, schedule)` (05 §2) and
  the `def.id` half of `Configuration::id()` ([EXEC-4]).
- `World = (nodes[], links[])`, static (§4), logical-only with no physical-layout
  leak (§3.3). The input to `bake` (05 §6) and to the scheduler's lookahead graph
  (08).
- `Plan` (file 17), `Properties` (file 18), and `Seed` (file 04) are orthogonal,
  independently content-addressed components ([SPAT-2], [SPAT-3]).
- Every link latency is `>= MIN_LINK_LATENCY > 0` ([SPAT-11]); file 08 may assume
  a strictly positive lookahead horizon for every node.
- The reproduction artifact is the self-contained `(seed, scenario, schedule)`
  bundle ([SPAT-28]); files 23 and 07 own its on-disk format and storage.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md). The copies below are
> the tasks whose primary area is this file ([PLAN-3]); they are kept in
> sync with the master plan's order/digest by the doc lint ([`28-engineering-standards.md`](28-engineering-standards.md)).

- [x] **T-SPAT-1** Define `ScenarioDef = (World, Plan, Properties, Seed)` as an
  immutable pure value with no live handles, host paths, or wall-clock; property-test
  immutability and that equal content ⇒ equal `id`. — satisfies [SPAT-1], [SPAT-4];
  spec §1, §2.
  - Completed by `crates/crucible/src/model.rs`: `ScenarioDefForm` is the
    materialized pure `(World, Plan, Properties, Seed)` tuple, clones validated
    components at construction, exposes only immutable component accessors, and
    reconstructs the executable `ScenarioDef` handle from the tuple's component
    hashes plus seed. `ScenarioDef` keeps its `id` and `Seed` private, carries no
    live handles, and remains equal by content address. Image inputs are limited
    to `blake3:<hash>` references, host-path image refs are rejected before
    scenario construction, and the scenario model is gated against direct
    wall-clock APIs. The focused
    `scenario_def_form_is_immutable_pure_four_tuple_value` test and
    `checks.crucible.phase1.spatialScenarioDefValue` gate cover clone semantics,
    no-live-handle behavior, equal-content/equal-id cases, tuple-component
    identity sensitivity, host-path rejection, and wall-clock exclusion.
- [x] **T-SPAT-2** Enforce the four-layer orthogonality structurally (links in
  `World`, faults in `Plan`, assertions in `Properties`, entropy in `Seed`); add a
  lint/test that no layer is folded into another. — satisfies [SPAT-2], [SPAT-33];
  spec §1, §10.
  - Completed by `crates/crucible/src/model.rs`: `ScenarioBuilder` stores world
    nodes/links, plan entries, property assertions, and seed in separate fields,
    exposes distinct entry points for each layer, and composes through
    `World::from_nodes_and_links`, `Plan::from_entries_for_world`,
    `Properties::from_assertions_for_world`, and
    `World::scenario_def_with_plan_properties_and_seed`. The canonical scenario
    material records only component refs plus seed material, so topology, faults,
    assertions, and entropy are not folded into a boot/entrypoint event. The
    focused `scenario_layers_stay_structurally_orthogonal` test and
    `checks.crucible.phase1.spatialLayerOrthogonality` gate cover builder and
    serialized-form layer separation, component identity isolation, wrong-layer
    rejection, and static linting against boot-event/entrypoint folding APIs.
- [x] **T-SPAT-3** Implement independent BLAKE3 content-addressing for `World`,
  `Plan`, and `Properties`, and cross-reuse tests (one `World` across many defs; one
  `Plan`/`Properties` across many worlds). — satisfies [SPAT-3], [SPAT-5]; spec §2,
  §8.
  - Completed by `crates/crucible/src/model.rs`: `World`, `Plan`, and
    `Properties` each expose independent canonical bytes and BLAKE3 content
    addresses in separate domains (`crucible.model.world.v1`,
    `crucible.model.plan.v1`, and `crucible.model.properties.v1`). Scenario
    identity composes those component refs plus seed material instead of folding
    component material together. The focused
    `spatial_components_have_independent_content_addresses_and_cross_reuse` test
    and `checks.crucible.phase1.spatialComponentAddressing` gate cover exact
    component-domain hashes, one `World` reused across multiple scenario defs,
    one `Plan` and `Properties` bundle reused across compatible worlds, and
    scenario identity sensitivity to changing each component.
- [x] **T-SPAT-4** Implement `World = (nodes[], links[])` with unique `NodeId`s and
  canonical ordering; reject duplicate ids at build time. — satisfies [SPAT-6];
  spec §3.
  - Completed by `crates/crucible/src/model.rs`: `World` now carries canonical
    `nodes` and `links`, `World::from_nodes_and_links` sorts both collections
    before hashing, and build-time validation rejects duplicate `NodeId`s.
    `crates/crucible/src/lib.rs` covers authoring-order-insensitive topology
    hashes and link material changing scenario/bake identity;
    `checks.crucible.phase1.spatialWorldTopology` gates the task.
- [x] **T-SPAT-5** Implement `NodeDef`/`VmDef` carrying only launch-time inputs
  (arch, content-addressed kernel/root/initrd, cmdline, memory, fixed vCPU count,
  fixed icount shift, ready point, white-box opt-in); test no host-path leakage.
  — satisfies [SPAT-7], [SPAT-8]; spec §3.1.
  - Completed by `crates/crucible/src/model.rs`: `WorldNode` and
    `NodeTemplate` are the concrete NodeDef/VmDef-bearing model for this phase
    and carry only launch-time inputs: `VmArchitecture`, content-addressed
    kernel/root/initrd references, command line, memory size, fixed vCPU count,
    fixed icount shift, ready point, and white-box opt-in. TOML, compact binary,
    and canonical material include those fields, and parsing rejects host-path
    image references. The focused
    `world_node_launch_inputs_are_portable_and_identity_bearing` test and
    `checks.crucible.phase1.spatialNodeLaunchInputs` gate cover field retention,
    identity sensitivity, serialization round trips, fixed-memory validation, and
    no host-path leakage.
- [x] **T-SPAT-6** Implement the `ReadyPoint` policy set (fixed-icount /
  network-idle / console-marker / agent-signal) and gate white-box ready points
  behind the white-box opt-in. — satisfies [SPAT-9]; spec §3.1.
  - Completed by `crates/crucible/src/model.rs`: `WorldNode` carries the
    canonical `ReadyPoint` and `WhiteBoxPolicy`, the `ReadyPoint` enum includes
    `FixedIcount`, `NetworkIdle`, `ConsoleMarker`, and `AgentSignal`, and
    `World::validate_ready_point_policies` rejects `AgentSignal` unless
    `WhiteBoxPolicy::Enabled` is set. Model `bake` and QEMU bake validation call
    the shared validator before producing a genesis snapshot, and ready-point
    material is part of the canonical world/bake hash input. `crates/crucible/src/lib.rs`
    covers canonical hashing, material sensitivity, all four policies, and
    white-box opt-in rejection; `checks.crucible.phase1.executionReadyPoint`
    gates the task.
- [x] **T-SPAT-7** Implement `LinkDef` with canonically-ordered endpoints
  validated against declared nodes. — satisfies [SPAT-10]; spec §3.2.
  - Completed by `crates/crucible/src/model.rs`: `LinkDef::new` canonicalizes
    endpoint order and rejects self-loops, `World::validate_topology` rejects
    links to undeclared nodes and duplicate canonical links, and the canonical
    world material includes the sorted link endpoint pairs. The
    `world_topology_rejects_invalid_links` regression and
    `checks.crucible.phase1.spatialWorldTopology` gate cover the validation.
- [x] **T-SPAT-8** Implement the `MIN_LINK_LATENCY` floor and reject zero/negative
  latency, sub-floor `latency - jitter`, and out-of-range loss at build time. —
  satisfies [SPAT-11], [SPAT-12], [SPAT-13]; spec §3.2, §9.
  - Completed by `crates/crucible/src/model.rs`: `MIN_LINK_LATENCY` is exported as
    the one-nanosecond floor, `LinkDef::with_transport` rejects sub-floor base
    latency and `latency - jitter` combinations, and unsigned `SimDuration`
    keeps negative latency unrepresentable at the model boundary.
    `LinkLossProbability` stores loss as fixed-point millionths and rejects
    values above `1_000_000`; canonical world material includes link latency,
    jitter, loss, and bandwidth. `crates/crucible/src/lib.rs` covers identity
    sensitivity and rejection cases, and
    `checks.crucible.phase1.spatialLinkTransport` gates the task.
- [x] **T-SPAT-9** Guarantee the `World` encodes only logical topology with no
  physical-transport-layout leak, and that `ScenarioDef::id` is invariant under
  transport-layout/host-geometry changes. — satisfies [SPAT-14], [SPAT-15]; spec
  §3.3.
  - Completed by
    `checks.crucible.phase1.spatialLogicalTopology`: `World::nodes` is the one
    heterogeneous logical VM/block/9p collection and `World::links` holds the
    logical link characteristics. Canonical World and `DeviceId` material includes
    only logical clock/artifact/latency fields. Completion-order source numbers
    and request/response ring capacities live in `WorldIoInstantiationLayout`,
    derived from canonical node order plus `WorldIoLayoutPolicy` only when the
    session/scheduler resolves concrete artifacts. VM-only v1 identity, TOML, and
    binary bytes remain unchanged. Existing tests vary real shmem layout and host
    memory geometry without changing scenario/bake identity; the World-I/O tests
    also vary device ring policy without changing World/device identity or the
    resulting production scheduler effects. This directly proves that the
    logical identities are invariant under the physical layout inputs accepted
    at instantiation.
- [x] **T-SPAT-10** Make the topology static (no add/remove node, no link-set
  mutation) and verify the participant set, RNG-stream set, lookahead graph, and
  bake set are functions of `World` alone. — satisfies [SPAT-16], [SPAT-18]; spec
  §4.
  - Completed in `crates/crucible/src/model.rs`: `World` now stores nodes and
    links behind immutable accessors, exposes `World::static_topology()`, and
    derives the participant set, per-entity RNG-stream set, directed lookahead
    graph, and bake-node set from logical world topology alone. The focused
    `world_static_topology_is_derived_from_world_only` test covers schedule
    independence and canonical derivation, while
    `checks.crucible.phase1.spatialStaticTopology` gates the task.
- [x] **T-SPAT-11** Model membership dynamics (crash/restart/partition/heal/
  isolate/rejoin) as `Plan` faults over the static topology; verify a not-yet-joined
  participant is a declared node held inactive. — satisfies [SPAT-17]; spec §4.
  - Completed in `crates/crucible/src/model.rs`: `Plan` and `PlanEntry`
    carry typed `MembershipFault` values (`Crash`, `Partition`, `Isolate`, and
    `NotYetJoined`) plus `Heal` entries, and `Plan::from_entries_for_world`
    validates every membership fault against declared `World` nodes and links.
    The focused `membership_plan_faults_layer_over_static_world_topology` test
    proves not-yet-joined nodes remain declared participants and bake nodes,
    with rejoin expressed as healing the `NotYetJoined` tag after activation,
    while `membership_plan_rejects_dynamic_or_undeclared_topology_targets`
    rejects undeclared node/link targets, premature heals, and not-yet-joined
    holds scheduled after `t = 0`. `checks.crucible.phase1.spatialMembershipFaults`
    gates the task.
- [x] **T-SPAT-12** Carry `Plan` as an orthogonal content-addressed component
  (defined in 17) with build-time validation of node/link references and
  virtual-time scheduling. — satisfies [SPAT-19], [SPAT-20]; spec §5.1.
  - Completed in `crates/crucible/src/model.rs`: `Plan` now carries an
    independent content hash over canonical `PlanEntry` material, entries are
    canonicalized by virtual time and semantic fault material, and
    `World::scenario_def_with_plan` composes `World` and `Plan` component
    hashes without folding the plan into topology. The focused
    `plan_content_address_is_orthogonal_and_canonical` test covers
    authoring-order independence, plan reuse across compatible worlds, virtual
    time ordering, scenario identity sensitivity to the plan, and continued
    build-time node/link validation. `checks.crucible.phase1.spatialPlanComponent`
    gates the task.
- [x] **T-SPAT-13** Carry `Properties` as an orthogonal content-addressed component
  (defined in 18) with build-time predicate node-reference validation. — satisfies
  [SPAT-21]; spec §5.2.
  - Completed in `crates/crucible/src/model.rs`: `Properties` now carries an
    independent content hash over canonical `AssertionDef` material, covers the
    five property quantifier shapes from file 18, and validates every declared
    predicate node reference against `World` before scenario composition.
    `World::scenario_def_with_plan_and_properties` composes `World`, `Plan`, and
    `Properties` component hashes without folding assertions into topology or
    faults. The focused
    `properties_content_address_is_orthogonal_and_validated` test covers
    authoring-order independence, property reuse across compatible worlds,
    scenario identity sensitivity to properties, and rejection of undeclared
    predicate nodes. `checks.crucible.phase1.spatialPropertiesComponent` gates
    the task.
- [x] **T-SPAT-14** Carry `Seed` as the root entropy (04), part of identity, with
  name-hashed per-entity stream forking so unrelated `World` edits don't perturb
  other streams. — satisfies [SPAT-22]; spec §5.3.
  - Completed in `crates/crucible/src/model.rs`: `Seed` now carries the 256-bit
    root entropy component, participates directly in `ScenarioDef` identity via
    `World::scenario_def_with_plan_properties_and_seed`, and derives per-entity
    decision-RNG streams from the seed plus stable `RngStreamId` domain/name
    material. `World::seeded_rng_streams` projects the static world stream set
    into seed-derived stream roots, and the focused
    `seed_is_scenario_identity_and_name_hashed_stream_root` test covers explicit
    default-seed compatibility, seed identity sensitivity, all seed bytes feeding
    the stream root, node/link domain separation, and unchanged existing stream
    roots across unrelated world edits. `checks.crucible.phase1.spatialSeedComponent`
    gates the task.
- [x] **T-SPAT-15** Implement the code-first `ScenarioBuilder` with structurally
  orthogonal entry points and node/world templating; no boot-event folding. —
  satisfies [SPAT-23]; spec §6, §10.
  - Completed in `crates/crucible/src/model.rs`: `ScenarioBuilder` now exposes
    distinct world-layer entry points (`world`, `node`, `node_like`, `link`,
    `link_with_transport`, `link_def`), plan-layer entry points (`plan`,
    `plan_entry`), properties-layer entry points (`properties`, `property`), and
    `seed`, all flowing through the existing validated component composition path.
    `NodeTemplate` supports reusable node settings and builder-level `node_like`
    templating, with no boot-event topology/assertion folding API. The focused
    `scenario_builder_keeps_authoring_layers_structurally_orthogonal` test and
    `checks.crucible.phase1.spatialScenarioBuilder` gate cover builder/manual
    identity equality, world reuse, node-template rejection, and plan/properties
    validation against the static world layer.
- [x] **T-SPAT-16** Implement the serializable content-addressed form (canonical
  TOML + compact binary, same canonical bytes) with round-trip equality and
  content-addressed-reference-only images. — satisfies [SPAT-24], [SPAT-25]; spec
  §6.1, §8.
  - Completed in `crates/crucible/src/model.rs`: `ScenarioDefForm` now carries the
    materialized `World`, `Plan`, `Properties`, and `Seed` components for
    storage/exchange, reconstructs the canonical `ScenarioDef`, and exposes
    deterministic TOML plus compact binary round-trip APIs. The component types
    (`World`, `Plan`, `Properties`, and `Seed`) expose matching independent
    TOML/binary round-trip APIs, and parsing validates serialized ids against
    recomputed content addresses before returning a form. `ContentAddressedBlobRef`
    parses only `blake3:<hash>` image/kernel/initrd references and the TOML parser
    rejects host-path image references before deserialization. The focused
    `serializable_scenario_form_round_trips_and_rejects_host_paths` test and
    `checks.crucible.phase1.spatialSerializableForm` gate cover scenario/component
    round-trip equality, id mismatch rejection, and content-addressed-reference-only
    image validation.
- [x] **T-SPAT-17** Implement `ScenarioFamily` parametric over seed/fault-density/
  topology-size(+shape) producing concrete validated `ScenarioDef`s, with a run
  pinning exactly one instance. — satisfies [SPAT-26], [SPAT-27]; spec §7.
  - Completed in `crates/crucible/src/model.rs`: `ScenarioFamily` now owns a
    deterministic finite `FamilySpace` over `SeedSpace`, exact fixed-point
    `FaultDensity`, `TopologySizeRange`, and `TopologyShape`, with bounded
    cardinality and non-wrapping sample enumeration. Instantiating a `FamilyParams`
    point builds a concrete `World`, density-scaled `Plan`, and `Properties`,
    validates them through the same component constructors as the code-first
    builder, and returns a `PinnedScenario` carrying only the concrete
    `ScenarioDefForm` plus its parameter point. `PinnedScenario::genesis_configuration`
    pairs the executable `Configuration` with the concrete form, so runs pin one
    concrete `ScenarioDef` and retain the self-contained scenario material without
    executing a family handle. The focused
    `scenario_family_pins_concrete_validated_instances` test and
    `checks.crucible.phase1.spatialScenarioFamily` gate cover deterministic
    sampling, seed/density/topology identity sensitivity, out-of-space rejection,
    and pinned-instance execution.
- [x] **T-SPAT-18** Implement the self-contained `(seed, scenario, schedule)`
  reproduction artifact, content-addressed and offline-replayable, verified by the
  replay oracle. — satisfies [SPAT-28], [SPAT-29]; spec §7.1.
  - Completed in `crates/crucible/src/model.rs`: `ReproductionArtifact` now
    captures the complete validated `ScenarioDefForm`, derives the seed from that
    scenario form, embeds the recorded `Schedule`, and content-addresses exactly
    that tuple with BLAKE3 over compact canonical bytes. `Schedule` and
    `ReproductionArtifact` both expose compact binary round-trip APIs, so a
    transported artifact can be decoded and replayed without a family handle.
    `ReproductionArtifact::replay` reduces the embedded scenario/schedule tuple,
    and `verify_replay` returns `ReproductionArtifactReplayMismatch` if the
    spatial replay oracle reaches any state other than an external target. The
    focused `reproduction_artifact_is_self_contained_and_replay_checked` test and
    `checks.crucible.phase1.spatialReproductionArtifact` gate cover offline
    artifact byte decoding, pinned-instance capture, canonical id stability, and
    schedule/state drift rejection.
- [x] **T-SPAT-19** Implement canonicalization (sorted collections, canonical
  endpoint ordering, fixed field/integer/duration encoding, exact probability
  encoding, content-addressed refs) and prove meaning-not-spelling hashing across
  hosts. — satisfies [SPAT-30]; spec §8.
  - Completed in `crates/crucible/src/model.rs`: the spatial component
    constructors canonicalize world nodes/links, symmetric link and partition
    endpoints, plan entries, property assertions, and compound predicate sets
    before hashing or serializing. Canonical material uses fixed field order,
    explicit string lengths where needed, virtual-nanosecond durations,
    fixed-point link-loss/fault-density millionths, and `blake3:<hash>`
    kernel/root/initrd references. The focused
    `canonicalization_hashes_meaning_not_authoring_spelling` test and
    `checks.crucible.phase1.spatialCanonicalization` gate prove that different
    authoring order and endpoint spelling produce identical canonical bytes,
    compact binary, TOML, and content hashes, while changed probability or blob
    references change identity.
- [x] **T-SPAT-20** Implement build-time validation for fault params, heal tags,
  and Plan times with precise localized errors. — satisfies [SPAT-31]; spec §9.
  - Completed in `crates/crucible/src/model.rs`: `Plan::from_entries_for_world`
    rejects invalid membership fault targets, undeclared partition links,
    unknown heal tags, heal-before-activate times, and non-zero-time
    `NotYetJoined` activations before hashing/running. Fault params and plan
    times are typed (`MembershipFault`, `PartitionDirection`, unsigned
    `VirtualTime`), while serialized TOML parsing for plan components and full
    scenario forms rejects negative `at_ticks`, unknown partition directions, and
    unsupported fault-parameter fields before serde can collapse them into generic parse
    failures. Failures carry localized `EngineError` payloads naming the
    offending node, link endpoints, heal tag, activation time, heal time, plan
    entry index, invalid direction, and unsupported field.
    The focused `plan_validation_reports_precise_fault_heal_and_time_errors`
    test and `checks.crucible.phase1.spatialPlanValidation` gate lock down the
    exact build-time and parse-time error payloads plus canonical
    partition-parameter spelling.
- [x] **T-SPAT-21** Implement the full parse/build-time validation pass (the §9
  table) rejecting ill-formed scenarios before hashing/running; assert no
  well-formedness check is deferred to runtime. — satisfies [SPAT-32]; spec §9.
  - Completed by `crates/crucible/src/model.rs` and `crates/crucible-qemu`: the
    scenario-form constructors, TOML parser, and compact-binary parser validate
    `World`, `Plan`, and `Properties` before returning a runnable
    `ScenarioDefForm`; the parse paths also validate component content before
    checking serialized ids. The spatial pass rejects duplicate nodes, undeclared
    link endpoints, invalid latency/jitter/loss, bad plan refs,
    unsupported/unknown plan fault params, dangling heal tags, negative plan
    times, undeclared property refs, empty compound predicates, white-box ready
    points without opt-in, zero fixed vCPU counts, and out-of-range fixed icount
    shifts. `WorldNode` now carries fixed `smp_vcpus` and `icount_shift`, and
    both fields participate in world/scenario identity; `crucible-qemu`
    launch-profile validation mirrors those rows before spawn and continues to
    reject MTTCG/non-pinned launch material. The focused
    `scenario_def_form_rejects_well_formedness_matrix_before_hashing` test and
    `checks.crucible.phase1.spatialValidationPass` gate lock the §9 validation
    matrix to parse/build time.
