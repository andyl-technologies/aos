# 31 — Decision Register

This file records the **load-bearing design decisions** behind Crucible: the
choices that shaped the rest of the RFC, the honest reasons they were made, the
alternatives that were weighed and rejected, and the requirements and files each
decision affects. It exists so that a reader who disagrees with the system can
find *where* and *why* the fork in the road was taken, and so that a future
revision can revisit a decision with the original reasoning in front of it.

Requirement IDs in this file use the prefix `D` (decisions: `D-1`, `D-2`, …).
Unlike the `MUST`/`SHOULD` requirements in the topic files, a `D-n` entry is not
a normative statement to be tested — it is a *recorded rationale*. The normative
force lives in the requirement IDs each decision **affects**; this register is
the "why" behind those "what"s. Per [`00-conventions.md`](00-conventions.md), a
`SHOULD` deviation requires a recorded rationale, and this is where such
rationales live.

Each entry has a fixed shape:

```text
- **[D-n] <one-line title>**
  - **Status:** Decided | Open
  - **Decision:** what was chosen.
  - **Rationale:** why, honestly.
  - **Alternatives considered:** what else was on the table and why it lost.
  - **Affects:** the requirement IDs / files this decision shapes.
```

IDs are stable for the life of the RFC ([`00-conventions.md`](00-conventions.md)):
a superseded decision is marked so in place and a new `D-n` is added rather than
renumbered. `Decided` means the design commits to this choice and the spec is
written around it; `Open` means the design has a default but the question is
genuinely unresolved and is tracked as a spike in
[`30-risks-spikes.md`](30-risks-spikes.md).

---

## Decided

### D-1 — Instruction-level hermetic determinism is the contract

- **Status:** Decided
- **Decision:** Crucible's determinism contract is **hermetic
  instruction-level determinism**: for a fixed `(ScenarioDef, seed, Schedule)`
  every VM produces a bit-identical instruction stream `S` and architectural
  state trajectory `T` keyed by instruction count, achieved by *eliminating*
  every entropy source at its origin. The contract is explicitly **not**
  message-sequence determinism (same delivered cross-node messages, black-box
  interiors), and explicitly **not** record/replay (run once nondeterministically,
  log the outcomes, replay the log).
- **Rationale:** The expensive part of any deterministic-simulation effort —
  pinning the CPU model, suppressing `RDRAND`/`RDTSC` leakage, seeding guest
  entropy, driving virtual time from instruction count — is shared by all three
  contracts. Once that work is done, the interior of each VM is *already*
  bit-identical, so the stronger instruction-level contract is very nearly free,
  and it buys disproportionate value: trivial fork/resume (branches share a
  bit-identical prefix `T`, no reconciliation), a meaningful replay oracle
  ([INV-2] is only expressible if replay is bit-identical), divergence bisection
  to a single instruction (only possible because `T` is a function of icount),
  and byte-exact debugging. A weaker contract makes each of these untestable or
  impossible. The record/replay variant was rejected on a structural ground (see
  alternatives): a replay log is itself the output of a first, nondeterministic
  run, valid only for that exact build and host path, with no "golden first run"
  guarantee — whereas source elimination makes the *first* run already
  deterministic, so any run reproduces any other and a divergence is a real
  defect, not a stale log.
- **Alternatives considered:**
  - *Message-sequence determinism (the common "deterministic simulation"
    bar).* Rejected: it cannot reproduce interior bugs, cannot guarantee a fork
    agrees with its parent's interior, and cannot bisect a divergence to an
    instruction. It also is not actually cheaper given the elimination work is
    shared.
  - *Record/replay as the determinism mechanism.* Rejected as the *shipped*
    mechanism ([NG-6]): a replay log papers over live nondeterminism rather than
    removing it, is tied to one build/host quirk, and makes forks and the replay
    oracle ill-defined. QEMU's own record/replay is retained only as a
    *diagnostic* to *find* a residual entropy leak (it diverges precisely where
    one leaks), never as the contract's foundation.
- **Affects:** [G-1], [NG-6], [INV-1], [INV-10], [DET-1]–[DET-7], [DET-28];
  files 01, 04, [`30-risks-spikes.md`](30-risks-spikes.md).

### D-2 — icount is the canonical clock; ns is derived; the shift is fixed

- **Status:** Decided
- **Decision:** A VM's notion of time is its executed guest **instruction count
  (icount)**. Virtual nanoseconds are derived by the fixed mapping
  `ns = icount << shift` for a configured integer `shift`, supplied as
  `-icount shift=N`. The shift is a **fixed integer**, never `-icount shift=auto`,
  and it is part of the scenario's content hash.
- **Rationale:** Instruction count is the only per-VM quantity that is a pure
  function of the guest's own execution and is independent of host speed; making
  it the clock turns "time" into a counter the host can *read and command*
  rather than a quantity the host *races against*. `auto` mode adapts the
  instructions-per-nanosecond ratio to host execution speed at runtime, which
  makes the number of instructions retired before a virtual-timer deadline a
  function of how fast the host is — directly destroying [DET-1]. A fixed shift
  makes timer deadlines map to deterministic icounts on any host. Deriving ns
  from icount (rather than tracking ns independently) means there is exactly one
  clock and no second quantity to keep consistent. The shipped default is
  `shift=0`, so one retired guest instruction advances virtual time by one
  nanosecond. That default preserves the finest timer resolution while the
  scheduler and plugin ABI are still being hardened, and any later tuning is an
  explicit scenario-hash change rather than an invisible launch drift.
- **Alternatives considered:**
  - *`-icount shift=auto`.* Rejected: host-speed-dependent by construction;
    incompatible with cross-host reproducibility ([DET-9]).
  - *Tracking virtual nanoseconds as the primary clock with icount derived from
    it.* Rejected: ns is not a pure function of guest execution alone; making the
    instruction counter primary keeps the clock pinned to the guest.
  - *Per-scenario auto-tuned shift chosen once at bake time.* Rejected for the
    first cut: a tuned-then-frozen shift is still a parameter that must be
    recorded and re-gated, and the simplest correct thing is an explicit fixed
    integer in the scenario hash. (Choosing a *good* default shift value is a
    tuning question, not a determinism question — see [`30-risks-spikes.md`](30-risks-spikes.md).)
- **Affects:** [INV-4], [DET-8], [DET-9], [DET-10]; files 04, 09, 10.

### D-3 — QEMU TCG, not KVM

- **Status:** Decided
- **Decision:** Guests run under QEMU's **Tiny Code Generator (TCG)** binary
  translation, never under KVM hardware virtualization.
- **Rationale:** Determinism requires that instruction execution, interrupt
  delivery boundaries, timestamp counters, and floating-point results be a pure
  function of the inputs — which is only achievable when QEMU *emulates* the CPU
  rather than delegating to the host's silicon. Under TCG with `-icount`, the
  TSC is derived from the instruction counter ([DET-8]), interrupts are delivered
  at deterministic translation-block boundaries ([INV-4], E7), and soft-float
  makes FP a deterministic function of inputs across host CPUs (E15). KVM exposes
  the host CPU's real TSC, real `RDRAND`, real feature set, and host-timing-driven
  interrupt delivery, none of which can be made deterministic from outside.
- **Alternatives considered:**
  - *KVM with paravirtual clamps.* Rejected: the host CPU is in the loop for
    timing, entropy, and FP; there is no host-side seam that makes the interior
    bit-identical. KVM also cannot suppress wall-clock warp the way the plugin's
    time-control handshake does under TCG.
  - *A hybrid (KVM for boot, TCG for the measured window).* Rejected: the
    transition would itself be a nondeterminism boundary, and bake (D-8) already
    removes the cost argument for KVM boot.
- **Affects:** [G-1], [INV-4], [DET-1], [DET-4] (E4, E7, E10, E15); files 04
  (§4.6), 10.

### D-4 — Single vCPU per VM; multi-vCPU determinism is out of scope

> **Superseded in part by [D-22].** D-4's rejection of MTTCG **STANDS**: MTTCG
> instruction-interleaving determinism remains a non-goal. The clause asserting
> that *all* multi-vCPU determinism is out of scope and that the harness rejects
> any `-smp > 1` scenario is **superseded by D-22**, which establishes
> deterministic multi-vCPU via **single-threaded round-robin TCG** (not MTTCG).
> Read D-4 below as the original single-vCPU framing; D-22 is the current decision
> for the multi-vCPU dimension.

- **Status:** Decided
- **Decision:** Every VM runs single-vCPU (`-smp 1`). Multi-threaded TCG (MTTCG)
  instruction-interleaving determinism is a non-goal; the harness rejects a
  scenario that configures more than one vCPU. A guest that wants parallelism
  runs it serialized on one vCPU.
- **Rationale:** Concurrent vCPUs interleave memory operations nondeterministically
  under MTTCG (E13); making that interleaving reproducible would require either
  a deterministic memory-ordering model inside TCG (which does not exist) or a
  global lock that serializes execution — which is single-vCPU by another name,
  but slower and far more complex. Single-vCPU is the only point on the
  cost/determinism curve where the contract is achievable with the existing TCG
  machinery. Most distributed-systems bugs Crucible targets are *cross-node*
  ordering bugs, not intra-node multi-core races, so single-vCPU per VM loses
  little of the target value.
- **Alternatives considered:**
  - *MTTCG with a deterministic scheduler over vCPU steps.* Rejected: no
    deterministic memory model exists at the TCG level; the engineering cost is
    open-ended and the determinism is unproven.
  - *Global-lock serialized MTTCG.* Rejected: equivalent determinism to single
    vCPU but slower and more complex.
- **Affects:** [NG-1], [DET-23] (E13); files 01, 04, 10.

### D-5 — QEMU-guest-only scope; no in-process Rust testing mode

- **Status:** Decided
- **Decision:** Crucible is a **QEMU-guest** simulator. A "node" is always a
  guest VM or an I/O sub-node. Crucible does **not** provide an in-process
  harness for testing the host's own async Rust code (a node that is really an
  in-process task standing in for a service).
- **Rationale:** The entire determinism contract is built on sealing a QEMU VM's
  entropy boundary from outside; an in-process "node" would run real host code
  with real host entropy, host scheduling, and host time, and would need a
  completely different (and far weaker) determinism story. Mixing the two would
  blur the contract and create a second, untrustworthy determinism regime that
  users could accidentally rely on. Keeping the scope to "what runs under the
  patched QEMU" keeps one contract, one set of gates, and one mental model.
- **Alternatives considered:**
  - *A dual mode (in-process for fast unit-style tests, QEMU for fidelity).*
    Rejected: two determinism regimes, two sets of bugs, and the in-process mode
    cannot uphold instruction-level determinism (D-1) at all, so it would teach
    users a weaker contract under the same name.
- **Affects:** [NG-2]; files 01, 02 (glossary "Node"), 03.

### D-6 — Any unmodified guest; black-box default, white-box opt-in

- **Status:** Decided
- **Decision:** Determinism and all core capabilities are achieved **entirely
  host-side** on an arbitrary, unmodified guest kernel and root image, with only
  launch-time configuration. Black-box observation (network, disk/9p, console,
  QMP-readable state, crash/hang detection, plugin-harvested basic-block
  coverage) is the **default and the floor**. A fine-grained in-guest white-box
  channel (markers, assertions via a trapped-instruction doorbell) is an
  **optional, explicitly-enabled** enhancement that is never required and never
  perturbs deterministic execution.
- **Rationale:** Requiring guest modification (an agent, a kernel patch, injected
  image content) would (a) break the promise that the *same image used in
  production* runs deterministically here, (b) make the system guest-OS-specific,
  and (c) create a path by which guest-side state becomes load-bearing for
  determinism, which is exactly what the contract forbids ([DET-15]). Because all
  entropy is sealed from outside, the guest can be a sealed black box that
  happens to behave identically. White-box is kept strictly additive so that
  enabling it cannot become a hidden precondition: its inputs obey the same
  icount-stamped injection contract, and its markers are *observational* event-log
  entries excluded from determinism comparison, so a scenario with white-box on
  is fingerprint-identical to one with it compiled out.
- **Alternatives considered:**
  - *A required in-guest agent (richer observability, simpler host side).*
    Rejected: violates [G-2]/[INV-5], makes guests non-portable, and risks the
    agent's own nondeterminism leaking into the contract.
  - *White-box markers that influence scheduling (e.g. a guest barrier the
    scheduler honors).* Rejected: that would make a white-box feature
    load-bearing for ordering, breaking [GHC-2]; markers are observational only.
- **Affects:** [G-2], [G-3], [INV-5], [DET-15]–[DET-17], [ARCH-8], [GHC-1],
  [GHC-2]; files 01, 04 (§4.5), 16.

### D-7 — White-box signalling is a trapped-instruction doorbell over a virtio-serial channel

- **Status:** Decided
- **Decision:** The optional white-box guest→host signal is a **trapped
  instruction doorbell** (a reserved port-I/O / hypercall-style trap) serviced
  synchronously by the in-VM plugin, carrying its payload over a **virtio-serial
  device channel**. The doorbell is the synchronous "I have something to say"
  edge; the virtio-serial channel is the byte transport for the payload.
- **Rationale:** A trapped instruction is the only guest→host signal that is
  *synchronous with respect to icount* — the trap happens at a precise instruction
  count, so the plugin can stamp the marker against icount and make any reply
  visible at a deterministic count, exactly as the injection contract requires
  ([DET-11], 4.4). Polling a shared region or watching an MMIO doorbell
  asynchronously would reintroduce arrival-driven (wall-clock-correlated) timing.
  virtio-serial is chosen for the *payload* because it is a stock, well-understood
  device present in essentially every guest, so the white-box path needs no exotic
  guest driver; the doorbell rides on top to give the synchronous, icount-precise
  edge that a bare serial write would lack.
- **Alternatives considered:**
  - *A custom PCI device for the whole channel.* Rejected: requires a bespoke
    guest driver, undermining "any unmodified guest" even for the opt-in path,
    and adds device-model surface to the patch series.
  - *Pure virtio-serial with no doorbell (host polls the ring).* Rejected: host
    polling is arrival-driven, not icount-driven, so it cannot stamp markers
    deterministically against instruction count.
  - *A shared-memory mailbox the guest writes and the host polls.* Rejected: same
    arrival-driven defect; no synchronous trap to anchor the icount.
- **Affects:** [GHC-2], [DET-17], [DET-11]; files 12 (plugin trap servicing),
  16 (channel), 04 (§4.4).

### D-8 — One unified execution model: start ≡ resume ≡ fork via recursive `instantiate`

- **Status:** Decided
- **Decision:** There is exactly **one** state type (`Configuration =
  (ScenarioDef, Schedule)`), **one** function that produces a runnable state from
  it (`instantiate`, recursive, base case is boot), and **one** function that
  extends it (`step`). Start, resume, and fork are the *same operation*:
  `instantiate` at a checkpoint loads a cached snapshot if present, else replays
  from the nearest cached ancestor, else boots. `bake` boots each VM once to a
  defined ready point and snapshots it, so even the very first run is a *resume*
  from the genesis checkpoint — there is no privileged cold-start path.
- **Rationale:** Save/resume/fork/replay/search are, in most systems, four or
  five separately hand-written code paths, each with its own lifecycle-bug
  surface, and they drift apart over time (this is precisely the failure mode the
  prior internal exploration hit when it grew these features reactively). Modeling
  every position as a `Configuration` and every realization as one recursive
  `instantiate` collapses them into call sites of a single function, so a bug
  fixed once is fixed everywhere and the replay oracle ([INV-2]) becomes a
  *property of the data model* rather than a coincidence between two code paths.
  Baking removes the last special case (cold boot), making the boot path itself
  just the recursion's leaf, exercised on every run.
- **Alternatives considered:**
  - *Separate boot/snapshot/restore/fork subsystems (the conventional layout).*
    Rejected: multiple lifecycle-bug surfaces, drift, and an untestable replay
    relationship — the explicit defect this RFC is correcting ([G-4]).
  - *A privileged cold-start path with bake as an optimization only.* Rejected:
    a path exercised only on first run is the one most likely to be subtly wrong;
    bake makes the common path the only path.
- **Affects:** [G-4], [INV-1], [INV-2], [ARCH-1], [ARCH-2], [EXEC-1]–[EXEC-4];
  files 03, 05, 07.

### D-9 — Two orthogonal graphs: immutable spatial + content-addressed temporal DAG

- **Status:** Decided
- **Decision:** Crucible is organized as two orthogonal, content-addressed
  graphs joined by one reduction: the **spatial graph** (the immutable
  `ScenarioDef` — World, Plan, Properties, Seed — "configuration #0", which says
  nothing about time) and the **temporal graph** (a content-addressed DAG of
  checkpoints whose edges are Decisions, the closure of genesis under `step`).
  Structure and behavior are separate data; the engine is the pure function
  between them.
- **Rationale:** Keeping *what the system is* separate from *what it does over
  decision-time* is what makes resume, fork, and search uniform — they are all
  positions in, and expansions of, one DAG over one fixed definition. The spatial
  graph never changes during a run, so it is hashed once and shared across
  scenarios that reuse a kernel/image/sub-plan; the temporal graph only ever
  *grows by appending Decisions*, never by mutating state in place, so identity is
  always content and a re-derived state and a stored snapshot of the same point
  are the *same object* ([INV-2], [INV-6]). Folding the two into one mutable graph
  would lose content-addressed sharing and make the replay oracle inexpressible.
- **Alternatives considered:**
  - *A single mutable execution tree with in-place state.* Rejected: no
    content-addressed sharing, forks copy state, and the fat-≡-thin oracle cannot
    be stated.
  - *Treating the fault Plan as part of the temporal (decision) stream rather
    than the spatial definition.* Rejected: the Plan is *declarative and
    reproducible structure* (part of the scenario hash); only the *resolved*
    probabilistic firings are Decisions in the Schedule. Keeping the Plan spatial
    keeps the scenario identity stable.
- **Affects:** [INV-6], [INV-2], [SPAT-*], [TEMP-*], [EXEC-1]; files 03 (§2), 06,
  07.

### D-10 — Conservative PDES with an exact-local vs conservative-network horizon

- **Status:** Decided
- **Decision:** Cross-node advancement uses **conservative parallel
  discrete-event simulation (Chandy–Misra–Bryant)**: a node advances only into a
  region of virtual time where no peer could deliver an event earlier. The
  refinement is the **horizon rule**: `horizon(n) = min(next exact local event of
  n, n.virtual_time + lookahead(n))`, where *exact local events* (timers, disk/9p
  I/O completions) are host-computed and give an exact horizon with no slack, and
  only *guest→guest network* needs the conservative CMB lookahead bound (minimum
  inbound link latency). Separately, **sync frequency is decoupled from ordering
  exactness**: ordering is always exact and never a tuning knob; the only knob is
  how often the scheduler rendezvouses all nodes (for assertion-drain /
  topology-change), and it can never affect which instruction sees which input.
- **Rationale:** Conservative PDES is chosen over optimistic (speculate-and-
  rollback) PDES because rollback over a full VM memory image is enormously
  expensive and would itself be a determinism hazard; conservative execution
  never speculates past a point a peer could still affect, so it never rolls back.
  Naive CMB, however, is slow because it applies a conservative lookahead bound to
  *every* advance, including ones the host can predict exactly. The exact-local
  refinement recovers most of the speed: timers and I/O completions are computed
  host-side, so their horizons are exact and the node can run right up to them
  with no conservative slack — only genuinely unpredictable guest→guest traffic
  pays the lookahead tax. Decoupling sync frequency from exactness lets operators
  tune throughput (rarely rendezvous) without ever risking correctness (ordering
  is fixed by `(virtual_time, node_id, sequence)` regardless).
- **Alternatives considered:**
  - *Optimistic PDES (Time Warp) with rollback.* Rejected: rolling back VM state
    is prohibitively expensive and a determinism hazard; conservative execution
    avoids it entirely.
  - *Lock-step (advance all nodes by a fixed quantum together).* Rejected:
    throws away the parallelism the lookahead window allows and either
    over-synchronizes (slow) or risks missing an early delivery (incorrect).
  - *Pure CMB with no exact-local refinement.* Rejected: applies conservative
    slack to predictable events too, leaving large amounts of safe parallelism
    and fast-forward on the table.
- **Affects:** [INV-3], [INV-8], [DET-6], [DET-12], [SCHED-*]; files 04 (§4.2.2),
  08, 15.

### D-11 — I/O is uniform scheduled sub-nodes, not a freeze-time hack

- **Status:** Decided
- **Decision:** Disk, 9p, and network-link I/O are modeled as **first-class I/O
  sub-nodes** in the same scheduling graph as VMs, each with its own
  icount-derived clock, emitting **deterministic completion events** that the
  scheduler resolves in the *same total order* (`(virtual_time, node_id,
  sequence)`) as frame deliveries and fault activations. A disk read finishes at a
  virtual time the sub-node computes from the request and a fixed model — making
  its completion an *exact local event* — not "whenever the host disk finishes."
- **Rationale:** The tempting alternative is a "freeze time" hack: pause the
  guest's virtual clock while host I/O runs, then resume. That makes I/O latency
  invisible (always zero modeled latency) and, worse, couples completion ordering
  to host-timing the moment two I/Os overlap. Treating I/O as scheduling nodes
  with computed completion times instead (a) gives I/O *modeled* latency that is
  part of the deterministic timeline, (b) makes a completion an exact local event
  that yields an exact horizon (D-10), and (c) routes disk/9p/net completions
  through the *one* total order, so all three cross-node event kinds are scheduled
  by one mechanism with one tie-break. One mechanism is far easier to prove
  deterministic than three special paths.
- **Alternatives considered:**
  - *Freeze-the-clock-during-host-I/O.* Rejected: zero modeled latency, and
    host-timing-coupled ordering on overlapping I/O — a direct [INV-3] violation.
  - *Synchronous in-line I/O on the vCPU thread.* Rejected: still host-timing for
    completion order, and serializes everything even when the model would allow
    overlap.
- **Affects:** [ARCH-7], [INV-3], [INV-8], [DET-16] (E19); files 03 (§7), 08, 15.

### D-12 — One authoritative scheduler as an actor; session-as-actor; no long-held locks

- **Status:** Decided
- **Decision:** All advancement of virtual time and all resolution of cross-node
  ordering flow through **exactly one scheduler**, realized as an **actor** that
  owns its state and mutates it only on its own task, **yielding between quanta**
  so control operations (pause, resume, step, snapshot, fork, query, topology
  change) are applied only at quantum boundaries. The live, controllable run is a
  **session**, also modeled as an actor that owns its `RuntimeState` and drives
  the scheduler by messages — never by shared-state mutation, and never by holding
  a lock across a RUN phase.
- **Rationale:** A single source of timing truth is the precondition for [INV-3]:
  if any second component could advance a clock or deliver an event out of band,
  the total order would be a host-timing race. Realizing it as a yielding actor
  serves *two* goals at once: determinism (state mutated on one task has no
  host-thread interleave to make nondeterministic) and responsiveness (a control
  message can be serviced at a well-defined boundary without a torn, mid-quantum
  read, and without a long-held lock blocking control). The quantum becomes the
  atomic unit of *both* advancement and control. Session-as-actor extends the same
  discipline to the control plane: control is *messages to an actor*, so there is
  no shared-state mutation path to race.
- **Alternatives considered:**
  - *A scheduler guarded by a mutex that control code locks to interact.*
    Rejected: long-held locks across a RUN phase block control (unresponsive) and
    invite mid-quantum reads; the actor's yield-between-quanta gives the same
    safety without blocking.
  - *Multiple cooperating schedulers (one per node-cluster).* Rejected: two
    sources of timing truth cannot produce one total order without a coordination
    protocol that is itself a scheduler — so it collapses back to one.
- **Affects:** [INV-8], [INV-3], [ARCH-5], [ARCH-9], [SCHED-1]–[SCHED-4],
  [SESS-*]; files 03 (§5, §8), 08, 20.

### D-13 — One unified content-addressed event log; causal vs observational in the schema

- **Status:** Decided
- **Decision:** There is a **single, totally-ordered, content-addressed event
  log** that is simultaneously the determinism oracle, the assertion input, the
  debugging artifact, the fork index, and the coverage record. Entries that may
  legitimately vary between equivalent runs (e.g. white-box markers, timing-only
  observations) are distinguished as **observational** *in the schema itself* —
  not by an out-of-band side flag — and are excluded from determinism comparison;
  everything else is **causal** and is part of the bit-identical comparison.
- **Rationale:** A single log means every consumer reads the *same* record, so
  "checking a property" is a pure fold over the same bytes the determinism gate
  compares, and offline checking a year later is identical to online checking. The
  causal/observational distinction has to be intrinsic to each entry's type
  because the determinism comparison is a function of the schema: if "is this
  comparable?" were a side flag, two builds could disagree about which entries
  count, silently weakening the contract. Putting it in the schema makes the
  comparable subset a typed, versioned, content-addressed fact.
- **Alternatives considered:**
  - *Separate logs per consumer (a determinism log, an assertion log, a coverage
    log).* Rejected: duplicate records drift, and the "same bytes" guarantee
    between the oracle and the assertion engine is lost.
  - *A single log with an external "ignore for determinism" flag list.* Rejected:
    the comparable set must be intrinsic and versioned, not external state that
    can mismatch across builds.
- **Affects:** [INV-1], [INV-6], [DET-28], [OBS-*], [ASRT-*]; files 18, 19.

### D-14 — No bespoke formal-methods engine; temporal-property checking only; optional offline conformance

- **Status:** Decided
- **Decision:** The assertion layer is a **fixed, closed vocabulary** of temporal
  property quantifiers (Always / Sometimes / Eventually / AfterQuiescence /
  Reachable) evaluated as a pure fold over the recorded event log. Crucible
  contains **no model checker** and **no specification-language evaluator**.
  Conformance against an external formal specification, if ever wanted, is an
  **optional offline** step performed by separate tooling fed Crucible's exported
  trace — never an in-runtime engine.
- **Rationale:** The event log already does the hard work: because it is the
  deterministic, totally-ordered, complete record of everything that happened,
  checking a property is a fold over it, and the system gets enormous value from a
  *small* vocabulary without taking on the open-ended complexity (and
  maintenance, and determinism surface) of a model-checking engine. A built-in
  spec evaluator would be a large subsystem whose own determinism would have to be
  proven, for a capability that is better served — when actually needed — by
  mature external tooling consuming the exported trace offline. Keeping checking
  to a pure fold also means declaring or removing a property cannot perturb the
  run ([ASRT-2]).
- **Alternatives considered:**
  - *An in-runtime LTL/CTL evaluator or model checker.* Rejected ([NG-3]):
    large, open-ended, adds a determinism surface to prove, and duplicates mature
    external tools for the rare case it is wanted.
  - *No assertion vocabulary at all (users grep the trace).* Rejected: the small
    fixed vocabulary captures the common temporal shapes (invariant, liveness,
    bounded liveness, end-state, coverage) with reproducible, hashed semantics.
- **Affects:** [NG-3], [ASRT-1], [ASRT-2]; files 01, 18, 19.

### D-15 — Shared-memory co-sim transport over IPC barriers; the shmem ABI is the single source of truth

- **Status:** Decided
- **Decision:** The host↔plugin co-simulation transport is a **`#[repr(C)]`
  shared-memory region** per VM (per-node clocks, status, and SPSC frame queues
  with `FrameEntry` payloads), driven by a per-node max-advance ceiling and futex
  wake — not an IPC-barrier / message-passing rendezvous. Every input carries its
  **delivery icount in-band** so the consumer is time-driven, not arrival-driven.
  The shared-memory layout (the `crucible-shmem` ABI) is the **single, explicitly
  versioned source of truth** for the boundary, covered by conformance
  tests/golden vectors.
- **Rationale:** The most important correctness property of the transport is that
  a payload's *presence* on a queue never determines its *visibility* to the
  guest ([DET-13], [DET-34]); the consumer reads the in-band delivery icount and
  makes the input visible at exactly that count. A shared-memory region with an
  in-band delivery icount expresses this directly and cheaply; an IPC-barrier
  protocol would tend to couple visibility to message arrival (a wall-clock race)
  unless every message also carried the icount — at which point the barrier is
  pure overhead over the shmem queue. Shared memory with a futex wake is also the
  lowest-latency option, which matters for the per-quantum handshake cost (G-9).
  Making the `#[repr(C)]` layout the single versioned source of truth (rather than
  a hand-maintained protocol doc plus a struct) means host and plugin cannot drift,
  and golden vectors pin the wire format across versions ([G-8]).
- **Alternatives considered:**
  - *Message-passing over a socket / IPC barriers.* Rejected: higher latency per
    quantum and a tendency to make visibility arrival-driven; the in-band-icount
    discipline is harder to enforce.
  - *Two sources of truth (a prose protocol spec + an independently-written
    struct).* Rejected: they drift; the ABI struct is canonical and conformance
    vectors test it.
- **Affects:** [G-8], [G-9], [INV-3], [DET-11], [DET-13], [DET-34], [SHM-*],
  [PROTO-*]; files 04 (§4.4, §4.9), 13, 14.

### D-16 — QEMU patches are inert unless sim mode is active

- **Status:** Decided
- **Decision:** Every mechanism in the AOS QEMU patch series is **inert unless
  simulation mode is explicitly activated** (plugin loaded + sim flags). The same
  AOS QEMU source built and run without sim mode active is **behaviorally
  identical to upstream**; each patch carries a micro-test proving both that it
  *takes effect* in sim mode and that it is *inert* out of sim mode.
- **Rationale:** AOS ships *one* QEMU package, used both for production
  virtualization and for Crucible. A determinism patch that changed non-sim
  behavior would silently alter AOS's production QEMU — unacceptable. Gating every
  patch behind sim mode lets Crucible's mechanisms live in the shipped QEMU
  without risk, keeps the patch series upstreamable (inert-by-default is the
  posture upstream expects), and makes the inertness itself testable
  ([gate:qemu-inert]). It also means a single from-source build serves both
  purposes, consistent with AOS's hermetic-from-source principle (G-7).
- **Alternatives considered:**
  - *A separate "Crucible QEMU" fork built only for simulation.* Rejected: two
    QEMU builds to maintain, two security surfaces, and divergence risk; one
    inert-by-default package is simpler and safer.
  - *Patches always active but "harmless" in production.* Rejected: "harmless"
    is unprovable in general; inert-unless-sim-mode with a per-patch inertness
    test is the provable posture ([INV-7]).
- **Affects:** [G-7], [INV-7], [DET-36], [DET-37]; files 04 (§4.10), 10, 11.

### D-17 — Standalone of the RFC-0007 (ratchet) ratchet; shared substrate gated for later

- **Status:** Decided
- **Decision:** Crucible **ships standalone** and does **not** depend on RFC-0007
  (`ratchet`, the AOS sibling Nix-evaluator engine) landing. Any shared
  lower-level substrate — a content-addressed store plus a dependency-gated
  invalidation primitive common to ratchet's incremental cache and Crucible's
  temporal graph — is **gated behind a future integration**; until then Crucible
  vendors or reimplements the small amount it needs and marks the seam.
- **Rationale:** `ratchet` and Crucible are genuine conceptual cousins (both are
  content-addressed, incremental, determinism-obsessed Rust graph-reduction
  systems), and a shared substrate is attractive in principle. But ratchet is
  still in flight; making Crucible depend on it would couple Crucible's schedule
  to ratchet's and risk co-evolving two unstable interfaces at once. Shipping
  standalone keeps Crucible's foundation-first plan (G-5) under its own control,
  and the small content-addressed-store surface Crucible needs is cheap to
  vendor/reimplement behind a clearly marked seam, so the eventual merge is a
  contained refactor rather than a prerequisite.
- **Alternatives considered:**
  - *Build Crucible on ratchet's substrate now.* Rejected: couples two unstable
    schedules and two in-flight interfaces; violates the standalone non-goal
    ([NG-7]).
  - *Permanently fork the substrate (never integrate).* Rejected: gives up the
    real long-term win of a shared content-addressed primitive; the seam is
    marked so integration stays cheap.
- **Affects:** [NG-7]; files README (§"Relationship to RFC-0007"),
  [`30-risks-spikes.md`](30-risks-spikes.md), and the packaging/AOS-integration
  "ratchet gate".

### D-18 — Naming: "Crucible," distinct from the sibling ratchet engine

- **Status:** Decided
- **Decision:** The system is named **Crucible**; crates are `crucible-*` and the
  CLI binary is `crucible`. The name is chosen to be distinct from RFC-0007's
  `ratchet`, and neither the RFC nor any Crucible code/comments/docs refer to any
  prior internal exploration by name nor to any third-party commercial product
  ([CONV-1]); RFC-0007 / `ratchet` may be named as the AOS sibling.
- **Rationale:** A crucible is a vessel in which materials are subjected to
  extreme, controlled conditions to test and transform them — an apt metaphor for
  subjecting a distributed system to controlled, reproducible, adversarial
  conditions to find where it breaks. The name is deliberately *different* from
  `ratchet` because the two are independent systems with independent schedules
  (D-17): a shared or punning name would imply a coupling that does not exist and
  would confuse the gated-for-later substrate relationship. The [CONV-1]
  constraint (no prior-project or commercial-product names) keeps the design
  described as its own and avoids implying lineage from or compatibility with any
  external tool.
- **Alternatives considered:**
  - *A name punning on or derived from `ratchet`.* Rejected: implies a coupling
    that D-17 explicitly avoids.
  - *Reusing a recognizable name from a commercial or prior product.* Rejected
    by [CONV-1]; it would mislead about lineage and compatibility.
- **Affects:** [CONV-1]; files 00 (§"Voice and naming"), README, 02.

### D-22 — Deterministic multi-vCPU via single-threaded round-robin TCG; MTTCG rejected

- **Status:** Decided
- **Decision:** Multi-vCPU determinism is achieved with **single-threaded
  round-robin TCG** (`-accel tcg,thread=single`): all vCPUs run on one host
  thread, and the round-robin switch boundary is a fixed, content-addressed
  `rr_switch_quantum` measured in node-icount. The same source-elimination
  contract that makes a single-vCPU guest bit-identical is extended over all N
  vCPUs and the round-robin cursor. **MTTCG is rejected.** This supersedes the
  multi-vCPU-out-of-scope clause of D-4 (whose MTTCG rejection stands).
- **Rationale:** MTTCG interleaves vCPU memory operations on separate host
  threads with no deterministic memory-ordering model, so it cannot be made
  reproducible host-side. Single-threaded round-robin TCG instead serializes all
  vCPUs onto one host thread, and — critically — the switch boundary is itself an
  **icount-commandable quantum**, exactly like virtual time: the scheduler decides
  *when* a vCPU switch happens by a node-icount count, not by host scheduling, so
  the interleaving is a pure function of icount. That makes an SMP guest as
  deterministic as a single-vCPU one and lets the vCPU switch be a branchable
  Decision (D-24). The cost is throughput (no real host parallelism *within* a
  node), which is the right trade for a determinism-first simulator.
- **Alternatives considered:**
  - *MTTCG (multi-threaded TCG).* Rejected: nondeterministic vCPU interleaving;
    no deterministic memory model at the TCG level (the D-4 rejection, which
    stands).
  - *Global-lock MTTCG.* Rejected: a global lock serializes execution — it is
    single-vCPU-by-another-name, but slower and more complex, with none of the
    icount-commandable-switch benefit of round-robin TCG.
- **Affects:** [G-10], [DET-23], the Contract A restatement, [SCHED-45], [PLUG-3],
  [QEMU-5], E21–E24; files 01, 04, 08, 09, 10, 11, 12, 13.

### D-23 — Node clock stays aggregate; per-vCPU state is plugin-internal and in the fingerprint

- **Status:** Decided
- **Decision:** A node's clock remains a **single aggregate icount** even with N
  vCPUs; per-vCPU architectural state lives **inside the plugin** and is folded
  into the **extended fingerprint** (all N vCPUs' register files + the round-robin
  cursor). The shared-memory ABI is **unchanged**: there are **no per-vCPU shmem
  slots** and no per-vCPU clocks.
- **Rationale:** Virtual time is a property of the *node*, not of an individual
  vCPU; the round-robin TCG model already advances all vCPUs against one
  aggregate instruction counter (D-22). Exposing a per-vCPU dimension into the
  shmem ABI, the scheduler, and the total order would leak an internal detail
  across the whole boundary for no gain — the scheduler orders *nodes*, and the
  vCPU interleaving is resolved inside the plugin under the aggregate clock.
  Keeping per-vCPU state plugin-internal (but in the fingerprint, so determinism
  is still fully checked over all vCPUs) preserves the existing ABI and total
  order untouched.
- **Alternatives considered:**
  - *Per-vCPU shmem slots.* Rejected: leaks the vCPU dimension into the
    scheduler, the ABI, and the total order for no benefit.
  - *Per-vCPU clocks.* Rejected: virtual time is a node property; N clocks per
    node would need an intra-node ordering protocol the round-robin cursor already
    provides under one aggregate clock.
- **Affects:** [SHM-37], [TIME-34], [DET-43]; files 13, 09, 04.

### D-24 — vCPU-switch and interrupt timing is a first-class `Decision::Preemption`

- **Status:** Decided, gated by S12 fallback
- **Decision:** The vCPU-switch boundary and timer-interrupt delivery timing are a
  first-class **`Decision::Preemption`** in the Decision taxonomy: deterministic by
  default, but **branchable by the explorer** to explore concurrency interleavings.
  It works for single-vCPU guests too — varying the timer-interrupt delivery icount
  explores intra-thread races without a second vCPU. Phase 0 does not enable this
  branchable surface until the commanded preemption-injection capability exists
  and S12 passes without fallback.
- **Rationale:** Once the vCPU switch is an icount-commandable quantum (D-22), the
  *choice* of switch point (or interrupt-delivery point) is exactly the kind of
  resolved, reproducible decision the temporal graph already branches on for faults
  and scheduling. Making it a Decision lets the state-space search explore
  interleavings the same way it explores fault firings — each branch
  bit-reproducible, the campaign adaptive. Extending it to interrupt timing means
  even single-vCPU guests get an intra-thread race-exploration dimension.
- **Alternatives considered:**
  - *Fixed default interleaving only (no exploration).* Rejected: forecloses the
    headline concurrency-bug-finding value of multi-vCPU support ([G-11]).
  - *Preemption as an out-of-band tuning knob rather than a Decision.* Rejected: a
    knob that changes `T` but is not a recorded Decision breaks the
    `T = f(Configuration)` model; it must be a branch in the temporal graph.
- **Affects:** [G-11], the EXEC Decision taxonomy, [SCHED-46], [ADV-39]; files 03,
  07, 08, 22.
- **Phase-0 S12 outcome:** `checks.crucible.phase0.s12PreemptionDecision` found
  no known current preemption-injection surface in the QEMU wiring, local patch
  directory, production trace plugin, or Rust crates. This decision remains a
  target architecture decision rather than an enabled implementation surface.
  Crucible keeps default deterministic interleaving only until the patch-series
  injection capability lands and S12 is rerun.
- **Engine schedule surface:** T-EXEC-19 now implements the Rust execution-model
  recording discipline: nonzero RR-boundary default preemptions are derived
  without schedule entries, while explorer-supplied `Decision::Preemption`
  values are explicit replay material. This does not enable the QEMU
  commanded-injection surface.

### D-26 — App-controlled randomness as an optional white-box exploration dimension

- **Status:** Decided
- **Decision:** Application-controlled randomness is an **optional white-box
  exploration dimension**: a guest may request a random value via the doorbell, and
  the host serves it as a **`Decision::AppRandom`** drawn from the *single seeded
  decision source* and written back over the doorbell. It is **never required** to
  run any guest; a guest that does not opt in is unaffected.
- **Rationale:** White-box guests that want their *own* randomness driven by the
  explorer (so the search can branch on the values the application draws) get it for
  free from the existing seeded decision source — the same source that resolves
  fault firings and schedules. Serving it as a Decision keeps every drawn value
  reproducible and branchable, and routing it over the existing doorbell means no
  new transport. Keeping it strictly optional and white-box preserves D-6: a
  black-box guest never needs it, and enabling it cannot become a hidden
  determinism precondition.
- **Alternatives considered:**
  - *A required guest RNG hook.* Rejected: violates D-6 (any unmodified guest,
    black-box floor); app randomness must be opt-in white-box only.
  - *A separate entropy source for app randomness.* Rejected: a second seeded
    source is a second thing to keep deterministic; the single decision source
    already serves every reproducible choice.
- **Affects:** [DET-44], [GHC-37], [GHC-38], the EXEC AppRandom Decision, [ADV-40];
  files 16, 04, 03, 22.

### D-27 — Guided / adaptive exploration: pluggable fixed-point guidance + optional deterministic bandit

- **Status:** Decided
- **Decision:** State-space exploration is **guided** by a pluggable, fixed-point
  **guidance signal** (coverage / novelty / assertion-proximity) and an optional
  **deterministic bandit** over exploration choices. Exploration is
  **campaign-adaptive** — the campaign steers itself toward interesting regions —
  but **each individual run is bit-identical** (the guidance is a pure function of
  the recorded results so far).
- **Rationale:** Blind exploration wastes the deterministic substrate; a guidance
  signal computed as a fixed-point fold over the (deterministic, content-addressed)
  event log lets the campaign prioritize coverage-novel or assertion-proximate
  branches without sacrificing per-run reproducibility. Making the bandit
  *deterministic* (seeded, replayable) keeps the *campaign itself* reproducible
  given the same starting corpus, while still adapting. The signal is pluggable so
  new objectives (a new coverage metric, a new novelty notion) drop in without
  changing the engine.
- **Alternatives considered:**
  - *Random / round-robin frontier expansion.* Rejected: ignores the feedback the
    deterministic log makes cheap; far less efficient at finding bugs.
  - *A nondeterministic (wall-clock-seeded) bandit.* Rejected: makes the campaign
    irreproducible; the bandit must be seeded and replayable.
- **Affects:** [ADV-34]–[ADV-38], [ASRT-33], [OBS-37]; files 22, 18, 19.

### D-28 — Distributed and continuous exploration over the shared content-addressed store

- **Status:** Decided
- **Decision:** Exploration may be **distributed** across hosts and run
  **continuously** over a **shared content-addressed store**. Two claims are kept
  distinct: **Claim A** — *reproduction* of any found configuration is
  **host-independent** (content addressing makes location orthogonal to `T`);
  **Claim B** — *scheduling and distribution of work* across the fleet **may be
  nondeterministic** (which host explores which branch is a scaling concern, not a
  correctness one). The fleet store is the future **RFC-0007 (`ratchet`) ratchet
  seam**, but Crucible **ships standalone** (D-17).
- **Rationale:** The content-addressed temporal graph already makes a checkpoint's
  identity independent of where it was computed, so distributing exploration is a
  pure scaling win: any host can reproduce any branch another host found (Claim A),
  while the *assignment* of branches to hosts can be opportunistic and
  nondeterministic without touching reproducibility (Claim B). Separating the two
  claims prevents the common confusion that "distributed" implies "nondeterministic
  results." The shared store is exactly the substrate RFC-0007's incremental cache
  also wants, so it is the marked integration seam (D-17) — but, per D-17, Crucible
  vendors what it needs and ships without waiting on ratchet.
- **Alternatives considered:**
  - *Single-host exploration only.* Rejected: forecloses the fuzzing fan-out [G-6]
    motivates.
  - *Deterministic global work scheduling across the fleet.* Rejected: needlessly
    couples throughput to a global order; Claim B explicitly allows nondeterministic
    distribution because reproduction (Claim A) does not depend on it.
- **Affects:** file 35 ([DCE-*]), `gate:fleet-equivalence`,
  `gate:campaign-continuity`, [PKG-43], [PKG-44], [PKG-45]; references [NG-7], D-17.

### D-29 — Failure triage: content-addressed signature clustering + signature-preserving minimization

- **Status:** Decided
- **Decision:** Failure triage is **content-addressed failure-signature
  clustering** (group failures by a content hash of their failure signature) plus
  **signature-preserving minimization** (shrink a failing configuration while its
  signature is preserved) plus **per-cluster reports**. It is entirely **offline**
  over the recorded event log — **no new execution path**.
- **Rationale:** A continuous, distributed campaign (D-28) finds many failures, most
  of them duplicates; clustering by a content-addressed signature collapses
  duplicates automatically and deterministically (same signature ⇒ same cluster).
  Signature-preserving minimization yields the smallest reproducer that still
  exhibits the bug, which is what a human triager actually needs. Doing it all
  offline over the existing log means triage adds no determinism surface and no new
  execution path — it is a pure fold/derivation over artifacts already produced.
- **Alternatives considered:**
  - *Raw per-failure reports with no clustering.* Rejected: drowns the triager in
    duplicates from a continuous campaign.
  - *Online minimization during exploration.* Rejected: adds an execution path and
    a determinism surface; minimization is an offline derivation over recorded
    failures.
- **Affects:** file 34 ([TRI-*]).

### D-30 — Time-travel and gdb debugging on instantiate + checkpoint-DAG + replay

- **Status:** Decided
- **Decision:** Time-travel and gdb debugging are built on the **existing**
  `instantiate` + checkpoint-DAG + replay machinery: stepping and reverse-stepping
  are positions in, and replays within, the temporal graph. The **non-canonical
  debug branch** (a user mutating state and continuing) is **excluded from the
  replay oracle** and is **not artifact-reproducible** — and it is **distinct from
  the still-forbidden [ADV-33] detach-to-free-running-QEMU**: the debug branch still
  runs under the deterministic scheduler, it is simply not a canonical, replayable
  artifact.
- **Rationale:** Debugging gets time-travel "for free" because the temporal graph
  already realizes any past configuration via `instantiate` (D-8) and reverse-step
  is just replay to an earlier checkpoint. Letting a user mutate-and-continue is
  invaluable for interactive debugging, but such a branch is by definition off the
  canonical decision stream, so it must be explicitly excluded from the replay
  oracle ([INV-2]) — it is a *what-if*, not a reproducible run. Marking it distinct
  from [ADV-33] is essential: the forbidden thing is detaching the guest to a
  free-running, non-scheduler-controlled QEMU (which breaks determinism wholesale);
  the debug branch stays under the deterministic scheduler and merely forfeits
  artifact-reproducibility.
- **Alternatives considered:**
  - *A separate record/replay debugger.* Rejected: duplicates the temporal graph
    and reintroduces a replay-log contract (D-1, [NG-6]); the checkpoint DAG already
    gives reverse-step.
  - *Allowing the debug branch into the replay oracle.* Rejected: a mutate-continue
    branch is not on the canonical decision stream and cannot be a replayable
    artifact without redefining the oracle.
- **Affects:** file 36 ([DBG-*]), [SESS-32], [SESS-33], [CLI-27]; references
  [ADV-33], [INV-2], D-8.
- **Phase-0 S14 outcome:** `checks.crucible.phase0.s14GdbstubFallback` found no
  hermetic gdb client package, no implemented session/CLI `open_gdbstub` path,
  and no known gdbstub single-step mediation hook in the scanned AOS QEMU
  patch/plugin integration surface. D-30 remains the target architecture
  decision, but Phase 0 enables only the conservative policy fallback:
  `fallback_adopted=read_only_attach_crucible_driven_step_until_gdbstub_gate`.
  Live read-only attach neutrality and gdb single-step routing are not claimed
  until the debug surface is implemented and S14 passes without fallback.

---

## Open

These decisions have a working default but are **genuinely unresolved**. Each is
tracked as a spike in [`30-risks-spikes.md`](30-risks-spikes.md); the default
ships and the spike either confirms it or supplies the resolved choice (which then
becomes a new `Decided` entry referencing the one it supersedes).

### D-19 — Architecture matrix beyond x86_64 and aarch64

- **Status:** Open
- **Decision (provisional):** The first determinism contract is established and
  gated for **x86_64**, with **aarch64** as the second target. Whether and which
  further guest architectures (e.g. riscv64) are in scope — and whether each meets
  the entropy-elimination set under TCG `-icount` — is **unresolved**.
- **Rationale:** Each architecture has its own entropy surface (its own
  RNG/timestamp instructions, its own timer/interrupt model, its own TCG
  soft-float behavior, its own KASLR story), so the §4.6 elimination set must be
  re-derived and re-gated per arch. x86_64 first because it is the most common
  guest and the most exercised TCG target; aarch64 second for breadth. Committing
  to a broader matrix now would commit to per-arch work whose cost is not yet
  measured.
- **Alternatives considered:** *Commit to a fixed N-arch matrix up front* —
  rejected: premature; the per-arch elimination cost is unknown until x86_64 and
  aarch64 are green. *x86_64-only forever* — rejected as too narrow given AOS's
  multi-arch posture; aarch64 is at least intended.
- **Affects:** [DET-18] (per-arch entropy set), [DET-20], [G-2]; files 04 (§4.6),
  10. *Spike:* [`30-risks-spikes.md`](30-risks-spikes.md) (arch matrix).

### D-20 — Remote checkpoint-store backend

- **Status:** Open
- **Decision (provisional):** The temporal graph's checkpoint store is **local /
  filesystem-backed** for the first cut, content-addressed so a remote backend is
  a drop-in later. Whether a **remote/shared checkpoint store** (for distributed
  fuzzing fan-out and team-shared reproduction artifacts) is in scope, and which
  backend, is **unresolved** — and is entangled with the gated ratchet
  content-addressed-store integration (D-17).
- **Rationale:** Content addressing ([INV-6]) makes the store's *location*
  orthogonal to correctness, so a local store is correct and sufficient to gate
  the foundation; a remote store is a scaling feature for distributed exploration
  that should not block Phase 1. The backend choice is deliberately deferred
  because it may be satisfied by the shared ratchet substrate once that lands
  (D-17), and choosing a separate backend now risks duplicating that work.
- **Alternatives considered:** *Pick a remote backend now* — rejected: premature
  and possibly duplicative of the ratchet substrate. *Local-only permanently* —
  rejected: forecloses distributed fuzzing fan-out, which [G-6] motivates.
- **Affects:** [INV-6], [G-6], [NG-7]; files 07, and the packaging "ratchet gate".
  *Spike:* [`30-risks-spikes.md`](30-risks-spikes.md) (remote store backend).

### D-21 — Minimum link-latency floor value

- **Status:** Open
- **Decision (provisional):** The conservative CMB lookahead is the minimum
  inbound link latency to a node, so a link latency of *zero* would collapse the
  parallelism window and force lock-step. There is therefore a **minimum
  link-latency floor** below which a configured latency is clamped (or rejected);
  the **exact floor value** (and whether zero-latency links are clamped vs.
  rejected vs. handled by a same-virtual-time tie-break) is **unresolved**.
- **Rationale:** Lookahead *is* the parallelism budget (D-10): the floor trades
  modeling fidelity (how low a latency a scenario may express) against throughput
  (how much safe parallelism the window allows) and against the degenerate
  zero-latency case. The right value depends on measured per-quantum overhead and
  on whether realistic scenarios ever need sub-floor latencies, neither of which
  is known until the scheduler and transport are benchmarked.
- **Alternatives considered:** *No floor (allow zero-latency links)* — rejected:
  zero lookahead forces lock-step and can create same-virtual-time delivery cycles
  that the total order alone may not break cleanly. *A large fixed floor* —
  rejected without data: would needlessly cap fidelity. The value is left to the
  benchmark-driven spike.
- **Affects:** [INV-3], [DET-12], [SCHED-*], [G-9]; files 08, 25. *Spike:*
  [`30-risks-spikes.md`](30-risks-spikes.md) (lookahead floor / zero-latency
  links).

### D-25 — Default `rr_switch_quantum` value

- **Status:** Open
- **Decision (provisional):** The round-robin vCPU-switch quantum (D-22) ships
  with a **provisional fixed integer** value in node-icount. The choice is
  **correctness-neutral** — any fixed quantum is deterministic — so the question is
  purely the *default*: small enough to surface realistic intra-VM races, large
  enough not to crater multi-vCPU throughput. The resolved value is established by
  spike **S13**.
- **Rationale:** The quantum trades the round-robin model's race-surfacing power
  (finer ⇒ more interleavings explored) against throughput (finer ⇒ more
  switch overhead). Since every fixed quantum is deterministic (D-22, [RISK-25]),
  this is a perf/sensitivity tuning question, not a determinism question, and the
  right value depends on measured throughput and race yield — neither known until
  the round-robin scheduler is benchmarked (S13).
- **Alternatives considered:** *A very fine fixed quantum* — rejected without data:
  maximizes race surface but may crater throughput. *A very coarse fixed quantum* —
  rejected without data: cheap but may miss realistic races. The value is left to
  the benchmark-driven spike, with a per-branch explorer override as the fallback.
- **Affects:** [SCHED-45], [PLUG-3], [G-9]; files 08, 22, 25. *Spike:*
  [`30-risks-spikes.md`](30-risks-spikes.md) §30.11c (S13, `rr_switch_quantum`
  granularity vs throughput).
- **Phase-0 S13 outcome:** `checks.crucible.phase0.s13RrSwitchQuantumFallback`
  adopted `rr_switch_quantum=4096` as a modeled-throughput default-only fallback
  because S12 disabled commanded preemption exploration. D-25 remains open until
  S12 passes without fallback and S13 can measure empirical throughput plus
  race-surfacing yield.

---

## Relationship to spikes already in the determinism contract

Two further questions are *already* carried as spikes in the determinism contract
([`04-determinism-contract.md`](04-determinism-contract.md) §4.9) and are recorded
here only as pointers, not as separate `D-n` entries, because they are entropy-set
questions rather than architecture decisions:

- **Snapshot/restore completeness** ([DET-32], E20): whether `loadvm` reproduces
  icount, bias, full TCG/device/timer and plugin time-control state so a restored
  fat checkpoint passes the replay oracle. The unified execution model (D-8) and
  the temporal graph (D-9) *assume* this holds; until verified, snapshot-based
  fast-resume is gated behind the spike.
- **KASLR/ASLR necessity** ([DET-33], E11/E12): whether `nokaslr`/`norandmaps`
  are *required* or merely conservative given fully-seeded boot entropy. The
  default ships with randomization disabled; the spike establishes whether it can
  be re-enabled (which would broaden "any unmodified guest" fidelity under D-6).

These are owned by the determinism contract and tracked in
[`30-risks-spikes.md`](30-risks-spikes.md); they are noted here so the register is
a complete map of what is unsettled.

## Spike Results

These entries record risk-spike outcomes required by
[`30-risks-spikes.md`](30-risks-spikes.md) §30.1. They are not `D-n` design
decisions; they retire, reclassify, or adopt fallbacks for rows in the risk
register.

- **RISK-4 / RISK-5 / T-RISK-1 — S1 single-VM fingerprint**
  - **Status:** PASS; the fatal single-VM deterministic-execution risk is
    retired for the stock Linux diskless proof path.
  - **Check:** `checks.crucible.phase0.s1Fingerprint`.
  - **Result:** `scenario=stock-linux-diskless-initramfs-workload`,
    `boot_medium=initramfs`, `block_devices=0`, `vcpus=1`,
    `cadence=100000000`, `horizon_icount=3200000000`,
    `host_adversary=jitter-load`, `stop_request=plugin-requested-icount-pause`,
    `extended_fingerprint_match=true`,
    `aggregate_icount_stream_match=true`,
    `cadence_fingerprint_match=true`,
    `horizon_fingerprint_match=true`,
    `plugin_exit_fingerprint_compared=true`,
    `paused_migration_state_match=not_asserted`, `samples=32`,
    `horizon_retired=3200000000`,
    `horizon_extended_hash=9d1e61606ac54920`,
    `horizon_register_hash=a732f3acdae34c85`,
    `horizon_ram_hash=110f5442638e18ba`, `horizon_ram_bytes=268967936`,
    `pause_retired=3200000005`, `pause_overshoot=5`,
    `pause_extended_hash=5b766fd1f851292b`,
    `pause_register_hash=d69c6c9e1a874f24`,
    `pause_ram_hash=110f5442638e18ba`,
    `device_event_capture=true`,
    `device_event_scope=io_event_multiset`,
    `device_event_device_name_scope=excluded`,
    `device_event_value_scope=stores_only`,
    `device_state_scope=io_event_multiset`,
    `horizon_device_event_hash=1ba88ef5d7831ee0`,
    `pause_device_event_hash=1ba88ef5d7831ee0`,
    `migration_state_hash_a=not_recorded`,
    `migration_state_hash_b=not_recorded`,
    `migration_state_comparison=diagnostic_not_gated`,
    `migration_state_scope=diagnostic_qemu_migration_stream_at_plugin_pause`,
    `migration_state_retired=3200000005`,
    `migration_normalization=icount_host_timer_offsets_zeroed_by_qemu_patch`,
    `register_read_failures=0`,
    `register_count_assertion=nonempty_single_vcpu`,
    `block_device_assertion=launch_argv_scan`,
    `mismatch_localization=component`, `first_differing_line=none`,
    `first_differing_component=none`, `rr_as_diagnostic=not_used`,
    `det29_phase0_device_state_scope=io_event_multiset`,
    `det29_full_device_cadence_complete=false`, `s1_complete=true`,
    `open_gap=paused_qemu_migration_state_timer_icount_hpet`.
  - **Scope:** validates one stock Linux kernel plus diskless initramfs workload
    launched twice with `-smp 1`, `-accel tcg,thread=single`,
    `-icount shift=0,sleep=off,align=off`, no block devices, fixed RTC, fixed
    seed material through `fw_cfg`, `virtio-rng`, and conservative boot entropy
    controls. The second run adds scheduling jitter/load. The proof compares the
    aggregate instruction stream, one nonempty vCPU register hash, RAM hash, and
    IO-event multiset digest at each cadence point including the requested
    `3200000000` horizon. It also compares the plugin-exit fingerprint at the
    deterministic `3200000005` retired-instruction pause point. Raw QEMU
    migration streams at that pause point are diagnostic-only because repeated
    runs exposed nondeterministic serialized `timer/icount` bias and HPET/local
    timer state after the guest-facing fingerprint had already matched. This
    does not claim the full production DET-29 device-state digest at every
    cadence point; that remains owned by the later QEMU-device fingerprint gates.
    The QEMU RR-TCG icount idle-warp fix is load-bearing for this result.
  - **Fallback:** raw paused migration byte identity is not adopted as the S1
    pass signal; S1 is green for the scoped Phase-0 execution-fingerprint proof
    path.

- **RISK-6 / RISK-7 / T-RISK-2 — S2 block/9p HLT-vs-busy-poll**
  - **Status:** PASS; delayed synchronous virtio-block and virtio-9p reads idle
    in the measured target Linux guest, so idle fast-forward applies to this
    blocking-read path.
  - **Check:** `checks.crucible.phase0.s2HltBusyPoll`.
  - **Result:** `target_guest=stock_linux_initramfs`,
    `qemu_accel=tcg_thread_single`, `icount=shift0_sleep_off_align_off`,
    `workload_block_reads=32`, `workload_9p_reads=32`,
    `block_outstanding_wait_source=qemu_block_read_throttle_iops_20`,
    `ninep_outstanding_wait_source=qemu_9p_read_throttle_iops_20`,
    `idle_threshold_ppm=900000`, `block_idle_fraction_requirement=ge_900000`,
    `block_busy_poll_fraction_requirement=le_100000`,
    `block_idled_operations=32`, `block_busy_polled_operations=0`,
    `block_idle_fraction_ppm=1000000`,
    `block_operations_with_io_events=32`, `block_operations_without_io_events=0`,
    `block_busy_poll_instruction_distribution=empty`,
    `block_hlt_observed=true`, `block_io_events_observed_per_operation=true`,
    `block_idle_threshold_met=true`,
    `ninep_idle_fraction_requirement=ge_900000`,
    `ninep_busy_poll_fraction_requirement=le_100000`,
    `ninep_idled_operations=32`, `ninep_busy_polled_operations=0`,
    `ninep_idle_fraction_ppm=1000000`,
    `ninep_operations_with_io_events=32`, `ninep_operations_without_io_events=0`,
    `ninep_busy_poll_instruction_distribution=empty`,
    `ninep_hlt_observed=true`, `ninep_io_events_observed_per_operation=true`,
    `ninep_idle_threshold_met=true`, `fallback_adopted=false`,
    `correctness_dependency=none_busy_poll_remains_bit_correct`,
    `busy_poll_mitigation_decision=not_needed_for_measured_delayed_sync_read_path`,
    `s2_complete=true`.
  - **Scope:** validates the Phase-0 S2 measurement path for one stock Linux
    kernel plus initramfs under TCG/icount with QEMU-throttled virtio-block and
    QEMU-throttled virtio-9p reads. The throttles create an outstanding device
    completion interval, the guest workload completes all 64 reads and prints
    `TEST_RESULT:PASS`, and the plugin verifies every bracketed operation
    included device I/O events before the idle/busy classification is accepted.
  - **Fallback:** none adopted for the measured delayed synchronous read path;
    the exactness-preserving busy-poll fast-forward of [IO-30] remains the
    specified fallback if a future target path commonly busy-polls.

- **RISK-8 / RISK-9 / T-RISK-4 — S3 savevm/loadvm completeness fallback**
  - **Status:** PASS WITH FALLBACK; the thin/replay checkpoint realization is
    adopted as the Phase-0 default, so unverified fat snapshots are not used.
  - **Check:** `checks.crucible.phase0.s3SavevmLoadvm`.
  - **Result:** `qmp_snapshot_save_available=true`,
    `qmp_snapshot_load_available=true`, `qmp_migrate_available=true`,
    `qmp_migrate_incoming_available=true`,
    `qmp_human_monitor_command_available=true`,
    `qmp_legacy_savevm_loadvm_available=false`, `hmp_savevm_used=false`,
    `restore_transport=snapshot_save_load`,
    `vmstate_node=qcow2_internal_snapshot`, `snapshot_points=1`,
    `snapshot_point_0=diskless_boot_window`,
    `snapshot_icount=100000000`, `suffix_segment_icount=50000000`,
    `suffix_logical_horizon=150000000`,
    `suffix_fingerprint_match=true`,
    `suffix_stream_hash=f6defe3619623dd8`, `register_hash_match=true`,
    `suffix_register_hash=9ceff31179cf3b96`, `ram_hash_match=true`,
    `suffix_ram_hash=4b38bd1adad92f0c`, `suffix_ram_bytes=268967936`,
    `suffix_state_hash=7e48fe1730d53378`,
    `device_event_hash_match=not_measured_in_diskless_scope`,
    `current_vmstate_snapshot_smoke=true`,
    `current_vmstate_snapshot_scope=diskless_single_vcpu_qemu_vmstate`,
    `mid_io_burst_snapshot_covered=false`,
    `plugin_time_control_snapshot_covered=false`,
    `full_fat_checkpoint_complete=false`,
    `crucible_owned_state_roundtrip=true`,
    `ring_snapshot_restore=pass`, `ring_live_hash=a3e895964e3c9a45`,
    `overlay_delta_roundtrip=pass`, `overlay_hash=e1215fa76fa5ab16`,
    `rng_position_roundtrip=pass`, `rng_next=7f0e17493d165353`,
    `thin_checkpoint_default=true`, `fat_snapshot_default=false`,
    `loadvm_branch_enabled=false`,
    `fallback_adopted=thin_replay_until_full_s3`,
    `risk8_status=mitigated_by_fallback_not_retired_for_fat_snapshot`,
    `risk9_status=retired_thin_replay_default`,
    `s3_fallback_adopted=true`.
  - **Scope:** validates only the currently available QMP
    `snapshot-save`/`snapshot-load` path for a diskless single-vCPU VMState
    snapshot and a suffix replay comparison, plus a host-side Crucible-owned
    ring/overlay/RNG round-trip. It deliberately does not claim the full S3 pass
    criterion for a restored fat checkpoint at several snapshot points, a
    mid-I/O burst, device-event state hashing, or plugin time-control state.
  - **Fallback:** adopted. `instantiate` and the temporal graph default to thin
    checkpoint realization by replay from genesis or a verified ancestor; the
    fat-snapshot `loadvm` branch remains disabled until a later S3 rerun proves
    the complete replay-oracle surface. This retires RISK-9 for the default
    realization discipline and mitigates RISK-8 by non-use of unverified fat
    snapshots.

- **RISK-12 / T-RISK-5 — S5 guest virtual-memory payload reads**
  - **Status:** PASS; the virtual pointer+length payload form is retained for
    the future white-box channel, with no physical/pinned fallback adopted.
  - **Check:** `checks.crucible.phase0.s5VirtualMemory`.
  - **Result:** `qemu_plugin_read_memory_vaddr_available=true`,
    `doorbell_surface=phase0_instruction_marker_double`,
    `payload_source=register_triplet_kind_ptr_len`,
    `virtual_address_read_result=pass`, `placements=3`,
    `resident_read=pass`, `page_spanning_read=pass`,
    `paged_mmap_read=pass`, `resident_hash=93a22074ef79eb33`,
    `page_spanning_hash=ecd488b1a020006b`,
    `paged_mmap_hash=98f3acaccd62e603`,
    `marker_icounts=3002401208,3002411158,3002477481`,
    `marker_icounts_reproducible=true`,
    `read_bytes_match_expected=true`, `read_hashes_reproducible=true`,
    `side_effect_free_fingerprint_match=true`,
    `final_state_hash=a44d04105ec7d933`,
    `final_ram_hash=2e8cb41c2c678a33`,
    `final_register_hash=00d6dfa86854f13d`,
    `production_whitebox_channel_implemented=false`,
    `physical_pinned_fallback_adopted=false`, `s5_complete=true`.
  - **Scope:** validates QEMU's plugin virtual-memory read API from a synchronous
    instruction-marker double in one diskless x86_64 Linux guest. The guest
    supplies `(kind, ptr, len)` through registers at the marker; the plugin reads
    resident, page-spanning, and normal anonymous-`mmap` payloads at that marker,
    then compares read-enabled and read-disabled final fingerprints. This does
    not implement the production white-box doorbell, binary decoder, disabled
    inertness behavior, app-random write-back, or white-box on/off gate.
  - **Fallback:** none adopted for the measured virtual-address read path; the
    physical / pinned identity-mapped page remains a specified fallback if a later
    production channel path invalidates this spike.

- **RISK-13 / T-RISK-6 — S6 KASLR/ASLR determinism**
  - **Status:** PASS; KASLR/userspace ASLR are deterministic under the measured
    seeded diskless stock-Linux proof path and may be recorded as a per-image
    capability.
  - **Check:** `checks.crucible.phase0.s6KaslrAslr`.
  - **Result:** `scenario=stock-linux-diskless-initramfs-kaslr-aslr`,
    `boot_medium=initramfs`, `block_devices=0`, `vcpus=1`,
    `cadence=200000000`, `horizon_icount=3400000000`,
    `host_adversary=jitter-load`, `qemu_internal_seed=0x0010c006`,
    `guest_entropy_seed=fw_cfg_and_deterministic_virtio_rng`,
    `control_cmdline_has_nokaslr_norandmaps=true`,
    `randomized_cmdline_has_nokaslr_norandmaps=false`,
    `control_fingerprint_match=true`, `control_bases_identical=true`,
    `control_samples=18`, `randomized_fingerprint_match=true`,
    `randomized_sample_count_match=true`, `randomized_bases_identical=true`,
    `randomized_samples_a=18`, `randomized_samples_b=18`,
    `control_randomize_va_space=0`, `randomized_randomize_va_space=2`,
    `kernel_text_nonzero=true`, `kernel_base_identical=true`,
    `stack_base_identical=true`, `heap_base_identical=true`,
    `brk_base_identical=true`, `mmap_base_identical=true`,
    `vdso_base_identical=true`, `kernel_base_differs_from_control=true`,
    `stack_base_differs_from_control=true`,
    `heap_base_differs_from_control=true`,
    `brk_base_differs_from_control=true`,
    `mmap_base_differs_from_control=true`,
    `vdso_base_differs_from_control=true`,
    `control_kernel_text=ffffffff81000000`,
    `randomized_kernel_text=ffffffffb9600000`,
    `control_stack=00007fffffffd748`,
    `randomized_stack=00007ffe6ae895a8`,
    `control_heap=0000555555559890`,
    `randomized_heap=000055c0ee4c2890`,
    `control_brk=000055555557a000`,
    `randomized_brk=000055c0ee4e3000`,
    `control_mmap=00007ffff7dcd000`,
    `randomized_mmap=00007f9f1b1b8000`,
    `control_vdso=00007ffff7fc6000`,
    `randomized_vdso=00007f9f1b3b1000`,
    `final_extended_hash=e870395413c66341`,
    `final_register_hash=46cc2a780110c1fc`,
    `final_ram_hash=76c52fb94c593648`, `final_ram_bytes=268967936`,
    `register_read_failures=0`, `device_event_capture=false`,
    `block_device_assertion=launch_argv_scan`,
    `first_differing_line=none`, `first_differing_component=none`,
    `randomization_reenabled_capability=true`,
    `default_decision=randomization_may_be_enabled_per_image`,
    `fallback_adopted=none`, `s6_complete=true`.
  - **Scope:** validates the Phase-0 S6 opportunity spike for one stock Linux
    kernel plus diskless initramfs under deterministic QEMU seeding. The control
    keeps `nokaslr norandmaps`; the randomized run removes them, confirms
    userspace ASLR is enabled through `/proc/sys/kernel/randomize_va_space`,
    reads a nonzero kernel text base from `/proc/kallsyms`, samples user address
    bases, and compares two randomized extended fingerprints plus explicit base
    reports under host jitter. The proof uses QMP only to stop at a fixed icount
    after the guest reports PASS; it does not flip the global launch default.
  - **Fallback:** none adopted. Randomization may be enabled only when recorded
    as an image capability; the conservative flags remain valid for images that
    have not passed the same gate.

- **RISK-14 / T-RISK-7 — S7 exact deadline and ceiling**
  - **Status:** PASS WITH FALLBACK; the required exact deadline export is absent
    in the measured QEMU build and the current plugin pause surface overshoots,
    so scheduler fast-forward/lookahead through this path stays disabled until
    the patch-series capability lands.
  - **Check:** `checks.crucible.phase0.s7DeadlineCeiling`.
  - **Result:** `scenario=stock-linux-diskless-initramfs-ceiling-probe`,
    `boot_medium=initramfs`, `block_devices=0`, `vcpus=1`,
    `qemu_internal_seed=0x0010c007`,
    `deadline_symbol=qemu_plugin_clock_deadline_ns`,
    `deadline_api_available=false`,
    `idle_wake_icount_reported=unavailable`,
    `actual_timer_fire_icount=not_measured_missing_deadline_api`,
    `exact_deadline_match=false`, `request_exact_all=true`,
    `zero_overshoot_all=false`, `max_pause_overshoot=9`,
    `fixed_a_target=180000000`, `fixed_a_exit_retired=180000001`,
    `fixed_a_pause_overshoot=1`, `fixed_b_target=180000037`,
    `fixed_b_exit_retired=180000046`, `fixed_b_pause_overshoot=9`,
    `interior_target=180000004`, `interior_exit_retired=180000013`,
    `interior_pause_overshoot=9`, `interior_target_tb_index=2`,
    `interior_target_tb_insns=12`, `interior_target_inside_tb=true`,
    `exact_next_deadline_capability=false`,
    `max_advance_exact_capability=false`,
    `layer1_scheduler_fast_forward_enabled=false`,
    `fallback_adopted=clock_deadline_export_and_tb_split_required`,
    `s7_complete=true`.
  - **Scope:** validates the Phase-0 S7 decision for the current QEMU/plugin
    surface. The probe checks for the exact deadline export as a runtime
    capability and records that it is unavailable, which is enough to reject
    production exact-deadline use in this build. It also runs two fixed ceilings
    and one dynamically selected interior-TB ceiling, proving the plugin can
    request a pause at the requested instruction but the VM-visible stop still
    occurs after that instruction. This does not measure a real timer-fire
    `idle_wake_icount` because the required deadline API is missing.
  - **Fallback:** require the `qemu_plugin_clock_deadline_ns` export and a
    TB-split/max-advance implementation that stops exactly at the authorized
    ceiling before enabling Layer-1 scheduler fast-forward or conservative
    lookahead through this surface.

- **RISK-16 / T-RISK-9 — S9 QEMU build identity and inertness**
  - **Status:** PASS; Phase-2 now ties the active AOS `qemu-crucible` build to a
    manifest-derived build identity, proves the committed patch bytes regenerate
    from the tracked stack, consumes that evidence in `gate:patch-microtests`, and
    keeps the separate `gate:qemu-inert` upstream-vs-patched sim-off proof green.
    The Phase-0 S9 result below remains historical fallback evidence only.
  - **Current checks:** `checks.crucible.phase2.qemuPatchRegeneration`,
    `checks.crucible.phase2.gates.patchMicrotests`, and
    `checks.crucible.phase2.gates.qemuInert`.
  - **Current result:** `qemu_package=qemu-crucible`, `qemu_version=10.0.0`,
    `qemu_source_hash=sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=`,
    `patch_count=27`,
    `patch_series_hash=2ed729cda5e0b78b208a6ef61b7b07af658435a71e50e247e701314c26bd57f8`,
    `patch_branch_ref=crucible/qemu-10.0.0`,
    `patch_branch_bundle_hash=6661ad51927d0e61744e180a2989072da83e9342e6d2f37908bc2dfd20c0dfb1`,
    `patch_branch_head_commit=1ca198288b0ca503b8dd86b459dfe03cd1959e46`,
    `patch_branch_material_hash=6b325a5a18abb07d7d7576012e562aac10eecab8ce3a042d1080102cf20c0e97`,
    `qemu_build_id=3c402016048ce1d4c4e84d4e183b39a409d13cf7dff14f09954d9fb4b2ffd374`,
    `qemu_nix_hash=35aad46df419155f4ce336d66dd4eac329348b333b1d202937ad05a0d94add09`,
    `qemu_configure_flags_hash=716c3de64e42d5fee65c1b0ebb4dc213f282aba1d916820e1896ee36bc0db5f8`,
    `regenerated_patch_bytes_match_committed=true`,
    `apply_clean_regenerated_series=true`, `apply_clean_patch_fuzz=0`,
    `patch_branch_bundle_verified=true`,
    `patch_branch_commit_hashes_match_manifest=true`,
    `qemu_package_patch_phase_generated_from_manifest=true`,
    `artifact_build_id_match=true`, `artifact_validator_rejects_mismatch=true`,
    `artifact_mismatch_regates=true`, and `qemu_version_bump_regate_enforced=true`.
  - **Historical S9 result:** `qemu_package=qemu-crucible`, `qemu_version=9.2.4`,
    `qemu_derivation_path=/nix/store/lf1mn770yyh83j3lif4dmvzjk820grdk-qemu-crucible-9.2.4.drv`,
    `qemu_output_path=/nix/store/dvv5iv1qz2hp6a90i5nffb7ja5avlch5-qemu-crucible-9.2.4`,
    `qemu_build_id=729b568e369aac8b090a2b743ef14f1e8338fcbfa8d6e0412d5ba2dc973a5ba4`,
    `qemu_nix_hash=bbdaae2e7c1a5ac000ae311c840e659db2925b1e43f3af877c54a00f456caa5c`,
    `patch_count=1`,
    `patch_0001_name=<first-carried-patch>`,
    `patch_0001_hash=<sha256>`,
    `patch_series_hash=f2b409e1639b9616d6daa321774131028b6e7ef35185a2d49950ec187aab2653`,
    `plugins_enabled=true`, `patch_apply_list_matches=true`,
    `plugin_exports_present=true`, `rr_switch_quantum_default_zero=true`,
    `non_sim_icount_patch_present=true`, `s1_result_consumed=true`,
    `s1_result_status=PASS`,
    `s1_source=checks.crucible.phase0.s1Fingerprint`,
    `s1_horizon_extended_hash=9d1e61606ac54920`,
    `s1_horizon_register_hash=a732f3acdae34c85`,
    `s1_horizon_ram_hash=110f5442638e18ba`,
    `s1_pause_retired=3200000005`, `s1_pause_overshoot=5`,
    `artifact_build_id_match=true`,
    `changed_build_id=0ef981435eda56587842ef79aa7e665ffc03e7798e6e72a9135cf19b4b5c856e`,
    `artifact_mismatch_regates=true`,
    `changed_build_negative_control=mutated_build_id_material`,
    `full_upstream_inertness_comparison=false`,
    `qemu_inert_gate_status=fallback_pending_upstream_comparison`,
    `fallback_adopted=pin_build_id_and_regate_on_change`,
    `s9_complete=true`.
  - **Current source pin:** T-PATCH-1 advances the carried QEMU source pin to
    `qemu_version=10.0.0` with
    `qemu_source_hash=sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=`,
    enforced by `checks.crucible.phase2.qemuPatchSeries` and consumed by
    `checks.crucible.phase2.qemuPatchRegeneration`.
  - **Scope:** validates the active no-silent-drift decision for the current AOS
    QEMU package. The Phase-2 regeneration gate records the QEMU version/source
    hash, package-file hash, configure flag hash, manifest patch count,
    patch-series hash, tracked-branch bundle hash, tracked-branch material hash,
    and sim capability flags as build-id material; emits a
    reproduction-artifact-shaped JSON carrying `qemu_build_id`; mutates the build
    material as a negative control; and verifies that the artifact re-gates rather
    than reproduces against the changed identity.
  - **Fallback:** retired for the active 10.0.0 package. The historical Phase-0 S9
    fallback remains useful only as provenance for the older 9.2.4 spike.

- **RISK-17 / T-RISK-10 — S10 aarch64 doorbell**
  - **Status:** PASS WITH FALLBACK; aarch64 white-box support is not available in
    the current AOS QEMU/guest-emitter surface, so aarch64 remains black-box-only
    until the aarch64 target and doorbell implementation land.
  - **Check:** `checks.crucible.phase0.s10Aarch64Doorbell`.
  - **Result:** `qemu_package=qemu-crucible`,
    `qemu_target_list=x86_64-softmmu`,
    `qemu_aarch64_softmmu_target=false`,
    `qemu_system_aarch64_available=false`,
    `crucible_guest_workspace_member=false`,
    `production_aarch64_doorbell_trap_implemented=false`,
    `whitebox_on_trap_tested=false`, `whitebox_off_inertness_tested=false`,
    `marker_icount_reproducible=not_tested`,
    `payload_read_result=not_tested`, `aarch64_whitebox_supported=false`,
    `aarch64_blackbox_only_fallback=true`,
    `fallback_adopted=aarch64_black_box_only_until_qemu_target_and_doorbell`,
    `s10_complete=true`.
  - **Scope:** validates the Phase-0 S10 decision for the current repository
    surface. The check proves the packaged QEMU target list is x86_64-only, the
    `qemu-system-aarch64` binary is absent, `crucible-guest` is not a workspace
    member, and the production trace plugin contains no aarch64 white-box
    doorbell trap path. It therefore does not run an aarch64 guest and does not
    prove any `HLT`/`BRK`/`hvc` immediate traps precisely.
  - **Fallback:** ship aarch64 as black-box-only for Crucible until an AOS-built
    aarch64 QEMU target, single-source aarch64 doorbell encoding, production
    plugin trap, and `crucible-guest` emitter exist; rerun S10 before enabling
    aarch64 white-box markers.

- **RISK-10 / RISK-11 / T-RISK-3 — S4 shmem visibility is icount-not-wallclock**
  - **Status:** PASS; the measured §13.9 shared-memory visibility discipline
    makes delivery a function of `delivery_icount` and consumer `current_icount`,
    not producer-store or consumer-poll wall-clock timing.
  - **Check:** `checks.crucible.phase0.s4ShmemVisibility`.
  - **Result:** `model=shmem_scheduler_node_double`,
    `shared_memory=MAP_SHARED`, `ring_ordering=release_acquire_spsc`,
    `source_nodes=2`, `consumer_nodes=1`, `rings=2`,
    `frames_per_source=16`, `total_frames=32`, `delivery_groups=8`,
    `run_x_skew=producer_publish_path`, `run_y_skew=consumer_poll_path`,
    `delivery_rule=delivery_icount_lte_current_icount`,
    `tie_break_key=delivery_icount_src_node_seq`,
    `consumer_ceiling=delivery_icount_minus_1_until_group_present`,
    `producer_skew_ceiling_wait_observed=true`,
    `consumer_skew_early_peek_observed=true`, `arrival_order_differs=true`,
    `publish_order_unique_nonzero=true`, `visibility_vectors_match=true`,
    `visibility_icounts_equal_delivery_icount=true`,
    `injection_order_match=true`,
    `arrival_order_negative_control_failed=true`,
    `late_enqueue_negative_control_failed=true`, `late_delivery_failures=0`,
    `early_delivery_failures=0`, `late_enqueue_failures=0`,
    `fallback_adopted=false`,
    `scope=phase0_shmem_visibility_discipline_not_qemu_device_injection`,
    `s4_complete=true`.
  - **Scope:** validates the Phase-0 S4 transport invariant with forked
    producer/consumer node doubles over a real `MAP_SHARED` region and §13-style
    release/acquire SPSC rings. The run uses two inbound producers so coincident
    deliveries exercise the `(delivery_icount, src_node, seq)` tie-break, and it
    includes negative controls proving arrival-order delivery and late enqueue are
    rejected. This does not claim production QEMU/plugin/device injection is
    implemented; that remains covered by later `gate:layer1-injection` and QEMU
    integration gates.
  - **Fallback:** none adopted for the measured shmem visibility discipline; a
    future production leak must be localized and removed rather than papered over.

- **RISK-15 / T-RISK-8 — TCG-exec coverage overhead**
  - **Status:** PASS; risk retired for the Phase-0 basic-block coverage
    extraction overhead spike in [GHC-7].
  - **Check:** `checks.crucible.phase0.coverageOverhead`.
  - **Result:** `workload_iterations=20000000`,
    `repetitions=3`, `baseline_retired_reference=hook_off_retired_instructions`,
    `coverage_representation=translated_tb_id_set`,
    `hook_off_retired_instructions_avg=2927901535`,
    `coverage_on_retired_instructions_avg=2927880209`,
    `hook_off_tb_execs_avg=620774308`,
    `coverage_on_tb_execs_avg=620768268`,
    `coverage_unique_entries_min=113515`,
    `baseline_ips_avg=376719868.42`, `disabled_ips_avg=378668857.82`,
    `hook_off_ips_avg=383461997.27`, `coverage_on_ips_avg=387955620.92`,
    `disabled_on_vs_baseline_min=0.9920`,
    `coverage_on_vs_baseline_min=1.0211`,
    `coverage_on_vs_hook_off_min=0.9136`,
    `max_retired_instruction_delta=0.000044`,
    `max_tb_exec_delta=0.000023`, `coverage_budget_min=0.7000`.
  - **Scope:** validates one AOS-built QEMU boot-and-workload scenario under the
    S1 deterministic launch controls with no plugin, plugin-loaded/no-callback
    disabled mode, hook-registered count mode, and coverage-on translated-TB-id
    set mode. The no-plugin baseline has no direct instruction counter, so its
    IPS is a fixed-work normalized IPS using the paired hook-count retired
    instruction count after identical workload output and tight hook-vs-coverage
    equal-work assertions. The spike records a Phase-0 overhead result; [PERF-14]
    and the production perf-bench gate still own long-term baselines and
    regression thresholds.
  - **Fallback:** none adopted.

- **RISK-18 / T-RISK-11 — shmem ABI drift fails closed**
  - **Status:** PASS; risk retired for the Phase-0 ABI-drift defense proof in
    [SHM-31].
  - **Check:** `checks.crucible.phase0.abiDrift`.
  - **Result:** `generated_header_diff_detected=1`,
    `c_static_assert_drift_failed=1`,
    `c_static_assert_specific_offset_failed=1`,
    `rust_static_assert_drift_failed=1`,
    `rust_static_assert_specific_offset_failed=1`,
    `golden_vector_drift_mismatch=1`,
    `golden_vector_good_c_matches_rust=1`,
    `golden_vector_good_c_roundtrip=1`,
    `golden_vector_good_rust_roundtrip=1`,
    `golden_vector_drifted_c_matches_generated=1`,
    `golden_vector_drifted_c_mismatch=1`, `good_c_header_compiles=1`,
    `good_rust_layout_compiles=1`, `drifted_field=node_count`,
    `expected_node_count_offset=12`, `drifted_node_count_offset=16`,
    `drifted_header_size=256`.
  - **Scope:** validates a throwaway RegionHeader layout model generated from
    Rust `#[repr(C)]` facts. The generated C header and good Rust layout compile;
    a deliberate size-preserving C-side and Rust-side field-order drift fails the
    specific `node_count` / `queue_capacity` offset static assertions while the
    drifted header remains 256 bytes. The generated-header diff is nonempty, a
    good C encoder matches the Rust golden bytes, good C and Rust views round-trip
    the fixture byte-for-byte, and a drifted C encoder matches the generated
    drifted fixture while differing from the good fixture. The production
    `crucible-shmem` crate and full
    `gate:abi-conformance` still own the permanent generated header, checked-in
    golden corpus, and version-bump workflow.
  - **Fallback:** none adopted.

- **RISK-19 / T-RISK-12 — cross-process futex stress**
  - **Status:** PASS; risk retired for the non-private futex wake/wait idiom in
    [SHM-26].
  - **Check:** `checks.crucible.phase0.futexStress`.
  - **Result:** `iterations=2000000`, `jitter_workers=2`,
    `futex_private=false`, `lost_wakes=0`, `spurious_advances=0`,
    `timed_out_after_wake=0`, `successful_wait_returns=1999954`,
    `minimum_successful_returns=1000000`,
    `successful_spurious_wait_returns=1999999`, `race_returns=30`,
    `futex_wait_calls=1999983`, `futex_wake_calls=2000000`,
    `spurious_wake_calls=2000000`.
  - **Scope:** validates the publish-precondition / read-counter / re-check /
    wait race across separate processes sharing one futex word. The future shmem
    hot path must use the same non-private futex pattern; replacing it with a
    private futex or an auxiliary event primitive alone reopens [RISK-19].
  - **Fallback:** none adopted.

- **RISK-20 / T-RISK-13 — no-leak QEMU lifecycle**
  - **Status:** PASS; risk retired for the modeled QEMU child lifecycle paths in
    [QEMU-29] and [QEMU-31].
  - **Check:** `checks.crucible.phase0.lifecycle`.
  - **Result:** `clean_stop=1`, `control_stop=1`, `guest_crash=1`,
    `plugin_hang=1`, `setup_failure=1`, `host_sigkill=1`, `parent_death=1`,
    `survivors=0`, `reaped=7`.
  - **Scope:** validates lifecycle mechanics against real AOS-built QEMU
    children: QMP quit, SIGTERM stop, SysRq-triggered guest kernel panic under
    `panic=1 -no-reboot`, a hanging QEMU plugin, setup failure, direct SIGKILL,
    and parent death without unwind using `PR_SET_PDEATHSIG=SIGKILL` under a
    subreaper. The future production `QemuNode` wrapper must preserve the same
    die-with-parent and unconditional reap behavior.
  - **Fallback:** none adopted.

- **RISK-21 / T-RISK-14 — search-tree growth stays bounded**
  - **Status:** PASS; risk retired for the Phase-0 synthetic representative
    search-growth model exercising the bounding concepts in the temporal-graph and
    search-strategy design.
  - **Check:** `checks.crucible.phase0.searchTreeGrowth`.
  - **Result:** `scenario=pending-message-fault-temporal-graph`, `replicas=4`,
    `pending_message_slots=14`, `max_faults=4`, `search_depth_limit=4`,
    `raw_depth_limit=5`, `raw_branching_proxy=46812255`,
    `bounded_seen_nodes=351`, `bounded_accepted_nodes=351`,
    `bounded_expanded_nodes=102`, `bounded_raw_edges=1009`,
    `bounded_reduced_edges=823`, `partial_order_skipped_edges=0`,
    `symmetry_skipped_edges=186`, `dedup_hits=35`, `frontier_pruned=687`,
    `frontier_dropped=438`, `frontier_replaced=249`,
    `bounded_max_frontier=64`, `frontier_budget=64`,
    `uncapped_seen_nodes=66349`, `uncapped_expanded_nodes=66349`,
    `uncapped_max_frontier=12512`, `uncapped_frontier_pruned=0`,
    `accepted_coverage_bits=47`, `expanded_coverage_bits=47`,
    `uncapped_expanded_coverage_bits=48`, `estimated_store_bytes=67392`,
    `store_budget_bytes=196608`, `dedup_compression_ratio_x1000=133368247`.
  - **Scope:** validates a deterministic synthetic temporal-graph search model:
    symmetric replica relabeling, source/destination/payload pending messages,
    append/ack/heartbeat delivery effects, crash/drop/partition/heal/timer
    decisions, event-log/RNG/materialized-reference coordinates,
    content-addressed canonical state IDs, symmetry-reduced successor generation,
    coverage-guided priority scoring, and a hard frontier cap compared with an
    uncapped reference. Partial-order reduction is deliberately not load-bearing in
    this spike; the production temporal graph, replay oracle, search engine, and
    scenario corpus still own the permanent implementation.
  - **Fallback:** none adopted.

- **RISK-22 / T-RISK-15 — lookahead budget yields multi-VM parallelism**
  - **Status:** PASS; risk retired for the Phase-0 deterministic scheduler
    cost-model surface.
  - **Check:** `checks.crucible.phase0.multiVmParallelism`.
  - **Result:** `scenario=conservative-lookahead-cost-model`,
    `topology=uniform-full-mesh`, `host_core_parallelism_kind=modeled`,
    `vm_nodes=4`, `host_cores=4`, `simulated_horizon_vt=1048576`,
    `min_link_latency_floor=512`, `sync_cost_units=48`,
    `dispatch_cost_units=2`, `target_parallelism_x1000=3500`,
    `declared_zero_latency_rejected=1`,
    `declared_subfloor_latency_rejected=1`,
    `subfloor_fault_input_latency=128`,
    `subfloor_fault_effective_latency=512`,
    `raised_fault_input_latency=2048`,
    `raised_fault_effective_latency=2048`,
    `unfloored_latency_64_parallelism_x1000=2133`,
    `monotonic_parallelism=1`, `halving_sync_frequency=1`,
    `sample_0_latency=512`, `sample_0_windows=2048`,
    `sample_0_parallelism_x1000=3605`, `sample_1_latency=1024`,
    `sample_1_windows=1024`, `sample_1_parallelism_x1000=3792`,
    `sample_2_latency=2048`, `sample_2_windows=512`,
    `sample_2_parallelism_x1000=3893`, `sample_3_latency=4096`,
    `sample_3_windows=256`, `sample_3_parallelism_x1000=3946`,
    `floor_parallelism_x1000=3605`, `modeled_recommended_latency=1024`,
    `modeled_recommended_parallelism_x1000=3792`,
    `max_latency_parallelism_x1000=3946`,
    `floor_vs_unfloored_subfloor_ratio_x1000=1690`.
  - **Scope:** validates the conservative lookahead cost model before the
    production scheduler exists: link latency is the per-node lookahead budget,
    declared zero/sub-floor base latencies fail, sub-floor latency faults clamp to
    the floor, raised latency faults widen the budget, synchronization frequency
    falls as latency rises, and the modeled floor already clears the four-node
    parallelism target. Real threaded host measurements, perf baselines, and
    critical-path workload corpus coverage still belong to the production
    scheduler and `gate:perf-bench`.
  - **Fallback:** none adopted.

- **RISK-23 / RISK-24 / T-RISK-16 — risk register and Phase-0 checklist guard**
  - **Status:** PASS; the Phase-0 risk-register maintenance rule and foundational
    blocker checklist rule are now enforced by a hermetic doc check.
  - **Check:** `checks.crucible.phase0.riskRegisterGate`.
  - **Result:** `checked_risk_tasks=20`, `retired_decision_entries=20`,
    `phase0_foundational_blockers_open=0`, `unexpected_checked_nonrisk_tasks=0`,
    `phase1_plus_checked_tasks=0`.
  - **Scope:** validates the current RFC state: every checked Phase-0 risk spike
    has a retirement or fallback-adoption record and a decision-register check
    name, all foundational blockers are either passed or fallback-adopted, and no
    non-risk checklist item is marked complete while foundational blockers remain
    open. The full RFC coverage/gate catalog lint remains owned by `T-PLAN-1`;
    this check is the narrower RISK-23/RISK-24 guard.
  - **Fallback:** none adopted.

- **RISK-25 / T-RISK-17 — diskless multi-vCPU RR-TCG fingerprint**
  - **Status:** PASS; risk retired for the diskless no-block-device proof path of
    deterministic multi-vCPU interleaving under single-threaded RR-TCG.
  - **Check:** `checks.crucible.phase0.s11MultiVcpuFingerprint`.
  - **Result:** `boot_medium=initramfs`, `block_devices=0`, `vcpus=4`,
    `rr_switch_quantum=4096`, `cadence=100000000`, `host_adversary=jitter-load`,
    `extended_fingerprint_match=true`, `aggregate_icount_stream_match=true`,
    `horizon_fingerprint_match=true`, `samples=33`,
    `final_extended_hash=16e7a49bfce0eb0f`,
    `final_register_hash=ba71b2992131002d`,
    `final_ram_hash=6f3239f7118a53e2`, `final_ram_bytes=268967936`,
    `register_read_failures=0`,
    `register_count_assertion=nonempty_per_vcpu`,
    `device_event_capture=false`, `block_device_assertion=launch_argv_scan`,
    `mismatch_localization=component`, `first_differing_line=none`,
    `first_differing_component=none`, `fallback=smp1_not_needed`.
  - **Scope:** validates a stock Linux kernel with a diskless initramfs running an
    SMP pthread spinlock workload across four guest vCPUs. The extended samples
    compare the aggregate instruction stream, per-vCPU register hashes, RAM
    hash, RR cursor, RR quantum, and final horizon fingerprint across an
    identical run and a host-jitter run. The check asserts every sampled vCPU
    has a nonempty register descriptor set and zero register-read failures.
    Memory/device-event callbacks are disabled in this diskless proof; full
    device-event hashing remains later §4.6 gate work. The check scans the
    actual launch argv for block-device options before running. The block-backed
    diagnostic path is
    not used as the retirement proof because it exposed a separate
    device-completion timing leak; production device-state hashing and
    block-device determinism remain owned by the later [DET-29] / QEMU-device
    gates.
  - **Fallback:** no `-smp 1` fallback adopted.

- **RISK-26 / T-RISK-18 — S12 `Decision::Preemption`**
  - **Status:** PASS WITH FALLBACK; no known commanded preemption exploration
    surface is available in the current QEMU/plugin implementation, so
    branchable `Decision::Preemption` exploration remains disabled and only the
    default deterministic interleaving is enabled.
  - **Check:** `checks.crucible.phase0.s12PreemptionDecision`.
  - **Result:**
    `preemption_surface_scan_scope=qemu_nix_all_qemu_patches_trace_plugin_crates`,
    `known_preemption_injection_surface_found=false`,
    `preemption_injection_api_available=not_detected`,
    `preemption_patch_present=not_detected`,
    `plugin_preemption_surface_present=not_detected`,
    `vcpu_switch_injection_tested=false`,
    `interrupt_timing_injection_tested=false`,
    `commanded_preemption_choices_tested=0`,
    `commanded_preemption_reproducible=not_tested`,
    `commanded_preemption_discriminating=not_tested`,
    `known_race_manifested_under_one_choice=not_tested`,
    `known_race_absent_under_another_choice=not_tested`,
    `single_vcpu_interrupt_variation_distinct=not_tested`,
    `default_determinism_prereqs_green=true`,
    `default_determinism_prereqs_source=decision_register_s1_s11`,
    `s1_decision_entry_consumed=true`, `s1_result_status=PASS`,
    `s1_horizon_extended_hash=9d1e61606ac54920`,
    `s1_pause_retired=3200000005`, `s11_decision_entry_consumed=true`,
    `s11_result_status=PASS`, `s11_vcpus=4`, `s11_block_devices=0`,
    `s11_rr_switch_quantum=4096`,
    `s11_extended_fingerprint_match=true`,
    `s11_horizon_fingerprint_match=true`,
    `s11_final_extended_hash=16e7a49bfce0eb0f`,
    `decision_preemption_exploration_enabled=false`,
    `fallback_adopted=default_deterministic_interleaving_only_until_preemption_injection`,
    `s12_complete=true`.
  - **Scope:** validates the Phase-0 S12 decision for the current repository
    surface. The check proves the active QEMU patch exports RR/fingerprint
    helpers and finds no known commanded preemption-injection API across the
    scanned QEMU wiring, patch directory, production trace plugin, and Rust
    crates. It requires the recorded green S1 and S11 decision-register entries
    as default-determinism prerequisites. It does not run a forced vCPU-switch or
    interrupt-timing branch and does not prove the known race can be surfaced by
    commanded preemption.
  - **Fallback:** keep `Decision::Preemption` exploration disabled and ship only
    default deterministic interleaving until preemption injection lands in the
    AOS QEMU patch series; rerun S12 before enabling the explorer branch.
    T-EXEC-19 supplies the engine schedule representation for that future branch,
    but does not change this fallback.

- **RISK-27 / T-RISK-19 — S13 `rr_switch_quantum` default**
  - **Status:** PASS WITH FALLBACK; the throughput side of the default-only RR
    quantum choice is modeled, but race yield is unavailable because S12 disabled
    commanded preemption exploration. D-25 remains open.
  - **Check:** `checks.crucible.phase0.s13RrSwitchQuantumFallback`.
  - **Result:** `candidate_quantums=1024,2048,4096,8192,16384`,
    `throughput_metric=modeled_retired_instruction_efficiency_x1000`,
    `throughput_measurement_scope=modeled_rr_switch_overhead_default_only`,
    `target_efficiency_x1000=980`, `sample_0_efficiency_x1000=941`,
    `sample_2_rr_switch_quantum=4096`, `sample_2_efficiency_x1000=984`,
    `coarse_baseline_rr_switch_quantum=16384`,
    `coarse_baseline_efficiency_x1000=996`,
    `selected_vs_coarse_efficiency_x1000=987`,
    `selected_phase0_default_rr_switch_quantum=4096`,
    `selected_default_basis=s11_green_smallest_quantum_above_throughput_floor`,
    `race_yield_tested=false`,
    `race_yield_source=not_available_s12_preemption_explorer_disabled`,
    `s12_decision_entry_consumed=true`,
    `decision_preemption_exploration_enabled=false`,
    `d25_status=open_until_s12_passes_without_fallback`,
    `fallback_adopted=modeled_throughput_default_only_quantum_until_preemption_injection`,
    `s13_complete=true`.
  - **Scope:** validates only the Phase-0 default-only fallback. It does not
    measure S12 race yield, does not claim the final D-25 default is resolved, and
    does not exercise commanded vCPU-switch or interrupt-timing branches.
  - **Fallback:** use `rr_switch_quantum=4096` for default deterministic
    interleaving based on the modeled overhead check until commanded preemption
    injection lands; rerun S12 and S13 before closing D-25 or enabling per-branch
    explorer quantum overrides.

- **RISK-28 / T-RISK-20 — S14 gdbstub attach/step**
  - **Status:** PASS WITH FALLBACK; the live gdbstub attach/step measurement is
    not runnable yet because the current repository has no hermetic gdb client,
    backend `open_gdbstub` implementation, CLI debug command, or AOS QEMU gdbstub
    mediation hook/gate.
  - **Check:** `checks.crucible.phase0.s14GdbstubFallback`.
  - **Result:** `scan_scope=pkgs_emulation_crates_rfc_debug_specs`,
    `hermetic_gdb_client_available=false`,
    `qemu_gdbstub_mediation_scan_scope=aos_qemu_nix_patches_plugin`,
    `known_aos_qemu_gdbstub_step_hook_detected=false`,
    `aos_qemu_gdbstub_mediation_patch_implemented=false`,
    `session_open_gdbstub_implemented=false`,
    `cli_debug_command_implemented=false`,
    `read_only_gdbstub_ops_tested=false`,
    `read_only_fingerprint_neutral=not_tested`,
    `read_only_icount_neutral=not_tested`, `gdb_single_step_tested=false`,
    `gdb_single_step_routed_through_scheduler=not_tested`,
    `gdb_single_step_policy=disabled_until_s14_green`,
    `raw_gdb_single_step_allowed_by_crucible_policy=false`,
    `policy_enforcement_runtime=not_implemented`,
    `default_debug_policy=read_only_attach_crucible_driven_step_reverse_step`,
    `live_gdbstub_attach_gate_status=fallback_pending_debug_surface`,
    `s1_decision_entry_consumed=true`, `s1_result_status=PASS`,
    `s1_horizon_extended_hash=9d1e61606ac54920`,
    `s1_pause_retired=3200000005`,
    `fallback_adopted=read_only_attach_crucible_driven_step_until_gdbstub_gate`,
    `s14_complete=true`.
  - **Scope:** validates only the Phase-0 fallback decision for the current
    source surface. The check proves the debug specs define the conservative
    read-only/Crucible-driven-step posture and that the scanned AOS integration
    files do not currently add a Crucible-owned gdb single-step hook. It does not
    inspect upstream QEMU internals, attach gdb, read registers or memory through
    a live gdbstub, set breakpoints, or prove scheduler-routed single-step.
  - **Fallback:** keep raw gdb single-step disabled by Crucible policy and require
    future debug advancement to use Crucible-driven step/reverse-step until a
    hermetic debug client, backend/CLI gdbstub implementation, and mediation gate
    land; rerun S14 before treating [DBG-1] or [SCHED-46] as satisfied for live
    debugging.

## Implementation checklist

> Decisions are *realized* by the per-area tasks in the files they affect (listed
> under each entry's **Affects**), not by tasks of their own; the authoritative,
> ordered tasks live in [`32-implementation-plan.md`](32-implementation-plan.md).
> This register therefore carries only the tasks for decisions that *themselves*
> need a tracked spike before they can move from **Open** to **Decided**. Each is
> a spike whose home is [`30-risks-spikes.md`](30-risks-spikes.md).

- [ ] **T-D-1** Run the architecture-matrix spike: re-derive and gate the §4.6
  entropy-elimination set for **aarch64** (after x86_64 is green) and assess
  riscv64 feasibility; record the resolved matrix as a new Decided entry
  superseding D-19. — resolves [D-19]; satisfies [DET-18] (per-arch); spec
  [`30-risks-spikes.md`](30-risks-spikes.md), §04.6.
- [ ] **T-D-2** Run the remote-checkpoint-store spike: confirm the local
  content-addressed store's interface is backend-pluggable and decide whether the
  remote backend is satisfied by the gated ratchet substrate (D-17) or a separate
  store; record the resolution superseding D-20. — resolves [D-20]; satisfies
  [INV-6]; spec [`30-risks-spikes.md`](30-risks-spikes.md), §07.
- [ ] **T-D-3** Run the lookahead-floor spike: benchmark per-quantum overhead,
  choose the minimum link-latency floor value, and decide clamp-vs-reject for
  zero-latency links; record the resolution superseding D-21. — resolves [D-21];
  satisfies [DET-12], [G-9]; spec [`30-risks-spikes.md`](30-risks-spikes.md),
  §08, §25.
- [ ] **T-D-4** After S12 passes without fallback, rerun the
  `rr_switch_quantum`-granularity spike (S13): sweep the
  round-robin switch quantum, measure multi-vCPU throughput against the perf budget
  and race-surfacing yield via the S12 explorer, choose the default value, and
  record the resolution superseding D-25 (the per-branch explorer override is the
  fallback). — resolves [D-25]; satisfies [SCHED-45], [G-9]; spec
  [`30-risks-spikes.md`](30-risks-spikes.md), §30.11c, §22, §25.
