# 25 — Performance Targets

This file states Crucible's **performance contract** and — more importantly — the
**cost model that justifies every number in it**. Performance is goal [G-9]; it is
real but explicitly *secondary* to correctness ([G-5], [G-1]). The targets here
are not aspirations divorced from the design: each one is derived from a
mechanism specified elsewhere in this RFC (the icount clock of
[`09-virtual-time-icount.md`](09-virtual-time-icount.md), the conservative-PDES
scheduler of [`08-scheduling.md`](08-scheduling.md), the shared-memory transport
of [`13-shmem-abi.md`](13-shmem-abi.md), the bake-once execution model of
[`05-execution-model.md`](05-execution-model.md), and the copy-on-write temporal
graph of [`07-temporal-graph.md`](07-temporal-graph.md)). Requirement IDs here use
the prefix `PERF`.

The spine of this file is a single claim, defended in §25.1–§25.3 and made
normative in §25.4–§25.10:

> **Exactness and speed are not in tension.** The same quantity — minimum link
> latency — is *both* the determinism bound (no peer can deliver earlier than
> `vt + lookahead`, [SCHED-6]) *and* the parallelism budget (each node may run
> that far independently on its own host core, [SCHED-40]). Tightening one tightens
> the other; loosening one loosens the other. The design never trades exactness for
> speed. It trades *parallelism* for tighter latency, and only when the scenario
> demands sub-millisecond links.

The one true tension — granularity versus parallelism — is named and resolved in
§25.2 and §25.10. Everything else follows from the cost model.

A note on scope, per [NG-5]: Crucible models *virtual* time, not host wall-clock
fidelity. These targets are about how fast a simulation *runs on the host*, never
about how fast the guest "is." A target stated in wall-clock seconds is a property
of the harness, never a guest-visible quantity; nothing in this file may leak host
timing into `S`, `T`, or the schedule ([INV-1], [DET-1]).

---

## 25.1 The cost model

The wall-clock cost of a Crucible run is a function of three quantities, each
owned by a mechanism specified elsewhere. State them precisely, then compose them.

### 25.1.1 The TCG floor

Crucible executes every guest under QEMU TCG ([QEMU-1]), which binary-translates
guest instructions into host instructions and interprets the guest in software.
TCG is the *price of determinism*: it is the only backend in which "advance the
guest to virtual time `T`" has a host-independent meaning (retire exactly the
instructions that fit before `T`, [QEMU-1] rationale). That price is a slowdown
relative to native execution.

> **Cost-model fact 1 (the TCG floor).** A single guest's *busy* execution —
> instructions actually retired — runs at roughly **1/10 to 1/20 of native
> single-threaded speed** on the same host core, for typical integer/control-flow
> workloads, with the exact factor depending on the guest's instruction mix and
> the cost of the plugin's per-translation-block instrumentation
> ([`12-qemu-plugin.md`](12-qemu-plugin.md)). This is the floor: no amount of
> scheduling cleverness makes retired guest instructions cheaper than TCG makes
> them.

The 10–20x range is the modeled planning figure, not a guarantee for an arbitrary
workload; floating-point-heavy guests (soft-float under TCG) sit at the slow end,
and the plugin's coverage hook adds to the constant factor when enabled (§25.5).
The figure is what the *targets below are budgeted against*, and the perf-bench
gate (§25.7) measures the real factor on the AOS reference guest so the planning
figure is continuously validated rather than assumed.

### 25.1.2 Idle is free

A guest spends most of its wall-clock life *idle* — halted in `HLT` waiting for a
timer or an interrupt. Under Crucible, idle virtual time costs **zero**
wall-clock. When a node goes idle, the scheduler fast-forwards its clock to the
exact next wake time (`T_wake`, an exact local event, [SCHED-28]) in one jump: no
busy spin, no host sleep, no instructions retired.

> **Cost-model fact 2 (idle fast-forward).** A span of guest *idle* virtual time
> contributes **0** to wall-clock, regardless of its virtual duration. A 60-second
> idle gap and a 60-millisecond idle gap cost the same: one clock jump. Idle is
> not executed; it is *computed* ([SCHED-28], [QEMU-36] idle path).

This is why a scenario that, on real hardware, would take an hour of mostly-idle
waiting can complete in seconds of host time: only the busy fraction is paid for,
and even that is paid for at the TCG rate, not the wall-clock rate.

### 25.1.3 The composed model

Combine the two facts with the parallelism budget of §25.2. Let a scenario have
`k` VM nodes; let node `i` retire `B_i` *busy* instructions over the whole run;
let `IPS_tcg` be the host's TCG instruction-retire rate (≈ `IPS_native / 10..20`);
let `P` be the realized parallelism (the average number of nodes that run
concurrently on distinct host cores, `1 ≤ P ≤ min(k, cores)`, bounded by the
critical path — §25.2); and let `T_amortized_boot` be the per-scenario share of
boot, which the bake-once model (§25.4) drives toward zero.

> **Cost-model fact 3 (the wall-clock model).**
>
> ```text
>                    sum over nodes i of  B_i           (busy instructions only;
>   wall_clock  ≈   ───────────────────────────   +    idle contributes 0)
>                       IPS_tcg  ×  P
>
>                  +  T_amortized_boot               (→ 0 under bake-once, §25.4)
>                  +  T_sync_overhead                (< a few %, §25.3)
> ```
>
> i.e. **wall-clock ≈ guest busy-time (at the TCG rate) ÷ parallelism, plus
> amortized boot, plus a small bounded sync overhead.** Idle time is absent from
> the numerator because it is fast-forwarded to zero (fact 2). The TCG floor
> (fact 1) sets the rate; parallelism (§25.2) divides the busy work across cores;
> the remaining two terms are driven small by §25.3 and §25.4.

This composed model is the justification for every target that follows. Each `PERF`
requirement below pins one term of this equation to a measurable budget.

- **[PERF-1]** Crucible's performance contract MUST be evaluated against the cost
  model `wall_clock ≈ (Σ busy_i) / (IPS_tcg × P) + T_amortized_boot +
  T_sync_overhead` of §25.1.3, in which idle virtual time contributes zero
  wall-clock ([SCHED-28]) and busy instructions are charged at the TCG rate
  ([QEMU-1]). The perf-bench gate (§25.7) MUST measure each term of this model
  separately so a regression is attributed to a specific term, never to an opaque
  aggregate. *Gate:* `gate:perf-bench`. *Spec:* §25.1; routes [G-9].

- **[PERF-2]** The harness MUST fast-forward every span of idle virtual time to
  the exact next wake icount at zero wall-clock cost (no busy spin, no host
  sleep), so the busy-time numerator of the cost model excludes idle entirely
  ([SCHED-28], [QEMU-36]). A run whose wall-clock scales with *idle* virtual
  duration (rather than with busy instructions) is a performance defect and MUST
  be caught by the idle-compression check of §25.7. *Gate:* `gate:perf-bench`.
  *Spec:* §25.1.2; routes [G-9], references [SCHED-28].

---

## 25.2 Parallelism is the lookahead budget

The single most important performance property of Crucible is that **multi-VM
runs parallelize across host cores**, and the amount of parallelism available is
*exactly the conservative lookahead budget* the scheduler already computes for
determinism. This is not a coincidence; it is the same quantity viewed two ways
([SCHED-41]).

### 25.2.1 The identity: latency is both the bound and the budget

The causal law of the network model ([SCHED-5], §8.3) is: a frame emitted by `A`
at virtual time `T_emit` cannot become visible at `B` before `T_emit + L(A→B)`.
The scheduler turns this into the **lookahead** `lookahead(B) = min inbound link
latency` ([SCHED-6]): `B` may safely advance to `vt(B) + lookahead(B)` without
missing any cross-node dependency, because no peer can produce an earlier event.

Read for *correctness*, lookahead is the determinism bound: a node never runs past
a point a peer could still affect, so the total order ([INV-3]) is exact.

Read for *speed*, the very same lookahead is the parallelism budget: while `B` is
entitled to advance `lookahead(B)` of virtual time without re-synchronizing, every
*other* node is simultaneously entitled to advance its own lookahead — so `k`
nodes can run on `k` host cores concurrently, each retiring instructions inside
its own lookahead window, with no host-side coordination until a window closes
([SCHED-40], [SCHED-41]).

> **The identity.** `lookahead = min link latency` is *both* "the soonest a peer
> can affect me" (the exactness bound) *and* "how far I may run alone on my own
> core" (the parallelism budget). They are the same number. You cannot widen the
> parallelism budget without widening the determinism bound, and vice versa —
> which is exactly why **exactness and speed are not in tension**: improving one
> never costs the other.

### 25.2.2 Approaching Nx, bounded by the critical path

On an `N`-core host running `N` VM nodes with adequate link latency (lookahead
windows large enough that per-window synchronization is amortized to noise,
§25.3), the run approaches **Nx** the throughput of a fully serialized run, because
each node's busy instructions are retired on its own core in parallel. The bound
on this speedup is the scenario's **critical path**: the longest chain of causally
dependent busy work (a request that must reach `A`, be processed, reply to `B`,
be processed, reply to `C`, …) cannot be parallelized away, because each link in
the chain must wait `link_latency` for the previous one. A scenario that is one
long causal chain has critical path ≈ total busy work and realizes `P ≈ 1`
regardless of core count; a scenario of `N` mostly-independent nodes realizes
`P ≈ N`.

This is the standard PDES speedup law, and it is why `P` in the cost model
(§25.1.3) is `min(available_cores, k)` *attenuated by the critical-path fraction*,
not a free `N`.

### 25.2.3 The sub-millisecond-latency parallelism collapse

The minimum link-latency floor ([SCHED-20], §8.7) exists for *both* progress and
parallelism. Its performance meaning is sharp and must be stated plainly:

> **Cost-model fact 4 (the latency/parallelism trade).** Parallelism is
> proportional to the lookahead window. Halving the minimum link latency halves
> every node's lookahead, halves how far each node may run before it must
> re-synchronize, and therefore **roughly halves the realized parallelism** (and
> doubles per-virtual-time synchronization frequency, §25.3). As link latency
> approaches the resolution of a single translation block, the lookahead window
> approaches zero and the linked nodes degrade to **single-translation-block
> lockstep** — the scheduler rendezvouses almost every TB, parallelism collapses
> to `P ≈ 1`, and synchronization overhead dominates ([SCHED-20] rationale).

This is the *granularity-versus-parallelism* tension named in the file header, and
it is the **only** place performance and the scenario's demands genuinely trade
off. The resolution (§25.10) is that the trade is (a) *explicit and
scenario-controlled* — a scenario that declares sub-millisecond links is *asking*
for tight ordering and *accepting* the parallelism cost, never surprised by it;
(b) *never a correctness cost* — a sub-millisecond-latency run is exactly as
deterministic as a high-latency one, only slower ([SCHED-41] "parallelism is a
speed property, never a correctness property"); and (c) *floored* — the minimum
link-latency floor forbids zero/sub-floor links outright ([SCHED-20]), so a
scenario cannot accidentally request single-TB lockstep; it must clear the floor,
and the floor is in the content hash ([SCHED-21]) so the chosen trade is part of
the scenario's identity.

- **[PERF-3]** Crucible MUST exploit the conservative lookahead window as
  host-level parallelism: nodes whose lookahead windows do not constrain each
  other MUST be eligible to run concurrently on distinct host cores up to that
  window ([SCHED-40]), so that a `k`-node run on an `N`-core host approaches `min(k,
  N)`× the throughput of a serialized run, attenuated only by the scenario's
  critical path (§25.2.2). The realized parallelism `P` MUST be a measured output
  of the perf-bench gate. *Gate:* `gate:perf-bench`. *Spec:* §25.2; routes [G-9],
  references [SCHED-40], [SCHED-41].

- **[PERF-4]** The achievable parallelism MUST be understood and reported as the
  lookahead budget: larger minimum link latency permits proportionally larger
  independent advances and thus more concurrency; the minimum link-latency floor
  ([SCHED-20]) is the floor on parallelism. The perf-bench gate MUST include a
  sweep that varies minimum link latency and confirms realized parallelism scales
  with it (down to the floor), validating the latency-is-the-budget identity of
  §25.2.1. *Gate:* `gate:perf-bench`. *Spec:* §25.2.1; routes [G-9], references
  [SCHED-20], [SCHED-21], [SCHED-41].

- **[PERF-5]** The harness MUST NOT improve parallelism by any means that weakens
  exactness: parallelism comes *only* from running independent lookahead windows
  concurrently while RESOLVE/EMIT remain serialized through the single scheduler
  in the total order of §8.6 ([SCHED-40]). A serialized run (`P = 1`) and a
  maximally-parallel run MUST produce bit-identical `S`, `T`, and canonical event
  logs; this is asserted by `gate:e2e-determinism` and re-checked under the
  perf-bench gate's varied-core-count sweep ([HARN-11] varied core counts). *Gate:*
  `gate:e2e-determinism`, `gate:perf-bench`. *Spec:* §25.2; routes [INV-1], [INV-3],
  references [SCHED-40].

- **[PERF-6]** The performance documentation and the perf-bench gate MUST treat
  sub-millisecond link latency as an explicit, scenario-controlled
  parallelism-versus-granularity trade (§25.2.3): a scenario that declares links at
  or near the minimum floor accepts reduced parallelism (toward `P ≈ 1`) in
  exchange for tighter ordering, with **no** change to determinism. The gate MUST
  include a low-latency scenario and confirm it (a) still passes determinism and
  (b) exhibits the predicted parallelism reduction rather than a determinism
  failure. *Gate:* `gate:perf-bench`, `gate:e2e-determinism`. *Spec:* §25.2.3;
  routes [G-9], references [SCHED-20].

---

## 25.3 The synchronization-overhead budget

The third term of the cost model is the cost the harness pays *to be
deterministic*: publishing clocks, computing horizons, setting ceilings, waking
parked nodes, and resolving cross-node events. The architectural decision that
makes this term small is that all hot-path coordination is **shared-memory atomics
plus at most one futex**, never an IPC round-trip ([SHM-1], [QEMU-18]).

### 25.3.1 Why shared memory, not IPC round-trips

An IPC-round-trip transport pays a kernel-mediated request/response on *every*
synchronization event: at sub-millisecond synchronization granularity with several
nodes, the round-trip overhead can consume a large fraction — even the majority —
of wall-clock, and frame-delivery precision is chained to synchronization
frequency (a frame can only land at a barrier). Crucible avoids both by carrying
all per-quantum timing and all frame delivery in a single mapped region
([SHM-1], [SHM-2]): a node reading its ceiling is one acquire load; the scheduler
raising a ceiling is one release store plus an optional wake; a frame's
deliverability is the comparison `delivery_icount <= current_icount` of two
integers ([SHM-33]), with the wall-clock moment of the producer's store
irrelevant. The cost of a synchronization event drops from a microsecond-scale
syscall round-trip to a **tens-of-nanoseconds** atomic memory operation.

> **Cost-model fact 5 (sync is atomics, not syscalls).** A per-quantum
> synchronization event (publish clock, read ceiling, check inbound rings) costs
> **tens of nanoseconds** of atomic memory traffic per node — the cost of a few
> cache-line accesses — not the microseconds of a kernel IPC round-trip. A futex
> wake is paid only when a node actually parks and must be woken, not per quantum
> ([SHM-26], [SHM-27]).

### 25.3.2 The budget

The synchronization overhead is the product of per-event cost (fact 5) and event
frequency (set by the lookahead window, §25.2: tighter windows ⇒ more events). The
contract budgets the *product*:

- **[PERF-7]** The total synchronization / determinism overhead — every cost the
  harness pays that is *not* retiring guest instructions or fast-forwarding idle
  (clock publishes, horizon computation, ceiling stores, futex wakes, RESOLVE/EMIT
  bookkeeping) — MUST be **less than a few percent** (target: **< 5%**, the
  perf-bench warning threshold; **< 10%** the hard-fail threshold) of the run's
  guest busy-execution wall-clock, for scenarios whose minimum link latency is at
  or above the recommended operating point (§25.8). The perf-bench gate MUST
  measure this fraction directly and fail on the hard threshold. *Gate:*
  `gate:perf-bench`. *Spec:* §25.3; routes [G-9].

- **[PERF-8]** All hot-path cross-node synchronization MUST be expressed as
  shared-memory atomics plus at most one futex syscall per park/wake, never an IPC
  round-trip per quantum ([SHM-1], [QEMU-18]); a per-quantum QMP or plugin-IPC
  round-trip on the advance/delivery path is both a determinism defect and a
  performance defect. The perf-bench gate MUST assert zero per-quantum syscalls on
  the advance path beyond the futex park/wake (e.g. by syscall counting over a
  fixed advance workload). *Gate:* `gate:perf-bench`, `gate:layer1-injection`.
  *Spec:* §25.3.1; routes [G-9], references [SHM-1], [SHM-2], [QEMU-18].

- **[PERF-9]** The per-translation-block plugin overhead (the clock publish, the
  ceiling check, the inbound-ring check executed at TB boundaries,
  [`12-qemu-plugin.md`](12-qemu-plugin.md)) MUST be bounded to a small constant
  number of atomic operations and MUST NOT scale with node count on the common
  path (a node checks only its own slot and its own inbound rings, not a global
  structure). The perf-bench gate MUST measure per-TB plugin overhead and confirm
  it is node-count-independent. *Gate:* `gate:perf-bench`. *Spec:* §25.3.1; routes
  [G-9].

### 25.3.3 Rendezvous frequency is a perf knob, never a correctness knob

The only schedule-related tunable is the **rendezvous frequency** ([SCHED-12]):
how often the scheduler brings all nodes to a common virtual time for
assertion-drain and topology swaps. It is purely a performance-and-observation
knob — it cannot change which instruction sees which input ([SCHED-11], [SCHED-13]).
Its *performance* effect is real: a finer rendezvous means more global
bookkeeping; a coarser one means less. Because event delivery is continuous and
exact independent of it ([SCHED-13]), the knob trades observation latency
(assertion-drain granularity) for bookkeeping overhead with **zero** effect on
correctness.

- **[PERF-10]** The rendezvous frequency MUST be a pure performance/observation
  knob ([SCHED-12]): increasing it increases assertion-drain granularity at the
  cost of more global bookkeeping; decreasing it reduces overhead. Two runs at
  different rendezvous frequencies MUST be bit-identical in `S`, `T`, and canonical
  log ([SCHED-12]); the perf-bench gate MUST sweep rendezvous frequency, confirm
  bit-identical results across the sweep, and report the overhead-versus-frequency
  curve so the recommended operating point (§25.8) is data-driven. *Gate:*
  `gate:perf-bench`, `gate:e2e-determinism`. *Spec:* §25.3.3; routes [G-9], [INV-1],
  references [SCHED-11], [SCHED-12], [SCHED-13].

---

## 25.4 Boot amortization: bake once, resume always

A guest cold-boot is the single most expensive operation in the system (seconds of
TCG-rate execution to reach a ready point). The execution model
([`05-execution-model.md`](05-execution-model.md)) is built so that **boot is paid
at most once per `World`, never once per scenario**: `bake(World)` boots each VM
to a deterministic ready point and snapshots it as the content-addressed *genesis*
checkpoint ([EXEC-16], [QEMU-23]); thereafter `start`, `resume`, and `fork` are all
the same `instantiate` call whose base case is *loading* genesis, not booting it
([G-4], [QEMU-27]). The only true cold boot in the entire system lives inside
`bake` ([QEMU-23]).

> **Cost-model fact 6 (boot is amortized to ≈0).** The `T_amortized_boot` term of
> the cost model is `boot_cost / scenarios_sharing_the_World`. Because genesis is
> content-addressed by `World` + determinism pins and shared across every scenario
> and fork with the same `World` ([QEMU-24], [EXEC-18]), running `M` scenarios over
> one baked `World` pays boot *once* and amortizes it across all `M` — driving the
> per-scenario boot share toward zero as `M` grows. A fuzzing campaign of millions
> of scenarios over one `World` pays boot essentially never.

- **[PERF-11]** Crucible MUST NOT cold-boot a guest per scenario: boot MUST occur
  only inside `bake` ([QEMU-23]), the resulting genesis checkpoint MUST be
  content-addressed by `World` + determinism pins and reused across every scenario
  and fork with the same `World` ([QEMU-24], [EXEC-18]), and `start`/`resume`/`fork`
  MUST realize from a snapshot or replay rather than a fresh boot ([QEMU-27]). The
  perf-bench gate MUST assert that the number of cold boots over a campaign of `M`
  scenarios sharing one `World` is independent of `M` (ideally 1 per VM per
  `World`, modulo cache eviction). *Gate:* `gate:perf-bench`. *Spec:* §25.4; routes
  [G-9], [G-4], references [QEMU-23], [QEMU-24].

- **[PERF-12]** Snapshot **restore** (`loadvm` of a content-addressed genesis or
  descendant, [QEMU-25]) MUST be substantially cheaper than the cold boot it
  replaces — the target is **sub-second** restore-to-runnable for the AOS
  reference guest, versus seconds for a cold boot — so that resuming a scenario is
  interactive. The perf-bench gate MUST measure restore-to-runnable latency and
  track it against this target. Where the savevm-completeness spike ([QEMU-21]) has
  not yet certified `loadvm`, the **thin-checkpoint replay** fallback ([QEMU-26])
  is used instead; its cost is the replay term (§25.6) and MUST likewise be
  measured. *Gate:* `gate:perf-bench`, `gate:replay-oracle`. *Spec:* §25.4; routes
  [G-9], references [QEMU-21], [QEMU-25], [QEMU-26].

---

## 25.5 Fuzzing throughput and coverage-extraction overhead

Reproduce-then-explore ([G-6]) means the system's *throughput* — scenarios
explored per unit of host time — is a first-class performance property, because a
coverage-guided fuzzing campaign ([`22-advanced-features.md`](22-advanced-features.md))
lives or dies by it. Throughput is the cost model (§25.1.3) applied to short
scenarios that share a baked `World` (so boot ≈ 0, §25.4) and fork cheaply
(so per-scenario setup ≈ delta, §25.6).

### 25.5.1 The throughput target

A concrete throughput number is only meaningful once a baseline exists on real
hardware, so the contract is stated as **a measured baseline plus a
no-regression ratchet**, not a hardcoded constant:

- **[PERF-13]** The perf-bench gate MUST establish and track a **fuzzing
  throughput baseline** for a representative small scenario, expressed in
  **scenarios per host core per hour** (the natural unit, since the cost model
  parallelizes across cores). Once a baseline is recorded for the AOS reference
  guest on the reference host, the gate MUST flag any regression below a
  configured fraction of the baseline (target: no more than a **10%** throughput
  regression without an accompanying recorded rationale in
  [`31-decision-register.md`](31-decision-register.md)). The headline planning
  target is **on the order of 10^3–10^5 short scenarios per core per hour** for a
  small fork-and-explore scenario over a baked `World` — the wide range reflecting
  that throughput is dominated by per-scenario *busy* instructions, which is
  scenario-dependent; the gate's job is to hold whatever baseline is measured, not
  to assert a universal constant. *Gate:* `gate:perf-bench`. *Spec:* §25.5; routes
  [G-9], [G-6].

### 25.5.2 Coverage extraction must be cheap when on, free when off

Coverage-guided fuzzing harvests basic-block coverage from the plugin's TCG-exec
hook with no guest instrumentation ([`22-advanced-features.md`](22-advanced-features.md),
glossary "Coverage"). A per-executed-block hook is on the hottest possible path
(it fires for every block the guest runs), so its cost is load-bearing for fuzzing
throughput, and its *absence* when disabled must be near-total.

- **[PERF-14]** The TCG-exec coverage hook MUST be **cheap when enabled and
  near-zero when disabled**: when coverage is off, the hook MUST add no measurable
  per-block cost (no callback registered, no branch taken on the hot path —
  ideally compiled/registered out entirely, [`12-qemu-plugin.md`](12-qemu-plugin.md));
  when on, it MUST add only a bounded small constant per executed block (a cheap
  set/bitmap insertion), and MUST NOT allocate or lock on the per-block path. The
  perf-bench gate MUST measure guest IPS with coverage off versus on and assert the
  off-cost is within noise of no-hook and the on-cost is within a configured budget
  (target: coverage-on guest IPS **≥ ~70%** of coverage-off guest IPS for the
  reference guest). *Gate:* `gate:perf-bench`. *Spec:* §25.5.2; routes [G-9], [G-6].

- **[PERF-15]** Coverage extraction MUST NOT perturb the guest instruction stream
  or virtual time ([HARN-7] observation-only): it is a read-only digest of which
  blocks executed, never a modification of `S` or `T`. A coverage configuration
  that changes the fingerprint or the canonical log is a determinism defect, not
  merely a performance one. *Gate:* `gate:single-vm-fingerprint`,
  `gate:perf-bench`. *Spec:* §25.5.2; routes [DET-1], [G-6], references [HARN-7].

### 25.5.3 Distributed exploration: fleet throughput scales near-linearly

A guided/distributed exploration campaign ([`35-distributed-exploration.md`](35-distributed-exploration.md))
spreads the fork-and-explore work of §25.5 across **multiple explorer hosts** that
share one content-addressed store (07, [INV-6]). The single-host throughput unit
of [PERF-13] — scenarios per core per hour — is then a *per-host* contract that
the fleet sums: total parallelism is approximately **`hosts × per-host lookahead
P`**, so aggregate throughput MUST grow near-linearly with explorer-host count
until the shared store's bandwidth saturates (the point at which adding hosts no
longer adds throughput because store I/O — fetching ancestors, publishing new
checkpoints — becomes the bottleneck).

- **[PERF-27]** The fleet's exploration throughput contract — the per-host
  scenarios/core/hour figure of [PERF-13] — MUST scale **near-linearly with
  explorer-host count up to shared-store bandwidth saturation**: aggregate
  throughput ≈ `Σ over hosts of (cores × per-core rate)`, with total parallelism
  ≈ `hosts × per-host lookahead P` (§25.2), until store I/O saturates. The
  perf-bench gate MUST add a **fleet sweep** (1..N explorer hosts) reporting
  aggregate throughput and per-host store-I/O overhead (the distributed analogue
  of the [PERF-3] core-count sweep), and MUST flag a deviation from the
  near-linear-to-saturation curve. This binds `gate:perf-bench` and the new
  `gate:campaign-continuity` (added by 24 per §25.11). *Gate:* `gate:perf-bench`,
  `gate:campaign-continuity`. *Spec:* §25.5.3; routes [G-9], [G-6], references
  [PERF-3], [PERF-13], [`35-distributed-exploration.md`](35-distributed-exploration.md).

### 25.5.4 Continuous coverage: the cumulative-coverage ratchet

A continuous campaign accumulates coverage across many CI runs. Coverage is a
*monotone* quantity by construction — a basic block once exercised stays
exercised in the campaign's accumulated corpus — so a *drop* in cumulative
coverage across CI runs is never legitimate progress; it is a regression (a lost
corpus, a broken seed, a coverage-extraction defect). The contract makes this
monotonicity a gated property, the coverage analogue of the throughput ratchet of
[PERF-13].

- **[PERF-28]** A campaign's **accumulated coverage MUST be monotone
  non-decreasing across cumulative CI runs**: the union of basic blocks (and any
  other tracked coverage signal, §25.5.2) exercised by the campaign's corpus MUST
  never shrink from one cumulative run to the next. The perf-bench gate MUST track
  cumulative coverage versus run count and **flag a regression** when cumulative
  coverage decreases (distinguishing it from a flat run, which is legitimate). A
  legitimate reset (a fresh campaign lineage, e.g. after a QEMU/ABI bump,
  [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md) [PKG-44])
  MUST be an explicit, recorded baseline event in
  [`31-decision-register.md`](31-decision-register.md), never a silent decrease.
  This binds `gate:perf-bench` and the new `gate:campaign-continuity` (added by 24
  per §25.11). *Gate:* `gate:perf-bench`, `gate:campaign-continuity`. *Spec:*
  §25.5.4; routes [G-9], [G-6], references [PERF-13].

---

## 25.6 Snapshot, fork, and replay cost

The temporal graph ([`07-temporal-graph.md`](07-temporal-graph.md)) is
copy-on-write: a checkpoint shares unchanged state (memory pages, device blocks,
log prefixes) with its ancestors, so a fork does not copy the world. This makes
the *exploration* operations — the ones a state-space search or fuzzing campaign
performs millions of times — cost proportional to the *delta*, not to the absolute
state size.

> **Cost-model fact 7 (fork cost ∝ delta).** A fork of a checkpoint costs `O(delta)`
> — the size of the pages/blocks/log entries that diverge from the shared
> ancestor — not `O(total state)`. Forking a 1 GiB-RAM VM to explore a single
> alternative decision touches only the handful of pages that decision changes, so
> the fork is cheap and `N` sibling forks share the ancestor's pages until each
> writes ([07] CoW, [SHM-22] ring snapshot, glossary "Copy-on-write").

- **[PERF-16]** A fork MUST cost proportional to its delta from the shared
  ancestor, not to absolute state size: forking a checkpoint MUST share unchanged
  memory pages, device overlay blocks, and event-log prefixes copy-on-write with
  its ancestor ([07], [QEMU-12] CoW disks), so `N` sibling forks of one ancestor
  consume `O(ancestor + Σ deltas)` storage, not `O(N × ancestor)`. The perf-bench
  gate MUST measure fork cost (time and bytes) as a function of delta size and
  confirm it is independent of absolute state size. *Gate:* `gate:perf-bench`,
  `gate:content-address`. *Spec:* §25.6; routes [G-9], [G-6], references [INV-6].

- **[PERF-17]** Snapshot **capture** cost MUST scale with changed state, not total
  state, on the common path (incremental/CoW capture of what diverged since the
  parent), and snapshot serialization MUST be byte-deterministic for content
  addressing without a cost that dominates the run ([SHM-22] padding-canonicalized
  ring serialization, [07]). The perf-bench gate MUST track snapshot capture and
  restore latency over the checkpoint corpus. *Gate:* `gate:perf-bench`,
  `gate:replay-oracle`. *Spec:* §25.6; routes [G-9], references [SHM-22].

- **[PERF-18]** Where realization uses **replay** rather than `loadvm` (the
  default until the savevm spike is green, [QEMU-21]/[QEMU-26]), the cost MUST be
  bounded by *advancing from the nearest cached ancestor over the missing schedule
  suffix*, not by re-running from genesis: the temporal graph's cached fat/thin
  ancestors ([07]) MUST keep the replay suffix short. The perf-bench gate MUST
  measure replay cost as a function of suffix length and confirm that
  checkpoint density keeps the realized suffix bounded (so resume/bisection stays
  cheap, [HARN-9] binary search relies on cheap resume). *Gate:* `gate:perf-bench`,
  `gate:replay-oracle`. *Spec:* §25.6; routes [G-9], references [QEMU-26], [HARN-9].

---

## 25.7 Measurement and the perf-bench gate

Performance that is not measured regresses silently. Crucible defines a dedicated
**performance benchmark gate** — distinct from the determinism gates ([HARN-1]
catalog) — that measures every term of the cost model and flags regressions. It is
proposed here and is canonical (the gate catalog in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.1 adds
it; see §25.11).

### 25.7.1 What `gate:perf-bench` measures

The gate runs a fixed benchmark corpus (small, hermetic scenarios over the AOS
reference guest, built from source per [G-7]) and records, per the cost-model
terms (§25.1.3):

```text
  perf-bench metrics (one row per benchmark scenario)
  ──────────────────────────────────────────────────────────────────────
  tcg_ips             retired guest instructions / host second   (TCG floor, fact 1)
  idle_compression    wall-clock vs idle virtual duration         (fact 2: must be flat)
  parallelism_P       realized concurrent-node factor             (§25.2)
  sync_overhead_pct   non-execution wall-clock / busy wall-clock  (PERF-7, fact 5)
  per_tb_ns           plugin per-TB overhead, ns                  (PERF-9)
  boot_amortization   cold boots per M-scenario campaign          (PERF-11)
  restore_latency     loadvm/replay to-runnable latency           (PERF-12)
  fuzz_throughput     scenarios / core / hour                     (PERF-13)
  coverage_on_off     guest IPS coverage-on / coverage-off ratio  (PERF-14)
  fork_cost           time + bytes as a function of delta size    (PERF-16)
  replay_cost         replay time as a function of suffix length  (PERF-18)
```

### 25.7.2 The gate's contract

- **[PERF-19]** Crucible MUST define and maintain `gate:perf-bench`: a CI
  benchmark gate that runs a fixed, hermetic benchmark corpus and records the
  metrics of §25.7.1, one row per scenario, attributed to the cost-model term each
  validates (§25.1.3). Unlike a determinism gate ([HARN-2], which is a pure
  pass/fail on byte-identity), the perf-bench gate is a **regression gate**: it
  compares each metric against a stored baseline and **fails on a regression beyond
  a configured threshold** (per-metric, with the headline thresholds of [PERF-7]
  sync-overhead, [PERF-13] throughput, and [PERF-14] coverage-ratio), while
  *recording* absolute numbers for trend tracking. A baseline update MUST be an
  explicit, reviewed change (so a regression cannot be laundered into the
  baseline silently), recorded in
  [`31-decision-register.md`](31-decision-register.md). *Gate:* `gate:perf-bench`.
  *Spec:* §25.7; routes [G-9].

- **[PERF-20]** `gate:perf-bench` MUST be **stable enough to gate on**: it MUST
  pin the host profile it runs on (core count, CPU model class) and report metrics
  in host-independent terms where possible (instructions, instruction-ratios, byte
  counts, syscall counts, parallelism factor) rather than raw wall-clock, so that a
  metric regression reflects a real efficiency loss and not host noise. Where a
  wall-clock metric is unavoidable (restore latency, throughput), the gate MUST use
  a tolerance band sized to the measured host variance and MUST treat a *flaky*
  perf result as a signal to widen the host-independent metric coverage, never as a
  reason to quarantine the metric. The perf-bench gate MUST NOT be confused with or
  substituted for any determinism gate: a determinism property MUST never be
  "covered" by a perf measurement, and vice versa ([HARN-3] layer-gate ownership).
  *Gate:* `gate:perf-bench`. *Spec:* §25.7; routes [G-9], [G-5], references
  [HARN-2], [HARN-3].

- **[PERF-21]** The perf-bench corpus and its baselines MUST be content-addressed
  and versioned alongside the determinism corpus ([HARN-32] golden vectors), so a
  benchmark scenario's identity and its expected baseline travel together and a
  baseline cannot drift out of sync with the scenario it measures. A perf
  regression MUST be reproducible from the recorded benchmark scenario + host
  profile, the same way a determinism failure reproduces from its artifact
  ([HARN-27]). *Gate:* `gate:perf-bench`, `gate:content-address`. *Spec:* §25.7;
  routes [G-9], [INV-6], references [HARN-27].

---

## 25.8 The recommended operating point

The cost model has one externally-chosen input that materially affects
performance: the scenario's minimum link latency (and the related rendezvous
frequency). The contract names a recommended operating point so a scenario author
gets good performance by default without thinking about the trade of §25.2.3.

- **[PERF-22]** Crucible MUST document a **recommended operating point** for
  link latency and rendezvous frequency at which the synchronization overhead
  budget ([PERF-7]) and the parallelism target ([PERF-3]) are both met for a
  typical multi-VM scenario, and MUST default new scenarios toward it. The
  operating point is **data-driven** — derived from the perf-bench sweeps of
  [PERF-4] (latency-vs-parallelism) and [PERF-10] (rendezvous-vs-overhead), not
  guessed — and is the latency at or above which per-window synchronization is
  amortized to noise (the **millisecond-scale** link latency typical of
  distributed-systems testing, comfortably above the minimum floor of [SCHED-20]).
  A scenario that deliberately operates below it (sub-millisecond links) is
  honoring the explicit trade of [PERF-6], not misconfigured. *Gate:*
  `gate:perf-bench`. *Spec:* §25.8; routes [G-9], references [SCHED-20], [PERF-4],
  [PERF-6], [PERF-10].

---

## 25.9 Memory footprint

The shared-memory transport and the CoW temporal graph trade host memory for
speed; the footprint must stay modest enough to run realistic multi-VM scenarios
on a single host.

- **[PERF-23]** The host memory footprint MUST be dominated by (a) each VM's guest
  RAM (unavoidable, set by the `World`) and (b) the shared-memory region's frame
  rings ([`13-shmem-abi.md`](13-shmem-abi.md) §13.3), and the ring storage MUST be
  sized to the configured queue capacity × frame size × directed pairs in use
  (`ring_count`, [SHM-7]), not to a dense `k²` allocation when most pairs carry no
  traffic. The CoW temporal graph ([PERF-16]) MUST keep the incremental cost of an
  additional fork proportional to its delta, so that a broad search's memory grows
  with explored deltas, not with `forks × full-state`. The perf-bench gate MUST
  track peak host RSS over a representative search and confirm it scales with
  guest RAM + active rings + Σ deltas, not with the number of forks. *Gate:*
  `gate:perf-bench`. *Spec:* §25.9; routes [G-9], references [SHM-7], [PERF-16].

---

## 25.10 Tensions, stated honestly

This file's claims are strong; this section states the two tensions plainly and
shows exactly how the design resolves (or does not resolve) each, so the contract
is not read as marketing.

### 25.10.1 Determinism versus speed — *resolved, not traded*

The naive expectation is that determinism is bought with speed: that forcing an
exact instruction-level order across machines must serialize everything and kill
parallelism. **It does not, and the reason is the identity of §25.2.1.** The
quantity that makes ordering exact (lookahead = min link latency: no peer can
deliver earlier) is the *same* quantity that grants parallelism (each node may run
that far alone). The scheduler computes it once and uses it both ways
([SCHED-6], [SCHED-40]). The total order is computed from the event *keys*, not
from which host thread finished first ([SCHED-15], [SCHED-40] "order is
key-derived, not host-timing"), so a fully-parallel run and a fully-serialized run
are bit-identical ([PERF-5]). **Crucible does not sacrifice exactness for speed.**
The cost of determinism is the *TCG floor* (fact 1) — paying to emulate rather
than run natively — and that cost is fixed, paid once per retired instruction,
*orthogonal* to parallelism. Parallelism then divides that fixed cost across cores
(§25.1.3). So determinism costs a constant factor (TCG), not a loss of scaling.

- **[PERF-24]** The performance contract MUST NOT be met by any mechanism that
  weakens determinism: every optimization (idle fast-forward, lookahead
  parallelism, CoW fork, snapshot resume, coverage hook) MUST preserve [INV-1] and
  the determinism gates exactly. The perf-bench gate MUST run *after* and *in
  addition to* the determinism gates, never in place of them; a scenario that is
  faster but not bit-identical is a failure, not a win. Any future optimization
  proposed for speed MUST demonstrate it is determinism-neutral (passes
  `gate:e2e-determinism` and `gate:adversarial-determinism`) before it is accepted.
  *Gate:* `gate:e2e-determinism`, `gate:adversarial-determinism`, `gate:perf-bench`.
  *Spec:* §25.10.1; routes [G-1], [G-5], [G-9], [INV-1].

### 25.10.2 Granularity versus parallelism — *a real trade, made explicit and floored*

This is the one genuine trade (§25.2.3, fact 4): tighter link latency buys tighter
cross-node ordering granularity but costs parallelism, because parallelism *is* the
lookahead window. Crucible does not pretend this trade away. It manages it three
ways: it is **explicit and scenario-owned** (the author chooses link latencies;
the choice is in the content hash, [SCHED-21]); it is **floored** so it can never
silently collapse to single-TB lockstep ([SCHED-20] rejects sub-floor links at
lowering time); and it is **never a correctness trade** — a tight-latency scenario
is exactly as deterministic as a loose one, only slower ([PERF-6], [SCHED-41]). The
design *trades parallelism for tighter latency only when the scenario demands
sub-millisecond links*, and surfaces the cost rather than hiding it.

- **[PERF-25]** The granularity-versus-parallelism trade MUST be explicit,
  floored, and correctness-neutral: the scenario author chooses link latency
  (recorded in the content hash, [SCHED-21]); the minimum floor ([SCHED-20])
  forbids the degenerate single-TB-lockstep case; and a sub-floor-but-above-minimum
  low-latency scenario MUST pass determinism unchanged while exhibiting the
  predicted parallelism reduction ([PERF-6]). The perf-bench gate MUST document and
  measure this trade (the [PERF-4] sweep) so an author can predict the parallelism
  cost of a latency choice before running. *Gate:* `gate:perf-bench`. *Spec:*
  §25.10.2; routes [G-9], references [SCHED-20], [SCHED-21], [SCHED-41], [PERF-4],
  [PERF-6].

---

## 25.11 The canonical perf gate (coordinate with 24)

`gate:perf-bench` is proposed by this file and is **canonical**: it is the named CI
check that enforces this file's contract, exactly as the determinism gates enforce
the determinism contract. Per [HARN-1], every gate referenced in this RFC must
appear in the canonical catalog in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.1
verbatim. This file therefore *requests* that the catalog add `gate:perf-bench`
(layer/phase guarded: **cross-layer, runs after the determinism gates in the phase
plan, Phase ≥ L2**; primary requirement: **G-9**; one-line criterion: *cost-model
metrics meet their baselines; no metric regresses beyond threshold*). It is a
**regression** gate ([PERF-19]), not a byte-identity gate, which is the one way it
differs structurally from every gate already in the catalog.

- **[PERF-26]** `gate:perf-bench` MUST be added to the canonical gate catalog in
  [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.1
  verbatim and wired into the phase plan
  ([`32-implementation-plan.md`](32-implementation-plan.md)) **after** the
  determinism gates of the same phase (performance is gated only once the
  correctness it measures against exists, [G-5]). The doc-lint
  ([`28-engineering-standards.md`](28-engineering-standards.md)) that flags
  referenced-but-undefined gates MUST be satisfied by this addition; until 24's
  catalog lists it, this reference is the source of the request. *Gate:*
  `gate:perf-bench`. *Spec:* §25.11; routes [G-9], references [HARN-1].

---

## 25.12 Realizing host parallelism: the admission rule and the work plan

§25.2 says *where* multi-VM parallelism comes from. This section says *how any
candidate speedup is admitted at all*, and enumerates the specific host-parallel
mechanisms this file commits to building. It exists because "make it faster" is
the one class of change most likely to quietly destroy the property the whole
system is for, and because the design has a single checkable rule that keeps that
from happening.

### 25.12.1 The admission rule: two classes, no third

Determinism requires the *guest-observable* transition sequence to be a pure
function of `(image, cmdline, seed, I, Schedule)` ([DET-3], [INV-1]). It does
**not** require the host to be single-threaded. A host-parallel mechanism is
admissible if and only if it belongs to one of exactly two classes:

- **Class A — outside the observable boundary.** The parallel work produces
  nothing the guest, the execution fingerprint, or the canonical event log can
  observe; or it produces a value that is a pure function of an input stream
  already fixed before the worker starts. A digest over a captured byte range is
  Class A: the bytes cannot change while the worker runs, so the digest cannot
  depend on *when* it runs.
- **Class B — commit pinned to virtual time.** The parallel work *is* observable,
  but the virtual-time coordinate at which it becomes observable is computed
  **before** the work is dispatched, and the requester stalls if it reaches that
  coordinate first. The I/O sub-node contract is already Class B: a completion
  lands at a time that is a pure function of `(request icount, modeled latency,
  per-device RNG draw)` ([IO-3], [IO-21], [IO-24]), which leaves the host free to
  do the underlying work whenever it likes.

There is no third class. "Run it in parallel and it will probably come out the
same" is not an admission argument, and neither is a measured bit-identical
result on one host: Class A and Class B are arguments *about the mechanism*, and
the gates then confirm the argument was true. MTTCG (`thread=multi`) is the
canonical rejected proposal — it is neither Class A (guest memory ordering is
observable) nor Class B (there is no pre-computed commit coordinate; the
interleaving *is* the output), which is why it is forbidden outright ([NG-1],
[DET-23]) rather than merely discouraged.

### 25.12.2 Axis 1 — cross-node execution on host workers (the primary lever)

This is the axis §25.2 already specifies, and the one with the most headroom: `P`
in the cost model is realized here or not at all.

The determinism-critical half is the run set and its ordering — the scheduler
derives the set of nodes whose horizons do not constrain each other, and orders
the resulting advance plans by a **completion-order key** computed from the plans
themselves, so outcomes commit in an order that is a function of the scenario and
never of which host worker finished first — RESOLVE and EMIT stay serialized
through the single scheduler in the total order of §8.6 ([SCHED-40], [INV-3]).
The half that turns that into wall-clock is the runtime: the selected nodes must
actually be advanced on distinct host workers rather than one after another on
the calling thread. Until they are, the run set is a plan that nothing executes
in parallel, and `P ≈ 1` regardless of core count or lookahead.

[PERF-29] closes that gap: dispatch the run set across a pool of
`max_host_workers`, let each worker advance its own node to its own ceiling, and
commit outcomes strictly in completion-order-key order. The worker count is a
host resource, not scenario content — it MUST NOT enter any content hash and MUST
NOT change `S`, `T`, or the canonical log, which is exactly the varied-core-count
identity `gate:adversarial-determinism` already asserts ([HARN-11]).

### 25.12.3 Axis 2 — fingerprint digestion off the vCPU thread

The single-VM execution fingerprint samples at a fixed icount cadence, and each
sample digests writable guest RAM together with serialized non-RAM device state
([DET-3], 24 §4). At the specified cadence that is a full pass over writable
guest RAM every few thousand retired instructions, taken synchronously on the
vCPU thread: the guest does not advance while it runs. For any realistic guest
RAM size this is one of the largest non-TCG costs in the system, and it is pure
Class A work — the digest is a function of bytes, and the bytes at the sample
coordinate are fixed by definition.

[PERF-30] moves it off the vCPU thread: capture the sample under
write-protection or dirty-page tracking so the guest resumes immediately, and
digest the captured image on a worker. The result MUST be byte-identical to the
synchronous digest. That identity is not a hoped-for outcome but the reason the
offload is admissible at all — it is the same pure function, evaluated
elsewhere — and `gate:single-vm-fingerprint` is its proof.

### 25.12.4 Axis 3 — overlapping host device work behind a pinned completion

The I/O contract fixes *when* a completion is delivered ([IO-3]); it does not
require the host work behind that completion to happen at that moment, or
serially. Every device-side cost that is not the completion itself — reading a
backing extent, decompressing, checksumming, serializing a reply — MAY run on a
host pool from the moment the request is observed, provided the completion still
lands at the pre-computed icount and the requester stalls, without moving that
icount, if it arrives first. This is Class B by construction.

[PERF-31] makes the overlap explicit and measurable. The load-bearing assertion
is not that the fast path is fast: it is that the *race outcome is not
observable*. Whether the guest reaches the completion coordinate before the host
finishes the work or after it, the delivered icount MUST be the same, and the
same as a fully synchronous run.

### 25.12.5 Axis 4 — translation-side and replay-side parallelism

Two smaller levers, one of them subtle.

**Ahead-of-time translation.** A translation block is a pure function of the
guest bytes and the translation flags, so generating one on a helper thread is
Class A *in its output*. It is not automatically Class A in its *effect*: block
partitioning interacts with the icount budget and with where per-instruction
plugin callbacks fall, so a change in which blocks exist can move an observable
boundary even when every block is individually correct. This is the one axis
where the class argument does not carry itself, so [PERF-32] requires
fingerprint-neutrality to be *measured* — bit-identical fingerprints with
translation prefetch on and off — before the mechanism may be enabled at all.

**Segment-parallel replay.** Replay and divergence bisection walk serially from a
checkpoint to a target coordinate, at a cost bounded by suffix length
([PERF-18]). Because every checkpoint is a realizable start state, a suffix
spanning `n` checkpoints is `n` independent replays that may run concurrently,
one per worker, and be joined at the checkpoint coordinates. This accelerates the
debug loop — `goto`, reverse-step, bisect ([DBG-14], [DBG-17]) — rather than the
forward run, which is why [PERF-33] keeps it separate from Axis 1.

### 25.12.6 What is deliberately not on the list

Recorded so a later reader does not re-derive these as missed opportunities:

- **Any parallel-vCPU execution inside one node.** Rejected by the admission rule
  (§25.12.1) and by [NG-1]. The only known way to run guest vCPUs on multiple
  host cores *and* keep the interleaving pure is deterministic multiprocessing —
  quantum-scoped memory ownership, or speculative execution rolled back against a
  canonical serial order — which needs conflict detection on every guest memory
  access plus per-quantum rollback of CPU and memory state. That instrumentation
  routinely costs more than the parallelism returns, and it would fight [G-11],
  which makes the round-robin switch point a first-class explorable `Decision`
  rather than an implementation detail to be optimized away.
- **Sampling or thinning the fingerprint to go faster.** The fingerprint cadence
  is determinism evidence, not telemetry. The answer to an expensive digest is
  §25.12.3, not a coarser one.
- **Widening lookahead beyond the modeled minimum link latency.** That is not a
  speedup; it is a different scenario, and the floor is part of the scenario's
  identity ([SCHED-20], [SCHED-21]).

- **[PERF-29]** The QEMU-backed runtime MUST execute the scheduler's concurrent
  run set on distinct host workers — each selected node advanced to its own
  ceiling concurrently, bounded by `max_host_workers` — and MUST commit the
  resulting outcomes in completion-order-key order, never in worker-completion
  order ([SCHED-40], [INV-3]). The worker count MUST NOT appear in any content
  hash and MUST NOT change `S`, `T`, or the canonical event log; a run at one
  worker and a run at `max_host_workers` MUST be bit-identical. The perf-bench
  gate MUST report realized `P` from this path, not from a modeled projection.
  *Gate:* `gate:perf-bench`, `gate:adversarial-determinism`. *Spec:* §25.12.2;
  routes [G-9], references [PERF-3], [PERF-5], [HARN-11].

- **[PERF-30]** Execution-fingerprint digestion MUST NOT hold the vCPU thread for
  the duration of the digest: the sample MUST be captured at its exact icount
  coordinate and digested off the vCPU thread, with the guest free to advance
  once the capture is consistent. The digest value MUST be byte-identical to the
  synchronous computation for every sample, and the offload MUST NOT change the
  sample cadence, the sampled coordinates, or the event boundaries that force a
  sample. *Gate:* `gate:single-vm-fingerprint`, `gate:perf-bench`. *Spec:*
  §25.12.3; routes [G-9], references [DET-3], [PERF-9].

- **[PERF-31]** Device-side host work MAY be dispatched to a host pool when the
  request is observed rather than when the completion is due, provided the
  delivered completion icount remains the pure function of `(request icount,
  modeled latency, per-device RNG draw)` required by [IO-3]. The requester MUST
  stall if it reaches the completion coordinate before the host work finishes,
  and that stall MUST NOT move the delivered icount: a run in which the guest
  wins the race and a run in which the host wins it MUST deliver identical
  icounts and identical canonical logs. *Gate:* `gate:e2e-determinism`,
  `gate:perf-bench`. *Spec:* §25.12.4; routes [G-9], references [IO-3], [IO-21],
  [IO-24].

- **[PERF-32]** Ahead-of-time or concurrent translation-block generation MAY be
  enabled only behind measured fingerprint-neutrality: the perf-bench gate MUST
  demonstrate bit-identical execution fingerprints and canonical logs with the
  mechanism on and off, over a corpus that includes translation-heavy boot, and
  MUST treat any divergence as a blocking failure rather than a tolerance. Absent
  that evidence the mechanism MUST stay off, because block partitioning can move
  observable icount-budget and plugin-callback boundaries even when every block
  is individually correct. *Gate:* `gate:perf-bench`,
  `gate:single-vm-fingerprint`. *Spec:* §25.12.5; routes [G-9], references
  [PERF-24].

- **[PERF-33]** Replay to a target coordinate MUST be parallelizable across
  checkpoint segments: a suffix spanning `n` checkpoints MUST be replayable as
  `n` concurrent segment replays joined at the checkpoint coordinates, yielding
  the same state and canonical log as the equivalent serial replay. The
  divergence-bisect path MUST use it, and the segment count MUST NOT change the
  located divergence coordinate. *Gate:* `gate:replay-oracle`,
  `gate:divergence-bisect`. *Spec:* §25.12.5; routes [G-9], references [PERF-18],
  [DBG-14], [DBG-17].

- **[PERF-34]** Every host-parallel mechanism admitted under this file MUST be
  recorded with its admission class — Class A (outside the observable boundary)
  or Class B (commit pinned to a virtual-time coordinate computed before
  dispatch) — and the gate that proves the class argument (§25.12.1). A proposed
  speedup that fits neither class MUST be rejected regardless of measured
  bit-identity on any particular host, and a mechanism whose class argument is
  later falsified MUST be disabled rather than tolerance-banded. *Gate:*
  `gate:perf-bench`, `gate:e2e-determinism`. *Spec:* §25.12.1; routes [G-9],
  references [PERF-5], [PERF-24].

---

## 25.13 Summary

```text
COST MODEL (25.1)
  wall ≈ (Σ busy_i) / (IPS_tcg × P) + amortized_boot + sync_overhead
    fact 1  TCG floor: busy instructions cost ~10–20× native (the determinism price)
    fact 2  idle fast-forwarded to ZERO wall-clock (60s gap == 60ms gap == one jump)
    fact 3  the composed model; perf-bench pins each term separately

PARALLELISM = LOOKAHEAD BUDGET (25.2)
    the identity: min link latency is BOTH the exactness bound AND the run-alone budget
    N nodes on N cores → ~Nx, bounded by the critical path
    fact 4  sub-ms latency collapses parallelism toward single-TB lockstep (the floor stops it)

SYNC OVERHEAD (25.3)
    fact 5  atomics (tens of ns), not IPC round-trips (µs); futex only on park/wake
    budget: < a few % of guest busy-execution (warn 5%, fail 10%)  [PERF-7]
    rendezvous frequency is a perf knob, never a correctness knob   [PERF-10]

BOOT (25.4)   fact 6  bake once per World; boot amortized → 0 over M scenarios  [PERF-11]
FUZZING (25.5)        baseline + no-regression ratchet; coverage cheap-on/free-off [PERF-13/14]
FORK (25.6)   fact 7  CoW: fork cost ∝ delta, not total state                    [PERF-16]
MEASURE (25.7)        gate:perf-bench — a REGRESSION gate over cost-model metrics [PERF-19]

TENSIONS (25.10)
    determinism vs speed   — RESOLVED: same lookahead serves both; TCG is a flat factor
    granularity vs parallelism — REAL, but explicit + floored + correctness-neutral
    the design NEVER sacrifices exactness for speed; it trades PARALLELISM for tighter
    latency only when a scenario demands sub-ms links — and says so.

HOST PARALLELISM (25.12)
    admission rule: Class A (outside the observable boundary) or Class B (commit
      pinned to a virtual-time coordinate computed BEFORE dispatch). No third class.
    axis 1  run the scheduler's concurrent run set on real host workers  [PERF-29]
    axis 2  fingerprint digestion off the vCPU thread (Class A)          [PERF-30]
    axis 3  device host work overlapped behind a pinned completion (B)   [PERF-31]
    axis 4  AoT translation (proof required) + segment-parallel replay   [PERF-32/33]
    NOT on the list: parallel vCPUs in a node, thinner fingerprints, wider lookahead
```

If the cost model is `busy / (TCG × parallelism) + amortized boot + small sync`,
and parallelism is the lookahead budget that determinism already requires, then
Crucible is fast *because* it is exact, not in spite of it — the same conservative
bound that proves no event arrives too early is the same bound that lets every node
run ahead on its own core.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is performance, tracked by [PLAN-3]. They are
> sequenced **after** the determinism gates of their phase ([G-5]): performance is
> measured only once the correctness it is measured against exists.

Completed by `checks.crucible.phase7.gates.perfBench`,
`checks.fleet.crucible-perf`, and
`checks.crucible.phase0.coverageOverhead`: the perf-bench regression gate runs
the harness cost-model substrate (`crucible-harness`'s `perf` module and the
`gate_perf_bench` test target) over a hermetic reference corpus. It evaluates
the §25.1 cost model `wall_clock ≈ (Σ busy_i) / (IPS_tcg × P)
+ T_amortized_boot + T_sync_overhead` term by term and asserts the structural and
relative properties of the whole T-PERF suite: idle fast-forwards to zero
([PERF-2]); realized parallelism `P` rises with the lookahead budget and with
cores, bounded by the critical path ([PERF-3], [PERF-4]); serial and parallel runs
are bit-identical and a sub-millisecond-latency scenario trades parallelism, never
determinism ([PERF-5], [PERF-6]); the sync-overhead budget (warn 5% / fail 10%),
node-count-independent per-TB overhead, and rendezvous neutrality hold ([PERF-7],
[PERF-9], [PERF-10]); boot amortizes to one cold boot per VM per `World`, restore
is recorded, fork cost is delta-bounded, and replay cost is suffix-bounded
([PERF-11], [PERF-12], [PERF-16], [PERF-18]); coverage is cheap-on/free-off and
observation-only ([PERF-14], [PERF-15]); the throughput and cumulative-coverage
ratchets and the fleet near-linear sweep hold ([PERF-13], [PERF-27], [PERF-28]);
peak RSS scales with active state, not fork count ([PERF-23]); the gate is a
per-metric *regression* gate with content-addressed baselines, pins a host profile
and prefers host-independent metrics, runs after (never instead of) the
determinism gates, and is registered verbatim in the canonical catalog and phase
plan ([PERF-1], [PERF-19]..[PERF-26]). The gate is wired at
`checks.crucible.phase7.gates.perfBench` and gates `gate:e2e-determinism`.

The gate proves the cost model's *structure and relations* against a hermetic,
deterministic substrate. The *absolute numbers measured against the live AOS
reference guest and logical explorer-host fleet*
— the measured TCG IPS floor, the measured multi-VM speedup `P` ([PERF-3]), the
measured restore-to-runnable and checkpoint-corpus capture latencies ([PERF-12],
[PERF-17]), the measured fuzzing-throughput and coverage-IPS baselines ([PERF-13],
[PERF-14]), and the real explorer-host fleet sweep ([PERF-27]) — are discharged by
the real-process fleet check `checks.fleet.crucible-perf`, which rides the
TCG-only hermetic-closure fleet runner (`tests/crucible/_fleet-runner.nix`,
[PKG-15]/[PKG-30]) and times **real host wall-clock around real `crucible` CLI
process executions over the real built closure** ([PKG-1]). Every timed
invocation uses `--backend qemu` and launches the closure-owned patched QEMU and
production plugin under TCG against the AOS-built kernel/root fixture before the
session workload. A sequential/concurrent batch yields throughput and realized
speedup ([PERF-13], [PERF-3]); a save→resume round-trip yields restore latency
([PERF-12]); and the logical-host concurrency sweep records the reference-runner
fleet scaling point ([PERF-27]). `checks.crucible.phase0.coverageOverhead`
separately measures hook-off and coverage-on TCG IPS over three repetitions,
enforces the 70% floor, and preserves retired-instruction/TB counts ([PERF-14]).
The deterministic gate holds the contract's shape and regression ratchets while
the fleet and phase-0 checks supply the live reference-host measurements.

T-PERF-29 is additionally completed by
`checks.crucible.phase7.qemuHostParallel`. That gate boots two production
`QemuNode` backends for a one-worker reference and two more for a two-worker
dispatch, feeds both runs the same scheduler-authored concurrent RUN set, and
commits results by the precomputed completion-order key. It requires exact
equality of state fingerprints, virtual-time outcomes, causal decisions, and
observable events; hashes only that worker-neutral evidence; and reports the
peak overlap and wall time measured around the real owner-thread dispatch. The
perf-bench result imports that live `P` and timing evidence rather than treating
the modeled cost projection as the implementation proof.

T-PERF-30 is additionally completed by
`checks.crucible.phase7.fingerprintDigestOffload`. QEMU captures the exact
length-framed writable-RAM and non-RAM VMState preimages while holding the BQL
and a migration dirty-log owner, preserving any pre-existing owner, then returns
detached immutable allocations. The vCPU callback submits those allocations to
a bounded dedicated worker and publishes reached icount without running their
SHA-256 computations; duplicate callback visits to the same ceiling do not
resubmit the boundary. The production live-QEMU corpus runs with the synchronous
oracle disabled under adversarial host load. A separate acceptance-only run
enables the former synchronous component digests at every boundary and fails
unless all five offloaded samples are byte-identical. The corpus retains the
periodic, frame-delivery, fault-activation, and terminal coordinates at
`4000000, 4000001, 8000000, 8000001, 12000000`. The perf-bench result imports
the Class-A admission, exact-capture, corpus-identity, cadence, coordinate, and
forced-boundary evidence from this real-backend gate.

T-PERF-31 is additionally completed by
`checks.crucible.phase7.deviceHostWorkOverlap`. The live block-device path
observes one `SLOT_BLK_IO` request at a time, computes and publishes its
completion icount before placing the request on a bounded device worker queue,
then performs the backing read/write COMPUTE on that worker. If the guest reaches
the coordinate first, the device-wait path leaves it parked at that exact icount
until the response is ready; host wall time is never added to the modeled
completion. The certifying gate boots the real patched QEMU, production Rust
plugin, AOS kernel, and write workload three times: a fully synchronous
reference, an asynchronous leg that withholds the guest wake until host work
finishes, and an asynchronous leg that delays host work while allowing the guest
to reach its pinned horizon. The `crucible-shmem` virtio-blk launch disables
ioeventfd for that device, the submit callback exits the current TCG reservation,
and the max-advance callback freezes the guest at the request boundary until the
host publishes the pinned deadline. QEMU's queued-advance barrier then remains
armed until the plugin commits the corresponding logical-time offset; an
overlapping waiter retries after that barrier releases rather than making
`-EBUSY` guest-visible. The gate requires every request/completion coordinate
and the unified canonical I/O log bytes to match across all three legs. The
perf-bench result imports the Class-B pin, dispatch, stall, and race evidence
from that live-backend gate.

T-PERF-32 is additionally completed by
`checks.crucible.phase7.translationPrefetchNeutrality`. Patch 0046 adds an
experimental, sim-only TCG helper that is off by default. On a translation miss,
the RR vCPU remains stopped while a separately registered TCG context generates
the requested block on a dedicated host thread; the enabled path reserves its
own code-generation region without changing the normal single-threaded RR
configuration. The certifying gate runs the production QEMU and Rust plugin
twice with the helper disabled and twice with it enabled over the
translation-heavy Linux cold-boot fingerprint corpus. It requires exact equality
of every normalized result line, including the final execution fingerprint,
per-boundary architectural evidence, and canonical boundary-log digest. The
enabled runs additionally prove that the helper started and completed every
request; the certifying run generated and completed 2,163 translation requests.
The gate uses an exact comparison with blocking divergence policy, and the
perf-bench result imports its Class-A admission and neutrality evidence.

T-PERF-33 is additionally completed by
`checks.crucible.phase7.segmentParallelReplay`. The replay coordinator selects
an ordered subset of realizable checkpoints while retaining the original
ancestor, constructs one suffix segment per selected checkpoint, and launches
every segment on its own scoped host worker. Each worker starts from the exact
checkpoint state and returns its end state plus coordinate-tagged canonical-log
entries. The join rejects a worker failure or panic, an out-of-interval or
backwards log coordinate, and any state that does not exactly reproduce the next
checkpoint; successful logs are concatenated in checkpoint-coordinate order,
never host-completion order. The certifying replay-oracle case synchronizes four
workers at a barrier and requires its final state and full canonical log to equal
the one-segment replay from the same ancestor. The divergence-bisect entry point
uses that coordinator for every left/right match probe, repeats the complete
bisection with requested segment counts 1, 2, and 4, and fails if any count moves
the first differing icount. The seeded gate locates icount 17 for all three
counts. The perf-bench result imports the Class-A admission and the state, log,
worker, and coordinate-invariance evidence from `gate:replay-oracle` and
`gate:divergence-bisect`.

T-PERF-34 is completed by the fail-closed register in
`crucible_harness::perf::admission`, enforced by
`checks.crucible.phase7.gates.perfBench`. The register names every mechanism
admitted by §25.12: scheduler host workers and device host-work overlap are Class
B because their observable commit coordinates are fixed before dispatch;
fingerprint digestion, translation prefetch, and checkpoint-segment replay are
Class A because detached work is outside the observable boundary and results
rejoin only at validated canonical coordinates. Every entry carries its concrete
class argument and one or more names from a closed proving-gate catalog. The
validator rejects missing required mechanisms, duplicate or empty identifiers,
empty arguments, missing or duplicate gates, and unknown gate labels. The class
is a two-variant enum, so a proposed third class cannot be represented as an
admission. Negative perf-bench cases remove a required mechanism, clear its
proving gates, and substitute a nonexistent gate; all three are blocking
failures rather than tolerance-banded measurements. The perf result publishes
the complete five-mechanism register and its reject-unclassified policy.

- [x] **T-PERF-1** Implement the cost-model instrumentation: measure and attribute
  wall-clock to busy-instruction execution (TCG IPS), idle fast-forward, sync
  overhead, and amortized boot as separate terms. — satisfies [PERF-1], [PERF-2];
  spec §25.1.
- [x] **T-PERF-2** Implement the idle-compression check: assert wall-clock is flat
  in idle virtual duration (a 60s idle gap costs the same as a 60ms one). —
  satisfies [PERF-2]; spec §25.1.2.
- [x] **T-PERF-3** Implement realized-parallelism measurement (`P`) and the
  multi-VM speedup benchmark (k nodes on N cores → approaches min(k,N)×, attenuated
  by critical path). — satisfies [PERF-3]; spec §25.2.
- [x] **T-PERF-4** Implement the latency sweep: vary minimum link latency and
  confirm realized parallelism scales with it down to the floor (the
  latency-is-the-budget identity). — satisfies [PERF-4]; spec §25.2.1.
- [x] **T-PERF-5** Add the serial-vs-parallel bit-identity cross-check to the perf
  corpus (P=1 and P=max produce identical S/T/canonical log). — satisfies
  [PERF-5]; spec §25.2.
- [x] **T-PERF-6** Add a sub-millisecond-latency scenario and assert it stays
  deterministic while exhibiting the predicted parallelism reduction (the explicit
  trade). — satisfies [PERF-6], [PERF-25]; spec §25.2.3, §25.10.2.
- [x] **T-PERF-7** Implement the sync-overhead budget measurement and the
  warn-5%/fail-10% thresholds against guest busy-execution wall-clock. — satisfies
  [PERF-7]; spec §25.3.
- [x] **T-PERF-8** Implement the no-per-quantum-syscall assertion (syscall count
  over a fixed advance workload is the futex park/wake only; zero IPC round-trips).
  — satisfies [PERF-8]; spec §25.3.1.
- [x] **T-PERF-9** Implement per-TB plugin-overhead measurement and assert it is a
  small constant independent of node count. — satisfies [PERF-9]; spec §25.3.1.
- [x] **T-PERF-10** Implement the rendezvous-frequency sweep: bit-identical across
  the sweep, with the overhead-versus-frequency curve recorded for the operating
  point. — satisfies [PERF-10]; spec §25.3.3.
- [x] **T-PERF-11** Implement the boot-amortization check: cold boots over an
  M-scenario campaign sharing one World is independent of M (≈1 per VM per World).
  — satisfies [PERF-11]; spec §25.4.
- [ ] **T-PERF-12** Implement restore-to-runnable latency measurement (loadvm and
  the replay fallback), tracked against the sub-second target. — satisfies
  [PERF-12]; spec §25.4.
- [ ] **T-PERF-13** Establish the fuzzing-throughput baseline (scenarios/core/hour)
  and the no-regression ratchet. — satisfies [PERF-13]; spec §25.5.1.
- [x] **T-PERF-14** Implement coverage-on-vs-off guest-IPS measurement and assert
  off-cost ≈ no-hook and on-cost within budget (≥ ~70% of off-IPS). — satisfies
  [PERF-14]; spec §25.5.2.
- [x] **T-PERF-15** Assert coverage extraction is observation-only (no fingerprint
  or canonical-log change with coverage on). — satisfies [PERF-15]; spec §25.5.2.
  Completed by `checks.crucible.phase6.basicBlockCoverage`: a production
  loaded-QEMU coverage-on/off run reaches the same exact icount and proves an
  identical execution fingerprint, canonical causal log, and independent
  instruction/register/RR-cursor/writable-RAM/device-I/O trajectory. The
  coverage-on run still publishes live guest blocks through the callback owned
  by T-PLUG-15/T-ADV-10.
- [x] **T-PERF-16** Implement fork-cost measurement (time + bytes vs delta size)
  and confirm independence of absolute state size (CoW). — satisfies [PERF-16];
  spec §25.6.
- [x] **T-PERF-17** Implement snapshot capture/restore latency tracking over the
  checkpoint corpus (incremental capture, byte-deterministic serialization). —
  satisfies [PERF-17]; spec §25.6.
- [x] **T-PERF-18** Implement replay-cost measurement (vs suffix length) and
  confirm checkpoint density keeps the suffix bounded. — satisfies [PERF-18]; spec
  §25.6.
- [x] **T-PERF-19** Implement `gate:perf-bench` as a regression gate over the
  §25.7.1 metric set with stored, reviewed baselines and per-metric thresholds. —
  satisfies [PERF-19]; spec §25.7.
- [x] **T-PERF-20** Make the perf gate gate-able: pin the host profile, prefer
  host-independent metrics, tolerance-band the unavoidable wall-clock ones, and
  keep it strictly separate from the determinism gates. — satisfies [PERF-20];
  spec §25.7.2.
- [x] **T-PERF-21** Content-address and version the perf corpus + baselines
  alongside the determinism golden vectors; make a perf regression reproducible
  from scenario + host profile. — satisfies [PERF-21]; spec §25.7.2.
- [x] **T-PERF-22** Derive and document the recommended operating point (link
  latency + rendezvous frequency) from the [PERF-4]/[PERF-10] sweeps and default
  new scenarios toward it. — satisfies [PERF-22]; spec §25.8.
- [x] **T-PERF-23** Implement peak-RSS tracking over a representative search and
  confirm footprint scales with guest RAM + active rings + Σ deltas, not with fork
  count. — satisfies [PERF-23]; spec §25.9.
- [x] **T-PERF-24** Wire perf-bench to run after (never instead of) the determinism
  gates, and require any speed optimization to demonstrate determinism-neutrality
  before acceptance. — satisfies [PERF-24]; spec §25.10.1.
- [x] **T-PERF-25** Document and measure the granularity-vs-parallelism trade (the
  [PERF-4] sweep) so an author can predict the parallelism cost of a latency
  choice. — satisfies [PERF-25]; spec §25.10.2.
- [x] **T-PERF-26** Add `gate:perf-bench` to the canonical gate catalog (24 §1.1)
  verbatim and wire it into the phase plan after the same-phase determinism gates;
  satisfy the referenced-gate doc-lint. — satisfies [PERF-26]; spec §25.11.
- [ ] **T-PERF-27** Implement the fleet throughput sweep (1..N explorer hosts):
  report aggregate scenarios/core/hour and per-host store-I/O overhead, assert
  near-linear scaling to shared-store-bandwidth saturation (total parallelism ≈
  hosts × per-host P), binding `gate:perf-bench` + `gate:campaign-continuity`. —
  satisfies [PERF-27]; spec §25.5.3; cross-ref
  [`35-distributed-exploration.md`](35-distributed-exploration.md).
- [x] **T-PERF-28** Implement the cumulative-coverage ratchet: track campaign
  coverage vs run count, flag a decrease as a regression (flat is legitimate),
  require an explicit recorded baseline event for a fresh campaign lineage,
  binding `gate:perf-bench` + `gate:campaign-continuity`. — satisfies [PERF-28];
  spec §25.5.4.

The remaining tasks realize the host parallelism of §25.12. They are sequenced
after the whole determinism stack, not merely after their own phase's gates:
each one is a change to *when host work happens*, and the only thing that makes
such a change safe is a determinism suite that already passes and can therefore
falsify it ([PERF-24], [PERF-34]). T-PERF-29 is the primary lever — until the run
set is executed on real workers, `P` is a projection and every other axis is a
constant-factor trim on a serial run.

- [x] **T-PERF-29** Execute the scheduler's concurrent run set on a host worker
  pool: advance each selected node to its own ceiling on its own worker, bounded
  by `max_host_workers`, and commit outcomes strictly in completion-order-key
  order. Assert worker count is absent from every content hash and that
  `max_host_workers = 1` and `= N` are bit-identical in `S`, `T`, and the
  canonical log; report realized `P` measured from this path. — satisfies
  [PERF-29]; spec §25.12.2.
- [x] **T-PERF-30** Move execution-fingerprint digestion off the vCPU thread:
  capture the sample at its exact icount coordinate under write-protection or
  dirty-page tracking, resume the guest, and digest on a worker. Assert
  byte-identical digests versus the synchronous path over the fingerprint corpus,
  and unchanged cadence, coordinates, and forced-sample event boundaries. —
  satisfies [PERF-30]; spec §25.12.3.
- [x] **T-PERF-31** Dispatch device-side host work at request-observation time
  behind the pinned completion icount, with a requester stall that cannot move
  the delivered coordinate. Assert identical completion icounts and canonical
  logs across a forced guest-wins-the-race run, a forced host-wins-the-race run,
  and a fully synchronous run. — satisfies [PERF-31]; spec §25.12.4.
- [x] **T-PERF-32** Add the translation-prefetch neutrality experiment: run the
  perf corpus (including a translation-heavy cold boot) with concurrent
  translation-block generation on and off, and require bit-identical fingerprints
  and canonical logs as the precondition for enabling it; treat any divergence as
  a blocking failure and keep the mechanism off by default until the evidence
  exists. — satisfies [PERF-32]; spec §25.12.5.
- [x] **T-PERF-33** Implement segment-parallel replay: split a replay suffix at
  checkpoint coordinates, replay the segments concurrently, and join them.
  Assert equality with serial replay in state and canonical log, wire it into the
  divergence-bisect path, and assert the located divergence coordinate is
  independent of segment count. — satisfies [PERF-33]; spec §25.12.5.
- [x] **T-PERF-34** Maintain the host-parallelism admission register: each
  admitted mechanism records its class (A or B), the argument for that class, and
  the gate that proves it; the perf-bench gate fails on an admitted mechanism
  with no recorded class or no proving gate. — satisfies [PERF-34]; spec
  §25.12.1.
