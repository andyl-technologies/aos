# 22 — Advanced features: fork, search, coverage, and fuzzing

This file specifies Crucible's **advanced exploration features** — the
capabilities that turn a single deterministic run into a *systematic exploration*
of the schedule and fault space: pause/resume/stop, fork, save/restore,
state-space search, basic-block coverage, coverage-guided fuzzing, and the
self-contained reproduction-and-minimization artifact. Together they are the
realization of [G-6] (reproduce-then-explore): once a failure reproduces
bit-identically from a seed, the space *around* that failure can be walked with a
graph traversal instead of by luck.

Requirement IDs in this file use the prefix `ADV` (see
[`00-conventions.md`](00-conventions.md)). The canonical gates this file is bound
by are defined in [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md):
`gate:replay-oracle`, `gate:e2e-determinism`, `gate:divergence-bisect`,
`gate:content-address`, and `gate:single-vm-fingerprint`. This file is a *pure
consumer* of the layers below it: it introduces **no new state representation**
and **no second execution path**. Every feature here is an operation on the one
content-addressed temporal graph ([`07-temporal-graph.md`](07-temporal-graph.md))
expressed through the one execution model ([`05-execution-model.md`](05-execution-model.md))
and driven by the one session actor ([`20-session-control-plane.md`](20-session-control-plane.md)).
It reads coverage from the plugin's TCG-exec hook
([`12-qemu-plugin.md`](12-qemu-plugin.md) §12.8) recorded as observational
entries in the unified event log ([`19-observability-event-log.md`](19-observability-event-log.md)),
explores parametric `ScenarioFamily` spaces ([`06-spatial-graph.md`](06-spatial-graph.md) §7),
and emits reproduction artifacts ([`06-spatial-graph.md`](06-spatial-graph.md) §7.1,
[`23-cli.md`](23-cli.md)).

The code blocks in this file are illustrative sketches per
[`00-conventions.md`](00-conventions.md): they show intended types and call order
so the spec is concrete, but the authoritative statement is always the prose
requirement. A sketch that disagrees with a requirement is a defect in the sketch.

## 22.1 The dependency order (read this first)

The single most important fact about this file is that **none of its features
exist independently**. They form a strict dependency ladder, and each rung is
built only after the rung below it is *green* — that is, only after its phase
gate ([`00-conventions.md`](00-conventions.md) "Phase gates", [G-5]) passes.
Reading the ladder bottom-up:

```text
  ┌─────────────────────────────────────────────────────────────────────┐
  │ 5. coverage-guided fuzzing       ← samples/mutates schedule+faults    │ ADV §22.7
  │ 4. state-space search            ← enumerates Decisions at frontiers  │ ADV §22.5
  │ 3. coverage feedback             ← black-box TCG basic blocks (12)    │ ADV §22.6
  │ 2. fork                          ← instantiate a non-tip Configuration│ ADV §22.3
  │ 1. complete, ORACLE-VALIDATED save/restore  (07 §6, INV-2)            │ ADV §22.4
  │ 0. exact hermetic determinism    (04, INV-1; the bedrock)            │ — (files 04, 09–13)
  └─────────────────────────────────────────────────────────────────────┘
        each rung is built ONLY after the rung below it passes its gate (G-5)
```

The order is non-negotiable and load-bearing:

1. **Exact determinism first.** Fork, search, and fuzzing all *replay* schedules
   and *compare* runs. If a single VM is not bit-identical for a fixed
   `(image, cmdline, seed, injected inputs)` ([DET-3], `gate:single-vm-fingerprint`),
   then "the same fork twice" disagrees and every feature above is unreliable.
   Determinism is the bedrock; nothing is built before it
   (`gate:layer0-determinism`, `gate:e2e-determinism`).
2. **Complete, oracle-validated save/restore second.** A snapshot that silently
   drops a piece of device or scheduler state produces a *wrong* resume — and a
   wrong resume poisons every fork and every search node descended from it. The
   replay oracle ([INV-2], [`07-temporal-graph.md`](07-temporal-graph.md) §6,
   `gate:replay-oracle`) makes save/restore *self-checking*: a fat checkpoint that
   does not hash-equal its replay-from-ancestor derivation is rejected. Save/restore
   is built on determinism and is itself gated before fork.
3. **Fork third.** A fork is `instantiate` of a non-tip `Configuration`
   ([`05-execution-model.md`](05-execution-model.md) §6) — i.e. branching the
   temporal graph at a checkpoint. It is correct *because* save/restore is
   oracle-validated and determinism is exact; the fork's correctness is the same
   `gate:replay-oracle` check, not a new one.
4. **State-space search fourth.** Search is systematic fork: enumerate the
   `Decision`s available at a frontier checkpoint, `step` each to a child, and
   explore. It needs fork to be correct and the content-addressed DAG to dedup
   (07 §1, §9), so it is built on fork.
5. **Coverage-guided fuzzing last.** Fuzzing biases search/sampling by a coverage
   signal. It needs the coverage feed (built on the determinism-preserving plugin
   hook, §22.6) *and* search/fork beneath it, so it sits at the top of the ladder.

This is *why* such features were historically unreliable: they were grown
reactively on top of a *weaker* determinism contract (same delivered-message
sequence, not the same instruction stream) and an *unvalidated* snapshot path, so
a fork or a resume could silently diverge and no gate would catch it. Crucible
inverts that: each rung has a gate, and a higher rung's tasks are sequenced after
the lower rung's gate is green ([G-5], [PLAN-4]).

- **[ADV-1]** The advanced features MUST be implemented in the dependency order
  *exact determinism → complete, oracle-validated save/restore → fork →
  state-space search → coverage-guided fuzzing*. A feature MUST NOT be built (its
  tasks MUST NOT be sequenced) before the layer below it has passed its phase gate
  ([G-5], [PLAN-4]): determinism (`gate:single-vm-fingerprint`,
  `gate:e2e-determinism`) before save/restore; save/restore (`gate:replay-oracle`)
  before fork; fork before search; coverage (§22.6) and search before fuzzing.
  *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:* §22.1; cross-ref
  [G-5], [PLAN-4].

- **[ADV-2]** Every feature in this file MUST be expressed purely as operations
  on the one content-addressed temporal graph (07) via `instantiate`/`step` (05),
  driven by the session actor (20). No feature MAY introduce a state
  representation outside `(ScenarioDef, Schedule)` (05 [EXEC-25]), a checkpoint
  store outside the `DagStore` (07 §7), or a second execution path distinct from
  `instantiate` (05 [EXEC-14]). *Gate:* `gate:replay-oracle`,
  `gate:content-address`. *Spec:* §22.1; cross-ref 05 §9, 07 §10.

- **[ADV-3]** No feature in this file MAY weaken the determinism contract of
  file 04 to make exploration tractable: a feature that cannot be made
  bit-deterministic (e.g. a sampling step that reads host entropy) MUST route its
  nondeterminism through the seeded decision source and record it as a `Decision`
  (05 §3, [INV-10]), never read host wall-clock or thread RNG on a path that
  influences `State`. *Gate:* `gate:harness-lint`, `gate:e2e-determinism`. *Spec:*
  §22.1; routes [INV-1], [INV-9], [INV-10].

## 22.2 Pause, resume, stop: responsive control at quantum boundaries

The three lifecycle operations are owned by the session actor (20); this file
states only how the advanced features rely on them. They are responsive — a
`pause` lands within a bounded number of quanta ([SESS-3]), never "whenever the
run happens to stop" — *because* the session is an actor that services control
commands queued at **quantum boundaries** and yields between quanta
([`20-session-control-plane.md`](20-session-control-plane.md) §1, §3, [INV-8]).
There is no engine-wide lock to wait on, so a search driver or a fuzzer can pause
a long-running exploration branch and fork it immediately.

- **pause** moves `Running → Paused(UserRequested)` at the next boundary check
  ([SESS-14]); it changes only whether the loop steps, not scheduler-owned state,
  so it is observation-class and never enters the schedule ([SESS-22]).
- **resume** is `Continue`: `Paused → Running` ([SESS-10]); it continues appending
  decisions to the same configuration. Resume+continue is bit-identical to an
  uninterrupted run because scheduler and RNG state live inside the configuration
  (05 [EXEC-13]).
- **stop** terminates the run cleanly, shutting the scheduler and backend down and
  moving to `Stopped(outcome)` ([SESS-14]). A stopped session is still forkable
  from its final checkpoint ([SESS-19], §2.1 of file 20).

- **[ADV-4]** The advanced features MUST drive pause, resume (`continue`), and
  stop exclusively as session commands (20 §4); they MUST NOT manipulate the
  engine or scheduler directly. A pause issued by a search/fuzz driver MUST take
  effect within the bounded quantum latency of [SESS-3], and resume+continue MUST
  be bit-identical to an uninterrupted run (05 [EXEC-13]). *Gate:*
  `gate:control-responsive`, `gate:replay-oracle`. *Spec:* §22.2; cross-ref 20 §3,
  [SESS-3], [SESS-14].

- **[ADV-5]** Pause and stop MUST be observation-class with respect to the
  canonical run: pausing, resuming, or stopping an exploration branch MUST NOT
  change its canonical event log or its schedule (20 [SESS-22]). An exploration
  that pauses a branch a thousand times to fork it MUST produce the identical
  causal subsequence (19 [OBS-24]) to one that ran it straight through. *Gate:*
  `gate:e2e-determinism`. *Spec:* §22.2; cross-ref 19 [OBS-22], [OBS-24].

## 22.3 Fork: branching the temporal graph at a checkpoint

A **fork** branches the temporal graph (07) at a checkpoint: it takes an existing
checkpoint — a recorded `Configuration` somewhere in the DAG, not necessarily the
tip — and continues from it by appending *different* `Decision`s than the original
run took. In execution-model terms, a fork is exactly `instantiate` of a **non-tip
`Configuration`** (a prefix `(def, schedule[0..k])`, 05 §6) followed by `step` with
divergent decisions. There is no `fork()` distinct from `start()`/`resume()`: all
three are one `instantiate`, differing only in which configuration is the argument
(05 [EXEC-14], §5 "start ≡ resume ≡ fork").

```text
  parent run:   genesis ──d0──► c1 ──d1──► c2 ──d2──► c3 (tip)
                                  │
                                  │ fork at c1 (a NON-TIP checkpoint, 05 §6)
                                  ▼
  child branch: genesis ──d0──► c1 ──d1'─► c2' ──d2'─► ...   (different decisions)

  fork(c1)  =  instantiate( (def, schedule[0..1]) )   then  step(..) with d1' ≠ d1
            =  loadvm c1's fat snapshot  (07 §4)  — or replay-from-ancestor if thin
  CoW-shared: c2' stores only its delta from c1 (07 §5); the parent is untouched.
```

The fork's correctness is *inherited*, not re-proven: realizing `c1` is the same
`instantiate` whose every branch is content-equal by the replay oracle
(05 [EXEC-17], [INV-2]); the child shares the parent's checkpoints copy-on-write in
the `DagStore` (07 §5), and CoW is copy-on-*write*, so mutating the child cannot
affect the parent (20 [SESS-19]). A forked branch is an independent session actor
with its own mailbox and lifecycle (20 [SESS-19]).

- **[ADV-6]** A fork MUST be `instantiate` of a non-tip `Configuration` — a
  prefix `(def, schedule[0..k])` for `k ≤ len` (05 §6) — followed by `step` (05
  §3) with `Decision`s that differ from the parent's. The fork point MAY be any
  checkpoint in the temporal graph: a tip, a savepoint, or an interior node (07
  §2). There MUST NOT be a fork realization path distinct from
  `start`/`resume`/`instantiate` (05 [EXEC-14], 20 [SESS-11], [SESS-18]). *Gate:*
  `gate:replay-oracle`. *Spec:* §22.3; cross-ref 05 §5/§6, 07 §10, 20 §7.

- **[ADV-7]** A fork MUST be copy-on-write shared with its parent in the
  `DagStore` (07 §5): the child checkpoint stores only its delta from the fork
  point (dirty VM pages, dirty overlay pages, its schedule delta, its appended log
  segment, 07 [TEMP-15]), and unchanged state resolves by reference up the parent
  chain. The marginal cost of a fork MUST be proportional to its delta, not to the
  full state size (07 [TEMP-17]). Mutating the child MUST NOT affect the parent
  (copy-on-*write*, 20 [SESS-19]). *Gate:* `gate:content-address`. *Spec:* §22.3;
  cross-ref 07 §5.

- **[ADV-8]** Every fork MUST be validated by the replay oracle (07 §6, [INV-2]):
  the realized state of a forked checkpoint MUST be content-equal whether reached
  by `loadvm` of a fat snapshot or by replay-from-ancestor (05 [EXEC-17]). A fork
  whose realization fails the oracle MUST be localized by divergence bisection (24,
  [INV-10]), never silently repaired (05 [EXEC-24], 07 [TEMP-19]). The fork's
  correctness MUST be the *same* `gate:replay-oracle` check as save/restore — fork
  introduces no new correctness obligation beyond it. *Gate:* `gate:replay-oracle`,
  `gate:divergence-bisect`. *Spec:* §22.3; cross-ref 07 §6, 05 §8.

- **[ADV-9]** A forked branch MUST be an independent session actor (20) with its
  own mailbox, lifecycle state machine, and lock-free observation mirror; it MUST
  be servable from a `Paused` or `Stopped` parent directly and from a `Running`
  parent by first pausing at the next quantum boundary (20 [SESS-19]). The fork
  operation MUST be recordable so an interactively-forked exploration reproduces
  (the fork is a structural `fork` event in the log, 19 §19.7; the divergent
  decisions enter the child's schedule). *Gate:* `gate:control-responsive`,
  `gate:replay-oracle`. *Spec:* §22.3; cross-ref 20 §7, 19 §19.7.

### 22.3.1 Scope note: no detach-to-live-debug VM

> **Non-normative scope note.** A prior exploration could *fork a savepoint into
> a full-speed, uncontrolled live QEMU* — a bootable VM running on host wall-clock
> with determinism intentionally abandoned — for interactive human debugging.
> Crucible's `save`/`fork` deliberately do **not** do this. A Crucible fork or
> savepoint produces a *controlled checkpoint* in the temporal graph (a
> `Configuration` realized via `instantiate`, §22.3, §22.4), still inside the
> deterministic contract (04) and the one execution path (05 [EXEC-14]); it is not
> a hand-off to a free-running, non-deterministic instance.
>
> "Detach this savepoint into a live, full-speed, non-deterministic QEMU for
> interactive debugging" is therefore **explicitly out of scope for this RFC**: it
> abandons the determinism contract for that instance and would be a *second
> execution path* ([ADV-2], 05 [EXEC-14]). If such a capability is wanted later it
> MUST be a separate, clearly-marked **escape hatch** built on
> `materialize-to-image` ([`15-io-subnodes.md`](15-io-subnodes.md)) that takes a
> checkpoint out of the deterministic world entirely — never a mode of `save`/`fork`
> and never part of the deterministic path.

- **[ADV-33]** Crucible's `save`/`fork` MUST produce only controlled checkpoints
  in the temporal graph (realized via `instantiate`, [ADV-6], [ADV-13]) and MUST
  NOT provide a "detach to a live, full-speed, non-deterministic QEMU for
  interactive debugging" capability: doing so would abandon the determinism
  contract for that instance and introduce a second execution path forbidden by
  [ADV-2] / 05 [EXEC-14]. Any future interactive-live-debug capability MUST be a
  separate, explicitly-marked escape hatch built on `materialize-to-image`
  ([`15-io-subnodes.md`](15-io-subnodes.md)), outside the deterministic path, never
  a mode of `save`/`fork`. *Gate:* `gate:e2e-determinism`. *Spec:* §22.3.1;
  cross-ref 05 [EXEC-14], 15.

## 22.4 Save and restore: two strategies, one oracle

Save/restore exists in **two strategies**, and the relationship between them is
the whole reason Crucible's snapshots are trustworthy:

1. **Replay-from-seed** — the *always-correct* strategy and the **oracle**.
   Re-derive a configuration by `reduce`/replaying its schedule forward from a
   known-good ancestor (ultimately the baked genesis snapshot, 05 §6). It depends
   only on Contract A/B determinism (04) and the recorded schedule delta — never on
   any snapshot's completeness — so it is correct *by construction*. A thin
   checkpoint (07 §4) restores this way. This is slow (it re-runs the suffix) but
   it cannot be wrong.

2. **Snapshot-restore** — the *fast* strategy that **must be validated**.
   `loadvm` a materialized (fat) checkpoint (07 §3) directly, skipping the replay.
   This is fast but is a *cache* of `reduce`, and a cache can be wrong: a `savevm`
   that fails to capture a device register, a scheduler queue, or an RNG position
   produces a snapshot that restores to the wrong state (the snapshot-completeness
   risk, [`30-risks-spikes.md`](30-risks-spikes.md)).

The two strategies are tied together by the **replay oracle** ([INV-2], 07 §6): a
fat checkpoint MUST hash-equal its replay-from-ancestor derivation, or it is
rejected as a corrupt cache entry and the thin (replay) form is used instead. This
is precisely what *makes snapshot bugs visible* instead of silently poisoning every
descendant: the slow-but-correct strategy is the yardstick the fast strategy is
measured against, continuously, as a CI gate.

```text
  restore strategies for a checkpoint c:
  ──────────────────────────────────────────────────────────────────────
  (A) replay-from-seed   : instantiate(nearest fat ancestor) then replay
                            the schedule suffix to c.   ALWAYS CORRECT (the oracle)
                            depends only on Contract A/B + schedule delta (04, 07 §4)
  (B) snapshot-restore   : loadvm(c.fat_snapshot).        FAST, MUST BE VALIDATED
                            a cache of reduce(); can be incomplete/wrong

  oracle (INV-2, 07 §6):  hash( loadvm(c.fat) ) == hash( replay-to-c )
                          fail ⇒ reject the fat snapshot, fall back to (A),
                          localize via divergence bisection (24)  — never smooth over
  hedge:                  if savevm is unreliable for a device, leave c THIN (07 §4,
                          [TEMP-13]) — degrade to slow, never to wrong.
```

- **[ADV-10]** Crucible MUST provide both restore strategies and MUST treat
  replay-from-seed as the source of truth: (A) replay-from-seed (thin restore, 07
  §4) MUST be correct independent of any snapshot's completeness, depending only on
  Contract A/B determinism (04) and the recorded schedule delta; (B)
  snapshot-restore (fat `loadvm`, 07 §3) MUST be treated as a validatable cache of
  `reduce`. *Gate:* `gate:replay-oracle`. *Spec:* §22.4; cross-ref 07 §3, §4, 05
  §4, §5.

- **[ADV-11]** A fat (snapshot) checkpoint MUST be validated against its
  replay-from-ancestor derivation by the replay oracle (07 §6, [INV-2]) before it
  is trusted: `hash(loadvm(fat)) == hash(replay-to-c)`. A fat snapshot that fails
  MUST be rejected (dropped to thin) and the replay strategy used; the failure MUST
  be localized to the first differing decision/instruction by divergence bisection
  (24), never smoothed over ([INV-10], 07 [TEMP-18], [TEMP-19]). The oracle is the
  mechanism by which snapshot bugs are *made visible*. *Gate:* `gate:replay-oracle`,
  `gate:divergence-bisect`. *Spec:* §22.4; cross-ref 07 §6.

- **[ADV-12]** When a device's snapshot is unreliable (the savevm-completeness
  hedge, [`30-risks-spikes.md`](30-risks-spikes.md), 07 [TEMP-13]) the affected
  checkpoints MUST be kept **thin**: restore degrades to the slower replay strategy
  but stays bit-correct, because replay-from-ancestor never depends on snapshot
  completeness. Snapshot completeness MUST therefore never be a *correctness*
  prerequisite for save/restore, only a *performance* optimization. *Gate:*
  `gate:replay-oracle`. *Spec:* §22.4; cross-ref 07 §4, 30.

- **[ADV-13]** Save (`create_savepoint`, 20 §7) MUST materialize the current
  configuration as a fat checkpoint keyed by `config.id()` (05 [EXEC-4]),
  CoW-shared (07 §5) and oracle-validated (07 §6), with the thin form
  `(parent, schedule_delta)` remaining the source of truth (07 §4). Restore MUST be
  `instantiate` of the recorded configuration (05 §5): `loadvm` if fat-and-valid,
  else replay-from-nearest-fat-ancestor. A session restored from a savepoint MUST
  be the same kind of object as one started at genesis, differing only in its
  configuration (20 [SESS-18]). *Gate:* `gate:replay-oracle`,
  `gate:content-address`. *Spec:* §22.4; cross-ref 20 §7, 05 §5/§9, 07 §3/§4.

## 22.5 State-space search

### 22.5.1 The schedule as a tree of Decisions

A run's schedule is a totally-ordered list of `Decision`s (05 §3) — and at each
scheduling point the scheduler had a *set* of available choices, of which the run
took one. The space of all schedules is therefore a **tree** (made a DAG by
content-addressed dedup, 07 §1): nodes are configurations (checkpoints), edges are
decisions, and the branching factor at a node is the number of genuine choices
available there. **State-space search is the systematic expansion of the temporal
graph by enumerating the `Decision`s at frontier checkpoints** and `step`-ping each
to a child configuration — exactly the operation in 05 §9 and 07 §10, driven by a
frontier work-list instead of a single user's fork commands.

```text
                      genesis (def, [])
                     /        |        \         ← enumerate Decisions at the frontier
                  d=A        d=B        d=C        (05 §3: fault branch with RNG draw,
                  /            |           \        RNG draw, override)
               c_A           c_B           c_C    ← step() each to a child (07 §1)
              / \            / \           / \
            ...  ...       ...  ...       ...  ... ← frontier expands; DAG dedups (07 §9)

  search = repeatedly: pick a frontier node (strategy §22.5.2), instantiate it
           (05 §5; fork from the cheapest cached ancestor), enumerate its
           Decisions, step each to a child, push children to the work-list,
           prune with symmetry + partial-order reduction (07 §9, §22.5.3).
```

What is enumerated at a frontier is the closed `Decision` taxonomy of 05 §3, but
only at unresolved runtime choice points: probabilistic fault branches are
recorded with their paired decision-RNG draw, standalone decision-RNG draws may
branch where a stream value is itself the choice, and search/fuzz *overrides*
(`Decision::Override`, 05 §3) substitute a non-default choice at a scheduling
point. Delivery order branches exist only for a genuine delivery tie that [INV-3]
does not already resolve; the current RESOLVE key orders due events by
`(virtual_time, consumer, producer, sequence)`, so ordinary `Decision::DeliveryOrder`
records are deterministic replay material rather than search branches. Because a
child reached by two different paths that denote the same `(def, schedule)` is
one node by content address (07 §1, 05 [EXEC-26]), the search work-list is
self-deduplicating.

- **[ADV-14]** State-space search MUST express the schedule space as the
  content-addressed temporal graph (07 §1): nodes are checkpoints (recorded
  `Configuration`s), edges are `Decision`s (05 §3). Search MUST proceed by
  enumerating the available `Decision`s at a frontier checkpoint, `step`-ping each
  to a child configuration (07 §1), and treating the graph as both the work-list
  and the dedup index — a configuration reached by two paths MUST be one node by
  content address (05 [EXEC-26], 07 [TEMP-1]). *Gate:* `gate:content-address`,
  `gate:replay-oracle`. *Spec:* §22.5.1; cross-ref 05 §3/§9, 07 §1/§10.

- **[ADV-15]** The `Decision`s enumerated at a frontier MUST be drawn from the
  closed taxonomy of 05 §3 (probabilistic fault-fires outcome with its paired
  decision-RNG draw, standalone decision-RNG draw, `Decision::Override` for a
  non-default scheduling choice, and delivery order only if [INV-3] leaves a
  genuine unresolved tie). Search MUST NOT enumerate choices that [INV-3]'s total
  order already resolves deterministically (no genuine tie ⇒ no branch, 05
  [EXEC-8]); it branches only where a *genuine* choice exists. *Gate:*
  `gate:content-address`. *Spec:* §22.5.1; cross-ref 05 §3, [INV-3].

- **[ADV-16]** Each frontier node MUST be realized via `instantiate` (05 §5),
  forking from the cheapest correct cached ancestor (loadvm a fat ancestor, else
  replay a thin suffix). Search MUST keep most checkpoints thin and materialize
  only hot nodes (repeated fork hubs, shared replay paths) under the temporal
  graph's materialization budget (07 [TEMP-14]); the choice of which nodes are fat
  MUST be a performance decision that does not change any node's denoted state (07
  [TEMP-12], [TEMP-14]). *Gate:* `gate:replay-oracle`, `gate:content-address`.
  *Spec:* §22.5.1; cross-ref 07 §4, §5.

### 22.5.2 Search strategies

The *order* in which the frontier is expanded is a pluggable **strategy** — the
search is correct under any strategy (it explores the same graph), but the
strategy decides which failures are found first under a finite budget.

```rust,illustrative
/// How the search picks the next frontier checkpoint to expand. The graph
/// explored is the same under every strategy; the strategy only orders the
/// frontier, trading off depth, breadth, and coverage gain under a budget.
pub enum SearchStrategy {
    /// Breadth-first: shallowest frontier node first. Finds the
    /// minimal-decision failure (shortest schedule to a bug) first.
    BreadthFirst,
    /// Depth-first: deepest frontier node first. Cheap memory; drives a single
    /// line deep before backtracking.
    DepthFirst,
    /// Priority: a deterministic, seeded ordering by a score (e.g. proximity to
    /// a target assertion, fault density). Ties broken by content-address order.
    Priority { score: ScoreFn },
    /// Coverage-guided: expand the node whose children are predicted to reach
    /// the most new coverage (§22.6); the bridge to fuzzing (§22.7).
    CoverageGuided,
}
```

Every strategy MUST be a *deterministic* function of the seed and the graph: two
search runs with the same family, seed, and budget MUST expand the same nodes in
the same order and discover the same failures, so a search is itself reproducible.
Ties in any ordering are broken by content-address order (07 §1), never by host
map-iteration or wall-clock ([INV-9]).

- **[ADV-17]** State-space search MUST support pluggable frontier-expansion
  strategies including at least breadth-first, depth-first, priority (a seeded
  deterministic score), and coverage-guided (§22.6). The explored graph MUST be
  identical under every strategy (correctness MUST NOT depend on strategy); the
  strategy MUST only order the frontier. *Gate:* `gate:content-address`. *Spec:*
  §22.5.2.

- **[ADV-18]** Every search strategy MUST be a deterministic function of
  `(family/scenario, seed, budget)` and the content-addressed graph: two searches
  with identical inputs MUST expand the same nodes in the same order and discover
  the same failures. Frontier ordering ties MUST be broken by content-address order
  (07 §1), never by host map-iteration order, thread scheduling, or wall-clock
  ([INV-9], [INV-10]). A search MUST be reproducible as a unit, not only its
  individual runs. *Gate:* `gate:e2e-determinism`, `gate:harness-lint`. *Spec:*
  §22.5.2; routes [INV-1], [INV-9].

### 22.5.3 Reduction for tractability: symmetry and partial-order reduction

Branching at every scheduling point makes the graph exponential; search is
tractable only because two **soundness-preserving reductions** (07 §9) avoid
generating nodes provably equivalent to nodes already explored. These are
**graph-level node-deduplication optimizations over the content-addressed DAG**,
**not a formal-methods engine** ([NG-3]): Crucible includes no model checker and no
specification-language evaluator. The reductions are heuristics for *not building
nodes we can prove redundant*, expressed entirely in the `id` and
`coverage_fingerprint` the temporal graph already carries (07 §2).

- **Symmetry reduction** (07 [TEMP-27]). When frontier checkpoints are equivalent
  up to a relabeling of interchangeable entities (e.g. three identical replica VMs:
  "replica A crashes" and "replica B crashes" reach structurally equivalent
  states), the search explores **one representative** and treats the symmetric
  others as covered, detected by a canonical-relabeling fingerprint derived from
  the `coverage_fingerprint` (07 §2). States that produce an identical
  `(def, schedule)` are already deduped by content address (07 §1); symmetry
  reduction extends this to states equivalent-up-to-relabeling but not
  byte-identical.

- **Partial-order reduction** (07 [TEMP-28]). When two `Decision`s are independent
  — their effects commute, e.g. delivering an in-flight message to unrelated node X
  and, separately, to unrelated node Y — the search explores **one representative
  interleaving** instead of all permutations. Independence is detected
  conservatively from the scheduling structure (08): two decisions are independent
  when they touch disjoint node sets and neither enables nor disables the other.

Both reductions MUST be **sound**: they MUST skip a node only when it is provably
equivalent (by canonical fingerprint, or by conservative independence) to a node
already explored, and **explore when in doubt** — a missed reduction costs time, an
unsound one costs coverage.

- **[ADV-19]** State-space search MUST apply symmetry reduction and partial-order
  reduction (07 §9, [TEMP-27], [TEMP-28]) as the mechanism that keeps the graph
  tractable: symmetry collapses frontier checkpoints equivalent up to relabeling of
  interchangeable entities (canonical-relabeling fingerprint, 07 §2); partial-order
  reduction explores one representative interleaving of independent (commuting,
  disjoint-node, non-enabling) `Decision`s (08). Both MUST be sound — skip only
  provably-equivalent nodes, explore when in doubt. *Gate:* `gate:content-address`.
  *Spec:* §22.5.3; cross-ref 07 §9, 08.

- **[ADV-20]** The reductions MUST be implemented as graph-level
  node-deduplication optimizations over the content-addressed DAG (using `id` and
  `coverage_fingerprint`, 07 §2), and MUST NOT be a model checker or a
  specification-language evaluator ([NG-3], 07 [TEMP-29]). They MUST NOT change the
  denoted state of any explored node; they only avoid *generating* provably
  redundant nodes. Crucible MUST NOT contain an in-runtime formal-methods engine.
  *Gate:* `gate:content-address`. *Spec:* §22.5.3; routes [NG-3]; cross-ref 07
  [TEMP-29].

### 22.5.4 Guided and adaptive exploration

> The strategies of §22.5.2 fix an expansion order up front. A *guided* campaign
> goes further: it scores frontier nodes from the coverage projection (§22.6) and
> temporal-graph metadata (07 §2) and lets that score steer expansion — and an
> *adaptive* campaign tunes which strategy/signal mix is used as it learns. The
> non-negotiable rule that makes this safe in Crucible is the separation between
> the **campaign** and the **run**: the campaign is allowed to be adaptive, but
> **every individual run it spawns stays bit-identical** to a non-guided run of
> the same `(def, seed, schedule)`. Guidance is the campaign's own concern; it is
> a reader of realized state and never a participant in `reduce`. The default —
> coverage-only, no adaptivity — reproduces the existing behavior of §22.5.2
> exactly.

A **guidance signal** is a deterministic scoring function over a *realized*
frontier checkpoint: it reads the checkpoint's coverage projection (§22.6) and
its temporal-graph metadata (07 §2) and returns a fixed-point score used only to
order the frontier. Signals are pure readers — they never enter `reduce`,
scheduling, virtual time, or injection, and never change a fingerprint.

```rust,illustrative
/// Scores a realized frontier checkpoint to order expansion. A signal is a
/// READER ONLY: it never influences reduce/scheduling/time/injection and never
/// changes a fingerprint. Scores are fixed-point integers (never f64), and a
/// composite is a deterministic fixed-point weighted sum over a fixed signal
/// order, ties broken by content-address order (07 §1).
pub trait GuidanceSignal {
    /// Deterministic fixed-point score from the coverage projection (§22.6) and
    /// temporal-graph metadata (07 §2). MUST NOT read host wall-clock or thread
    /// RNG; any signal-internal randomness draws from the seeded source.
    fn score(&self, node: &RealizedCheckpoint) -> FixedScore;
}

// Built-ins:
//   Coverage          — the existing CoverageGuided behavior (§22.5.2).
//   NoveltyRarity     — inverse-frequency over a deterministically-maintained
//                       rarity table (rare blocks score higher).
//   AssertionProximity— the distance-to-assertion metric defined in 18 (fwd-ref).
```

- **[ADV-34]** State-space search and fuzzing MAY consume a pluggable
  **guidance-signal** abstraction: a `GuidanceSignal` that deterministically
  scores a *realized* frontier checkpoint from its coverage projection (§22.6) and
  temporal-graph metadata (07 §2). Crucible MUST provide at least three built-in
  signals — coverage (the existing `CoverageGuided` behavior, §22.5.2),
  novelty/rarity (inverse-frequency over a deterministically-maintained rarity
  table), and assertion-proximity (the distance metric defined in 18,
  forward-ref). Signals MUST compose by a deterministic fixed-point weighted sum,
  with ties broken by content-address order (07 §1). Signals MUST be **readers
  only**: a signal MUST NOT influence `reduce`, scheduling, virtual time, or
  injection, and MUST NOT change a fingerprint (§22.6.2 [ADV-23], [INV-1]). The
  default — coverage only, no adaptivity — MUST reproduce the existing behavior of
  §22.5.2. *Gate:* `gate:content-address`, `gate:single-vm-fingerprint`. *Spec:*
  §22.5.4; cross-ref §22.6, 07 §2, 18.

- **[ADV-35]** Guidance scores and weights MUST be fixed-point/integer and MUST
  NEVER be `f64`: float summation is not associative across hosts and is banned on
  any ordering path ([INV-9]). Signal combination MUST use a fixed order (by signal
  id, then content-address order of realized nodes, 07 §1), so the composite score
  is a deterministic function of the realized graph. Any signal-internal randomness
  MUST draw from the seeded decision source and MUST be recorded ([ADV-3], [INV-10]).
  *Gate:* `gate:e2e-determinism`, `gate:harness-lint`. *Spec:* §22.5.4; routes
  [INV-9], [INV-10].

- **[ADV-36]** Adaptive strategy selection is **OPTIONAL and off by default**.
  When enabled, it MUST be a deterministic multi-armed bandit (default: a
  deterministic UCB rule) over a *fixed ordered set* of expansion arms (the
  existing strategies of §22.5.2 plus signal-weight presets, §22.5.4). The bandit
  MUST credit a deterministic reward — new coverage, novelty gain,
  assertion-proximity progress, and *dominantly* a confirmed failure — and MUST
  apply credit in content-address order (07 §1). All bandit state transitions MUST
  be a deterministic function of the realized graph and the seed; no host
  wall-clock or thread RNG ([ADV-3], [INV-9]). *Gate:* `gate:e2e-determinism`,
  `gate:content-address`. *Spec:* §22.5.4; cross-ref §22.5.2, §22.6.

- **[ADV-37]** An adaptive/guided campaign MUST be **campaign-adaptive but
  run-deterministic**: its arm selections, rewards, and expansion order MUST be a
  deterministic function of `(family, seed, budget, content-addressed graph,
  signal+bandit config)` and reproducible *as a unit*. Guidance MUST change only
  *which* nodes are expanded and *in what order* — never *what a node denotes*
  ([INV-1]). The signal+bandit config MUST be hashed into the **campaign
  identity**. A reproduction artifact (§22.8) MUST remain a bare
  `(def, seed, schedule)` bundle reproducible by replay alone, with **no reference
  to the campaign, signals, or bandit** ([ADV-28], 06 [SPAT-27]). *Gate:*
  `gate:e2e-determinism`, `gate:content-address`, `gate:replay-oracle`. *Spec:*
  §22.5.4; cross-ref §22.8, 06 §7.1.

- **[ADV-38]** Guidance MUST be sound under reduction and fair. Because scores are
  functions of the canonical `coverage_fingerprint` (07 §2), a node and its
  symmetric representative MUST score identically, so guidance MUST NOT defeat
  symmetry or partial-order reduction (§22.5.3, [ADV-19]): it is ordering-only over
  the same explored graph. A **fairness floor** — a bounded fraction of expansions
  allocated breadth-first — MUST be enforced to prevent starvation of the frontier.
  *Gate:* `gate:content-address`, `gate:e2e-determinism`. *Spec:* §22.5.4;
  cross-ref §22.5.3, 07 §2/§9.

### 22.5.5 Interleaving and preemption exploration

The decision taxonomy (05 §3) includes `Decision::Preemption` — the vCPU-switch
and interrupt-timing decision derived from 05/08. Branching on *when* a vCPU is
preempted (and when the timer interrupt lands) is the highest-leverage intra-node
exploration axis, because it reaches concurrency bugs that no schedule of
*delivered messages* alone can expose — and it works even for a **single-vCPU
guest** by varying when the timer interrupt preempts the running vCPU.

- **[ADV-39]** State-space search and fuzzing MUST be able to branch on
  `Decision::Preemption` (the vCPU-switch + interrupt-timing decision of 05/08)
  within the bounded `[deadline, horizon]` window — the highest-leverage intra-node
  axis, working even for single-vCPU guests (varying when the timer interrupt
  preempts). Search MUST apply partial-order reduction over commuting preemptions
  (§22.5.3, [ADV-19]) to stay tractable. Each preemption-branch child MUST be a
  content-addressed temporal-graph node (07 §1) validated by the replay oracle (07
  §6, [INV-2]). *Gate:* `gate:replay-oracle`, `gate:content-address`. *Spec:*
  §22.5.5; cross-ref 05 §3, 08, 07 §9.

### 22.5.6 App-controlled randomness as a search dimension

When a scenario opts into app-requested randomness (`Decision::AppRandom`, 16/05),
the value served to the guest at each draw is itself a degree of freedom. Search
and fuzzing MAY treat the served value as a mutation/branch dimension. This is
strictly additive: a scenario with no app-random draws explores exactly as before.

- **[ADV-40]** When a scenario opts into app-requested randomness
  (`Decision::AppRandom`, 16/05), search and fuzzing MAY explore alternative served
  values as a mutation/branch dimension, bounded by the per-scenario draw cap and a
  per-draw seeded value-sampling budget. This capability MUST be strictly
  optional/additive: a scenario with no app-random draws MUST explore identically
  to before. Each alternative served value MUST be recorded as a `Decision` (05 §3)
  so the branch is reproducible ([ADV-3], [INV-1]). *Gate:* `gate:e2e-determinism`,
  `gate:content-address`. *Spec:* §22.5.6; cross-ref 16, 05 §3.

## 22.6 Coverage: black-box basic-block feedback

### 22.6.1 The signal

The exploration feedback signal is **basic-block coverage** harvested from the
plugin's TCG-execution hook (12 §12.8, [PLUG-35]): as the guest executes
translated blocks, the plugin folds each block's guest program counter into a
fixed-size coverage map. This is **black-box** — it needs **no guest
instrumentation, no source, no symbols, and works on any binary** ([G-2], [G-3]),
because the signal comes from the *translator*, not the guest. It is the coverage
analogue of the whole "any unmodified guest" goal: you learn which code the guest
exercised without the guest cooperating at all.

Coverage costs nothing when off: the hook is a **registration-time opt-in**
(`coverage=on`, [PLUG-5]), never a per-block runtime branch (12 [PLUG-36]), and
enabling it MUST NOT change the instruction stream `S` or the architectural
trajectory `T` — coverage is an observation, so turning it on or off MUST NOT
change a fingerprint (12 [PLUG-35], [PLUG-37]).

- **[ADV-21]** Coverage MUST be basic-block coverage harvested from the plugin's
  TCG-exec hook (12 §12.8) with **zero guest instrumentation**: it MUST work on an
  arbitrary guest binary with no source, symbols, or in-guest agent ([G-2], [G-3]).
  Enabling coverage MUST be a registration-time opt-in (12 [PLUG-5], [PLUG-36]) and
  MUST NOT alter the instruction stream or architectural trajectory — a run's
  execution fingerprint MUST be identical with coverage on or off (12 [PLUG-35],
  [PLUG-37]). *Gate:* `gate:single-vm-fingerprint`, `gate:any-guest`. *Spec:*
  §22.6.1; cross-ref 12 §12.8.

### 22.6.2 Coverage is an observational event-log record

Coverage enters the **one event log** (19) as **observational** `coverage` entries
(19 §19.7, [OBS-29]): basic-block coverage from the plugin hook and any white-box
named coverage markers (16). Because coverage entries are observational, they are
**excluded from the determinism comparison** (19 [OBS-22], [OBS-29]) — two
equivalent runs may legitimately record different coverage interleaving without it
being a determinism bug — yet the per-checkpoint `coverage_fingerprint` (07 §2) is a
*deterministic digest* derived from the coverage projection, so it is stable enough
to drive search and dedup. Search and fuzzing read the **coverage projection** of
the log (19 [OBS-4]) as their feedback signal; there is no second coverage record
that can drift from the log.

- **[ADV-22]** Coverage MUST be recorded in the one event log as observational
  `coverage` entries (19 §19.7, [OBS-29]) and MUST be excluded from the determinism
  comparison (19 [OBS-22]). Search and coverage-guided fuzzing MUST read the
  coverage projection of the log (19 [OBS-4]) as their feedback signal; the
  per-checkpoint `coverage_fingerprint` (07 §2) MUST be a deterministic digest
  derived from that projection. No feature MAY maintain a coverage record parallel
  to the log. *Gate:* `gate:e2e-determinism`, `gate:content-address`. *Spec:*
  §22.6.2; cross-ref 19 §19.6.3, 07 §2.

- **[ADV-23]** Coverage MUST feed the search and fuzzer as feedback only and MUST
  NOT influence scheduling, virtual time, or injection (12 [PLUG-37]): recording or
  reading coverage MUST be free of any effect on `reduce` ([INV-1]). A
  coverage-guided strategy biases *which configurations are explored*, never *what a
  configuration denotes*. *Gate:* `gate:e2e-determinism`,
  `gate:single-vm-fingerprint`. *Spec:* §22.6.2; routes [INV-1].

## 22.7 Coverage-guided fuzzing

### 22.7.1 What is fuzzed

Fuzzing is **coverage-guided sampling and mutation of the schedule and the fault
plan**, over the parameter space of a `ScenarioFamily` (06 §7). Where state-space
search *enumerates* decisions systematically, fuzzing *samples and mutates* them,
biased toward new coverage — trading completeness for reach into a much larger
space (more nodes, larger topologies, denser fault plans) than exhaustive search
can cover. Three things are varied, all of them part of the model (so the result is
reproducible):

- **the `ScenarioFamily` parameter point** (06 §7): the seed, the fault density,
  and the topology size/shape, sampled deterministically from a meta-seed. Sampling
  pins **one concrete `ScenarioDef`** with a fixed `id` (06 [SPAT-26], [SPAT-27]);
  a run never executes a family, only a pinned instance.
- **the schedule** (05 §3): which `Decision`s are taken at scheduling points,
  expressed as `Decision::Override`s layered onto a base run.
- **the fault plan** (17): which faults fire, when, and where — the part of the
  `ScenarioDef`'s `Plan` (06) that the family's fault-density axis scales.

```text
  fuzz loop (coverage-guided, fully seeded):
  ──────────────────────────────────────────────────────────────────────────
  corpus := seed schedules/params (each reproducible: §22.8)
  repeat under a budget:
    1. pick a corpus entry (energy ∝ coverage novelty; deterministic, seeded)
    2. mutate it: sample a ScenarioFamily point (06 §7) and/or layer schedule
       + fault-plan Decision::Overrides (05 §3, 17) — mutation is SEEDED
    3. pin a concrete ScenarioDef (06 [SPAT-27]); run it (instantiate, 05 §5)
    4. read the coverage projection (§22.6); if it reaches NEW coverage,
       add the mutant to the corpus (corpus management §22.7.2)
    5. if a property is violated (18) → emit a reproduction artifact (§22.8)
  every choice (sampling, energy, mutation) is a Decision (05 §3) → REPRODUCIBLE
```

- **[ADV-24]** Fuzzing MUST be coverage-guided sampling/mutation of the schedule
  (05 §3, via `Decision::Override`s) and the fault plan (17), over a
  `ScenarioFamily` parameter space (06 §7). A fuzz iteration MUST pin exactly one
  concrete `ScenarioDef` instance with a fixed `id` (06 [SPAT-26], [SPAT-27]) —
  fuzzing MUST NOT execute a family directly. Fuzzing MUST read the coverage
  projection (§22.6, 19 [OBS-29]) as its feedback signal and bias exploration
  toward new coverage. *Gate:* `gate:content-address`, `gate:e2e-determinism`.
  *Spec:* §22.7.1; cross-ref 06 §7, 05 §3, 17.

- **[ADV-25]** Every fuzzer choice — corpus-entry selection, mutation, family
  sampling, and energy assignment — MUST be a deterministic function of a recorded
  seed, expressed as `Decision`s (05 §3) or as the family parameter point (06 §7),
  so a fuzzing campaign is itself reproducible: re-running the campaign with the
  same meta-seed and budget MUST explore the same mutants and discover the same
  failures ([INV-1], [INV-9]). The fuzzer MUST NOT read host wall-clock or thread
  RNG on any path that selects a mutant or feeds `State` (06 §7 sampling is seeded;
  [ADV-3]). *Gate:* `gate:e2e-determinism`, `gate:harness-lint`. *Spec:* §22.7.1;
  routes [INV-1], [INV-9].

### 22.7.2 Corpus management and throughput

The **corpus** is the retained set of inputs (schedules + family points) worth
mutating — by construction, the inputs that have each reached coverage no other
corpus entry reaches. Corpus entries are content-addressed (each is a reproduction
artifact, §22.8) and stored in the `DagStore` (07 §7) like any other artifact, so
corpus membership and dedup ride the same content addressing as the temporal graph
([INV-6]). Corpus management — admission (new coverage ⇒ keep), pruning (drop
entries subsumed by others), and energy assignment (favor entries near coverage
frontiers) — MUST be deterministic and seeded so a campaign reproduces ([ADV-25]).

> **Cross-ref.** Scaling a fuzzing campaign across many hosts and keeping a
> continuously-growing corpus is specified separately in
> [`35-distributed-continuous-exploration.md`](35-distributed-continuous-exploration.md)
> (DCE); this section specifies only the single-host corpus and its content
> addressing, on which the distributed/continuous capability builds.

Throughput matters because fuzzing's reach is throughput-bound: idle time is
fast-forwarded to zero wall-clock (12 §12.3.5), forks are CoW-cheap (07 §5), and
runs parallelize up to the lookahead budget — the fuzzer MUST meet the **fuzzing
throughput target stated in [`25-performance-targets.md`](25-performance-targets.md)**
(runs/iterations per wall-clock unit), which is what makes coverage-guided search
of a large space practical rather than aspirational ([G-9]).

- **[ADV-26]** The fuzzer MUST manage a content-addressed corpus stored in the
  `DagStore` (07 §7): admission MUST be coverage-driven (an input is retained iff
  it reaches coverage no retained entry reaches, §22.6), and pruning, dedup, and
  energy assignment MUST be deterministic and seeded ([ADV-25]). Each corpus entry
  MUST be a self-contained reproduction artifact (§22.8), so any corpus entry —
  not only a failure — reproduces bit-identically. *Gate:* `gate:content-address`,
  `gate:replay-oracle`. *Spec:* §22.7.2; cross-ref 07 §7, §22.8.

- **[ADV-27]** The fuzzer MUST meet the fuzzing throughput target of
  [`25-performance-targets.md`](25-performance-targets.md), exploiting idle
  fast-forward (12 §12.3.5), CoW-cheap forks (07 §5), and multi-run parallelism up
  to the lookahead budget (08). Throughput MUST be measured in deterministic work
  units (runs/mutants per wall-clock unit) and MUST NOT be achieved by weakening
  determinism or skipping oracle validation ([ADV-3], [ADV-11]). *Gate:*
  `gate:e2e-determinism`. *Spec:* §22.7.2; forward-ref 25; routes [G-9].

## 22.8 Reproduction and minimization

### 22.8.1 Every interesting finding is a self-contained artifact

The payoff of the whole ladder is that **every interesting finding emits a
self-contained reproduction artifact** that reproduces the finding
**bit-identically**. A reproduction artifact is the `(seed, scenario, schedule)`
bundle of 06 §7.1 / 23: the pinned concrete `ScenarioDef` (with its `id`, 06
[SPAT-27]), the seed, and the recorded `Schedule` (including any operator/search
`Decision::Override`s and any interactively-injected faults recorded as decisions,
20 [SESS-20]). Because a run is `reduce(ScenarioDef, Schedule)` ([INV-1]) and the
schedule captures every genuine choice (05 [EXEC-8]), the artifact reproduces the
run to the instruction with no reference to the search/fuzz campaign or the family
that found it (06 [SPAT-27]).

> **Cross-ref.** Triaging discovered findings — deduplicating, classifying, and
> ranking the failures these artifacts represent — is specified separately in
> [`34-failure-triage.md`](34-failure-triage.md) (TRI); this section specifies
> only how a single finding is captured and minimized into a reproducible artifact.

The artifact is correct by **replay alone** — `def + seed + schedule` reproduces by
re-reduction, needing no stored snapshots (07 [TEMP-23]). Where a content-addressed
store is shared, the artifact MAY reference stored checkpoints/log segments by
content key to fetch-rather-than-recompute (07 [TEMP-23], 19 [OBS-30]), but the
store MUST NOT be required for correctness.

- **[ADV-28]** Every interesting finding (a property violation, a divergence, or a
  retained corpus entry) MUST emit a self-contained reproduction artifact: the
  pinned concrete `ScenarioDef` (with its `id`), the seed, and the recorded
  `Schedule` (06 §7.1, 23), reproducing the finding **bit-identically** by replay
  alone with no reference to the discovering campaign or family (06 [SPAT-27],
  [INV-1]). The artifact MUST be correct without any stored snapshot; it MAY
  reference stored checkpoints/log segments by content key for speed where a store
  is shared (07 [TEMP-23], 19 [OBS-30]). *Gate:* `gate:e2e-determinism`,
  `gate:replay-oracle`, `gate:content-address`. *Spec:* §22.8.1; cross-ref 06 §7.1,
  23, 07 §7.

- **[ADV-29]** A reproduction artifact MUST reproduce a finding regardless of how
  the finding was reached (interactive forking, state-space search, or
  coverage-guided fuzzing): all three reduce to the same `(def, seed, schedule)`
  bundle because all three are operations on the one execution model (05) and
  temporal graph (07). An interactively-discovered finding MUST emit the same kind
  of artifact as a fuzzed one (20 [SESS-20]). *Gate:* `gate:e2e-determinism`.
  *Spec:* §22.8.1; cross-ref 20 §8, 05 §9.

### 22.8.2 Minimization (shrinking)

A raw finding from search or fuzzing is usually larger than the bug needs — a long
schedule with many irrelevant decisions, a fault set with faults that do not
contribute to the failure. **Minimization** is a pass that shrinks the schedule and
the fault set **while preserving the failure**: it repeatedly removes or simplifies
decisions/faults and re-runs, keeping a candidate only if the *same* property still
fails (the failure-preserving predicate). Because every candidate is itself a fully
reproducible run ([ADV-28]) and the failure predicate is a fold over the event log
(19, 18), minimization is a deterministic search for a smaller artifact that
still triggers the same violation.

```text
  minimize(artifact, fails?):
  ──────────────────────────────────────────────────────────────────────
  cur := artifact
  repeat until no candidate shrinks further (deterministic, seeded order):
    for each removable decision / heal-able fault / shrinkable param in cur:
      cand := cur with that element removed/simplified   (still a valid Schedule)
      if fails?(run(cand))  AND  same violation (18)  →  cur := cand   (accept)
  emit cur  — the minimal artifact that still reproduces the SAME failure
  every candidate run is bit-reproducible ([ADV-28]); the result is stable.
```

Minimization MUST preserve *the same* failure, not merely *a* failure: the shrunk
artifact MUST trigger the same property violation (or the same divergence) as the
original, checked by the same assertion fold over the event log (18, 19). The
minimization process MUST be deterministic (a seeded candidate order) so the
minimal artifact it produces is stable across runs.

- **[ADV-30]** Crucible MUST provide a minimization (shrinking) pass that reduces
  a finding's schedule and fault set while preserving the failure: it MUST
  repeatedly remove/simplify `Decision`s and faults, re-run, and accept a candidate
  only if it still triggers the **same** property violation or divergence (the
  failure-preserving predicate, checked by the assertion fold over the event log,
  18/19). The minimal result MUST itself be a self-contained, bit-reproducible
  artifact ([ADV-28]). *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`.
  *Spec:* §22.8.2; cross-ref 18, 19, 06 §7.1.

- **[ADV-31]** Minimization MUST be deterministic: the candidate-shrink order MUST
  be a seeded, content-address-tie-broken function (never host map-iteration or
  wall-clock, [INV-9]), so the minimal artifact is stable across runs on any host.
  Each candidate run MUST be validated like any run (oracle, fingerprint), so a
  candidate that diverges is detected, not silently accepted ([ADV-11], [INV-10]).
  *Gate:* `gate:e2e-determinism`, `gate:harness-lint`. *Spec:* §22.8.2; routes
  [INV-1], [INV-9].

## 22.9 The unifying view

The closing point of this file — and the reason these features are reliable in
Crucible where they were not before — is that **fork, save, resume, search,
replay, and minimization are all operations on the one content-addressed temporal
graph (07), driven by the one execution model (05), with coverage and the decision
tree as the only exploration drivers.** There is no abstract specification, no
model checker, no second execution path, and no separate snapshot store. The whole
of "advanced features" is:

```text
  fork      = instantiate a non-tip Configuration (05 §6) + step different Decisions
  save      = materialize a fat Checkpoint keyed by config.id (07 §3), oracle-checked
  resume    = instantiate the tip (05 §5)
  replay    = re-reduce a schedule + assert fingerprint == stored (the oracle, 07 §6)
  search    = enumerate Decisions at frontier Checkpoints; step each; dedup by id;
              prune by symmetry + partial-order reduction (07 §9)
  fuzz      = seeded coverage-guided sampling/mutation of schedule + fault plan,
              over a ScenarioFamily (06 §7); corpus in the DagStore (07 §7)
  reproduce = the (def, seed, schedule) artifact; minimize = failure-preserving shrink
  ───────────────────────────────────────────────────────────────────────────────
  ALL of the above: operations on ONE temporal graph (07), via ONE instantiate (05),
  driven by coverage (§22.6) + the Decision tree (05 §3). No abstract spec (NG-3).
```

Because they are all the *same* small algebra over the *same* graph, a single
correctness check — the replay oracle ([INV-2]) plus the single-VM fingerprint
([DET-3]) — validates all of them at once: if "instantiate the same configuration
twice agrees" (05 §11, [EXEC-31]), then start, resume, fork, save-completeness,
each search node, and each fuzz mutant are correct *by the same check*, because
they are the same operation. That collapse is what makes the advanced features
trustworthy rather than a fresh set of lifecycle-bug surfaces.

- **[ADV-32]** Fork, save, resume, replay, state-space search, coverage-guided
  fuzzing, reproduction, and minimization MUST all be operations on the single
  content-addressed temporal graph (07) via the single `instantiate` of the
  execution model (05), with coverage (§22.6) and the `Decision` tree (05 §3) as
  the only exploration drivers and the replay oracle ([INV-2]) plus single-VM
  fingerprint ([DET-3]) as the unifying correctness check (05 [EXEC-31]). There
  MUST be no abstract specification engine ([NG-3]), no second execution path (05
  [EXEC-14]), and no checkpoint/state representation outside the graph (05
  [EXEC-25], 07 [TEMP-30]). *Gate:* `gate:replay-oracle`,
  `gate:single-vm-fingerprint`, `gate:content-address`. *Spec:* §22.9; cross-ref 05
  §9/§11, 07 §10, [NG-3].

## 22.10 Summary

```text
DEPENDENCY ORDER (§22.1, G-5): exact determinism (04) → oracle-validated
  save/restore (07 §6, INV-2) → fork (05 §6) → state-space search → coverage-guided
  fuzzing. Each rung built ONLY after the rung below passes its gate. This is why
  these features were unreliable before (weak determinism + unvalidated snapshots)
  and how Crucible avoids it (a gate per rung).

PAUSE/RESUME/STOP (§22.2): session commands serviced at quantum boundaries (20),
  responsive because the actor yields between quanta (INV-8); observation-class.

FORK (§22.3): instantiate a non-tip Configuration (05 §6) + divergent Decisions;
  CoW-shared (07 §5); validated by the SAME replay oracle as restore (07 §6).

SAVE/RESTORE (§22.4): replay-from-seed (always correct, the ORACLE) vs
  snapshot-restore (fast, MUST be validated). The oracle makes snapshot bugs
  VISIBLE; unreliable snapshots stay thin (degrade to slow, never wrong).

STATE-SPACE SEARCH (§22.5): schedule = tree of Decisions (05 §3); search =
  systematic expansion of the temporal graph at frontier checkpoints; strategies
  BFS/DFS/priority/coverage-guided; tractable via symmetry + partial-order
  reduction (07 §9). NOT a formal-methods engine (NG-3).

COVERAGE (§22.6): black-box basic-block coverage from the plugin TCG-exec hook
  (12 §12.8); any binary, no guest instrumentation; observational event-log record
  (19); feeds search/fuzzer; never affects reduce.

FUZZING (§22.7): seeded coverage-guided sampling/mutation of schedule + fault plan
  over a ScenarioFamily (06 §7); content-addressed corpus in the DagStore (07 §7);
  meets the fuzzing throughput target (25).

REPRODUCTION (§22.8): every finding ⇒ self-contained (seed, scenario, schedule)
  artifact that reproduces bit-identically (06 §7.1, 23); minimization shrinks the
  schedule/fault set while preserving the SAME failure.

UNIFYING VIEW (§22.9): fork/save/resume/search/replay/fuzz/minimize are all
  operations on ONE temporal graph via ONE instantiate; one oracle + one
  fingerprint validate them all. No abstract spec needed.
```

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is the advanced features, tracked by [PLAN-3]. They
> are sequenced strictly after the determinism, save/restore-oracle, and
> control-plane foundations they depend on ([ADV-1], [G-5], [PLAN-4]).

- [x] **T-ADV-1** Encode and enforce the dependency-order gating: a CI/plan check
  that the advanced-feature phases are sequenced exact-determinism →
  oracle-validated save/restore → fork → search → fuzzing, with no rung's tasks
  scheduled before the lower rung's gate is green. — satisfies [ADV-1], [ADV-2],
  [ADV-3]; spec §22.1.
  Completed by `checks.crucible.phase6.advancedDependencyLadder`: the
  `crucible-harness::phase_plan` module now carries an executable
  `ADVANCED_FEATURE_TASK_ORDER` over the exact-determinism, save/restore, fork,
  search, coverage-feedback, and fuzzing rungs. The checker requires the
  determinism, replay-oracle, and control-plane phase gates to occur before
  phase-6 ADV work, parses this authoritative checklist to keep every
  `T-ADV-1` through `T-ADV-21` task in the executable ladder, and inspects the
  real `tests/crucible/default.nix` check graph so scheduled ADV checks must be
  wrapped in `greenBeforeAdvance` with the lower green gates and earlier ADV
  task checks they depend on. Phase-6 check imports must also pass explicit
  `taskIds` at the scheduling site so defaulted task IDs in imported files
  cannot hide future ADV work from the ladder. It rejects synthetic drifts where
  fuzzing is scheduled before coverage/search, where a foundational gate is
  moved too late, or where a future ADV check is wired outside the dependency
  ladder.
- [x] **T-ADV-2** Wire pause/resume/stop for exploration drivers as session
  commands serviced at quantum boundaries (no engine lock), observation-class, with
  resume+continue bit-identical to an uninterrupted run. — satisfies [ADV-4],
  [ADV-5]; spec §22.2; cross-ref 20 §3.
  Completed by `checks.crucible.phase6.explorationLifecycle`: the
  `crucible-session::ExplorationLifecycleDriver` owns only a session actor
  mailbox sender plus a live quantum-boundary snapshot, routing pause, resume,
  and stop through `SessionCommand::{Pause, Continue, Stop}`. The gate exercises
  the driver against a live `SessionActor`, requires every acknowledgement to
  land within the one-quantum lifecycle bound, asserts lifecycle commands do not
  appear as scheduler-owned control operations, and compares a paused/resumed run
  against an uninterrupted run for identical schedule and event-log replay.
- [x] **T-ADV-3** Implement fork as `instantiate` of a non-tip configuration plus
  divergent `step`s, CoW-shared with the parent, with no fork-specific realization
  path; assert the child is an independent session actor that cannot mutate the
  parent; ensure `save`/`fork` produce only controlled deterministic checkpoints
  and never a detach-to-live-non-deterministic-QEMU debug mode. — satisfies
  [ADV-6], [ADV-7], [ADV-9], [ADV-33]; spec §22.3, §22.3.1; cross-ref 05 §6, 07
  §5, 20 §7.
  Completed by `checks.crucible.phase6.explorationFork`: the session engine now
  exposes `fork_child`, accepts only paused or stopped parents, delegates branch
  creation to `TemporalGraph::fork`, and returns a normal child `SessionActor`
  with its own mailbox and live snapshot loaded at the forked branch
  configuration. The gate forks from an interior non-tip prefix with a divergent
  decision, asserts the branch is a thin checkpoint parented at the fork point,
  runs and stops the child actor, and proves the parent boundary snapshot is
  unchanged.
- [x] **T-ADV-4** Validate every fork by the replay oracle (same
  `gate:replay-oracle` as restore), localizing any divergence by bisection; assert
  fork adds no new correctness obligation. — satisfies [ADV-8]; spec §22.3;
  cross-ref 07 §6, 24.
  Completed by `checks.crucible.phase6.gates.replayOracle`: the Phase 6
  replay-oracle gate now exercises fork bases and fork branches through the same
  `TemporalGraph::replay_checkpoint` path used by restore. It proves fork
  validates any cached base before recording a branch, keeps the branch thin
  until ordinary materialization, checks the materialized branch with
  `graph.replay`, rejects corrupt branch caches, evicts them back to thin replay,
  and feeds the observed mismatch into the existing replay-oracle bisection API
  to localize the first differing fork decision.
- [x] **T-ADV-5** Implement the two restore strategies (replay-from-seed as the
  always-correct oracle; snapshot-restore as the validatable fast cache) and the
  oracle check that makes snapshot bugs visible, with divergence localization. —
  satisfies [ADV-10], [ADV-11]; spec §22.4; cross-ref 07 §6.
  Completed by `checks.crucible.phase6.restoreStrategies`: the temporal graph
  now has a phase6 gate proving thin replay remains the source-of-truth DAG node,
  fat checkpoint materialization is admitted only after `replay_checkpoint`, exact
  snapshot restore agrees with replay-from-seed, and corrupt cached snapshots
  are rejected by the `instantiate` restore path before being evicted back to
  thin replay. The gate feeds the observed `ReplayOracleMismatch` into the
  replay-oracle bisection API and asserts the first differing decision is
  localized for the fat/thin disagreement.
- [x] **T-ADV-6** Implement the savevm-completeness hedge (keep unreliable-snapshot
  checkpoints thin; degrade to slow replay, never to wrong) and wire save as a
  fat-checkpoint materialize keyed by config.id with thin-as-source-of-truth. —
  satisfies [ADV-12], [ADV-13]; spec §22.4; cross-ref 07 §4, 30.
  Completed by `checks.crucible.phase6.savevmCompleteness`: the savevm hedge
  gate proves device-marked unreliable snapshots are evicted to thin checkpoints
  and still replay through `instantiate`, global thin-replay fallback evicts hot
  fat caches without changing runtime identity, and the user-facing `save` path
  persists a fat checkpoint keyed by the configuration id while retaining the
  thin source-of-truth DAG node.
- [x] **T-ADV-7** Implement state-space search as systematic frontier expansion of
  the temporal graph (enumerate genuine `Decision`s, step each child, dedup by
  content address), realizing each frontier node via `instantiate` from the
  cheapest cached ancestor under the materialization budget. — satisfies [ADV-14],
  [ADV-15], [ADV-16]; spec §22.5.1; cross-ref 05 §3/§9, 07 §1.
  Completed by `checks.crucible.phase6.stateSpaceSearch`: graph search now
  realizes the frontier through the same `resume`/`instantiate` path used by
  fork and restore, reports that runtime in `TemporalGraphSearch`, enumerates
  closed-taxonomy choices from the realized runtime frontier, excludes
  deterministic delivery orders and control-plane decisions from search branching,
  deduplicates children by content-addressed configuration id, marks
  already-recorded reruns, keeps cold children thin, and materializes only hot
  explored children admitted by the materialization budget.
- [x] **T-ADV-8** Implement pluggable, deterministic search strategies (BFS, DFS,
  priority, coverage-guided) with content-address-tie-broken ordering; prove the
  explored graph and discovered failures are identical for identical
  (scenario, seed, budget). — satisfies [ADV-17], [ADV-18]; spec §22.5.2.
  Completed by `checks.crucible.phase6.searchStrategies`: strategy-driven search
  now expands the temporal graph through the existing single-frontier search API,
  supports breadth-first, depth-first, seeded priority, and coverage-guided
  frontier ordering, breaks every strategy tie by configuration content address,
  records deterministic expansion order plus reached graph and failure reports,
  and proves same-input reproducibility plus complete-budget graph equivalence in
  the `gate_search_strategies` Rust target, with graph-level reductions deferred
  to T-ADV-9.
- [x] **T-ADV-9** Implement symmetry reduction and partial-order reduction as
  sound graph-level node-deduplication over the content-addressed DAG (07 §9),
  explicitly not a model checker / spec-language evaluator (NG-3). — satisfies
  [ADV-19], [ADV-20]; spec §22.5.3; cross-ref 07 §9, 08.
  Completed by `checks.crucible.phase6.searchReductions`: reduced strategy
  search now admits an explicit `FrontierReductionPolicy`, applies the existing
  single-frontier graph reductions while preserving content-addressed
  configuration identities, records canonical partial-order representatives on
  demand before covering non-canonical interleavings, re-queues recorded
  representatives so strategy order does not decide reachability, finds
  symmetry representatives at graph scope outside the current candidate set via
  canonical relabeling keys, and gates the behavior as DAG node deduplication
  rather than model checking or spec-language evaluation.
- [x] **T-ADV-10** Consume black-box basic-block coverage from the plugin TCG-exec
  hook (12 §12.8) as a registration-time opt-in with zero fingerprint effect,
  working on any binary with no guest instrumentation. — satisfies [ADV-21]; spec
  §22.6.1; cross-ref 12 §12.8.
  Completed by `checks.crucible.phase6.basicBlockCoverage`: the engine exposes
  a registration-time `BasicBlockCoverageConfig` that defaults off, creates no
  engine coverage consumer in off mode, rejects invalid enabled maps, and
  produces a consumer token only for enabled coverage. The plugin coverage model
  converts validated TCG-exec observations into protocol payloads, and the QEMU
  host bridge maps modeled `(icount, guest_pc, block_len, map_index)` payloads into
  black-box `ObservableEvent::coverage_block` entries with no guest source,
  symbols, or in-guest agent. The gate proves the modeled event is sourced from
  the external execution trace surface, remains observational in the unified
  event log, is excluded from the determinism comparison, and compares modeled
  coverage-off and coverage-on single-VM fingerprint streams. The production
  plugin now owns stock QEMU TB translation/execution/flush callbacks and exact
  TB-entry icount observation, with Rust callback-model and executable C ABI
  evidence. Its bounded callback sink is now connected through the ABI-v2 per-VM
  SPSC transport: the host drains it at quantum completion, validates the record
  and boundary, and the generic `SimulationBackend`/`BackendQuantumLoop` path
  appends the observation to the scheduler log before the session actor publishes
  that same canonical entry. Shutdown returns any final drained entries through
  the same dense-sequence admission path before the actor publishes the stopped
  state. No QEMU-local observation collection survives the boundary as a
  parallel record. The production loaded-QEMU gate runs an uninstrumented
  standalone multiboot guest to the same exact icount with coverage off and on.
  The enabled run observes live guest blocks, while the execution fingerprint,
  canonical causal log, and independent instruction/register/RR-cursor/
  writable-RAM/device-I/O trajectory remain identical. The disabled run
  installs no coverage callback, and both teardown triggers drain admitted
  callbacks before clean QEMU exit.
- [x] **T-ADV-11** Record coverage as observational `coverage` event-log entries
  (19) excluded from the determinism comparison, feeding search/fuzzing and the
  per-checkpoint coverage fingerprint; assert coverage never affects `reduce`. —
  satisfies [ADV-22], [ADV-23]; spec §22.6.2; cross-ref 19 §19.6.3, 07 §2.
  Completed by `checks.crucible.phase6.coverageFeedback`: the advanced gate now
  composes the phase-4 unified coverage projection with the phase-6 search
  strategy path, stamps checkpoints only from event-log coverage, proves
  `CoverageGuided` search reads those checkpoint coverage fingerprints, exposes
  the same projection fingerprint through the coverage-guided fuzzing feedback
  view that T-ADV-12 will sample from, and asserts distinct coverage logs change
  only the observation fingerprint while `reduce(def, schedule)` and causal
  event-log determinism remain unchanged.
- [x] **T-ADV-12** Implement coverage-guided fuzzing: seeded sampling/mutation of
  the schedule (via `Decision::Override`) and fault plan over a `ScenarioFamily`
  (06 §7), pinning one concrete `ScenarioDef` per iteration, biased by the coverage
  projection. — satisfies [ADV-24], [ADV-25]; spec §22.7.1; cross-ref 06 §7, 05 §3,
  17.
  Completed by `checks.crucible.phase6.coverageGuidedFuzzing`: `ScenarioFamily`
  now exposes a seeded `fuzz_coverage_guided` pass that reads the T-ADV-11
  event-log coverage feedback view for the `CoverageGuidedFuzzing` consumer,
  deterministically samples one finite family parameter point per iteration,
  selects a deterministic in-memory corpus parent and energy, pins the sampled
  point to a concrete `ScenarioDef`, appends an explicit `Decision::Override`
  schedule mutation, and returns a coverage-biased candidate order plus first-seen
  coverage markers. The gate proves identical `(family, meta-seed, feedback,
  budget)` inputs reproduce the same mutants and choices, that generated
  candidates reduce as ordinary `(def, schedule)` configurations, and that
  fault-plan variation comes through the family density axis; durable DagStore
  corpus admission, pruning, persisted energy state, and throughput measurement
  were completed under the T-ADV-13 scope.
- [x] **T-ADV-13** Implement content-addressed corpus management (coverage-driven
  admission, seeded pruning/energy, each entry a reproduction artifact in the
  DagStore) and meet the fuzzing throughput target of 25 without weakening
  determinism or oracle validation. — satisfies [ADV-26], [ADV-27]; spec §22.7.2;
  cross-ref 07 §7, 25.
  Completed by `checks.crucible.phase6.coverageGuidedCorpus`: coverage-guided
  fuzzing now has a durable corpus mode that seeds a self-contained
  `ReproductionArtifact`, stores every retained corpus entry as compact canonical
  artifact bytes plus corpus-entry descriptors in the `DagStore`, chooses mutation
  parents by seeded persisted energy, admits only first-seen coverage fingerprints,
  deterministically prunes subsumed duplicate-coverage candidates, and reports
  deterministic generated mutant work units plus replay-oracle validation counts
  before claiming the local throughput target. The gate proves store-key/id
  equality for retained artifacts, descriptor persistence, artifact byte decoding
  and replay, stable same-seed corpus results, and no skipped replay validation for
  generated mutants; emitting this artifact form for every failure source remains
  the T-ADV-14 scope.
- [x] **T-ADV-14** Implement self-contained reproduction artifacts ((def, seed,
  schedule) reproducing bit-identically by replay alone, store-references optional)
  for every finding regardless of discovery path. — satisfies [ADV-28], [ADV-29];
  spec §22.8.1; cross-ref 06 §7.1, 23.
  Completed by `checks.crucible.phase6.reproductionArtifacts`: interesting
  findings now emit a `FindingReproductionArtifact` wrapper around the existing
  self-contained `(seed, scenario, schedule)` `ReproductionArtifact`, with explicit
  discovery-path tags for interactive forks, state-space search failures,
  coverage-guided fuzzing candidates, and retained corpus entries. Interactive
  forks and `CoverageGuidedFuzzIteration` expose path-specific emission hooks,
  state-space search records the artifact directly in each `SearchDiscoveredFailure`,
  retained corpus artifacts can be reloaded from the `DagStore`, and the gate
  proves the same configuration yields the same artifact id across
  interactive/search discovery, artifacts replay without stored snapshots or
  campaign/family handles, stored artifact bytes reload into the same replay
  evidence, retained corpus descriptor drift is rejected, and mismatched scenario
  forms are rejected explicitly.
- [x] **T-ADV-15** Implement the deterministic minimization (shrinking) pass that
  reduces the schedule/fault set while preserving the same failure (assertion fold
  predicate), with a seeded candidate order and per-candidate oracle/fingerprint
  validation, emitting a stable minimal artifact. — satisfies [ADV-30], [ADV-31];
  spec §22.8.2; cross-ref 18, 19.
  Completed by `checks.crucible.phase6.minimization`: `FindingReproductionArtifact`
  now exposes a deterministic `minimize` pass that enumerates shorter recorded
  schedule subsequences in shortest-first seeded content-address order, including
  candidates that remove recorded fault decisions; every candidate is captured and
  replayed as a self-contained artifact before the assertion-fold
  failure-fingerprint oracle can accept it; accepted candidates must preserve the
  original finding fingerprint; and the gate proves repeated same-seed runs produce
  the same shortest artifact while rejecting non-reproducing starts and stale
  public replay evidence.
- [x] **T-ADV-16** Implement and test the unifying view: assert fork/save/resume/
  replay/search/fuzz/minimize are all operations on the one temporal graph via the
  one `instantiate`, validated by the single replay-oracle + single-VM-fingerprint
  check, with no abstract spec engine and no second execution path. — satisfies
  [ADV-32]; spec §22.9; cross-ref 05 §9/§11, 07 §10.
  Completed by `checks.crucible.phase6.unifyingView`: `TemporalGraph` now exposes
  `validate_unified_operation`, which takes typed operation evidence, proves it
  carries an internally consistent operation output, records the named
  configuration in the graph, realizes it through the single `instantiate`
  entrypoint, checks the reduced state against the runtime state, materializes
  the runtime into a checkpoint, and validates it with the same replay-oracle
  path while reporting the single-VM fingerprint. The gate feeds that one report
  path with evidence from resume, fork, save, replay, state-space search,
  coverage-guided fuzzing, self-contained reproduction artifacts, and
  minimization, proves they all validate on the same temporal graph id, and
  rejects mismatched or forged operation evidence before graph admission.
- [ ] **T-ADV-17** Implement the `GuidanceSignal` abstraction with three built-in
  signals (coverage = the existing `CoverageGuided` behavior; novelty/rarity over a
  deterministically-maintained rarity table; assertion-proximity from the 18
  distance metric) and fixed-point deterministic composition (content-address
  tie-break); prove the default (coverage only, no adaptivity) reproduces the
  existing §22.5.2 behavior and that signals are readers-only (no fingerprint
  effect). — satisfies [ADV-34], [ADV-35]; spec §22.5.4; cross-ref §22.6, 07 §2, 18.
  Partial evidence from `checks.crucible.phase6.guidanceSignals`: the model exposes a
  `GuidanceSignal` trait with coverage, novelty/rarity, and assertion-proximity
  built-ins, fixed-point integer `GuidanceScore`s, deterministic sorted
  `GuidanceSignalComposition`, a coverage-only ordering key wired into the
  existing `SearchStrategy::CoverageGuided` checkpoint coverage key, and tests
  showing that attaching coverage feedback leaves checkpoint identity unchanged.
  Completion remains open on an owned, deterministically maintained rarity table;
  deriving proximity from the assertion-distance metric; applying composite
  scores and content-address tie-breaking to real search expansion; and proving
  that the integrated readers-only path cannot affect fingerprints.
- [ ] **T-ADV-18** Implement optional, off-by-default adaptive strategy selection
  (deterministic multi-armed bandit, default UCB) over a fixed ordered set of
  expansion arms with a deterministic reward model (new coverage, novelty gain,
  assertion-proximity progress, dominantly a confirmed failure; credited in
  content-address order) and a breadth-first fairness floor; prove the campaign is
  reproducible as a unit and that its config is hashed into the campaign identity
  while the reproduction artifact stays a bare (def, seed, schedule) bundle. —
  satisfies [ADV-36], [ADV-37], [ADV-38]; spec §22.5.4; cross-ref §22.5.3, §22.8.
  Partial evidence from `checks.crucible.phase6.adaptiveStrategies`: adaptive selection is
  represented by an off-by-default `AdaptiveStrategyConfig`, deterministic
  integer reward scoring over a fixed ordered arm set, content-address sorting of
  caller-supplied reward credits, graph-fingerprinted seeded exploration bonuses,
  a breadth-first fairness floor, and a campaign identity hash covering the
  signal/bandit configuration while leaving individual reproduction candidates as
  ordinary `(def, schedule)` configurations. Completion remains open on the
  required deterministic UCB default and integration with real campaign expansion,
  realized-graph reward credit, reduction, reproduction, and fairness behavior.
- [ ] **T-ADV-19** Add a determinism lint that bans `f64` on signal/bandit ordering
  paths (scores, weights, reward accumulation), enforcing fixed-point/integer
  arithmetic and fixed combination order. — satisfies [ADV-35]; spec §22.5.4;
  cross-ref [INV-9], `gate:harness-lint`.
  Partial evidence from `checks.crucible.phase6.guidanceDeterminismLint`: the guided
  exploration model exposes `lint_guidance_determinism_source`, and the gate proves
  `f64` score/reward source is rejected while fixed-point `u64` score source is
  accepted in synthetic inputs. Completion remains open on wiring a
  comment/string-aware scan of the actual signal and bandit ordering sources into
  `gate:harness-lint`, with mutation negatives that prove the real path is covered.
- [x] **T-ADV-20** Implement branching on `Decision::Preemption` (vCPU-switch +
  interrupt-timing) within the bounded [deadline, horizon] window — working for
  single-vCPU guests — with partial-order reduction over commuting preemptions and
  each preemption-branch child a content-addressed, oracle-validated temporal-graph
  node. — satisfies [ADV-39]; spec §22.5.5; cross-ref 05 §3, 08, 07 §6/§9.
  Completed by `checks.crucible.phase6.preemptionBranching`: `TemporalGraph`
  branches bounded `[deadline, horizon]` frontiers over both
  `Decision::Preemption` vCPU-switch and interrupt-timing decisions for
  single-vCPU guests. The gate proves commuting decisions on distinct nodes are
  collapsed by the explicit partial-order independence policy to the stable
  content-addressed canonical schedule. Every explored child and each unique
  representative of a covered child is materialized through the same
  replay-oracle-checked fat checkpoint path, and the gate verifies their
  content addresses and replay evidence.
- [ ] **T-ADV-21** Implement optional, additive exploration of app-controlled
  randomness (`Decision::AppRandom`, 16/05) as a mutation/branch dimension over
  served values, bounded by the per-scenario draw cap and a per-draw seeded
  value-sampling budget, recording each alternative as a `Decision`; prove a
  scenario with no app-random draws explores identically to before. — satisfies
  [ADV-40]; spec §22.5.6; cross-ref 16, 05 §3.
  Partial evidence from `checks.crucible.phase6.appRandomBranching`: `TemporalGraph` now
  branches over seeded `Decision::AppRandom` served values for caller-supplied draw
  sites, returns no children when a scenario has no app-random draw sites, preserves
  the existing graph in that no-draw case, and relies on `try_step`/`reduce` to
  enforce the per-scenario app-random draw cap for every sampled alternative.
  Completion remains open on deriving sites from recorded observations rather
  than caller-supplied data, validating a bounded per-draw sampling budget, and
  proving no-draw equivalence through the integrated exploration driver.
