# 36 — Time-travel and source-level debugging

This file specifies Crucible's **time-travel + source-level debugging**: the
operator-facing capability to attach a debugger to a node at a precise virtual-time
coordinate, inspect its architectural and source-level state, and move that node —
or the whole world — *backward and forward* through deterministic virtual time, all
without weakening the determinism contract.

The single most important thing to say about this capability is what it is **not**:
it is **not a new execution path, a new state representation, or a new clock**. It
is a *projection* of the substrate this RFC already builds — the checkpoint DAG
(07), the `instantiate`/replay machinery (05, 10), the fork operation (22), the QMP
control channel (10 §10.4), and the unified event log (19) — onto the vocabulary an
operator with a debugger expects. Every debugging operation in this file decomposes
into operations the session control plane (20) and the execution model (05) already
define; the only genuinely new rule is the one that fences off **non-canonical
mutation** (§36.5). Everything else is an arrangement of existing parts.

Requirement IDs in this file use the prefix `DBG` (see
[`00-conventions.md`](00-conventions.md)). The canonical gates this file is bound by
are defined in [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md):
`gate:replay-oracle`, `gate:e2e-determinism`, `gate:control-responsive`,
`gate:layer0-determinism`, and `gate:divergence-bisect`. This file is a *consumer*
of the layers below it and introduces no second execution path ([ADV-2], 05
[EXEC-14]).

Forward and cross references: the execution model is
[`05-execution-model.md`](05-execution-model.md); the checkpoint DAG and the
ancestor-replay branch of `instantiate` are
[`07-temporal-graph.md`](07-temporal-graph.md) §4; host-side QEMU integration,
the three channels, and QMP are [`10-qemu-integration.md`](10-qemu-integration.md);
the conditions/triggers/breakpoint vocabulary is
[`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md); the unified
event log (the divergence/failure/coordinate source) is
[`19-observability-event-log.md`](19-observability-event-log.md); the session actor,
breakpoints, step modes, and control-operation determinism are
[`20-session-control-plane.md`](20-session-control-plane.md); fork and the
detach-to-live-debug scope note are
[`22-advanced-features.md`](22-advanced-features.md) §22.3.1 [ADV-33]; the CLI
surface this file extends is [`23-cli.md`](23-cli.md); the spikes this file depends
on are [`30-risks-spikes.md`](30-risks-spikes.md).

The code blocks in this file are illustrative sketches per
[`00-conventions.md`](00-conventions.md) ("Code sketches in this RFC"): they show
intended types and call order so the spec is concrete, but the authoritative
statement is always the prose requirement. A sketch that disagrees with a
requirement is a defect in the sketch.

---

## 36.1 The capability, in one paragraph, and what it is built on

A Crucible debug session is an ordinary session (20) instantiated at a checkpoint
configuration (05 §5), with one extra out-of-band channel opened to the node's QEMU
child: **QEMU's gdbstub**, proxied to an operator's gdb-protocol client. Crucible
serves the *machine* (registers, memory, the vCPU set, the virtual-time coordinate)
and the *time machine* (goto / reverse-step / reverse-continue, realized as
restore-nearest-checkpoint-then-replay); the gdb-protocol client plus the
operator-supplied DWARF do the *source mapping* (function names, line numbers, local
variables). Crucible ships **no symbol server** and resolves no DWARF itself
(§36.7). Read-only inspection is the default and is determinism-preserving down to
the byte. Before the operator can mutate guest-visible state or take execution
under their own control, they must explicitly create a clearly-marked
**non-canonical debug branch** with `fork-debug` (§36.5); otherwise the operation is
rejected and the canonical run is never touched.

The capability is, deliberately, an assembly of five existing mechanisms:

```text
  debugging primitive              built on (this RFC)
  ─────────────────────────────    ──────────────────────────────────────────────
  attach at a coordinate           instantiate(checkpoint config)            05 §5, 10 §10.5
  inspect (regs/mem/backtrace)     QMP introspection + gdbstub read packets  10 §10.4
  breakpoint (canonical)           17a Condition breakpoint (out-of-band)    17a, 20 §6
  go to icount / virtual time T    restore ≤T checkpoint + replay to T       07 §4, 05 §5
  reverse step / reverse continue  the SAME goto, to an earlier coordinate   07 §4, 19 §19.6.2
  mutate / take control            fork a NON-CANONICAL debug branch         22 §22.3, 20 §8
```

- **[DBG-1]** Time-travel and source-level debugging MUST be implemented entirely as
  a projection of the existing substrate — the checkpoint DAG (07), `instantiate`
  and its ancestor-replay branch (05 §5, 07 §4), the fork operation (22 §22.3), the
  QMP control channel (10 §10.4), the breakpoint vocabulary (17a, 20 §6), and the
  unified event log (19) — and MUST NOT introduce a new execution path, a new state
  representation outside `(ScenarioDef, Schedule)` (05 [EXEC-25]), a separate reverse
  engine, or a clock other than virtual time (icount, 09). *Gate:*
  `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:* §36.1; cross-ref 05
  [EXEC-14], [ADV-2].

- **[DBG-2]** Crucible's debugger surface MUST be **CLI plus a gdb-protocol stub
  only**. A graphical/web debugging UI is out of scope ([NG-4]); this file specifies
  the operator-facing capability as the `crucible debug` subcommand (§36.6) and the
  proxied gdbstub channel (§36.2), nothing more. *Gate:* `gate:control-responsive`.
  *Spec:* §36.1; cross-ref [NG-4], 23.

- **[DBG-3]** Crucible MUST serve, over the debug surface, the **machine** (the
  architectural state of a node's vCPU set and its memory and device state, via QMP
  introspection and the gdbstub) and the **virtual-time coordinate** (the node's
  icount and the world's virtual time, 09); it MUST NOT serve **source mapping**.
  DWARF resolution — functions, lines, types, locals — is performed by the
  operator's gdb-protocol client against operator-supplied debug info. Crucible
  ships no symbol server (§36.7). *Gate:* `gate:control-responsive`. *Spec:* §36.1,
  §36.7.

---

## 36.2 Attach: the gdbstub as a fourth out-of-band logical plane

### 36.2.1 An attach is an instantiate

To attach a debugger, Crucible does exactly what every other realization does: it
`instantiate`s a configuration (05 §5). The operator names a coordinate (§36.6); the
session resolves it to a checkpoint configuration in the temporal graph (07); the
node's QEMU child is brought up at that configuration via the priority-ordered
`instantiate` branches (loadvm an exact fat snapshot, else replay from the nearest
fat ancestor, else baked-genesis-load-plus-replay — 10 §10.5). The result is a live,
controllable runtime sitting at a precise `(def, schedule)` / icount coordinate,
indistinguishable from any other instantiated runtime — because it *is* one.

- **[DBG-4]** A debug attach MUST be an `instantiate` (05 §5) of the checkpoint
  configuration the operator's coordinate resolves to (§36.6), realized by the same
  priority-ordered branches as any other realization (exact-snapshot loadvm,
  ancestor-replay, baked-genesis-plus-replay — 10 §10.5). The attached runtime MUST
  be an ordinary instantiated runtime distinguished only by its configuration; there
  MUST be no debug-specific realization path. *Gate:* `gate:replay-oracle`. *Spec:*
  §36.2.1; cross-ref 05 §5, 10 §10.5.

### 36.2.2 The gdbstub is the fourth logical plane

A VM node owns three logical channel roles to its QEMU child (10 §10.3): the plugin-IPC
control plane (handshake/teardown only), the shared-memory data plane including its
futex/eventfd wake objects (the per-quantum hot path), and the QMP plane (out-of-band
machine control). When a debug session is active, the node opens a **fourth,
out-of-band logical plane: QEMU's gdbstub**, alongside the other three. This is a
protocol-role count, not a count of kernel objects. Like QMP, it is strictly
out-of-band: it carries **no per-quantum
timing and no frame data**, it never participates in the advance/delivery hot path,
and it is silent with respect to the scheduler's total order. It carries debugger
read/write/breakpoint/step packets between the operator's gdb-protocol client and
the node's machine, and nothing else.

```text
  the logical planes a node owns to its QEMU child (10 §10.3, extended here):
  ──────────────────────────────────────────────────────────────────────────────
  1. plugin-IPC control  handshake + Quit only            (silent during a run)  14
  2. shared-memory data  ceiling/clock/frame rings + futex/eventfd wake objects  13
  3. QMP                 out-of-band machine control: savevm/loadvm/quit         10 §10.4
  4. gdbstub (DEBUG)     out-of-band debugger packets: read/write/bp/step        THIS FILE
                         carries NO per-quantum timing, NO frame data, NO order  ([SHM-2])
```

Crucible mediates the gdbstub through the standalone GPL-2.0-only
`crucible-debug-gateway` process. The gateway terminates QEMU's private RSP socket
and presents the stable gdb-protocol endpoint that the operator points a client at
(`--gdb-listen`, §36.9). The Apache controller speaks to the gateway only through
the owned-byte, versioned Unix-socket protocol in `crucible-protocol`; it neither
links the gateway nor handles QEMU-private objects. Mediation is what lets Crucible
enforce the read-only/mutation boundary (§36.3, §36.5), keep one GDB connection
alive while a QEMU runtime is replaced (§36.9.1), and serve time-travel verbs
(§36.4) that a raw gdbstub has no concept of.

- **[DBG-5]** When a debug session is active, the node MUST open a **fourth,
  out-of-band logical plane** — QEMU's gdbstub — alongside the three roles of
  10 §10.3 (plugin-IPC control, shared-memory data plus futex/eventfd wakes,
  QMP). The gdbstub channel MUST carry **no
  per-quantum timing and no frame data** ([SHM-2], [PROTO-1]); it MUST NOT
  participate in the advance/delivery hot path or the scheduler's total order, and
  it MUST be active only while a debug session is attached. *Gate:*
  `gate:control-responsive`, `gate:layer0-determinism`. *Spec:* §36.2.2; cross-ref
  10 §10.3, [SHM-2].

- **[DBG-6]** Crucible MUST **mediate** the gdbstub channel rather than expose the
  raw QEMU gdbstub directly. The separate GPL-side debugger gateway MUST terminate
  QEMU's private RSP socket and present the stable operator endpoint; the Apache
  controller MUST communicate with that gateway only through the versioned
  `crucible-protocol` Unix-socket boundary. The gateway and controller MUST remain
  separate processes and MUST NOT exchange QEMU structures, native pointers, or
  callback tables. The operator connects an ordinary gdb-protocol client to the
  gateway endpoint. *Gate:* `gate:control-responsive`, `gate:license-boundary`.
  *Spec:* §36.2.2, §36.9.1; cross-ref 37.

- **[DBG-7]** A node MAY expose **more than one vCPU** to the debugger as distinct
  gdb threads (§36.8): Crucible's single-threaded round-robin TCG with `-icount`
  makes a multi-vCPU node deterministic, and each vCPU is presented to the
  gdb-protocol client as a thread. Reads, breakpoints, and time-travel landings MUST
  be coherent across all of a node's vCPUs (§36.8). *Gate:*
  `gate:layer0-determinism`. *Spec:* §36.2.2, §36.8.

---

## 36.3 Read-only inspection preserves determinism, byte-for-byte

### 36.3.1 Reads append nothing causal and advance no virtual time

The first-class debugging mode is **read-only**, and read-only inspection is
*exactly* determinism-preserving. Reading registers, memory, a backtrace, a thread
list, or a watchpoint value MUST NOT append any **causal** entry to the event log
(19 §19.3), MUST NOT mutate the configuration (05 §2), and MUST NOT advance virtual
time outside the deterministic step machinery (the scheduler, 08, driven through
Crucible's own step/reverse-step). The operative guarantee is the same one the live
control plane already gives for observation (20 [SESS-22], 19 [OBS-24]), stated here
for the debugger: the **canonical causal subsequence of the event log (19 §19.5)
MUST be byte-identical whether or not a read-only debugger is attached.**

A debugger attach, a thousand register reads, a backtrace walk, and a detach MUST
leave a causal subsequence indistinguishable from a run that was never debugged.
Observational entries (a `diagnostic` marking "debugger attached") MAY appear — they
are excluded from the determinism comparison by construction (19 [OBS-22]) — but no
causal entry, no decision, and no virtual-time advance is permitted as a side effect
of a read.

- **[DBG-8]** Read-only inspection (register reads, memory reads, backtrace/stack
  walk, thread/vCPU enumeration, watchpoint value reads) MUST NOT append any
  **causal** entry to the event log (19 §19.3), MUST NOT mutate the `Configuration`
  (05 §2), and MUST NOT advance virtual time except through Crucible's deterministic
  step machinery (08). *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:*
  §36.3.1; cross-ref 19 §19.5, 20 [SESS-22].

- **[DBG-9]** The **canonical causal subsequence** of the event log (19 §19.5) MUST
  be **byte-identical** whether or not a read-only debugger is attached: a run
  debugged read-only (attach, inspect arbitrarily, detach) and the same run never
  debugged MUST produce identical causal subsequences under the canonical
  serialization (19 §19.4). Any read-only debugger operation that changes the causal
  subsequence is a determinism defect and MUST fail the gate ([INV-10]), never be
  smoothed over. *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:*
  §36.3.1; cross-ref 19 [OBS-21], [OBS-24].

- **[DBG-10]** A debugger attach, the inspection traffic during a session, and a
  detach MUST be recordable only as **observational** entries (19 §19.3, e.g. a
  `diagnostic` kind) so that enabling debugging never moves the gate (19 [OBS-22]).
  The session MUST NOT record any read as a `Decision` (05 §3) or a control-log
  entry (20 §8), because a read changes no scheduler-owned state. *Gate:*
  `gate:e2e-determinism`. *Spec:* §36.3.1; cross-ref 19 §19.3, 20 §8.

### 36.3.2 Canonical breakpoints are hardware/out-of-band — never trap-instruction patching

A debugger breakpoint that works by **patching a trap instruction into guest
memory** (the classic software breakpoint) *mutates guest-visible state*. On a
**canonical** attach — one that intends to leave the canonical run bit-identical —
that is forbidden, because the byte it overwrites is part of `S`/`T` and would change
the causal subsequence (and, worse, would be a guest-memory mutation that — per
§36.5 — must fork a non-canonical branch). Crucible therefore requires that a
breakpoint honored on a **canonical** attach be realized **out-of-band**, without
writing guest-visible memory: as a **hardware/out-of-band breakpoint** in exactly
the sense Crucible's own 17a `Condition` breakpoints already are (20 §6) — predicates
evaluated by the engine/plugin over the event log and the machine state at
deterministic evaluation points ([TRIG-16]), or QEMU hardware debug registers /
gdbstub hardware breakpoints that the CPU model traps without a memory write.

A breakpoint that is **realizable only by writing guest memory** (a software trap on
an architecture or address where no hardware/out-of-band mechanism is available)
MUST be **refused** on a canonical attach, with a clear, typed error telling the
operator the breakpoint cannot be set without first authorizing mutation and issuing
`fork-debug` (`--allow-mutate`, §36.5, §36.6). It is never silently downgraded to a
memory patch or used as an implicit fork trigger.

```text
  breakpoint on a CANONICAL attach (read-only intent):
  ──────────────────────────────────────────────────────────────────────────────
  ALLOWED  out-of-band:  - a 17a Condition breakpoint (engine/plugin predicate, 20 §6)
                         - a QEMU hardware breakpoint / debug register (CPU traps it)
                         → NO guest-visible memory write; canonical run byte-identical
  REFUSED  software trap-instruction patch into guest memory
                         → would mutate S/T; would have to fork (§36.5)
                         → typed error: "set --allow-mutate, then run fork-debug"
```

- **[DBG-11]** A breakpoint honored on a **canonical** debug attach MUST be realized
  **without mutating guest-visible memory**: as an out-of-band breakpoint in the same
  sense as Crucible's 17a `Condition` breakpoints (20 §6) — an engine/plugin
  predicate evaluated at deterministic evaluation points ([TRIG-16]), or a QEMU
  hardware breakpoint / debug-register trap that the CPU model honors without a
  memory write. A canonical breakpoint MUST NOT be implemented by patching a trap
  instruction into guest memory. *Gate:* `gate:e2e-determinism`,
  `gate:replay-oracle`, `gate:layer0-determinism`. *Spec:* §36.3.2; cross-ref 20 §6,
  17a §17a.2.

- **[DBG-12]** A breakpoint that is realizable **only** by writing guest-visible
  memory (no hardware/out-of-band mechanism is available for that architecture or
  address) MUST be **refused** on a canonical attach, with a clear typed error that
  names the limitation and directs the operator to `--allow-mutate` (§36.5, §36.6).
  It MUST NOT be silently downgraded to a guest-memory patch. *Gate:*
  `gate:e2e-determinism`. *Spec:* §36.3.2, §36.5; cross-ref §36.6.

- **[DBG-13]** A gdb-protocol client's request to set a *software* breakpoint on a
  canonical attach MUST be transparently satisfied by the out-of-band mechanism of
  [DBG-11] where one is available (so an unmodified gdb-protocol client "just works"
  without knowing the breakpoint is hardware/out-of-band), and refused per [DBG-12]
  where none is. The session MUST NOT translate a client software-breakpoint request
  into a guest-memory write on a canonical attach. *Gate:* `gate:e2e-determinism`.
  *Spec:* §36.3.2.

---

## 36.4 Reverse and time-travel: goto is restore-nearest-then-replay

### 36.4.1 There is no reverse engine — only restore + deterministic replay

Time-travel in Crucible is **not** a recorded undo log, an inverse-execution engine,
or a snapshot-of-every-instruction. "Go to icount / virtual time `T`" is **exactly**
the ancestor-replay branch of `instantiate` (05 §5, 07 §4) aimed at a target
coordinate: **restore the nearest checkpoint at a coordinate `≤ T`, then
deterministically replay forward to `T`.** Because replay is bit-exact and
host-independent (Contract A/B, 04; the replay oracle, [INV-2]), the state at `T` is
the same on every host, in any process, whether reached by going forward in the
first place or by "rewinding" to it later. Reverse inherits the replay-oracle
guarantee for free: a rewound coordinate is the *same configuration*, identified by
content address, as the forward one.

```text
  goto(T)  ==  instantiate( the checkpoint config whose coordinate ≤ T that is
                            nearest to T )   then   replay forward to exactly T
           ==  the ancestor-replay branch of instantiate (05 §5, 07 §4),
               aimed at a target coordinate instead of the tip.

  no separate reverse engine · no per-instruction undo log · host-independent ·
  inherits the replay-oracle guarantee ([INV-2]): goto(T) is the SAME config as
  having run forward to T (content-addressed, 05 [EXEC-26]).
```

- **[DBG-14]** "Go to icount / virtual time `T`" (forward or backward) MUST be
  realized as **restore-nearest-checkpoint-at-coordinate-`≤ T`-then-replay-to-`T`** —
  the ancestor-replay branch of `instantiate` (05 §5, 07 §4) aimed at a target
  coordinate rather than the tip. Crucible MUST NOT implement a separate reverse
  engine, a per-instruction undo log, or any reverse mechanism outside `instantiate`
  + deterministic replay. *Gate:* `gate:replay-oracle`. *Spec:* §36.4.1; cross-ref
  05 §5, 07 §4.

- **[DBG-15]** A coordinate reached by `goto` MUST be **exact and host-independent**
  and MUST be the **same configuration** (content address, 05 [EXEC-26]) as the one
  reached by running forward to that coordinate: `goto` inherits the replay-oracle
  guarantee ([INV-2]) with no additional correctness obligation. A `goto` whose
  realization disagrees with the forward derivation MUST be localized by divergence
  bisection (24), never silently accepted ([INV-10]). *Gate:* `gate:replay-oracle`,
  `gate:divergence-bisect`. *Spec:* §36.4.1; cross-ref 05 [EXEC-26], [INV-2].

### 36.4.2 Reverse-step grains mirror the forward StepMode set

A reverse step is a `goto` to an earlier coordinate computed from the current one and
a **grain**. The reverse grains MUST mirror the forward `StepMode` set the session
already defines (20 §4.3) — *instruction*, *quantum*, *event*, *assertion*, *timer*
— so that "reverse-step over an event" is the mirror of "step over an event," landing
at the previous coordinate of the same grain. Each reverse grain resolves, against
the event log (19) and the scheduler's deterministic structure (08), to a precise
earlier coordinate, and `goto` then realizes it.

`reverse-continue to a 17a Condition` (the mirror of continue-to-breakpoint) MUST be
realized as: **find the latest event-log coordinate `≤` the current coordinate at
which the predicate held**, then `goto` it. The search is a backward scan of the
totally-ordered, icount-stamped event log (19) for the most recent point satisfying
the shared 17a `Condition` vocabulary (17a §17a.2, the same predicates used by
triggers, assertions, and forward breakpoints), evaluated over the log prefix — a
pure function of the log, never a re-execution that could perturb anything.

```text
  forward (20 §4.3)            reverse (this file)
  ──────────────────────       ─────────────────────────────────────────────────
  step instruction             reverse-step instruction  → goto(prev instruction coord)
  step quantum                 reverse-step quantum       → goto(prev quantum boundary)
  step event                   reverse-step event         → goto(prev cross-node event)
  step assertion               reverse-step assertion     → goto(prev assertion change)
  step timer                   reverse-step timer         → goto(prev timer fire)
  continue → breakpoint        reverse-continue → 17a Cond → goto(latest coord ≤ now
                                                              where the predicate held)
```

- **[DBG-16]** Reverse-step grains MUST mirror the forward `StepMode` set (20 §4.3):
  *instruction*, *quantum*, *event*, *assertion*, and *timer*. A reverse step MUST
  resolve its grain to a precise earlier coordinate (against the event log, 19, and
  the scheduler structure, 08) and realize it by `goto` ([DBG-14]). A reverse step of
  a given grain MUST land at the same coordinate as the forward step of that grain
  would have reached arriving at the current coordinate. *Gate:* `gate:replay-oracle`,
  `gate:control-responsive`. *Spec:* §36.4.2; cross-ref 20 §4.3.

- **[DBG-17]** `reverse-continue` to a 17a `Condition` MUST be realized as: find the
  **latest event-log coordinate `≤` the current coordinate at which the predicate
  held** — a backward scan of the totally-ordered, icount-stamped event log (19)
  evaluating the shared 17a `Condition` vocabulary (17a §17a.2) over the log prefix
  — then `goto` that coordinate ([DBG-14]). The predicate evaluation MUST be a pure
  function of the log prefix (17a [TRIG-16], 20 [SESS-15]) and MUST NOT re-execute or
  perturb the run. If no such coordinate exists at or before the current one,
  reverse-continue MUST land at genesis (or report no-match), never run backward past
  the start. *Gate:* `gate:replay-oracle`, `gate:control-responsive`. *Spec:*
  §36.4.2; cross-ref 17a §17a.2, 19 §19.6.2.

### 36.4.3 Per-node and whole-world time travel

Two scopes of time travel are required, and both land **all of a node's vCPUs at the
same deterministic coordinate** (§36.8):

- **Per-node time travel** moves *one node* to an earlier (or later) coordinate **by
  its own icount**. Mechanically it is `goto` over that node's checkpoints; the other
  nodes are not re-instantiated. This is the common debugger workflow: rewind the
  node under the debugger to just before a fault.
- **Whole-world time travel** moves the **whole `Configuration` to an earlier
  prefix** — the entire multi-node world to a coordinate expressed as a **world
  virtual time or an event-sequence number**. This is realized by the *same machinery
  as a fork minus the divergent decisions*: `instantiate` the prefix configuration
  `(def, schedule[0..k])` (05 §6) that the world coordinate resolves to, landing every
  node at the world coordinate simultaneously. Where a fork then appends *different*
  decisions, whole-world time travel simply lands at the prefix and stops (a read-only
  rewind) — it is a fork that has not yet diverged.

```text
  per-node time travel    goto over ONE node's checkpoints, by that node's icount;
                          other nodes untouched; node's vCPUs land coherently (§36.8)

  whole-world time travel instantiate( (def, schedule[0..k]) )  (05 §6) — the world
                          prefix the coordinate (virtual time | event seq) resolves to;
                          EVERY node lands at the world coordinate simultaneously.
                          SAME realization as fork, minus the divergent decisions
                          (a fork that has not yet diverged).
```

- **[DBG-18]** Crucible MUST support **per-node time travel** — move one node to an
  earlier/later coordinate by *its own icount* via `goto` over that node's
  checkpoints, leaving other nodes un-re-instantiated — and **whole-world time
  travel** — move the whole `Configuration` to an earlier prefix
  `(def, schedule[0..k])` (05 §6) named by a **world virtual time or an event-sequence
  number**, the *same realization as a fork minus the divergent decisions*, landing
  every node at the world coordinate simultaneously. *Gate:* `gate:replay-oracle`.
  *Spec:* §36.4.3; cross-ref 05 §6, 22 §22.3.

- **[DBG-19]** Both per-node and whole-world time travel MUST land **all of a node's
  vCPUs at the same deterministic coordinate** (§36.8): a multi-vCPU node MUST never
  be left with its vCPUs straddling different icounts after a `goto`. A whole-world
  `goto` MUST land every node — and within each node every vCPU — at the resolved
  world coordinate. *Gate:* `gate:replay-oracle`, `gate:layer0-determinism`. *Spec:*
  §36.4.3, §36.8.

### 36.4.4 Opportunistic fat-checkpoint cadence bounds reverse latency

Reverse-step latency is dominated by the replay distance from the nearest fat
checkpoint at coordinate `≤ T` to `T` (07 §4): a thin region means a long replay. To
bound it while a debug session is attached, Crucible MAY **opportunistically
materialize fat checkpoints at a configurable cadence** (`--checkpoint-stride`,
§36.6) along the region the operator is stepping through, so a subsequent
reverse-step restores from a nearby fat checkpoint instead of replaying far. This is
**purely a performance optimization**: materializing or evicting a fat checkpoint is
always a cache decision that never changes a node's denoted state (07 [TEMP-14],
[TEMP-26], 05 [EXEC-30]), and eviction is always safe. Correctness never depends on
the cadence; only latency does.

- **[DBG-20]** Crucible MAY opportunistically materialize fat checkpoints at a
  configurable cadence (`--checkpoint-stride`, §36.6) while a debug session is
  attached, to bound reverse-step latency by shortening the replay distance from the
  nearest fat checkpoint (07 §4). This MUST be **performance-only**: it MUST be a
  cache decision that never changes any node's denoted state (07 [TEMP-14],
  [TEMP-26], 05 [EXEC-30]), eviction of an opportunistic fat checkpoint MUST always
  be safe, and debugging correctness MUST NOT depend on the cadence — only latency.
  Until the savevm-completeness spike (S3, 30 §30.4) is green, opportunistic
  checkpoints MUST default to thin/replay (§36.9). *Gate:* `gate:replay-oracle`.
  *Spec:* §36.4.4; cross-ref 07 §4, 30 §30.4.

---

## 36.5 The non-canonical debug branch: the one genuinely new rule

Everything above keeps the canonical run pristine. The **one genuinely new rule** in
this file is what happens when the operator stops merely *observing* and starts
*acting*: before the operator **mutates guest-visible state** (writes a register,
writes memory, sets a software/memory-patch breakpoint where one is required) **or
continues execution under their own control** (a free `continue`/step that the
canonical schedule did not prescribe), they must issue `fork-debug`. Until that
explicit operation completes, every mutation and free-control request is rejected.
The resulting clearly-marked non-canonical debug branch is the only mutable target,
and the **canonical run is never mutated.**

This is the third category of execution, distinct from both the canonical run and the
[ADV-33] escape hatch:

```text
  three categories of execution (this RFC):
  ──────────────────────────────────────────────────────────────────────────────
  1. canonical run            reduce(def, schedule); the deterministic backbone;
                              the replay oracle's truth (05, 19 §19.5).
  2. non-canonical debug      THIS FILE: created only by an explicit `fork-debug`
     branch                   before mutation or free control. STILL inside virtual time + the one
                              execution path; clearly marked; excluded from the
                              replay oracle; NOT a (seed,scenario,schedule) artifact.
  3. detach-to-live QEMU      [ADV-33]: free-running, host-wall-clock, determinism
     (FORBIDDEN here)         abandoned. A second execution path. Out of scope; only
                              ever a separate escape hatch on materialize-to-image.
```

### 36.5.1 The fork, and what marks it

A non-canonical debug branch is an ordinary fork (22 §22.3): `instantiate` of the
fork-point configuration followed by the operator's divergent actions. It is **inside
virtual time and the one execution path** — the guest still runs under TCG `-icount`,
the scheduler still owns the total order, there is no host-wall-clock free-run. That
is precisely what makes it the *third* category and **distinct from [ADV-33]'s
forbidden detach-to-free-running-QEMU**: [ADV-33] abandons the determinism contract
and is a second execution path; the non-canonical debug branch does neither.

Because the branch carries arbitrary operator edits, it is **excluded from the replay
oracle** (it has no thin derivation: an arbitrary register/memory write is not a
`reduce` of any schedule), is **not representable as a `(seed, scenario, schedule)`
artifact**, and MUST be **visibly distinguished** everywhere it can be seen: in the
temporal-graph view, in the event-log **fork marker** (19 §19.7 `fork`, flagged
non-canonical), and in the live mirror / status surface (20 §9).

- **[DBG-21]** Before the operator **mutates guest-visible state** (writes a register
  or memory, or sets a breakpoint that requires a guest-memory write, [DBG-12]) **or
  takes execution under their own control** (a `continue`/step the canonical schedule
  did not prescribe), they MUST successfully issue `fork-debug`. The session MUST
  reject such an action while attached to the canonical run and MUST NOT create a
  branch as an implicit side effect of the rejected request. `fork-debug` MUST create
  a clearly-marked non-canonical debug branch (22 §22.3), initially as a whole-world
  fork, and all subsequent mutable operations MUST target it. The
  canonical configuration and its causal subsequence MUST remain bit-identical to a
  never-debugged run ([DBG-9]). *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`.
  *Spec:* §36.5.1; cross-ref 22 §22.3, 20 §8.

- **[DBG-22]** A non-canonical debug branch MUST be **excluded from the replay
  oracle** (07 §6, [INV-2]): it carries arbitrary operator edits that are not a
  `reduce` of any schedule, so it has no thin derivation and MUST NOT be subjected to
  the fat==thin equality. It MUST NOT be representable as a `(seed, scenario,
  schedule)` reproduction artifact (06 §7.1, 23) and MUST NOT be model-reproducible.
  Excluding it MUST NOT weaken the oracle for canonical checkpoints. *Gate:*
  `gate:replay-oracle`. *Spec:* §36.5.1; cross-ref 07 §6, 06 §7.1.

- **[DBG-23]** A non-canonical debug branch MUST be **visibly distinguished**
  everywhere it is observable: in the temporal-graph view (07), via a **non-canonical
  flag on its `fork` event-log marker** (19 §19.7), and in the live mirror / status
  surface (20 §9). An operator (or a tool) MUST never confuse a non-canonical branch
  for the canonical run or for a reproducible fork. *Gate:* `gate:e2e-determinism`.
  *Spec:* §36.5.1; cross-ref 19 §19.7, 20 §9.

- **[DBG-24]** The non-canonical debug branch MUST remain **inside virtual time and
  the one execution path** (the guest runs under TCG `-icount`, the scheduler owns the
  total order; no host-wall-clock free-run), and is therefore **distinct from
  [ADV-33]'s forbidden detach-to-free-running-QEMU**, which abandons the determinism
  contract and would be a second execution path. [ADV-33] still stands: this file
  adds a **third category** (between the canonical run and the [ADV-33] escape hatch),
  not a relaxation of it. A capability that takes a checkpoint out of the
  deterministic world entirely remains out of scope and, if ever wanted, MUST be the
  separate `materialize-to-image` escape hatch of [ADV-33], never a mode of debug.
  *Gate:* `gate:e2e-determinism`. *Spec:* §36.5.1; cross-ref 22 §22.3.1, [ADV-33].

### 36.5.2 What is recordable vs what is a debug-edit script

Operator interventions split by whether the model can express them:

- An edit **expressible as a `Decision` or a control-log entry** (20 §8) — inject a
  fault, heal a fault, override a scheduling decision, a state-mutating `Action`
  breakpoint — is **recorded per 20 §8**, keyed by the virtual-time boundary at which
  it applies. Such a branch's *schedule-expressible* part is reproducible exactly as
  an interactively-controlled run is (20 [SESS-20]); it is the ordinary
  control-log-recorded case.
- An **arbitrary guest-state edit** (a raw register write, a memory poke, a
  memory-patch breakpoint) is **not** expressible as a `Decision`. It MUST be recorded
  as an **explicit debug-edit script hung off the fork point** — an ordered,
  human-readable record of the exact edits and the coordinates at which they were
  applied — so the branch is *re-derivable from the fork point plus the script* for
  the operator's own re-use, but it is **never model-reproducible** (it is not a
  `(seed, scenario, schedule)` artifact, [DBG-22]) and never enters the replay oracle.

```text
  operator edit on a non-canonical branch        recorded as
  ────────────────────────────────────────       ────────────────────────────────
  inject/heal fault, override a Decision,         a Decision / control-log entry
  state-mutating Action breakpoint                (20 §8) — schedule-expressible,
                                                  reproducible like an interactive run
  raw register write / memory poke /              a DEBUG-EDIT SCRIPT hung off the
  memory-patch breakpoint                         fork point — re-derivable for the
                                                  operator, NEVER model-reproducible
                                                  ([DBG-22]); never in the oracle
```

- **[DBG-25]** An operator edit on a non-canonical debug branch that is
  **expressible as a `Decision` / control-log entry** (inject/heal a fault, override
  a scheduling decision, a state-mutating `Action` breakpoint, 20 §8) MUST be
  recorded per 20 §8, keyed by the virtual-time boundary at which it applies, so its
  schedule-expressible part is reproducible exactly as an interactively-controlled run
  (20 [SESS-20]). *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:*
  §36.5.2; cross-ref 20 §8.

- **[DBG-26]** An **arbitrary guest-state edit** that is *not* expressible as a
  `Decision` (a raw register write, a memory poke, a memory-patch breakpoint) MUST be
  recorded as an **explicit debug-edit script hung off the fork point** — an ordered
  record of the exact edits and the coordinates at which they were applied — so the
  branch is re-derivable from the fork point plus the script for the operator's own
  use, but it MUST be **never model-reproducible** (not a `(seed, scenario, schedule)`
  artifact, [DBG-22]) and MUST never enter the replay oracle. *Gate:*
  `gate:replay-oracle`. *Spec:* §36.5.2; cross-ref [DBG-22], 20 §8.

---

## 36.6 The debug target resolver: event-log and triage integration

A debugger is most useful pointed at the moment a bug happened, and Crucible already
records every such moment in the one event log (19). The debug target resolver turns
a triage coordinate into a `goto` target. The operator names the coordinate one of
several ways, each resolving to a checkpoint configuration / virtual-time coordinate
the attach (§36.2) then realizes:

```text
  --at <icount|vtime>     a precise per-node icount or world virtual time (09)
  --at-event <seq>        the coordinate of event-log entry `seq` (19 §19.2)
  --at-failure            the first assertion-violation point (18, 19) — the bug
  --at-checkpoint <hash>  a checkpoint by content address (07)
```

`--at-failure` resolves to the **first assertion-violation point** recorded in the
event log (18, 19) — the single most common debugging entry point, the place the
property broke. A **divergence-bisection coordinate** `(node, icount, kind)` (24, the
output of `gate:divergence-bisect`) is directly usable as a `goto` target: the
bisector already pins a divergence to a precise icount-stamped event-log coordinate
(19 §19.6.2), which is exactly what the resolver consumes. Reverse-continue and the
bisecting resolver share this path, localizing any divergence by bisection before
handing the debugger a replay-oracle-checked coordinate.

And the loop closes with triage ergonomics: a **non-passing run's failure footer**
(the CLI's failure rendering, 23 §4) MUST print a **copy-pasteable
`crucible debug <artifact> --at-failure`** command, so a developer goes from "it
failed" to "I'm sitting in a debugger at the failure" in one paste — the debugging
analogue of the `crucible replay` repro command (23 [CLI-10]).

- **[DBG-27]** The debug target resolver MUST accept, and resolve to a checkpoint
  configuration / virtual-time coordinate the attach (§36.2) realizes: `--at
  <icount|vtime>` (a per-node icount or world virtual time, 09); `--at-event <seq>`
  (the coordinate of event-log entry `seq`, 19 §19.2); `--at-failure` (the **first
  assertion-violation point**, 18, 19); and `--at-checkpoint <hash>` (a checkpoint by
  content address, 07). *Gate:* `gate:control-responsive`, `gate:replay-oracle`.
  *Spec:* §36.6; cross-ref 19 §19.2, 18, 07.

- **[DBG-28]** A divergence-bisection coordinate `(node, icount, kind)` (24, 19
  §19.6.2) MUST be directly usable as a `goto`/attach target: because the bisector
  pins a divergence to a precise icount-stamped event-log coordinate ([OBS-28]), the
  resolver MUST consume it without translation. *Gate:* `gate:divergence-bisect`,
  `gate:replay-oracle`. *Spec:* §36.6; cross-ref 24, 19 §19.6.2.

- **[DBG-29]** A non-passing run's failure footer (23 §4) MUST print a
  copy-pasteable **`crucible debug <artifact> --at-failure`** command (the debugging
  analogue of the `crucible replay` repro command, 23 [CLI-10]), so an operator goes
  from a reported failure to an attached debugger at the failure point in one paste.
  *Gate:* `gate:e2e-determinism`. *Spec:* §36.6; cross-ref 23 §4, [CLI-10].

---

## 36.7 Scope note: Crucible ships no symbol server (DWARF is the operator's)

> **Scope note.** Crucible serves the *machine* and the *virtual-time coordinate*;
> it does **not** serve *source mapping*. There is no Crucible symbol server, no
> DWARF parser inside Crucible, and no built-in mapping from an icount/PC to a source
> file and line. Source-level debugging — functions, line numbers, types, locals,
> pretty-printing — is performed **entirely by the operator's gdb-protocol client**
> against **operator-supplied debug info** (the DWARF for the guest binaries the
> operator is debugging), over the proxied gdbstub channel (§36.2). Crucible's
> contribution is to put the gdb-protocol client at an exact, reproducible
> virtual-time coordinate with a coherent multi-vCPU machine view; everything
> source-level is the client's job with the operator's symbols. DWARF/source-mapping
> support inside Crucible is **out of scope for this RFC**.

- **[DBG-30]** Crucible MUST NOT ship a symbol server or perform DWARF/source
  resolution itself: source-level mapping (functions, lines, types, locals) MUST be
  performed by the operator's gdb-protocol client against operator-supplied debug
  info over the proxied gdbstub channel (§36.2). Crucible's responsibility ends at
  serving the machine and the virtual-time coordinate ([DBG-3]); DWARF/source-mapping
  inside Crucible is out of scope. *Gate:* `gate:control-responsive`. *Spec:* §36.7;
  cross-ref §36.1, §36.2.

---

## 36.8 Multi-vCPU debugging: vCPUs as gdb threads, landed at one coordinate

Multi-vCPU nodes are a goal of this RFC, made deterministic by **single-threaded
round-robin TCG with `-icount`**: the vCPUs of a node are scheduled in a fixed
round-robin under one instruction clock, so a multi-vCPU node's `T` is a pure
function of icount exactly as a single-vCPU node's is. Debugging is designed to be
multi-vCPU-aware on top of that determinism:

- A node's vCPUs are exposed to the gdb-protocol client as distinct **gdb threads**,
  so the operator can list them, select one, and read its registers/backtrace — the
  ordinary multi-threaded debugging experience, with each "thread" being a vCPU.
- **Whole-world and per-node time travel land all of a node's vCPUs at the same
  deterministic round-robin coordinate** ([DBG-19]): a `goto` MUST NOT leave a node's
  vCPUs straddling different icounts. The coordinate is the world/per-node coordinate
  the resolver (§36.6) produced, and every vCPU of the affected node(s) is at the
  state that coordinate denotes.
- Reads, canonical breakpoints, and reverse operations MUST be **coherent across all
  of a node's vCPUs**: a breakpoint on any vCPU, a memory read, and a backtrace all
  observe the single, consistent machine state at the landed coordinate.

- **[DBG-31]** A multi-vCPU node MUST expose each of its vCPUs to the gdb-protocol
  client as a distinct **gdb thread**; the node's determinism MUST rest on
  single-threaded round-robin TCG with `-icount` (so `T` is a pure function of
  icount). Listing, selecting, and reading a vCPU/thread MUST be ordinary read-only
  inspection ([DBG-8]). *Gate:* `gate:layer0-determinism`, `gate:control-responsive`.
  *Spec:* §36.8; cross-ref §36.2, §36.3.

- **[DBG-32]** Per-node and whole-world time travel MUST land **all of an affected
  node's vCPUs at the same deterministic coordinate** ([DBG-19]): a `goto` MUST NOT
  leave a node's vCPUs at different icounts, and a whole-world `goto` MUST land every
  node — and within each node every vCPU — at the resolved world coordinate. Reads,
  canonical breakpoints, and reverse operations MUST be coherent across a node's
  vCPUs (one consistent machine state at the landed coordinate). *Gate:*
  `gate:replay-oracle`, `gate:layer0-determinism`. *Spec:* §36.8; cross-ref §36.4.3.

---

## 36.9 The CLI surface and layering (also added to 23)

The operator front door is the `crucible debug` subcommand. Like every other
subcommand (23 [CLI-1]), it is a **thin wrapper**: it holds no debug state of its
own, and every verb decomposes into existing session operations (20 §4) plus the
gdbstub proxy (§36.2). These flags and verbs are specified here and **also added to
the CLI catalogue in [`23-cli.md`](23-cli.md)**.

```text
  crucible debug <artifact|savepoint|--session <addr>> [FLAGS]

  TARGET (choose one)
    <artifact>            a reproduction artifact (06 §7.1) to attach to
    <savepoint>           a savepoint / checkpoint hash (07)
    --session <addr>      attach to a running session via the daemon (21)

  COORDINATE (the resolver, §36.6)
    --at <icount|vtime>   attach at a per-node icount or world virtual time (09)
    --at-event <seq>      attach at the coordinate of event-log entry `seq` (19)
    --at-failure          attach at the first assertion-violation point (18, 19)
    --at-checkpoint <hash>  attach at a checkpoint by content address (07)

  DEBUG CONTROL
    --node <id>           which node to attach the gdbstub to (multi-vCPU as threads, §36.8)
    --gdb-listen <addr>   the gdb-protocol endpoint to listen on (§36.2)
    --read-only           inspection only; canonical run pristine (DEFAULT)
    --allow-mutate        authorize eligibility for explicit `fork-debug`; never forks implicitly (§36.5)
    --checkpoint-stride <n>  opportunistic fat-checkpoint cadence to bound reverse latency (§36.4.4)

  INTERACTIVE VERBS (over the session command set, 20 §4)
    attach-gdb            open/point the gdbstub channel at the current coordinate (§36.2)
    fork-debug            explicitly create a whole-world non-canonical branch (§36.5)
    goto <coord>          restore-nearest-then-replay to a coordinate (§36.4.1)
    reverse-step <grain>  reverse instruction|quantum|event|assertion|timer (§36.4.2)
    reverse-continue <Condition>  to the latest coord ≤ now where the predicate held (§36.4.2)
    exec -- <argv...>     run a noninteractive command through the guest agent (§36.9.3)
    pty [--columns N --rows N] -- <argv...>  bridge a guest PTY (§36.9.3)
    ssh                   bridge bytes to the agent's configured in-guest SSH server (§36.9.3)
```

`--read-only` is the **default**: an attach inspects and time-travels without ever
mutating the canonical run. `--allow-mutate` only authorizes the operator to invoke
`fork-debug`; it neither mutates nor forks by itself. Mutation and free run control
remain rejected until that explicit whole-world fork completes. Guest exec, PTY,
resize, and SSH-compatible channels additionally require the closed `shell`
capability and the current controller lease; `--allow-mutate` is never itself an
authorization credential. Each interactive verb
decomposes into existing session operations plus the gdbstub proxy: `attach-gdb` is
the channel of §36.2; `goto`/`reverse-step`/`reverse-continue` are `instantiate` of a
resolved coordinate (§36.4) driven through the session as ordinary, boundary-deferred
commands (20 §5); the CLI holds **no debug state**.

- **[DBG-33]** The CLI MUST expose `crucible debug <artifact|savepoint|--session>`
  with the coordinate flags (`--at`, `--at-event`, `--at-failure`, `--at-checkpoint`,
  §36.6), the debug-control flags (`--node`, `--gdb-listen`, `--read-only` *(the
  default)*, `--allow-mutate`, `--checkpoint-stride`), and the interactive verbs
  `attach-gdb`, `fork-debug`, `goto`, `reverse-step`, `reverse-continue`, `exec`,
  `pty`, and `ssh`. These MUST also be
  reflected in the CLI catalogue of [`23-cli.md`](23-cli.md). *Gate:*
  `gate:control-responsive`. *Spec:* §36.9; cross-ref 23, §36.6.

- **[DBG-34]** `--read-only` MUST be the default and MUST guarantee the canonical run
  stays bit-identical ([DBG-9]); `--allow-mutate` MUST grant eligibility for an
  explicit `fork-debug` but MUST NOT itself fork or mutate the canonical run. *Gate:*
  `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:* §36.9, §36.5.

- **[DBG-35]** `crucible debug` MUST be a thin wrapper holding **no debug state of
  its own** (23 [CLI-1], [CLI-2]): each flag and verb MUST decompose into existing
  session commands (20 §4) plus the gdbstub proxy (§36.2) — `attach-gdb` opens the
  fourth logical plane ([DBG-5]); `fork-debug` is the ordinary fork operation with
  non-canonical metadata (§36.5); `goto`/`reverse-step`/`reverse-continue` are
  `instantiate` of a resolved coordinate (§36.4) driven as ordinary boundary-deferred
  session commands (20 §5). A debug behavior with no corresponding session/proxy
  operation is a layering defect. *Gate:* `gate:control-responsive`. *Spec:* §36.9;
  cross-ref 23 [CLI-1], 20 §4/§5.

### 36.9.1 Stable GDB ownership and atomic runtime replacement

The debugger gateway, not the CLI and not an individual QEMU child, owns the
operator's GDB connection. Every QEMU child exposes a private Unix RSP socket to the
gateway. A `goto`, reverse-step, reverse-continue, or scenario fork therefore
replaces the backend behind one stable GDB connection instead of asking the
operator to reconnect.

Replacement is a two-phase transaction. The controller first instantiates and
replays a candidate world while the current world remains paused and usable. The
gateway connects to the candidate QEMU endpoint with bounded I/O, verifies a paused
stop reply, and replays acknowledged debugger state (thread selections and
hardware breakpoints). Only after the controller has verified the candidate's
configuration, checkpoint, node identity, and opaque gateway generation may the
gateway promote it. Any prepare, replay, or evidence failure aborts the candidate
and leaves the old runtime, graph, attach record, and GDB connection unchanged. A
post-promotion evidence mismatch is an unrecoverable failed lifecycle, never a
reason to pretend the old runtime is still selected.

Control-socket loss must not make transaction outcome unknowable. Prepare and
commit are idempotent, and every newly negotiated controller can query the active
and prepared endpoint/generation identities before retrying or reconciling. A lost
prepare acknowledgement leaves a discoverable candidate; a lost commit
acknowledgement permits the same generation to be committed again with the same
success result. Malformed, truncated, or disconnected control clients close only
their connection and never terminate the gateway or discard the active backend.

Production replacement is whole-world and proof-carrying. At each completed
scheduler boundary, the lifecycle samples every live node's execution fingerprint;
after the temporal graph materializes that boundary, the session seals those
samples to the exact `RuntimeState` identity, including its node-blob set,
instruction counters, scheduler state, and event-log offset. A replacement must
both reproduce that original live evidence and agree with an independently replayed
candidate before promotion. Coordinate equality alone is insufficient. If a lost
commit or abort acknowledgement leaves gateway ownership indeterminate, Crucible
quarantines every possibly selected whole-world or single-node candidate and
rejects further scheduler/debugger work until gateway process termination is
observed. Retiring the previous world revokes scheduler and gateway authority
immediately; cleanup reporting distinguishes observed reap from detached cleanup
whose process exit was not observed.

The gateway parses RSP as a bounded byte stream: acknowledgements, interrupts,
split packets, coalesced packets, asynchronous output, and stop packets are not
modeled as synchronous request/reply frames. Canonical policy is allow-by-exception.
Known read-only queries and acknowledged hardware breakpoints may reach QEMU;
memory/register writes, software breakpoints, monitor commands, process control,
file operations, watchpoints not explicitly supported, and unknown packets fail
closed. `continue`, `step`, and `vCont` are sent to the session scheduler rather
than directly to QEMU.

Scheduler run control permits one outstanding operator request. In RSP
acknowledgement mode, the gateway writes `+` before making that request visible to
the host, deduplicates retransmission, and binds the request to both a monotone
request ID and the operator-connection generation. Poll and completion are
idempotent across control-channel reconnects. Ctrl-C supersedes either a queued or
in-flight continue, while operator disconnect cancels the request without failing
the simulation session. Scheduler-produced stop packets retain their encoded bytes
until GDB acknowledges them; `-` retransmits the same packet and is never forwarded
to QEMU.

- **[DBG-41]** The standalone GPL debugger gateway MUST own one stable operator GDB
  connection across QEMU replacement. Replacement MUST use prepare/validate/hydrate
  then commit, with bounded I/O and the old backend retained until the candidate's
  paused state, replay oracle, node, endpoint, checkpoint, and gateway generation
  are verified. Failure before commit MUST preserve the previous runtime and
  debugger state atomically. Prepare and commit MUST be idempotent across lost
  acknowledgements, and a reconnect MUST be able to query active and prepared
  endpoint/generation identities before recovery. A failed control connection MUST
  NOT terminate the gateway. *Gate:* `gate:replay-oracle`,
  `gate:control-responsive`, `gate:license-boundary`. *Spec:* §36.9.1.

- **[DBG-42]** The gateway MUST parse RSP incrementally with bounded buffering and
  MUST enforce canonical policy fail-closed. Raw GDB run control MUST be routed to
  the scheduler; no packet may advance QEMU outside scheduler order. Unknown or
  unsupported packets MUST be rejected locally. *Gate:* `gate:layer0-determinism`,
  `gate:control-responsive`. *Spec:* §36.9.1; cross-ref §36.10.1.

### 36.9.2 Local and remote access, authentication, and leases

Local debugging uses the daemon's Unix socket and authenticated peer credentials.
Remote debugging uses the existing HTTP/2 control transport with mutual TLS; the
CLI opens a local loopback listener and relays GDB bytes to the daemon, so ordinary
GDB still connects to a local target. An unauthenticated mode is permitted only as
an explicit trusted-network option with an explicit bind address; it is never the
default and must not silently widen a loopback or Unix-only listener.

Authorization is capability based: `observe`, `control`, `mutate`, `shell`, and
`admin`. A session admits multiple observers but exactly one controller lease.
Lease generations make release and reconnect idempotent while rejecting stale
control. Mutation and shell require an explicit non-canonical debug fork before the
operation is admitted; possessing a capability does not weaken that invariant.

- **[DBG-43]** Debug access MUST support Unix peer authentication locally and mTLS
  over the daemon's HTTP/2 transport remotely. Unauthenticated access MUST require
  an explicit trusted-bind option. Authorization MUST enforce the five debugger
  capabilities, one controller lease, multiple observers, and stale-generation
  rejection on every control, mutation, and shell request. *Gate:*
  `gate:control-responsive`. *Spec:* §36.9.2; cross-ref 21.

- **[DBG-44]** Remote GDB MUST use a client-side loopback relay over the authenticated
  daemon transport. The CLI remains stateless beyond its live relay connection;
  session and gateway state remain server-side. *Gate:* `gate:control-responsive`.
  *Spec:* §36.9.2; cross-ref 23.

### 36.9.3 Guest introspection: exec, PTY, and SSH compatibility

Debugger introspection targets a guest VM, never the Crucible host. A debug-capable
guest image advertises a versioned guest-agent feature and exposes a deterministic
virtio-serial-style port implemented through the public shared-memory protocol.
The ABI carries owned command, stream, resize, exit-status, and close records only;
it contains no native pointers or process-private objects. Adding this transport is
an explicit shared-memory ABI version change and must pass ABI conformance on both
x86_64 and aarch64.

The concrete port reuses the already-attested per-architecture white-box
doorbell as a deterministic guest rendezvous rather than adding another QEMU
control plane. The guest supplies one fixed 4,608-byte mutable `CRGX` v1 buffer.
On each trap the GPL-side plugin validates an optional complete `CRGI` response,
publishes it to the plugin-to-host ring, dequeues at most one host request, and
overwrites the same guest buffer with that request or an idle reply. The frame
has a 16-byte pointer-free header, a bounded complete `CRGI` record, and a
zero-checked tail. Guest and plugin directions are closed and fail loudly when
reversed. This makes the port “virtio-serial-style” at the stream API without
introducing a virtual device or transferring a descriptor across the process
boundary.

The response exchange is acknowledged. When the fixed 64-entry plugin-to-host
ring is full, the plugin returns `retry`, retains the guest response sequence,
and does not dequeue a host request. The guest retries the same complete record
after a fixed deterministic spin interval. A host request is peeked but not
committed until the corresponding guest-memory write succeeds. Both directional
rings start at sequence one and fail closed on gaps, duplicates, stale entries,
or overflow. The host and plugin validate not only the outer exchange direction
but also the embedded `CRGI` request/response kind; the reserved feature channel
can carry only the initial feature advertisement.

The native surface supports argv-based noninteractive exec and an interactive PTY.
An SSH-compatible byte bridge is also provided for existing operator tooling, but
it terminates at the guest agent rather than exposing a host shell. Opening any of
these channels requires the `shell` capability and an explicit whole-world
non-canonical scenario fork first. Whole-world scope is the initial implementation:
forking only one node while peers continue on canonical history would create an
ambiguous network world.

The guest agent launches exec and PTY children directly from argv without shell
parsing. PTYs use an in-guest pseudoterminal and accept resize records. SSH
compatibility is advertised only when the image configures an in-guest SSH server
argv that speaks its protocol over standard input/output; the bridge does not
assume or discover a host executable.

The agent bounds concurrent channels at 64, its global response backlog at 64
records, and each output-reader handoff at two 4,096-byte chunks. Full queues
apply child-pipe backpressure rather than consuming guest memory without bound.
Channel-local open, capacity, input, and terminal errors return a typed `CRGI`
terminal error without terminating the agent; the channel is closed and its
identifier becomes reusable after that record. Reader I/O failures use the same
terminal path, and terminal records have priority over ordinary output when
capacity returns. Round-robin channel and per-stream cursors prevent a noisy
stdout from starving stderr, another channel, or exit status. Transport
corruption remains fatal. SSH protocol stdout and diagnostic stderr remain
distinct streams. Every child runs in a private session/process group; PTY
children additionally acquire the slave as their controlling terminal. Resize
retains an owned control descriptor, and channel close removes that descriptor
and sends `SIGHUP` to the PTY process group. Direct-child exit also hangs up
descendants that retain stream descriptors. Agent shutdown terminates and reaps
remaining process groups and joins their bounded readers.

An idle agent still has a causal instruction-count cost: it polls only after a
fixed spin count, but it is not timing-neutral. Therefore an image or daemon MUST
NOT activate `crucible-guest agent` on canonical execution. Activation belongs
to the authorized whole-world non-canonical debug fork and is recorded as part
of that fork's causal configuration. A future interrupt-backed device may remove
polling, but is not required by this protocol version.

Guest streams are ephemeral by default and excluded from canonical artifacts. An
operator may explicitly request transcript recording on the non-canonical branch.
Every runtime reposition closes existing exec, PTY, and SSH streams with a typed
reason; the operator may reopen them after the new world is committed. No shell
file-descriptor or guest-agent session is silently transferred between QEMU
instances.

- **[DBG-45]** Guest exec/PTY/SSH introspection MUST use a capability-advertised,
  versioned shared-memory guest-agent protocol and MUST target the guest, never the
  host. The native protocol MUST support argv exec, PTY byte streams and resize,
  exit status, and close; SSH compatibility MUST be a byte bridge to the same guest
  agent. *Gate:* `gate:abi-conformance`, `gate:license-boundary`. *Spec:* §36.9.3;
  cross-ref 13.

- **[DBG-46]** Shell-capable access MUST require an explicit whole-world
  non-canonical fork. Streams MUST close on reposition and be reopened explicitly.
  They are ephemeral by default; optional recording belongs only to the
  non-canonical branch and never changes canonical causal bytes. *Gate:*
  `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:* §36.9.3; cross-ref §36.5.

### 36.9.4 Toolchain and architecture gates

The shipped suite includes GNU GDB built hermetically from source using AOS
packages. Live debugger gates first establish the x86_64 path, then require the
same attach/read/breakpoint/reposition/run-control and guest-introspection contract
on aarch64. Architecture support is not complete while either required live gate
uses a model double or fallback.

- **[DBG-47]** The Crucible suite MUST ship a hermetic GNU GDB and MUST pass live
  x86_64 and aarch64 gates for stable attach, read-only neutrality, scheduler-routed
  run control, atomic reverse/goto replacement, and guest exec/PTY/SSH transport. The
  aarch64 gate is required completion, not an optional follow-up. *Gate:*
  `gate:layer0-determinism`, `gate:abi-conformance`. *Spec:* §36.9.4.

---

## 36.10 Risks and spikes

The debugging capability rests on the same substrate spikes the rest of the RFC
does, plus a debugging-specific one. The debugging-specific spike is added to
[`30-risks-spikes.md`](30-risks-spikes.md) as well.

### 36.10.1 SPIKE — does attaching/stepping the gdbstub disturb icount or the plugin's time control?

**Assumption under test.** Opening the gdbstub channel, reading registers/memory, and
issuing gdb-protocol stepping commands do **not** perturb the node's `-icount`, the
icount bias, or the plugin's time-control state — i.e. an attached read-only debug
session leaves `S`/`T` and the causal subsequence bit-identical to an un-attached run
([DBG-9]), and a gdb single-step does not advance virtual time outside the
deterministic step machinery.

**What to measure.** Run S1's single-VM fingerprint procedure (30 §30.2) twice: once
un-attached (the control), once with a gdbstub attached that performs a scripted
sequence of register/memory reads at the same cadence points; diff the fingerprint
sequences and the causal subsequences. Separately, issue gdb single-step commands and
measure whether icount advances by exactly the stepped instructions and whether the
plugin's reported deadline/ceiling state is unchanged.

**Pass/fail.** *Pass:* attached and un-attached fingerprint sequences and causal
subsequences are byte-identical, and gdb stepping advances icount by exactly the
stepped instructions with no time-control perturbation. *Fail:* any divergence — the
gdbstub leaked into icount or time control.

**Until green — the conservative default.** Until this spike is green, the debug
surface MUST default to **read-only plus Crucible-driven step/reverse-step**, with
**gdb single-step disabled** (the operator steps via Crucible's deterministic step
verbs, §36.4.2, not via the raw gdbstub single-step), so no gdbstub operation can
perturb virtual time.

- **[DBG-36]** Crucible MUST treat "does attaching/stepping the gdbstub disturb the
  node's `-icount`, icount bias, or the plugin's time control?" as a **SPIKE** (also
  recorded in [`30-risks-spikes.md`](30-risks-spikes.md)): a throwaway measurement
  comparing attached vs un-attached fingerprint sequences and causal subsequences
  (30 §30.2), and gdb single-step icount exactness. Until the spike is green, the
  debug surface MUST default to **read-only plus Crucible-driven step/reverse-step
  with gdb single-step disabled**, so no gdbstub operation can advance virtual time
  outside the deterministic step machinery ([DBG-8]). *Gate:*
  `gate:layer0-determinism`, `gate:e2e-determinism`. *Spec:* §36.10.1; cross-ref 30
  §30.2.

### 36.10.2 The other debugging risks

- **[DBG-37]** **Multi-vCPU debugging coherence** is a risk gated by
  determinism: the single-threaded round-robin TCG `-icount` model (§36.8) MUST be
  validated to land all of a node's vCPUs at one coordinate after a `goto`
  ([DBG-19], [DBG-32]) and to present coherent reads/breakpoints across vCPU/threads;
  a vCPU left straddling icounts is a determinism defect, not a tolerance. *Gate:*
  `gate:layer0-determinism`, `gate:replay-oracle`. *Spec:* §36.10.2; cross-ref §36.8.

- **[DBG-38]** The **read-only vs mutating boundary** MUST be **gate-enforced**, not
  documented-and-hoped: a test MUST assert that a read-only debug session leaves the
  canonical causal subsequence byte-identical ([DBG-9]), that mutation and
  free-control are rejected until an explicit `fork-debug`, and that those actions
  affect only the resulting non-canonical branch ([DBG-21]). A path by which a read
  or an inspection mutates canonical state
  is a determinism defect. *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`.
  *Spec:* §36.10.2; cross-ref §36.3, §36.5.

- **[DBG-39]** **Reverse-step latency** is a performance risk bounded by the
  opportunistic fat-checkpoint cadence (§36.4.4, [DBG-20]): latency scales with the
  replay distance from the nearest fat checkpoint, so a thin region means slow
  reverse-step. The cadence MUST bound it as a performance-only optimization (07
  [TEMP-14]); correctness MUST NOT depend on it. *Gate:* `gate:replay-oracle`.
  *Spec:* §36.10.2; cross-ref §36.4.4, 07 §4.

- **[DBG-40]** The **snapshot-completeness dependency** (S3, 30 §30.4) is a
  prerequisite for fat-checkpoint-accelerated time travel: until S3 is green, time
  travel MUST default to **thin/replay** ([QEMU-21], [DBG-20]) — slower but always
  bit-correct, because reverse = restore-nearest-thin-ancestor-then-replay never
  depends on snapshot completeness (07 [TEMP-13]). Source-mapping / DWARF support is
  out of scope ([DBG-30]) and carries no Crucible-side risk. *Gate:*
  `gate:replay-oracle`. *Spec:* §36.10.2; cross-ref 30 §30.4, [DBG-30].

---

## 36.11 Summary

```text
WHAT IT IS (§36.1): time-travel + source-level debugging as a PROJECTION of the
  existing substrate (checkpoint DAG 07, instantiate/replay 05/10, fork 22, QMP 10,
  event log 19) — NOT a new execution path, state representation, or clock.
  CLI + gdb-stub only (web UI is NG-4); Crucible serves the machine + the
  virtual-time coordinate, the gdb client + operator DWARF do source mapping.

ATTACH (§36.2): a debug attach = instantiate(checkpoint config); the gdbstub is a
  FOURTH out-of-band channel beside plugin-IPC/shmem/QMP — no per-quantum/frame data.

READ-ONLY (§36.3): reads append no causal entry, mutate no config, advance no
  virtual time; canonical causal subsequence BYTE-IDENTICAL with/without a debugger.
  Canonical breakpoints are hardware/out-of-band (like 17a Conditions) — NEVER a
  guest-memory trap patch; a memory-only breakpoint is REFUSED on a canonical attach.

TIME TRAVEL (§36.4): goto(T) = restore-nearest-checkpoint-≤-T + replay to T (the
  ancestor-replay branch of instantiate); NO reverse engine; inherits the oracle.
  Reverse grains mirror forward StepMode (instruction/quantum/event/assertion/timer);
  reverse-continue = latest log coord ≤ now where a 17a Condition held. Per-node
  (by icount) AND whole-world (a prefix, = a fork minus divergence) time travel;
  opportunistic fat-checkpoint cadence bounds reverse latency (perf only).

NON-CANONICAL DEBUG BRANCH (§36.5 — the one new rule): the operator must issue
  `fork-debug` before mutating guest-visible state or taking control; otherwise the
  request is rejected. The explicit operation creates a clearly-marked non-canonical
  branch; the canonical run is never mutated. Excluded from the oracle,
  not a (seed,scenario,schedule) artifact, visibly marked. STILL inside virtual time
  + one execution path → a THIRD category, distinct from [ADV-33]'s forbidden
  detach-to-free-running-QEMU (which still stands). Decision-expressible edits → 20 §8;
  arbitrary guest edits → a debug-edit script, never model-reproducible.

TRIAGE (§36.6): --at <icount|vtime> / --at-event / --at-failure / --at-checkpoint;
  a divergence-bisection (node,icount,kind) is a goto target; a failed run prints a
  copy-pasteable `crucible debug <artifact> --at-failure`.

MULTI-vCPU (§36.8): vCPUs as gdb threads; round-robin TCG + icount; whole-world /
  per-node time travel lands all of a node's vCPUs at the same coordinate.

CLI (§36.9, also in 23): crucible debug … --read-only(default)|--allow-mutate;
  verbs attach-gdb/fork-debug/goto/reverse-step/reverse-continue; a thin wrapper, no
  debug state. `--allow-mutate` grants eligibility but never forks implicitly.

GATEWAY + REMOTE (§36.9.1–§36.9.2): a separate GPL process owns the stable GDB
  connection and atomically swaps verified QEMU backends; RSP is bounded,
  asynchronous, fail-closed, and scheduler-routed for run control. Local Unix-peer
  auth, remote HTTP/2+mTLS relay, explicit trusted-bind unauth only; capability roles,
  one controller lease, multiple observers.

GUEST INTROSPECTION (§36.9.3–§36.9.4): explicit whole-world non-canonical fork,
  then guest-agent argv exec, PTY, or SSH compatibility over a versioned public
  shmem protocol — never a host shell. Streams close on reposition, are ephemeral by
  default, and may be recorded only explicitly. Hermetic GNU GDB; required live
  x86_64 then aarch64 gates.

SPIKE (§36.10): does attaching/stepping the gdbstub disturb icount or time control?
  Until green: read-only + Crucible-driven step, gdb single-step disabled. Plus:
  multi-vCPU coherence, gate-enforced read/mutate boundary, reverse-step latency,
  snapshot-completeness (default thin/replay until S3 green), DWARF out of scope.
```

The shape of this file is the shape of the guarantee: a debugger is just another
consumer of the deterministic substrate. Inspection is free of effect; time travel
is restore-plus-replay; the only place the operator can break determinism is by
mutating state — and that is possible only after an explicit `fork-debug` creates a
clearly-marked branch rather than touching the canonical run.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks whose
> primary area is time-travel/source-level debugging, tracked by [PLAN-3].
> They are sequenced strictly after the determinism, save/restore-oracle,
> control-plane, fork, and event-log foundations they depend on ([ADV-1], [G-5],
> [PLAN-4]).

The completed entries among T-DBG-1 through T-DBG-8 record graph-model, session
command, existing one-runtime attach, and CLI planning gates that were present
before the production-completion work. T-DBG-6 and T-DBG-8 were reopened when the
explicit `fork-debug` policy replaced implicit forking. These entries do **not** by themselves claim stable
GDB across runtime replacement, authenticated remote access, scheduler-mediated RSP
run control, guest exec/PTY/SSH, a hermetic GDB client, or live aarch64 parity. Those
end-to-end claims remain open in T-DBG-9 through T-DBG-14 and MUST NOT be reported
complete from model-double evidence.

- [x] **T-DBG-1** Implement debug attach as `instantiate` of a resolved checkpoint
  configuration (05 §5, 10 §10.5) and the **fourth out-of-band gdbstub channel**
  (alongside plugin-IPC/shmem/QMP), mediated/proxied to a `--gdb-listen` gdb-protocol
  endpoint, carrying no per-quantum/frame data. — satisfies [DBG-1], [DBG-2],
  [DBG-3], [DBG-4], [DBG-5], [DBG-6]; spec §36.1, §36.2.
  Completed under `checks.crucible.phase6.debugAttach`: `TemporalGraph::debug_attach`
  now accepts a resolved checkpoint configuration, realizes it through the same
  `resume`/`instantiate` path as ordinary graph operations, and reports the
  resulting runtime together with an explicit four-channel debug boundary:
  plugin-IPC, shared memory, QMP, and a mediated gdbstub. The QEMU launch builder
  adds a validated `-gdb` endpoint only for debug launches, and the
  `QemuGdbstubProxy` binds the operator `--gdb-listen` address, connects to
  QEMU's raw gdbstub endpoint, and forwards debugger bytes outside the scheduler
  hot path. The tests assert both the four-channel contract and local proxy
  mediation, with no per-quantum timing or frame payload. The packaged
  `crucible debug` route additionally requires a successful live QEMU/plugin
  boot and reports its protocol/ABI/icount/fingerprint proof before exposing the
  mediated debug plan.
- [x] **T-DBG-2** Implement read-only inspection that appends no causal entry,
  mutates no config, and advances no virtual time, with a gate test that the
  canonical causal subsequence is byte-identical with/without a debugger and that
  attach/inspect/detach are recorded only as observational entries. — satisfies
  [DBG-8], [DBG-9], [DBG-10]; spec §36.3.1.
  Completed under `checks.crucible.phase6.readOnlyDebugInspection`:
  `TemporalGraph::read_only_debug_inspection` records attach/inspect/detach as
  `diagnostic` event-log entries whose class is observational, uses an immutable
  graph receiver, captures before/after graph, checkpoint, runtime icount,
  scheduler-state, and virtual-time footprints, and exposes `proves_read_only()`
  for the debugger contract. Observations are stamped with the graph-derived
  checkpoint time, and a requested coordinate that differs from that checkpoint
  fails the read-only proof. The gate compares the canonical causal subsequence
  with and without the API-generated debugger observations, proves it is
  byte-identical, and asserts that register, memory, backtrace, thread/vCPU, and
  watchpoint reads append no causal entry and advance no virtual time.
  The CLI live-backend proof is observational and remains outside this canonical
  projection, so attaching the production debug route does not change the
  scenario's causal bytes.
- [x] **T-DBG-3** Implement canonical breakpoints as hardware/out-of-band (17a
  `Condition` predicate or QEMU hardware breakpoint), transparently satisfying a
  client software-breakpoint request where a mechanism exists and **refusing**
  (typed error → `--allow-mutate`) a memory-write-only breakpoint on a canonical
  attach; never patch a trap into guest memory. — satisfies [DBG-11], [DBG-12],
  [DBG-13]; spec §36.3.2.
  Completed under `checks.crucible.phase6.canonicalDebugBreakpoint`:
  `TemporalGraph::canonical_debug_breakpoint` resolves canonical breakpoint requests
  only to out-of-band mechanisms (`EngineCondition` or `QemuHardwareBreakpoint`),
  transparently satisfies a client software-breakpoint request through the mediated
  gdbstub as a QEMU hardware breakpoint when available, and returns
  `EngineError::DebugBreakpointRequiresAllowMutate` with `--allow-mutate` guidance
  when the request has no canonical mechanism. The gate asserts the report never
  mutates guest memory, never uses a memory patch, the proxy rewrites real `Z0`
  software-breakpoint packets to `Z1` hardware-breakpoint packets, and the proxy
  refuses `Z0` locally when no hardware breakpoint mechanism is available.
  The live CLI route composes this proxy policy with hermetic QEMU/plugin
  execution; it never enables raw gdb single-step or a guest-memory trap patch.
- [x] **T-DBG-4** Implement `goto` as restore-nearest-checkpoint-≤-T-then-replay (the
  ancestor-replay branch of `instantiate`), reverse-step grains mirroring the forward
  StepMode set, and reverse-continue as the latest-log-coordinate-≤-now-where-a-17a-
  Condition-held backward scan; assert a rewound coordinate is the same content-
  addressed configuration as the forward one (oracle), localizing any divergence by
  bisection. — satisfies [DBG-14], [DBG-15], [DBG-16], [DBG-17]; spec §36.4.1,
  §36.4.2.
  Completed by `checks.crucible.phase6.debugTimeTravel`:
  `TemporalGraph::debug_goto` resolves configuration, checkpoint, event-sequence,
  virtual-time, and per-node icount coordinates, restores the nearest recorded
  checkpoint at or before the target, replays the remaining schedule suffix through
  the ordinary instantiate path, and materializes a target checkpoint for the replay
  oracle. Reverse-step resolves instruction, quantum, event, assertion, and timer
  grains to earlier coordinates and delegates motion to `debug_goto`; the session
  `StepMode` set mirrors the reverse-grain set. Reverse-continue scans checked
  event-log prefixes backward with the 17a condition evaluator, chooses the latest
  matching coordinate before the current log limit, and realizes it through the same
  `goto`. A rewound coordinate must match the forward content-addressed
  configuration, and replay-oracle mismatch returns a debug bisection coordinate
  localizing the first differing schedule prefix.
- [x] **T-DBG-5** Implement per-node (by icount) and whole-world (prefix
  `(def, schedule[0..k])`, = fork minus divergence) time travel that lands all of a
  node's vCPUs at one deterministic coordinate, plus the opportunistic
  fat-checkpoint cadence (`--checkpoint-stride`) as a performance-only,
  eviction-always-safe optimization defaulting to thin/replay until S3 is green. —
  satisfies [DBG-18], [DBG-19], [DBG-20]; spec §36.4.3, §36.4.4.
  Completed by `checks.crucible.phase6.debugScopedTimeTravel`:
  `TemporalGraph::debug_per_node_time_travel` resolves an exact node icount on the
  same linear schedule family, derives only that node's landed material from the
  baked source-of-truth restore and target replay suffix, and proves all other nodes
  retain the attached runtime material. `TemporalGraph::debug_whole_world_time_travel` resolves
  schedule-prefix, virtual-time, and event-sequence world targets to prefix
  configurations and realizes them through `goto`, giving fork-minus-divergence
  semantics without appending decisions. The checkpoint cadence API walks
  `--checkpoint-stride` prefix points through the existing savevm hedge: the default
  `thin_replay_until_full_s3` hedge records thin replay checkpoints only and may evict
  existing fat cache entries, while a verified hedge may cache fat checkpoints, with
  eviction falling back to bit-identical replay.
- [ ] **T-DBG-6** Implement the **non-canonical debug branch**: expose an explicit
  whole-world `fork-debug` operation and reject guest-state mutation or
  operator-controlled continue until it succeeds, leaving the canonical run
  bit-identical; exclude it from the replay oracle and from
  `(seed, scenario, schedule)` artifacts; visibly mark it in the graph, the event-log
  `fork` marker, and the live mirror; keep it inside virtual time + the one execution
  path (distinct from [ADV-33], which still stands); record Decision-expressible edits
  per 20 §8 and arbitrary guest edits as a never-model-reproducible debug-edit script.
  — satisfies [DBG-21], [DBG-22], [DBG-23], [DBG-24], [DBG-25], [DBG-26]; spec §36.5.
  The branch data model is covered by
  `checks.crucible.phase6.debugNonCanonicalBranch`:
  `TemporalGraph::debug_non_canonical_branch` requires the first recorded
  mutating/operator-controlled action to match the declared branch trigger and records
  it as non-canonical branch metadata sourced from the already-instantiated attach
  runtime, not as a canonical `Configuration`. The branch report proves the canonical
  graph/runtime footprint and canonical-run causal event-log projection are
  byte-identical, stores schedule-expressible decisions and control-log operations
  separately from arbitrary guest edits, records arbitrary register/memory/breakpoint
  edits in a never-model-reproducible debug-edit script, marks the branch in the
  temporal-graph view, a causal catalog-kind `fork` event-log marker flagged
  non-canonical, and live status, and keeps the branch inside virtual time plus the
  single execution path while excluding it from replay-oracle and
  `(seed, scenario, schedule)` artifacts. Completion remains open until the session
  and CLI expose the explicit transition and prove that forbidden requests never
  fork as a side effect.
- [x] **T-DBG-7** Implement the debug target resolver (`--at`, `--at-event`,
  `--at-failure` = first assertion-violation point, `--at-checkpoint`), accept a
  divergence-bisection `(node, icount, kind)` coordinate directly as a goto target,
  and emit a copy-pasteable `crucible debug <artifact> --at-failure` in the failure
  footer (23 §4). — satisfies [DBG-27], [DBG-28], [DBG-29]; spec §36.6.
  Completed by `checks.crucible.phase6.debugTargetResolver`:
  `TemporalGraph::debug_resolve_target` accepts direct `--at` coordinates,
  event-log `--at-event` sequences, `--at-failure` by scanning for the first
  assertion-state violation, `--at-checkpoint` content addresses, and node-local
  divergence-bisection coordinates, then returns the `DebugGotoRequest` consumed by
  restore-plus-replay `debug_goto`. `DebugFailureFooterCommand` centralizes the
  copy-pasteable `crucible debug <artifact> --at-failure` footer and the CLI failure
  artifact writer uses it.
- [ ] **T-DBG-8** Implement the `crucible debug` CLI surface (also added to 23) as a
  thin wrapper holding no debug state — coordinate + debug-control flags
  (`--read-only` default, `--allow-mutate`, `--node`, `--gdb-listen`,
  `--checkpoint-stride`) and verbs attach-gdb/fork-debug/goto/reverse-step/reverse-continue
  decomposing into session commands + the gdbstub proxy — expose vCPUs as gdb
  threads with coherent reads/breakpoints/landings, document Crucible-ships-no-symbol-
  server, run the gdbstub-disturbs-icount spike (defaulting read-only + Crucible-
  driven step with gdb single-step disabled until green), and gate-enforce the
  read/mutate boundary. — satisfies [DBG-7], [DBG-30], [DBG-31], [DBG-32], [DBG-33],
  [DBG-34], [DBG-35], [DBG-36], [DBG-37], [DBG-38], [DBG-39], [DBG-40]; spec §36.7,
  §36.8, §36.9, §36.10.
  Most of the surface is covered by `checks.crucible.phase6.debugCliSurface`:
  `crucible debug` now parses artifact/savepoint and `--session` targets plus
  `--at`, `--at-event`, `--at-failure`, `--at-checkpoint`, `--node`,
  `--gdb-listen`, `--read-only`, `--allow-mutate`, `--checkpoint-stride`, and the
  attach-gdb/goto/reverse-step/reverse-continue verbs. The CLI planner records only
  delegated session commands and mediated gdbstub-proxy operations, defaults
  artifacts to `--at-failure`, savepoints to their checkpoint coordinate, and
  sessions to the current coordinate, realizes reverse-step through the debug
  reverse-step/goto restore-plus-replay path rather than unsupported forward session
  step modes, proves that the CLI holds no debugger state, defaults to read-only
  inspection, exposes the no
  symbol server policy, requires coherent multi-vCPU gdb threads, and keeps raw gdb
  single-step disabled. Executing the command also resolves the hermetic
  production backend, boots the packaged QEMU/plugin under TCG, and reports the
  negotiated protocol/ABI plus terminal icount/fingerprint before presenting
  the thin delegated debug plan. The remote unary client now implements an
  explicit `fork-debug` plus argv `exec`, interactive `pty`, and configured
  in-guest `ssh` byte bridging. The fork RPC requires the transport-derived
  controller to hold `control`, `mutate`, and `shell`, records a typed
  guest-introspection trigger/action on the whole-world branch, and every guest
  record is rejected while the session remains canonical. Completion remains
  open for the remaining remote goto/reverse dispatch and live gates.
- [ ] **T-DBG-9** Replace the Apache-side one-QEMU proxy with the standalone GPL
  debugger gateway, a stable asynchronous GDB listener, bounded fail-closed RSP
  parsing, and scheduler-routed `continue`/`step`/`vCont`. Prove split/coalesced
  packets, acknowledgements, async output/stops, EOF, and unsupported mutations.
  — satisfies [DBG-6], [DBG-41], [DBG-42]; spec §36.2.2, §36.9.1.
  In progress: the standalone gateway and Apache control client now negotiate over
  the versioned Unix protocol; prepare/commit are reconnect-recoverable and
  state-epoch checked; semantic `OK` responses, not transport acknowledgements,
  define replayable thread/breakpoint state. A process-boundary gate keeps one GDB
  connection across two QEMU Unix RSP backends, including asynchronous console
  output, scheduler-routed `continue`/`step`/`vCont`, and atomic commit barriers.
  Run-control packets are queued across the versioned gateway boundary and consumed
  by the session actor as ordinary session commands, so canonical repositioning still
  rejects forward execution until `fork-debug`; the gateway never forwards them
  directly to QEMU. No unauthenticated TCP listener exists by default; the
  component-only loopback listener requires an explicit trusted-host launch policy.
  The authenticated daemon relay and live breakpoint/terminal run-control gates
  remain open, so this task is not complete.
- [ ] **T-DBG-10** Implement production whole-world candidate instantiate/replay,
  gateway prepare/hydrate/commit, verified endpoint/generation evidence, rollback
  before promotion, and stable GDB state across goto/reverse/fork. — satisfies
  [DBG-14]–[DBG-19], [DBG-41]; spec §36.4, §36.9.1.
  In progress: the production lifecycle replays two independent whole-world
  candidates to the exact scheduler/event-log/node-counter target, requires both
  candidates to agree, and compares the selected candidate with original live
  fingerprints sealed to the graph's complete `RuntimeState`. The standalone
  gateway promotes the candidate's private Unix RSP endpoint with reconnect/status
  reconciliation. Indeterminate prepare/commit/abort outcomes quarantine possibly
  selected worlds or nodes until gateway termination is observed; successful
  promotion transfers gateway ownership before revoking the retired world's
  scheduler authority, and cleanup evidence does not claim an unobserved reap.
  Completion remains open for live end-to-end gates across goto, reverse, and fork.
- [ ] **T-DBG-11** Enforce debugger identities, capability roles, one-controller
  leases, Unix peer authentication, remote HTTP/2+mTLS relay, and explicit trusted
  unauthenticated bind policy in the daemon and CLI. — satisfies [DBG-43], [DBG-44];
  spec §36.9.2.
  In progress: the HTTP/2 daemon now has a mandatory-client-certificate TLS
  serving path. It derives a stable authenticated principal from the leaf
  certificate fingerprint and places that identity in each connection's request
  extensions. The CLI loads matching server-CA/client-certificate/client-key PEM
  material for authenticated HTTP/2 clients. Cleartext `serve` requires the
  explicit `--trusted-unauthenticated-bind` policy and cannot be combined with TLS.
  Per-certificate deny-by-default role mappings now enforce the five closed
  capabilities; duplicate principals fail configuration. Controller ownership is
  session-local, generation-guarded, and checked against the transport-derived
  principal on every operation. Authenticated attach allocates a daemon-loopback
  stable gateway, and the CLI exposes it through a bounded client-side loopback
  relay over HTTP/2 while retaining and finally releasing the controller lease.
  Read-only service cannot acquire, attach, open, or write a debugger relay.
  Completion remains open for Unix peer credentials, multiple-observer RPC
  plumbing, and live mTLS/relay conformance evidence.
- [ ] **T-DBG-12** Version the public shared-memory ABI for the debug guest agent and
  implement whole-world-forked argv exec, PTY, resize, exit/close, and SSH-compatible
  byte bridging; close all streams on reposition and keep recording opt-in. —
  satisfies [DBG-45], [DBG-46], [SHM-47], [SHM-48]; spec §36.9.3, 13 §13.3.9.
  The independently implementable `crucible-protocol::guest_introspection`
  codec now freezes the owned `CRGI` v1 record header and closed feature, argv
  exec, PTY, SSH bridge, input, resize, close, output, and exit vocabulary. It
  rejects zero channel identities, unknown flags/features, unbounded argv and
  chunks, malformed UTF-8, invalid terminal sizes, and trailing bytes. ABI v6
  appends one bounded request ring and one bounded response ring per VM, with
  checked C and Rust geometry, role-specific host/plugin accessors, full-record
  validation before publication and consumption, and fail-loud backpressure.
  The `CRGX` v1 fixed guest-buffer exchange, role-preserving detached plugin
  ring handle, live QEMU callback adapter, host `QemuNode` request/response
  methods, and `crucible-guest agent` runtime now connect those rings end to end.
  The agent advertises capabilities, launches direct argv exec and controlling-
  terminal PTY children, applies bounded output backpressure, isolates SSH
  diagnostics, resizes PTYs through owned descriptors, reports typed channel
  errors and exit status/signal, and optionally bridges to a configured in-guest
  SSH stdio server. Direction and sequence validation, retry acknowledgement,
  post-write request commit, and child cleanup are implemented. The
  scheduler/backend/session boundary now routes node-addressed records, and the
  authenticated HTTP/2 daemon carries encoded `CRGI` records only after the
  typed whole-world guest-introspection fork. The CLI exposes argv exec, PTY
  stdin/stdout, and SSH-compatible byte bridging. The session-owned response
  broker demultiplexes bounded records by `(node, channel)` and synthesizes typed
  closure on successful runtime replacement. Completion remains open for local
  raw-terminal handling and live resize propagation, transcript persistence,
  and live x86_64/aarch64 evidence.
- [ ] **T-DBG-13** Package GNU GDB hermetically from source and add user workflows
  for local/remote GDB, reverse commands, guest exec, PTY, and SSH compatibility. —
  satisfies [DBG-47]; spec §36.9.4; cross-ref 23, 26.
- [ ] **T-DBG-14** Pass live x86_64 and aarch64 gates for read-only neutrality,
  hardware breakpoints, scheduler run control, atomic runtime replacement, stable
  GDB, and guest exec/PTY/SSH introspection without model doubles or fallback. Update S14 and the
  decision register only from captured live evidence. — satisfies [DBG-36],
  [DBG-41], [DBG-42], [DBG-47]; spec §36.9.4, §36.10.1.
