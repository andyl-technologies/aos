# 21 — The control API: programmatic surface and RPC

This file specifies Crucible's **control API**: the programmatic and RPC surface
through which a CLI, a search driver, a conformance suite, or any other
programmatic client drives a live session. It is a *thin wrapper* over the session
actor's closed command set
([`20-session-control-plane.md`](20-session-control-plane.md) §4): every RPC
maps to a session command or a read of the session's lock-free mirror, and the
API adds *no* new control semantics of its own. The API surface is the boundary
across which the CLI ([`23-cli.md`](23-cli.md)), the search/fuzzing driver
([`22-advanced-features.md`](22-advanced-features.md)), and external tooling reach
a running scenario.

Crucible has **no web UI** ([INV/NG-4], [`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md)).
This file specifies a programmatic API plus a machine-to-machine RPC surface, and
nothing about a browser front-end. Where the reference service shape uses
streaming RPCs, it does so for *programmatic* clients (the CLI over HTTP/2, an
in-process Rust client, a conformance harness); no requirement here is shaped by,
or accommodates, a browser. A request shape that exists *only* to work around a
browser limitation is out of scope and MUST NOT appear in this API.

Requirement IDs in this file use the prefix `API` (see
[`00-conventions.md`](00-conventions.md)). The canonical gates referenced here —
`gate:abi-conformance`, `gate:control-responsive`, `gate:e2e-determinism`, and
`gate:replay-oracle` — are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md). This
file depends on the session command set and lifecycle
([`20-session-control-plane.md`](20-session-control-plane.md)), the unified event
log and its open-set kind catalog
([`19-observability-event-log.md`](19-observability-event-log.md) §19.7), the
versioned-interfaces goal ([G-8]), and the in-process test double
([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §3,
`SimDouble`). It is consumed by the CLI ([`23-cli.md`](23-cli.md)), advanced
features ([`22-advanced-features.md`](22-advanced-features.md)), and the
conformance suite (24).

The code blocks in this file are illustrative sketches per the conventions in
[`00-conventions.md`](00-conventions.md) ("Code sketches in this RFC"), not the
implementation; the authoritative statement is always the prose requirement. A
sketch that disagrees with a requirement is a defect in the sketch.

---

## 21.1 Scope and transport

The API is two co-designed things sharing one message vocabulary:

1. **A programmatic Rust client** — an in-process, async, typed client the CLI
   and the search driver link directly, talking to a `crucible-session` actor
   ([`20-session-control-plane.md`](20-session-control-plane.md) §3) *without*
   serialization when the session is in the same process. This is the fast path:
   the CLI driving a session it launched, the search driver forking and stepping
   thousands of sessions, the conformance suite driving the in-process double.

2. **An RPC surface** — a gRPC/Connect-style service over HTTP/2 that exposes the
   *same* command vocabulary to out-of-process clients (a CLI attaching to a
   long-lived daemon, a remote search driver, a CI conformance runner). The wire
   types are the serialized form of the in-process types; the in-process client is
   the trait the RPC client also implements, so a caller is transport-agnostic.

Both share one **message model** (§21.3): the open-set, dotted-`kind`-plus-typed-
attributes payloads that mirror the event-log schema
([`19-observability-event-log.md`](19-observability-event-log.md) §19.2.2,
§19.7). The transport is a frame for that model, never a second model.

```text
  callers                       client trait            transport          session
  ───────────────────────────   ─────────────────────   ───────────────    ──────────────────
  crucible (CLI, 23)        ┐
  search/fuzz driver (22)   ├─▶  trait ControlClient  ┬▶ in-process (direct)  ┐
  conformance suite (24)    ┘    (async, typed)        │   no serialization    ├▶ crucible-session
                                                       └▶ RPC over HTTP/2  ────┘   actor (20 §3)
                                                          (gRPC/Connect)         backend: QEMU (10)
                                                                                 or SimDouble (24 §3)
```

- **[API-1]** Crucible MUST expose its control plane as (a) a programmatic,
  async, typed **in-process Rust client** and (b) an **RPC surface** over HTTP/2
  (a gRPC/Connect-style service), both implementing one `ControlClient` trait so a
  caller is transport-agnostic. The in-process client MUST reach a same-process
  `crucible-session` actor ([`20-session-control-plane.md`](20-session-control-plane.md)
  §3) without serializing, and the RPC surface MUST expose the *same* command
  vocabulary to out-of-process clients. *Gate:* `gate:abi-conformance`,
  `gate:control-responsive`. *Spec:* §21.1.

- **[API-2]** The API MUST be a **thin wrapper** over the session command set
  ([`20-session-control-plane.md`](20-session-control-plane.md) §4): every RPC and
  every client method MUST map to one session command (§4 of 20) or one read of
  the session's lock-free mirror ([SESS-23]), and MUST add no control semantics of
  its own (no command not in 20 §4, no state not in 20 §2). The mapping is the one
  in §21.2; an RPC that does work the session command set cannot is a layering
  defect. *Gate:* `gate:control-responsive`. *Spec:* §21.1, §21.2; routes
  [SESS-10].

- **[API-3]** The API MUST NOT include a browser front-end, browser-specific RPCs,
  or request shapes whose only purpose is to accommodate a browser transport
  limitation ([NG-4]). The streaming RPCs of §21.2 exist for *programmatic*
  clients (the CLI over HTTP/2, the in-process client, the conformance harness)
  only. *Gate:* `gate:abi-conformance`. *Spec:* §21.1; routes [NG-4].

- **[API-4]** The wire types MUST be the serialized form of the in-process types,
  not a parallel model: the open-set payload model (§21.3) MUST be identical across
  the in-process and RPC paths, so the in-process double and the QEMU backend are
  driven through byte-identical command/event vocabularies and the conformance
  suite (§21.6) can run the same lifecycle against both. *Gate:*
  `gate:abi-conformance`. *Spec:* §21.1, §21.3, §21.6.

---

## 21.2 The service surface

The service mirrors the session lifecycle ([`20-session-control-plane.md`](20-session-control-plane.md)
§2) and command set (§4). It has stateless unary RPCs for discovery and lifecycle,
one **bidirectional Control stream** as the primary driving surface, and a
simpler **Watch + Send** pair (server-streaming events + unary command dispatch)
for clients that do not want a bidi stream. Every method maps to the session
command set; none invents control semantics ([API-2]).

```text
  service CrucibleControl {
    // ── discovery / capabilities ────────────────────────────────────────────
    Hello(HelloRequest)            -> HelloResponse          // version + capabilities
    ListScenarios(…)               -> ListScenariosResponse  // scenarios the server knows

    // ── session lifecycle (unary) ───────────────────────────────────────────
    CreateSession(…)               -> SessionRef             // 20 §4: instantiate(genesis)
    ResumeSession(…)               -> SessionRef             // 20 §4: instantiate(checkpoint)
    ListSessions(…)                -> ListSessionsResponse
    DestroySession(…)              -> DestroySessionResponse  // 20 §4: stop + drop
    GetReproduction(…)             -> GetReproductionResponse // recorded command stream (20 §8)

    // ── attach + drive ──────────────────────────────────────────────────────
    Control(stream ControlRequest) -> stream ControlResponse  // bidi: cmds ⇄ events/state/results
    Watch(Attach)                  -> stream ControlResponse   // server-stream: snapshot + tail
    Send(SendRequest)              -> SendResponse             // unary: one command, one result
  }
```

### 21.2.1 RPC → session command mapping

```text
  RPC method        session op (20)                          notes
  ───────────────   ──────────────────────────────────────  ──────────────────────────────────
  Hello             (none; read server identity)             version + open-set capabilities (§21.6)
  ListScenarios     (none; read scenario registry)           names + descriptions; no session
  CreateSession     new actor; Command::Start (20 §4.1)      from scenario ref OR inline def;
                                                             seed; start_paused → Paused(Instan.)
  ResumeSession     new actor at checkpoint (20 §4.1)        self-contained scenario/schedule/checkpoint closure
  ListSessions      read registry + each mirror (SESS-23)    current state may be stale; attach for live
  DestroySession    Command::Stop then drop the actor        epoch-guarded (§21.5)
  GetReproduction   read control log (20 §8)                 recorded command stream (§21.5.2)
  Control (bidi)    Attach + a stream of Command (20 §4)     events/state/results back (§21.4)
  Watch             Attach (read-only)                       snapshot-on-attach + replay + live tail
  Send              one Command (20 §4) via Send envelope    CommandResult + optional StateUpdate
```

- **[API-5]** The service MUST expose at least: `Hello` (server version +
  capabilities, §21.6), `ListScenarios`, `CreateSession`, `ResumeSession`,
  `ListSessions`, `DestroySession`, `GetReproduction` (§21.5.2), a
  bidirectional `Control` stream (§21.4), a server-streaming `Watch`, and a unary
  `Send`. Each MUST map to the session operation named in §21.2.1 and MUST add no
  control semantics beyond the session command set ([API-2]). *Gate:*
  `gate:abi-conformance`,
  `gate:control-responsive`. *Spec:* §21.2, §21.2.1.

- **[API-6]** `Hello` MUST be callable before any session exists, MUST be
  side-effect-free, and MUST return the protocol version (§21.6) and the server's
  open-set capabilities — the command, breakpoint, fault, and event-payload kinds
  it understands (§21.3, §21.6) — so a client discovers the kind catalog rather
  than hard-coding it. `ListScenarios` MUST be side-effect-free and MUST return the
  scenarios the server can instantiate (name, description, source identifier).
  *Gate:* `gate:abi-conformance`. *Spec:* §21.2, §21.6.

- **[API-7]** `CreateSession` MUST accept either a **scenario reference** (a name
  the server resolves, [`06-spatial-graph.md`](06-spatial-graph.md)) **or an
  inline ScenarioDef** (a self-contained definition, mutually exclusive with the
  name), a **seed**, and a **start-paused** flag (default true: the session lands
  in `Paused { Instantiated }` after `Start`, [SESS-5], so a client can set
  breakpoints and faults before the first `Continue`). It MUST instantiate the
  genesis configuration `(def, [])` via the session's single `instantiate`
  ([SESS-11]) and return a `SessionRef` (id + epoch + seed, §21.5).
  `ResumeSession` MUST accept a self-contained scenario form payload, schedule,
  and fat checkpoint closure, reject seed, scenario-payload, or closure
  mismatches, instantiate the recorded non-genesis configuration through the same
  session lifecycle, and return a normal `SessionRef`. *Gate:*
  `gate:control-responsive`, `gate:replay-oracle`. *Spec:* §21.2; cross-ref 20
  §4.1, 06.

- **[API-8]** `ListSessions` MUST return each live session's `SessionRef` with the
  state read from its lock-free mirror ([SESS-23]); the returned state MAY be
  stale by the time the client renders it, and a client that needs live state MUST
  open a `Control` or `Watch` stream. `DestroySession` MUST `stop` the session
  ([SESS-14]) and drop its actor, MUST be epoch-guarded (§21.5), and MUST be
  idempotent against an already-absent session id (returning success, not a
  spurious error). *Gate:* `gate:control-responsive`. *Spec:* §21.2; cross-ref 20
  §9.

- **[API-9]** `Send` MUST dispatch exactly one `Command` against an attached
  session and MUST return the `CommandResult` synchronously, plus an optional
  `StateUpdate` when the command transitioned the session into `Paused`/`Stopped`
  (because a run-state transition is not itself an event-log entry — 20 §2 — a
  `Watch`-only client could not otherwise observe it). Events *caused* by the
  command MUST flow through the per-session broadcast and be visible to `Watch`
  ([SESS-24], [OBS-31]). *Gate:* `gate:control-responsive`. *Spec:* §21.2; cross-ref
  20 §9, 19 §19.6.5.

- **[API-10]** `Watch` and `Send` MUST together be capability-equivalent to the
  `Control` bidi stream for any single client: a client that opens `Watch` (to
  receive snapshot, replay, and live tail, §21.4) and issues `Send` per command
  MUST be able to drive the full session lifecycle (start, continue, pause, step,
  inject/heal, breakpoint, savepoint, fork, stop) identically to a bidi client.
  Neither the bidi nor the Watch+Send path may offer a command the other cannot.
  *Gate:* `gate:abi-conformance`. *Spec:* §21.2; cross-ref 20 §4.

---

## 21.3 The open-set payload model

Following the versioned-interfaces goal ([G-8]) and mirroring the event-log schema
([`19-observability-event-log.md`](19-observability-event-log.md) §19.2.2,
§19.7), **commands, events, faults, and breakpoint conditions are identified by a
dotted `kind` string plus a typed attribute map**, not by a closed wire enum. A
new kind — a new fault, a new breakpoint condition, a new event payload — is added
by registering its `kind` string and attribute schema, *without changing the wire
types* and without breaking decoders of existing kinds. The closed parts of the
wire (the envelope, the source set, the run-state machine) stay closed; the
*payloads* are open.

```text
  ExtensionPayload { kind: "crucible.fault.network_partition",
                     attributes: { "sides": …, "links": …, … } }

  open-set categories (dotted kind):     wire-closed (intrinsic):
    crucible.cmd.*       commands           ControlRequest / ControlResponse envelope
    crucible.bp.*        breakpoint conds   EventSource (Scenario/Engine/Node/Guest/Command)
    crucible.fault.*     faults             SessionState machine (Loaded/Running/Paused/Stopped)
    crucible.event.*     event payloads     SessionRef / epoch
```

The attribute map is a string-keyed map of scalar values (string, int, uint,
double, bool, bytes), read by name and type — so a projection or assertion reads a
field rather than scraping a message string ([OBS-11]). This is the wire face of
the event-log payload of [§19.2.2].

- **[API-11]** Events, commands, faults, and breakpoint conditions on the wire
  MUST be identified by an **open-set dotted `kind` string** (e.g.
  `crucible.cmd.continue`, `crucible.fault.network_partition`,
  `crucible.event.message_delivered`) plus a **typed attribute map**, mirroring the
  event-log payload schema ([`19-observability-event-log.md`](19-observability-event-log.md)
  §19.2.2, §19.7). The wire MUST NOT model these categories as closed enums.
  *Gate:* `gate:abi-conformance`. *Spec:* §21.3; cross-ref 19 §19.2.2, §19.7.

- **[API-12]** Event payloads on the wire MUST use the **same `kind` strings and
  the same typed attributes** as the unified event log's catalog
  ([`19-observability-event-log.md`](19-observability-event-log.md) §19.7); the API
  MUST NOT define a parallel event vocabulary ([OBS-35]). An event delivered over
  `Control`/`Watch` MUST carry the log entry's `kind`, `at` (virtual-time + per-node
  icount), `source`, typed attributes, `level`, and an `observational` flag derived
  from the entry's `EventClass` ([OBS-13], §21.4). *Gate:* `gate:abi-conformance`,
  `gate:e2e-determinism`. *Spec:* §21.3; cross-ref 19 §19.2, §19.7.

- **[API-13]** Adding a new `kind` (command, breakpoint, fault, or event payload)
  MUST be a backward-compatible change that does **not** alter the wire envelope
  types and does **not** break decoders of existing kinds ([OBS-10], [G-8]): an old
  client receiving an unknown event `kind` MUST be able to treat it as opaque
  (carry its `kind` and attributes) rather than failing, and a server receiving an
  unknown command or fault `kind` MUST reject it with a typed
  `Unsupported`/`InvalidArgument` error (§21.5.3), never panic or corrupt the
  stream. *Gate:* `gate:abi-conformance`. *Spec:* §21.3; cross-ref 19 §19.2.2.

- **[API-14]** A client MUST treat an unfamiliar `kind` as **opaque** rather than
  rejecting it (forward compatibility), and the server MUST advertise the kinds it
  understands in `Hello`'s capabilities ([API-6]) so a client can detect that a
  `kind` it wants to *send* is unsupported before sending it. The capability set
  MUST be the four open-set categories (commands, breakpoints, faults, event
  payloads). *Gate:* `gate:abi-conformance`. *Spec:* §21.3, §21.6.

---

## 21.4 Streaming: replay then live tail, snapshot-on-attach

The streaming surface (`Control` and `Watch`) delivers the one event log
([`19-observability-event-log.md`](19-observability-event-log.md) §19.1) as a
**cursor**: a client attaches at a sequence number, receives **historical replay**
from that sequence up to the log's current length, then a **live tail** of new
entries as they are appended. The **causal subsequence is deterministic** ([OBS-21],
[OBS-23]); **observational entries flow too** ([OBS-15], [OBS-31]) so an interactive
viewer sees diagnostics and white-box markers, but they never affect the
determinism comparison. The stream is a **pure observation** of the run ([OBS-31]):
attaching, replaying, or detaching never changes the run or stalls the scheduler
([INV-8]).

On attach the server MAY include an **aggregate snapshot** — node statuses, fired
events, active faults, assertion states, savepoints, breakpoints, the recorded
command stream — every field of which is derivable by replaying the log to the
attach sequence ([OBS-4]), so a fresh client renders initial state without folding
the whole log itself.

```text
  Control / Watch stream:
    client ─▶ Attach { session_id, expected_epoch?, from_seq, client_name }
    server ─▶ Attached { epoch, event_log_len, current_state, capabilities,
                         version, snapshot? }       (snapshot-on-attach, §21.4)
    server ─▶ Event*  (replay: from_seq .. event_log_len)   ← historical, deterministic causal
    server ─▶ Event*  (live tail: appended entries)         ← causal + observational
    server ─▶ StateUpdate*   (run-state changes; not log entries — 20 §2)
    client ─▶ Command*  (Control bidi only; Watch uses Send)
    server ─▶ CommandResult* (correlated by command_id)
    server ─▶ SessionClosed { reason }   (final; no further responses)
```

- **[API-15]** `Control` and `Watch` MUST deliver the one event log
  ([`19-observability-event-log.md`](19-observability-event-log.md) §19.1) as a
  cursor: given `Attach.from_seq`, the server MUST first **replay** historical
  entries from `from_seq` up to the log length at attach (reported in `Attached`),
  then deliver a **live tail** of subsequently appended entries. `from_seq = 0`
  MUST replay the whole log; a `from_seq` beyond the current length MUST skip
  replay and deliver only the live tail. *Gate:* `gate:abi-conformance`,
  `gate:control-responsive`. *Spec:* §21.4; cross-ref 19 §19.6.5.

- **[API-16]** The streamed **causal subsequence** MUST be deterministic: across
  two runs of the same `(scenario, seed, schedule)`, a client replaying from the
  same `from_seq` MUST receive a byte-identical causal subsequence ([OBS-21],
  [OBS-23]) under the canonical payload encoding. **Observational entries MUST also
  flow** over the stream ([OBS-15], [OBS-31]) and MUST carry the `observational`
  flag (derived from `EventClass`, [OBS-13]) so a client can include them in an
  interactive view and exclude them from any determinism comparison it performs.
  *Gate:* `gate:e2e-determinism`, `gate:abi-conformance`. *Spec:* §21.4; cross-ref
  19 §19.3, §19.5.

- **[API-17]** Streaming MUST be a **pure observation** ([OBS-31]): subscribing,
  replaying, or detaching MUST NOT change the run, its schedule, or its causal
  subsequence, and MUST NOT stall the scheduler — the stream is fed from the
  session's broadcast bus ([SESS-24]) with lag-or-drop bounded buffers, so a slow
  or absent subscriber never back-pressures the actor ([INV-8]). The number of
  attached observers MUST NOT influence `State`. *Gate:* `gate:e2e-determinism`,
  `gate:control-responsive`. *Spec:* §21.4; cross-ref 20 §9, 19 §19.6.5.

- **[API-18]** On attach the server MUST report, in `Attached`, the session epoch
  (§21.5), the event-log length at attach, the current run-state, the protocol
  capabilities (§21.6), and the server version, and MAY include an aggregate
  **snapshot** (node statuses, fired events, active faults, assertion states,
  savepoints, breakpoints, and the recorded command stream) when the server's
  capabilities advertise `snapshot_on_attach`. Every snapshot field MUST be
  derivable by replaying the log to the attach sequence ([OBS-4]); the snapshot is
  an optimization, never a second source of truth. *Gate:* `gate:abi-conformance`.
  *Spec:* §21.4; cross-ref 19 §19.1.

- **[API-19]** Run-state transitions MUST be delivered as `StateUpdate` messages
  distinct from event-log entries, because a run-state change is not itself a log
  entry ([`20-session-control-plane.md`](20-session-control-plane.md) §2). A
  `StateUpdate` MUST carry the new `SessionState` and MUST be applied
  monotonically by clients (a later state supersedes an earlier one); a
  `Watch`-only client MUST be able to track run-state purely from `StateUpdate`
  plus the `SendResponse` state field ([API-9]). *Gate:* `gate:control-responsive`.
  *Spec:* §21.4; cross-ref 20 §2.

---

## 21.5 Epoch guards and session identity

A `SessionRef` is `(session_id, session_epoch, …)`. The **epoch** is a
server-monotonic counter incremented on every `CreateSession` or
`ResumeSession`, so a session id that has been destroyed and recreated has a
different epoch. A client that cached an id can pass `expected_epoch` on attach
and on any lifecycle/command RPC; the server fails fast (a typed precondition
error, or `SessionClosed` with reason `EPOCH_MISMATCH` on a stream) when the
epoch does not match — detecting a **recycled session id** before a command lands
on the wrong incarnation.

The session also exposes its **reproduction context**: the recorded operator
command stream ([`20-session-control-plane.md`](20-session-control-plane.md) §8,
[SESS-20]) keyed by the virtual-time boundary at which each command was applied, so
an operator-driven run is as reproducible as a scripted one ([G-6]). The API
surfaces this through the per-attach snapshot and the unary `GetReproduction` RPC.

### 21.5.1 Epoch guards

```text
  CreateSession  → SessionRef { id="s7", epoch=3, … }   (epoch monotone per server)
  …session destroyed, "s7" recreated…                   (epoch now 4)
  client cached epoch=3:
    Attach { id="s7", expected_epoch=3 } → SessionClosed{ EPOCH_MISMATCH }   (recycled id detected)
    Send   { id="s7", expected_epoch=3 } → FailedPrecondition (epoch 3 != 4)
```

- **[API-20]** A `SessionRef` MUST carry a `session_id` and a server-monotonic
  `session_epoch` incremented on every `CreateSession` or `ResumeSession`, so a
  recreated id has a distinct epoch. Every attach, lifecycle (`DestroySession`,
  `GetReproduction`), and command RPC (`Send`) MUST accept an optional
  `expected_epoch`; when set and it does not match the session's current epoch,
  the server MUST fail fast — a typed `FailedPrecondition`/epoch-mismatch error
  on a unary RPC, or a
  `SessionClosed { reason: EPOCH_MISMATCH }` on a stream — and MUST NOT apply the
  command. This detects a **recycled session id** before a command lands on the
  wrong incarnation. *Gate:* `gate:abi-conformance`, `gate:control-responsive`.
  *Spec:* §21.5, §21.5.1.

- **[API-21]** Session identity (`session_id`, `session_epoch`) MUST be the
  closed, intrinsic part of the protocol (not an open-set kind), and the epoch MUST
  be a pure server-side concept that MUST NOT enter `State` or the causal
  subsequence: the epoch is host bookkeeping for client cache invalidation, never a
  simulation input ([INV-1], [OBS-23]). Two runs differing only in the server epoch
  they happened to be assigned MUST produce identical causal subsequences. *Gate:*
  `gate:e2e-determinism`. *Spec:* §21.5; cross-ref 19 §19.5.

### 21.5.2 Reproduction context

- **[API-22]** The API MUST expose the session's **recorded command stream** — the
  control log of operator interventions ([`20-session-control-plane.md`](20-session-control-plane.md)
  §8, [SESS-20]), each entry carrying its payload, the virtual-time boundary at
  which it was applied, the event-log sequence right before it ran, and the
  `CommandResult` returned — through both the per-attach snapshot ([API-18]) and a
  unary `GetReproduction` RPC. This is the reproduction context: re-applying the
  recorded stream at the same virtual-time boundaries reproduces an operator-driven
  run bit-identically ([SESS-21], [G-6], cross-ref 20/§8, 23, 06). *Gate:*
  `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:* §21.5.2; cross-ref 20 §8,
  23, 06.

- **[API-23]** Each recorded command MUST be keyed by the **virtual-time boundary**
  at which it took effect, never by the host wall-clock at which it was issued
  ([SESS-13], [SESS-21]); a wall-clock timestamp MAY accompany it as an
  *observational* ordering aid for commands issued within one virtual-time tick, but
  the reproduction MUST depend only on the virtual-time key. A reproduction context
  produced by an interactively-driven run and one produced by a scripted run of the
  same schedule MUST be equivalent (re-applying either yields the same causal
  subsequence). *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:*
  §21.5.2; cross-ref 20 §8.

### 21.5.3 Errors

The command-result and RPC-status taxonomy mirrors the session's typed,
state-preserving rejection ([SESS-6], [SESS-29]): a rejected command leaves the
session unchanged and returns a typed reason.

```text
  command rejection codes (CommandResult.rejected):
    INVALID_STATE     command not valid in the current run-state (20 §2.1, SESS-6)
    NOT_FOUND         referenced breakpoint/fault tag/checkpoint absent (SESS-29)
    INVALID_ARGUMENT  malformed payload / bad attribute schema
    UNSUPPORTED       unknown command/fault/bp kind not in capabilities (API-13)
    INTERNAL          backend or oracle error (BackendError / OracleViolation, SESS-29)
```

- **[API-24]** A command the session rejects MUST be reported as a typed
  `CommandResult::Rejected` with a code from the closed set `INVALID_STATE`,
  `NOT_FOUND`, `INVALID_ARGUMENT`, `UNSUPPORTED`, `INTERNAL`, mirroring the
  session's typed rejection ([SESS-6], [SESS-29]); a rejected command MUST leave
  the session state unchanged (rejection is total and side-effect-free) and MUST
  NOT close the stream. Lifecycle RPC failures (unknown session, epoch mismatch,
  unknown scenario) MUST use the equivalent transport status. *Gate:*
  `gate:control-responsive`, `gate:abi-conformance`. *Spec:* §21.5.3; cross-ref 20
  §11.

---

## 21.6 Versioning and conformance

Per [G-8], the control-plane RPC is one of the three boundary ABIs that MUST be
explicitly versioned and covered by conformance tests / golden vectors. The
protocol carries an explicit **protocol version**; the open-set kind catalog
(§21.3) is discovered at runtime via `Hello`; and a **reference client +
conformance suite** drives the full lifecycle against both the QEMU backend and
the in-process double, gated by `gate:abi-conformance`
([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)).

- **[API-25]** The protocol MUST carry an **explicit protocol version**
  (major.minor.patch + build identifier) returned by `Hello` and in `Attached`.
  A wire-incompatible change MUST bump the major version; a backward-compatible
  addition (a new RPC, a new open-set `kind`, a new optional field) MUST NOT bump
  the major version ([G-8], [API-13]). A client and server MUST be able to detect
  a major-version mismatch from `Hello` and refuse to proceed with a typed error
  rather than mis-decoding. *Gate:* `gate:abi-conformance`. *Spec:* §21.6.

- **[API-26]** The control-plane RPC MUST be covered by **golden vectors**: a
  frozen, content-addressed corpus of serialized requests, responses, events, and
  payload kinds for the current protocol version, byte-for-byte compared by
  `gate:abi-conformance` (the RPC third of the boundary-ABI suite,
  [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §8,
  alongside the shmem and protocol vectors). A change to the wire MUST regenerate
  the golden vectors in the same change, and an unintended wire change MUST fail
  the gate. *Gate:* `gate:abi-conformance`. *Spec:* §21.6; cross-ref 24 §8.

- **[API-27]** A **reference client and conformance suite** MUST exist that drives
  the **full session lifecycle** — `Hello`, `ListScenarios`, `CreateSession`
  (scenario ref and inline def; seeded; start-paused), attach via `Control` and via
  `Watch`+`Send`, `continue`/`pause`/`step`, `inject_fault`/`heal_fault`,
  `set`/`remove` breakpoint, `create_savepoint`, `fork`, `query`,
  `GetReproduction`, `DestroySession`, and epoch-guard rejection — and asserts
  identical observable behavior against **both** the QEMU backend (10) and the
  in-process double (`SimDouble`, 24 §3). A divergence between the two backends
  through this interface is a conformance failure. *Gate:* `gate:abi-conformance`.
  *Spec:* §21.6; cross-ref 24 §3, 20 §10.

- **[API-28]** The conformance suite MUST include **contract/snapshot tests over
  every RPC and every message variant**: each unary RPC's request/response, every
  `ControlRequest`/`ControlResponse` envelope arm (`Attached`, `Event`,
  `CommandResult`, `StateUpdate`, `StopReply`/equivalent, `SessionClosed`), each
  command-result code (§21.5.3), and each open-set `kind` from the capabilities set
  MUST have a snapshot test pinning its serialized shape. A new RPC or message
  variant MUST NOT merge without its contract test. *Gate:* `gate:abi-conformance`.
  *Spec:* §21.6; cross-ref 19 §19.7.

- **[API-29]** Because the session is defined against the pluggable backend trait
  ([SESS-26]), the conformance suite, the reference client, and the
  `gate:control-responsive` API tests MUST run against the in-process `SimDouble`
  **without booting real QEMU** ([SESS-28], 24 §3); only fidelity properties
  require the QEMU backend. An API or conformance test that needs real QEMU to
  exercise the *control plane* (as opposed to guest fidelity) is a design defect.
  *Gate:* `gate:abi-conformance`, `gate:control-responsive`. *Spec:* §21.6;
  cross-ref 20 §10, 24 §2, §3.

---

## 21.7 Determinism: the API must not perturb the run

The load-bearing constraint: **the API MUST NOT introduce nondeterminism into the
run.** A run is `reduce(ScenarioDef, Schedule)` ([INV-1]); the API is a control and
observation surface over the session actor, and the session already guarantees
that mutating commands take effect only at **deterministic quantum boundaries**
([SESS-13], [SESS-21], 20 §5/§8). The API inherits this: when a command lands —
not the wall-clock at which a client sent it, the number or speed of attached
observers, the transport (in-process vs RPC), or the order RPCs arrived on
different connections — MUST NOT influence `State`.

```text
  what the API surface guarantees about determinism:
  ───────────────────────────────────────────────────────────────────────────
  mutating command (inject/heal/fork/savepoint/Action-bp)
       → applied at the next QUANTUM BOUNDARY (20 §5), recorded in the
         control log keyed by virtual-time boundary (20 §8) → deterministic
  read-only RPC (Hello/List*/Watch/Query/GetReproduction)
       → pure observation; never enters the schedule (20 §8, SESS-22)
  client wall-clock / RPC arrival order / #observers / transport
       → MUST NOT influence State (INV-1) — the boundary is the only timing truth
```

- **[API-30]** The API MUST NOT introduce nondeterminism into the run ([INV-1]):
  a mutating command MUST take effect at a **deterministic quantum boundary**
  ([SESS-13], [SESS-21], 20 §5), and the client's wall-clock send time, the
  transport (in-process vs RPC), the number and speed of attached observers, and
  the arrival order of RPCs on independent connections MUST NOT influence which
  boundary it lands at, the causal subsequence, or `State`. Two runs of the same
  `(scenario, seed, schedule)` driven by the same command stream at the same
  virtual-time boundaries MUST be bit-identical regardless of transport or observer
  load. *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`,
  `gate:control-responsive`. *Spec:* §21.7; routes [INV-1], [INV-8].

- **[API-31]** Read-only RPCs (`Hello`, `ListScenarios`, `ListSessions`, `Watch`,
  `GetReproduction`, and `query`-class reads) MUST be pure observation: they MUST
  NOT enter the schedule, MUST NOT appear in the reproduction context, and MUST be
  answerable from the lock-free mirror / event-log cursor without entering the
  stepping path ([SESS-22], [SESS-23]). A run with and without read-only API
  traffic MUST produce the identical canonical event log. *Gate:*
  `gate:replay-oracle`, `gate:control-responsive`. *Spec:* §21.7; cross-ref 20
  §8, §9.

---

## 21.8 Summary

```text
SCOPE (§21.1): a programmatic in-process Rust client + an RPC surface (gRPC/Connect
  over HTTP/2), both ONE ControlClient trait. THIN wrapper over the session command
  set (20 §4). NO web UI, NO browser-shaped RPCs (NG-4).

SERVICE (§21.2): Hello · ListScenarios · CreateSession · ResumeSession ·
  ListSessions · DestroySession · GetReproduction · Control(bidi) ·
  Watch(server-stream) · Send(unary). Each maps to a session command (20) or a
  mirror read.

PAYLOAD MODEL (§21.3): open-set dotted `kind` + typed attribute map for commands,
  events, faults, breakpoints — SAME catalog as the event log (19 §19.7). New kinds
  don't break the wire (G-8); envelope/source/state machine stay closed.

STREAMING (§21.4): attach at from_seq → historical REPLAY → live TAIL. Causal
  subsequence deterministic (OBS-21); observational entries flow too (OBS-15).
  Snapshot-on-attach. Pure observation, never stalls the scheduler (OBS-31, INV-8).

IDENTITY (§21.5): SessionRef = (id, epoch); epoch guards detect a recycled id.
  Reproduction context = the recorded command stream keyed by virtual-time boundary
  (20 §8) → operator-driven runs reproduce bit-identically (G-6).

VERSIONING (§21.6): explicit protocol version; golden vectors; a reference client +
  conformance suite drives the full lifecycle against BOTH the QEMU backend and the
  in-process double — gate:abi-conformance. Contract/snapshot tests over every RPC
  + message variant.

DETERMINISM (§21.7): the API MUST NOT perturb the run — commands take effect at
  deterministic quantum boundaries (20); transport/observer-load/wall-clock never
  influence State (INV-1).
```

The shape of this file is the shape of the boundary: a thin, versioned, open-set
wrapper over the one session command set, observing the one event log, that adds
expressiveness without adding a single new source of nondeterminism — so a run
driven through the API is exactly as reproducible as a scripted one, whether it
ran in-process against the double or over the wire against QEMU.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is the control API, tracked by [PLAN-3] and kept in
> sync with the master plan by the doc lint
> ([`28-engineering-standards.md`](28-engineering-standards.md)).

- [x] **T-API-1** Define the one `ControlClient` trait (async, typed) and its two
  implementations — an in-process client reaching a same-process
  `crucible-session` actor without serializing, and an RPC client over HTTP/2 —
  so callers are transport-agnostic; assert the wire types are the serialized form
  of the in-process types. — satisfies [API-1], [API-4]; spec §21.1.
  Completed by `checks.crucible.phase5.apiControlClient`: `crucible-api::client`
  defines the async `ControlClient` trait, `InProcessControlClient` over the
  same-process session actor handles, `RpcControlClient` over an HTTP/2 endpoint,
  and a shared `ControlWireModel` backed by the frozen RPC ABI encoder. The
  focused gate test proves both transports negotiate through the same typed trait:
  the RPC client posts the typed `Hello` payload over HTTP/2 to
  `/crucible.rpc/hello`, and both transports serialize through the same wire
  model; command mapping remains T-API-2.
- [x] **T-API-2** Implement the API as a thin wrapper over the session command set:
  every method/RPC maps to one session command (20 §4) or one lock-free mirror
  read, with no control semantics of its own and no browser-shaped request. —
  satisfies [API-2], [API-3]; spec §21.1, §21.2.
  Completed by `checks.crucible.phase5.apiSessionCommandMapping`:
  `crucible-api::session_mapping` declares the closed service-method mapping,
  the full `SessionCommandKind::ALL` API command mapping, and the
  `validate_thin_api_mapping` gate assertion. `CreateSession` maps to
  `SessionCommandKind::Start`, `DestroySession` maps to `Stop`, session listings
  and watch attach snapshots read `LiveQueryKind::Status`, and `Control`/`Send`
  accept exactly one session command per typed programmatic envelope. Lifecycle
  RPC execution remains T-API-3; streaming equivalence remains T-API-4.
- [x] **T-API-3** Implement the discovery/lifecycle unary RPCs — `Hello`
  (version + open-set capabilities), `ListScenarios`, `CreateSession` (scenario ref
  or inline def + seed + start-paused), `ResumeSession` (self-contained scenario
  payload and checkpoint closure), `ListSessions`, `DestroySession`
  (epoch-guarded, idempotent) — each mapped to its session op (§21.2.1). —
  satisfies [API-5], [API-6], [API-7], [API-8]; spec §21.2, §21.2.1.
  Completed by `checks.crucible.phase5.apiLifecycleUnary`:
  `crucible-api::lifecycle` implements side-effect-free `Hello` and
  `ListScenarios`, scenario-ref and inline `CreateSession` backed by a live
  `SessionActor` and `SessionCommand::Start`, lock-free mirror-backed
  `ListSessions`, self-contained scenario-payload/checkpoint-closure
  `ResumeSession`, and epoch-guarded/idempotent `DestroySession` via
  `SessionCommand::Stop`. The shared `ControlClient` trait exposes those unary
  methods, with
  `InProcessLifecycleClient` driving the actor registry directly and
  `RpcControlClient` posting the corresponding HTTP/2 unary RPC paths.
  Scenario-ref creation re-materializes canonical scenario material with the
  request seed; inline RPC carries the scenario seed separately from the request
  seed so mismatches are rejected. Streaming `Control`, `Watch`, and `Send`
  remain T-API-4.
- [x] **T-API-4** Implement the bidirectional `Control` stream and the
  `Watch`+`Send` pair, asserting Watch+Send is capability-equivalent to bidi
  (full lifecycle drivable from either), with `Send` returning CommandResult +
  optional StateUpdate. — satisfies [API-9], [API-10]; spec §21.2.
  Completed by `checks.crucible.phase5.apiStreamingEquivalence`:
  `crucible-api::streaming` defines shared attach metadata, `ControlStream`,
  `WatchStream`, unary `SendRequest`/`SendResponse`, typed `CommandResult`, and
  optional `StateUpdate`. `ControlClient`/`RpcControlClient` expose transport
  paths for `Control` attach/send, `Watch` attach, and unary `Send`; all command
  paths advertise the same command capability set from the thin API mapping
  table, dispatch accepted commands through the same session actor mailbox
  helper, use the session lifecycle transition model for invalid-state command
  results, and now share monotonic live `StateUpdate` streaming via T-API-7.
- [x] **T-API-5** Implement the open-set payload model (dotted `kind` + typed
  attribute map) for commands/events/faults/breakpoints, reusing the event-log
  catalog (19 §19.7); opaque-unknown-kind handling on receive, typed
  Unsupported/InvalidArgument on send; capabilities-advertised kinds. — satisfies
  [API-11], [API-12], [API-13], [API-14]; spec §21.3.
  Completed by `checks.crucible.phase5.apiOpenSetPayload`:
  `crucible-api::open_set` defines the shared `OpenSetPayload` typed attribute
  map, category capability catalog, event-log envelope conversion, opaque
  unknown-event receive path, and typed Unsupported/InvalidArgument send
  validation. Event payload schemas are generated from the unified event-kind
  catalog, command kinds from the thin session command mapping table, faults from
  the existing taxonomy keys, and breakpoint kinds from the shared predicate
  vocabulary. `Hello` now advertises the four dotted open-set categories and the
  ABI golden seed uses dotted command and catalog event kinds.
- [x] **T-API-6** Implement the streaming cursor: replay from `from_seq` then live
  tail, deterministic causal subsequence with observational entries flowing
  (flagged), pure non-stalling observation, and optional snapshot-on-attach with
  every field log-derivable. — satisfies [API-15], [API-16], [API-17], [API-18];
  spec §21.4; cross-ref 19 §19.6.5, 20 §9.
  Completed by `checks.crucible.phase5.apiStreamingCursor`:
  `crucible-session::SessionEventLog` now exposes attach-tail subscription and a
  retained-prefix snapshot fold without changing append or broadcast semantics.
  `crucible-api::streaming` reports the attach replay tail as `event_log_len`,
  includes a log-derived `AttachSnapshot` when `snapshot_on_attach` is
  advertised, and adds `recv_event` helpers that convert replay/live frames into
  open-set API event envelopes carrying cursor, level, source, and
  observational flag. The cursor gate replays causal plus observational entries
  from `from_seq = 0`, proves attach beyond the tail skips historical replay, and
  verifies live-tail delivery after attach without changing the live state.
- [x] **T-API-7** Implement `StateUpdate` delivery distinct from event-log entries,
  applied monotonically, so a Watch-only client tracks run-state from
  StateUpdate + SendResponse. — satisfies [API-19]; spec §21.4; cross-ref 20 §2.
  Completed by `checks.crucible.phase5.apiStateUpdateStream`:
  `crucible-api::streaming` now subscribes each `Control`/`Watch` attach to the
  session actor's state-transition bus, exposes monotone
  `StreamingStateUpdateFrame` delivery separately from event-log frames, and
  maps state-transition lag to a distinct streaming error. The RPC client reads
  one framed stream and demultiplexes event and state-update frames on demand so
  a state-only receiver cannot be starved behind undrained event frames. The
  HTTP/2 gate emits framed `state-update-frame` messages beside event frames.
  The state-update gate proves a Watch-only client advances Loaded -> Paused ->
  Running -> Paused -> Stopped from `SendResponse` plus `StateUpdate` frames,
  verifies monotone state-update sequence numbers, and asserts those updates do
  not appear as event-log frames.
- [x] **T-API-8** Implement epoch guards: server-monotonic `session_epoch` on
  `SessionRef`, `expected_epoch` on attach/lifecycle/command RPCs, fast-fail with
  FailedPrecondition / SessionClosed(EPOCH_MISMATCH) on a recycled id; prove the
  epoch never enters State or the causal subsequence. — satisfies [API-20],
  [API-21]; spec §21.5, §21.5.1.
  Completed by `checks.crucible.phase5.apiEpochGuards`:
  `SessionRef` remains the closed `(id, epoch, seed)` protocol identity, the
  lifecycle control plane allocates a server-monotonic epoch on every
  `CreateSession`, and `DestroySession`, `Control`/`Watch` attach, and `Send`
  all accept an optional `expected_epoch` guard. Stale session references and
  mismatched expected epochs return typed epoch-mismatch errors before actor
  dispatch, state mutation, or event-log append. The epoch guard gate proves
  matching epochs allow cleanup, stale epochs leave live state and event-log
  cursor unchanged, and session epochs advance across successive creates while
  remaining outside the causal event-log subsequence.
- [x] **T-API-9** Implement the reproduction context: expose the recorded command
  stream (keyed by virtual-time boundary, with at-seq, result, observational
  wall-clock aid) via per-attach snapshot and `GetReproduction`; prove
  interactive and scripted runs of the same schedule reproduce equivalently. —
  satisfies [API-22], [API-23]; spec §21.5.2; cross-ref 20 §8, 23, 06.
  Completed by `checks.crucible.phase5.apiReproductionContext`:
  the session actor now publishes an actor-owned `SessionReproductionLog` from
  the engine boundary-control log, carrying the command payload, virtual-time
  boundary, pre-command event-log sequence, accepted result, and an
  observational ordering aid that is not a replay input. `AttachSnapshot` carries
  the same recorded command stream as unary `GetReproduction`, both in-process
  and over the HTTP/2 RPC client. The gate proves `GetReproduction` is read-only,
  stale expected epochs fail before actor dispatch, attach snapshots and unary
  reads agree, and an injected intervention driven interactively through
  `Control` matches the same scripted `Send` schedule.
- [x] **T-API-10** Implement the typed command-rejection and RPC-status taxonomy
  (INVALID_STATE/NOT_FOUND/INVALID_ARGUMENT/UNSUPPORTED/INTERNAL), total and
  side-effect-free, never closing the stream. — satisfies [API-24]; spec §21.5.3;
  cross-ref 20 §11.
  Completed by `checks.crucible.phase5.apiCommandStatusTaxonomy`: `CommandResult`
  rejections now use the closed five-code taxonomy and map to the same
  `RpcStatusCode` set used by transport errors. The HTTP/2 client decodes typed
  lifecycle and streaming failures for epoch mismatch, missing scenarios, and
  missing sessions without closing live streams; rejected `Send` commands remain
  side-effect-free and subsequent commands on the stream still run.
- [x] **T-API-11** Implement explicit protocol versioning (major.minor.patch +
  build) in Hello/Attached, major-bump on wire-incompatible change, detect+refuse
  on major mismatch. — satisfies [API-25]; spec §21.6.
- [x] **T-API-12** Freeze golden vectors for the RPC ABI (requests, responses,
  events, payload kinds) wired into `gate:abi-conformance` as the RPC third of the
  boundary-ABI suite; regenerate-in-the-same-change discipline. — satisfies
  [API-26]; spec §21.6; cross-ref 24 §8.
  Completed by `crucible-api::rpc_abi` and
  `checks.crucible.phase2.gates.abiConformance`: the seed RPC ABI corpus freezes
  Hello request/response, Attached, one command request/response, one event, and
  the advertised open-set payload kinds with explicit
  `major.minor.patch+build` versioning and typed major-mismatch rejection. The
  full reference-client lifecycle suite remains T-API-13.
- [x] **T-API-13** Build the reference client + conformance suite driving the full
  lifecycle (Hello…DestroySession incl. both attach paths, faults, breakpoints,
  savepoint, fork, GetReproduction, epoch-guard rejection) against BOTH the QEMU
  backend and the in-process `SimDouble`, with contract/snapshot tests over every
  RPC and message variant. — satisfies [API-27], [API-28], [API-29]; spec §21.6;
  cross-ref 24 §3, 20 §10.
  Completed by `checks.crucible.phase5.apiReferenceClientConformance`: the
  reference `ControlClient` conformance driver now runs the full lifecycle through
  `InProcessLifecycleClient` over a `SimDouble` stepping backend and through the
  HTTP/2 `RpcControlClient`. The suite exercises scenario-ref and inline
  `CreateSession`, both `Control` and `Watch` attach paths, `Send` through
  continue/pause/step/fault/breakpoint/savepoint/fork/query, `GetReproduction`,
  stale epoch rejection, `DestroySession`, and idempotent destroy. The gate also
  runs the `crucible-qemu` `qemu_node_satisfies_simulation_backend_trait` test,
  which exercises `QemuNode` step/apply/fingerprint/snapshot/restore/shutdown
  through the `SimulationBackend` contract. The ABI and wire-snapshot tests now
  explicitly cover the frozen RPC request, response, streaming-frame, error, and
  open-set payload variants.
- [x] **T-API-14** Prove the API introduces no nondeterminism: mutating commands
  land at deterministic quantum boundaries; transport, observer load, wall-clock,
  and RPC arrival order do not influence the causal subsequence or State; read-only
  RPCs never enter the schedule. — satisfies [API-30], [API-31]; spec §21.7;
  cross-ref 20 §8, §9.
  Completed by `checks.crucible.phase5.apiNondeterminism`: the shared
  `ControlClient` nondeterminism gate drives the same paused-boundary
  scheduler-control stream through quiet/noisy in-process and HTTP/2 RPC
  clients, plus RPC lanes that assert the test server observed both
  `GetReproduction`-before-`Send` and `Send`-before-`GetReproduction` orders on
  independent client requests. It then compares final state, event-log cursor,
  causal/observational event counts, last event sequence, reproduction context,
  and accepted command results with transport removed from the projection. A
  separate streaming lane appends a non-empty causal/observational event burst
  while undrained `Control` and `Watch` observers are attached, then compares the
  replayed causal event payload projection between quiet and noisy runs. The
  noisy lanes interleave read-only `Hello`/`List*`/`Watch`/`GetReproduction` and
  query-class traffic around the mutating commands, and yield between requests
  while production API control paths statically forbid wall-clock reads. The gate
  also re-runs the reproduction-context and streaming-cursor read-only checks.
