# 19 — Observability: the unified event log

This file specifies Crucible's **event log**: the single, totally-ordered,
content-addressed, icount-stamped event stream that is *simultaneously* the
determinism oracle, the assertion-checking input, the debugging artifact, the
fork-point index, and the coverage record. There is exactly one log, and it is
the one source of truth for everything that happened during a run.

The thing this file is most concerned with is *collapsing* what would otherwise
be several overlapping records — a determinism trace, a separate
human-debugging log, a separate assertion event stream, a separate coverage
fingerprint — into one stream from which every consumer takes a *projection*.
The benefit of one stream is that the determinism gate, the assertion checker,
the divergence bisector, the coverage harvester, and the live control-plane
viewer all see *the same ordered facts*; there is no second record that can drift
out of sync with the first.

Requirement IDs in this file use the prefix `OBS` (see
[`00-conventions.md`](00-conventions.md)). The canonical gates referenced here —
`gate:replay-oracle`, `gate:e2e-determinism`, `gate:divergence-bisect`,
`gate:content-address`, and `gate:harness-lint` — are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md). This
file is a producer for, and a hard dependency of, the assertion vocabulary
([`18-assertions-properties.md`](18-assertions-properties.md)), the control-plane
streaming surface ([`20-session-control-plane.md`](20-session-control-plane.md),
[`21-api.md`](21-api.md)), coverage and search
([`22-advanced-features.md`](22-advanced-features.md)), reproduction artifacts
([`23-cli.md`](23-cli.md)), and divergence bisection
([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)). The
temporal graph stores the log's offset and shares its prefix
([`07-temporal-graph.md`](07-temporal-graph.md) §3, §5); the guest↔host channel
feeds it observational guest markers
([`16-guest-host-channel.md`](16-guest-host-channel.md) §16.5).

The code blocks in this file are illustrative sketches per the conventions in
[`00-conventions.md`](00-conventions.md) ("Code sketches in this RFC"), not the
implementation; the authoritative statement is always the prose requirement. A
sketch that disagrees with a requirement is a defect in the sketch.

## 19.1 One log, one source of truth

The most important property of Crucible's observability is *unity*: there is one
event log, and every observability consumer reads a projection of it. A run does
not produce a determinism trace *and* a debug log *and* an assertion stream *and*
a coverage record; it produces one totally-ordered stream of entries, and the
oracle, the assertion checker, the bisector, the coverage harvester, and the live
viewer each filter and fold that one stream. This is the design decision that
keeps the artifacts from drifting apart: the thing the determinism gate compares
is *the same record* a human opens to debug, *the same record* the assertion pass
folds over, and *the same record* a fork offset points into.

- **[OBS-1]** Crucible MUST maintain exactly **one** event log per run: a single,
  totally-ordered stream of entries that is simultaneously the determinism oracle
  ([§19.5](#195-determinism-the-causal-subsequence-is-byte-identical)), the
  assertion-checking input ([§19.6](#196-consumers-of-the-log)), the debugging
  artifact, the fork-point index ([§19.4](#194-content-addressing-and-prefix-sharing)),
  and the coverage record. There MUST NOT be a second, parallel record of "what
  happened" (no separate determinism trace, no separate JSONL debug log, no
  separate assertion event stream) that a consumer reads instead of the log; every
  consumer MUST read a **projection** of the one log. *Gate:* `gate:replay-oracle`,
  `gate:harness-lint`. *Spec:* §19.1.

- **[OBS-2]** Every entry in the log MUST be appended through a single append path
  so that sequencing, icount-stamping, and the causal/observational classification
  ([§19.3](#193-causal-vs-observational-is-baked-into-the-schema)) are applied
  uniformly. No engine, node, device, plugin, or control-plane code path MAY write
  to the log except through this append path, so that the log is the *only* place
  events are recorded and its total order is the *only* ordering of record. *Gate:*
  `gate:harness-lint`. *Spec:* §19.1, §19.2.

- **[OBS-3]** The log MUST be **append-only** within a run: an appended entry is
  never mutated or removed in place. Forking truncates a *copy* at an offset
  ([§19.4](#194-content-addressing-and-prefix-sharing)) rather than editing the
  shared prefix; the prefix up to a fork point is immutable and shared
  ([`07-temporal-graph.md`](07-temporal-graph.md) §5). *Gate:* `gate:content-address`.
  *Spec:* §19.1, §19.4.

- **[OBS-4]** Each consumer of the log MUST be expressible as a pure **projection**
  (a filter and/or fold) over the one stream: the determinism comparison is the
  projection that keeps the causal subsequence ([§19.5](#195-determinism-the-causal-subsequence-is-byte-identical)),
  assertion evaluation is the fold that interprets assertion-evaluated and
  state-changed entries ([§19.6](#196-consumers-of-the-log)), coverage is the
  projection that collects coverage entries, and the live viewer is the streaming
  identity projection. A consumer MUST NOT require any record other than the log.
  *Gate:* `gate:harness-lint`. *Spec:* §19.1, §19.6.

## 19.2 The entry schema

Every log entry carries: a monotonic sequence number; the virtual-time / icount
coordinate at which it occurred; its source; a structured, open-set payload
(`kind` plus typed attributes); a display level; and — *as part of the schema, not
a side flag* — its classification as **causal** or **observational**. The
classification is a property of the entry's variant, decided at the typed append
site, not a boolean a caller can forget to set. That distinction is the subject of
[§19.3](#193-causal-vs-observational-is-baked-into-the-schema); this section gives
the whole record shape.

```rust,illustrative
/// One entry in the unified event log (§19.1). Every observability consumer
/// reads a projection of a stream of these (§19.6).
///
/// `class` is *not* a side flag: it is a typed field that the append API sets
/// from the payload variant (§19.3), so the causal/observational split is a
/// property of the schema, not of a caller's discipline.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LogEntry {
    /// Monotonic per-run sequence number, assigned at append (§19.2). Dense and
    /// gap-free over the *whole* log; the determinism comparison renumbers the
    /// causal subsequence separately (§19.5) so observational interleaving does
    /// not shift causal positions.
    pub seq: u64,

    /// The virtual-time / icount coordinate at which this entry occurred (09).
    /// A pure function of the schedule prefix for causal entries (INV-4); the
    /// canonical ordering key together with `source` and `seq` (INV-3).
    pub at: VirtualTime, // virtual_time + per-node icount (09)

    /// Where this entry originated (§19.2.1).
    pub source: EventSource,

    /// What happened: an open-set `kind` with typed attributes (§19.2.2, §19.7).
    pub payload: EventPayload,

    /// Display priority (§19.2.3): how loud, orthogonal to `class` (how
    /// determinism-relevant). Never used by the determinism comparison.
    pub level: Level,

    /// Whether this entry is part of the deterministic backbone (`Causal`) or a
    /// run-to-run-variable observation (`Observational`). Determined by the
    /// payload variant at the typed append site, never set ad hoc (§19.3).
    pub class: EventClass,
}

/// The causal-vs-observational distinction, baked into the schema (§19.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum EventClass {
    /// Part of the deterministic backbone: MUST be byte-identical across runs of
    /// the same (scenario, seed, schedule). This is what the determinism gates
    /// compare (§19.5).
    Causal,
    /// A descriptive observation that MAY legitimately vary between equivalent
    /// runs (poll counts, white-box markers, host diagnostics). Excluded from
    /// the determinism comparison (§19.3, §19.5).
    Observational,
}

/// Display priority, orthogonal to `EventClass` (§19.2.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Level {
    Trace, // highest-frequency, lowest-information (per-tick internal state)
    Debug, // routine internal events, noisy in normal operation
    Info,  // meaningful state changes a user normally wants to see
    Warn,  // unusual but non-fatal conditions
    Error, // failures and assertion violations
}
```

A single causal entry, rendered as one canonical line of the log's text
projection (the canonical serialization is the binary form of
[§19.4](#194-content-addressing-and-prefix-sharing); this text rendering is the
human/debug projection):

```text
seq=00041  at=vt:000123456ns icount{node=raft-a:9_812_440}  src=node:raft-a  class=causal  lvl=info  kind=message_delivered  from=raft-b to=raft-a link=l0 seq=7 len=512 deliver_icount=9_812_440
```

And an observational entry (a host diagnostic), interleaved in the same stream but
excluded from the determinism comparison:

```text
seq=00042  at=vt:000123456ns icount{node=raft-a:9_812_440}  src=engine  class=observational  lvl=debug  kind=diagnostic  name=executor.poll_count node=raft-a value=37
```

- **[OBS-5]** Every log entry MUST carry, at minimum: a monotonic per-run `seq`
  (§19.2); the `at` virtual-time / icount coordinate at which it occurred (09); a
  `source` (§19.2.1); a structured `payload` with an open-set `kind` and typed
  attributes (§19.2.2, §19.7); a display `level` (§19.2.3); and an `EventClass`
  (`Causal` or `Observational`) determined by the payload variant (§19.3). An
  entry missing any of these fields is malformed. *Gate:* `gate:harness-lint`.
  *Spec:* §19.2.

- **[OBS-6]** `seq` MUST be assigned at append, dense and gap-free over the whole
  log (causal and observational entries share one numbering), and MUST be
  monotonically increasing in append order. `seq` MUST NOT be used as the
  cross-run determinism comparison key (because observational interleaving differs
  between runs); the determinism comparison renumbers the causal subsequence
  independently ([§19.5](#195-determinism-the-causal-subsequence-is-byte-identical)).
  *Gate:* `gate:harness-lint`, `gate:replay-oracle`. *Spec:* §19.2, §19.5.

- **[OBS-7]** Every entry MUST be stamped with the `at` coordinate (virtual time +
  the per-node icount, 09) at which the event occurred (for outputs/transitions) or
  was taken (for state reads), consistent with the black-box observation stamping
  of [`16-guest-host-channel.md`](16-guest-host-channel.md) [GHC-8] and the
  injection ordering of [INV-3]. The total order of the log MUST be the
  `(at.virtual_time, source.node_id, seq)` order ([INV-3]); an entry whose
  position depends on host wall-clock or host-scheduling order is a contract
  violation. *Gate:* `gate:e2e-determinism`. *Spec:* §19.2.

### 19.2.1 Source

The `source` answers "who said this," and is one of a closed set of origins so
that projections can filter by origin (e.g. "show only what node `raft-a` did")
without parsing free text.

```rust,illustrative
/// The origin of a log entry (§19.2.1). A closed set so projections can filter
/// by origin without parsing free text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EventSource {
    /// A scenario-defined event/fault in the Plan (06, 17).
    Scenario { event: ScenarioEventId },
    /// The simulation engine itself: the scheduler, the temporal graph, the
    /// fault subsystem, the assertion checker (08, 17, 18).
    Engine,
    /// A node: a VM node or an I/O sub-node (06, 15), identified by NodeId.
    Node { node: NodeId },
    /// A guest, via black-box observation or a white-box doorbell marker (16).
    Guest { node: NodeId },
    /// A control-plane command, tagged with the client-supplied correlation id
    /// so subscribers can correlate cause (the command) and effect (20, 21).
    Command { command_id: CommandId },
}
```

- **[OBS-8]** The `source` of an entry MUST be one of a closed set: `Scenario`
  (a Plan event/fault, 06/17), `Engine` (scheduler / temporal graph / fault
  subsystem / assertion checker, 08/17/18), `Node` (a VM or I/O sub-node, 06/15),
  `Guest` (black-box observation or white-box marker, 16), or `Command` (a
  control-plane command, tagged with its client correlation id, 20/21). The set is
  closed and versioned; projections MUST be able to filter by `source` without
  parsing free text. *Gate:* `gate:harness-lint`. *Spec:* §19.2.1.

- **[OBS-9]** Engine-side entries appended while dispatching a control-plane
  command MUST be sourced `Command { command_id }` with the client-supplied id, so
  that the live stream ([§19.6](#196-consumers-of-the-log), 20/21) lets a
  subscriber correlate a command with the entries it caused. This MUST NOT change
  the entry's `EventClass`: a command-caused causal transition is still `Causal`;
  a command-caused diagnostic is still `Observational`. *Gate:* `gate:harness-lint`.
  *Spec:* §19.2.1.

### 19.2.2 Payload: open-set kind + typed attributes

The payload is the *what*. It is an **open set** of kinds: the catalog in
[§19.7](#197-event-kind-catalog) is the initial, versioned vocabulary, but the
schema is designed so that new kinds can be added (with a schema-version bump)
without breaking decoders of older kinds. Each kind carries **typed attributes**
(not a free-form blob), so that projections and assertions read fields by name and
type rather than scraping a message string. A free-form `diagnostic` kind with a
small typed key/value body exists as the escape hatch for things that do not
deserve a first-class kind.

- **[OBS-10]** The `payload` MUST be a structured value with an **open-set**
  `kind` discriminator and **typed attributes** per kind (§19.7), not a free-form
  string or untyped blob. The catalog of [§19.7](#197-event-kind-catalog) is the
  initial versioned vocabulary; adding a `kind` MUST be a backward-compatible,
  schema-versioned change (§19.4) that does not break decoders of existing kinds.
  A general `diagnostic` kind with a small typed key/value body MUST exist as the
  escape hatch for entries that do not warrant a first-class kind. *Gate:*
  `gate:harness-lint`, `gate:content-address`. *Spec:* §19.2.2, §19.7.

- **[OBS-11]** Each `kind`'s attributes MUST be readable by name and type by
  projections and the assertion checker ([§19.6](#196-consumers-of-the-log), 18)
  without parsing a human message string. A human-readable summary MAY be derived
  from the typed attributes for the text/debug projection, but it MUST be a
  *derivation* of the typed fields, never the authoritative content. *Gate:*
  `gate:harness-lint`. *Spec:* §19.2.2.

### 19.2.3 Level vs class

`Level` (Trace…Error) and `EventClass` (Causal/Observational) are **orthogonal**.
`Level` governs verbosity — "how loud is this, should a viewer at this filter show
it" — and is *never* consulted by the determinism comparison. `EventClass` governs
determinism — "can two equivalent runs disagree on this" — and is *never* a
display concern. A causal entry may be `Trace`-level (a high-frequency state
transition a user usually filters out but which is still part of the deterministic
backbone); an observational entry may be `Error`-level (a host diagnostic about a
serious-but-run-variable condition). Conflating the two — e.g. excluding
`Debug`-level entries from the determinism comparison — is a defect.

- **[OBS-12]** `Level` and `EventClass` MUST be orthogonal fields with independent
  meanings: `Level` governs display verbosity and MUST NOT influence the
  determinism comparison; `EventClass` governs determinism and MUST NOT be derived
  from or coupled to `Level`. The determinism comparison MUST key off `EventClass`
  alone (causal subsequence), never off `Level`. Each emission site MUST pick its
  own `Level`; there is no kind-to-level default mapping that a consumer may rely
  on. *Gate:* `gate:replay-oracle`, `gate:harness-lint`. *Spec:* §19.2.3.

## 19.3 Causal vs observational is baked into the schema

The single most load-bearing distinction in the log is between **causal** entries
— the deterministic backbone, which MUST be byte-identical across runs of the same
`(scenario, seed, schedule)` — and **observational** entries, which describe the
run but MAY legitimately vary between equivalent runs and are therefore *excluded*
from the determinism comparison. This distinction is **part of the schema**: it is
the typed `EventClass` field ([§19.2](#192-the-entry-schema)), set by the typed
append API from the payload variant, not a boolean an emitter may forget to flip.

Why baked in, not a side flag: if "is this comparable" were a caller-supplied
boolean defaulting to one value, then every new emission site would be one missed
default away from either (a) silently excluding a real causal event from the gate
(a determinism hole the gate would never catch) or (b) silently including a
genuinely run-variable observation in the gate (a flaky gate). Making the class a
property of the payload variant means the decision is made *once*, where the kind
is defined, and is mechanically checkable: the kind catalog ([§19.7](#197-event-kind-catalog))
fixes each kind's class, and a lint (`gate:harness-lint`) verifies no append site
overrides it.

- **Causal entries** are the deterministic skeleton of the run: state transitions,
  cross-node message delivery and drop, fault activation/heal, node lifecycle,
  timer fire, scheduler quanta/ticks, savepoint/fork structural markers, and
  assertion *evaluations and state changes* (the property-relevant facts). Their
  sequence and their typed attributes are a pure function of
  `(scenario, seed, schedule)`.
- **Observational entries** are descriptions layered over that skeleton: executor
  poll counts and other host-runtime internals, white-box guest markers (which are
  observational even though their *icounts* are deterministic — see
  [`16-guest-host-channel.md`](16-guest-host-channel.md) §16.5.2 [GHC-24]),
  `tracing`-bridged host diagnostics ([§19.6.6](#1966-tracing-integration)), and
  any host-side measurement that is not part of `reduce`.

```text
  EventClass = property of the payload kind (§19.7), set at the typed append site
  ─────────────────────────────────────────────────────────────────────────────
  CAUSAL (deterministic backbone, compared by the gates §19.5):
    state_transition · trigger_fired · message_delivered · message_dropped ·
    fault_activated · fault_healed · node_started · node_crashed ·
    node_completed · timer_armed · timer_fired · timer_cancelled · tick ·
    savepoint · fork · assertion_evaluated · assertion_state_changed
  OBSERVATIONAL (descriptive, excluded from the comparison §19.5):
    diagnostic · coverage · guest_marker · (host-runtime internals, poll counts)

  NOT a side flag: a lint (gate:harness-lint) verifies the class of an appended
  entry matches its kind's catalog class; no append site may override it.
```

- **[OBS-13]** The causal-vs-observational distinction MUST be encoded in the
  schema as the typed `EventClass` field ([§19.2](#192-the-entry-schema)), and an
  entry's `EventClass` MUST be determined by its payload `kind` per the catalog
  ([§19.7](#197-event-kind-catalog)), assigned by the typed append API — **not** by
  a free, caller-supplied boolean that an emission site can set or forget. *Gate:*
  `gate:harness-lint`. *Spec:* §19.3, §19.7.

- **[OBS-14]** Causal entries MUST be exactly the deterministic backbone of the
  run: state transitions, cross-node message delivery/drop, fault activation/heal,
  node lifecycle, timer fires, scheduler ticks/quanta, savepoint/fork structural
  markers, and assertion evaluations and state changes (§19.7). Their sequence and
  typed attributes MUST be a pure function of `(scenario, seed, schedule)` ([INV-1],
  [INV-4]). *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:* §19.3,
  §19.5, §19.7.

- **[OBS-15]** Observational entries MUST be exactly those that may legitimately
  vary between equivalent runs and that are not part of `reduce`: host-runtime
  internals (executor poll counts and similar), white-box guest markers (16,
  observational by [GHC-24] even though their icounts are deterministic),
  `tracing`-bridged host diagnostics ([§19.6.6](#1966-tracing-integration)), and
  coverage entries. Observational entries MUST be excluded from the determinism
  comparison ([§19.5](#195-determinism-the-causal-subsequence-is-byte-identical)).
  *Gate:* `gate:e2e-determinism`. *Spec:* §19.3, §19.5.

- **[OBS-16]** A lint MUST verify that every append site's recorded `EventClass`
  matches the catalog class of its payload `kind` ([§19.7](#197-event-kind-catalog)),
  so that no site can silently mis-class an entry (excluding a real causal event
  from the gate, or including a run-variable observation in it). A `kind` whose
  class is ambiguous MUST be resolved in the catalog before it is used. *Gate:*
  `gate:harness-lint`. *Spec:* §19.3, §19.7.

## 19.4 Content addressing and prefix sharing

The log is **content-addressed** and stored in **segments** so that a fork shares
the common prefix with its parent rather than copying it. This is the
observability face of the temporal graph's copy-on-write sharing
([`07-temporal-graph.md`](07-temporal-graph.md) §5) and of content addressing
([INV-6]). A checkpoint references the log by an **offset**
([`07-temporal-graph.md`](07-temporal-graph.md) §3, `event_log_offset`): the log
prefix up to that offset is shared by reference with the checkpoint's ancestors,
and a resume or fork continues appending its own segment after it.

```text
  log = ordered sequence of content-addressed segments (BLAKE3-keyed, §19.4)
  ───────────────────────────────────────────────────────────────────────────
  parent run:   [seg A]──[seg B]──[seg C]
                                    │  fork at offset = end(B)
                                    ▼
  child  run:   [seg A]──[seg B]──[seg D]   (A,B shared by ref; D is new)

  checkpoint.event_log_offset (07 §3) = (offset into the log, ref to prefix)
  identical segments reached by different paths are stored once (INV-6).
```

- **[OBS-17]** The log MUST be stored as a sequence of **content-addressed
  segments**, each keyed by the BLAKE3 hash of its bytes, in the same
  content-addressed store as the temporal graph
  ([`07-temporal-graph.md`](07-temporal-graph.md) §7). Identical segments reached
  by different decision paths MUST be stored exactly once (deduplicated), per
  [INV-6]. *Gate:* `gate:content-address`. *Spec:* §19.4; cross-ref 07 §5, §7.

- **[OBS-18]** A fork MUST share the common log prefix with its parent **by
  reference** and append only its own new segment(s); it MUST NOT copy the shared
  prefix. The marginal log storage cost of a fork MUST be proportional to the
  bytes it appends after the fork point, not to the length of the whole log,
  consistent with the CoW sharing of
  [`07-temporal-graph.md`](07-temporal-graph.md) [TEMP-15], [TEMP-17]. *Gate:*
  `gate:content-address`. *Spec:* §19.4; cross-ref 07 §5.

- **[OBS-19]** A checkpoint MUST reference the log by an **offset** plus a content
  reference to the shared prefix (the `event_log_offset` of
  [`07-temporal-graph.md`](07-temporal-graph.md) §3 [TEMP-7]); this file owns the
  log and the segment layout, and the temporal graph stores only the offset and
  the prefix reference (it MUST NOT redefine the log's byte layout, per [TEMP-8]).
  A resume MUST continue appending at that offset. *Gate:* `gate:content-address`,
  `gate:replay-oracle`. *Spec:* §19.4; cross-ref 07 §3.

- **[OBS-20]** The log's **canonical serialization** MUST be a deterministic
  binary encoding with a fixed schema version, fixed-width little-endian scalars,
  and a deterministic field order, so that the content hash of a segment is a pure
  function of the causal-plus-observational entries it contains and is identical
  across hosts and processes. The schema version MUST be bumped on any change to
  the entry layout or the kind catalog ([§19.7](#197-event-kind-catalog)), and the
  serialization MUST round-trip (decode∘encode is the identity on a valid
  segment). A human-readable text projection (the `text` rendering of
  [§19.2](#192-the-entry-schema)) is a derived view, never the canonical form.
  *Gate:* `gate:content-address`. *Spec:* §19.4.

## 19.5 Determinism: the causal subsequence is byte-identical

The determinism contract for the log is precise: across two runs of the same
`(scenario, seed, schedule)`, the **causal subsequence** of the log — the
projection that keeps only `EventClass::Causal` entries — MUST be **byte-identical**
after the causal subsequence is renumbered independently of observational
interleaving. This is exactly what `gate:replay-oracle` and `gate:e2e-determinism`
compare. Observational entries are excluded from this comparison: they may appear,
vanish, or differ between the two runs without indicating a determinism bug.

The **canonical run** (equivalently the **canonical event log**), as the term is
used in 20/22, is this causal subsequence under the canonical serialization: the
`EventClass::Causal` projection renumbered independently of observational
interleaving. It is the deterministic backbone two runs are compared on.

The renumbering is what makes the comparison robust to observational noise: two
runs may interleave different numbers of `diagnostic` or `tracing`-bridged entries
(host poll counts differ run to run), which would shift the dense `seq` of every
following causal entry. The comparison therefore strips observational entries
first and renumbers the surviving causal entries from zero, then compares
field-by-field (`at`, `source`, `payload`, and `class`, which is `Causal` by
construction) byte-for-byte.

```text
  determinism comparison (gate:replay-oracle / gate:e2e-determinism):
  ──────────────────────────────────────────────────────────────────
  causal(run) := [ e for e in log(run) if e.class == Causal ]
                 then renumber seq 0..N (drop observational interleaving)
  PASS  iff  serialize(causal(run_1)) == serialize(causal(run_2))   byte-for-byte
  a mismatch is localized to the first differing causal entry (§19.6.2, INV-10).
```

- **[OBS-21]** Across two runs of the same `(scenario, seed, schedule)`, the
  **causal subsequence** of the log (the `EventClass::Causal` projection,
  renumbered independently of observational interleaving) MUST be **byte-identical**
  under the canonical serialization ([§19.4](#194-content-addressing-and-prefix-sharing)).
  This is the determinism oracle that `gate:replay-oracle` and `gate:e2e-determinism`
  compare ([INV-1], [INV-2]). *Gate:* `gate:replay-oracle`, `gate:e2e-determinism`.
  *Spec:* §19.5.

- **[OBS-22]** Observational entries MUST be **excluded** from the determinism
  comparison of [OBS-21]: two runs that differ only in their observational entries
  (count, content, or interleaving) MUST compare equal. The comparison MUST strip
  observational entries and renumber the surviving causal entries before comparing,
  so that differing observational interleaving does not shift causal positions
  (§19.5; consistent with [GHC-24], [GHC-30] for white-box markers). *Gate:*
  `gate:e2e-determinism`. *Spec:* §19.5.

- **[OBS-23]** The causal subsequence MUST be a pure function of
  `(scenario, seed, schedule)` ([INV-1]): no host wall-clock, host-scheduling
  order, host RNG, or uncontrolled external input MAY influence which causal
  entries are recorded, their order, their `at` coordinates, or their typed
  attributes. A causal entry whose value depends on any of these is a contract
  violation and MUST fail the gate, never be smoothed over ([INV-10]). *Gate:*
  `gate:e2e-determinism`, `gate:harness-lint`. *Spec:* §19.5.

- **[OBS-24]** Enabling, disabling, or changing the *verbosity* of observational
  output (raising/lowering the `Level` filter, turning the `tracing` bridge on/off,
  enabling white-box markers) MUST NOT change the causal subsequence and therefore
  MUST NOT change the determinism comparison result. A run with all observational
  output disabled and the same run with maximal observational output MUST have
  identical causal subsequences. *Gate:* `gate:e2e-determinism`. *Spec:* §19.5;
  cross-ref [GHC-2], [GHC-30].

- **[OBS-25]** The fat-checkpoint replay oracle of
  [`07-temporal-graph.md`](07-temporal-graph.md) §6 MUST use the causal-subsequence
  equality of [OBS-21] as (part of) its content-hash comparison: a fat checkpoint's
  realized causal subsequence MUST equal the causal subsequence of its
  replay-from-ancestor derivation ([INV-2], [TEMP-18]). The event-log offset
  ([§19.4](#194-content-addressing-and-prefix-sharing)) MUST be consistent with the
  replayed prefix. *Gate:* `gate:replay-oracle`. *Spec:* §19.5; cross-ref 07 §6.

## 19.6 Consumers of the log

Every observability consumer reads a **projection** of the one log
([OBS-4](#191-one-log-one-source-of-truth)). This section enumerates them and
states what each takes from the stream.

### 19.6.1 Assertion checking (18), including offline

The assertion checker folds over the log's causal entries — specifically the
`assertion_evaluated` and `assertion_state_changed` kinds, plus the
property-relevant transitions it watches — to decide Always / Sometimes /
Eventually / AfterQuiescence / Reachable verdicts. Because the log is the single
record of the run, assertion checking works identically **live** (folding as
entries are appended) and **offline** (folding over a stored log, or its causal
subsequence, after the run). White-box assertion *markers* (16) enter the log as
observational entries but are evaluated by the *same* fold under the *same*
Always/Sometimes/Reachable semantics ([GHC-25]).

- **[OBS-26]** Assertion checking ([`18-assertions-properties.md`](18-assertions-properties.md))
  MUST be a fold over the one log: it MUST read `assertion_evaluated`,
  `assertion_state_changed`, and the property-relevant causal transitions it
  watches, and MUST produce identical verdicts whether folding **live** (as entries
  are appended) or **offline** (over a stored log). It MUST NOT require any record
  other than the log. *Gate:* `gate:replay-oracle`. *Spec:* §19.6.1; forward-ref 18.

- **[OBS-27]** White-box guest assertion markers (16) MUST be recorded as
  observational entries (`guest_marker` kind, §19.7) and MUST be evaluated by the
  same assertion fold under the same Always/Sometimes/Reachable semantics as
  black-box assertions ([GHC-25]). Folding the same stored log offline MUST yield
  the same assertion verdicts as the live fold. *Gate:* `gate:any-guest`. *Spec:*
  §19.6.1; cross-ref [GHC-24], [GHC-25].

### 19.6.2 Divergence bisection (24)

When two runs that should be identical are not — a replay-oracle failure, a
suspected nondeterminism — the divergence is **localized to the first differing
causal entry** by comparing the two runs' causal subsequences
([§19.5](#195-determinism-the-causal-subsequence-is-byte-identical)). Because the
causal subsequence is totally ordered and icount-stamped, the first differing
entry pins the divergence to a precise `(node, icount)` and `kind`, which
`gate:divergence-bisect` then drives down to the first differing decision or
instruction ([INV-10]). The log is the bisection input; there is no second trace
to reconcile.

- **[OBS-28]** Divergence bisection ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md))
  MUST localize a determinism failure to the **first differing causal entry** of
  the two runs' causal subsequences ([§19.5](#195-determinism-the-causal-subsequence-is-byte-identical)),
  reporting its `at` (node + icount), `source`, and `kind`, so the failure pins to
  a precise point rather than a whole-run mismatch ([INV-10]). The log MUST be the
  sole bisection input; a divergence MUST NOT be smoothed over. *Gate:*
  `gate:divergence-bisect`. *Spec:* §19.6.2; cross-ref [INV-10], 24.

### 19.6.3 Coverage (22)

Basic-block coverage harvested from the plugin's TCG-execution hook (no guest
instrumentation, [GHC-7] item 7) and any white-box named coverage markers ([GHC-22])
enter the log as **observational** `coverage` entries. Coverage-guided fuzzing and
state-space search ([`22-advanced-features.md`](22-advanced-features.md)) read the
coverage projection of the log as their feedback signal; the per-checkpoint
coverage fingerprint of [`07-temporal-graph.md`](07-temporal-graph.md) §2 is a
deterministic digest derived from this projection.

- **[OBS-29]** Coverage MUST be recorded in the one log as observational
  `coverage` entries (§19.7): basic-block coverage from the plugin TCG-exec hook
  ([GHC-7] item 7) and white-box named coverage markers ([GHC-22]). Coverage-guided
  search and fuzzing ([`22-advanced-features.md`](22-advanced-features.md)) MUST
  read the coverage projection as their feedback signal, and the
  `coverage_fingerprint` of [`07-temporal-graph.md`](07-temporal-graph.md) §2 MUST
  be a deterministic digest derived from it. Because coverage entries are
  observational, they MUST NOT affect the determinism comparison ([OBS-22]). *Gate:*
  `gate:e2e-determinism`. *Spec:* §19.6.3; forward-ref 22.

- **[OBS-37]** The assertion-proximity **distance-to-satisfaction** of
  [`18-assertions-properties.md`](18-assertions-properties.md) §18.13 ([ASRT-33])
  MUST be recorded in the **one** log as an **observational** projection — a distinct
  observational `assertion_proximity` kind (§19.7) — and MUST be **excluded** from the
  determinism comparison ([OBS-22], like every other observational entry). Its
  **per-checkpoint minimum** (the closest the run came, [ASRT-33]) MUST be a
  **deterministic digest derived from the projection** — analogous to the
  `coverage_fingerprint` of [`07-temporal-graph.md`](07-temporal-graph.md) §2
  ([OBS-29]) — and is **consumed by guided search**
  ([`22-advanced-features.md`](22-advanced-features.md)) as a steering signal only.
  No consumer or feature MAY maintain a proximity record **parallel to the log**
  ([OBS-1], [OBS-4]); the proximity projection MUST be read from the one log like any
  other projection. *Gate:* `gate:e2e-determinism`, `gate:content-address`. *Spec:*
  §19.6.3, §19.7; cross-ref 18 §18.13, 22.

### 19.6.4 Reproduction artifacts (23)

A reproduction artifact ([`23-cli.md`](23-cli.md), [`06-spatial-graph.md`](06-spatial-graph.md))
is the self-contained `(seed, scenario, schedule)` bundle that reproduces a run
bit-identically; the log is its **debugging artifact** and its **fork-point
index**. The artifact need not embed the full log (the log is recomputed by
replay), but the log MUST be reconstructible from the artifact and its causal
subsequence MUST match the original run's ([OBS-21]). When a content-addressed
store is shared, the artifact MAY reference stored log segments by content key
([`07-temporal-graph.md`](07-temporal-graph.md) [TEMP-23]) so the log is fetched
rather than recomputed.

- **[OBS-30]** The log MUST be the debugging artifact and fork-point index of a
  reproduction artifact ([`23-cli.md`](23-cli.md)): replaying a run from its
  `(seed, scenario, schedule)` artifact MUST reconstruct a log whose causal
  subsequence is byte-identical to the original's ([OBS-21]). The artifact MUST NOT
  be required to embed the full log for correctness (it is recomputable by replay),
  but where a content-addressed store is shared the artifact MAY reference stored
  log segments by content key ([TEMP-23]) to fetch rather than recompute the log.
  *Gate:* `gate:content-address`, `gate:replay-oracle`. *Spec:* §19.6.4; cross-ref
  06, 23.

### 19.6.5 Live streaming to the control plane (20/21)

A live session ([`20-session-control-plane.md`](20-session-control-plane.md))
streams log entries to subscribers as they are appended, over the control-plane
API ([`21-api.md`](21-api.md)). The stream is a cursor over the one log: a
subscriber receives entries from a cursor position onward, with `Command`-sourced
entries ([OBS-9](#1921-source)) letting it correlate its own commands with their
effects. Streaming MUST be a pure observation: subscribing to, or unsubscribing
from, the live stream MUST NOT change the run (no determinism effect, consistent
with [INV-8]'s actor-yields-between-quanta model so streaming does not stall the
scheduler).

- **[OBS-31]** The control plane ([`20-session-control-plane.md`](20-session-control-plane.md),
  [`21-api.md`](21-api.md)) MUST be able to stream log entries to subscribers as a
  cursor over the one log (entries from a cursor position onward), with both causal
  and observational entries available and `Command`-sourced entries ([OBS-9])
  correlating commands to effects. Subscribing or unsubscribing MUST be a pure
  observation that does not change the run or its causal subsequence, and MUST NOT
  stall the scheduler (consistent with [INV-8]). *Gate:* `gate:e2e-determinism`.
  *Spec:* §19.6.5; forward-ref 20, 21.

### 19.6.6 `tracing` integration

Host-side diagnostics via the `tracing` crate are an **observational, opt-in**
bridge: Crucible's engine MAY mirror selected internal events to `tracing` for
familiar `RUST_LOG`-style debugging, but the `tracing` bridge is *off by default*,
every `tracing`-bridged entry is `EventClass::Observational`, and the bridge MUST
NOT influence determinism. Concretely: `tracing` subscriber configuration,
filtering, and output are host concerns that may vary between runs and machines,
so nothing the engine does for `tracing` may enter the causal subsequence or
change the order in which causal entries are appended.

- **[OBS-32]** Host diagnostics via `tracing` MUST be **observational and opt-in**:
  the bridge MUST be off by default, every `tracing`-mirrored entry MUST be
  `EventClass::Observational`, and enabling/configuring/filtering `tracing` MUST
  NOT change the causal subsequence or the order in which causal entries are
  appended ([OBS-24]). The `tracing` bridge MUST NOT be on any ordering-significant
  engine path ([INV-9]). *Gate:* `gate:e2e-determinism`, `gate:harness-lint`.
  *Spec:* §19.6.6.

- **[OBS-33]** The engine's own ordering-significant code MUST NOT depend on
  `tracing` being installed, configured, or capturing: with no subscriber, with a
  capturing subscriber, and with a filtering subscriber, the causal subsequence
  MUST be identical ([INV-9], [OBS-24]). `tracing` MUST be a sink the engine writes
  to, never a source the engine reads ordering from. *Gate:* `gate:harness-lint`.
  *Spec:* §19.6.6.

## 19.7 Event-kind catalog

The `kind` discriminator is an **open set**; the table below is the initial,
versioned vocabulary, with each kind's `EventClass` fixed here
([OBS-13](#193-causal-vs-observational-is-baked-into-the-schema)). Adding a kind is
a backward-compatible, schema-versioned change ([OBS-10](#1922-payload-open-set-kind--typed-attributes)).
Kinds 18, 20, 22, and 24 all reference this catalog: assertion kinds feed 18, the
streamed kinds feed 20/21, the coverage kind feeds 22, and the whole causal
subsequence feeds the comparison and bisection of 24.

An **I/O completion** (block/9p response, 15) is recorded as a
`message_delivered`-class causal entry — its delivery is a cross-node event with a
`deliver_icount` exactly like a frame delivery — rather than as a separate
`io_completed` kind, so no distinct catalog kind is needed for it.

A **trigger firing** (a scenario event's trigger condition became true and its
action ran, [`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md)
§17a.3.3 [TRIG-19]) is recorded as a **causal** entry — `trigger_fired`, together
with the action's own causal entries (`fault_activated`/`fault_healed`,
`timer_armed`/`timer_fired`/`timer_cancelled`, `node_started`/`node_completed`,
`savepoint`/`fork`). A trigger firing is deterministic engine behavior, **not** a
`Decision` ([TRIG-19]): given the log prefix, whether a condition is true at an
evaluation point is *computed*, never *chosen*, so the firing belongs on the
deterministic backbone the gates compare (§19.5), distinct from an observational
entry. **Conditions are evaluated, not logged**: the engine evaluates the shared
17a `Condition` vocabulary at deterministic evaluation points ([TRIG-16]) over the
log prefix, but only a *firing* (and its action) is appended as a causal entry —
the per-point truth of every standing condition is not itself a log entry.

| `kind` | class | source(s) | typed attributes (sketch) |
| --- | --- | --- | --- |
| `state_transition` | Causal | Engine, Node | `node`, `from_state`, `to_state`, `cause` |
| `event_activated` | Causal | Scenario | `event`, `summary` (a Plan event/fault fired, 17) |
| `trigger_fired` | Causal | Engine, Scenario | `event`, `condition` (summary), `action` (a trigger's condition became true and its action ran, 17a §17a.3.3) |
| `fault_activated` | Causal | Scenario, Engine | `tag`, `kind` (partition/crash/loss/…), `targets`, `description` (17) |
| `fault_healed` | Causal | Scenario, Engine | `tag` (the fault deactivated, 17) |
| `node_started` | Causal | Engine, Node | `node`, `ready_point` (icount) |
| `node_crashed` | Causal | Engine, Node | `node`, `reason` |
| `node_completed` | Causal | Engine, Node | `node`, `outcome` |
| `timer_armed` | Causal | Engine, Node | `timer`, `fire_icount` (08, 09) |
| `timer_fired` | Causal | Engine, Node | `timer` |
| `timer_cancelled` | Causal | Engine, Node | `timer` |
| `message_delivered` | Causal | Node, Engine | `from`, `to`, `link`, `seq`, `len`, `deliver_icount` (08, 13, 15) |
| `message_dropped` | Causal | Node, Engine | `from`, `to`, `link`, `reason` (loss/partition/crash) |
| `assertion_evaluated` | Causal | Engine, Guest | `id`, `flavor`, `condition`, `message`, typed `details` (18, 16) |
| `assertion_state_changed` | Causal | Engine | `id`, `new_state` (satisfied/violated/…) (18) |
| `savepoint` | Causal | Engine, Command | `checkpoint_id`, `event_log_offset` (07 §3) |
| `fork` | Causal | Engine, Command | `from_checkpoint_id`, `schedule_delta` (07 §10) |
| `tick` | Causal | Engine | `virtual_time`, per-node `icount` (one scheduler quantum, 08) |
| `diagnostic` | Observational | Engine, Node, Command | `name`, typed key/value `details` (the escape hatch, §19.2.2) |
| `coverage` | Observational | Engine, Guest | `kind` (basic_block / named), `id`/`block`, `node` (22, [GHC-7]/[GHC-22]) |
| `assertion_proximity` | Observational | Engine | `id`, `quantifier`, `distance` (non-negative u128, 0=satisfied), `node` (18 §18.13, [ASRT-33]; steering-only, excluded from the comparison) |
| `guest_marker` | Observational | Guest | `marker_kind` (assert/lifecycle/event/coverage/random_request), typed body (16 §16.5) |
| `guest_measurement_begin` | Observational | Guest | `node`, `retired_icount`, `measurement`, `instance` (16 §16.5, RFC-0019 §08.4) |
| `guest_metric_sample` | Observational | Guest | `node`, `retired_icount`, `measurement`, `instance`, `metric`, one bounded typed value (16 §16.5, RFC-0019 §08.4) |
| `guest_measurement_end` | Observational | Guest | `node`, `retired_icount`, `measurement`, `instance` (16 §16.5, RFC-0019 §08.4) |
| `guest_semantic_marker` | Observational | Guest | `node`, `retired_icount`, `marker`, `instance`, bounded key-ordered typed details (16 §16.5, RFC-0019 §08.4) |

```rust,illustrative
/// The open-set payload (§19.2.2). The catalog (§19.7) fixes each variant's
/// `EventClass` (§19.3); the typed attributes are read by name (§19.2.2).
/// Adding a variant is a schema-versioned, backward-compatible change (§19.4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive] // open set: new kinds may be added with a schema-version bump
pub enum EventPayload {
    // ── Causal: the deterministic backbone (§19.3, [OBS-14]) ──────────────
    StateTransition { node: NodeId, from_state: StateId, to_state: StateId, cause: CauseId },
    EventActivated { event: ScenarioEventId, summary: Str },
    TriggerFired { event: ScenarioEventId, condition: Str, action: Str }, // 17a §17a.3.3

    FaultObservation { observation: FaultObservation }, // signal, binding, opportunity, choice, or effect
    NodeStarted { node: NodeId, ready_point: u64 /* icount */ },
    NodeCrashed { node: NodeId, reason: Str },
    NodeCompleted { node: NodeId, outcome: NodeOutcome },
    TimerArmed { node: NodeId, timer: TimerId, fire_icount: u64 },
    TimerFired { node: NodeId, timer: TimerId },
    TimerCancelled { node: NodeId, timer: TimerId },
    MessageDelivered { from: NodeId, to: NodeId, link: LinkId, seq: u64, len: u32, deliver_icount: u64 },
    MessageDropped { from: NodeId, to: NodeId, link: LinkId, reason: DropReason },
    AssertionEvaluated { id: AssertionId, flavor: AssertionFlavor, condition: bool, message: Str, details: Attrs },
    AssertionStateChanged { id: AssertionId, new_state: AssertionState },
    Savepoint { checkpoint_id: ContentHash, event_log_offset: EventLogOffset },
    Fork { from_checkpoint_id: ContentHash, schedule_delta: SmallVec<[Decision; 1]> },
    Tick { virtual_time: VirtualTime, icount: BTreeMap<NodeId, u64> },

    // ── Observational: descriptive, excluded from the comparison (§19.3) ──
    Diagnostic { name: Str, details: Attrs },
    Coverage { kind: CoverageKind, id: CoverageId, node: NodeId },
    AssertionProximity { id: AssertionId, quantifier: AssertionFlavor, distance: u128, node: Option<NodeId> }, // 18 §18.13, steering-only
    GuestMarker { node: NodeId, marker_kind: MarkerKind, body: Attrs }, // from 16 §16.5
    GuestMeasurementBegin { node: NodeId, retired_icount: u64, measurement: Str, instance: Str },
    GuestMetricSample { node: NodeId, retired_icount: u64, measurement: Str, instance: Str, metric: Str, value: TypedValue },
    GuestMeasurementEnd { node: NodeId, retired_icount: u64, measurement: Str, instance: Str },
    GuestSemanticMarker { node: NodeId, retired_icount: u64, marker: Str, instance: Str, details: Attrs },
}
```

- **[OBS-34]** The event-kind catalog MUST include at least the kinds of the
  §19.7 table — state transitions; event/fault activation and heal; trigger
  firing (`trigger_fired`); node lifecycle (started/crashed/completed); timers
  (armed/fired/cancelled); message delivered/dropped; assertion evaluated and
  state-changed; savepoint and fork structural markers; scheduler tick/quantum;
  and the observational `diagnostic`, `coverage`, `assertion_proximity`, and
  `guest_marker`, `guest_measurement_begin`, `guest_metric_sample`,
  `guest_measurement_end`, and `guest_semantic_marker` kinds — with
  each kind's `EventClass` fixed as in the table ([OBS-13], [OBS-14], [OBS-15]).
  The catalog is open and versioned ([OBS-10]). *Gate:* `gate:harness-lint`,
  `gate:content-address`. *Spec:* §19.7.

- **[OBS-35]** The catalog of §19.7 MUST be the single source of truth that 18, 20,
  21, 22, and 24 reference for kinds and their classes: assertion kinds for the
  checker (18), the streamable kinds for the control plane (20/21), the `coverage`
  kind for fuzzing/search (22), and the whole causal subsequence for the comparison
  and bisection of 24. A consumer MUST NOT define a parallel kind vocabulary; it
  MUST read this catalog's kinds and classes. *Gate:* `gate:harness-lint`. *Spec:*
  §19.7; cross-ref 18, 20, 21, 22, 24.

- **[OBS-36]** A **trigger firing** ([`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md)
  §17a.3.3, [TRIG-19]) MUST be recorded as a **causal** entry — a `trigger_fired`
  kind together with the action's own causal kinds (`fault_activated`/`fault_healed`,
  `timer_armed`/`timer_fired`/`timer_cancelled`, `node_started`/`node_completed`,
  `savepoint`/`fork`) — and MUST NOT be appended to the `Schedule` as a `Decision`,
  because a firing is *computed* from the log prefix, not *chosen* ([TRIG-19]).
  Conditions MUST be evaluated, not logged: the engine evaluates the shared 17a
  `Condition` vocabulary at deterministic evaluation points ([TRIG-16]), but only a
  firing (and its action) is appended; the per-point truth of a standing condition
  is not itself a log entry. Only the *probabilistic outcomes of a fired action*
  (e.g. a probabilistic fault's per-frame draws) are `Decision`s ([TRIG-20]), never
  the firing. *Gate:* `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:* §19.7,
  §19.3; cross-ref 17a §17a.3.3.

## 19.8 Summary

```text
ONE LOG (§19.1): totally-ordered · content-addressed · icount-stamped stream that
  IS the determinism oracle · the assertion input · the debug artifact ·
  the fork-point index · the coverage record — every consumer reads a projection.

SCHEMA (§19.2): seq · at(virtual_time + per-node icount) · source · payload
  (open-set kind + typed attrs) · level · EventClass(Causal|Observational).
  EventClass is a SCHEMA FIELD set by the kind (§19.3), not a caller flag.

DETERMINISM (§19.5): causal subsequence is BYTE-IDENTICAL across runs of the same
  (scenario, seed, schedule) — what gate:replay-oracle / gate:e2e-determinism
  compare. Observational entries excluded; causal renumbered past observational
  interleaving. First differing causal entry localizes a divergence (§19.6.2).

CONTENT ADDRESSING (§19.4): log = content-addressed segments; a fork SHARES the
  parent prefix by reference; a checkpoint references a log OFFSET (07 §3).

CONSUMERS (§19.6): assertions (18, live+offline) · divergence bisection (24) ·
  coverage (22) · reproduction artifacts (23) · live control-plane stream (20/21).
  tracing (§19.6.6) is observational, opt-in, off by default — never determinism.

CATALOG (§19.7): open, versioned kinds with fixed classes; 18/20/22/24 reference it.
```

The shape of this file is the shape of the guarantee: one ordered, classed,
content-addressed stream, whose causal projection is the deterministic backbone
the gates compare and whose observational entries enrich debugging without ever
moving the gate. Every other observability surface — assertions, bisection,
coverage, reproduction, live streaming, `tracing` — is a projection of this one
log, so they cannot disagree about what happened.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is the unified event log, tracked by [PLAN-3].

- [x] **T-OBS-1** Implement the single unified `LogEntry`/`EventLog` with one
  append path, replacing any notion of separate determinism-trace / debug-log /
  assertion-stream / coverage-record; every consumer reads a projection. —
  satisfies [OBS-1], [OBS-2], [OBS-3], [OBS-4]; spec §19.1.
  Completed by `checks.crucible.phase4.eventLogUnified`: `EventLog` now owns
  exactly **one** event log per run, all scheduler append sites route through the
  single append path `EventLog::append_entries`, and offset plus condition-log
  consumers read projections from that one retained stream.
- [x] **T-OBS-2** Define the entry schema (`seq`, `at` virtual-time+icount,
  `source`, open-set typed `payload`, `level`, `EventClass`) with monotonic
  gap-free `seq`, icount stamping, and the closed `EventSource` set incl.
  `Command` correlation. — satisfies [OBS-5], [OBS-6], [OBS-7], [OBS-8], [OBS-9];
  spec §19.2, §19.2.1.
  Completed by `checks.crucible.phase4.eventLogSchema`: `LogEntry` now carries a
  full `EventLogTime` (`VirtualTime` plus an `Icount` stamp, with a node on
  node-local stamps), `EventSource`, `EventLevel`, and `EventClass`;
  command-caused entries preserve `Command { command_id }` correlation, and
  append material includes the schema fields in the content-addressed segment.
- [x] **T-OBS-3** Implement the open-set, typed `payload` (kind + named typed
  attributes, `diagnostic` escape hatch) read by name, and the orthogonal
  `Level`-vs-`EventClass` rule (level never consulted by the comparison). —
  satisfies [OBS-10], [OBS-11], [OBS-12]; spec §19.2.2, §19.2.3.
  Completed by `checks.crucible.phase4.eventLogPayload`: `LogEntry` now stores an
  open-set `EventPayload` projection with a kind string and typed named
  `EventAttributeValue` fields, exposes name/type accessors for projections,
  includes that payload view in canonical entry and segment material, and carries
  a typed `diagnostic` escape hatch whose display `EventLevel` stays independent
  from `EventClass`.
- [x] **T-OBS-4** Bake the causal/observational split into the schema: class is a
  function of the payload kind set at the typed append site, with a lint that
  rejects any append whose class mismatches the catalog. — satisfies [OBS-13],
  [OBS-14], [OBS-15], [OBS-16]; spec §19.3, §19.7.
  Completed by `checks.crucible.phase4.eventLogClassCatalog`: `LogEntry` now
  exposes a catalog-class predicate, the unified `EventLog::append_entries` path
  rejects entries whose recorded class disagrees with the typed payload-kind
  catalog, and private scheduler regressions prove both class mismatch and
  typed-kind drift fail before append.
- [x] **T-OBS-5** Implement content-addressed log segments (BLAKE3-keyed,
  deduplicated), prefix-sharing forks, checkpoint `event_log_offset` references,
  and a deterministic versioned binary canonical serialization with a derived text
  view. — satisfies [OBS-17], [OBS-18], [OBS-19], [OBS-20]; spec §19.4; cross-ref
  07 §3, §5, §7.
  Completed by `checks.crucible.phase4.eventLogContentAddress`: `EventLog`
  now writes versioned binary event-log segments through a shared BLAKE3-keyed
  DAG store, exposes only a derived text projection for readable assertions,
  deduplicates identical segment bytes across shared stores and cloned forks,
  and preserves checkpoint `event_log_offset` references through runtime
  materialization.
- [x] **T-OBS-6** Implement the determinism comparison: causal-subsequence
  projection, independent renumbering past observational interleaving, byte-for-byte
  equality wired to `gate:replay-oracle`/`gate:e2e-determinism`, and consistency
  with the fat-checkpoint oracle and log offset. — satisfies [OBS-21], [OBS-22],
  [OBS-23], [OBS-24], [OBS-25]; spec §19.5; cross-ref 07 §6, 24.
  Completed by `checks.crucible.phase4.eventLogDeterminism`: `EventLog` now exposes
  a canonical renumbered causal subsequence projection, the replay-oracle and
  e2e-determinism gates compare its byte-identical binary serialization while
  excluding observational interleaving, and fat-checkpoint replay explicitly
  rejects inconsistent retained `event_log_offset` state.
- [x] **T-OBS-7** Wire assertion checking as a live-or-offline fold over the one
  log (assertion_evaluated/state_changed + watched transitions), folding white-box
  observational markers under the same Always/Sometimes/Reachable semantics. —
  satisfies [OBS-26], [OBS-27]; spec §19.6.1; cross-ref 16, 18.
  Completed by `checks.crucible.phase4.eventLogAssertionFold`: assertion
  checking reconstructs checked `ConditionEventLogPrefix` values from the stored
  scheduler event log and feeds the same `HostAssertionEvaluator` fold live and
  offline; `assertion_state_changed`/`assertion_evaluated` are fixed as causal
  catalog kinds, and white-box assertion markers project through typed
  `guest_marker` entries while preserving the same Always/Sometimes/Reachable
  verdict semantics.
- [x] **T-OBS-8** Wire divergence bisection to localize a determinism failure to
  the first differing causal entry (node+icount, source, kind) with the log as the
  sole input. — satisfies [OBS-28]; spec §19.6.2; cross-ref 24.
  Completed by `checks.crucible.phase4.eventLogDivergenceBisect`: the causal
  event-log comparator now reports the first differing causal entry's
  node/icount, source, and kind directly from the log, and assertion replay
  divergence carries that same point into the bisection handoff instead of
  smoothing an event-stream mismatch into a later assertion-report difference.
- [x] **T-OBS-9** Record coverage (plugin TCG basic blocks + white-box named
  markers) as observational `coverage` entries feeding fuzzing/search and the
  per-checkpoint coverage fingerprint, excluded from the comparison. — satisfies
  [OBS-29]; spec §19.6.3; cross-ref 07 §2, 22.
  Completed by `checks.crucible.phase4.eventLogCoverage`: TCG basic-block hits and
  white-box named coverage markers project as observational `coverage` entries,
  checkpoint coverage fingerprints are derived from that coverage projection, and
  causal determinism comparison continues to exclude coverage-only differences.
- [x] **T-OBS-10** Make the log the debugging artifact and fork-point index of a
  reproduction artifact: replay reconstructs a byte-identical causal subsequence;
  shared-store artifacts reference log segments by content key. — satisfies
  [OBS-30]; spec §19.6.4; cross-ref 06, 23.
  Completed by `checks.crucible.phase4.eventLogReproductionArtifact`: compact
  event-log metadata records the fork-point index and causal-subsequence digest
  for `(seed, scenario, schedule)` replay, replay verification rejects causal
  drift without requiring the original full log, and persisted shared-store
  reproduction artifacts carry event-log segment content keys.
- [x] **T-OBS-11** Implement live control-plane streaming as a cursor over the one
  log (causal + observational, `Command` correlation), a pure non-stalling
  observation. — satisfies [OBS-31]; spec §19.6.5; cross-ref 20, 21.
  Completed by `checks.crucible.phase4.eventLogControlPlaneStreaming`: live
  control-plane cursor subscribers receive causal and observational entries,
  including `Command`-sourced control correlations, from the one session-owned
  event log; subscribing and dropping a subscriber are API/session observations
  that do not enqueue commands, advance the scheduler, or mutate the live
  snapshot. Future cursors clamp to the live tail, and retained replay is served
  in bounded batches before the stream follows the broadcast tail.
- [x] **T-OBS-12** Implement the `tracing` bridge as observational, opt-in, off by
  default, off all ordering-significant paths, with the causal subsequence
  identical under no/capturing/filtering subscribers. — satisfies [OBS-32],
  [OBS-33]; spec §19.6.6.
  Completed by `checks.crucible.phase4.eventLogTracingBridge`: `crucible` now
  exposes an opt-in `TracingBridge`/`TracingBridgeConfig` that is disabled by
  default, mirrors only observational diagnostic entries, ignores subscriber
  capture/filtering/panics as host-output concerns, and keeps the causal
  subsequence byte-identical with no subscriber, capturing subscriber, and
  filtering subscriber modes.
- [x] **T-OBS-13** Implement and freeze the open, versioned event-kind catalog
  with each kind's fixed class, as the single source of truth referenced by
  18/20/21/22/24; golden-vector the canonical serialization of each kind; record a
  trigger firing as a causal `trigger_fired` entry (never a `Schedule` `Decision`)
  and evaluate conditions without logging the per-point truth of a standing
  condition. — satisfies [OBS-34], [OBS-35], [OBS-36]; spec §19.7, §19.3.
  Completed by `checks.crucible.phase4.eventKindCatalogFreeze`: `crucible` now
  exposes `event_catalog` as the versioned single source for event-kind classes,
  includes all §19.7 required kinds plus currently emitted scheduler kinds, freezes
  the catalog and structural 18/20/21/22/24 dependency map with a golden-vector
  canonical serialization, and regresses that `trigger_fired` entries remain causal
  event-log entries rather than `Schedule` `Decision`s while condition truth stays
  evaluated rather than logged.
- [x] **T-OBS-14** Record the assertion-proximity distance (18 §18.13) as a distinct
  observational `assertion_proximity` event-log kind, excluded from the determinism
  comparison; derive its per-checkpoint **minimum** as a deterministic digest of the
  projection (analogous to `coverage_fingerprint`) consumed by guided search; forbid
  any proximity record parallel to the log. — satisfies [OBS-37]; spec §19.6.3,
  §19.7; cross-ref 18 §18.13, 22.
  Completed by `checks.crucible.phase4.eventLogAssertionProximity`: `crucible` now
  emits typed observational `assertion_proximity` entries, excludes them from the
  causal determinism projection, derives a minimum-distance assertion-proximity
  projection fingerprint from the unified log, and threads that digest through
  checkpoint and temporal-graph cache feedback for guided-search consumers without
  introducing a second proximity record parallel to the log.
