# Event log

Every Crucible run produces exactly **one** event log: a single, densely
sequenced, content-addressed stream of typed entries. The same stream is the
determinism oracle, the assertion-checking input, the debugging artifact, the
fork-point index, the coverage record, and the live control-plane feed. There
is no separate determinism trace, debug log, assertion stream, or coverage
record; every consumer reads a projection of the one log.

This page documents the log as implemented in `crucible-engine`. The scheduler
that produces entries is in [scheduling.md](scheduling.md); the assertion fold
that reads them is in [assertions.md](assertions.md); trigger evaluation is in
[conditions-and-triggers.md](conditions-and-triggers.md); checkpoint offsets
and fork structure are in [execution-graph.md](execution-graph.md); the
determinism contract the causal comparison enforces is in
[determinism.md](determinism.md).

## Code map

| Path | Owns |
|------|------|
| `crates/crucible/crucible-engine/src/scheduler/event_log.rs` | `SchedulerEventLogEntry`, `EventLogTime`, `EventSource`, `EventLevel`, `EventPayload`, `EventLog`, causal, coverage, and proximity projections |
| `.../scheduler/event_codec.rs` | Entry construction, class/source/level derivation, canonical material, binary segment codec, text view |
| `.../scheduler/event_log/projection_material.rs` | Coverage and proximity projection material |
| `.../scheduler/control_state.rs` | `SchedulerEventLogClass`, `SchedulerEventLogPayload`, `SchedulerEventLogAppend`, `EventDiagnosticPayload` |
| `.../scheduler.rs` | Segment magic, version, and byte codes |
| `.../event_catalog.rs`, `.../event_catalog/catalog.rs` | `EVENT_KIND_CATALOG_VERSION`, the kind catalog, the consumer dependency map |
| `.../tracing_bridge.rs` | `TracingBridge`, `TracingBridgeConfig` |
| `.../model/materialized.rs` | `EventLogOffset`, checkpoint coverage and proximity fingerprints |
| `.../model/reproduction.rs` | `ReproductionEventLogArtifact`, `ReproductionEventLogReplay` |
| `crates/crucible/crucible-session/src/session/streams.rs` | `SessionEventLog`, `EventLogCursor`, `SessionEventLogStream` |
| `crates/crucible/crucible-control-api/src/open_set.rs` | `OpenSetEventEnvelope`, the API form of an entry |

All `.../` paths are under `crates/crucible/crucible-engine/src/`.

## Why one log

If each consumer kept its own record, the records would drift: the bytes the
determinism gate compares would no longer be the bytes the assertion engine
folds, and offline checking would stop being equivalent to online checking.
With one log, checking a property is a pure fold over the same bytes the
determinism gate compares, a checkpoint's fork point is an offset into those
bytes, and a live viewer sees the same ordered facts.

The second load-bearing decision is that the causal-versus-observational split
is intrinsic to each entry's kind rather than an external "ignore for
determinism" list. If comparability were a side flag, two builds could disagree
about which entries count and silently weaken the contract. Fixing the class
per kind in a versioned catalog makes the comparable subset a typed, versioned,
content-addressed fact.

## Entry schema

```rust
pub struct SchedulerEventLogEntry {
    sequence: u64,                 // dense per-run sequence, assigned at append
    at: EventLogTime,              // virtual time plus exact tick stamp
    source: EventSource,           // closed origin set
    level: EventLevel,             // display verbosity
    class: SchedulerEventLogClass, // Causal | Observational, from the catalog
    event_payload: EventPayload,   // open-set kind plus typed attributes
    payload: SchedulerEventLogPayload, // typed scheduler payload
    content_hash: ContentHash,     // hash of this entry's canonical material
}
```

Fields are private; consumers read them through `sequence()`, `at()`, `time()`,
`source()`, `level()`, `class()`, `event_payload()`, `payload()`, and
`content_hash()`. `has_valid_content_hash()` recomputes the hash, and
`class_matches_catalog()` checks the class against the catalog.

### Sequence

`sequence` is dense and gap-free over the whole log: causal and observational
entries share one numbering, assigned in append order. It identifies position
within one run and is the cursor unit for streaming. It is not a cross-run
comparison key, because observational interleaving differs between equivalent
runs; the determinism comparison renumbers the causal subsequence instead.

### Time

```rust
pub struct EventLogTime {
    pub virtual_time: VirtualTime,  // scheduler virtual time of the entry
    pub stamp: EventLogTickStamp,
}

pub struct EventLogTickStamp {
    pub node: Option<NodeId>,       // owning node, when node-local
    pub tick: SimInstant,           // exact logical tick, including idle-jump bias
    pub retired: Option<Icount>,    // raw retired count, when independently observed
}
```

`EventLogTime` is `VirtualTime` plus an exact logical tick, with a node on
node-local stamps and an optional independently observed raw retirement
witness. For a resolved `backend_input` entry, `virtual_time` is the
scheduler's logical delivery time and the stamp records the target VM's exact
physical retired-instruction count, computed when the scheduler resolves the
delivery, before a later backend restart can rebase that node's
logical-to-physical mapping. The segment decoder rejects a `backend_input`
entry whose stamp lacks a retired count or whose source is not
`EventSource::Node` for the stamped node. Virtual-time units are defined in
[virtual-time.md](virtual-time.md).

### Source

`EventSource` is a closed set so projections can filter by origin without
parsing text:

| Variant | Origin |
|---------|--------|
| `Scenario { event }` | A scenario event-graph entry: `trigger_fired`, `trigger_action_applied` |
| `Engine` | Scheduler, temporal graph, fault subsystem, assertion engine, evaluation boundaries, diagnostics |
| `Node { node }` | A VM node or deterministic I/O sub-node: backend inputs, I/O completions, preemptions |
| `Guest { node }` | A guest marker or black-box guest signal |
| `Command { command_id }` | A control-plane command, tagged with its session-local correlation id |

The source is derived from the typed payload at construction, never supplied
by the caller. A scheduled control operation is sourced
`Command { command_id }` with the operation's sequence, so a subscriber can
correlate a command with the entries it caused. The command source does not
change the entry's class.

### Level and class

`EventLevel` (`Trace`, `Debug`, `Info`, `Warn`, `Error`) is display verbosity.
`SchedulerEventLogClass` (`Causal`, `Observational`) is determinism relevance.
They are independent: a causal entry can be `Trace` (evaluation boundaries and
RNG draws are), and an observational diagnostic can be `Error`. The determinism
comparison selects entries by class alone; a level filter never removes an
entry from it. Both level and class are derived deterministically from the
typed payload at construction (`scheduler_event_log_payload_level` and the
catalog), except that a diagnostic carries its own level.

## Payload: open-set kind with typed attributes

```rust
pub struct EventPayload {
    kind: String,                                       // catalog kind
    attributes: BTreeMap<String, EventAttributeValue>,  // typed, by name
}

pub enum EventAttributeValue {
    Bool(bool), U64(u64), U128(u128), String(String), Bytes(Vec<u8>),
    Node(NodeId), Event(EventId), VirtualTime(VirtualTime), Icount(Icount),
    Level(EventLevel),
}
```

The kind is an open set governed by the catalog; attributes are typed and
read by name through `attribute`, `bool`, `u64`, `u128`, `string`, `bytes`,
`node`, `event`, `virtual_time`, `icount`, and `level`. Projections and the
assertion engine never scrape a message string. The attribute map is a
`BTreeMap`, so attribute order in canonical material is deterministic.

`EventPayload::diagnostic(name, details)` builds the `diagnostic` escape hatch
for facts that do not warrant a first-class kind: kind `diagnostic` with a
`name` attribute plus typed key/value details. Diagnostics are observational.

The open-set view is projected from the typed `SchedulerEventLogPayload`
(`ResolvedHappening`, `Decision`, `Observable`, `EvaluationBoundary`,
`TriggerFired`, `TriggerActionApplied`, `FaultObservation`, `Diagnostic`) by
`event_payload_from_scheduler_payload`; both are part of the entry's canonical
material.

## Class is a function of the kind

The causal/observational class is fixed per kind by the catalog and assigned
by the typed construction path, not by a caller-supplied boolean:

1. Every scheduler constructor builds the open-set payload first and looks up
   the kind's class with `event_kind_catalog_class`.
2. `EventLog::append_entries` re-checks every entry with
   `class_matches_catalog()` and rejects a mismatch, or a kind absent from the
   catalog, with `SchedulerError::BoundaryViolation` before anything is
   written.
3. `SchedulerEventLogEntry::from_retained_open_event`, the adapter for retained
   open-set events in offline evidence checking, accepts only kinds whose
   recorded class matches the catalog.

A new emission site therefore cannot silently exclude a real causal event from
the gate or include a run-variable observation in it.

## Event-kind catalog

`crucible_engine::event_catalog` is the versioned single source for event kinds
and their classes:

```rust
pub const EVENT_KIND_CATALOG_VERSION: u32 = 7;

pub fn event_kind_catalog() -> &'static [EventKindCatalogEntry];
pub fn event_kind_catalog_entry(kind: &str) -> Option<&'static EventKindCatalogEntry>;
pub fn event_kind_catalog_class(kind: &str) -> Option<SchedulerEventLogClass>;
pub fn event_kind_catalog_dependency_map() -> &'static [EventKindCatalogDependency];
pub fn event_kind_catalog_canonical_bytes() -> Vec<u8>;
```

Each `EventKindCatalogEntry` fixes a kind's class, its allowed source families,
and its stable typed attribute names. Adding a kind, changing a class, or
changing an attribute set bumps the version and regenerates the golden-vector
canonical serialization:

```text
event_kind_catalog.version=7
event_kind_catalog.entries=56
entry kind=app_random class=causal sources=guest,node attributes=node,request_id,stream_domain,stream_name,value,width
...
event_kind_catalog.dependencies=<n>
dependency consumer=<surface> kinds=<kind>,<kind>,...
```

The dependency map records which consumer surfaces read which kinds: the
assertion engine reads `assertion_evaluated`, `assertion_state_changed`,
`assertion_proximity`, and `guest_marker`; the control plane and API read every
kind (`*`); search and fuzzing read `coverage` and `assertion_proximity`; the
determinism harness reads the full causal set. Consumers read this catalog; none
defines a parallel kind vocabulary.

The current catalog (56 kinds):

| Class | Kinds |
|-------|-------|
| Causal: scheduler | `backend_input`, `io_completion`, `control`, `delivery_order`, `rng_draw`, `override`, `preemption`, `campaign_selection`, `app_random`, `evaluation_boundary`, `execution_budget_exhausted`, `probabilistic_effect` |
| Causal: triggers and structure | `trigger_fired`, `trigger_action_applied`, `event_activated`, `savepoint`, `fork`, `tick`, `state_transition` |
| Causal: node, timer, message lifecycle | `node_started`, `node_crashed`, `node_completed`, `timer_armed`, `timer_fired`, `timer_cancelled`, `message_delivered`, `message_dropped` |
| Causal: assertions | `assertion_evaluated`, `assertion_state_changed` |
| Causal: signal-driven fault evidence | `signal_sample`, `signal_transition`, `signal_state_transition`, `binding_activation`, `binding_deactivation`, `association_transition`, `fault_opportunity`, `effect_choice`, `effect_combined`, `effect_committed`, `effect_applied`, `effect_rejected`, `network_profile`, `trace_alignment` |
| Observational: black-box observations | `network_delivered`, `console_output`, `memory_sample`, `observed_io_completion`, `node_state`, `coverage` |
| Observational: guest channel | `guest_marker`, `guest_measurement_begin`, `guest_metric_sample`, `guest_measurement_end`, `guest_semantic_marker` |
| Observational: other | `diagnostic`, `assertion_proximity` |

The signal-driven fault kinds are documented with the fault model in
the [signal-driven faults](../../users/crucible/signal-driven-faults.md)
guide. Some causal kinds
(`event_activated`, `state_transition`, the node, timer, and message lifecycle
kinds, `savepoint`, `tick`) have fixed classes in the catalog but no emitter in
the current scheduler codec; I/O completions are recorded as `io_completion`
and frame deliveries as `backend_input`.

Notes on specific kinds:

- **Trigger firings are causal and are not decisions.** Whether a condition is
  true at an evaluation point is computed from the log prefix, not chosen, so a
  firing is a `trigger_fired` entry (attributes `event`, `condition`, `action`,
  `at`) on the deterministic backbone, followed by `trigger_action_applied`
  entries for its effects. Only probabilistic outcomes of an action are
  schedule decisions. Conditions are evaluated, not logged: the per-point truth
  of a standing condition is never an entry.
- **Black-box observations are observational.** A checked condition prefix
  requires the black-box surface (`network_delivered`, `console_output`,
  `coverage`, `memory_sample`, `observed_io_completion`, `node_state`) to be
  recorded as observational with icount stamps matching their payloads. The
  causal facts they describe are carried by causal kinds such as
  `backend_input` and `io_completion`.
- **Guest markers are observational** even though their retired icounts are
  deterministic. An assertion-flavored marker is a `guest_marker` with
  `marker_kind = "assert"` and the attributes `assertion`, `flavor`,
  `condition`, `must_hit`, `message`, `location`, `retired_icount`, `node`, and
  `detail.<i>.key` / `detail.<i>.value` with `details_len`; a plain marker has
  `marker_kind = "event"` and `marker`.
- **Coverage** entries have `kind = "basic_block"` (`guest_pc`, `block_len`,
  `block`, `execution_icount`, `node`) from the plugin's TCG execution hook, or
  `kind = "named"` (`id`, `retired_icount`, `node`) from white-box coverage
  markers.

## Append path

`EventLog` owns sequencing, content addressing, and the condition prefix.
`EventLog::append_entries` is the single append path; every scheduler append
site routes through it. For one batch (normally one quantum's entries) it:

1. Requires each entry's sequence to equal the next dense sequence.
2. Requires each entry's class to match the catalog.
3. Encodes the batch as one binary segment chained to the current prefix, and
   decodes it back to derive the text view (an encode that does not decode is a
   boundary violation).
4. Stores the segment bytes in the segment store and verifies the returned key
   equals the BLAKE3 hash of the bytes.
5. Advances byte and event counts with overflow checks, computes the new prefix
   hash and `EventLogOffset`, and extends the checked `ConditionEventLogPrefix`
   used by triggers and assertions.

It returns a `SchedulerEventLogAppend { entries, segment_bytes, segment_text,
segment_hash, offset }`. A validation failure rejects the whole batch before
any segment is written, and the offset and prefix advance only after every
step succeeds. The log is append-only: entries are never mutated or removed
in place.

## Segments and content addressing

Each append is one versioned binary segment. Scalars are little-endian;
strings are a `u64` length followed by UTF-8 bytes; optional values are a
presence byte (`0` absent, `1` present) followed by the value:

```text
segment:
  magic             16 bytes  "CRUCIBLE-ELOGSEG"
  version           u32       5
  previous_prefix   32 bytes  prefix hash this segment extends
  entry_count       u64
  entries[entry_count]:
    sequence              u64
    at_virtual_time_ticks u64
    at_tick               u64
    at_raw_retired        optional u64
    at_node               optional string
    source                string   canonical source material
    level                 u8       0 trace, 1 debug, 2 info, 3 warn, 4 error
    class                 u8       0 causal, 1 observational
    payload_kind          string
    payload_attr_count    u64
    content_hash          32 bytes entry hash
    entry_material        string   full canonical entry material
```

Decoding rejects a wrong magic, an unsupported version, trailing bytes, and
the `backend_input` stamp violations above, and `decode(encode(x)) == x` holds
for every valid segment. Older segment versions are rejected rather than
reinterpreted under new semantics.

Hash domains:

| Hash | Definition |
|------|------------|
| Entry | `ContentHash::from_canonical_material("crucible.scheduler.event-log.entry.v5", material)` over sequence, time, source, level, class, open-set payload, and typed payload |
| Segment key | BLAKE3 of the segment bytes |
| Empty prefix | Domain `crucible.scheduler.event-log.prefix.v2`, material `empty=true` |
| Prefix after append | Domain `crucible.scheduler.event-log.prefix.v2` over `previous_prefix`, `appended_segment`, cumulative `bytes`, cumulative `events` |

A checkpoint references the log by `EventLogOffset { prefix, appended_segment,
bytes, events }`; the log owns the byte layout and the checkpoint stores only
the offset. `EventLog::from_offset_with_segment_store` resumes after an offset,
using the reconstructed prefix as the next segment's `previous_prefix`.

```text
parent run:  [seg A]--[seg B]--[seg C]
                          |  fork at offset = end(B)
                          v
child run:   [seg A]--[seg B]--[seg D]   A and B shared by reference; D is new
```

`EventLog::with_segment_store` shares a `DagStore` with the temporal graph.
Forks and clones continue from a shared prefix and append only their own
segments, so a fork's marginal log cost is proportional to what it appends.
Identical segment bytes reached by different paths have the same key and are
stored once.

`segment_text` is a derived, human-readable view (format
`crucible.scheduler.event-log.segment-text.v5`, `canonical_format=
crucible.scheduler.event-log.segment.v5`) with one `key=value` line per field.
It is never the canonical form.

## Determinism comparison

The canonical run is the causal subsequence under the canonical segment
encoding. `event_log_causal_projection(entries)`:

1. Keeps only `SchedulerEventLogClass::Causal` entries, remembering each one's
   raw index.
2. Renumbers the survivors from zero and recomputes their entry hashes.
3. Encodes the renumbered entries as one segment chained to the empty prefix.

`compare_event_log_determinism(expected, reproduced)` compares the two
canonical byte strings. Two runs that differ only in observational entries
(count, content, or interleaving) compare equal, because observational entries
are stripped before renumbering and so cannot shift causal positions. Level is
part of the compared material, but it is a deterministic function of the
payload.

```text
causal(run) := [e in log(run) where e.class == Causal], renumbered 0..N
PASS  iff  segment_bytes(causal(run_1)) == segment_bytes(causal(run_2))
```

The replay-oracle and end-to-end determinism gates compare exactly this
projection. Enabling or disabling observational
output (the `tracing` bridge, white-box markers, diagnostics) cannot change the
causal projection.

## Projections

### Assertion fold

The assertion engine reads the log through checked `ConditionEventLogPrefix`
values: live from `EventLog::condition_prefix()` at each scheduler boundary,
offline by rebuilding the same prefixes from retained entries. Both feed the
same `HostAssertionEvaluator` fold live and offline, so verdicts are identical.
Assertion state changes return to the log as causal `assertion_state_changed`
entries (`id`, `new_state`), where trigger `AssertionState` leaves can read
them. White-box assertion markers are observational `guest_marker` entries
folded under the same `Always`/`Sometimes`/`Reachable` semantics. See
[assertions.md](assertions.md).

### Divergence localization

When causal projections differ, `EventLogDeterminismComparison::mismatch`
reports the first differing renumbered index, the raw index on each side, both
entries, and an `EventLogCausalDivergencePoint { raw_index, at, source, kind }`
per side. The point carries the node/logical tick, source, and kind directly
from the log, so a failure pins to a precise entry rather than a whole-run
mismatch. Assertion replay divergence carries the same point into its
`gate:divergence-bisect` handoff instead of reporting a later assertion-report
difference. The harness-side bisection over fingerprint streams and decision
traces is in `crates/crucible/crucible-test-support/src/divergence.rs`; see
[failure-triage.md](failure-triage.md).

### Coverage projection

`event_log_coverage_projection(entries)` keeps every `coverage` entry in log
order as `EventLogCoverageProjectionEntry { raw_index, at, source, observation
}`, where `EventLogCoverageObservation` is `BasicBlock { node, guest_pc,
block_len }` or `Named { node, marker }`. The projection's content hash is
computed over the sorted unique observation set under
`crucible.scheduler.event-log.coverage-projection.v1` (the default hash when
empty), so repeated hits of one block do not change it.
`coverage_fingerprint_from_event_log` returns that hash, and checkpoint coverage
fingerprints are derived from that coverage projection. `EventLogCoverageFeedback`
hands the same digest to state-space search and coverage-guided fuzzing
(`EventLogCoverageFeedbackConsumer`); neither owns a parallel coverage record.
Coverage entries are observational and never affect the determinism comparison.

### Assertion-proximity projection

The assertion-proximity **distance-to-satisfaction** described in
[assertions.md](assertions.md#assertion-proximity-gradient) is recorded as a
distinct observational `assertion_proximity` kind (`id`, `quantifier`,
`distance` as `u128`, optional `node`), built with
`ObservableEvent::assertion_proximity`. `event_log_assertion_proximity_projection`
keeps the entries in log order and hashes the minimum-distance entry per
`(assertion, quantifier, node)` under
`crucible.scheduler.event-log.assertion-proximity-projection.v1`.
`assertion_proximity_fingerprint_from_event_log` returns that digest, and
`with_assertion_proximity_from_event_log` stores it in checkpoint metadata
without changing checkpoint identity. Guided search reads the digest as a
steering signal; no proximity record exists parallel to the log, and the entries
are excluded from the causal comparison.

### Reproduction artifacts

A reproduction artifact is the self-contained `(seed, scenario, schedule)`
bundle (see [reproduction](../../users/crucible/reproduction.md) and
[failure-triage.md](failure-triage.md)); it does not embed the full log, which
replay recomputes. Compact event-log metadata records the fork-point index and
causal-subsequence digest instead:

```rust
pub struct ReproductionEventLogArtifact {
    pub reproduction_artifact: ContentHash,
    pub fork_point: EventLogOffset,          // debugging fork-point index
    pub causal_subsequence: ContentHash,     // hash of canonical causal bytes
    pub causal_subsequence_bytes: usize,
    pub causal_subsequence_events: usize,
    pub coverage_fingerprint: ContentHash,
    pub shared_store_segments: Vec<ContentHash>, // sorted, unique segment keys
    // plus a private content-addressed id
}
```

Replay produces a `ReproductionEventLogReplay`, whose `passes()` requires the
metadata to belong to the replayed artifact and the recomputed causal digest,
byte length, event count, and coverage fingerprint to match. Causal drift is
rejected without needing the original full log. When a store is shared, the
artifact names log segments by content key so the log can be fetched rather
than recomputed.

### Control-plane streaming

The session owns a `SessionEventLog` hub fed with every appended entry. A
subscriber attaches with an `EventLogCursor { next_sequence }` and receives
`SessionEventLogFrame { generation, cursor, next_cursor, entry }` values
carrying full causal and observational entries, including `Command`-sourced
control correlations:

- Attach subscribes to the broadcast tail first, then clamps a future cursor to
  the retained tail, so no entry appended in between is lost.
- Retained entries from the cursor are replayed in batches of
  `SESSION_EVENT_LOG_REPLAY_BATCH_SIZE` (64) before the stream follows the live
  broadcast tail (capacity `SESSION_EVENT_LOG_BROADCAST_CAPACITY`, 1024).
- A subscriber that lags the bounded tail resumes from the retained log at its
  cursor.
- When the session truncates the hub to re-align it with the engine's log,
  the generation counter advances and later frames carry the new generation.
- Subscribing and dropping a subscriber are observations: they do not enqueue
  a session command, await the scheduler, advance the run, or mutate the live
  snapshot.

`SessionEventLog::snapshot_through` returns event, causal, and observational
counts through a cursor. On the wire, `open_set_event_envelope_from_entry`
converts an entry to an `OpenSetEventEnvelope { sequence, at, source, level,
observational, payload }`. The API surface is in [control-api.md](control-api.md)
and the session in [session.md](session.md).

### `tracing` bridge

Host diagnostics reach `tracing` only through `TracingBridge`, configured by
`TracingBridgeConfig { enabled }`, which defaults to disabled. When disabled,
`mirror_diagnostic` returns `None`. When enabled, it returns an observational
`diagnostic` entry and best-effort emits the same diagnostic under the target
`crucible::tracing_bridge`, ignoring subscriber capture, filtering, and panics
(`catch_unwind`). The bridge is a sink at the edge of log production: it never
reads subscriber state and is never on an ordering-significant path, so the
causal subsequence is byte-identical with no subscriber, a capturing
subscriber, and filtering subscriber modes.

## Tests

| Check | Covers |
|-------|--------|
| `checks.crucible.phase4.eventLogUnified` | One log per run, single append path, projections |
| `checks.crucible.phase4.eventLogSchema` | `EventLogTime`, `EventSource`, `EventLevel`, class, `Command` correlation |
| `checks.crucible.phase4.eventLogPayload` | Open-set payload, typed attributes, `diagnostic` escape hatch |
| `checks.crucible.phase4.eventLogClassCatalog` | Catalog class enforcement at append |
| `checks.crucible.phase4.eventLogContentAddress` | Versioned binary segments, BLAKE3 keys, dedup, offsets |
| `checks.crucible.phase4.eventLogDeterminism` | Renumbered causal subsequence, observational exclusion |
| `checks.crucible.phase4.eventLogAssertionFold` | Live and offline assertion fold over the log |
| `checks.crucible.phase4.eventLogDivergenceBisect` | First differing causal entry localization |
| `checks.crucible.phase4.eventLogCoverage` | Coverage entries and checkpoint fingerprints |
| `checks.crucible.phase4.eventLogReproductionArtifact` | Fork-point index and causal digest metadata |
| `checks.crucible.phase4.eventLogControlPlaneStreaming` | Cursor streaming, non-perturbation |
| `checks.crucible.phase4.eventLogTracingBridge` | Opt-in bridge, subscriber independence |
| `checks.crucible.phase4.eventKindCatalogFreeze` | Catalog golden vector and dependency map |
| `checks.crucible.phase4.eventLogAssertionProximity` | Proximity entries and minimum-distance fingerprint |

Gate wiring is described in [testing-and-gates.md](testing-and-gates.md).
