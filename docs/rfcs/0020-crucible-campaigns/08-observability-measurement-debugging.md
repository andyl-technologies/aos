# 08 — Measurements, observability, findings, and debugging

Campaign guidance is useful only when its feedback is canonical, meaningful,
and explainable. Crucible distinguishes barriers, properties, measurements,
metrics, objectives, operational telemetry, and findings.

## 08.1 Concepts

| Concept | Question answered |
| --- | --- |
| Barrier/marker | Where does an attempt begin, pause, or stop? |
| Property | Is this execution behavior correct? |
| Measurement | What canonical values were observed over a declared window? |
| Metric | How is one measurement value represented and aggregated? |
| Objective | Should a metric be minimized, maximized, targeted, or constrained? |
| Guidance signal | How should observations influence future exploration? |
| Operational telemetry | How fast/expensive was execution on this host? |
| Finding | What stable failure occurred and how is it reproduced? |

- **[CMEAS-1]** Properties MUST NOT be encoded as optimization metrics. A hard
  correctness failure remains a property verdict even when guidance assigns it
  dominant reward.
- **[CMEAS-2]** Operational telemetry MUST NOT be accepted as a canonical
  measurement source or influence modeled selections.

## 08.2 Measurement definition

```rust,illustrative
pub struct MeasurementDefinition {
    pub id: MeasurementId,
    pub begin: BoundarySelector,
    pub end: BoundarySelector,
    pub timeout: Option<ModeledTimeout>,
    pub cohort: CohortPolicy,
    pub metrics: Vec<MetricDefinition>,
}

pub struct MetricDefinition {
    pub id: MetricId,
    pub value_type: MetricValueType,
    pub unit: UnitId,
    pub source: MetricSource,
    pub aggregation: Aggregation,
}
```

Canonical metric values are signed/unsigned integers, reduced rationals,
Boolean/enumerated values, or bounded integer vectors. Aggregations include
count, sum, min, max, exact mean rational, histogram over declared integer bins,
first/last, and event delta. Overflow behavior is checked and explicit.

The initial executable definition component is
`crucible.model.measurement-definitions.v1`. One scenario admits at most 4,096
measurement windows, 1,024 metrics per window, and 65,536 metrics in aggregate.
A fixed-memory preflight also limits the aggregate canonical component body to
32 MiB before allocating its encoded representation.
A cohort admits at most 4,096 nodes. Enumerations and histogram boundary sets
admit at most 4,096 values, integer vectors declare a nonzero maximum no greater
than 65,536 elements, compound boundaries admit at most 64 children and 32
levels, and every measurement identifier is 1-128 bytes in the closed ASCII
profile `[A-Za-z0-9._\-/:]+`. Constructors sort measurement IDs, metric IDs,
cohort nodes, enumeration alternatives, and histogram boundaries before
content addressing and reject duplicates.

Scenario TOML and compact scenario forms use schema v7. A nonempty measurement
component contributes its exact component content hash to scenario identity.
Noncurrent scenario or outer reproduction schemas are rejected by ordinary
runtime admission.

The measurement component's canonical body is whitespace-free UTF-8 JSON over
the field order shown above; the repeated `metrics` Rust field has wire key
`metric` so TOML renders `[[measurement.metric]]`. Struct fields retain
declaration order; enums use the lowercase `snake_case` `kind` tag, cohort
variants additionally use the `value` field, options use JSON `null` or their
value, integers use canonical
decimal JSON numbers, and collections use the canonical orders required above.
No object map with implementation-dependent key order occurs in this body. Its
identity is
`H("crucible.model.measurement-definitions.v1", lowercase_hex(body))`, using
the execution model's canonical-material hash function. Scenario compact v7
stores that body as one length-prefixed blob and readers must re-encode and
compare it exactly after semantic validation. Campaign `ScenarioArtifact`
record body v1 carries exact scenario-form-v7 bytes under execution-model
payload schema v3. Ordinary runtime admission rejects every other execution-
model payload schema.

The closed v1 tags are:

- value types `signed_integer`, `unsigned_integer`, `reduced_rational`,
  `boolean`, `enumerated`, and `integer_vector`;
- sources `guest`, `virtual_time`, `node_icount`, `modeled_event_count`,
  `network_modeled_drop_count`, `storage_completion_count`, and
  `scheduler_event_count`;
- aggregations `count`, `sum`, `min`, `max`, `exact_mean`, `histogram`, `first`,
  `last`, and `event_delta`;
- timeouts `virtual_time`, `node_icount`, and `event_count`; and
- cohort policies `all`, `any`, and `quorum`.

Boundary tags are `scenario_genesis`, `scenario_ready`, `plan_event`,
`fault_opportunity`, `fault_transition`, `fault_applied`, `guest_marker`,
`property_verdict`, `virtual_time`, `node_icount`, `event_count`,
`scheduler_quiescence`, `network_idle`, `all`, and `any`. Fault boundaries name
an exact scenario fault-binding ID; guest markers are declarations in this
component and additionally require at least one white-box-enabled VM.

Model-owned sources produce unsigned integer samples; other type/source pairs
fail admission. The unit registry is `boolean`, `bytes`, `dimensionless`,
`events`, `instructions`, `operations`, `packets`, `ratio`, `samples`, and
`virtual_nanoseconds`. Adding a tag or unit requires a component schema version.
Model-owned virtual time, node icount, event counts, network drops, and storage
completions require `virtual_nanoseconds`, `instructions`, `events`, `packets`,
and `operations` respectively.

Model-owned samples are a pure projection of the authenticated dense scheduler
log. `virtual_time` emits the entry's virtual-time tick value at every entry;
`node_icount` emits the entry's icount only when its node stamp equals the
declared node; `modeled_event_count` emits `1` for an exact matching
`trigger_fired.event`; `network_modeled_drop_count` emits `1` for each
`message_dropped` whose required `link` equals the optional declared link (or
for every declared-network link when omitted); `storage_completion_count`
emits `1` for each `io_completion.node` matching the declared node; and
`scheduler_event_count` emits `1` for every scheduler entry. A required typed
attribute that is absent or has another type, or a model event whose closed
source is not the catalog-admitted engine/scenario/node authority, fails replay
rather than silently undercounting. Guest and model samples are merged only
after independent source validation and before the common window and
aggregation evaluator.

Both producers emit an entry's samples while that entry is replayed, and the
evaluator folds each sample into its metric's aggregate at once; no sample
outlives its entry. Projection work per entry is bounded by the declared model
metrics, so neither the sample count nor the log length bounds memory. The same
log and definitions therefore produce byte-identical results regardless of
host timing or adapter call order.

`virtual_time` and `node_icount` are level sources: they report a coordinate
at every entry that carries one, so the number of samples they produce depends
on how finely the scheduler divided the run. Only aggregations that depend on
a window's endpoints or extremes, `first`, `last`, `event_delta`, `min`, and
`max`, are defined over them. Event sources (`modeled_event_count`,
`network_modeled_drop_count`, `storage_completion_count`, and
`scheduler_event_count`) and guest samples admit every aggregation.

- **[CMEAS-23]** Measurement evaluation MUST fold each admitted sample into its
  metric's aggregate when the sample's entry is replayed and MUST NOT retain
  samples or per-sample evidence. Its state MUST be bounded by the declared
  measurements, metrics, and histogram bins, independent of log length.
  Scenario validation MUST reject `count`, `sum`, `exact_mean`, and
  `histogram` over the level sources `virtual_time` and `node_icount`.

The pure replay result is
`crucible.model.measurement-evaluation.v3`. Evaluation authenticates each
scheduler entry as it streams, in dense order, and terminal input contains at
most 65,536 node counters. A window decides whether an entry lies inside it
when that entry is replayed, except that a begin boundary resolved only at the
terminal coordinate admits the samples at that coordinate; the evaluator keeps
one pending fold per unopened window for the samples at the latest virtual
time and discards it when time advances. A fixed-memory preflight caps the
final canonical evaluation body at 32 MiB.

The canonical v1 evaluation body is whitespace-free UTF-8 JSON with this
language-neutral shape (brackets denote ordered collections, not literal JSON
syntax):

```text
Evaluation = {
  definitions: ContentHash,
  measurement: { MeasurementId: { window: Window, metrics: { MetricId: Metric } } }
}
Metric = {
  samples: u64,
  aggregate: Aggregate | null
}
Boundary = { sequence: u64|null, at: VirtualTime, events: [Event], cohort: [NodeId] }
Event = { sequence: u64, content_hash: ContentHash }
Window = { kind: not_started }
       | { kind: open, begin: Boundary }
       | { kind: completed, begin: Boundary, end: Boundary }
       | { kind: timed_out, begin: Boundary, timeout: Boundary }
```

The `measurement` and `metrics` object keys are lexicographically ordered.
Struct fields retain the order above. Sample and aggregate values use a
lowercase `snake_case` `kind` plus `value`; their common tags are `signed`,
`unsigned`, `rational`, `boolean`, `enumerated`, `signed_vector`, and
`unsigned_vector`, and aggregates additionally admit `histogram`. A rational
value is `{negative,numerator,denominator}` in that order. `ContentHash` remains
`{bytes:[32 u8]}`. A metric's `samples` is the number of samples its window
admitted. The identity is
`H("crucible.model.measurement-evaluation.v3", lowercase_hex(body))`. Version 3
drops version 2's per-sample list and per-sample entry hashes: both are a pure
function of the replayed log, which the measurement set already references
segment by segment ([CMEAS-20]), so [CMEAS-8] is met by derivation.

Each satisfying boundary retains its completing sequence and virtual-time
coordinate plus the exact scheduler-entry hashes in scheduler order and the
exact selected cohort members. Compound `all` evidence is the ordered union of
its children; `any` chooses the first child in declared order at the first
satisfying scheduler boundary. Cohort `any` chooses the first member in event
order, `all` retains every declared member, and `quorum` retains the first
declared number of distinct members in event order. Samples on both the begin
and end/timeout entries are included. When an end selector and timeout become
true on the same scheduler entry, the declared end wins.

Virtual-time, node-icount, event-count, and scheduler-quiescence terminal
coordinates and the scenario-ready coordinate are modeled replay inputs, never
wall-clock observations. Samples are filtered by both the exact virtual-time
coordinates and scheduler sequences of their window. A network-idle end
selector starts its idle interval when the measurement opens rather than at
scenario genesis. Exact integer arithmetic rejects overflow; rationals use a
reduced signed-magnitude numerator and positive denominator; integer histograms
use inclusive declared upper bounds plus one overflow bin. `count`, numeric
`sum`, and histogram may aggregate an empty window, while `first`, `last`,
`min`, `max`, exact mean, and event delta require samples. Only a completed
window commits a measurement: a completed window without the samples its
aggregation requires fails evaluation, while a `not_started`, `open`, or
`timed_out` window with no admitted sample reports that aggregate as `null`.
Objective projection skips a `null` aggregate, so the campaign records a
missing measurement instead of a numeric score. Retained evaluation
bytes are accepted only by recomputing the complete result and comparing the
canonical body exactly.

The evaluator accepts only normalized typed samples already attached to an
authenticated scheduler sequence. T-CAM-3.2 owns conversion of bounded guest
messages, including marker instance keys; an instance-bearing selector cannot
match a noncurrent instance-free marker payload. T-CAM-3.3 owns projection of
model-derived sources. Those producers cannot alter window or aggregation
semantics.

Example:

```toml
[[measurement]]
id = "recovery"
begin = { event = "fault-applied", binding = "uplink-disruption" }
end = { guest_marker = "routing-converged", cohort = "all-routers" }
timeout = { virtual_milliseconds = 5000 }

[[measurement.metric]]
id = "latency-ns"
type = "event-time-delta"
unit = "virtual_nanoseconds"

[[measurement.metric]]
id = "packets-lost"
type = "counter-delta"
source = "network.modeled-drop-count"
unit = "packets"
```

- **[CMEAS-3]** Every measurement boundary and source MUST resolve during
  scenario validation or be a declared bounded dynamic guest marker.
- **[CMEAS-4]** Measurement windows MUST use virtual time, node icount, modeled
  event sequence, or semantic guest coordinates. Host wall time is forbidden.

## 08.3 Boundary selectors

Supported boundaries include:

- scenario genesis or ready point;
- stable fault opportunity, transition, or applied effect;
- named guest marker with instance key;
- property verdict;
- virtual-time or icount coordinate;
- event count;
- scheduler quiescence;
- modeled network-idle window;
- all/any/quorum of a named node cohort reaching a marker;
- an explicitly declared conjunction/disjunction of the above.

Distributed guest systems often require an `all` or declared quorum marker, not
the first node to report convergence. Cohort membership comes from scenario
identity and cannot vary with host placement.

- **[CMEAS-5]** A stop boundary reached by several events at one virtual
  coordinate MUST use the scheduler's canonical event order and record the exact
  satisfying event set.

## 08.4 Guest measurement protocol

The white-box protocol adds:

```text
MeasurementBegin(measurement ID, instance key)
MetricSample(measurement ID, instance key, metric ID, typed value)
MeasurementEnd(measurement ID, instance key)
SemanticMarker(marker ID, instance key, bounded typed details)
```

These are doorbell protocol version 3 kinds 6 through 9. Every ID and instance
is a `u16`-length-prefixed 1..=128-byte ASCII identifier whose accepted bytes
are alphanumeric plus `.`, `_`, `-`, `/`, and `:`. A typed value begins with one
closed tag:

```text
0 signed i64
1 unsigned u64
2 reduced rational { negative:u8, numerator:u128, denominator:u128 }
3 boolean
4 enumerated identifier
5 signed vector { count:u16, values:[i64] }
6 unsigned vector { count:u16, values:[u64] }
```

Vectors contain at most 512 elements. A rational has a positive denominator,
is reduced, and encodes zero only as `(false,0,1)`. A semantic marker carries at
most 64 details in strictly increasing identifier order. Every complete marker
body is at most 4,608 bytes, matching the dedicated shared-memory marker entry;
the detail-count bound does not waive this aggregate byte limit. The shared
protocol decoder rejects unknown tags, noncanonical rationals, invalid
identifiers, duplicate or unsorted details, and every exceeded bound before
constructing a scheduler event. RFC-0010 §16.5 owns the byte-exact layout and
golden vectors.

The scenario predeclares accepted measurement and metric IDs, metric types and
units, exact marker/instance boundary pairs, and node/cohort policies. A run
holds at most 65,536 simultaneously open `(node,measurement,instance)` tuples.
`MeasurementBegin` opens exactly one
tuple; duplicate begin, sample/end without an open tuple, and an unclosed tuple
at sealing are terminal guest-protocol violations. A sample must name a guest-
sourced declared metric and match its declared type, enumerated vocabulary, and
vector limit. Because evaluation v1 retains one window per measurement, every
guest-sourced measurement must declare exactly one unique instance across its
instance-bearing begin/end selectors, and every lifecycle message must name
that instance; an absent or conflicting instance contract fails the attempt
closed. Semantic-marker details are bounded typed diagnostic material;
they do not become metric samples merely by sharing the value codec.

The QEMU host maps the four messages to the observational event-catalog kinds
`guest_measurement_begin`, `guest_metric_sample`, `guest_measurement_end`, and
`guest_semantic_marker`. Their retired-icount and scheduler sequence are
canonical modeled coordinates. The fresh campaign driver validates the exact
scenario contract and lifecycle before an observation candidate or verified
measurement evaluation can be retained. Current campaign production accepts
guest-sourced metrics through this path; T-CAM-3.3 remains responsible for the
model-owned sources.

Guest reports only facts requiring application knowledge, such as a new routing
epoch becoming converged. The host derives network delivery/loss, fault
application time, instruction counts, device completions, and scheduler events
from canonical model evidence rather than trusting duplicated guest counters.

The protocol is deliberately test-framework-neutral. A Rust guest may wrap a
property-testing library, and any guest may use its native assertion framework,
but neither framework is the campaign boundary. Stable properties,
measurements, markers, and typed choice requests cross the guest protocol so
applications in any language participate in the same replay and guidance
model.

- **[CMEAS-6]** Guest metric values are untrusted protocol input. The closed
  value tag, canonical representation, and aggregate wire bounds MUST be
  checked before scheduler-event construction. Exact scenario ID, source,
  value-type, cohort, and begin/sample/end lifecycle checks MUST complete before
  campaign observation or measurement-evidence admission; any mismatch fails
  the attempt closed.
- **[CMEAS-7]** A guest measurement message MUST NOT itself advance virtual time
  except through the ordinary instruction and doorbell protocol path.

## 08.5 Observation and objective evidence

An observation records:

```text
attempt and child configuration
stop outcome and satisfying boundaries
property verdict set
measurement definitions and exact samples
aggregated metric vector
coverage projection
discovered choice opportunities and branch points
event-log range and evidence digests
```

The immutable scenario definition validates and content-addresses measurement
windows, static boundary references, cohort rules, metric types, sources, and
exact aggregation policy before execution. Current `MeasurementSet` schema v2
retains one execution-model-verified evaluation. Its canonical binary fields
occur in the order shown:

```text
schema-version = 2
definitions: CampaignHash
payload-schema: u32
evaluation: CampaignHash
payload: bytes (nonempty, at most 32 MiB)
evidence: sorted set<ContentId> (at most 4,096)
```

The complete measurement-set body is at most 33 MiB so the 32-MiB evaluation
plus canonical framing fits one generic envelope. `definitions` and
`evaluation` are the exact raw execution-model identities; the payload schema
selects the model-specific verifier. The campaign layer retains those bytes and
generic evidence children but never treats a caller-asserted hash as semantic
proof. Current Crucible payload schema 3 retains the canonical
`crucible.model.measurement-evaluation.v3` body and adds an exact raw-input
contract. Its `evidence` set contains one `Trace` content ID using
`crucible.executor.measurement-replay-evidence.v3` plus the attempt-log segment
leaves it references. The strict canonical CBOR manifest binds the
scenario-definition ID, configuration ID, measurement-definition hash, entry
count, final attempt-log chain hash, ordered segment references, and terminal
ready, frontier, per-node icount, and quiescence state; the segments carry the
complete authenticated scheduler-event sequence
([`15-segmented-event-log.md`](15-segmented-event-log.md)). The manifest is
bounded at 64 MiB; its node collections use the model's deterministic count
limits and reject oversized declared lengths before reserving their contents.
Verification requires the supplied manifest's ID to equal its evidence edge,
authenticates every segment in order, rederives all guest and model samples
solely from the manifest and its segments, evaluates the windows again, and
exact-compares the definition hash, evaluation hash, and payload bytes. A
missing or additional evidence edge, stale binding, forged or non-dense log,
invalid guest message, noncanonical leaf, or replay disagreement fails closed.
Immutable storage alone does not confer semantic status on either payload.

The current measurement-set schema is v2 and contains replay-verified
evaluations. `PropertyVerdictSet` and
`CoverageProjection` remain bounded name/identity maps or sets with generic
child-bearing envelopes. Model-owned sample production is implemented by
T-CAM-3.3. Payload schema 2 provides the codec and replay foundation for
complete raw measurement-event retention. Live QEMU results flow through the
prepared-result journal and child-first publication. Automatic finding
retention applies the admission-bound policy to production checkpoint
inventories and publishes exact semantic pins with the finding transaction.

The daemon's local prepared-publication formats use this closed registry:

| Schema name | Current version | Contract |
|---|---:|---|
| `crucible.executor.prepared-semantic-attempt-result` | 11 | Contains the observation, optional resolved-effect trace manifest, content-ordered raw measurement replay leaves, and optional finding closure. Leaves name their attempt-log segments, the observation its trace segments, and the finding its retained replay records in eight first-seen tables, by identity; the payload carries no segment or replay-record bytes. |
| `crucible.executor.prepared-result-journal-state` | 4 | Binds the execution key, observation/finding IDs, raw-leaf count and ordered-ID-set hash, referenced-segment count and ordered-reference hash (attempt-log segments, then resolved-effect trace segments, under hash domain v2), retained-record count and ordered-ID hash, payload limit, length, and hash. |
| `crucible.attempt.event-log-segment` | 1 | One sealed, content-addressed run of attempt-log entries. The journal owns a copy of every segment its result references, attempt-log and resolved-effect trace alike. |

Readers accept only prepared-result version 11 and journal-state version 4. A
state file and its result payload must use those exact current versions;
mismatches fail closed. Decoding a prepared result reads and authenticates
every referenced segment and retained replay record from the stores it is
given, one at a time; a missing, substituted, or corrupt segment or record
fails closed.

Finding minimization replays a candidate up to twice per reduction step, and
the choice opportunities and selections each replay yields grow with the
replayed run. The replay transcript therefore writes each distinct record to a
record directory under the executor's attempt namespace as it arrives and
keeps only identities in memory. Staging a journal copies every retained
record into the journal's own `records/` directory beside `segments/`, and
reopening reads records only from there. The distinct records of both passes
are charged against a per-finding allowance equal to the run-length
publication allowance for replay-capture segments, and their count against the
prepared-result reader's replay-validation reference allowance.

The prepared-result codec validates raw-leaf closure ownership without claiming
measurement semantics. It checks each singleton edge and its trace ID, scenario,
configuration, and measurement-definition bindings. It cannot compare the
retained evaluation payload with `replay(raw, definitions)` because the journal
does not own authenticated scenario definitions. Production preparation and
recovery must resolve those definitions from the admitted semantic closure and
invoke `verify_crucible_measurement_publication` for the observation and every
finding replay before publishing any leaf or parent. The current codecs
establish the durable representation; they do not by themselves claim
production recovery or publication wiring.

The observation stores both `ConfigurationId` and
`ConfigurationArtifactId`. The former is semantic graph identity; the latter is
the exact replayable child evidence. Coverage storage adds immutable projection
records and derives their identity union, so a new projector can rebuild the
same union without mutating an old bitmap in place.

Objective evaluation produces three strict canonical record schemas.
Objective evaluation and ranking explanation use current schema v2; survivor
selection uses current schema v1. Fields occur in the order shown:

```text
ObjectiveEvaluationV2:
  schema-version: u32
  observation: ObservationId
  configuration: ConfigurationId
  policy: CampaignPolicyId
  rejections: sorted set<ObjectiveRejection>
  components: sorted map<string, ObjectiveComponent>
  scalar-reward: option<FixedReward>

ObjectiveComponent:
  measurement: string
  goal: minimize | maximize
  weight-micros: nonzero u64
  value: option<ObjectiveValue>

ObjectiveValue:
  signed-i64 | unsigned-u64 |
  reduced-rational(negative: bool, numerator: u128, denominator: nonzero u128)

FixedReward:
  negative: bool
  numerator-magnitude: minimal big-endian bytes
  denominator-magnitude: minimal nonzero big-endian bytes
```

The component map exactly repeats the policy's objective names, directions, and
millionth-denominated weights. A missing verified numeric aggregate retains the
component with `value = None` and an exact `MissingMeasurement(name)` rejection.
Failed or inconclusive properties, guest crashes, assertion failures, and
scenario failures are also retained as closed rejection variants. A scenario
failure rejection binds the ordered failure-reason vector by a domain-separated
digest rather than duplicating its potentially large text. Objective evaluation
and ranking explanation are always written as current schema v2. Every other
version is rejected.
`scalar-reward` exists only for a
nonempty, rejection-free vector and is the reduced arbitrary-precision sum of
direction-adjusted weighted values. Objective values and rewards never use
floating point.

The execution-model adapter owns the semantic projection from a verified model
measurement payload to objective values. For current Crucible measurement
payload schema 3, objective names are `measurement-id.metric-id`; the adapter
verifies the definition hash, evaluation hash, payload bytes, and observation's
exact measurement-set identity, accepts only scalar numeric aggregates, and
rejects ambiguous qualified names or nonnumeric aggregates. A caller must first
perform the singleton raw-leaf replay above;
the objective adapter cannot infer that provenance from a supplied typed
evaluation. The generic campaign layer then applies the immutable policy and
filtering rules.

```text
RankingExplanationV2:
  schema-version: u32
  evaluation: ObjectiveEvaluationId
  disposition: selected-objective | selected-novelty |
    selected-breadth-first | filtered(rejections) |
    pareto-dominated(ObjectiveEvaluationId) | rank-pruned
  primary-rank: option<u32>
  novelty-score: u64
  breadth-ordinal: u64

SurvivorSelectionV1:
  schema-version: u32
  policy: CampaignPolicyId
  rule: (method, keep, novelty-reserve, breadth-first-reserve)
  considered: sorted map<ConfigurationId, ObjectiveEvaluationId>
  selected: sorted set<ConfigurationId>
  explanations: sorted map<ConfigurationId, RankingExplanationId>
```

The selection's considered and explanation key sets are identical, the selected
set is a subset of considered configurations and no larger than `keep`, and the
two reserves sum to at most `keep`. Repository publication authenticates the
complete dependency union before its first new decision write and is
content-addressed replayable. Imported and restarted closure validation repeats
the exact policy, observation, property, evaluation, explanation, and ranking
basis checks.

- **[CMEAS-8]** Raw canonical samples and aggregation evidence MUST be retained
  or reproducibly derivable for every metric that influences a proposal,
  survivor selection, or finding report.
- **[CMEAS-9]** Changing objective weights creates a policy revision and may
  re-evaluate existing observations without rerunning their scenarios.

## 08.6 Campaign and operational event streams

The canonical campaign event vocabulary includes:

```text
campaign-created
policy-activated
budget-granted
choice-opportunity-discovered
branch-request-issued
proposal-issued
attempt-observed
credit-applied
survivors-selected
finding-published
pin-changed
campaign-paused/resumed/sealed
snapshot-published
```

Operational telemetry includes:

```text
attempt-reserved/retried
executor/QEMU-started/stopped
planner-invoked/rejected/timed-out
hot-template-created/evicted
fork/restore/replay latency
dirty RSS and overlay bytes
store transfer/cache statistics
daemon control latency
```

Canonical events reference content-addressed facts. Operational events may use
host timestamps and IDs but are stored in a separate telemetry stream and are
excluded from configuration, campaign-planning evidence, and finding identity.

- **[CMEAS-10]** The CLI and API MUST label canonical versus operational fields.
  A combined display may correlate them but the encoded records remain separate.

## 08.7 Findings

```rust,illustrative
pub struct Finding {
    pub signature: FindingSignature,
    pub observation: ObservationId,
    pub reproduction: ReproductionArtifactId,
    pub first_seen_snapshot: CampaignSnapshotId,
    pub occurrences: MerkleSet<ObservationId>,
    pub minimized: Option<ReproductionArtifactId>,
    pub exact_pins: FindingExactPins,
    pub candidate_bundle: Option<FindingCandidateBundleId>,
    pub candidate_occurrences: Option<FindingCandidateOccurrenceSet>,
}
```

The canonical finding record represents `occurrences` as an authenticated
Merkle-set root plus a checked count of at most 1,000,000 observations. It also
retains the exact latest occurrence so the owner can prove one set insertion
without rescanning history. `exact_pins` contains four sorted sets:
`pre_failure`, `measurement_boundary`, `post_failure`, and `additional`. The
256 bound charges role associations, so one checkpoint serving two roles costs
two entries even though its immutable body is stored once. Rediscovery unions
each role independently. The daemon selector authenticates no more than 4,096
scheduler-bearing candidates for the exact finding configuration. It chooses
the greatest event count strictly before the causal failure, the greatest count
at or before the last successful measurement boundary, and the least count at
or after failure; equal-count candidates choose the content-address-least root.
Missing eligible roles remain empty and never prevent thin reproduction.
The current schema v4 retains the first verified candidate bundle and an
authenticated occurrence set containing every verified bundle. Every
noncurrent finding schema is rejected by normal admission.
The signature retains at most 4,096 canonical evidence object IDs. Every
referenced identity or root is an exact envelope child. `first_seen_snapshot`
is the authenticated parent snapshot at which the first observation was already
visible; using the successor that publishes the finding would create a
content-address cycle.

The sole current `ReproductionArtifact` schema v3 binds the semantic scenario and configuration,
their exact `ScenarioArtifactId` and `ConfigurationArtifactId`, the stable
failure fingerprint, at most 34 MiB of static execution-model bytes, and the
ordered run-length segments those bytes reference, each a trace-leaf child
with its encoded length ([§15.11](15-segmented-event-log.md#1511-segmented-reproduction-schedules)).
The campaign layer does not trust those opaque bytes by inspection. A
typed execution-model adapter replays them, re-derives all identities and the
failure fingerprint, and only then publishes the immutable record.

When the reproduction is minimized, the same schema names the exact original
reproduction and retains a nonzero execution-model policy schema with at most
64 KiB of policy bytes, at most 4,096 dense candidate outcomes, and the final
replayed state. Each candidate retains
its sequence, self-contained artifact identity, schedule identity, replayed
state, optional observed failure fingerprint, and accepted bit. At most one
candidate is accepted; it is last and its observed fingerprint equals the
finding fingerprint, and its replayed state equals the retained final replayed
state. Crucible policy v4 contains the deterministic seed, the
4,096-candidate hard bound, and the automatic interesting window when one is
selected; earlier policy versions are rejected. The adapter reruns the bounded
minimization before publication and the repository requires the trace's
original to be the finding's original reproduction. Every noncurrent reproduction body is rejected by ordinary runtime.

The signature includes property/assertion identity, stable guest or QEMU failure
class, relevant target/opportunity, and canonical causal evidence. It excludes
executor, PID, wall time, and materialization tier. Rediscovery unions occurrence
observations into one cluster.

The exact-snapshot PUCT owner may consume only three closed policy-guidance
signals from this root: `finding.property-violation`, `finding.divergence`, and
`finding.timeout`. It scans current clusters and their authenticated occurrence
sets under the RFC 03 aggregate bounds, matches only canonical observations
already credited to the requested branch point, and adds the configured
positive millionth weight once per cluster occurrence. The compact event counts
remain explainable by finding class; unconfigured classes do not affect reward.
Canonical frontier engine version 9 with state schema 4 consumes these counts only through the
exact snapshot-bound `PlannerCandidateGuidanceV2` record. The coordinator
recomputes the record and its saturating weighted reward before publication and
again during restart/import validation; the planner never reads the finding
root or occurrence bodies directly.

The checked `QueryCampaignFindings` service reads at most four complete
finding records in deterministic signature-index order from one exact current
snapshot. Its minimal Merkle range proof authenticates every body identity,
signature key, continuation cursor, and EOF before the API or CLI exposes the
page. Authorization grants those finding bodies and the complete anchoring
snapshot metadata, but not the observation, reproduction, evidence, or exact
checkpoint bodies they name.

The separate checked `GetCampaignFindingObject` capability authenticates one
exact finding membership and returns only its requested representative/latest
observation, original/minimized reproduction artifact, or one schedule
segment of either reproduction. The
`explain-finding` porcelain composes the representative-observation and
original-reproduction reads, then requires both responses to carry the same
finding and the reproduction's exact configuration artifact to equal the
observation child. It renders the identities needed to locate evidence and
perform independent replay without granting arbitrary evidence or checkpoint
body reads.

A rich candidate may additionally name four closed triage replay roles:
minimization-original, minimization-selected, verification-original, and
verification-selected. The current `FindingTriageReplayEvidence` storage
contract uses a small schema-v3 manifest root that commits the reproduction,
observed campaign signature, payload schema, total payload length, one
ordered schema-v1 chunk child of at most 32 MiB, and the attempt-log segments
the payload references, each named in payload order as an owned trace leaf
by content ID and length. The opaque execution-model payload is bounded at
32 MiB: it references each replayed attempt log by its manifest and embeds no
log entries or recording frames ([CMEAS-27]). The evidence ID is always the
stored manifest root ID. A record's log segments are published before the
record, and the finding occurrence-object service serves them by role and
position, one segment per response.

`GetCampaignFindingTriageReplaySegment` is the only checked service operation
that transfers these stored envelopes. Its request binds the principal,
campaign, exact current snapshot, finding, candidate bundle, closed replay
role, evidence root, root-first object ordinal, exact object content ID, and
fixed 32 MiB segment index. The response repeats the authenticated storage
description and server-derived range, carries the finding and occurrence
membership proofs, and is bounded by the ordinary 64 MiB component-message
limit. A client fetches and authenticates every root segment before it learns
or requests manifest children. It then fetches all child envelopes in declared
order and authenticates the complete physical layout and logical evidence ID
before decoding or exposing the replay. Missing, reordered, substituted,
mixed-snapshot, wrong-role, stale-description, or corrupt segments fail closed.
A partial manifest or chunk sequence reveals no replay bytes.

Failure-findings ledger v5 retains the exact ordered request/response transcript
for every replay role by content address. Capture stores each canonical request
and response as its own blob in an evidence store as it arrives. A per-finding
evidence record names the finding-level exchanges, the report projection, and
occurrence chunks of at most 1,024 occurrences; each chunk entry names its page
exchange, its three object exchanges, and the ordered segment exchanges of all
four replay roles, each followed by a content-addressed list of the exchanges
that served that role's log segments in record order. The record and each chunk
entry also name, for the original and any minimized reproduction, a
content-addressed list of the reproduction's schedule-segment exchanges in
manifest order. The ledger itself is a manifest of `(finding, record)` pairs
in canonical finding-ID order, bounded at 16 MiB, whose content address is the
triage result's stored-ledger key. Offline import authenticates one finding and
one occurrence at a time: a store-backed service answers only requests whose
canonical bytes hash to an exchange the current record names, and it
revalidates each request binding, proof, description, canonical range,
envelope content ID, manifest, chunk, and final logical identity before
model-specific replay decoding. Every blob read is bounded and verifies its
content address; a record, chunk, or manifest is accepted only in its exact
canonical encoding. A portable finding bundle carries the one-finding manifest,
its evidence store, and the executable archive ([CMEAS-24]).

The checked `ExplainCampaignAttempt` capability authenticates one attempt and
its unique execution-basis admission in `roots.accounting`, its branch proposal
in `roots.exploration` when present, and its canonical completion or absence in
`roots.observations`. The returned path and selection close the semantic chain
from branch request cause and admission ordinal through the exact edge and
value to the resulting observation. The CLI `explain-attempt` view exposes
those identities and reads the observation's bounded canonical effect trace
and measurement event leaf through proof-bearing chunks. It verifies each full
leaf's content ID before projecting applied network effects, marker names,
typed route details from the failover marker, and unsigned guest metric samples;
raw packet payloads and unrelated guest marker details are not rendered.

- **[CMEAS-11]** Every finding MUST carry a self-contained `(scenario, seed,
  schedule)` reproduction artifact and verify it before publication. The
  artifact's schedule segments are part of it; they are retained as its
  content children ([CCOMP-32]).
- **[CMEAS-12]** Retaining an exact closure improves debug startup but MUST NOT be
  required to reproduce the finding.

## 08.8 Failure retention policy

On a critical failure, policy may retain:

- the nearest exact checkpoint before the causal fault/selection;
- the exact checkpoint at the last successful measurement boundary;
- a post-failure stopped checkpoint when safe;
- the schedule suffix and resolved effect trace;
- relevant event-log and metric closure;
- console, stack, core, or debugger metadata allowed by export policy.

Retention is asynchronous only after a canonical safe stop. If exact capture
fails, the finding and thin replay artifact still publish, with a localized
retention diagnostic.

Exact-checkpoint selection is operational acceleration, but its selected roots
are canonical finding children once committed. Candidate authentication and
selection occur before finding publication; publication unions the selected
roles with the existing cluster in the same snapshot transition as the new
occurrence. Original/minimized reproduction and direct observation-owned
measurement, property, or coverage evidence roots pull their complete
authenticated child closures into the finding closure.

## 08.9 Debugging and stepping

`campaign debug` chooses the cheapest retained state, restores it into an
exclusive debug session, and initially remains canonical/read-only. Reading
registers, memory, device state, event history, signals, bindings, selections,
and metrics does not change the run.

Resume, step, or selection override from the retained configuration creates a
new canonical campaign branch only if it publishes a debugger-caused
`BranchRequest` at a declared branch point. Arbitrary register/memory writes,
skipped events, and QMP mutations create a non-canonical derived debug session
with explicit provenance.

- **[CMEAS-13]** Debugger actions MUST never mutate the retained campaign object
  or exact closure. Every writable session receives private overlays and host
  continuation state.

## 08.10 Explainability

For any configuration or proposal, the system can answer:

```text
Why was this value legal?
Which producer offered it?
Which finite or generated source proposed it, and why was that request issued?
Did another request cause deduplicate onto the same semantic edge?
Which planner invocation, planning view, engine artifact, budget, and scores
caused the coordinator to accept it?
Which checkpoint realized the parent?
What exact selection entered the schedule?
Which effects and guest-visible outcomes followed?
How was reward credited to ancestors?
Why was the branch retained, pruned, or made a finding?
```

- **[CMEAS-14]** Explainability data MUST name the accepted planner invocation,
  bounded planning view, engine/artifact, coordinator validation and accounting,
  and content-addressed evidence actually used for the step, not a best-effort
  reconstruction from current policy or an unverified planner claim.
