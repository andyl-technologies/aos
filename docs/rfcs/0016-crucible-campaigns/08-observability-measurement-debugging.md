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

Scenario TOML and compact scenario forms write schema v6. Scenario v5 remains
readable only as the exact compatibility form with no measurement definitions;
empty definitions deliberately preserve the prior scenario identity. A
nonempty component contributes its exact component content hash to scenario
identity. Reproduction artifacts carrying v6 scenario bytes write outer v6,
while prior outer v5 artifacts remain readable.

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
the execution model's canonical-material hash function. Scenario compact v6
stores that body as one length-prefixed blob and readers must re-encode and
compare it exactly after semantic validation. Campaign `ScenarioArtifact`
payload v1 remains the retained scenario-form-v5 profile; new scenario-form-v6
imports use payload v2.

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

Projection admits at most 4,000,000 model-metric-by-event visits, 1,000,000
emitted samples, and 64 MiB of aggregate canonical sample JSON. These checks
use checked arithmetic and run before proportional allocation. The same log
and definitions therefore produce byte-identical samples regardless of host
timing or adapter call order.

The pure replay result is
`crucible.model.measurement-evaluation.v1`. Evaluation first authenticates a
dense scheduler-log range, then admits at most 1,000,000 normalized samples and
1,000,000 scheduler entries. Normalized samples have a separate aggregate
64-MiB canonical-body limit, and terminal input contains at most 65,536 node
counters. The checked product of all begin/end selector-tree nodes and scheduler
entries plus the terminal visit is at most 4,000,000 visits. A fixed-memory
preflight also caps the final canonical evaluation body at 32 MiB. These are
deliberate aggregate work bounds: individual schema maxima are not promised to
compose without limit.

The canonical v1 evaluation body is whitespace-free UTF-8 JSON with this
language-neutral shape (brackets denote ordered collections, not literal JSON
syntax):

```text
Evaluation = {
  definitions: ContentHash,
  measurement: { MeasurementId: { window: Window, metrics: { MetricId: Metric } } }
}
Metric = {
  samples: [{ sequence, measurement, metric, value }],
  aggregate: Aggregate,
  evidence: [ContentHash]
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
`{bytes:[32 u8]}`. The identity is
`H("crucible.model.measurement-evaluation.v1", lowercase_hex(body))`.

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
`min`, `max`, exact mean, and event delta require samples. Retained evaluation
bytes are accepted only by recomputing the complete result and comparing the
canonical body exactly.

The evaluator accepts only normalized typed samples already attached to an
authenticated scheduler sequence. T-CAM-3.2 owns conversion of bounded guest
messages, including marker instance keys; an instance-bearing selector cannot
match the legacy instance-free marker payload. T-CAM-3.3 owns projection of
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
units, exact marker/instance boundary pairs, and node/cohort policies. One run
retains at most 1,000,000 scheduler entries and at most 65,536 simultaneously
open `(node,measurement,instance)` tuples. `MeasurementBegin` opens exactly one
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
proof. For Crucible payload schema 1, the daemon recomputes
`crucible.model.measurement-evaluation.v1`, exact-compares the payload, and
checks both hashes before the value can be consumed as verified measurement
input. Immutable storage alone does not confer that semantic status.

Legacy measurement-set schema v1 remains readable and preserves its original
content identity. It contains named `MeasurementSeries` values with a nonempty
sample vector and claimed same-type aggregate, and is explicitly not a verified
evaluation or valid new policy input. `PropertyVerdictSet` and
`CoverageProjection` remain bounded name/identity maps or sets with generic
child-bearing envelopes. Model-owned sample production, complete raw event-log
retention, and objective evaluation remain owned by T-CAM-3.3 through
T-CAM-3.5.

The observation stores both `ConfigurationId` and
`ConfigurationArtifactId`. The former is semantic graph identity; the latter is
the exact replayable child evidence. Coverage storage adds immutable projection
records and derives their identity union, so a new projector can rebuild the
same union without mutating an old bitmap in place.

Objective evaluation produces a separate deterministic record naming the
observation and policy:

```rust,illustrative
pub struct ObjectiveEvaluation {
    pub observation: ObservationId,
    pub policy: CampaignPolicyId,
    pub admissible: bool,
    pub metric_vector: Vec<ObjectiveValue>,
    pub scalar_reward: Option<FixedReward>,
    pub pareto_class: Option<ParetoClassId>,
}
```

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
    pub exact_pins: Vec<ExactClosureId>,
}
```

The canonical schema-v1 record represents `occurrences` as an authenticated
Merkle-set root plus a checked count of at most 1,000,000 observations. It also
retains the exact latest occurrence so the owner can prove one set insertion
without rescanning history. `exact_pins` is a sorted bounded set of at most 256
`ExactCheckpointId` values, and the signature retains at most 4,096 canonical
evidence object IDs. Every referenced identity or root is an exact envelope
child. `first_seen_snapshot` is the authenticated parent snapshot at which the
first observation was already visible; using the successor that publishes the
finding would create a content-address cycle.

`ReproductionArtifact` schema v1 binds the semantic scenario and configuration,
their exact `ScenarioArtifactId` and `ConfigurationArtifactId`, the stable
failure fingerprint, and at most 32 MiB of self-contained execution-model
bytes. The campaign layer does not trust those opaque bytes by inspection. A
typed execution-model adapter replays them, re-derives all identities and the
failure fingerprint, and only then publishes the immutable record.

The signature includes property/assertion identity, stable guest or QEMU failure
class, relevant target/opportunity, and canonical causal evidence. It excludes
executor, PID, wall time, and materialization tier. Rediscovery unions occurrence
observations into one cluster.

The checked `QueryCampaignFindings` service reads at most four complete
finding records in deterministic signature-index order from one exact current
snapshot. Its minimal Merkle range proof authenticates every body identity,
signature key, continuation cursor, and EOF before the API or CLI exposes the
page. Authorization grants those finding bodies and the complete anchoring
snapshot metadata, but not the observation, reproduction, evidence, or exact
checkpoint bodies they name.

The separate checked `GetCampaignFindingObject` capability authenticates one
exact finding membership and returns only its requested representative/latest
observation or original/minimized reproduction artifact. The
`explain-finding` porcelain composes the representative-observation and
original-reproduction reads, then requires both responses to carry the same
finding and the reproduction's exact configuration artifact to equal the
observation child. It renders the identities needed to locate evidence and
perform independent replay without granting arbitrary evidence or checkpoint
body reads.

The checked `ExplainCampaignAttempt` capability authenticates one attempt and
its unique execution-basis admission in `roots.accounting`, its branch proposal
in `roots.exploration` when present, and its canonical completion or absence in
`roots.observations`. The returned path and selection close the semantic chain
from branch request cause and admission ordinal through the exact edge and
value to the resulting observation. The CLI `explain-attempt` view exposes
those identities without granting evidence-set or checkpoint bodies.

- **[CMEAS-11]** Every finding MUST carry a self-contained `(scenario, seed,
  schedule)` reproduction artifact and verify it before publication.
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
