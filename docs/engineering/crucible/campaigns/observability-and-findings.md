# Measurements, observability, and findings

Guidance is only useful when its feedback is canonical, meaningful, and
explainable. Crucible distinguishes:

| Concept | Question answered |
| --- | --- |
| Barrier or marker | Where does an attempt begin, pause, or stop? |
| Property | Is this execution correct? |
| Measurement | What canonical values were observed over a declared window? |
| Metric | How is one measured value represented and aggregated? |
| Objective | Should a metric be minimized, maximized, targeted, or constrained? |
| Guidance signal | How should observations influence future exploration? |
| Operational telemetry | How fast or expensive was execution on this host? |
| Finding | What stable failure occurred and how is it reproduced? |

Properties are never encoded as optimization metrics: a correctness failure
remains a property verdict even when guidance gives it dominant reward.
Operational telemetry is never a canonical measurement source and never
influences modeled selections.

## Measurements

Measurement definitions are a scenario component owned by
`crucible_engine::model::measurement`:

```rust,ignore
pub struct MeasurementDefinition {
    id: MeasurementId,
    begin: BoundarySelector,
    end: BoundarySelector,
    timeout: Option<ModeledTimeout>,
    cohort: CohortPolicy,
    metrics: Vec<MetricDefinition>,  // TOML: [[measurement.metric]]
}

pub struct MetricDefinition {
    id: MetricId,
    value_type: MetricValueType,
    unit: UnitId,
    source: MetricSource,
    aggregation: Aggregation,
}
```

| Vocabulary | Closed values |
| --- | --- |
| Value types | `signed_integer`, `unsigned_integer`, `reduced_rational`, `boolean`, `enumerated`, `integer_vector` |
| Sources | `guest`, `virtual_time`, `node_icount`, `modeled_event_count`, `network_modeled_drop_count`, `storage_completion_count`, `scheduler_event_count` |
| Aggregations | `count`, `sum`, `min`, `max`, `exact_mean`, `histogram`, `first`, `last`, `event_delta` |
| Timeouts | `virtual_time`, `node_icount`, `event_count` |
| Cohorts | `all`, `any`, `quorum` |
| Boundaries | `scenario_genesis`, `scenario_ready`, `plan_event`, `fault_opportunity`, `fault_transition`, `fault_applied`, `guest_marker`, `property_verdict`, `virtual_time`, `node_icount`, `event_count`, `scheduler_quiescence`, `network_idle`, `all`, `any` |
| Units | `boolean`, `bytes`, `dimensionless`, `events`, `instructions`, `operations`, `packets`, `ratio`, `samples`, `virtual_nanoseconds` |

Canonical metric values are integers, reduced rationals, Boolean or enumerated
values, or bounded integer vectors, with checked overflow. Model-owned sources
produce unsigned samples in a fixed unit (virtual time in
`virtual_nanoseconds`, icount in `instructions`, event counts in `events`,
network drops in `packets`, storage completions in `operations`), and are a pure
projection of the authenticated dense scheduler log. Fault boundaries name an
exact fault-binding ID; guest markers are declared in the component and need at
least one white-box VM. Adding a tag or unit requires a new component version.

One scenario admits at most 4,096 measurement windows, 1,024 metrics per
window, and 65,536 metrics overall, with a 32 MiB preflight on the canonical
component body. Identifiers are 1 to 128 bytes of `[A-Za-z0-9._\-/:]`.
Constructors sort measurement IDs, metric IDs, cohort nodes, enumerations, and
histogram boundaries before content addressing and reject duplicates. The
component's canonical body is whitespace-free JSON with declaration field
order and lowercase `snake_case` `kind` tags, and its content hash contributes
to scenario identity; readers re-encode and compare it exactly.

A measurement is committed only when its declared start and end boundaries
have both been reached. A timeout produces an explicit censored or terminal
observation according to the schema; it is never silently converted into a
poor numeric score. Objectives over measurements are evaluated by the
coordinator, which publishes an `ObjectiveEvaluation` keyed by
`(active policy, observation)` after recomputing the exact scalar; planners
consume it only through owner-recomputed guidance (see
[PUCT](exploration.md#tree-policy-deterministic-puct)).

## Event streams

Canonical campaign events reference content-addressed facts: campaign created,
policy activated, budget granted, opportunity discovered, branch request
issued, proposal issued, attempt observed, credit applied, survivors selected,
finding published, pin changed, lifecycle changes, snapshot published.

Operational telemetry covers reservations and retries, executor and QEMU
start and stop, planner invocation, rejection, and timeout, hot template
creation and eviction, fork, restore, and replay latency, dirty RSS and overlay
bytes, store and cache statistics, and control latency. Operational events may
use host timestamps and IDs but are kept in a separate stream and excluded from
configuration identity, planning evidence, and finding identity. The CLI and
API label canonical and operational fields; a combined display may correlate
them, but the encoded records stay separate. `crucible_daemon::campaign_diagnostics`
routes bounded, path-free operational failures to a deployment-owned sink
without changing semantic state.

## Findings

```rust,ignore
pub struct Finding {
    signature: FindingSignature,
    observation: ObservationId,                  // representative
    reproduction: ReproductionArtifactId,
    first_seen_snapshot: CampaignSnapshotId,
    occurrences: /* Merkle-set root + count */,  // at most 1,000,000
    minimized: Option<ReproductionArtifactId>,
    exact_pins: FindingExactPins,
    candidate_bundle: Option<FindingCandidateBundleId>,
    candidate_occurrences: Option<FindingCandidateOccurrenceSet>,
}
```

- The **signature** includes the property or assertion identity, the stable
  guest or QEMU failure class, the relevant target or opportunity, and
  canonical causal evidence (at most 4,096 evidence IDs). It excludes executor,
  PID, wall time, and materialization tier. Rediscovery unions occurrences into
  one cluster. The finding retains the latest occurrence so one set insertion
  can be proven without rescanning history.
- `first_seen_snapshot` is the parent snapshot in which the first observation
  was already visible; naming the publishing successor would create a cycle.
- `exact_pins` holds four sorted role sets: `pre_failure`,
  `measurement_boundary`, `post_failure`, and `additional`, with at most 256
  role associations. The daemon selects among at most 4,096 authenticated
  scheduler-bearing checkpoints for the finding configuration: the greatest
  event count strictly before the failure, the greatest at or before the last
  successful measurement boundary, and the least at or after the failure, ties
  broken by content address. Missing roles stay empty and never prevent thin
  reproduction.

### Reproduction artifacts

A `ReproductionArtifact` binds the semantic and exact scenario and
configuration identities, a stable failure fingerprint, and at most 32 MiB of
self-contained execution-model bytes. The campaign layer does not trust those
bytes by inspection: a typed execution-model adapter replays them, re-derives
every identity and the fingerprint, and only then publishes the record. Every
finding therefore exports the scenario, seed, schedule, evidence, and artifact
identities needed for single-host reproduction without campaign state, daemon,
or shared store.

A minimized reproduction additionally names the original reproduction, the
minimization policy, at most 4,096 dense candidate outcomes, and the final
replayed state. At most one candidate is accepted, it is last, and its observed
fingerprint equals the finding's. The adapter reruns the bounded minimization
before publication (see [minimization](exploration.md#reduction-and-minimization)).

### Reading findings

- `QueryCampaignFindings` reads at most four complete finding records per page
  from one exact snapshot, in signature-index order, with a Merkle range proof
  that authenticates every body, key, cursor, and end-of-file. It grants the
  finding bodies but not the observations, reproductions, or checkpoints they
  name.
- `GetCampaignFindingObject` authenticates one finding membership and returns
  only its representative or latest observation, or its original or minimized
  reproduction. `crucible campaign explain-finding` composes the observation
  and original reproduction reads and checks that they agree.
- A rich finding candidate may carry triage replay evidence in four roles
  (minimization original and selected, verification original and selected).
  The evidence is a small manifest root plus one to three chunks of at most
  32 MiB (80 MiB payload). `GetCampaignFindingTriageReplaySegment` is the only
  operation that transfers it, in fixed 32 MiB segments bound to the principal,
  campaign, snapshot, finding, role, and object ordinal. A client
  authenticates the complete layout before decoding, and a partial sequence
  reveals no replay bytes.

Portable finding bundles (`crucible campaign finding-bundle`) retain the exact
request and response transcript for every replay role so offline import can
revalidate every binding and proof before model-specific decoding.

## Explanation

Every adaptive decision is explainable from durable facts:
`ExplainCampaignAttempt` names the attempt, its execution basis, proposal,
request, and completion; `GetCampaignPlannerRankings` returns an accepted
planner step with its proof-bearing PUCT rankings; survivor decisions carry a
per-configuration explanation (see [beam and Pareto survival](exploration.md#beam-and-pareto-survival)).
Reports distinguish property filtering, Pareto domination, budget pruning,
retention eviction, and genuine exhaustion, and label probability estimates as
descriptive, guidance-biased, or statistically weighted.

## Debugging

A debugger selection at a declared branch point is an ordinary
debugger-caused branch request and remains canonical. Arbitrary register or
memory mutation creates a non-canonical debug session and never changes
retained canonical state. `DebugCampaign` opens an exclusive read-only session
from an authenticated finding. User-facing workflows are in the
[debugging guide](../../../users/crucible/debugging.md).
