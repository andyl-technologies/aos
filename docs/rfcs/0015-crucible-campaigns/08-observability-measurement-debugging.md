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

The scenario predeclares accepted IDs, value types, units, occurrence limits,
and node/cohort policies. Unexpected IDs or type mismatches fail according to
the declared guest-protocol violation policy.

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

- **[CMEAS-6]** Guest metric values are untrusted protocol input and MUST be
  bounds/type checked before event-log admission.
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
attempt-leased/retried
worker-started/stopped
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

The signature includes property/assertion identity, stable guest or QEMU failure
class, relevant target/opportunity, and canonical causal evidence. It excludes
worker, PID, wall time, and materialization tier. Rediscovery unions occurrence
observations into one cluster.

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
Which observation snapshot and scores caused the planner to choose it?
Which checkpoint realized the parent?
What exact selection entered the schedule?
Which effects and guest-visible outcomes followed?
How was reward credited to ancestors?
Why was the branch retained, pruned, or made a finding?
```

- **[CMEAS-14]** Explainability data MUST be content-addressed evidence already
  used by the planner, not a best-effort reconstruction from current policy.
