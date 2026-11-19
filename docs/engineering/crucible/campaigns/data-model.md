# Campaign data model

The campaign model keeps immutable content under one mutable user-visible
reference. Its authoritative state is a set of facts and their Merkle
projections. Daemon queues, iterators, and frontier indexes are rebuildable
from that state. The types live in `crucible-campaign` (`model`, `exploration`,
`choice`, `observation`, `finding`, `policy`, and `repository` modules).

Examples on this page are simplified field sketches. The registered schema
version of every record is listed in the [schema registry](schema-registry.md).

## Identity

Every stored campaign record has exactly one identity: a record-specific typed
wrapper around the generic `ContentId` of its complete canonical
[content envelope](storage.md#content-envelope). There is no second logical
hash that could disagree with the storage identity.

```text
ScenarioDefId     = H(world, plan, properties, measurements, selectables, seed)
ConfigurationId   = H(ScenarioDefId, Schedule)

CampaignLineageId = H(ScenarioDefId, ScenarioArtifactId,
                      GenesisConfigurationId, ConfigurationArtifactId,
                      CrucibleVersion, QemuBuildAndAtomicPatch,
                      ProtocolVersions)

CampaignPolicyId   = H(canonical CampaignPolicy)
CampaignSnapshotId = H(canonical CampaignSnapshot)
CampaignViewId     = H(canonical CampaignPlanningView)
```

Values such as `ConfigurationId`, `BranchPointId`, and `BranchEdgeId` are
semantic digests derived from other records; they are not stored record
identities. Stored records (policies, snapshots, facts, choice domains,
opportunities, selections, planner artifacts, Merkle nodes) use typed
`ContentId` wrappers.

Choice-related records have both an exact and a semantic identity. The exact
`ChoiceDomainId`, `SelectableId`, and `ChoiceOpportunityId` cover
presentation metadata such as labels and landmarks. The corresponding
`ChoiceDomainSemanticId`, `SelectableSemanticId`, and
`ChoiceOpportunitySemanticId` omit it. Branch points and edges derive from the
semantic IDs, so a label change does not split a branch, while storage closure
and provenance retain the exact IDs.

The textual and canonical-binary form of a stored-record ID includes its
registered schema tag (`schema-name@kind.version.digest`). A policy content ID
therefore cannot be decoded as a planner-state or generator ID merely because
they share an object kind. The generic content ID becomes authoritative only
after the named envelope is loaded and authenticated as the claimed schema.

The human campaign name is not an identity component: it is a mutable
reference such as `network-recovery -> CampaignSnapshotId`.

`CampaignLineage` carries both semantic scenario and genesis identities and
exact references to the owned `ScenarioArtifact` and `ConfigurationArtifact`
records. Repository reads resolve those records and recheck every cross-record
binding. A QEMU, Crucible, guest-protocol, shared-memory protocol, scenario
schema, or exact-closure change begins a new lineage; a policy revision never
changes existing configuration IDs.

## Policy

```rust,ignore
pub struct CampaignPolicy {
    scenario: ScenarioDefId,
    campaign_seed: CampaignSeed,
    mode: CampaignMode,          // Strict | Streaming | Statistical
    explorer: ExplorerPolicy,    // TreeSearch | Beam | Exhaustive
    choice_policies: BTreeMap<String, ChoicePolicy>,
    objectives: BTreeMap<String, Objective>,
    guidance: BTreeMap<String, GuidanceWeight>,
    stop_conditions: BTreeSet<String>,
    fairness: FairnessPolicy,
    retention: RetentionPolicy,
    admit_scenario_defaults: bool,
    intervention_learning: InterventionLearningPolicy,
    attempt_timeout_policy: Option<CampaignAttemptTimeoutPolicy>,
    statistical_sampling: Option<StatisticalSamplingDesign>,
    sequential_monte_carlo: Option<SequentialMonteCarloDesign>,
}
```

`CampaignPolicyIdentity` groups the scenario, seed, mode, and exploration
engine; `CampaignPolicy::rules` supplies the remaining fields.

- `Strict` folds attempt results in deterministic admission order, so the
  proposal sequence can be re-derived.
- `Streaming` incorporates observations as they arrive. Each branch and finding
  remains reproducible, but campaign evolution may depend on arrival order.
- `Statistical` enforces the sampling and weighting rules described in
  [statistical mode](exploration.md#statistical-mode).

The mode selects the observation-fold contract and is fixed for one campaign
reference. Steering may activate another policy only with the same mode;
changing mode requires deriving a new campaign.

An optional attempt timeout bounds every attempt's stop by an absolute
virtual-time deadline, an absolute scheduler-quantum deadline, or both. The
first modeled bound reached produces a proof-bearing `PolicyTimeout` outcome;
terminal and assertion outcomes take precedence, and virtual time wins a
same-quantum tie. An optional host completion watchdog is operational
supervision: its expiry aborts the assignment as an infrastructure failure and
never becomes a modeled timeout or finding.

Resource placement is not policy. Worker count, memory limits, CPU affinity,
store endpoints, and cache inventory are daemon configuration. Budgets are
immutable grants recorded in campaign accounting, so a long-lived campaign can
receive more work without changing its identity.

## Snapshot

```rust,ignore
pub struct CampaignSnapshot {
    parent: Option<CampaignSnapshotId>,
    lineage: CampaignLineageId,
    active_policy: CampaignPolicyId,
    roots: CampaignRoots,
    transition: Option<CampaignFactId>,
    budget_ledger: CampaignBudgetLedgerId,
}
```

| Root | Contents |
| --- | --- |
| `graph` | Configurations, branch points, schedule edges, discovered opportunities |
| `exploration` | Branch requests, proposals, candidate sources, continuation and planner-scan indexes |
| `observations` | Canonical attempt results, determinism conflicts, measurements, verdicts, coverage, paths, expansion credits, objective evaluations |
| `corpus` | Retained configurations and reproduction artifacts worth further mutation |
| `coverage` | Grow-only set of canonical coverage projections |
| `findings` | Failure signatures, clusters, minimization products |
| `pins` | User and policy retention decisions |
| `accounting` | Budget grants, admissions, dispositions, policy activation, lifecycle and operator commands |
| `coordination` | Coordinator progress, planner-step and result indexes; excluded from semantic planner input |

The budget ledger additionally indexes, for every branch request, which
semantic attempts it spent and which proposals it caused. Its authenticated
entry counts give exact per-request spending without scanning history.

Snapshot history for one reference is linear because exactly one coordinator
owns it. A non-genesis snapshot names exactly one `transition` fact that caused
the parent-to-child change. Reading a snapshot replays that transition
contract: each successor must preserve lineage, change only the roots its
transition permits, and reconstruct the exact affected Merkle entries. A
transition family without an implemented replay projection fails closed on
import. Genesis has canonical empty roots, except that `graph` and `corpus`
contain exactly the lineage's genesis configuration.

Expansion state, frontier, statistics, and status are projections. A snapshot
must be readable without any daemon-local queue, reservation, PID, socket,
hot-fork handle, or filesystem path, and deleting every projection cache cannot
change its meaning. Advancing a name is a compare-and-swap from one snapshot ID
to another, performed only after every new object is published and
authenticated.

## Facts

Facts are immutable, carry causal references, and live in persistent Merkle
maps rather than a flat log. The current variants of `CampaignFact` are:

| Fact | Purpose |
| --- | --- |
| `ChoiceOpportunityDiscovered` | Explicit operator discovery of an opportunity at a parent configuration |
| `BranchRequestAccepted` | A validated request plus an immutable summary of its source cardinality and budget window |
| `PlannerAdvanced` | One accepted planner step |
| `ProposalIssued` | One proposal emitted by a request |
| `AttemptAdmitted` | An attempt admission (execution basis or additional cause) |
| `AttemptClosed` | A non-modeled terminal disposition for an admitted ordinal |
| `ObservationCredited` | Canonical incorporation of an observation and its expansion credits |
| `FindingPublished` | A new or rediscovered finding cluster |
| `ObjectiveEvaluationPublished` | An owner-recomputed objective evaluation for `(policy, observation)` |
| `PolicyActivated`, `BudgetGranted`, `ControlRequested` | Steering, budget, and lifecycle commands |
| `PinChanged`, `PinCommandAccepted` | Retention intent for a configuration |
| `CampaignDerived` | First snapshot of a derived campaign |
| `DiscoveryRequested` | An idempotent explicit discovery command |
| `SavepointCaptureRequested`, `SavepointCaptureResolved`, `SavepointContinuationSelected` | Operational capture of a paused attempt boundary and its selected continuation |

Notable rules:

- Publishing a `ChoiceOpportunity` body does not make it campaign knowledge.
  It becomes authoritative only through `ChoiceOpportunityDiscovered` or as a
  discovered choice in a canonical observation. A branch request must find the
  exact opportunity under its `(BranchPointId, ChoiceOpportunityId)` graph key;
  object presence in the store is insufficient.
- `AttemptClosed` carries a `NonModeledAttemptDisposition`:
  `OperatorCancelled`, `PermanentlyIncompatible`, `InvalidInput`,
  `Unauthorized`, or `TerminalWorkerFailure`. It closes the admitted ordinal
  without inventing an observation or modeled outcome. Retriable operational
  failure never closes an ordinal.
- `CampaignDerived` preserves lineage and every semantic root, changes only
  the coordination root, and names the exact source snapshot. A replacement
  policy must keep the scenario and mode.
- Pin and objective-publication commands resolve exact replay before
  staleness: retrying the same command returns the first accepted result,
  while reusing a command ID with different content fails closed. Unpinning
  writes a `retention = None` tombstone rather than erasing history.
- A savepoint capture references an existing attempt and its declared stop. It
  spends no budget, does not advance the frontier, and does not change pins.
  The executor drives the attempt to the stop, captures the reached boundary
  without publishing a semantic observation, and keeps it as a physical GC root
  until it is discarded or a selected continuation takes ownership.

### Planner steps

```rust,ignore
pub struct CampaignPlanningView {
    graph_root, exploration_root, observations_root, corpus_root,
    coverage_root, findings_root, accounting_root,
}
```

The planning view contains every canonical input allowed to affect proposal
order. It deliberately excludes pins, coordinator bookkeeping, physical
retention, materializations, and store placement, so a storage-tier or pin
change cannot perturb strict proposal order.

A `PlannerInvocation` binds the planner engine, policy artifact, policy,
planner state, planning view, one exact served scan page, and an explicit
planning budget. A `PlannerStep` records the invocation, the retained request
digest, a disposition, the next planner state, the planner's usage claim, the
coordinator's recomputed accounting, and the guidance evidence used.

```text
PlannerDisposition := ContinueScan { cursor }
                    | Issue { selected, issued_branch_requests, issued_proposals }
                    | NoWork
```

`ContinueScan` is accepted only for an incomplete served page, and its cursor
must equal that page's last position. `NoWork` is accepted only for a complete
page. A first scan, or a scan after the semantic view changes, starts at the
beginning; a same-view continuation starts exactly at the prior cursor. The
coordinator recomputes the page from the named view at acceptance and on import,
so a result cannot skip a key, invent end-of-file, or substitute input
accounting. Accounting is always recomputed by the coordinator; the planner's
own usage claim is diagnostic.

## Branch points, requests, proposals, attempts, observations

```text
BranchPointId = H(parent ConfigurationId, ChoiceOpportunitySemanticId)
BranchEdgeId  = H(BranchPointId, ChoiceDomainSemanticId, ChoiceValue)
```

Request cause and proposal provenance are absent from both identities. If a
policy generator and an operator request emit the same value, both proposal
facts stay visible but converge on one branch edge and, when the stop condition
and other execution inputs also match, one semantic attempt.

```rust,ignore
pub struct BranchRequest {
    branch_point: BranchPointId,
    parent: ConfigurationArtifactId,
    opportunity: ChoiceOpportunityId,
    domain: ChoiceDomainId,
    source: CandidateSource,     // see exploration.md
    cause: BranchRequestCause,   // Planner | Operator | Debugger
                                 // | ExhaustivePolicy | ScenarioDefault
    budget: BranchBudget,        // maximum_proposals, maximum_attempts
    stop: StopCondition,
}
```

`maximum_proposals` bounds values emitted by the request, including values
that deduplicate against prior work. `maximum_attempts` bounds new semantic
attempts the request may cause. Attaching a new cause to an already admitted
edge consumes no attempt and never re-executes it. `ScenarioDefault` is valid
only with the active policy, an enabled scenario-default bit, a singleton
finite source equal to the opportunity default, and a one-proposal,
one-attempt budget.

```rust,ignore
pub struct Attempt {
    start: AttemptStart,   // Discover | Branch | AfterAttempt
    path: BranchPathId,
    stop: StopCondition,
    continuation_input: Option<AttemptContinuationInput>,
}
```

- `Discover` realizes a configuration until its next pending choice or
  terminal outcome without pretending an edge exists.
- `Branch` resumes a known parent opportunity and applies exactly one recorded
  selection.
- `AfterAttempt` continues from the configuration reached by an earlier
  attempt.

`AttemptId` digests only these semantic inputs. Executor, reservation
generation, retry number, start time, preferred materialization, request, and
proposal are excluded. Separate `AttemptAdmission` records link every proposal
that justified the attempt: exactly one `ExecutionBasis` (which spends the
request budget, fixes statistical sampling provenance, and carries a global
`AdmissionOrdinal`) and any number of `AdditionalCause` records, which can
neither trigger execution nor change estimator eligibility.

`BranchPath` retains each `(BranchPointId, BranchEdgeId)` segment because an
edge digest is not invertible. Feedback credits every branch point on the path
without an in-memory search stack. A convergent configuration keeps every path
that reached it; planner admission deterministically uses the path with the
lowest `BranchPathId`.

Stop conditions:

```text
StopCondition := NextChoice | NamedBoundary(name) | Terminal
               | VirtualTimePicoseconds(t) | EventCount(n)
               | ExecutionQuanta(q) | VirtualTimeOrExecutionQuanta { t, q }
               | NextChoiceOrExecutionQuanta { q }
               | Observation(ObservationCondition)
               | Bounded { primary, policy deadlines }
```

Quantum bounds are absolute scheduler coordinates from scenario genesis, so a
resumed attempt charges only the suffix after its checkpoint. Terminal and
assertion outcomes take precedence over every deadline, and virtual time wins a
same-quantum tie. The intrinsic fallback of `NextChoiceOrExecutionQuanta`
reports a distinct `BoundedPrimaryTimeout`, and a policy deadline reports
`PolicyTimeout`; neither can authorize a selected continuation.

```rust,ignore
pub struct Observation {
    attempt: AttemptId,
    child: ConfigurationId,
    child_content: ConfigurationArtifactId,
    path: BranchPathId,
    stop: StopOutcome,
    measurements: MeasurementSetId,
    properties: PropertyVerdictSetId,
    coverage: CoverageProjectionId,
    discovered_choices: BTreeSet<ChoiceOpportunityId>,
    produced_selections: BTreeSet<SelectionId>,
    resolved_effect_trace: Option<ContentId>,
}
```

Every referenced identity is an exact envelope child, so an accepted
observation roots its complete replay closure. `produced_selections` are the
selections made while execution continued through opportunities discovered by
the same attempt; each must resolve to exactly one discovered opportunity.

Modeled timeout, crash, assertion failure, and successful stop are observation
outcomes. QEMU or executor loss, daemon restart, reservation loss, and store
unavailability are operational outcomes and never receive modeled reward. A
temporal-graph child is created only after execution produces and
authenticates it, never merely because a proposal exists.

## Continuation state

For one branch point the campaign projects an `ExpansionState`: its requests,
proposals, admissions, observations, statistics, and a paged map of
per-request `ContinuationState`:

```text
ContinuationState := Ready
                   | WaitingForFeedback { completed_visits, required_visits }
                   | Open | Exhausted | Closed
```

`WaitingForFeedback` carries the exact distinct observation-credit count and
the next inclusive threshold. It is not a timer.

Feedback is idempotent. An expansion credit is the fact
`H("crucible.campaign.expansion-credit.v1", ObservationId || BranchPointId)`.
Canonical observation publication creates one credit for each distinct branch
point on the authenticated path; an exact replay or a determinism-conflict
observation creates none. Credits are indexed per branch point inside the
observations root, so restart recovers visit counts without listing the store.

The exploration root also anchors a continuation index (one compact projection
per request) and an ordered planner-scan index containing every request whose
proposal cap is unspent, ordered by branch-point hash then request digest.
The snapshot owner updates these indexes in the same transition that changes
the underlying request, proposal, or admission, and cold validation recomputes
every delta.

## Lifecycle

```text
created -> running -> paused -> running -> completed
               \                    /
                -> derived campaign
```

`CampaignState` is `Created`, `Running`, `Paused`, `Completed`, or `Sealed`.
`CampaignControlAction` is `Resume`, `Pause(ActiveAttemptPolicy)`, `Complete`,
`Seal`, `Unseal`, or `ActivatePolicy`. The active-attempt policy is `Drain`,
`ExactCheckpoint`, or `CancelAndRetry`; it is retained from the authoritative
pause transition until `resume` or `complete` clears it, so a daemon derives
both state and pause behavior from one authenticated snapshot.

- Pause and restart require nothing outside the snapshot and its reachable
  objects. In-flight attempts without published observations become claimable
  again.
- Steering publishes a new policy and activation fact; it never rewrites prior
  proposals, observations, or findings.
- Deriving from an older snapshot creates a new reference that shares all
  reachable objects without copying them.
- Additional budget or a policy revision may reopen a completed campaign unless
  it is sealed.
