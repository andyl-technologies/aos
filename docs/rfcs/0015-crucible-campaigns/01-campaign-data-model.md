# 01 — Campaign data model and lifecycle

The campaign model uses immutable content under one mutable user-visible ref.
Its authoritative state is a set of facts and their Merkle projections; mutable
daemon queues and iterator objects are rebuildable indexes.

## 01.1 Identity hierarchy

```text
ScenarioDefId = H(world, plan, properties, measurements, selectables, seed)

ConfigurationId = H(ScenarioDefId, Schedule)

CampaignLineageId = H(
  ScenarioDefId,
  GenesisConfigurationId,
  CrucibleVersion,
  QemuBuildAndPatchSeries,
  ProtocolVersions
)

CampaignPolicyId = H(canonical CampaignPolicy)

CampaignSnapshotId = H(canonical CampaignSnapshot)
```

The human campaign name is not an identity component. It is a mutable reference
such as `network-recovery -> CampaignSnapshotId`.

- **[CMOD-10]** A policy revision MUST NOT change existing configuration IDs.
  Every proposal MUST name the policy revision that issued it.
- **[CMOD-11]** A QEMU, Crucible, guest protocol, shared-memory protocol, scenario
  schema, or exact-closure compatibility change MUST fork a new lineage unless
  the relevant version contract explicitly admits the old representation.

## 01.2 Campaign policy

```rust,illustrative
pub struct CampaignPolicy {
    pub schema_version: u32,
    pub scenario: ScenarioRef,
    pub campaign_seed: Seed,
    pub mode: CampaignMode,
    pub choice_policies: Vec<ChoicePolicy>,
    pub explorer: ExplorerPolicy,
    pub objectives: Vec<Objective>,
    pub guidance: Vec<GuidanceWeight>,
    pub stop_conditions: Vec<NamedStopCondition>,
    pub fairness: FairnessPolicy,
    pub retention: RetentionPolicy,
}

pub enum CampaignMode {
    Strict,
    Streaming,
    Statistical,
}
```

`Strict` records and commits planner inputs in deterministic attempt order so
the campaign proposal sequence can be re-derived. `Streaming` incorporates
completed observations as they arrive and promises branch/finding
reproducibility rather than arrival-order-independent campaign evolution.
`Statistical` enforces the sampling and weighting restrictions in §03.8.

Resource placement is not policy. Worker count, memory limits, CPU affinity,
host names, store endpoint, and cache inventory are daemon configuration.
Budgets are immutable grants recorded in campaign accounting so a long-lived
campaign can receive more work without changing its original identity.

## 01.3 Campaign snapshot

```rust,illustrative
pub struct CampaignSnapshot {
    pub schema_version: u32,
    pub parents: Vec<CampaignSnapshotId>,
    pub lineage: CampaignLineageId,
    pub active_policy: CampaignPolicyId,
    pub graph_root: ContentHash,
    pub exploration_root: ContentHash,
    pub observations_root: ContentHash,
    pub corpus_root: ContentHash,
    pub coverage_root: ContentHash,
    pub findings_root: ContentHash,
    pub pins_root: ContentHash,
    pub accounting_root: ContentHash,
}
```

The roots name immutable canonical maps or sets:

| Root | Contents |
| --- | --- |
| `graph_root` | Configurations, schedule edges, choice-point locations, and graph metadata. |
| `exploration_root` | Proposal and planner-step facts, generator specifications, and derived continuation snapshots. |
| `observations_root` | Attempt results, measurements, properties, coverage projections, and causal evidence. |
| `corpus_root` | Retained configurations and reproduction artifacts worth further mutation. |
| `coverage_root` | Grow-only union of canonical coverage identities. |
| `findings_root` | Failure signatures, clusters, minimization products, and reproduction artifacts. |
| `pins_root` | User and policy retention decisions for configurations and exact closures. |
| `accounting_root` | Budget grants, consumed attempts, modeled completion counts, policy activation, pause/resume, and operator commands. |

- **[CMOD-12]** Every snapshot root MUST name an immutable object whose children
  are discoverable without listing the backing store.
- **[CMOD-13]** Advancing a campaign name MUST be a compare-and-swap from one
  snapshot ID to another. Objects MUST be published and authenticated before the
  ref is advanced.
- **[CMOD-14]** A snapshot MUST be readable without any daemon-local queue,
  lease, PID, socket, hot-fork handle, or filesystem path.

## 01.4 Campaign facts

```rust,illustrative
pub enum CampaignFact {
    ChoiceDiscovered(ChoicePoint),
    PlannerAdvanced(PlannerStep),
    ProposalIssued(Proposal),
    ObservationPublished(Observation),
    FindingPublished(Finding),
    PolicyActivated(PolicyActivation),
    BudgetGranted(BudgetGrant),
    ControlRequested(ControlRequest),
    PinChanged(PinChange),
}
```

Facts are immutable and carry causal references. They may be represented in
persistent Merkle maps rather than replayed from a flat log. A projection cache
may summarize them, but the facts remain sufficient to rebuild it.

`PlannerStep` makes adaptation explicit:

```rust,illustrative
pub struct PlannerStep {
    pub parent: Option<PlannerStepId>,
    pub policy: CampaignPolicyId,
    pub observation_basis: ContentHash,
    pub selected_expansion: ExpansionKey,
    pub issued_proposals: Vec<ProposalId>,
    pub score_evidence: GuidanceEvidence,
}
```

- **[CMOD-15]** Every adaptive proposal MUST be reachable from a planner step
  that names the exact observation root and policy used to produce it.
- **[CMOD-16]** Rebuilding projections from the same facts MUST produce the same
  canonical frontier, statistics, and reports. Projection caches that disagree
  are corrupt and MUST be rejected.

## 01.5 Expansion, proposal, attempt, and observation

```rust,illustrative
pub struct ExpansionKey {
    pub parent: ConfigurationId,
    pub choice_point: ChoicePointId,
}

pub struct Proposal {
    pub expansion: ExpansionKey,
    pub domain: ChoiceDomainId,
    pub value: ChoiceValue,
    pub policy: CampaignPolicyId,
    pub ordinal: u64,
    pub guidance_basis: ContentHash,
}

pub struct Attempt {
    pub proposal: ProposalId,
    pub parent: ConfigurationId,
    pub selection: Selection,
    pub stop: StopCondition,
}

pub struct Observation {
    pub attempt: AttemptId,
    pub child: ConfigurationId,
    pub path: Vec<SelectionId>,
    pub stop: StopOutcome,
    pub measurements: MeasurementSetId,
    pub properties: PropertyVerdictSetId,
    pub coverage: CoverageProjectionId,
    pub discovered_choices: Vec<ChoicePointId>,
}
```

`AttemptId` is a digest of semantic attempt inputs. Lease owner, retry number,
start time, and preferred materialization are excluded. A repeated attempt may
produce identical bytes and deduplicate. If it does not, the replay oracle
localizes a determinism defect.

- **[CMOD-17]** A proposal MUST validate its value against the named domain
  before an attempt can be admitted.
- **[CMOD-18]** A temporal-graph child MUST NOT be created merely because a
  proposal exists. It is admitted after execution produces and authenticates the
  child configuration.
- **[CMOD-19]** Modeled timeout, crash, assertion failure, and successful stop
  are observation outcomes. Worker loss, daemon restart, lease expiry, and store
  unavailability are operational outcomes and MUST NOT be assigned modeled
  reward.

## 01.6 Derived continuation state

For one `ExpansionKey`, the projection computes:

```rust,illustrative
pub struct ExpansionContinuation {
    pub expansion: ExpansionKey,
    pub generator: CandidateGeneratorId,
    pub proposals: ContentHash,
    pub observations: ContentHash,
    pub statistics: ExpansionStatistics,
    pub state: ContinuationState,
}

pub enum ContinuationState {
    Ready,
    WaitingForFeedback { completed_visits: u64, required_visits: u64 },
    Open,
    Exhausted,
    Closed,
}
```

This object may be cached, but it is derived from the policy, choice point,
proposals, and observations. A static generator's next cursor is the first
unissued ordinal. An adaptive generator additionally derives its interval tree,
per-arm rewards, and widening eligibility from observations.

## 01.7 Lifecycle

A campaign lifecycle is user intent over durable state, not the lifetime of a
daemon process:

```text
created -> running -> paused -> running -> quiescent/completed
               \                    /
                -> forked lineage --
```

`pause` stops new attempt issuance and chooses a declared active-attempt policy:
drain, exact-checkpoint, or cancel-and-retry. `resume` reconstructs projections
from the head and resumes pulling work. `complete` means a user stop condition,
budget condition, or genuine finite exhaustion has been recorded. Additional
budget or a policy revision may reopen a completed campaign unless the operator
sealed it.

- **[CMOD-20]** Pause and daemon restart MUST require no state outside the
  campaign snapshot and reachable objects. In-flight attempts without published
  observations become claimable again.
- **[CMOD-21]** Steering future exploration MUST publish a new policy object and
  activation fact. It MUST NOT rewrite prior proposals, observations, or
  findings.
- **[CMOD-22]** Forking a campaign from an older snapshot creates a new named ref
  sharing all immutable reachable objects. It MUST NOT copy the object closure.
