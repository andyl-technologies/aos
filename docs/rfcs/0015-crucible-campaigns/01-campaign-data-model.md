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

CampaignViewId = H(canonical CampaignPlanningView)

PlannerInvocationId = H(
  PlannerEngineId,
  PolicyArtifactId,
  CampaignPolicyId,
  PlannerStateId,
  CampaignViewId,
  PlanningBudget
)
```

The human campaign name is not an identity component. It is a mutable reference
such as `network-recovery -> CampaignSnapshotId`.

- **[CMOD-10]** A policy revision MUST NOT change existing configuration IDs.
  Every proposal MUST name the policy revision that issued it.
- **[CMOD-11]** A QEMU, Crucible, guest protocol, shared-memory protocol, scenario
  schema, or exact-closure compatibility change MUST begin a new lineage unless
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
    pub parent: Option<CampaignSnapshotId>,
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

Snapshot ancestry for one campaign ref is linear in this RFC because exactly
one coordinator owns that ref. `derive` creates another named ref at an existing
snapshot; it does not create a multi-parent merge commit. Immutable facts may be
shared by any number of refs without giving more than one writer authority over
any ref.

The roots name immutable canonical maps or sets:

| Root | Contents |
| --- | --- |
| `graph_root` | Configurations, branch points, schedule edges, and graph metadata. |
| `exploration_root` | Branch requests, proposals, planner-step facts, candidate-source specifications, and derived expansion-state snapshots. |
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
  reservation, PID, socket, hot-fork handle, or filesystem path.

## 01.4 Campaign facts

```rust,illustrative
pub enum CampaignFact {
    ChoiceOpportunityDiscovered(ChoiceOpportunity),
    BranchRequestIssued(BranchRequest),
    PlannerAdvanced(PlannerStep),
    ProposalIssued(Proposal),
    AttemptAdmitted(AttemptAdmission),
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
pub struct CampaignPlanningView {
    pub graph_root: ContentHash,
    pub exploration_root: ContentHash,
    pub observations_root: ContentHash,
    pub corpus_root: ContentHash,
    pub coverage_root: ContentHash,
    pub findings_root: ContentHash,
    pub accounting_root: ContentHash,
}
```

The planning view contains every canonical input permitted to affect proposal
order. It deliberately excludes pins, physical retention, materializations,
store placement, and operational state. A policy that uses finding retention or
debugging state must first model the relevant semantic fact in one of the
included roots; it cannot observe a physical pin implicitly.

```rust,illustrative
pub struct PlannerStep {
    pub parent: Option<PlannerStepId>,
    pub invocation: PlannerInvocationId,
    pub policy: CampaignPolicyId,
    pub engine: PlannerEngineId,
    pub policy_artifact: PolicyArtifactId,
    pub input_view: CampaignViewId,
    pub budget: PlanningBudget,
    pub selected_branch_point: BranchPointId,
    pub selected_source: BranchRequestId,
    pub issued_proposals: Vec<ProposalId>,
    pub coordinator_accounting: PlanningAccounting,
    pub score_evidence: GuidanceEvidence,
}
```

`input_view` is the complete immutable semantic pre-step basis. Naming only the
observation root is insufficient because fairness, prior proposals, stop
conditions, and budget consumption can all affect the next proposal. Naming the
whole snapshot would be too broad because a storage-tier or pin change must not
perturb strict proposal order. The post-step snapshot includes the accepted
planner step, preserving an acyclic history. Accounting is recomputed by the
coordinator from accepted outputs and the input view; a planner's resource-usage
report is diagnostic only.

- **[CMOD-15]** Every adaptive proposal MUST be reachable from a planner step
  that names the complete planning view, engine and policy artifact, policy,
  explicit planning budget, selected candidate source, coordinator-computed
  accounting result, and evidence used to produce it.
- **[CMOD-16]** Rebuilding projections from the same facts MUST produce the same
  canonical frontier, statistics, and reports. Projection caches that disagree
  are corrupt and MUST be rejected.

## 01.5 Branch point, request, proposal, attempt, and observation

```rust,illustrative
pub struct BranchPoint {
    pub id: BranchPointId,
    pub parent: ConfigurationId,
    pub opportunity: ChoiceOpportunityId,
}

pub struct BranchRequest {
    pub branch_point: BranchPointId,
    pub source: CandidateSource,
    pub cause: BranchRequestCause,
    pub budget: BranchBudget,
    pub stop: StopCondition,
}

pub enum CandidateSource {
    Finite {
        values: CanonicalSet<ChoiceValue>,
    },
    Generated {
        generator: CandidateGeneratorSpecId,
    },
}

pub struct BranchBudget {
    pub maximum_proposals: u64,
    pub maximum_attempts: u64,
}

pub enum BranchRequestCause {
    Planner(PlannerInvocationId),
    Operator(CampaignCommandId),
    Debugger(DebugSessionId),
    ExhaustivePolicy(CampaignPolicyId),
}

pub struct Proposal {
    pub branch_point: BranchPointId,
    pub request: BranchRequestId,
    pub domain: ChoiceDomainId,
    pub value: ChoiceValue,
    pub policy: CampaignPolicyId,
    pub planner_invocation: Option<PlannerInvocationId>,
    pub ordinal: u64,
    pub guidance_basis: CampaignViewId,
}

pub struct BranchEdge {
    pub branch_point: BranchPointId,
    pub domain: ChoiceDomainId,
    pub value: ChoiceValue,
}

pub struct Attempt {
    pub edge: BranchEdgeId,
    pub parent: ConfigurationId,
    pub selection: Selection,
    pub stop: StopCondition,
}

pub struct AttemptAdmission {
    pub attempt: AttemptId,
    pub proposal: ProposalId,
    pub role: AttemptAdmissionRole,
}

pub enum AttemptAdmissionRole {
    ExecutionBasis,
    AdditionalCause,
}

pub struct Observation {
    pub attempt: AttemptId,
    pub child: ConfigurationId,
    pub path: Vec<BranchEdgeId>,
    pub stop: StopOutcome,
    pub measurements: MeasurementSetId,
    pub properties: PropertyVerdictSetId,
    pub coverage: CoverageProjectionId,
    pub discovered_choices: Vec<ChoiceOpportunityId>,
}
```

`BranchPointId` is the digest of `(parent, opportunity)`. `BranchEdgeId` is the
digest of the canonical `BranchEdge`. The completed observation binds that edge
to its authenticated child configuration in the temporal graph. Request cause
and proposal provenance are intentionally absent from both identities. If a
policy generator and an operator's finite request both emit the same value, both
proposal facts remain visible but they converge on one branch edge and one
semantic attempt when stop and other execution inputs also match. Requests with
different stop conditions still share the edge but may admit distinct attempts.
This is campaign-knowledge deduplication, not a loss of audit history.

A finite source is bounded by the request even when the selectable's legal
domain is enormous. For example, an operator may request `{0, 20_000, 500_000}`
from an integer domain containing billions of values. A generated source names
a versioned deterministic generator and derives its continuation from facts.
Both sources are consumed lazily under `BranchBudget`; neither creates all
attempts at request publication time.

`maximum_proposals` bounds values emitted by that request, including values that
deduplicate against prior work. `maximum_attempts` bounds new semantic attempts
that request may cause. Attaching a new proposal cause to an already admitted
edge consumes no attempt and never re-executes it merely to satisfy provenance.

Planner cause names policy and observation basis directly rather than the
`PlannerStepId` that records resulting proposals. This keeps the content graph
acyclic while preserving the full causal chain.

`AttemptId` is the digest of the canonical `Attempt` semantic inputs. Executor,
reservation generation, retry number, start time, preferred materialization,
branch request, and
proposal cause are excluded. Separate `AttemptAdmission` facts link every
proposal that justified the attempt. Exactly one `ExecutionBasis` says which
proposal spent the attempt budget and fixes statistical sampling provenance;
later duplicates are `AdditionalCause` and cannot trigger execution or
retroactively change estimator eligibility. A repeated attempt may produce
identical bytes and deduplicate. If it does not, the replay oracle localizes a
determinism defect.

- **[CMOD-17]** A proposal MUST validate its value against the named domain
  before an attempt can be admitted.
- **[CMOD-18]** A temporal-graph child MUST NOT be created merely because a
  proposal exists. It is admitted after execution produces and authenticates the
  child configuration.
- **[CMOD-19]** Modeled timeout, crash, assertion failure, and successful stop
  are observation outcomes. QEMU/executor loss, daemon restart, reservation
  loss, and store
  unavailability are operational outcomes and MUST NOT be assigned modeled
  reward.
## 01.6 Derived continuation state

For one `BranchPointId`, the campaign projects an `ExpansionState`:

```rust,illustrative
pub struct ExpansionState {
    pub branch_point: BranchPointId,
    pub requests: ContentHash,
    pub proposals: ContentHash,
    pub observations: ContentHash,
    pub statistics: ExpansionStatistics,
    pub continuations: MerkleMap<BranchRequestId, ContinuationState>,
}

pub enum ContinuationState {
    Ready,
    WaitingForFeedback { completed_visits: u64, required_visits: u64 },
    Open,
    Exhausted,
    Closed,
}
```

This object may be cached, but it is derived from branch requests, policy,
choice opportunity, proposals, and observations. A finite source's next cursor
is the first unissued value in canonical request order. A generated source
additionally derives its interval tree, per-arm rewards, and widening
eligibility from observations. Adding a finite operator request does not close,
replace, or reset any generated continuation already attached to the branch
point.

## 01.7 Lifecycle

A campaign lifecycle is user intent over durable state, not the lifetime of a
daemon process:

```text
created -> running -> paused -> running -> quiescent/completed
               \                    /
                -> derived campaign --
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
- **[CMOD-22]** Deriving a campaign from an older snapshot or configuration
  creates a new named ref sharing all immutable reachable objects. It MUST NOT
  copy the object closure.
- **[CMOD-23]** `BranchPointId` MUST identify the pair of a parent
  `ConfigurationId` and stable `ChoiceOpportunityId`. Campaign policy, request
  cause, candidate source, and materialization tier MUST NOT enter that ID.
- **[CMOD-24]** The semantic edge for one legal selected value at a branch point
  MUST deduplicate regardless of whether planner, operator, debugger, or
  exhaustive requests proposed it. Every proposal cause remains separately
  auditable as campaign knowledge.
- **[CMOD-25]** Creating semantic alternatives, deriving a named campaign,
  hot-forking a QEMU realization, and mutating a debugger session MUST remain
  distinct operations in canonical schemas, APIs, CLI output, and audit facts.
- **[CMOD-26]** Checkpoint presence and hot-fork eligibility MUST be
  materialization metadata. Neither may create, remove, or change a semantic
  branch point or edge.
- **[CMOD-27]** A finite `CandidateSource` MUST have an explicit cardinality
  bound and validate every value before publication. Publishing a branch
  request MUST NOT eagerly create its proposals, attempts, configurations, or
  QEMU children.
- **[CMOD-28]** Each admitted attempt MUST have exactly one immutable
  `ExecutionBasis`. Additional request causes MUST NOT consume another attempt,
  change sampling provenance, or trigger another execution. Conflicting
  execution bases are a campaign-integrity error.
