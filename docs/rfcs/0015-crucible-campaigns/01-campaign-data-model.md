# 01 — Campaign data model and lifecycle

The campaign model uses immutable content under one mutable user-visible ref.
Its authoritative state is a set of facts and their Merkle projections; mutable
daemon queues and iterator objects are rebuildable indexes.

## 01.1 Identity hierarchy

Every stored campaign record has exactly one identity: a record-specific typed
wrapper around the generic `ContentId` of its complete canonical content
envelope. There is no second logical hash that can disagree with the storage
identity. The formulas below describe the semantic fields encoded in each
record body; the actual hash input also contains the envelope version, schema
name and version, exact sorted child-reference table, and body framing defined
in §06.1.

```text
ScenarioDefId = H(world, plan, properties, measurements, selectables, seed)

ConfigurationId = H(ScenarioDefId, Schedule)

CampaignLineageId = H(
  ScenarioDefId,
  ScenarioArtifactId,
  GenesisConfigurationId,
  ConfigurationArtifactId,
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
  PlanningScanPage,
  PlanningBudget
)
```

`CampaignHash` and semantic wrappers such as `ConfigurationId`,
`BranchPointId`, and `BranchEdgeId` identify values derived from other
canonical records. They are not independently stored record identities. Stored
objects such as policies, snapshots, facts, choice domains, opportunities,
selections, planner artifacts, and Merkle nodes use typed `ContentId` wrappers.
Presentation-independent choice-domain semantics have a separate explicitly
named `ChoiceDomainSemanticId`; selectable declarations and runtime
opportunities similarly expose `SelectableSemanticId` and
`ChoiceOpportunitySemanticId`. Their stored `*Id` values remain exact typed
`ContentId` wrappers and therefore cover presentation metadata too. Semantic
branch-point and edge derivation uses the explicitly named semantic IDs, while
storage closure and provenance retain the exact IDs.

The public textual and canonical-binary form of a stored-record ID includes its
exact registered schema tag as well as the generic `ContentId`. A policy-family
content ID cannot therefore be parsed or decoded as a planner-state,
planner-engine, or candidate-generator ID merely because those records share an
`ObjectKind`. The underlying generic content ID becomes authoritative only
after the named envelope is loaded and authenticated as the claimed record
schema.

The normative owner, version, object-kind domain, and compatibility gates for
every format introduced here are frozen in
[`schema-registry.tsv`](schema-registry.tsv). Adding or changing a format
requires updating that registry and its executable completeness check.

The human campaign name is not an identity component. It is a mutable reference
such as `network-recovery -> CampaignSnapshotId`.

`CampaignLineage` carries both semantic scenario/genesis identities and exact
typed content references to owned `ScenarioArtifact` and
`ConfigurationArtifact` records. The scenario record binds its semantic
`ScenarioDefId` and execution-model schema to the exact canonical payload. The
configuration record binds its semantic `ConfigurationId`, its
`ScenarioDefId`, and the exact `ScenarioArtifactId` to its canonical payload.
Repository reads resolve these records and recheck every cross-record binding;
validation is not limited to the campaign-creation path.

Campaign creation inserts the exact genesis configuration artifact into the
canonical graph and corpus keys, publishes any candidate-generator closure,
and verifies the complete snapshot closure before advancing the name. A
semantic digest without the corresponding reachable bytes is not a readable
campaign. Raw pre-RFC scenario/configuration blobs require explicit migration
into these owned records before import; they are never guessed to be either a
legacy blob or a record based on their bytes.

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
    pub graph_root: ContentId,
    pub exploration_root: ContentId,
    pub observations_root: ContentId,
    pub corpus_root: ContentId,
    pub coverage_root: ContentId,
    pub findings_root: ContentId,
    pub pins_root: ContentId,
    pub accounting_root: ContentId,
    pub coordination_root: ContentId,
    pub transition: Option<CampaignFactId>,
}
```

Snapshot ancestry for one campaign ref is linear in this RFC because exactly
one coordinator owns that ref. `derive` creates another named ref at an existing
snapshot; it does not create a multi-parent merge commit. Immutable facts may be
shared by any number of refs without giving more than one writer authority over
any ref. A non-genesis snapshot names exactly one `transition` fact that caused
the parent-to-child change; a genesis snapshot has neither parent nor
transition. This direct edge makes lifecycle history independently auditable
without inferring causality from changed projection roots.

Reading a snapshot replays its transition contract, rather than merely checking
that all named objects exist. Each successor preserves lineage, changes only
the roots permitted by its typed transition, proves its active-policy delta,
and reconstructs the exact affected Merkle entries. Lifecycle actions are then
folded from genesis in forward order. Genesis has canonical empty roots outside
the graph/corpus, and those two roots contain exactly the lineage's typed
genesis configuration at their canonical keys. A transition family whose owner
codec and replay projection are not implemented fails closed on import.

The roots name immutable canonical maps or sets:

| Root | Contents |
| --- | --- |
| `graph_root` | Configurations, branch points, schedule edges, and graph metadata. |
| `exploration_root` | Branch requests, proposals, and candidate-source specifications. |
| `observations_root` | Attempt results, measurements, properties, coverage projections, and causal evidence. |
| `corpus_root` | Retained configurations and reproduction artifacts worth further mutation. |
| `coverage_root` | Grow-only union of canonical coverage identities. |
| `findings_root` | Failure signatures, clusters, minimization products, and reproduction artifacts. |
| `pins_root` | User and policy retention decisions for configurations and exact closures. |
| `accounting_root` | Budget grants, consumed attempts, modeled completion counts, policy activation, pause/resume, and operator commands. |
| `coordination_root` | Durable coordinator progress, planner-step identity/replay indexes, and other authenticated control-plane state excluded from semantic planner input. |

The nine-root layout is `crucible.campaign.snapshot` schema v2. Schema-v1
snapshot bodies and envelopes are rejected rather than reinterpreted with a
different root order. `coordination_root` exists so recording a paginated
planner step does not change the immutable planning view that the next page
must resume.

Expansion-state, frontier, statistics, and status objects are rebuildable
projections over these authoritative roots. A snapshot may name an optional
authenticated projection cache through non-authoritative acceleration metadata,
but deleting every such cache cannot make the snapshot unreadable or alter its
semantic value.

- **[CMOD-12]** Every snapshot root MUST name an immutable object whose children
  are discoverable without listing the backing store.
- **[CMOD-13]** Advancing a campaign name MUST be a compare-and-swap from one
  snapshot ID to another. Objects MUST be published and authenticated before the
  ref is advanced.
- **[CMOD-14]** A snapshot MUST be readable without any daemon-local queue,
  reservation, PID, socket, hot-fork handle, or filesystem path.

Each canonical object is wrapped in the generic child-bearing envelope from
§06.1. Record-specific constructors derive the child table from the decoded
body and reject missing, extra, duplicated, or wrongly role-tagged references.
Generic storage, transfer, retention, and garbage-collection code can therefore
walk every closure without importing campaign record types, while the campaign
codec remains responsible for the stronger record-specific correspondence.

## 01.4 Campaign facts

```rust,illustrative
pub enum CampaignFact {
    ChoiceOpportunityDiscovered(ChoiceOpportunityId),
    BranchRequestIssued(BranchRequestId),
    PlannerAdvanced(PlannerStepId),
    ProposalIssued(ProposalId),
    AttemptAdmitted(AttemptAdmissionId),
    AttemptClosed {
        attempt: AttemptId,
        ordinal: AdmissionOrdinal,
        disposition: NonModeledAttemptDisposition,
    },
    ObservationPublished(ObservationId),
    FindingPublished(FindingId),
    PolicyActivated(PolicyActivation),
    BudgetGranted(BudgetGrant),
    ControlRequested(ControlRequest),
    PinChanged(PinChange),
}
```

Facts are immutable and carry causal references. They may be represented in
persistent Merkle maps rather than replayed from a flat log. A projection cache
may summarize them, but the facts remain sufficient to rebuild it.

`AttemptClosed` records the admitted attempt, its global ordinal, and an
explicit non-modeled disposition such as accepted operator cancellation,
permanent incompatibility, invalid input, or authorization refusal. Retriable
operational failure does not close an ordinal. This is the only non-observation
path that can close strict ordering, and it cannot be interpreted as a modeled
timeout, crash, or assertion result.

`PlannerStep` makes adaptation explicit:

```rust,illustrative
pub struct CampaignPlanningView {
    pub graph_root: ContentId,
    pub exploration_root: ContentId,
    pub observations_root: ContentId,
    pub corpus_root: ContentId,
    pub coverage_root: ContentId,
    pub findings_root: ContentId,
    pub accounting_root: ContentId,
}
```

The planning view contains every canonical input permitted to affect proposal
order. It deliberately excludes pins, coordinator bookkeeping, physical
retention, materializations, store placement, and operational state. A policy
that uses finding retention or debugging state must first model the relevant
semantic fact in one of the included roots; it cannot observe a physical pin or
coordination index implicitly.

```rust,illustrative
pub struct PlannerInvocation {
    pub engine: PlannerEngineId,
    pub policy_artifact: PolicyArtifactId,
    pub policy: CampaignPolicyId,
    pub planner_state: PlannerStateId,
    pub input_view: CampaignViewId,
    pub scan_page: PlanningScanPage,
    pub budget: PlanningBudget,
}

pub struct PlanningScanPage {
    pub after: Option<PlanningScanPosition>,
    pub limit: u32,
    pub positions: Vec<PlanningScanPosition>,
    pub complete: bool,
    pub input_bytes: u64,
}

pub struct PlannerStep {
    pub parent: Option<PlannerStepId>,
    pub invocation: PlannerInvocationId,
    pub policy: CampaignPolicyId,
    pub engine: PlannerEngineId,
    pub policy_artifact: PolicyArtifactId,
    pub input_view: CampaignViewId,
    pub disposition: PlannerDisposition,
    pub next_state: PlannerStateId,
    pub usage_claim: PlanningUsage,
    pub coordinator_accounting: PlanningAccounting,
    pub score_evidence: GuidanceEvidence,
}

pub enum PlannerDisposition {
    ContinueScan { cursor: PlanningScanCursor },
    Issue {
        selected: PlanningScanPosition,
        issued_branch_requests: Vec<BranchRequestId>,
        issued_proposals: Vec<ProposalId>,
    },
    NoWork,
}

pub struct PlanningAccounting {
    pub branch_requests: u64,
    pub proposals: u64,
    pub attempts: u64,
    pub deduplicated: u64,
    pub input_objects: u64,
    pub input_bytes: u64,
    pub fuel: u64,
}
```

`PlannerInvocation` schema v2 binds the exact coordinator-served continuation
page. Positions are strictly increasing after the authenticated `after`
position and name canonical branch-request bodies in `input_view`. A
non-complete page contains exactly `limit` positions; `complete` is true only
when owner recomputation reaches EOF. `input_objects` is the position count and
`input_bytes` is the checked sum of canonical served request-body bytes. Schema
v1 invocations are rejected rather than interpreted as having an implicit page.

`input_view` is the complete immutable semantic pre-step basis. Naming only the
observation root is insufficient because fairness, prior proposals, stop
conditions, and budget consumption can all affect the next proposal. Naming the
whole snapshot would be too broad because a storage-tier or pin change must not
perturb strict proposal order. The post-step snapshot includes the accepted
planner step, preserving an acyclic history. `ContinueScan` is bound to the
same immutable `input_view` and emits no semantic outputs; `NoWork` likewise
records a completed scan without inventing a selected source. `Issue` alone
names a selected continuation and accepted output IDs. Output IDs are unique,
`attempts + deduplicated == proposals`, and the branch-request/proposal counts
match the accepted lists. Accounting is recomputed by the coordinator from
accepted outputs and measured bounded input execution; a planner's retained
`usage_claim` is diagnostic only. The coordinator records planner-step,
invocation-result, and current-head indexes as one exact `coordination_root`
delta. This complete disposition/claim/accounting layout is registered as
`crucible.campaign.planner-step` schema v3; v1 and v2 envelopes are rejected
rather than reinterpreted under the new field order.

`ContinueScan` is accepted only for a non-complete served page and its cursor
must equal that page's last position. `NoWork` is accepted only for a complete
page. A first scan, or a scan after the semantic view changes, starts at
`None`; a same-view page after `ContinueScan` starts at exactly the prior
accepted cursor. A same-view `NoWork` closes that scan and cannot be reopened.
The coordinator derives this start from the authenticated planner head and
recomputes the entire page from the named view at acceptance and on
imported-snapshot validation; therefore a result cannot skip an authoritative
key, invent EOF, or substitute different input accounting.

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
    pub parent: ConfigurationArtifactId,
    pub opportunity: ChoiceOpportunityId,
    pub domain: ChoiceDomainId,
    pub source: CandidateSource,
    pub cause: BranchRequestCause,
    pub budget: BranchBudget,
    pub stop: StopCondition,
}

pub enum CandidateSource {
    Finite(FiniteCandidateSource),
    Generated(CandidateGeneratorSpecId),
}

pub struct FiniteCandidateSource {
    // Private; constructed only through a nonempty, bounded validator.
    values: CanonicalSet<ChoiceValue>,
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
    pub domain: ChoiceDomainSemanticId,
    pub value: ChoiceValue,
}

pub struct Attempt {
    pub start: AttemptStart,
    pub path: BranchPathId,
    pub stop: StopCondition,
}

pub enum AttemptStart {
    Discover {
        configuration: ConfigurationArtifactId,
    },
    Branch {
        edge: BranchEdgeId,
        parent: ConfigurationArtifactId,
        selection: SelectionId,
    },
}

pub struct BranchPath {
    pub edges: Vec<BranchEdgeId>,
}

pub struct AttemptAdmission {
    pub attempt: AttemptId,
    pub role: AttemptAdmissionRole,
}

pub enum AttemptAdmissionRole {
    ExecutionBasis {
        proposal: Option<ProposalId>,
        cause: BranchRequestCause,
        admission_ordinal: AdmissionOrdinal,
    },
    AdditionalCause {
        proposal: ProposalId,
    },
}

pub struct Observation {
    pub attempt: AttemptId,
    pub child: ConfigurationId,
    pub path: BranchPathId,
    pub stop: StopOutcome,
    pub measurements: MeasurementSetId,
    pub properties: PropertyVerdictSetId,
    pub coverage: CoverageProjectionId,
    pub discovered_choices: Vec<ChoiceOpportunityId>,
}
```

`BranchPointId` is the semantic digest of `(parent configuration identity,
opportunity semantics)`. A branch request additionally carries exact parent,
opportunity, and effective-domain object IDs so closure validation can prove
that semantic identity before publication. `BranchEdgeId` is the digest of the
canonical edge using `ChoiceDomainSemanticId`, so presentation-only domain
changes do not split a semantic branch. The completed observation binds that edge
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

`AttemptStart::Discover` is the bootstrap form. It realizes a configuration
until the next pending choice or terminal outcome without pretending a choice
edge already exists. `AttemptStart::Branch` resumes a known parent opportunity
and applies exactly one recorded selection. A discovery basis has no proposal
but still records its command or policy cause and global `AdmissionOrdinal`.
The ordinal belongs to campaign accounting, not `AttemptId`; strict projection
uses it to fold completions in a stable order. `BranchPathId` authenticates the
ordered edge path used for guidance backpropagation. It is never reconstructed
by choosing an arbitrary parent from a graph with shared descendants.

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
    pub source_snapshot: CampaignSnapshotId,
    pub input_view: CampaignViewId,
    pub branch_point: BranchPointId,
    pub request_root: ContentId,
    pub proposal_root: ContentId,
    pub admission_root: ContentId,
    pub observation_root: ContentId,
    pub statistics: ExpansionStatistics,
    pub page_after: Option<BranchRequestId>,
    pub page_size: u32,
    pub next_after: Option<BranchRequestId>,
    pub continuations: CanonicalMap<BranchRequestId, ContinuationState>,
}

pub struct FeedbackWait {
    completed_visits: u64,
    required_visits: u64,
}

pub enum ContinuationState {
    Ready,
    WaitingForFeedback(FeedbackWait),
    Open,
    Exhausted,
    Closed,
}
```

`FeedbackWait` is constructed only when `completed_visits < required_visits`;
its fields are private and strict decoding enforces the same invariant. Reaching
the threshold produces `Ready` rather than an already-eligible waiting value.
This changes no canonical wire bytes.

Schema version 2 binds every page to an authenticated campaign snapshot and its
complete planning view. The request, proposal, and admission roots are
homogeneous branch-point projections rebuilt by the owner from the view's
authoritative exploration and accounting roots. They are not caller-selected
subsets. The observation root is the exact view observation root. Schema
version 1 has no compatibility interpretation after admission became a
required derivation input and is rejected at both the record body and envelope
layers.

A finite source's next cursor is the first unissued value in canonical request
order. A proposal without an admission disposition leaves the continuation
`Open`; it does not increase admitted-child statistics. When every issued
proposal has a disposition, another value is `Ready` while proposal budget
remains, the source is `Exhausted` only after every finite value is admitted
or deduplicated, and it is `Closed` when proposal budget ends first. Distinct
`ExecutionBasis` attempts contribute admitted children; `AdditionalCause`
records do not.

A generated source additionally derives its interval tree, per-arm rewards,
and widening eligibility from observations. Adding a finite operator request
does not close, replace, or reset any generated continuation already attached
to the branch point.

The canonical map embedded in one expansion-state page is bounded to the
requested size, which is itself limited to 10,000. Homogeneous request indexes
use the request content digest as their ordering key, so Merkle scan order and
canonical `BranchRequestId` order agree. `page_after` must be authenticated as
a member of the exact request root; a fabricated or cross-branch cursor is
rejected. `next_after` is the last returned request only when another request
exists. Page boundaries are excluded from planning semantics.

Landing a structural canonical codec does not make a derived record admissible.
The repository owner now recomputes finite, observation-empty
`ExpansionState` pages from their source snapshot. Generated requests and
observation-bearing views remain fail-closed until their owners land.
The repository owner now accepts snapshot-bound `ContinueScan` and `NoWork`
planner results, retains the planner claim, independently accounts bounded
inputs and fuel, derives the parent from the authenticated planner-head index,
and validates exact replay and imported-root deltas. `Issue` remains fail-closed
until the coordinator can compose request, proposal, and admission ownership
without introducing a second authority path. This prevents a structurally valid
result from becoming canonical evidence before its semantic owner validator
exists.

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
  `ConfigurationId` and stable `ChoiceOpportunitySemanticId`. Exact
  presentation-bearing opportunity/declaration/domain content IDs, campaign
  policy, request cause, candidate source, and materialization tier MUST NOT
  enter that ID.
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
  `ExecutionBasis` and one globally ordered `AdmissionOrdinal`. Additional
  request causes MUST NOT consume another attempt, change sampling provenance,
  or trigger another execution. Conflicting execution bases or ordinals are a
  campaign-integrity error.
