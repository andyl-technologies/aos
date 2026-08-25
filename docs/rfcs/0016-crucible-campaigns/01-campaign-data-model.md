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

Finding reproduction uses the same exact-artifact rule. A schema-v1
`ReproductionArtifact` binds semantic and exact scenario/configuration
identities, a stable failure fingerprint, and verifier-checked self-contained
execution-model bytes. Schema v2 is used only for a minimized reproduction and
additionally retains its original schema-v1 reproduction, versioned exact
minimization policy, dense bounded candidate history, and final replayed state.
A schema-v1 `Finding` binds its normalized signature, representative and
occurrence observations, original and optional legacy minimized reproductions,
the authenticated first-seen parent snapshot, and optional untyped exact
checkpoint accelerators. Schema v2 replaces that untyped accelerator set with
bounded pre-failure, last-successful-measurement, post-failure, and additional
role sets and requires every minimized reproduction to carry schema-v2
minimization evidence. A schema-v1 Finding references only schema-v1
reproductions; a schema-v2 Finding retains a schema-v1 original and, when
present, a schema-v2 minimized reproduction whose trace also names that v1
original. Both record families preserve schema-v1 body/envelope
identity on legacy reads. They remain `ObjectKind::Finding` records with
distinct registered schemas; a broad finding content ID is not authoritative
until its envelope schema and complete child table are authenticated.

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
The mode is fixed for one campaign ref because it selects the observation-fold
and reproducibility contract. Steering may activate another policy only with
the same mode; changing mode requires deriving a new campaign.

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
one coordinator owns that ref. `derive` creates another named ref whose first
owned snapshot is an audited successor of the exact source snapshot; it does
not create a multi-parent merge commit or mutate the source ref. Immutable facts may be
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
| `observations_root` | Canonical attempt results, retained determinism conflicts, measurements, properties, coverage projections, paths, and causal evidence. |
| `corpus_root` | Retained configurations and reproduction artifacts worth further mutation. |
| `coverage_root` | Grow-only set of canonical coverage-projection records; their deterministic identity union is derived. |
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
    ChoiceOpportunityDiscovered {
        parent: ConfigurationArtifactId,
        branch_point: BranchPointId,
        opportunity: ChoiceOpportunityId,
    },
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
    ObservationCredited(ObservationId),
    FindingPublished(FindingId),
    ObjectiveEvaluationPublished(ObjectiveEvaluationId),
    PolicyActivated(PolicyActivation),
    BudgetGranted(BudgetGrant),
    ControlRequested(ControlRequest),
    PinChanged(PinChange),
    PinCommandAccepted(PinRequest),
    CampaignDerived(CampaignDerivation),
}
```

Publishing a valid `ChoiceOpportunity` body does not make it campaign
knowledge. The graph owner admits it only through an exact
`ChoiceOpportunityDiscovered` transition or as a discovered choice in a
canonical observation. Both paths authenticate the complete declaration and
domain closure and bind the opportunity to the campaign scenario and exact
parent-derived branch point. A branch request must find the exact opportunity
under its domain-separated `(BranchPointId, ChoiceOpportunityId)` graph key;
backing-store presence, global opportunity membership, an arbitrary Merkle key,
or a caller-supplied subset root is insufficient. Campaign-fact schema v2 made
the explicit discovery parent and branch point part of the fact rather than
reinterpreting the former layout.

`CampaignDerived` names the exact source snapshot and policy active in the new
child. Its successor preserves lineage and every semantic root, changes only
the coordination root by adding the ordinary authenticated parent-result
locator, and sets its parent to that source. A supplied replacement policy must
have the same scenario and campaign mode; policy publication and target-ref
creation are one owner transaction. Exact retries resolve the first derived
snapshot from the target history even after later target mutations. They are
bound to that target's most recent founding derivation edge; a locator inherited
from an ancestor derived campaign cannot replay as the child ref's own result.
Campaign-fact schema v3 adds this transition. Schema v4 adds
`ObservationCredited`, whose owner recomputes both scoped expansion credits and
the child configuration-to-path membership described in §01.6. Schema v5 adds
`PinCommandAccepted(PinRequest)`, which binds the caller's command ID, exact
parent snapshot, configuration, retention tier or removal, and bounded reason
in one owner-validated transition. Schema v6 adds
`ObjectiveEvaluationPublished(ObjectiveEvaluationId)`, which makes one exact
active-policy evaluation of one canonical observation authoritative. Every
variant that predates
`CampaignDerived` continues to encode as schema v2, preserving its canonical
bytes and `CampaignFactId`; only `CampaignDerived` encodes as v3, only
`ObservationCredited` encodes as v4, and only `PinCommandAccepted` encodes as
v5, and only `ObjectiveEvaluationPublished` encodes as v6. Schema-v2 through
schema-v5 fact bodies and envelopes remain canonically readable for existing
history. A body cannot carry a variant introduced by another version, and
body/envelope version mismatches fail closed. Historical schema-v2
`ObservationPublished` successors are
validated against either their original observation-only delta or the interim
credit-bearing delta; new publication always uses the unambiguous schema-v4
owner.

The pin owner resolves command replay before staleness. An exact retry returns
the first accepted parent/child snapshot pair; reuse of the command ID with a
different `PinRequest` fails closed. The configuration must already occur in
the parent's authenticated graph. Acceptance inserts the v5 fact under both
`accounting.command(command_id)` and `pins.configuration(configuration_id)`;
unpinning writes a `retention = None` tombstone at the same pin key rather than
deleting historical intent. Imported and restarted histories recompute these
two exact root deltas and the ordinary parent-result locator.

The objective owner derives
`H("crucible.campaign-objective-evaluation.v1", policy_content_id_text ||
observation_content_id_text)` and maps it to the exact evaluation ID in
`roots.observations`. The policy must be active and the observation must own its
attempt's canonical observation key in the parent snapshot. The owner validates
the evaluation's policy contract, child configuration, property filtering, and
exact scalar recomputation before its first write. The successor changes only
`roots.observations` and the ordinary parent-result coordination locator.
Exact-evaluation replay resolves before staleness after later mutations; a
different evaluation for the same `(policy, observation)` basis fails closed.
Import and restart validation recompute the same key, basis, and two root
deltas.

The language-neutral canonical field order is:

```text
PinRequestV1 = command_id | expected_snapshot | PinChangeV1
PinChangeV1 = configuration_id | optional(thin | exact) |
              nfc_reason_utf8_0_to_4096_bytes
pin_request_digest =
  H("crucible.campaign-pin-request.v1", canonical(PinRequestV1))
```

The optional retention field uses absence for removal. The reason rejects NUL,
non-NFC text, and encoded content beyond 4,096 bytes.

Facts are immutable and carry causal references. They may be represented in
persistent Merkle maps rather than replayed from a flat log. A projection cache
may summarize them, but the facts remain sufficient to rebuild it.

`AttemptClosed` records the admitted attempt, its global ordinal, and an
explicit non-modeled disposition such as accepted operator cancellation,
permanent incompatibility, invalid input, or authorization refusal. Retriable
operational failure does not close an ordinal. This is the only non-observation
path that can close strict ordering, and it cannot be interpreted as a modeled
timeout, crash, or assertion result.
In strict mode both an accepted observation and `AttemptClosed` advance the
same admission-completion sequence owner. Its value is therefore a typed
`Observation` or `AttemptClosed` fact, and the next completion must carry the
immediately following global admission ordinal. Separate per-attempt and
per-ordinal disposition indexes make closure replay and claim filtering
independent of ancestry scans.

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
    pub request: RetainedPlannerRequestId,
    pub request_digest: CampaignHash,
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

pub struct PlannerCandidateGuidance {
    pub input_view: CampaignViewId,
    pub policy: CampaignPolicyId,
    pub position: PlanningScanPosition,
    pub domain: ChoiceDomainId,
    pub domain_semantics: ChoiceDomainSemanticId,
    pub value: ChoiceValue,
    pub ordinal: u64,
    pub edge: BranchEdgeId,
    pub statistics: PuctEdgeStatistics,
    pub novelty_events: u64,
    pub objective_reward_micros: i64,
    pub finding_events: BTreeMap<FindingKind, u64>,
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
delta. Schema v4 additionally commits both a
`crucible.campaign.retained-planner-request` schema-v1 record and the
domain-separated digest of its exact canonical `PlannerRequestV1` body. The
retained record is a distinct Policy-kind envelope whose children name the
stored invocation, direct basis, expected snapshot, and every bundled object;
import validation decodes that record and recomputes the digest. This makes the
by-value interpretation bundle auditable even when two requests share one
`PlannerInvocationId`. Standalone step loading cannot prove the request's
snapshot precondition and therefore requires the exact owning snapshot. The
complete layout is registered as
`crucible.campaign.planner-step` schema v4; v1 through v3 envelopes are rejected
rather than reinterpreted under the new field order. The typed `PlannerStepId`
decoder continues to admit schema-v3 content IDs so an existing
`CampaignFact` schema-v2 `PlannerAdvanced` body remains canonically readable;
dereferencing that legacy ID as a current planner-step record still fails
closed because only a schema-v4 envelope is executable or owner-validatable.

`PlannerCandidateGuidance` is the schema-v2, at-most-64-KiB owner projection
used by canonical frontier engine version 2. Its exact envelope children are
the input view, active policy, served branch request, and exact choice domain.
It repeats the offer tuple plus authenticated semantic edge and decomposed PUCT
statistics so an authority-free planner can validate and score the record using
the request's by-value policy. An accepted retained request stores every
guidance envelope as a child. Local acceptance, restart, and imported-snapshot
validation reconstruct the exact records from the owning snapshot; a
structurally canonical substituted score, semantic domain, reward count, or
offer tuple fails closed.
Schema v2 inserts `objective_reward_micros` after `novelty_events`; it is the
owner-derived signed scalar-objective sum for that edge. Schema-v1 guidance
remains canonically readable and retains its original body, envelope, and
`PlannerCandidateGuidanceId`; owner recomputation preserves v1 when
authenticating historical requests. New requests always carry v2.

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
    pub schema_version: u32, // v2 explicit/uniform or v3 modeled finite
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
    ModeledFinite(ModeledFiniteCandidateSource),
    Generated(CandidateGeneratorSpecId),
}

pub struct FiniteCandidateSource {
    // Private; constructed only through a nonempty, bounded validator.
    values: CanonicalSet<ChoiceValue>,
    // None means implicit weight one for every value.
    prior_weights: Option<CanonicalMap<ChoiceValue, u64>>,
}

pub struct ModeledFiniteCandidateSource {
    // Must equal the referenced opportunity's model_prior.
    model: ProbabilityModelId,
    // Exact positive masses resolved by the execution-model adapter.
    prior_weights: CanonicalMap<ChoiceValue, u64>,
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

pub struct BranchPathSegment {
    pub branch_point: BranchPointId,
    pub edge: BranchEdgeId,
}

pub struct BranchPath {
    pub segments: Vec<BranchPathSegment>,
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
    pub child_content: ConfigurationArtifactId,
    pub path: BranchPathId,
    pub stop: StopOutcome,
    pub measurements: MeasurementSetId,
    pub properties: PropertyVerdictSetId,
    pub coverage: CoverageProjectionId,
    pub discovered_choices: CanonicalSet<ChoiceOpportunityId>,
}
```

`BranchRequest` schema v1 encodes a uniform finite source as candidate-source
tag 0 and a generated source as tag 1. Schema v2 preserves both encodings and
adds tag 2 for an explicitly weighted finite source encoded as a canonical map
from value to positive `u64` raw weight. Schema v3 adds tag 3, followed by one
`ProbabilityModelId` and a canonical value-to-positive-`u64` map, for finite
masses resolved by the execution-model adapter. The modeled ID must equal the
referenced opportunity's `model_prior`; an absent or different model fails
before request publication or import acceptance. Each map is nonempty,
contains at most 4,096 entries, and its keys are exactly the finite value set.
Absolute mass scale is immaterial; the owner normalizes masses only when
constructing exact planner guidance. New uniform, generated, and explicitly
weighted requests retain schema v2 and its established keyed generator
streams; a newly authored modeled finite request uses v3. V1 and v2 request
bodies retain their original content identities. A weighted source is invalid
in v1, and a modeled source is invalid before v3.

`BranchPath` schema version 2 retains each `BranchPointId` beside its
non-invertible `BranchEdgeId`. This lets a restart rebuild observation credit
for every ancestor without an in-memory MCTS stack or a reverse hash lookup.
Version 1 edge-only paths retain their exact body and envelope identity for
historical reads, but new writers always produce version 2. The current
admission owner accepts a legacy path only for a single-edge genesis request.
A version-2 path must end in the exact `(BranchPointId, BranchEdgeId)` selected
by its request. Its prefix is empty for genesis; for a non-genesis parent, the
prefix identity must be a member of that exact parent configuration's
authenticated nested path set in the source snapshot's observation root.
Canonical `ObservationCredited` incorporation adds the observation's complete
path to its exact child configuration set. The nested set retains every path to
a convergent configuration rather than selecting one graph parent. Direct
admission authenticates its caller-supplied prefix. Atomic planner `Issue`
keeps path choice outside the pure planner protocol and deterministically uses
the member with the lowest `BranchPathId` ordering key. That member must be a
scoped version-2 path or planner admission fails closed; imported owner
recomputation derives the same path from the immutable parent snapshot.

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
The semantic child identity and exact child artifact are both present: graph
deduplication uses the former, while closure validation and replay retain the
latter. Measurement, property, coverage, path, and discovered-choice records
are exact children of the observation envelope.
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
ordered branch-point/edge path used for guidance backpropagation. It is never
reconstructed by choosing an arbitrary parent from a graph with shared
descendants.

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

pub struct ExpansionCredit {
    pub observation: ObservationId,
    pub branch_point: BranchPointId,
}

pub struct ExpansionStatistics {
    pub admitted_children: u64,
    pub completed_visits: u64,
    pub reward_sum_micros: i64,
    pub novelty_events: u64,
    pub findings: u64,
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

pub struct ContinuationProjection {
    pub request: BranchRequestId,
    pub branch_point: BranchPointId,
    pub state: ContinuationState,
}
```

`ExpansionCredit` schema version 1 is the idempotent count fact
`CreditId = H("crucible.campaign.expansion-credit.v1",
ObservationId || BranchPointId)`. Its envelope has the canonical observation as
one typed child. Canonical observation publication creates exactly one credit
for each distinct branch point in the authenticated path. Exact replay creates
none, and a determinism-conflict observation creates none. The observation root
maps a domain-separated branch-point anchor to a nested Merkle set whose keys
are `CreditId` and whose values are exact expansion-credit content IDs. This
lets restart and imported-snapshot validation recover visit counts without a
process-local search stack or a repository listing operation.

`ContinuationProjection` schema version 1 is the compact authenticated current
state of one request. New genesis snapshots anchor one canonical empty nested
frontier index under `exploration_root`. Each nested key is the exact
`BranchRequestId` content digest and each value is the content ID of the
corresponding projection. The projection body names its request as a typed
envelope child, so closure traversal retains the authoritative request without
store listing.

The snapshot owner updates the nested index in the same transition that issues
a request, records a proposal, admits a disposition, or accepts an atomic
planner issue. It independently recomputes the exact old and new states during
import and restart validation; a mismatching projection is corrupt. A finite
request starts `Ready`, becomes `Open` while a proposal awaits disposition, and
returns to `Ready` or becomes `Exhausted` or `Closed` from the exact admitted
budget and source state. Generated requests start and remain `Open` at this
checkpoint because deterministic generated-source enumeration and feedback
ownership remain an implementation-plan gate.

Legacy schema-v2 snapshots without the frontier-index anchor remain readable,
but proof-bearing frontier queries fail closed. Ordinary mutations preserve
that unindexed shape and MUST NOT synthesize a partial index; a future migration
must rebuild and authenticate the complete index atomically.

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
The repository owner recomputes static `ExpansionState` pages from their source
snapshot even after modeled observations exist. Static readiness and exhaustion
depend only on exact proposal/admission dispositions, while the page binds the
source view's exact observation root. `completed_visits` is the authenticated
entry count of that branch point's nested credit set. The compact
`ExpansionState` cache keeps reward, novelty, and finding fields neutral; the
separate exact-snapshot PUCT projection owner folds coverage novelty and
policy-weighted finding occurrences without trusting cached values.
History-dependent generated requests remain fail-closed until their feedback
owners land.
The repository owner accepts snapshot-bound `ContinueScan`, `NoWork`, and
finite-source `Issue` results, retains the planner claim, independently accounts
bounded inputs and fuel, derives the parent from the authenticated planner-head
index, and validates exact replay and imported-root deltas. `Issue` atomically
composes the sole-writer request, proposal, deterministic attempt, admission,
accounting, and coordination projections. Generated proposal enumeration and
history-dependent generated proposal enumeration remain fail-closed until their
dedicated owners land. Direct `AdmitProposal` authenticates caller-supplied
cumulative paths, while planner `Issue` derives its canonical cumulative path
from the same owner index. This prevents a structurally valid result from
becoming canonical evidence before its semantic owner validator exists.

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

The lifecycle projection retains the exact active-attempt policy from the
authoritative pause transition. Ordinary sealed snapshots preserve that policy;
only `resume` or `complete` clears it. A daemon therefore derives both the state
and its pause behavior from one authenticated snapshot instead of consulting
process-local intent or re-reading a moving head.

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
- **[CMOD-29]** Policy activation on one campaign ref MUST preserve
  `CampaignMode`. A mode change MUST derive another campaign so existing
  observation ordering cannot be reinterpreted.
- **[CMOD-30]** A choice opportunity MUST become authoritative campaign
  knowledge only through the exact discovery owner or a canonical observation
  owner. Branch-request acceptance MUST require its canonical graph membership
  and MUST NOT infer authority from immutable-object presence alone.
