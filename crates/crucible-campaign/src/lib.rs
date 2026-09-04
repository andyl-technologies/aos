//! Canonical campaign identities, facts, planning state, and component contracts.
//!
//! Campaign state is immutable, content addressed, and independent of executor
//! placement. This module owns the portable semantic vocabulary shared by the
//! coordinator, planner, API, and local executor. Native process handles,
//! QEMU-private state, storage paths, and runtime closures are deliberately not
//! representable here.
//!
//! Spec index: RFC-0019 files 01, 02, 04a, 06, 09.
//!
//! Module map: `artifact`, `choice`, `model`, and `objective` own the portable
//! campaign vocabulary; `campaign_service`, `execution`, and `planner_service`
//! own component contracts; `repository` owns authenticated persistence and
//! transitions; `codec`, `identity`, `object`, and `merkle` own canonical
//! encoding, typed identities, envelopes, and authenticated maps.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod artifact;
mod authority;
mod campaign_service;
mod choice;
mod codec;
mod execution;
mod executor_capability;
mod exploration;
mod finding;
mod identity;
mod merkle;
mod model;
mod object;
mod object_profile;
mod objective;
mod observation;
mod planner_service;
mod policy;
mod repository;

pub use artifact::{ConfigurationArtifact, ScenarioArtifact};
pub use authority::{
    DebuggerAuthorityKey, DebuggerSubmission, PlannerAuthorityKey, PlannerSubmission,
};
pub use campaign_service::{
    ApplyCampaignCommandRequest, ApplyCampaignCommandResponse, CampaignAuthorizationError,
    CampaignChoiceEntry, CampaignChoiceObject, CampaignChoiceObjectKind, CampaignClient,
    CampaignClientError, CampaignFindingObject, CampaignFindingObjectKind, CampaignGraphEntry,
    CampaignListEntry, CampaignName, CampaignPrincipal, CampaignPrincipalAuthorizer,
    CampaignService, CampaignServiceErrorResponse, CampaignServiceFailure,
    CampaignServiceFailureSource, CampaignServiceOperation, CampaignServiceRetryDisposition,
    CreateCampaignRequest, CreateCampaignResponse, DeriveCampaignRequest, DeriveCampaignResponse,
    ExplainCampaignAttemptRequest, ExplainCampaignAttemptResponse, GetCampaignChoiceObjectRequest,
    GetCampaignChoiceObjectResponse, GetCampaignFindingObjectRequest,
    GetCampaignFindingObjectResponse, GetCampaignFrontierObjectRequest,
    GetCampaignFrontierObjectResponse, GetCampaignGraphObjectRequest,
    GetCampaignGraphObjectResponse, GetCampaignPlannerRankingsRequest,
    GetCampaignPlannerRankingsResponse, GetCampaignRequest, GetCampaignResponse,
    GetCampaignSnapshotRequest, GetCampaignSnapshotResponse, ListCampaignsRequest,
    ListCampaignsResponse, MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_LIST_PAGE_ITEMS, MAX_CAMPAIGN_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES, MAX_CREATE_CAMPAIGN_GENERATOR_BYTES,
    MAX_CREATE_CAMPAIGN_GENERATORS, PinCampaignRequest, PinCampaignResponse,
    QueryCampaignChoicesRequest, QueryCampaignChoicesResponse, QueryCampaignFindingsRequest,
    QueryCampaignFindingsResponse, QueryCampaignFrontierRequest, QueryCampaignFrontierResponse,
    QueryCampaignGraphRequest, QueryCampaignGraphResponse, RepositoryCampaignService,
    RepositoryCampaignServiceError, SubmitCampaignBranchRequest, SubmitCampaignBranchResponse,
    WatchCampaignRequest, WatchCampaignResponse,
};
pub use choice::{
    BooleanDomain, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain, ChoiceGroup,
    ChoiceGroupApplication, ChoiceGroupDomain, ChoiceGroupValue, ChoiceOpportunity,
    ChoiceRelationalConstraint, ChoiceSource, ChoiceTuple, ChoiceValue, DiscreteAlternative,
    DiscreteDomain, IntegerDomain, IntegerRepresentation, IntegerValue, ModelSampleEvidence,
    ModelSampleVerifier, SelectableDeclaration, Selection, SelectionOrigin,
};
pub use codec::CampaignCodecError;
pub use execution::{
    AssignmentId, AttemptResourceLimits, CancelAttemptExecutionDisposition,
    CancelAttemptExecutionRequest, CancelAttemptExecutionResponse,
    CheckpointAttemptExecutionDisposition, CheckpointAttemptExecutionRequest,
    CheckpointAttemptExecutionResponse, DaemonEpoch, ExecutionId, ExecutionRetentionIntent,
    ExecutorClient, ExecutorClientError, ExecutorCompatibilityProfile, ExecutorControlService,
    ExecutorRejection, ExecutorResumeService, ExecutorService, ExecutorStatusService,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
    MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES, ResumeAttemptExecutionDisposition,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, SubmitAttemptDisposition,
    SubmitAttemptRequest, SubmitAttemptResponse, attempt_execution_basis_digest,
};
pub use executor_capability::{
    DescribeExecutorRequest, ExecutorCapabilityService, ExecutorCapabilitySet,
    ExecutorCapacityReport, ExecutorDescription, ExecutorMaterializationCapability,
    ExecutorMaterializationLocality, WatchExecutorCapacityRequest,
};
pub use exploration::{
    Attempt, AttemptAdmission, AttemptAdmissionRole, AttemptStart, BranchBudget,
    BranchEdgeVisitStatistics, BranchPath, BranchPathSegment, BranchPuctProjection, BranchRequest,
    BranchRequestCause, CandidateSource, ContinuationProjection, ContinuationState,
    ExpansionCredit, ExpansionState, ExpansionStatistics, FeedbackWait, FiniteCandidateSource,
    GUIDANCE_MICROS_PER_UNIT, GuidanceEvidence, MAX_BRANCH_EDGE_VISIT_PROJECTION_BYTES,
    MAX_BRANCH_EDGE_VISIT_PROJECTION_CREDITS, MAX_BRANCH_FINDING_OCCURRENCE_VISITS,
    MAX_BRANCH_FINDING_PROJECTION_BYTES, MAX_BRANCH_FINDING_ROOT_ENTRIES,
    MAX_BRANCH_NOVELTY_IDENTITIES, MAX_BRANCH_NOVELTY_IDENTITY_VISITS,
    MAX_BRANCH_NOVELTY_OBSERVATIONS, MAX_BRANCH_NOVELTY_PROJECTION_BYTES,
    MAX_BRANCH_NOVELTY_ROOT_ENTRIES, MAX_BRANCH_OBJECTIVE_EVALUATIONS,
    MAX_BRANCH_OBJECTIVE_PROJECTION_BYTES, MAX_BRANCH_PRIOR_NORMALIZATION_VISITS,
    MAX_PLANNER_GUIDANCE_DOMAIN_BYTES, PlannerCandidateGuidance, PlannerDisposition,
    PlannerProposalDisposition, PlannerStep, PlannerStepProposal, PlanningAccounting,
    PlanningScanCursor, PlanningScanPage, PlanningScanPosition, PlanningUsage,
    ProgressiveWideningDecision, Proposal, PuctEdgeStatistics, PuctScore, StopCondition,
};
pub use finding::{
    Finding, FindingExactPins, FindingKind, FindingMinimizationAttempt,
    FindingMinimizationEvidence, FindingOccurrenceSet, FindingSignature, FindingTarget,
    GUIDANCE_SIGNAL_FINDING_DIVERGENCE, GUIDANCE_SIGNAL_FINDING_PROPERTY_VIOLATION,
    GUIDANCE_SIGNAL_FINDING_TIMEOUT, MAX_FINDING_CAUSAL_EVIDENCE, MAX_FINDING_EXACT_PINS,
    MAX_FINDING_MINIMIZATION_ATTEMPTS, MAX_FINDING_MINIMIZATION_POLICY_BYTES,
    MAX_FINDING_OCCURRENCES, ReproductionArtifact,
};
pub use identity::{
    AlternativeId, AttemptAdmissionId, AttemptId, BranchEdgeId, BranchPathId, BranchPointId,
    BranchRequestId, CampaignCommandId, CampaignFactId, CampaignHash, CampaignLineageId,
    CampaignPolicyId, CampaignSnapshotId, CampaignViewId, CandidateGeneratorSpecId, ChoiceClassId,
    ChoiceDomainId, ChoiceDomainSemanticId, ChoiceGroupId, ChoiceOpportunityId,
    ChoiceOpportunitySemanticId, ChoiceRngStreamId, ConfigurationArtifactId, ConfigurationId,
    ContinuationProjectionId, CoverageProjectionId, CreditId, DebugSessionId, ExactCheckpointId,
    ExpansionStateId, FindingId, MeasurementSetId, ObjectiveEvaluationId, ObservationId,
    PlannerCandidateGuidanceId, PlannerEngineId, PlannerInvocationId, PlannerStateId,
    PlannerStepId, PolicyArtifactId, ProbabilityModelId, PropertyVerdictSetId, ProposalId,
    RankingExplanationId, ReproductionArtifactId, RetainedPlannerRequestId, ScenarioArtifactId,
    ScenarioDefId, SelectableId, SelectableSemanticId, SelectionId, SurvivorSelectionId,
};
pub use merkle::{
    CampaignStoreError, MAX_PROVEN_PAGE_ITEMS, MerkleMap, MerkleMapLookupProof, MerkleMapPage,
    MerkleMapPageProof, MerkleMapRoot,
};
pub use model::{
    ActiveAttemptPolicy, AdmissionOrdinal, BudgetGrant, CampaignControlAction, CampaignDerivation,
    CampaignFact, CampaignLineage, CampaignPlanningView, CampaignRoots, CampaignSnapshot,
    CampaignState, ControlRequest, NonModeledAttemptDisposition, PinChange, PinRequest,
    PinRetention, PlannerEngine, PlannerInvocation, PlannerState, PlanningBudget, PolicyActivation,
    PolicyArtifact,
};
pub use object::{CampaignRecordKind, ChildReference, ObjectEnvelope};
pub use object_profile::{CAMPAIGN_OBJECT_PROFILE_POLICY_V1, CampaignObjectProfiler};
pub use objective::{
    FixedReward, MAX_LEXICOGRAPHIC_COMPONENT_VISITS, MAX_PARETO_COMPONENT_VISITS,
    MAX_SURVIVOR_CANDIDATES, MAX_SURVIVOR_EVIDENCE_BYTES, MAX_WEIGHTED_RANKING_BYTE_VISITS,
    ObjectiveComponent, ObjectiveEvaluation, ObjectiveRejection, ObjectiveValue, RankingCandidate,
    RankingDisposition, RankingExplanation, RankingMethod, SurvivorRule, SurvivorSelection,
    SurvivorSelectionBundle, evaluate_objectives, rank_survivors,
};
pub use observation::{
    CoverageProjection, MeasurementEvaluationPayload, MeasurementSeries, MeasurementSet,
    MetricValue, Observation, PropertyEvidence, PropertyVerdict, PropertyVerdictSet, StopOutcome,
};
pub use planner_service::{
    AuthorizedPlannerService, AuthorizedPlannerServiceError, CANONICAL_FRONTIER_OFFERS_CAPABILITY,
    CANONICAL_FRONTIER_PUCT_CAPABILITY, CampaignPlanningBundle, CanonicalFrontierPlanner,
    CanonicalFrontierPlannerBasis, CanonicalPuctPlanner, CanonicalPuctPlannerBasis,
    MAX_PLANNER_COMPONENT_MESSAGE_BYTES, MAX_RETAINED_PLANNER_REQUEST_BUNDLE_OBJECTS,
    MAX_RETAINED_PLANNER_REQUEST_BYTES, PlannerCandidateRanking, PlannerClient, PlannerClientError,
    PlannerEngineOutput, PlannerExecutionSupervisor, PlannerRequest, PlannerResponse,
    PlannerService, PurePlannerEngine, SupervisedPlannerExecution,
};
pub use policy::{
    BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, BOUNDARY_INTEGER_GENERATOR_MAX_LANDMARKS,
    CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION, CORPUS_MUTATION_GENERATOR_MAX_CREDITS,
    CORPUS_MUTATION_GENERATOR_MAX_DISTANCE, CORPUS_MUTATION_GENERATOR_MAX_INPUT_BYTES,
    CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS, CORPUS_MUTATION_GENERATOR_MAX_WORK_ITEMS,
    COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, CampaignMode, CampaignPolicy,
    CampaignSeed, CandidateGeneratorAlgorithm, CandidateGeneratorSpec, ChoicePolicy, ExactRational,
    ExplorerPolicy, FEEDBACK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
    FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, FairnessPolicy, GuidanceWeight,
    LANDMARK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
    LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, LOG_INTEGER_GENERATOR_MAX_CANDIDATES,
    MEASUREMENT_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
    MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
    ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION, ORDERED_MIXTURE_GENERATOR_MAX_CANDIDATES,
    ORDERED_MIXTURE_GENERATOR_MAX_DEPTH, ORDERED_MIXTURE_GENERATOR_MAX_WORK_ITEMS, Objective,
    ObjectiveGoal, PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
    PERMUTED_INTEGER_GENERATOR_MAX_CARDINALITY,
    PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
    PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA, PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS,
    ProgressiveWideningPolicy, PuctPolicy,
    RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, RetentionPolicy,
    STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
    STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, STRATIFIED_INTEGER_GENERATOR_MAX_STRATA,
    WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
    WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES, WeightedGenerator,
};
pub use repository::{
    AttemptAdmissionResult, AttemptQueue, AttemptQueueCursor, AttemptQueueError,
    AttemptReservation, BranchRequestResult, CampaignCommandResult, CampaignDerivationResult,
    CampaignExecutorCancelOutcome, CampaignExecutorCheckpointOutcome, CampaignExecutorDriver,
    CampaignExecutorDriverConfigError, CampaignExecutorDriverError, CampaignExecutorStepOutcome,
    CampaignExecutorStore, CampaignHead, CampaignHeadPage, CampaignLifecycle,
    CampaignPinRetentionRecord, CampaignPinRetentionSummary, CampaignPlannerDriver,
    CampaignPlannerDriverConfigError, CampaignPlannerDriverError, CampaignPlannerStepOutcome,
    CampaignRepository, CampaignRepositoryError, CampaignSupervisor, CampaignSupervisorConfigError,
    CampaignSupervisorError, CampaignSupervisorStepOutcome, ChoiceDiscovery, ChoiceDiscoveryResult,
    ClaimableAttemptPage, FindingPublicationResult, MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS,
    MAX_CAMPAIGN_CLOSURE_OBJECTS, MAX_CAMPAIGN_SUPERVISOR_WORKER_SLOTS,
    MAX_OBSERVATION_CHOICE_DISCOVERIES, MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
    MAX_PLANNER_SCAN_PAGE_ITEMS, NonModeledAttemptResult, ObjectiveEvaluationPublicationResult,
    ObservationCandidate, ObservationDisposition, ObservationResult, PlannerStepResult,
    ProposalResult, ResolvedSelection, WorkerSlotId,
};

#[cfg(test)]
mod tests;
