//! Canonical campaign identities, facts, planning state, and component contracts.
//!
//! Campaign state is immutable, content addressed, and independent of executor
//! placement. This module owns the portable semantic vocabulary shared by the
//! coordinator, planner, API, and local executor. Native process handles,
//! QEMU-private state, storage paths, and runtime closures are deliberately not
//! representable here.

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
mod identity;
mod merkle;
mod model;
mod object;
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
    CampaignClientError, CampaignGraphEntry, CampaignName, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignService, CampaignServiceErrorResponse,
    CampaignServiceFailure, CampaignServiceFailureSource, CampaignServiceOperation,
    CampaignServiceRetryDisposition, CreateCampaignRequest, CreateCampaignResponse,
    DeriveCampaignRequest, DeriveCampaignResponse, GetCampaignChoiceObjectRequest,
    GetCampaignChoiceObjectResponse, GetCampaignFrontierObjectRequest,
    GetCampaignFrontierObjectResponse, GetCampaignGraphObjectRequest,
    GetCampaignGraphObjectResponse, GetCampaignRequest, GetCampaignResponse,
    GetCampaignSnapshotRequest, GetCampaignSnapshotResponse, MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES, MAX_CREATE_CAMPAIGN_GENERATOR_BYTES,
    MAX_CREATE_CAMPAIGN_GENERATORS, PinCampaignRequest, PinCampaignResponse,
    QueryCampaignChoicesRequest, QueryCampaignChoicesResponse, QueryCampaignFrontierRequest,
    QueryCampaignFrontierResponse, QueryCampaignGraphRequest, QueryCampaignGraphResponse,
    RepositoryCampaignService, RepositoryCampaignServiceError, SubmitCampaignBranchRequest,
    SubmitCampaignBranchResponse, WatchCampaignRequest, WatchCampaignResponse,
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
    ExecutorRejection, ExecutorService, ExecutorStatusService, GetAttemptExecutionDisposition,
    GetAttemptExecutionRequest, GetAttemptExecutionResponse, MAX_EXECUTOR_COMPONENT_MESSAGE_BYTES,
    SubmitAttemptDisposition, SubmitAttemptRequest, SubmitAttemptResponse,
};
pub use executor_capability::{
    DescribeExecutorRequest, ExecutorCapabilityService, ExecutorCapabilitySet,
    ExecutorCapacityReport, ExecutorDescription, ExecutorMaterializationCapability,
    ExecutorMaterializationLocality, WatchExecutorCapacityRequest,
};
pub use exploration::{
    Attempt, AttemptAdmission, AttemptAdmissionRole, AttemptStart, BranchBudget, BranchPath,
    BranchPathSegment, BranchRequest, BranchRequestCause, CandidateSource, ContinuationProjection,
    ContinuationState, ExpansionCredit, ExpansionState, ExpansionStatistics, FeedbackWait,
    FiniteCandidateSource, GUIDANCE_MICROS_PER_UNIT, GuidanceEvidence, PlannerDisposition,
    PlannerProposalDisposition, PlannerStep, PlannerStepProposal, PlanningAccounting,
    PlanningScanCursor, PlanningScanPage, PlanningScanPosition, PlanningUsage,
    ProgressiveWideningDecision, Proposal, PuctEdgeStatistics, PuctScore, StopCondition,
};
pub use identity::{
    AlternativeId, AttemptAdmissionId, AttemptId, BranchEdgeId, BranchPathId, BranchPointId,
    BranchRequestId, CampaignCommandId, CampaignFactId, CampaignHash, CampaignLineageId,
    CampaignPolicyId, CampaignSnapshotId, CampaignViewId, CandidateGeneratorSpecId, ChoiceClassId,
    ChoiceDomainId, ChoiceDomainSemanticId, ChoiceGroupId, ChoiceOpportunityId,
    ChoiceOpportunitySemanticId, ChoiceRngStreamId, ConfigurationArtifactId, ConfigurationId,
    ContinuationProjectionId, CoverageProjectionId, CreditId, DebugSessionId, ExactCheckpointId,
    ExpansionStateId, FindingId, MeasurementSetId, ObservationId, PlannerEngineId,
    PlannerInvocationId, PlannerStateId, PlannerStepId, PolicyArtifactId, ProbabilityModelId,
    PropertyVerdictSetId, ProposalId, RetainedPlannerRequestId, ScenarioArtifactId, ScenarioDefId,
    SelectableId, SelectableSemanticId, SelectionId,
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
pub use observation::{
    CoverageProjection, MeasurementSeries, MeasurementSet, MetricValue, Observation,
    PropertyEvidence, PropertyVerdict, PropertyVerdictSet, StopOutcome,
};
pub use planner_service::{
    AuthorizedPlannerService, AuthorizedPlannerServiceError, CANONICAL_FRONTIER_OFFERS_CAPABILITY,
    CampaignPlanningBundle, CanonicalFrontierPlanner, MAX_PLANNER_COMPONENT_MESSAGE_BYTES,
    MAX_RETAINED_PLANNER_REQUEST_BUNDLE_OBJECTS, MAX_RETAINED_PLANNER_REQUEST_BYTES, PlannerClient,
    PlannerClientError, PlannerEngineOutput, PlannerExecutionSupervisor, PlannerRequest,
    PlannerResponse, PlannerService, PurePlannerEngine, SupervisedPlannerExecution,
};
pub use policy::{
    BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, BOUNDARY_INTEGER_GENERATOR_MAX_LANDMARKS,
    CampaignMode, CampaignPolicy, CampaignSeed, CandidateGeneratorAlgorithm,
    CandidateGeneratorSpec, ChoicePolicy, ExactRational, ExplorerPolicy, FairnessPolicy,
    GuidanceWeight, LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
    LOG_INTEGER_GENERATOR_MAX_CANDIDATES, ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
    ORDERED_MIXTURE_GENERATOR_MAX_CANDIDATES, ORDERED_MIXTURE_GENERATOR_MAX_DEPTH,
    ORDERED_MIXTURE_GENERATOR_MAX_WORK_ITEMS, Objective, ObjectiveGoal,
    PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION, PERMUTED_INTEGER_GENERATOR_MAX_CARDINALITY,
    PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
    PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA, PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy,
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
    CampaignExecutorStore, CampaignHead, CampaignLifecycle, CampaignPinRetentionRecord,
    CampaignPinRetentionSummary, CampaignPlannerDriver, CampaignPlannerDriverConfigError,
    CampaignPlannerDriverError, CampaignPlannerStepOutcome, CampaignRepository,
    CampaignRepositoryError, CampaignSupervisor, CampaignSupervisorConfigError,
    CampaignSupervisorError, CampaignSupervisorStepOutcome, ChoiceDiscoveryResult,
    ClaimableAttemptPage, MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS, MAX_CAMPAIGN_SUPERVISOR_WORKER_SLOTS,
    MAX_PLANNER_SCAN_PAGE_ITEMS, NonModeledAttemptResult, ObservationCandidate,
    ObservationDisposition, ObservationResult, PlannerStepResult, ProposalResult,
    ResolvedSelection, WorkerSlotId,
};

#[cfg(test)]
mod tests;
