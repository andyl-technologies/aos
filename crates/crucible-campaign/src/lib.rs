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
mod choice;
mod codec;
mod exploration;
mod identity;
mod merkle;
mod model;
mod object;
mod policy;
mod repository;

pub use artifact::{ConfigurationArtifact, ScenarioArtifact};
pub use choice::{
    BooleanDomain, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain, ChoiceGroup,
    ChoiceGroupApplication, ChoiceGroupDomain, ChoiceGroupValue, ChoiceOpportunity,
    ChoiceRelationalConstraint, ChoiceSource, ChoiceTuple, ChoiceValue, DiscreteAlternative,
    DiscreteDomain, IntegerDomain, IntegerRepresentation, IntegerValue, ModelSampleEvidence,
    ModelSampleVerifier, SelectableDeclaration, Selection, SelectionOrigin,
};
pub use codec::CampaignCodecError;
pub use exploration::{
    Attempt, AttemptAdmission, AttemptAdmissionRole, AttemptStart, BranchBudget, BranchPath,
    BranchRequest, BranchRequestCause, CandidateSource, ContinuationState, ExpansionState,
    ExpansionStatistics, FeedbackWait, FiniteCandidateSource, GuidanceEvidence, PlannerStep,
    PlanningAccounting, Proposal, StopCondition,
};
pub use identity::{
    AlternativeId, AttemptAdmissionId, AttemptId, BranchEdgeId, BranchPathId, BranchPointId,
    BranchRequestId, CampaignCommandId, CampaignFactId, CampaignHash, CampaignLineageId,
    CampaignPolicyId, CampaignSnapshotId, CampaignViewId, CandidateGeneratorSpecId, ChoiceClassId,
    ChoiceDomainId, ChoiceDomainSemanticId, ChoiceGroupId, ChoiceOpportunityId,
    ChoiceOpportunitySemanticId, ChoiceRngStreamId, ConfigurationArtifactId, ConfigurationId,
    CoverageProjectionId, CreditId, DebugSessionId, ExpansionStateId, FindingId, MeasurementSetId,
    ObservationId, PlannerEngineId, PlannerInvocationId, PlannerStateId, PlannerStepId,
    PolicyArtifactId, ProbabilityModelId, PropertyVerdictSetId, ProposalId, ScenarioArtifactId,
    ScenarioDefId, SelectableId, SelectableSemanticId, SelectionId,
};
pub use merkle::{CampaignStoreError, MerkleMap, MerkleMapPage, MerkleMapRoot};
pub use model::{
    ActiveAttemptPolicy, AdmissionOrdinal, BudgetGrant, CampaignControlAction, CampaignFact,
    CampaignLineage, CampaignPlanningView, CampaignRoots, CampaignSnapshot, CampaignState,
    ControlRequest, NonModeledAttemptDisposition, PinChange, PinRetention, PlannerEngine,
    PlannerInvocation, PlannerState, PlanningBudget, PolicyActivation, PolicyArtifact,
};
pub use object::{CampaignRecordKind, ChildReference, ObjectEnvelope};
pub use policy::{
    CampaignMode, CampaignPolicy, CampaignSeed, CandidateGeneratorAlgorithm,
    CandidateGeneratorSpec, ChoicePolicy, ExactRational, ExplorerPolicy, FairnessPolicy,
    GuidanceWeight, Objective, ObjectiveGoal, ProgressiveWideningPolicy, PuctPolicy,
    RetentionPolicy, WeightedGenerator,
};
pub use repository::{
    BranchRequestResult, CampaignCommandResult, CampaignHead, CampaignRepository,
    CampaignRepositoryError, ResolvedSelection,
};

#[cfg(test)]
mod tests;
