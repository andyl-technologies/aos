//! Compiles ordered policy inputs into inert, portable candidate plans.
//!
//! The partition performs no live publication or effects. Its dormant journal
//! seam verifies exact ancestry/currentness prerequisites, retains every
//! canonical output and diagnostic, and releases only revalidated postcommit
//! authority for an external controller.

mod advisory;
mod authority;
mod compiler;
mod controller_adapter;
mod deployment_head;
mod model;
mod namespace;
mod protected_journal;
mod protected_owner;
mod public_create_source;
mod resources;

pub use advisory::{
    AdvisoryActionV1, AdvisoryDecisionV1, AdvisoryDegradationV1, AdvisoryKindV1, AdvisoryPlanV1,
    AdvisoryStatusV1, PortableAdvisoryProgramV1,
};
pub use authority::{
    AuthenticatedEndpointCatalogV1, AuthorityPlanV1, EffectiveGrantV1, EndpointCatalogEntryV1,
    EndpointCatalogError, EndpointCatalogVerifierV1, EndpointUseV1,
};
pub use compiler::{PolicyCompilationError, PolicyCompilerV1};
pub use controller_adapter::{
    PolicyCompilerControllerCommitV1, policy_compiler_controller_commit_v1,
};
pub use deployment_head::{
    PolicyDeploymentHeadErrorV1, PolicyDeploymentHeadV1, PolicyDeploymentInputsV1,
    PolicyDeploymentSourcesV1, admit_fixed_policy_deployment_head_v1,
    decode_policy_deployment_sources_v1, verify_policy_deployment_head_v1,
};
pub use model::{
    AdvisoryPlanCommitmentV1, AncestorPolicyCommitmentV1, AncestorPolicyInputV1,
    AuthenticatedCacheDomainV1, AuthenticatedSandboxProjectRelationV1, AuthorityPlanCommitmentV1,
    BackendCapabilitiesV1, CacheDomainBindingV1, CacheDomainInputV1, CacheDomainVerifierV1,
    CandidateAuthorityV1, CompiledPolicyCandidateV1, CompiledPolicyCommitmentV1,
    ExplanationCommitmentV1, ExplanationDecisionV1, ExplanationEntryV1, ExplanationReasonV1,
    ExplanationStageV1, HardResourcePlanCommitmentV1, InputSourceV1,
    MAXIMUM_ADVISORY_RULES_PER_LAYER, MAXIMUM_CANONICAL_OBJECT_BYTES,
    MAXIMUM_EXPLANATION_ENTRIES_PER_STAGE, MAXIMUM_GRANTS_PER_LAYER,
    MAXIMUM_NAMESPACE_RULES_PER_LAYER, MAXIMUM_POLICY_ANCESTORS, MAXIMUM_POLICY_LAYER_BYTES,
    MAXIMUM_POLICY_LAYER_WORK_UNITS, NamespaceBackendFeatureV1, NamespacePlanCommitmentV1,
    NodePolicyCommitmentV1, NodePolicyInputV1, PlanExplanationV1, PolicyCompilerInputV1,
    PolicyCompilerLimitsV1, PolicyLayerV1, PolicyModelError, PortablePolicyOutputV1,
    ProjectPolicyCommitmentV1, ProjectPolicyInputV1, RedactedSubjectV1, RequestPolicyCommitmentV1,
    RequestPolicyInputV1, RevocationInputV1, SandboxProjectRelationVerifierV1,
    SitePolicyCommitmentV1, SitePolicyInputV1, StageExplanationV1,
};
pub use namespace::{
    AuthenticatedExecutableSourceV1, AuthenticatedNamespaceCatalogV1, ExecutableSourceVerifierV1,
    LogicalSourceV1, NamespaceCatalogError, NamespaceCatalogVerifierV1, NamespaceCompositionV1,
    NamespaceDestinationV1, NamespaceExecutionClassV1, NamespaceGraphSchemaV1, NamespaceModelError,
    NamespacePlanV1, NamespacePresentationFeatureV1, NamespaceRuleV1, NamespaceSourceClassV1,
    PortableNamespaceGraphV1, ViewExecutionV1,
};
pub use protected_journal::{
    AppliedPolicyPublicationV1, PolicyCheckpointCommitOutcomeV1, PolicyCheckpointOutcomeUnknownV1,
    PolicyCheckpointRecoveryV1, PolicyCompilerColdObservationV1, PolicyCompilerEffectHandoffV1,
    PolicyCompilerJournalEnvelopeV1, PolicyCompilerJournalErrorV1, PolicyCompilerJournalKeyV1,
    PolicyCompilerJournalProjectionV1, PolicyCompilerJournalRecordKindV1,
    PolicyCompilerJournalSchemaV1, PolicyCompilerJournalSnapshotV1,
    PolicyCompilerPostcommitCapabilityV1, PolicyCompilerProtectedJournalV1,
    PolicyCompilerReplayValidatorV1, PolicyEffectObservationCommitOutcomeV1,
    PolicyEffectObservationOutcomeUnknownV1, PolicyEffectObservationRecoveryV1,
    PolicyPublicationColdRecoveryV1, PolicyPublicationCommitOutcomeV1,
    PolicyPublicationOutcomeUnknownV1, PolicyPublicationPrerequisitesV1,
    PolicyPublicationRecoveryV1, PreparedPolicyCheckpointV1, PreparedPolicyEffectObservationV1,
    PreparedPolicyPublicationV1, normalized_policy_input_digest_v1,
};
pub use protected_owner::{
    PolicyCompilerProtectedCheckpointRecoveryV1, PolicyCompilerProtectedColdOutcomeV1,
    PolicyCompilerProtectedObservationRecoveryV1, PolicyCompilerProtectedOpenReportV1,
    PolicyCompilerProtectedOwnerV1,
};
pub use public_create_source::{
    CurrentCreatePolicySourceErrorV1, CurrentCreateProjectPolicySourceV1,
    current_parentless_create_project_source_v1,
};
pub use resources::{
    BackendEnforcementSetV1, HardEnforcementV1, HardLimitProvenanceV1, HardLimitRequestV1,
    HardLimitValueV1, HardResourceKeyV1, HardResourceModelError, HardResourcePlanV1,
    HardResourceProfileV1, HardResourceScopeV1, PORTABLE_LIMIT_DIMENSIONS, ResolvedHardLimitV1,
    ResolvedHardLimitValueV1, UnlimitedProvenanceV1,
};
