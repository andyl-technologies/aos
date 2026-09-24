//! Compiles ordered policy inputs into inert, portable candidate plans.
//!
//! The partition performs no live publication or effects. Its dormant journal
//! seam verifies exact ancestry/currentness prerequisites, retains every
//! canonical output and diagnostic, and releases only revalidated postcommit
//! authority for an external controller.

mod advisory;
mod authority;
mod binding_v2;
mod cache_journal_readback;
mod cache_readback_pin;
mod cache_readback_session;
mod compiler;
mod controller_adapter;
mod controller_hold_pin;
mod controller_hold_readback;
mod controller_readback_session;
mod deployment_head;
mod model;
mod namespace;
mod project_source_v2;
mod protected_journal;
mod protected_owner;
mod public_create_source;
mod resources;
mod root_challenge_record;
mod source_hold_readback;

pub use advisory::{
    AdvisoryActionV1, AdvisoryDecisionV1, AdvisoryDegradationV1, AdvisoryKindV1, AdvisoryPlanV1,
    AdvisoryStatusV1, PortableAdvisoryProgramV1,
};
pub use authority::{
    AuthenticatedEndpointCatalogV1, AuthorityPlanV1, EffectiveGrantV1, EndpointCatalogEntryV1,
    EndpointCatalogError, EndpointCatalogVerifierV1, EndpointUseV1,
};
pub use binding_v2::{
    CLOSED_POLICY_BINDING_BYTES_V2, ClosedPolicyRootCacheCutV2, ClosedPolicyRootCasBaseV2,
    ClosedPolicyRootCasObservationV2, ClosedPolicyRootSessionV2, closed_policy_binding_digest_v2,
    propose_closed_current_create_explicit_policy_binding_v2,
    propose_closed_current_create_policy_binding_v2,
    read_fixed_inert_closed_policy_binding_hold_v1, release_fixed_closed_policy_cache_hold_v1,
    release_fixed_closed_policy_controller_hold_v1,
    release_fixed_closed_policy_source_domain_hold_v1,
    release_fixed_inert_closed_policy_binding_hold_v1,
    require_no_fixed_closed_policy_binding_hold_v1, with_fixed_closed_policy_binding_session_v2,
    with_fixed_explicit_closed_policy_binding_session_v2,
};
pub use cache_journal_readback::{
    read_fixed_policy_cache_hold_v1, read_fixed_policy_cache_journals_v1,
};
pub use cache_readback_pin::{CacheReadbackPinErrorV1, admit_fixed_cache_readback_pin_v1};
pub use cache_readback_session::{
    ClosedCacheReadbackRootChallengeV1, ClosedCacheReadbackRootObservationV1,
    ClosedCacheReadbackSessionErrorV1, with_fixed_closed_cache_readback_session_v1,
};
pub use compiler::{PolicyCompilationError, PolicyCompilerV1};
pub use controller_adapter::{
    PolicyCompilerControllerCommitV1, policy_compiler_controller_commit_v1,
};
pub use controller_hold_pin::{ControllerHoldPinErrorV1, admit_fixed_controller_hold_pin_v1};
pub use controller_hold_readback::{
    CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1, ControllerHoldReadbackChallengeV1,
    ControllerHoldReadbackErrorV1, PinnedControllerHoldSignerV1, VerifiedControllerHoldReadbackV1,
    encode_controller_hold_signer_credential_v1, sign_fixed_controller_hold_readback_v1,
    verify_controller_hold_readback_v1,
};
pub use controller_readback_session::{
    ClosedControllerReadbackSessionErrorV1, ClosedControllerRootChallengeV1,
    ClosedControllerRootObservationV1, with_fixed_closed_controller_readback_session_v1,
};
pub use deployment_head::{
    PolicyDeploymentHeadErrorV1, PolicyDeploymentHeadV1, PolicyDeploymentInputsV1,
    PolicyDeploymentSourcesV1, SignedProjectPolicyHeadV1, SignedProjectPolicySourceV1,
    admit_fixed_policy_deployment_head_v1, admit_fixed_policy_signer_pins_v1,
    admit_fixed_signed_project_policy_source_v1, decode_policy_deployment_sources_v1,
    verify_policy_deployment_head_v1, verify_signed_project_policy_source_v1,
    with_fixed_current_policy_head_lease_v1,
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
pub use project_source_v2::{
    AdmittedSignedProjectPolicySourceV2, SignedProjectPolicyHeadV2,
    VerifiedSignedProjectPolicySourceV2, admit_fixed_signed_project_policy_source_v2,
    verify_signed_project_policy_source_v2,
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
    CurrentCreatePolicyBarrierHeadsV2, CurrentCreatePolicySourceErrorV1,
    CurrentCreateProjectPolicySourceV1, checked_parentless_create_policy_draft_v1,
    checked_parentless_create_policy_draft_v2, checked_parentless_create_verified_policy_draft_v2,
    current_parentless_create_project_source_v1, with_current_create_policy_source_barrier_v2,
    with_current_create_policy_source_barrier_v3, with_current_create_policy_source_barrier_v4,
    with_current_parentless_create_ancestry_v1,
};
pub use resources::{
    BackendEnforcementSetV1, HardEnforcementV1, HardLimitProvenanceV1, HardLimitRequestV1,
    HardLimitValueV1, HardResourceKeyV1, HardResourceModelError, HardResourcePlanV1,
    HardResourceProfileV1, HardResourceScopeV1, PORTABLE_LIMIT_DIMENSIONS, ResolvedHardLimitV1,
    ResolvedHardLimitValueV1, UnlimitedProvenanceV1,
};
pub use source_hold_readback::{
    PinnedSourceHoldReadbackSignerV1, SOURCE_HOLD_READBACK_BYTES_V1, SourceHoldReadbackChallengeV1,
    SourceHoldReadbackErrorV1, encode_source_hold_readback_signer_credential_v1,
    sign_current_source_hold_readback_v1, verify_current_source_hold_readback_v1,
};
