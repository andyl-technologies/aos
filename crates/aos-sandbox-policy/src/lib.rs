//! Compiles bounded policy inputs into inert, portable candidate plans.
//!
//! The compiler owns authority intersection, namespace lowering, hard-resource
//! resolution and advisory selection. Its candidate DATA does not establish
//! protected input provenance, publication currentness or runtime authority.
//! Those joins and all signing, Journal and effect custody remain with callers.
//!
//! On Linux, `policy_signer_credential` owns the existing public verifier DATA
//! and its role-specific framing. These public keys do not establish protected
//! credential custody, currentness, signing authority, or admission.
//!
//! The private model module owns bounded inputs and candidate DATA. The compiler
//! module orders authority, namespace, resources and advisory lowering.

mod advisory;
mod authority;
mod compiler;
mod model;
mod publisher_revision;
pub use publisher_revision::{PreparedPublisherPolicyRevisionV1, RetainedPublisherCompilerOriginV3,
    PublisherPolicyDataError, NormalizedPolicyInputErrorV1, normalized_policy_input_digest_v1,
    retain_publisher_compiler_derivation_v3};
mod namespace;
mod resources;

#[cfg(target_os = "linux")]
pub mod policy_signer_credential;

pub use advisory::{
    AdvisoryActionV1, AdvisoryDecisionV1, AdvisoryDegradationV1, AdvisoryKindV1, AdvisoryPlanV1,
    AdvisoryStatusV1, PortableAdvisoryProgramV1,
};
pub use authority::{
    AuthenticatedEndpointCatalogV1, AuthorityPlanV1, EffectiveGrantV1, EndpointCatalogEntryV1,
    EndpointCatalogError, EndpointCatalogVerifierV1, EndpointUseV1,
};
pub use compiler::{PolicyCompilationError, PolicyCompilerV1};
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
pub use resources::{
    BackendEnforcementSetV1, HardEnforcementV1, HardLimitProvenanceV1, HardLimitRequestV1,
    HardLimitValueV1, HardResourceKeyV1, HardResourceModelError, HardResourcePlanV1,
    HardResourceProfileV1, HardResourceScopeV1, PORTABLE_LIMIT_DIMENSIONS, ResolvedHardLimitV1,
    ResolvedHardLimitValueV1, UnlimitedProvenanceV1,
};

pub use advisory::canonicalize_advisory_actions;
pub use authority::canonical_endpoint_catalog_v1;
pub use model::{canonical_bytes, compiled_policy_candidate_digest_v1, digest};
pub use namespace::{canonical_namespace_catalog_v1, validate_portable_namespace_rule_order};
