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
//! Protocol owns canonical publisher revisions, provenance and commitment DATA.
//! This crate qualifies derivation against genuine typed compiler inputs; its
//! normalized input digest creates no current admission or protected owner loan.

mod advisory;
mod authority;
mod compiler;
mod model;
mod publisher_revision;
pub use publisher_revision::{
    NormalizedPolicyInputErrorV1, compare_publisher_compiler_derivation_v3,
    normalized_policy_input_digest_v1, retain_publisher_compiler_derivation_v3,
    verify_publisher_compiler_derivation_v3,
};
mod namespace;
mod resources;

/// Names existing Policy journal DATA keys without granting native authority.
pub mod journal_keys;

/// Materializes parentless compiler input from authenticated model layers.
pub mod parentless_input;

/// Checks canonical signed input DATA without native admission.
pub mod signed_inputs;

/// Checks signed Controller comparison DATA without native custody or authority.
pub mod controller_readback;

/// Owns canonical Controller project-readback DATA and raw verification.
pub mod controller_project_readback;

/// Compares complete saved Root role tuples without native custody or grants.
#[cfg(all(target_os = "linux", feature = "native-journal"))]
pub mod root_role_pins_data;

/// Compares complete settled Source floors without native custody or grants.
#[cfg(all(target_os = "linux", feature = "native-journal"))]
pub mod root_saved_floor_data;

/// Verifies saved Root signed-source DATA without native custody.
pub mod root_signed_sources_data;

/// Shares raw Root signed-input DATA and full historical-row comparison.
#[cfg(all(target_os = "linux", feature = "native-journal"))]
pub mod root_policy_inputs_data;

/// Derives and compares saved Controller history without native authority.
#[cfg(all(target_os = "linux", feature = "native-journal"))]
pub mod controller_history_data;

/// Checks the existing Controller successor signature and clock DATA.
#[cfg(all(target_os = "linux", feature = "native-journal"))]
pub mod controller_successor_data;

/// Checks current-Nix packet and signature DATA without a native role loan.
#[cfg(all(target_os = "linux", feature = "native-journal"))]
pub mod nix_current_data;

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
    MAXIMUM_ADVISORY_RULES_PER_LAYER, MAXIMUM_EXPLANATION_ENTRIES_PER_STAGE,
    MAXIMUM_GRANTS_PER_LAYER, MAXIMUM_NAMESPACE_RULES_PER_LAYER, MAXIMUM_POLICY_ANCESTORS,
    MAXIMUM_POLICY_LAYER_BYTES, MAXIMUM_POLICY_LAYER_WORK_UNITS, NamespaceBackendFeatureV1,
    NamespacePlanCommitmentV1, NodePolicyCommitmentV1, NodePolicyInputV1, PlanExplanationV1,
    PolicyCompilerInputV1, PolicyCompilerLimitsV1, PolicyLayerV1, PolicyModelError,
    PortablePolicyOutputV1, ProjectPolicyCommitmentV1, ProjectPolicyInputV1, RedactedSubjectV1,
    RequestPolicyCommitmentV1, RequestPolicyInputV1, RevocationInputV1,
    SandboxProjectRelationVerifierV1, SitePolicyCommitmentV1, SitePolicyInputV1,
    StageExplanationV1,
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
    ResolvedHardLimitValueV1, SpecResourceCompatibilityErrorV1, UnlimitedProvenanceV1,
    inherited_parentless_resource_namespace_entries_v1, require_specification_resource_profile_v1,
};

pub use advisory::canonicalize_advisory_actions;
pub use authority::canonical_endpoint_catalog_v1;
pub use namespace::{canonical_namespace_catalog_v1, validate_portable_namespace_rule_order};

/// Contains nonissuing Root public broker-plan trust comparison DATA.
pub mod root_trust_data;

/// Contains unsigned Root prospective Storage-plan comparison DATA.
pub mod root_use_plan_data;

/// Canonical closed publication comparison DATA for independent native owners.
pub mod q04_data;

/// Retains fixed Root journals and their genuine native Policy role custody.
///
/// The portable compiler and comparison models remain available without this
/// Linux-only feature. Native constructors require their original fixed owners.
#[cfg(all(feature = "native-journal", target_os = "linux"))]
pub mod native;

/// Owns portable publication schemas, prerequisites and comparison DATA.
pub mod publication;

/// Shares passive Create U Security layout and its concrete lexical geometry recipe.
pub mod storage_create_use_data;

/// Compares Source Current reply DATA without constructing native custody.
pub mod source_current_data;

/// Compares Ownership bundle DATA without constructing native custody.
#[cfg(all(feature = "native-journal", target_os = "linux"))]
pub mod bundle_ownership_data;

/// Compares borrowed Cache proof and observed clock DATA without native custody.
pub mod cache_current_data;

/// Checks complete Controller accepted-history DATA without native admission.
#[cfg(all(feature = "native-journal", target_os = "linux"))]
pub mod controller_acceptance_data;

/// Shares the guarded current-Create comparison programme without native custody.
pub mod root_current_compile_recipe;

/// Shares passive protected Session representation recipes.
pub mod storage_session_geometry_data;
