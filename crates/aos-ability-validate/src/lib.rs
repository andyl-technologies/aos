//! Semantic validation for AOS ability contracts.
//!
//! Byte-level validation turns unchecked portable documents into checked
//! values without acquiring runtime resources or performing effects. Static
//! artifact builders additionally use an explicit filesystem-backed gate that
//! binds projected records to their exact package companions. The checked
//! wrappers retain the exact canonical documents that were validated.

#![forbid(unsafe_code)]

mod authority;
mod binding;
pub mod build_frontend;
mod effect;
mod error;
mod graph;
mod output;
mod package_contract;
mod package_projection;
mod projection;
mod schema;
mod static_contract;
mod transition_authority;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod regression_tests;

pub use authority::{InvocationAuthorizationError, ValueAuthorizationError};
pub use binding::PreparedBindingCandidates;
pub use error::ValidationErrors;
pub use graph::{
    BindingAuthorityKind, BindingValidationInputs, CheckedBindingPlan, CheckedEffectPlan,
    CheckedPackageDocument, ValidationContext,
};
pub use output::{InputValidationError, OutputValidationError, ProviderReadinessError};
pub use package_contract::{
    CheckedPackageContract, PackageContractValidationError, package_source_supported_features,
};
pub use package_projection::{
    CONFIG_ARTIFACT_SELECTOR_MARKER, ConfigArtifactSelector, InterfaceDocumentProjection,
    PACKAGE_OUTPUT_SELECTOR_MARKER, PACKAGE_PROJECTION_SCHEMA, PackageAbilityProjection,
    PackageOutputSelector, decode_package_projection, resolve_artifact_selectors,
    resolve_package_projection,
};
pub use schema::{SchemaPath, validate_value};
pub use static_contract::{
    CheckedStaticAbilityContract, StaticAbilityArtifactClass, StaticAbilityContractExpectation,
    StaticAbilityContractValidationError, StaticAbilityExecutionStage, StaticAbilityPlatform,
    validate_static_ability_artifacts,
};
pub use transition_authority::{
    CheckedTransitionAuthority, TransitionAuthorityError, TransitionAuthorityInputs,
};

/// Borrows one ability contract and the context needed to validate it.
#[derive(Debug)]
pub enum AbilityContractData<'a> {
    /// Describes a package companion before it is published or consumed.
    PackageSource {
        /// Contains the canonical `package.json` bytes.
        manifest: &'a [u8],
        /// Contains every canonical interface document retained by the companion.
        retained_interfaces: &'a [Vec<u8>],
    },
    /// Describes a static OCI or boot contract emitted by an artifact builder.
    Static {
        /// Contains the canonical static-contract JSON bytes.
        contract: &'a [u8],
        /// Supplies the artifact, stage, and platform selected by the builder.
        expectation: &'a StaticAbilityContractExpectation,
    },
}

/// Retains an ability contract after the shared semantic gate accepts it.
#[derive(Clone, Debug)]
pub enum CheckedAbilityContract {
    /// Retains a checked package companion contract.
    PackageSource(Box<CheckedPackageContract>),
    /// Retains a checked static artifact contract.
    Static(CheckedStaticAbilityContract),
}

/// Reports which contract family failed the shared semantic gate.
#[derive(Debug, thiserror::Error)]
pub enum AbilityContractValidationError {
    /// A package companion violated its canonical or semantic contract.
    #[error("validating ability package source contract")]
    PackageSource(#[source] PackageContractValidationError),
    /// A static artifact contract violated its canonical or semantic contract.
    #[error("validating static ability artifact contract")]
    Static(#[source] StaticAbilityContractValidationError),
}

/// Validates package-source and static-artifact data through one semantic gate.
///
/// Package publication and byte-only static callers use this dispatch point.
/// Artifact builders use [`validate_static_ability_artifacts`], which applies
/// the same static gate before checking the referenced package companions.
///
/// # Errors
///
/// Returns a family-specific error when canonical decoding, bounded schema
/// validation, semantic package checks, artifact references, launch
/// obligations, or builder expectations fail.
pub fn validate_ability_contract(
    data: AbilityContractData<'_>,
) -> Result<CheckedAbilityContract, AbilityContractValidationError> {
    match data {
        AbilityContractData::PackageSource {
            manifest,
            retained_interfaces,
        } => package_contract::validate_package_contract(manifest, retained_interfaces)
            .map(Box::new)
            .map(CheckedAbilityContract::PackageSource)
            .map_err(AbilityContractValidationError::PackageSource),
        AbilityContractData::Static {
            contract,
            expectation,
        } => static_contract::validate_static_ability_contract(contract, expectation)
            .map(CheckedAbilityContract::Static)
            .map_err(AbilityContractValidationError::Static),
    }
}
