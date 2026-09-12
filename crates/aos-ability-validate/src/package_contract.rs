//! Canonical package-companion validation shared by builders and APM.
//!
//! A package companion contains one `package.json` and the exact interface
//! documents retained below `interfaces/`. Publication may leave interfaces
//! named only by deployment requirements unresolved, while every exported or
//! implemented interface must be present in this local catalog.

use std::collections::BTreeSet;

use aos_ability_model::document::DocumentError;
use aos_ability_model::{InterfaceDocument, PackageDocument, RequiredFeature, decode_canonical};
use thiserror::Error;

use crate::{CheckedPackageDocument, ValidationContext, ValidationErrors};

/// Retains a package manifest after canonical and semantic validation.
#[derive(Clone, Debug)]
pub struct CheckedPackageContract {
    package: CheckedPackageDocument,
    context: ValidationContext,
}

impl CheckedPackageContract {
    /// Returns the exact canonical package document.
    #[must_use]
    pub const fn package(&self) -> &PackageDocument {
        self.package.document()
    }

    /// Returns the validated retained-interface catalog.
    #[must_use]
    pub const fn validation_context(&self) -> &ValidationContext {
        &self.context
    }
}

/// Reports failure to decode or semantically validate a package companion.
#[derive(Debug, Error)]
pub enum PackageContractValidationError {
    /// A built-in required-feature name violated the closed identity grammar.
    #[error("constructing the supported ability feature set")]
    Feature(#[source] aos_ability_model::identity::IdentityError),
    /// The package manifest was not a supported canonical document.
    #[error("decoding canonical ability package manifest")]
    PackageDocument(#[source] DocumentError),
    /// A retained interface was not a supported canonical document.
    #[error("decoding canonical retained interface document {index}")]
    InterfaceDocument {
        /// Identifies the interface document in deterministic input order.
        index: usize,
        /// Preserves the canonical decoding failure.
        #[source]
        source: DocumentError,
    },
    /// The retained interface catalog was semantically invalid.
    #[error("validating retained ability interface catalog")]
    InterfaceCatalog(#[source] ValidationErrors),
    /// The package disagreed with the validated retained interfaces.
    #[error("validating ability package semantics")]
    PackageSemantics(#[source] ValidationErrors),
}

/// Validates one canonical package manifest and its retained public interfaces.
///
/// This is the shared build and publication entry point. It accepts unresolved
/// requirement-only interfaces because a package build cannot assume the
/// eventual deployment catalog. Planning revalidates those requirements
/// against the complete authenticated catalog before binding.
///
/// # Errors
///
/// Returns an error when any document is noncanonical, exceeds the version-1
/// bounds, requests unsupported semantics, duplicates an interface identity,
/// or violates package ordering, activation, export, implementation, handler,
/// ownership, or locally resolvable requirement invariants.
pub(crate) fn validate_package_contract<B>(
    manifest: &[u8],
    retained_interfaces: impl IntoIterator<Item = B>,
) -> Result<CheckedPackageContract, PackageContractValidationError>
where
    B: AsRef<[u8]>,
{
    let supported_features = supported_features()?;
    let package = decode_canonical::<PackageDocument>(
        manifest,
        aos_ability_model::ABILITY_LIMITS_V1,
        &supported_features,
    )
    .map_err(PackageContractValidationError::PackageDocument)?;

    let interfaces = retained_interfaces
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            decode_canonical::<InterfaceDocument>(
                bytes.as_ref(),
                aos_ability_model::ABILITY_LIMITS_V1,
                &supported_features,
            )
            .map_err(|source| PackageContractValidationError::InterfaceDocument { index, source })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let context = ValidationContext::new(supported_features, interfaces)
        .map_err(PackageContractValidationError::InterfaceCatalog)?;
    let package = context
        .validate_package_contract(package)
        .map_err(PackageContractValidationError::PackageSemantics)?;

    Ok(CheckedPackageContract { package, context })
}

fn supported_features() -> Result<BTreeSet<RequiredFeature>, PackageContractValidationError> {
    [
        aos_ability_model::builtin::AB_IMAGE_ROLLOUT_FEATURE,
        "abilities-v1",
        aos_ability_model::PROVIDER_STATE_FORMAT_V1,
        aos_ability_model::PROVIDER_STATE_ADOPTION_V1,
    ]
    .into_iter()
    .map(RequiredFeature::new)
    .collect::<Result<_, _>>()
    .map_err(PackageContractValidationError::Feature)
}

#[cfg(test)]
mod tests {
    use aos_ability_model::encode_canonical;

    use super::validate_package_contract;

    #[test]
    fn accepts_the_shared_reference_package_contract() {
        let fixture = crate::test_support::stateful_owner_plan_fixture();
        let package = encode_canonical(&fixture.binding_inputs.packages[0])
            .expect("fixture package must encode");
        let interfaces = fixture
            .interfaces
            .iter()
            .map(|document| encode_canonical(document).expect("fixture interface must encode"))
            .collect::<Vec<_>>();

        validate_package_contract(&package, &interfaces)
            .expect("reference package contract must validate");
    }

    #[test]
    fn rejects_semantic_bypass_after_canonical_decoding() {
        let fixture = crate::test_support::stateful_owner_plan_fixture();
        let mut package = fixture.binding_inputs.packages[0].clone();
        package.exports[0].implementation = aos_contract::Sha256Digest::of_bytes(b"bypass");
        let package = encode_canonical(&package).expect("mutated package must remain canonical");
        let interfaces = fixture
            .interfaces
            .iter()
            .map(|document| encode_canonical(document).expect("fixture interface must encode"))
            .collect::<Vec<_>>();

        let error = validate_package_contract(&package, &interfaces)
            .expect_err("semantic export mismatch must fail closed");

        assert!(format!("{error:?}").contains("package export lacks a matching exact"));
    }
}
