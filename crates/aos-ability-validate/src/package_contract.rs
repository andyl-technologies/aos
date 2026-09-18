//! Canonical package-companion validation shared by builders and APM.
//!
//! A package companion contains one `package.json` and the exact interface
//! documents retained below `interfaces/`. Publication may leave interfaces
//! named only by deployment requirements unresolved, while every exported or
//! implemented interface must be present in this local catalog.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::DocumentError;
use aos_ability_model::{
    GuaranteeKey, InterfaceDocument, InterfaceKey, LocalKey, PackageDocument, RequiredFeature,
    decode_canonical,
};
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

    /// Returns package-local interface aliases and their checked documents.
    #[must_use]
    pub fn retained_interfaces(&self) -> BTreeMap<&LocalKey, &InterfaceDocument> {
        self.package()
            .interfaces
            .iter()
            .filter_map(|(alias, key)| {
                self.context
                    .interface(key)
                    .map(|document| (alias, document))
            })
            .collect()
    }

    /// Returns one checked retained interface by its package-local alias.
    #[must_use]
    pub fn retained_interface(&self, alias: &LocalKey) -> Option<&InterfaceDocument> {
        self.package()
            .interfaces
            .get(alias)
            .and_then(|key| self.context.interface(key))
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
    /// Package-local declarations disagreed with the retained semantic catalog.
    #[error("validating package-local ability declarations")]
    LocalDeclarations(#[source] anyhow::Error),
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
    let supported_features = package_source_supported_features()?;
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

    validate_local_declarations(package.document(), &context)
        .map_err(PackageContractValidationError::LocalDeclarations)?;

    Ok(CheckedPackageContract { package, context })
}

fn validate_local_declarations(
    package: &PackageDocument,
    context: &ValidationContext,
) -> anyhow::Result<()> {
    let retained = package
        .interfaces
        .iter()
        .map(|(alias, key)| {
            let document = context.interface(key).ok_or_else(|| {
                anyhow::anyhow!(
                    "package interface alias '{}' has no exact retained document",
                    alias.as_str()
                )
            })?;
            let actual = document.interface_key()?;
            anyhow::ensure!(
                actual == *key,
                "package interface alias '{}' differs from its retained document",
                alias.as_str()
            );
            Ok(key.clone())
        })
        .collect::<anyhow::Result<BTreeSet<InterfaceKey>>>()?;
    anyhow::ensure!(
        retained.len() == context.interface_catalog().len(),
        "retained interface catalog contains documents not owned by a package interface alias"
    );

    let declared_guarantees = package
        .guarantees
        .values()
        .map(|declaration| declaration.key())
        .collect::<anyhow::Result<BTreeSet<GuaranteeKey>>>()?;
    anyhow::ensure!(
        declared_guarantees.len() == package.guarantees.len(),
        "package guarantee aliases derive duplicate semantic identities"
    );

    let mut referenced_guarantees = BTreeSet::new();
    for key in &retained {
        let document = context
            .interface(key)
            .ok_or_else(|| anyhow::anyhow!("checked retained interface disappeared"))?;
        referenced_guarantees.extend(document.interface.guarantees.iter().cloned());
        for method in document.interface.methods.values() {
            referenced_guarantees.extend(method.guarantees.iter().cloned());
        }
    }
    for requirement in package.requirements.iter().chain(
        package
            .implementation
            .providers
            .iter()
            .flat_map(|provider| &provider.requirements),
    ) {
        referenced_guarantees.extend(requirement.guarantees.iter().cloned());
    }
    anyhow::ensure!(
        declared_guarantees == referenced_guarantees,
        "package guarantee declarations must exactly cover all referenced guarantee identities"
    );

    if let Some(module) = &package.package_module {
        anyhow::ensure!(
            package.artifacts.contains(&module.artifact),
            "package module artifact is absent from the retained artifact catalog"
        );
    } else {
        anyhow::ensure!(
            package.qualification.package_probe.is_some()
                && package.interfaces.is_empty()
                && package.guarantees.is_empty()
                && package.option_declarations.is_empty()
                && package.exports.is_empty()
                && package.requirements.is_empty()
                && package.implementation.providers.is_empty()
                && package.implementation.handlers.is_empty(),
            "package without an ability module must contain only its package probe"
        );
    }
    let implementation_descriptors = package
        .implementation
        .providers
        .iter()
        .map(aos_ability_model::ProviderImplementation::descriptor_digest)
        .collect::<anyhow::Result<BTreeSet<_>>>()?;
    anyhow::ensure!(
        implementation_descriptors.len() == package.implementation.providers.len(),
        "package implementation descriptors must be unique"
    );
    anyhow::ensure!(
        package.implementation.providers.windows(2).all(|pair| {
            pair[0].interface < pair[1].interface
                || (pair[0].interface == pair[1].interface && pair[0].name < pair[1].name)
        }),
        "package implementations must be unique and in canonical interface/name order"
    );
    anyhow::ensure!(
        package
            .implementation
            .providers
            .iter()
            .map(|provider| &provider.name)
            .collect::<BTreeSet<_>>()
            .len()
            == package.implementation.providers.len(),
        "package implementation names must be unique"
    );
    for export in &package.exports {
        let provider = package
            .implementation
            .providers
            .iter()
            .find(|provider| provider.name == export.implementation_name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "package export '{}' names absent implementation '{}'",
                    export.name.as_str(),
                    export.implementation_name.as_str()
                )
            })?;
        anyhow::ensure!(
            provider.interface == export.interface
                && provider.descriptor_digest()? == export.implementation,
            "package export '{}' does not match its exact retained implementation",
            export.name.as_str()
        );
    }
    for (implementation, qualification) in &package.qualification.implementations {
        anyhow::ensure!(
            implementation_descriptors.contains(implementation),
            "package qualification claim names an absent implementation descriptor"
        );
        anyhow::ensure!(
            package.artifacts.contains(&qualification.observer.artifact),
            "package qualification observer is absent from the retained artifact catalog"
        );
    }

    Ok(())
}

/// Returns the exact semantic feature set accepted by the package-source reader.
///
/// Reference decoders and documentation consumers use this shared set so they
/// cannot drift from the package publication gate.
///
/// # Errors
///
/// Returns an error if a built-in feature name violates the closed identity
/// grammar.
pub fn package_source_supported_features()
-> Result<BTreeSet<RequiredFeature>, PackageContractValidationError> {
    [
        aos_ability_model::FEATURE_ABILITIES_V1,
        aos_ability_model::FEATURE_ABILITY_EFFECTS_V1,
        aos_ability_model::PROVIDER_STATE_FORMAT_V1,
        aos_ability_model::PROVIDER_STATE_ADOPTION_FEATURE,
    ]
    .into_iter()
    .map(RequiredFeature::new)
    .collect::<Result<_, _>>()
    .map_err(PackageContractValidationError::Feature)
}

/// Reports whether a package document authors executable effect semantics.
///
/// Publication, validation, and runtime selection use this structural query so
/// the `ability-effects-v1` gate cannot drift into a separately authored mode.
pub fn package_uses_effects(package: &PackageDocument) -> bool {
    !package.implementation.handlers.is_empty()
        || package.implementation.providers.iter().any(|provider| {
            provider.provider_module.is_some()
                || !provider.owns_resource_kinds.is_empty()
                || provider.handler.is_some()
        })
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{
        ABILITY_LIMITS_V1, FEATURE_ABILITY_EFFECTS_V1, GuaranteeDeclaration, InterfaceName,
        LocalKey, PackageDocument, encode_canonical,
    };

    use super::{package_source_supported_features, validate_package_contract};

    #[test]
    fn accepts_the_shared_reference_package_contract() {
        let fixture = crate::test_support::stateful_owner_plan_fixture();
        let package = encode_canonical(&fixture.binding_inputs.packages[0])
            .expect("fixture package must encode");
        let interfaces = fixture
            .interfaces
            .iter()
            .filter(|document| {
                let key = document
                    .interface_key()
                    .expect("fixture interface identity");
                fixture.binding_inputs.packages[0]
                    .interfaces
                    .values()
                    .any(|declared| declared == &key)
            })
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
            .filter(|document| {
                let key = document
                    .interface_key()
                    .expect("fixture interface identity");
                fixture.binding_inputs.packages[0]
                    .interfaces
                    .values()
                    .any(|declared| declared == &key)
            })
            .map(|document| encode_canonical(document).expect("fixture interface must encode"))
            .collect::<Vec<_>>();

        let error = validate_package_contract(&package, &interfaces)
            .expect_err("semantic export mismatch must fail closed");

        assert!(format!("{error:?}").contains("package export lacks a matching exact"));
    }

    #[test]
    fn rejects_an_unreferenced_package_guarantee_declaration() {
        let fixture = crate::test_support::stateful_owner_plan_fixture();
        let mut package = fixture.binding_inputs.packages[0].clone();
        package.guarantees.insert(
            LocalKey::new("unused").expect("valid alias"),
            GuaranteeDeclaration {
                name: InterfaceName::new("test.unused").expect("valid name"),
                version: 1.try_into().expect("nonzero version"),
                semantics: "unused semantic promise".to_string(),
                description: "Unused documentation.".to_string(),
            },
        );
        let package = encode_canonical(&package).expect("mutated package must encode");
        let interfaces = retained_interface_bytes(&fixture);

        let error = validate_package_contract(&package, &interfaces)
            .expect_err("unreferenced guarantee declaration must fail closed");

        assert!(format!("{error:?}").contains("exactly cover"));
    }

    #[test]
    fn effect_authorship_and_reader_feature_must_match() {
        let fixture = crate::test_support::stateful_owner_plan_fixture();
        let interfaces = retained_interface_bytes(&fixture);
        let mut package = fixture.binding_inputs.packages[0].clone();
        package
            .required_features
            .retain(|feature| feature.as_str() != FEATURE_ABILITY_EFFECTS_V1);
        let encoded = encode_canonical(&package).expect("effect package must encode");
        let error = validate_package_contract(&encoded, &interfaces)
            .expect_err("effect authorship without its reader gate must fail");
        assert!(
            format!("{error:?}").contains(
                "package effect declarations and ability-effects-v1 must appear together"
            )
        );

        package
            .required_features
            .push(aos_ability_model::RequiredFeature::new(FEATURE_ABILITY_EFFECTS_V1).unwrap());
        package.required_features.sort();
        package.implementation.providers.clear();
        package.implementation.handlers.clear();
        let encoded = encode_canonical(&package).expect("effect-free package must encode");
        let error = validate_package_contract(&encoded, &interfaces)
            .expect_err("an effect reader gate without effect authorship must fail");
        assert!(
            format!("{error:?}").contains(
                "package effect declarations and ability-effects-v1 must appear together"
            )
        );
    }

    #[test]
    fn package_decoder_rejects_the_obsolete_activation_mode_field() {
        let fixture = crate::test_support::stateful_owner_plan_fixture();
        let encoded = encode_canonical(&fixture.binding_inputs.packages[0])
            .expect("fixture package must encode");
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("activation_mode".to_string(), serde_json::json!("obsolete"));
        let encoded = serde_json::to_vec(&value).unwrap();

        aos_ability_model::decode_canonical::<PackageDocument>(
            &encoded,
            ABILITY_LIMITS_V1,
            &package_source_supported_features().unwrap(),
        )
        .expect_err("the removed field must fail closed");
    }

    fn retained_interface_bytes(fixture: &crate::test_support::PlanFixture) -> Vec<Vec<u8>> {
        fixture
            .interfaces
            .iter()
            .filter(|document| {
                let key = document
                    .interface_key()
                    .expect("fixture interface identity");
                fixture.binding_inputs.packages[0]
                    .interfaces
                    .values()
                    .any(|declared| declared == &key)
            })
            .map(|document| encode_canonical(document).expect("fixture interface must encode"))
            .collect()
    }
}
