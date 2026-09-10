//! Canonical public reference data derived from an authenticated ability companion.
//!
//! This object is deliberately separate from [`crate::PackageDocumentation`].
//! Its identity follows the signed ability manifest, while package-authored
//! prose retains the documentation object's independent byte identity.

use std::collections::BTreeSet;

use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityActivationMode, AggregationContract, HandlerDescriptor,
    InterfaceDocument, LocalKey, PackageDocument, RequiredFeature, RequirementDeclaration,
    ScopePath, ValueSchema, VersionedDocument, decode_canonical, encode_canonical,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{DocumentationError, Result};

/// Exact schema discriminator for generated package ability reference data.
pub const ABILITY_REFERENCE_SCHEMA: &str = "aos.package-ability-reference/v1";

/// Maximum canonical reference size admitted by version 1.
pub const MAX_ABILITY_REFERENCE_BYTES: usize = 4 * 1024 * 1024;

/// Returns the reference semantics implemented by this reader build.
///
/// This set is reader-owned. Package declarations cannot add semantics the
/// reader does not understand merely by naming them in `required_features`.
///
/// # Errors
///
/// Returns an error if a built-in feature identifier is invalid.
pub fn ability_reference_supported_features() -> Result<BTreeSet<RequiredFeature>> {
    ["abilities-v1", "ability-effects-v1"]
        .into_iter()
        .map(|feature| RequiredFeature::new(feature).map_err(invalid_model))
        .collect()
}

/// One public export and the exact interface document it implements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityExportReference {
    /// Names the export inside the package.
    pub name: LocalKey,
    /// Retains the complete public request, operator configuration, result,
    /// method, and guarantee contract.
    pub interface: InterfaceDocument,
    /// Defines contribution aggregation when the export accepts contributions.
    pub aggregation: Option<AggregationContract>,
    /// Identifies the separately authenticated provider implementation.
    pub implementation: Sha256Digest,
}

/// One public operation-handler schema without its executable artifact path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityHandlerReference {
    /// Names the handler inside the package.
    pub name: LocalKey,
    /// Names the entry point inside the separately authenticated handler artifact.
    pub entry_point: String,
    /// Defines the closed handler argument schema.
    pub arguments: ValueSchema,
    /// Defines the closed handler result schema.
    pub result: ValueSchema,
}

/// Bounded public reference projection of one signed package ability companion.
///
/// The projection retains public operator configuration schemas, but never a
/// desired deployment instance's configuration value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageAbilityReference {
    /// Carries [`ABILITY_REFERENCE_SCHEMA`].
    pub schema: String,
    /// Names required reference semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Names the package selected by the enclosing signed release.
    pub package: LocalKey,
    /// Preserves the exact authored package version.
    pub version: String,
    /// SHA-256 of the exact canonical package manifest bytes.
    pub manifest_sha256: Sha256Digest,
    /// Domain-separated semantic identity of the package manifest.
    pub package_digest: Sha256Digest,
    /// States whether the package may author structured activation effects.
    pub activation_mode: AbilityActivationMode,
    /// Lists public exports in canonical package order.
    pub exports: Vec<AbilityExportReference>,
    /// Lists declarative lower-interface requirements in canonical alias order.
    pub requirements: Vec<RequirementDeclaration>,
    /// Lists public handler argument/result schemas in canonical name order.
    pub handlers: Vec<AbilityHandlerReference>,
    /// Names declared ownership roots without deployment assignments.
    pub ownership: Vec<ScopePath>,
}

impl PackageAbilityReference {
    /// Generates public reference data from structurally checked companion documents.
    ///
    /// This constructor derives and retains exact document identities, but it
    /// does not authenticate a release signature or establish that the caller
    /// obtained the documents from the signed companion named by a release.
    ///
    /// # Errors
    ///
    /// Returns an error when an export's exact interface document is absent,
    /// duplicated, or inconsistent, or when the generated reference is invalid.
    pub fn from_documents(
        package: &PackageDocument,
        interfaces: &[InterfaceDocument],
    ) -> Result<Self> {
        let manifest = encode_canonical(package).map_err(invalid_model)?;
        let manifest_sha256 = Sha256Digest::of_bytes(&manifest);
        let package_digest = package.content_digest().map_err(invalid_model)?;

        let mut exports = Vec::with_capacity(package.exports.len());
        for export in &package.exports {
            let mut matching = interfaces.iter().filter_map(|document| {
                document
                    .interface_key()
                    .ok()
                    .filter(|key| key == &export.interface)
                    .map(|_| document)
            });
            let interface = matching.next().ok_or_else(|| {
                invalid(format!(
                    "export '{}' has no exact public interface document",
                    export.name.as_str()
                ))
            })?;
            if matching.next().is_some() {
                return Err(invalid(format!(
                    "export '{}' repeats its public interface document",
                    export.name.as_str()
                )));
            }
            exports.push(AbilityExportReference {
                name: export.name.clone(),
                interface: interface.clone(),
                aggregation: export.aggregation.clone(),
                implementation: export.implementation,
            });
        }

        let handlers = package
            .implementation
            .handlers
            .iter()
            .map(|(name, handler)| handler_reference(name, handler))
            .collect();
        let reference = Self {
            schema: ABILITY_REFERENCE_SCHEMA.to_string(),
            required_features: package.required_features.clone(),
            package: package.package.name.clone(),
            version: package.package.version.clone(),
            manifest_sha256,
            package_digest,
            activation_mode: package.activation_mode,
            exports,
            requirements: package.requirements.clone(),
            handlers,
            ownership: package.ownership.clone(),
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Decodes exact canonical reference JSON under the version-1 bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized data.
    pub fn from_canonical_json(
        bytes: &[u8],
        supported_features: &BTreeSet<RequiredFeature>,
    ) -> Result<Self> {
        if bytes.len() > MAX_ABILITY_REFERENCE_BYTES {
            return Err(invalid("ability reference exceeds the 4 MiB limit"));
        }
        let reference: Self = decode_canonical(bytes, ABILITY_LIMITS_V1, supported_features)
            .map_err(invalid_model)?;
        reference.validate()?;
        for export in &reference.exports {
            let interface_bytes = encode_canonical(&export.interface).map_err(invalid_model)?;
            decode_canonical::<InterfaceDocument>(
                &interface_bytes,
                ABILITY_LIMITS_V1,
                supported_features,
            )
            .map_err(invalid_model)?;
        }
        if reference.canonical_json()? != bytes {
            return Err(invalid("ability reference is not canonical JSON"));
        }
        Ok(reference)
    }

    /// Encodes the reference as exact canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical encoding fails.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = encode_canonical(self).map_err(invalid_model)?;
        if bytes.len() > MAX_ABILITY_REFERENCE_BYTES {
            return Err(invalid("ability reference exceeds the 4 MiB limit"));
        }
        Ok(bytes)
    }

    /// Validates reference identities, canonical order, and portable schema bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference is internally inconsistent or exceeds
    /// the shared ability contract limits.
    pub fn validate(&self) -> Result<()> {
        if self.schema != ABILITY_REFERENCE_SCHEMA {
            return Err(invalid(format!(
                "unsupported ability reference schema '{}'",
                self.schema
            )));
        }
        if self.version.is_empty() || self.version.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes
        {
            return Err(invalid("ability reference has an invalid package version"));
        }
        let max_items = ABILITY_LIMITS_V1.max_collection_items as usize;
        if self.exports.len() > max_items
            || self.requirements.len() > max_items
            || self.handlers.len() > max_items
            || self.ownership.len() > max_items
        {
            return Err(invalid("ability reference exceeds its collection limit"));
        }

        let mut export_names = BTreeSet::new();
        let mut previous_export = None;
        for export in &self.exports {
            if previous_export.is_some_and(|previous: &LocalKey| previous >= &export.name)
                || !export_names.insert(export.name.clone())
            {
                return Err(invalid(
                    "ability reference exports are not in canonical order",
                ));
            }
            export.interface.content_digest().map_err(invalid_model)?;
            previous_export = Some(&export.name);
        }
        let mut previous_handler = None;
        for handler in &self.handlers {
            if previous_handler.is_some_and(|previous: &LocalKey| previous >= &handler.name) {
                return Err(invalid(
                    "ability reference handlers are not in canonical order",
                ));
            }
            if !handler.arguments.is_within_limits(
                ABILITY_LIMITS_V1.max_structural_depth,
                ABILITY_LIMITS_V1.max_collection_items,
            ) || !handler.result.is_within_limits(
                ABILITY_LIMITS_V1.max_structural_depth,
                ABILITY_LIMITS_V1.max_collection_items,
            ) {
                return Err(invalid("ability handler schema exceeds shared limits"));
            }
            previous_handler = Some(&handler.name);
        }
        Ok(())
    }
}

impl VersionedDocument for PackageAbilityReference {
    const SCHEMA: &'static str = ABILITY_REFERENCE_SCHEMA;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }
}

fn handler_reference(name: &LocalKey, handler: &HandlerDescriptor) -> AbilityHandlerReference {
    AbilityHandlerReference {
        name: name.clone(),
        entry_point: handler.entry_point.clone(),
        arguments: handler.arguments.clone(),
        result: handler.result.clone(),
    }
}

fn invalid(message: impl Into<String>) -> DocumentationError {
    DocumentationError::Invalid(message.into())
}

fn invalid_model(error: impl std::fmt::Display) -> DocumentationError {
    invalid(format!("invalid ability reference model: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> PackageAbilityReference {
        PackageAbilityReference {
            schema: ABILITY_REFERENCE_SCHEMA.to_string(),
            required_features: vec![
                RequiredFeature::new("abilities-v1").expect("valid feature name"),
            ],
            package: LocalKey::new("demo").expect("valid package name"),
            version: "1.0.0".to_string(),
            manifest_sha256: Sha256Digest::of_bytes("manifest"),
            package_digest: Sha256Digest::of_bytes("package"),
            activation_mode: AbilityActivationMode::ContractsOnly,
            exports: Vec::new(),
            requirements: Vec::new(),
            handlers: Vec::new(),
            ownership: Vec::new(),
        }
    }

    #[test]
    fn decoding_requires_reader_owned_feature_support() {
        let reference = reference();
        let bytes = reference.canonical_json().expect("encode reference");

        assert!(PackageAbilityReference::from_canonical_json(&bytes, &BTreeSet::new()).is_err());

        let supported =
            BTreeSet::from([RequiredFeature::new("abilities-v1").expect("valid feature name")]);
        let decoded = PackageAbilityReference::from_canonical_json(&bytes, &supported)
            .expect("decode supported reference");
        assert_eq!(decoded, reference);
    }

    #[test]
    fn decoding_rejects_noncanonical_reference_bytes() {
        let reference = reference();
        let mut bytes = b" \n".to_vec();
        bytes.extend(reference.canonical_json().expect("encode reference"));
        let supported =
            BTreeSet::from([RequiredFeature::new("abilities-v1").expect("valid feature name")]);

        assert!(PackageAbilityReference::from_canonical_json(&bytes, &supported).is_err());
    }

    #[test]
    fn decoding_does_not_self_authorize_nested_interface_features() {
        let supported =
            BTreeSet::from([RequiredFeature::new("abilities-v1").expect("valid feature name")]);
        let mut interface = decode_canonical::<InterfaceDocument>(
            include_bytes!("../../../tests/abilities/fixtures/interface.json"),
            ABILITY_LIMITS_V1,
            &supported,
        )
        .expect("decode interface fixture");
        interface.required_features.push(
            RequiredFeature::new("future-interface-semantics").expect("valid future feature"),
        );
        let mut reference = reference();
        reference.exports.push(AbilityExportReference {
            name: LocalKey::new("echo").expect("valid export name"),
            interface,
            aggregation: None,
            implementation: Sha256Digest::of_bytes("implementation"),
        });
        let bytes = reference.canonical_json().expect("encode reference");

        assert!(PackageAbilityReference::from_canonical_json(&bytes, &supported).is_err());
    }
}
