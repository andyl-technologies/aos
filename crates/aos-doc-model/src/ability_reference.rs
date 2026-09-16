//! Canonical public reference data derived from a checked signed package projection.
//!
//! This object is deliberately separate from [`crate::PackageDocumentation`].
//! Its identity follows the signed ability manifest, while package-authored
//! prose retains the documentation object's independent byte identity.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{
    ABILITY_LIMITS_V1, GuaranteeDeclaration, HandlerDescriptor, InterfaceDocument, InterfaceKey,
    LocalKey, OptionVisibility, PackageOptionDeclaration, ProviderImplementation, RequiredFeature,
    RequirementDeclaration, ValueSchema, VersionedDocument, decode_canonical, encode_canonical,
    validate_package_option_declarations,
};
use aos_ability_validate::{CheckedPackageContract, package_source_supported_features};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{
    DocumentationError, InlineSpan, OptionDocument, OptionOwner, PathSegment, ProseBlock, Result,
    SourceLocator,
};

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
/// Returns an error if the package reader or reference-specific feature set
/// cannot be constructed.
pub fn ability_reference_supported_features() -> Result<BTreeSet<RequiredFeature>> {
    package_source_supported_features().map_err(invalid_model)
}

/// One public export and the exact interface identity it implements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityExportReference {
    /// Names the export inside the package.
    pub name: LocalKey,
    /// Identifies the public interface retained in the package interface map.
    pub interface: InterfaceKey,
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

/// Bounded public reference projection of one checked signed package document.
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
    /// Maps every package-local interface alias to its exact retained document.
    pub interfaces: BTreeMap<LocalKey, InterfaceDocument>,
    /// Retains every package-authored guarantee semantic and description once.
    pub guarantees: BTreeMap<LocalKey, GuaranteeDeclaration>,
    /// Retains mechanically derived package-owned option declarations.
    pub option_declarations: Vec<PackageOptionDeclaration>,
    /// Retains every package-owned provider implementation, including unexported providers.
    pub implementations: Vec<ProviderImplementation>,
    /// Lists public exports in canonical package order.
    pub exports: Vec<AbilityExportReference>,
    /// Lists declarative lower-interface requirements in canonical alias order.
    pub requirements: Vec<RequirementDeclaration>,
    /// Lists public handler argument/result schemas in canonical name order.
    pub handlers: Vec<AbilityHandlerReference>,
}

impl PackageAbilityReference {
    /// Generates public reference data from one shared checked package contract.
    ///
    /// This constructor derives and retains exact document identities. Its input
    /// has already passed the shared package and retained-interface semantic gate,
    /// but the caller remains responsible for authenticating the enclosing release.
    ///
    /// # Errors
    ///
    /// Returns an error when the checked contract cannot be projected into a
    /// bounded, internally consistent public reference.
    pub fn from_checked_contract(checked: &CheckedPackageContract) -> Result<Self> {
        let package = checked.package();
        let manifest = encode_canonical(package).map_err(invalid_model)?;
        let manifest_sha256 = Sha256Digest::of_bytes(&manifest);
        let package_digest = package.content_digest().map_err(invalid_model)?;
        let interfaces = package
            .interfaces
            .iter()
            .map(|(alias, expected_key)| {
                let document = checked.retained_interface(alias).ok_or_else(|| {
                    invalid(format!(
                        "package interface alias '{}' has no retained document",
                        alias.as_str()
                    ))
                })?;
                let actual_key = document.interface_key().map_err(invalid_model)?;
                if &actual_key != expected_key {
                    return Err(invalid(format!(
                        "package interface alias '{}' resolves to a different interface identity",
                        alias.as_str()
                    )));
                }

                Ok((alias.clone(), document.clone()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut exports = Vec::with_capacity(package.exports.len());
        for export in &package.exports {
            if !interfaces
                .values()
                .any(|document| document.interface_key().ok().as_ref() == Some(&export.interface))
            {
                return Err(invalid(format!(
                    "export '{}' has no exact public interface document",
                    export.name.as_str()
                )));
            }

            let mut matching_provider = None;
            for provider in &package.implementation.providers {
                let descriptor = provider.descriptor_digest().map_err(invalid_model)?;
                if provider.interface == export.interface && descriptor == export.implementation {
                    if matching_provider.replace(provider).is_some() {
                        return Err(invalid(format!(
                            "export '{}' repeats its provider implementation",
                            export.name.as_str()
                        )));
                    }
                }
            }
            matching_provider.ok_or_else(|| {
                invalid(format!(
                    "export '{}' has no exact provider implementation",
                    export.name.as_str()
                ))
            })?;

            exports.push(AbilityExportReference {
                name: export.name.clone(),
                interface: export.interface.clone(),
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
            interfaces,
            guarantees: package.guarantees.clone(),
            option_declarations: package.option_declarations.clone(),
            implementations: package.implementation.providers.clone(),
            exports,
            requirements: package.requirements.clone(),
            handlers,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Resolves the exact retained interface document for an export.
    ///
    /// # Errors
    ///
    /// Returns an error when the export names an interface outside the checked
    /// package-local interface map.
    pub fn interface_for_export(
        &self,
        export: &AbilityExportReference,
    ) -> Result<&InterfaceDocument> {
        self.interfaces
            .values()
            .find(|document| document.interface_key().ok().as_ref() == Some(&export.interface))
            .ok_or_else(|| {
                invalid(format!(
                    "export '{}' has no retained interface document",
                    export.name.as_str()
                ))
            })
    }

    /// Resolves the exact provider implementation selected by an export.
    ///
    /// # Errors
    ///
    /// Returns an error when the export's interface and implementation identity
    /// do not select exactly one retained implementation.
    pub fn implementation_for_export(
        &self,
        export: &AbilityExportReference,
    ) -> Result<&ProviderImplementation> {
        let mut matches = self.implementations.iter().filter(|implementation| {
            implementation.interface == export.interface
                && implementation.descriptor_digest().ok() == Some(export.implementation)
        });
        let implementation = matches.next().ok_or_else(|| {
            invalid(format!(
                "export '{}' has no retained provider implementation",
                export.name.as_str()
            ))
        })?;
        if matches.next().is_some() {
            return Err(invalid(format!(
                "export '{}' repeats its retained provider implementation",
                export.name.as_str()
            )));
        }
        Ok(implementation)
    }

    /// Derives transient option documents from the checked signed declarations.
    ///
    /// The returned values are a renderer/editor DTO. They do not create a
    /// second authored option surface or alter the signed package document.
    #[must_use]
    pub fn documented_options(&self) -> Vec<OptionDocument> {
        self.option_declarations
            .iter()
            .filter(|declaration| declaration.visibility == OptionVisibility::Public)
            .map(|declaration| {
                let path = declaration
                    .path
                    .iter()
                    .cloned()
                    .map(documented_path_segment)
                    .collect::<Vec<_>>();
                OptionDocument {
                    display_path: declaration.path.join("."),
                    path,
                    option_type: declaration.structured_type.clone(),
                    type_signature: declaration.type_signature.clone(),
                    description: vec![ProseBlock::Paragraph {
                        spans: vec![InlineSpan::Text {
                            text: declaration.description.clone(),
                        }],
                    }],
                    default: declaration.default.clone(),
                    example: declaration.example.clone(),
                    visibility: declaration.visibility,
                    read_only: declaration.read_only,
                    deprecated: declaration.deprecated.clone(),
                    replacement: declaration.replacement.as_ref().map(|replacement| {
                        replacement
                            .iter()
                            .cloned()
                            .map(documented_path_segment)
                            .collect()
                    }),
                    owner: OptionOwner {
                        package: self.package.as_str().to_string(),
                        root: declaration.path.first().cloned().unwrap_or_default(),
                        interface_abi: None,
                    },
                    contributable: declaration.contributable,
                    source: Some(SourceLocator {
                        path: declaration.source.path.clone(),
                    }),
                }
            })
            .collect()
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
        for interface in reference.interfaces.values() {
            let interface_bytes = encode_canonical(interface).map_err(invalid_model)?;
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
        if self.interfaces.len() > max_items
            || self.guarantees.len() > max_items
            || self.option_declarations.len() > max_items
            || self.implementations.len() > max_items
            || self.exports.len() > max_items
            || self.requirements.len() > max_items
            || self.handlers.len() > max_items
        {
            return Err(invalid("ability reference exceeds its collection limit"));
        }

        let mut interface_identities = BTreeMap::new();
        for (alias, interface) in &self.interfaces {
            let identity = interface.interface_key().map_err(invalid_model)?;
            if let Some(previous) = interface_identities.insert(identity, alias) {
                // Multiple aliases may intentionally name one declaration, but
                // the exact document must remain identical under those aliases.
                if self.interfaces.get(previous) != Some(interface) {
                    return Err(invalid(
                        "ability interface aliases resolve to inconsistent documents",
                    ));
                }
            }
        }
        for guarantee in self.guarantees.values() {
            guarantee.key().map_err(invalid_model)?;
            for text in [&guarantee.semantics, &guarantee.description] {
                if text.is_empty()
                    || text.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes
                    || text.chars().any(char::is_control)
                {
                    return Err(invalid("ability guarantee contains invalid text"));
                }
            }
        }
        validate_package_option_declarations(&self.option_declarations, &ABILITY_LIMITS_V1)
            .map_err(invalid_model)?;
        let mut implementation_names = BTreeSet::new();
        let mut implementation_identities = BTreeSet::new();
        for implementation in &self.implementations {
            let descriptor = implementation.descriptor_digest().map_err(invalid_model)?;
            if !interface_identities.contains_key(&implementation.interface) {
                return Err(invalid(
                    "ability implementation references an interface outside the package declarations",
                ));
            }
            if !implementation_names.insert(implementation.name.clone()) {
                return Err(invalid("ability reference repeats an implementation name"));
            }
            if !implementation_identities.insert((implementation.interface.clone(), descriptor)) {
                return Err(invalid(
                    "ability reference repeats an implementation identity",
                ));
            }
        }
        if self.implementations.windows(2).any(|pair| {
            pair[0].interface > pair[1].interface
                || (pair[0].interface == pair[1].interface && pair[0].name >= pair[1].name)
        }) {
            return Err(invalid(
                "ability reference implementations are not in canonical interface/name order",
            ));
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
            if !interface_identities.contains_key(&export.interface) {
                return Err(invalid(
                    "ability export references an interface outside the package declarations",
                ));
            }
            if !implementation_identities
                .contains(&(export.interface.clone(), export.implementation))
            {
                return Err(invalid(
                    "ability export references an implementation outside the package declarations",
                ));
            }
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

fn documented_path_segment(value: String) -> PathSegment {
    let wildcard = value
        .strip_prefix('<')
        .and_then(|name| name.strip_suffix('>'))
        .filter(|name| !name.is_empty());
    match wildcard {
        Some(name) => PathSegment::Wildcard {
            name: name.to_string(),
        },
        None => PathSegment::Literal { value },
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
    use aos_ability_model::{ArtifactReference, RequirementStrength};

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
            interfaces: BTreeMap::new(),
            guarantees: BTreeMap::new(),
            option_declarations: Vec::new(),
            implementations: Vec::new(),
            exports: Vec::new(),
            requirements: Vec::new(),
            handlers: Vec::new(),
        }
    }

    fn implementation(
        interface: InterfaceKey,
        requirements: Vec<RequirementDeclaration>,
    ) -> ProviderImplementation {
        ProviderImplementation {
            name: LocalKey::new("echo").expect("implementation name"),
            description: "Implements the echo test interface.".to_string(),
            interface,
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes(b"content"),
                store_path: "/nix/store/echo-provider".to_string(),
                nar_hash: Sha256Digest::of_bytes(b"nar"),
                closure: Sha256Digest::of_bytes(b"closure"),
            },
            requirements,
            desired_schema: None,
            composition_schema: None,
            provider_module: None,
            handler: None,
            owns_resource_kinds: Vec::new(),
            guarantees: Vec::new(),
            state_format: None,
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
    fn state_format_reference_round_trips_only_for_the_new_reader() {
        let mut reference = reference();
        reference.required_features.push(
            RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)
                .expect("valid state-format feature"),
        );
        let bytes = reference.canonical_json().expect("encode reference");
        let old_reader =
            BTreeSet::from([RequiredFeature::new("abilities-v1").expect("valid feature")]);

        assert!(PackageAbilityReference::from_canonical_json(&bytes, &old_reader).is_err());
        let decoded = PackageAbilityReference::from_canonical_json(
            &bytes,
            &ability_reference_supported_features().expect("new reader features"),
        )
        .expect("new reader accepts state-format reference");
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
    fn decoding_requires_the_complete_package_documentation_projection() {
        let reference = reference();
        let supported =
            BTreeSet::from([RequiredFeature::new("abilities-v1").expect("valid feature name")]);

        for field in ["option_declarations", "implementations"] {
            let mut value = serde_json::to_value(&reference).expect("serialize reference");
            value
                .as_object_mut()
                .expect("reference object")
                .remove(field);
            let bytes =
                aos_contract::canonical::to_vec(&value).expect("encode incomplete reference");

            assert!(PackageAbilityReference::from_canonical_json(&bytes, &supported).is_err());
        }
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
        let interface_key = interface.interface_key().expect("interface key");
        let mut reference = reference();
        reference
            .interfaces
            .insert(LocalKey::new("echo").expect("interface alias"), interface);
        let implementation = implementation(interface_key.clone(), Vec::new());
        let implementation_key = implementation
            .descriptor_digest()
            .expect("implementation descriptor");
        reference.implementations.push(implementation);
        reference.exports.push(AbilityExportReference {
            name: LocalKey::new("echo").expect("valid export name"),
            interface: interface_key,
            implementation: implementation_key,
        });
        let bytes = reference.canonical_json().expect("encode reference");

        assert!(PackageAbilityReference::from_canonical_json(&bytes, &supported).is_err());
    }

    #[test]
    fn provider_requirements_are_resolved_from_the_exact_implementation() {
        let supported = ability_reference_supported_features().expect("reader features");
        let interface = decode_canonical::<InterfaceDocument>(
            include_bytes!("../../../tests/abilities/fixtures/interface.json"),
            ABILITY_LIMITS_V1,
            &supported,
        )
        .expect("decode interface fixture");
        let interface_key = interface.interface_key().expect("interface key");
        let requirement = RequirementDeclaration {
            description: "Describes this consumed ability.".to_string(),
            alias: LocalKey::new("runtime").expect("requirement alias"),
            accepted_interfaces: vec![interface_key.clone().into()],
            methods: Vec::new(),
            guarantees: Vec::new(),
            strength: RequirementStrength::Required,
            fallback: None,
        };
        let mut reference = reference();
        reference
            .interfaces
            .insert(LocalKey::new("echo").expect("interface alias"), interface);
        let implementation = implementation(interface_key.clone(), vec![requirement.clone()]);
        let implementation_key = implementation
            .descriptor_digest()
            .expect("implementation descriptor");
        reference.implementations.push(implementation);
        reference.exports.push(AbilityExportReference {
            name: LocalKey::new("echo").expect("export name"),
            interface: interface_key,
            implementation: implementation_key,
        });

        let bytes = reference.canonical_json().expect("encode reference");
        let decoded = PackageAbilityReference::from_canonical_json(&bytes, &supported)
            .expect("decode provider requirements");
        assert_eq!(decoded, reference);
        assert_eq!(
            decoded
                .implementation_for_export(&decoded.exports[0])
                .expect("export implementation")
                .requirements,
            vec![requirement]
        );
    }
}
