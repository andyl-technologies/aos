//! Verified package schema projection shared by CLI, Hub, and language tooling.
//!
//! The response keeps the two authenticated source objects intact. It derives
//! editor-facing option and method rows from the checked ability reference and
//! binds them to both source identities. It never extends or rewrites the
//! canonical package documentation artifact.

use aos_ability_model::{InterfaceKey, LocalKey, MethodDescriptor};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{
    DocumentationError, OptionDocument, PackageAbilityReference, PackageDocumentation, Result,
};

/// Exact schema discriminator for package tooling responses.
pub const PACKAGE_TOOLING_RESPONSE_SCHEMA: &str = "aos.package-tooling-response/v1";

/// Media type for canonical package tooling response JSON.
pub const PACKAGE_TOOLING_RESPONSE_FORMAT: &str = "aos.package-tooling-response/v1+json";

/// Maximum canonical response size admitted by version 1.
pub const MAX_PACKAGE_TOOLING_RESPONSE_BYTES: usize = 12 * 1024 * 1024;

const MAX_TOOLING_METHODS: usize = 16_384;

/// Identities that bind a tooling projection to its two authenticated inputs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageToolingIdentity {
    /// SHA-256 of the exact canonical package documentation bytes.
    pub documentation_sha256: String,
    /// Semantic configuration identity carried by package documentation.
    pub semantic_schema_sha256: String,
    /// SHA-256 of the exact canonical package ability manifest bytes.
    pub ability_manifest_sha256: Sha256Digest,
    /// Domain-separated semantic identity of the checked package manifest.
    pub ability_package_digest: Sha256Digest,
}

/// One exported interface method and its exact checked schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageToolingMethodSchema {
    /// Names the public package export through which the method is available.
    pub export: LocalKey,
    /// Identifies the exact retained interface document.
    pub interface: InterfaceKey,
    /// Names the method inside that interface.
    pub method: LocalKey,
    /// Retains the complete provider-neutral method descriptor.
    pub descriptor: MethodDescriptor,
}

/// One checked, versioned package schema response for tools and editors.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageToolingResponse {
    /// Carries [`PACKAGE_TOOLING_RESPONSE_SCHEMA`].
    pub schema: String,
    /// Binds every derived field to both authenticated inputs.
    pub identity: PackageToolingIdentity,
    /// Retains the unchanged canonical package documentation object.
    pub documentation: PackageDocumentation,
    /// Retains the unchanged checked package ability reference.
    pub ability_reference: PackageAbilityReference,
    /// Public option schemas derived from `ability_reference`.
    pub options: Vec<OptionDocument>,
    /// Public exported method schemas derived from `ability_reference`.
    pub methods: Vec<PackageToolingMethodSchema>,
}

impl PackageToolingResponse {
    /// Derives a tooling response from its two independently authenticated inputs.
    ///
    /// # Errors
    ///
    /// Returns an error when an input is invalid, the package coordinates do
    /// not match, or the resulting response exceeds the version-1 bound.
    pub fn new(
        documentation: PackageDocumentation,
        ability_reference: PackageAbilityReference,
    ) -> Result<Self> {
        documentation.validate()?;
        ability_reference.validate()?;
        if ability_reference.package.as_str() != documentation.package.name
            || ability_reference.version != documentation.package.version
        {
            return Err(invalid(
                "package documentation and ability reference coordinates differ",
            ));
        }

        let identity = identity_for(&documentation, &ability_reference)?;
        let options = ability_reference.documented_options();
        let methods = method_schemas(&ability_reference)?;
        let response = Self {
            schema: PACKAGE_TOOLING_RESPONSE_SCHEMA.to_string(),
            identity,
            documentation,
            ability_reference,
            options,
            methods,
        };
        response.validate()?;
        Ok(response)
    }

    /// Decodes and verifies exact canonical tooling response JSON.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, oversized, unsupported,
    /// or internally inconsistent response bytes.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PACKAGE_TOOLING_RESPONSE_BYTES {
            return Err(invalid("package tooling response exceeds the 12 MiB limit"));
        }
        let response: Self = aos_contract::canonical::from_slice(bytes, "package tooling response")
            .map_err(invalid_model)?;
        response.validate()?;
        if response.canonical_json()? != bytes {
            return Err(invalid("package tooling response is not canonical JSON"));
        }
        Ok(response)
    }

    /// Encodes the response as exact canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical encoding fails, or when
    /// the encoded response exceeds the version-1 bound.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = aos_contract::canonical::to_vec(self).map_err(invalid_model)?;
        if bytes.len() > MAX_PACKAGE_TOOLING_RESPONSE_BYTES {
            return Err(invalid("package tooling response exceeds the 12 MiB limit"));
        }
        Ok(bytes)
    }

    /// Computes the content identity used as the response ETag.
    ///
    /// # Errors
    ///
    /// Returns an error when the response cannot be validated and encoded.
    pub fn response_sha256(&self) -> Result<String> {
        Ok(Sha256Digest::of_bytes(&self.canonical_json()?).to_string())
    }

    /// Recomputes every identity and derived schema from the source objects.
    ///
    /// # Errors
    ///
    /// Returns an error when an input is invalid, identities differ, or any
    /// option or method row was not derived from the checked ability reference.
    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKAGE_TOOLING_RESPONSE_SCHEMA {
            return Err(invalid(format!(
                "unsupported package tooling response schema '{}'",
                self.schema
            )));
        }
        self.documentation.validate()?;
        self.ability_reference.validate()?;
        if self.ability_reference.package.as_str() != self.documentation.package.name
            || self.ability_reference.version != self.documentation.package.version
        {
            return Err(invalid(
                "package documentation and ability reference coordinates differ",
            ));
        }
        if self.identity != identity_for(&self.documentation, &self.ability_reference)? {
            return Err(invalid("package tooling response identity mismatch"));
        }
        if self.options != self.ability_reference.documented_options() {
            return Err(invalid(
                "package tooling option schemas were not derived from the ability reference",
            ));
        }
        if self.methods != method_schemas(&self.ability_reference)? {
            return Err(invalid(
                "package tooling method schemas were not derived from the ability reference",
            ));
        }
        Ok(())
    }
}

fn identity_for(
    documentation: &PackageDocumentation,
    ability_reference: &PackageAbilityReference,
) -> Result<PackageToolingIdentity> {
    Ok(PackageToolingIdentity {
        documentation_sha256: documentation.document_sha256()?,
        semantic_schema_sha256: documentation.identity.semantic_schema_sha256.clone(),
        ability_manifest_sha256: ability_reference.manifest_sha256,
        ability_package_digest: ability_reference.package_digest,
    })
}

fn method_schemas(
    ability_reference: &PackageAbilityReference,
) -> Result<Vec<PackageToolingMethodSchema>> {
    let mut methods = Vec::new();
    for export in &ability_reference.exports {
        let interface = ability_reference.interface_for_export(export)?;
        if methods
            .len()
            .saturating_add(interface.interface.methods.len())
            > MAX_TOOLING_METHODS
        {
            return Err(invalid("too many projected package method schemas"));
        }
        methods.extend(
            interface
                .interface
                .methods
                .iter()
                .map(|(method, descriptor)| PackageToolingMethodSchema {
                    export: export.name.clone(),
                    interface: export.interface.clone(),
                    method: method.clone(),
                    descriptor: descriptor.clone(),
                }),
        );
    }
    Ok(methods)
}

fn invalid(message: impl Into<String>) -> DocumentationError {
    DocumentationError::Invalid(message.into())
}

fn invalid_model(error: impl std::fmt::Display) -> DocumentationError {
    invalid(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use aos_ability_model::{
        ABILITY_LIMITS_V1, ArtifactReference, InterfaceDocument, OptionSource, OptionType,
        OptionVisibility, PackageOptionDeclaration, ProviderImplementation, RequiredFeature,
        decode_canonical,
    };

    use crate::{DocumentationIdentity, DocumentedPackage};

    fn documentation() -> PackageDocumentation {
        let mut document = PackageDocumentation {
            schema: crate::DOCUMENT_SCHEMA.to_string(),
            package: DocumentedPackage {
                name: "fixture".to_string(),
                version: "1".to_string(),
                platform: "x86_64-linux".to_string(),
                summary: "Tooling fixture".to_string(),
                homepage: None,
                license: "Apache-2.0".to_string(),
            },
            identity: DocumentationIdentity {
                semantic_schema_sha256: String::new(),
                runtime_nar_hash: format!("sha256:{}", "a".repeat(64)),
                source_nar_hash: format!("sha256:{}", "b".repeat(64)),
            },
        };
        document.identity.semantic_schema_sha256 = document
            .computed_semantic_schema_sha256()
            .expect("semantic identity");
        document
    }

    fn ability_reference() -> PackageAbilityReference {
        let supported = crate::ability_reference_supported_features().expect("reader features");
        let interface = decode_canonical::<InterfaceDocument>(
            include_bytes!("../../../tests/abilities/fixtures/interface.json"),
            ABILITY_LIMITS_V1,
            &supported,
        )
        .expect("interface fixture");
        let interface_key = interface.interface_key().expect("interface identity");
        let implementation = ProviderImplementation {
            name: LocalKey::new("echo-provider").expect("implementation"),
            description: "Implements the fixture interface.".to_string(),
            interface: interface_key.clone(),
            guarantees: Vec::new(),
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes("provider-content"),
                store_path: "/nix/store/00000000000000000000000000000000-provider".to_string(),
                nar_hash: Sha256Digest::of_bytes("provider-nar"),
                closure: Sha256Digest::of_bytes("provider-closure"),
            },
            requirements: Vec::new(),
            desired_schema: None,
            provider_module: None,
            handler: None,
            owns_resource_kinds: Vec::new(),
            state_format: None,
        };
        let implementation_key = implementation
            .descriptor_digest()
            .expect("implementation identity");

        PackageAbilityReference {
            schema: crate::ABILITY_REFERENCE_SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new("abilities-v1").expect("feature")],
            package: LocalKey::new("fixture").expect("package"),
            version: "1".to_string(),
            manifest_sha256: Sha256Digest::of_bytes("manifest"),
            package_digest: Sha256Digest::of_bytes("package"),
            interfaces: BTreeMap::from([(LocalKey::new("echo").expect("alias"), interface)]),
            guarantees: BTreeMap::new(),
            option_declarations: vec![PackageOptionDeclaration {
                path: vec!["fixture".to_string(), "enable".to_string()],
                type_signature: "bool".to_string(),
                structured_type: OptionType::Bool,
                description: "Enables the fixture.".to_string(),
                default: None,
                example: None,
                visibility: OptionVisibility::Public,
                read_only: false,
                contributable: false,
                deprecated: None,
                replacement: None,
                source: OptionSource {
                    path: aos_ability_model::RelativePath::new("module.nix").expect("source path"),
                },
            }],
            implementations: vec![implementation],
            exports: vec![crate::AbilityExportReference {
                name: LocalKey::new("echo").expect("export"),
                interface: interface_key,
                implementation: implementation_key,
            }],
            requirements: Vec::new(),
            handlers: Vec::new(),
        }
    }

    #[test]
    fn response_derives_and_revalidates_every_schema_row() {
        let response = PackageToolingResponse::new(documentation(), ability_reference())
            .expect("checked tooling response");
        assert_eq!(response.options.len(), 1);
        assert!(!response.methods.is_empty());

        let bytes = response.canonical_json().expect("canonical response");
        let decoded =
            PackageToolingResponse::from_canonical_json(&bytes).expect("decode checked response");
        assert_eq!(decoded, response);

        let mut forged = response;
        forged.options.clear();
        assert!(forged.canonical_json().is_err());
    }
}
