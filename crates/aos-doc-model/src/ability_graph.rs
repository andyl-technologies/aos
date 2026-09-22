//! Release-wide ability relationships derived from checked package references.
//!
//! The graph is a disposable read projection. Package ability references remain
//! the signed authority; this module deduplicates their exact interface
//! documents and resolves requirement selectors against public exports for one
//! release and platform.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{
    GuaranteeKey, InterfaceDocument, InterfaceKey, LocalKey, RequirementDeclaration,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{DocumentationError, PackageAbilityReference, Result};

/// Schema discriminator for a release-wide ability graph.
pub const RELEASE_ABILITY_GRAPH_SCHEMA: &str = "aos.release-ability-graph/v1";

/// Maximum canonical graph size accepted by readers.
pub const MAX_RELEASE_ABILITY_GRAPH_BYTES: usize = 32 * 1024 * 1024;

/// Identifies one package version within a release platform.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAbilityPackageId {
    /// Names the package.
    pub name: LocalKey,
    /// Selects the package version.
    pub version: String,
}

/// Retains the authenticated identities for one graph package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAbilityPackage {
    /// Identifies the package in graph relations.
    pub id: ReleaseAbilityPackageId,
    /// Identifies the exact canonical package manifest bytes.
    pub manifest_sha256: Sha256Digest,
    /// Identifies the package manifest semantics.
    pub package_digest: Sha256Digest,
}

/// Retains one exact shared interface contract once for the release graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAbilityInterface {
    /// Identifies the exact public contract.
    pub key: InterfaceKey,
    /// Retains the checked public contract document.
    pub document: InterfaceDocument,
}

/// Identifies one public package export.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAbilityProviderId {
    /// Identifies the package containing the export.
    pub package: ReleaseAbilityPackageId,
    /// Names the public export inside the package.
    pub export: LocalKey,
}

/// Describes one public provider available to release consumers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAbilityProvider {
    /// Identifies this public export in graph relations.
    pub id: ReleaseAbilityProviderId,
    /// Names the package-local implementation selected by the export.
    pub implementation: LocalKey,
    /// Identifies the implementation descriptor selected by the export.
    pub implementation_digest: Sha256Digest,
    /// Identifies the exact public interface implemented by the provider.
    pub interface: InterfaceKey,
    /// Names the exact interface methods supported by this implementation.
    pub methods: Vec<LocalKey>,
    /// Names the exact execution guarantees supplied by this implementation.
    pub guarantees: Vec<GuaranteeKey>,
}

/// Identifies a package-level or implementation-level requirement.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAbilityRequirementId {
    /// Identifies the consuming package.
    pub package: ReleaseAbilityPackageId,
    /// Names the consuming implementation, or remains absent for package imports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation: Option<LocalKey>,
    /// Names the requirement within its consumer scope.
    pub alias: LocalKey,
}

/// Describes one consumed ability and all exact release matches.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAbilityRequirement {
    /// Identifies the requirement in the release graph.
    pub id: ReleaseAbilityRequirementId,
    /// Retains the checked provider-neutral requirement declaration.
    pub declaration: RequirementDeclaration,
    /// Lists exact interface contracts admitted by the requirement selectors.
    pub matching_interfaces: Vec<InterfaceKey>,
    /// Lists public release providers that may satisfy the requirement.
    pub matching_providers: Vec<ReleaseAbilityProviderId>,
}

/// Complete ability relationships for one release platform.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAbilityGraph {
    /// Carries [`RELEASE_ABILITY_GRAPH_SCHEMA`].
    pub schema: String,
    /// Selects the release platform shared by every package reference.
    pub platform: String,
    /// Lists package identities in canonical order.
    pub packages: Vec<ReleaseAbilityPackage>,
    /// Lists exact shared interface contracts in canonical key order.
    pub interfaces: Vec<ReleaseAbilityInterface>,
    /// Lists public providers in canonical identifier order.
    pub providers: Vec<ReleaseAbilityProvider>,
    /// Lists consumed abilities and their resolved release matches.
    pub requirements: Vec<ReleaseAbilityRequirement>,
}

impl ReleaseAbilityGraph {
    /// Builds a graph from verified package references for one release platform.
    ///
    /// # Errors
    ///
    /// Returns an error when a reference is invalid, a package identity repeats,
    /// or two references retain different documents for one exact interface key.
    pub fn from_references<'a>(
        platform: impl Into<String>,
        references: impl IntoIterator<Item = &'a PackageAbilityReference>,
    ) -> Result<Self> {
        let platform = platform.into();
        if platform.is_empty() {
            return Err(invalid("release ability graph platform must not be empty"));
        }

        let mut packages = BTreeMap::new();
        let mut interfaces = BTreeMap::new();
        let mut providers = BTreeMap::new();
        let mut pending_requirements = Vec::new();

        for reference in references {
            reference.validate()?;
            let package_id = ReleaseAbilityPackageId {
                name: reference.package.clone(),
                version: reference.version.clone(),
            };
            let package = ReleaseAbilityPackage {
                id: package_id.clone(),
                manifest_sha256: reference.manifest_sha256,
                package_digest: reference.package_digest,
            };
            if packages.insert(package_id.clone(), package).is_some() {
                return Err(invalid(format!(
                    "release ability graph repeats package '{}@{}'",
                    package_id.name, package_id.version
                )));
            }

            for document in reference.interfaces.values() {
                let key = document.interface_key().map_err(invalid_model)?;
                if let Some(previous) = interfaces.insert(key.clone(), document.clone()) {
                    if previous != *document {
                        return Err(invalid(
                            "release ability graph has inconsistent exact interface documents",
                        ));
                    }
                }
            }

            for export in &reference.exports {
                let implementation = reference.implementation_for_export(export)?;
                let id = ReleaseAbilityProviderId {
                    package: package_id.clone(),
                    export: export.name.clone(),
                };
                let provider = ReleaseAbilityProvider {
                    id: id.clone(),
                    implementation: implementation.name.clone(),
                    implementation_digest: export.implementation,
                    interface: export.interface.clone(),
                    methods: implementation.methods.clone(),
                    guarantees: implementation.guarantees.clone(),
                };
                if providers.insert(id, provider).is_some() {
                    return Err(invalid("release ability graph repeats a public export"));
                }
            }

            append_requirements(
                &mut pending_requirements,
                &package_id,
                None,
                &reference.requirements,
            );
            for implementation in &reference.implementations {
                append_requirements(
                    &mut pending_requirements,
                    &package_id,
                    Some(&implementation.name),
                    &implementation.requirements,
                );
            }
        }

        let mut requirements = Vec::with_capacity(pending_requirements.len());
        for (id, declaration) in pending_requirements {
            let matching_interfaces = interfaces
                .keys()
                .filter(|key| {
                    declaration
                        .accepted_interfaces
                        .iter()
                        .any(|selector| selector.matches(key))
                })
                .cloned()
                .collect::<Vec<_>>();
            let matching_interface_set = matching_interfaces.iter().collect::<BTreeSet<_>>();
            let matching_providers = providers
                .values()
                .filter(|provider| {
                    matching_interface_set.contains(&provider.interface)
                        && declaration
                            .methods
                            .iter()
                            .all(|method| provider.methods.contains(method))
                        && declaration
                            .guarantees
                            .iter()
                            .all(|guarantee| provider.guarantees.contains(guarantee))
                })
                .map(|provider| provider.id.clone())
                .collect();
            requirements.push(ReleaseAbilityRequirement {
                id,
                declaration,
                matching_interfaces,
                matching_providers,
            });
        }
        requirements.sort_by(|left, right| left.id.cmp(&right.id));

        let graph = Self {
            schema: RELEASE_ABILITY_GRAPH_SCHEMA.to_string(),
            platform,
            packages: packages.into_values().collect(),
            interfaces: interfaces
                .into_iter()
                .map(|(key, document)| ReleaseAbilityInterface { key, document })
                .collect(),
            providers: providers.into_values().collect(),
            requirements,
        };
        graph.validate()?;
        Ok(graph)
    }

    /// Decodes and verifies exact canonical graph JSON.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized data.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RELEASE_ABILITY_GRAPH_BYTES {
            return Err(invalid("release ability graph exceeds the 32 MiB limit"));
        }
        let graph: Self = serde_json::from_slice(bytes)?;
        graph.validate()?;
        if graph.canonical_json()? != bytes {
            return Err(invalid("release ability graph is not canonical JSON"));
        }
        Ok(graph)
    }

    /// Encodes the graph as exact canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical encoding fails.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = aos_contract::canonical::to_vec(self).map_err(invalid_model)?;
        if bytes.len() > MAX_RELEASE_ABILITY_GRAPH_BYTES {
            return Err(invalid("release ability graph exceeds the 32 MiB limit"));
        }
        Ok(bytes)
    }

    /// Validates graph identities, canonical ordering, and relation targets.
    ///
    /// # Errors
    ///
    /// Returns an error when graph rows repeat, are out of order, or reference
    /// packages, interfaces, or providers absent from the graph.
    pub fn validate(&self) -> Result<()> {
        if self.schema != RELEASE_ABILITY_GRAPH_SCHEMA {
            return Err(invalid(format!(
                "unsupported release ability graph schema '{}'",
                self.schema
            )));
        }
        if self.platform.is_empty() {
            return Err(invalid("release ability graph platform must not be empty"));
        }

        ensure_strict_order(&self.packages, |left, right| left.id < right.id, "packages")?;
        ensure_strict_order(
            &self.interfaces,
            |left, right| left.key < right.key,
            "interfaces",
        )?;
        ensure_strict_order(
            &self.providers,
            |left, right| left.id < right.id,
            "providers",
        )?;
        ensure_strict_order(
            &self.requirements,
            |left, right| left.id < right.id,
            "requirements",
        )?;

        let package_ids = self
            .packages
            .iter()
            .map(|package| &package.id)
            .collect::<BTreeSet<_>>();
        let interface_keys = self
            .interfaces
            .iter()
            .map(|interface| &interface.key)
            .collect::<BTreeSet<_>>();
        let provider_ids = self
            .providers
            .iter()
            .map(|provider| &provider.id)
            .collect::<BTreeSet<_>>();

        for interface in &self.interfaces {
            if interface.document.interface_key().map_err(invalid_model)? != interface.key {
                return Err(invalid("release ability graph interface key mismatch"));
            }
        }
        for provider in &self.providers {
            if !package_ids.contains(&provider.id.package) {
                return Err(invalid("release ability provider names an absent package"));
            }
            if !interface_keys.contains(&provider.interface) {
                return Err(invalid(
                    "release ability provider names an absent interface",
                ));
            }
        }
        for requirement in &self.requirements {
            if !package_ids.contains(&requirement.id.package)
                || requirement.id.alias != requirement.declaration.alias
            {
                return Err(invalid("release ability requirement identity mismatch"));
            }
            ensure_strict_values(&requirement.matching_interfaces, "matching interfaces")?;
            ensure_strict_values(&requirement.matching_providers, "matching providers")?;
            if requirement
                .matching_interfaces
                .iter()
                .any(|key| !interface_keys.contains(key))
                || requirement
                    .matching_providers
                    .iter()
                    .any(|id| !provider_ids.contains(id))
            {
                return Err(invalid(
                    "release ability requirement names an absent graph node",
                ));
            }
            let expected_interfaces = self
                .interfaces
                .iter()
                .filter(|interface| {
                    requirement
                        .declaration
                        .accepted_interfaces
                        .iter()
                        .any(|selector| selector.matches(&interface.key))
                })
                .map(|interface| interface.key.clone())
                .collect::<Vec<_>>();
            if requirement.matching_interfaces != expected_interfaces {
                return Err(invalid(
                    "release ability requirement has incorrect interface matches",
                ));
            }
            let expected_providers = self
                .providers
                .iter()
                .filter(|provider| {
                    expected_interfaces.contains(&provider.interface)
                        && requirement
                            .declaration
                            .methods
                            .iter()
                            .all(|method| provider.methods.contains(method))
                        && requirement
                            .declaration
                            .guarantees
                            .iter()
                            .all(|guarantee| provider.guarantees.contains(guarantee))
                })
                .map(|provider| provider.id.clone())
                .collect::<Vec<_>>();
            if requirement.matching_providers != expected_providers {
                return Err(invalid(
                    "release ability requirement has incorrect provider matches",
                ));
            }
            for provider_id in &requirement.matching_providers {
                let provider = self
                    .providers
                    .binary_search_by(|candidate| candidate.id.cmp(provider_id))
                    .ok()
                    .and_then(|index| self.providers.get(index))
                    .ok_or_else(|| invalid("release ability requirement provider is absent"))?;
                if !requirement
                    .matching_interfaces
                    .contains(&provider.interface)
                {
                    return Err(invalid(
                        "release ability requirement provider does not implement a matched interface",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn append_requirements(
    output: &mut Vec<(ReleaseAbilityRequirementId, RequirementDeclaration)>,
    package: &ReleaseAbilityPackageId,
    implementation: Option<&LocalKey>,
    requirements: &[RequirementDeclaration],
) {
    output.extend(requirements.iter().cloned().map(|declaration| {
        (
            ReleaseAbilityRequirementId {
                package: package.clone(),
                implementation: implementation.cloned(),
                alias: declaration.alias.clone(),
            },
            declaration,
        )
    }));
}

fn ensure_strict_order<T>(
    values: &[T],
    ordered: impl Fn(&T, &T) -> bool,
    label: &str,
) -> Result<()> {
    if values.windows(2).any(|pair| !ordered(&pair[0], &pair[1])) {
        return Err(invalid(format!(
            "release ability graph {label} are not in strict canonical order"
        )));
    }
    Ok(())
}

fn ensure_strict_values<T: Ord>(values: &[T], label: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(format!(
            "release ability graph {label} are not in strict canonical order"
        )));
    }
    Ok(())
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
    use aos_ability_model::{
        ABILITY_LIMITS_V1, ArtifactReference, InterfaceName, InterfaceSelector,
        ProviderImplementation, RequiredFeature, RequirementStrength, decode_canonical,
    };

    fn empty_reference(package: &str) -> PackageAbilityReference {
        PackageAbilityReference {
            schema: crate::ABILITY_REFERENCE_SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new("abilities-v1").expect("valid feature")],
            package: LocalKey::new(package).expect("valid package"),
            version: "1.0.0".to_string(),
            manifest_sha256: Sha256Digest::of_bytes(format!("{package} manifest")),
            package_digest: Sha256Digest::of_bytes(format!("{package} package")),
            interfaces: BTreeMap::new(),
            guarantees: BTreeMap::new(),
            option_declarations: Vec::new(),
            implementations: Vec::new(),
            exports: Vec::new(),
            requirements: Vec::new(),
            handlers: Vec::new(),
        }
    }

    fn interface_document() -> InterfaceDocument {
        let supported = crate::ability_reference_supported_features().expect("reader features");
        decode_canonical(
            include_bytes!("../../../tests/abilities/fixtures/interface.json"),
            ABILITY_LIMITS_V1,
            &supported,
        )
        .expect("decode interface fixture")
    }

    fn provider(
        package: &str,
        interface: &InterfaceDocument,
        supports_methods: bool,
    ) -> PackageAbilityReference {
        let key = interface.interface_key().expect("interface key");
        let implementation = ProviderImplementation {
            name: LocalKey::new("default").expect("implementation name"),
            description: "Provides the shared contract.".to_string(),
            interface: key.clone(),
            methods: supports_methods
                .then(|| interface.interface.methods.keys().cloned().collect())
                .unwrap_or_default(),
            guarantees: supports_methods
                .then(|| interface.interface.guarantees.clone())
                .unwrap_or_default(),
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes(format!("{package} content")),
                store_path: format!("/nix/store/{package}-provider"),
                nar_hash: Sha256Digest::of_bytes(format!("{package} nar")),
                closure: Sha256Digest::of_bytes(format!("{package} closure")),
            },
            requirements: Vec::new(),
            desired_schema: None,
            composition_schema: None,
            provider_module: None,
            handler: None,
            owns_resource_kinds: Vec::new(),
            state_format: None,
        };
        let digest = implementation
            .descriptor_digest()
            .expect("implementation digest");
        let mut reference = empty_reference(package);
        reference.interfaces.insert(
            LocalKey::new("shared").expect("interface alias"),
            interface.clone(),
        );
        reference.implementations.push(implementation);
        reference.exports.push(crate::AbilityExportReference {
            name: LocalKey::new("service").expect("export name"),
            interface: key,
            implementation: digest,
        });
        reference
    }

    #[test]
    fn graph_resolves_cross_package_ambiguity_and_unresolved_requirements() {
        let interface = interface_document();
        let key = interface.interface_key().expect("interface key");
        let mut consumer = empty_reference("consumer");
        consumer.requirements = vec![
            RequirementDeclaration {
                alias: LocalKey::new("missing").expect("requirement alias"),
                description: "Needs an unpublished contract.".to_string(),
                accepted_interfaces: vec![InterfaceSelector {
                    name: InterfaceName::new("aos.missing").expect("interface name"),
                    abi: key.abi,
                    descriptor: None,
                }],
                methods: Vec::new(),
                guarantees: Vec::new(),
                strength: RequirementStrength::Required,
                fallback: None,
            },
            RequirementDeclaration {
                alias: LocalKey::new("observe").expect("requirement alias"),
                description: "Needs the shared contract's observation method.".to_string(),
                accepted_interfaces: vec![key.clone().into()],
                methods: interface.interface.methods.keys().cloned().collect(),
                guarantees: interface.interface.guarantees.clone(),
                strength: RequirementStrength::Required,
                fallback: None,
            },
            RequirementDeclaration {
                alias: LocalKey::new("runtime").expect("requirement alias"),
                description: "Accepts either provider of the shared contract.".to_string(),
                accepted_interfaces: vec![key.clone().into()],
                methods: Vec::new(),
                guarantees: Vec::new(),
                strength: RequirementStrength::Required,
                fallback: None,
            },
        ];
        let first = provider("provider-a", &interface, true);
        let second = provider("provider-b", &interface, false);

        let graph =
            ReleaseAbilityGraph::from_references("x86_64-linux", [&consumer, &first, &second])
                .expect("build release graph");

        assert_eq!(graph.interfaces.len(), 1);
        assert_eq!(graph.providers.len(), 2);
        assert!(graph.requirements[0].matching_providers.is_empty());
        assert_eq!(graph.requirements[1].matching_interfaces, vec![key]);
        assert_eq!(graph.requirements[1].matching_providers.len(), 1);
        assert_eq!(graph.requirements[2].matching_interfaces.len(), 1);
        assert_eq!(graph.requirements[2].matching_providers.len(), 2);
        let bytes = graph.canonical_json().expect("canonical graph");
        assert_eq!(
            ReleaseAbilityGraph::from_canonical_json(&bytes).expect("decode graph"),
            graph
        );
    }
}
