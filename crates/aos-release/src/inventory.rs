//! Closed package eligibility inventory emitted by Nix evaluation.
//!
//! ```json
//! {"schema_version":"aos.release.package-inventory/v1",
//!  "platforms":["x86_64-linux","aarch64-linux","x86_64-darwin","aarch64-darwin"],
//!  "packages":[{"name":"example","platforms":[{"platform":"x86_64-linux",
//!  "decision":{"state":"eligible"}}]}]}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::{require_identifier, require_store_path};
use crate::plan::{PackagePlan, PlannedArtifact, PlannedArtifactSet, PlatformCell};
use crate::platform::{MatrixCell, Platform, require_complete_package_platforms};

/// Exact schema emitted by the Nix package inventory.
pub const PACKAGE_INVENTORY_V1: &str = "aos.release.package-inventory/v1";

/// Exact schema for target-specific evaluated Nix identities.
pub const DERIVATION_INVENTORY_V1: &str = "aos.release.derivation-inventory/v1";

/// Nix-derived package eligibility for every canonical target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInventoryV1 {
    /// Exact inventory schema identifier.
    pub schema_version: String,
    /// Closed platform roster in canonical order.
    pub platforms: Vec<Platform>,
    /// Every structurally discovered package, sorted by name.
    pub packages: Vec<InventoryPackage>,
}

/// Complete target eligibility for one discovered package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryPackage {
    /// Canonical package name.
    pub name: String,
    /// Exactly one decision for every canonical target.
    pub platforms: Vec<InventoryPlatformCell>,
}

/// One target decision from the Nix policy inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryPlatformCell {
    /// Exact target identity.
    pub platform: Platform,
    /// Explicit eligibility or inapplicability.
    pub decision: InventoryDecision,
}

/// Fail-closed package publication decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InventoryDecision {
    /// The package is a public root on this target.
    Eligible {},
    /// A versioned policy proves this target is inapplicable.
    NotApplicable {
        /// Stable eligibility rule.
        rule: String,
        /// Public explanation authored by the target policy.
        reason: String,
    },
}

/// Exact derivations and outputs evaluated for one target package set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationInventoryV1 {
    /// Exact derivation-inventory schema identifier.
    pub schema_version: String,
    /// Target for every derivation in this document.
    pub platform: Platform,
    /// Eligible packages and their exact Nix identities.
    pub packages: Vec<DerivationPackage>,
}

/// Evaluated Nix identity for one eligible package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationPackage {
    /// Canonical package name.
    pub name: String,
    /// Nix-derived public distribution metadata, absent when incomplete.
    pub publication: Option<PackagePublicationMetadata>,
    /// Exact source and dependency-source store roots needed to rebuild it.
    pub source_store_paths: Vec<String>,
    /// Exact `.drv` path.
    pub derivation: String,
    /// Every named output produced by the derivation.
    pub outputs: Vec<DerivationOutput>,
    /// Signed package contract source and its evaluated selector bindings.
    pub contract: Option<DerivationPackageContract>,
}

/// Evaluated publication inputs for one canonical package contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationPackageContract {
    /// Context-free PackageDocument file produced by its own derivation.
    pub document: DerivationContractDocument,
    /// Exact package outputs selected by the symbolic document.
    pub selectors: Vec<DerivationSelectorResolution>,
}

/// Exact Nix identity of a context-free PackageDocument file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationContractDocument {
    /// Derivation that produces the document as its `out` output.
    pub derivation: String,
    /// Evaluated regular-file store path.
    pub store_path: String,
}

/// Evaluated binding for one symbolic package-output selector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationSelectorResolution {
    /// Canonical package name selected by the PackageDocument.
    pub package: String,
    /// Canonical output name selected from that package.
    pub output: String,
    /// Exact evaluated store path for the selected output.
    pub store_path: String,
}

/// Public distribution metadata required by atomic registry authoring.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePublicationMetadata {
    /// Exact package version common to every published platform.
    pub version: String,
    /// Human-readable package purpose.
    pub description: String,
    /// Optional canonical project home page.
    pub homepage: Option<String>,
    /// SPDX-compatible license expression for the distributed output.
    pub license_expression: String,
    /// Public maintainer identities.
    pub maintainers: Vec<String>,
}

impl PackagePublicationMetadata {
    pub(crate) fn validate(&self) -> Result<()> {
        semver::Version::parse(&self.version).context("parsing package publication version")?;
        for (value, label) in [
            (&self.description, "package description"),
            (&self.license_expression, "package license expression"),
        ] {
            if value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control)
            {
                bail!("{label} must contain printable public text");
            }
        }
        if self.homepage.as_ref().is_some_and(|value| {
            value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control)
        }) {
            bail!("package homepage contains invalid public text");
        }
        if self.maintainers.is_empty()
            || self.maintainers.iter().any(|value| {
                value.trim().is_empty() || value.len() > 1024 || value.chars().any(char::is_control)
            })
        {
            bail!("package maintainers must contain nonempty public identities");
        }
        Ok(())
    }
}

/// One named Nix derivation output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationOutput {
    /// Nix output name.
    pub name: String,
    /// Exact owning derivation when this is a separately built companion.
    ///
    /// Ordinary outputs inherit the package payload derivation. A distinct
    /// derivation keeps ability-only source changes from renaming unchanged
    /// payload outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<String>,
    /// Evaluated output store path.
    pub store_path: String,
}

impl DerivationInventoryV1 {
    /// Validates ordering, uniqueness, and every Nix path.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong schema, duplicate or unsorted packages,
    /// invalid derivations, empty/duplicate outputs, or invalid output paths.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != DERIVATION_INVENTORY_V1 {
            bail!("unsupported derivation inventory schema");
        }
        if self
            .packages
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            bail!("derivation inventory packages must be unique and sorted");
        }
        for package in &self.packages {
            require_identifier(&package.name, "derivation package name")?;
            if let Some(publication) = &package.publication {
                publication.validate()?;
            }
            if package
                .source_store_paths
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                bail!("derivation package source paths must be unique and sorted");
            }
            for source in &package.source_store_paths {
                require_store_path(source, false)?;
            }
            require_store_path(&package.derivation, true)?;
            if package.outputs.is_empty() {
                bail!("derivation package has no outputs");
            }
            let mut output_names = BTreeSet::new();
            let mut output_paths = BTreeSet::new();
            for output in &package.outputs {
                require_identifier(&output.name, "derivation output name")?;
                if output.name == "abilities" {
                    bail!("package contract must not be encoded as an ordinary output");
                }
                if let Some(derivation) = &output.derivation {
                    require_store_path(derivation, true)?;
                }
                require_store_path(&output.store_path, false)?;
                if !output_names.insert(&output.name) || !output_paths.insert(&output.store_path) {
                    bail!("derivation package repeats an output name or store path");
                }
            }
            if let Some(contract) = &package.contract {
                require_store_path(&contract.document.derivation, true)?;
                require_store_path(&contract.document.store_path, false)?;
                if output_paths.contains(&contract.document.store_path) {
                    bail!("package contract document repeats a payload output path");
                }
                if contract.selectors.windows(2).any(|pair| pair[0] >= pair[1]) {
                    bail!("package contract selectors must be unique and sorted");
                }
                for selector in &contract.selectors {
                    if selector.package != "self" {
                        require_identifier(&selector.package, "contract selector package")?;
                    }
                    require_identifier(&selector.output, "contract selector output")?;
                    if selector.output == "abilities" {
                        bail!("package contract cannot select another package contract");
                    }
                    require_store_path(&selector.store_path, false)?;
                }
            }
        }

        let evaluated_outputs = self
            .packages
            .iter()
            .flat_map(|package| {
                package.outputs.iter().map(move |output| {
                    (
                        (package.name.as_str(), output.name.as_str()),
                        output.store_path.as_str(),
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        for package in &self.packages {
            let Some(contract) = &package.contract else {
                continue;
            };
            for selector in &contract.selectors {
                let selected_package = if selector.package == "self" {
                    package.name.as_str()
                } else {
                    selector.package.as_str()
                };
                let selected = evaluated_outputs
                    .get(&(selected_package, selector.output.as_str()))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "package contract selector {}:{} is absent from the derivation inventory",
                            selector.package,
                            selector.output
                        )
                    })?;
                if *selected != selector.store_path {
                    bail!("package contract selector resolution differs from its evaluated output");
                }
            }
        }
        Ok(())
    }
}

impl PackageInventoryV1 {
    /// Validates ordering, closure, and every package-platform decision.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong schema or platform roster, an empty,
    /// duplicate, or unsorted package list, incomplete cells, invalid policy
    /// identifiers, or an invalid package-owned projection.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != PACKAGE_INVENTORY_V1 {
            bail!("unsupported package inventory schema");
        }
        if self.platforms.as_slice() != Platform::ALL {
            bail!("package inventory platform roster is not canonical");
        }
        if self.packages.is_empty() {
            bail!("package inventory is empty");
        }
        if self
            .packages
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            bail!("package inventory names must be unique and sorted");
        }
        for package in &self.packages {
            require_identifier(&package.name, "inventory package name")?;
            require_complete_package_platforms(
                package.platforms.iter().map(|cell| &cell.platform),
            )?;
            if package.platforms.len() != Platform::ALL.len() {
                bail!("inventory package contains a duplicate platform cell");
            }
            if package
                .platforms
                .iter()
                .map(|cell| cell.platform)
                .ne(Platform::ALL)
            {
                bail!("inventory package platform cells are not in canonical order");
            }
            for cell in &package.platforms {
                validate_decision(&cell.decision)?;
            }
        }
        Ok(())
    }

    /// Converts Nix eligibility into the package portion of a release plan.
    ///
    /// # Errors
    ///
    /// Returns an error when either inventory is invalid or evaluated
    /// derivations do not exactly close the eligible matrix cells.
    pub fn package_plan(&self, derivations: &[DerivationInventoryV1]) -> Result<Vec<PackagePlan>> {
        self.validate()?;
        let derivations = index_derivations(self, derivations)?;
        let mut plans = Vec::with_capacity(self.packages.len());
        for package in &self.packages {
            let publication = package_publication_metadata(package, &derivations)?;
            let mut platforms = Vec::with_capacity(package.platforms.len());
            for cell in &package.platforms {
                let decision = match &cell.decision {
                    InventoryDecision::Eligible {} if publication.is_some() => {
                        let evaluated = derivations
                            .get(&(cell.platform, package.name.as_str()))
                            .ok_or_else(|| {
                                anyhow::anyhow!("eligible package lacks an evaluated derivation")
                            })?;
                        if evaluated.source_store_paths.is_empty() {
                            bail!(
                                "publishable package '{}' for {} lacks retained source evidence",
                                package.name,
                                cell.platform
                            );
                        }
                        let mut artifacts = evaluated
                            .outputs
                            .iter()
                            .map(|output| PlannedArtifact {
                                id: format!(
                                    "package/{}/{}/{}",
                                    package.name, cell.platform, output.name
                                ),
                                derivation: Some(
                                    output
                                        .derivation
                                        .clone()
                                        .unwrap_or_else(|| evaluated.derivation.clone()),
                                ),
                                output: Some(output.name.clone()),
                                store_path: Some(output.store_path.clone()),
                                source_store_paths: evaluated.source_store_paths.clone(),
                            })
                            .collect::<Vec<_>>();
                        if let Some(contract) = &evaluated.contract {
                            artifacts.push(PlannedArtifact {
                                id: format!("package/{}/{}/contract", package.name, cell.platform),
                                derivation: Some(contract.document.derivation.clone()),
                                output: Some("contract".to_owned()),
                                store_path: Some(contract.document.store_path.clone()),
                                source_store_paths: evaluated.source_store_paths.clone(),
                            });
                        }
                        artifacts.sort_by(|left, right| left.id.cmp(&right.id));

                        MatrixCell::Artifact {
                            artifact: PlannedArtifactSet { artifacts },
                        }
                    }
                    InventoryDecision::Eligible {} => MatrixCell::Blocked {
                        required_work: "Provide complete package publication metadata".to_owned(),
                        failure_evidence: crate::digest::Sha256Digest::of_canonical(
                            "aos.release.package-publication-metadata/v1",
                            &(package.name.as_str(), cell.platform),
                        )?,
                    },
                    InventoryDecision::NotApplicable { rule, reason } => {
                        MatrixCell::NotApplicable {
                            rule: rule.clone(),
                            reason: reason.clone(),
                        }
                    }
                };
                platforms.push(PlatformCell {
                    platform: cell.platform,
                    decision,
                });
            }
            plans.push(PackagePlan {
                name: package.name.clone(),
                publication: publication.cloned(),
                platforms,
            });
        }
        Ok(plans)
    }
}

fn package_publication_metadata<'a>(
    package: &InventoryPackage,
    derivations: &BTreeMap<(Platform, &'a str), &'a DerivationPackage>,
) -> Result<Option<&'a PackagePublicationMetadata>> {
    let mut selected = None;
    let mut incomplete = false;
    for cell in &package.platforms {
        if !matches!(&cell.decision, InventoryDecision::Eligible {}) {
            continue;
        }
        let metadata = derivations
            .get(&(cell.platform, package.name.as_str()))
            .and_then(|package| package.publication.as_ref());
        match (selected, metadata) {
            (_, None) => incomplete = true,
            (None, Some(metadata)) => selected = Some(metadata),
            (Some(expected), Some(metadata)) if expected != metadata => {
                bail!("package publication metadata differs across target platforms")
            }
            _ => {}
        }
    }
    Ok((!incomplete).then_some(selected).flatten())
}

fn index_derivations<'a>(
    package_inventory: &PackageInventoryV1,
    inventories: &'a [DerivationInventoryV1],
) -> Result<BTreeMap<(Platform, &'a str), &'a DerivationPackage>> {
    if inventories.len() != Platform::ALL.len()
        || inventories
            .iter()
            .map(|inventory| inventory.platform)
            .collect::<BTreeSet<_>>()
            != Platform::ALL.into_iter().collect()
    {
        bail!("derivation inventories must cover every canonical platform exactly once");
    }
    let mut indexed = BTreeMap::new();
    for inventory in inventories {
        inventory.validate()?;
        for package in &inventory.packages {
            if indexed
                .insert((inventory.platform, package.name.as_str()), package)
                .is_some()
            {
                bail!("derivation inventories repeat a package-platform cell");
            }
        }
    }

    for package in &package_inventory.packages {
        for cell in &package.platforms {
            let present = indexed.contains_key(&(cell.platform, package.name.as_str()));
            if present != matches!(&cell.decision, InventoryDecision::Eligible {}) {
                bail!("derivation inventory does not match package eligibility");
            }
        }
    }
    if indexed.len()
        != package_inventory
            .packages
            .iter()
            .flat_map(|package| &package.platforms)
            .filter(|cell| matches!(&cell.decision, InventoryDecision::Eligible {}))
            .count()
    {
        bail!("derivation inventory contains an unknown package");
    }
    Ok(indexed)
}

fn validate_decision(decision: &InventoryDecision) -> Result<()> {
    match decision {
        InventoryDecision::Eligible {} => Ok(()),
        InventoryDecision::NotApplicable { rule, reason } => {
            require_identifier(rule, "package eligibility rule")?;
            if reason.trim().is_empty()
                || reason.len() > 1024
                || reason.chars().any(char::is_control)
            {
                bail!("package inapplicability reason must contain printable public text");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_PATH: &str = "/nix/store/cccccccccccccccccccccccccccccccc-example-source";

    fn decision(platform: Platform) -> InventoryPlatformCell {
        InventoryPlatformCell {
            platform,
            decision: InventoryDecision::Eligible {},
        }
    }

    #[test]
    fn inventory_accepts_target_policy_decision_shape() -> Result<()> {
        let eligible = serde_json::from_value::<InventoryDecision>(serde_json::json!({
            "state": "eligible"
        }))?;
        let not_applicable = serde_json::from_value::<InventoryDecision>(serde_json::json!({
            "state": "not-applicable",
            "rule": "recipe-policy/v1",
            "reason": "The recipe constraints exclude the selected target"
        }))?;

        validate_decision(&eligible)?;
        validate_decision(&not_applicable)?;
        Ok(())
    }

    #[test]
    fn inventory_materializes_the_closed_plan_matrix() -> Result<()> {
        let inventory = PackageInventoryV1 {
            schema_version: PACKAGE_INVENTORY_V1.to_owned(),
            platforms: Platform::ALL.to_vec(),
            packages: vec![InventoryPackage {
                name: "example".to_owned(),
                platforms: Platform::ALL.into_iter().map(decision).collect(),
            }],
        };
        let derivations = Platform::ALL
            .into_iter()
            .map(|platform| DerivationInventoryV1 {
                schema_version: DERIVATION_INVENTORY_V1.to_owned(),
                platform,
                packages: vec![DerivationPackage {
                    name: "example".to_owned(),
                    source_store_paths: vec![SOURCE_PATH.to_owned()],
                    publication: Some(PackagePublicationMetadata {
                        version: "1.0.0".to_owned(),
                        description: "Example package".to_owned(),
                        homepage: Some("https://example.invalid".to_owned()),
                        license_expression: "Apache-2.0".to_owned(),
                        maintainers: vec!["Example Maintainer".to_owned()],
                    }),
                    derivation: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv"
                        .to_owned(),
                    outputs: vec![
                        DerivationOutput {
                            name: "out".to_owned(),
                            derivation: None,
                            store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example"
                                .to_owned(),
                        },
                        DerivationOutput {
                            name: "module".to_owned(),
                            derivation: Some(
                                "/nix/store/cccccccccccccccccccccccccccccccc-example-module.drv"
                                    .to_owned(),
                            ),
                            store_path:
                                "/nix/store/dddddddddddddddddddddddddddddddd-example-module"
                                    .to_owned(),
                        },
                    ],
                    contract: Some(DerivationPackageContract {
                        document: DerivationContractDocument {
                            derivation:
                                "/nix/store/11111111111111111111111111111111-example-contract.drv"
                                    .to_owned(),
                            store_path:
                                "/nix/store/ffffffffffffffffffffffffffffffff-example-contract"
                                    .to_owned(),
                        },
                        selectors: vec![DerivationSelectorResolution {
                            package: "example".to_owned(),
                            output: "out".to_owned(),
                            store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example"
                                .to_owned(),
                        }],
                    }),
                }],
            })
            .collect::<Vec<_>>();
        let plan = inventory.package_plan(&derivations)?;
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].platforms.len(), 4);
        let MatrixCell::Artifact { artifact } = &plan[0].platforms[0].decision else {
            panic!("eligible fixture should produce an artifact plan");
        };
        assert_eq!(artifact.artifacts.len(), 3);
        assert_eq!(
            artifact.artifacts[0].id,
            "package/example/x86_64-linux/contract"
        );
        assert_eq!(artifact.artifacts[0].output.as_deref(), Some("contract"));
        assert_eq!(
            artifact.artifacts[0].store_path.as_deref(),
            Some("/nix/store/ffffffffffffffffffffffffffffffff-example-contract")
        );
        assert_eq!(
            artifact.artifacts[1].derivation.as_deref(),
            Some("/nix/store/cccccccccccccccccccccccccccccccc-example-module.drv")
        );
        assert_eq!(
            plan[0]
                .publication
                .as_ref()
                .map(|value| value.version.as_str()),
            Some("1.0.0")
        );
        Ok(())
    }

    #[test]
    fn inventory_rejects_a_contract_selector_with_a_different_evaluated_path() {
        let inventory = DerivationInventoryV1 {
            schema_version: DERIVATION_INVENTORY_V1.to_owned(),
            platform: Platform::X86_64Linux,
            packages: vec![DerivationPackage {
                name: "example".to_owned(),
                publication: None,
                source_store_paths: vec![SOURCE_PATH.to_owned()],
                derivation: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv".to_owned(),
                outputs: vec![DerivationOutput {
                    name: "out".to_owned(),
                    derivation: None,
                    store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example".to_owned(),
                }],
                contract: Some(DerivationPackageContract {
                    document: DerivationContractDocument {
                        derivation:
                            "/nix/store/11111111111111111111111111111111-example-contract.drv"
                                .to_owned(),
                        store_path: "/nix/store/ffffffffffffffffffffffffffffffff-example-contract"
                            .to_owned(),
                    },
                    selectors: vec![DerivationSelectorResolution {
                        package: "example".to_owned(),
                        output: "out".to_owned(),
                        store_path: "/nix/store/gggggggggggggggggggggggggggggggg-wrong".to_owned(),
                    }],
                }),
            }],
        };

        assert!(inventory.validate().is_err());
    }

    #[test]
    fn inventory_rejects_policy_inputs_on_eligible_decisions() {
        let decision = serde_json::from_value::<InventoryDecision>(serde_json::json!({
            "state": "eligible",
            "role": "public-package"
        }));

        assert!(decision.is_err());
    }

    #[test]
    fn inventory_rejects_implicit_or_reordered_targets() {
        let inventory = PackageInventoryV1 {
            schema_version: PACKAGE_INVENTORY_V1.to_owned(),
            platforms: Platform::LINUX.to_vec(),
            packages: Vec::new(),
        };
        assert!(inventory.validate().is_err());
    }

    #[test]
    fn inventory_rejects_publishable_package_without_source_evidence() {
        let inventory = PackageInventoryV1 {
            schema_version: PACKAGE_INVENTORY_V1.to_owned(),
            platforms: Platform::ALL.to_vec(),
            packages: vec![InventoryPackage {
                name: "example".to_owned(),
                platforms: Platform::ALL.into_iter().map(decision).collect(),
            }],
        };
        let derivations = Platform::ALL
            .into_iter()
            .map(|platform| DerivationInventoryV1 {
                schema_version: DERIVATION_INVENTORY_V1.to_owned(),
                platform,
                packages: vec![DerivationPackage {
                    name: "example".to_owned(),
                    publication: Some(PackagePublicationMetadata {
                        version: "1.0.0".to_owned(),
                        description: "Example package".to_owned(),
                        homepage: None,
                        license_expression: "Apache-2.0".to_owned(),
                        maintainers: vec!["Example Maintainer".to_owned()],
                    }),
                    source_store_paths: Vec::new(),
                    derivation: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv"
                        .to_owned(),
                    outputs: vec![DerivationOutput {
                        name: "out".to_owned(),
                        derivation: None,
                        store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example"
                            .to_owned(),
                    }],
                    contract: None,
                }],
            })
            .collect::<Vec<_>>();

        assert!(inventory.package_plan(&derivations).is_err());
    }
}
