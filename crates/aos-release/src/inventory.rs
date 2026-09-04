//! Closed package eligibility inventory emitted by Nix evaluation.
//!
//! ```json
//! {"schema_version":"aos.release.package-inventory/v1",
//!  "platforms":["x86_64-linux","aarch64-linux","x86_64-darwin","aarch64-darwin"],
//!  "packages":[{"name":"example","platforms":[{"platform":"x86_64-linux",
//!  "decision":{"state":"eligible","disposition":"target","wave":1,"blockers":[]}}]}]}
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
    Eligible {
        /// Structural package class.
        disposition: String,
        /// Cross-build wave, where applicable.
        wave: Option<u8>,
        /// Versioned implementation constraints retained for evidence.
        blockers: Vec<String>,
    },
    /// A versioned policy proves this target is inapplicable.
    NotApplicable {
        /// Stable eligibility rule.
        rule: String,
        /// Public explanation.
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
    /// Exact upstream source store paths; empty means repository source.
    pub source_store_paths: Vec<String>,
    /// Exact `.drv` path.
    pub derivation: String,
    /// Every named output produced by the derivation.
    pub outputs: Vec<DerivationOutput>,
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
                require_store_path(&output.store_path, false)?;
                if !output_names.insert(&output.name) || !output_paths.insert(&output.store_path) {
                    bail!("derivation package repeats an output name or store path");
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
    /// identifiers, or a disposition that conflicts with its platform.
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
                validate_decision(cell.platform, &cell.decision)?;
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
                    InventoryDecision::Eligible { blockers, .. }
                        if blockers.is_empty() && publication.is_some() =>
                    {
                        let evaluated = derivations
                            .get(&(cell.platform, package.name.as_str()))
                            .ok_or_else(|| {
                                anyhow::anyhow!("eligible package lacks an evaluated derivation")
                            })?;
                        MatrixCell::Artifact {
                            artifact: PlannedArtifactSet {
                                artifacts: evaluated
                                    .outputs
                                    .iter()
                                    .map(|output| PlannedArtifact {
                                        id: format!(
                                            "package/{}/{}/{}",
                                            package.name, cell.platform, output.name
                                        ),
                                        derivation: Some(evaluated.derivation.clone()),
                                        output: Some(output.name.clone()),
                                        store_path: Some(output.store_path.clone()),
                                        source_store_paths: evaluated.source_store_paths.clone(),
                                    })
                                    .collect(),
                            },
                        }
                    }
                    InventoryDecision::Eligible { blockers, .. } => {
                        let blockers = if blockers.is_empty() {
                            "distribution-metadata-missing".to_owned()
                        } else {
                            blockers.join(", ")
                        };
                        MatrixCell::Blocked {
                            required_work: format!("Close package-platform blockers: {blockers}"),
                            failure_evidence: crate::digest::Sha256Digest::of_canonical(
                                "aos.release.package-blockers/v1",
                                &(blockers, publication.is_some()),
                            )?,
                        }
                    }
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
        if !matches!(&cell.decision, InventoryDecision::Eligible { .. }) {
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
            if present != matches!(&cell.decision, InventoryDecision::Eligible { .. }) {
                bail!("derivation inventory does not match package eligibility");
            }
        }
    }
    if indexed.len()
        != package_inventory
            .packages
            .iter()
            .flat_map(|package| &package.platforms)
            .filter(|cell| matches!(&cell.decision, InventoryDecision::Eligible { .. }))
            .count()
    {
        bail!("derivation inventory contains an unknown package");
    }
    Ok(indexed)
}

fn validate_decision(platform: Platform, decision: &InventoryDecision) -> Result<()> {
    match decision {
        InventoryDecision::Eligible {
            disposition,
            wave,
            blockers,
        } => {
            if !matches!(
                disposition.as_str(),
                "target" | "independent" | "linux-only" | "darwin-only"
            ) {
                bail!("eligible package has an invalid disposition");
            }
            if (disposition == "linux-only" && !platform.supports_images())
                || (disposition == "darwin-only" && platform.supports_images())
            {
                bail!("eligible package disposition conflicts with its platform");
            }
            if wave.is_none_or(|wave| !(1..=5).contains(&wave)) {
                bail!("eligible package requires a valid publication wave");
            }
            for blocker in blockers {
                require_identifier(blocker, "package inventory blocker")?;
            }
            Ok(())
        }
        InventoryDecision::NotApplicable { rule, reason } => {
            require_identifier(rule, "package eligibility rule")?;
            if reason.trim().is_empty() || reason.len() > 1024 {
                bail!("package inapplicability reason must contain 1 through 1024 bytes");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(platform: Platform) -> InventoryPlatformCell {
        InventoryPlatformCell {
            platform,
            decision: InventoryDecision::Eligible {
                disposition: if platform.supports_images() {
                    "linux-only"
                } else {
                    "target"
                }
                .to_owned(),
                wave: Some(1),
                blockers: Vec::new(),
            },
        }
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
                    source_store_paths: vec![],
                    publication: Some(PackagePublicationMetadata {
                        version: "1.0.0".to_owned(),
                        description: "Example package".to_owned(),
                        homepage: Some("https://example.invalid".to_owned()),
                        license_expression: "Apache-2.0".to_owned(),
                        maintainers: vec!["Example Maintainer".to_owned()],
                    }),
                    derivation: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv"
                        .to_owned(),
                    outputs: vec![DerivationOutput {
                        name: "out".to_owned(),
                        store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example"
                            .to_owned(),
                    }],
                }],
            })
            .collect::<Vec<_>>();
        let plan = inventory.package_plan(&derivations)?;
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].platforms.len(), 4);
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
    fn inventory_retains_explicit_package_blockers() -> Result<()> {
        let mut cell = decision(Platform::X86_64Linux);
        cell.decision = InventoryDecision::Eligible {
            disposition: "target".to_owned(),
            wave: Some(1),
            blockers: vec!["cross-build-not-qualified".to_owned()],
        };
        let inventory = PackageInventoryV1 {
            schema_version: PACKAGE_INVENTORY_V1.to_owned(),
            platforms: Platform::ALL.to_vec(),
            packages: vec![InventoryPackage {
                name: "example".to_owned(),
                platforms: [
                    cell,
                    decision(Platform::Aarch64Linux),
                    decision(Platform::X86_64Darwin),
                    decision(Platform::Aarch64Darwin),
                ]
                .into(),
            }],
        };
        let derivations = Platform::ALL
            .into_iter()
            .map(|platform| DerivationInventoryV1 {
                schema_version: DERIVATION_INVENTORY_V1.to_owned(),
                platform,
                packages: vec![DerivationPackage {
                    name: "example".to_owned(),
                    source_store_paths: vec![],
                    publication: Some(PackagePublicationMetadata {
                        version: "1.0.0".to_owned(),
                        description: "Example package".to_owned(),
                        homepage: None,
                        license_expression: "Apache-2.0".to_owned(),
                        maintainers: vec!["Example Maintainer".to_owned()],
                    }),
                    derivation: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv"
                        .to_owned(),
                    outputs: vec![DerivationOutput {
                        name: "out".to_owned(),
                        store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example"
                            .to_owned(),
                    }],
                }],
            })
            .collect::<Vec<_>>();
        let plan = inventory.package_plan(&derivations)?;
        assert!(matches!(
            plan[0].platforms[0].decision,
            MatrixCell::Blocked { .. }
        ));
        Ok(())
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
}
