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
use crate::platform::{MatrixCell, Platform};

/// Exact schema emitted by the Nix package inventory.
pub const PACKAGE_INVENTORY_V1: &str = "aos.release.package-inventory/v1";

/// Exact schema for target-specific evaluated Nix identities.
pub const DERIVATION_INVENTORY_V1: &str = "aos.release.derivation-inventory/v1";

/// Nix-derived package eligibility for an explicitly selected target roster.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInventoryV1 {
    /// Exact inventory schema identifier.
    pub schema_version: String,
    /// Closed selected platform roster in caller-supplied order.
    pub platforms: Vec<Platform>,
    /// Every structurally discovered package, sorted by name.
    pub packages: Vec<InventoryPackage>,
}

/// Complete selected-target eligibility for one discovered package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryPackage {
    /// Canonical package name.
    pub name: String,
    /// Exactly one decision for every selected target.
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
    /// Evaluated native deployment-envelope derivation and directory root.
    #[serde(default)]
    pub deployment: Option<DerivationArtifact>,
    /// Evaluated module-generated documentation derivation and directory root.
    #[serde(default)]
    pub module_documentation: Option<DerivationArtifact>,
    /// Authenticated native package qualification companion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<DerivationArtifact>,
}

/// Exact Nix identity of an independently built publication artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationArtifact {
    /// Derivation that produces the artifact.
    pub derivation: String,
    /// Named output of the artifact derivation.
    pub output: String,
    /// Evaluated immutable file or directory store root.
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
        aos_registry_surface::package_version::validate_package_version(&self.version)
            .context("validating package publication version")?;
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
    /// Logical package output name.
    pub name: String,
    /// Exact owning derivation, absent for a content-addressed store input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<String>,
    /// Exact Nix output, absent for a content-addressed store input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// Evaluated output store path.
    pub store_path: String,
    /// Native companion selecting this exact named output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<DerivationArtifact>,
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
                if output.derivation.is_some() != output.output.is_some() {
                    bail!("derivation inventory output has an incomplete Nix identity");
                }
                if let Some(output) = &output.output {
                    require_identifier(output, "derivation output name")?;
                }
                require_store_path(&output.store_path, false)?;
                if !output_names.insert(&output.name) || !output_paths.insert(&output.store_path) {
                    bail!("derivation package repeats an output name or store path");
                }
            }
            for artifact in [
                &package.deployment,
                &package.module_documentation,
                &package.qualification,
            ]
            .into_iter()
            .flatten()
            .chain(
                package
                    .outputs
                    .iter()
                    .filter_map(|output| output.deployment.as_ref()),
            ) {
                require_store_path(&artifact.derivation, true)?;
                require_identifier(&artifact.output, "native artifact output")?;
                require_store_path(&artifact.store_path, false)?;
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
        self.validate_for_platforms(&Platform::ALL)
    }

    /// Validates an inventory for an explicit selected platform roster.
    ///
    /// This validates the same schema, ordering, package closure, and decisions
    /// as [`Self::validate`] while allowing a caller to check the exact subset
    /// that it asked Nix to evaluate. Full release planning continues to use
    /// [`Self::validate`] and therefore requires [`Platform::ALL`].
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or duplicate expected roster, a different
    /// inventory roster, an empty, duplicate, or unsorted package list,
    /// incomplete cells, invalid policy identifiers, or an invalid
    /// package-owned projection.
    pub fn validate_for_platforms(&self, expected: &[Platform]) -> Result<()> {
        if self.schema_version != PACKAGE_INVENTORY_V1 {
            bail!("unsupported package inventory schema");
        }
        if expected.is_empty() {
            bail!("expected package inventory platform roster is empty");
        }
        if expected.iter().copied().collect::<BTreeSet<_>>().len() != expected.len() {
            bail!("expected package inventory platform roster contains duplicates");
        }
        if self.platforms.as_slice() != expected {
            bail!("package inventory platform roster differs from the requested selection");
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
            if package.platforms.len() != expected.len() {
                bail!("inventory package contains a duplicate platform cell");
            }
            if package
                .platforms
                .iter()
                .map(|cell| cell.platform)
                .ne(expected.iter().copied())
            {
                bail!("inventory package platform cells differ from the requested selection");
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
            let platform_versions = package
                .platforms
                .iter()
                .filter(|cell| matches!(cell.decision, InventoryDecision::Eligible {}))
                .filter_map(|cell| {
                    let evaluated = derivations.get(&(cell.platform, package.name.as_str()))?;
                    let metadata = evaluated.publication.as_ref()?;
                    (metadata.version != publication?.version)
                        .then(|| (cell.platform, metadata.version.clone()))
                })
                .collect();
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
                            .filter(|output| output.derivation.is_some())
                            .map(|output| PlannedArtifact {
                                id: format!(
                                    "package/{}/{}/{}",
                                    package.name, cell.platform, output.name
                                ),
                                derivation: output.derivation.clone(),
                                output: output.output.clone(),
                                store_path: Some(output.store_path.clone()),
                                source_store_paths: evaluated.source_store_paths.clone(),
                            })
                            .collect::<Vec<_>>();
                        for (name, native) in [
                            ("deploymentArtifact", &evaluated.deployment),
                            ("documentationArtifact", &evaluated.module_documentation),
                            ("qualificationArtifact", &evaluated.qualification),
                        ] {
                            if let Some(native) = native {
                                artifacts.push(PlannedArtifact {
                                    id: format!(
                                        "package/{}/{}/{name}",
                                        package.name, cell.platform
                                    ),
                                    derivation: Some(native.derivation.clone()),
                                    output: Some(native.output.clone()),
                                    store_path: Some(native.store_path.clone()),
                                    source_store_paths: evaluated.source_store_paths.clone(),
                                });
                            }
                        }
                        for output in evaluated
                            .outputs
                            .iter()
                            .filter(|output| output.name != "out")
                        {
                            if let Some(native) = &output.deployment {
                                artifacts.push(PlannedArtifact {
                                    id: format!(
                                        "package/{}/{}/deploymentArtifact.{}",
                                        package.name, cell.platform, output.name
                                    ),
                                    derivation: Some(native.derivation.clone()),
                                    output: Some(native.output.clone()),
                                    store_path: Some(native.store_path.clone()),
                                    source_store_paths: evaluated.source_store_paths.clone(),
                                });
                            }
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
                platform_versions,
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
    let mut selected: Option<&PackagePublicationMetadata> = None;
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
            (Some(expected), Some(metadata)) => {
                // Native ports may use different upstream source versions.
                // Shared catalog text and licensing must still agree.
                let mut comparable = metadata.clone();
                comparable.version.clone_from(&expected.version);
                if expected != &comparable {
                    bail!(
                        "package '{}' publication metadata differs across target platforms",
                        package.name
                    );
                }
            }
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
    fn native_release_models_reject_legacy_contract_slots() {
        let mut package = serde_json::json!({
            "name":"example", "publication":null, "source_store_paths":[],
            "derivation":"/nix/store/11111111111111111111111111111111-example.drv", "outputs":[]
        });
        assert!(serde_json::from_value::<DerivationPackage>(package.clone()).is_ok());
        package["contract"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<DerivationPackage>(package).is_err());

        let mut planned = serde_json::json!({"artifacts":[]});
        assert!(serde_json::from_value::<PlannedArtifactSet>(planned.clone()).is_ok());
        planned["package_contract"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<PlannedArtifactSet>(planned).is_err());

        let mut finalized = serde_json::json!({"artifact_ids":[]});
        assert!(
            serde_json::from_value::<crate::manifest::FinalArtifactSet>(finalized.clone()).is_ok()
        );
        finalized["package_contract"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<crate::manifest::FinalArtifactSet>(finalized).is_err());
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
        let mut derivations = Platform::ALL
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
                            deployment: None,
                            name: "out".to_owned(),
                            derivation: Some(
                                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv"
                                    .to_owned(),
                            ),
                            output: Some("out".to_owned()),
                            store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example"
                                .to_owned(),
                        },
                        DerivationOutput {
                            deployment: None,
                            name: "module".to_owned(),
                            derivation: None,
                            output: None,
                            store_path:
                                "/nix/store/dddddddddddddddddddddddddddddddd-example-module"
                                    .to_owned(),
                        },
                    ],
                    deployment: Some(DerivationArtifact {
                        derivation:
                            "/nix/store/11111111111111111111111111111111-example-deployment.drv"
                                .to_owned(),
                        output: "out".to_owned(),
                        store_path:
                            "/nix/store/ffffffffffffffffffffffffffffffff-example-deployment"
                                .to_owned(),
                    }),
                    module_documentation: Some(DerivationArtifact {
                        derivation:
                            "/nix/store/22222222222222222222222222222222-example-documentation.drv"
                                .to_owned(),
                        output: "out".to_owned(),
                        store_path:
                            "/nix/store/gggggggggggggggggggggggggggggggg-example-documentation"
                                .to_owned(),
                    }),
                    qualification: None,
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
            "package/example/x86_64-linux/deploymentArtifact"
        );
        assert_eq!(artifact.artifacts[0].output.as_deref(), Some("out"));
        assert_eq!(
            artifact.artifacts[0].store_path.as_deref(),
            Some("/nix/store/ffffffffffffffffffffffffffffffff-example-deployment")
        );
        assert_eq!(
            artifact.artifacts[1].id,
            "package/example/x86_64-linux/documentationArtifact"
        );
        assert_eq!(artifact.artifacts[2].id, "package/example/x86_64-linux/out");
        assert_eq!(
            plan[0]
                .publication
                .as_ref()
                .map(|value| value.version.as_str()),
            Some("1.0.0")
        );
        assert!(plan[0].platform_versions.is_empty());

        for target in &mut derivations {
            if !target.platform.supports_images() {
                target.packages[0].publication.as_mut().unwrap().version = "0.9.0".into();
            }
        }
        let plan = inventory.package_plan(&derivations)?;
        assert_eq!(plan[0].version_for(Platform::X86_64Linux), Some("1.0.0"));
        assert_eq!(plan[0].version_for(Platform::Aarch64Linux), Some("1.0.0"));
        assert_eq!(plan[0].version_for(Platform::X86_64Darwin), Some("0.9.0"));
        assert_eq!(plan[0].version_for(Platform::Aarch64Darwin), Some("0.9.0"));
        assert_eq!(plan[0].platform_versions.len(), 2);

        let bytes = crate::canonical::to_vec(&plan[0])?;
        let decoded: PackagePlan = crate::canonical::from_slice(&bytes, "package plan")?;
        assert_eq!(decoded, plan[0]);

        derivations[3].packages[0]
            .publication
            .as_mut()
            .unwrap()
            .license_expression = "GPL-3.0-only".into();
        assert!(inventory.package_plan(&derivations).is_err());
        Ok(())
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
    fn inventory_validates_the_exact_selected_platform_roster() -> Result<()> {
        let inventory = PackageInventoryV1 {
            schema_version: PACKAGE_INVENTORY_V1.to_owned(),
            platforms: vec![Platform::X86_64Linux],
            packages: vec![InventoryPackage {
                name: "example".to_owned(),
                platforms: vec![decision(Platform::X86_64Linux)],
            }],
        };

        inventory.validate_for_platforms(&[Platform::X86_64Linux])?;
        assert!(inventory.validate().is_err());
        assert!(inventory.validate_for_platforms(&[]).is_err());
        assert!(
            inventory
                .validate_for_platforms(&[Platform::X86_64Linux, Platform::X86_64Linux])
                .is_err()
        );
        Ok(())
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
                        deployment: None,
                        name: "out".to_owned(),
                        derivation: Some(
                            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv".to_owned(),
                        ),
                        output: Some("out".to_owned()),
                        store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example"
                            .to_owned(),
                    }],
                    deployment: None,
                    module_documentation: None,
                    qualification: None,
                }],
            })
            .collect::<Vec<_>>();

        assert!(inventory.package_plan(&derivations).is_err());
    }
}
