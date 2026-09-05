//! Shared server qualification policy and release-transition applicability.
//!
//! Nix exports this document; the coordinator canonicalizes it and embeds it in
//! the signed plan. Offline consumers need neither Nix nor the source checkout.
//!
//! ```text
//! qualification-contract/v1
//!   promises + exclusions + targets + package_rules + requirements
//!   thresholds[edge | candidate | stable | emergency]
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::evidence::GateRequirement;
use crate::plan::{ReleaseClass, ReleasePlanV1};
use crate::platform::Platform;

/// Schema of the shared, source-controlled qualification contract.
pub const CONTRACT_V1: &str = "aos.release.qualification-contract/v1";

/// Hold point at which evidence authorizes the next release operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationPhase {
    /// Evidence available before closing the immutable bundle.
    Build,
    /// Evidence over exact anonymously downloaded staging artifacts.
    Staging,
    /// Fresh public-health evidence before advancing a channel range.
    Rollout,
    /// Observation, retention, and handoff evidence before completion.
    Complete,
}

/// Artifact population to which a requirement applies.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationScope {
    /// One release-wide exercise over the full artifact set.
    Release,
    /// One functional test per published package and platform.
    Packages,
    /// One lifecycle test per reference image target and system variant.
    Images,
    /// One lifecycle test per reference OCI target.
    Containers,
}

/// Source of an observation; operator reports remain machine-validated evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationMethod {
    /// A bounded test executor produces the observation.
    Automated,
    /// An operator records a physical or operational exercise.
    Operator,
}

/// Required reference environment, including reproducible machine configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTarget {
    /// Stable environment name; it is not a claim that qualification passed.
    pub id: String,
    /// Exact execution architecture and operating system.
    pub platform: Platform,
    /// Image or container environment.
    pub kind: TargetKind,
    /// Whether an absent artifact blocks this contract.
    pub required: bool,
    /// Public machine, firmware, runtime, and resource requirements.
    pub configuration: BTreeMap<String, String>,
}

/// Reference environment kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    /// UEFI disk-image environment.
    Image,
    /// OCI container runtime environment.
    Container,
}

/// Consequence-driven role of a package root.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageRole {
    /// Baseline functional and publication obligations.
    GeneralCatalog,
    /// Complete declared workload lifecycle.
    QualifiedWorkload,
    /// Boot, update, trust, persistence, or recovery obligations.
    SystemIntegrity,
}

/// Classification for one package in the complete discovered inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRule {
    /// Exact discovered package name.
    pub name: String,
    /// Minimum role; runtime dependency use can raise it.
    pub role: PackageRole,
    /// Requires dependencies to inherit the consuming root's obligations.
    pub inherit_dependency_obligations: bool,
}

/// Shared requirement with applicability at one hold point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRequirement {
    /// Stable requirement identity across release classes.
    pub id: String,
    /// Hold point that requires the result.
    pub phase: QualificationPhase,
    /// Subject population, expanded from the signed artifact matrix.
    pub scope: QualificationScope,
    /// Required observation method.
    pub method: QualificationMethod,
    /// Includes the requirement only for main-registry release classes.
    pub production_only: bool,
    /// Named acceptance conditions; each requires an affirmative observation.
    pub checks: Vec<String>,
    /// Existing Nix regression coverage; never substitutes for live evidence.
    pub regressions: Vec<String>,
    /// Identities whose change invalidates previous observations.
    pub invalidated_by: Vec<String>,
}

/// Class-dependent obligations in the same server contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationThresholds {
    /// Required measured mixed-workload observation duration.
    pub soak_seconds: u64,
    /// Maximum age of an operational exercise at admission.
    pub exercise_max_age_seconds: u64,
    /// Requires a separately signed reviewer attestation.
    pub require_independent_review: bool,
    /// Rejects every blocked required package/image cell.
    pub require_complete_matrix: bool,
}

/// One authoritative qualification policy for testing and production.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationContractV1 {
    /// Exact document schema.
    pub schema_version: String,
    /// Reviewed contract identity.
    pub id: String,
    /// User-visible functional obligations.
    pub promises: Vec<String>,
    /// Explicit boundaries of the claims.
    pub exclusions: Vec<String>,
    /// Thresholds keyed by the closed release-class vocabulary.
    pub thresholds: BTreeMap<String, QualificationThresholds>,
    /// Required reference environments.
    pub targets: Vec<QualificationTarget>,
    /// Complete package classification, independent of platform eligibility.
    pub package_rules: Vec<PackageRule>,
    /// Shared gate catalog.
    pub requirements: Vec<QualificationRequirement>,
}

impl QualificationContractV1 {
    /// Validates the catalog and minimum server-contract obligations.
    ///
    /// # Errors
    /// Returns an error for unknown schemas, missing classifications, duplicate
    /// identities, weakened baseline thresholds, or absent mandatory gates.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTRACT_V1 || self.id != "aos-server-v1" {
            bail!("unsupported qualification contract");
        }
        nonempty_strings(&self.promises, "contract promises")?;
        nonempty_strings(&self.exclusions, "contract exclusions")?;
        unique(
            self.targets.iter().map(|target| target.id.as_str()),
            "target",
        )?;
        unique(
            self.package_rules.iter().map(|rule| rule.name.as_str()),
            "package rule",
        )?;
        unique(
            self.requirements.iter().map(|gate| gate.id.as_str()),
            "requirement",
        )?;
        if self.package_rules.is_empty()
            || self
                .package_rules
                .iter()
                .any(|rule| !rule.inherit_dependency_obligations)
        {
            bail!("qualification must classify packages and inherit dependency obligations");
        }
        for target in &self.targets {
            if !target.platform.supports_images() || target.configuration.is_empty() {
                bail!("reference image/container targets require Linux and explicit configuration");
            }
            for (key, value) in &target.configuration {
                require_identifier(key, "target configuration key")?;
                if value.trim().is_empty() {
                    bail!("empty target configuration value");
                }
            }
        }
        for platform in [Platform::X86_64Linux, Platform::Aarch64Linux] {
            for kind in [TargetKind::Image, TargetKind::Container] {
                if !self.targets.iter().any(|target| {
                    target.platform == platform && target.kind == kind && target.required
                }) {
                    bail!("server contract requires image and OCI targets on both Linux platforms");
                }
            }
        }
        for gate in &self.requirements {
            nonempty_strings(&gate.checks, "acceptance conditions")?;
            for identity in ["subject", "policy", "executor", "environment"] {
                if !gate.invalidated_by.iter().any(|value| value == identity) {
                    bail!("requirement {} omits invalidation by {identity}", gate.id);
                }
            }
        }
        // These are admission floors, not a second configurable catalog. An
        // operator cannot select a contract with only an easy smoke gate.
        for (id, phase, scope, production_only) in [
            (
                "build-integrity",
                QualificationPhase::Build,
                QualificationScope::Release,
                false,
            ),
            (
                "package-function",
                QualificationPhase::Staging,
                QualificationScope::Packages,
                false,
            ),
            (
                "image-installation",
                QualificationPhase::Staging,
                QualificationScope::Images,
                false,
            ),
            (
                "image-lifecycle",
                QualificationPhase::Staging,
                QualificationScope::Images,
                false,
            ),
            (
                "image-update-recovery",
                QualificationPhase::Staging,
                QualificationScope::Images,
                false,
            ),
            (
                "container-lifecycle",
                QualificationPhase::Staging,
                QualificationScope::Containers,
                false,
            ),
            (
                "staging-delivery",
                QualificationPhase::Staging,
                QualificationScope::Release,
                false,
            ),
            (
                "operator-recovery",
                QualificationPhase::Staging,
                QualificationScope::Release,
                false,
            ),
            (
                "production-recovery",
                QualificationPhase::Staging,
                QualificationScope::Release,
                true,
            ),
            (
                "rollout-health",
                QualificationPhase::Rollout,
                QualificationScope::Release,
                false,
            ),
            (
                "rollout-observation",
                QualificationPhase::Complete,
                QualificationScope::Release,
                false,
            ),
        ] {
            if !self.requirements.iter().any(|gate| {
                gate.id == id
                    && gate.phase == phase
                    && gate.scope == scope
                    && gate.production_only == production_only
            }) {
                bail!("qualification contract lacks mandatory requirement {id}");
            }
        }
        let classes = ["edge", "candidate", "stable", "emergency"];
        if self.thresholds.len() != classes.len() {
            bail!("qualification thresholds must cover exactly four release classes");
        }
        for (class, minimum_soak) in classes.into_iter().zip([86400, 604800, 1209600, 1209600]) {
            let value = self
                .thresholds
                .get(class)
                .ok_or_else(|| anyhow::anyhow!("missing {class} thresholds"))?;
            if value.soak_seconds < minimum_soak
                || value.exercise_max_age_seconds == 0
                || value.exercise_max_age_seconds > 2592000
                || (class != "edge" && !value.require_independent_review)
                || (matches!(class, "stable" | "emergency") && !value.require_complete_matrix)
            {
                bail!("{class} qualification thresholds weaken the server contract");
            }
        }
        Ok(())
    }

    /// Returns the obligations selected by the release class.
    ///
    /// # Errors
    /// Returns an error if that class has no threshold record.
    pub fn thresholds_for(&self, class: ReleaseClass) -> Result<&QualificationThresholds> {
        let name = match class {
            ReleaseClass::Edge => "edge",
            ReleaseClass::Candidate => "candidate",
            ReleaseClass::Stable => "stable",
            ReleaseClass::Emergency => "emergency",
        };
        self.thresholds
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("missing {name} qualification thresholds"))
    }

    /// Selects requirements without allowing per-release manual deselection.
    pub fn selected(&self, class: ReleaseClass) -> impl Iterator<Item = &QualificationRequirement> {
        self.requirements
            .iter()
            .filter(move |gate| !gate.production_only || class != ReleaseClass::Edge)
    }

    /// Derives the exact gate identities bound into a release plan.
    ///
    /// # Errors
    /// Returns an error if a requirement cannot be canonically encoded.
    pub fn gates(&self, class: ReleaseClass) -> Result<Vec<GateRequirement>> {
        self.selected(class)
            .map(|requirement| {
                Ok(GateRequirement {
                    policy_id: requirement.id.clone(),
                    policy_digest: Sha256Digest::of_canonical(
                        CONTRACT_V1,
                        &(requirement, self.thresholds_for(class)?),
                    )?,
                    required_for_stable: true,
                })
            })
            .collect()
    }

    /// Requires the plan's gate and package populations to match this contract.
    ///
    /// # Errors
    /// Returns an error for policy drift, missing packages, omitted images, or
    /// blocked cells where the selected thresholds require completeness.
    pub fn validate_plan(&self, plan: &ReleasePlanV1) -> Result<()> {
        self.validate()?;
        match &plan.qualification_predecessor {
            Some(prior)
                if prior.registry == plan.registry && prior.release_id != plan.release_id =>
            {
                require_identifier(&prior.release_id, "qualification predecessor release")?;
            }
            _ => bail!("server contract requires a distinct same-registry predecessor"),
        }
        if plan.gates != self.gates(plan.release_class)?
            || plan.public_evidence_policy_digest != Sha256Digest::of_canonical(CONTRACT_V1, self)?
        {
            bail!("release gates or evidence policy differ from the frozen qualification contract");
        }
        let packages: BTreeSet<_> = plan
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        let rules: BTreeSet<_> = self
            .package_rules
            .iter()
            .map(|rule| rule.name.as_str())
            .collect();
        if packages != rules {
            bail!("qualification classification differs from the complete package inventory");
        }
        if plan.images.is_empty() {
            bail!("server qualification requires the Linux image matrix");
        }
        for image in &plan.images {
            if image
                .platforms
                .iter()
                .any(|cell| !matches!(cell.decision, crate::platform::MatrixCell::Artifact { .. }))
            {
                bail!("required server image target is blocked or inapplicable");
            }
        }
        if self
            .thresholds_for(plan.release_class)?
            .require_complete_matrix
            && plan.packages.iter().any(|package| {
                package
                    .platforms
                    .iter()
                    .any(|cell| cell.decision.is_blocked())
            })
        {
            bail!("qualification profile requires a complete package matrix");
        }
        Ok(())
    }
}

fn nonempty_strings(values: &[String], label: &str) -> Result<()> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        bail!("{label} must be nonempty");
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        bail!("duplicate {label}");
    }
    Ok(())
}

fn unique<'a>(values: impl Iterator<Item = &'a str>, label: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_identifier(value, label)?;
        if !seen.insert(value) {
            bail!("duplicate {label}: {value}");
        }
    }
    Ok(())
}
