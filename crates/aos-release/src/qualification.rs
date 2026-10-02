//! Shared qualification policy, scoped assurance and release applicability.
//!
//! Nix exports this document; the coordinator canonicalizes it and embeds it in
//! the signed plan. Offline consumers need neither Nix nor the source checkout.
//!
//! ```text
//! qualification-contract
//!   promises + exclusions + typed targets + claims + requirements + package_rules
//!   profiles[build | smoke | functional | soak]
//!   destinations[(surface, tier, channel kind) -> profile]
//!   fitness[storage-restore | alert-delivery | authority-recovery | hub-restore | key-rotation]
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::evidence::GateRequirement;
use crate::plan::{
    QUALIFICATION_SNAPSHOT_RELEASE_PREFIX, QUALIFICATION_SNAPSHOT_TAG_PREFIX, ReleasePlan,
    SurfaceRole,
};
use crate::platform::Platform;
use crate::registry::RegistryTier;

pub mod capabilities;
pub mod change_scope;
pub mod claims;
pub mod environment;
mod floors;
pub mod limits;
pub mod profiles;

#[cfg(test)]
mod plan_tests;

pub use change_scope::ChangeScope;
pub use profiles::{
    ClaimSelection, ContractDestination, EffectiveProfile, FitnessBinding, FitnessKind,
    ProfileFitness, ProfileOverridePolicy, QualificationProfile, RolloutPolicy, RolloutRing,
};

/// Schema of the qualification contract.
pub const QUALIFICATION_CONTRACT: &str = "aos.release.qualification-contract/v2";

/// Reviewed identity every qualification contract carries.
pub const QUALIFICATION_CONTRACT_ID: &str = "aos-system-v2";

/// Digest domain for requirement and claim gate policies.
pub const GATE_POLICY_DOMAIN: &str = "aos.release.gate-policy/v1";

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
    /// Typed environment scope, including execution topology.
    pub environment: environment::EnvironmentProfile,
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

/// Booted execution required to prove a package's functional behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PackageExecution {
    /// Exercises the package from recovery UKIs in one system image variant.
    RecoveryImage {
        /// Exact system image variant carrying the package.
        system_variant: String,
    },
    /// Exercises authenticated K3s packages and the published OCI workload in a fleet.
    K3sFleet {
        /// Exact system image variant booted by both fleet members.
        system_variant: String,
        /// Server and worker roles whose package artifacts enter the case subjects.
        topology: K3sTopology,
    },
}

/// Supported K3s service arrangements for staged package qualification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum K3sTopology {
    /// Schedules workloads on a combined server and its separate worker.
    CombinedWorker,
    /// Runs an agentless control plane and schedules workloads on its worker.
    ControlPlaneWorker,
}

impl K3sTopology {
    /// Returns the complete package population exercised by this topology.
    #[must_use]
    pub const fn packages(self) -> [&'static str; 3] {
        match self {
            Self::CombinedWorker => ["k3s", "k3s-combined", "k3s-worker"],
            Self::ControlPlaneWorker => ["k3s", "k3s-control-plane", "k3s-worker"],
        }
    }
}

impl PackageExecution {
    /// Returns the system image variant required by this execution environment.
    #[must_use]
    pub fn system_variant(&self) -> &str {
        match self {
            Self::RecoveryImage { system_variant } | Self::K3sFleet { system_variant, .. } => {
                system_variant
            }
        }
    }
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
    /// Special execution environment required by this package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<PackageExecution>,
}

/// Shared requirement with applicability at one hold point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRequirement {
    /// Stable requirement identity across destinations.
    pub id: String,
    /// Exact evaluated native-adapter matrix for the matrix requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_operation_spec:
        Option<crate::qualification_evidence::NativeOperationQualificationSpec>,
    /// Restricts a native ability obligation to production-tier destinations.
    #[serde(default, skip_serializing_if = "is_false")]
    pub production_only: bool,
    /// Hold point that requires the result.
    pub phase: QualificationPhase,
    /// Subject population, expanded from the signed artifact matrix.
    pub scope: QualificationScope,
    /// Required observation method.
    pub method: QualificationMethod,
    /// Named acceptance conditions; each requires an affirmative observation.
    pub checks: Vec<String>,
    /// Existing Nix regression coverage; never substitutes for live evidence.
    pub regressions: Vec<String>,
    /// Identities whose change invalidates previous observations.
    pub invalidated_by: Vec<String>,
    /// Numeric acceptance bounds checked independently of textual assertions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub measurements: BTreeMap<String, claims::MeasurementRequirement>,
}

/// One authoritative qualification policy for testing and production.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationContract {
    /// Exact document schema.
    pub schema_version: String,
    /// Reviewed contract identity.
    pub id: String,
    /// User-visible functional obligations.
    pub promises: Vec<String>,
    /// Explicit boundaries of the claims.
    pub exclusions: Vec<String>,
    /// Required reference environments.
    pub targets: Vec<QualificationTarget>,
    /// Complete package classification, independent of platform eligibility.
    pub package_rules: Vec<PackageRule>,
    /// Shared gate catalog.
    pub requirements: Vec<QualificationRequirement>,
    /// Scoped assurance obligations.
    pub claims: Vec<claims::QualificationClaim>,
    /// Release-train support promise, copied verbatim into the signed
    /// registry's `[support]` table.
    pub support: aos_registry_surface::support::SupportPolicy,
    /// Named obligation bundles.
    pub profiles: Vec<QualificationProfile>,
    /// Publication table selecting a profile per surface, tier, and channel kind.
    pub destinations: Vec<ContractDestination>,
    /// Recurring environment exercises that profiles may require.
    pub fitness: Vec<FitnessKind>,
}

impl QualificationContract {
    /// Validates the catalog and minimum server-contract obligations.
    ///
    /// # Errors
    /// Returns an error for an unknown schema or identity, missing
    /// classifications, duplicate identities, absent mandatory gates, weakened
    /// assurance floors, or an invalid support policy, profile, destination,
    /// or fitness table.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != QUALIFICATION_CONTRACT || self.id != QUALIFICATION_CONTRACT_ID {
            bail!("unsupported qualification contract");
        }
        self.support
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid support policy: {error}"))?;

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
        self.validate_package_rules()?;
        self.validate_targets()?;
        for gate in &self.requirements {
            nonempty_strings(&gate.checks, "acceptance conditions")?;
            claims::merge_measurements(&mut BTreeMap::new(), &gate.measurements)?;
            if gate.id == crate::qualification_evidence::NATIVE_ADAPTER_MATRIX_REQUIREMENT {
                let spec = gate.native_operation_spec.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "native adapter matrix requirement lacks its exact specification"
                    )
                })?;
                crate::qualification_evidence::validate_native_operation_qualification_spec(spec)?;
                if gate
                    .checks
                    .iter()
                    .filter(|check| {
                        check.as_str() == crate::qualification_evidence::NATIVE_ADAPTER_MATRIX_CHECK
                    })
                    .count()
                    != 1
                {
                    bail!("native adapter matrix requirement lacks its stable acceptance check");
                }
            } else if gate.native_operation_spec.is_some() {
                bail!("non-matrix qualification requirement carries a native adapter matrix");
            }
            for identity in ["subject", "policy", "executor", "environment"] {
                if !gate.invalidated_by.iter().any(|value| value == identity) {
                    bail!("requirement {} omits invalidation by {identity}", gate.id);
                }
            }
        }
        floors::validate_requirement_floors(self)?;
        claims::validate_claims(self)?;
        floors::validate_assurance_floors(self)?;
        profiles::validate_tables(self)
    }

    fn validate_package_rules(&self) -> Result<()> {
        if self.package_rules.is_empty()
            || self
                .package_rules
                .iter()
                .any(|rule| !rule.inherit_dependency_obligations)
        {
            bail!("qualification must classify packages and inherit dependency obligations");
        }
        for rule in &self.package_rules {
            let Some(execution) = &rule.execution else {
                continue;
            };
            require_identifier(
                execution.system_variant(),
                "package execution image variant",
            )?;
            if let PackageExecution::K3sFleet { topology, .. } = execution {
                if !topology.packages().contains(&rule.name.as_str()) {
                    bail!("K3s fleet topology does not exercise package {}", rule.name);
                }
                for package in topology.packages() {
                    if !self.package_rules.iter().any(|rule| rule.name == package) {
                        bail!("K3s fleet lacks its companion package rule {package}");
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_targets(&self) -> Result<()> {
        for target in &self.targets {
            if !target.platform.supports_images() {
                bail!("reference image/container targets require Linux and explicit configuration");
            }
            target.environment.validate(target.platform)?;
            match (target.kind, target.environment.boot) {
                (TargetKind::Image, environment::BootImplementation::SystemdBootUki)
                | (TargetKind::Container, environment::BootImplementation::LinuxContainer) => {}
                _ => bail!("target boot implementation differs from its artifact kind"),
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
        Ok(())
    }

    /// Computes the policy identity under its schema domain.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Sha256Digest::of_canonical(&self.schema_version, self)
    }

    /// Returns the named profile.
    ///
    /// # Errors
    /// Returns an error when no profile has that name.
    pub fn profile(&self, name: &str) -> Result<&QualificationProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.name == name)
            .ok_or_else(|| anyhow::anyhow!("unknown qualification profile {name}"))
    }

    /// Returns the destination cell for a tier, surface, and channel kind.
    ///
    /// # Errors
    /// Returns an error when the contract has no such destination.
    pub fn destination(
        &self,
        tier: RegistryTier,
        surface: SurfaceRole,
        channel_kind: &str,
    ) -> Result<&ContractDestination> {
        self.destinations
            .iter()
            .find(|destination| {
                destination.registry_tier == tier
                    && destination.surface == surface
                    && destination.channel == channel_kind
            })
            .ok_or_else(|| {
                anyhow::anyhow!("{surface}/{channel_kind} is not a destination on the {tier} tier")
            })
    }

    /// Returns every destination carried by registries of one tier, in contract order.
    pub fn destinations_for(
        &self,
        tier: RegistryTier,
    ) -> impl Iterator<Item = &ContractDestination> {
        self.destinations
            .iter()
            .filter(move |destination| destination.registry_tier == tier)
    }

    /// Returns the named fitness kind.
    ///
    /// # Errors
    /// Returns an error when no fitness kind has that identifier.
    pub fn fitness_kind(&self, kind: &str) -> Result<&FitnessKind> {
        self.fitness
            .iter()
            .find(|fitness| fitness.kind == kind)
            .ok_or_else(|| anyhow::anyhow!("unknown fitness kind {kind}"))
    }

    /// Returns the requirement ids every profile requires: the destination-
    /// independent baseline used for build evidence and snapshots.
    #[must_use]
    pub fn baseline_requirements(&self) -> BTreeSet<&str> {
        let mut profiles = self.profiles.iter();
        let Some(first) = profiles.next() else {
            return BTreeSet::new();
        };
        let mut baseline: BTreeSet<&str> = first.requirements.iter().map(String::as_str).collect();
        for profile in profiles {
            baseline.retain(|id| profile.requires(id));
        }
        baseline
    }

    /// Derives the gate identity of one requirement.
    ///
    /// # Errors
    /// Returns an error if the requirement cannot be canonically encoded.
    pub fn requirement_gate(
        &self,
        requirement: &QualificationRequirement,
    ) -> Result<GateRequirement> {
        Ok(GateRequirement {
            policy_id: requirement.id.clone(),
            policy_digest: Sha256Digest::of_canonical(GATE_POLICY_DOMAIN, requirement)?,
            blocking: true,
        })
    }

    /// Derives the gate identity of one claim, bound to its target and
    /// the referenced requirements in contract order.
    ///
    /// # Errors
    /// Returns an error for an unknown target or requirement, or a failed
    /// canonical encoding.
    pub fn claim_gate(&self, claim: &claims::QualificationClaim) -> Result<GateRequirement> {
        let target = self
            .targets
            .iter()
            .find(|target| target.id == claim.target)
            .ok_or_else(|| anyhow::anyhow!("claim {} references an unknown target", claim.id))?;
        let requirements: Vec<_> = self
            .requirements
            .iter()
            .filter(|requirement| claim.requirements.contains(&requirement.id))
            .collect();
        if requirements.len() != claim.requirements.len() {
            bail!("claim {} references an unknown requirement", claim.id);
        }
        Ok(GateRequirement {
            policy_id: format!("claim-{}", claim.id),
            policy_digest: Sha256Digest::of_canonical(
                GATE_POLICY_DOMAIN,
                &(claim, target, requirements),
            )?,
            blocking: claim.blocks_release,
        })
    }

    /// Returns whether a claim applies under a profile's selection and change scope.
    ///
    /// # Errors
    /// Returns an error for an unknown claim target, or a change-scoped profile
    /// evaluated without a recorded change scope.
    pub fn claim_applies(
        &self,
        profile: &QualificationProfile,
        claim: &claims::QualificationClaim,
        scope: Option<&ChangeScope>,
    ) -> Result<bool> {
        let selected = match profile.claims {
            ClaimSelection::None => false,
            ClaimSelection::Functional => claim.phase == QualificationPhase::Staging,
            ClaimSelection::Qualified => true,
        };
        if !selected {
            return Ok(false);
        }
        if !profile.change_scoped {
            return Ok(true);
        }
        let scope = scope.ok_or_else(|| {
            anyhow::anyhow!(
                "change-scoped profile {} requires a recorded change scope",
                profile.name
            )
        })?;
        let target = self
            .targets
            .iter()
            .find(|target| target.id == claim.target)
            .ok_or_else(|| anyhow::anyhow!("claim {} references an unknown target", claim.id))?;
        Ok(match target.kind {
            TargetKind::Image => scope.image_affecting,
            TargetKind::Container => scope.container_affecting,
        })
    }

    /// Derives the exact gate identities of one destination under a change scope.
    ///
    /// Requirement gates follow the profile's requirement list; claim gates
    /// follow its claim selection, narrowed by the change scope when the
    /// profile is change-scoped. `scope` may be `None` only for profiles that
    /// are not change-scoped.
    ///
    /// # Errors
    /// Returns an error for an unknown profile, a change-scoped profile
    /// without a scope, or a failed canonical encoding.
    pub fn gates(
        &self,
        destination: &ContractDestination,
        scope: Option<&ChangeScope>,
    ) -> Result<Vec<GateRequirement>> {
        let profile = self.profile(&destination.profile)?;
        let mut gates = self
            .requirements
            .iter()
            .filter(|requirement| profile.requires(&requirement.id))
            .filter(|requirement| {
                !requirement.production_only
                    || destination.registry_tier == RegistryTier::Production
            })
            .map(|requirement| self.requirement_gate(requirement))
            .collect::<Result<Vec<_>>>()?;
        for claim in &self.claims {
            if self.claim_applies(profile, claim, scope)? {
                gates.push(self.claim_gate(claim)?);
            }
        }
        Ok(gates)
    }

    /// Requires the plan's gate and package populations to match this contract.
    ///
    /// # Errors
    /// Returns an error for policy drift, missing packages, omitted images,
    /// invalid destinations, or blocked cells where a selected profile requires
    /// completeness.
    pub fn validate_plan(&self, plan: &ReleasePlan) -> Result<()> {
        self.validate()?;
        let snapshot_release_id =
            format!("{QUALIFICATION_SNAPSHOT_RELEASE_PREFIX}{}", plan.version);
        let snapshot_source_tag = format!("{QUALIFICATION_SNAPSHOT_TAG_PREFIX}{}", plan.version);
        match &plan.qualification_predecessor {
            Some(prior)
                if prior.registry == plan.registry
                    && prior.release_id != plan.release_id
                    && !plan
                        .release_id
                        .starts_with(QUALIFICATION_SNAPSHOT_RELEASE_PREFIX)
                    && !plan
                        .source
                        .source_tag
                        .starts_with(QUALIFICATION_SNAPSHOT_TAG_PREFIX) =>
            {
                require_identifier(&prior.release_id, "qualification predecessor release")?;
            }
            None if plan.release_id == snapshot_release_id
                && plan.source.source_tag == snapshot_source_tag
                && plan.destinations.is_empty() => {}
            _ => {
                bail!(
                    "server contract requires a distinct same-registry predecessor or an explicitly reserved non-public qualification snapshot"
                )
            }
        }
        if plan.public_evidence_policy_digest != self.digest()? {
            bail!("release evidence policy differs from the frozen qualification contract");
        }
        crate::plan::destinations::validate_planned_destinations(plan, self)?;

        // The complete inventory also retains packages excluded from every
        // publication target. Blocked eligible targets still require rules.
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
        self.validate_package_execution_images(plan)?;
        if self.requires_complete_matrix(plan)?
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

    /// Returns whether any selected obligation rejects blocked matrix cells.
    ///
    /// # Errors
    /// Returns an error for an unknown destination profile.
    pub fn requires_complete_matrix(&self, plan: &ReleasePlan) -> Result<bool> {
        for destination in &plan.destinations {
            if self.profile(&destination.profile)?.require_complete_matrix {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Rejects missing package execution images before builds or signatures.
    fn validate_package_execution_images(&self, plan: &ReleasePlan) -> Result<()> {
        use crate::platform::MatrixCell;

        for package in &plan.packages {
            let Some(execution) = self
                .package_rules
                .iter()
                .find(|rule| rule.name == package.name)
                .and_then(|rule| rule.execution.as_ref())
            else {
                continue;
            };

            for cell in package
                .platforms
                .iter()
                .filter(|cell| matches!(cell.decision, MatrixCell::Artifact { .. }))
            {
                let variant = execution.system_variant();
                let bound_image = plan
                    .images
                    .iter()
                    .find(|image| image.system_variant == variant);
                let image_cell = bound_image.and_then(|image| {
                    image
                        .platforms
                        .iter()
                        .find(|image_cell| image_cell.platform == cell.platform)
                });
                if !image_cell.is_some_and(|image_cell| {
                    matches!(image_cell.decision, MatrixCell::Artifact { .. })
                }) {
                    bail!(
                        "package {} requires execution image {variant} for {} in the release plan",
                        package.name,
                        cell.platform,
                    );
                }
            }
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

fn is_false(value: &bool) -> bool {
    !*value
}
