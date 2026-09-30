//! Qualification profiles, publication destinations, and fitness kinds.
//!
//! A destination is one `(surface role, registry tier, channel kind)` cell of
//! the publication table. It selects a named profile: the bundle of gates,
//! claims, soak, review, matrix completeness, fitness requirements, rollout
//! rings, and override policy that a release must satisfy before it reaches
//! that destination. Fitness kinds describe recurring environment exercises
//! whose signed attestations a profile may demand.
//!
//! ```text
//! profile     -> requirements + claims + soak + review + rings + fitness + override
//! destination -> (surface, tier, channel kind) -> profile, after[]
//! fitness     -> kind + method + bindings + checks
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::limits::{FINAL_RING_PARTITIONS, MINIMUM_QUALIFIED_SOAK_SECONDS};
use super::{QualificationContract, QualificationMethod};
use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::plan::SurfaceRole;
use crate::registry::{RegistryTier, channel_kind};

/// Digest domain binding a profile's obligations into a planned destination.
pub const PROFILE_DIGEST_DOMAIN: &str = "aos.release.qualification-profile/v1";

/// Which scoped assurance claims a profile requires.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimSelection {
    /// No target assurance claim applies.
    None,
    /// Every staging-phase functional claim (A2) applies.
    Functional,
    /// Functional claims plus every completion-phase qualified claim (A3).
    Qualified,
}

/// One cumulative rollout step and the observation required before the next.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutRing {
    /// Cumulative partition count reached by this ring; the last ring is 256.
    pub partitions: u16,
    /// Minimum observation time after this ring before the next may advance.
    pub observe_seconds: u64,
}

/// Ordered rollout rings of a profile or accepted override.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutPolicy {
    /// Strictly increasing cumulative partition counts ending at 256.
    pub rings: Vec<RolloutRing>,
}

/// Freshness a profile demands of one fitness attestation kind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileFitness {
    /// Maximum age of the attestation at publication or advance.
    pub max_age_seconds: u64,
}

/// Fields a signed profile override may relax for one destination.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileOverridePolicy {
    /// Whether an override may lower the observation window.
    pub soak_seconds: bool,
    /// Whether an override may replace the rollout rings.
    pub rings: bool,
}

/// Soak and rollout values in force for one planned destination.
///
/// These are the profile's values unless the plan carries an accepted signed
/// override for the destination, in which case they are the override's.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveProfile {
    /// Minimum observed window for A3 claims and `rollout-observation`.
    pub soak_seconds: u64,
    /// Rollout rings the destination's channel advances through.
    pub rings: Vec<RolloutRing>,
}

/// Named bundle of obligations selected by a destination.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProfile {
    /// Stable profile name referenced by destinations.
    pub name: String,
    /// Human-readable purpose.
    pub description: String,
    /// Release- and package-scope requirement ids required at their own phase.
    pub requirements: Vec<String>,
    /// Target assurance claims required by this profile.
    pub claims: ClaimSelection,
    /// Whether image, container, and package obligations follow the change scope.
    pub change_scoped: bool,
    /// Minimum observed window for A3 claims and `rollout-observation`.
    pub soak_seconds: u64,
    /// Distinct release-evidence reviewer signatures required over the staging report.
    pub review_threshold: u16,
    /// Rejects every blocked package or image cell.
    pub require_complete_matrix: bool,
    /// Requires operator acceptance of the isolated registry transaction.
    pub review_registry_transaction: bool,
    /// Fitness attestation kinds and their maximum age at admission.
    pub fitness: BTreeMap<String, ProfileFitness>,
    /// Rollout rings for the destination's channel.
    pub rollout: RolloutPolicy,
    /// Which fields a signed override may relax.
    #[serde(rename = "override")]
    pub override_policy: ProfileOverridePolicy,
}

impl QualificationProfile {
    /// Computes the identity bound into a planned destination.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Sha256Digest::of_canonical(PROFILE_DIGEST_DOMAIN, self)
    }

    /// Returns whether the profile requires a release- or package-scope requirement.
    #[must_use]
    pub fn requires(&self, requirement_id: &str) -> bool {
        self.requirements.iter().any(|id| id == requirement_id)
    }

    /// Returns the soak and rings in force without an override.
    #[must_use]
    pub fn effective(&self) -> EffectiveProfile {
        EffectiveProfile {
            soak_seconds: self.soak_seconds,
            rings: self.rollout.rings.clone(),
        }
    }

    /// Returns whether any field of this profile may be relaxed by an override.
    #[must_use]
    pub const fn is_overridable(&self) -> bool {
        self.override_policy.soak_seconds || self.override_policy.rings
    }

    /// Validates the profile against the contract's requirement and fitness catalogs.
    ///
    /// # Errors
    /// Returns an error for a malformed name, an unknown or duplicate
    /// requirement, a missing `build-integrity` floor, qualified claims without
    /// `rollout-observation` or with a soak below one day, malformed rings, or
    /// an unknown fitness kind.
    pub fn validate(&self, contract: &QualificationContract) -> Result<()> {
        require_identifier(&self.name, "qualification profile name")?;
        if self.description.trim().is_empty() {
            bail!("qualification profile {} lacks a description", self.name);
        }

        let mut seen = BTreeSet::new();
        for id in &self.requirements {
            let requirement = contract
                .requirements
                .iter()
                .find(|requirement| &requirement.id == id)
                .ok_or_else(|| {
                    anyhow::anyhow!("profile {} references unknown requirement {id}", self.name)
                })?;
            if matches!(
                requirement.scope,
                super::QualificationScope::Images | super::QualificationScope::Containers
            ) {
                bail!(
                    "profile {} selects target-scoped requirement {id}; targets are selected by claims",
                    self.name
                );
            }
            if !seen.insert(id) {
                bail!("profile {} repeats requirement {id}", self.name);
            }
        }
        // Every profile proves the bundle it publishes was built as planned.
        if !self.requires("build-integrity") {
            bail!("profile {} omits the build-integrity floor", self.name);
        }
        if self.claims == ClaimSelection::Qualified {
            if !self.requires("rollout-observation") {
                bail!(
                    "profile {} claims qualified assurance without rollout-observation",
                    self.name
                );
            }
            if self.soak_seconds < MINIMUM_QUALIFIED_SOAK_SECONDS {
                bail!(
                    "profile {} claims qualified assurance with a soak below {MINIMUM_QUALIFIED_SOAK_SECONDS} seconds",
                    self.name
                );
            }
        }

        validate_rings(&self.rollout.rings)
            .map_err(|error| anyhow::anyhow!("profile {}: {error}", self.name))?;
        for kind in self.fitness.keys() {
            if !contract.fitness.iter().any(|fitness| &fitness.kind == kind) {
                bail!("profile {} requires unknown fitness kind {kind}", self.name);
            }
        }
        Ok(())
    }
}

/// Validates cumulative rollout rings: nonempty, strictly increasing, ending at 256.
///
/// # Errors
/// Returns an error for an empty list, a zero or non-increasing partition
/// count, or a final ring other than 256 partitions.
pub fn validate_rings(rings: &[RolloutRing]) -> Result<()> {
    let Some(last) = rings.last() else {
        bail!("rollout requires at least one ring");
    };
    if rings.first().is_some_and(|ring| ring.partitions == 0)
        || rings
            .windows(2)
            .any(|pair| pair[0].partitions >= pair[1].partitions)
    {
        bail!("rollout rings must be strictly increasing cumulative partition counts");
    }
    if last.partitions != FINAL_RING_PARTITIONS {
        bail!("final rollout ring must cover all {FINAL_RING_PARTITIONS} partitions");
    }
    Ok(())
}

/// Returns the inclusive partition range advanced by one-based ring `ring`.
///
/// # Errors
/// Returns an error when `ring` is zero or beyond the last ring.
pub fn ring_range(rings: &[RolloutRing], ring: u16) -> Result<(u16, u16)> {
    let index = usize::from(ring)
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("rollout rings are numbered from 1"))?;
    let current = rings
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("rollout ring {ring} is beyond the planned rings"))?;
    let first = index
        .checked_sub(1)
        .and_then(|previous| rings.get(previous))
        .map_or(0, |previous| previous.partitions);
    let last = current
        .partitions
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("rollout ring {ring} covers no partition"))?;
    Ok((first, last))
}

/// One cell of the publication table and the profile it selects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractDestination {
    /// Publication surface role.
    pub surface: SurfaceRole,
    /// Registry tier whose registries carry this destination.
    pub registry_tier: RegistryTier,
    /// Channel kind: `edge`, `candidate`, or `stable`.
    pub channel: String,
    /// Selected profile name.
    pub profile: String,
    /// Surface roles that must already hold a publication for the same release.
    pub after: Vec<SurfaceRole>,
}

impl ContractDestination {
    /// Returns the destination name for a concrete channel, `<role>/<channel>`.
    #[must_use]
    pub fn name_for(&self, channel: &str) -> String {
        format!("{}/{channel}", self.surface)
    }
}

/// Identity a fitness attestation must bind and match at admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FitnessBinding {
    /// Destination surface identity: Hub deployment id or static surface identity.
    Surface,
    /// Hub schema version; recorded as null for static surfaces.
    HubSchema,
    /// Digest of the plan's signer roster.
    SignerRoster,
    /// Digest of the maintainer tooling closure.
    Tooling,
    /// Digest of the maintainer alert configuration.
    AlertConfig,
}

impl FitnessBinding {
    /// Returns the exact public spelling used as a bindings map key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Surface => "surface",
            Self::HubSchema => "hub-schema",
            Self::SignerRoster => "signer-roster",
            Self::Tooling => "tooling",
            Self::AlertConfig => "alert-config",
        }
    }
}

/// One recurring environment exercise recorded by a signed attestation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FitnessKind {
    /// Stable kind identifier referenced by profiles.
    pub kind: String,
    /// Automated or operator exercise.
    pub method: QualificationMethod,
    /// Identities the attestation must carry and match live values.
    pub bindings: Vec<FitnessBinding>,
    /// Named acceptance conditions; each requires an affirmative observation.
    pub checks: Vec<String>,
}

/// Validates the profile, destination, and fitness tables of a contract.
///
/// # Errors
/// Returns an error for an empty table, a duplicate or malformed entry, an
/// invalid profile, a destination outside the tier's channel policy, a
/// production destination with claims but no review, or a malformed `after`.
pub(super) fn validate_tables(contract: &QualificationContract) -> Result<()> {
    if contract.profiles.is_empty() || contract.destinations.is_empty() {
        bail!("current contracts require profiles and destinations");
    }

    let mut kinds = BTreeSet::new();
    for fitness in &contract.fitness {
        require_identifier(&fitness.kind, "fitness kind")?;
        if !kinds.insert(fitness.kind.as_str()) {
            bail!("duplicate fitness kind {}", fitness.kind);
        }
        if fitness.checks.is_empty()
            || fitness.checks.iter().collect::<BTreeSet<_>>().len() != fitness.checks.len()
            || fitness.bindings.is_empty()
            || fitness.bindings.iter().collect::<BTreeSet<_>>().len() != fitness.bindings.len()
        {
            bail!(
                "fitness kind {} requires distinct checks and bindings",
                fitness.kind
            );
        }
        for check in &fitness.checks {
            require_identifier(check, "fitness check")?;
        }
    }

    let mut names = BTreeSet::new();
    for profile in &contract.profiles {
        profile.validate(contract)?;
        if !names.insert(profile.name.as_str()) {
            bail!("duplicate qualification profile {}", profile.name);
        }
    }

    let mut cells = BTreeSet::new();
    for destination in &contract.destinations {
        let kind = channel_kind(&destination.channel)?;
        if kind != destination.channel {
            bail!(
                "destination channel {} must be a channel kind, not a concrete channel",
                destination.channel
            );
        }
        if !destination
            .registry_tier
            .allowed_channel_kinds()
            .contains(&kind)
        {
            bail!(
                "destination {}/{} is outside the {} tier channel policy",
                destination.surface,
                destination.channel,
                destination.registry_tier
            );
        }
        if !cells.insert((destination.surface, destination.registry_tier, kind)) {
            bail!(
                "duplicate destination {}/{} on the {} tier",
                destination.surface,
                destination.channel,
                destination.registry_tier
            );
        }
        let profile = contract.profile(&destination.profile)?;
        // Every publication to consumers is reviewed by a human when it
        // carries any assurance claim, regardless of software maturity.
        if destination.registry_tier == RegistryTier::Production
            && profile.claims != ClaimSelection::None
            && profile.review_threshold == 0
        {
            bail!(
                "production destination {}/{} carries claims without independent review",
                destination.surface,
                destination.channel
            );
        }
        match destination.surface {
            SurfaceRole::Staging if !destination.after.is_empty() => {
                bail!("staging destinations cannot wait on another surface")
            }
            SurfaceRole::Production if destination.after != [SurfaceRole::Staging] => {
                bail!("production destinations must follow the staging surface")
            }
            SurfaceRole::Staging | SurfaceRole::Production => {}
        }
    }
    Ok(())
}
