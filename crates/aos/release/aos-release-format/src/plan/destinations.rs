//! Planned publication surfaces and destinations.
//!
//! A plan freezes two surfaces (staging and production) and one
//! destination per contract cell compatible with the release class. Each
//! planned destination binds the selected profile's digest, its derived gates,
//! and the soak and rollout rings in force, so a later soak or ring change
//! (including a signed override) changes the plan digest.
//!
//! ```json
//! {"name":"production/stable","surface":"production","channel":"stable",
//!  "profile":"soak","profile_digest":"sha256:...","soak_seconds":604800,
//!  "gates":[{"policy_id":"build-integrity","policy_digest":"sha256:...","blocking":true}],
//!  "rings":[{"partitions":4,"observe_seconds":86400},{"partitions":256,"observe_seconds":0}]}
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{ReleaseClass, ReleasePlan};
use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::evidence::GateRequirement;
use crate::qualification::limits::MINIMUM_QUALIFIED_SOAK_SECONDS;
use crate::qualification::profiles::{EffectiveProfile, RolloutRing, ring_range, validate_rings};
use crate::qualification::{ContractDestination, QualificationContract, QualificationProfile};
use crate::registry::{channel_kind, registry_policy};

/// Role of one publication endpoint in the release pipeline.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceRole {
    /// Qualification surface read by executors and reviewers.
    Staging,
    /// Consumer-facing surface.
    Production,
}

impl SurfaceRole {
    /// Returns the exact public spelling used in destination names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

impl fmt::Display for SurfaceRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SurfaceRole {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "staging" => Ok(Self::Staging),
            "production" => Ok(Self::Production),
            _ => bail!("unknown surface role: {value}"),
        }
    }
}

/// Implementation kind of a publication surface.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceKind {
    /// An AOS Hub deployment reached through its RPC publication protocol.
    Hub,
    /// A static origin (filesystem, S3, SFTP, or read-only HTTPS) written directly.
    Static,
}

/// One frozen publication endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSurface {
    /// Staging or production.
    pub role: SurfaceRole,
    /// Hub deployment or static origin.
    pub kind: SurfaceKind,
    /// Public read-back origin, or the upload origin for static surfaces, such as
    /// `https://aos.staging.andyl.org`, `file:///srv/registry`, or `s3://bucket/prefix`.
    pub origin: String,
    /// Anonymous HTTPS or file origin used for read-back when `origin` is not
    /// anonymously fetchable (S3, SFTP). `None` means the same as `origin`.
    pub readback_origin: Option<String>,
    /// Hub deployment id, or the static surface identity served at `<readback>/.aos-surface`.
    pub identity: String,
}

impl PlannedSurface {
    /// Returns the origin from which the surface is read back anonymously.
    #[must_use]
    pub fn readback(&self) -> &str {
        self.readback_origin.as_deref().unwrap_or(&self.origin)
    }

    /// Validates identities and origin schemes for the surface kind.
    ///
    /// # Errors
    /// Returns an error for a malformed identity, an origin scheme the kind
    /// does not support, or a read-back origin that is not anonymously
    /// fetchable.
    pub fn validate(&self) -> Result<()> {
        require_identifier(&self.identity, "surface identity")?;
        let allowed: &[&str] = match self.kind {
            SurfaceKind::Hub => &["https://"],
            SurfaceKind::Static => &["https://", "file://", "s3://", "sftp://"],
        };
        require_origin(&self.origin, allowed, "surface origin")?;
        if let Some(readback) = &self.readback_origin {
            require_origin(
                readback,
                &["https://", "file://"],
                "surface read-back origin",
            )?;
        } else if !self.origin.starts_with("https://") && !self.origin.starts_with("file://") {
            bail!(
                "surface {} requires an anonymous read-back origin",
                self.role
            );
        }
        Ok(())
    }
}

fn require_origin(value: &str, allowed: &[&str], label: &str) -> Result<()> {
    if !allowed.iter().any(|scheme| value.starts_with(scheme))
        || value.ends_with('/')
        || value.contains('?')
        || value.contains('#')
        || value.contains('@')
        || value.contains(char::is_whitespace)
    {
        bail!("{label} must be a bare origin using one of {allowed:?}: {value}");
    }
    Ok(())
}

/// One planned publication destination and the obligations bound to it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedDestination {
    /// `<surface role>/<channel>`, such as `production/stable-2026.3`.
    pub name: String,
    /// Surface the channel lives on.
    pub surface: SurfaceRole,
    /// Full channel name, such as `stable` or `stable-2026.3`.
    pub channel: String,
    /// Selected contract profile name.
    pub profile: String,
    /// Digest of the selected profile's obligations.
    pub profile_digest: Sha256Digest,
    /// Observation window in force: the profile's, or an accepted override's.
    pub soak_seconds: u64,
    /// Exact gate identities derived for this destination.
    pub gates: Vec<GateRequirement>,
    /// Rollout rings in force: the profile's, or an accepted override's.
    pub rings: Vec<RolloutRing>,
}

impl PlannedDestination {
    /// Returns the soak and rings in force for this destination.
    #[must_use]
    pub fn effective(&self) -> EffectiveProfile {
        EffectiveProfile {
            soak_seconds: self.soak_seconds,
            rings: self.rings.clone(),
        }
    }

    /// Returns the inclusive partition range advanced by one-based ring `ring`.
    ///
    /// # Errors
    /// Returns an error when `ring` is zero or beyond the planned rings.
    pub fn ring_range(&self, ring: u16) -> Result<(u16, u16)> {
        ring_range(&self.rings, ring)
    }

    /// Returns the channel kind of this destination's channel.
    ///
    /// # Errors
    /// Returns an error for a malformed channel name.
    pub fn channel_kind(&self) -> Result<&str> {
        channel_kind(&self.channel)
    }
}

/// Reference to an accepted signed profile override bound into the plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileOverrideRef {
    /// Destination name the override relaxes.
    pub destination: String,
    /// Canonical digest of the accepted override payload.
    pub override_digest: Sha256Digest,
}

/// Destination requested before planning fills in the contract's obligations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedDestination {
    /// Surface the channel lives on.
    pub surface: SurfaceRole,
    /// Full channel name.
    pub channel: String,
    /// Soak and rings accepted by a signed override; `None` uses the profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<EffectiveProfile>,
}

/// Splits `<role>/<channel>` into its surface role and channel name.
///
/// # Errors
/// Returns an error for a missing separator, an unknown role, or a channel
/// whose kind is not `edge`, `candidate`, or `stable`.
pub fn parse_destination_name(name: &str) -> Result<(SurfaceRole, &str)> {
    let (role, channel) = name
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("destination name must be <surface>/<channel>: {name}"))?;
    let role = role.parse()?;
    channel_kind(channel)?;
    Ok((role, channel))
}

/// Returns whether a release class may be published to a channel kind.
///
/// Edge versions reach only edge channels; release candidates only candidate
/// channels; final versions go to candidate and then stable.
#[must_use]
pub fn class_allows_channel_kind(class: ReleaseClass, kind: &str) -> bool {
    match class {
        ReleaseClass::Edge => kind == "edge",
        ReleaseClass::Candidate => kind == "candidate",
        ReleaseClass::Stable => matches!(kind, "candidate" | "stable"),
    }
}

/// Requires the plan's surfaces and destinations to be exactly those the
/// contract prescribes for its registry tier and release class.
///
/// # Errors
/// Returns an error for missing or duplicate surfaces, identical surface
/// identities, a destination set differing from the contract's, profile or
/// gate drift, an invalid or missing change scope, an override outside the
/// profile's policy, or an unsatisfiable `after` prerequisite.
pub(crate) fn validate_planned_destinations(
    plan: &ReleasePlan,
    contract: &QualificationContract,
) -> Result<()> {
    validate_surfaces(plan)?;
    if let Some(scope) = &plan.change_scope {
        scope.validate()?;
    }
    if plan.is_qualification_snapshot() {
        if !plan.destinations.is_empty() || !plan.profile_overrides.is_empty() {
            bail!("qualification snapshots have no publication destinations");
        }
        return Ok(());
    }

    let tier = registry_policy(&plan.registry)?.tier();
    let expected: Vec<&ContractDestination> = contract
        .destinations_for(tier)
        .filter(|destination| class_allows_channel_kind(plan.release_class, &destination.channel))
        .collect();
    if expected.is_empty() {
        bail!(
            "{:?} releases have no destination on the {tier} registry tier",
            plan.release_class
        );
    }
    if plan.destinations.len() != expected.len() {
        bail!(
            "plan selects {} destinations; the contract prescribes {} for this tier and class",
            plan.destinations.len(),
            expected.len()
        );
    }

    let mut names = BTreeSet::new();
    let mut matched = BTreeSet::new();
    for planned in &plan.destinations {
        if !names.insert(planned.name.as_str()) {
            bail!("duplicate planned destination {}", planned.name);
        }
        let (role, channel) = parse_destination_name(&planned.name)?;
        if role != planned.surface || channel != planned.channel {
            bail!(
                "destination name {} disagrees with its surface or channel",
                planned.name
            );
        }
        let kind = channel_kind(channel)?;
        let cell = expected
            .iter()
            .find(|destination| destination.surface == role && destination.channel == kind)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "destination {} is not prescribed for this tier and release class",
                    planned.name
                )
            })?;
        if !matched.insert((role, kind)) {
            bail!("destination cell {role}/{kind} is planned twice");
        }
        let profile = contract.profile(&cell.profile)?;
        if planned.profile != profile.name || planned.profile_digest != profile.digest()? {
            bail!(
                "destination {} binds a different profile than the contract selects",
                planned.name
            );
        }
        if planned.gates != contract.gates(cell, plan.change_scope.as_ref())? {
            bail!(
                "destination {} gates differ from the contract and change scope",
                planned.name
            );
        }
        validate_effective_values(plan, planned, profile)?;
        for after in &cell.after {
            if !plan
                .destinations
                .iter()
                .any(|other| other.surface == *after && other.channel == planned.channel)
            {
                bail!(
                    "destination {} must follow {after}/{} but the plan has no such destination",
                    planned.name,
                    planned.channel
                );
            }
        }
    }

    if plan.change_scope.is_none()
        && expected
            .iter()
            .map(|destination| contract.profile(&destination.profile))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .any(|profile| profile.change_scoped)
    {
        bail!("a change-scoped destination profile requires a recorded change scope");
    }

    let mut overridden = BTreeSet::new();
    for reference in &plan.profile_overrides {
        if !names.contains(reference.destination.as_str()) {
            bail!(
                "profile override references unplanned destination {}",
                reference.destination
            );
        }
        if !overridden.insert(reference.destination.as_str()) {
            bail!(
                "destination {} carries more than one profile override",
                reference.destination
            );
        }
    }
    Ok(())
}

fn validate_surfaces(plan: &ReleasePlan) -> Result<()> {
    let mut roles = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for surface in &plan.surfaces {
        surface.validate()?;
        if !roles.insert(surface.role) {
            bail!("plan declares surface role {} twice", surface.role);
        }
        if !identities.insert(surface.identity.as_str()) {
            bail!("staging and production surface identities must differ");
        }
    }
    for required in [SurfaceRole::Staging, SurfaceRole::Production] {
        if !roles.contains(&required) {
            bail!("plan lacks its {required} surface");
        }
    }

    // A production Hub admits bundles only with a staging receipt it can
    // verify, and it cannot yet verify receipts signed for static staging.
    let kind = |role| {
        plan.surfaces
            .iter()
            .find(|surface| surface.role == role)
            .map(|surface| surface.kind)
    };
    if kind(SurfaceRole::Staging) == Some(SurfaceKind::Static)
        && kind(SurfaceRole::Production) == Some(SurfaceKind::Hub)
    {
        bail!(
            "a static staging surface cannot precede a production Hub: the Hub cannot verify static staging receipts yet"
        );
    }
    Ok(())
}

/// Requires the destination's soak and rings to be the profile's, or an
/// accepted override's within the profile's override policy and the floors.
fn validate_effective_values(
    plan: &ReleasePlan,
    planned: &PlannedDestination,
    profile: &QualificationProfile,
) -> Result<()> {
    validate_rings(&planned.rings)
        .map_err(|error| anyhow::anyhow!("destination {}: {error}", planned.name))?;
    let overridden = plan
        .profile_overrides
        .iter()
        .any(|reference| reference.destination == planned.name);
    let soak_changed = planned.soak_seconds != profile.soak_seconds;
    let rings_changed = planned.rings != profile.rollout.rings;

    if !overridden {
        if soak_changed || rings_changed {
            bail!(
                "destination {} relaxes its profile without an accepted override",
                planned.name
            );
        }
        return Ok(());
    }
    if !profile.is_overridable() {
        bail!(
            "destination {} profile {} permits no override",
            planned.name,
            profile.name
        );
    }
    if soak_changed && !profile.override_policy.soak_seconds {
        bail!(
            "destination {} override changes a soak the profile does not permit",
            planned.name
        );
    }
    if rings_changed && !profile.override_policy.rings {
        bail!(
            "destination {} override changes rings the profile does not permit",
            planned.name
        );
    }
    if planned.soak_seconds < MINIMUM_QUALIFIED_SOAK_SECONDS {
        bail!(
            "destination {} override lowers the soak below {MINIMUM_QUALIFIED_SOAK_SECONDS} seconds",
            planned.name
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "destinations_tests.rs"]
mod tests;
