//! Threshold-signed relaxations of one destination's soak and rollout rings.
//!
//! An emergency is planned, not improvised: release-evidence signers approve
//! a profile override that references an incident, the planner applies it to
//! the requested destination, and the plan binds the override's digest in
//! `profile_overrides`. Only fields the profile marks overridable may change;
//! the soak may never drop below one day and the rings must still end at 256.
//!
//! ```json
//! {"schema_version":"aos.release.profile-override/v1",
//!  "registry":"andyl/main","release_id":"release-2026.9.1",
//!  "destination":"production/stable","incident_reference":"INC-2026-0042",
//!  "soak_seconds":86400,
//!  "rings":[{"partitions":32,"observe_seconds":3600},{"partitions":256,"observe_seconds":0}],
//!  "authority_id":"release-evidence-v1","approved_at":"2026-09-02T00:00:00Z"}
//! ```
//!
//! Each signer submits a separate signed envelope whose payload carries its
//! own `authority_id` and `approved_at`; every other field must agree. The
//! override identity bound into the plan covers only the agreed fields.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::plan::{ProfileOverrideRef, ReleasePlan, RequestedDestination, parse_destination_name};
use crate::qualification::limits::MINIMUM_QUALIFIED_SOAK_SECONDS;
use crate::qualification::profiles::validate_rings;
use crate::qualification::{
    EffectiveProfile, QualificationContract, QualificationProfile, RolloutRing,
};
use crate::registry::{channel_kind, registry_policy};
use crate::signing::{SignerRequirement, SignerRole, TrustedEd25519Key};

/// Exact profile-override schema identifier and digest domain.
pub const PROFILE_OVERRIDE: &str = "aos.release.profile-override/v1";

/// One signer's approval of a relaxed soak and rollout for one destination.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileOverride {
    /// Exact override schema.
    pub schema_version: String,
    /// Registry trust domain of the release.
    pub registry: String,
    /// Immutable release identity the override applies to.
    pub release_id: String,
    /// Destination name, `<role>/<channel>`.
    pub destination: String,
    /// Incident record justifying the relaxation.
    pub incident_reference: String,
    /// Replacement observation window; at least one day.
    pub soak_seconds: Option<u64>,
    /// Replacement rollout rings; must still end at 256 partitions.
    pub rings: Option<Vec<RolloutRing>>,
    /// Release-evidence key that signed this approval.
    pub authority_id: String,
    /// RFC 3339 UTC approval time.
    pub approved_at: String,
}

/// Signer-independent fields whose digest the plan binds.
#[derive(Serialize)]
struct OverrideBody<'a> {
    registry: &'a str,
    release_id: &'a str,
    destination: &'a str,
    incident_reference: &'a str,
    soak_seconds: Option<u64>,
    rings: Option<&'a [RolloutRing]>,
}

impl ProfileOverride {
    /// Computes the signer-independent override identity bound into a plan.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn digest(&self) -> Result<Sha256Digest> {
        Sha256Digest::of_canonical(
            PROFILE_OVERRIDE,
            &OverrideBody {
                registry: &self.registry,
                release_id: &self.release_id,
                destination: &self.destination,
                incident_reference: &self.incident_reference,
                soak_seconds: self.soak_seconds,
                rings: self.rings.as_deref(),
            },
        )
    }

    /// Validates the override against the destination's profile.
    ///
    /// # Errors
    /// Returns an error for a wrong schema, malformed identities or time, an
    /// override that changes nothing, a field the profile does not mark
    /// overridable, a soak below [`MINIMUM_QUALIFIED_SOAK_SECONDS`], or rings
    /// that are not strictly increasing to 256.
    pub fn validate(&self, profile: &QualificationProfile) -> Result<()> {
        if self.schema_version != PROFILE_OVERRIDE {
            bail!("unsupported profile override schema");
        }
        registry_policy(&self.registry)?;
        require_identifier(&self.release_id, "override release id")?;
        require_identifier(&self.authority_id, "override authority id")?;
        parse_destination_name(&self.destination)?;
        if self.incident_reference.trim().is_empty() {
            bail!("profile override must reference an incident record");
        }
        if !self.approved_at.ends_with('Z') || humantime::parse_rfc3339(&self.approved_at).is_err()
        {
            bail!("profile override approval time must be RFC 3339 UTC");
        }
        if self.soak_seconds.is_none() && self.rings.is_none() {
            bail!("profile override relaxes nothing");
        }

        if let Some(soak) = self.soak_seconds {
            if !profile.override_policy.soak_seconds {
                bail!(
                    "profile {} does not permit overriding its soak",
                    profile.name
                );
            }
            if soak < MINIMUM_QUALIFIED_SOAK_SECONDS {
                bail!(
                    "profile override soak {soak} is below {MINIMUM_QUALIFIED_SOAK_SECONDS} seconds"
                );
            }
        }
        if let Some(rings) = &self.rings {
            if !profile.override_policy.rings {
                bail!(
                    "profile {} does not permit overriding its rings",
                    profile.name
                );
            }
            validate_rings(rings)?;
        }
        Ok(())
    }

    /// Returns the soak and rings in force after applying this override.
    ///
    /// # Errors
    /// Returns any [`ProfileOverride::validate`] failure.
    pub fn apply(&self, profile: &QualificationProfile) -> Result<EffectiveProfile> {
        self.validate(profile)?;
        Ok(EffectiveProfile {
            soak_seconds: self.soak_seconds.unwrap_or(profile.soak_seconds),
            rings: self
                .rings
                .clone()
                .unwrap_or_else(|| profile.rollout.rings.clone()),
        })
    }
}

/// A profile override that reached its signer threshold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedOverride {
    /// Agreed override fields (taken from the first verified approval).
    pub payload: ProfileOverride,
    /// Soak and rings in force for the destination.
    pub effective: EffectiveProfile,
    /// Reference the plan must carry in `profile_overrides`.
    pub reference: ProfileOverrideRef,
    /// Distinct release-evidence keys that approved, sorted.
    pub signers: Vec<String>,
}

impl AcceptedOverride {
    /// Returns the planner request that applies this override.
    ///
    /// # Errors
    /// Returns an error for a malformed destination name.
    pub fn requested_destination(&self) -> Result<RequestedDestination> {
        let (surface, channel) = parse_destination_name(&self.payload.destination)?;
        Ok(RequestedDestination {
            surface,
            channel: channel.to_owned(),
            effective: Some(self.effective.clone()),
        })
    }

    /// Requires `plan` to bind this override and its effective values.
    ///
    /// # Errors
    /// Returns an error when the plan omits the override reference, names a
    /// different release, or freezes different soak or rings for the
    /// destination.
    pub fn validate_for(&self, plan: &ReleasePlan) -> Result<()> {
        if plan.registry != self.payload.registry || plan.release_id != self.payload.release_id {
            bail!("profile override names a different release");
        }
        if !plan.profile_overrides.contains(&self.reference) {
            bail!("plan does not bind the accepted profile override");
        }
        if plan.destination(&self.payload.destination)?.effective() != self.effective {
            bail!("plan destination differs from the accepted override");
        }
        Ok(())
    }
}

/// Verifies threshold-signed approvals of one profile override.
///
/// Every envelope must be signed by a distinct key of the release-evidence
/// role in `signers`, carry that key as `authority_id`, and agree on every
/// other field; the number of approvals must reach the role threshold. The
/// override is validated against the profile the contract selects for its
/// destination on the registry's tier.
///
/// # Errors
/// Returns an error for no approvals, an invalid or untrusted signature, a
/// signer outside the role or repeated, disagreeing approvals, a registry or
/// release other than `registry`/`release_id`, an unknown destination, any
/// [`ProfileOverride::validate`] failure, or an unmet threshold.
pub fn verify_overrides(
    contract: &QualificationContract,
    registry: &str,
    release_id: &str,
    signers: &[SignerRequirement],
    envelopes: &[Vec<u8>],
    keys: &[TrustedEd25519Key],
) -> Result<AcceptedOverride> {
    let role = signers
        .iter()
        .find(|role| role.role == SignerRole::ReleaseEvidence)
        .ok_or_else(|| anyhow::anyhow!("plan lacks a release-evidence role"))?;
    let trusted: BTreeMap<_, _> = keys
        .iter()
        .map(|key| (key.key_id.clone(), key.public_key))
        .collect();

    let mut approvals = Vec::new();
    let mut keys_seen = BTreeSet::new();
    for bytes in envelopes {
        let (key, approval): (String, ProfileOverride) =
            crate::receipt::verify_signed_receipt_with_key(bytes, &trusted)?;
        if approval.authority_id != key || !role.key_ids.contains(&key) {
            bail!("profile override signer is not a planned release-evidence key");
        }
        if !keys_seen.insert(key) {
            bail!("profile override repeats a signer");
        }
        approvals.push(approval);
    }
    let Some(first) = approvals.first() else {
        bail!("profile override has no approvals");
    };
    let digest = first.digest()?;
    for approval in &approvals {
        if approval.digest()? != digest {
            bail!("profile override approvals disagree");
        }
    }
    if first.registry != registry || first.release_id != release_id {
        bail!("profile override names a different release");
    }

    let (surface, channel) = parse_destination_name(&first.destination)?;
    let tier = registry_policy(registry)?.tier();
    let cell = contract.destination(tier, surface, channel_kind(channel)?)?;
    let profile = contract.profile(&cell.profile)?;
    let effective = first.apply(profile)?;
    if keys_seen.len() < usize::from(role.threshold) {
        bail!(
            "profile override requires {} release-evidence approvals; {} verified",
            role.threshold,
            keys_seen.len()
        );
    }

    Ok(AcceptedOverride {
        payload: first.clone(),
        effective,
        reference: ProfileOverrideRef {
            destination: first.destination.clone(),
            override_digest: digest,
        },
        signers: keys_seen.into_iter().collect(),
    })
}

#[cfg(test)]
#[path = "profile_override_tests.rs"]
mod tests;
