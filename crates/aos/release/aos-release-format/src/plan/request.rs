//! Planner input and destination materialization.
//!
//! A reviewed [`ReleasePlanRequest`] plus the Nix-derived package inventory,
//! locally derived source identity, and shared contract materialize into a
//! validated [`ReleasePlan`]. Requests name surfaces and destinations; the
//! planner fills each destination's profile, gates, soak, and rings from the
//! contract.
//!
//! ```json
//! {"schema_version":"aos.release.plan-request/v1",
//!  "surfaces":[{"role":"staging","kind":"hub","origin":"https://aos.staging.andyl.org",
//!               "readback_origin":null,"identity":"staging-2026-09"}],
//!  "destinations":[{"surface":"production","channel":"stable"}],
//!  "change_scope":null,"profile_overrides":[]}
//! ```

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{
    ImagePlan, PLAN_REQUEST, PlannedDestination, PlannedSurface, PlanningSource,
    ProfileOverrideRef, ReleaseClass, ReleasePlan, RequestedDestination, RetentionPolicy,
    SourceIdentity,
};
use crate::RELEASE_PLAN;
use crate::digest::Sha256Digest;
use crate::inventory::{DerivationInventoryV1, PackageInventoryV1};
use crate::qualification::QualificationContract;
use crate::qualification::change_scope::ChangeScope;
use crate::registry::registry_policy;
use crate::signing::SignerRequirement;

/// Reviewed planner input whose package matrix is derived from Nix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePlanRequest {
    /// Exact planner-input schema identifier.
    pub schema_version: String,
    /// Same-registry preceding snapshot, required for shared server qualification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_predecessor: Option<crate::qualification_evidence::QualificationPredecessor>,
    /// Immutable release identity.
    pub release_id: String,
    /// SemVer-compatible calendar release version.
    pub version: String,
    /// Maturity and authorization class.
    pub release_class: ReleaseClass,
    /// Canonical public registry identity.
    pub registry: String,
    /// Exact registry commit on which authoring must begin.
    pub registry_base_commit: String,
    /// Exact compare-and-swap registry generation.
    pub registry_base_generation: u64,
    /// Whether the base is the root commit of a registry that no surface
    /// serves yet.
    ///
    /// A first release's base must be installed on each surface by the signed
    /// `step bootstrap` before anything is published there. The planner does
    /// not copy the flag into the plan; the bootstrap intents bind the plan
    /// digest and base commit instead. Omitted when false, so ordinary
    /// requests keep their exact bytes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub first_release: bool,
    /// Source reachability and authorization policy.
    pub source: PlanningSource,
    /// Complete Linux system-image intent.
    pub images: Vec<ImagePlan>,
    /// Role-separated signer thresholds and public key ids.
    pub signers: Vec<SignerRequirement>,
    /// Staging and production publication surfaces.
    pub surfaces: Vec<PlannedSurface>,
    /// Requested destinations; the planner fills profile, gates, soak, and
    /// rings. Qualification snapshots request none.
    pub destinations: Vec<RequestedDestination>,
    /// Recorded change scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_scope: Option<ChangeScope>,
    /// Accepted signed profile overrides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_overrides: Vec<ProfileOverrideRef>,
    /// Retention and corresponding-source policy.
    pub retention: RetentionPolicy,
    /// Digest of the public evidence policy.
    pub public_evidence_policy_digest: Sha256Digest,
    /// Digest of the restricted operator policy, without private contents.
    pub restricted_operator_policy_digest: Sha256Digest,
}

impl ReleasePlanRequest {
    /// Combines reviewed inputs, Nix eligibility, locally derived Git data, and
    /// the shared contract into a validated plan whose destinations are
    /// filled from the contract.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong request schema, inconsistent derived
    /// source policy, invalid inventory, a requested destination the contract
    /// does not prescribe, or any invalid final release plan.
    pub fn materialize(
        self,
        inventory: &PackageInventoryV1,
        derivations: &[DerivationInventoryV1],
        source: SourceIdentity,
        qualification: QualificationContract,
    ) -> Result<ReleasePlan> {
        if self.schema_version != PLAN_REQUEST {
            bail!("unsupported release plan request schema");
        }
        if source.protected_branch != self.source.protected_branch
            || source.source_tag != self.source.source_tag
            || source.contributor_authorization_digest
                != self.source.contributor_authorization_digest
        {
            bail!("derived source identity is outside the requested source policy");
        }

        let destinations = planned_destinations(
            &qualification,
            &self.registry,
            &self.destinations,
            self.change_scope.as_ref(),
        )?;
        let plan = ReleasePlan {
            schema_version: RELEASE_PLAN.to_owned(),
            qualification,
            qualification_predecessor: self.qualification_predecessor,
            release_id: self.release_id,
            version: self.version,
            release_class: self.release_class,
            registry: self.registry,
            registry_base_commit: self.registry_base_commit,
            registry_base_generation: self.registry_base_generation,
            source,
            packages: inventory.package_plan(derivations)?,
            images: self.images,
            signers: self.signers,
            surfaces: self.surfaces,
            destinations,
            change_scope: self.change_scope,
            profile_overrides: self.profile_overrides,
            retention: self.retention,
            public_evidence_policy_digest: self.public_evidence_policy_digest,
            restricted_operator_policy_digest: self.restricted_operator_policy_digest,
        };
        plan.validate()?;
        Ok(plan)
    }
}

/// Fills requested destinations with the contract's profile, gates, soak, and rings.
///
/// # Errors
/// Returns an error for an unknown registry, a channel the contract does not
/// prescribe for this tier and surface, or a failed gate derivation.
pub fn planned_destinations(
    contract: &QualificationContract,
    registry: &str,
    requested: &[RequestedDestination],
    change_scope: Option<&ChangeScope>,
) -> Result<Vec<PlannedDestination>> {
    let tier = registry_policy(registry)?.tier();
    requested
        .iter()
        .map(|request| {
            let kind = crate::registry::channel_kind(&request.channel)?;
            let cell = contract.destination(tier, request.surface, kind)?;
            let profile = contract.profile(&cell.profile)?;
            let effective = request
                .effective
                .clone()
                .unwrap_or_else(|| profile.effective());
            Ok(PlannedDestination {
                name: cell.name_for(&request.channel),
                surface: request.surface,
                channel: request.channel.clone(),
                profile: profile.name.clone(),
                profile_digest: profile.digest()?,
                soak_seconds: effective.soak_seconds,
                gates: contract.gates(cell, change_scope)?,
                rings: effective.rings,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical;

    /// Returns a minimal reviewed request as JSON.
    fn request_json() -> serde_json::Value {
        let digest = Sha256Digest::of_bytes(b"policy").to_string();
        serde_json::json!({
            "schema_version": PLAN_REQUEST,
            "release_id": "release-2026.9.0-dev.20260927.1",
            "version": "2026.9.0-dev.20260927.1",
            "release_class": "edge",
            "registry": "andyl/experimental",
            "registry_base_commit": "a".repeat(64),
            "registry_base_generation": 0,
            "source": {
                "protected_branch": "master",
                "source_tag": "release/2026.9.0-dev.20260927.1",
                "contributor_authorization_digest": digest,
            },
            "images": [],
            "signers": [],
            "surfaces": [],
            "destinations": [],
            "retention": {
                "policy_id": "retention",
                "policy_digest": digest,
                "require_corresponding_source": true,
            },
            "public_evidence_policy_digest": digest,
            "restricted_operator_policy_digest": digest,
        })
    }

    #[test]
    fn ordinary_requests_omit_the_first_release_flag() -> Result<()> {
        let request: ReleasePlanRequest = serde_json::from_value(request_json())?;
        assert!(!request.first_release);

        let bytes = canonical::to_vec(&request)?;
        let text = std::str::from_utf8(&bytes)?;
        assert!(!text.contains("first_release"));
        Ok(())
    }

    #[test]
    fn first_release_requests_round_trip_the_flag() -> Result<()> {
        let mut value = request_json();
        value["first_release"] = serde_json::Value::Bool(true);
        let request: ReleasePlanRequest = serde_json::from_value(value)?;
        assert!(request.first_release);

        let bytes = canonical::to_vec(&request)?;
        let decoded: ReleasePlanRequest = canonical::from_slice(&bytes, "plan request")?;
        assert!(decoded.first_release);
        assert_eq!(decoded, request);
        Ok(())
    }
}
