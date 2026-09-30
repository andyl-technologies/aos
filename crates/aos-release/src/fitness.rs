//! Signed attestations that recurring environment exercises were performed.
//!
//! A fitness attestation records that one exercise kind declared by the
//! contract (backup restore, alert delivery, authority recovery, Hub restore,
//! key rotation) ran against identities it names in `bindings`. Profiles
//! demand kinds with a maximum age; publication or channel advance to a
//! destination requires every demanded kind to be fresh and bound to the live
//! identities. Attestations are maintainer-wide, not per release, and are
//! signed with the standard receipt envelope by a release-evidence key.
//!
//! ```json
//! {"schema_version":"aos.release.fitness-attestation/v1",
//!  "kind":"hub-restore","registry":"andyl/main",
//!  "performed_at":"2026-09-01T00:00:00Z",
//!  "checks":{"isolated-hub-restore":{"passed":true,"detail":"..."}},
//!  "bindings":{"surface":"production-2026-09","hub-schema":"42"},
//!  "evidence_digest":"sha256:...","operator":"oncall",
//!  "authority_id":"release-evidence-v1"}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::require_identifier;
use crate::digest::Sha256Digest;
use crate::plan::{ReleasePlan, SurfaceKind};
use crate::qualification::{FitnessBinding, FitnessKind, QualificationProfile};
use crate::qualification_evidence::CheckObservation;
use crate::registry::registry_policy;
use crate::signing::{SignerRole, TrustedEd25519Key};

/// Exact fitness attestation schema identifier.
pub const FITNESS_ATTESTATION: &str = "aos.release.fitness-attestation/v1";

/// Digest domain of a plan's canonical signer roster.
pub const SIGNER_ROSTER_DOMAIN: &str = "aos.release.signer-roster/v1";

/// Exact schema of an operator or automation exercise report.
pub const FITNESS_REPORT: &str = "aos.release.fitness-report/v1";

/// Unsigned exercise report from which an attestation is recorded.
///
/// ```json
/// {"schema_version":"aos.release.fitness-report/v1",
///  "performed_at":"2026-09-01T00:00:00Z",
///  "checks":{"isolated-hub-restore":{"passed":true,"detail":"..."}},
///  "operator":"oncall"}
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FitnessReport {
    /// Exact report schema.
    pub schema_version: String,
    /// RFC 3339 UTC time the exercise finished.
    pub performed_at: String,
    /// Observed acceptance checks.
    pub checks: BTreeMap<String, CheckObservation>,
    /// Operator or automation identity that performed the exercise.
    pub operator: String,
}

impl FitnessReport {
    /// Builds the attestation payload for this report, bound to live identities.
    ///
    /// `evidence_digest` identifies the retained restricted report and
    /// `authority_id` the release-evidence key that will sign the payload.
    ///
    /// # Errors
    /// Returns an error for a wrong report schema, a live identity the kind
    /// binds but that is unknown, or an attestation that fails
    /// [`FitnessAttestation::validate`] (for example missing or failed
    /// checks).
    pub fn attest(
        &self,
        kind: &FitnessKind,
        live: &LiveBindings,
        evidence_digest: Sha256Digest,
        authority_id: &str,
    ) -> Result<FitnessAttestation> {
        if self.schema_version != FITNESS_REPORT {
            bail!("unsupported fitness report schema");
        }
        let attestation = FitnessAttestation {
            schema_version: FITNESS_ATTESTATION.to_owned(),
            kind: kind.kind.clone(),
            registry: live.registry.clone(),
            performed_at: self.performed_at.clone(),
            checks: self.checks.clone(),
            bindings: live.recorded(kind)?,
            evidence_digest,
            operator: self.operator.clone(),
            authority_id: authority_id.to_owned(),
        };
        attestation.validate(kind)?;
        Ok(attestation)
    }
}

/// Signed record that one environment exercise was performed and passed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FitnessAttestation {
    /// Exact attestation schema.
    pub schema_version: String,
    /// Fitness kind declared by the contract.
    pub kind: String,
    /// Registry trust domain whose environment was exercised.
    pub registry: String,
    /// RFC 3339 UTC time the exercise finished.
    pub performed_at: String,
    /// Exactly the kind's checks, each passed with a recorded detail.
    pub checks: BTreeMap<String, CheckObservation>,
    /// Binding name to observed identity; `null` only where the kind's
    /// binding is vacuous (Hub schema on a static surface).
    pub bindings: BTreeMap<String, Option<String>>,
    /// Digest of the retained restricted exercise report.
    pub evidence_digest: Sha256Digest,
    /// Operator or automation identity that performed the exercise.
    pub operator: String,
    /// Release-evidence key that signed the attestation.
    pub authority_id: String,
}

/// Live identities an attestation's bindings must match at admission.
///
/// A `None` identity means the live value is unknown, which fails closed for
/// any binding that requires it. `surface_kind` decides whether the
/// `hub-schema` binding is vacuous (`Static`) or required (`Hub`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LiveBindings {
    /// Registry of the release being admitted.
    pub registry: String,
    /// Destination surface identity: Hub deployment id or static identity.
    pub surface: Option<String>,
    /// Destination surface kind.
    pub surface_kind: Option<SurfaceKind>,
    /// Hub schema version reported by the destination Hub.
    pub hub_schema: Option<String>,
    /// Digest of the plan's signer roster; see [`signer_roster_digest`].
    pub signer_roster: Option<Sha256Digest>,
    /// Digest of the maintainer configuration's tooling closure.
    pub tooling: Option<Sha256Digest>,
    /// Digest of the maintainer configuration's alert section.
    pub alert_config: Option<Sha256Digest>,
}

impl LiveBindings {
    /// Returns the bindings map an attestation of `kind` must record now.
    ///
    /// # Errors
    /// Returns an error when a live identity the kind binds is unknown.
    pub fn recorded(&self, kind: &FitnessKind) -> Result<BTreeMap<String, Option<String>>> {
        kind.bindings
            .iter()
            .map(|binding| Ok((binding.as_str().to_owned(), self.expected(*binding)?)))
            .collect()
    }

    /// Returns the identity an attestation must record for `binding`.
    ///
    /// # Errors
    /// Returns an error when the live value the binding requires is unknown.
    pub fn expected(&self, binding: FitnessBinding) -> Result<Option<String>> {
        let unknown = || anyhow::anyhow!("live {} identity is unknown", binding.as_str());
        let digest = |value: Option<Sha256Digest>| {
            value
                .map(|digest| Some(digest.to_string()))
                .ok_or_else(unknown)
        };
        match binding {
            FitnessBinding::Surface => self.surface.clone().map(Some).ok_or_else(unknown),
            FitnessBinding::HubSchema => match self.surface_kind.ok_or_else(unknown)? {
                // Static surfaces have no Hub schema; the binding is recorded as null.
                SurfaceKind::Static => Ok(None),
                SurfaceKind::Hub => self.hub_schema.clone().map(Some).ok_or_else(unknown),
            },
            FitnessBinding::SignerRoster => digest(self.signer_roster),
            FitnessBinding::Tooling => digest(self.tooling),
            FitnessBinding::AlertConfig => digest(self.alert_config),
        }
    }
}

/// Computes the `signer-roster` binding identity of a plan.
///
/// # Errors
/// Returns an error if canonical encoding fails.
pub fn signer_roster_digest(plan: &ReleasePlan) -> Result<Sha256Digest> {
    Sha256Digest::of_canonical(SIGNER_ROSTER_DOMAIN, &plan.signers)
}

impl FitnessAttestation {
    /// Validates the attestation against its contract kind, independent of time.
    ///
    /// # Errors
    /// Returns an error for a wrong schema or kind, a malformed registry or
    /// identity, a non-UTC time, checks or bindings that differ from the
    /// kind's, a failed or undocumented check, or a null binding other than
    /// `hub-schema`.
    pub fn validate(&self, kind: &FitnessKind) -> Result<()> {
        if self.schema_version != FITNESS_ATTESTATION {
            bail!("unsupported fitness attestation schema");
        }
        if self.kind != kind.kind {
            bail!(
                "fitness attestation is for {}, not {}",
                self.kind,
                kind.kind
            );
        }
        registry_policy(&self.registry)?;
        require_identifier(&self.operator, "fitness operator")?;
        require_identifier(&self.authority_id, "fitness authority id")?;
        if !self.performed_at.ends_with('Z')
            || humantime::parse_rfc3339(&self.performed_at).is_err()
        {
            bail!("fitness attestation time must be RFC 3339 UTC");
        }

        let required: BTreeSet<&str> = kind.checks.iter().map(String::as_str).collect();
        let recorded: BTreeSet<&str> = self.checks.keys().map(String::as_str).collect();
        if required != recorded {
            bail!("fitness attestation checks differ from kind {}", kind.kind);
        }
        if self
            .checks
            .values()
            .any(|check| !check.passed || check.detail.trim().is_empty())
        {
            bail!("fitness attestation records a failed or undocumented check");
        }

        let required: BTreeSet<&str> = kind
            .bindings
            .iter()
            .map(|binding| binding.as_str())
            .collect();
        let recorded: BTreeSet<&str> = self.bindings.keys().map(String::as_str).collect();
        if required != recorded {
            bail!(
                "fitness attestation bindings differ from kind {}",
                kind.kind
            );
        }
        for (name, value) in &self.bindings {
            if value.is_none() && name != FitnessBinding::HubSchema.as_str() {
                bail!("fitness binding {name} cannot be null");
            }
        }
        Ok(())
    }

    /// Requires the attestation to satisfy `profile`'s demand for `kind` now.
    ///
    /// # Errors
    /// Returns an error for any [`FitnessAttestation::validate`] failure, a
    /// kind the profile does not demand, a registry other than the live one,
    /// a future or older-than-allowed exercise, or a binding whose recorded
    /// identity differs from the live identity (or whose live identity is
    /// unknown).
    pub fn validate_for(
        &self,
        profile: &QualificationProfile,
        kind: &FitnessKind,
        live: &LiveBindings,
        now: &str,
    ) -> Result<()> {
        self.validate(kind)?;
        let demand = profile.fitness.get(&kind.kind).ok_or_else(|| {
            anyhow::anyhow!(
                "profile {} does not demand fitness kind {}",
                profile.name,
                kind.kind
            )
        })?;
        if self.registry != live.registry {
            bail!("fitness attestation exercised registry {}", self.registry);
        }

        let performed = humantime::parse_rfc3339(&self.performed_at)?;
        let now = humantime::parse_rfc3339(now)?;
        let age = now
            .duration_since(performed)
            .map_err(|_| anyhow::anyhow!("fitness attestation is from the future"))?
            .as_secs();
        if age > demand.max_age_seconds {
            bail!(
                "{} fitness attestation is {age} seconds old; profile {} allows {}",
                kind.kind,
                profile.name,
                demand.max_age_seconds
            );
        }

        for binding in &kind.bindings {
            let expected = live.expected(*binding)?;
            let recorded = self.bindings.get(binding.as_str()).cloned().flatten();
            if recorded != expected {
                bail!(
                    "{} fitness binding {} differs from the live identity",
                    kind.kind,
                    binding.as_str()
                );
            }
        }
        Ok(())
    }

    /// Verifies a signed attestation envelope by a planned release-evidence key.
    ///
    /// # Errors
    /// Returns an error for an invalid or untrusted signature, a signer outside
    /// the plan's release-evidence role, or an `authority_id` that differs from
    /// the signing key.
    pub fn verify_signed(
        bytes: &[u8],
        plan: &ReleasePlan,
        keys: &[TrustedEd25519Key],
    ) -> Result<Self> {
        let role = plan
            .signers
            .iter()
            .find(|role| role.role == SignerRole::ReleaseEvidence)
            .ok_or_else(|| anyhow::anyhow!("plan lacks a release-evidence role"))?;
        Self::verify_signed_by(bytes, &role.key_ids, keys)
    }

    /// Verifies a signed attestation envelope by one of `evidence_key_ids`.
    ///
    /// Attestations are maintainer-wide, so a coordinator without a frozen
    /// plan verifies them against its configured release-evidence roster.
    ///
    /// # Errors
    /// Returns an error for an invalid or untrusted signature, a signer outside
    /// `evidence_key_ids`, or an `authority_id` that differs from the signing
    /// key.
    pub fn verify_signed_by(
        bytes: &[u8],
        evidence_key_ids: &[String],
        keys: &[TrustedEd25519Key],
    ) -> Result<Self> {
        let trusted: BTreeMap<_, _> = keys
            .iter()
            .map(|key| (key.key_id.clone(), key.public_key))
            .collect();
        let (key, attestation): (String, Self) =
            crate::receipt::verify_signed_receipt_with_key(bytes, &trusted)?;
        if attestation.authority_id != key || !evidence_key_ids.contains(&key) {
            bail!("fitness attestation signer is not a release-evidence key");
        }
        Ok(attestation)
    }
}

/// Requires a fresh, bound attestation for every fitness kind a destination's
/// profile demands.
///
/// # Errors
/// Returns an error for an unknown destination, profile, or
/// kind, or a demanded kind for which no attestation satisfies
/// [`FitnessAttestation::validate_for`]; the error names the kind and the
/// newest attestation's failure.
pub fn require_destination_fitness(
    plan: &ReleasePlan,
    destination: &str,
    attestations: &[FitnessAttestation],
    live: &LiveBindings,
    now: &str,
) -> Result<()> {
    let contract = &plan.qualification;
    let profile = contract.profile(&plan.destination(destination)?.profile)?;
    for name in profile.fitness.keys() {
        let kind = contract.fitness_kind(name)?;
        let mut candidates: Vec<_> = attestations
            .iter()
            .filter(|attestation| attestation.kind == *name)
            .collect();
        candidates.sort_by(|left, right| right.performed_at.cmp(&left.performed_at));
        let mut failure = None;
        let satisfied = candidates.iter().any(|attestation| {
            match attestation.validate_for(profile, kind, live, now) {
                Ok(()) => true,
                Err(error) => {
                    failure.get_or_insert(error);
                    false
                }
            }
        });
        if !satisfied {
            match failure {
                Some(error) => bail!("{destination} requires fresh {name} fitness: {error}"),
                None => bail!("{destination} requires a {name} fitness attestation"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "fitness_tests.rs"]
mod tests;
