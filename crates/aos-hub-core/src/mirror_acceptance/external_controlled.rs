//! Independent review of a bounded emulator-only External Mirror probe.
//!
//! This document authorizes functional probes of the already installed External
//! prerequisite inside one reserved namespace. It does not assert Hosted memory,
//! throughput, whole-workload Native byte safety or provider-drain qualification.
//! Those observations remain separate requirements for production readiness.
//!
//! ```text
//! artifact = {version, purpose, execution, reviewerKeyId, deploymentId,
//! publicOrigin, sourceDigest, scriptVersion, protectedProfile,
//! directEvidenceSha256, externalDomainSha256, upstreamBase, placementPrefix,
//! maximumObjectBytes, installation, issuedAt, validUntil, signature}
//! ```

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    direct_upload::{
        DirectProtectedExternalProfile, DirectProtectedProfile, direct_worker_emulated_script_id,
        valid_direct_digest, valid_direct_identity,
    },
    mirror_work::{MirrorOriginal, digest, MIRROR_MAX_OBJECT_BYTES},
};

const DOMAIN: &[u8] = b"aos.hub.controlled-external-mirror-functional-probe.v1\0";
/// Maximum encoded functional artifact; no bulk data is retained in it.
pub const CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES: usize = 32 * 1024;

/// Names only the supported full and pull-through functional probe paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledExternalMirrorPurpose {
    /// Ordinary mirror discovery, staging, publication and fresh delivery.
    FullAndPullThroughFunctionalProbeV1,
}

/// Prevents an emulator observation from being interpreted as Hosted evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledExternalMirrorExecution {
    /// Source-built Worker and independently observed local provider fixture.
    EmulatedExternal,
}

/// Commits independently retained installation, custody and prerequisite reports.
///
/// None of these fields is a caller result flag. The independent reviewer must
/// inspect the actual bounded reports and source-built artifacts before signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlledExternalMirrorInstallation {
    /// Final common source-built release tuple and derivation/output identities.
    pub artifact_manifest_sha256: String,
    /// Actual installed Worker Wasm bytes.
    pub wasm_sha256: String,
    /// Actual installed Worker JavaScript bytes.
    pub script_sha256: String,
    /// Actual Native serving executable bytes.
    pub native_executable_sha256: String,
    /// Actual selected Worker configuration, including distinct reviewer role.
    pub configuration_sha256: String,
    /// Independently observed physical namespace and selected live process pins.
    pub namespace_observation_sha256: String,
    /// Actual authenticated clock observations and timestamp brackets.
    pub clock_observation_sha256: String,
    /// Exact independently reviewed Mirror Read/closure provider observations.
    pub provider_contract_observation_sha256: String,
    /// Actual signed, independently accepted External prerequisite artifact bytes.
    pub prerequisite_artifact_sha256: String,
}

/// Separately signs bounded functional authority without production claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlledExternalMirrorArtifact {
    /// Closed format version, currently one.
    pub version: u8,
    /// Exact functional purpose; other approval documents cannot substitute.
    pub purpose: ControlledExternalMirrorPurpose,
    /// Exact emulator execution class, unavailable in ordinary production.
    pub execution: ControlledExternalMirrorExecution,
    /// Independently selected Mirror reviewer identity.
    pub reviewer_key_id: String,
    /// Actual installed deployment audience.
    pub deployment_id: String,
    /// Actual independently observed public Worker origin.
    pub public_origin: String,
    /// Actual compiled common Worker source commitment.
    pub source_digest: String,
    /// Source-derived emulator script identity; never a Cloudflare version label.
    pub script_version: String,
    /// Genuine independently accepted current External prerequisite.
    pub protected_profile: DirectProtectedExternalProfile,
    /// Exact accepted prerequisite evidence commitment.
    pub direct_evidence_sha256: String,
    /// Commitment to separately installed Mirror-specific transport and cohorts.
    pub external_domain_sha256: String,
    /// Exact public fixture surface selected before starting the probe.
    pub upstream_base: String,
    /// Exact relative reserved root; only its full and pull-through placements apply.
    pub placement_prefix: String,
    /// Explicit bounded functional size ceiling, not a throughput measurement.
    pub maximum_object_bytes: u64,
    /// Independently retained actual installation and provider reports.
    pub installation: ControlledExternalMirrorInstallation,
    /// Immutable first authorization timestamp.
    pub issued_at: u64,
    /// Immutable exclusive cutoff, at most fifteen minutes after issue.
    pub valid_until: u64,
    /// Independent reviewer Ed25519 signature in the functional-only domain.
    pub signature: String,
}

impl ControlledExternalMirrorArtifact {
    /// Checks closed scope, installed prerequisite and bounded validity.
    ///
    /// # Errors
    /// Refuses malformed, stale, nonreserved or unrelated installation facts.
    pub fn validate_unsigned(&self, now: u64) -> Result<()> {
        self.protected_profile.validate()?;
        let origin = url::Url::parse(&self.public_origin)?;
        let source = url::Url::parse(&self.upstream_base)?;
        let segments: Vec<_> = self.placement_prefix.split('/').collect();
        let reserved = segments.len() == 3
            && segments[0] == ".aos-mirror-qualification"
            && segments[1].len() == 32
            && segments[1]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && segments[2] == "final";
        ensure!(
            self.version == 1
                && valid_direct_identity(&self.reviewer_key_id)
                && valid_direct_identity(&self.deployment_id)
                && valid_direct_digest(&self.source_digest)
                && self.script_version == direct_worker_emulated_script_id(&self.source_digest)?
                && valid_direct_digest(&self.direct_evidence_sha256)
                && valid_direct_digest(&self.external_domain_sha256)
                && origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.path() == "/"
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && source.scheme() == "https"
                && source.host_str().is_some()
                && source.username().is_empty()
                && source.password().is_none()
                && source.query().is_none()
                && source.fragment().is_none()
                && reserved
                && self.issued_at <= now
                && now < self.valid_until
                && self
                    .valid_until
                    .checked_sub(self.issued_at)
                    .is_some_and(|ttl| ttl <= 900)
                && (1..=MIRROR_MAX_OBJECT_BYTES).contains(&self.maximum_object_bytes)
                && self.maximum_object_bytes
                    <= self
                        .protected_profile
                        .runtime_qualification
                        .maximum_object_bytes
                        .get(),
            "controlled External mirror identity, reserved scope or cutoff differs"
        );
        crate::url_guard::is_safe_remote_url(&self.upstream_base)?;
        let facts = &self.installation;
        for hash in [
            &facts.artifact_manifest_sha256,
            &facts.wasm_sha256,
            &facts.script_sha256,
            &facts.native_executable_sha256,
            &facts.configuration_sha256,
            &facts.namespace_observation_sha256,
            &facts.clock_observation_sha256,
            &facts.provider_contract_observation_sha256,
            &facts.prerequisite_artifact_sha256,
        ] {
            ensure!(
                valid_direct_digest(hash),
                "controlled Mirror installation observation absent"
            );
        }
        let profile = &self.protected_profile.profile;
        let full_prefix = crate::keymap::r2_key(
            &profile.selector.association.binding_prefix,
            &self.placement_prefix,
        );
        for cohort in [&profile.read_cohort, &profile.write_cohort] {
            ensure!(
                within(&cohort.admitted_prefix, &full_prefix),
                "controlled Mirror namespace escapes actual admitted cohort"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES,
            "controlled External Mirror artifact exceeds bound"
        );
        Ok(())
    }

    /// Encodes the exact functional-only signed statement.
    ///
    /// # Errors
    /// Refuses an oversized document or serialization failure.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned)?;
        ensure!(
            bytes.len() <= CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES,
            "controlled Mirror signed bytes exceed bound"
        );
        Ok([DOMAIN, &bytes].concat())
    }

    /// Verifies the independent installed reviewer key and exact runtime audience.
    ///
    /// # Errors
    /// Refuses foreign signatures, expired facts or changed current prerequisites.
    pub fn require_current(
        &self,
        deployment: &str,
        origin: &str,
        source: &str,
        script: &str,
        profile: &DirectProtectedProfile,
        direct_evidence: &str,
        trusted_public_hex: &str,
        now: u64,
    ) -> Result<()> {
        self.validate_unsigned(now)?;
        ensure!(
            self.deployment_id == deployment
                && self.public_origin == origin
                && self.source_digest == source
                && self.script_version == script
                && self.protected_profile.digest()? == profile.digest()?
                && matches!(profile, DirectProtectedProfile::External { .. })
                && self.direct_evidence_sha256 == direct_evidence
                && valid_direct_digest(trusted_public_hex),
            "controlled External Mirror differs from the actual current runtime"
        );
        let public: [u8; 32] = hex::decode(trusted_public_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("controlled Mirror reviewer key invalid"))?;
        let signature = Signature::from_slice(&hex::decode(&self.signature)?)?;
        VerifyingKey::from_bytes(&public)?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("controlled Mirror signature invalid"))
    }

    /// Restricts an actual Native original to this finite namespace and source.
    ///
    /// # Errors
    /// Refuses another source, size, destination or prerequisite.
    pub fn require_original(&self, original: &MirrorOriginal, now: u64) -> Result<()> {
        self.validate_unsigned(now)?;
        original.validate()?;
        let selected = original
            .external_destination
            .as_ref()
            .context("controlled External Mirror received Managed original")?;
        ensure!(
            selected.protected_profile == self.protected_profile
                && selected.acceptance_digest == self.direct_evidence_sha256
                && original.protected_profile_digest == self.protected_profile.digest()?
                && original.upstream_base == self.upstream_base
                && ["full", "pull-through"]
                    .iter()
                    .any(|mode| original.placement_prefix
                        == format!("{}/{mode}", self.placement_prefix))
                && original.verification.size() <= self.maximum_object_bytes,
            "controlled Mirror original escaped its signed finite probe"
        );
        Ok(())
    }
}

fn within(prefix: &str, key: &str) -> bool {
    prefix.is_empty()
        || key == prefix
        || key
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Addresses a distinct emulator-only functional document for one real profile.
///
/// # Errors
/// Refuses malformed source, deployment, profile or namespace identities.
pub fn controlled_external_mirror_key(
    deployment: &str,
    source: &str,
    script: &str,
    profile: &DirectProtectedProfile,
) -> Result<String> {
    ensure!(
        valid_direct_identity(deployment)
            && valid_direct_digest(source)
            && script == direct_worker_emulated_script_id(source)?
            && matches!(profile, DirectProtectedProfile::External { .. }),
        "controlled Mirror registry identity invalid"
    );
    Ok(format!(
        "controlled-external-mirror-v1:{}",
        digest(&(deployment, source, script, profile.digest()?))?
    ))
}

/// Checks that the functional verifier is independent of another reviewer key.
///
/// Encoded public-key letter case does not create a distinct signing role.
///
/// # Errors
/// Refuses malformed key bytes or reuse of the independently selected reviewer.
pub fn require_distinct_external_mirror_reviewer(
    functional_hex: &str,
    other_hex: &str,
) -> Result<()> {
    let functional: [u8; 32] = hex::decode(functional_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("functional Mirror reviewer key invalid"))?;
    let other: [u8; 32] = hex::decode(other_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("prerequisite reviewer key invalid"))?;
    ensure!(
        functional != other,
        "functional Mirror reviewer must be independent"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
