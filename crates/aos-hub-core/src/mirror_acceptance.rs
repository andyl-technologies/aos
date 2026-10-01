//! Purpose-separated review of the managed mirror producer and its measurements.
//!
//! Direct upload approval remains a prerequisite. It does not cover upstream
//! fetching, NAR decoding, mirror journals, acknowledgement or buffer admission.
//! A reviewer accepts those measurements for one exact built script and profile.
//! Controlled measurements never authorize production, even when signed.
//!
//! ```text
//! artifact = {version, purpose, execution, deploymentId, sourceDigest,
//! scriptVersion, protectedProfile, directEvidenceSha256, evidence, signature}
//! signature = Ed25519(mirror acceptance domain || canonical unsigned artifact)
//! ```

use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::direct_upload::{
    direct_worker_emulated_script_id, encode_direct_control, valid_direct_digest,
    valid_direct_identity, DirectManagedR2Profile, DirectPrivateStagePolicyRef,
    DirectProtectedProfile,
};
use crate::mirror_work::{MIRROR_MAX_OBJECT_BYTES, MIRROR_MAX_PARTS_PER_STEP, MIRROR_PART_BYTES};

mod evidence;
pub use evidence::*;

pub mod live;
pub mod pack;

#[cfg(test)]
mod tests;

const DOMAIN: &[u8] = b"aos.hub.accepted-managed-mirror-producer.v1\0";

/// Maximum encoded acceptance artifact, including bounded evidence samples.
pub const MIRROR_ACCEPTANCE_MAX_BYTES: usize = 128 * 1024;

/// Maximum simultaneous bulk producers retaining a part or decoder window.
pub const MIRROR_BULK_BUFFERED_PRODUCERS: u32 = 1;

/// Reserved simultaneous producers for independently bounded metadata.
pub const MIRROR_METADATA_BUFFERED_PRODUCERS: u32 = 2;

/// Encoded, plain and decoder-window ceiling for the metadata producer class.
pub const MIRROR_METADATA_BUFFER_BYTES: u64 = 256 * 1024;

/// Names the exact producer purpose authorized by the reviewer role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorAcceptancePurpose {
    /// Upstream fetching, verification and guarded managed R2 publication.
    ManagedR2MirrorV1,
}

/// Distinguishes production execution from evidence-only controlled runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorAcceptanceExecution {
    /// Actual hosted Worker and managed R2 measurements.
    Hosted,
    /// Source-built controlled runner; cannot grant production admission.
    Controlled,
}

/// Retains raw protected candidate facts without an accepted runtime wrapper.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorCandidateProfile {
    /// Actual material-derived public managed descriptor.
    pub profile: DirectManagedR2Profile,
    /// Actual installed policy projection for the isolated namespace.
    pub private_stage_policy: DirectPrivateStagePolicyRef,
}

/// Commits the fixed geometry enforced by the producer, rather than readiness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorProducerGeometry {
    /// Rust part-buffer ceiling.
    pub part_bytes: u64,
    /// Maximum bounded parts selected by one control request.
    pub parts_per_control: u32,
    /// Shared per-isolate bulk part/decoder producer admission ceiling.
    pub bulk_buffered_producers: u32,
    /// Separately reserved metadata part/decoder producer admission ceiling.
    pub metadata_buffered_producers: u32,
    /// Each metadata producer's encoded, plain and decoder-window ceiling.
    pub metadata_buffer_bytes: u64,
    /// Maximum accepted Zstandard frame window.
    pub decoder_window_bytes: u64,
    /// Maximum decoded block retained before hashing.
    pub decoder_block_bytes: u64,
    /// Native BYOB input view ceiling.
    pub reader_bytes: u64,
}

impl MirrorProducerGeometry {
    /// Returns the implementation's fixed geometry without claiming measurement.
    #[must_use]
    pub fn current() -> Self {
        Self {
            part_bytes: MIRROR_PART_BYTES,
            parts_per_control: MIRROR_MAX_PARTS_PER_STEP,
            bulk_buffered_producers: MIRROR_BULK_BUFFERED_PRODUCERS,
            metadata_buffered_producers: MIRROR_METADATA_BUFFERED_PRODUCERS,
            metadata_buffer_bytes: MIRROR_METADATA_BUFFER_BYTES,
            decoder_window_bytes: 8 * 1024 * 1024,
            decoder_block_bytes: 128 * 1024,
            reader_bytes: 64 * 1024,
        }
    }
}

/// Independently reviewed acceptance of one mirror producer artifact.
///
/// No field is an operator activation flag. Structural validation cannot prove
/// observations occurred: the authorized reviewer must inspect the committed
/// raw reports and release pack before signing this closed document.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MirrorAcceptanceArtifact {
    /// Closed acceptance format, currently one.
    pub version: u32,
    /// Exact authorized workflow, covered by a distinct signing domain.
    pub purpose: MirrorAcceptancePurpose,
    /// Actual environment from which the measurements were collected.
    pub execution: MirrorAcceptanceExecution,
    /// Identity of the installed reviewer role; never a key learned from evidence.
    pub reviewer_key_id: String,
    /// Exact deployment audience.
    pub deployment_id: String,
    /// Exact public HTTPS origin.
    pub public_origin: String,
    /// Source-built workers-rs version.
    pub workers_rs_version: String,
    /// Actual compiled source commitment.
    pub source_digest: String,
    /// Actual hosted version metadata or derived controlled source identity.
    pub script_version: String,
    /// Complete actual managed material, policy and prerequisite runtime profile.
    pub protected_profile: Option<DirectProtectedProfile>,
    /// Actual raw controlled profile; mutually exclusive with production facts.
    pub candidate_profile: Option<MirrorCandidateProfile>,
    /// Exact independently verified prerequisite direct evidence commitment.
    pub direct_evidence_sha256: Option<String>,
    /// Fixed admitted buffer and decoding geometry.
    pub geometry: MirrorProducerGeometry,
    /// Largest encoded or plain object admitted by this mirror acceptance.
    pub maximum_object_bytes: u64,
    /// First accepted observation timestamp.
    pub issued_at: u64,
    /// Immutable acceptance cutoff; configuration cannot renew it.
    pub valid_until: u64,
    /// Full measured workload, correctness, memory and release evidence.
    pub evidence: MirrorAcceptanceEvidence,
    /// Lowercase hexadecimal reviewer Ed25519 signature.
    pub signature: String,
}

impl MirrorAcceptanceArtifact {
    /// Checks the immutable reviewer cutoff immediately before a new dispatch.
    ///
    /// This check grants no authority by itself. The caller must already have
    /// verified signature, purpose and current runtime pins, and must repeat
    /// this check after every capacity wait before invoking the provider.
    ///
    /// # Errors
    /// Returns an error when the clock is outside the accepted evidence window.
    pub fn validate_dispatch_time(&self, latest_now: u64) -> Result<()> {
        ensure!(
            self.issued_at <= latest_now && latest_now < self.valid_until,
            "mirror immutable acceptance cutoff reached"
        );
        Ok(())
    }

    /// Checks a review candidate without granting dispatch authority.
    ///
    /// # Errors
    /// Returns a value-free error for invalid identities or insufficient evidence.
    pub fn validate_unsigned(&self, now: u64) -> Result<()> {
        let origin = url::Url::parse(&self.public_origin)?;
        ensure!(
            self.version == 1
                && valid_direct_identity(&self.reviewer_key_id)
                && valid_direct_identity(&self.deployment_id)
                && self.workers_rs_version == "0.8.5"
                && valid_direct_digest(&self.source_digest)
                && valid_direct_identity(&self.script_version)
                && origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none()
                && self.issued_at <= now
                && now < self.valid_until
                && self.geometry == MirrorProducerGeometry::current()
                && (1..=MIRROR_MAX_OBJECT_BYTES).contains(&self.maximum_object_bytes),
            "mirror acceptance identity, geometry or validity differs"
        );
        match self.execution {
            MirrorAcceptanceExecution::Hosted => {
                let Some(
                    profile @ DirectProtectedProfile::Managed {
                        profile: raw,
                        runtime_qualification,
                        ..
                    },
                ) = &self.protected_profile
                else {
                    anyhow::bail!("hosted mirror acceptance requires managed profile");
                };
                profile.validate()?;
                ensure!(
                    self.candidate_profile.is_none()
                        && self
                            .direct_evidence_sha256
                            .as_deref()
                            .is_some_and(valid_direct_digest)
                        && raw.deployment_id == self.deployment_id
                        && self.maximum_object_bytes
                            <= runtime_qualification.maximum_object_bytes.get()
                        && !self.script_version.starts_with("emulated-"),
                    "hosted mirror acceptance prerequisite or identity differs"
                );
            }
            MirrorAcceptanceExecution::Controlled => {
                let candidate = self
                    .candidate_profile
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("controlled mirror actual profile absent"))?;
                mirror_candidate_profile_digest(
                    &candidate.profile,
                    &candidate.private_stage_policy,
                )?;
                ensure!(
                    self.protected_profile.is_none()
                        && self.direct_evidence_sha256.is_none()
                        && candidate.profile.deployment_id == self.deployment_id
                        && self.script_version
                            == direct_worker_emulated_script_id(&self.source_digest)?,
                    "controlled mirror source identity or raw profile differs"
                );
            }
        }
        self.evidence.validate(self)?;
        ensure!(
            serde_json::to_vec(self)?.len() <= MIRROR_ACCEPTANCE_MAX_BYTES,
            "mirror acceptance exceeds bound"
        );
        Ok(())
    }

    /// Encodes the exact purpose-separated reviewer statement.
    ///
    /// # Errors
    /// Returns an error if the closed artifact exceeds its encoding bound.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned)?;
        ensure!(
            bytes.len() <= MIRROR_ACCEPTANCE_MAX_BYTES,
            "mirror signature payload exceeds bound"
        );
        Ok([DOMAIN, bytes.as_slice()].concat())
    }

    /// Verifies the installed reviewer role and exact measured candidate.
    ///
    /// The role may share a key with another review purpose only when that role
    /// is explicitly authorized for both. Its public key is installed separately
    /// from the artifact; a direct-upload signature cannot verify this domain.
    ///
    /// # Errors
    /// Returns an error for invalid evidence, foreign purposes or signatures.
    pub fn verify(&self, trusted_public_hex: &str, now: u64) -> Result<()> {
        self.validate_unsigned(now)?;
        ensure!(
            valid_direct_digest(trusted_public_hex),
            "mirror reviewer key malformed"
        );
        let public: [u8; 32] = hex::decode(trusted_public_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("mirror reviewer key malformed"))?;
        ensure!(
            self.signature.len() == 128
                && self
                    .signature
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "mirror signature malformed"
        );
        let signature = Signature::from_slice(&hex::decode(&self.signature)?)?;
        VerifyingKey::from_bytes(&public)?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("mirror acceptance signature invalid"))?;
        Ok(())
    }

    /// Requires hosted acceptance matching the current producer and profile.
    ///
    /// # Errors
    /// Returns an error for controlled evidence, stale or changed runtime pins.
    pub fn require_production(
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
        self.verify(trusted_public_hex, now)?;
        ensure!(
            self.execution == MirrorAcceptanceExecution::Hosted
                && self.deployment_id == deployment
                && self.public_origin == origin
                && self.source_digest == source
                && self.script_version == script
                && self.protected_profile.as_ref() == Some(profile)
                && self.direct_evidence_sha256.as_deref() == Some(direct_evidence),
            "mirror production acceptance differs from current producer"
        );
        Ok(())
    }
}

/// Addresses the separately installed acceptance for one actual built script.
///
/// # Errors
/// Returns an error for malformed deployment, source or script identities.
pub fn mirror_acceptance_key(deployment: &str, source: &str, script: &str) -> Result<String> {
    ensure!(
        valid_direct_identity(deployment)
            && valid_direct_digest(source)
            && valid_direct_identity(script),
        "mirror acceptance address invalid"
    );
    let mut hash = Sha256::new();
    hash.update(b"aos.hub.mirror-acceptance-address.v1\0");
    hash.update(encode_direct_control(&(deployment, source, script))?);
    Ok(format!("mirror-v1:{}", hex::encode(hash.finalize())))
}

/// Commits actual raw candidate material without claiming accepted runtime.
///
/// This identity is usable only by a separate protected candidate executor in
/// its closed fixture namespace. Production requires the full accepted profile
/// above. Creating this digest grants neither a work plan nor publication rights.
///
/// # Errors
/// Returns an error for malformed material, policy or namespace projections.
pub fn mirror_candidate_profile_digest(
    profile: &DirectManagedR2Profile,
    policy: &DirectPrivateStagePolicyRef,
) -> Result<String> {
    profile.validate()?;
    ensure!(
        valid_direct_identity(&policy.policy_id)
            && valid_direct_digest(&policy.policy_digest)
            && policy.namespace == profile.bucket_namespace,
        "mirror candidate policy differs"
    );
    let mut hash = Sha256::new();
    hash.update(b"aos.hub.mirror-candidate-raw-profile.v1\0");
    hash.update(encode_direct_control(&(
        profile,
        policy,
        MirrorProducerGeometry::current(),
    ))?);
    Ok(hex::encode(hash.finalize()))
}
