//! Independently reviewed, emulator-only OCI document SDK acceptance.
//!
//! This purpose grants neither Direct upload, presigning, mirror work nor
//! hosted provider readiness. Its installation and SDK observations must be
//! captured independently from the actual selected Native/workerd pair.
//!
//! ```text
//! artifact = {version:1, purpose:"oci_documents",
//!   executionKind:"emulated_managed_sdk", reviewerKeyId, profile,
//!   evidence, evidenceSha256, signature}
//! ```

use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::direct_upload::{direct_qualification_digest, valid_direct_digest};

pub mod anchor;
mod evidence;
mod profile;

#[cfg(any(test, feature = "test-fixtures"))]
mod fixtures;

#[cfg(feature = "test-fixtures")]
pub use fixtures::oci_sdk_emulation_fixture;

pub use evidence::{
    OciSdkEmulationEvidence, OciSdkInstallation, OciSdkObjectObservation, OciSdkObservationScope,
};
pub use profile::OciSdkEmulationProfile;

/// Bounds an independently reviewed OCI SDK artifact before decoding.
pub const MAX_OCI_SDK_EMULATION_ARTIFACT_BYTES: usize = 32 * 1024;

const SIGNATURE_DOMAIN: &[u8] = b"aos.oci-documents.emulated-sdk-acceptance.v1\0";

/// Derives the separate acceptance registry slot for the installed emulator.
///
/// # Errors
/// Rejects malformed deployment/source identity or a script not derived from
/// that exact source. The slot grants no permission without a reviewed artifact.
pub fn oci_sdk_emulation_acceptance_key(
    deployment: &str,
    source: &str,
    script: &str,
) -> Result<String> {
    ensure!(
        valid_identity(deployment)
            && valid_direct_digest(source)
            && script == crate::direct_upload::direct_worker_emulated_script_id(source)?,
        "OCI SDK registry identity differs"
    );
    Ok(format!(
        "oci-sdk-emulator-v1-{}",
        direct_qualification_digest(&(
            "aos.oci-documents.emulated-sdk-registry.v1",
            deployment,
            source,
            script,
        ))?
    ))
}

/// Limits the accepted operation family to OCI document storage and readback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciSdkAcceptancePurpose {
    /// Enables only the separately configured OCI document SDK adapter.
    OciDocuments,
}

/// Identifies an independently observed local workerd SDK execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciSdkAcceptanceExecution {
    /// Makes no statement about actual Cloudflare accounts or hosted execution.
    EmulatedManagedSdk,
}

/// Carries a bounded independent review of one exact emulator installation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkEmulationArtifact {
    /// Closed artifact version, currently one.
    pub version: u32,
    /// Closed OCI-only purpose; other operation families are not representable.
    pub purpose: OciSdkAcceptancePurpose,
    /// Explicit emulator execution; hosted readiness is not representable.
    pub execution_kind: OciSdkAcceptanceExecution,
    /// Identity selected from an independently configured reviewer key map.
    pub reviewer_key_id: String,
    /// Exact public SDK namespace, code, clock and private staging policy.
    pub profile: OciSdkEmulationProfile,
    /// Independently retained installed-process and actual SDK observations.
    pub evidence: OciSdkEmulationEvidence,
    /// Canonical commitment to all installation and SDK observations.
    pub evidence_sha256: String,
    /// Independently reviewed original issue time in UTC seconds.
    pub issued_at: u64,
    /// Exclusive end of this permission, never renewed by a retry or lookup.
    pub expires_at: u64,
    /// Lowercase hexadecimal Ed25519 signature under the selected reviewer.
    pub signature: String,
}

impl OciSdkEmulationArtifact {
    /// Decodes the closed artifact after applying its encoded-byte bound.
    ///
    /// # Errors
    /// Rejects oversized, malformed, secret-bearing or unknown-field input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_OCI_SDK_EMULATION_ARTIFACT_BYTES,
            "OCI SDK acceptance exceeds its bound"
        );
        serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("OCI SDK acceptance is malformed"))
    }

    /// Checks a candidate's complete public facts without granting acceptance.
    ///
    /// # Errors
    /// Rejects a changed audience, code, namespace, installation, unsupported
    /// clock, missing actual observations or a future/expired original window.
    pub fn validate_unsigned(&self, deployment: &str, origin: &str, latest_now: u64) -> Result<()> {
        ensure!(
            self.version == 1
                && valid_identity(&self.reviewer_key_id)
                && self.profile.deployment_id == deployment
                && self.profile.public_origin == origin
                && self.issued_at <= latest_now
                && latest_now < self.expires_at
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|ttl| { ttl > 30 && ttl <= 3600 })
                && valid_direct_digest(&self.evidence_sha256)
                && direct_qualification_digest(&self.evidence)? == self.evidence_sha256,
            "OCI SDK acceptance audience, facts or original window differs"
        );
        self.profile.validate()?;
        self.evidence.validate(&self.profile, self.issued_at)?;
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_OCI_SDK_EMULATION_ARTIFACT_BYTES,
            "OCI SDK acceptance exceeds its bound"
        );
        Ok(())
    }

    /// Verifies current OCI-only permission under a separately selected reviewer.
    ///
    /// The caller supplies the trusted key. No key from the artifact or a
    /// runtime discovery response may be used as reviewer trust.
    ///
    /// # Errors
    /// Rejects invalid public facts, a stale original, malformed keys/signatures
    /// or an artifact not signed by the independently selected reviewer.
    pub fn verify(
        &self,
        deployment: &str,
        origin: &str,
        trusted_public_hex: &str,
        latest_now: u64,
    ) -> Result<()> {
        self.validate_unsigned(deployment, origin, latest_now)?;
        ensure!(
            valid_direct_digest(trusted_public_hex)
                && self.signature.len() == 128
                && self
                    .signature
                    .bytes()
                    .all(|byte| { byte.is_ascii_digit() || matches!(byte, b'a'..=b'f') }),
            "OCI SDK reviewer key or signature is malformed"
        );
        let public: [u8; 32] = hex::decode(trusted_public_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("OCI SDK reviewer key is malformed"))?;
        let signature = hex::decode(&self.signature)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
            .ok_or_else(|| anyhow::anyhow!("OCI SDK signature is malformed"))?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| anyhow::anyhow!("OCI SDK reviewer key is malformed"))?
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("OCI SDK acceptance signature is invalid"))
    }

    /// Encodes the domain-separated identity for an independent reviewer.
    ///
    /// It exposes no signing key and grants no runtime permission.
    ///
    /// # Errors
    /// Rejects an oversized or unserializable public identity.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let identity = serde_json::to_vec(&(
            self.version,
            self.purpose,
            self.execution_kind,
            &self.reviewer_key_id,
            self.profile.digest()?,
            &self.evidence_sha256,
            self.issued_at,
            self.expires_at,
        ))?;
        ensure!(
            identity.len() <= MAX_OCI_SDK_EMULATION_ARTIFACT_BYTES,
            "OCI SDK acceptance identity exceeds its bound"
        );
        Ok([SIGNATURE_DOMAIN, identity.as_slice()].concat())
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests;
