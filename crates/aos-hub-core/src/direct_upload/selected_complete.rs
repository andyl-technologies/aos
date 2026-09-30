//! Compact identity bindings for one destination of a retained Complete intent.
//!
//! Construction checks the full original admission and Complete required set.
//! The selected manifest and whole protected profile pin identify one object;
//! they establish no authorization, provider settlement or publication readiness.
//!
//! ```text
//! version, session, operationId, expectedResourceVersion, completeIntentDigest,
//! manifest { placement, manifestDigest, partCount }, protectedProfileDigest
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::*;

/// Maximum encoded bytes of a selected-object Complete identity binding.
pub const MAX_DIRECT_SELECTED_COMPLETE_BYTES: usize = 8 * 1024;

/// Closed identity binding for exactly one required Complete destination.
///
/// Consumers must check this against independently retained originals with
/// [`Self::validate_for`]. Neither a valid encoding nor matching identity grants
/// permission to read, mutate, promote or publish an object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectSelectedCompleteCommitment {
    /// Closed representation version, currently one.
    pub version: u32,
    /// Exact original upload session and immutable admission fingerprint.
    pub session: DirectSessionRef,
    /// Original Complete operation, unchanged across destination selection.
    pub operation_id: String,
    /// Original Complete logical CAS version.
    pub expected_resource_version: WireInteger,
    /// Existing fingerprint of the entire retained Complete, including other destinations.
    pub complete_intent_digest: String,
    /// Exactly one manifest from the full ordered required set.
    pub manifest: DirectManifestCommitment,
    /// Whole protected profile pin captured before the original staging creation.
    pub protected_profile_digest: String,
}

impl DirectSelectedCompleteCommitment {
    /// Constructs a selected binding after checking the entire original intent.
    ///
    /// The caller supplies the independently retained admission and Complete,
    /// and the independently resolved complete protected profile.
    ///
    /// # Errors
    /// Returns a value-free error for malformed or changed originals, an incomplete
    /// required set, a foreign destination, a changed profile pin or excessive size.
    pub fn new(
        admission: &DirectUploadAdmission,
        complete: &DirectCompleteRequest,
        placement_id: WireInteger,
        deployment: &str,
        protected_profile: &DirectProtectedProfile,
    ) -> Result<Self> {
        let complete_intent_digest = validate_originals(admission, complete, deployment)?;
        let manifest = complete
            .manifests
            .iter()
            .find(|manifest| manifest.placement.placement_id == placement_id)
            .ok_or_else(|| anyhow::anyhow!("selected direct complete destination absent"))?;
        let placement = admission
            .placements
            .iter()
            .find(|placement| placement.placement_id == placement_id)
            .ok_or_else(|| anyhow::anyhow!("selected direct admission destination absent"))?;
        let protected_profile_digest = protected_profile.digest()?;
        ensure!(
            placement.protected_profile_digest == protected_profile_digest,
            "selected direct complete protected profile mismatch"
        );

        let result = Self {
            version: 1,
            session: complete.session.clone(),
            operation_id: complete.operation_id.clone(),
            expected_resource_version: complete.expected_resource_version,
            complete_intent_digest,
            manifest: manifest.clone(),
            protected_profile_digest,
        };
        result.validate()?;
        Ok(result)
    }

    /// Checks the closed representation without asserting original identity or authority.
    ///
    /// # Errors
    /// Returns a value-free error for unknown version, invalid identity, counters,
    /// manifest, profile pin or excessive encoded size.
    pub fn validate(&self) -> Result<()> {
        self.session.validate()?;
        self.manifest.placement.validate()?;
        ensure!(
            self.version == 1
                && valid_direct_digest(&self.operation_id)
                && (1..=i64::MAX as u64).contains(&self.expected_resource_version.get())
                && valid_direct_digest(&self.complete_intent_digest)
                && valid_direct_digest(&self.manifest.manifest_digest)
                && self.manifest.part_count <= MAX_DIRECT_PARTS
                && valid_direct_digest(&self.protected_profile_digest),
            "invalid selected direct complete commitment"
        );
        ensure!(
            encode_direct_control(self)?.len() <= MAX_DIRECT_SELECTED_COMPLETE_BYTES,
            "selected direct complete commitment exceeds limit"
        );
        Ok(())
    }

    /// Checks every field against the full independently retained originals.
    ///
    /// This comparison includes unselected destinations through the unchanged
    /// full Complete fingerprint. It grants no authorization or readiness.
    ///
    /// # Errors
    /// Returns a value-free error for malformed, incomplete, reordered or changed
    /// originals, a changed profile or any selected binding mismatch.
    pub fn validate_for(
        &self,
        admission: &DirectUploadAdmission,
        complete: &DirectCompleteRequest,
        deployment: &str,
        protected_profile: &DirectProtectedProfile,
    ) -> Result<()> {
        self.validate()?;
        let expected = Self::new(
            admission,
            complete,
            self.manifest.placement.placement_id,
            deployment,
            protected_profile,
        )?;
        ensure!(
            self == &expected,
            "selected direct complete original mismatch"
        );
        Ok(())
    }

    /// Encodes a structurally valid closed binding within its 8 KiB wire limit.
    ///
    /// # Errors
    /// Returns a value-free error for malformed fields or excessive encoded size.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(encode_direct_control(self)?)
    }

    /// Decodes a closed binding after checking its raw 8 KiB wire limit.
    ///
    /// Original identity must still be checked with [`Self::validate_for`].
    ///
    /// # Errors
    /// Returns a value-free error for excessive bytes, missing, duplicate or unknown
    /// fields, malformed JSON or invalid representation fields.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_DIRECT_SELECTED_COMPLETE_BYTES,
            "selected direct complete commitment exceeds limit"
        );
        let result: Self = decode_direct_control(bytes)?;
        result.validate()?;
        Ok(result)
    }
}

fn validate_originals(
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    deployment: &str,
) -> Result<String> {
    admission.validate(deployment)?;
    let digest = complete.fingerprint()?;
    ensure!(
        complete.session.session_id == admission.session_id
            && complete.session.logical_fingerprint == admission.logical_fingerprint
            && complete.manifests.len() == admission.placements.len(),
        "selected direct complete admission mismatch"
    );

    let part_count = admission.intent.part_count()?;
    // Comparing the full sorted sets prevents selection from hiding missing or
    // changed destinations. The Complete fingerprint also binds their manifests.
    for (manifest, placement) in complete.manifests.iter().zip(&admission.placements) {
        ensure!(
            manifest.placement == placement.public_ref(deployment)?
                && manifest.part_count == part_count,
            "selected direct complete required manifest mismatch"
        );
    }
    Ok(digest)
}

#[cfg(test)]
mod tests;
