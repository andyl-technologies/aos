//! Independent measured direct-upload acceptance preparation and explicit signing.
//!
//! Preparation assembles a closed unsigned candidate from reviewed file hashes,
//! actual deployment projections and retained measurements. Signing separately
//! requires the exact candidate SHA-256 chosen by a reviewer, a protected raw
//! Ed25519 seed and the independently installed public verifier. Neither action
//! deploys a Worker, writes acceptance KV or grants production dispatch.
//!
//! ```text
//! prepare(selection-file, new-candidate-file) -> candidate SHA-256
//! sign(selection-file, candidate-file, reviewed SHA-256,
//!      private raw 32-byte seed file, installed public hex file,
//!      new-artifact-file) -> signed artifact SHA-256
//! ```

mod assembly;
mod captures;
mod files;
mod installation;
mod measurements;
mod privacy;
pub mod raw;
mod readback;
mod reports;
mod selection;

pub use privacy::{
    DirectReviewGuardCoverage, DirectReviewHttpCapture, DirectReviewPrivacyPolicyReport,
    DirectReviewPrivacyReport, DirectReviewRuntimeMutationApi, DirectReviewWriterAssessment,
};
pub use selection::*;

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Result};
use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| anyhow::anyhow!("reviewer UTC clock unavailable"))
}

/// Encodes a conservative clock policy commitment for installation before measurement.
///
/// This public configuration commitment excludes observations and conveys no
/// measured qualification, signature or runtime acceptance.
///
/// # Errors
/// Returns an error for unsupported uncertainty or public encoding failure.
pub fn direct_upload_review_clock_policy(uncertainty_seconds: u64) -> Result<String> {
    let policy = aos_hub_core::direct_upload::DirectClockPolicy {
        version: 1,
        mode: aos_hub_core::direct_upload::DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: aos_hub_core::direct_upload::WireInteger::new(uncertainty_seconds),
    };
    let commitment = policy.commitment()?;
    serde_json::to_string_pretty(&serde_json::json!({"policy":policy,"commitment":commitment}))
        .map_err(|_| anyhow::anyhow!("installed clock policy cannot be encoded"))
}

/// Prepares an unsigned acceptance candidate from explicitly selected measurements.
///
/// Returns the exact file SHA-256 for independent review. The output contains no
/// local input paths or private material and never overwrites an existing file.
///
/// # Errors
/// Returns a value-free error for substituted inputs, missing or inconsistent
/// reports, unknown formats, insufficient measurements, expired bounds or I/O.
pub fn prepare_direct_upload_review(selection_file: &Path, output: &Path) -> Result<String> {
    let candidate = assembly::assemble(selection_file, now()?)?;
    let bytes = serde_json::to_vec_pretty(&candidate)
        .map_err(|_| anyhow::anyhow!("review candidate cannot be encoded"))?;
    files::write_new(output, &bytes)?;
    Ok(files::digest(&bytes))
}

/// Signs the exact independently reviewed candidate under the installed verifier.
///
/// The private key input is an owner-private regular file containing exactly 32
/// raw seed bytes. The public file contains a lowercase 64-character hex key,
/// optionally followed by one newline. The selection and every measured input
/// are revalidated; the candidate commitment is rechecked immediately before
/// signing. This method writes only the signed artifact, without activation.
///
/// # Errors
/// Returns a value-free error for unsafe private custody, substituted selection,
/// candidate or reports, key mismatch, expired evidence, encoding or output I/O.
pub fn sign_direct_upload_review(
    selection_file: &Path,
    candidate_file: &Path,
    reviewed_candidate_sha256: &str,
    reviewer_key_file: &Path,
    installed_public_key_file: &Path,
    output: &Path,
) -> Result<String> {
    ensure!(
        aos_hub_core::direct_upload::valid_direct_digest(reviewed_candidate_sha256),
        "reviewed candidate commitment malformed"
    );
    let reviewed_bytes = files::read_bytes(candidate_file, files::DOCUMENT_LIMIT)?;
    ensure!(
        files::digest(&reviewed_bytes) == reviewed_candidate_sha256,
        "reviewed candidate changed or was substituted"
    );
    let candidate: selection::DirectReviewCandidate = serde_json::from_slice(&reviewed_bytes)
        .map_err(|_| anyhow::anyhow!("review candidate is not a closed supported format"))?;
    let rebuilt = assembly::assemble(selection_file, now()?)?;
    ensure!(
        candidate.version == 1
            && candidate.artifact.signature.is_empty()
            && serde_json::to_vec(&candidate)? == serde_json::to_vec(&rebuilt)?,
        "reviewed candidate differs from selected current measurements"
    );
    let public = files::public_key(&files::read_bytes(installed_public_key_file, 65)?)?;
    ensure!(
        public == candidate.trusted_public_key,
        "independently installed reviewer verifier differs"
    );

    let private = crate::auth::seal::read_secret_file_zeroizing_capped(reviewer_key_file, 32)
        .map_err(|_| anyhow::anyhow!("reviewer private key custody or size invalid"))?;
    let seed =
        Zeroizing::new(<[u8; 32]>::try_from(private.as_slice()).map_err(|_| {
            anyhow::anyhow!("reviewer private key must contain exactly 32 raw bytes")
        })?);
    // The pinned dalek zeroize feature clears SigningKey's seed on drop.
    let key = SigningKey::from_bytes(&seed);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == public,
        "reviewer private key differs from installed verifier"
    );
    let mut artifact = candidate.artifact;
    artifact.validate_unsigned(&artifact.deployment_id, &artifact.public_origin, now()?)?;
    let signing_bytes = artifact.signing_bytes()?;
    ensure!(
        files::read_bytes(candidate_file, files::DOCUMENT_LIMIT)? == reviewed_bytes,
        "reviewed candidate changed immediately before signing"
    );
    artifact.signature = hex::encode(key.sign(&signing_bytes).to_bytes());
    artifact.verify(
        &artifact.deployment_id,
        &artifact.public_origin,
        &public,
        now()?,
    )?;
    let bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|_| anyhow::anyhow!("signed review artifact cannot be encoded"))?;
    files::write_new(output, &bytes)?;
    Ok(files::digest(&bytes))
}

#[cfg(test)]
mod tests;
