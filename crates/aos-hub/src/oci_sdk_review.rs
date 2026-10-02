//! Offline, independently selected local OCI SDK candidate preparation and signing.
//!
//! This fixture-only workflow joins exact installed bytes, live namespace and
//! Native process observations, authenticated Clock captures and a one-shot
//! positive anchor. It grants no Direct, Copy, mirror, S3 or Hosted authority.
//! The signed observed-operation scope covers only anchor PUT/conditional GET,
//! not business dispatch refusal after expiry or full runtime qualification.
//!
//! ```text
//! oci-sdk-observe-native -> private process report/configuration
//! oci-sdk-prepare(selected actual inputs) -> new unsigned candidate + SHA
//! oci-sdk-sign(exact reviewed candidate SHA, private seed, installed verifier)
//!   -> new signed OCI-only artifact + SHA
//! oci-sdk-verify(artifact, separate verifier, expected audience/source) -> SHA
//! ```

mod anchor;
mod assembly;
mod clock;
mod files;
mod json;
mod native;
mod observations;
mod selection;

pub use selection::*;

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{ensure, Result};
use aos_hub_core::oci_sdk_emulation::OciSdkEmulationArtifact;
use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Creates new ephemeral owner-private reviewer keys for this local fixture.
///
/// It never loads an existing seed, configures reviewer trust or installs an
/// artifact. The caller independently selects and installs the new verifier.
///
/// # Errors
/// Rejects unavailable OS entropy, unsafe output custody or existing outputs.
pub fn create_oci_sdk_fixture_key(private_output: &Path, public_output: &Path) -> Result<String> {
    use rand::TryRngCore as _;

    let mut seed = Zeroizing::new([0_u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|_| anyhow::anyhow!("OCI fixture OS entropy unavailable"))?;
    let key = SigningKey::from_bytes(&seed);
    let public = hex::encode(key.verifying_key().to_bytes());
    files::write_new(private_output, seed.as_slice())?;
    files::write_new(public_output, public.as_bytes())?;
    Ok(public)
}

/// Observes one owned Native process without granting OCI provider permission.
///
/// Creates two new owner-private files: exact argv/environment configuration
/// and a value-free public process/executable projection. The running process
/// must match the independently selected executable and remain unchanged.
///
/// # Errors
/// Rejects changed process lifetime/owner/executable, excessive inputs, unsafe
/// output custody, an existing output, or unavailable Linux process readback.
pub fn observe_oci_sdk_native(
    pid: u32,
    executable: &Path,
    configuration_output: &Path,
    observation_output: &Path,
) -> Result<String> {
    native::observe(pid, executable, configuration_output, observation_output)
        .map_err(|_| anyhow::anyhow!("OCI Native observation refused"))
}

/// Prepares a closed unsigned OCI-only candidate from selected actual captures.
///
/// The returned SHA identifies exact new candidate bytes for independent
/// review. This operation performs no SDK effect, registry write or activation.
///
/// # Errors
/// Rejects unsafe custody, substituted files, invalid Clock authentication,
/// unknown anchors, old source relabeling, changed installed facts or cutoffs.
pub fn prepare_oci_sdk_review(selection_file: &Path, output: &Path) -> Result<String> {
    let candidate = assembly::assemble(selection_file, now()?)
        .map_err(|_| anyhow::anyhow!("OCI SDK selected actual evidence refused"))?;
    let bytes = serde_json::to_vec_pretty(&candidate)?;
    files::write_new(output, &bytes)?;
    Ok(files::digest(&bytes))
}

/// Signs only an explicitly reviewed, rebuilt candidate under the separate verifier.
///
/// The private fixture seed is exactly 32 raw bytes in owner-private custody.
/// Every selected capture and installed file is reread; an issue/cutoff cannot
/// be renewed, and no unknown SDK original can become a positive observation.
///
/// # Errors
/// Rejects changed candidate/evidence, unsafe keys, a mismatched verifier,
/// expired original, malformed encoding or an existing output.
pub fn sign_oci_sdk_review(
    selection_file: &Path,
    candidate_file: &Path,
    reviewed_sha256: &str,
    private_key_file: &Path,
    installed_public_file: &Path,
    output: &Path,
) -> Result<String> {
    ensure!(
        aos_hub_core::direct_upload::valid_direct_digest(reviewed_sha256),
        "OCI reviewed candidate hash malformed"
    );
    let bytes = files::private_bytes(candidate_file, files::DOCUMENT_LIMIT)?;
    ensure!(
        files::digest(&bytes) == reviewed_sha256,
        "OCI reviewed candidate changed"
    );
    let candidate: OciSdkReviewCandidate = serde_json::from_slice(&bytes)?;
    let rebuilt = assembly::assemble(selection_file, now()?)
        .map_err(|_| anyhow::anyhow!("OCI SDK selected actual evidence refused"))?;
    ensure!(
        candidate.version == 1
            && candidate.artifact.signature.is_empty()
            && serde_json::to_vec(&candidate)? == serde_json::to_vec(&rebuilt)?,
        "OCI reviewed candidate differs from rebuilt actual evidence"
    );
    let public = files::public_key(&files::private_bytes(installed_public_file, 65)?)?;
    ensure!(
        public == candidate.trusted_public_key,
        "OCI separately installed reviewer differs"
    );
    let private = files::private_bytes(private_key_file, 32)?;
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(private.as_slice())
            .map_err(|_| anyhow::anyhow!("OCI reviewer seed must contain exactly 32 raw bytes"))?,
    );
    let key = SigningKey::from_bytes(&seed);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == public,
        "OCI fixture seed differs from installed reviewer"
    );
    let mut artifact = candidate.artifact;
    artifact.validate_unsigned(
        &artifact.profile.deployment_id,
        &artifact.profile.public_origin,
        now()?,
    )?;
    ensure!(
        files::private_bytes(candidate_file, files::DOCUMENT_LIMIT)?.as_slice() == bytes.as_slice(),
        "OCI reviewed candidate changed immediately before signing"
    );
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes()?).to_bytes());
    artifact.verify(
        &artifact.profile.deployment_id,
        &artifact.profile.public_origin,
        &public,
        now()?,
    )?;
    let bytes = serde_json::to_vec_pretty(&artifact)?;
    files::write_new(output, &bytes)?;
    Ok(files::digest(&bytes))
}

/// Verifies a current OCI-only artifact against independently selected expectations.
///
/// This offline verifier returns exact file SHA; it neither installs acceptance
/// nor returns a dispatch profile or any production provider qualification.
///
/// # Errors
/// Rejects unsafe input custody, malformed signatures, a changed audience,
/// reviewer/source/script, expired original or unsupported observed scope.
pub fn verify_oci_sdk_review(
    artifact_file: &Path,
    public_file: &Path,
    reviewer_id: &str,
    deployment: &str,
    origin: &str,
    source: &str,
    script: &str,
) -> Result<String> {
    let bytes = files::private_bytes(
        artifact_file,
        aos_hub_core::oci_sdk_emulation::MAX_OCI_SDK_EMULATION_ARTIFACT_BYTES as u64,
    )?;
    let artifact = OciSdkEmulationArtifact::decode(&bytes)?;
    let public = files::public_key(&files::private_bytes(public_file, 65)?)?;
    ensure!(
        artifact.reviewer_key_id == reviewer_id
            && artifact.profile.worker_source_digest == source
            && artifact.profile.worker_script_version == script,
        "OCI selected reviewer or source differs"
    );
    artifact.verify(deployment, origin, &public, now()?)?;
    Ok(files::digest(&bytes))
}

#[cfg(test)]
mod tests;
