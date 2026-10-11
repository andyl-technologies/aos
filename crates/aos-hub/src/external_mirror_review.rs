//! Explicit independent review of a finite emulator-only External Mirror probe.
//!
//! Preparation reopens selected actual files, verifies the unchanged current
//! Direct prerequisite, and joins the installed tuple, domain, provider journal
//! and authenticated Clock observations. Signing requires an explicitly reviewed
//! candidate SHA and a separate ephemeral reviewer. It performs no provider call,
//! installation, business dispatch or Hosted qualification.
//!
//! ```text
//! mirror-functional-fixture-key -> new private seed and separate public verifier
//! mirror-functional-prepare(selection) -> candidate and exact SHA for review
//! mirror-functional-sign(selection, reviewed candidate SHA, private seed)
//! mirror-functional-verify(selection, signed artifact) -> exact artifact SHA
//! mirror-functional-registry-key(selection, signed artifact) -> shared typed key
//! ```

mod assembly;
mod clock;
mod domain;
mod installation;
mod observations;
mod provider;
mod selection;

// The existing offline reviewer owns the bounded file and output custody rules.
// Both tools use that implementation rather than adding another filesystem policy.
#[path = "oci_sdk_review/files.rs"]
mod files;

#[path = "oci_sdk_review/observations.rs"]
mod clock_records;

pub use selection::{
    ExternalMirrorReviewCandidate, ExternalMirrorReviewSelection, MirrorClockFiles,
    MirrorReviewFile, MirrorReviewInputs,
};

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, ensure};
use aos_hub_core::mirror_acceptance::external_controlled::{
    CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES, ControlledExternalMirrorArtifact,
    controlled_external_mirror_key,
};
use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Creates new owner-private ephemeral keys for the distinct functional reviewer.
///
/// The caller installs and independently reviews the verifier before selecting
/// the initial configuration. This operation does not load an existing seed.
///
/// # Errors
/// Refuses unavailable entropy, unsafe custody or existing output files.
pub fn create_external_mirror_fixture_key(
    private_output: &Path,
    public_output: &Path,
) -> Result<String> {
    crate::oci_sdk_review::create_oci_sdk_fixture_key(private_output, public_output)
}

/// Prepares an unsigned functional-only candidate from exact actual retained inputs.
///
/// Returns the new candidate's complete SHA for independent review. It does not
/// sign, install acceptance, contact a provider or dispatch a business operation.
///
/// # Errors
/// Refuses substituted files, unknown reports, changed installation or current
/// prerequisite, invalid Clock authentication, incomplete provider journals or expiry.
pub fn prepare_external_mirror_review(selection: &Path, output: &Path) -> Result<String> {
    let candidate = assembly::assemble(selection, now()?)
        .map_err(|_| anyhow::anyhow!("External Mirror selected actual inputs refused"))?;
    candidate.artifact.validate_unsigned(now()?)?;
    let bytes = serde_json::to_vec_pretty(&candidate)?;
    ensure!(
        bytes.len() <= files::DOCUMENT_LIMIT as usize,
        "Mirror candidate exceeds bound"
    );
    files::write_new(output, &bytes)?;
    Ok(files::digest(&bytes))
}

/// Signs only the explicitly reviewed candidate after rereading its actual inputs.
///
/// The selected seed must match the separately installed functional verifier.
/// The unchanged current Direct loader and immutable issue/cutoff are checked
/// again; neither selection nor signing renews prerequisite authority.
///
/// # Errors
/// Refuses changed candidate/evidence, missing explicit review, key reuse,
/// substituted verifier, invalid current scope or unsafe/existing output custody.
pub fn sign_external_mirror_review(
    selection: &Path,
    candidate_file: &Path,
    reviewed_sha256: &str,
    private_file: &Path,
    public_file: &Path,
    output: &Path,
) -> Result<String> {
    ensure!(
        aos_hub_core::direct_upload::valid_direct_digest(reviewed_sha256),
        "Mirror reviewed SHA malformed"
    );
    let bytes = files::private_bytes(candidate_file, files::DOCUMENT_LIMIT)?;
    ensure!(
        files::digest(&bytes) == reviewed_sha256,
        "Mirror reviewed candidate changed"
    );
    let candidate: ExternalMirrorReviewCandidate = serde_json::from_slice(&bytes)?;
    let rebuilt = assembly::assemble(selection, now()?)
        .map_err(|_| anyhow::anyhow!("External Mirror selected actual inputs refused"))?;
    ensure!(
        candidate.version == 1
            && candidate.artifact.signature.is_empty()
            && serde_json::to_vec(&candidate)? == serde_json::to_vec(&rebuilt)?,
        "Mirror reviewed candidate differs from actual inputs"
    );
    let public = files::public_key(&files::private_bytes(public_file, 65)?)?;
    ensure!(
        public == candidate.trusted_public_key,
        "Mirror installed verifier differs"
    );
    let private = files::private_bytes(private_file, 32)?;
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(private.as_slice())
            .map_err(|_| anyhow::anyhow!("Mirror reviewer seed must be exactly 32 raw bytes"))?,
    );
    let key = SigningKey::from_bytes(&seed);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == public,
        "Mirror seed differs from installed verifier"
    );
    ensure!(
        files::private_bytes(candidate_file, files::DOCUMENT_LIMIT)?.as_slice() == bytes.as_slice(),
        "Mirror reviewed candidate changed immediately before signing"
    );

    let mut artifact = candidate.artifact;
    artifact.validate_unsigned(now()?)?;
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes()?).to_bytes());
    require_signature(&artifact, &rebuilt, &public, now()?)?;
    let bytes = serde_json::to_vec_pretty(&artifact)?;
    ensure!(
        bytes.len() <= CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES,
        "Mirror signed artifact exceeds bound"
    );
    files::write_new(output, &bytes)?;
    Ok(files::digest(&bytes))
}

fn require_signature(
    artifact: &ControlledExternalMirrorArtifact,
    candidate: &ExternalMirrorReviewCandidate,
    public: &str,
    current: u64,
) -> Result<()> {
    let mut unsigned = artifact.clone();
    unsigned.signature.clear();
    ensure!(
        serde_json::to_vec(&unsigned)? == serde_json::to_vec(&candidate.artifact)?
            && public == candidate.trusted_public_key,
        "Mirror artifact differs from actual reviewed selection"
    );
    let profile = aos_hub_core::direct_upload::DirectProtectedProfile::External {
        profile: candidate.artifact.protected_profile.profile.clone(),
        runtime_qualification: candidate
            .artifact
            .protected_profile
            .runtime_qualification
            .clone(),
    };
    artifact.require_current(
        &candidate.artifact.deployment_id,
        &candidate.artifact.public_origin,
        &candidate.artifact.source_digest,
        &candidate.artifact.script_version,
        &profile,
        &candidate.artifact.direct_evidence_sha256,
        public,
        current,
    )
}

/// Verifies a signed functional artifact against reread actual inputs and shared codec.
///
/// Returns only the exact artifact SHA, without installation or permission to
/// reuse a different profile, source, cohort, process or namespace.
///
/// # Errors
/// Refuses expired or changed actual inputs, unsafe files, foreign signatures
/// or a document different from the exact selected functional candidate.
pub fn verify_external_mirror_review(selection: &Path, artifact_file: &Path) -> Result<String> {
    let candidate = assembly::assemble(selection, now()?)
        .map_err(|_| anyhow::anyhow!("External Mirror selected actual inputs refused"))?;
    let bytes = files::private_bytes(artifact_file, CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES as u64)?;
    let artifact: ControlledExternalMirrorArtifact = serde_json::from_slice(&bytes)?;
    require_signature(&artifact, &candidate, &candidate.trusted_public_key, now()?)?;
    Ok(files::digest(&bytes))
}

/// Derives the dedicated functional KV address through the shared Rust codec.
///
/// Rechecks the signed artifact and selected actual inputs. A key derivation or
/// subsequent KV readback is not proof of a business operation's acceptance.
///
/// # Errors
/// Refuses any failed current verification, invalid shared identity or unsafe file.
pub fn external_mirror_registry_key(selection: &Path, artifact_file: &Path) -> Result<String> {
    let verified_sha256 = verify_external_mirror_review(selection, artifact_file)?;
    let bytes = files::private_bytes(artifact_file, CONTROLLED_EXTERNAL_MIRROR_MAX_BYTES as u64)?;
    ensure!(
        files::digest(&bytes) == verified_sha256,
        "Mirror artifact changed before key derivation"
    );
    let artifact: ControlledExternalMirrorArtifact = serde_json::from_slice(&bytes)?;
    let profile = aos_hub_core::direct_upload::DirectProtectedProfile::External {
        profile: artifact.protected_profile.profile,
        runtime_qualification: artifact.protected_profile.runtime_qualification,
    };
    controlled_external_mirror_key(
        &artifact.deployment_id,
        &artifact.source_digest,
        &artifact.script_version,
        &profile,
    )
}

#[cfg(test)]
mod tests;
