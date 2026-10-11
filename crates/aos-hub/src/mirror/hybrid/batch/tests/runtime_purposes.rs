//! Read-only qualification of an independently supplied signed purpose chain.
//!
//! The driver never creates reviewer evidence or signatures. A fresh protected
//! discovery reply is checked in its original guard domain before independently
//! trusted direct, mirror and pack artifacts are joined. This validates supplied
//! admission prerequisites, not an observed production mirror dispatch.

use std::{io::Read as _, path::PathBuf};

use anyhow::{ensure, Result};
use aos_hub_core::mirror_acceptance::{
    pack::MirrorPackAcceptanceArtifact, MirrorAcceptanceArtifact,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inputs {
    direct_artifact: PathBuf,
    mirror_artifact: PathBuf,
    pack_artifact: PathBuf,
    direct_public_key: PathBuf,
    mirror_public_key: PathBuf,
    deployment_guard_key: PathBuf,
    original_challenge: PathBuf,
    deployment_reply: PathBuf,
    deployment_reply_signature: PathBuf,
}

fn read(path: &std::path::Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum,
        "purpose input is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "purpose input exceeds bound");
    Ok(bytes)
}

fn public_key(path: &std::path::Path) -> Result<String> {
    let text = String::from_utf8(read(path, 65)?)?;
    let selected = text.trim();
    ensure!(
        valid_direct_digest(selected),
        "independent reviewer key invalid"
    );
    Ok(selected.into())
}

fn verify(inputs: Inputs) -> Result<serde_json::Value> {
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
    let direct_bytes = read(&inputs.direct_artifact, 128 * 1024)?;
    let mirror_bytes = read(&inputs.mirror_artifact, 128 * 1024)?;
    let pack_bytes = read(
        &inputs.pack_artifact,
        aos_hub_core::mirror_acceptance::pack::MIRROR_PACK_ACCEPTANCE_MAX_BYTES as u64,
    )?;
    let direct: DirectWorkerQualificationArtifact = serde_json::from_slice(&direct_bytes)?;
    let mirror: MirrorAcceptanceArtifact = serde_json::from_slice(&mirror_bytes)?;
    let pack: MirrorPackAcceptanceArtifact = serde_json::from_slice(&pack_bytes)?;
    let direct_public = public_key(&inputs.direct_public_key)?;
    let mirror_public = public_key(&inputs.mirror_public_key)?;
    ensure!(
        direct_public != mirror_public,
        "mirror reviewer role must be independent of direct reviewer"
    );

    // The key is operator supplied; no acceptance artifact can choose it. It
    // stays private and neither key bytes nor a key commitment enter reports.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::symlink_metadata(&inputs.deployment_guard_key)?
            .permissions()
            .mode();
        ensure!(
            mode & 0o077 == 0,
            "deployment guard key custody is not private"
        );
    }
    let guard = StorageWorkKey::new(read(&inputs.deployment_guard_key, 4096)?)?;
    let challenge: DirectWorkerDeploymentChallenge =
        serde_json::from_slice(&read(&inputs.original_challenge, 256 * 1024)?)?;
    let reply_bytes = read(&inputs.deployment_reply, 256 * 1024)?;
    let signature = String::from_utf8(read(&inputs.deployment_reply_signature, 256)?)?;
    let reply = verify_direct_worker_deployment_reply(
        &guard,
        signature.trim(),
        &reply_bytes,
        &challenge,
        now,
    )?;
    let identity = reply.identity;
    let raw = direct
        .evidence
        .managed_profile
        .as_ref()
        .context("managed direct prerequisite absent")?;
    let latest = now
        .checked_add(raw.clock_uncertainty_seconds.get())
        .context("purpose clock overflow")?;
    direct.verify(
        &identity.deployment_id,
        &identity.public_origin,
        &direct_public,
        latest,
    )?;
    direct.verify_deployment_identity(&identity, &direct_public)?;
    let policy = direct
        .evidence
        .private_stage_policy
        .clone()
        .context("managed policy prerequisite absent")?;
    let profile =
        DirectProtectedProfile::managed(raw.clone(), policy, direct.evidence.runtime.clone())?;
    mirror.require_production(
        &identity.deployment_id,
        &identity.public_origin,
        &identity.source_digest,
        &identity.script_version,
        &profile,
        &direct.evidence_sha256,
        &mirror_public,
        latest,
    )?;
    pack.require_production(&mirror, &mirror_public, latest, pack.geometry.pack_bytes)?;

    let hash = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    Ok(serde_json::json!({
        "version": 1, "purposeChain": "verified", "productionAdmission": "unknown",
        "reason": "fresh authenticated discovery and independent signed purposes verified; no production dispatch was executed",
        "deploymentId": identity.deployment_id, "sourceDigest": identity.source_digest, "scriptVersion": identity.script_version,
        "directFileSha256": hash(&direct_bytes), "mirrorFileSha256": hash(&mirror_bytes), "packFileSha256": hash(&pack_bytes),
        "authenticatedDeploymentReplySha256": hash(&reply_bytes), "directEvidenceSha256": direct.evidence_sha256,
        "fullSignedMirrorArtifactSha256": aos_hub_core::mirror_work::digest(&mirror)?,
        "directPublicKey": direct_public, "mirrorPublicKey": mirror_public,
        "mirrorAcceptanceKey": aos_hub_core::mirror_acceptance::mirror_acceptance_key(&identity.deployment_id, &identity.source_digest, &identity.script_version)?,
        "packAcceptanceKey": aos_hub_core::mirror_acceptance::pack::mirror_pack_acceptance_key(&identity.deployment_id, &identity.source_digest, &identity.script_version)?,
    }))
}

#[test]
#[ignore = "requires independently supplied signed purposes and fresh protected discovery"]
fn independently_supplied_signed_purposes() -> Result<()> {
    let root = PathBuf::from(std::env::var("AOS_MIRROR_RUNTIME_EVIDENCE")?);
    let report = match std::env::var_os("AOS_MIRROR_PURPOSE_INPUT") {
        None => {
            serde_json::json!({"version": 1, "purposeChain": "unknown", "productionAdmission": "unknown",
            "reason": "independent signed chain and fresh authenticated deployment observation were not supplied"})
        }
        Some(path) => {
            let inputs: Inputs = serde_json::from_slice(&read(&PathBuf::from(path), 16 * 1024)?)?;
            match verify(inputs) {
                Ok(report) => report,
                Err(_) => {
                    std::fs::write(
                        root.join("purpose-observations.json"),
                        serde_json::to_vec_pretty(&serde_json::json!({
                            "version": 1, "purposeChain": "refused", "productionAdmission": "unknown",
                            "reason": "supplied purpose chain or original authenticated deployment observation was refused",
                        }))?,
                    )?;
                    anyhow::bail!("independent supplied purpose validation refused; value-free evidence retained");
                }
            }
        }
    };
    std::fs::write(
        root.join("purpose-observations.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}
