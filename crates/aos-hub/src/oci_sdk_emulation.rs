//! Explicit Native opt-in for independently reviewed emulator-only OCI SDK use.
//!
//! Reviewer trust is read from a separate bounded private file. This loader
//! never produces Direct accepted profiles or mirror authority. The actual
//! running Native executable must match the independent installation report.
//!
//! ```json
//! {"oci-emulator-reviewer":"<hexadecimal Ed25519 public key>"}
//! ```

use std::{collections::BTreeMap, io::Read as _, path::Path};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    direct_upload::valid_direct_digest,
    mirror_guard::MirrorGuardIssuer,
    oci_sdk_emulation::{OciSdkEmulationArtifact, MAX_OCI_SDK_EMULATION_ARTIFACT_BYTES},
};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

/// Retains one verified OCI-only emulator acceptance and its independent reviewer.
#[derive(Clone)]
pub struct NativeOciSdkEmulation {
    artifact: OciSdkEmulationArtifact,
    reviewer: String,
}

impl NativeOciSdkEmulation {
    /// Loads explicit OCI-only permission for this actual running Native process.
    ///
    /// # Errors
    /// Rejects insecure or oversized files, malformed input, unknown reviewers,
    /// wrong origins/code/process, invalid signatures or unavailable permission.
    pub fn from_files(
        acceptance_path: &Path,
        review_keys_path: &Path,
        deployment: &str,
        worker_origin: &str,
        native_origin: &str,
    ) -> Result<Self> {
        let bytes = crate::auth::seal::read_secret_file_zeroizing_capped(
            acceptance_path,
            MAX_OCI_SDK_EMULATION_ARTIFACT_BYTES as u64,
        )
        .map_err(|_| anyhow::anyhow!("OCI SDK acceptance input is unavailable"))?;
        let keys =
            crate::auth::seal::read_secret_file_zeroizing_capped(review_keys_path, 16 * 1024)
                .map_err(|_| anyhow::anyhow!("OCI SDK reviewer input is unavailable"))?;
        Self::from_bytes(
            &bytes,
            &keys,
            deployment,
            worker_origin,
            native_origin,
            &running_executable_sha256()?,
            u64::try_from(aos_hub_core::clock::now_unix_secs())?,
        )
    }

    fn from_bytes(
        bytes: &[u8],
        keys: &[u8],
        deployment: &str,
        worker_origin: &str,
        native_origin: &str,
        executable_sha256: &str,
        raw_now: u64,
    ) -> Result<Self> {
        ensure!(
            keys.len() <= 16 * 1024,
            "OCI SDK reviewer input exceeds bound"
        );
        let artifact = OciSdkEmulationArtifact::decode(bytes)?;
        let reviewers: BTreeMap<String, String> = serde_json::from_slice(keys)
            .map_err(|_| anyhow::anyhow!("OCI SDK reviewer input is malformed"))?;
        ensure!(
            !reviewers.is_empty() && reviewers.len() <= 32,
            "OCI SDK reviewer set is invalid"
        );
        for (identity, key) in &reviewers {
            ensure!(
                !identity.is_empty()
                    && identity.len() <= 256
                    && !identity.chars().any(char::is_control)
                    && valid_direct_digest(key),
                "OCI SDK reviewer identity or key is invalid"
            );
            let public: [u8; 32] = hex::decode(key)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("OCI SDK reviewer key is invalid"))?;
            VerifyingKey::from_bytes(&public)
                .map_err(|_| anyhow::anyhow!("OCI SDK reviewer key is invalid"))?;
        }
        let reviewer = reviewers
            .get(&artifact.reviewer_key_id)
            .context("OCI SDK reviewer is not independently trusted")?
            .clone();
        ensure!(
            artifact.profile.native_origin == native_origin
                && artifact.evidence.installation.native_executable_sha256 == executable_sha256,
            "OCI SDK acceptance selected another Native process or origin"
        );
        let accepted = Self { artifact, reviewer };
        accepted.check(deployment, worker_origin, raw_now)?;
        Ok(accepted)
    }

    /// Rechecks current OCI-only permission without granting any other workflow.
    ///
    /// # Errors
    /// Rejects changed audience, an expired original or conservative clock overflow.
    pub(crate) fn check(&self, deployment: &str, worker_origin: &str, raw_now: u64) -> Result<()> {
        let latest = raw_now
            .checked_add(self.artifact.profile.clock_policy.uncertainty_seconds.get())
            .context("OCI SDK clock overflow")?;
        self.artifact
            .verify(deployment, worker_origin, &self.reviewer, latest)
    }

    pub(crate) fn document_effect(
        &self,
    ) -> Result<aos_hub_core::hybrid_ingress::OciDocumentEffect> {
        Ok(aos_hub_core::hybrid_ingress::OciDocumentEffect {
            protected_profile_digest: self.artifact.profile.digest()?,
            acceptance_digest: self.artifact.evidence_sha256.clone(),
            issued_at: self.artifact.issued_at,
            expires_at: self.artifact.expires_at,
            clock_uncertainty_seconds: self.artifact.profile.clock_policy.uncertainty_seconds.get(),
        })
    }

    pub(crate) fn projection_identity(
        &self,
        deployment: &str,
        worker_origin: &str,
    ) -> Result<(String, MirrorGuardIssuer, u64)> {
        self.check(
            deployment,
            worker_origin,
            u64::try_from(aos_hub_core::clock::now_unix_secs())?,
        )?;
        Ok((
            self.artifact.profile.digest()?,
            MirrorGuardIssuer {
                source_digest: self.artifact.profile.worker_source_digest.clone(),
                script_version: self.artifact.profile.worker_script_version.clone(),
            },
            self.artifact.profile.clock_policy.uncertainty_seconds.get(),
        ))
    }
}

// The Linux executable handle selects the live process's actual inode, rather
// than a path that could be replaced after an independent process observation.
fn running_executable_sha256() -> Result<String> {
    ensure!(
        cfg!(target_os = "linux"),
        "OCI SDK process observation requires Linux"
    );
    let mut file = std::fs::File::open("/proc/self/exe")
        .map_err(|_| anyhow::anyhow!("OCI SDK running executable is unavailable"))?;
    let length = file.metadata()?.len();
    ensure!(
        length > 0 && length <= 256 * 1024 * 1024,
        "OCI SDK executable exceeds its bound"
    );
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .context("OCI SDK executable length overflow")?;
        ensure!(
            total <= length,
            "OCI SDK executable changed during observation"
        );
        digest.update(&buffer[..count]);
    }
    ensure!(
        total == length && file.metadata()?.len() == length,
        "OCI SDK executable changed during observation"
    );
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests;
