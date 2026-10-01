//! Installs reviewed mirror purposes without replacing the measured Worker.
//!
//! The operator selects a public reviewer key and KV binding before deployment.
//! Activation consumes already signed hosted mirror and optional pack evidence,
//! checks the actual protected deployment and direct prerequisite, then writes
//! only the version-specific acceptance records. It grants no readiness claim.
//!
//! ```text
//! installed reviewer + KV -> measured unchanged script -> reviewed signatures
//!                         -> authenticated discovery -> exact KV publication
//! ```

use std::path::Path;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::direct_upload::{DirectProtectedProfile, DirectWorkerDeploymentIdentity};
use aos_hub_core::mirror_acceptance::pack::{
    mirror_pack_acceptance_key, MirrorPackAcceptanceArtifact, MIRROR_PACK_ACCEPTANCE_MAX_BYTES,
};
use aos_hub_core::mirror_acceptance::{
    mirror_acceptance_key, MirrorAcceptanceArtifact, MIRROR_ACCEPTANCE_MAX_BYTES,
};

use super::{Assets, HybridDeployConfig, HybridDirectUploadTrustConfig};

mod live;

pub use live::{activate_hybrid_mirror_live, HybridMirrorLiveAcceptanceConfig};

/// Selects independently installed mirror reviewer trust and its KV binding.
#[derive(Clone, Debug)]
pub struct HybridMirrorTrustConfig {
    /// Independently selected Ed25519 public verifier, as lowercase hexadecimal.
    pub public_key: String,
    /// Operator-selected Cloudflare KV namespace identifier.
    pub namespace_id: String,
}

impl HybridMirrorTrustConfig {
    /// Reads the public verifier using the existing bounded installer contract.
    ///
    /// # Errors
    /// Returns an error for a nonregular, oversized or invalid verifier file or
    /// namespace. No verifier is learned from an acceptance document.
    pub fn from_public_key_file(path: &Path, namespace_id: String) -> Result<Self> {
        let trust = HybridDirectUploadTrustConfig::from_public_key_file(path, namespace_id)?;
        Ok(Self {
            public_key: trust.public_key,
            namespace_id: trust.namespace_id,
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        HybridDirectUploadTrustConfig {
            public_key: self.public_key.clone(),
            namespace_id: self.namespace_id.clone(),
        }
        .validate()
    }
}

/// Holds independently signed hosted evidence selected for explicit installation.
#[derive(Clone, Debug)]
pub struct HybridMirrorAcceptanceConfig {
    /// Full ordinary mirror artifact; signatures and raw-report commitments persist.
    pub mirror: MirrorAcceptanceArtifact,
    /// Optional separately signed pack purpose linked to this exact mirror artifact.
    pub pack: Option<MirrorPackAcceptanceArtifact>,
}

impl HybridMirrorAcceptanceConfig {
    /// Reads closed bounded artifacts without signing or accepting measurements.
    ///
    /// # Errors
    /// Returns a value-free error for malformed, nonregular or oversized inputs.
    /// Missing pack evidence leaves pack inspection unavailable.
    pub fn from_files(mirror: &Path, pack: Option<&Path>) -> Result<Self> {
        Ok(Self {
            mirror: super::direct_upload::read_config_file_with_limit(
                mirror,
                MIRROR_ACCEPTANCE_MAX_BYTES,
            )?,
            pack: pack
                .map(|path| {
                    super::direct_upload::read_config_file_with_limit(
                        path,
                        MIRROR_PACK_ACCEPTANCE_MAX_BYTES,
                    )
                })
                .transpose()?,
        })
    }

    fn records(
        &self,
        cfg: &HybridDeployConfig,
        identity: &DirectWorkerDeploymentIdentity,
        now: u64,
    ) -> Result<Vec<AcceptanceRecord>> {
        let trust = cfg
            .mirror_trust
            .as_ref()
            .context("mirror activation requires independently installed reviewer trust")?;
        trust.validate()?;
        let direct = cfg
            .direct_upload_acceptance
            .as_ref()
            .context("mirror activation requires the independently signed direct prerequisite")?;
        let direct_trust = cfg
            .direct_upload_trust
            .as_ref()
            .context("mirror activation requires installed direct reviewer trust")?;
        direct.validate(cfg)?;
        direct
            .artifact
            .verify_deployment_identity(identity, &direct_trust.public_key)?;

        let evidence = &direct.artifact.evidence;
        let raw = evidence
            .managed_profile
            .as_ref()
            .context("mirror activation requires a qualified managed R2 profile")?;
        let policy = evidence
            .private_stage_policy
            .as_ref()
            .context("mirror activation requires the qualified private stage policy")?;
        let profile =
            DirectProtectedProfile::managed(raw.clone(), policy.clone(), evidence.runtime.clone())?;
        let latest = now
            .checked_add(raw.clock_uncertainty_seconds.get())
            .context("mirror activation clock overflow")?;
        direct.artifact.verify(
            &cfg.deployment_id,
            &cfg.external_url,
            &direct_trust.public_key,
            latest,
        )?;
        self.mirror.require_production(
            &cfg.deployment_id,
            &cfg.external_url,
            &identity.source_digest,
            &identity.script_version,
            &profile,
            &direct.artifact.evidence_sha256,
            &trust.public_key,
            latest,
        )?;

        let mut records = vec![AcceptanceRecord::new(
            mirror_acceptance_key(
                &cfg.deployment_id,
                &identity.source_digest,
                &identity.script_version,
            )?,
            &self.mirror,
            MIRROR_ACCEPTANCE_MAX_BYTES,
        )?];
        if let Some(pack) = &self.pack {
            pack.require_production(
                &self.mirror,
                &trust.public_key,
                latest,
                pack.geometry.pack_bytes,
            )?;
            records.push(AcceptanceRecord::new(
                mirror_pack_acceptance_key(
                    &cfg.deployment_id,
                    &identity.source_digest,
                    &identity.script_version,
                )?,
                pack,
                MIRROR_PACK_ACCEPTANCE_MAX_BYTES,
            )?);
        }
        Ok(records)
    }
}

struct AcceptanceRecord {
    key: String,
    bytes: Vec<u8>,
}

impl AcceptanceRecord {
    fn new(key: String, artifact: &impl serde::Serialize, maximum: usize) -> Result<Self> {
        let bytes = serde_json::to_vec(artifact)?;
        ensure!(
            bytes.len() <= maximum,
            "mirror acceptance exceeds registry limit"
        );
        Ok(Self { key, bytes })
    }
}

/// Publishes reviewed mirror purposes for the actual unchanged hosted deployment.
///
/// Existing protected discovery authenticates the current source, script and
/// managed material. Every selected artifact is checked before the first KV
/// write and rechecked before each write. A failed write may leave a valid
/// subset installed; exact reinstallation is safe and grants no additional
/// purpose. The operator's existing Wrangler credential supplies KV authority.
///
/// # Errors
/// Returns an error for missing installed trust or prerequisites, invalid or
/// controlled evidence, changed runtime/profile pins, guard key custody,
/// discovery refusal, expiry or provider KV write failure.
pub async fn activate_hybrid_mirror(
    assets: &Assets,
    cfg: &HybridDeployConfig,
    guard_key_file: &Path,
    acceptance: &HybridMirrorAcceptanceConfig,
) -> Result<()> {
    super::render_hybrid_wrangler_toml(cfg)?;
    let direct = cfg
        .direct_upload_acceptance
        .as_ref()
        .context("mirror activation requires an independently signed direct prerequisite")?;
    let selectors = direct
        .artifact
        .evidence
        .external_profiles
        .iter()
        .map(|item| item.profile.selector.clone())
        .collect();
    let identity = super::inspect_hybrid_direct_upload(cfg, guard_key_file, selectors).await?;
    let now = || -> Result<u64> { Ok(u64::try_from(aos_hub_core::clock::now_unix_secs())?) };
    let records = acceptance.records(cfg, &identity, now()?)?;
    let trust = cfg
        .mirror_trust
        .as_ref()
        .context("mirror reviewer trust disappeared")?;
    let staging = tempfile::Builder::new()
        .prefix("aos-hub-mirror-acceptance")
        .tempdir()?;

    for (index, record) in records.iter().enumerate() {
        let path = staging.path().join(format!("accepted-{index}.json"));
        tokio::fs::write(&path, &record.bytes).await?;
        // A previous KV request or staging write may have crossed a deployment
        // change or review cutoff. Authenticate current installed pins again;
        // this cannot renew any artifact's immutable validity window.
        let current = super::inspect_hybrid_direct_upload(
            cfg,
            guard_key_file,
            direct
                .artifact
                .evidence
                .external_profiles
                .iter()
                .map(|item| item.profile.selector.clone())
                .collect(),
        )
        .await?;
        acceptance.records(cfg, &current, now()?)?;
        let arguments = vec![
            "kv".into(),
            "key".into(),
            "put".into(),
            record.key.clone(),
            "--namespace-id".into(),
            trust.namespace_id.clone(),
            "--path".into(),
            path.to_string_lossy().into_owned(),
            "--remote".into(),
        ];
        super::run_wrangler(assets, &arguments, None, None).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
