//! Publishes the independently reviewed live purpose for an unchanged deployment.
//!
//! Direct, ordinary mirror and pack prerequisites remain independently signed.
//! This child publishes only the live-specific record, using the installed
//! reviewer role and the exact full signed ordinary artifact commitment.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use aos_hub_core::direct_upload::DirectWorkerDeploymentIdentity;
use aos_hub_core::mirror_acceptance::live::{
    mirror_live_acceptance_key, MirrorLiveAcceptanceArtifact, LIVE_ACCEPTANCE_MAX_BYTES,
};
use tokio::io::AsyncWriteExt as _;

use super::{AcceptanceRecord, HybridMirrorAcceptanceConfig};
use crate::cloudflare::{Assets, HybridDeployConfig};

/// Selects independently signed prerequisites and a separate live-purpose review.
#[derive(Clone, Debug)]
pub struct HybridMirrorLiveAcceptanceConfig {
    /// Exact ordinary mirror and required pack artifacts, including signatures.
    pub prerequisites: HybridMirrorAcceptanceConfig,
    /// Separately purposed live review with all thirteen actual report commitments.
    pub live: MirrorLiveAcceptanceArtifact,
}

impl HybridMirrorLiveAcceptanceConfig {
    /// Reads closed bounded documents without manufacturing review evidence.
    ///
    /// # Errors
    /// Returns a value-free error for nonregular, malformed or oversized files.
    pub fn from_files(mirror: &Path, pack: &Path, live: &Path) -> Result<Self> {
        Ok(Self {
            prerequisites: HybridMirrorAcceptanceConfig::from_files(mirror, Some(pack))?,
            live: crate::cloudflare::direct_upload::read_config_file_with_limit(
                live,
                LIVE_ACCEPTANCE_MAX_BYTES,
            )?,
        })
    }

    fn record(
        &self,
        cfg: &HybridDeployConfig,
        identity: &DirectWorkerDeploymentIdentity,
        now: u64,
    ) -> Result<AcceptanceRecord> {
        self.prerequisites
            .pack
            .as_ref()
            .context("live activation requires the separately reviewed pack prerequisite")?;
        // Reuse the ordinary installer validator without publishing its records.
        // A malformed prerequisite cannot leave a newly installed live subset.
        self.prerequisites.records(cfg, identity, now)?;

        let trust = cfg
            .mirror_trust
            .as_ref()
            .context("live activation requires independently installed reviewer trust")?;
        let raw = identity
            .managed_profile
            .as_ref()
            .context("live activation requires the authenticated managed profile")?;
        let latest = now
            .checked_add(raw.clock_uncertainty_seconds.get())
            .context("live activation clock overflow")?;
        self.live
            .require_production(&self.prerequisites.mirror, &trust.public_key, latest)?;

        AcceptanceRecord::new(
            mirror_live_acceptance_key(&self.live.mirror_artifact_sha256)?,
            &self.live,
            LIVE_ACCEPTANCE_MAX_BYTES,
        )
    }

    async fn current_record(
        &self,
        cfg: &HybridDeployConfig,
        guard_key_file: &Path,
    ) -> Result<AcceptanceRecord> {
        let direct = cfg
            .direct_upload_acceptance
            .as_ref()
            .context("live activation requires an independently signed direct prerequisite")?;
        let selectors = direct
            .artifact
            .evidence
            .external_profiles
            .iter()
            .map(|item| item.profile.selector.clone())
            .collect();
        let identity =
            crate::cloudflare::inspect_hybrid_direct_upload(cfg, guard_key_file, selectors).await?;

        self.record(
            cfg,
            &identity,
            u64::try_from(aos_hub_core::clock::now_unix_secs())?,
        )
    }
}

/// Publishes one live-purpose record after checking its full reviewed chain.
///
/// Authenticated discovery and original review cutoffs are rechecked after each
/// awaited staging operation and immediately before and after KV publication.
/// Only the separately purposed live record is written. The selected deployment
/// must already have its ordinary and pack prerequisites installed; this command
/// makes no runtime qualification claim and does not redeploy the Worker.
///
/// # Errors
/// Returns an error for missing trust or prerequisites, invalid or controlled
/// artifacts, changed current pins, expiry, private staging or KV publication
/// failure. A post-write refusal does not erase a possibly published record.
pub async fn activate_hybrid_mirror_live(
    assets: &Assets,
    cfg: &HybridDeployConfig,
    guard_key_file: &Path,
    acceptance: &HybridMirrorLiveAcceptanceConfig,
) -> Result<()> {
    crate::cloudflare::render_hybrid_wrangler_toml(cfg)?;
    let record = acceptance.current_record(cfg, guard_key_file).await?;
    let staging = tempfile::Builder::new()
        .prefix("aos-hub-mirror-live-acceptance")
        .tempdir()?;
    let path = staging.path().join("live.json");

    let mut output = private_output(&path).await?;
    acceptance.current_record(cfg, guard_key_file).await?;
    output.write_all(&record.bytes).await?;
    acceptance.current_record(cfg, guard_key_file).await?;
    output.flush().await?;
    acceptance.current_record(cfg, guard_key_file).await?;
    drop(output);

    let trust = cfg
        .mirror_trust
        .as_ref()
        .context("live reviewer trust disappeared")?;
    let arguments = publication_arguments(&record.key, &trust.namespace_id, &path);
    crate::cloudflare::run_wrangler(assets, &arguments, None, None).await?;
    acceptance.current_record(cfg, guard_key_file).await?;
    Ok(())
}

async fn private_output(path: &Path) -> Result<tokio::fs::File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    options
        .open(path)
        .await
        .context("creating private live acceptance output")
}

fn publication_arguments(key: &str, namespace: &str, path: &Path) -> Vec<String> {
    vec![
        "kv".into(),
        "key".into(),
        "put".into(),
        key.into(),
        "--namespace-id".into(),
        namespace.into(),
        "--path".into(),
        PathBuf::from(path).to_string_lossy().into_owned(),
        "--remote".into(),
    ]
}

#[cfg(test)]
mod tests;
