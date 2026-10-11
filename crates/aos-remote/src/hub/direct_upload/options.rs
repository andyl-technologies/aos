//! Shared local retry and provider-network options for product upload adapters.
//!
//! Journals retain unresolved server effects across restarts. A new run selects
//! a distinct file; it never truncates or adopts an existing operation namespace.

use std::path::PathBuf;

use aos_net::direct_upload::{
    DirectClientError, ProviderOptions, ensure_private_checkpoint_directory,
};
use aos_proto_types::direct_upload::DirectUploadCapabilities;

use super::super::HubClient;
use super::{DirectUploadCoordinator, checkpoint_namespace};

/// Explicit local custody options shared by publication, cache and OCI clients.
#[derive(Clone, Debug, Default)]
pub struct DirectUploadOptions {
    /// Optional exact existing or new private SQLite retry journal pathname.
    pub journal: Option<PathBuf>,
    /// Optional closed provider origin/CIDR/public-CA operator policy pathname.
    pub provider_policy: Option<PathBuf>,
    /// Selects a new journal file while preserving unresolved older runs.
    pub new_run: bool,
    /// Optional smaller aggregate provider request count, from1 through32.
    pub maximum_parallel_parts: Option<usize>,
    /// Aggregate direct streamed bytes per second; zero is unlimited.
    pub bytes_per_second: u64,
    /// Original renewable credential provider; absent means fixed JWT custody.
    pub authentication: Option<std::sync::Arc<dyn super::DirectHubAuthentication>>,
    /// Shared value-free client observations, including renewals and replays.
    pub metrics: std::sync::Arc<aos_net::direct_upload::DirectTransferMetrics>,
}

impl DirectUploadOptions {
    /// Opens the exact authenticated owner with durable before-effect custody.
    ///
    /// Without an explicit journal, state lives under XDG_STATE_HOME or the
    /// user's HOME/.local/state. Existing unsafe directories are refused rather
    /// than chmodded. New-run suffixes affect local operation identity only;
    /// they never replace a server control effect or make unknown work safe.
    ///
    /// # Errors
    /// Refuses missing/relative state roots, unsafe file custody, expired
    /// discovery, invalid operator policy or an existing concurrent owner.
    pub async fn open(
        &self,
        hub: &HubClient,
        capabilities: DirectUploadCapabilities,
    ) -> Result<DirectUploadCoordinator, DirectClientError> {
        let namespace = checkpoint_namespace(hub, &capabilities)?;
        let mut journal = match &self.journal {
            Some(path) => path.clone(),
            None => state_directory()?.join(format!("{namespace}.sqlite")),
        };
        if self.new_run {
            let parent = journal.parent().ok_or(DirectClientError::Checkpoint)?;
            let name = journal
                .file_name()
                .and_then(|value| value.to_str())
                .filter(|value| !value.is_empty() && value.len() <= 90)
                .ok_or(DirectClientError::Checkpoint)?;
            let nonce = hex::encode(rand::random::<[u8; 16]>());
            journal = parent.join(format!("{name}.{nonce}"));
        }
        let parent = journal.parent().ok_or(DirectClientError::Checkpoint)?;
        ensure_private_checkpoint_directory(parent)?;
        let policy = self.provider_policy.clone();
        let mut provider = tokio::task::spawn_blocking(move || match policy {
            Some(path) => {
                ProviderOptions::from_policy_file(&path).map_err(|_| DirectClientError::Invalid)
            }
            None => Ok(ProviderOptions::default()),
        })
        .await
        .map_err(|_| DirectClientError::Checkpoint)??;
        provider.maximum_parallel_parts = self.maximum_parallel_parts.unwrap_or(32);
        provider.bytes_per_second = self.bytes_per_second;
        DirectUploadCoordinator::open_with_metrics(
            hub,
            capabilities,
            &journal,
            provider,
            self.authentication.clone(),
            self.metrics.clone(),
        )
        .await
    }
}

pub(super) fn state_directory() -> Result<PathBuf, DirectClientError> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(std::env::var_os("HOME").ok_or(DirectClientError::Checkpoint)?)
            .join(".local/state"),
    };
    if !base.is_absolute() {
        return Err(DirectClientError::Checkpoint);
    }
    Ok(base.join("aos/direct-uploads"))
}

impl DirectUploadOptions {
    /// Opens before-effect logical publication custody without provider authority.
    ///
    /// This distinct journal commits the original canonical Hub, explicit
    /// registry selector and generation before a publication exists. Its header
    /// pins the genuinely authenticated actor/deployment and registry incarnation.
    /// The later direct object journal independently reconciles full capabilities.
    /// It contains bounded hashes/progress and a private Native manifest lease,
    /// never provider grants or file contents.
    ///
    /// # Errors
    /// Refuses malformed scope, unsafe local custody or an existing concurrent run.
    pub async fn publication_journal(
        &self,
        hub: &HubClient,
        registry: &str,
        generation: &str,
    ) -> Result<aos_net::direct_upload::SqliteDirectCheckpoints, DirectClientError> {
        use sha2::{Digest as _, Sha256};
        if !aos_proto_types::direct_upload::valid_direct_identity(registry)
            || !aos_proto_types::direct_upload::valid_direct_digest(generation)
        {
            return Err(DirectClientError::Invalid);
        }
        let _ = super::DirectHubControl::new(hub)?;
        let mut digest = Sha256::new();
        digest.update(b"aos.publication.metadata-admission.v1\0");
        for field in [
            hub.base.as_bytes(),
            registry.as_bytes(),
            generation.as_bytes(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        let namespace = hex::encode(digest.finalize());
        let mut journal = match &self.journal {
            Some(path) => {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(DirectClientError::Checkpoint)?;
                path.with_file_name(format!("{name}.admission"))
            }
            None => state_directory()?.join(format!("admission-{namespace}.sqlite")),
        };
        if self.new_run {
            let name = journal
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| name.len() <= 90)
                .ok_or(DirectClientError::Checkpoint)?;
            journal = journal.with_file_name(format!(
                "{name}.{}",
                hex::encode(rand::random::<[u8; 16]>())
            ));
        }
        ensure_private_checkpoint_directory(
            journal.parent().ok_or(DirectClientError::Checkpoint)?,
        )?;
        let create = match std::fs::symlink_metadata(&journal) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => return Err(DirectClientError::Checkpoint),
        };
        aos_net::direct_upload::SqliteDirectCheckpoints::open(&journal, &namespace, create).await
    }
}
