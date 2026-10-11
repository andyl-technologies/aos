//! Authenticated Hub direct discovery and descriptor-backed cache staging.
//!
//! Generic HTTP stores and negotiated old standalone caches retain their original
//! transport. Positively identified Hub callers require closed discovery; a
//! bearer credential alone does not identify a server as a Hub.

use std::fs::File;
use std::io::{Read as _, Seek as _, Write as _};
use std::path::Path;
use std::sync::{Arc, atomic::Ordering};

use anyhow::{Context as _, Result};
use aos_net::direct_upload::{AdmittedSource, open_regular_source_file};
use aos_proto_types::direct_upload::*;
use aos_remote::{DirectHubControl, DirectStageFile, DirectUploadCoordinator, HubClient};
use sha2::{Digest as _, Sha256};

use super::HttpBackend;

impl HttpBackend {
    pub(super) async fn discover_direct(
        &self,
        jobs: usize,
        bytes_per_second: u64,
    ) -> Result<Option<Arc<DirectUploadCoordinator>>> {
        let value = self
            .direct
            .get_or_try_init(|| async {
                let header_token = self
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                    .and_then(|(_, value)| value.strip_prefix("Bearer "));
                let hub_identified = self.is_hub.load(Ordering::Relaxed);
                if !hub_identified {
                    return Ok(None);
                }
                // An explicit caller credential owns this workflow. A shared
                // origin cache must not choose a different actor before proof.
                let token = match header_token {
                    Some(token) => token.to_owned(),
                    None => match self.engine.auth().get(&self.origin) {
                        Some(aos_net::Credential::Bearer { token, .. }) => token,
                        _ => anyhow::bail!("direct cache upload needs an authenticated Hub bearer"),
                    },
                };
                let hub = HubClient::connect_with_token(&self.origin, &token)?;
                let mut options = self.direct_options.clone();
                let proof = aos_remote::discover_publication_transport(&hub, &options).await?;
                let hub = proof.authenticated_hub();
                if proof.transfer_mode() == DirectAdvertisedTransferMode::Legacy {
                    self.legacy_direct_bearer
                        .set(tokio::sync::Mutex::new(proof.legacy_bearer()?))
                        .map_err(|_| anyhow::anyhow!("legacy Hub credential custody conflicts"))?;
                    return Ok(None);
                }
                let capabilities = DirectHubControl::new(&hub)?
                    .with_metrics(options.metrics.clone())
                    .capabilities(&DirectCapabilitiesTarget::CacheDelivery {
                        delivery_url: self.base_url.clone(),
                    })
                    .await?;
                proof.validate_actor(&capabilities)?;
                anyhow::ensure!(
                    capabilities.transfer_mode == DirectAdvertisedTransferMode::DirectRequired,
                    "cache transfer policy changed after authenticated discovery"
                );
                options.maximum_parallel_parts = Some(jobs.clamp(1, 32));
                options.bytes_per_second = bytes_per_second;
                Ok::<_, anyhow::Error>(Some(Arc::new(options.open(&hub, capabilities).await?)))
            })
            .await?;
        Ok(value.clone())
    }

    pub(super) async fn stage_direct_bytes(
        &self,
        path: &str,
        bytes: &[u8],
        phase: DirectDependencyPhase,
    ) -> Result<bool> {
        let Some(coordinator) = self.discover_direct(32, 0).await? else {
            return Ok(false);
        };
        let mut file = tempfile::tempfile().context("creating direct metadata snapshot")?;
        file.write_all(bytes)?;
        file.rewind()?;
        let sha = hex::encode(Sha256::digest(bytes));
        stage_file(&coordinator, path, file, bytes.len() as u64, &sha, phase).await?;
        Ok(true)
    }

    pub(super) async fn stage_direct_file(
        &self,
        path: &str,
        source: &Path,
        expected_sha: Option<&str>,
    ) -> Result<bool> {
        let Some(coordinator) = self.discover_direct(32, 0).await? else {
            return Ok(false);
        };
        let source = source.to_owned();
        let expected = expected_sha.map(str::to_owned);
        let (file, size, sha) = tokio::task::spawn_blocking(move || {
            let mut file =
                open_regular_source_file(&source).context("opening direct static source")?;
            let metadata = file.metadata()?;
            anyhow::ensure!(
                metadata.is_file() && metadata.len() <= 16 * 1024 * 1024 * 1024,
                "direct static source is not an admitted bounded regular file"
            );
            let sha = match expected {
                Some(sha) => sha,
                None => {
                    let mut hash = Sha256::new();
                    let mut buffer = [0_u8; 64 * 1024];
                    let mut remaining = metadata.len();
                    while remaining != 0 {
                        let count = remaining.min(buffer.len() as u64) as usize;
                        file.read_exact(&mut buffer[..count])?;
                        hash.update(&buffer[..count]);
                        remaining -= count as u64;
                    }
                    hex::encode(hash.finalize())
                }
            };
            Ok::<_, anyhow::Error>((file, metadata.len(), sha))
        })
        .await
        .context("direct static admission worker failed")??;
        stage_file(
            &coordinator,
            path,
            file,
            size,
            &sha,
            DirectDependencyPhase::Visibility,
        )
        .await?;
        Ok(true)
    }
}

async fn stage_file(
    coordinator: &DirectUploadCoordinator,
    path: &str,
    file: File,
    size: u64,
    sha: &str,
    phase: DirectDependencyPhase,
) -> Result<()> {
    let DirectCapabilitiesTarget::Cache { cache_id } = coordinator.target() else {
        anyhow::bail!("direct cache discovery returned a different owner");
    };
    let source = AdmittedSource::admit(file, size, sha, coordinator.part_size()).await?;
    coordinator
        .stage(vec![DirectStageFile {
            target: DirectUploadTarget::CacheObject {
                cache_id: cache_id.clone(),
                path: path.to_owned(),
            },
            source,
            phase,
        }])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
