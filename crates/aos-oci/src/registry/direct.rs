//! Readiness-gated OCI direct staging with original Distribution authentication.
//!
//! The existing bodyless allocator retains a logical Native upload owner. File
//! ranges travel to reviewed provider origins only; Native receives controls.
//! Every blob stages before final completion and manifest/tag publication.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_net::direct_upload::{AdmittedSource, DirectClientError, SourceWaveBudget};
use aos_oci_types::Descriptor;
use aos_proto_types::direct_upload::*;
use aos_remote::{DirectHubControl, DirectStageFile, DirectUploadCoordinator, HubClient};
use bytes::Bytes;
use reqwest::header::HeaderMap;
use reqwest::{Method, StatusCode};
use tokio_util::sync::CancellationToken;

use super::{PushOptions, RegistryClient, check_response, ensure_not_cancelled, repository_path};
use crate::layout::open_verified_blob;
use crate::reference::RegistryReference;

impl RegistryClient {
    pub(super) fn observe_direct_readiness(&self, response: &reqwest::Response) -> Result<()> {
        let readiness = response.headers().get_all("aos-direct-upload");
        if readiness.iter().next().is_none() {
            return Ok(());
        }
        anyhow::ensure!(
            readiness.iter().count() == 1
                && readiness.iter().next().is_some_and(|value| value == "1"),
            "OCI direct readiness header is invalid"
        );
        let registry = response.headers().get_all("aos-registry-id");
        anyhow::ensure!(
            registry.iter().count() == 1,
            "OCI direct readiness has no exact registry selector"
        );
        let registry = registry
            .iter()
            .next()
            .context("OCI direct registry selector is absent")?
            .to_str()
            .context("OCI direct registry selector is not ASCII")?;
        anyhow::ensure!(
            valid_direct_identity(registry),
            "OCI direct registry selector is invalid"
        );
        let mut original = self
            .inner
            .direct_registry
            .lock()
            .map_err(|_| anyhow::anyhow!("OCI direct registry custody failed"))?;
        if let Some(original) = original.as_ref() {
            anyhow::ensure!(original == registry, "OCI direct registry selector changed");
        } else {
            *original = Some(registry.to_owned());
        }
        Ok(())
    }
}

pub(super) async fn upload_blobs_if_required(
    client: &RegistryClient,
    reference: &RegistryReference,
    descriptors: &[Descriptor],
    scope: &str,
    options: &PushOptions,
) -> Result<Option<DirectOciAuthority>> {
    let Some(first) = descriptors.first() else {
        return Ok(None);
    };
    ensure_not_cancelled(&options.cancellation)?;
    let probe = client.url(&format!(
        "v2/{}/blobs/{}",
        repository_path(reference),
        first.digest
    ))?;
    let response = client
        .send(
            Method::HEAD,
            probe.clone(),
            scope,
            &HeaderMap::new(),
            None,
            &options.cancellation,
        )
        .await?;
    check_response(
        &response,
        &[StatusCode::OK, StatusCode::NOT_FOUND],
        "discovering OCI direct readiness",
    )?;
    let registry = client
        .inner
        .direct_registry
        .lock()
        .map_err(|_| anyhow::anyhow!("OCI direct registry custody failed"))?
        .clone();
    let Some(registry) = registry else {
        return Ok(None);
    };
    let authentication = Arc::new(OciAuthentication {
        client: client.clone(),
        scope: scope.to_owned(),
        probe,
        cancellation: options.cancellation.clone(),
    });
    let origin = client.inner.origin.as_str();
    let (hub, initial_token) = authentication.owned_credentials(origin).await?;
    let capabilities = DirectHubControl::new(&hub)?
        .with_metrics(client.direct_options.metrics.clone())
        .capabilities(&DirectCapabilitiesTarget::OciRepository {
            registry,
            repository: reference.repository().to_string(),
        })
        .await?;
    // A positive readiness discriminator can never authorize a legacy body
    // after failed or contradictory discovery, even on an old checkpoint.
    anyhow::ensure!(
        capabilities.transfer_mode == DirectAdvertisedTransferMode::DirectRequired,
        "OCI direct readiness contradicts authenticated transfer mode"
    );
    let mut direct_options = client.direct_options.clone();
    direct_options.authentication = Some(authentication.clone());
    let allocation_authority = DirectOciAuthority {
        authentication,
        capabilities: capabilities.clone(),
        proved: tokio::sync::Mutex::new(ProvedAllocationToken {
            token: initial_token,
            valid_until: capabilities.valid_until.get(),
            checked: tokio::time::Instant::now(),
        }),
    };
    let coordinator = direct_options.open(&hub, capabilities).await?;

    let mut seen = std::collections::BTreeSet::new();
    let mut wave = Vec::new();
    let mut staged = false;
    let mut budget = SourceWaveBudget::default();
    for descriptor in descriptors {
        ensure_not_cancelled(&options.cancellation)?;
        if !seen.insert(descriptor.digest) {
            continue;
        }
        let allocation = allocate(
            client,
            reference,
            descriptor,
            scope,
            &coordinator,
            &allocation_authority,
            &options.cancellation,
        )
        .await?;
        let Some(upload_id) = allocation else {
            continue;
        };
        if !budget.reserve(descriptor.size, coordinator.part_size())? {
            stage_wave(
                &coordinator,
                std::mem::take(&mut wave),
                &options.cancellation,
            )
            .await?;
            staged = true;
            budget = SourceWaveBudget::default();
            anyhow::ensure!(
                budget.reserve(descriptor.size, coordinator.part_size())?,
                "OCI source budget refused an empty wave"
            );
        }
        let file = open_verified_blob(&options.source, descriptor)?;
        let source = AdmittedSource::admit(
            file,
            descriptor.size,
            &descriptor.digest.encoded(),
            coordinator.part_size(),
        )
        .await?;
        wave.push(DirectStageFile {
            target: DirectUploadTarget::OciBlob { upload_id },
            source,
            phase: DirectDependencyPhase::Content,
        });
    }
    if !wave.is_empty() {
        stage_wave(&coordinator, wave, &options.cancellation).await?;
        staged = true;
    }
    if staged {
        tokio::select! {
            result = coordinator.finish(Duration::from_secs(3600)) => result?,
            () = options.cancellation.cancelled() => anyhow::bail!("OCI direct transfer cancelled; original journal retained"),
        }
        eprintln!("Direct upload client: {}", coordinator.diagnostic_summary());
    }
    Ok(Some(allocation_authority))
}

async fn allocate(
    client: &RegistryClient,
    reference: &RegistryReference,
    descriptor: &Descriptor,
    _scope: &str,
    coordinator: &DirectUploadCoordinator,
    authority: &DirectOciAuthority,
    cancellation: &CancellationToken,
) -> Result<Option<String>> {
    let original = coordinator
        .prepare_oci_allocation(&descriptor.digest.encoded(), descriptor.size)
        .await?;
    if let Some(upload_id) = original.upload_id.clone() {
        return Ok(Some(upload_id));
    }
    let mut url = client.url(&format!("v2/{}/blobs/uploads/", repository_path(reference)))?;
    url.query_pairs_mut()
        .append_pair("digest", &descriptor.digest.to_string())
        .append_pair("size", &descriptor.size.to_string())
        .append_pair("aos_operation_id", &original.operation_id);
    // Unknown lost replies replay this exact persisted operation/URI. Native
    // resolves the original logical owner; the client never chooses a new one.
    let (response, token) = authority.post(client, url, cancellation).await?;
    if response.status() == StatusCode::CREATED {
        // Reuse evidence must use the same proved actor as allocation. A denied
        // HEAD fails closed; it cannot substitute a shared cached credential.
        let head = client
            .inner
            .http
            .head(client.url(&format!(
                "v2/{}/blobs/{}",
                repository_path(reference),
                descriptor.digest
            ))?)
            .bearer_auth(token.as_str());
        let head = tokio::select! {
            () = cancellation.cancelled() => anyhow::bail!("OCI direct transfer cancelled"),
            response = head.send() => response.map_err(|_| anyhow::anyhow!("OCI direct reuse request failed"))?,
        };
        check_response(
            &head,
            &[StatusCode::OK],
            "verifying an already-published direct blob",
        )?;
        anyhow::ensure!(
            head.headers().contains_key("content-length")
                && head.headers().contains_key("docker-content-digest"),
            "direct blob reuse lacks exact size/digest evidence"
        );
        super::push::validate_remote_blob_head(&head, descriptor)?;
        return Ok(None);
    }
    check_response(
        &response,
        &[StatusCode::ACCEPTED],
        "allocating OCI direct logical upload",
    )?;
    let values = response.headers().get_all("docker-upload-uuid");
    anyhow::ensure!(
        values.iter().count() == 1,
        "OCI direct logical allocation has no exact upload identity"
    );
    let upload_id = values
        .iter()
        .next()
        .context("OCI direct upload identity is absent")?
        .to_str()
        .context("OCI direct upload identity is not ASCII")?;
    let retained = coordinator
        .retain_oci_allocation(&original, upload_id)
        .await?;
    Ok(retained.upload_id)
}

struct OciAuthentication {
    client: RegistryClient,
    scope: String,
    probe: url::Url,
    cancellation: CancellationToken,
}

impl std::fmt::Debug for OciAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OciAuthentication([original realm credentials])")
    }
}

impl OciAuthentication {
    async fn owned_credentials(
        &self,
        canonical_hub: &str,
    ) -> Result<(HubClient, zeroize::Zeroizing<String>), DirectClientError> {
        if canonical_hub != self.client.inner.origin.as_str() {
            return Err(DirectClientError::Invalid);
        }
        let response = self
            .client
            .send(
                Method::HEAD,
                self.probe.clone(),
                &self.scope,
                &HeaderMap::new(),
                None,
                &self.cancellation,
            )
            .await
            .map_err(|_| DirectClientError::Denied)?;
        if !matches!(response.status(), StatusCode::OK | StatusCode::NOT_FOUND) {
            return Err(DirectClientError::Denied);
        }
        let token = self
            .client
            .token_for_scope(&self.scope)
            .map_err(|_| DirectClientError::Denied)?
            .ok_or(DirectClientError::Denied)?;
        // Discovery proves this exact owned token after the shared-cache read.
        // No later control dispatch may read the shared cache again.
        let hub = HubClient::connect_with_token(canonical_hub, &token)
            .map_err(|_| DirectClientError::Invalid)?;
        Ok((hub, token))
    }
}

#[async_trait::async_trait]
impl aos_remote::DirectHubAuthentication for OciAuthentication {
    async fn authenticate(&self, canonical_hub: &str) -> Result<HubClient, DirectClientError> {
        self.owned_credentials(canonical_hub)
            .await
            .map(|(hub, _)| hub)
    }
}

pub(super) struct DirectOciAuthority {
    authentication: Arc<OciAuthentication>,
    capabilities: DirectUploadCapabilities,
    proved: tokio::sync::Mutex<ProvedAllocationToken>,
}

struct ProvedAllocationToken {
    token: zeroize::Zeroizing<String>,
    valid_until: u64,
    checked: tokio::time::Instant,
}

impl DirectOciAuthority {
    async fn proved_token(
        &self,
        client: &RegistryClient,
        force: bool,
    ) -> Result<zeroize::Zeroizing<String>> {
        let mut original = self.proved.lock().await;
        let cached = client.token_for_scope(&self.authentication.scope)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| anyhow::anyhow!("OCI direct clock failed"))?
            .as_secs();
        if force
            || cached.as_ref().map(|token| token.as_str()) != Some(original.token.as_str())
            || original.checked.elapsed() >= Duration::from_secs(60)
            || original.valid_until.saturating_sub(now) <= 30
        {
            let (hub, token) = self
                .authentication
                .owned_credentials(client.inner.origin.as_str())
                .await?;
            let proved = DirectHubControl::new(&hub)?
                .with_metrics(client.direct_options.metrics.clone())
                .capabilities(&self.capabilities.target)
                .await?;
            let mut expected = self.capabilities.clone();
            expected.valid_until = proved.valid_until;
            anyhow::ensure!(
                expected == proved,
                "OCI direct actor or provider authority changed"
            );
            original.token = token;
            original.valid_until = proved.valid_until.get();
            original.checked = tokio::time::Instant::now();
        }
        // Only clone an authenticated owned token. A later shared refresh is
        // unrelated to this immutable request snapshot and cannot replace it.
        Ok(original.token.clone())
    }

    pub(super) async fn put_manifest(
        &self,
        client: &RegistryClient,
        url: url::Url,
        headers: &HeaderMap,
        bytes: Bytes,
        cancellation: &CancellationToken,
    ) -> Result<reqwest::Response> {
        anyhow::ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "OCI manifest exceeds the Worker document limit"
        );
        anyhow::ensure!(
            super::same_authority(&url, &client.inner.origin)
                && client.inner.origin == self.authentication.client.inner.origin,
            "OCI direct manifest origin changed"
        );
        let DirectCapabilitiesTarget::OciRepository { repository, .. } = &self.capabilities.target
        else {
            anyhow::bail!("OCI direct manifest authority is not a repository");
        };
        let prefix = format!("/v2/{repository}/manifests/");
        anyhow::ensure!(
            url.path()
                .strip_prefix(&prefix)
                .is_some_and(|reference| !reference.is_empty() && !reference.contains('/'))
                && url.query().is_none()
                && url.fragment().is_none(),
            "OCI direct manifest repository or reference changed"
        );
        for attempt in 0..2 {
            let token = self.proved_token(client, attempt != 0).await?;
            // The exact document/reference is retained across authentication
            // retries. No shared scoped token can replace this proved actor.
            let request = client
                .inner
                .http
                .put(url.clone())
                .headers(headers.clone())
                .bearer_auth(token.as_str())
                .body(bytes.clone());
            let response = tokio::select! {
                () = cancellation.cancelled() => anyhow::bail!("OCI direct manifest cancelled"),
                response = request.send() => response.map_err(|_| anyhow::anyhow!("OCI direct manifest request failed; original document retained"))?,
            };
            client.observe_direct_readiness(&response)?;
            if attempt == 0
                && matches!(
                    response.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                )
            {
                continue;
            }
            return Ok(response);
        }
        anyhow::bail!("OCI direct manifest authorization failed")
    }

    async fn post(
        &self,
        client: &RegistryClient,
        url: url::Url,
        cancellation: &CancellationToken,
    ) -> Result<(reqwest::Response, zeroize::Zeroizing<String>)> {
        anyhow::ensure!(
            super::same_authority(&url, &client.inner.origin)
                && client.inner.origin == self.authentication.client.inner.origin,
            "OCI direct allocation origin changed"
        );
        for attempt in 0..2 {
            let token = self.proved_token(client, attempt != 0).await?;

            // URI/op/digest/size are the original retained allocation. A shared
            // scoped-token refresh cannot replace the token after this proof.
            let request = client
                .inner
                .http
                .post(url.clone())
                .bearer_auth(token.as_str())
                .header(reqwest::header::CONTENT_LENGTH, "0")
                .body(Bytes::new());
            let response = tokio::select! {
                () = cancellation.cancelled() => anyhow::bail!("OCI direct transfer cancelled"),
                response = request.send() => response.map_err(|_| anyhow::anyhow!("OCI direct logical allocation failed; original operation retained"))?,
            };
            client.observe_direct_readiness(&response)?;
            if attempt == 0
                && matches!(
                    response.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                )
            {
                continue;
            }
            return Ok((response, token));
        }
        anyhow::bail!("OCI direct allocation authorization failed")
    }
}

#[cfg(test)]
mod tests;

async fn stage_wave(
    coordinator: &DirectUploadCoordinator,
    wave: Vec<DirectStageFile>,
    cancellation: &CancellationToken,
) -> Result<()> {
    tokio::select! {
        result = coordinator.stage(wave) => result.map(|_| ()).map_err(Into::into),
        () = cancellation.cancelled() => anyhow::bail!("OCI direct transfer cancelled; original journal retained"),
    }
}
