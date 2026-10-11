//! Explicit registry-owner publication staging and the cross-destination barrier.
//!
//! Selected Hub origins use metadata admission and direct provider staging. All
//! objects stage before final completion; Native derives their actual dependency
//! graph. Unrelated destinations retain the existing phase-major transport.

use std::io::Read as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_cache::AuthOptions;
use aos_net::direct_upload::SourceWaveBudget;
use aos_proto_types::direct_upload::*;
use aos_proto_types::{BeginRegistryPublicationRequest, RegistryPublicationObjectInput};
use aos_remote::{DirectStagePath, DirectUploadCoordinator, DirectUploadOptions, HubClient};
use sha2::{Digest as _, Sha256};

use super::{StaticOriginFile, VisibilityBarrier};

pub(super) struct HubPublication {
    hub: HubClient,
    prepared: aos_remote::PreparedDirectPublication,
    coordinator: DirectUploadCoordinator,
    options: DirectUploadOptions,
    staged: bool,
}

#[async_trait::async_trait]
impl VisibilityBarrier for HubPublication {
    async fn finish(&self) -> Result<()> {
        if self.staged {
            self.coordinator.finish(Duration::from_secs(3600)).await?;
        }
        aos_remote::commit_direct_publication(&self.hub, &self.prepared, &self.options).await?;
        eprintln!(
            "Direct upload client: {}",
            self.coordinator.diagnostic_summary()
        );
        Ok(())
    }
}

/// Admits and stages an explicitly selected Hub destination without visibility.
pub(super) async fn stage_if_selected(
    destination: &str,
    files: &[StaticOriginFile],
    auth: &AuthOptions,
) -> Result<Option<HubPublication>> {
    let selected = match (&auth.hub_origin, &auth.hub_registry) {
        (None, None) => return Ok(None),
        (Some(origin), Some(registry)) if !registry.is_empty() => (origin, registry),
        _ => anyhow::bail!("Hub registry uploads require both --hub-origin and --hub-registry"),
    };
    let origin = metadata_origin(selected.0)?;
    let destination = url::Url::parse(destination).context("invalid static destination")?;
    if !matches!(destination.scheme(), "http" | "https")
        || destination.origin().ascii_serialization() != origin
    {
        return Ok(None);
    }

    let inventory_files = files.to_vec();
    let registry = selected.1.clone();
    let request = tokio::task::spawn_blocking(move || inventory(&inventory_files, &registry))
        .await
        .context("static inventory worker failed")??;

    let mut options = auth.direct_upload.clone();
    if let Some(secret) = &auth.token {
        options.authentication = Some(Arc::new(aos_remote::DirectProvisioningAuthentication::new(
            &origin,
            secret.clone(),
        )?));
    }
    let hub = authenticate(&origin, auth, &options).await?;
    let discovery = aos_remote::discover_publication_transport(&hub, &options).await?;
    anyhow::ensure!(
        discovery.transfer_mode() == DirectAdvertisedTransferMode::DirectRequired,
        "explicit Hub publication destination does not advertise direct transport"
    );
    let prepared =
        aos_remote::prepare_direct_publication(&hub, &request, &options, &discovery).await?;
    let publication = &prepared.publication;
    let coordinator = prepared.open_coordinator(&hub, &options).await?;

    let inputs: std::collections::BTreeMap<_, _> = request
        .objects
        .iter()
        .map(|input| (input.path.as_str(), input))
        .collect();
    let sources: std::collections::BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.relative_path.as_str(), &file.source))
        .collect();
    anyhow::ensure!(
        publication.objects.len() == inputs.len(),
        "Hub changed the static inventory count"
    );
    let mut seen_paths = std::collections::BTreeSet::new();
    let mut seen_ids = std::collections::BTreeSet::new();
    let mut wave = Vec::new();
    let mut staged = false;
    let mut budget = SourceWaveBudget::default();
    for object in &publication.objects {
        let input = inputs
            .get(object.path.as_str())
            .context("Hub introduced a static inventory path")?;
        anyhow::ensure!(
            object.object_id > 0
                && seen_paths.insert(object.path.as_str())
                && seen_ids.insert(object.object_id)
                && object.sha256 == input.sha256
                && object.byte_size == input.byte_size
                && object.kind == input.kind
                && object.media_type == input.media_type,
            "Hub changed the exact static inventory"
        );
        if object.verified {
            continue;
        }
        let byte_size = u64::try_from(object.byte_size)?;
        if !budget.reserve(byte_size, coordinator.part_size())? {
            coordinator.stage_paths(std::mem::take(&mut wave)).await?;
            budget = SourceWaveBudget::default();
            anyhow::ensure!(
                budget.reserve(byte_size, coordinator.part_size())?,
                "static source budget refused an empty wave"
            );
            staged = true;
        }
        wave.push(DirectStagePath {
            source: sources
                .get(object.path.as_str())
                .context("missing static source")?
                .to_path_buf(),
            expected_sha256: Some(object.sha256.clone()),
            target: DirectUploadTarget::PublicationObject {
                publication_id: publication.publication_id.clone(),
                surface_object_id: WireInteger::new(u64::try_from(object.object_id)?),
                path: object.path.clone(),
            },
            phase: if object.kind == "immutable" {
                DirectDependencyPhase::Content
            } else {
                DirectDependencyPhase::Visibility
            },
        });
    }
    if !wave.is_empty() {
        coordinator.stage_paths(wave).await?;
        staged = true;
    }
    Ok(Some(HubPublication {
        hub,
        prepared,
        coordinator,
        options,
        staged,
    }))
}

fn metadata_origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value).context("invalid explicit Hub origin")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "Hub origin must be a bare HTTP(S) origin"
    );
    Ok(url.origin().ascii_serialization())
}

async fn authenticate(
    origin: &str,
    auth: &AuthOptions,
    options: &DirectUploadOptions,
) -> Result<HubClient> {
    if let Some(provider) = &options.authentication {
        return Ok(provider.authenticate(origin).await?);
    }
    let token = auth
        .headers
        .iter()
        .find_map(|header| {
            let (name, value) = header.split_once(':')?;
            if !name.trim().eq_ignore_ascii_case("authorization") {
                return None;
            }
            value.trim().strip_prefix("Bearer ")
        })
        .context("Hub publication upload needs a provisioning token or explicit bearer")?;
    HubClient::connect_with_token(origin, token)
}

fn inventory(
    files: &[StaticOriginFile],
    registry: &str,
) -> Result<BeginRegistryPublicationRequest> {
    anyhow::ensure!(
        !files.is_empty() && files.len() <= 50_000,
        "static inventory exceeds publication limits"
    );
    let mut objects = Vec::with_capacity(files.len());
    let mut refs = None;
    let mut head = None;
    for source in files {
        let mut file = aos_net::direct_upload::open_regular_source_file(&source.source)
            .context("opening static inventory source")?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() <= MAX_DIRECT_OBJECT_BYTES,
            "static inventory source is not an admitted bounded regular file"
        );
        let mut hash = Sha256::new();
        let mut remaining = metadata.len();
        let mut buffer = [0_u8; 64 * 1024];
        let capture_bound = match source.relative_path.as_str() {
            "info/refs" => Some(4 * 1024 * 1024),
            "HEAD" => Some(4096),
            _ => None,
        };
        if let Some(bound) = capture_bound {
            anyhow::ensure!(
                metadata.len() <= bound,
                "static refs/HEAD exceeds its metadata bound"
            );
        }
        let mut captured = Vec::new();
        while remaining != 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            if capture_bound.is_some() {
                captured.extend_from_slice(&buffer[..count]);
            }
            remaining -= count as u64;
        }
        anyhow::ensure!(
            file.read(&mut buffer[..1])? == 0,
            "static inventory source grew during hashing"
        );
        let sha = hex::encode(hash.finalize());
        anyhow::ensure!(
            source
                .sha256
                .as_ref()
                .is_none_or(|expected| expected == &sha)
                && source
                    .byte_size
                    .is_none_or(|expected| expected == metadata.len()),
            "static source changed its retained digest/size"
        );
        match source.relative_path.as_str() {
            "info/refs" => refs = Some(captured),
            "HEAD" => head = Some(captured),
            _ => {}
        }
        objects.push(RegistryPublicationObjectInput {
            path: source.relative_path.clone(),
            sha256: sha,
            byte_size: i64::try_from(metadata.len())?,
            kind: if crate::registry::surface_keymap::cache_control(&source.relative_path)
                == crate::registry::surface_keymap::MUTABLE_CACHE_CONTROL
            {
                "mutable_pointer"
            } else {
                "immutable"
            }
            .into(),
            media_type: source.content_type.into(),
        });
    }
    let refs = refs.context("static Hub publication requires info/refs")?;
    let head = head.context("static Hub publication requires HEAD")?;
    let head = std::str::from_utf8(&head)?.trim();
    let commit = if let Some(reference) = head.strip_prefix("ref: ") {
        std::str::from_utf8(&refs)?
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .find_map(|(oid, name)| (name == reference).then_some(oid))
            .context("static HEAD reference is absent from frozen info/refs")?
    } else {
        head
    };
    anyhow::ensure!(
        valid_direct_digest(commit),
        "static HEAD does not resolve to a SHA-256 commit"
    );
    let generation = aos_remote::publication_inventory_digest(&objects)?;
    Ok(BeginRegistryPublicationRequest {
        registry: registry.into(),
        generation,
        refs_digest: hex::encode(Sha256::digest(&refs)),
        default_commit: commit.into(),
        parent_publication_id: String::new(),
        objects,
    })
}

#[cfg(test)]
mod tests;
