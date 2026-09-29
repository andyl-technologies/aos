//! Connects publication inventory to private direct staging and final barriers.
//!
//! Every independent object, including mutable narinfo leaves, stages before
//! final completion. Native derives the authenticated dependency graph; the
//! client never treats path shape or a parallel HTTP write as leaf authority.

use std::os::fd::OwnedFd;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_net::direct_upload::{AdmittedSource, SourceWaveBudget};
use aos_remote::hub_types::direct_upload::{
    DirectDependencyPhase, DirectUploadTarget, WireInteger,
};
use aos_remote::{DirectStageFile, DirectUploadOptions, HubClient, hub_types};

use super::inventory::open_publication_object;
use crate::cli::HubAccessArgs;

pub(super) async fn upload_if_required(
    options: &DirectUploadOptions,
    hub: &HubClient,
    prepared: &aos_remote::PreparedDirectPublication,
    root: &OwnedFd,
    declared: &[hub_types::RegistryPublicationObjectInput],
    objects: &[&hub_types::RegistryPublicationObject],
) -> Result<bool> {
    let publication_id = &prepared.publication.publication_id;
    let coordinator = prepared.open_coordinator(hub, options).await?;

    let declared: std::collections::BTreeMap<_, _> = declared
        .iter()
        .map(|input| (input.path.as_str(), input))
        .collect();
    anyhow::ensure!(
        declared.len() == objects.len(),
        "publication direct inventory count differs"
    );
    let mut seen_paths = std::collections::BTreeSet::new();
    let mut seen_ids = std::collections::BTreeSet::new();
    for object in objects {
        let input = declared
            .get(object.path.as_str())
            .copied()
            .context("publication direct response introduced a path")?;
        anyhow::ensure!(
            seen_paths.insert(object.path.as_str())
                && seen_ids.insert(object.object_id)
                && object.object_id > 0
                && input.sha256 == object.sha256
                && input.byte_size == object.byte_size
                && input.kind == object.kind
                && input.media_type == object.media_type,
            "publication direct response changed the exact declared object set"
        );
    }

    let mut pending = objects
        .iter()
        .copied()
        .filter(|object| !object.verified)
        .peekable();
    let mut staged = false;
    while pending.peek().is_some() {
        let mut files = Vec::new();
        let mut budget = SourceWaveBudget::default();
        while let Some(object) = pending.peek().copied() {
            let byte_size = u64::try_from(object.byte_size)
                .context("publication direct object size is invalid")?;
            // Large descriptors do not retain whole-file body buffers. Reserve
            // the actual fixed-width part catalogue and descriptor count.
            if !budget.reserve(byte_size, coordinator.part_size())? {
                break;
            }
            let input = declared
                .get(object.path.as_str())
                .copied()
                .context("publication response introduced an undeclared direct object")?;
            anyhow::ensure!(
                input.sha256 == object.sha256
                    && input.byte_size == object.byte_size
                    && input.kind == object.kind
                    && input.media_type == object.media_type,
                "publication response changed a declared direct object"
            );
            let path = input.path.clone();
            let source_root = root.try_clone()?;
            let file =
                tokio::task::spawn_blocking(move || open_publication_object(&source_root, &path))
                    .await
                    .context("publication source worker failed")??;
            let source =
                AdmittedSource::admit(file, byte_size, &object.sha256, coordinator.part_size())
                    .await?;
            files.push(DirectStageFile {
                target: DirectUploadTarget::PublicationObject {
                    publication_id: publication_id.to_owned(),
                    surface_object_id: WireInteger::new(
                        u64::try_from(object.object_id)
                            .context("publication direct object ID is invalid")?,
                    ),
                    path: object.path.clone(),
                },
                source,
                phase: if object.kind == "immutable" {
                    DirectDependencyPhase::Content
                } else {
                    DirectDependencyPhase::Visibility
                },
            });
            pending.next();
        }
        coordinator.stage(files).await?;
        staged = true;
    }
    if staged {
        coordinator.finish(Duration::from_secs(3600)).await?;
        eprintln!("Direct upload client: {}", coordinator.diagnostic_summary());
    }
    Ok(true)
}

struct PublicationAuthentication(HubAccessArgs);

impl std::fmt::Debug for PublicationAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublicationAuthentication([redacted])")
    }
}

#[async_trait::async_trait]
impl aos_remote::DirectHubAuthentication for PublicationAuthentication {
    async fn authenticate(
        &self,
        canonical_hub: &str,
    ) -> Result<HubClient, aos_net::direct_upload::DirectClientError> {
        crate::commands::hub::client::hub_client(canonical_hub, self.0.token.as_deref())
            .await
            .map_err(|_| aos_net::direct_upload::DirectClientError::Denied)
    }
}

pub(super) fn options(access: &HubAccessArgs) -> DirectUploadOptions {
    DirectUploadOptions {
        authentication: Some(std::sync::Arc::new(PublicationAuthentication(
            access.clone(),
        ))),
        journal: access.direct_upload_journal.clone(),
        provider_policy: access.direct_provider_policy.clone(),
        new_run: access.new_direct_upload_run,
        ..DirectUploadOptions::default()
    }
}
