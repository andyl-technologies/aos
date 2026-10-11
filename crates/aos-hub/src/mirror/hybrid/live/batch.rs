//! Fresh batched metadata under one retained SQL source and destination selection.
//!
//! Capability absence permits only the existing singleton read, with four bounded
//! concurrent controls. A failed batch is never silently retried as singleton work.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    db::{Database, RegistryRecord},
    hybrid_ingress::live::HybridLiveDeliveryTarget,
    storage_work::{
        live_metadata_batch::{self, LiveMetadataOutcome},
        StorageWorkOperation, StorageWorkOutcome,
    },
};
use base64::Engine as _;
use futures_util::{stream, FutureExt as _, StreamExt as _};

use super::super::selection::Selection;
use crate::storage_work::RemoteStorageWorkClient;

/// Retrieves ordered fresh metadata without per-object discovery or Native source reads.
///
/// # Errors
/// Refuses unsupported paths, any changed original selection, unknown capability,
/// malformed results or explicit per-source refusals before returning partial data.
pub(crate) async fn metadata(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry_id: i64,
    paths: &[String],
) -> Result<Vec<Option<Vec<u8>>>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let Some(source) = db.registry_mirror(registry_id).await? else {
        return Ok(vec![None; paths.len()]);
    };
    if source.mode != "pull_through" {
        return Ok(vec![None; paths.len()]);
    }
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("live registry disappeared")?;
    let selection = Selection::capture(db, work, &registry, source).await?;
    let batch_supported = work.supports_live_metadata_batch().await?;
    selection.validate_current(db, work, &registry).await?;

    let mut ordered = paths.to_vec();
    ordered.sort();
    ordered.dedup();
    let mut returned = std::collections::BTreeMap::new();
    for chunk in ordered.chunks(live_metadata_batch::MAX_TARGETS) {
        let targets: Vec<_> = chunk
            .iter()
            .map(|path| super::target_for(&selection, &registry, path))
            .collect();
        let observations =
            exchange(db, work, &registry, &selection, &targets, batch_supported).await?;
        for (path, bytes) in chunk.iter().zip(observations) {
            returned.insert(path.clone(), bytes);
        }
    }
    selection.validate_current(db, work, &registry).await?;
    paths
        .iter()
        .map(|path| {
            returned
                .get(path)
                .cloned()
                .context("live batch omitted a path")
        })
        .collect()
}

async fn exchange(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry: &RegistryRecord,
    selection: &Selection,
    targets: &[HybridLiveDeliveryTarget],
    batch_supported: bool,
) -> Result<Vec<Option<Vec<u8>>>> {
    // The same immutable selection surrounds every physical control and reply;
    // changed current SQL cannot relabel observations under a newly captured RV.
    selection.validate_current(db, work, registry).await?;
    let bytes = exchange_targets(
        work,
        &selection.placement,
        &selection.binding,
        targets,
        batch_supported,
        || selection.validate_current(db, work, registry),
    )
    .await?;
    selection.validate_current(db, work, registry).await?;
    Ok(bytes)
}

async fn exchange_targets<F, Fut>(
    work: &RemoteStorageWorkClient,
    placement: &aos_hub_core::db::SurfacePlacementRecord,
    binding: &aos_hub_core::db::BindingRecord,
    targets: &[HybridLiveDeliveryTarget],
    batch_supported: bool,
    current: F,
) -> Result<Vec<Option<Vec<u8>>>>
where
    F: Fn() -> Fut + Sync,
    Fut: std::future::Future<Output = Result<()>> + Send,
{
    live_metadata_batch::validate_selection(targets)?;
    if batch_supported {
        current().await?;
        let plan = work.plan_for_placement(
            placement,
            binding,
            StorageWorkOperation::InspectMirrorLiveMetadataBatch {
                targets: targets.to_vec(),
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = work.execute(&plan).await?;
        current().await?;
        let StorageWorkOutcome::MirrorLiveMetadataBatch { items } = result.outcome else {
            anyhow::bail!("live metadata batch result shape differs");
        };
        let mut returned = vec![None; targets.len()];
        let mut deferred = Vec::new();
        for (index, item) in items.into_iter().enumerate() {
            match item.outcome {
                LiveMetadataOutcome::Found { content_base64, .. } => {
                    returned[index] =
                        Some(base64::engine::general_purpose::STANDARD.decode(content_base64)?);
                }
                LiveMetadataOutcome::NotFound => {}
                LiveMetadataOutcome::Refused {
                    reason: live_metadata_batch::LiveMetadataRefusal::ResultBudget,
                } => {
                    deferred.push((index, &targets[index]));
                }
                LiveMetadataOutcome::Refused { reason } => {
                    anyhow::bail!("live metadata source refused: {reason:?}");
                }
            }
        }
        // Only explicit response-capacity refusal retries. Positive and absent
        // positions retain their observation; every retry uses the old selection.
        for (index, bytes) in singletons(work, placement, binding, deferred, &current).await? {
            returned[index] = bytes;
        }
        current().await?;
        return Ok(returned);
    }

    let deferred = targets.iter().enumerate().collect();
    let results = singletons(work, placement, binding, deferred, &current).await?;
    Ok(results.into_iter().map(|(_, bytes)| bytes).collect())
}

async fn singletons<F, Fut>(
    work: &RemoteStorageWorkClient,
    placement: &aos_hub_core::db::SurfacePlacementRecord,
    binding: &aos_hub_core::db::BindingRecord,
    deferred: Vec<(usize, &HybridLiveDeliveryTarget)>,
    current: &F,
) -> Result<Vec<(usize, Option<Vec<u8>>)>>
where
    F: Fn() -> Fut + Sync,
    Fut: std::future::Future<Output = Result<()>> + Send,
{
    let deferred: Vec<_> = deferred
        .into_iter()
        .map(|(index, target)| (index, target.clone()))
        .collect();
    let results = stream::iter(deferred.into_iter().map(|(index, target)| {
        async move {
            current().await?;
            let plan = work.plan_for_placement(
                placement,
                binding,
                StorageWorkOperation::InspectMirrorLiveMetadata {
                    target: target.clone(),
                },
                aos_hub_core::clock::now_unix_secs(),
            )?;
            let result = work.execute(&plan).await?;
            current().await?;
            let bytes = decode_singleton(&target, result.outcome)?;
            Ok((index, bytes))
        }
        .boxed()
    }))
    .buffer_unordered(live_metadata_batch::MAX_LEGACY_QUERIES)
    .collect::<Vec<Result<_>>>()
    .await;
    let mut results = results.into_iter().collect::<Result<Vec<_>>>()?;
    results.sort_by_key(|(index, _)| *index);
    Ok(results)
}

fn decode_singleton(
    target: &HybridLiveDeliveryTarget,
    outcome: StorageWorkOutcome,
) -> Result<Option<Vec<u8>>> {
    match outcome {
        StorageWorkOutcome::NotFound => Ok(None),
        StorageWorkOutcome::MirrorLiveMetadata {
            sha256,
            size,
            content_base64,
        } => {
            ensure!(
                content_base64.len() <= 175_000,
                "live metadata encoding exceeds bound"
            );
            let bytes = base64::engine::general_purpose::STANDARD.decode(content_base64)?;
            ensure!(
                bytes.len() as u64 == size
                    && size <= target.maximum_bytes
                    && aos_hub_core::hybrid_ingress::body_sha256(&bytes) == sha256,
                "live metadata body commitment differs"
            );
            Ok(Some(bytes))
        }
        _ => anyhow::bail!("live metadata result shape differs"),
    }
}

#[cfg(test)]
mod tests;
