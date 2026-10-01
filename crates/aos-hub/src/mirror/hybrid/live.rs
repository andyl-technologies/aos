//! Current uncached upstream selections for public Worker delivery.
//!
//! This path records no mirror original, changes no catalogue and opens no body
//! at Native. It rechecks the complete SQL selection before issuing metadata.

use anyhow::{Context as _, Result};
use aos_hub_core::{db::Database, hybrid_ingress::live::HybridLiveDeliveryTarget};

use crate::storage_work::RemoteStorageWorkClient;
use base64::Engine as _;

pub(super) mod batch;

/// Selects current SQL pins without opening an upstream body at Native.
///
/// # Errors
/// Refuses unsupported source semantics or a changed registry, binding or placement.
pub(crate) async fn delivery(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry_id: i64,
    path: &str,
) -> Result<Option<HybridLiveDeliveryTarget>> {
    if !aos_hub_core::hybrid_ingress::live::live_path(path) {
        return Ok(None);
    }
    let Some(source) = db.registry_mirror(registry_id).await? else {
        return Ok(None);
    };
    if source.mode != "pull_through" {
        return Ok(None);
    }
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("mirror registry disappeared")?;
    let selected = super::selection::Selection::capture(db, work, &registry, source).await?;
    let target = target_for(&selected, &registry, path);
    target.validate()?;
    selected.validate_current(db, work, &registry).await?;
    Ok(Some(target))
}

fn target_for(
    selected: &super::selection::Selection,
    registry: &aos_hub_core::db::RegistryRecord,
    path: &str,
) -> HybridLiveDeliveryTarget {
    let class = aos_hub_core::hybrid_ingress::live::delivery_class(path);
    HybridLiveDeliveryTarget {
        registry_id: registry.id,
        registry_resource_version: registry.resource_version,
        mirror_resource_version: selected.source.resource_version,
        placement_id: selected.placement.id,
        placement_resource_version: selected.placement.resource_version,
        write_spec_version: selected.placement.write_spec_version,
        placement_prefix: selected.placement.prefix.clone(),
        binding_id: selected.binding.id,
        binding_resource_version: selected.binding.resource_version,
        protected_profile_digest: selected.profile_digest.clone(),
        upstream_base: selected.source.source_url.clone(),
        path: path.into(),
        class,
        maximum_bytes: if class
            == aos_hub_core::hybrid_ingress::live::HybridLiveDeliveryClass::Metadata
        {
            128 * 1024
        } else {
            aos_hub_core::mirror_work::MIRROR_MAX_OBJECT_BYTES
        },
    }
}

/// Retrieves only the bounded metadata query output from storage-local execution.
///
/// # Errors
/// Refuses bulk paths, changed SQL pins or mismatched body commitments.
pub(crate) async fn metadata(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry_id: i64,
    path: &str,
) -> Result<Option<Vec<u8>>> {
    use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkOutcome};

    let Some(target) = delivery(db, work, registry_id, path).await? else {
        return Ok(None);
    };
    anyhow::ensure!(
        target.class == aos_hub_core::hybrid_ingress::live::HybridLiveDeliveryClass::Metadata,
        "bulk upstream bodies require public Worker delivery"
    );
    let placement = db
        .surface_placement(target.placement_id)
        .await?
        .context("live metadata placement disappeared")?;
    let binding = db
        .binding(target.binding_id)
        .await?
        .context("live metadata binding disappeared")?;
    let plan = work.plan_for_placement(
        &placement,
        &binding,
        StorageWorkOperation::InspectMirrorLiveMetadata {
            target: target.clone(),
        },
        aos_hub_core::clock::now_unix_secs(),
    )?;
    let result = work.execute(&plan).await?;
    anyhow::ensure!(
        delivery(db, work, registry_id, path).await?.as_ref() == Some(&target),
        "live metadata selection changed during read"
    );
    match result.outcome {
        StorageWorkOutcome::NotFound => Ok(None),
        StorageWorkOutcome::MirrorLiveMetadata {
            sha256,
            size,
            content_base64,
        } => {
            anyhow::ensure!(
                content_base64.len() <= 175_000,
                "live metadata encoding exceeds bound"
            );
            let bytes = base64::engine::general_purpose::STANDARD.decode(&content_base64)?;
            anyhow::ensure!(
                bytes.len() <= 128 * 1024
                    && size == bytes.len() as u64
                    && aos_hub_core::hybrid_ingress::body_sha256(&bytes) == sha256,
                "live metadata body commitment differs"
            );
            Ok(Some(bytes))
        }
        _ => anyhow::bail!("live metadata result shape differs"),
    }
}
