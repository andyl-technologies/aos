//! Fresh compact mirror controls and immutable External effect deadlines.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    db::Database,
    mirror_work::{MirrorOriginal, MirrorStep},
    storage_work::{StorageWorkOperation, StorageWorkPlan},
};

use crate::storage_work::RemoteStorageWorkClient;

pub(super) async fn plan(
    db: &Database,
    work: &RemoteStorageWorkClient,
    original: &MirrorOriginal,
    operation: StorageWorkOperation,
) -> Result<StorageWorkPlan> {
    // Historical Managed status and acknowledgement controls are deliberately
    // built from the retained original, without loading a replacement writer.
    if original.external_destination.is_none() {
        let now = aos_hub_core::clock::now_unix_secs();
        return Ok(StorageWorkPlan {
            version: 1,
            plan_id: uuid::Uuid::new_v4().simple().to_string(),
            deployment_id: work.deployment_id().into(),
            issued_at: now,
            expires_at: now
                .checked_add(30)
                .context("mirror control expiry overflow")?,
            placement_id: original.placement_id,
            placement_resource_version: original.placement_resource_version,
            binding_id: original.binding_id,
            binding_resource_version: original.binding_resource_version,
            binding_kind: "deployment_r2".into(),
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
            placement_prefix: original.placement_prefix.clone(),
            operation,
        });
    }
    let placement = db
        .surface_placement(original.placement_id)
        .await?
        .context("mirror placement disappeared")?;
    let binding = db
        .binding(original.binding_id)
        .await?
        .context("mirror binding disappeared")?;
    let mut plan = work.plan_for_placement(
        &placement,
        &binding,
        operation,
        aos_hub_core::clock::now_unix_secs(),
    )?;
    if let Some(selected) = &original.external_destination {
        let replay_only = match &plan.operation {
            StorageWorkOperation::MirrorTransfer { step, .. } => replay(step),
            StorageWorkOperation::MirrorTransferBatch { items } => {
                items.iter().all(|item| replay(&item.step))
            }
            _ => false,
        };
        if !replay_only {
            let cutoff = i64::try_from(selected.expires_at)?
                .checked_sub(1)
                .context("mirror External effect cutoff underflow")?;
            plan.expires_at = plan.expires_at.min(cutoff);
            ensure!(
                plan.issued_at < plan.expires_at,
                "mirror External original has no remaining effect window"
            );
        }
        selected.validate_plan(&plan)?;
    }
    original.validate_plan(&plan)?;
    Ok(plan)
}

fn replay(step: &MirrorStep) -> bool {
    matches!(
        step,
        MirrorStep::Status { .. } | MirrorStep::Acknowledge { .. }
    )
}
