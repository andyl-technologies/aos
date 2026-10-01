//! Ordered independent item settlement through the production mirror guard path.
//!
//! Eight controls may await independent Durable Objects. Actual object buffers
//! and provider streams retain their separate measured Bulk/Metadata admission.
//! Every admitted item is drained before returning across a publication barrier.

use anyhow::{Context as _, Result};
use aos_hub_core::mirror_batch::{MirrorBatchOutcome, MirrorBatchResult};
use aos_hub_core::storage_work::{
    StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
};
use futures_util::StreamExt as _;
use worker::Env;

pub(crate) async fn execute(
    env: &Env,
    plan: &StorageWorkPlan,
    body: &[u8],
    signature: &str,
    candidate: bool,
) -> Result<StorageWorkResult> {
    let StorageWorkOperation::MirrorTransferBatch { items } = &plan.operation else {
        anyhow::bail!("not a mirror phase batch");
    };
    let mut pending =
        futures_util::stream::iter(items.iter().enumerate().map(|(index, item)| async move {
            let result = super::runtime::dispatch_selected(
                env,
                plan,
                body,
                signature,
                candidate,
                Some(index),
            )
            .await;
            let outcome = match result {
                Ok((progress, source_bytes)) => MirrorBatchOutcome::Progress {
                    progress,
                    source_bytes,
                },
                Err(_) => MirrorBatchOutcome::Refused,
            };
            Ok::<_, anyhow::Error>((
                index,
                MirrorBatchResult {
                    job_id: item.original.job_id.clone(),
                    original_digest: aos_hub_core::mirror_work::digest(&item.original)?,
                    outcome,
                },
            ))
        }))
        .buffer_unordered(8);
    let mut completed = Vec::with_capacity(items.len());
    while let Some(result) = pending.next().await {
        completed.push(result?);
    }
    completed.sort_by_key(|(index, _)| *index);
    let items = completed
        .into_iter()
        .map(|(_, result)| result)
        .collect::<Vec<_>>();
    let source_bytes = items.iter().try_fold(0_u64, |total, result| {
        let bytes = match &result.outcome {
            MirrorBatchOutcome::Progress { source_bytes, .. } => *source_bytes,
            MirrorBatchOutcome::Refused => 0,
        };
        total
            .checked_add(bytes)
            .context("mirror batch source-byte accounting overflow")
    })?;
    Ok(crate::surface::storage_work_result(
        plan,
        StorageWorkOutcome::MirrorBatch { items },
        source_bytes,
    ))
}
