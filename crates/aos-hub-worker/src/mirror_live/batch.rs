//! Bounded live metadata reads under one independently accepted producer identity.
//!
//! Each source still uses the singleton bounded query implementation. The batch
//! retains ordered explicit refusals and never treats a failed read as absence.

use anyhow::{ensure, Context as _, Result};
use futures_util::{stream, StreamExt as _};

use aos_hub_core::storage_work::{
    live_metadata_batch::{
        self, LiveMetadataObservation, LiveMetadataOutcome, LiveMetadataRefusal,
    },
    StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
};

/// Executes the additive batch with at most two full metadata producers.
///
/// # Errors
/// Refuses changed profiles, expired originals or acceptance cutoffs; source
/// failures remain explicit items only while the original authority is current.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn inspect(
    env: &worker::Env,
    plan: &StorageWorkPlan,
) -> Result<StorageWorkResult> {
    let StorageWorkOperation::InspectMirrorLiveMetadataBatch { targets } = &plan.operation else {
        anyhow::bail!("not a live metadata batch");
    };
    live_metadata_batch::validate_targets(targets, plan)?;
    let config = crate::direct_upload::config::QualifiedConfig::load(env).await?;
    let (profile, _) = config.managed(env)?;
    ensure!(
        targets[0].protected_profile_digest == profile.digest()?,
        "live batch profile changed"
    );
    let (accepted, live) =
        crate::mirror_import::acceptance::require_live(env, &profile, &config.acceptance_evidence)
            .await?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let current = || -> Result<()> {
        let latest = config.latest_now()?;
        accepted.check(latest)?;
        live.validate_dispatch_time(latest)?;
        plan.validate(&deployment, i64::try_from(latest)?)?;
        ensure!(
            latest < u64::try_from(plan.expires_at)?,
            "live batch request expired"
        );
        Ok(())
    };
    current()?;
    let cutoff = plan.expires_at;
    let latest_now = || config.latest_now();
    let items = collect_until_expiry(
        targets,
        &current,
        |target| {
            super::query_source(
                target,
                cutoff,
                config.uncertainty,
                target.maximum_bytes.min(live.maximum_bytes),
                &current,
                &latest_now,
            )
        },
        cutoff,
        &latest_now,
        worker::Delay::from,
    )
    .await?;
    current()?;
    let source_bytes = items.iter().filter_map(|item| item.source_bytes).sum();
    let mut result = crate::surface::storage_work_result(
        plan,
        StorageWorkOutcome::MirrorLiveMetadataBatch { items },
        source_bytes,
    );
    live_metadata_batch::bound_result(targets, &mut result)?;
    Ok(result)
}

// This deadline owns the complete collection, including both pending body
// producers. An already unreturnable batch cannot retain metadata capacity for
// the separate singleton/public stream's 600-second read horizon.
async fn collect_until_expiry<'a, F, Fut, S, Timer>(
    targets: &'a [aos_hub_core::hybrid_ingress::live::HybridLiveDeliveryTarget],
    current: &impl Fn() -> Result<()>,
    read: F,
    expires_at: i64,
    latest_now: &impl Fn() -> Result<u64>,
    sleep: S,
) -> Result<Vec<LiveMetadataObservation>>
where
    F: Fn(&'a aos_hub_core::hybrid_ingress::live::HybridLiveDeliveryTarget) -> Fut,
    Fut: std::future::Future<Output = Result<(StorageWorkOutcome, u64)>>,
    S: FnOnce(std::time::Duration) -> Timer,
    Timer: std::future::Future<Output = ()>,
{
    let remaining = expires_at
        .checked_sub(i64::try_from(latest_now()?)?)
        .filter(|seconds| *seconds > 0)
        .context("live batch original expired")?;
    let timer = sleep(std::time::Duration::from_secs(u64::try_from(remaining)?));
    let collection = collect(targets, current, read);
    match futures_util::future::select(Box::pin(collection), Box::pin(timer)).await {
        futures_util::future::Either::Left((result, _)) => result,
        futures_util::future::Either::Right(_) => anyhow::bail!("live batch original expired"),
    }
}

// Both the real Worker path and native fixtures use this exact ordered scheduler.
async fn collect<'a, F, Fut>(
    targets: &'a [aos_hub_core::hybrid_ingress::live::HybridLiveDeliveryTarget],
    current: &impl Fn() -> Result<()>,
    read: F,
) -> Result<Vec<LiveMetadataObservation>>
where
    F: Fn(&'a aos_hub_core::hybrid_ingress::live::HybridLiveDeliveryTarget) -> Fut,
    Fut: std::future::Future<Output = Result<(StorageWorkOutcome, u64)>>,
{
    live_metadata_batch::validate_selection(targets)?;
    let response_full = std::cell::Cell::new(false);
    let mut pending = stream::iter(targets.iter().enumerate().map(|(index, target)| {
        let read = &read;
        let response_full = &response_full;
        async move {
            current()?;
            let outcome = if response_full.get() {
                // No body or provider dispatch is needed after a positive body
                // exhausted this response. A fresh bounded singleton may retry.
                (
                    LiveMetadataOutcome::Refused {
                        reason: LiveMetadataRefusal::ResultBudget,
                    },
                    Some(0),
                )
            } else {
                match read(target).await {
                    Ok((StorageWorkOutcome::NotFound, 0)) => {
                        (LiveMetadataOutcome::NotFound, Some(0))
                    }
                    Ok((
                        StorageWorkOutcome::MirrorLiveMetadata {
                            sha256,
                            size,
                            content_base64,
                        },
                        bytes,
                    )) => (
                        LiveMetadataOutcome::Found {
                            sha256,
                            size,
                            content_base64,
                        },
                        Some(bytes),
                    ),
                    Ok(_) => anyhow::bail!("live source returned an unexpected shape"),
                    Err(_) => (
                        LiveMetadataOutcome::Refused {
                            reason: LiveMetadataRefusal::SourceReadFailed,
                        },
                        None,
                    ),
                }
            };
            // A source error cannot hide expiry or a changed producer identity.
            current()?;
            Ok((
                index,
                LiveMetadataObservation {
                    target_digest: live_metadata_batch::target_digest(target)?,
                    source_bytes: outcome.1,
                    outcome: outcome.0,
                },
            ))
        }
    }))
    .buffered(live_metadata_batch::MAX_PRODUCERS);
    let mut returned = Vec::with_capacity(targets.len());
    let mut encoded_bytes = 0_usize;
    while let Some(observation) = pending.next().await {
        let (_, mut item) = observation?;
        let bytes = serde_json::to_vec(&item)?.len();
        // Bound retained positives during production, before the final envelope
        // check. At most two completed reads can be pending behind an earlier one.
        if encoded_bytes + bytes > aos_hub_core::storage_work::MAX_RESULT_BYTES - 16 * 1024
            && matches!(item.outcome, LiveMetadataOutcome::Found { .. })
        {
            response_full.set(true);
            item.outcome = LiveMetadataOutcome::Refused {
                reason: LiveMetadataRefusal::ResultBudget,
            };
        }
        encoded_bytes += serde_json::to_vec(&item)?.len();
        returned.push(item);
    }
    Ok(returned)
}

#[cfg(test)]
#[path = "batch/tests.rs"]
mod tests;
