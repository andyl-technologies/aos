//! Bounded signed mirror phase batches with independent item settlement.
//!
//! An outer plan authenticates every exact original and step. The physical-key
//! owner verifies that same outer body and selects its item by index. A refused
//! item cannot cancel another admitted item or weaken dependent phase ordering.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::mirror_work::{MirrorOriginal, MirrorProgress, MirrorStep};
use crate::storage_work::StorageWorkPlan;

/// One exact original and the next bounded phase admitted for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorBatchItem {
    /// Immutable source, destination and business operation identity.
    pub original: MirrorOriginal,
    /// Freshly authorized dependent phase, never a mutation permission cache.
    pub step: MirrorStep,
}

/// Positive item progress or a bounded refusal, preserving request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MirrorBatchOutcome {
    /// Actual positive retained state from the physical-key owner.
    Progress {
        /// Full exact progress, containing no source body.
        progress: MirrorProgress,
        /// Actual source bytes consumed by this item.
        source_bytes: u64,
    },
    /// This item's original or effect remains refused or unsettled.
    Refused,
}

/// One independently correlated result within the outer response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorBatchResult {
    /// Exact retained business operation, not the outer transport plan ID.
    pub job_id: String,
    /// Canonical digest of the full original.
    pub original_digest: String,
    /// Independent positive progress or explicit refusal.
    pub outcome: MirrorBatchOutcome,
}

/// Validates every item against the same signed destination and bounded shape.
///
/// # Errors
/// Returns an error for oversized/empty batches, duplicate originals, changed
/// destination pins or malformed phases. Physical-key conflicts still settle
/// through the actual guard, rather than this structural check.
pub fn validate_items(items: &[MirrorBatchItem], plan: &StorageWorkPlan) -> Result<()> {
    ensure!(
        (1..=64).contains(&items.len()),
        "mirror phase batch size is invalid"
    );
    let mut jobs = std::collections::BTreeSet::new();
    for item in items {
        item.original.validate_plan(plan)?;
        item.step.validate()?;
        ensure!(
            jobs.insert(&item.original.job_id),
            "mirror phase batch repeats an original"
        );
    }
    Ok(())
}

/// Rechecks the ordered original partition, positive phases and byte budgets.
///
/// # Errors
/// Returns an error for omitted/reordered originals, invalid progress, changed
/// ACK identity, or source costs exceeding the exact admitted bounded phase.
pub fn validate_results(
    items: &[MirrorBatchItem],
    results: &[MirrorBatchResult],
    source_bytes: u64,
) -> Result<()> {
    ensure!(items.len() == results.len(), "mirror batch omitted an item");
    let mut observed = 0_u64;
    for (item, result) in items.iter().zip(results) {
        ensure!(
            result.job_id == item.original.job_id
                && result.original_digest == crate::mirror_work::digest(&item.original)?,
            "mirror batch changed item order or original"
        );
        if let MirrorBatchOutcome::Progress {
            progress,
            source_bytes,
        } = &result.outcome
        {
            progress.validate(&item.original)?;
            let maximum = match item.step {
                MirrorStep::UploadParts { maximum_parts, .. }
                | MirrorStep::CopyParts { maximum_parts, .. } => {
                    u64::from(maximum_parts) * crate::mirror_work::MIRROR_PART_BYTES
                }
                MirrorStep::VerifyStage => item.original.verification.size(),
                _ => 0,
            };
            ensure!(
                *source_bytes <= maximum,
                "mirror batch item exceeds its source-byte budget"
            );
            if let MirrorStep::Acknowledge { commit_digest } = &item.step {
                ensure!(
                    progress.commit_digest(&item.original)? == *commit_digest,
                    "mirror batch acknowledgement changed final proof"
                );
            }
            observed = observed
                .checked_add(*source_bytes)
                .ok_or_else(|| anyhow::anyhow!("mirror batch source-byte accounting overflow"))?;
        }
    }
    ensure!(
        observed == source_bytes,
        "mirror batch source-byte aggregate differs"
    );
    Ok(())
}
