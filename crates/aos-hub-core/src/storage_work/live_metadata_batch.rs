//! Closed fresh metadata batches with exact per-path authority commitments.
//!
//! ```text
//! request = {targets: [same selection, distinct sorted paths]}
//! reply = {items: [{target_digest, source_bytes, outcome}]}
//! ```
//!
//! A refusal is not absence. Failed body reads have unknown byte counts; the
//! envelope counts only known completed reads and cannot establish total cost.

use anyhow::{ensure, Context as _, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{StorageWorkPlan, StorageWorkResult, MAX_RESULT_BYTES};
use crate::hybrid_ingress::live::{HybridLiveDeliveryClass, HybridLiveDeliveryTarget};

/// Capability name for the additive live metadata batch protocol.
pub const OPERATION: &str = "inspect_mirror_live_metadata_batch_v1";
/// Maximum distinct selectors sharing one immutable source selection.
pub const MAX_TARGETS: usize = 32;
/// Maximum simultaneous full bounded source reads within a Worker batch.
pub const MAX_PRODUCERS: usize = 2;
/// Maximum parallel legacy queries when the Worker advertises only singleton reads.
pub const MAX_LEGACY_QUERIES: usize = 4;

/// Explicit refusal without manufactured absence or a retained provider receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveMetadataRefusal {
    /// Source status, framing, timeout or read failed; consumed bytes are unknown.
    SourceReadFailed,
    /// A read is deferred, or its positive body exceeds the aggregate response budget.
    ResultBudget,
}

/// One live metadata result, without implying an immutable stored identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LiveMetadataOutcome {
    /// Complete bounded source response with independently checked body commitment.
    Found {
        /// Lowercase SHA-256 of the complete returned body.
        sha256: String,
        /// Exact decoded body size, at most the original metadata ceiling.
        size: u64,
        /// Standard-base64 complete metadata bytes; never pack content.
        content_base64: String,
    },
    /// Exact selected source returned HTTP 404.
    NotFound,
    /// An explicit non-absence failure; Native must not commit a partial lookup.
    Refused {
        /// Closed reason, with no provider URL, credential or error text.
        reason: LiveMetadataRefusal,
    },
}

/// Ordered observation correlated with the canonical full original selector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveMetadataObservation {
    /// SHA-256 of the canonical full original, including path and all authority pins.
    pub target_digest: String,
    /// Known fully consumed source bytes, or `None` for an unsuccessful body read.
    pub source_bytes: Option<u64>,
    /// Positive output, exact absence or explicit refusal at this position.
    pub outcome: LiveMetadataOutcome,
}

/// Commits the entire selected source, SQL pins, class and byte ceiling.
///
/// # Errors
/// Returns an error for an invalid target or serialization failure.
pub fn target_digest(target: &HybridLiveDeliveryTarget) -> Result<String> {
    target.validate()?;
    Ok(crate::hybrid_ingress::body_sha256(&serde_json::to_vec(
        target,
    )?))
}

/// Checks bounded ordered selectors sharing the exact original source selection.
///
/// # Errors
/// Returns an error for duplicates, bulk paths, changed pins or a mismatched plan.
pub fn validate_targets(
    targets: &[HybridLiveDeliveryTarget],
    plan: &StorageWorkPlan,
) -> Result<()> {
    validate_selection(targets)?;
    ensure!(
        plan.binding_kind == "deployment_r2",
        "live batch requires managed R2"
    );
    for target in targets {
        ensure!(
            target.placement_id == plan.placement_id
                && target.placement_resource_version == plan.placement_resource_version
                && target.binding_id == plan.binding_id
                && target.binding_resource_version == plan.binding_resource_version
                && target.placement_prefix == plan.placement_prefix,
            "live batch differs from the original placement fence"
        );
    }
    Ok(())
}

/// Checks the closed selector set before configuration, capacity or provider access.
///
/// # Errors
/// Returns an error for an empty, excessive, unordered or inconsistent selection.
pub fn validate_selection(targets: &[HybridLiveDeliveryTarget]) -> Result<()> {
    ensure!(
        !targets.is_empty() && targets.len() <= MAX_TARGETS,
        "live batch size refused"
    );
    let first = &targets[0];
    for (index, target) in targets.iter().enumerate() {
        target.validate()?;
        ensure!(
            target.class == HybridLiveDeliveryClass::Metadata && target.maximum_bytes <= 128 * 1024,
            "bulk live batch refused"
        );
        let mut same_selection = target.clone();
        same_selection.path = first.path.clone();
        ensure!(
            same_selection == *first,
            "live batch source selection changed"
        );
        ensure!(
            index == 0 || targets[index - 1].path < target.path,
            "live batch paths unordered"
        );
    }
    Ok(())
}

/// Checks the complete ordered result partition and honest known-byte accounting.
///
/// # Errors
/// Returns an error for missing, reordered or rewritten items, malformed positives,
/// inconsistent refusal accounting or excessive decoded metadata.
pub fn validate_observations(
    targets: &[HybridLiveDeliveryTarget],
    items: &[LiveMetadataObservation],
    source_bytes: u64,
) -> Result<()> {
    validate_selection(targets)?;
    ensure!(
        items.len() == targets.len(),
        "live batch omitted an original"
    );
    let mut known_bytes = 0_u64;
    for (target, item) in targets.iter().zip(items) {
        ensure!(
            item.target_digest == target_digest(target)?,
            "live batch original changed"
        );
        match &item.outcome {
            LiveMetadataOutcome::Found {
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
                    bytes.len() as u64 == *size
                        && *size <= target.maximum_bytes
                        && crate::hybrid_ingress::body_sha256(&bytes) == *sha256
                        && item.source_bytes == Some(*size),
                    "live metadata body commitment differs"
                );
            }
            LiveMetadataOutcome::NotFound => {
                ensure!(item.source_bytes == Some(0), "absence byte count differs")
            }
            LiveMetadataOutcome::Refused {
                reason: LiveMetadataRefusal::SourceReadFailed,
            } => {
                ensure!(
                    item.source_bytes.is_none(),
                    "failed live read claims a complete byte count"
                );
            }
            LiveMetadataOutcome::Refused {
                reason: LiveMetadataRefusal::ResultBudget,
            } => {
                ensure!(
                    item.source_bytes
                        .is_some_and(|size| size <= target.maximum_bytes),
                    "budget refusal count differs"
                );
            }
        }
        known_bytes = known_bytes
            .checked_add(item.source_bytes.unwrap_or(0))
            .context("live batch byte count overflow")?;
    }
    ensure!(
        source_bytes == known_bytes,
        "live batch known byte count differs"
    );
    Ok(())
}

/// Fits complete observations within the unchanged whole-result JSON ceiling.
///
/// Positive bodies that cannot fit become explicit budget refusals; known source
/// costs remain retained. No selector is dropped or truncated.
///
/// # Errors
/// Returns an error for a non-batch result, invalid observations or envelope overflow.
pub fn bound_result(
    targets: &[HybridLiveDeliveryTarget],
    result: &mut StorageWorkResult,
) -> Result<()> {
    let super::StorageWorkOutcome::MirrorLiveMetadataBatch { items } = &result.outcome else {
        anyhow::bail!("not a live batch result");
    };
    validate_observations(targets, items, result.source_bytes)?;
    // At most 32 replacements; encoding includes the full transport envelope.
    while serde_json::to_vec(result)?.len() > MAX_RESULT_BYTES {
        let super::StorageWorkOutcome::MirrorLiveMetadataBatch { items } = &mut result.outcome
        else {
            anyhow::bail!("live batch result changed");
        };
        let item = items
            .iter_mut()
            .rev()
            .find(|item| matches!(item.outcome, LiveMetadataOutcome::Found { .. }))
            .context("live batch envelope exceeds bound")?;
        item.outcome = LiveMetadataOutcome::Refused {
            reason: LiveMetadataRefusal::ResultBudget,
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests;
