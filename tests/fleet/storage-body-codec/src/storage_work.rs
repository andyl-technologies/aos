//! Closed GC metadata observations through the actual Native result validator.
//!
//! This retains the distinction between structural decoding and authenticated
//! handler/SQL/claim/provider evidence. No result here grants Delete permission
//! or proves absence. Every content-bearing operation remains unsupported.

use anyhow::{ensure, Result};
use aos_hub_core::storage_work::{
    StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult, MAX_PLAN_BYTES,
    MAX_RESULT_BYTES,
};

#[cfg(test)]
mod tests;

pub(super) fn decode(
    request: &[u8],
    reply: &[u8],
    deployment: &str,
) -> Result<(StorageWorkPlan, &'static str)> {
    ensure!(
        request.len() <= MAX_PLAN_BYTES && reply.len() <= MAX_RESULT_BYTES,
        "storage work observation exceeds the closed wire bound"
    );
    let plan: StorageWorkPlan = serde_json::from_slice(request)?;
    let result: StorageWorkResult = serde_json::from_slice(reply)?;
    ensure!(
        serde_json::to_vec(&plan)? == request && serde_json::to_vec(&result)? == reply,
        "storage work observation is noncanonical"
    );
    plan.validate_observation_shape(deployment)?;
    ensure!(
        matches!(
            &plan.operation,
            StorageWorkOperation::ListPage { .. }
                | StorageWorkOperation::Head { .. }
                | StorageWorkOperation::HashOciRange { .. }
                | StorageWorkOperation::DeleteIfMatches { .. }
        ),
        "storage work content operation is unsupported"
    );
    aos_hub::storage_work::validate_result_for_test(&plan, &result)?;
    let class = if matches!(result.outcome, StorageWorkOutcome::NotFound) {
        "storage_work_not_found_metadata"
    } else {
        "storage_work_gc_metadata"
    };
    Ok((plan, class))
}
