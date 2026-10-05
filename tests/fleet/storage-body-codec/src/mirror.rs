//! Exact Mirror transport bodies and retained physical guard correlations.
//!
//! The shared production validators check complete originals, progress, ordered
//! results and source costs. These observations authenticate no MAC, prove no
//! current SQL authority, and do not turn a refusal into provider settlement.

use anyhow::{ensure, Result};
use aos_hub_core::{
    mirror_guard::{
        batch::{
            validate_mirror_guard_batch_reply_observation, MirrorGuardBatchLookup,
            MirrorGuardBatchReply, MIRROR_EXTERNAL_FUNCTIONAL_GUARD_BATCH_LOOKUP_PATH,
            MIRROR_GUARD_BATCH_LOOKUP_PATH,
        },
        validate_mirror_guard_reply_observation, MirrorGuardExecution, MirrorGuardLookup,
        MirrorGuardReply, MIRROR_EXTERNAL_FUNCTIONAL_GUARD_LOOKUP_PATH, MIRROR_GUARD_LOOKUP_PATH,
        MIRROR_GUARD_MAX_BYTES,
    },
    storage_work::StorageWorkOperation,
};
use serde::{de::DeserializeOwned, Serialize};

#[cfg(test)]
mod tests;

/// Recognizes only the existing typed Mirror operations selected for observation.
pub(super) fn supports_operation(operation: &StorageWorkOperation) -> bool {
    matches!(
        operation,
        StorageWorkOperation::MirrorTransfer { .. }
            | StorageWorkOperation::MirrorTransferBatch { .. }
            | StorageWorkOperation::InspectMirrorPack { .. }
            | StorageWorkOperation::InspectMirrorLiveMetadata { .. }
            | StorageWorkOperation::InspectMirrorLiveMetadataBatch { .. }
            | StorageWorkOperation::InspectMirrorMembership { .. }
            | StorageWorkOperation::InspectMirrorTreeInventory { .. }
    )
}

/// Recognizes exact production and finite External guard paths, without a query.
pub(super) fn supports_path(path: &str) -> bool {
    matches!(
        path,
        MIRROR_GUARD_LOOKUP_PATH
            | MIRROR_GUARD_BATCH_LOOKUP_PATH
            | MIRROR_EXTERNAL_FUNCTIONAL_GUARD_LOOKUP_PATH
            | MIRROR_EXTERNAL_FUNCTIONAL_GUARD_BATCH_LOOKUP_PATH
    )
}

/// Decodes canonical retained guard bodies without authenticating their MAC.
///
/// # Errors
/// Refuses foreign purpose, source, deployment, original, receipt, nonce, time,
/// unknown fields, noncanonical JSON or a body exceeding the shared wire bound.
pub(super) fn decode_guard(
    path: &str,
    request: &[u8],
    reply: &[u8],
    source_digest: &str,
    deployment: &str,
) -> Result<(&'static str, &'static str, String)> {
    let execution = match path {
        MIRROR_GUARD_LOOKUP_PATH | MIRROR_GUARD_BATCH_LOOKUP_PATH => MirrorGuardExecution::Hosted,
        MIRROR_EXTERNAL_FUNCTIONAL_GUARD_LOOKUP_PATH
        | MIRROR_EXTERNAL_FUNCTIONAL_GUARD_BATCH_LOOKUP_PATH => {
            MirrorGuardExecution::ControlledExternalFunctional
        }
        _ => anyhow::bail!("Mirror guard endpoint remains unsupported"),
    };

    if matches!(
        path,
        MIRROR_GUARD_LOOKUP_PATH | MIRROR_EXTERNAL_FUNCTIONAL_GUARD_LOOKUP_PATH
    ) {
        let request: MirrorGuardLookup = canonical(request)?;
        let reply: MirrorGuardReply = canonical(reply)?;
        ensure!(
            request.deployment_id == deployment
                && request.execution == execution
                && request.issuer.source_digest == source_digest,
            "Mirror guard audience, purpose or implementation differs"
        );
        validate_mirror_guard_reply_observation(&request, &reply)?;
        Ok((
            "mirror_guard",
            "mirror_guard_metadata",
            request.request_nonce,
        ))
    } else {
        let request: MirrorGuardBatchLookup = canonical(request)?;
        let reply: MirrorGuardBatchReply = canonical(reply)?;
        ensure!(
            request.deployment_id == deployment
                && request.execution == execution
                && request.issuer.source_digest == source_digest,
            "Mirror batch guard audience, purpose or implementation differs"
        );
        validate_mirror_guard_batch_reply_observation(&request, &reply)?;
        Ok((
            "mirror_guard_batch",
            "mirror_guard_batch_metadata",
            request.request_nonce,
        ))
    }
}

fn canonical<T: DeserializeOwned + Serialize>(body: &[u8]) -> Result<T> {
    ensure!(
        body.len() <= MIRROR_GUARD_MAX_BYTES,
        "Mirror guard body exceeds its wire bound"
    );
    let value = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&value)? == body,
        "Mirror guard body is noncanonical"
    );
    Ok(value)
}
