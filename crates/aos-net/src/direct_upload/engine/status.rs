//! Bounded status reconciliation against original source and placement custody.

use aos_proto_types::direct_upload::*;

use super::{
    DirectCheckpointStore, DirectClientError, DirectObservedPart, DirectUploadControl,
    DirectUploadObject, helpers,
};
use crate::direct_upload::{PartChecksumAlgorithm, PartSource, provider::portable_part};

pub(super) async fn source_part(
    object: &DirectUploadObject,
    placement: &DirectPlacementRef,
    number: u32,
) -> Result<PartSource, DirectClientError> {
    let (offset, size) = object
        .intent
        .part_range(number)
        .map_err(|_| DirectClientError::Invalid)?;
    let algorithm = match placement.checksum_algorithm {
        DirectChecksumAlgorithm::Md5 => PartChecksumAlgorithm::Md5,
        DirectChecksumAlgorithm::Sha256 => PartChecksumAlgorithm::Sha256,
    };
    object
        .source
        .prepare_part(number, offset, size, algorithm)
        .await
        .map_err(|_| DirectClientError::SourceChanged)
}

pub(super) async fn check_observed(
    object: &DirectUploadObject,
    placement: &DirectPlacementRef,
    observed: &DirectManifestPart,
) -> Result<(), DirectClientError> {
    let source = source_part(object, placement, observed.part.part_number).await?;
    if portable_part(&source) != observed.part || !valid_direct_etag(&observed.etag) {
        return Err(DirectClientError::Invalid);
    }
    Ok(())
}

pub(super) async fn reconcile<C: DirectUploadControl, S: DirectCheckpointStore>(
    control: &C,
    store: &S,
    object: &DirectUploadObject,
    mut status: DirectSessionStatus,
) -> Result<DirectSessionStatus, DirectClientError> {
    let session = status.session.clone();
    let initial_version = status.resource_version;
    let initial_state = status.state;
    let mut after: Option<DirectPartCursor> = None;
    let maximum = (object.placements.len() as u64)
        .checked_mul(
            object
                .intent
                .part_count()
                .map_err(|_| DirectClientError::Invalid)? as u64,
        )
        .ok_or(DirectClientError::Invalid)?;
    let mut seen = 0u64;

    loop {
        status
            .validate_for(&session, &object.intent, &object.placements)
            .map_err(|_| DirectClientError::Invalid)?;
        if status.resource_version != initial_version || status.state != initial_state {
            return Err(DirectClientError::Blocked);
        }
        helpers::active_or_verified(status.state)?;
        let mut observations = Vec::with_capacity(status.parts.len());
        for part in &status.parts {
            let position = (part.placement.placement_id.get(), part.part_number);
            if after.as_ref().is_some_and(|after| {
                position <= (after.placement.placement_id.get(), after.part_number)
            }) {
                return Err(DirectClientError::Invalid);
            }
            seen = seen
                .checked_add(1)
                .filter(|seen| *seen <= maximum)
                .ok_or(DirectClientError::Invalid)?;
            // A part's unknown UploadPart outcome is safely repeatable only
            // under the same original checksum/length. Unknown server-owned
            // Create/Complete/Promote/Abort remains a blocked session state.
            if let Some(observed) = &part.observed {
                check_observed(object, &part.placement, observed).await?;
                observations.push(DirectObservedPart {
                    session: session.clone(),
                    placement: part.placement.clone(),
                    observed: observed.clone(),
                });
            }
        }
        store.record_server_parts(&observations).await?;
        let Some(next) = status.next_cursor.clone() else {
            status.parts.clear();
            return Ok(status);
        };
        let position = (next.placement.placement_id.get(), next.part_number);
        if next.part_number == 0
            || after.as_ref().is_some_and(|after| {
                position <= (after.placement.placement_id.get(), after.part_number)
            })
        {
            return Err(DirectClientError::Invalid);
        }
        after = Some(next);
        let encoded_cursor =
            encode_direct_control(&after).map_err(|_| DirectClientError::Invalid)?;
        let cursor_digest = hex::encode(sha2::Sha256::digest(&encoded_cursor));
        let operation_id =
            helpers::operation("status-page", &[&session.session_id, &cursor_digest]);
        let response = helpers::control(
            control,
            &DirectUploadRequest::StatusBatch(DirectBatch {
                operation_id,
                items: vec![DirectStatusQuery {
                    session: session.clone(),
                    after: after.clone(),
                    maximum_parts: object.discovery.maximum_batch_parts,
                }],
            }),
        )
        .await?;
        if response.sessions.len() != 1 || !response.grants.is_empty() {
            return Err(DirectClientError::Invalid);
        }
        status = response
            .sessions
            .into_iter()
            .next()
            .ok_or(DirectClientError::Invalid)?;
    }
}

use sha2::Digest as _;
