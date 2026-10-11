//! Closed ordinary storage observations through the Native result validator.
//!
//! Decoding distinguishes exact typed content from metadata and known literal
//! refusals. It grants no authority, authenticates no reply MAC, and does not
//! imply that Native consumed or accepted the independently captured reply.
//!
//! ```text
//! Decode(request, fullReply, deployment, status) -> (plan, class, payloadCounts)
//! NativeConsumption = independently retained prefix SHA/bytes/EOF per attempt
//! ```

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_work::{
    StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult, MAX_PLAN_BYTES,
};

use crate::Payload;

#[cfg(test)]
mod tests;

#[cfg(test)]
fn decode(
    request: &[u8],
    reply: &[u8],
    deployment: &str,
) -> Result<(StorageWorkPlan, &'static str)> {
    decode_transport(request, reply, deployment, 200).map(|(plan, class, _)| (plan, class))
}

pub(super) fn decode_transport(
    request: &[u8],
    reply: &[u8],
    deployment: &str,
    status: u16,
) -> Result<(StorageWorkPlan, &'static str, Payload)> {
    ensure!(
        request.len() <= MAX_PLAN_BYTES,
        "storage work observation exceeds the closed wire bound"
    );
    let plan: StorageWorkPlan = serde_json::from_slice(request)?;
    ensure!(
        serde_json::to_vec(&plan)? == request,
        "storage work original is noncanonical"
    );
    plan.validate_observation_shape(deployment)?;
    ensure!(
        reply.len() <= plan.operation.maximum_result_bytes(),
        "storage work reply exceeds its actual operation bound"
    );
    ensure!(
        supported(&plan.operation),
        "storage work operation remains unsupported"
    );
    let mut payload = Payload::metadata();
    if let StorageWorkOperation::PutMetadata { content_base64, .. }
    | StorageWorkOperation::PutProbe { content_base64, .. } = &plan.operation
    {
        // The shared plan validator already decoded this standard-base64 body.
        payload.request_raw_object_bytes = validated_base64_bytes(content_base64)?.to_string();
    }

    if status != 200 {
        ensure!(
            known_refusal(status, reply),
            "storage work refusal is not a source-owned literal"
        );
        return Ok((plan, "storage_work_refusal_metadata", payload));
    }
    let result: StorageWorkResult = serde_json::from_slice(reply)?;
    ensure!(
        serde_json::to_vec(&result)? == reply,
        "storage work reply is noncanonical"
    );
    aos_hub::storage_work::validate_result_for_test(&plan, &result)?;

    match &result.outcome {
        StorageWorkOutcome::OciRange { content_base64, .. } => {
            payload.reply_raw_object_bytes = validated_base64_bytes(content_base64)?.to_string();
        }
        StorageWorkOutcome::GitObject { content_base64, .. }
        | StorageWorkOutcome::Metadata { content_base64, .. } => {
            payload.selected_data_bytes = validated_base64_bytes(content_base64)?.to_string();
        }
        StorageWorkOutcome::GitObjects { objects } => {
            payload.selected_data_bytes = sum_lengths(
                objects
                    .iter()
                    .map(|object| validated_base64_bytes(&object.content_base64)),
            )?
            .to_string();
        }
        StorageWorkOutcome::MetadataObjects { page } => {
            payload.selected_data_bytes = sum_lengths(
                page.objects
                    .iter()
                    .filter_map(|object| object.document.as_ref())
                    .map(|document| validated_base64_bytes(&document.content_base64)),
            )?
            .to_string();
        }
        StorageWorkOutcome::Documentation { page } => {
            payload.selected_data_bytes = serde_json::to_vec(page)?.len().to_string();
        }
        StorageWorkOutcome::DocumentationContent { document_base64 } => {
            payload.selected_data_bytes = validated_base64_bytes(document_base64)?.to_string();
        }
        StorageWorkOutcome::GitTreeEntries { page, .. } => {
            payload.selected_data_bytes = serde_json::to_vec(page)?.len().to_string();
        }
        StorageWorkOutcome::GitPackProjection { projection } => {
            payload.selected_data_bytes = sum_lengths(
                projection
                    .objects
                    .iter()
                    .map(|object| validated_base64_bytes(&object.content_base64)),
            )?
            .to_string();
        }
        StorageWorkOutcome::GitPackTreeProjection { projection } => {
            payload.selected_data_bytes = projection
                .page
                .as_ref()
                .map(|page| serde_json::to_vec(page).map(|bytes| bytes.len()))
                .transpose()?
                .unwrap_or(0)
                .to_string();
        }
        StorageWorkOutcome::MirrorLiveMetadata { content_base64, .. } => {
            payload.selected_data_bytes = validated_base64_bytes(content_base64)?.to_string();
        }
        StorageWorkOutcome::MirrorLiveMetadataBatch { items } => {
            use aos_hub_core::storage_work::live_metadata_batch::LiveMetadataOutcome;

            payload.selected_data_bytes = sum_lengths(items.iter().filter_map(|item| {
                if let LiveMetadataOutcome::Found { content_base64, .. } = &item.outcome {
                    Some(validated_base64_bytes(content_base64))
                } else {
                    None
                }
            }))?
            .to_string();
        }
        StorageWorkOutcome::MirrorTreeInventory { projection } => {
            payload.selected_data_bytes = projection
                .page
                .as_ref()
                .map(|page| serde_json::to_vec(page).map(|bytes| bytes.len()))
                .transpose()?
                .unwrap_or(0)
                .to_string();
        }
        _ => {}
    }
    let class = if matches!(result.outcome, StorageWorkOutcome::NotFound) {
        "storage_work_not_found_metadata"
    } else if matches!(
        plan.operation,
        StorageWorkOperation::ListPage { .. }
            | StorageWorkOperation::Head { .. }
            | StorageWorkOperation::HashOciRange { .. }
            | StorageWorkOperation::DeleteIfMatches { .. }
    ) {
        "storage_work_gc_metadata"
    } else if crate::mirror::supports_operation(&plan.operation) {
        "mirror_storage_work_typed_observation"
    } else {
        "storage_work_typed_observation"
    };
    Ok((plan, class, payload))
}

fn supported(operation: &StorageWorkOperation) -> bool {
    crate::mirror::supports_operation(operation)
        || matches!(
            operation,
            StorageWorkOperation::ListPage { .. }
                | StorageWorkOperation::Head { .. }
                | StorageWorkOperation::HashOciRange { .. }
                | StorageWorkOperation::DeleteIfMatches { .. }
                | StorageWorkOperation::InspectSha256 { .. }
                | StorageWorkOperation::InspectGitObject { .. }
                | StorageWorkOperation::InspectGitObjects { .. }
                | StorageWorkOperation::FilterGitTreeEntries { .. }
                | StorageWorkOperation::InspectStoredGitPack { .. }
                | StorageWorkOperation::FilterStoredGitPackTree { .. }
                | StorageWorkOperation::InspectMetadata { .. }
                | StorageWorkOperation::InspectMetadataObjects { .. }
                | StorageWorkOperation::InspectDocumentation { .. }
                | StorageWorkOperation::InspectDocumentationContent { .. }
                | StorageWorkOperation::InspectOciRange { .. }
                | StorageWorkOperation::PutMetadata { .. }
                | StorageWorkOperation::PutProbe { .. }
                | StorageWorkOperation::DeleteProbe { .. }
        )
}

fn known_refusal(status: u16, body: &[u8]) -> bool {
    matches!(
        (status, body),
        (
            401,
            b"storage work signature is required" | b"storage work plan is not authorized"
        ) | (
            413,
            b"storage work plan is too large" | b"storage work result exceeds its limit"
        ) | (409, b"binding snapshot is unavailable")
            | (501, b"external storage operation is unavailable")
            | (503, b"storage work failed")
    )
}

// Length is counted only after the shared validators have actually decoded the
// exact base64 field. This arithmetic adds no parallel permissive decoder.
fn validated_base64_bytes(body: &str) -> Result<usize> {
    ensure!(body.len() % 4 == 0, "validated base64 geometry differs");
    let padding = body
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .count();
    (body.len() / 4)
        .checked_mul(3)
        .and_then(|size| size.checked_sub(padding))
        .context("validated base64 byte count overflowed")
}

fn sum_lengths(mut lengths: impl Iterator<Item = Result<usize>>) -> Result<usize> {
    lengths.try_fold(0usize, |total, next| {
        total
            .checked_add(next?)
            .context("selected body count overflowed")
    })
}
