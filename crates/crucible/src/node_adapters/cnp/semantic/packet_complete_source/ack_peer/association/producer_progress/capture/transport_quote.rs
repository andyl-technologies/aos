//! Prices the independently owned Source side of the selected SDK effect.
//!
//! The genuine SDK prospective row supplies closed typed-family bounds. This
//! row does not include the SDK row itself, native process credit, local native
//! decoder, current-history serialization scratch, or final semantic/Host and
//! Journal output construction. The parent separately conjoins all of them.

use super::{
    bridge::CaptureAdminBridge, confirmation::CaptureConfirmationOwners, owner::CaptureOnceOwner,
    post_confirmation::CapturePostConfirmationOwners, prefix::CapturePrefixOwners,
    sdk_effect::CaptureSdkOwners, signing::CaptureSigningOwners,
};
use crate::node_contract::{RuntimeError, WorldActivation};
use crucible_node_contract::Id;
use crucible_node_provider::client::{
    OriginalRestoredSettledCaptureConstructionData, RestoredSettledCaptureAuxiliaryBody,
};
use crucible_node_provider::retained_metadata::serialization_storage::original_json_value_storage_extent_data;
use std::mem::size_of;

pub(super) fn future_storage_data(
    sdk: &OriginalRestoredSettledCaptureConstructionData,
    world: &WorldActivation,
    maximum_prefix: usize,
    maximum_runtime: usize,
    maximum_checkpoint: usize,
    maximum: usize,
) -> Result<(usize, usize, usize), RuntimeError> {
    let counts = sdk.maximum_auxiliary_originals_data();
    let originals = counts[0]
        .checked_add(counts[1])
        .ok_or(RuntimeError::ResourceLimit)?;
    let frame = sdk.maximum_frame_bytes_data();
    let prefix = original_json_value_storage_extent_data(maximum_prefix)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    let checkpoint = original_json_value_storage_extent_data(maximum_checkpoint)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    let terminal =
        original_json_value_storage_extent_data(frame).map_err(|_| RuntimeError::ResourceLimit)?;
    let proof = CaptureSigningOwners::future_storage_data(sdk, maximum)?;
    let world = world.retained_requested_storage_data(maximum)?;
    let mut world_bytes = world.independent_bytes();
    for shared in world.shared_allocations() {
        world_bytes = add(world_bytes, shared.requested_bytes(), maximum)?;
    }

    // All IDs are constructed/validated through the closed <=128-byte Id
    // grammar. The upload helper reserves 128 requested String bytes before
    // formatting each independent routing ID, without later bank growth.
    let routing = multiply(originals, size_of::<Id>() + 128, maximum)?;
    let bodies = multiply(
        originals,
        size_of::<RestoredSettledCaptureAuxiliaryBody>(),
        maximum,
    )?;
    let id_backing = multiply(originals, 128, maximum)?;
    // Each Begin/Chunk/Finish body independently clones its transfer ID; each
    // Begin also clones a full reference. The entire closed request backing
    // conservatively dominates that one actual reference subtree, separately
    // for each ordinal; actual Source→SDK backing is checked before reserve.
    let upload_begin_refs = multiply(2, sdk.maximum_upload_request_backing_bytes_data(), maximum)?;
    let chunk_payloads = add(maximum_prefix, maximum_runtime, maximum)?;
    let input_refs = multiply(2, sdk.maximum_capture_request_backing_bytes_data(), maximum)?;

    let mut retained = sum(
        &[
            size_of::<CaptureSdkOwners>(),
            size_of::<CapturePostConfirmationOwners>(),
            size_of::<CaptureOnceOwner>(),
            size_of::<CaptureConfirmationOwners>(),
            size_of::<CapturePrefixOwners>(),
            size_of::<CaptureAdminBridge>(),
            sdk.maximum_capture_request_backing_bytes_data(),
            sdk.maximum_begin_body_backing_bytes_data(),
            sdk.maximum_upload_request_backing_bytes_data(),
            sdk.maximum_upload_request_backing_bytes_data(),
            sdk.maximum_confirmation_request_backing_bytes_data(),
            proof.0,
            routing,
            bodies,
            id_backing,
            upload_begin_refs,
            chunk_payloads,
            // Prefix Value +canonical bank; its independent SDK input payload copy
            // and all retained Source Chunk bytes coexist until final discharge.
            prefix.value_dom_requested_bytes,
            maximum_prefix,
            checkpoint.value_dom_requested_bytes,
            maximum_checkpoint,
            maximum_prefix,
            maximum_runtime,
            input_refs,
            terminal.value_dom_requested_bytes,
            frame,
            // Capture ID, operation ID and confirmation ID remain Source-owned.
            128,
            128,
            128,
            // Bridge owns actual fresh World and four independent full references.
            world_bytes,
            sdk.maximum_capture_request_backing_bytes_data(),
            sdk.maximum_capture_request_backing_bytes_data(),
            sdk.maximum_capture_request_backing_bytes_data(),
            sdk.maximum_capture_request_backing_bytes_data(),
            128,
            128,
        ],
        maximum,
    )?;
    // Empty extension maps may own their conservative tree root. The helper
    // constructs every Source body with an empty map; no open caller extension
    // population is accepted as extra credit by this row.
    let roots = crate::node_contract::NodeRuntime::capture_protocol_tree_storage(
        originals,
        0,
        size_of::<(String, serde_json::Value)>(),
        std::mem::align_of::<(String, serde_json::Value)>(),
        maximum,
    )?;
    retained = add(retained, roots, maximum)?;
    let transient = sum(
        &[
            proof.1,
            prefix
                .canonical_pass_requested_bytes()
                .map_err(|_| RuntimeError::ResourceLimit)?,
            checkpoint
                .canonical_pass_requested_bytes()
                .map_err(|_| RuntimeError::ResourceLimit)?,
            terminal
                .canonical_pass_requested_bytes()
                .map_err(|_| RuntimeError::ResourceLimit)?,
            // Ledger frontier serialization keeps one U64 decimal String live
            // beside its destination Value/encoded output, never a new quota.
            20,
        ],
        maximum,
    )?;
    let scratch = sum(
        &[
            proof.2,
            CaptureSdkOwners::counter_scratch_data(),
            CapturePostConfirmationOwners::counter_scratch_data(),
            CaptureOnceOwner::counter_scratch_data(),
            CaptureConfirmationOwners::counter_scratch_data(),
            CapturePrefixOwners::counter_scratch_data(),
            CaptureAdminBridge::counter_scratch_data(),
            counter_scratch_data(),
        ],
        maximum,
    )?;
    sum(&[retained, transient, scratch], maximum)?;
    Ok((retained, transient, scratch))
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<&OriginalRestoredSettledCaptureConstructionData>() + size_of::<&WorldActivation>()
        + size_of::<[usize; 2]>() + size_of::<usize>()
        + size_of::<Result<(usize, usize, usize), RuntimeError>>()
        + size_of::<[usize; 34]>() + size_of::<[usize; 5]>() + size_of::<[usize; 6]>()
        + size_of::<&[usize]>() + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<crucible_node_provider::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>()
        + size_of::<Result<crucible_node_provider::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData, crucible_node_provider::ProviderError>>()
        + size_of::<Result<usize, RuntimeError>>() + size_of::<Option<usize>>()
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

fn multiply(count: usize, bytes: usize, maximum: usize) -> Result<usize, RuntimeError> {
    count
        .checked_mul(bytes)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    values
        .iter()
        .try_fold(0, |total, bytes| add(total, *bytes, maximum))
}
