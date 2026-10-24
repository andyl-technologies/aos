//! Quotes actual Commit projections and model construction before Prepare.
//!
//! The Source lends the same four authenticated raw originals, nested launch5
//! bytes and cached selected model row. The current raw receiver ceiling bounds
//! lexical events before applying compiled DTO/tree layouts. This DATA producer
//! creates no Value, model, lease, receipt, continuation or allocation grant.

use super::*;
use crate::reference_packet::service::complete_restore::transfer::{
    PacketCompleteRestoreOwnerValidationStorage, selected_issuer_decode_counter_scratch_data,
    selected_issuer_decode_storage_data, selected_value_decode_storage_data,
};
use crate::retained_metadata::serialization_storage::{
    original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
};
use std::mem::{align_of, size_of};

/// Borrows independently authenticated originals for a native Commit quote.
///
/// The actual Source/installed window authenticates their provenance. A numeric
/// report, matching serialized labels or these input loans do not grant custody.
/// Raw sources represent semantic occurrences, never native spare capacities.
pub struct PacketNativeRestoreCommitConstructionInputs<'a> {
    /// Borrows the actual selected typed launch5 retained beneath its purpose.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Borrows that same authenticated nested launch5 bank, not the outer wrapper.
    pub encoded_launch: &'a [u8],
    /// Borrows complete Source15 source binding from the private original birth.
    pub source_birth: &'a [u8],
    /// Borrows the same original expected host registration bytes.
    pub host_registration: &'a [u8],
    /// Borrows canonical Source kernel-binding bytes authenticated by Admit.
    pub kernel_binding: &'a [u8],
    /// Borrows canonical Source policy-binding bytes authenticated by Admit.
    pub policy_binding: &'a [u8],
    /// Borrows the actual selected owner/model DATA retained by the cold validator.
    pub model: &'a PacketCompleteRestoreOwnerValidationStorage,
    /// Bounds the complete conjunction under the actual installed policy.
    pub maximum_requested_bytes: usize,
}

/// Separates actual Commit/model owners from input and fresh-target ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketNativeRestoreCommitConstructionData {
    original_projection_bytes: usize,
    incoming_commit_bytes: usize,
    immutable_launch_bytes: usize,
    attempt_and_model_header_bytes: usize,
    model_control_bytes: usize,
    held_receipt_response_bytes: usize,
    measurement_bytes: usize,
    declared_counter_scratch_bytes: usize,
    requested_bytes: usize,
}

impl PacketNativeRestoreCommitConstructionData {
    /// Returns this complete Commit/model requested-storage row as DATA.
    pub fn requested_bytes(&self) -> usize {
        self.requested_bytes
    }

    /// Returns separately named original/projection/model/hold/measurement terms.
    pub fn requested_terms_data(&self) -> [usize; 8] {
        [
            self.original_projection_bytes,
            self.incoming_commit_bytes,
            self.immutable_launch_bytes,
            self.attempt_and_model_header_bytes,
            self.model_control_bytes,
            self.held_receipt_response_bytes,
            self.measurement_bytes,
            self.declared_counter_scratch_bytes,
        ]
    }
}

/// Names explicit compiled views before quote traversal or decimal formatting.
///
/// Streamed executable buffers are a separate named native construction phase.
/// Compiler/recursive frames and allocator physical overhead remain separate.
pub fn original_native_restore_commit_construction_counter_scratch_data() -> usize {
    size_of::<Result<std::cell::Ref<'static, crate::reference_packet::service::ack_emitter::NativeAckBoot>, ProviderError>>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<std::cell::Ref<'static, crate::reference_packet::service::ack_emitter::NativeAckBoot>>()
        + size_of::<Result<std::cell::Ref<'static, crate::reference_packet::service::ack_emitter::NativeAckBoot>, std::cell::BorrowError>>()
        + size_of::<PacketNativeRestoreCommitConstructionInputs<'static>>()
        + size_of::<PacketNativeRestoreCommitConstructionData>()
        + selected_issuer_decode_counter_scratch_data()
        + crate::reference_packet::service::native_startup::PacketNativeInvocationPurposeData::original_launch_literal_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + size_of::<[&[u8]; 4]>() + size_of::<std::array::IntoIter<&[u8], 4>>()
        + size_of::<[usize; 8]>() + size_of::<[usize; 10]>()
        + size_of::<crate::reference_packet::control::PacketControlSnapshotValidationLayouts>()
        + crate::reference_packet::service::complete_restore::maximum_complete_restore_held_evidence_counter_scratch_data()
        + size_of::<[u8; 4]>() + size_of::<[u8; 8]>()
}

/// Quotes every independent Commit projection and selected model owner as DATA.
///
/// All four original semantic values are rescanned from the same actual private
/// Source banks. Two DOMs cover independent native construction and clone/rebuild
/// requests without assuming Source/native spare capacities coincide. The
/// canonical work remains charged while these originals coexist. Model spare
/// capacities come from the separately validated archived model row.
///
/// The actual raw Commit ceiling bounds five possible independent receive,
/// guard, endpoint, attempt and validation Value owners. Three compiled typed
/// views cover Begin, Commit and proof decoding; context/model roots are named
/// separately. No encoded byte is treated as an observed heap byte.
///
/// # Errors
/// Refuses another selected restoration family, absent/malformed raw originals,
/// unsupported receiving/launch bounds, unavailable model DATA, overflow or an
/// independently installed requested-storage excess. No limits are raised.
pub fn original_native_restore_commit_construction_storage_data(
    inputs: &PacketNativeRestoreCommitConstructionInputs<'_>,
) -> Result<PacketNativeRestoreCommitConstructionData, ProviderError> {
    if inputs.launch.complete_restore_selection
        != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || inputs.model.total_bytes == 0
        || inputs.maximum_requested_bytes == 0
        || inputs.encoded_launch.is_empty()
        || inputs.encoded_launch.len() > 1024 * 1024
    {
        return Err(refused());
    }
    let maximum = inputs.maximum_requested_bytes;
    let raw = usize::try_from(inputs.launch.limits.frame_bytes.get()).map_err(|_| refused())?;
    if raw == 0 || raw > 65_536 {
        return Err(refused());
    }
    let frame = original_json_value_storage_extent_data(raw)?;
    let layouts = crate::reference_packet::control::packet_control_snapshot_validation_layouts();
    let slot = layouts
        .maximum_typed_slot_bytes
        .max(size_of::<PacketCompleteRestoreCommitRequest>())
        .max(size_of::<PacketCompleteRestoreTransferProof>())
        .max(size_of::<PacketCompleteRestoreCommitContext>())
        .max(size_of::<PacketNative5SourceLaunch>());
    let mut original_projection_bytes = 0usize;
    for original in [
        inputs.source_birth,
        inputs.host_registration,
        inputs.kernel_binding,
        inputs.policy_binding,
    ] {
        original_projection_bytes = add(
            original_projection_bytes,
            selected_value_decode_storage_data(original, maximum)?,
        )?;
    }
    let incoming_commit_bytes = sum(&[
        mul(5, frame.value_dom_requested_bytes)?,
        mul(3, mul(frame.maximum_value_nodes, slot)?)?,
        frame.canonical_work_requested_bytes,
        frame.canonical_output_requested_bytes,
        3 * size_of::<Envelope>(),
        size_of::<crate::bodies::BeginRequest>(),
        size_of::<PacketCompleteRestoreCommitContext>(),
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES,
    ])?;
    let immutable_launch_bytes =
        selected_issuer_decode_storage_data(inputs.encoded_launch, slot, maximum)?;
    let attempt_and_model_header_bytes = sum(&[
        size_of::<RefCell<NativeCompleteRestoreAttempt>>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            align_of::<RefCell<NativeCompleteRestoreAttempt>>(),
        )?,
        size_of::<VerifiedCompleteRestoration>(),
        size_of::<VerifiedCompleteRestorationHeld>(),
        size_of::<PacketPreparedCompleteModel>(),
        size_of::<PacketDecodedControlSnapshot>(),
        size_of::<PacketCompleteRestorePhysicalHold>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            align_of::<PacketCompleteRestorePhysicalHold>(),
        )?,
        size_of::<PacketNativeRestoredCommitHold>(),
        size_of::<[usize; 8]>(),
    ])?;
    let model_control_bytes = inputs.model.total_bytes;
    let held = maximum_complete_restore_held_evidence_bytes()?;
    let held_receipt_response_bytes = sum(&[
        held,
        held,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
        65_536,
    ])?;
    // The two real measurements are sequential; both returned references remain
    // live. The actual called Prepare streamer keeps one fixed 256 KiB bank and
    // before/after metadata; no whole executable Vec or current_exe path exists.
    let measurement_bytes = add(
        super::super::restore_prepare::original_prepare_executable_measurement_counter_scratch_data(
        ),
        2 * ("blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/octet-stream".len()),
    )?;
    let declared_counter_scratch_bytes =
        original_native_restore_commit_construction_counter_scratch_data();
    let requested_bytes = sum(&[
        original_projection_bytes,
        incoming_commit_bytes,
        immutable_launch_bytes,
        attempt_and_model_header_bytes,
        model_control_bytes,
        held_receipt_response_bytes,
        measurement_bytes,
        declared_counter_scratch_bytes,
    ])?;
    if requested_bytes > maximum {
        return Err(refused());
    }
    Ok(PacketNativeRestoreCommitConstructionData {
        original_projection_bytes,
        incoming_commit_bytes,
        immutable_launch_bytes,
        attempt_and_model_header_bytes,
        model_control_bytes,
        held_receipt_response_bytes,
        measurement_bytes,
        declared_counter_scratch_bytes,
        requested_bytes,
    })
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}
fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}
fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, term| add(sum, *term))
}
