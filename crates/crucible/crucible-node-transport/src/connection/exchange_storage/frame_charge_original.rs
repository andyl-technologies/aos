//! Preserves the independent original frame charge and fixed-counter oracle.

use super::*;

pub(super) fn charge_frame(
    data: &mut OriginalPacketPrefixStorageData,
    projected: OriginalSerializationStorageData,
    request: bool,
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    if projected.maximum_encoded_bytes > maximum_frame.min(65_536) {
        return Err(credit());
    }
    if let Some(retained) = data.native_retained_backing_bytes.as_mut() {
        // Plan, outgoing guard and containment own three independent DOMs.
        // The canonical frame bank is another persistent allocation.
        *retained = sum(&[
            *retained,
            mul(3, projected.retained_value_backing_bytes)?,
            projected.canonical_output_requested_bytes,
            if request {
                add(128, growth(128)?)?
            } else {
                128
            },
        ])?;
    }
    let deep_copy = projected.dom_and_canonical_scratch_bytes;
    data.original_plan_requested_bytes = add(data.original_plan_requested_bytes, deep_copy)?;
    data.outgoing_guard_requested_bytes =
        add(data.outgoing_guard_requested_bytes, add(deep_copy, 128)?)?;
    data.containment_requested_bytes = add(data.containment_requested_bytes, deep_copy)?;
    data.canonical_requested_bytes = add(
        data.canonical_requested_bytes,
        projected.canonical_output_requested_bytes,
    )?;
    let framed = add(projected.maximum_encoded_bytes, 4)?;
    data.outgoing_framed_bytes = add(data.outgoing_framed_bytes, framed)?;
    data.original_literal_required_bytes = add(data.original_literal_required_bytes, framed)?;
    // All retained canonical banks plus every sequential validation construction
    // are conservatively simultaneous here. This sums source-pinned passes,
    // rather than inferring a typed heap allowance from transport wire bytes.
    let typed_slots = mul(
        4,
        add(
            projected.sequence_elements,
            mul(4, projected.sequence_containers)?,
        )?,
    )?;
    let typed_element = size_of::<crucible_node_format::ObservationBatch>()
        .max(size_of::<crucible_node_format::Event>())
        .max(size_of::<ContentRef>())
        .max(size_of::<Id>());
    let typed_validation = sum(&[
        mul(typed_slots, typed_element)?,
        super::super::restore_input_quote::tree_storage(
            projected.sequence_containers,
            projected.sequence_elements,
            size_of::<(&Id, U64)>(),
            align_of::<(&Id, U64)>(),
        )?,
        mul(2 * 128, projected.sequence_elements)?,
        size_of::<ResponseBody>().max(size_of::<RequestBody>()),
        acknowledgements::serde_error_storage(projected.maximum_encoded_bytes)?,
    ])?;
    data.preparation_transient_requested_bytes = add(
        data.preparation_transient_requested_bytes,
        add(mul(projected.requested_total()?, 4)?, typed_validation)?,
    )?;
    if request {
        if let Some(retained) = data.native_retained_backing_bytes.as_mut() {
            *retained = add(*retained, acknowledgements::successful_ack_storage()?)?;
        }
        data.successful_ack_cache_requested_bytes = add(
            data.successful_ack_cache_requested_bytes,
            acknowledgements::successful_ack_storage()?,
        )?;
        data.original_plan_requested_bytes = add(data.original_plan_requested_bytes, growth(128)?)?;
    }
    Ok(())
}

pub(super) const fn counter_scratch_data() -> usize {
    size_of::<OriginalPacketPrefixStorageData>()
        + size_of::<Projection>()
        + 4 * size_of::<OriginalSerializationStorageData>()
        + 2 * size_of::<MetadataObserver<'static>>()
        + 2 * size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<blake3::Hasher>()
        + size_of::<Body<'static>>()
        + 20
        + "blake3-256".len()
        + "cnp.blob.v1".len()
        + 64
        + acknowledgements::PREFIX_ACK_COUNTER_ADDITIONAL
}
