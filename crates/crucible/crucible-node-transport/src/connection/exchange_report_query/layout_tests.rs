//! Compares the real shared query producer against its independent old body.
//!
//! crucible-lint: panic-shortcut: typed fixture assertions intentionally stop tests.

use super::*;

fn original_native_query_receive_storage_from_limits(
    limits: crate::handshake::Limits,
    purpose: Purpose,
) -> Result<OriginalReportQueryReceiveStorageData, ProviderError> {
    let mut data = original_query_receive_storage_from_limits(limits, purpose)?;
    if matches!(purpose, Purpose::OriginalObserve12) {
        // This is the actual restricted native receive, not a feature-selected
        // generic read. Raw framing, parser, Error and partial owner terms stay.
        data.raw_and_envelope_requested_bytes = sum(&[
            acknowledgements::native_original_open_ack_storage(data.maximum_frame_body_bytes)?,
            mul(2, size_of::<Envelope>())?,
            size_of::<ConnectionIncident>(),
        ])?;
    }
    data.requested_bytes()?;
    Ok(data)
}

fn original_query_receive_storage_from_limits(
    limits: crate::handshake::Limits,
    purpose: Purpose,
) -> Result<OriginalReportQueryReceiveStorageData, ProviderError> {
    crucible_node_format::Validate::validate(&limits)?;
    let bytes = allowance(limits.frame_bytes.get())?;
    let typed_query = match purpose {
        Purpose::OriginalObserve12 => 0,
        Purpose::FreshCompletedAdmit13 => sum(&[
            size_of::<PacketNativeFreshRestoreAllocationQuery>(),
            growth(PACKET_FRESH_RESTORE_ALLOCATION_QUERY.len())?,
            mul(3, growth(32)?)?,
        ])?,
    };
    let result = OriginalReportQueryReceiveStorageData {
        maximum_frame_body_bytes: bytes,
        // This reuses the real full-R raw/parser/four-DOM/canonical/error
        // primitive, not the smaller successful ACK or original-clone bound.
        // Its ResponseBody header is conservative extra; RequestBody below is
        // independently charged for the actual restricted Observe decode.
        raw_and_envelope_requested_bytes: sum(&[
            acknowledgements::open_ack_storage(bytes)?,
            mul(2, size_of::<Envelope>())?,
            size_of::<ConnectionIncident>(),
        ])?,
        typed_query_requested_bytes: sum(&[
            size_of::<RequestBody>(),
            size_of::<crate::bodies::ObserveRequest>(),
            growth("blake3-256".len())?,
            growth("cnp.owner-binding.v1".len())?,
            growth(64)?,
            typed_query,
            // Query serde/DTO construction visits its three bounded Bytes
            // formatters before callbacks; malformed strings are rejected by
            // the scalar guard before that independent typed construction.
            match purpose {
                Purpose::OriginalObserve12 => 0,
                Purpose::FreshCompletedAdmit13 => mul(3, growth(43)?)?,
            },
        ])?,
        correlation_requested_bytes: sum(&[
            crate::connection::restore_input_quote::tree_storage(
                1,
                1,
                size_of::<Id>() + size_of::<Envelope>(),
                align_of::<Id>().max(align_of::<Envelope>()),
            )?,
            128,
        ])?,
        declared_counter_scratch_bytes: original_counter_scratch_data(),
        original_literal_required_bytes: add(bytes, 4)?,
        original_descriptor_required_bytes:
            crate::transport::original_frames::original_frame_slot_layout(),
    };
    result.requested_bytes()?;
    Ok(result)
}

const fn original_counter_scratch_data() -> usize {
    size_of::<OriginalReportQueryReceiveStorageData>()
        + size_of::<Result<OriginalReportQueryReceiveStorageData, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<&OriginalReportQueryReceiveStorageData>()
        + size_of::<Envelope>()
        + size_of::<ReceivedFrame>()
        + size_of::<Purpose>()
        + size_of::<&OriginalNativeReportStartupAllocation>()
        + acknowledgements::native_original_open_ack_counter_scratch_data()
        + size_of::<OriginalReportQueryReceiveStorageData>()
        + size_of::<Result<OriginalReportQueryReceiveStorageData, ProviderError>>()
        + size_of::<crate::handshake::Limits>()
        + size_of::<[usize; 3]>()
        + size_of::<bool>()
}

fn components(data: &OriginalReportQueryReceiveStorageData) -> [usize; 7] {
    [
        data.maximum_frame_body_bytes,
        data.raw_and_envelope_requested_bytes,
        data.typed_query_requested_bytes,
        data.correlation_requested_bytes,
        data.declared_counter_scratch_bytes,
        data.original_literal_required_bytes,
        data.original_descriptor_required_bytes,
    ]
}

#[test]
fn actual_query_producers_preserve_both_purposes_and_native_refinement() -> Result<(), ProviderError>
{
    let (_, authority, _, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    for frame_bytes in [1, 1024, 16_777_216] {
        let mut limits = authority.limits();
        limits.frame_bytes = U64::new(frame_bytes);
        for purpose in [Purpose::OriginalObserve12, Purpose::FreshCompletedAdmit13] {
            for native in [false, true] {
                let actual = if native {
                    native_query_receive_storage_from_limits(limits, purpose)?
                } else {
                    query_receive_storage_from_limits(limits, purpose)?
                };
                let mut original = if native {
                    original_native_query_receive_storage_from_limits(limits, purpose)?
                } else {
                    original_query_receive_storage_from_limits(limits, purpose)?
                };
                let increment = original_report_query_receive_counter_scratch_data()
                    - original_counter_scratch_data();
                assert_eq!(increment,
                    2 * size_of::<shared::ReportQueryReceiveComponents>()
                    + 2 * size_of::<Result<shared::ReportQueryReceiveComponents, ProviderError>>()
                    + 2 * size_of::<&shared::ReportQueryFixedLayoutData>()
                    + 2 * size_of::<&crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack::AckFixedLayoutData>()
                    + 2 * size_of::<usize>()
                    + 2 * size_of::<Result<usize, ProviderError>>()
                    + size_of::<crate::handshake::Limits>()
                    + size_of::<Purpose>());
                original.declared_counter_scratch_bytes += increment;
                assert_eq!(components(&actual), components(&original));
                assert_eq!(actual.requested_bytes()?, original.requested_bytes()?);
            }
        }
    }
    Ok(())
}

#[test]
fn actual_query_producers_preserve_invalid_limit_refusals() -> Result<(), Box<dyn std::error::Error>>
{
    let (_, authority, _, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    for field in 0..5 {
        for value in [0, u64::MAX] {
            let mut limits = authority.limits();
            match field {
                0 => limits.frame_bytes = U64::new(value),
                1 => limits.nesting = U64::new(value),
                2 => limits.requests = U64::new(value),
                3 => limits.journal_entries = U64::new(value),
                4 => limits.blob_chunk_bytes = U64::new(value),
                _ => unreachable!(),
            }
            for purpose in [Purpose::OriginalObserve12, Purpose::FreshCompletedAdmit13] {
                let actual = query_receive_storage_from_limits(limits, purpose)
                    .err()
                    .ok_or("actual invalid limit accepted")?;
                let original = original_query_receive_storage_from_limits(limits, purpose)
                    .err()
                    .ok_or("original invalid limit accepted")?;
                assert_eq!(actual.to_string(), original.to_string());
                assert!(native_query_receive_storage_from_limits(limits, purpose).is_err());
            }
        }
    }
    Ok(())
}

#[test]
fn actual_private_layouts_and_literal_overflow_remain_defining() {
    assert_eq!(
        layout::FIXED.fresh_query_bytes,
        size_of::<PacketNativeFreshRestoreAllocationQuery>()
    );
    assert_eq!(layout::FIXED.envelope_bytes, size_of::<Envelope>());
    assert_eq!(
        layout::FIXED.connection_incident_bytes,
        size_of::<ConnectionIncident>()
    );
    assert_eq!(layout::FIXED.request_body_bytes, size_of::<RequestBody>());
    assert_eq!(
        layout::FIXED.observe_request_bytes,
        size_of::<crate::bodies::ObserveRequest>()
    );
    assert_eq!(
        layout::FIXED.correlation_key_value_bytes,
        size_of::<Id>() + size_of::<Envelope>()
    );
    assert_eq!(
        layout::FIXED.correlation_entry_alignment,
        align_of::<Id>().max(align_of::<Envelope>())
    );
    assert_eq!(
        shared::original_literal_required_bytes(usize::MAX - 4).unwrap(),
        usize::MAX
    );
    assert!(shared::original_literal_required_bytes(usize::MAX - 3).is_err());
}
