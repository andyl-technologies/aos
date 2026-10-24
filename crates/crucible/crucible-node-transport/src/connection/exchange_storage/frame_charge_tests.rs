//! Compares the shared frame arithmetic with its independent original producer.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn quote(native: bool) -> OriginalPacketPrefixStorageData {
    OriginalPacketPrefixStorageData {
        native_retained_backing_bytes: native.then_some(0),
        frames: 0,
        requests: 0,
        evidence_payload_bytes: 0,
        outgoing_framed_bytes: 0,
        incoming_framed_bytes: 0,
        new_transport_credit_bytes: 0,
        original_plan_requested_bytes: 0,
        acknowledgement_index_requested_bytes: 0,
        canonical_requested_bytes: 0,
        record_slots_requested_bytes: 0,
        outgoing_guard_requested_bytes: 0,
        response_iterator_requested_bytes: 0,
        successful_ack_cache_requested_bytes: 0,
        one_open_ack_requested_bytes: 0,
        containment_requested_bytes: 0,
        construction_transient_requested_bytes: 0,
        preparation_transient_requested_bytes: 0,
        declared_quote_scratch_bytes: 0,
        original_literal_required_bytes: 0,
        original_slots_required: 0,
    }
}

fn frame() -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut fields = Projection::new(usize::MAX)?;
    fields.add_object()?;
    fields.add_field("body")?;
    fields.add_object()?;
    fields.add_field("number")?;
    fields.add_value(&1e20f64)?;
    fields.add_field("text")?;
    fields.add_string("quote\" slash\\ unicodeé")?;
    fields.add_field("extensions")?;
    fields.add_object()?;
    fields.finish(usize::MAX)
}

fn compare(
    actual: &mut OriginalPacketPrefixStorageData,
    original: &mut OriginalPacketPrefixStorageData,
    request: bool,
    maximum: usize,
) -> TestResult {
    let actual_result = charge_frame(actual, frame()?, request, maximum);
    let original_result = frame_charge_original::charge_frame(original, frame()?, request, maximum);

    assert_eq!(format!("{actual_result:?}"), format!("{original_result:?}"));
    assert_eq!(actual, original);
    Ok(())
}

#[test]
fn shared_frame_charge_keeps_every_component_and_exact_frame_refusal() -> TestResult {
    let maximum = frame()?.maximum_encoded_bytes;
    for native in [false, true] {
        for request in [false, true] {
            let mut actual = quote(native);
            let mut original = quote(native);

            compare(&mut actual, &mut original, request, maximum)?;
            assert!(actual.outgoing_framed_bytes > 4);
            assert!(actual.preparation_transient_requested_bytes > 0);
            assert_eq!(actual.successful_ack_cache_requested_bytes > 0, request);

            let mut refused = quote(native);
            let mut old_refused = quote(native);
            compare(&mut refused, &mut old_refused, request, maximum - 1)?;
            assert!(charge_frame(&mut quote(native), frame()?, request, maximum - 1).is_err());
            assert_eq!(refused, quote(native));
        }
    }
    Ok(())
}

#[test]
fn shared_frame_charge_keeps_original_overflow_and_failed_mutation_prefix() -> TestResult {
    let maximum = frame()?.maximum_encoded_bytes;
    for request in [false, true] {
        let mut actual = quote(true);
        actual.original_plan_requested_bytes = usize::MAX;
        let mut original = quote(true);
        original.original_plan_requested_bytes = usize::MAX;

        compare(&mut actual, &mut original, request, maximum)?;
        assert_eq!(actual.original_plan_requested_bytes, usize::MAX);
        assert!(
            actual
                .native_retained_backing_bytes
                .is_some_and(|bytes| bytes > 0)
        );
        assert_eq!(actual.outgoing_guard_requested_bytes, 0);
        assert_eq!(actual.preparation_transient_requested_bytes, 0);
    }
    Ok(())
}

#[test]
fn shared_frame_adapter_adds_only_its_actual_defining_header_family() {
    assert_eq!(
        Connection::<crate::client::DeadlineStream>::original_packet_prefix_quote_scratch_bytes_data(),
        frame_charge_original::counter_scratch_data()
            + FRAME_CHARGE_ADAPTER_COUNTER_SCRATCH_DATA
            + 2 * size_of::<&crate::reference_packet::control::PacketControlReply>(),
    );
    assert_eq!(
        FRAME_CHARGE_ADAPTER_COUNTER_SCRATCH_DATA,
        2 * size_of::<&mut OriginalPacketPrefixStorageData>()
            + size_of::<OriginalSerializationStorageData>()
            + size_of::<bool>()
            + 2 * size_of::<usize>()
            + 2 * size_of::<&crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack::AckFixedLayoutData>()
            + size_of::<Result<(), ProviderError>>(),
    );
}
