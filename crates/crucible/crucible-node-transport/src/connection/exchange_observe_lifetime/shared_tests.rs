//! Checks the real lifetime adapters against their full original implementation.
//!
//! These are arithmetic fixtures only. No connection, native preparation,
//! original Source, admitted bank or releasing owner is manufactured.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Prefix = OriginalPacketPrefixStorageData;

fn prefix(requests: usize, maximum_frame: usize) -> Result<Prefix, ProviderError> {
    let open_ack = if requests == 0 {
        0
    } else {
        acknowledgements::open_ack_storage(maximum_frame)?
    };
    Ok(Prefix {
        native_retained_backing_bytes: None,
        frames: requests + 1,
        requests,
        evidence_payload_bytes: 0,
        outgoing_framed_bytes: 0,
        incoming_framed_bytes: 0,
        new_transport_credit_bytes: 0,
        original_plan_requested_bytes: 11,
        acknowledgement_index_requested_bytes: 13,
        canonical_requested_bytes: 17,
        record_slots_requested_bytes: 19,
        outgoing_guard_requested_bytes: 23,
        response_iterator_requested_bytes: 29,
        successful_ack_cache_requested_bytes: 31,
        one_open_ack_requested_bytes: open_ack,
        containment_requested_bytes: 37,
        construction_transient_requested_bytes: 41,
        preparation_transient_requested_bytes: 43,
        declared_quote_scratch_bytes: 47,
        original_literal_required_bytes: 0,
        original_slots_required: 0,
    })
}

fn base_outcome(data: &Prefix, maximum: usize, original: bool) -> Result<[usize; 3], String> {
    if original {
        <Prefix as original::OriginalPacketPrefixLifetimeDataExt>::native_observe_lifetime_storage_data(data, maximum)
            .map(|value| [value.retained_requested_bytes, value.maximum_simultaneous_transient_bytes, value.declared_counter_scratch_bytes])
            .map_err(|error| format!("{error:?};{error}"))
    } else {
        data.native_observe_lifetime_storage_data(maximum)
            .map(|value| {
                [
                    value.retained_requested_bytes,
                    value.maximum_simultaneous_transient_bytes,
                    value.declared_counter_scratch_bytes,
                ]
            })
            .map_err(|error| format!("{error:?};{error}"))
    }
}

fn original_outcome(
    data: &Prefix,
    maximum_frame: usize,
    maximum: usize,
    old: bool,
) -> Result<[usize; 4], String> {
    if old {
        <Prefix as original::OriginalPacketPrefixLifetimeDataExt>::native_original_observe_lifetime_storage_data(data, maximum_frame, maximum)
            .map(|value| original::original_components(&value))
            .map_err(|error| format!("{error:?};{error}"))
    } else {
        data.native_original_observe_lifetime_storage_data(maximum_frame, maximum)
            .map(|value| {
                [
                    value.retained_requested_bytes,
                    value.encoding,
                    value.acknowledgement,
                    value.scratch,
                ]
            })
            .map_err(|error| format!("{error:?};{error}"))
    }
}

#[test]
fn exact_original_partitions_and_returned_query_match_complete_old_bodies() -> TestResult {
    for requests in [0, 1] {
        for frame in [64, 1024] {
            let data = prefix(requests, frame)?;
            let maximum = data.requested_bytes()?;

            assert_eq!(
                base_outcome(&data, maximum, false),
                base_outcome(&data, maximum, true)
            );
            assert!(base_outcome(&data, maximum, false).is_ok());
            assert_eq!(
                original_outcome(&data, frame, maximum, false),
                original_outcome(&data, frame, maximum, true)
            );
            assert!(original_outcome(&data, frame, maximum, false).is_ok());

            assert_eq!(
                base_outcome(&data, maximum - 1, false),
                base_outcome(&data, maximum - 1, true)
            );
            assert!(base_outcome(&data, maximum - 1, false).is_err());
            assert_eq!(
                original_outcome(&data, frame, maximum - 1, false),
                original_outcome(&data, frame, maximum - 1, true)
            );
            assert!(original_outcome(&data, frame, maximum - 1, false).is_err());
        }
    }

    let receive = OriginalReportQueryReceiveStorageData {
        maximum_frame_body_bytes: 1024,
        raw_and_envelope_requested_bytes: 11,
        typed_query_requested_bytes: 13,
        correlation_requested_bytes: 17,
        declared_counter_scratch_bytes: 19,
        original_literal_required_bytes: 1028,
        original_descriptor_required_bytes: 23,
    };
    let actual = Prefix::native_observe_returned_query_storage_data(&receive)?;
    let old = <Prefix as original::OriginalPacketPrefixLifetimeDataExt>::native_observe_returned_query_storage_data(&receive)?;
    assert_eq!(actual, old);
    assert!(actual > receive.typed_query_requested_bytes);
    Ok(())
}

#[test]
fn ack_queries_keep_zero_request_raw_cap_equality_and_first_error_order() -> TestResult {
    let zero = prefix(0, 0)?;
    let maximum = zero.requested_bytes()?;
    // The unused invalid frame cap must not cause an early ACK query.
    assert_eq!(
        original_outcome(&zero, 0, maximum, false),
        original_outcome(&zero, 0, maximum, true)
    );
    assert!(original_outcome(&zero, 0, maximum, false).is_ok());

    let mut wrong_zero = prefix(0, 0)?;
    wrong_zero.one_open_ack_requested_bytes = 1;
    assert_eq!(
        original_outcome(&wrong_zero, 0, usize::MAX, false),
        original_outcome(&wrong_zero, 0, usize::MAX, true)
    );
    assert!(original_outcome(&wrong_zero, 0, usize::MAX, false).is_err());

    let mut wrong_ack = prefix(1, 64)?;
    wrong_ack.one_open_ack_requested_bytes += 1;
    assert_eq!(
        original_outcome(&wrong_ack, 64, usize::MAX, false),
        original_outcome(&wrong_ack, 64, usize::MAX, true)
    );
    assert!(original_outcome(&wrong_ack, 64, usize::MAX, false).is_err());

    let valid = prefix(1, 64)?;
    assert_eq!(
        original_outcome(&valid, 0, usize::MAX, false),
        original_outcome(&valid, 0, usize::MAX, true)
    );
    assert!(original_outcome(&valid, 0, usize::MAX, false).is_err());

    let mut overflowing = prefix(1, 64)?;
    overflowing.original_plan_requested_bytes = usize::MAX;
    assert_eq!(
        original_outcome(&overflowing, 0, usize::MAX, false),
        original_outcome(&overflowing, 0, usize::MAX, true)
    );
    assert!(original_outcome(&overflowing, 0, usize::MAX, false).is_err());
    Ok(())
}

#[test]
fn real_counter_chain_adds_only_the_declared_nested_adapter_families() {
    let old_base = <Prefix as original::OriginalPacketPrefixLifetimeDataExt>::native_observe_lifetime_counter_scratch_data();
    let old_original = <Prefix as original::OriginalPacketPrefixLifetimeDataExt>::native_original_observe_lifetime_counter_scratch_data();
    let old_prepared = <Prefix as original::OriginalPacketPrefixLifetimeDataExt>::native_original_observe_prepared_lifetime_counter_scratch_data();

    assert_eq!(
        Prefix::native_observe_lifetime_counter_scratch_data(),
        old_base + OBSERVE_LIFETIME_ADAPTER_COUNTER_SCRATCH_DATA
    );
    assert_eq!(
        Prefix::native_original_observe_lifetime_counter_scratch_data(),
        old_original
            + OBSERVE_LIFETIME_ADAPTER_COUNTER_SCRATCH_DATA
            + ORIGINAL_OBSERVE_LIFETIME_ADAPTER_COUNTER_SCRATCH_DATA
    );
    assert_eq!(
        Prefix::native_original_observe_prepared_lifetime_counter_scratch_data(),
        old_prepared
            + OBSERVE_LIFETIME_ADAPTER_COUNTER_SCRATCH_DATA
            + ORIGINAL_OBSERVE_LIFETIME_ADAPTER_COUNTER_SCRATCH_DATA
    );
}
