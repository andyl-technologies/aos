//! Compares shared ACK geometry with every original private algorithm.

use super::*;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

type TestResult = Result<(), TestError>;

#[test]
fn actual_ack_header_supplier_and_successful_bound_match_original() -> TestResult {
    assert_eq!(
        ACK_FIXED_LAYOUT.response_body_bytes,
        size_of::<ResponseBody>()
    );
    assert_eq!(
        ACK_FIXED_LAYOUT.received_frame_bytes,
        size_of::<ReceivedFrame>()
    );
    assert_eq!(
        ACK_FIXED_LAYOUT.maximum_blob_result_bytes,
        size_of::<BlobBeginResult>()
            .max(size_of::<BlobChunkResult>())
            .max(size_of::<BlobFinishResult>())
    );
    assert_eq!(
        successful_ack_storage()?,
        original::successful_ack_storage()?
    );
    Ok(())
}

#[test]
fn shared_raw_error_and_native_lifetimes_preserve_all_original_components() -> TestResult {
    for bytes in [1, 2, 31, 4096, 65_536, crate::transport::MAX_FRAME_BYTES] {
        assert_eq!(open_ack_storage(bytes)?, original::open_ack_storage(bytes)?);
        assert_eq!(
            serde_error_storage(bytes)?,
            original::serde_error_storage(bytes)?
        );
        let split = open_ack_lifetime_storage_data(bytes)?;
        let old = original::open_ack_lifetime_storage_data(bytes)?;
        assert_eq!(split.retained, old.retained);
        assert_eq!(split.returning, old.returning);
        assert_eq!(
            add(split.retained, split.returning)?,
            open_ack_storage(bytes)?
        );

        let native = native_original_open_ack_lifetime_storage_data(bytes)?;
        let old_native = original::native_original_open_ack_lifetime_storage_data(bytes)?;
        assert_eq!(native.retained, old_native.retained);
        assert_eq!(native.returning, old_native.returning);
        assert_eq!(native.retained, split.retained);
        assert!(native.returning <= split.returning);
        assert_eq!(
            native_original_open_ack_storage(bytes)?,
            original::native_original_open_ack_storage(bytes)?
        );
    }
    // Error formatting has no raw-frame guard; zero remains an ordinary
    // arithmetic input rather than being rejected by a newly hoisted check.
    assert_eq!(serde_error_storage(0)?, original::serde_error_storage(0)?);
    Ok(())
}

#[test]
fn raw_refusals_and_error_overflow_keep_original_errors() {
    for bytes in [0, crate::transport::MAX_FRAME_BYTES + 1, usize::MAX] {
        assert!(open_ack_storage(bytes).is_err());
        assert_eq!(
            open_ack_storage(bytes).err().map(|error| error.to_string()),
            original::open_ack_storage(bytes)
                .err()
                .map(|error| error.to_string())
        );
        assert_eq!(
            native_original_open_ack_storage(bytes)
                .err()
                .map(|error| error.to_string()),
            original::native_original_open_ack_storage(bytes)
                .err()
                .map(|error| error.to_string())
        );
        assert_eq!(
            open_ack_lifetime_storage_data(bytes)
                .err()
                .map(|error| error.to_string()),
            original::open_ack_lifetime_storage_data(bytes)
                .err()
                .map(|error| error.to_string())
        );
    }
    assert!(serde_error_storage(usize::MAX).is_err());
    assert_eq!(
        serde_error_storage(usize::MAX)
            .err()
            .map(|error| error.to_string()),
        original::serde_error_storage(usize::MAX)
            .err()
            .map(|error| error.to_string())
    );
    // A numeric layout record has no type/owner authority; the pure checked
    // arithmetic must still refuse an overflowing caller-supplied extent.
    let overflowing = shared::AckFixedLayoutData {
        response_body_bytes: usize::MAX,
        ..ACK_FIXED_LAYOUT
    };
    assert!(shared::successful_ack_storage(&overflowing).is_err());
    assert!(shared::open_ack_storage(1, &overflowing).is_err());
}

#[test]
fn actual_new_facts_and_forwarding_windows_are_separate_from_old_counter_terms() {
    let loan = size_of::<&shared::AckFixedLayoutData>();
    assert_eq!(
        shared::open_ack_lifetime_counter_scratch_data(),
        original::open_ack_lifetime_counter_scratch_data() + 2 * loan
    );
    assert_eq!(
        shared::native_original_open_ack_counter_scratch_data(),
        original::native_original_open_ack_counter_scratch_data() + 4 * loan
    );
    assert_eq!(
        open_ack_lifetime_counter_scratch_data(),
        shared::open_ack_lifetime_counter_scratch_data()
            + loan
            + size_of::<Result<OpenAckLifetimeStorageData, ProviderError>>()
            + size_of::<usize>()
    );
    assert_eq!(
        native_original_open_ack_counter_scratch_data(),
        shared::native_original_open_ack_counter_scratch_data()
            + loan
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<OpenAckLifetimeStorageData, ProviderError>>()
            + size_of::<usize>()
    );
    assert_eq!(
        Connection::<crate::client::DeadlineStream>::original_packet_prefix_quote_scratch_bytes_data(),
        original::original_packet_prefix_quote_scratch_bytes_data()
            + PREFIX_ACK_COUNTER_ADDITIONAL
            + super::super::FRAME_CHARGE_ADAPTER_COUNTER_SCRATCH_DATA
            + 2 * size_of::<&crate::reference_packet::control::PacketControlReply>()
    );
}
