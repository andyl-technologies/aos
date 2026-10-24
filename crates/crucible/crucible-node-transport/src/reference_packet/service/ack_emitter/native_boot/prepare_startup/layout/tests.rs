//! Compares the connected layout consumer with the full independent old quote.

use super::super::*;
use super::{counter_scratch_data, original};
use crate::client::DeadlineStream;
use crucible_node_format::{Bytes, canonical};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] crucible_node_format::ContractError),
}

type TestResult = Result<(), TestError>;

fn geometry_launch() -> Result<PacketNative5SourceLaunch, serde_json::Error> {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // This is geometry-only DTO DATA. Empty program events are not a valid
    // native launch, admission, Source or successful Prepare construction.
    serde_json::from_value(json!({
        "schema_version":5,"selection":selection,
        "program":{"kind":"producer","program":{"schema":"source-owned.packet-program.v1","events":[]}},
        "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
        "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
        "limits":{"frame_bytes":"65536","nesting":"64","requests":"64","journal_entries":"256","blob_chunk_bytes":"1024"},
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
        "effects":"/not-opened-by-prepare-layout-control"
    }))
}

fn components(data: &PacketNativePrepareStartupStorageData) -> [usize; 6] {
    [
        data.retained_growth_bytes,
        data.maximum_simultaneous_transient_bytes,
        data.authority_clone_bytes,
        data.maximum_features,
        data.maximum_original_bytes,
        data.maximum_body_bytes,
    ]
}

#[test]
fn actual_prepare_layout_consumer_preserves_original_components_and_prices_new_headers()
-> TestResult {
    let mut launch = geometry_launch()?;
    launch.complete_restore_selection =
        Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
    launch.protocol_metadata_limits = Some(
        crate::reference_packet::service::PacketNative5ProtocolMetadataLimits {
            native_before_rows: U64::new(64),
            native_after_rows: U64::new(64),
        },
    );

    for frame_bytes in [1, 1024, 65_536] {
        launch.limits.frame_bytes = U64::new(frame_bytes);
        let bank = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
        let old = original::quote(&launch, &bank)?;
        let actual = original_native_prepare_startup_storage_data(&launch, &bank)?;

        assert_eq!(components(&actual), components(&old));
        // The layout supplier and verifier each add an aggregation-array slot.
        // The verifier additionally retains both input headers and its scalar
        // counter result. Existing R/T components above must remain identical.
        let expected_counter = sum(&[
            original::counter_scratch_data(),
            counter_scratch_data(),
            2 * size_of::<OriginalCompleteRestorePrepareInputsData<'static, DeadlineStream>>(),
            3 * size_of::<usize>(),
        ])?;
        assert_eq!(actual.declared_counter_scratch_bytes, expected_counter);
        assert_eq!(layout::counter_output_data(), expected_counter);
        assert_eq!(
            layout::response_owner_bytes_data(),
            Connection::<crate::client::DeadlineStream>::original_prepare_response_owner_layout_data()
        );
    }
    Ok(())
}

#[test]
fn original_prepare_selection_limits_and_encoded_extent_refusals_remain_identical() -> TestResult {
    let mut launch = geometry_launch()?;
    let encoded = b"{}";
    assert!(original::quote(&launch, encoded).is_err());
    assert_eq!(
        original::quote(&launch, encoded)
            .err()
            .map(|error| error.to_string()),
        original_native_prepare_startup_storage_data(&launch, encoded)
            .err()
            .map(|error| error.to_string())
    );
    launch.complete_restore_selection =
        Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
    launch.protocol_metadata_limits = Some(
        crate::reference_packet::service::PacketNative5ProtocolMetadataLimits {
            native_before_rows: U64::new(64),
            native_after_rows: U64::new(64),
        },
    );

    for frame_bytes in [0, 65_537] {
        launch.limits.frame_bytes = U64::new(frame_bytes);
        assert!(original::quote(&launch, encoded).is_err());
        assert_eq!(
            original::quote(&launch, encoded)
                .err()
                .map(|error| error.to_string()),
            original_native_prepare_startup_storage_data(&launch, encoded)
                .err()
                .map(|error| error.to_string())
        );
    }
    launch.limits.frame_bytes = U64::new(65_536);
    let too_large = vec![b' '; 1024 * 1024 + 1];
    for bytes in [b"".as_slice(), too_large.as_slice()] {
        assert!(original::quote(&launch, bytes).is_err());
        assert_eq!(
            original::quote(&launch, bytes)
                .err()
                .map(|error| error.to_string()),
            original_native_prepare_startup_storage_data(&launch, bytes)
                .err()
                .map(|error| error.to_string())
        );
    }
    Ok(())
}
