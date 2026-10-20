//! Compares the real original-report consumer with independent full old bodies.

use super::super::*;
use super::{counter_scratch_data, original};
use crucible_node_format::{Bytes, U64};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

type TestResult = Result<(), TestError>;

fn geometry_launch() -> Result<PacketNative5SourceLaunch, serde_json::Error> {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // This is geometry-only launch DATA from the actual canonical fixture.
    // Empty program events do not assert native launch or report admission.
    let mut launch: PacketNative5SourceLaunch = serde_json::from_value(json!({
        "schema_version":5,"selection":selection,
        "program":{"kind":"producer","program":{"schema":"source-owned.packet-program.v1","events":[]}},
        "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
        "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
        "limits":{"frame_bytes":"65536","nesting":"64","requests":"256","journal_entries":"4096","blob_chunk_bytes":"1024"},
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
        "effects":"/not-opened-by-report-layout-control"
    }))?;
    launch.capture_profile =
        crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 {
            native_before_protocol_bytes: U64::new(65536),
            native_after_protocol_bytes: U64::new(65536),
            host_protocol_bytes: U64::new(65536),
        };
    launch.capture_allocation_selection = Some(crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12);
    launch.ack_emitter_selection =
        Some(crate::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
    launch.native_codec_metadata_extent =
        Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB);
    launch.protocol_metadata_limits = Some(
        crate::reference_packet::service::PacketNative5ProtocolMetadataLimits {
            native_before_rows: U64::new(64),
            native_after_rows: U64::new(64),
        },
    );
    Ok(launch)
}

fn receive_components(launch: &PacketNative5SourceLaunch) -> Result<(usize, usize), ProviderError> {
    let receive = crate::connection::original_report_query_receive_storage_data(
        launch,
        PacketNativeReportStartupPurpose::OriginalObserve12,
    )?;
    Ok((receive.requested_bytes()?, crate::connection::OriginalPacketPrefixStorageData::native_observe_returned_query_storage_data(&receive)?))
}

fn outcome(
    result: Result<PacketNativeReportStartupStorageData, ProviderError>,
) -> Result<[usize; 2], String> {
    result
        .map(|data| {
            [
                data.retained_growth_bytes,
                data.maximum_simultaneous_transient_bytes,
            ]
        })
        .map_err(|error| format!("{error:?}; {error}"))
}

#[test]
fn actual_original_report_layout_consumer_keeps_full_dynamic_quote_and_new_counter_headers()
-> TestResult {
    let mut launch = geometry_launch()?;
    for chunk in [1024, 4096] {
        launch.limits.blob_chunk_bytes = U64::new(chunk);
        let shapes = observe::project(&launch, MAXIMUM_COMPILED_PROJECTION_BYTES)?;
        let (receive, query) = receive_components(&launch)?;
        let old = original::quote(&launch, &shapes, receive, query)?;
        let actual = super::super::original(&launch, &shapes, receive, query)?;

        assert_eq!(actual.retained_growth_bytes, old.retained_growth_bytes);
        assert_eq!(
            actual.maximum_simultaneous_transient_bytes,
            old.maximum_simultaneous_transient_bytes
        );
        // The typed fixed aggregation bank grows from47 to48 real usize slots.
        let expected_counter = sum(&[
            original::counter_scratch_data(),
            counter_scratch_data(),
            size_of::<usize>(),
        ])?;
        assert_eq!(actual.declared_counter_scratch_bytes, expected_counter);
        assert_eq!(layout::counter_output_data(), expected_counter);
        assert_eq!(
            layout::capture_owner_bytes_data(),
            crate::reference_packet::endpoint::original_capture_report_owner_layout_data()
        );
        let fixed = layout::project();
        assert_eq!(
            fixed.produced_receipt_bytes,
            size_of::<crate::reference_packet::control::ProducedOriginalObserveReceipt>()
        );
        assert_eq!(
            fixed.observe_result_bytes,
            size_of::<crate::bodies::ObserveResult>()
        );
        assert_eq!(
            fixed.observation_batch_bytes,
            size_of::<crucible_node_format::ObservationBatch>()
        );
        assert_eq!(fixed.capture_report_bytes, size_of::<crate::reference_packet::service::capture_allocation::PacketNativeCaptureAllocationReport>());
        assert_eq!(fixed.content_ref_bytes, size_of::<ContentRef>());
        assert_eq!(
            fixed.content_entry_bytes,
            size_of::<(ContentRef, Vec<u8>)>()
        );
        assert_eq!(fixed.hasher_bytes, size_of::<blake3::Hasher>());
    }
    Ok(())
}

#[test]
fn original_report_prefix_selection_and_limit_refusals_keep_original_diagnostics() -> TestResult {
    let launch = geometry_launch()?;
    let shapes = observe::project(&launch, MAXIMUM_COMPILED_PROJECTION_BYTES)?;
    let (receive, query) = receive_components(&launch)?;
    let changes: &[fn(&mut PacketNative5SourceLaunch)] = &[
        |launch| launch.capture_allocation_selection = None,
        |launch| launch.ack_emitter_selection = None,
        |launch| launch.protocol_metadata_limits = None,
        |launch| launch.native_codec_metadata_extent = None,
        |launch| launch.selection.realization.bindings.clear(),
        |launch| launch.selection.realization.owner_bindings.clear(),
        |launch| launch.limits.frame_bytes = U64::new(0),
    ];
    for change in changes {
        let mut changed = geometry_launch()?;
        change(&mut changed);
        assert!(original::quote(&changed, &shapes, receive, query).is_err());
        assert_eq!(
            outcome(super::super::original(&changed, &shapes, receive, query)),
            outcome(original::quote(&changed, &shapes, receive, query))
        );
    }
    Ok(())
}
