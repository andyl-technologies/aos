//! Checks the real selected report quote against full independent old bodies.

use super::aggregation_original as original;
use super::*;
use crucible_node_format::{Bytes, ContentRef, Id, U64};
use crucible_source_birth_data::profile::reference_packet::service::native_startup::original_report;
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

fn components(launch: &PacketNative5SourceLaunch) -> Result<(usize, usize), ProviderError> {
    let receive = crate::connection::original_report_query_receive_storage_data(
        launch,
        PacketNativeReportStartupPurpose::OriginalObserve12,
    )?;
    Ok((receive.requested_bytes()?, crate::connection::OriginalPacketPrefixStorageData::native_observe_returned_query_storage_data(&receive)?))
}

fn signature(
    result: Result<PacketNativeReportStartupStorageData, ProviderError>,
) -> Result<[usize; 2], String> {
    result
        .map(|data| {
            [
                data.retained_growth_bytes(),
                data.maximum_simultaneous_transient_bytes(),
            ]
        })
        .map_err(|error| format!("{error:?}; {error}"))
}

#[test]
fn actual_selected_geometry_preserves_complete_original_aggregation() -> TestResult {
    for chunk in [1024, 4096] {
        let mut launch = geometry_launch()?;
        launch.limits.blob_chunk_bytes = U64::new(chunk);
        let shapes = observe::project(&launch, MAXIMUM_COMPILED_PROJECTION_BYTES)?;
        let (receive, query) = components(&launch)?;
        let expected = original::quote(&launch, &shapes, receive, query)?;
        let actual = super::original(&launch, &shapes, receive, query)?;

        assert_eq!(
            actual.retained_growth_bytes(),
            expected.retained_growth_bytes()
        );
        assert_eq!(
            actual.maximum_simultaneous_transient_bytes(),
            expected.maximum_simultaneous_transient_bytes()
        );
        assert_eq!(actual.raw_report_capacity(), expected.raw_report_capacity());
        assert_eq!(
            expected.declared_counter_scratch_bytes(),
            layout::counter_output_data()
        );
        assert_eq!(
            actual.declared_counter_scratch_bytes(),
            sum(&[
                original::counter_scratch_data(),
                original_report::AGGREGATION_COUNTER_SCRATCH_DATA,
                size_of::<usize>(),
            ])?
        );
    }
    Ok(())
}

#[test]
fn synthetic_two_tree_population_uses_actual_independent_key_and_value_layouts() -> TestResult {
    use std::mem::align_of;
    use crucible_source_birth_data::profile::reference_packet::service::native_startup::original_report::cache_tree_backing_data;
    type CacheValue = (
        crucible_node_format::HashRef,
        crate::reference_packet::control::PacketControlReply,
    );
    let actual = layout::cache_tree_layout_data();
    let mut old = MetadataObserver::new();
    old.tree::<ContentRef, Vec<u8>>(4)?;
    old.tree::<Id, CacheValue>(1)?;
    let expected =
        crate::retained_metadata::requested_metadata_backing_storage_data(&old.finish())?;

    assert_eq!(actual.key_bytes, size_of::<Id>());
    assert_eq!(actual.value_bytes, size_of::<CacheValue>());
    assert_eq!(actual.key_alignment, align_of::<Id>());
    assert_eq!(actual.value_alignment, align_of::<CacheValue>());
    assert_eq!(cache_tree_backing_data(&actual)?, expected);
    let mut changed = actual;
    changed.value_bytes = usize::MAX;
    assert!(cache_tree_backing_data(&changed).is_err());
    changed = actual;
    changed.value_alignment = usize::MAX;
    assert!(cache_tree_backing_data(&changed).is_err());
    Ok(())
}

#[test]
fn original_early_failures_and_single_binding_guard_keep_error_order() -> TestResult {
    let launch = geometry_launch()?;
    let shapes = observe::project(&launch, MAXIMUM_COMPILED_PROJECTION_BYTES)?;
    let (receive, query) = components(&launch)?;
    let changes: &[fn(&mut PacketNative5SourceLaunch)] = &[
        |launch| launch.capture_allocation_selection = None,
        |launch| launch.ack_emitter_selection = None,
        |launch| launch.protocol_metadata_limits = None,
        |launch| launch.native_codec_metadata_extent = None,
        |launch| launch.selection.realization.owner_bindings.clear(),
        |launch| {
            let binding = launch.selection.realization.owner_bindings[0].clone();
            launch.selection.realization.owner_bindings.push(binding);
        },
        |launch| launch.limits.frame_bytes = U64::new(0),
    ];
    for change in changes {
        let mut changed = geometry_launch()?;
        change(&mut changed);
        let expected = original::quote(&changed, &shapes, receive, query)
            .map(|data| {
                [
                    data.retained_growth_bytes(),
                    data.maximum_simultaneous_transient_bytes(),
                ]
            })
            .map_err(|error| format!("{error:?}; {error}"));

        assert!(expected.is_err());
        assert_eq!(
            signature(super::original(&changed, &shapes, receive, query)),
            expected
        );
    }
    Ok(())
}
