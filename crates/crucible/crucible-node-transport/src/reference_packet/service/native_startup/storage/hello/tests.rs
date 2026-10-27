//! Compares real Hello queries with the independent complete original producer.

use super::*;
use crucible_node_format::{Bytes, Id, U64};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

fn facts<T: crate::retained_metadata::ObserveMetadata + ?Sized>(
    value: &T,
) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(value)?;
    Ok(observer.finish())
}

fn lower(
    launch: &PacketNative5SourceLaunch,
    raw: crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
    maximum: usize,
) -> Result<HelloStorage, ProviderError> {
    let provider = facts(&launch.selection.provider)?;
    let guarantees = if let [binding] = launch.selection.realization.bindings.as_slice() {
        Some(facts(&binding.compatibility.guarantees_ref)?)
    } else {
        None
    };
    let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
    hello_shapes::project_with_raw(
        &fields,
        b"{}",
        raw,
        &original_native_hello_fixed_layout_data(),
        &provider,
        guarantees.as_ref(),
        maximum,
    )
}

fn outcome(result: Result<HelloStorage, ProviderError>) -> Result<[usize; 3], String> {
    result
        .map(|row| [row.retained, row.transient, row.scratch])
        .map_err(|error| format!("{error:?}; {error}"))
}

#[test]
fn original_hello_shared_arithmetic_keeps_every_old_phase_and_genuine_fixed_getter() -> TestResult {
    let mut launch = geometry_launch()?;
    for more_features in [false, true] {
        if more_features {
            for number in 0..24 {
                launch
                    .selection
                    .provider
                    .extensions_supported
                    .push(Id::new(format!("hello-extra-{number}"))?);
            }
        }
        for extent in [64, 1024, NATIVE_HELLO_BYTES] {
            let raw = original_json_value_storage_extent_data(extent)?;
            let old = original::project_with_raw(&launch, b"{}", raw, usize::MAX)?;
            let actual = project_with_raw(&launch, b"{}", raw, usize::MAX)?;
            let child = lower(&launch, raw, usize::MAX)?;
            assert_eq!(actual.retained, old.retained);
            assert_eq!(actual.transient, old.transient);
            assert_eq!(
                actual.scratch,
                old.scratch + hello_shapes::additional_counter_scratch_data()
            );
            assert_eq!(
                [child.retained, child.transient, child.scratch],
                [actual.retained, actual.transient, actual.scratch]
            );
            assert_eq!(
                hello_selection::feature_count_bound(&launch.selection.provider)?,
                (launch.selection.provider.extensions_supported.len() + 2).max(19)
            );
        }
    }
    // Bind the actual function signature before naming all three live inputs.
    let _validation: fn(usize, usize, usize) -> Result<usize, ProviderError> =
        hello_shapes::validation_backing;
    let helper_inputs = size_of::<usize>() // nodes
        + size_of::<usize>() // slots
        + size_of::<usize>(); // maximum
    let expected_headers = 3 * size_of::<PacketNative5LaunchValidationFields<'static>>()
        + 2 * size_of::<&PacketNative5LaunchValidationFields<'static>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + 2 * size_of::<&hello_shapes::HelloHeaderLayoutData>()
        + 2 * size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + 2 * size_of::<&mut crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + 2 * size_of::<Result<(), ProviderError>>()
        + 3 * size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + helper_inputs
        + size_of::<[usize; 2]>()
        + size_of::<usize>()
        + size_of::<&hello_shapes::HelloFixedLayoutData>()
        + size_of::<&crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<Option<&crate::retained_metadata::RetainedProtocolMetadataFacts>>();
    assert_eq!(
        hello_shapes::additional_counter_scratch_data(),
        expected_headers
    );

    let fixed = original_native_hello_fixed_layout_data();
    assert_eq!(fixed.headers.hello_request_bytes, size_of::<HelloRequest>());
    assert_eq!(
        fixed.headers.resume_session_bytes,
        size_of::<ResumeSession>()
    );
    assert_eq!(
        fixed.headers.extension_offer_bytes,
        size_of::<crate::handshake::ExtensionOfferV1>()
    );
    assert_eq!(
        fixed.headers.extension_selection_bytes,
        size_of::<crate::handshake::ExtensionSelectionV1>()
    );
    assert_eq!(
        fixed.headers.connection_authority_bytes,
        size_of::<crate::handshake::ConnectionAuthority>()
    );
    assert_eq!(fixed.headers.hello_result_bytes, size_of::<HelloResult>());
    assert_eq!(
        fixed.headers.metadata_observer_bytes,
        size_of::<MetadataObserver<'static>>()
    );
    assert_eq!(
        fixed.hello_selection_counter_scratch_bytes,
        hello_selection::counter_scratch_data()
    );
    assert_eq!(
        fixed.hello_reuse_counter_scratch_bytes,
        crate::handshake::Handshake::original_native_hello_reuse_counter_scratch_data()
    );
    assert_eq!(
        original_native_hello_fixed_layout_counter_scratch_data(),
        hello_shapes::fixed_layout_export_counter_scratch_data()
    );
    Ok(())
}

#[test]
fn original_hello_exact_limit_one_short_and_first_binding_refusal_stay_real() -> TestResult {
    let launch = geometry_launch()?;
    let raw = original_json_value_storage_extent_data(1024)?;
    let actual = project_with_raw(&launch, b"{}", raw, usize::MAX)?;
    let exact = actual.retained.max(actual.transient).max(actual.scratch);
    assert_eq!(
        outcome(project_with_raw(&launch, b"{}", raw, exact)),
        outcome(lower(&launch, raw, exact))
    );
    project_with_raw(&launch, b"{}", raw, exact)?;
    assert!(project_with_raw(&launch, b"{}", raw, exact - 1).is_err());
    assert_eq!(
        outcome(project_with_raw(&launch, b"{}", raw, exact - 1)),
        outcome(lower(&launch, raw, exact - 1))
    );
    for maximum in [0, 1] {
        let old = original::project_with_raw(&launch, b"{}", raw, maximum)
            .map_err(|error| format!("{error:?}; {error}"));
        let actual = outcome(project_with_raw(&launch, b"{}", raw, maximum));
        assert!(old.is_err());
        assert_eq!(actual.as_ref().err(), old.as_ref().err());
    }
    let mut missing = geometry_launch()?;
    missing.selection.realization.bindings.clear();
    for maximum in [0, usize::MAX] {
        let old = original::project_with_raw(&missing, b"{}", raw, maximum)
            .map_err(|error| format!("{error:?}; {error}"));
        let actual = outcome(project_with_raw(&missing, b"{}", raw, maximum));
        assert!(old.is_err());
        assert_eq!(actual.as_ref().err(), old.as_ref().err());
        assert_eq!(actual, outcome(lower(&missing, raw, maximum)));
    }
    Ok(())
}

#[test]
fn original_hello_synthetic_populations_keep_actual_typed_observer_arithmetic() -> TestResult {
    for (nodes, slots) in [
        (0, 0),
        (1, 260),
        (32768, 131328),
        (usize::MAX, 1),
        (1, usize::MAX),
    ] {
        let old = (|| {
            let mut observer = MetadataObserver::new();
            observer.tree::<&Id, ()>(nodes)?;
            observer.tree::<&String, ()>(nodes)?;
            observer.vector::<&Id>(slots)?;
            sum(
                &[
                    requested_metadata_backing_storage_data(&observer.finish())?,
                    4096,
                ],
                usize::MAX,
            )
        })();
        assert_eq!(
            hello_shapes::validation_backing(nodes, slots, usize::MAX)
                .map_err(|error| format!("{error:?}; {error}")),
            old.map_err(|error| format!("{error:?}; {error}"))
        );
    }
    for capacity in [0, 42, usize::MAX] {
        let old = (|| {
            let mut observer = MetadataObserver::new();
            for _ in 0..6 {
                observer.vector::<Id>(capacity)?;
            }
            requested_metadata_backing_storage_data(&observer.finish())
        })();
        assert_eq!(
            hello_shapes::roster_backing(capacity).map_err(|error| format!("{error:?}; {error}")),
            old.map_err(|error| format!("{error:?}; {error}"))
        );
    }
    Ok(())
}

#[test]
fn original_hello_capacity_observations_are_not_replaced_by_equal_decoded_content() -> TestResult {
    let mut launch = geometry_launch()?;
    let encoded = serde_json::to_vec(&launch.selection.provider)?;
    let before = facts(&launch.selection.provider)?;
    let additional = launch
        .selection
        .provider
        .protocol_versions
        .capacity()
        .checked_add(128)
        .ok_or_else(refused)?;
    launch
        .selection
        .provider
        .protocol_versions
        .try_reserve(additional)?;
    let after = facts(&launch.selection.provider)?;
    assert_eq!(serde_json::to_vec(&launch.selection.provider)?, encoded);
    assert!(after.vector_capacity_bytes > before.vector_capacity_bytes);
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused().into());
    };
    let guarantees = facts(&binding.compatibility.guarantees_ref)?;
    let fields = PacketNative5LaunchValidationFields::from_launch_data(&launch);
    let fixed = original_native_hello_fixed_layout_data();
    let raw = original_json_value_storage_extent_data(1024)?;
    let stale = hello_shapes::project_with_raw(
        &fields,
        b"{}",
        raw,
        &fixed,
        &before,
        Some(&guarantees),
        usize::MAX,
    )?;
    let actual = project_with_raw(&launch, b"{}", raw, usize::MAX)?;
    assert!(actual.retained > stale.retained);
    // These public facts do not authenticate provenance. Parent/Job same-original
    // commitment and remeasurement are a separate prerequisite, not this test.
    let missing =
        hello_shapes::project_with_raw(&fields, b"{}", raw, &fixed, &after, None, usize::MAX);
    assert!(missing.is_err());
    let mut excessive = original_native_hello_fixed_layout_data();
    excessive.headers.metadata_observer_bytes = usize::MAX;
    assert!(
        hello_shapes::project_with_raw(
            &fields,
            b"{}",
            raw,
            &excessive,
            &after,
            Some(&guarantees),
            usize::MAX
        )
        .is_err()
    );
    Ok(())
}
