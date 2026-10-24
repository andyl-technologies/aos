//! Checks the genuine selected schema producer against its full prior schedule.

use super::*;
use crucible_node_format::{Bytes, U64};
use serde_json::json;

fn launch() -> Result<PacketNative5SourceLaunch, serde_json::Error> {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // This is a real typed geometry fixture, not a full validated launch or
    // Source/native authority. Geometry does not authenticate its world/program.
    serde_json::from_value(json!({
        "schema_version":5,"selection":selection,
        "program":{"kind":"producer","program":{"schema":"source-owned.packet-program.v1","events":[]}},
        "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
        "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
        "limits":{"frame_bytes":"65536","nesting":"64","requests":"64","journal_entries":"256","blob_chunk_bytes":"1024"},
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
        "effects":"/not-opened-by-initial-shape-control"
    }))
}
fn original_birth_counter_scratch_data() -> usize {
    size_of::<crate::reference_packet::service::ack_emitter::OriginalNativeBirthReadScope<'static>>()
        + crate::reference_packet::control::PacketControl::original_native_birth_selection_counter_scratch_data()
        + crate::reference_packet::service::native_startup::data_equality::counter_scratch_data()
        + invocation_ingress_counter_scratch_data()
        + retained_overlap::counter_scratch_data()
        + coordinator_decode::counter_scratch_data()
        + decoded::counter_scratch_data()
        + fixed_layout::counter_scratch_data()
        + initial::original_initial_literal_shape_counter_scratch_data()
        + private_bootstrap::literal_shape_counter_scratch_data()
        + launch_validation_counter_scratch_data()
        + crate::reference_packet::Native5Policy::CONSTRUCTION_ADAPTER_SCRATCH_DATA
        // Exact lower restore-input aggregate initializer and owned callee input.
        + 2 * size_of::<crucible_source_birth_data::profile::reference_packet::service::native5_policy::Native5CompleteRestorePolicyInput>()
        + launch_validation::counter_scratch_data()
        + launch_decode::counter_scratch_data()
        + crate::reference_packet::service::native_startup::pre_dom::counter_scratch_data()
        // Complete return views coexist with the named payload/observer rows:
        // edition transpose, actual Hello phase, and exhaustive launch facts.
        // Canonical private bank growth: checked full/spare scalar views.
        + size_of::<[usize; 3]>()
        + size_of::<Result<usize, ProviderError>>()
        // Selected phase cap and occurrence-based partial native DTO view.
        + 2 * size_of::<bool>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 4]>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<Option<bool>, ProviderError>>()
        + size_of::<Result<hello::HelloStorage, ProviderError>>()
        // Private second-frame projection retains its independent raw extent
        // beside the original max-raw result and nested helper views.
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>()
        + 3 * size_of::<decoded::DecodedStorage>()
        + size_of::<[usize; 12]>()
        + crate::handshake::Handshake::original_native_hello_reuse_counter_scratch_data()
        + crate::protocol_snapshot::owned11::correspondence::envelope_counter_scratch_data()
        + size_of::<PacketNativeBirthStartupStorageData>()
        + size_of::<PacketNativeBirthStartupInputs<'_>>()
        // The defining launch observer includes its complete borrowed field
        // views beside the observer and returned facts. Both Core and native
        // admit this same fixed window before the exhaustive launch walk.
        + crate::retained_metadata::retained_native_launch_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + crate::reference_packet::service::complete_restore::transfer::selected_issuer_decode_counter_scratch_data()
        + size_of::<InitialCounterLocals>()
        + crate::connection::original_packet_prefix_startup_counter_scratch_data()
        + crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes()
        // The closed once-Admit outer projector holds association, kernel and
        // policy counters together; this precedes any native constructor.
        + 3 * size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection>()
        + 5 * size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>()
        + size_of::<[u8; 20]>()
        + size_of::<[u8; 64]>()
        // The known launch/program serializers can format a Bytes leaf before
        // reaching the event sink. Its base64 spelling is a substring of this
        // same authenticated canonical launch, bounded by the launch grammar.
        + PRIVATE_LAUNCH_BYTES
        + crate::reference_packet::service::ack_emitter::original_native_restoration_activation_counter_scratch_data()
}

fn outcome(value: Result<InitialSchemaStorage, ProviderError>) -> Result<[usize; 2], String> {
    value
        .map(|value| [value.transient, value.retained_reference_children])
        .map_err(|error| format!("{error:?};{error}"))
}

fn original_outcome(
    value: Result<original::InitialSchemaStorage, ProviderError>,
) -> Result<[usize; 2], String> {
    value
        .map(|value| [value.transient, value.retained_reference_children])
        .map_err(|error| format!("{error:?};{error}"))
}

#[test]
fn actual_schema_schedule_preserves_every_selector_and_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::reference_packet::service::{
        PacketNative5AckEmitterSelection as Ack,
        PacketNative5ConfirmationSelection as Confirmation,
        capture_allocation::PacketNative5CaptureAllocationSelection as Capture,
        complete_restore::{
            PacketNative5CompleteRestoreSelection as Restore,
            PacketNative5RestoreInputEmitterSelection as Input,
        },
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection as Fresh,
    };
    for selectors in 0..32 {
        for restore in [
            None,
            Some(Restore::SourceSignedOwned11),
            Some(Restore::SourceSignedTransfer12),
        ] {
            let mut launch = launch()?;
            launch.confirmation_selection =
                (selectors & 1 != 0).then_some(Confirmation::AfterProtocolPoll5);
            launch.ack_emitter_selection = (selectors & 2 != 0).then_some(Ack::CanonicalSdkBlob5);
            launch.restore_input_emitter_selection =
                (selectors & 4 != 0).then_some(Input::CanonicalSdkRestoreInputs12);
            launch.capture_allocation_selection =
                (selectors & 8 != 0).then_some(Capture::OriginalObserve12);
            launch.fresh_restore_allocation_selection =
                (selectors & 16 != 0).then_some(Fresh::CompletedAdmit13);
            launch.complete_restore_selection = restore;
            for maximum in [0, 1, 64, 65_536, usize::MAX] {
                assert_eq!(
                    outcome(project(&launch, maximum)),
                    original_outcome(original::project(&launch, maximum))
                );
            }
        }
    }
    Ok(())
}

#[test]
fn actual_schema_transient_has_exact_and_one_short_control()
-> Result<(), Box<dyn std::error::Error>> {
    let launch = launch()?;
    let quoted = project(&launch, usize::MAX)?;
    let exact = quoted.transient;
    assert_eq!(
        outcome(project(&launch, exact)),
        original_outcome(original::project(&launch, exact))
    );
    assert_eq!(project(&launch, exact)?.transient, exact);
    assert!(project(&launch, exact.checked_sub(1).ok_or("schema extent absent")?).is_err());
    Ok(())
}

#[test]
fn actual_schema_adapter_is_added_to_original_defining_counter() {
    // The saved whole counter predates Schema, Admit, Hello and private backing.
    // Each adapter contributes its genuine defining row; keep the Schema-only
    // header assertion below independent of this composition.
    assert_eq!(
        original_native_birth_startup_counter_scratch_data(),
        original_birth_counter_scratch_data()
            // Both claim paths now retain the terminal origin-check views.
            + size_of::<&mut bool>()
            + size_of::<&std::thread::ThreadId>()
            + size_of::<&crate::operational_time::OperationalDeadline>()
            + 2 * size_of::<&str>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + 2 * size_of::<Result<(), ProviderError>>()
            + counter_scratch_data()
            + admit::adapter_counter_scratch_data()
            + super::super::super::private_backing::ADAPTER_COUNTER_SCRATCH_DATA
            + crucible_source_birth_data::profile::reference_packet::service::native_startup::hello_shapes::additional_counter_scratch_data()
    );
    assert_eq!(
        counter_scratch_data(),
        size_of::<&PacketNative5SourceLaunch>()
            + 2 * size_of::<Fields<'static>>()
            + size_of::<Fields<'static>>()
            + size_of::<&Fields<'static>>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<Result<InitialSchemaStorage, ProviderError>>()
            + size_of::<&Fields<'static>>()
            + size_of::<usize>()
            + 2 * size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<&crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<&mut crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<usize>()
            + size_of::<usize>()
    );
}
