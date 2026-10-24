//! Compares the actual shared normalization stages with the full old producer.

use super::*;
use crucible_node_format::{Bytes, Id, canonical};
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

fn outcome(value: Result<AdmitStorage, ProviderError>) -> Result<[usize; 3], String> {
    value
        .map(|data| [data.retained, data.transient, data.scratch])
        .map_err(|error| format!("{error:?};{error}"))
}

fn old_outcome(value: Result<original::AdmitStorage, ProviderError>) -> Result<[usize; 3], String> {
    value
        .map(|data| [data.retained, data.transient, data.scratch])
        .map_err(|error| format!("{error:?};{error}"))
}

#[test]
fn staged_normalization_keeps_actual_private_geometry_and_old_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let mut launch = launch()?;
    // The original typed fixture already has its one executable artifact.
    // Its independent native measurement/authority is not claimed here.
    let encoded = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
    let mut source = serde_json::Map::new();
    for name in [
        "selection",
        "program",
        "coordinator",
        "limits",
        "storage",
        "capture_profile",
        "confirmation_selection",
        "ack_emitter_selection",
        "codec_metadata_extent",
        "native_codec_metadata_extent",
        "protocol_metadata_limits",
        "complete_restore_selection",
        "restore_input_emitter_selection",
        "capture_allocation_selection",
        "fresh_restore_allocation_selection",
        "report_startup_allocation",
        "native_startup_allocation",
    ] {
        source.insert(name.into(), serde_json::Value::Null);
    }
    source.insert("schema".into(), json!(crate::reference_packet::service::native_startup::PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA));
    let source = canonical::canonical_json(&serde_json::Value::Object(source))?;
    let private_id = Id::new("admit-geometry-original-private")?;
    let input = PacketNativeBirthStartupInputs {
        launch: &launch,
        private_launch: &private_id,
        encoded_launch: &encoded,
        source_birth: &source,
        host_registration: b"{}",
    };
    // Use the real preceding shape producer, not caller-supplied final rows.
    // This does not claim these inert base Values authenticate a Source bank.
    let private = private_bootstrap::project(&input, usize::MAX)?;
    let actual = project(&input, &private, usize::MAX)?;
    let expected = original::project(&input, &private, usize::MAX)?;
    assert_eq!(
        [actual.retained, actual.transient, actual.scratch],
        [expected.retained, expected.transient, expected.scratch]
    );
    assert!(actual.retained > 0 && actual.transient > 0 && actual.scratch > 0);

    for maximum in [0, 1, 65_536, actual.retained - 1, usize::MAX] {
        assert_eq!(
            outcome(project(&input, &private, maximum)),
            old_outcome(original::project(&input, &private, maximum))
        );
    }
    for registration in [b"".as_slice(), b"{".as_slice(), b"[]".as_slice()] {
        let changed = PacketNativeBirthStartupInputs {
            host_registration: registration,
            ..input
        };
        assert_eq!(
            outcome(project(&changed, &private, usize::MAX)),
            old_outcome(original::project(&changed, &private, usize::MAX))
        );
    }
    let executable = launch
        .selection
        .provider
        .implementation
        .artifacts
        .iter()
        .find(|artifact| artifact.role.as_str() == "executable")
        .ok_or("geometry fixture has no executable row")?
        .clone();
    for count in [0, 2] {
        launch
            .selection
            .provider
            .implementation
            .artifacts
            .retain(|artifact| artifact.role.as_str() != "executable");
        launch
            .selection
            .provider
            .implementation
            .artifacts
            .extend(std::iter::repeat_n(executable.clone(), count));
        let encoded = canonical::canonical_json(&serde_json::to_value(&launch)?)?;
        let changed = PacketNativeBirthStartupInputs {
            launch: &launch,
            private_launch: &private_id,
            encoded_launch: &encoded,
            source_birth: &source,
            host_registration: b"{}",
        };
        let private = private_bootstrap::project(&changed, usize::MAX)?;
        let actual = outcome(project(&changed, &private, usize::MAX));
        assert!(actual.is_err());
        assert_eq!(
            actual,
            old_outcome(original::project(&changed, &private, usize::MAX))
        );
    }
    assert!(original_native_birth_startup_counter_scratch_data() >= adapter_counter_scratch_data());
    Ok(())
}
