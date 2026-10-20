//! Compares real Producer/Reactive launch fixtures with secret-free validation.
//!
//! These controls exercise original pure validation and serializer boundaries.
//! They install no Source, worker, OS budget, private File/key or native grant.

#![allow(clippy::unwrap_used)]

use super::{fixture, modeled_storage_selection, producer, reactive};
use crate::ProviderError;
use crate::reference_packet::service::{
    self, PacketConnectedSourceProgram, PacketNative5CaptureProfile,
    PacketNative5LaunchValidationFields, PacketNative5LaunchValidationProjection,
    PacketNative5PathSerializationData, PacketNative5SourceLaunch,
};
use crate::reference_service::InstalledContent;
use crucible_node_format::{Bytes, U64, canonical};
use serde_json::json;
use std::{
    io::{self, Write},
    path::PathBuf,
};

fn launch(reactive_member: bool) -> PacketNative5SourceLaunch {
    let coordinator = fixture::five();
    let member = usize::from(reactive_member);
    let program = if reactive_member {
        PacketConnectedSourceProgram::Reactive {
            program: reactive(&coordinator, member).definition().clone(),
        }
    } else {
        PacketConnectedSourceProgram::Producer {
            program: producer().definition(),
        }
    };
    let selection = coordinator.participants[member].clone();
    let bytes = canonical::canonical_json(&serde_json::to_value(coordinator).unwrap()).unwrap();
    let selected = modeled_storage_selection();
    PacketNative5SourceLaunch {
        schema_version: 5,
        selection,
        program,
        controller_pid: U64::new(1),
        controller_uid: U64::new(0),
        controller_executable: canonical::content_ref(
            b"launch projection test executable",
            "application/octet-stream",
        )
        .unwrap(),
        admission_token: Bytes::new(vec![7; 32]),
        initial_coordinator: InstalledContent {
            reference: canonical::content_ref(&bytes, "application/json").unwrap(),
            bytes: Bytes::new(bytes),
        },
        limits: selected.limits,
        storage: selected.storage,
        capture_profile: PacketNative5CaptureProfile::OriginalArrays6,
        confirmation_selection: None,
        ack_emitter_selection: None,
        native_codec_metadata_extent: None,
        protocol_metadata_limits: None,
        complete_restore_selection: None,
        restore_input_emitter_selection: None,
        capture_allocation_selection: None,
        fresh_restore_allocation_selection: None,
        effects: PathBuf::from("/unused/launch-projection-original-effect-path"),
    }
}

fn observed(value: Result<(), ProviderError>) -> Result<(), String> {
    value.map_err(|error| format!("{error:?}; {error}"))
}

fn assert_validation_parity(launch: &PacketNative5SourceLaunch) {
    let before_token = (
        launch.admission_token.as_slice().as_ptr(),
        launch.admission_token.allocation_capacity(),
    );
    let before_coordinator = (
        launch.initial_coordinator.bytes.as_slice().as_ptr(),
        launch.initial_coordinator.bytes.allocation_capacity(),
    );
    let expected = observed(launch.validate_original_for_projection_test_data());
    assert_eq!(observed(launch.validate()), expected);
    let projected = PacketNative5LaunchValidationProjection::from_launch_data(launch);
    assert_eq!(observed(projected.validate_data()), expected);
    assert_eq!(
        projected.token_length_data(),
        launch.admission_token.as_slice().len()
    );
    assert_eq!(
        (
            launch.admission_token.as_slice().as_ptr(),
            launch.admission_token.allocation_capacity()
        ),
        before_token
    );
    assert_eq!(
        (
            launch.initial_coordinator.bytes.as_slice().as_ptr(),
            launch.initial_coordinator.bytes.allocation_capacity()
        ),
        before_coordinator
    );
}

#[test]
fn real_producer_and_reactive_validator_use_the_original_schedule() {
    for reactive in [false, true] {
        let launch = launch(reactive);
        assert!(launch.validate_original_for_projection_test_data().is_ok());
        assert_validation_parity(&launch);
    }
}

#[test]
fn source_fields_refuse_with_original_first_error_and_diagnostic() {
    let changes: &[fn(&mut PacketNative5SourceLaunch)] = &[
        |launch| launch.schema_version = 4,
        |launch| launch.storage.snapshot_bytes = U64::new(0),
        |launch| launch.limits.requests = U64::new(1),
        |launch| launch.controller_pid = U64::new(0),
        |launch| launch.controller_uid = U64::new(u64::MAX),
        |launch| launch.admission_token = Bytes::new(vec![0; 31]),
        |launch| launch.initial_coordinator.bytes = Bytes::new(b"not-json".to_vec()),
        |launch| {
            let bytes = b"{malformed coordinator".to_vec();
            launch.initial_coordinator.reference =
                canonical::content_ref(&bytes, "application/json").unwrap();
            launch.initial_coordinator.bytes = Bytes::new(bytes);
        },
        |launch| {
            launch.initial_coordinator.reference.media_type = "application/octet-stream".into()
        },
        |launch| {
            if let PacketConnectedSourceProgram::Producer { program } = &mut launch.program {
                program.events[0].payload =
                    Some(Bytes::new(b"changed actual program payload".to_vec()));
            }
        },
        |launch| {
            launch.selection.realization.extensions.insert(
                "projection.literal-value".into(),
                json!({"$serde_json::private::RawValue":"null"}),
            );
        },
        |launch| {
            launch.capture_profile = PacketNative5CaptureProfile::CompactBytes7 {
                native_before_protocol_bytes: U64::new(0),
                native_after_protocol_bytes: U64::new(1),
                host_protocol_bytes: U64::new(1),
            };
        },
    ];
    for reactive in [false, true] {
        for change in changes {
            let mut launch = launch(reactive);
            change(&mut launch);
            assert_validation_parity(&launch);
        }
    }
}

fn optional_fields(launch: &mut PacketNative5SourceLaunch, mask: u16) {
    launch.confirmation_selection =
        (mask & 1 != 0).then_some(service::PacketNative5ConfirmationSelection::AfterProtocolPoll5);
    launch.ack_emitter_selection =
        (mask & 2 != 0).then_some(service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
    launch.native_codec_metadata_extent = (mask & 4 != 0)
        .then_some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB);
    launch.complete_restore_selection = (mask & 8 != 0).then_some(
        service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
    );
    launch.restore_input_emitter_selection = (mask & 16 != 0)
        .then_some(service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12);
    launch.capture_allocation_selection = (mask & 32 != 0).then_some(
        service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12,
    );
    launch.fresh_restore_allocation_selection = (mask & 64 != 0).then_some(service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13);
    launch.protocol_metadata_limits =
        (mask & 128 != 0).then_some(service::PacketNative5ProtocolMetadataLimits {
            native_before_rows: U64::new(128),
            native_after_rows: U64::new(256),
        });
}

#[test]
fn every_optional_skip_combination_has_exact_original_json_credit() {
    let mut launch = launch(false);
    for mask in 0..=255 {
        optional_fields(&mut launch, mask);
        for profile in [
            PacketNative5CaptureProfile::OriginalArrays6,
            PacketNative5CaptureProfile::CompactBytes7 {
                native_before_protocol_bytes: U64::new(1),
                native_after_protocol_bytes: U64::new(2),
                host_protocol_bytes: U64::new(3),
            },
            PacketNative5CaptureProfile::OwnedProtocol11 {
                native_before_protocol_bytes: U64::new(1),
                native_after_protocol_bytes: U64::new(2),
                host_protocol_bytes: U64::new(3),
            },
        ] {
            launch.capture_profile = profile;
            let expected = crate::connection::serialized_credit(&launch, usize::MAX).unwrap();
            let projected = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
            assert_eq!(
                projected.serialized_credit_data(expected).unwrap(),
                expected
            );
            assert!(projected.serialized_credit_data(expected - 1).is_err());
        }
    }
}

#[test]
fn selected_policy_branches_preserve_original_diagnostics() {
    for reactive in [false, true] {
        for mask in [0, 1, 3, 7, 15, 31, 63, 127, 255] {
            for owned in [false, true] {
                let mut launch = launch(reactive);
                optional_fields(&mut launch, mask);
                if owned {
                    launch.capture_profile = PacketNative5CaptureProfile::OwnedProtocol11 {
                        native_before_protocol_bytes: U64::new(1024),
                        native_after_protocol_bytes: U64::new(1024),
                        host_protocol_bytes: U64::new(1024),
                    };
                }
                assert_validation_parity(&launch);
            }
        }
    }
}

#[derive(Default)]
struct Chunks {
    used: usize,
    ends: Vec<usize>,
}

impl Write for Chunks {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used += bytes.len();
        self.ends.push(self.used);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn original_formatter_chunk_boundaries_preserve_refusal_and_complete_count() {
    let launch = launch(false);
    let mut chunks = Chunks::default();
    serde_json::to_writer(&mut chunks, &launch).unwrap();
    let projected = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
    let mut boundaries = vec![0, 1, chunks.used];
    for end in chunks.ends {
        boundaries.push(end);
        boundaries.push(end.saturating_sub(1));
    }
    boundaries.sort_unstable();
    boundaries.dedup();
    for maximum in boundaries {
        let original = crate::connection::serialized_credit(&launch, maximum)
            .map_err(|error| format!("{error:?}; {error}"));
        let actual = projected
            .serialized_credit_data(maximum)
            .map_err(|error| format!("{error:?}; {error}"));
        assert_eq!(actual, original, "maximum={maximum}");
    }
}

#[test]
fn exact_token_and_path_shapes_never_reconstruct_private_values() {
    use std::os::unix::ffi::OsStringExt;
    let mut launch = launch(false);
    for length in [0, 1, 2, 3, 31, 32, 33, 257] {
        launch.admission_token = Bytes::new((0..length).map(|index| index as u8).collect());
        for path in ["", "/quote\"/slash\\/line\n/tab\t", "/雪/\u{1f}/\0"] {
            launch.effects = PathBuf::from(path);
            let expected = crate::connection::serialized_credit(&launch, usize::MAX).unwrap();
            let projected = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
            assert_eq!(
                projected.serialized_credit_data(expected).unwrap(),
                expected
            );
            assert!(projected.serialized_credit_data(expected - 1).is_err());
        }
    }
    launch.effects = PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', 0xff]));
    launch.storage.snapshot_bytes = U64::new(0);
    launch.initial_coordinator.bytes = Bytes::new(b"malformed".to_vec());
    let projected = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
    assert_eq!(
        projected.path_serialization_data(),
        PacketNative5PathSerializationData::InvalidUtf8
    );
    assert_validation_parity(&launch);
    assert!(matches!(
        projected.validate_data(),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));
}

#[test]
fn unrepresentable_inert_shapes_refuse_without_constructing_secret_or_serde_error() {
    let launch = launch(false);
    let fields = PacketNative5LaunchValidationFields::from_launch_data(&launch);
    let projection = PacketNative5LaunchValidationProjection::from_parts_data(
        fields,
        usize::MAX,
        PacketNative5PathSerializationData::QuotedUtf8 { bytes: 2 },
    );
    assert!(matches!(
        projection.serialized_credit_data(usize::MAX),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));
    let projection = PacketNative5LaunchValidationProjection::from_parts_data(
        fields,
        32,
        PacketNative5PathSerializationData::Unrepresentable,
    );
    assert!(matches!(
        projection.validate_data(),
        Err(ProviderError::ResourceExhausted(
            "prepared whole frame bytes"
        ))
    ));
}
