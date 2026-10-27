//! Compares actual ordinary view consumers against the independent old serializers.

use super::super::{
    Identity, NativeImport18BirthConstruction, NativeImport18PrivateBirthAttempt,
    PacketCompleteAckHostRegistrationPlan, Stage,
};
use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;
use crate::node_contract::RuntimeError;
use crucible_node_format::{Bytes, Id, U64, canonical};
use crucible_node_transport::{
    client::CanonicalAckCodecMetadataExtent,
    reference_packet::{
        coordinator::PacketNative5CoordinatorInstallation,
        service::{
            PacketConnectedSourceProgram, PacketNative5AckEmitterSelection,
            PacketNative5CaptureProfile, PacketNative5ConfirmationSelection,
            PacketNative5LaunchValidationFields, PacketNative5ProtocolMetadataLimits,
            PacketNative5SourceLaunch,
            capture_allocation::PacketNative5CaptureAllocationSelection,
            complete_restore::{
                PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
            },
            fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
        },
    },
    reference_service::InstalledContent,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{
    io::{self, Write},
    path::PathBuf,
};

#[path = "oracle.rs"]
mod oracle;

fn launch(
    reactive: bool,
) -> (
    PacketNative5SourceLaunch,
    PacketNative5CoordinatorInstallation,
) {
    let mut coordinator = fixture::coordinator();
    let mut literal = Map::new();
    literal.insert(
        "$serde_json::private::RawValue".into(),
        Value::String("[1,2]".into()),
    );
    literal.insert(
        "$serde_json::private::Number".into(),
        Value::String("1.0".into()),
    );
    coordinator
        .template
        .as_object_mut()
        .unwrap()
        .insert("literal-view-fixture".into(), Value::Object(literal));
    let member = usize::from(reactive);
    let storage = fixture::storage_selection();
    let encoded = canonical::canonical_json(&serde_json::to_value(&coordinator).unwrap()).unwrap();
    let reference = canonical::content_ref(&encoded, "application/json").unwrap();
    let launch = PacketNative5SourceLaunch {
        schema_version: 5,
        selection: coordinator.participants[member].clone(),
        program: if reactive {
            PacketConnectedSourceProgram::Reactive {
                program: fixture::reactive(&coordinator, member),
            }
        } else {
            PacketConnectedSourceProgram::Producer {
                program: fixture::producer(),
            }
        },
        controller_pid: U64::new(u64::from(std::process::id())),
        controller_uid: U64::new(0),
        controller_executable: reference.clone(),
        admission_token: Bytes::new(vec![23; 32]),
        initial_coordinator: InstalledContent {
            reference,
            bytes: Bytes::new(encoded),
        },
        limits: storage.limits,
        storage: storage.storage,
        capture_profile: PacketNative5CaptureProfile::OriginalArrays6,
        confirmation_selection: None,
        ack_emitter_selection: None,
        native_codec_metadata_extent: None,
        protocol_metadata_limits: None,
        complete_restore_selection: None,
        restore_input_emitter_selection: None,
        capture_allocation_selection: None,
        fresh_restore_allocation_selection: None,
        effects: PathBuf::from("private-view-effects"),
    };
    // These are actual shared typed fixture operands for a serializer test.
    // No launch.validate/Source quote/Hello/native success is inferred here.
    (launch, coordinator)
}

fn select_schema(launch: &mut PacketNative5SourceLaunch, schema: u8) {
    launch.native_codec_metadata_extent = None;
    launch.protocol_metadata_limits = None;
    launch.complete_restore_selection = None;
    launch.restore_input_emitter_selection = None;
    launch.capture_allocation_selection = None;
    match schema {
        6 => {}
        7 => {
            launch.native_codec_metadata_extent =
                Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
        }
        8 => {
            launch.protocol_metadata_limits = Some(PacketNative5ProtocolMetadataLimits {
                native_before_rows: U64::new(17),
                native_after_rows: U64::new(19),
            })
        }
        9 => {
            launch.complete_restore_selection =
                Some(PacketNative5CompleteRestoreSelection::SourceSignedOwned11)
        }
        10 => {
            launch.complete_restore_selection =
                Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        }
        11 => {
            launch.restore_input_emitter_selection =
                Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
        }
        12 => {
            launch.capture_allocation_selection =
                Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        }
        _ => panic!("unsupported test schema"),
    }
}

// Deliberately failed DATA calls only the ordinary pure view helper. These
// fields cannot authenticate a Source or satisfy a stage/constructor quote.
fn owner(coordinator: PacketNative5CoordinatorInstallation) -> NativeImport18BirthConstruction {
    NativeImport18BirthConstruction {
        identity: Identity {
            source: 0,
            process: std::process::id(),
            thread: std::thread::current().id(),
            launch_operands: [0; 32],
        },
        inputs_started: false,
        registration: Some(PacketCompleteAckHostRegistrationPlan {
            connection_id: Id::new("planned-controller").unwrap(),
            features: vec![Id::new("feature-a").unwrap(), Id::new("feature-z").unwrap()],
            extensions: Vec::new(),
            envelope_extensions: vec!["x-alpha".into(), "x-zeta".into()],
        }),
        private_launch: None,
        coordinator: Some(coordinator),
        source_value: None,
        registration_value: None,
        source_bank: None,
        registration_bank: None,
        private_birth: NativeImport18PrivateBirthAttempt::new_data(),
        stage: Stage::Initialized,
        failed: true,
    }
}

fn to_value_equal(left: &impl Serialize, right: &impl Serialize) {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => assert_eq!(left, right),
        (Err(left), Err(right)) => {
            assert_eq!(left.classify(), right.classify());
            assert_eq!(left.to_string(), right.to_string());
        }
        _ => panic!("old and shared serializer outcomes differ"),
    }
}

#[test]
fn real_ordinary_consumer_preserves_all_source_schema_and_registration_bytes() {
    for reactive in [false, true] {
        let (mut launch, coordinator) = launch(reactive);
        let owner = owner(coordinator);
        for schema in 6..=12 {
            select_schema(&mut launch, schema);
            let (source, registration) = owner.views(&launch).unwrap();
            let (original_source, original_registration) =
                oracle::original_views(&owner, &launch).unwrap();
            let encoded = serde_json::to_vec(&source).unwrap();
            assert_eq!(encoded, serde_json::to_vec(&original_source).unwrap());
            assert_eq!(
                serde_json::to_vec(&registration).unwrap(),
                serde_json::to_vec(&original_registration).unwrap()
            );
            to_value_equal(&source, &original_source);
            to_value_equal(&registration, &original_registration);

            let value: Value = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(
                value["schema"],
                format!("source-owned.packet-canonical-ack-source-binding/{schema}")
            );
            assert_eq!(
                value.as_object().unwrap().len(),
                10 + match schema {
                    6 => 0,
                    12 => 5,
                    _ => 1,
                }
            );
            assert!(value.get("fresh_restore_allocation_selection").is_none());
            if schema == 12 {
                for name in [
                    "native_codec_metadata_extent",
                    "protocol_metadata_limits",
                    "complete_restore_selection",
                    "restore_input_emitter_selection",
                ] {
                    assert!(value[name].is_null());
                }
            }
        }
    }
}

#[test]
fn shared_worker_view_takes_only_nonsecret_fields_and_keeps_present_options() {
    let (mut launch, coordinator) = launch(false);
    select_schema(&mut launch, 12);
    launch.confirmation_selection = Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5);
    launch.ack_emitter_selection = Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
    launch.native_codec_metadata_extent = Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB);
    launch.protocol_metadata_limits = Some(PacketNative5ProtocolMetadataLimits {
        native_before_rows: U64::new(3),
        native_after_rows: U64::new(5),
    });
    launch.complete_restore_selection =
        Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
    launch.restore_input_emitter_selection =
        Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12);
    launch.fresh_restore_allocation_selection =
        Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13);
    launch.capture_profile = PacketNative5CaptureProfile::OwnedProtocol11 {
        native_before_protocol_bytes: U64::new(101),
        native_after_protocol_bytes: U64::new(103),
        host_protocol_bytes: U64::new(107),
    };
    let worker = SourceBirthView {
        fields: PacketNative5LaunchValidationFields::from_launch_data(&launch),
        coordinator: &coordinator,
    };
    let original = oracle::OriginalSourceBirthView {
        launch: &launch,
        coordinator: &coordinator,
    };
    let encoded = serde_json::to_vec(&worker).unwrap();
    assert_eq!(encoded, serde_json::to_vec(&original).unwrap());
    to_value_equal(&worker, &original);
    let output: Value = serde_json::from_slice(&encoded).unwrap();
    assert!(output.get("fresh_restore_allocation_selection").is_none());

    launch.admission_token = Bytes::new(vec![99; 7]);
    launch.effects = PathBuf::from("a different private effects path");
    let worker = SourceBirthView {
        fields: PacketNative5LaunchValidationFields::from_launch_data(&launch),
        coordinator: &coordinator,
    };
    assert_eq!(serde_json::to_vec(&worker).unwrap(), encoded);
}

struct RefusingWriter {
    maximum: usize,
    bytes: Vec<u8>,
}

impl Write for RefusingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = (self.maximum - self.bytes.len()).min(bytes.len());
        if length == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.bytes.extend_from_slice(&bytes[..length]);
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn compare_write_errors(left: &impl Serialize, right: &impl Serialize) {
    let expected = serde_json::to_vec(left).unwrap();
    for maximum in [0, 1, 9, expected.len() / 2, expected.len() - 1] {
        let mut left_output = RefusingWriter {
            maximum,
            bytes: Vec::new(),
        };
        let mut right_output = RefusingWriter {
            maximum,
            bytes: Vec::new(),
        };
        let left = serde_json::to_writer(&mut left_output, left).unwrap_err();
        let right = serde_json::to_writer(&mut right_output, right).unwrap_err();
        assert_eq!(left.classify(), right.classify());
        assert_eq!(left.to_string(), right.to_string());
        assert_eq!(left_output.bytes, right_output.bytes);
        assert_eq!(left_output.bytes, expected[..maximum]);
    }
}

#[test]
fn actual_serializer_refusal_keeps_original_field_order_and_written_prefix() {
    let (mut launch, coordinator) = launch(true);
    let owner = owner(coordinator);
    for schema in 6..=12 {
        select_schema(&mut launch, schema);
        let (source, registration) = owner.views(&launch).unwrap();
        let (old_source, old_registration) = oracle::original_views(&owner, &launch).unwrap();
        compare_write_errors(&source, &old_source);
        compare_write_errors(&registration, &old_registration);
    }
}

#[test]
fn actual_view_binding_refusals_keep_original_operand_precedence() {
    let (mut launch, coordinator) = launch(false);
    let mut owner = owner(coordinator);
    launch.selection.realization.bindings.clear();
    assert!(matches!(
        owner.views(&launch),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert!(matches!(
        oracle::original_views(&owner, &launch),
        Err(RuntimeError::ForeignAuthority)
    ));

    owner.registration = None;
    assert!(matches!(
        owner.views(&launch),
        Err(RuntimeError::OwnerUnavailable)
    ));
    assert!(matches!(
        oracle::original_views(&owner, &launch),
        Err(RuntimeError::OwnerUnavailable)
    ));
    owner.coordinator = None;
    assert!(matches!(
        owner.views(&launch),
        Err(RuntimeError::OwnerUnavailable)
    ));
    assert!(matches!(
        oracle::original_views(&owner, &launch),
        Err(RuntimeError::OwnerUnavailable)
    ));
}

#[path = "tests/derivation.rs"]
mod derivation;

#[path = "original_launch_custody.rs"]
mod original_launch_custody;

#[test]
fn original_launch_tuple_census_preserves_every_moved_bank_and_selected_view() {
    use crate::node_adapters::cnp::semantic::PacketCompleteSemanticSource;
    use crate::node_adapters::cnp::source_birth_derivation::original_launch::OriginalSourceBirthLaunches;
    use crate::node_contract::restored_owner_history::merge_capacity_metadata_data;
    use crucible_node_transport::retained_metadata::observe_retained_native_launch;

    let mut launches = [launch(false).0, launch(true).0, launch(true).0];
    for (index, launch) in launches.iter_mut().enumerate() {
        let mut token = Vec::with_capacity(173 + index * 31);
        token.extend_from_slice(launch.admission_token.as_slice());
        launch.admission_token = Bytes::new(token);
    }
    let original_banks = launches.each_ref().map(|launch| {
        (
            launch.admission_token.as_slice().as_ptr(),
            launch.admission_token.allocation_capacity(),
            launch.initial_coordinator.bytes.as_slice().as_ptr(),
            launch.initial_coordinator.bytes.allocation_capacity(),
        )
    });
    let mut children = Default::default();
    for launch in &launches {
        merge_capacity_metadata_data(
            &mut children,
            &observe_retained_native_launch(launch).unwrap(),
        )
        .unwrap();
    }
    let mut input = Some(launches);
    let mut retained = None;
    OriginalSourceBirthLaunches::retain_into(&mut input, &mut retained).unwrap();
    let retained = retained.unwrap();
    let selected = retained.selected(1).unwrap();
    let repeated = retained.selected(1).unwrap();

    let actual = retained
        .retained_capacity_metadata_data(usize::MAX, None)
        .unwrap();
    let bytes = PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
        &actual,
        usize::MAX,
    )
    .unwrap();

    assert!(input.is_none());
    assert_eq!(actual.capacity_records, children.capacity_records + 1);
    assert_eq!(
        actual.shared_backing_views,
        children.shared_backing_views + 1
    );
    assert_eq!(actual.string_capacity_bytes, children.string_capacity_bytes);
    assert_eq!(actual.vector_capacity_bytes, children.vector_capacity_bytes);
    assert_eq!(actual.observed_nodes, children.observed_nodes + 2);
    assert_eq!(retained.retained_requested_storage_data(bytes), Ok(bytes));
    assert_eq!(
        retained.retained_requested_storage_data(bytes - 1),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(selected.known_backing_data(), Ok(bytes));
    assert!(selected.same_original(&repeated));
    assert!(std::ptr::eq(selected.original(), &retained.originals()[1]));
    for (launch, (token, token_capacity, coordinator, coordinator_capacity)) in
        retained.originals().iter().zip(original_banks)
    {
        assert_eq!(launch.admission_token.as_slice().as_ptr(), token);
        assert_eq!(launch.admission_token.allocation_capacity(), token_capacity);
        assert_eq!(
            launch.initial_coordinator.bytes.as_slice().as_ptr(),
            coordinator
        );
        assert_eq!(
            launch.initial_coordinator.bytes.allocation_capacity(),
            coordinator_capacity
        );
    }
    assert_eq!(
        retained.retained_capacity_metadata_data(actual.capacity_records, None),
        Ok(actual)
    );
    assert_eq!(
        retained.retained_capacity_metadata_data(actual.capacity_records - 1, None),
        Err(RuntimeError::ResourceLimit)
    );
    drop(retained);
    assert_eq!(selected.known_backing_data(), Ok(bytes));
    assert_eq!(repeated.known_backing_data(), Ok(bytes));
}
