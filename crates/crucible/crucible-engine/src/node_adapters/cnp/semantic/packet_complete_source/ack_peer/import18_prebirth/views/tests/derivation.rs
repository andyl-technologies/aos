//! Compares the complete contained-data algorithm with the original pure stages.
//!
//! Real complete fixtures install the ACK declaration before binding hashes are
//! derived. Successful controls assert full launch validity, not merely view or
//! Hello validity. No child is spawned and no native/Source bank is accepted.

use super::*;
use crate::node_adapters::cnp::{
    semantic::packet_complete_source::PacketCompleteSemanticSource,
    source_birth_derivation::derive::{
        DerivationCause, DerivationInput, DerivationStage, ExpectedCoordinator, OutputLimits,
        WorldRefusal, derive_source_birth,
    },
};
use crucible_node_transport::reference_packet::service::{
    PacketNative5LaunchValidationProjection,
    complete_restore::import18::hello::{
        native_import18_hello_declaration_data, native_import18_prospective_host_registration_data,
    },
};

fn complete_launch(
    reactive: bool,
) -> (
    PacketNative5SourceLaunch,
    PacketNative5CoordinatorInstallation,
) {
    let coordinator = fixture::coordinator_with_ack();
    let member = usize::from(reactive);
    let bytes = canonical::canonical_json(&serde_json::to_value(&coordinator).unwrap()).unwrap();
    let storage = fixture::storage_selection();
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
        controller_pid: U64::new(1),
        controller_uid: U64::new(0),
        controller_executable: canonical::content_ref(
            b"pure derivation test executable",
            "application/octet-stream",
        )
        .unwrap(),
        admission_token: Bytes::new(vec![7; 32]),
        initial_coordinator: InstalledContent {
            reference: canonical::content_ref(&bytes, "application/json").unwrap(),
            bytes: Bytes::new(bytes),
        },
        limits: storage.limits,
        storage: storage.storage,
        capture_profile: PacketNative5CaptureProfile::OwnedProtocol11 {
            native_before_protocol_bytes: U64::new(65536),
            native_after_protocol_bytes: U64::new(65536),
            host_protocol_bytes: U64::new(65536),
        },
        confirmation_selection: Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5),
        ack_emitter_selection: Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5),
        native_codec_metadata_extent: Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB),
        protocol_metadata_limits: Some(PacketNative5ProtocolMetadataLimits {
            native_before_rows: U64::new(128),
            native_after_rows: U64::new(256),
        }),
        complete_restore_selection: None,
        restore_input_emitter_selection: None,
        capture_allocation_selection: None,
        fresh_restore_allocation_selection: None,
        effects: PathBuf::from("/never-opened-pure-derivation"),
    };
    launch.validate().unwrap();
    (launch, coordinator)
}

fn planned(launch: &PacketNative5SourceLaunch) -> PacketCompleteAckHostRegistrationPlan {
    let declaration = native_import18_hello_declaration_data(launch).unwrap();
    let mut names = None;
    declaration
        .retain_registration_names_into_data(&mut names)
        .unwrap();
    let (features, envelope_extensions) = names.unwrap();
    PacketCompleteAckHostRegistrationPlan {
        connection_id: Id::new("pure-derivation-controller").unwrap(),
        features,
        extensions: Vec::new(),
        envelope_extensions,
    }
}

fn copy_plan(
    plan: &PacketCompleteAckHostRegistrationPlan,
) -> PacketCompleteAckHostRegistrationPlan {
    PacketCompleteAckHostRegistrationPlan {
        connection_id: plan.connection_id.clone(),
        features: plan.features.clone(),
        extensions: plan.extensions.clone(),
        envelope_extensions: plan.envelope_extensions.clone(),
    }
}

fn expected(
    reactive: bool,
    original: &PacketNative5CoordinatorInstallation,
) -> ExpectedCoordinator<'_> {
    if reactive {
        ExpectedCoordinator::Reactive(original)
    } else {
        ExpectedCoordinator::Producer(original)
    }
}

// This reference retains the ordinary real Source comparator and independent
// pre-extraction serializers. It never delegates orchestration to the facade.
fn original_banks(
    launch: &PacketNative5SourceLaunch,
    original: &PacketNative5CoordinatorInstallation,
    plan: &PacketCompleteAckHostRegistrationPlan,
    reactive: bool,
) -> (Vec<u8>, Vec<u8>) {
    launch.validate().unwrap();
    let coordinator = PacketNative5CoordinatorInstallation::decode(
        launch.initial_coordinator.bytes.as_slice(),
        &launch.selection,
    )
    .unwrap();
    let member = usize::from(reactive);
    let source = if reactive {
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            fixture::installation(original, member),
            fixture::reactive(original, member),
            original.clone(),
            fixture::storage_selection(),
        )
        .unwrap()
    } else {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            fixture::installation(original, member),
            fixture::producer(),
            original.clone(),
            fixture::storage_selection(),
        )
        .unwrap()
    };
    source
        .authenticate_collecting_world_scope(&coordinator)
        .unwrap();
    let mut owner = owner(coordinator);
    owner.registration = Some(copy_plan(plan));
    let (view, _) = oracle::original_views(&owner, launch).unwrap();
    let source = serde_json::to_value(view).unwrap();
    let (_, view) = oracle::original_views(&owner, launch).unwrap();
    let registration = serde_json::to_value(view).unwrap();
    let declaration = native_import18_hello_declaration_data(launch).unwrap();
    native_import18_prospective_host_registration_data(
        launch,
        &declaration,
        &registration,
        usize::MAX,
    )
    .unwrap();
    (
        canonical::canonical_json(&source).unwrap(),
        canonical::canonical_json(&registration).unwrap(),
    )
}

#[test]
fn complete_producer_and_reactive_derivation_matches_original_both_banks() {
    for reactive in [false, true] {
        let (launch, original) = complete_launch(reactive);
        let plan = planned(&launch);
        let reference = original_banks(&launch, &original, &plan, reactive);
        let projection = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
        let result = derive_source_birth(
            DerivationInput {
                launch: &projection,
                expected: expected(reactive, &original),
                registration: &plan,
            },
            OutputLimits {
                maximum_output_bytes: usize::MAX,
            },
        )
        .unwrap();

        assert_eq!(result.source_bytes(), reference.0);
        assert_eq!(result.registration_bytes(), reference.1);
        let requested = result.requested_bank_bytes();
        let exact = requested[0].checked_add(requested[1]).unwrap();
        let exact_result = derive_source_birth(
            DerivationInput {
                launch: &projection,
                expected: expected(reactive, &original),
                registration: &plan,
            },
            OutputLimits {
                maximum_output_bytes: exact,
            },
        )
        .unwrap();
        assert_eq!(exact_result.into_banks(), reference);
        let short = derive_source_birth(
            DerivationInput {
                launch: &projection,
                expected: expected(reactive, &original),
                registration: &plan,
            },
            OutputLimits {
                maximum_output_bytes: exact - 1,
            },
        )
        .unwrap_err();
        assert_eq!(short.stage(), DerivationStage::OutputReservation);
        assert!(matches!(short.cause(), DerivationCause::OutputLimit));
        assert!(short.source_prefix().is_empty());
        assert!(short.registration_prefix().is_empty());
    }
}

#[test]
fn candidate_failure_precedes_deferred_original_guard_and_output_refusal() {
    let (mut launch, _) = complete_launch(false);
    let plan = planned(&launch);
    for malformed in [false, true] {
        if malformed {
            let bytes = b"{malformed coordinator".to_vec();
            launch.initial_coordinator.reference =
                canonical::content_ref(&bytes, "application/json").unwrap();
            launch.initial_coordinator.bytes = Bytes::new(bytes);
        } else {
            launch.schema_version = 4;
        }
        let old = launch.validate().unwrap_err();
        let projection = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
        let failed = derive_source_birth(
            DerivationInput {
                launch: &projection,
                expected: ExpectedCoordinator::Deferred(WorldRefusal::ForeignCreatorThread),
                registration: &plan,
            },
            OutputLimits {
                maximum_output_bytes: 0,
            },
        )
        .unwrap_err();
        assert_eq!(failed.stage(), DerivationStage::LaunchValidation);
        let DerivationCause::Provider(actual) = failed.cause() else {
            panic!("wrong cause");
        };
        assert_eq!(format!("{actual:?}; {actual}"), format!("{old:?}; {old}"));
        launch.schema_version = 5;
    }
}

#[test]
fn independent_original_mismatch_precedes_changed_registration() {
    for reactive in [false, true] {
        let (launch, mut original) = complete_launch(reactive);
        let mut plan = planned(&launch);
        // The original operand is independent: change it without touching the
        // candidate bytes, content reference or actual selected member.
        original.template["independent-original-test"] = Value::Bool(true);
        plan.features.clear();
        let projection = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
        let failed = derive_source_birth(
            DerivationInput {
                launch: &projection,
                expected: expected(reactive, &original),
                registration: &plan,
            },
            OutputLimits {
                maximum_output_bytes: 0,
            },
        )
        .unwrap_err();
        assert_eq!(failed.stage(), DerivationStage::WorldComparison);
        assert!(
            matches!(failed.cause(), DerivationCause::World(reason) if *reason == if reactive {
            WorldRefusal::ReactiveCoordinatorChanged
        } else { WorldRefusal::ProducerCoordinatorChanged })
        );
        assert_eq!(
            failed.original_runtime_error(),
            Some(RuntimeError::ForeignAuthority)
        );
    }
}

#[test]
fn genuine_hello_and_registration_refusals_keep_the_original_boundaries() {
    let (mut launch, original) = complete_launch(false);
    let mut plan = planned(&launch);
    plan.features.clear();
    let projection = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
    let failed = derive_source_birth(
        DerivationInput {
            launch: &projection,
            expected: ExpectedCoordinator::Producer(&original),
            registration: &plan,
        },
        OutputLimits {
            maximum_output_bytes: 0,
        },
    )
    .unwrap_err();
    assert_eq!(failed.stage(), DerivationStage::ProspectiveRegistration);
    assert_eq!(
        failed.original_runtime_error(),
        Some(RuntimeError::ForeignAuthority)
    );

    // Keep the original ACK/confirmation and its selected metadata extent:
    // clearing them would enter the smaller legacy policy-credit boundary.
    // Arrays-six has no owned-protocol metadata, which Hello still requires.
    launch.protocol_metadata_limits = None;
    launch.capture_profile = PacketNative5CaptureProfile::OriginalArrays6;
    launch.validate().unwrap();
    let projection = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
    projection.validate_data().unwrap();
    let failed = derive_source_birth(
        DerivationInput {
            launch: &projection,
            expected: ExpectedCoordinator::Producer(&original),
            registration: &plan,
        },
        OutputLimits {
            maximum_output_bytes: 0,
        },
    )
    .unwrap_err();
    assert_eq!(failed.stage(), DerivationStage::HelloDeclaration);
    assert_eq!(
        failed.original_runtime_error(),
        Some(RuntimeError::UnsupportedFacet)
    );
    assert!(failed.source_prefix().is_empty());
    assert!(failed.registration_prefix().is_empty());
}
