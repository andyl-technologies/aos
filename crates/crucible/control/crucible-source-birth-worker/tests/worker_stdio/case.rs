//! Builds the existing complete Producer/Reactive fixtures without Source grants.
use super::fixture;
use crucible_engine::node_adapters::cnp::PacketCompleteAckHostRegistrationPlan;
use crucible_node_format::*;
use crucible_node_transport::reference_packet::control::PacketNative5StorageSelection;
use crucible_node_transport::reference_packet::service::complete_restore::import18::hello::native_import18_hello_declaration_data;
use crucible_node_transport::reference_packet::{
    PacketEvent, PacketProgramDefinition,
    connected::{PacketConnectedDefinition, PacketInputConnection},
    coordinator::PacketNative5CoordinatorInstallation,
    service::*,
};
use crucible_node_transport::{
    client::CanonicalAckCodecMetadataExtent, reference_service::InstalledContent,
};
use serde_json::json;
use std::path::PathBuf;
pub(super) fn storage_selection() -> PacketNative5StorageSelection {
    PacketNative5StorageSelection {
        storage: PacketNative5StorageLimits {
            snapshot_bytes: U64::new(65_536),
            control_snapshot_bytes: U64::new(65_536),
            protocol_snapshot_bytes: U64::new(1024 * 1024),
            frame_bank_bytes: U64::new(1024 * 1024),
            frames_per_direction: U64::new(64),
            hello_bytes: U64::new(2 * 65_536 + 8),
            settlement_bytes: U64::new(1024 * 1024),
        },
        limits: crucible_node_transport::handshake::Limits {
            frame_bytes: U64::new(65_536),
            nesting: U64::new(64),
            requests: U64::new(32),
            journal_entries: U64::new(64),
            blob_chunk_bytes: U64::new(4096),
        },
    }
}

fn content(value: &impl serde::Serialize) -> ContentRef {
    canonical::content_ref(
        &canonical::canonical_json(&json!(value)).unwrap(),
        "application/json",
    )
    .unwrap()
}

pub(super) fn coordinator_with_ack() -> PacketNative5CoordinatorInstallation {
    complete_coordinator(fixture::five_with_ack(true))
}

fn complete_coordinator(
    mut installed: PacketNative5CoordinatorInstallation,
) -> PacketNative5CoordinatorInstallation {
    for (index, selected) in installed.participants.iter_mut().enumerate() {
        let capabilities = CapabilityProfile {
            schema_version: 1,
            facets: selected.realization.bindings[0]
                .compatibility
                .operating_contract
                .facets
                .clone(),
            devices_ref: selected.realization.descriptors[0].model_ref.clone(),
            requirements_ref: serde_json::from_value::<GuaranteeProfile>(
                installed.template["nodes"][index]["guarantees"].clone(),
            )
            .unwrap()
            .limitations_ref,
            extensions: Extensions::new(),
        };
        selected.realization.bindings[0]
            .compatibility
            .capabilities_ref = content(&capabilities);
        selected.realization.owner_bindings[0].node_bindings[0].binding_hash =
            selected.realization.bindings[0].identity().unwrap();
        selected.realize.resource_limits.memory_bytes = U64::new(16 * 1024 * 1024);
        selected.realize.resource_limits.content_bytes = U64::new(4 * 1024 * 1024);
        installed.template["nodes"][index]["binding"] = json!(selected.realization.bindings[0]);
        installed.template["owner_bindings"][index] = json!(selected.realization.owner_bindings[0]);
    }
    let mut world: WorldBinding =
        serde_json::from_value(installed.template["world"].clone()).unwrap();
    for (index, selected) in installed.participants.iter().enumerate() {
        world.node_bindings[index].binding_hash =
            selected.realization.bindings[0].identity().unwrap();
    }
    installed.template["world"] = json!(world);
    let identity = world.identity().unwrap();
    installed.template["activation"]["world_binding_hash"] = json!(identity);
    for selected in &mut installed.participants {
        selected.world = identity.clone();
    }
    installed
}

pub(super) fn reactive(
    installed: &PacketNative5CoordinatorInstallation,
    member: usize,
) -> PacketConnectedDefinition {
    let world: WorldBinding = serde_json::from_value(installed.template["world"].clone()).unwrap();
    let node = &installed.participants[member].realization.descriptors[0].id;
    PacketConnectedDefinition {
        schema: "source-owned.packet-connected-program/4".into(),
        connections: world
            .connections
            .iter()
            .filter(|route| &route.consumer.node_id == node)
            .map(|route| PacketInputConnection {
                id: route.id.clone(),
                policy: route.policy_ref.clone(),
                producer: route.producer.clone(),
                consumer: route.consumer.clone(),
                delay_ps: route.minimum_latency_ps,
            })
            .collect(),
        output: world
            .connections
            .iter()
            .find(|route| &route.producer.node_id == node)
            .map(|route| route.producer.clone()),
    }
}

pub(super) fn producer() -> PacketProgramDefinition {
    PacketProgramDefinition {
        schema: "source-owned.packet-program.v1".into(),
        events: vec![
            PacketEvent {
                id: Id::new("private-callback-0").unwrap(),
                evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                payload: None,
            },
            PacketEvent {
                id: Id::new("packet-callback-0").unwrap(),
                evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                payload: Some(Bytes::new(b"original-producer".to_vec())),
            },
        ],
    }
}

pub(super) fn complete_launch(
    is_reactive: bool,
) -> (
    PacketNative5SourceLaunch,
    PacketNative5CoordinatorInstallation,
) {
    let coordinator = coordinator_with_ack();
    let member = usize::from(is_reactive);
    let bytes = canonical::canonical_json(&serde_json::to_value(&coordinator).unwrap()).unwrap();
    let storage = storage_selection();
    let launch = PacketNative5SourceLaunch {
        schema_version: 5,
        selection: coordinator.participants[member].clone(),
        program: if is_reactive {
            PacketConnectedSourceProgram::Reactive {
                program: reactive(&coordinator, member),
            }
        } else {
            PacketConnectedSourceProgram::Producer {
                program: producer(),
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

pub(super) fn planned(launch: &PacketNative5SourceLaunch) -> PacketCompleteAckHostRegistrationPlan {
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
