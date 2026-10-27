//! Selects the original complete scene and all measured resources before Child.

use super::{configuration, measurement};
use crucible_daemon::node_qualification::*;
use crucible_engine::node_adapters::cnp::{
    PacketCompleteEffectReceiverGroup, PacketCompleteEffectReceiverReader,
    PacketCompleteSemanticSource,
};
use crucible_node_format::*;
use crucible_node_transport::{
    handshake::Limits,
    reference_packet::{
        control::PacketNative5StorageSelection,
        service::{PacketConnectedSourceProgram, PacketNative5SourceLaunch},
    },
};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        net::UnixDatagram,
    },
    path::PathBuf,
    rc::Rc,
};

pub(super) struct Installed {
    pub scene: configuration::World,
    pub sources: [Rc<PacketCompleteSemanticSource>; 3],
    pub authority: Rc<InstalledPacketCompleteCollectionAuthority>,
    pub _graph_owner: PacketCompleteGraphOwner,
    pub directory: PathBuf,
    pub directories: [PathBuf; 3],
    pub launches: [PacketNative5SourceLaunch; 3],
    pub receiver_group: Rc<PacketCompleteEffectReceiverGroup>,
    pub receiver_reader: PacketCompleteEffectReceiverReader,
    pub peer: PathBuf,
    pub peer_bytes: Vec<u8>,
    pub measurements: [PacketFixtureMeasurements; 3],
}

pub(super) fn install() -> Installed {
    let peer = measurement::required_path("CRUCIBLE_PACKET_WORLD_PEER");
    let source = measurement::required_path("CRUCIBLE_PACKET_WORLD_SOURCE");
    let inventory = measurement::required_path("CRUCIBLE_PACKET_WORLD_SOURCE_INVENTORY");
    let recipe = measurement::required_path("CRUCIBLE_PACKET_WORLD_COMPILER_RECEIPT");
    let measurements = std::array::from_fn(|member| {
        measurement::measurements(&peer, &source, &inventory, &recipe, member)
    });
    for selected in &measurements {
        selected.authenticate().unwrap();
    }
    let peer_bytes = fs::read(&peer).unwrap();
    measurements[0].peer.content.verify(&peer_bytes).unwrap();
    let proof = packet_complete_measured_graph_proof(&measurements).unwrap();
    let mut scene = configuration::World::new(
        measurements[0].peer.content.clone(),
        measurements[0].host.clone(),
        proof,
    );
    let interpretation = packet_complete_independent_graph_contract().unwrap();
    scene.content.insert(
        canonical::content_ref(&interpretation, "application/json").unwrap(),
        interpretation,
    );

    let limits = Limits {
        frame_bytes: U64::new(65_536),
        nesting: U64::new(64),
        requests: U64::new(256),
        journal_entries: U64::new(1024),
        blob_chunk_bytes: U64::new(4096),
    };
    // This is preparation storage, not a whole Capture geometry admission.
    let storage = PacketNative5StorageSelection {
        storage: crucible_node_transport::reference_packet::service::PacketNative5StorageLimits {
            snapshot_bytes: U64::new(65_536),
            control_snapshot_bytes: U64::new(65_536),
            protocol_snapshot_bytes: U64::new(1024 * 1024),
            hello_bytes: U64::new(256 * 1024),
            frame_bank_bytes: U64::new(1024 * 1024),
            frames_per_direction: U64::new(64),
            settlement_bytes: U64::new(1024 * 1024),
        },
        limits,
    };
    let capture_profile = crucible_node_transport::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6;
    let evidence_root = measurement::required_path("CRUCIBLE_PACKET_WORLD_EVIDENCE_ROOT");
    let directory = tempfile::Builder::new()
        .prefix("pc5-")
        .tempdir_in(evidence_root)
        .unwrap()
        .keep();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let directories = std::array::from_fn(|member| {
        let path = directory.join(format!("peer-{member}"));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    });
    let effect_paths: [PathBuf; 3] =
        std::array::from_fn(|member| directory.join(format!("effect-{member}.sock")));
    let receivers = effect_paths
        .each_ref()
        .map(|path| UnixDatagram::bind(path).unwrap());
    let (receiver_group, receiver_reader) =
        PacketCompleteEffectReceiverGroup::from_original_receivers(receivers);
    receiver_reader
        .authenticate_original_group(&receiver_group)
        .unwrap();

    let initial_bytes = configuration::encoded(&scene.coordinator);
    let initial = crucible_node_transport::reference_service::InstalledContent {
        reference: canonical::content_ref(&initial_bytes, "application/json").unwrap(),
        bytes: Bytes::new(initial_bytes),
    };
    let launches = std::array::from_fn(|member| {
        let mut secret = [0u8; 32];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut secret)
            .unwrap();
        PacketNative5SourceLaunch {
            capture_allocation_selection: None,
            fresh_restore_allocation_selection: None,
            native_codec_metadata_extent: Some(crucible_node_transport::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB),
            capture_profile: capture_profile.clone(),
            confirmation_selection: Some(crucible_node_transport::reference_packet::service::PacketNative5ConfirmationSelection::AfterProtocolPoll5),
            ack_emitter_selection: Some(crucible_node_transport::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5),
            schema_version: 5,
            selection: scene.coordinator.participants[member].clone(),
            program: match &scene.programmes[member] {
                PacketConnectedSourceProgram::Producer { program } => {
                    PacketConnectedSourceProgram::Producer {
                        program: program.clone(),
                    }
                }
                PacketConnectedSourceProgram::Reactive { program } => {
                    PacketConnectedSourceProgram::Reactive {
                        program: program.clone(),
                    }
                }
            },
            controller_pid: U64::new(u64::from(std::process::id())),
            controller_uid: U64::new(u64::from(fs::metadata("/proc/self").unwrap().uid())),
            controller_executable: measurements[0].host.clone(),
            admission_token: Bytes::new(secret.to_vec()),
            initial_coordinator: initial.clone(),
            limits,
            storage: storage.storage.clone(),
            protocol_metadata_limits: None,
            complete_restore_selection: None,
            restore_input_emitter_selection: None,
            effects: effect_paths[member].clone(),
        }
    });

    let sources = std::array::from_fn(|member| {
        let definition = scene.members[member].take().unwrap();
        let installed = match &scene.programmes[member] {
            PacketConnectedSourceProgram::Producer { program } => {
                PacketCompleteSemanticSource::new_producer_for_collecting_world(
                    definition.installation,
                    program.clone(),
                    scene.coordinator.clone(),
                    storage.clone(),
                )
            }
            PacketConnectedSourceProgram::Reactive { program } => {
                PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                    definition.installation,
                    program.clone(),
                    scene.coordinator.clone(),
                    storage.clone(),
                )
            }
        };
        let mut source = installed.unwrap();
        source
            .bind_original_capture_profile(capture_profile.clone())
            .unwrap();
        source.bind_original_confirmation_selection(Some(crucible_node_transport::reference_packet::service::PacketNative5ConfirmationSelection::AfterProtocolPoll5)).unwrap();
        source.bind_original_ack_emitter_selection(Some(crucible_node_transport::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)).unwrap();
        source
            .bind_original_ack_codec_metadata_extent(
                crucible_node_transport::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
            )
            .unwrap();
        source
            .bind_original_native_ack_codec_metadata_extent(
                crucible_node_transport::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
            )
            .unwrap();
        // These empty owning banks authenticate preparation resources only.
        // Their limits do not admit full protocol encoding or Capture.
        source
            .reserve_complete_capture_banks(
                crucible_engine::node_adapters::cnp::PacketCompleteCaptureBankLimits {
                    host_protocol_bytes: storage.storage.protocol_snapshot_bytes.get() as usize,
                    semantic_bytes: 65_536,
                    ancestry_bytes: 65_536,
                    journal_bytes: 65_536,
                },
                4 * 1024 * 1024,
            )
            .unwrap();

        source
            .bind_original_effect_receiver(
                receiver_group.clone(),
                member,
                effect_paths[member].clone(),
            )
            .unwrap();

        let (_, _, hello) = super::transport::handshake(
            member,
            &launches[member].selection,
            limits,
            launches[member]
                .admission_token
                .as_slice()
                .try_into()
                .unwrap(),
        );
        let crucible_node_transport::bodies::RequestBody::Hello(request) =
            crucible_node_transport::bodies::decode_request(hello.method, &hello.body).unwrap()
        else {
            panic!("selected original Hello schema")
        };
        let mut envelope_extensions = vec![
            "cnp.extension-negotiation/1".into(),
            "source-owned.packet-canonical-ack-admission/5".into(),
            "source-owned.packet-input/4".into(),
            crucible_node_transport::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION.into(),
        ];
        envelope_extensions.sort();
        source
            .reserve_original_canonical_ack_peer_birth(
                &launches[member],
                super::id(&format!("original-keyed-boot-{member}")),
                crucible_engine::node_adapters::cnp::PacketCompleteAckHostRegistrationPlan {
                    connection_id: super::id(&format!("complete-original-connection-{member}")),
                    features: request.required_features,
                    extensions: Vec::new(),
                    envelope_extensions,
                },
                8 * 1024 * 1024,
            )
            .unwrap();
        Rc::new(source)
    });
    let roster = PacketCompleteRoster::new(sources.clone(), &scene.coordinator).unwrap();
    let graph_owner = PacketCompleteGraphOwner::install(PacketCompleteGraphRequest {
        roster: roster.clone(),
        host: scene.host_source.clone(),
        measurements: [&measurements[0], &measurements[1], &measurements[2]],
        world: &scene.world,
        requirements: &scene.requirements,
        content: &scene.content,
        coordinator: &scene.coordinator,
    })
    .unwrap();

    // Launch declarations are data; the same source allocations remain the issuers.
    let retained_launches = std::array::from_fn(|member| {
        serde_json::from_value(serde_json::to_value(&launches[member]).unwrap()).unwrap()
    });
    eprintln!(
        "original complete preparation evidence: {}",
        directory.display()
    );
    let authority =
        InstalledPacketCompleteCollectionAuthority::install(PacketCompleteCollectionRequest {
            roster,
            host: scene.host_source.clone(),
            graph_policy: graph_owner.graph_policy().unwrap(),
            world: &scene.world,
            requirements: &scene.requirements,
            content: &scene.content,
            coordinator: &scene.coordinator,
            launches: retained_launches,
            directories: directories.clone(),
            limits: QualificationLimits {
                maximum_claim_bytes: 64 * 1024 * 1024,
                maximum_cases: 4096,
                maximum_evidence_objects: 4096,
                maximum_evidence_bytes: 64 * 1024 * 1024,
                maximum_total_evidence_bytes: 3 * 1024 * 1024 * 1024,
            },
            maximum_audit_bytes: 8 * 1024 * 1024,
        })
        .unwrap();
    Installed {
        scene,
        sources,
        authority,
        _graph_owner: graph_owner,
        directory,
        directories,
        launches,
        receiver_group,
        receiver_reader,
        peer,
        peer_bytes,
        measurements,
    }
}
