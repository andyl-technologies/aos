//! Installs the measured complete scene and every original pre-Child resource.

use super::{configuration, id, measurement, schedule, transport};
use crucible_daemon::node_qualification::*;
use crucible_engine::node_adapters::cnp::{PacketConnectedSemanticSource, PacketSemanticSource};
use crucible_node_format::*;
use crucible_node_transport::{
    client::{ClientContent, ClientCustody},
    handshake::Limits,
    reference_packet::service::{PacketConnectedSourceLaunch, PacketConnectedSourceProgram},
};
use crucible_store::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        net::UnixDatagram,
    },
    path::PathBuf,
    rc::Rc,
    sync::Arc,
    time::Duration,
};

pub(super) struct Installed {
    pub scene: configuration::World,
    pub authority: Rc<InstalledPacketConnectedCollectionAuthority>,
    pub _graph_owner: PacketConnectedGraphOwner,
    pub directory: PathBuf,
    pub directories: [PathBuf; 3],
    pub launches: [PacketConnectedSourceLaunch; 3],
    pub incidents: [Rc<transport::Incidents>; 3],
    pub peer: PathBuf,
    pub peer_bytes: Vec<u8>,
    pub measurements: [PacketFixtureMeasurements; 3],
    pub blobs: Arc<DirectoryBlobBackend>,
    pub refs: Arc<DirectoryRefBackend>,
    pub qualification_limits: QualificationLimits,
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
    let extent = usize::try_from(measurements[0].peer.content.length.get()).unwrap();
    assert!(extent > 0 && extent <= 64 * 1024 * 1024);
    let mut peer_bytes = Vec::new();
    peer_bytes.try_reserve_exact(extent).unwrap();
    File::open(&peer)
        .unwrap()
        .take(extent as u64 + 1)
        .read_to_end(&mut peer_bytes)
        .unwrap();
    assert_eq!(peer_bytes.len(), extent);
    measurements[0].peer.content.verify(&peer_bytes).unwrap();

    let proof = packet_connected_measured_graph_proof(&measurements).unwrap();
    let mut scene = configuration::World::new(
        measurements[0].peer.content.clone(),
        measurements[0].host.clone(),
        proof,
    );
    let interpretation = packet_connected_independent_graph_contract().unwrap();
    scene.content.insert(
        canonical::content_ref(&interpretation, "application/json").unwrap(),
        interpretation,
    );
    let participants = scene
        .members
        .take()
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(member, selected)| {
            let installation = selected.installation;
            match &scene.programmes[member] {
                PacketConnectedSourceProgram::Producer { program } => {
                    PacketConnectedParticipant::Producer(Rc::new(
                        PacketSemanticSource::new_for_collecting_connected_world(
                            installation,
                            program.clone(),
                            scene.coordinator.clone(),
                        )
                        .unwrap(),
                    ))
                }
                PacketConnectedSourceProgram::Reactive { program } => {
                    PacketConnectedParticipant::Reactive(Rc::new(
                        PacketConnectedSemanticSource::new_for_collecting_world(
                            installation,
                            program.clone(),
                            scene.coordinator.clone(),
                        )
                        .unwrap(),
                    ))
                }
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let roster = PacketConnectedRoster::new(participants, &scene.coordinator).unwrap();
    let graph_owner = PacketConnectedGraphOwner::install(PacketConnectedGraphRequest {
        roster: roster.clone(),
        host: scene.host_source.clone(),
        measurements: [&measurements[0], &measurements[1], &measurements[2]],
        world: &scene.world,
        requirements: &scene.requirements,
        content: &scene.content,
        coordinator: &scene.coordinator,
    })
    .unwrap();

    // Retain complete evidence after success or containment. This directory is
    // independent test evidence and is never published in Git or release roots.
    let evidence_root = measurement::required_path("CRUCIBLE_PACKET_WORLD_EVIDENCE_ROOT");
    let directory = tempfile::Builder::new()
        .prefix("pc4-")
        .tempdir_in(&evidence_root)
        .unwrap()
        .keep();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    println!(
        "original connected packet evidence: {}",
        directory.display()
    );
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
    let limits = Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(256),
        journal_entries: U64::new(1024),
        blob_chunk_bytes: U64::new(4096),
    };
    let initial = scene.initial_coordinator();
    let launches = std::array::from_fn(|member| {
        let mut secret = [0u8; 32];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut secret)
            .unwrap();
        let program = match &scene.programmes[member] {
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
        };
        PacketConnectedSourceLaunch {
            schema_version: 4,
            selection: scene.coordinator.participants[member].clone(),
            program,
            controller_pid: U64::new(std::process::id().into()),
            controller_uid: U64::new(fs::metadata("/proc/self").unwrap().uid().into()),
            controller_executable: measurements[0].host.clone(),
            admission_token: Bytes::new(secret.to_vec()),
            initial_coordinator: initial.clone(),
            limits,
            effects: effect_paths[member].clone(),
        }
    });
    let qualification_limits = QualificationLimits {
        maximum_claim_bytes: 64 * 1024 * 1024,
        maximum_cases: 4096,
        maximum_evidence_objects: 4096,
        maximum_evidence_bytes: 64 * 1024 * 1024,
        maximum_total_evidence_bytes: 3 * 1024 * 1024 * 1024,
    };
    let authority =
        InstalledPacketConnectedCollectionAuthority::install(PacketConnectedCollectionRequest {
            roster,
            host: scene.host_source.clone(),
            graph_policy: graph_owner.graph_policy().unwrap(),
            world: &scene.world,
            requirements: &scene.requirements,
            content: &scene.content,
            coordinator: &scene.coordinator,
            launches: std::array::from_fn(|member| {
                PacketConnectedSourceLaunch::decode(
                    &configuration::encoded(&launches[member]),
                    1024 * 1024,
                )
                .unwrap()
            }),
            directories: directories.clone(),
            schedule: schedule::scene(),
            limits: qualification_limits,
            maximum_audit_bytes: 8 * 1024 * 1024,
            receivers,
            maximum_oracle_bytes: 16 * 1024 * 1024,
            maximum_report_bytes: 512 * 1024 * 1024,
        })
        .unwrap();
    assert_eq!(authority.witness_plan().requirements.len(), 382);
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "original-packet-connected-world",
        directory.join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    Installed {
        scene,
        authority,
        _graph_owner: graph_owner,
        directory,
        directories,
        launches,
        incidents: std::array::from_fn(|_| transport::Incidents::new()),
        peer,
        peer_bytes,
        measurements,
        blobs,
        refs,
        qualification_limits,
    }
}

impl Installed {
    pub(super) fn peers<'a>(
        &'a self,
        native: [Box<dyn crucible_engine::node_adapters::cnp::CnpSemanticProcessSlot>; 3],
        journal: [Box<dyn PacketPeerJournalSlot>; 3],
    ) -> [Box<PreparedPacketConnectedPeer<'a, transport::Verifier>>; 3] {
        native
            .into_iter()
            .zip(journal)
            .enumerate()
            .map(|(member, (native_custody, journal_custody))| {
                let launch = PacketConnectedSourceLaunch::decode(
                    &configuration::encoded(&self.launches[member]),
                    1024 * 1024,
                )
                .unwrap();
                let token = launch.admission_token.as_slice().try_into().unwrap();
                let (handshake, verifier, hello) =
                    transport::handshake(member, &launch.selection, launch.limits, token);
                let mut content = ClientContent::new(64 * 1024 * 1024, 1024, 4096).unwrap();
                content
                    .install_borrowed(std::iter::once((
                        &self.measurements[member].peer.content,
                        self.peer_bytes.as_slice(),
                    )))
                    .unwrap();
                for (reference, body) in &self.scene.content {
                    content.install(reference.clone(), body.clone()).unwrap();
                }
                let provider = configuration::encoded(&launch.selection.provider);
                content
                    .install(
                        canonical::content_ref(&provider, "application/json").unwrap(),
                        provider,
                    )
                    .unwrap();
                self.authority
                    .prepare_connected_peer(
                        member,
                        PacketConnectedPeerLaunchRequest {
                            executable: self.peer.clone(),
                            directory: self.directories[member].clone(),
                            launch,
                            handshake,
                            verifier,
                            supervisor: self.incidents[member].clone(),
                            hello_schema: Rc::new(transport::HelloSchema),
                            hello,
                            connection: id(&format!(
                                "packet-connected-original-connection-{member}"
                            )),
                            content: ClientCustody::new(256, content).unwrap(),
                            native_custody,
                            journal_custody,
                            budget: Duration::from_secs(5),
                        },
                    )
                    .unwrap_or_else(|failure| {
                        panic!("original connected peer preparation refused: {}", failure)
                    })
            })
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .unwrap()
    }
}
