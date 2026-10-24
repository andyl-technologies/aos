//! Executes one genuinely installed three-peer world through nine complete windows.
//!
//! This explicit native fixture is excluded from the native-free roster. Running
//! its exact ignored selector requires the freshly compiled packet binary, exact
//! source tree, full source inventory and compiler command receipt. Missing inputs
//! fail; the fixture never reports success by skipping them. The full382 normative
//! rows remain unexecuted and Refused even when all54 original observations pass.

// crucible-lint: allow panic-shortcut -- This actual fixture fails on omitted inputs, wrong original associations or incomplete native reclamation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs::{self, File},
    io::Read,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        net::UnixDatagram,
    },
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use crucible_daemon::node_qualification::{
    CaseVerdict, InstalledPacketWorldCollectionAuthority, PacketCollectionFailure,
    PacketFixtureArtifact, PacketFixtureMeasurements, PacketWorldFixtureRequest,
    PacketWorldHostFailure, PacketWorldHostSupervisor, PacketWorldIndependentGraphOwner,
    PacketWorldIndependentGraphRequest, PacketWorldPeerTransport, PacketWorldStoredFixtureRequest,
    QualificationClaim, QualificationLimits, RequirementDisposition, accept_claim,
};
use crucible_engine::{
    node_adapters::cnp::PacketSemanticSource,
    node_admission::AdmissionLimits,
    node_contract::{OperationOutcome, RuntimeLimits, RuntimePollFailure},
};
use crucible_node_format::*;
use crucible_node_transport::{
    client::{ClientContent, ClientCustody},
    handshake::Limits,
    reference_packet::service::PacketSourceLaunch,
};
use crucible_store::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};

#[path = "packet_world_collection/configuration.rs"]
mod configuration;
#[path = "packet_world_collection/definition.rs"]
mod definition;
#[path = "packet_world_collection/transport.rs"]
mod transport;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn required_path(variable: &str) -> PathBuf {
    let value = std::env::var_os(variable)
        .unwrap_or_else(|| panic!("required native fixture input omitted: {variable}"));
    fs::canonicalize(value).unwrap()
}

fn measured(path: &Path, media_type: &str) -> ContentRef {
    let extent = path.metadata().unwrap().len();
    assert!(extent > 0 && extent <= 512 * 1024 * 1024);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes.len() as u64, extent);
    canonical::content_ref(&bytes, media_type).unwrap()
}

fn measurements(
    peer: &Path,
    source: &Path,
    inventory: &Path,
    recipe: &Path,
) -> PacketFixtureMeasurements {
    let roles = [
        (
            "adapter_source",
            source.join("crates/crucible/crucible-engine/src/node_adapters/cnp/semantic/packet_source.rs"),
        ),
        ("build_closure", inventory.to_path_buf()),
        (
            "contract_source",
            source.join("crates/crucible/crucible-node-transport/src/reference_packet/contracts.rs"),
        ),
        (
            "harness_source",
            source.join("crates/crucible/crucible-daemon/tests/packet_world_collection.rs"),
        ),
        (
            "native_source",
            source.join("crates/crucible/crucible-node-transport/src/reference_packet.rs"),
        ),
        (
            "program_source",
            source.join("crates/crucible/crucible-daemon/tests/packet_world_collection/configuration.rs"),
        ),
        (
            "provider_source",
            source.join("crates/crucible/crucible-node-transport/src/reference_packet/control.rs"),
        ),
        ("recipe", recipe.to_path_buf()),
    ];
    PacketFixtureMeasurements {
        peer: PacketFixtureArtifact {
            role: "executable".into(),
            path: peer.to_path_buf(),
            content: measured(peer, "application/octet-stream"),
        },
        host: measured(Path::new("/proc/self/exe"), "application/octet-stream"),
        sources: roles
            .into_iter()
            .map(|(role, path)| PacketFixtureArtifact {
                role: role.into(),
                content: measured(&path, "application/octet-stream"),
                path,
            })
            .collect(),
    }
}

// This explicit native fixture bounds physical cleanup/lifecycle waits. The
// operational watchdog neither advances nor authenticates modeled guest time.
#[allow(clippy::disallowed_methods)]
fn await_progress<T>(mut action: impl FnMut(&mut Context<'_>) -> Poll<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        match action(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => {
                assert!(
                    Instant::now() < deadline,
                    "actual original lifecycle exceeded fixture deadline"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

#[test]
#[ignore = "actual three-peer native lifecycle; requires explicitly measured fixture inputs"]
fn three_original_peers_share_one_activation_nine_windows_and_fifty_four_ack_cases() {
    let peer = required_path("CRUCIBLE_PACKET_WORLD_PEER");
    let source = required_path("CRUCIBLE_PACKET_WORLD_SOURCE");
    let inventory = required_path("CRUCIBLE_PACKET_WORLD_SOURCE_INVENTORY");
    let recipe = required_path("CRUCIBLE_PACKET_WORLD_COMPILER_RECEIPT");
    let measurement = measurements(&peer, &source, &inventory, &recipe);
    measurement.authenticate().unwrap();
    let peer_extent = usize::try_from(measurement.peer.content.length.get()).unwrap();
    assert!(peer_extent > 0 && peer_extent <= 64 * 1024 * 1024);
    let mut peer_bytes = Vec::new();
    peer_bytes.try_reserve_exact(peer_extent).unwrap();
    File::open(&peer)
        .unwrap()
        .take(u64::try_from(peer_extent).unwrap() + 1)
        .read_to_end(&mut peer_bytes)
        .unwrap();
    assert_eq!(peer_bytes.len(), peer_extent);
    measurement.peer.content.verify(&peer_bytes).unwrap();
    let definition = configuration::World::new(measurement.peer.content.clone());

    // Keep all immutable publications and original evidence after either outcome.
    // This is an explicit fixture audit directory, not a daemon GC contract.
    let directory = tempfile::Builder::new()
        .prefix("packet-world-original-")
        .tempdir()
        .unwrap()
        .keep();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    println!("original packet world evidence: {}", directory.display());
    let directories: [PathBuf; 3] = std::array::from_fn(|member| {
        let path = directory.join(format!("peer-{member}"));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    });
    let effect_paths: [PathBuf; 3] =
        std::array::from_fn(|member| directory.join(format!("effect-{member}.sock")));
    let receivers = effect_paths
        .each_ref()
        .map(|path| UnixDatagram::bind(path).unwrap());
    let programmes = definition.programmes.clone();
    let coordinator = definition.coordinator.clone();
    let initial = definition.initial_coordinator();
    let [member0, member1, member2] = definition.members;
    let sources: [Rc<PacketSemanticSource>; 3] = [member0, member1, member2]
        .into_iter()
        .enumerate()
        .map(|(member, data)| {
            Rc::new(
                PacketSemanticSource::new_for_collecting_world(
                    data.installation,
                    programmes[member].clone(),
                    coordinator.clone(),
                )
                .unwrap(),
            )
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let owner = PacketWorldIndependentGraphOwner::install(PacketWorldIndependentGraphRequest {
        sources: sources.clone(),
        measurements: [&measurement, &measurement, &measurement],
        world: &definition.world,
        requirements: &definition.requirements,
        content: &definition.content,
        coordinator: &definition.coordinator,
    })
    .unwrap();
    let limits = Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(256),
        journal_entries: U64::new(1024),
        blob_chunk_bytes: U64::new(4096),
    };
    let launches: [PacketSourceLaunch; 3] = std::array::from_fn(|member| {
        let mut secret = [0u8; 32];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut secret)
            .unwrap();
        PacketSourceLaunch {
            schema_version: 3,
            selection: coordinator.participants[member].clone(),
            program: programmes[member].clone(),
            controller_pid: U64::new(u64::from(std::process::id())),
            controller_uid: U64::new(fs::metadata("/proc/self").unwrap().uid().into()),
            controller_executable: measurement.host.clone(),
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
    // The installer borrows the complete launch before either copy or Child.
    let authority = InstalledPacketWorldCollectionAuthority::install(PacketWorldFixtureRequest {
        sources,
        graph_policy: owner.graph_policy().unwrap(),
        world: &definition.world,
        requirements: &definition.requirements,
        content: &definition.content,
        coordinator: &coordinator,
        launches: std::array::from_fn(|member| {
            PacketSourceLaunch::decode(&configuration::encoded(&launches[member]), 1024 * 1024)
                .unwrap()
        }),
        directories: directories.clone(),
        receivers,
        horizons: std::array::from_fn(|window| U64::new((window as u64 + 1) * 10)),
        operations: std::array::from_fn(|index| {
            id(&format!(
                "packet-original-window-{}-member-{}",
                index / 3,
                index % 3
            ))
        }),
        limits: qualification_limits,
        maximum_audit_bytes: 8 * 1024 * 1024,
        maximum_report_bytes: 512 * 1024 * 1024,
    })
    .unwrap();
    assert_eq!(authority.witness_plan().requirements.len(), 382);
    assert_eq!(authority.witness_plan().cases.len(), 436);
    let incidents: [Rc<transport::Incidents>; 3] =
        std::array::from_fn(|_| transport::Incidents::new());
    let transports = launches
        .into_iter()
        .enumerate()
        .map(|(member, launch)| {
            let secret: [u8; 32] = launch.admission_token.as_slice().try_into().unwrap();
            let (handshake, verifier, hello) =
                transport::handshake(member, &launch.selection, limits, secret);
            let mut content = ClientContent::new(64 * 1024 * 1024, 1024, 4096).unwrap();
            // Discover references the independently installed executable too.
            // Precharge its complete bytes before copying; identity alone cannot
            // satisfy the controller's required immutable content custody.
            content
                .install_borrowed(std::iter::once((
                    &measurement.peer.content,
                    peer_bytes.as_slice(),
                )))
                .unwrap();
            for (reference, body) in &definition.content {
                content.install(reference.clone(), body.clone()).unwrap();
            }
            let provider = configuration::encoded(&launch.selection.provider);
            content
                .install(
                    canonical::content_ref(&provider, "application/json").unwrap(),
                    provider,
                )
                .unwrap();
            PacketWorldPeerTransport {
                executable: peer.clone(),
                directory: directories[member].clone(),
                launch,
                handshake,
                verifier,
                supervisor: incidents[member].clone(),
                hello_schema: Rc::new(transport::HelloSchema),
                hello,
                connection: id(&format!("packet-original-connection-{member}")),
                content: ClientCustody::new(256, content).unwrap(),
                budget: Duration::from_secs(5),
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    let supervisor = PacketWorldHostSupervisor::new().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "original-packet-world",
        directory.join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.join("refs")));
    let result_references: [RefName; 27] = std::array::from_fn(|index| {
        RefName::new(format!(
            "node-packet-collecting-results/world-result-{index:02}"
        ))
        .unwrap()
    });
    let activation_reference = RefName::new("node-world-activations/packet-world").unwrap();
    let mut fixture =
        match authority.prepare_stored_world_fixture(PacketWorldStoredFixtureRequest {
            graph_owner: &owner,
            supervisor: &supervisor,
            transports,
            requirements: definition.requirements.clone(),
            activation: definition.activation.clone(),
            admission_limits: AdmissionLimits {
                maximum_content_bytes: 512 * 1024 * 1024,
                maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
                ..AdmissionLimits::default()
            },
            runtime_limits: RuntimeLimits {
                maximum_nodes: 3,
                maximum_owners: 3,
                maximum_operations: 27,
                maximum_retained_outputs: 3,
            },
            blobs: blobs.clone(),
            refs: refs.clone(),
            activation_reference: activation_reference.clone(),
            result_references: result_references.clone(),
            maximum_coordinator_bytes: 65536,
            maximum_each_result_bytes: 8 * 1024 * 1024,
            maximum_total_result_bytes: 216 * 1024 * 1024,
        }) {
            Ok(fixture) => fixture,
            Err(failure) => {
                let _original = failure;
                panic!(
                    "pre-Child complete world preparation refused: {:?}",
                    _original.original.preparation_error()
                )
            }
        };
    let execution = catch_unwind(AssertUnwindSafe(|| {
        if fixture.start().is_err() {
            panic!(
                "same original three-peer start refused: {:?}",
                fixture.start_error()
            );
        }
        let mut previous = None;
        await_progress(|context| {
            let result = fixture.poll(context);
            let progress = fixture.progress();
            if progress != previous {
                eprintln!("original packet actor progress: {progress:?}");
                previous = progress;
            }
            result
        })
        .unwrap_or_else(|failure| match failure {
            PacketWorldHostFailure::Lifecycle(PacketCollectionFailure::Native(
                RuntimePollFailure::Admission(error),
            )) => panic!("same original three-peer publication admission failed: {error}"),
            PacketWorldHostFailure::Lifecycle(PacketCollectionFailure::Runtime(error)) => {
                panic!("same original three-peer runtime failed: {error}")
            }
            PacketWorldHostFailure::Lifecycle(PacketCollectionFailure::Collection(_)) => {
                panic!("same original three-peer collection refused")
            }
            _ => panic!("same original three-peer lifecycle failed"),
        });
        let collected = fixture.collected().unwrap();
        for report in collected.iter().flatten() {
            // Issuance retains complete report data, including unexecuted rows.
            // Acceptance is a separate fresh installed-authority decision.
            let issued = report.issued.as_ref().unwrap();
            issued.reference().verify(issued.bytes()).unwrap();
            let claim: QualificationClaim = serde_json::from_value(
                canonical::parse_json(issued.bytes(), qualification_limits.maximum_claim_bytes)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(claim.requirements.len(), 382);
            for requirement in &claim.requirements {
                assert_eq!(requirement.disposition, RequirementDisposition::NotExecuted);
                let mandatory = format!("unexecuted-original-{}", requirement.requirement);
                let cases = requirement
                    .cases
                    .iter()
                    .filter(|case| case.case == mandatory)
                    .collect::<Vec<_>>();
                assert_eq!(cases.len(), 1);
                assert_eq!(cases[0].verdict, CaseVerdict::NotExecuted);
            }
            assert!(
                accept_claim(
                    issued.bytes(),
                    issued.reference(),
                    &authority.witness_plan().unit,
                    &authority.witness_plan().classes,
                    authority.as_ref(),
                    qualification_limits,
                )
                .is_err(),
                "unexecuted normative report cannot pass ordinary acceptance"
            );
            assert_eq!(report.attempts.attempted_cases().len(), 18);
            assert_eq!(report.attempts.authenticated_cases().len(), 18);
            assert_eq!(report.exact_observations.len(), 18);
            let mut before = 0;
            let mut after = 0;
            let mut original_outputs = 0;
            for observed in report.exact_observations.values() {
                observed
                    .snapshot_ref
                    .verify(observed.snapshot.as_slice())
                    .unwrap();
                let snapshot =
                    canonical::parse_json(observed.snapshot.as_slice(), 8 * 1024 * 1024).unwrap();
                assert_eq!(
                    snapshot[2][3].as_array().unwrap().len(),
                    3,
                    "same full activation owner roster"
                );
                let outcome: OperationOutcome =
                    serde_json::from_value(snapshot[4].clone()).unwrap();
                assert_eq!(
                    outcome.owners.len(),
                    1,
                    "local original owner route under full activation"
                );
                if snapshot[5] == false {
                    before += 1;
                    original_outputs += outcome.retained_outputs.len();
                } else {
                    assert_eq!(snapshot[5], true);
                    after += 1;
                }
                for object in &observed.objects {
                    object.reference.verify(&object.bytes).unwrap();
                }
            }
            assert_eq!((before, after, original_outputs), (9, 9, 1));
        }
        assert!(collected.iter().all(Option::is_some));
        for reference in &result_references {
            let target = refs.read_ref(reference).unwrap().unwrap();
            let body = blobs
                .read(target, None)
                .unwrap()
                .read_all(8 * 1024 * 1024)
                .unwrap();
            let value = canonical::parse_json(&body, 8 * 1024 * 1024).unwrap();
            assert_eq!(value["version"], 2);
        }
        assert!(refs.read_ref(&activation_reference).unwrap().is_some());
        assert!(incidents.iter().all(|original| original.is_empty()));
    }));

    // Native cleanup always runs against the same holder, even after an assertion
    // or installed callback failure; cleanup failure is not a successful outcome.
    fixture
        .retire_original()
        .unwrap_or_else(|_| panic!("original borrowed native transfer failed"));
    let reclaimed = await_progress(|context| fixture.poll_reclamation(context))
        .unwrap_or_else(|_| panic!("original independent kernel reclamation failed"));
    assert_eq!(reclaimed.runtime_worlds, 0);
    assert!(reclaimed.peers.iter().all(|peer| peer.native_returned
        && peer.kernel_reclaimed
        && peer.journal_retained
        && !peer.containment_fault));
    if let Err(failure) = execution {
        std::panic::resume_unwind(failure);
    }
}
