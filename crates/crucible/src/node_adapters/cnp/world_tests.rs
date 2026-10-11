//! Actual two-provider world publication and byte-preserving causal input.

#[path = "world_tests/graph.rs"]
mod graph;

#[path = "world_tests/custody.rs"]
mod custody;

#[path = "world_tests/input_failure.rs"]
mod input_failure;

use std::{
    collections::BTreeMap,
    path::Path,
    task::{Context, Poll, Waker},
};

use super::*;
use crate::{
    node_adapters::cnp::preparation::verify_companion,
    node_contract::{
        ActivationPublisher, BeginResult, NodeRuntime, OwnerIdentity, PreparedWorldPublication,
        PublicationStatus, RuntimeLimits, SimulationNode, Submission, ValidatedNodePreparation,
    },
    node_scheduling::InputPayload,
};

fn profile(provider: &Path, device: &Path, node: &str, closed_ingress: bool) -> ReferenceProfile {
    ReferenceProfile::build_public_linked(
        id(node),
        id(&format!("{node}-owner")),
        crucible_node_provider::conformance::measure_executable(provider).unwrap(),
        crucible_node_provider::conformance::measure_executable(device).unwrap(),
        U64::new(1000),
        U64::new(1_000_000_000),
        closed_ingress,
    )
    .unwrap()
}

fn installed(
    profile: ReferenceProfile,
    definition: &graph::Definition,
    provider: &Path,
    device: &Path,
) -> Installed {
    let standard = installation(provider, device);
    let bootstrap = ReferenceServiceBootstrap::fixture(
        &profile,
        graph::initial_authority(&profile.descriptor.id, definition.qualification()),
        entropy(),
        U64::new(u64::from(rustix::process::geteuid().as_raw())),
        standard.bootstrap.limits,
        standard.bootstrap.resource_limits,
        definition.world.identity().unwrap(),
    )
    .unwrap();
    let launch = bootstrap
        .install_qualifications(
            &profile,
            vec![InstalledContent {
                reference: definition.qualification().clone(),
                bytes: Bytes::new(definition.content[definition.qualification()].clone()),
            }],
        )
        .unwrap();
    Installed {
        profile,
        bootstrap: launch.bootstrap,
        qualifications: launch.qualification_refs,
    }
}

fn launch(
    provider: &Path,
    device: &Path,
    installed: &mut Installed,
    directory: PathBuf,
    retained: Rc<RefCell<Vec<CnpPeerCustody>>>,
    schemas: Rc<dyn BodySchemaVerifier>,
) -> CnpReferencePreparation {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = directory.join("control.sock");
    let slot = Box::new(Slot(retained));
    let mut child = Command::new(provider)
        .arg(&socket)
        .arg(device)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let mut guard = CnpLaunchGuard::new(child, directory, slot).ok().unwrap();
    let mut stdin = stdin;
    crucible_node_provider::transport::write_frame(
        &mut stdin,
        &serde_json::to_value(ReferenceServiceInstalledLaunchBootstrap {
            schema_version: 3,
            profile: PublicReferenceProfile::ByteLinkedV1 {
                closed_ingress: installed.profile.descriptor.id == id("producer"),
            },
            bootstrap: installed.bootstrap.clone(),
            qualification_refs: installed.qualifications.clone(),
        })
        .unwrap(),
        16 * 1024 * 1024,
    )
    .unwrap();
    drop(stdin);
    for _ in 0..300 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        socket.exists(),
        "actual public endpoint did not become available"
    );
    connect_with_schema(&mut guard, &socket, installed, schemas);
    match CnpReferencePreparation::prepare(guard, installed) {
        Ok(prepared) => prepared,
        Err(failure) => panic!(
            "actual public world preparation failed: {:?}",
            failure.error
        ),
    }
}

struct Publisher {
    record: ActivationRecord,
    nodes: Vec<ValidatedNodePreparation>,
    coordinator: InputPayload,
    publication: Option<PreparedWorldPublication>,
}

impl ActivationPublisher for Publisher {
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        panic!("a complete public world cannot use scalar publication")
    }

    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Unknown
    }

    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, crate::node_contract::RuntimeError> {
        assert_eq!(record, &self.record);
        assert_eq!(nodes, self.nodes);
        Ok(self.coordinator.clone())
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        preparation: &PreparedWorldPublication,
    ) -> PublicationStatus {
        assert_eq!(record, &self.record);
        assert_eq!(preparation.nodes(), self.nodes);
        assert_eq!(preparation.coordinator_snapshot(), &self.coordinator);
        self.publication = Some(preparation.clone());
        PublicationStatus::Committed
    }
}

fn position(tick: u64, phase: Phase) -> Position {
    Position::new(U64::new(tick), U64::new(0), phase)
}

fn quantum(
    runtime: &mut NodeRuntime,
    graph: &crate::node_admission::AdmittedGraph,
    activation: &crate::node_contract::WorldActivation,
    node: &Id,
    index: u64,
) -> Vec<u8> {
    let stage = id(&format!("stage/{node}/{index}"));
    let batch = id(&format!("batch/{node}/{index}"));
    let input = runtime
        .scheduler(graph, activation)
        .unwrap()
        .prepare_input_batch(
            node,
            stage.clone(),
            batch.clone(),
            position(index * 1000 + 1, Phase::BoundaryControl),
        )
        .unwrap();
    let deliveries = input.deliveries().to_vec();
    runtime.stage_inputs(input).unwrap();
    let retained = runtime.recover_input_staging(activation, &stage).unwrap();
    let input_commit = runtime.commit_input_acknowledgement(retained).unwrap();
    runtime.commit_input_staging(&input_commit).unwrap();
    let grant = runtime
        .scheduler(graph, activation)
        .unwrap()
        .admit_quantum(
            node,
            id(&format!("run/{node}/{index}")),
            id(&format!("window/{node}/{index}")),
            batch,
        )
        .unwrap();
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).unwrap() else {
        panic!("actual CNP provider refused a causally admitted original quantum");
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(runtime.poll(&token, &mut context), Poll::Pending));
    assert_eq!(runtime.close_quantum(&token).unwrap(), Submission::Accepted);
    let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut context) else {
        panic!("actual original CNP quantum did not close");
    };
    let publications = &outcome.scheduling.as_ref().unwrap().publications;
    assert_eq!(publications.len(), 1);
    assert_eq!(
        publications[0].publication_id,
        id(&format!("checksum-{}", index + 1))
    );
    assert_eq!(publications[0].native_sequence, U64::new(index + 1));
    assert_eq!(
        publications[0].publication,
        position((index + 1) * 1000, Phase::Publication)
    );
    let bytes = publications[0].payload_bytes.clone();
    let native: crucible_node_provider::reference_device::DeviceOutput =
        serde_json::from_slice(&bytes).unwrap();
    if node == &id("consumer") && index == 1 {
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].publication_id, id("checksum-1"));
        assert_eq!(deliveries[0].source_sequence, U64::new(0));
        assert_eq!(deliveries[0].native_sequence, U64::new(1));
        assert!(native.bytes_processed.get() > 0);
    }
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    bytes
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_two_public_providers_publish_complete_initial_world_and_consume_original_bytes() {
    run_actual_world(input_failure::FailureMode::None);
}

fn run_actual_world(failure: input_failure::FailureMode) {
    let provider = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE")
            .expect("set source-built provider"),
    );
    let device = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE")
            .expect("set source-built companion"),
    );
    let profiles = vec![
        profile(&provider, &device, "consumer", false),
        profile(&provider, &device, "producer", true),
    ];
    let qualification = b"Actual installed CNP byte-linked checksum fixture: complete original private native process custody, conservative quantized/nondeterministic/limited-state contracts, unchanged octets and producer IDs, bounded zero-latency boundary-sampled direct connection, coordinator transfer custody under consumer/state; native snapshot, pause, fork and CPU fidelity unsupported. Initial coordinator extraction requires actual freshly realized parked nodes and all original ready records.".to_vec();
    let artifacts = BTreeMap::from([
        (
            crucible_node_provider::conformance::measure_executable(&provider).unwrap(),
            provider.clone(),
        ),
        (
            crucible_node_provider::conformance::measure_executable(&device).unwrap(),
            device.clone(),
        ),
    ]);
    let definition = graph::Definition::build(&profiles, qualification, artifacts);
    let mut installed = profiles
        .into_iter()
        .map(|profile| installed(profile, &definition, &provider, &device))
        .collect::<Vec<_>>();
    let directory = std::env::temp_dir().join(format!(
        "cnp-core-world-{}-{}",
        std::process::id(),
        installed[0].bootstrap.admission_token.as_slice()[0]
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let retained = [
        Rc::new(RefCell::new(Vec::new())),
        Rc::new(RefCell::new(Vec::new())),
    ];
    let limits = RuntimeLimits::default();
    let (world_supervisor, world_slot) = custody::WorldSupervisor::reserve(limits);
    let transcript = Rc::new(input_failure::InputTranscript::default());
    let mut prepared = Vec::new();
    for (index, installed) in installed.iter_mut().enumerate() {
        prepared.push(launch(
            &provider,
            &device,
            installed,
            directory.join(installed.profile.descriptor.id.as_str()),
            Rc::clone(&retained[index]),
            transcript.clone(),
        ));
    }
    let pids = prepared
        .iter()
        .map(|node| node.companion_pid)
        .collect::<Vec<_>>();
    let graph = definition.admit(&installed, &prepared);
    let record = ActivationRecord {
        generation: installed[0].bootstrap.world_generation,
        activation_id: installed[0].bootstrap.activation_id.clone(),
        world_binding_hash: graph.world_binding_hash().clone(),
        owners: graph
            .owners()
            .map(|owner| {
                let node = &owner.node_bindings[0].node_id;
                let binding = graph.binding(node).unwrap();
                OwnerIdentity {
                    owner: owner.owner.id.clone(),
                    incarnation: binding.authority.incarnation_id.clone(),
                    generation: binding.authority.owner_generation,
                }
            })
            .collect(),
        boundary: position(0, Phase::BoundaryControl),
    };
    world_supervisor.install_original(&record);
    let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::new();
    for (prepared, installed) in prepared.into_iter().zip(&installed) {
        nodes.push(Box::new(
            prepared
                .into_node(&graph, &installed.profile.descriptor.id, installed, 8)
                .unwrap(),
        ));
    }
    let mut runtime = NodeRuntime::new(&graph, nodes, record.clone(), limits, world_slot)
        .ok()
        .unwrap();
    runtime.arm_all().unwrap();
    let coordinator = runtime
        .initial_coordinator_snapshot(&graph, 1024 * 1024)
        .unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&coordinator.bytes).unwrap();
    assert_eq!(decoded["schema"], "crucible/coordinator-initial/1");
    assert_eq!(decoded["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(decoded["preparations"].as_array().unwrap().len(), 2);
    assert_eq!(decoded["connections"].as_array().unwrap().len(), 1);
    assert_eq!(decoded["scheduler"]["state"], "not_initialized");
    let mut publisher = Publisher {
        record,
        nodes: runtime.prepared_node_records().unwrap().to_vec(),
        coordinator,
        publication: None,
    };
    let activation = runtime.activate(&mut publisher).unwrap();
    assert_eq!(activation.prepared_owners().unwrap().len(), 2);
    assert_eq!(
        activation.coordinator_snapshot(),
        Some(&publisher.coordinator)
    );
    assert!(publisher.publication.is_some());
    assert!(
        runtime
            .initial_coordinator_snapshot(&graph, 1024 * 1024)
            .is_err()
    );
    runtime.scheduler(&graph, &activation).unwrap();
    for node in graph.node_ids() {
        let observation = runtime.observe_scheduling(&activation, node).unwrap();
        runtime
            .scheduler(&graph, &activation)
            .unwrap()
            .accept_boundary_observation(observation)
            .unwrap();
    }
    let source = quantum(&mut runtime, &graph, &activation, &id("producer"), 0);
    assert_eq!(source, br#"{"bytes_processed":"0","checksum":"0"}"#);
    quantum(&mut runtime, &graph, &activation, &id("consumer"), 0);
    let failed_input = if failure != input_failure::FailureMode::None {
        Some(input_failure::fail_original_input(
            &mut runtime,
            &graph,
            &activation,
            &transcript,
            failure,
        ))
    } else {
        None
    };
    if failed_input.is_none() {
        let consumed = quantum(&mut runtime, &graph, &activation, &id("consumer"), 1);
        let output: crucible_node_provider::reference_device::DeviceOutput =
            serde_json::from_slice(&consumed).unwrap();
        let expected = source.iter().fold(0u64, |checksum, byte| {
            checksum.wrapping_mul(257).wrapping_add(u64::from(*byte))
        });
        assert_eq!(output.bytes_processed.get(), source.len() as u64);
        assert_eq!(output.checksum.get(), expected);
    }
    let mut quarantined = runtime.into_quarantine();
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..300 {
        match quarantined.poll_reclamation(&mut context) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(error)) => panic!("actual public world reclamation failed: {error:?}"),
            Poll::Pending => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    assert_eq!(quarantined.remaining_owners(), 0);
    drop(quarantined);
    let mut complete = world_supervisor.take();
    assert_eq!(complete.activation(), &publisher.record);
    assert_eq!(complete.node_preparations(), publisher.nodes);
    assert_eq!(complete.native_handle_count(), 2);
    assert_eq!(
        complete.operation_count(),
        if failed_input.is_some() { 2 } else { 3 }
    );
    assert_eq!(complete.input_batch_count(), 3);
    let original_world = complete.prepared_world_publication().unwrap();
    assert_eq!(original_world.nodes(), publisher.nodes);
    assert_eq!(
        original_world.coordinator_snapshot(),
        &publisher.coordinator
    );
    assert!(matches!(
        complete.poll_reclamation(&mut context),
        Poll::Ready(Ok(()))
    ));
    for slot in &retained {
        assert!(slot.borrow().is_empty());
    }
    // The original whole-world capsule survives successful native reclamation.
    // Only its explicit release transfers the leaf journals to their slots.
    drop(complete);
    for slot in &retained {
        assert_eq!(slot.borrow().len(), 1);
        let original = slot.borrow();
        let journals = original[0].runtime.as_ref().unwrap();
        assert_eq!(journals.prepared.as_ref().unwrap().record, publisher.record);
        assert_eq!(
            journals.preparation_attempt.as_ref(),
            Some(&publisher.record)
        );
        assert_eq!(journals.active.as_ref(), Some(&publisher.record));
        assert!(journals.pending.is_none());
        if journals.binding.compatibility.node_id == id("consumer") {
            if let Some(failed) = &failed_input {
                let (_, response, result) = transcript.accepted(failed.stage_operation());
                let public = journals.input.as_ref().unwrap().public.clone();
                let reference = journals.input.as_ref().unwrap().reference.clone();
                input_failure::assert_retained_input(&original[0], failed, &public, &response);
                if failure == input_failure::FailureMode::RegistryCredit {
                    input_failure::assert_peer_input(
                        original[0].controller.as_ref().unwrap(),
                        &result,
                        &public,
                        &reference,
                    );
                }
            } else {
                assert!(journals.input.is_none());
            }
        } else {
            assert!(journals.input.is_none());
        }
        let expected =
            if journals.binding.compatibility.node_id == id("producer") || failed_input.is_some() {
                1
            } else {
                2
            };
        assert_eq!(journals.windows.len(), expected);
        assert!(journals.windows.values().all(|window| window.consumed));
        drop(original);
        assert!(slot.borrow_mut()[0].poll_reclamation().unwrap());
    }
    for pid in pids {
        assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    }
    std::fs::remove_dir_all(directory).unwrap();
}
