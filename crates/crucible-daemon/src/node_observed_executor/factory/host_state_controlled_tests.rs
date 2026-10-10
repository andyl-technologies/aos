//! Actual installed held mutation and source-gone two-fresh exact controller worlds.

use super::*;
use crate::node_execution::{ExactOperationNames, ExactOperationRequest, plan_exact_operation};
use crate::node_observed_executor::{NodeObservedError, factory::InstalledControlledFaultProfile};
use crucible::node_adapters::{
    AuthoredFaultTransition, ControlledFaultProgram, FaultCoefficients, FaultProbability,
    FaultedLinkDefinition,
};

fn probability(value: u64) -> FaultProbability {
    FaultProbability {
        numerator: value.into(),
        denominator: 1.into(),
    }
}

fn stage_and_run(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    node: &str,
    name: &str,
    horizon: u64,
) -> OperationOutcome {
    observe(runtime, graph, activation);
    let grant = plan_exact_operation::<NodeObservedError, _>(
        runtime,
        ExactOperationRequest {
            graph,
            activation,
            node: &id(node),
            horizon: horizon.into(),
            names: ExactOperationNames {
                operation: id(name),
                stage: id(&format!("{name}/stage")),
                batch: id(&format!("{name}/batch")),
            },
        },
        |_| Ok(()),
    )
    .unwrap()
    .unwrap();
    run(runtime, grant)
}

fn finish_original(runtime: &mut NodeRuntime, operation: &Id) -> OperationOutcome {
    let token = runtime.recover(operation).unwrap();
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(outcome)) = runtime.poll(&token, &mut context) else {
        panic!("original held mutation disappeared");
    };
    let receipt = runtime.scheduling_receipt(&token).unwrap();
    let commit = runtime.commit_scheduling_receipt(receipt).unwrap();
    runtime.acknowledge_scheduled(&token, &commit).unwrap();
    outcome
}

fn suffix(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
) -> Vec<crucible::node_scheduling::NativePublication> {
    let mut publications = Vec::new();
    for round in 0..256 {
        observe(runtime, graph, activation);
        let mut progress = false;
        for node in graph.node_ids() {
            let cursor = runtime
                .scheduler(graph, activation)
                .unwrap()
                .position(node)
                .unwrap();
            if cursor.time_ps.get() >= 100_000 {
                continue;
            }
            let name = format!("suffix/{round}/{node}");
            let grant = plan_exact_operation::<NodeObservedError, _>(
                runtime,
                ExactOperationRequest {
                    graph,
                    activation,
                    node,
                    horizon: 100_000.into(),
                    names: ExactOperationNames {
                        operation: id(&name),
                        stage: id(&format!("{name}/stage")),
                        batch: id(&format!("{name}/batch")),
                    },
                },
                |_| Ok(()),
            )
            .unwrap();
            if let Some(grant) = grant {
                let outcome = run(runtime, grant);
                if outcome.node == id("disk") {
                    publications.extend(outcome.scheduling.unwrap().publications);
                }
                progress = true;
            }
        }
        if graph.node_ids().all(|node| {
            runtime
                .scheduler(graph, activation)
                .unwrap()
                .position(node)
                .unwrap()
                .time_ps
                .get()
                >= 100_000
        }) {
            return publications;
        }
        assert!(progress, "actual controller world made no safe progress");
    }
    panic!("finite actual controller world exceeded round credits");
}

fn native_state(
    record: &HostArchiveRecord,
    program: &ControlledFaultProgram,
) -> (
    crucible_device::netlink::LinkSnapshot,
    Vec<crucible::node_contract::FaultMutationRecord>,
) {
    let owner = record
        .manifest()
        .owners
        .iter()
        .find(|owner| owner.capture_owner_id == id("link-owner"))
        .unwrap();
    let bytes = record
        .content_bytes(owner.state_ref.as_ref().unwrap(), 64 * 1024 * 1024)
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["schema_version"], 3);
    let native: Vec<u8> = serde_json::from_value(envelope["native"].clone()).unwrap();
    let controller =
        crucible::node_adapters::ControlledFaultLink::restore(program, &native, 64 * 1024 * 1024)
            .unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&native).unwrap();
    let raw: crucible_node_contract::Bytes =
        serde_json::from_value(saved["native"].clone()).unwrap();
    (
        crucible_device::netlink::LinkSnapshot::from_canonical_bytes_with_limit(
            raw.as_slice(),
            64 * 1024 * 1024,
        )
        .unwrap(),
        controller.mutation_records().to_vec(),
    )
}

#[test]
#[ignore = "requires the source-built CRUCIBLE_REFERENCE_DEVICE and complete installed faulted transport"]
fn applied_original_fault_receipt_and_pending_packets_survive_source_gone_two_fresh_worlds() {
    cold_controller_world(false);
}

#[test]
#[ignore = "requires the source-built CRUCIBLE_REFERENCE_DEVICE and complete installed controlled packet transport"]
fn applied_original_corruption_receipt_preserves_original_packets_and_future_draws_after_source_death()
 {
    cold_controller_world(true);
}

fn cold_controller_world(packet: bool) {
    let directory = tempfile::tempdir().unwrap();
    let executable = std::path::PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.path().to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    let base = vec![0xab; 4096];
    let write = if packet {
        vec![7, 8, 9]
    } else {
        BlockRequest::write(101, 0, vec![7, 8, 9]).encode().unwrap()
    };
    let future = if packet {
        vec![10, 11, 12]
    } else {
        BlockRequest::read(103, 0, 3).encode().unwrap()
    };
    let lost = if packet {
        vec![1, 1, 1]
    } else {
        BlockRequest::write(102, 0, vec![1, 1, 1]).encode().unwrap()
    };
    let script = ScriptedSource::new(
        if packet {
            ScriptedRequestKind::Packet
        } else {
            ScriptedRequestKind::Block
        },
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: write.clone(),
            },
            ScriptedRequest {
                time_ps: 15,
                payload: lost,
            },
            ScriptedRequest {
                time_ps: 50_000,
                payload: future.clone(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let definition = FaultedLinkDefinition {
        version: 1,
        seed: 77.into(),
        stream: id("storage/requests"),
        source_node: 17,
        latency_ps: 1000.into(),
        floor_ps: 1000.into(),
        loss: crucible::node_adapters::FaultProbability {
            numerator: 0.into(),
            denominator: 1.into(),
        },
        duplicate: crucible::node_adapters::FaultProbability {
            numerator: 1.into(),
            denominator: 1.into(),
        },
        duplicate_gap_ps: 100.into(),
        corrupt: crucible::node_adapters::FaultProbability {
            numerator: 0.into(),
            denominator: 1.into(),
        },
        corruption_bits: 0,
    };
    let coefficients = |loss, duplicate| FaultCoefficients {
        loss: probability(loss),
        duplicate: probability(duplicate),
        corrupt: probability(0),
    };
    let mut controller = ControlledFaultProgram {
        version: 1,
        initial: definition,
        transitions: vec![
            AuthoredFaultTransition {
                at: Position::new(12.into(), 0.into(), Phase::BoundaryControl),
                coefficients: coefficients(1, 0),
            },
            AuthoredFaultTransition {
                at: Position::new(20.into(), 0.into(), Phase::BoundaryControl),
                coefficients: coefficients(0, 1),
            },
        ],
    };
    if packet {
        controller.transitions[1].coefficients.corrupt = probability(1);
    }
    let program = canonical::canonical_json(&serde_json::to_value(&controller).unwrap()).unwrap();
    let artifacts = [
        ("base", base.clone()),
        ("script", script),
        ("program", program),
    ];
    let references: Vec<_> = artifacts
        .iter()
        .enumerate()
        .map(|(index, (_, bytes))| {
            canonical::content_ref(
                bytes,
                if index == 2 {
                    "application/json"
                } else {
                    "application/octet-stream"
                },
            )
            .unwrap()
        })
        .collect();
    let mut paths = Vec::new();
    for ((name, bytes), reference) in artifacts.iter().zip(&references) {
        let path = directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        catalog
            .install_artifacts(vec![InstalledIoArtifact::path(
                path.clone(),
                reference.clone(),
            )])
            .unwrap();
        paths.push(path);
    }
    let selections = vec![
        InstalledNodeSelection {
            node: id("disk"),
            owner: id("disk-owner"),
            kind: if packet {
                InstalledNodeKind::HostPacketReceiver {
                    source_node: 7,
                    latency_ps: 1000.into(),
                }
            } else {
                InstalledNodeKind::HostIo {
                    profile: InstalledHostIoProfile::Block {
                        base_image: references[0].clone(),
                        source_node: 7,
                        read_ns: 1.into(),
                        write_ns: 1.into(),
                        flush_ns: 1.into(),
                        get_length_ns: 1.into(),
                        per_byte_ns: 1.into(),
                    },
                }
            },
        },
        InstalledNodeSelection {
            node: id("link"),
            owner: id("link-owner"),
            kind: InstalledNodeKind::HostControlledFaultLink {
                profile: InstalledControlledFaultProfile {
                    program: references[2].clone(),
                    producer: id("source"),
                    consumer: id("disk"),
                },
            },
        },
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: references[1].clone(),
                    consumer: id("link"),
                },
            },
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let factory = catalog.host_state_factory(&selections, &scenario).unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "faulted",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let prepared = catalog
        .prepare_world(
            &selections,
            scenario.clone(),
            ExecutionId::from_bytes([111; 16]).unwrap(),
        )
        .unwrap();
    let graph = prepared.graph;
    let mut runtime = prepared
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let activation = runtime
        .activate(&mut publisher(&blobs, &refs, "faulted-source"))
        .unwrap();
    for node in ["source", "link", "disk"] {
        exact(
            &mut runtime,
            &graph,
            &activation,
            node,
            &format!("initial/{node}"),
            10,
        );
    }
    let initial_cut = Position::new(10.into(), 0.into(), Phase::BoundaryControl);
    let before_refusal = runtime
        .fault_runtime_snapshot(initial_cut, 1.into(), 16 * 1024 * 1024)
        .unwrap();
    assert!(matches!(
        runtime
            .begin_fault_injection(&graph, &activation, &id("link"), id("controller/premature"),),
        Err(crucible::node_contract::RuntimePollFailure::Admission(
            crucible::node_contract::RuntimeError::InvalidTiming
        ))
    ));
    assert_eq!(
        before_refusal,
        runtime
            .fault_runtime_snapshot(initial_cut, 1.into(), 16 * 1024 * 1024)
            .unwrap()
    );
    assert!(matches!(
        runtime.runtime_snapshot(initial_cut, 1.into(), 16 * 1024 * 1024),
        Err(crucible::node_contract::RuntimeError::UnsupportedFacet)
    ));

    let birth_cut = Position::new(10.into(), 1.into(), Phase::BoundaryControl);
    for node in ["source", "link", "disk"] {
        settle(
            &mut runtime,
            &graph,
            &activation,
            node,
            &format!("birth/{node}"),
            birth_cut,
        );
    }
    exact(
        &mut runtime,
        &graph,
        &activation,
        "source",
        "pending/source",
        12,
    );
    let link_outcome = stage_and_run(
        &mut runtime,
        &graph,
        &activation,
        "link",
        "pending/link",
        12,
    );
    assert!(link_outcome.scheduling.unwrap().publications.is_empty());
    exact(
        &mut runtime,
        &graph,
        &activation,
        "disk",
        "pending/disk",
        12,
    );
    let cut = Position::new(12.into(), 0.into(), Phase::BoundaryControl);
    let limits = StateLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 1024 * 1024 * 1024,
        ..StateLimits::default()
    };
    let archive_path = directory.path().join("archive");
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    // A legacy archive cannot silently omit the selected controller state.
    assert!(
        archive
            .capture_world(
                &graph,
                &mut runtime,
                &activation,
                cut,
                9.into(),
                id("capture/legacy-refused"),
                requirements(),
                factory.as_ref(),
                factory.as_ref(),
            )
            .is_err()
    );
    let original_mutation = id("controller/original/0");
    let BeginResult::Accepted(token) = runtime
        .begin_fault_injection(&graph, &activation, &id("link"), original_mutation.clone())
        .unwrap()
    else {
        panic!("actual selected mutation refused");
    };
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(original_outcome)) = runtime.poll(&token, &mut context) else {
        panic!("native mutation did not produce its original held receipt");
    };
    assert!(
        matches!(original_outcome.progress, crucible::node_contract::ProgressEvidence::FaultMutationApplied { decision, .. } if decision.get() == 0)
    );
    // Capture the actual applied native mutation before coordinator commit/ACK.
    // The original FaultInjection permission and raw native receipt stay owned.
    let record = archive
        .capture_fault_world(
            &graph,
            &mut runtime,
            &activation,
            cut,
            9.into(),
            id("capture/faulted"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    let coordinator_bytes = record
        .content_bytes(&record.manifest().coordinator_state_ref, 64 * 1024 * 1024)
        .unwrap();
    let coordinator: serde_json::Value = serde_json::from_slice(&coordinator_bytes).unwrap();
    assert_eq!(coordinator["scheduler"]["schema_version"], 3);
    assert!(coordinator["scheduler"].get("original_epochs").is_none());
    let (before, original_journal) = native_state(&record, &controller);
    assert_eq!(before.rng_position, 5);
    assert_eq!(before.next_seq, 2);
    assert_eq!(before.inflight.len(), 2);
    assert_eq!(original_journal.len(), 1);
    assert_eq!(original_journal[0].operation, original_mutation);
    assert_eq!(
        original_journal[0].source.activation_id,
        activation.record().activation_id
    );
    assert_eq!(before.faults.loss.numerator, 1);
    let artifact = record.artifact().clone();
    assert_eq!(
        finish_original(&mut runtime, &original_mutation),
        original_outcome
    );
    let original_suffix = suffix(&mut runtime, &graph, &activation);
    assert_eq!(original_suffix.len(), 4);
    if packet {
        let mut oracle = crucible_device::fault::DeviceRng::fork(
            77,
            "crucible/controlled-fault-link-v1",
            "storage/requests",
        );
        // The duplicated original and lost input consume five base draws each;
        // the final corrupted input consumes five base draws plus one selector.
        for _ in 0..15 {
            oracle.next_u64();
        }
        let bit = (oracle.next_u64() % (future.len() as u64 * 8)) as usize;
        let mut expected = future.clone();
        expected[bit / 8] ^= 1 << (bit % 8);
        assert_ne!(expected, future);
        assert_eq!(original_suffix[0].payload_bytes, write);
        assert_eq!(original_suffix[1].payload_bytes, write);
        assert_eq!(original_suffix[2].payload_bytes, expected);
        assert_eq!(original_suffix[3].payload_bytes, expected);
    } else {
        let replies: Vec<_> = original_suffix
            .iter()
            .map(|publication| BlockResponse::decode(&publication.payload_bytes).unwrap())
            .collect();
        assert_eq!(
            replies
                .iter()
                .map(|reply| reply.request_id)
                .collect::<Vec<_>>(),
            vec![101, 101, 103, 103]
        );
        assert_eq!(replies[2].data, vec![7, 8, 9]);
        assert_eq!(replies[3].data, vec![7, 8, 9]);
    }
    assert_eq!(std::fs::read(&paths[0]).unwrap(), base);
    let original_final = archive
        .capture_fault_world(
            &graph,
            &mut runtime,
            &activation,
            Position::new(100_000.into(), 0.into(), Phase::BoundaryControl),
            30.into(),
            id("capture/original-final"),
            requirements(),
            factory.as_ref(),
            factory.as_ref(),
        )
        .unwrap();
    let (final_native, final_journal) = native_state(&original_final, &controller);
    assert_eq!(final_native.rng_position, if packet { 16 } else { 15 });
    assert_eq!(final_native.next_seq, 4);
    assert_eq!(final_journal.len(), 2);
    assert!(final_native.inflight.is_empty());
    drop(original_final);
    drop(record);
    drop(runtime);
    reclaim(&catalog);
    drop(activation);
    drop(graph);
    drop(factory);
    drop(catalog);
    drop(archive);
    for path in &paths {
        std::fs::remove_file(path).unwrap();
    }
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        directory.path().to_owned(),
        Duration::from_secs(5),
        4,
    )
    .unwrap();
    catalog
        .install_artifacts(
            references
                .iter()
                .cloned()
                .map(InstalledIoArtifact::archive_only)
                .collect(),
        )
        .unwrap();
    let archive = HostArchive::open(&archive_path, limits).unwrap();
    let record = archive.load(&artifact).unwrap();
    let reserved_before = catalog.custody().reserved_worlds();
    let mut wrong = selections.clone();
    let InstalledNodeKind::HostControlledFaultLink { profile } = &mut wrong[1].kind else {
        panic!("wrong selected fixture");
    };
    let mut changed = controller.clone();
    changed.transitions[1].coefficients.duplicate = probability(0);
    let changed_program =
        canonical::canonical_json(&serde_json::to_value(&changed).unwrap()).unwrap();
    profile.program = canonical::content_ref(&changed_program, "application/json").unwrap();
    catalog
        .install_artifacts(vec![InstalledIoArtifact::archive_only(
            profile.program.clone(),
        )])
        .unwrap();
    assert!(
        catalog
            .host_state_factory_from_archive(&wrong, &scenario, &record)
            .is_err()
    );
    assert!(
        catalog
            .prepare_host_restore_graph(
                &wrong,
                &scenario,
                &record,
                ExecutionId::from_bytes([117; 16]).unwrap()
            )
            .is_err()
    );
    assert_eq!(catalog.custody().reserved_worlds(), reserved_before);
    for nonce in [112, 113] {
        let (fresh_graph, mut branch) = restore(
            &mut catalog,
            &selections,
            &scenario,
            archive.load(&artifact).unwrap(),
            nonce,
            (&blobs, &refs),
            limits,
        );
        let fresh = branch.activation().clone();
        assert_ne!(fresh.record().owners, original_journal[0].source.owners);
        let saved = branch
            .runtime_mut()
            .fault_runtime_snapshot(cut, 9.into(), limits.maximum_record_bytes)
            .unwrap();
        assert_eq!(saved.schema_version, 4);
        assert!(
            saved
                .pending_acknowledgements()
                .contains(&original_mutation)
        );
        let recovered = finish_original(branch.runtime_mut(), &original_mutation);
        assert_eq!(recovered.progress, original_outcome.progress);
        assert!(
            branch
                .runtime_mut()
                .begin_fault_injection(&fresh_graph, &fresh, &id("link"), original_mutation.clone())
                .is_err()
        );
        let actual_suffix = suffix(branch.runtime_mut(), &fresh_graph, &fresh);
        assert_eq!(actual_suffix, original_suffix);
        let factory = catalog
            .host_state_factory_from_archive(
                &selections,
                &scenario,
                &archive.load(&artifact).unwrap(),
            )
            .unwrap();
        let final_record = archive
            .capture_fault_world(
                &fresh_graph,
                branch.runtime_mut(),
                &fresh,
                Position::new(100_000.into(), 0.into(), Phase::BoundaryControl),
                30.into(),
                id(&format!("capture/branch/{nonce}")),
                requirements(),
                factory.as_ref(),
                factory.as_ref(),
            )
            .unwrap();
        let (native, journal) = native_state(&final_record, &controller);
        assert_eq!(native, final_native);
        assert_eq!(journal[0], original_journal[0]);
        assert_eq!(journal.len(), 2);
        assert_eq!(journal[1].request, final_journal[1].request);
        assert_eq!(journal[1].operation, final_journal[1].operation);
        assert_eq!(
            journal[1].source.activation_id,
            fresh.record().activation_id
        );
        drop(final_record);
        drop(branch);
        reclaim(&catalog);
    }
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}
