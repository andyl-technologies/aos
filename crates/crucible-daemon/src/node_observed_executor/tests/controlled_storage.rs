//! Genuine ordinary observed worker with admitted coefficient controller between source and storage.

use super::*;
use crucible::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::{Position, canonical};

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_authored_controller_worker_applies_original_decisions_once_with_unchanged_timing() {
    ordinary_controller_world(false);
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_authored_corruption_controller_echoes_only_original_received_packet_bytes() {
    ordinary_controller_world(true);
}

fn ordinary_controller_world(packet: bool) {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "storage-observed",
        temporary.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        factory::measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let base = vec![0xab; 4096];
    let definition = crucible::node_adapters::FaultedLinkDefinition {
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
    let coefficients = |loss, duplicate| crucible::node_adapters::FaultCoefficients {
        loss: crucible::node_adapters::FaultProbability {
            numerator: loss,
            denominator: 1.into(),
        },
        duplicate: crucible::node_adapters::FaultProbability {
            numerator: duplicate,
            denominator: 1.into(),
        },
        corrupt: crucible::node_adapters::FaultProbability {
            numerator: 0.into(),
            denominator: 1.into(),
        },
    };
    let mut controller = crucible::node_adapters::ControlledFaultProgram {
        version: 1,
        initial: definition,
        transitions: vec![
            crucible::node_adapters::AuthoredFaultTransition {
                at: Position::new(
                    25_000.into(),
                    0.into(),
                    crucible_node_contract::Phase::BoundaryControl,
                ),
                coefficients: coefficients(1.into(), 0.into()),
            },
            crucible::node_adapters::AuthoredFaultTransition {
                at: Position::new(
                    75_000.into(),
                    0.into(),
                    crucible_node_contract::Phase::BoundaryControl,
                ),
                coefficients: coefficients(0.into(), 1.into()),
            },
        ],
    };
    if packet {
        controller.transitions[1].coefficients.corrupt.numerator = 1.into();
    }
    let program = canonical::canonical_json(&serde_json::to_value(&controller).unwrap()).unwrap();
    let program_ref = canonical::content_ref(&program, "application/json").unwrap();
    let program_path = temporary.path().join("adverse-program");
    std::fs::write(&program_path, &program).unwrap();
    let script = ScriptedSource::new(
        if packet {
            ScriptedRequestKind::Packet
        } else {
            ScriptedRequestKind::Block
        },
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: if packet {
                    vec![7, 8, 9]
                } else {
                    BlockRequest::write(101, 0, vec![7, 8, 9]).encode().unwrap()
                },
            },
            ScriptedRequest {
                time_ps: 50_000,
                payload: if packet {
                    vec![1, 1, 1]
                } else {
                    BlockRequest::write(102, 0, vec![1, 1, 1]).encode().unwrap()
                },
            },
            ScriptedRequest {
                time_ps: 100_000,
                payload: if packet {
                    vec![10, 11, 12]
                } else {
                    BlockRequest::read(103, 0, 3).encode().unwrap()
                },
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let base_ref = canonical::content_ref(&base, "application/octet-stream").unwrap();
    let script_ref = canonical::content_ref(&script, "application/octet-stream").unwrap();
    let base_path = temporary.path().join("base");
    let script_path = temporary.path().join("script");
    std::fs::write(&base_path, &base).unwrap();
    std::fs::write(&script_path, &script).unwrap();
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(program_path, program_ref.clone()),
            InstalledIoArtifact::path(base_path.clone(), base_ref.clone()),
            InstalledIoArtifact::path(script_path, script_ref.clone()),
        ])
        .unwrap();
    let selected = vec![
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
                        base_image: base_ref,
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
                profile: factory::InstalledControlledFaultProfile {
                    program: program_ref,
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
                    script: script_ref,
                    consumer: id("link"),
                },
            },
        },
    ];
    let scenario = catalog.scenario(&selected).unwrap();
    assert_eq!(scenario.world.connections.len(), 2);
    let execution = ExecutionId::from_bytes([72; 16]).unwrap();
    let backend = catalog
        .prepare(
            &selected,
            scenario,
            NodeRunConfiguration {
                horizon_ps: 200_000.into(),
                maximum_rounds: 128.into(),
                ..configuration()
            },
            execution,
            blobs.clone(),
            refs,
        )
        .unwrap();
    let planned = backend.scenario_artifact();
    repository
        .publish_scenario_artifact(
            planned.scenario(),
            planned.payload_schema(),
            planned.payload().to_vec(),
        )
        .unwrap();
    let configured = backend.configuration_artifact();
    repository
        .publish_configuration_artifact(
            configured.scenario(),
            configured.scenario_artifact(),
            configured.configuration(),
            configured.payload_schema(),
            configured.payload().to_vec(),
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    assert!(request.capabilities().roster().is_repeatable());
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository.clone(), backend, 1).unwrap();
    let _gc = repository.acquire_gc_exclusion_guard().unwrap();
    worker
        .submit("native-storage", &request, &admission)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(result) => break result,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("actual storage world quarantined: {reason}")
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(
            Instant::now() < deadline,
            "actual storage world stayed blocked"
        );
        // Yield between polls of the same original execution; its deadline stays unchanged.
        std::thread::yield_now();
    };
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let bytes = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let outgoing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut responses = Vec::new();
    let mut mutations = Vec::new();
    for event in outgoing["events"].as_array().unwrap() {
        let outcome: crucible::node_contract::OperationOutcome =
            serde_json::from_value(event.clone()).unwrap();
        if let crucible::node_contract::ProgressEvidence::FaultMutationApplied {
            reached,
            decision,
            ..
        } = &outcome.progress
        {
            mutations.push((*reached, *decision));
        }
        if outcome.node != id("disk") {
            continue;
        }
        for publication in &outcome.scheduling.as_ref().unwrap().publications {
            assert!(publication.evaluation.is_some());
            assert_eq!(publication.causal_parents.len(), 1);
            publication
                .payload
                .verify(&publication.payload_bytes)
                .unwrap();
            responses.push(publication.payload_bytes.clone());
        }
    }
    assert_eq!(responses.len(), 4);
    if packet {
        let mut oracle = crucible_device::fault::DeviceRng::fork(
            77,
            "crucible/controlled-fault-link-v1",
            "storage/requests",
        );
        for _ in 0..15 {
            oracle.next_u64();
        }
        let mut expected = vec![10, 11, 12];
        let bit = (oracle.next_u64() % (expected.len() as u64 * 8)) as usize;
        expected[bit / 8] ^= 1 << (bit % 8);
        assert_ne!(expected, vec![10, 11, 12]);
        assert_eq!(
            responses,
            vec![vec![7, 8, 9], vec![7, 8, 9], expected.clone(), expected]
        );
    } else {
        let responses: Vec<_> = responses
            .iter()
            .map(|bytes| BlockResponse::decode(bytes).unwrap())
            .collect();
        assert_eq!(
            responses
                .iter()
                .map(|response| response.request_id)
                .collect::<Vec<_>>(),
            vec![101, 101, 103, 103]
        );
        assert_eq!(responses[2].data, vec![7, 8, 9]);
        assert_eq!(responses[3].data, vec![7, 8, 9]);
    }
    assert_eq!(
        mutations,
        vec![
            (controller.transitions[0].at, 0.into()),
            (controller.transitions[1].at, 1.into())
        ]
    );
    assert_eq!(std::fs::read(base_path).unwrap(), base);
    assert_eq!(
        worker
            .submit("native-storage", &request, &admission)
            .unwrap(),
        ObservedAttemptState::Completed(result)
    );
}
