//! Exercises ordinary transport demands against original bytes and seeded draws.
//!
//! The independently consumed decision journal below is an output oracle, not
//! the executor's private journal or evidence of capture/continuation authority.

use super::*;
use crucible_device::{
    fault::DeviceRng,
    netlink::{jitter_shift_ticks, reorder_shift_ticks},
};
use crucible_engine::node_adapters::{
    FaultProbability, FaultedInput, FaultedLinkDefinition, SeededLinkDefinition,
};
use crucible_engine::node_scheduling::{NativePublication, event::direct_delivery};
use crucible_node_format::Phase;

#[derive(Clone, Copy, Debug)]
enum Transport {
    Seeded,
    CorruptDuplicate,
    Loss,
}

impl Transport {
    fn seeded(self) -> bool {
        matches!(self, Self::Seeded)
    }

    fn program(self) -> Vec<u8> {
        let value = if self.seeded() {
            serde_json::to_value(seeded_definition()).unwrap()
        } else {
            serde_json::to_value(faulted_definition(self)).unwrap()
        };
        canonical::canonical_json(&value).unwrap()
    }
}

fn seeded_definition() -> SeededLinkDefinition {
    SeededLinkDefinition {
        version: 1,
        seed: 77.into(),
        stream: id("ordinary/requests"),
        source_node: 17,
        latency_ps: 1000.into(),
        floor_ps: 1000.into(),
        jitter_ps: 5000.into(),
        reorder_ps: 3000.into(),
    }
}

fn faulted_definition(transport: Transport) -> FaultedLinkDefinition {
    let corrupt = matches!(transport, Transport::CorruptDuplicate);
    let probability = |enabled| FaultProbability {
        numerator: u64::from(enabled).into(),
        denominator: 1.into(),
    };
    FaultedLinkDefinition {
        version: 1,
        seed: 77.into(),
        stream: id("ordinary/requests"),
        source_node: 17,
        latency_ps: 1000.into(),
        floor_ps: 1000.into(),
        loss: probability(!corrupt),
        duplicate: probability(corrupt),
        duplicate_gap_ps: 100.into(),
        corrupt: probability(corrupt),
        corruption_bits: u32::from(corrupt),
    }
}

fn requests(transport: Transport) -> Vec<ScriptedRequest> {
    [10, 10_000]
        .into_iter()
        .enumerate()
        .map(|(index, time_ps)| ScriptedRequest {
            time_ps,
            payload: if transport.seeded() {
                BlockRequest::get_length(71 + index as u32)
                    .encode()
                    .unwrap()
            } else {
                [vec![0xff, 0, 0x80, 0x7f, 0x42], vec![0, 0xfe, 0, 1]][index].clone()
            },
        })
        .collect()
}

fn install(
    catalog: &mut InstalledNodeCatalog,
    directory: &std::path::Path,
    transport: Transport,
) -> Vec<InstalledNodeSelection> {
    let program = enroll(
        directory,
        "transport-program",
        &transport.program(),
        "application/octet-stream",
    );
    let script = ScriptedSource::new(
        if transport.seeded() {
            ScriptedRequestKind::Block
        } else {
            ScriptedRequestKind::Packet
        },
        requests(transport),
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let script = enroll(
        directory,
        "transport-script",
        &script,
        "application/octet-stream",
    );
    catalog
        .install_artifacts(vec![program.clone(), script.clone()])
        .unwrap();

    let sink = if transport.seeded() {
        let base = enroll(directory, "base", &[7, 8, 9], "application/octet-stream");
        catalog.install_artifacts(vec![base.clone()]).unwrap();
        InstalledNodeKind::HostIo {
            profile: InstalledHostIoProfile::Block {
                base_image: base.expected,
                source_node: 7,
                read_ns: 1.into(),
                write_ns: 1.into(),
                flush_ns: 1.into(),
                get_length_ns: 1.into(),
                per_byte_ns: 1.into(),
            },
        }
    } else {
        InstalledNodeKind::HostPacketReceiver {
            source_node: 7,
            latency_ps: 1000.into(),
        }
    };
    let link = if transport.seeded() {
        InstalledNodeKind::HostSeededLink {
            profile: super::super::super::InstalledSeededLinkProfile {
                program: program.expected,
                producer: id("source"),
                consumer: id("sink"),
            },
        }
    } else {
        InstalledNodeKind::HostFaultedLink {
            profile: super::super::super::InstalledFaultedLinkProfile {
                program: program.expected,
                producer: id("source"),
                consumer: id("sink"),
            },
        }
    };
    vec![
        InstalledNodeSelection {
            node: id("link"),
            owner: id("link-owner"),
            kind: link,
        },
        InstalledNodeSelection {
            node: id("sink"),
            owner: id("sink-owner"),
            kind: sink,
        },
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: script.expected,
                    consumer: id("link"),
                },
            },
        },
    ]
}

fn assert_output(
    publication: &NativePublication,
    bytes: &[u8],
    time: u64,
    parent: crucible_node_format::Position,
) {
    assert_eq!(publication.payload_bytes, bytes);
    assert_eq!(
        publication.payload,
        canonical::content_ref(bytes, "application/octet-stream").unwrap()
    );
    let evaluation = publication.evaluation.unwrap();
    assert_eq!(evaluation.time_ps.get(), time);
    assert_eq!(publication.causal_parents, vec![parent]);
    assert_eq!(parent.phase, Phase::Delivery);
    assert!(evaluation >= parent);
    assert!(publication.publication > evaluation);
}

#[test]
#[ignore = "requires source-built companion identity and ordinary installed transport execution"]
fn authored_transport_demands_preserve_rng_decisions_original_bytes_and_repeatability() {
    for transport in [
        Transport::Seeded,
        Transport::CorruptDuplicate,
        Transport::Loss,
    ] {
        let mut observed = Vec::new();
        for _ in 0..2 {
            let directory = tempfile::tempdir().unwrap();
            let mut catalog = catalog(directory.path());
            let selections = install(&mut catalog, directory.path(), transport);
            let baseline = catalog.scenario(&selections).unwrap();
            let original = baseline.canonical_bytes().unwrap();
            let raw = serde_json::to_vec_pretty(&demands(&baseline)).unwrap();
            let resolved = catalog
                .resolve_capabilities_raw(
                    &[InstalledCapabilityCandidate {
                        id: id("installed/ordinary-transport"),
                        selections,
                    }],
                    &raw,
                )
                .unwrap();
            assert_eq!(resolved.requirements_bytes, raw);
            assert_eq!(baseline.canonical_bytes().unwrap(), original);
            assert_ne!(
                resolved.scenario().world.scenario_ref,
                baseline.world.scenario_ref
            );

            let outcomes = execute(&mut catalog, &resolved, directory.path(), 30_000);
            let publications = outcomes
                .iter()
                .flat_map(|outcome| {
                    outcome
                        .scheduling
                        .as_ref()
                        .unwrap()
                        .publications
                        .iter()
                        .cloned()
                })
                .collect::<Vec<_>>();
            let from = |node: &str| {
                publications
                    .iter()
                    .filter(|publication| publication.endpoint.node_id == id(node))
                    .collect::<Vec<_>>()
            };
            let source = from("source");
            let link = from("link");
            let sink = from("sink");
            let originals = requests(transport);
            assert_eq!(source.len(), originals.len());
            for (publication, request) in source.iter().zip(&originals) {
                assert_eq!(publication.payload_bytes, request.payload);
                assert_eq!(publication.publication.time_ps.get(), request.time_ps);
            }

            let mut rng = DeviceRng::fork(
                77,
                if transport.seeded() {
                    "crucible/seeded-link-v1"
                } else {
                    "crucible/faulted-link-v1"
                },
                "ordinary/requests",
            );
            if transport.seeded() {
                assert_eq!(link.len(), originals.len());
                assert_eq!(sink.len(), originals.len());
                for (index, request) in originals.iter().enumerate() {
                    let draws = std::array::from_fn::<_, 5, _>(|_| rng.next_u64());
                    let at = request.time_ps
                        + 1000
                        + jitter_shift_ticks(draws[0], 5000)
                        + reorder_shift_ticks(draws[1], 3000);
                    let parent =
                        direct_delivery(source[index].publication, 0.into(), None).unwrap();
                    assert_output(link[index], &request.payload, at, parent);
                    let response = BlockResponse::decode(&sink[index].payload_bytes).unwrap();
                    assert_eq!(response.status, BlockStatus::Ok);
                    assert_eq!(response.request_id, 71 + index as u32);
                    assert_eq!(response.data, 3_u64.to_le_bytes());
                    assert_eq!(
                        sink[index].causal_parents,
                        vec![direct_delivery(link[index].publication, 0.into(), None).unwrap()]
                    );
                    let expected_response =
                        BlockResponse::ok(71 + index as u32, 3_u64.to_le_bytes().to_vec())
                            .encode()
                            .unwrap();
                    assert_output(
                        sink[index],
                        &expected_response,
                        at + 1000,
                        direct_delivery(link[index].publication, 0.into(), None).unwrap(),
                    );
                }
                assert_eq!(rng.position(), 10);
            } else {
                let definition = faulted_definition(transport);
                let mut native = definition.instantiate().unwrap();
                let mut journal = Vec::new();
                let mut expected = Vec::new();
                for (index, request) in originals.iter().enumerate() {
                    let parent =
                        direct_delivery(source[index].publication, 0.into(), None).unwrap();
                    let draws = std::array::from_fn::<_, 5, _>(|_| rng.next_u64());
                    let mut payload = request.payload.clone();
                    let selectors = if matches!(transport, Transport::CorruptDuplicate) {
                        let selector = rng.next_u64();
                        let bit = (selector % (payload.len() as u64 * 8)) as usize;
                        payload[bit / 8] ^= 1 << (bit % 8);
                        vec![selector]
                    } else {
                        Vec::new()
                    };
                    let resolved = definition
                        .consume(
                            &mut native,
                            &mut journal,
                            FaultedInput {
                                position: parent,
                                sequence: (index as u64).into(),
                                payload: &request.payload,
                            },
                            16,
                        )
                        .unwrap();
                    let recorded = serde_json::to_value(&journal[index]).unwrap();
                    assert_eq!(recorded["input"], serde_json::to_value(parent).unwrap());
                    assert_eq!(
                        recorded["sequence"],
                        serde_json::Value::String(index.to_string())
                    );
                    assert_eq!(
                        recorded["payload"],
                        serde_json::to_value(Bytes::new(request.payload.clone())).unwrap()
                    );
                    assert_eq!(
                        recorded["draws"]["values"],
                        serde_json::to_value(draws.map(|draw| draw.to_string())).unwrap()
                    );
                    assert_eq!(
                        recorded["draws"]["selectors"],
                        serde_json::to_value(
                            selectors.iter().map(u64::to_string).collect::<Vec<_>>()
                        )
                        .unwrap()
                    );
                    assert_eq!(
                        recorded["start"],
                        serde_json::Value::String(
                            (index * if selectors.is_empty() { 5 } else { 6 }).to_string()
                        )
                    );
                    if matches!(transport, Transport::Loss) {
                        assert!(resolved.deliveries.is_empty());
                        assert!(recorded["outputs"].as_array().unwrap().is_empty());
                    } else {
                        assert_eq!(resolved.deliveries.len(), 2);
                        assert_ne!(payload, request.payload);
                        for (copy, output) in resolved.deliveries.iter().enumerate() {
                            let at = request.time_ps + 1000 + copy as u64 * 100;
                            assert_eq!(output.payload, payload);
                            assert_eq!(output.key.delivery_icount, at);
                            expected.push((payload.clone(), at, parent));
                        }
                    }
                }
                assert_eq!(native.rng_position(), rng.position());
                assert_eq!(journal.len(), originals.len());
                assert_eq!(link.len(), expected.len());
                assert_eq!(sink.len(), expected.len());
                for (index, (bytes, at, parent)) in expected.iter().enumerate() {
                    assert_output(link[index], bytes, *at, *parent);
                    assert_output(
                        sink[index],
                        bytes,
                        at + 1000,
                        direct_delivery(link[index].publication, 0.into(), None).unwrap(),
                    );
                }
            }
            assert!(
                link.windows(2)
                    .all(|pair| pair[0].native_sequence < pair[1].native_sequence)
            );
            observed.push(publications);
        }
        assert_eq!(
            observed[0], observed[1],
            "fresh catalogs changed {transport:?} publications"
        );
    }
}

#[test]
#[ignore = "requires source-built companion identity and ordinary installed transport resolution"]
fn authored_transport_demands_refuse_controls_changed_programs_facets_and_bytes() {
    for transport in [Transport::Seeded, Transport::CorruptDuplicate] {
        let directory = tempfile::tempdir().unwrap();
        let mut catalog = catalog(directory.path());
        let selections = install(&mut catalog, directory.path(), transport);
        let baseline = catalog.scenario(&selections).unwrap();
        let required = demands(&baseline);
        let candidates = [InstalledCapabilityCandidate {
            id: id("installed/ordinary-transport"),
            selections,
        }];
        let link = required
            .nodes
            .iter()
            .position(|node| node.node == id("link"))
            .unwrap();
        let capabilities: CapabilityProfile =
            policy::object(&baseline, &baseline.compatibility[link].capabilities_ref).unwrap();
        let guarantees: GuaranteeProfile =
            policy::object(&baseline, &baseline.compatibility[link].guarantees_ref).unwrap();

        for operation in [
            "capture",
            "durable_restart",
            "fault_injection",
            "debug",
            "conditional_replay",
            "isolated_fork",
            "physical_pause",
            "quantum_begin",
        ] {
            let mut changed = required.clone();
            let facet = capabilities
                .facets
                .iter()
                .find(|facet| {
                    facet.id.as_str()
                        == match operation {
                            "capture" | "durable_restart" => "host/preservation-v1",
                            "physical_pause" => "host/physical-pause-v1",
                            _ => "host/exact-v1",
                        }
                })
                .unwrap()
                .clone();
            changed.nodes[link].operations =
                vec![crucible_engine::node_admission::OperationRequirement {
                    operation: id(operation),
                    facet,
                }];
            changed.nodes[link]
                .match_contract(
                    &baseline.descriptors[link],
                    &baseline.compatibility[link],
                    &capabilities,
                    &guarantees,
                )
                .unwrap();
            assert!(
                catalog.resolve_capabilities(&candidates, changed).is_err(),
                "unexpected ordinary transport operation: {operation}"
            );
        }
        let mut changed = required.clone();
        changed.nodes[link].guarantees.durable_restart = true;
        assert!(catalog.resolve_capabilities(&candidates, changed).is_err());
        let mut changed = required.clone();
        changed.nodes[link].operations[0].facet.version = 2;
        assert!(catalog.resolve_capabilities(&candidates, changed).is_err());
        let mut changed = required.clone();
        changed.nodes[link].operations[0].facet.configuration_ref =
            baseline.world.scenario_ref.clone();
        assert!(catalog.resolve_capabilities(&candidates, changed).is_err());

        if transport.seeded() {
            let mut changed = candidates.to_vec();
            changed[0].selections[1].kind = InstalledNodeKind::HostPacketReceiver {
                source_node: 7,
                latency_ps: 1000.into(),
            };
            // This edition still qualifies only the enrolled Block topology.
            assert!(catalog.scenario(&changed[0].selections).is_err());
            assert!(
                catalog
                    .resolve_capabilities(&changed, required.clone())
                    .is_err()
            );
        }

        let mut changed_program: serde_json::Value =
            serde_json::from_slice(&transport.program()).unwrap();
        changed_program["seed"] = serde_json::Value::String("78".into());
        let changed_program = canonical::canonical_json(&changed_program).unwrap();
        let artifact = enroll(
            directory.path(),
            "other-program",
            &changed_program,
            "application/octet-stream",
        );
        catalog.install_artifacts(vec![artifact.clone()]).unwrap();
        let mut changed = candidates.to_vec();
        match &mut changed[0].selections[link].kind {
            InstalledNodeKind::HostSeededLink { profile } => profile.program = artifact.expected,
            InstalledNodeKind::HostFaultedLink { profile } => profile.program = artifact.expected,
            _ => panic!("original transport selection"),
        }
        assert!(
            catalog
                .resolve_capabilities(&changed, required.clone())
                .is_err()
        );
        let resolved = catalog
            .resolve_capabilities(&candidates, required.clone())
            .unwrap();
        // A different valid canonical program must fail its original content
        // commitment during both regeneration and the actual preparation path.
        std::fs::write(directory.path().join("transport-program"), changed_program).unwrap();
        assert!(catalog.resolve_capabilities(&candidates, required).is_err());
        assert!(
            catalog
                .prepare_capability_world(&resolved, ExecutionId::from_bytes([114; 16]).unwrap())
                .is_err()
        );
    }
}
