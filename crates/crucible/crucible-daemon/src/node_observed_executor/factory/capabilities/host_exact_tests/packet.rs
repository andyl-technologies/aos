//! Exercises authored ordinary exact packet demands through the owning executor.
//!
//! Original opaque input bytes and fixed response delay supply the oracle. These
//! controls do not admit packet capture, control operations or transport faults.

use super::*;
use crucible_node_format::Phase;

const PACKETS: [(u64, &[u8]); 2] = [
    (10, &[0xff, 0x00, 0x80, 0x7f, 0x42]),
    (100, &[0x00, 0xfe, 0x00, 0x01]),
];

fn packet_source(
    catalog: &mut InstalledNodeCatalog,
    directory: &std::path::Path,
) -> Vec<InstalledNodeSelection> {
    let script = ScriptedSource::new(
        ScriptedRequestKind::Packet,
        PACKETS
            .iter()
            .map(|(time_ps, bytes)| ScriptedRequest {
                time_ps: *time_ps,
                payload: bytes.to_vec(),
            })
            .collect(),
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let script = enroll(
        directory,
        "packet-script",
        &script,
        "application/octet-stream",
    );
    catalog.install_artifacts(vec![script.clone()]).unwrap();

    vec![
        InstalledNodeSelection {
            node: id("packet"),
            owner: id("packet-owner"),
            kind: InstalledNodeKind::HostPacketReceiver {
                source_node: 7,
                latency_ps: 1000.into(),
            },
        },
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: script.expected,
                    consumer: id("packet"),
                },
            },
        },
    ]
}

#[test]
#[ignore = "requires source-built companion identity and installed original packet execution"]
fn authored_packet_demands_execute_original_opaque_echo_and_repeatable_publications() {
    let mut observed = Vec::new();
    for _ in 0..2 {
        let directory = tempfile::tempdir().unwrap();
        let mut catalog = catalog(directory.path());
        let selections = packet_source(&mut catalog, directory.path());
        let baseline = catalog.scenario(&selections).unwrap();
        let original = baseline.canonical_bytes().unwrap();
        let raw = serde_json::to_vec_pretty(&demands(&baseline)).unwrap();

        let resolved = catalog
            .resolve_capabilities_raw(
                &[InstalledCapabilityCandidate {
                    id: id("installed/packet-exact"),
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

        let outcomes = execute(&mut catalog, &resolved, directory.path(), 2000);
        let publications = outcomes
            .iter()
            .flat_map(|outcome| outcome.scheduling.as_ref().unwrap().publications.iter())
            .collect::<Vec<_>>();
        let sent = publications
            .iter()
            .filter(|publication| publication.endpoint.node_id == id("source"))
            .collect::<Vec<_>>();
        let echoed = publications
            .iter()
            .filter(|publication| publication.endpoint.node_id == id("packet"))
            .copied()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(sent.len(), PACKETS.len());
        assert_eq!(echoed.len(), PACKETS.len());
        for (index, (time_ps, bytes)) in PACKETS.iter().enumerate() {
            let original = sent[index];
            let response = &echoed[index];
            assert_eq!(original.payload_bytes, *bytes);
            assert_eq!(response.payload_bytes, *bytes);
            assert_eq!(response.payload, original.payload);
            assert_eq!(
                response.payload,
                canonical::content_ref(bytes, "application/octet-stream").unwrap()
            );
            let evaluation = response.evaluation.unwrap();
            assert_eq!(evaluation.time_ps.get(), *time_ps + 1000);
            assert!(response.publication > evaluation);
            assert_eq!(response.causal_parents.len(), 1);
            assert_eq!(response.causal_parents[0].time_ps.get(), *time_ps);
            assert_eq!(response.causal_parents[0].phase, Phase::Delivery);
        }
        assert!(
            echoed
                .windows(2)
                .all(|pair| pair[0].native_sequence < pair[1].native_sequence)
        );
        observed.push(echoed);
    }

    // Compare complete original response publications, including octets, content
    // identities, FIFO positions and parents, across fresh owning catalogs.
    assert_eq!(observed[0], observed[1]);
}

#[test]
#[ignore = "requires source-built companion identity and installed original packet resolution"]
fn authored_packet_demands_refuse_other_facets_changed_latency_and_changed_original_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let mut catalog = catalog(directory.path());
    let selections = packet_source(&mut catalog, directory.path());
    let baseline = catalog.scenario(&selections).unwrap();
    let required = demands(&baseline);
    let candidates = [InstalledCapabilityCandidate {
        id: id("installed/packet-exact"),
        selections,
    }];
    let packet = required
        .nodes
        .iter()
        .position(|node| node.node == id("packet"))
        .unwrap();
    let capabilities: CapabilityProfile =
        policy::object(&baseline, &baseline.compatibility[packet].capabilities_ref).unwrap();
    let guarantees: GuaranteeProfile =
        policy::object(&baseline, &baseline.compatibility[packet].guarantees_ref).unwrap();

    for operation in [
        "capture",
        "durable_restart",
        "debug",
        "fault_injection",
        "conditional_replay",
        "isolated_fork",
        "physical_pause",
        "quantum_begin",
    ] {
        let mut changed = required.clone();
        let facet_id = match operation {
            "capture" | "durable_restart" => "host/preservation-v1",
            "physical_pause" => "host/physical-pause-v1",
            _ => "host/exact-v1",
        };
        let facet = capabilities
            .facets
            .iter()
            .find(|facet| facet.id.as_str() == facet_id)
            .unwrap()
            .clone();
        changed.nodes[packet].operations =
            vec![crucible_engine::node_admission::OperationRequirement {
                operation: id(operation),
                facet,
            }];
        // Labels and complete advertised facet bodies match. Installed ordinary
        // operation policy must independently refuse the unqualified meaning.
        changed.nodes[packet]
            .match_contract(
                &baseline.descriptors[packet],
                &baseline.compatibility[packet],
                &capabilities,
                &guarantees,
            )
            .unwrap();
        assert!(
            catalog.resolve_capabilities(&candidates, changed).is_err(),
            "unexpected packet operation: {operation}"
        );
    }
    let mut changed = required.clone();
    changed.nodes[packet].guarantees.durable_restart = true;
    assert!(catalog.resolve_capabilities(&candidates, changed).is_err());
    let mut changed = required.clone();
    changed.nodes[packet].operations[0].facet.version = 2;
    assert!(catalog.resolve_capabilities(&candidates, changed).is_err());
    let mut changed = required.clone();
    changed.nodes[packet].operations[0].facet.configuration_ref =
        baseline.world.scenario_ref.clone();
    assert!(catalog.resolve_capabilities(&candidates, changed).is_err());

    let mut changed = candidates.to_vec();
    changed[0].selections[packet].kind = InstalledNodeKind::HostPacketReceiver {
        source_node: 7,
        latency_ps: 2000.into(),
    };
    assert!(
        catalog
            .resolve_capabilities(&changed, required.clone())
            .is_err()
    );
    let resolved = catalog
        .resolve_capabilities(&candidates, required.clone())
        .unwrap();
    let script_path = directory.path().join("packet-script");
    let mut changed_bytes = std::fs::read(&script_path).unwrap();
    let last = changed_bytes.last_mut().unwrap();
    *last ^= 0x01;
    // This remains a valid opaque-packet script. The immutable installed content
    // commitment, rather than a parser error, must reject the changed octets.
    assert!(ScriptedSource::from_script_bytes(&changed_bytes).is_ok());
    std::fs::write(script_path, changed_bytes).unwrap();
    assert!(catalog.resolve_capabilities(&candidates, required).is_err());
    assert!(
        catalog
            .prepare_capability_world(&resolved, ExecutionId::from_bytes([113; 16]).unwrap(),)
            .is_err()
    );
}
