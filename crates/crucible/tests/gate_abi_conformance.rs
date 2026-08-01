//! Checks the engine-side aggregate owner for `gate:abi-conformance`.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use crucible::{
    GuestAssertionDetail, GuestAssertionKind, Icount, MarkerId, NodeId, ObservableEventPayload,
    observable_event_from_whitebox_marker_payload,
};
use crucible_harness::abi::{GoldenVectorCase, run_golden_vectors};
use crucible_harness::gate_targets::gate_targets;
use crucible_protocol::{
    WhiteboxAssertionMarkerBody, WhiteboxAssertionMarkerFlavor, WhiteboxCoverageMarkerBody,
    WhiteboxEventMarkerBody, WhiteboxLifecycleMarkerEvent, WhiteboxMarkerDetail,
    WhiteboxMarkerPayload, WhiteboxRandomRequestBody,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::enum_variant_names)]
enum BoundaryAbi {
    ShmemLayoutAbi,
    GuestHostProtocolAbi,
    ControlPlaneRpcAbi,
    PluginIoWireAbi,
}

#[test]
fn gate_abi_conformance_engine_aggregates_boundary_abi_owners() {
    assert_frozen_golden_vectors(&[
        BoundaryAbi::ShmemLayoutAbi,
        BoundaryAbi::GuestHostProtocolAbi,
        BoundaryAbi::ControlPlaneRpcAbi,
        BoundaryAbi::PluginIoWireAbi,
    ]);
    assert_decode_encode_roundtrip();
    assert_abi_version_field();
    assert_version_bump_regenerates_vectors();
    assert_structure_aware_fuzz_corpus();
    assert_whitebox_marker_payloads_map_to_engine_event_semantics();
}

fn assert_frozen_golden_vectors(expected_abis: &[BoundaryAbi]) {
    assert_eq!(
        expected_abis.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            BoundaryAbi::ShmemLayoutAbi,
            BoundaryAbi::GuestHostProtocolAbi,
            BoundaryAbi::ControlPlaneRpcAbi,
            BoundaryAbi::PluginIoWireAbi,
        ])
    );

    let implemented_targets = gate_targets()
        .iter()
        .filter(|target| target.gate == "gate:abi-conformance" && !target.placeholder)
        .map(|target| target.package)
        .collect::<BTreeSet<_>>();
    assert!(implemented_targets.contains("crucible-shmem"));
    assert!(implemented_targets.contains("crucible-protocol"));
    assert!(implemented_targets.contains("crucible-api"));
    assert!(implemented_targets.contains("crucible-qemu-plugin"));
}

fn assert_decode_encode_roundtrip() {
    let cases = [GoldenVectorCase {
        name: String::from("engine.aggregate.boundary-abi"),
        expected_version: 1,
        actual_version: 1,
        expected_bytes: b"crucible.aggregate.boundary-abi.v1\n".to_vec(),
        actual_bytes: b"crucible.aggregate.boundary-abi.v1\n".to_vec(),
    }];
    assert!(run_golden_vectors(&cases).is_ok());
}

fn assert_abi_version_field() {
    assert!(gate_targets().iter().any(|target| {
        target.gate == "gate:abi-conformance"
            && target.package == "crucible"
            && target.required_features == ["test-double"].as_slice()
    }));
}

fn assert_version_bump_regenerates_vectors() {
    let drift = [GoldenVectorCase {
        name: String::from("engine.aggregate.boundary-abi"),
        expected_version: 1,
        actual_version: 2,
        expected_bytes: b"crucible.aggregate.boundary-abi.v1\n".to_vec(),
        actual_bytes: b"crucible.aggregate.boundary-abi.v1\n".to_vec(),
    }];
    assert!(run_golden_vectors(&drift).is_err());
}

fn assert_structure_aware_fuzz_corpus() {
    let target_pairs = gate_targets()
        .iter()
        .filter(|target| target.gate == "gate:abi-conformance")
        .map(|target| (target.package, target.test_target))
        .collect::<BTreeSet<_>>();
    assert!(target_pairs.contains(&("crucible-protocol", "gate_abi_conformance")));
    assert!(target_pairs.contains(&("crucible-qemu-plugin", "gate_abi_conformance")));
}

#[test]
fn whitebox_marker_payloads_map_to_engine_event_semantics() {
    assert_whitebox_marker_payloads_map_to_engine_event_semantics();
}

fn assert_whitebox_marker_payloads_map_to_engine_event_semantics() {
    let at = Icount { retired: 42 };
    let node = node("db-0");
    let assertion = WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
        flavor: WhiteboxAssertionMarkerFlavor::Reachable,
        condition: true,
        must_hit: true,
        id: String::from("guest.ready"),
        message: String::from("guest reported ready"),
        location: String::from("guest.rs:7"),
        details: vec![WhiteboxMarkerDetail::new("phase", "setup")],
    });
    let mapped = match observable_event_from_whitebox_marker_payload(at, node.clone(), &assertion) {
        Some(event) => event,
        None => panic!("assertion marker payload must map to an observable event"),
    };
    match mapped.payload() {
        ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node: mapped_node,
            marker,
        } => {
            assert_eq!(retired_icount, &at);
            assert_eq!(mapped_node, &node);
            assert_eq!(marker.id.name, "guest.ready");
            assert_eq!(marker.message, "guest reported ready");
            assert_eq!(marker.kind, GuestAssertionKind::Reachable);
            assert!(marker.condition);
            assert!(marker.must_hit);
            assert_eq!(
                marker.details,
                vec![GuestAssertionDetail::new("phase", "setup")]
            );
            assert_eq!(marker.location, "guest.rs:7");
        }
        other => panic!("assertion marker mapped to wrong event payload: {other:?}"),
    }

    let coverage = WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
        point: String::from("hot-path"),
    });
    let mapped = match observable_event_from_whitebox_marker_payload(at, node.clone(), &coverage) {
        Some(event) => event,
        None => panic!("coverage marker payload must map to an observable event"),
    };
    assert_eq!(
        mapped.payload(),
        &ObservableEventPayload::CoverageMarker {
            retired_icount: at,
            node: node.clone(),
            marker: MarkerId::from_name("hot-path"),
        },
    );

    let event = WhiteboxMarkerPayload::Event(WhiteboxEventMarkerBody {
        name: String::from("guest.note"),
        details: Vec::new(),
    });
    let mapped = match observable_event_from_whitebox_marker_payload(at, node.clone(), &event) {
        Some(event) => event,
        None => panic!("diagnostic marker payload must map to an observable event"),
    };
    assert_eq!(
        mapped.payload(),
        &ObservableEventPayload::GuestMarker {
            retired_icount: at,
            node: node.clone(),
            marker: MarkerId::from_name("guest.note"),
        },
    );

    let lifecycle = WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::TestDone);
    let mapped = match observable_event_from_whitebox_marker_payload(at, node.clone(), &lifecycle) {
        Some(event) => event,
        None => panic!("lifecycle marker payload must map to an observable event"),
    };
    assert_eq!(
        mapped.payload(),
        &ObservableEventPayload::GuestMarker {
            retired_icount: at,
            node: node.clone(),
            marker: MarkerId::from_name("lifecycle.test_done"),
        },
    );

    let random = WhiteboxMarkerPayload::RandomRequest(WhiteboxRandomRequestBody {
        request_id: 1,
        width_bytes: 4,
        stream_tag: String::from("rng"),
    });
    assert_eq!(
        observable_event_from_whitebox_marker_payload(at, node, &random),
        None
    );
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_string(),
    }
}
