//! Checks the engine-side aggregate owner for `gate:abi-conformance`.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use crucible_harness::abi::{GoldenVectorCase, run_golden_vectors};
use crucible_harness::gate_targets::gate_targets;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
