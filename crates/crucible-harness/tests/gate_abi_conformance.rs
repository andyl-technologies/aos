//! Checks the harness wiring for `gate:abi-conformance`.

#![forbid(unsafe_code)]

use crucible_harness::abi::{GoldenVectorCase, GoldenVectorMismatchKind, run_golden_vectors};
use crucible_harness::gate_targets::gate_targets;
use crucible_harness::{GateStatus, find_gate};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::enum_variant_names)]
enum BoundaryAbi {
    ShmemLayoutAbi,
    GuestHostProtocolAbi,
    ControlPlaneRpcAbi,
}

#[test]
fn gate_abi_conformance_is_implemented_in_catalog_and_targets() {
    assert!(matches!(
        find_gate("gate:abi-conformance").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));

    assert_frozen_golden_vectors(&[
        BoundaryAbi::ShmemLayoutAbi,
        BoundaryAbi::GuestHostProtocolAbi,
        BoundaryAbi::ControlPlaneRpcAbi,
    ]);
    assert_decode_encode_roundtrip();
    assert_abi_version_field();
    assert_version_bump_regenerates_vectors();
    assert_structure_aware_fuzz_corpus();
}

fn assert_frozen_golden_vectors(boundary_abis: &[BoundaryAbi]) {
    assert_eq!(
        boundary_abis,
        [
            BoundaryAbi::ShmemLayoutAbi,
            BoundaryAbi::GuestHostProtocolAbi,
            BoundaryAbi::ControlPlaneRpcAbi,
        ]
    );

    let targets = gate_targets()
        .iter()
        .filter(|target| target.gate == "gate:abi-conformance")
        .map(|target| (target.package, target.test_target, target.placeholder))
        .collect::<Vec<_>>();

    assert_eq!(
        targets,
        vec![
            ("crucible-harness", "gate_abi_conformance", false),
            ("crucible-shmem", "gate_abi_conformance", false),
            ("crucible-protocol", "gate_abi_conformance", false),
            ("crucible-api", "gate_abi_conformance", false),
            ("crucible-qemu-plugin", "gate_abi_conformance", false),
            ("crucible-guest", "gate_abi_conformance", false),
            ("crucible", "gate_abi_conformance", false),
        ],
    );
}

#[test]
fn golden_vector_runner_accepts_matching_vectors() {
    assert_decode_encode_roundtrip();
}

fn assert_decode_encode_roundtrip() {
    let cases = [GoldenVectorCase {
        name: String::from("rpc.hello-request"),
        expected_version: 1,
        actual_version: 1,
        expected_bytes: b"crucible.rpc/hello-request\n".to_vec(),
        actual_bytes: b"crucible.rpc/hello-request\n".to_vec(),
    }];

    assert!(run_golden_vectors(&cases).is_ok());
}

#[test]
fn golden_vector_runner_rejects_version_and_byte_drift() {
    assert_abi_version_field();
    assert_version_bump_regenerates_vectors();
}

fn assert_abi_version_field() {
    let matching_version = [GoldenVectorCase {
        name: String::from("rpc.version"),
        expected_version: 1,
        actual_version: 1,
        expected_bytes: b"stable".to_vec(),
        actual_bytes: b"stable".to_vec(),
    }];
    assert!(run_golden_vectors(&matching_version).is_ok());
}

fn assert_version_bump_regenerates_vectors() {
    let version_drift = [GoldenVectorCase {
        name: String::from("rpc.version"),
        expected_version: 1,
        actual_version: 2,
        expected_bytes: b"stable".to_vec(),
        actual_bytes: b"stable".to_vec(),
    }];
    let error = match run_golden_vectors(&version_drift) {
        Ok(()) => panic!("version drift must fail"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind,
        GoldenVectorMismatchKind::Version {
            expected: 1,
            actual: 2,
        },
    );
}

#[test]
fn golden_vector_runner_rejects_byte_drift() {
    let byte_drift = [GoldenVectorCase {
        name: String::from("rpc.bytes"),
        expected_version: 1,
        actual_version: 1,
        expected_bytes: b"stable".to_vec(),
        actual_bytes: b"drifted".to_vec(),
    }];
    let error = match run_golden_vectors(&byte_drift) {
        Ok(()) => panic!("byte drift must fail"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind,
        GoldenVectorMismatchKind::Bytes {
            expected_len: 6,
            actual_len: 7,
        },
    );
}

fn assert_structure_aware_fuzz_corpus() {
    let targets = gate_targets()
        .iter()
        .filter(|target| target.gate == "gate:abi-conformance")
        .map(|target| (target.package, target.test_target))
        .collect::<Vec<_>>();
    assert!(targets.contains(&("crucible-protocol", "gate_abi_conformance")));
    assert!(targets.contains(&("crucible-qemu-plugin", "gate_abi_conformance")));
}
