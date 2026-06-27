//! Checks the harness wiring for `gate:abi-conformance`.

#![forbid(unsafe_code)]

use crucible_harness::abi::{GoldenVectorCase, GoldenVectorMismatchKind, run_golden_vectors};
use crucible_harness::gate_targets::gate_targets;
use crucible_harness::{GateStatus, find_gate};

#[test]
fn gate_abi_conformance_is_implemented_in_catalog_and_targets() {
    assert!(matches!(
        find_gate("gate:abi-conformance").map(|spec| spec.status),
        Some(GateStatus::Implemented)
    ));

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
        ],
    );
}

#[test]
fn golden_vector_runner_accepts_matching_vectors() {
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
