//! Connects the real worker executable to actual complete typed launch fixtures.
//!
//! These ordinary process controls exercise protocol connectivity and parity.
//! They do not substitute for cgroup/quota/confinement or accepted Source banks.

#[path = "worker_stdio/case.rs"]
mod case;
#[path = "worker_stdio/fixture.rs"]
mod fixture;

use crucible_engine::node_adapters::cnp::source_birth_derivation::{
    derive::{
        DerivationInput, ExpectedCoordinator, OutputLimits, WorldRefusal, derive_source_birth,
    },
    literal_value::LiteralWriteWorkspace,
    request_wire::{JobContext, OperationalLimits, RequestInput, write_request},
    result_wire::{FailureInfo, Identity, ResultHeader, WireLimits, verify_stdout},
};
use crucible_node_transport::reference_packet::service::PacketNative5LaunchValidationProjection;
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

fn limits() -> OperationalLimits {
    OperationalLimits {
        maximum_input_bytes: 8 * 1024 * 1024,
        maximum_elements: 1_000_000,
        maximum_output_bytes: 8 * 1024 * 1024,
        maximum_diagnostic_bytes: 4096,
    }
}
fn context() -> JobContext {
    // Inert correlations for ordinary executable connectivity, not installed
    // identities or authorization. The real supervisor supplies measured IDs.
    JobContext {
        task_digest: [1; 32],
        worker_digest: [2; 32],
        algorithm_digest: [3; 32],
    }
}
fn run(bytes: &[u8], selected_worker: [u8; 32]) -> Output {
    let hex = |bytes: [u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let bounds = limits();
    let mut child = Command::new(env!("CARGO_BIN_EXE_crucible-source-birth-worker"))
        .args([
            "--worker-digest",
            &hex(selected_worker),
            "--algorithm-digest",
            &hex(context().algorithm_digest),
            "--maximum-input-bytes",
            &bounds.maximum_input_bytes.to_string(),
            "--maximum-elements",
            &bounds.maximum_elements.to_string(),
            "--maximum-output-bytes",
            &bounds.maximum_output_bytes.to_string(),
            "--maximum-diagnostic-bytes",
            &bounds.maximum_diagnostic_bytes.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let written = child.stdin.take().unwrap().write_all(bytes);
    if let Err(error) = written {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return child.wait_with_output().unwrap();
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("ordinary worker input failed: {error}");
    }
    child.wait_with_output().unwrap()
}
fn wire_limits() -> WireLimits {
    WireLimits {
        maximum_frame_bytes: 8 * 1024 * 1024 + 240,
        maximum_diagnostic_bytes: 4096,
    }
}

#[test]
fn actual_producer_and_reactive_child_match_facade_both_banks() {
    for reactive in [false, true] {
        let (launch, original) = case::complete_launch(reactive);
        let plan = case::planned(&launch);
        let projection = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
        let expected = || {
            if reactive {
                ExpectedCoordinator::Reactive(&original)
            } else {
                ExpectedCoordinator::Producer(&original)
            }
        };
        let mut bytes = Vec::new();
        let receipt = write_request(
            RequestInput {
                context: context(),
                launch: &projection,
                expected: expected(),
                registration: &plan,
            },
            &mut bytes,
            limits(),
            LiteralWriteWorkspace::new(8192).unwrap(),
        )
        .unwrap();
        let reference = derive_source_birth(
            DerivationInput {
                launch: &projection,
                expected: expected(),
                registration: &plan,
            },
            OutputLimits {
                maximum_output_bytes: limits().maximum_output_bytes,
            },
        )
        .unwrap();
        let child = run(&bytes, context().worker_digest);
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(child.stderr.is_empty());
        let verified = verify_stdout(
            &child.stdout,
            Identity {
                task_digest: context().task_digest,
                input_digest: receipt.input_digest,
            },
            wire_limits(),
        )
        .unwrap();
        assert_eq!(verified.source_bytes(), reference.source_bytes());
        assert_eq!(
            verified.registration_bytes(),
            reference.registration_bytes()
        );
        assert_eq!(receipt.wire_bytes, bytes.len());
    }
}

#[test]
fn actual_child_refusal_keeps_original_cause_stage_and_diagnostic() {
    let (launch, _original) = case::complete_launch(false);
    let plan = case::planned(&launch);
    let projection = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
    let mut bytes = Vec::new();
    let receipt = write_request(
        RequestInput {
            context: context(),
            launch: &projection,
            expected: ExpectedCoordinator::Deferred(WorldRefusal::ForeignCreatorProcess),
            registration: &plan,
        },
        &mut bytes,
        limits(),
        LiteralWriteWorkspace::new(8192).unwrap(),
    )
    .unwrap();
    let reference = derive_source_birth(
        DerivationInput {
            launch: &projection,
            expected: ExpectedCoordinator::Deferred(WorldRefusal::ForeignCreatorProcess),
            registration: &plan,
        },
        OutputLimits {
            maximum_output_bytes: limits().maximum_output_bytes,
        },
    )
    .unwrap_err();
    let identity = Identity {
        task_digest: context().task_digest,
        input_digest: receipt.input_digest,
    };
    let diagnostic = reference.cause().to_string();
    let expected = ResultHeader::failure(
        identity,
        FailureInfo::from_derivation(&reference).unwrap(),
        &diagnostic,
        4096,
    )
    .unwrap();
    let child = run(&bytes, context().worker_digest);
    assert!(child.status.success());
    assert!(child.stderr.is_empty());
    let verified = verify_stdout(&child.stdout, identity, wire_limits()).unwrap();
    assert_eq!(verified.header().encode(), expected.encode());
    assert_eq!(verified.diagnostic(), diagnostic.as_str());
    assert!(verified.source_bytes().is_empty());
    assert!(verified.registration_bytes().is_empty());
}

#[test]
fn actual_child_rejects_foreign_digest_corruption_truncation_and_extra_bytes() {
    let (launch, original) = case::complete_launch(false);
    let plan = case::planned(&launch);
    let projection = PacketNative5LaunchValidationProjection::from_launch_data(&launch);
    let mut bytes = Vec::new();
    write_request(
        RequestInput {
            context: context(),
            launch: &projection,
            expected: ExpectedCoordinator::Producer(&original),
            registration: &plan,
        },
        &mut bytes,
        limits(),
        LiteralWriteWorkspace::new(8192).unwrap(),
    )
    .unwrap();
    let wrong = run(&bytes, [9; 32]);
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    let mut corrupt = bytes.clone();
    corrupt[120] ^= 1;
    let mut extra = bytes.clone();
    extra.push(0);
    for invalid in [
        corrupt.as_slice(),
        &bytes[..159],
        &bytes[..bytes.len() - 1],
        extra.as_slice(),
    ] {
        let child = run(invalid, context().worker_digest);
        assert!(!child.status.success());
        assert!(child.stdout.is_empty());
    }
}
