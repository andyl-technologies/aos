//! Exact-checkpoint, attempt-boundary, and debug-policy quantum-loop tests.

use super::*;
use crucible::SchedulerOperationalFailureClass;

#[test]
fn stopped_checkpoint_artifact_keeps_the_pinned_source_without_copying() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("create checkpoint artifact directory: {error}"));
    let source = directory.path().join("active-overlay.qcow2");
    let bytes = b"stopped exact checkpoint bytes";
    fs::write(&source, bytes).unwrap_or_else(|error| panic!("write stopped artifact: {error}"));

    let artifact = checkpoint_artifact_from_stopped_file(&source, "test")
        .unwrap_or_else(|error| panic!("authenticate stopped artifact: {error}"));

    assert_eq!(artifact.identity, ContentHash::from_bytes(bytes));
    assert_eq!(artifact.length, bytes.len() as u64);
    assert!(artifact.chunks.is_empty());
    assert!(matches!(
        artifact.source,
        ProductionCheckpointArtifactSource::File(ref path) if path == &source
    ));
    let entries = fs::read_dir(directory.path())
        .unwrap_or_else(|error| panic!("read artifact directory: {error}"));
    assert_eq!(entries.count(), 1);
}

#[test]
fn exact_capture_reports_publication_and_release_failures_together() {
    let publication: Result<(), SchedulerError> = Err(SchedulerError::BoundaryViolation {
        message: String::from("publication failed"),
    });
    let cleanup = Err(SchedulerError::BoundaryViolation {
        message: String::from("resume failed"),
    });

    let error = match combine_exact_capture_result(publication, cleanup) {
        Ok(()) => panic!("both failures must reject capture"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("publication failed"));
    assert!(error.to_string().contains("resume failed"));
}

#[test]
fn attempt_quantum_reports_modeled_and_post_boundary_failures_together() {
    let operation: Result<(), SchedulerError> = Err(SchedulerError::BoundaryViolation {
        message: String::from("modeled quantum failed"),
    });
    let boundary = Err(LifecycleApiError::AttemptOperational {
        class: SchedulerOperationalFailureClass::Canceled,
        message: String::from("attempt cancellation failed closed"),
    });

    let error = match combine_attempt_quantum_boundary(operation, boundary) {
        Ok(()) => panic!("both failures must reject the quantum"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("modeled quantum failed"));
    assert!(
        error
            .to_string()
            .contains("attempt cancellation failed closed")
    );
    assert!(matches!(
        error,
        SchedulerError::OperationalBoundary {
            class: SchedulerOperationalFailureClass::Canceled,
            ..
        }
    ));
}

#[test]
fn attempt_quantum_admission_preserves_retryable_class() {
    let error = attempt_boundary_scheduler_error(
        "admit production attempt scheduler quantum",
        LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Retryable,
            message: String::from("resource controller temporarily unavailable"),
        },
    );

    assert!(matches!(
        error,
        SchedulerError::OperationalBoundary {
            class: SchedulerOperationalFailureClass::Retryable,
            ..
        }
    ));
    assert!(
        error
            .to_string()
            .contains("resource controller temporarily unavailable")
    );
}

fn debug_config(allow_requested_loopback_listen: bool) -> ProductionVmDebugConfig {
    ProductionVmDebugConfig {
        node: None,
        operator_listen: String::from("127.0.0.1:0"),
        all_nodes: allow_requested_loopback_listen,
        allow_requested_loopback_listen,
    }
}

#[test]
fn daemon_debug_policy_accepts_an_explicit_loopback_listener() {
    let listen = GdbListen::new("127.0.0.1:9000")
        .unwrap_or_else(|error| panic!("loopback listener should parse: {error}"));

    let requested = trusted_debug_listener(&debug_config(true), &listen)
        .unwrap_or_else(|error| panic!("daemon listener should be admitted: {error}"));

    assert_eq!(requested, SocketAddr::from(([127, 0, 0, 1], 9000)));
}

#[test]
fn fixed_debug_policy_rejects_a_different_listener() {
    let listen = GdbListen::new("127.0.0.1:9000")
        .unwrap_or_else(|error| panic!("loopback listener should parse: {error}"));

    let error = match trusted_debug_listener(&debug_config(false), &listen) {
        Ok(address) => panic!("fixed listener policy admitted {address}"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("does not match configured listener")
    );
}

#[test]
fn daemon_debug_policy_rejects_a_non_loopback_listener() {
    let listen = GdbListen::new("0.0.0.0:9000")
        .unwrap_or_else(|error| panic!("socket listener should parse: {error}"));

    let error = match trusted_debug_listener(&debug_config(true), &listen) {
        Ok(address) => panic!("daemon listener policy admitted {address}"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("must be loopback"));
}
