//! Model-only complete-world capture credit preflight tests.
//!
//! The existing admitted custody fixture supplies effect counters. These cases
//! do not assert process image, hardware or backend continuation qualification.

use super::*;
use std::{io::Write, os::unix::fs::OpenOptionsExt};

fn capture_runtime() -> (
    crate::node_admission::AdmittedGraph,
    NodeRuntime,
    WorldActivation,
    Vec<Rc<RefCell<NativeState>>>,
) {
    let (graph, _) = crate::node_admission::test_fixture_isolated_execution(false);
    let (graph, nodes, states, record) = admitted_parts_from_graph(graph);
    let mut runtime = NodeRuntime::new(
        &graph,
        nodes,
        record,
        RuntimeLimits::default(),
        crate::node_contract::test_custody_slot(),
    )
    .unwrap_or_else(|failure| panic!("{}", failure.error));
    let activation = activate(&mut runtime);
    for state in &states {
        state.borrow_mut().native_capture_bytes = Some(b"native model".to_vec());
    }
    (graph, runtime, activation, states)
}

fn limits() -> NativeCaptureLimits {
    NativeCaptureLimits {
        maximum_record_bytes: 64 * 1024,
        maximum_total_record_bytes: 1024 * 1024,
        maximum_objects: 16,
        maximum_artifact_bytes: 1024 * 1024,
        maximum_total_artifact_bytes: 1024 * 1024,
    }
}

fn retained_artifact(bytes: &[u8]) -> NativeCaptureArtifact {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "crucible-capture-credit-{}-{sequence}",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(bytes).unwrap();
    let artifact = NativeCaptureArtifact::from_file(
        id("model-resource"),
        "resource/model.bin".into(),
        crucible_node_contract::canonical::content_ref(bytes, "application/octet-stream").unwrap(),
        file,
    )
    .unwrap();
    std::fs::remove_file(path).unwrap();
    artifact
}

#[test]
fn exhausted_world_object_credit_does_not_enter_second_capture_hook() {
    let (graph, mut runtime, activation, states) = capture_runtime();
    let source = runtime
        .runtime_snapshot(position(0), 1.into(), 1024 * 1024)
        .unwrap();
    let budget = NativeCaptureLimits {
        maximum_objects: 1,
        ..limits()
    };

    assert!(matches!(
        runtime.capture_installed_native(&graph, &activation, &source, budget),
        Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))
    ));

    assert_eq!(states[0].borrow().native_capture_calls, 1);
    assert_eq!(states[0].borrow().native_capture_effects, 1);
    assert_eq!(states[1].borrow().native_capture_calls, 0);
    assert_eq!(states[1].borrow().native_capture_effects, 0);
    assert_eq!(
        runtime
            .runtime_snapshot(position(0), 1.into(), 1024 * 1024)
            .unwrap(),
        source
    );
}

#[test]
fn later_owner_receives_remaining_world_record_credits_before_effect() {
    let (graph, mut runtime, activation, states) = capture_runtime();
    let source = runtime
        .runtime_snapshot(position(0), 1.into(), 1024 * 1024)
        .unwrap();
    let first_size = states[0]
        .borrow()
        .native_capture_bytes
        .as_ref()
        .unwrap()
        .len();
    let budget = NativeCaptureLimits {
        maximum_total_record_bytes: first_size + 1,
        ..limits()
    };

    assert!(matches!(
        runtime.capture_installed_native(&graph, &activation, &source, budget),
        Err(RuntimePollFailure::Native(_))
    ));

    assert_eq!(states[0].borrow().native_capture_effects, 1);
    let second = states[1].borrow();
    assert_eq!(second.native_capture_calls, 1);
    assert_eq!(second.native_capture_effects, 0);
    assert_eq!(
        second.native_capture_limits[0].maximum_total_record_bytes,
        1
    );
    assert_eq!(second.native_capture_limits[0].maximum_record_bytes, 1);
    assert_eq!(
        second.native_capture_limits[0].maximum_objects,
        budget.maximum_objects - 1
    );
}

#[test]
fn later_owner_receives_remaining_streamed_artifact_credits_before_effect() {
    let (graph, mut runtime, activation, states) = capture_runtime();
    let source = runtime
        .runtime_snapshot(position(0), 1.into(), 1024 * 1024)
        .unwrap();
    for state in &states {
        state.borrow_mut().native_capture_artifacts = vec![retained_artifact(b"native image")];
    }
    let first_size = states[0].borrow().native_capture_artifacts[0]
        .reference()
        .length
        .get();
    let budget = NativeCaptureLimits {
        maximum_total_artifact_bytes: first_size + 1,
        ..limits()
    };

    assert!(matches!(
        runtime.capture_installed_native(&graph, &activation, &source, budget),
        Err(RuntimePollFailure::Native(_))
    ));

    assert_eq!(states[0].borrow().native_capture_effects, 1);
    let second = states[1].borrow();
    assert_eq!(second.native_capture_calls, 1);
    assert_eq!(second.native_capture_effects, 0);
    assert_eq!(
        second.native_capture_limits[0].maximum_total_artifact_bytes,
        1
    );
    assert_eq!(second.native_capture_limits[0].maximum_artifact_bytes, 1);
}
