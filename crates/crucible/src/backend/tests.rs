//! Mock simulation backend contract tests.

use super::*;

#[test]
fn simulation_backend_trait_is_object_safe_and_scheduler_timed() {
    let mut backend: Box<dyn SimulationBackend> = Box::new(MockSimulationBackend::new());
    let ceiling = VirtualTime { ticks: 11 };

    let observation = match backend.step_to(ceiling) {
        Ok(observation) => observation,
        Err(error) => panic!("mock backend should advance: {error}"),
    };

    assert_eq!(observation.requested_ceiling, ceiling);
    assert_eq!(observation.reached, ceiling);
    assert_eq!(backend.now(), ceiling);

    let input = BackendInput {
        node: NodeId {
            name: String::from("node-a"),
        },
        payload: vec![1, 2, 3],
    };
    if let Err(error) = backend.apply(&BackendEffect::DeliverInput(input), ceiling) {
        panic!("mock backend should apply scheduler-timed input: {error}");
    }
    let sample = match backend.fingerprint(NodeId {
        name: String::from("node-a"),
    }) {
        Ok(sample) => sample,
        Err(error) => panic!("mock backend should fingerprint: {error}"),
    };
    assert_eq!(sample.at, ceiling);

    let snapshot = match backend.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("mock backend should snapshot: {error}"),
    };
    if let Err(error) = backend.step_to(VirtualTime { ticks: 19 }) {
        panic!("mock backend should advance after snapshot: {error}");
    }
    assert_eq!(backend.now(), VirtualTime { ticks: 19 });
    if let Err(error) = backend.restore(&snapshot) {
        panic!("mock backend should restore known snapshot: {error}");
    }
    assert_eq!(backend.now(), ceiling);
}

#[test]
fn mock_simulation_backend_rejects_backend_owned_time_regression() {
    let mut backend = MockSimulationBackend::new();
    if let Err(error) = backend.step_to(VirtualTime { ticks: 7 }) {
        panic!("mock backend should advance: {error}");
    }

    let error = backend
        .step_to(VirtualTime { ticks: 6 })
        .expect_err("backend must not choose backwards time");

    assert!(error.to_string().contains("cannot advance backwards"));
    assert_eq!(backend.now(), VirtualTime { ticks: 7 });
}

#[test]
fn mock_simulation_backend_rejects_gdbstub_capability_with_typed_error() {
    let mut backend = MockSimulationBackend::new();
    let listen = match GdbListen::new("127.0.0.1:9000") {
        Ok(listen) => listen,
        Err(error) => panic!("test listen endpoint should be valid: {error}"),
    };
    let error = backend
        .open_gdbstub(
            NodeId {
                name: String::from("node-a"),
            },
            listen,
        )
        .expect_err("mock backend must not fake a gdbstub");

    assert_eq!(
        error,
        BackendError::Unsupported {
            capability: "open_gdbstub",
        }
    );
}
