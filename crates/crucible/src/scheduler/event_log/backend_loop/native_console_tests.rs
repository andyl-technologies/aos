//! Exercises the actual normalizer without implicit physical-time projection.

use super::*;
use crate::StepObservation;

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error(transparent)]
    Origin(#[from] crate::NativeConsoleOriginError),
    #[error(transparent)]
    Scheduler(#[from] SchedulerError),
}

struct RejectImplicitProjection;

impl QuantumLoop for RejectImplicitProjection {
    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: "unused diagnostic fixture drive".into(),
        })
    }

    fn backend_observation_time(
        &self,
        _node: &NodeId,
        _at: VirtualTime,
    ) -> Result<VirtualTime, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: "implicit native time projection refused".into(),
        })
    }
}

#[test]
fn native_console_normalizer_keeps_explicit_time_and_original_origin() -> Result<(), FixtureError> {
    let event = ObservableEvent::native_console_byte(
        VirtualTime { ticks: 100 },
        NodeId {
            name: "guest".into(),
        },
        crate::NativeConsoleByteOrigin {
            device: ContentHash { bytes: [9; 32] },
            stream: 7,
            logical_generation: 3,
            node_sequence: 1,
            stream_sequence: 1,
            emitted_ps: 50,
            raw_prefix: 1,
            vcpu: 0,
            byte: 0,
        },
    )?;
    let normalized = normalize_backend_observations(
        &RejectImplicitProjection,
        vec![event.clone()],
        VirtualTime { ticks: 200 },
    )?;
    assert_eq!(normalized, [event]);
    let modeled = ObservableEvent::console_output(
        VirtualTime { ticks: 50 },
        NodeId {
            name: "guest".into(),
        },
        vec![0],
    );
    assert!(
        normalize_backend_observations(
            &RejectImplicitProjection,
            vec![modeled],
            VirtualTime { ticks: 200 }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn console_output_stop_requires_the_owned_canonical_operation_endpoint() -> Result<(), FixtureError>
{
    let node = NodeId {
        name: "guest".into(),
    };
    let origin = crate::NativeConsoleByteOrigin {
        device: ContentHash { bytes: [9; 32] },
        stream: 1,
        logical_generation: 0,
        node_sequence: 2,
        stream_sequence: 2,
        emitted_ps: 81,
        raw_prefix: 0,
        vcpu: 0,
        byte: b'B',
    };
    let event = ObservableEvent::native_console_byte(
        VirtualTime { ticks: 5 },
        node.clone(),
        origin.clone(),
    )?;
    let mut step = StepObservation::from_advance_outcome(
        VirtualTime { ticks: 200 },
        crate::AdvanceOutcome::Paused {
            at: Icount { retired: 100 },
        },
    );
    step.physical_stop = crate::BackendPhysicalStop::ConsoleOutput { sequence: 2 };
    let mut completed = ConcurrentBackendRunOutcome {
        node: node.clone(),
        step,
        rng_evidence: Vec::new(),
        network_outputs: Vec::new(),
        observations: Vec::new(),
    };
    assert!(host_run_validation::validate_console_output(&completed).is_err());
    completed.observations.push(ObservableEvent::console_output(
        VirtualTime { ticks: 100 },
        node.clone(),
        b"B".to_vec(),
    ));
    assert!(host_run_validation::validate_console_output(&completed).is_err());
    completed.observations = vec![event.clone()];
    host_run_validation::validate_console_output(&completed)?;
    completed.step.physical_stop = crate::BackendPhysicalStop::ConsoleOutput { sequence: 3 };
    assert!(host_run_validation::validate_console_output(&completed).is_err());
    completed.step.physical_stop = crate::BackendPhysicalStop::ConsoleOutput { sequence: 2 };
    completed.node = NodeId {
        name: "other".into(),
    };
    assert!(host_run_validation::validate_console_output(&completed).is_err());
    assert_eq!(
        event.payload(),
        &crate::ObservableEventPayload::NativeConsoleByte { node, origin }
    );
    assert!(crate::BackendPhysicalStop::ConsoleOutput { sequence: 2 }.is_output());
    assert!(!crate::BackendPhysicalStop::UnclassifiedPause.is_output());
    Ok(())
}
