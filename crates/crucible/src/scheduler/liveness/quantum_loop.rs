//! Authoritative single-scheduler implementation of the quantum-loop boundary.

use super::*;

impl QuantumLoop for SingleScheduler {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.drive_authoritative_quantum(request)
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.admit_control_at_boundary(control);
        let SchedulerControlDrain {
            events,
            applications,
        } = self.drain_control_events()?;
        let at = SimInstant {
            nanos: self.frontier.ticks,
        };
        let event_log = self.emit_quantum_event_log(&events, &[], &[], at, false)?;
        self.commit_control_applications(applications);
        self.yield_to_control_inbox();
        Ok(event_log.entries)
    }

    fn append_backend_observable_events(
        &mut self,
        events: Vec<ObservableEvent>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.append_observable_events(events)
    }

    fn append_backend_causal_decisions(
        &mut self,
        decisions: Vec<Decision>,
    ) -> Result<(Vec<Decision>, Configuration, SchedulerEventLogAppend), SchedulerError> {
        let original_len = self.configuration.schedule.decisions().len();
        let mut recorder = DecisionRecorder::new(self.configuration.clone());
        for decision in decisions {
            let Decision::AppRandom(expected) = decision else {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "live backend emitted a causal decision other than app-random",
                    ),
                });
            };
            let actual = recorder
                .serve_app_random_request(
                    expected.node.clone(),
                    expected.stream.clone(),
                    expected.request_id,
                    expected.width,
                )
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("live backend app-random decision was rejected: {error}"),
                })?;
            if actual != expected.value {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "live backend app-random value {} differs from seeded value {actual}",
                        expected.value
                    ),
                });
            }
        }
        let configuration = recorder.into_configuration();
        let recorded = configuration.schedule.decisions()[original_len..].to_vec();
        let at = SimInstant {
            nanos: self.frontier.ticks,
        };
        let append = self.emit_quantum_event_log(&[], &recorded, &[], at, false)?;
        self.configuration = configuration.clone();
        Ok((recorded, configuration, append))
    }
}
