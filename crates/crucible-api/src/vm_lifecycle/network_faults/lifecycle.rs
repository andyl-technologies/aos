//! Lifecycle publication preflight at the network-interceptor boundary.

use super::*;

impl ProductionFaultEvaluationCursor {
    fn preview_next_sequence(
        self,
        coordinate: u64,
    ) -> Result<ProductionFaultEvaluationSequence, SchedulerError> {
        let mut preview = self;
        preview.next_sequence(coordinate)
    }
}

impl ProductionFaultNetworkInterceptor {
    pub(in crate::vm_lifecycle) fn preview_node_lifecycle_intents(
        &self,
        coordinate: FaultCoordinate,
        nodes: &mut ProductionNodeSet,
    ) -> Result<Vec<crucible_qemu::QemuNodeLifecycleIntent>, SchedulerError> {
        let sequence = self
            .cursor
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault evaluation cursor lock is poisoned"),
            })?
            .preview_next_sequence(coordinate.virtual_nanos)?;
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?;
        let limits = runtime.resource_limits();
        runtime
            .preview_node_lifecycle_intents(coordinate, sequence.same_coordinate, nodes)
            .map_err(|error| match error {
                crucible_qemu::ProductionFaultRuntimeError::ResourceLimit(error) => {
                    super::super::quantum_loop::map_journal_limit(error, limits)
                }
                error => SchedulerError::BoundaryViolation {
                    message: format!("preview production lifecycle intent: {error}"),
                },
            })
    }
}
