//! Production ownership of signal-driven network interception.
//!
//! The interceptor lives inside the backend quantum loop so committed QEMU
//! frames cannot bypass the exact pre-routing fault boundary. The executable
//! network adapter is layered onto this owner; the runtime itself is never
//! shared through a test-only or process-global side channel.

use super::*;
use crucible::{BackendNetworkOutputInterceptor, SchedulerEventLogAppend};

/// Owns the production signal continuation at the pre-routing network seam.
pub(super) struct ProductionFaultNetworkInterceptor {
    runtime: ProductionFaultRuntime,
    topology: crucible::model::WorldFaultTopology,
    coordinate: Option<u64>,
    coordinate_sequence: u64,
}

impl ProductionFaultNetworkInterceptor {
    /// Creates an interceptor around the admitted production continuation.
    #[must_use]
    pub(super) const fn new(
        runtime: ProductionFaultRuntime,
        topology: crucible::model::WorldFaultTopology,
    ) -> Self {
        Self {
            runtime,
            topology,
            coordinate: None,
            coordinate_sequence: 0,
        }
    }

    /// Returns mutable access for scheduler-boundary evaluation and snapshots.
    #[must_use]
    pub(super) fn runtime_mut(&mut self) -> &mut ProductionFaultRuntime {
        &mut self.runtime
    }

    /// Evaluates one ordered scheduler boundary through the owned continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the per-coordinate sequence overflows or
    /// the production runtime rejects evaluation.
    pub(super) fn evaluate_boundary(
        &mut self,
        coordinate: FaultCoordinate,
        backend: &mut ProductionNodeSet,
    ) -> Result<crucible::model::BindingEvaluation, SchedulerError> {
        let sequence = self.next_sequence(coordinate.virtual_nanos)?;
        self.runtime
            .evaluate_boundary(coordinate, sequence, backend)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("signal fault boundary failed closed: {error}"),
            })
    }

    fn next_sequence(&mut self, coordinate: u64) -> Result<u64, SchedulerError> {
        if self.coordinate == Some(coordinate) {
            self.coordinate_sequence =
                self.coordinate_sequence.checked_add(1).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: String::from(
                            "signal fault same-coordinate sequence space is exhausted",
                        ),
                    }
                })?;
        } else {
            self.coordinate = Some(coordinate);
            self.coordinate_sequence = 0;
        }
        Ok(self.coordinate_sequence)
    }
}

impl BackendNetworkOutputInterceptor<SingleScheduler, ProductionNodeSet>
    for ProductionFaultNetworkInterceptor
{
    fn intercept_network_outputs(
        &mut self,
        loop_impl: &mut SingleScheduler,
        _backend: &mut ProductionNodeSet,
        frontier: VirtualTime,
        outputs: &mut Vec<crucible::BackendNetworkOutput>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        let mut routed = Vec::new();
        for output in outputs.drain(..) {
            for route in loop_impl.resolve_backend_network_routes(&output)? {
                self.topology
                    .network_route_fault_targets(
                        &output.source.name,
                        &route.destination.name,
                        frontier.ticks,
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "network fault route `{}` {:?} is not represented by the admitted World fault topology: {error}",
                            route.link.name, route.direction
                        ),
                    })?;
                let mut output = output.clone();
                output.route = Some(route);
                routed.push(output);
            }
        }
        *outputs = routed;
        Ok(Vec::new())
    }
}
