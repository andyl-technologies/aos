//! Production ownership of signal-driven network interception.
//!
//! The interceptor lives inside the backend quantum loop so committed QEMU
//! frames cannot bypass the exact pre-routing fault boundary. The executable
//! network adapter is layered onto this owner; the runtime itself is never
//! shared through a test-only or process-global side channel.

use super::*;
use crucible::model::{
    ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION, FaultObjectId, FaultObservation,
    FaultObservationKind, FaultOpportunity, FaultPhase, NetworkAvailabilityState,
    NetworkEffectSpecification, OpportunityPayload, ResolvedBindingAction,
};
use crucible::{BackendNetworkOutputInterceptor, SchedulerEventLogAppend};

/// Owns the production signal continuation at the pre-routing network seam.
pub(super) struct ProductionFaultNetworkInterceptor {
    runtime: ProductionFaultRuntime,
    topology: crucible::model::WorldFaultTopology,
    links: Vec<crucible::LinkDef>,
    coordinate: Option<u64>,
    coordinate_sequence: u64,
}

impl ProductionFaultNetworkInterceptor {
    /// Creates an interceptor around the admitted production continuation.
    #[must_use]
    pub(super) const fn new(
        runtime: ProductionFaultRuntime,
        topology: crucible::model::WorldFaultTopology,
        links: Vec<crucible::LinkDef>,
    ) -> Self {
        Self {
            runtime,
            topology,
            links,
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
        scheduler: &mut SingleScheduler,
        backend: &mut ProductionNodeSet,
    ) -> Result<crucible::model::BindingEvaluation, SchedulerError> {
        let sequence = self.next_sequence(coordinate.virtual_nanos)?;
        let mut evaluation = self
            .runtime
            .evaluate_boundary(coordinate, sequence, backend)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("signal fault boundary failed closed: {error}"),
            })?;
        let impulses = self.runtime.drain_host_impulses();
        if !impulses.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "network availability produced an invalid boundary impulse action",
                ),
            });
        }
        evaluation
            .observations
            .extend(self.drop_unavailable_inflight(coordinate, scheduler)?);
        Ok(evaluation)
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

    fn drop_unavailable_inflight(
        &self,
        coordinate: FaultCoordinate,
        scheduler: &mut SingleScheduler,
    ) -> Result<Vec<FaultObservation>, SchedulerError> {
        let mut observations = Vec::new();
        for link in &self.links {
            let (endpoint_a, endpoint_b) = link.endpoints();
            for (source, destination) in [(endpoint_a, endpoint_b), (endpoint_b, endpoint_a)] {
                let stages = self
                    .topology
                    .network_route_fault_targets(
                        &source.name,
                        &destination.name,
                        coordinate.virtual_nanos,
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "cannot resolve in-flight availability route `{}` to `{}`: {error}",
                            source.name, destination.name
                        ),
                    })?;
                let mut blockers = BTreeMap::<ContentHash, ResolvedBindingAction>::new();
                for stage in stages
                    .iter()
                    .filter(|stage| stage.phases().contains(&FaultPhase::Admit))
                {
                    for action in self
                        .runtime
                        .host_state()
                        .matching(&stage.target, FaultPhase::Admit)
                    {
                        let EffectSpecification::Network(
                            NetworkEffectSpecification::Availability { state, .. },
                        ) = action.effect.specification()
                        else {
                            continue;
                        };
                        if !availability_allows(*state, stage.direction) {
                            blockers.insert(action.id(), action.clone());
                        }
                    }
                }
                if blockers.is_empty() {
                    continue;
                }
                let dropped = scheduler.drop_network_inflight_for_route(source, destination)?;
                if dropped.frame_count == 0 {
                    continue;
                }
                for action in blockers.values() {
                    let evidence = ContentHash::from_canonical_material(
                        "crucible.network-availability-inflight-drop.v1",
                        &format!(
                            "action={}\nroute-evidence={}\nframes={}",
                            action.id().to_hex(),
                            dropped.evidence.to_hex(),
                            dropped.frame_count
                        ),
                    );
                    observations.push(FaultObservation {
                        semantic_version: FAULT_RUNTIME_STATE_VERSION,
                        kind: FaultObservationKind::NetworkProfile,
                        coordinate,
                        binding: Some(action.binding.clone()),
                        target: Some(action.target.clone()),
                        opportunity: None,
                        evidence,
                    });
                }
            }
        }
        Ok(observations)
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
        let mut observations = Vec::new();
        let mut next_wakeup_nanos = None;
        for output in outputs.drain(..) {
            for route in loop_impl.resolve_backend_network_routes(&output)? {
                let stages = self
                    .topology
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
                let producer = FaultObjectId::parse(&output.source.name).map_err(|error| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "network frame producer `{}` is not a canonical fault object: {error}",
                            output.source.name
                        ),
                    }
                })?;
                let length_bytes = u64::try_from(output.payload.len()).map_err(|_error| {
                    SchedulerError::BoundaryViolation {
                        message: String::from("network frame length exceeds the fault ABI width"),
                    }
                })?;
                let payload = OpportunityPayload::NetworkFrame {
                    producer,
                    producer_sequence: output.sequence,
                    length_bytes,
                    payload_digest: ContentHash::from_bytes(&output.payload),
                };
                let mut admitted = true;
                for stage in stages
                    .iter()
                    .filter(|stage| stage.phases().contains(&FaultPhase::Admit))
                {
                    let opportunity = FaultOpportunity::new(
                        stage.target.clone(),
                        stage.operation,
                        FaultPhase::Admit,
                        FaultCoordinate {
                            virtual_nanos: frontier.ticks,
                            retired_instructions: Some(output.emit_icount.retired),
                        },
                        output.sequence,
                        Some(stage.direction),
                        payload.clone(),
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("construct network admission opportunity: {error}"),
                    })?;
                    let sequence = self.next_sequence(frontier.ticks)?;
                    let evaluation = self
                        .runtime
                        .evaluate_opportunity(&opportunity, sequence, _backend)
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!("signal network opportunity failed closed: {error}"),
                        })?;
                    next_wakeup_nanos =
                        earliest_wakeup(next_wakeup_nanos, evaluation.next_wakeup_nanos);
                    observations.extend(evaluation.observations);
                    let impulses = self.runtime.drain_host_impulses();
                    if !impulses.is_empty() {
                        return Err(SchedulerError::BoundaryViolation {
                            message: String::from(
                                "network availability produced an invalid impulse action",
                            ),
                        });
                    }
                    for action in self
                        .runtime
                        .host_state()
                        .matching(opportunity.target(), FaultPhase::Admit)
                    {
                        let EffectSpecification::Network(
                            NetworkEffectSpecification::Availability { state, .. },
                        ) = action.effect.specification()
                        else {
                            return Err(SchedulerError::BoundaryViolation {
                                message: format!(
                                    "production network admission encountered unadvertised effect `{}`",
                                    action.effect.kind().as_str()
                                ),
                            });
                        };
                        admitted &= availability_allows(*state, stage.direction);
                    }
                }
                if admitted {
                    routed.push(output);
                }
            }
        }
        *outputs = routed;
        if next_wakeup_nanos.is_some() {
            loop_impl.set_signal_fault_wakeup(next_wakeup_nanos)?;
        }
        if observations.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(vec![loop_impl.append_fault_observations(observations)?])
        }
    }
}

fn earliest_wakeup(current: Option<u64>, candidate: Option<u64>) -> Option<u64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.min(candidate)),
        (Some(current), None) => Some(current),
        (None, candidate) => candidate,
    }
}

fn availability_allows(
    state: NetworkAvailabilityState,
    direction: crucible::model::FaultDirection,
) -> bool {
    match state {
        NetworkAvailabilityState::Up => true,
        NetworkAvailabilityState::Down => false,
        NetworkAvailabilityState::ReceiveOnly => {
            direction == crucible::model::FaultDirection::Ingress
        }
        NetworkAvailabilityState::TransmitOnly => {
            direction != crucible::model::FaultDirection::Ingress
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::model::FaultDirection;

    #[test]
    fn directional_availability_has_a_closed_lattice() {
        for direction in [
            FaultDirection::AToB,
            FaultDirection::BToA,
            FaultDirection::Ingress,
            FaultDirection::Egress,
        ] {
            assert!(availability_allows(NetworkAvailabilityState::Up, direction));
            assert!(!availability_allows(
                NetworkAvailabilityState::Down,
                direction
            ));
        }
        assert!(availability_allows(
            NetworkAvailabilityState::ReceiveOnly,
            FaultDirection::Ingress
        ));
        assert!(!availability_allows(
            NetworkAvailabilityState::ReceiveOnly,
            FaultDirection::Egress
        ));
        assert!(availability_allows(
            NetworkAvailabilityState::TransmitOnly,
            FaultDirection::Egress
        ));
        assert!(!availability_allows(
            NetworkAvailabilityState::TransmitOnly,
            FaultDirection::Ingress
        ));
    }
}
