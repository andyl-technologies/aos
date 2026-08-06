//! Timed state owned by boundary-phase network effects.
//!
//! Boundary effects mutate adapter state rather than individual frames.  This
//! module records those mutations, derives exact scheduler wakeups, and applies
//! their live consequences when later frame opportunities cross the target.

use super::*;
use std::collections::BTreeSet;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TimedOutage {
    unavailable_until: u64,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NegotiatedModeState {
    usable_after: u64,
    rate_bps: u64,
    duplex: crucible::model::NetworkDuplex,
    lanes: u32,
    fec: crucible::model::NetworkFecMode,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct RouteTransitionState {
    converged_after: u64,
    old_route: FaultObjectId,
    new_route: FaultObjectId,
    in_flight_policy: NetworkInFlightPolicy,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ContactPlanState {
    intervals: Vec<crucible::model::NetworkPolicyContactInterval>,
    transition_sequence: u64,
}

impl ContactPlanState {
    fn carries_traffic(&self, now: u64) -> bool {
        self.intervals.iter().any(|interval| {
            let open = interval.start_nanos.checked_add(interval.acquisition_nanos);
            let teardown = interval.end_nanos.checked_sub(interval.teardown_nanos);
            open.is_some_and(|open| teardown.is_some_and(|teardown| open <= now && now < teardown))
        })
    }

    fn next_boundary(&self, now: u64) -> Option<u64> {
        self.intervals
            .iter()
            .flat_map(|interval| {
                [
                    Some(interval.start_nanos),
                    interval.start_nanos.checked_add(interval.acquisition_nanos),
                    interval.end_nanos.checked_sub(interval.teardown_nanos),
                    Some(interval.end_nanos),
                ]
            })
            .flatten()
            .filter(|boundary| *boundary > now)
            .min()
    }
}

/// Exact mutable state for all network effects admitted at `boundary`.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct BoundaryNetworkState {
    outages: BTreeMap<NetworkEffectStateKey, TimedOutage>,
    negotiated_modes: BTreeMap<NetworkEffectStateKey, NegotiatedModeState>,
    route_transitions: BTreeMap<NetworkEffectStateKey, RouteTransitionState>,
    contact_plans: BTreeMap<NetworkEffectStateKey, ContactPlanState>,
}

/// Nonlocal mutations requested by a boundary action batch.
#[derive(Debug, Default)]
pub(super) struct BoundaryNetworkApplication {
    /// Earliest adapter-owned timer coordinate.
    pub(super) next_wakeup_nanos: Option<u64>,
    /// Targets whose queued frames must be discarded.
    pub(super) clear_queued_targets: BTreeSet<crucible::model::ResolvedFaultTarget>,
    /// Route transitions that must update queued and in-flight path ownership.
    pub(super) route_transitions: Vec<BoundaryRouteApplication>,
}

/// One committed route-version transition and its traffic treatment.
#[derive(Clone, Debug)]
pub(super) struct BoundaryRouteApplication {
    pub(super) target: crucible::model::ResolvedFaultTarget,
    pub(super) old_route: FaultObjectId,
    pub(super) policy: NetworkInFlightPolicy,
}

impl BoundaryNetworkState {
    pub(super) fn validate_bounds(&self) -> Result<(), SchedulerError> {
        if self.outages.len() > 65_536
            || self.negotiated_modes.len() > 65_536
            || self.route_transitions.len() > 65_536
            || self.contact_plans.len() > 65_536
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network boundary checkpoint exceeds hard state bounds"),
            });
        }
        Ok(())
    }

    /// Applies one atomic boundary batch and expires completed timers.
    pub(super) fn apply_actions(
        &mut self,
        coordinate: FaultCoordinate,
        actions: impl IntoIterator<Item = ResolvedBindingAction>,
        topology: &crucible::model::WorldFaultTopology,
    ) -> Result<BoundaryNetworkApplication, SchedulerError> {
        self.expire(coordinate.virtual_nanos);
        let mut application = BoundaryNetworkApplication::default();
        for action in actions {
            let key = NetworkEffectStateKey::from_action(&action);
            if action.kind == BindingActionKind::RemovePersistent {
                self.outages.remove(&key);
                self.negotiated_modes.remove(&key);
                self.route_transitions.remove(&key);
                self.contact_plans.remove(&key);
                continue;
            }
            let EffectSpecification::Network(specification) = action.effect.specification() else {
                return Err(network_effect_application_error(
                    &action,
                    "non-network effect reached the boundary network adapter",
                ));
            };
            match specification {
                NetworkEffectSpecification::Flap {
                    down_nanos,
                    training_nanos,
                    recovery_nanos,
                } => {
                    let duration = down_nanos
                        .get()
                        .checked_add(training_nanos.get())
                        .and_then(|value| value.checked_add(recovery_nanos.get()))
                        .ok_or_else(|| {
                            network_effect_application_error(&action, "flap timeline overflowed")
                        })?;
                    let unavailable_until = coordinate
                        .virtual_nanos
                        .checked_add(duration)
                        .ok_or_else(|| {
                            network_effect_application_error(&action, "flap coordinate overflowed")
                        })?;
                    self.outages.insert(
                        key,
                        TimedOutage {
                            unavailable_until,
                            transition_sequence: action.transition_sequence,
                        },
                    );
                    application.next_wakeup_nanos =
                        earliest_wakeup(application.next_wakeup_nanos, Some(unavailable_until));
                }
                NetworkEffectSpecification::NegotiatedMode {
                    rate_bps,
                    duplex,
                    lanes,
                    fec,
                    training_nanos,
                } => {
                    let usable_after = coordinate
                        .virtual_nanos
                        .checked_add(training_nanos.get())
                        .ok_or_else(|| {
                        network_effect_application_error(
                            &action,
                            "negotiation coordinate overflowed",
                        )
                    })?;
                    self.negotiated_modes.insert(
                        key,
                        NegotiatedModeState {
                            usable_after,
                            rate_bps: rate_bps.get(),
                            duplex: *duplex,
                            lanes: lanes.get(),
                            fec: *fec,
                            transition_sequence: action.transition_sequence,
                        },
                    );
                    application.next_wakeup_nanos =
                        earliest_wakeup(application.next_wakeup_nanos, Some(usable_after));
                }
                NetworkEffectSpecification::ForwarderLifecycle {
                    downtime_nanos,
                    queue_policy,
                    ..
                } => {
                    let unavailable_until = coordinate
                        .virtual_nanos
                        .checked_add(downtime_nanos.get())
                        .ok_or_else(|| {
                            network_effect_application_error(
                                &action,
                                "forwarder downtime coordinate overflowed",
                            )
                        })?;
                    self.outages.insert(
                        key,
                        TimedOutage {
                            unavailable_until,
                            transition_sequence: action.transition_sequence,
                        },
                    );
                    if *queue_policy == crucible::model::NetworkStatePolicy::Clear {
                        application
                            .clear_queued_targets
                            .insert(action.target.clone());
                    }
                    application.next_wakeup_nanos =
                        earliest_wakeup(application.next_wakeup_nanos, Some(unavailable_until));
                }
                NetworkEffectSpecification::RouteTransition {
                    old_route,
                    new_route,
                    convergence_events,
                    in_flight_policy,
                } => {
                    let convergence_nanos =
                        maximum_state_machine_delay(topology, convergence_events, &action)?;
                    let converged_after = coordinate
                        .virtual_nanos
                        .checked_add(convergence_nanos)
                        .ok_or_else(|| {
                        network_effect_application_error(
                            &action,
                            "route convergence coordinate overflowed",
                        )
                    })?;
                    self.route_transitions.insert(
                        key,
                        RouteTransitionState {
                            converged_after,
                            old_route: old_route.clone(),
                            new_route: new_route.clone(),
                            in_flight_policy: *in_flight_policy,
                            transition_sequence: action.transition_sequence,
                        },
                    );
                    application
                        .route_transitions
                        .push(BoundaryRouteApplication {
                            target: action.target.clone(),
                            old_route: old_route.clone(),
                            policy: *in_flight_policy,
                        });
                    application.next_wakeup_nanos =
                        earliest_wakeup(application.next_wakeup_nanos, Some(converged_after));
                }
                NetworkEffectSpecification::Association {
                    selection_policy,
                    timer_policy,
                    authentication_policy,
                    traffic_policy,
                    ..
                } => {
                    let mut duration = 0_u64;
                    for reference in [
                        selection_policy,
                        timer_policy,
                        authentication_policy,
                        traffic_policy,
                    ] {
                        duration =
                            duration.max(association_interruption(topology, reference, &action)?);
                    }
                    let unavailable_until = coordinate
                        .virtual_nanos
                        .checked_add(duration)
                        .ok_or_else(|| {
                            network_effect_application_error(
                                &action,
                                "association coordinate overflowed",
                            )
                        })?;
                    self.outages.insert(
                        key,
                        TimedOutage {
                            unavailable_until,
                            transition_sequence: action.transition_sequence,
                        },
                    );
                    application.next_wakeup_nanos =
                        earliest_wakeup(application.next_wakeup_nanos, Some(unavailable_until));
                }
                NetworkEffectSpecification::Contact { intervals, .. } => {
                    let declaration =
                        topology.network_policy_artifact(intervals).ok_or_else(|| {
                            network_effect_application_error(
                                &action,
                                "contact plan disappeared after admission",
                            )
                        })?;
                    let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } =
                        &declaration.artifact
                    else {
                        return Err(network_effect_application_error(
                            &action,
                            "contact plan changed type after admission",
                        ));
                    };
                    let state = ContactPlanState {
                        intervals: intervals.clone(),
                        transition_sequence: action.transition_sequence,
                    };
                    application.next_wakeup_nanos = earliest_wakeup(
                        application.next_wakeup_nanos,
                        state.next_boundary(coordinate.virtual_nanos),
                    );
                    self.contact_plans.insert(key, state);
                }
                NetworkEffectSpecification::Availability { .. }
                | NetworkEffectSpecification::ProfileDelta { .. }
                | NetworkEffectSpecification::PropagationDelay { .. }
                | NetworkEffectSpecification::AccessDelay { .. }
                | NetworkEffectSpecification::Jitter { .. }
                | NetworkEffectSpecification::ServiceCurve { .. }
                | NetworkEffectSpecification::TokenBucket { .. }
                | NetworkEffectSpecification::QueuePolicy { .. }
                | NetworkEffectSpecification::FrameLoss { .. }
                | NetworkEffectSpecification::BurstErrorState { .. }
                | NetworkEffectSpecification::Duplicate { .. }
                | NetworkEffectSpecification::Reorder { .. }
                | NetworkEffectSpecification::PayloadTransform { .. }
                | NetworkEffectSpecification::DetectedFrameError { .. }
                | NetworkEffectSpecification::Mtu { .. }
                | NetworkEffectSpecification::PauseBackpressure { .. }
                | NetworkEffectSpecification::RecipientSubset { .. }
                | NetworkEffectSpecification::ForwardingMutation { .. }
                | NetworkEffectSpecification::ControlPlaneService { .. }
                | NetworkEffectSpecification::FirewallDisposition { .. }
                | NetworkEffectSpecification::ConnectionState { .. }
                | NetworkEffectSpecification::SharedMedium { .. }
                | NetworkEffectSpecification::RfChannel { .. }
                | NetworkEffectSpecification::ControlResultTransform { .. }
                | NetworkEffectSpecification::CustodyQueue { .. } => {
                    return Err(network_effect_application_error(
                        &action,
                        "non-boundary network effect reached boundary execution",
                    ));
                }
            }
        }
        application.next_wakeup_nanos = earliest_wakeup(
            application.next_wakeup_nanos,
            self.next_wakeup_nanos(coordinate.virtual_nanos),
        );
        Ok(application)
    }

    /// Applies active boundary state to a frame crossing one target.
    pub(super) fn apply_frame(
        &self,
        target: &crucible::model::ResolvedFaultTarget,
        now: u64,
        effects: &mut crucible::ResolvedNetworkFrameEffects,
    ) -> Result<(), SchedulerError> {
        if self
            .outages
            .iter()
            .any(|(key, outage)| &key.target == target && now < outage.unavailable_until)
            || self
                .negotiated_modes
                .iter()
                .any(|(key, mode)| &key.target == target && now < mode.usable_after)
        {
            effects.mark_drop();
        }
        for (key, mode) in &self.negotiated_modes {
            if &key.target == target && now >= mode.usable_after {
                effects.constrain_rate(mode.rate_bps).map_err(|error| {
                    SchedulerError::BoundaryViolation {
                        message: format!("apply negotiated network mode: {error}"),
                    }
                })?;
            }
        }
        for (key, transition) in &self.route_transitions {
            if &key.target == target
                && now < transition.converged_after
                && matches!(
                    transition.in_flight_policy,
                    NetworkInFlightPolicy::Drop | NetworkInFlightPolicy::TypedError
                )
            {
                effects.mark_drop();
            }
        }
        if self
            .contact_plans
            .iter()
            .any(|(key, contact)| &key.target == target && !contact.carries_traffic(now))
        {
            effects.mark_drop();
        }
        Ok(())
    }

    /// Returns the committed path version replacing the canonical static path.
    pub(super) fn route_path_override(
        &self,
        current_path: &FaultObjectId,
        now: u64,
    ) -> Option<&FaultObjectId> {
        self.route_transitions
            .values()
            .find(|transition| &transition.old_route == current_path)
            .map(|transition| {
                if now < transition.converged_after {
                    &transition.old_route
                } else {
                    &transition.new_route
                }
            })
    }

    pub(super) fn append_evidence(&self, material: &mut Vec<u8>) -> Result<(), SchedulerError> {
        append_evidence_count(material, self.outages.len())?;
        for (key, outage) in &self.outages {
            append_network_effect_state_key(material, key)?;
            material.extend_from_slice(&outage.unavailable_until.to_be_bytes());
            material.extend_from_slice(&outage.transition_sequence.to_be_bytes());
        }
        append_evidence_count(material, self.negotiated_modes.len())?;
        for (key, mode) in &self.negotiated_modes {
            append_network_effect_state_key(material, key)?;
            material.extend_from_slice(&mode.usable_after.to_be_bytes());
            material.extend_from_slice(&mode.rate_bps.to_be_bytes());
            material.push(match mode.duplex {
                crucible::model::NetworkDuplex::Half => 1,
                crucible::model::NetworkDuplex::Full => 2,
            });
            material.extend_from_slice(&mode.lanes.to_be_bytes());
            material.push(match mode.fec {
                crucible::model::NetworkFecMode::None => 1,
                crucible::model::NetworkFecMode::ReedSolomon => 2,
                crucible::model::NetworkFecMode::Ldpc => 3,
                crucible::model::NetworkFecMode::Convolutional => 4,
            });
            material.extend_from_slice(&mode.transition_sequence.to_be_bytes());
        }
        append_evidence_count(material, self.route_transitions.len())?;
        for (key, transition) in &self.route_transitions {
            append_network_effect_state_key(material, key)?;
            material.extend_from_slice(&transition.converged_after.to_be_bytes());
            append_evidence_bytes(material, transition.old_route.as_str().as_bytes())?;
            append_evidence_bytes(material, transition.new_route.as_str().as_bytes())?;
            material.push(in_flight_policy_tag(transition.in_flight_policy));
            material.extend_from_slice(&transition.transition_sequence.to_be_bytes());
        }
        append_evidence_count(material, self.contact_plans.len())?;
        for (key, contact) in &self.contact_plans {
            append_network_effect_state_key(material, key)?;
            material.extend_from_slice(&contact.transition_sequence.to_be_bytes());
            append_evidence_count(material, contact.intervals.len())?;
            for interval in &contact.intervals {
                material.extend_from_slice(&interval.start_nanos.to_be_bytes());
                material.extend_from_slice(&interval.end_nanos.to_be_bytes());
                append_evidence_bytes(material, interval.source.as_str().as_bytes())?;
                append_evidence_bytes(material, interval.destination.as_str().as_bytes())?;
                append_evidence_bytes(material, interval.beam.as_str().as_bytes())?;
                append_evidence_bytes(material, interval.gateway.as_str().as_bytes())?;
                material.extend_from_slice(&interval.minimum_range_mm.to_be_bytes());
                material.extend_from_slice(&interval.maximum_range_mm.to_be_bytes());
                append_evidence_bytes(material, interval.capacity_profile.as_str().as_bytes())?;
                material.extend_from_slice(&interval.acquisition_nanos.to_be_bytes());
                material.extend_from_slice(&interval.teardown_nanos.to_be_bytes());
                material.extend_from_slice(&interval.confidence.get().to_be_bytes());
                append_evidence_bytes(material, interval.provenance.as_str().as_bytes())?;
            }
        }
        Ok(())
    }

    fn expire(&mut self, now: u64) {
        self.outages
            .retain(|_key, outage| outage.unavailable_until > now);
    }

    fn next_wakeup_nanos(&self, now: u64) -> Option<u64> {
        self.outages
            .values()
            .map(|outage| outage.unavailable_until)
            .chain(self.negotiated_modes.values().map(|mode| mode.usable_after))
            .chain(
                self.route_transitions
                    .values()
                    .map(|transition| transition.converged_after),
            )
            .chain(
                self.contact_plans
                    .values()
                    .filter_map(|contact| contact.next_boundary(now)),
            )
            .filter(|coordinate| *coordinate > now)
            .min()
    }
}

fn maximum_state_machine_delay(
    topology: &crucible::model::WorldFaultTopology,
    reference: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<u64, SchedulerError> {
    let declaration = topology.network_policy_artifact(reference).ok_or_else(|| {
        network_effect_application_error(action, "state-machine policy disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::StateMachine { transitions, .. } =
        &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "state-machine policy changed type after admission",
        ));
    };
    Ok(transitions
        .iter()
        .map(|transition| transition.delay_nanos)
        .max()
        .unwrap_or(0))
}

fn association_interruption(
    topology: &crucible::model::WorldFaultTopology,
    reference: &FaultObjectId,
    action: &ResolvedBindingAction,
) -> Result<u64, SchedulerError> {
    let declaration = topology.network_policy_artifact(reference).ok_or_else(|| {
        network_effect_application_error(action, "association policy disappeared")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::Association(policy) = &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "association policy changed type after admission",
        ));
    };
    policy
        .time_to_trigger_nanos
        .checked_add(policy.authentication_nanos)
        .and_then(|value| value.checked_add(policy.interruption_nanos))
        .ok_or_else(|| network_effect_application_error(action, "association timeline overflowed"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crucible::model::{
        BindingActionCause, EffectLifetime, EffectRequest, NetworkEffectSpecification,
        ResolvedMappingOutput,
    };

    fn id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
    }

    fn positive(value: u64) -> crucible::model::PositiveU64 {
        crucible::model::PositiveU64::new("test", value)
            .unwrap_or_else(|error| panic!("test duration should be valid: {error}"))
    }

    fn target() -> crucible::model::ResolvedFaultTarget {
        crucible::model::ResolvedFaultTarget::NetworkSegment {
            segment: id("segment-a"),
            direction: crucible::model::FaultDirection::AToB,
        }
    }

    fn flap_action() -> ResolvedBindingAction {
        let effect = EffectRequest::new(
            crucible::model::EFFECT_SEMANTIC_VERSION,
            EffectLifetime::StateMachine,
            EffectSpecification::Network(NetworkEffectSpecification::Flap {
                down_nanos: positive(10),
                training_nanos: positive(20),
                recovery_nanos: positive(30),
            }),
        )
        .unwrap_or_else(|error| panic!("test flap should be valid: {error}"));
        ResolvedBindingAction {
            kind: BindingActionKind::Apply,
            binding: id("flap-binding"),
            target: target(),
            phase: FaultPhase::Boundary,
            effect: Arc::new(effect),
            mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
            mapped_digest: ContentHash::from_bytes(b"flap-mapping"),
            transition_sequence: 7,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 100,
                retired_instructions: None,
            },
            cause: BindingActionCause::Signal,
        }
    }

    #[test]
    fn flap_blocks_frames_until_the_exact_recovery_boundary() {
        let mut state = BoundaryNetworkState::default();
        let application = state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 100,
                    retired_instructions: None,
                },
                [flap_action()],
                &crucible::model::WorldFaultTopology::default(),
            )
            .unwrap_or_else(|error| panic!("test flap should apply: {error}"));
        assert_eq!(application.next_wakeup_nanos, Some(160));

        let mut blocked = crucible::ResolvedNetworkFrameEffects::default();
        state
            .apply_frame(&target(), 159, &mut blocked)
            .unwrap_or_else(|error| panic!("test frame should resolve: {error}"));
        assert!(blocked.is_dropped());

        let mut recovered = crucible::ResolvedNetworkFrameEffects::default();
        state
            .apply_frame(&target(), 160, &mut recovered)
            .unwrap_or_else(|error| panic!("test frame should resolve: {error}"));
        assert!(!recovered.is_dropped());
    }

    #[test]
    fn contact_plan_exposes_acquisition_open_and_teardown_boundaries() {
        let contact = ContactPlanState {
            intervals: vec![crucible::model::NetworkPolicyContactInterval {
                start_nanos: 100,
                end_nanos: 200,
                source: id("satellite"),
                destination: id("ground-station"),
                beam: id("beam-a"),
                gateway: id("gateway-a"),
                minimum_range_mm: 1,
                maximum_range_mm: 2,
                capacity_profile: id("capacity"),
                acquisition_nanos: 10,
                teardown_nanos: 20,
                confidence: crucible::model::ProbabilityMillionths::new(1_000_000)
                    .unwrap_or_else(|error| panic!("test confidence should be valid: {error}")),
                provenance: id("trace"),
            }],
            transition_sequence: 1,
        };
        assert_eq!(contact.next_boundary(99), Some(100));
        assert!(!contact.carries_traffic(109));
        assert_eq!(contact.next_boundary(100), Some(110));
        assert!(contact.carries_traffic(110));
        assert!(contact.carries_traffic(179));
        assert!(!contact.carries_traffic(180));
        assert_eq!(contact.next_boundary(180), Some(200));
    }
}
