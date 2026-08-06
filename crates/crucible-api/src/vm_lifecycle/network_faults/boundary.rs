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

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum AssociationPhase {
    Searching,
    Candidate,
    Authenticating,
    Associated,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AssociationState {
    policy: FaultObjectId,
    candidates: Vec<(FaultObjectId, i64)>,
    phase: AssociationPhase,
    current: Option<FaultObjectId>,
    pending: Option<FaultObjectId>,
    pending_since_nanos: Option<u64>,
    transfer_complete_nanos: Option<u64>,
    next_scan_nanos: u64,
    preserve_queued: bool,
    preserve_address: bool,
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
    associations: BTreeMap<NetworkEffectStateKey, AssociationState>,
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
    /// Attachment transitions whose pre-transition frames cannot retain addressing.
    pub(super) address_discontinuities: BTreeSet<crucible::model::ResolvedFaultTarget>,
}

/// One committed route-version transition and its traffic treatment.
#[derive(Clone, Debug)]
pub(super) struct BoundaryRouteApplication {
    pub(super) target: crucible::model::ResolvedFaultTarget,
    pub(super) old_route: FaultObjectId,
    pub(super) policy: NetworkInFlightPolicy,
}

impl BoundaryNetworkState {
    pub(super) fn activate_timed_outage(
        &mut self,
        action: &ResolvedBindingAction,
        now: u64,
        duration_nanos: u64,
    ) -> Result<u64, SchedulerError> {
        let unavailable_until = now.checked_add(duration_nanos).ok_or_else(|| {
            network_effect_application_error(action, "timed outage coordinate overflowed")
        })?;
        self.outages.insert(
            NetworkEffectStateKey::from_action(action),
            TimedOutage {
                unavailable_until,
                transition_sequence: action.transition_sequence,
            },
        );
        Ok(unavailable_until)
    }

    pub(super) fn validate_bounds(&self) -> Result<(), SchedulerError> {
        let association_candidates = self
            .associations
            .values()
            .try_fold(0_usize, |total, association| {
                total.checked_add(association.candidates.len())
            });
        if self.outages.len() > 65_536
            || self.negotiated_modes.len() > 65_536
            || self.route_transitions.len() > 65_536
            || self.contact_plans.len() > 65_536
            || self.associations.len() > 65_536
            || association_candidates.is_none_or(|count| count > 65_536)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network boundary checkpoint exceeds hard state bounds"),
            });
        }
        Ok(())
    }

    pub(super) fn validate_topology(
        &self,
        topology: &crucible::model::WorldFaultTopology,
    ) -> Result<(), SchedulerError> {
        for (key, association) in &self.associations {
            let declaration = topology
                .network_policy_artifact(&association.policy)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "restored association policy `{}` is absent from World",
                        association.policy
                    ),
                })?;
            let crucible::model::NetworkPolicyArtifactKind::Association(policy) =
                &declaration.artifact
            else {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "restored association policy `{}` has the wrong class",
                        association.policy
                    ),
                });
            };
            let expected = policy
                .candidates
                .iter()
                .map(|candidate| &candidate.candidate)
                .collect::<Vec<_>>();
            let actual = association
                .candidates
                .iter()
                .map(|(candidate, _score)| candidate)
                .collect::<Vec<_>>();
            let contains = |candidate: Option<&FaultObjectId>| {
                candidate.is_none_or(|candidate| actual.binary_search(&candidate).is_ok())
            };
            let phase_valid = match association.phase {
                AssociationPhase::Searching => {
                    association.current.is_none()
                        && association.pending.is_none()
                        && association.pending_since_nanos.is_none()
                        && association.transfer_complete_nanos.is_none()
                }
                AssociationPhase::Candidate => {
                    association.pending.is_some()
                        && association.pending_since_nanos.is_some()
                        && association.transfer_complete_nanos.is_none()
                }
                AssociationPhase::Authenticating => {
                    association.pending.is_some()
                        && association.pending_since_nanos.is_some()
                        && association.transfer_complete_nanos.is_some()
                }
                AssociationPhase::Associated => {
                    association.current.is_some()
                        && association.pending.is_none()
                        && association.pending_since_nanos.is_none()
                        && association.transfer_complete_nanos.is_none()
                }
            };
            if expected != actual
                || !contains(association.current.as_ref())
                || !contains(association.pending.as_ref())
                || !phase_valid
                || association.preserve_queued != policy.preserve_queued
                || association.preserve_address != policy.preserve_address
                || !matches!(
                    key.target,
                    crucible::model::ResolvedFaultTarget::NetworkAttachment { .. }
                )
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "restored association state violates its admitted World contract",
                    ),
                });
            }
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
                self.associations.remove(&key);
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
                NetworkEffectSpecification::Association { policy } => {
                    let declaration =
                        topology.network_policy_artifact(policy).ok_or_else(|| {
                            network_effect_application_error(
                                &action,
                                "association policy disappeared after admission",
                            )
                        })?;
                    let crucible::model::NetworkPolicyArtifactKind::Association(policy_fields) =
                        &declaration.artifact
                    else {
                        return Err(network_effect_application_error(
                            &action,
                            "association policy changed type after admission",
                        ));
                    };
                    let inputs = route::mapped_network_integers(&action)?;
                    if inputs.len() != 1 && inputs.len() != policy_fields.candidates.len() {
                        return Err(network_effect_application_error(
                            &action,
                            "association mapping must provide one shared input or one input per candidate",
                        ));
                    }
                    let candidates = policy_fields
                        .candidates
                        .iter()
                        .enumerate()
                        .map(|(index, candidate)| {
                            let input = inputs[if inputs.len() == 1 { 0 } else { index }];
                            route::lookup_network_integer_table(
                                &candidate.score,
                                input,
                                candidate.candidate.as_str(),
                            )
                            .map(|score| (candidate.candidate.clone(), score))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let prior = self.associations.remove(&key);
                    self.associations.insert(
                        key,
                        AssociationState {
                            policy: policy.clone(),
                            candidates,
                            phase: prior
                                .as_ref()
                                .map_or(AssociationPhase::Searching, |state| state.phase),
                            current: prior.as_ref().and_then(|state| state.current.clone()),
                            pending: prior.as_ref().and_then(|state| state.pending.clone()),
                            pending_since_nanos: prior
                                .as_ref()
                                .and_then(|state| state.pending_since_nanos),
                            transfer_complete_nanos: prior
                                .as_ref()
                                .and_then(|state| state.transfer_complete_nanos),
                            next_scan_nanos: coordinate.virtual_nanos,
                            preserve_queued: policy_fields.preserve_queued,
                            preserve_address: policy_fields.preserve_address,
                            transition_sequence: action.transition_sequence,
                        },
                    );
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
        self.advance_associations(coordinate.virtual_nanos, topology, &mut application)?;
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
        route_path_version: Option<&FaultObjectId>,
        topology: &crucible::model::WorldFaultTopology,
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
        for (key, association) in &self.associations {
            if &key.target != target {
                continue;
            }
            let selected_path_contains_attachment = association.current.as_ref().is_some_and(
                |selected| {
                    route_path_version.is_some_and(|path_version| {
                        topology.network_paths.iter().any(|path| {
                            path.id.as_str() == path_version.as_str()
                                && path.hops.iter().any(|hop| {
                                    matches!(
                                        hop,
                                        crucible::model::WorldNetworkPathHop::Segment { segment, .. }
                                            if segment.as_str() == selected.as_str()
                                    )
                                })
                        })
                    })
                },
            );
            if association.phase != AssociationPhase::Associated
                || !selected_path_contains_attachment
            {
                effects.mark_drop();
            }
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

    fn advance_associations(
        &mut self,
        now: u64,
        topology: &crucible::model::WorldFaultTopology,
        application: &mut BoundaryNetworkApplication,
    ) -> Result<(), SchedulerError> {
        for (key, state) in &mut self.associations {
            let declaration = topology
                .network_policy_artifact(&state.policy)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "association policy `{}` disappeared after admission",
                        state.policy
                    ),
                })?;
            let crucible::model::NetworkPolicyArtifactKind::Association(policy) =
                &declaration.artifact
            else {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "association policy `{}` changed type after admission",
                        state.policy
                    ),
                });
            };

            if state
                .transfer_complete_nanos
                .is_some_and(|complete| now >= complete)
            {
                state.current = state.pending.take();
                state.pending_since_nanos = None;
                state.transfer_complete_nanos = None;
                state.phase = if state.current.is_some() {
                    AssociationPhase::Associated
                } else {
                    AssociationPhase::Searching
                };
            }
            if state.phase == AssociationPhase::Authenticating {
                application.next_wakeup_nanos = earliest_wakeup(
                    application.next_wakeup_nanos,
                    state
                        .transfer_complete_nanos
                        .filter(|complete| *complete > now),
                );
                continue;
            }
            if now < state.next_scan_nanos {
                application.next_wakeup_nanos =
                    earliest_wakeup(application.next_wakeup_nanos, Some(state.next_scan_nanos));
                continue;
            }

            let best = state
                .candidates
                .iter()
                .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
                .map(|(candidate, score)| (candidate.clone(), *score));
            let qualifies = best.as_ref().is_some_and(|(candidate, score)| {
                if state.current.as_ref() == Some(candidate) {
                    return false;
                }
                state.current.as_ref().is_none_or(|current| {
                    state
                        .candidates
                        .iter()
                        .find(|(candidate, _score)| candidate == current)
                        .is_none_or(|(_candidate, current_score)| {
                            i128::from(*score)
                                >= i128::from(*current_score) + i128::from(policy.hysteresis)
                        })
                })
            });
            if qualifies {
                let candidate = best.map(|(candidate, _score)| candidate);
                if state.pending != candidate {
                    state.pending = candidate;
                    state.pending_since_nanos = Some(now);
                    state.phase = AssociationPhase::Candidate;
                }
                let residence_complete = state
                    .pending_since_nanos
                    .and_then(|since| since.checked_add(policy.time_to_trigger_nanos))
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("association residence coordinate overflowed"),
                    })?;
                if now >= residence_complete {
                    let transfer_complete = now
                        .checked_add(policy.authentication_nanos)
                        .and_then(|value| value.checked_add(policy.interruption_nanos))
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: String::from("association transfer coordinate overflowed"),
                        })?;
                    if !state.preserve_queued {
                        application.clear_queued_targets.insert(key.target.clone());
                    }
                    if !state.preserve_address {
                        application
                            .address_discontinuities
                            .insert(key.target.clone());
                    }
                    if transfer_complete == now {
                        state.current = state.pending.take();
                        state.pending_since_nanos = None;
                        state.transfer_complete_nanos = None;
                        state.phase = AssociationPhase::Associated;
                    } else {
                        state.phase = AssociationPhase::Authenticating;
                        state.transfer_complete_nanos = Some(transfer_complete);
                        application.next_wakeup_nanos =
                            earliest_wakeup(application.next_wakeup_nanos, Some(transfer_complete));
                    }
                } else {
                    application.next_wakeup_nanos =
                        earliest_wakeup(application.next_wakeup_nanos, Some(residence_complete));
                }
            } else {
                state.pending = None;
                state.pending_since_nanos = None;
                state.phase = if state.current.is_some() {
                    AssociationPhase::Associated
                } else {
                    AssociationPhase::Searching
                };
            }
            state.next_scan_nanos = now
                .checked_add(policy.scan_interval_nanos.get())
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("association scan coordinate overflowed"),
                })?;
            application.next_wakeup_nanos =
                earliest_wakeup(application.next_wakeup_nanos, Some(state.next_scan_nanos));
        }
        Ok(())
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
        append_evidence_count(material, self.associations.len())?;
        for (key, association) in &self.associations {
            append_network_effect_state_key(material, key)?;
            append_evidence_bytes(material, association.policy.as_str().as_bytes())?;
            material.push(match association.phase {
                AssociationPhase::Searching => 1,
                AssociationPhase::Candidate => 2,
                AssociationPhase::Authenticating => 3,
                AssociationPhase::Associated => 4,
            });
            append_optional_fault_object_id(material, association.current.as_ref())?;
            append_optional_fault_object_id(material, association.pending.as_ref())?;
            material.extend_from_slice(
                &association
                    .pending_since_nanos
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            material.extend_from_slice(
                &association
                    .transfer_complete_nanos
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            material.extend_from_slice(&association.next_scan_nanos.to_be_bytes());
            material.push(u8::from(association.preserve_queued));
            material.push(u8::from(association.preserve_address));
            material.extend_from_slice(&association.transition_sequence.to_be_bytes());
            append_evidence_count(material, association.candidates.len())?;
            for (candidate, score) in &association.candidates {
                append_evidence_bytes(material, candidate.as_str().as_bytes())?;
                material.extend_from_slice(&score.to_be_bytes());
            }
        }
        Ok(())
    }

    fn expire(&mut self, now: u64) {
        self.outages
            .retain(|_key, outage| outage.unavailable_until > now);
    }

    pub(super) fn next_wakeup_nanos(&self, now: u64) -> Option<u64> {
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
            .chain(self.associations.values().flat_map(|association| {
                [
                    Some(association.next_scan_nanos),
                    association.transfer_complete_nanos,
                ]
                .into_iter()
                .flatten()
            }))
            .filter(|coordinate| *coordinate > now)
            .min()
    }
}

fn append_optional_fault_object_id(
    material: &mut Vec<u8>,
    value: Option<&FaultObjectId>,
) -> Result<(), SchedulerError> {
    if let Some(value) = value {
        material.push(1);
        append_evidence_bytes(material, value.as_str().as_bytes())?;
    } else {
        material.push(0);
    }
    Ok(())
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

    fn association_action(policy: FaultObjectId, scores: [i64; 2]) -> ResolvedBindingAction {
        let effect = EffectRequest::new(
            crucible::model::EFFECT_SEMANTIC_VERSION,
            EffectLifetime::StateMachine,
            EffectSpecification::Network(NetworkEffectSpecification::Association {
                policy: policy.clone(),
            }),
        )
        .unwrap_or_else(|error| panic!("test association should be valid: {error}"));
        ResolvedBindingAction {
            kind: BindingActionKind::UpsertPersistent,
            binding: id("association-binding"),
            target: crucible::model::ResolvedFaultTarget::NetworkAttachment {
                endpoint: id("vm-a"),
                interface: id("interface-a"),
                attachment: id("attachment-a"),
            },
            phase: FaultPhase::Boundary,
            effect: Arc::new(effect),
            mapping_output: Arc::new(ResolvedMappingOutput::ServiceProfile {
                service_profile: policy,
                input_contracts: Vec::new(),
                inputs: scores
                    .into_iter()
                    .map(crucible::model::SignalValue::I64)
                    .collect(),
            }),
            mapped_digest: ContentHash::from_bytes(b"association-mapping"),
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            cause: BindingActionCause::Signal,
        }
    }

    fn association_topology(policy: FaultObjectId) -> crucible::model::WorldFaultTopology {
        let score = |candidate: &str| crucible::model::NetworkPolicyAssociationCandidate {
            candidate: id(candidate),
            score: crucible::model::NetworkPolicyIntegerTable {
                input_unit: id("quality"),
                output_unit: id("score"),
                interpolation: crucible::model::NetworkPolicyInterpolation::LinearTiesToEven,
                outside: crucible::model::NetworkPolicyOutsideRange::Clamp,
                points: vec![
                    crucible::model::NetworkPolicyIntegerPoint {
                        input: -1_000,
                        output: -1_000,
                    },
                    crucible::model::NetworkPolicyIntegerPoint {
                        input: 1_000,
                        output: 1_000,
                    },
                ],
            },
        };
        crucible::model::WorldFaultTopology {
            network_policy_artifacts: vec![crucible::model::WorldNetworkPolicyArtifact {
                id: policy,
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::Association(
                    crucible::model::NetworkPolicyAssociation {
                        hysteresis: 5,
                        time_to_trigger_nanos: 10,
                        scan_interval_nanos: positive(2),
                        authentication_nanos: 2,
                        interruption_nanos: 3,
                        preserve_queued: false,
                        preserve_address: false,
                        candidates: vec![score("segment-a"), score("segment-b")],
                    },
                ),
            }],
            ..crucible::model::WorldFaultTopology::default()
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
            .apply_frame(
                &target(),
                None,
                &crucible::model::WorldFaultTopology::default(),
                159,
                &mut blocked,
            )
            .unwrap_or_else(|error| panic!("test frame should resolve: {error}"));
        assert!(blocked.is_dropped());

        let mut recovered = crucible::ResolvedNetworkFrameEffects::default();
        state
            .apply_frame(
                &target(),
                None,
                &crucible::model::WorldFaultTopology::default(),
                160,
                &mut recovered,
            )
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

    #[test]
    fn association_executes_residence_authentication_and_handoff_timers() {
        let policy = id("association-policy");
        let topology = association_topology(policy.clone());
        let mut state = BoundaryNetworkState::default();
        let target = association_action(policy, [10, 20]).target;

        let initial = state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                [association_action(id("association-policy"), [10, 20])],
                &topology,
            )
            .unwrap_or_else(|error| panic!("initial association scan: {error}"));
        assert_eq!(initial.next_wakeup_nanos, Some(2));

        for now in [2, 4, 6, 8] {
            state
                .apply_actions(
                    FaultCoordinate {
                        virtual_nanos: now,
                        retired_instructions: None,
                    },
                    [],
                    &topology,
                )
                .unwrap_or_else(|error| panic!("association residence scan: {error}"));
        }
        let handoff = state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 10,
                    retired_instructions: None,
                },
                [],
                &topology,
            )
            .unwrap_or_else(|error| panic!("association handoff start: {error}"));
        assert!(handoff.clear_queued_targets.contains(&target));
        assert!(handoff.address_discontinuities.contains(&target));
        assert_eq!(handoff.next_wakeup_nanos, Some(15));

        state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 15,
                    retired_instructions: None,
                },
                [],
                &topology,
            )
            .unwrap_or_else(|error| panic!("association handoff completion: {error}"));
        let association = state
            .associations
            .values()
            .next()
            .unwrap_or_else(|| panic!("association state should remain active"));
        assert_eq!(association.phase, AssociationPhase::Associated);
        assert_eq!(association.current.as_ref(), Some(&id("segment-b")));
    }
}
