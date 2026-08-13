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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ControlPlaneContribution {
    service_curve: FaultObjectId,
    overflow_policy: FaultObjectId,
    activation_nanos: u64,
    segments: Vec<crucible::model::NetworkServiceSegment>,
    queue_bound: u64,
    overflow: crucible::model::NetworkPolicyOverflow,
    timeout_nanos: Option<u64>,
    typed_error: Option<FaultObjectId>,
    event_work_bits: u64,
    service_cursor_nanos: u64,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct QueuedNetworkControlEvent {
    pub(super) sequence: u64,
    pub(super) operation: crucible::model::FaultOperation,
    pub(super) technology: FaultObjectId,
    pub(super) result_schema: FaultObjectId,
    pub(super) result_digest: ContentHash,
    pub(super) release_nanos: u64,
    pub(super) action: ResolvedBindingAction,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct ControlPlaneTargetState {
    contributions: BTreeMap<FaultObjectId, ControlPlaneContribution>,
    events: Vec<QueuedNetworkControlEvent>,
    overflow_timeouts: Vec<ControlPlaneTimeout>,
    next_sequence: u64,
    dropped_events: u64,
    typed_errors: u64,
    timed_out_events: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ControlPlaneTimeout {
    deadline_nanos: u64,
    action: ResolvedBindingAction,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ControlPlaneOutcomeKind {
    Dropped,
    TypedError,
    TimedOut,
}

#[derive(Clone, Debug)]
pub(super) struct ControlPlaneOutcome {
    pub(super) action: ResolvedBindingAction,
    pub(super) kind: ControlPlaneOutcomeKind,
    pub(super) result: Option<FaultObjectId>,
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
    #[serde(with = "super::ordered_map_entries")]
    outages: BTreeMap<NetworkEffectStateKey, TimedOutage>,
    #[serde(with = "super::ordered_map_entries")]
    negotiated_modes: BTreeMap<NetworkEffectStateKey, NegotiatedModeState>,
    #[serde(with = "super::ordered_map_entries")]
    route_transitions: BTreeMap<NetworkEffectStateKey, RouteTransitionState>,
    #[serde(with = "super::ordered_map_entries")]
    contact_plans: BTreeMap<NetworkEffectStateKey, ContactPlanState>,
    #[serde(with = "super::ordered_map_entries")]
    associations: BTreeMap<NetworkEffectStateKey, AssociationState>,
    #[serde(with = "super::ordered_map_entries")]
    control_planes: BTreeMap<crucible::model::ResolvedFaultTarget, ControlPlaneTargetState>,
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
    /// Control events whose shared service completed at this boundary.
    pub(super) ready_control_events: Vec<QueuedNetworkControlEvent>,
    /// Immediate or timer-matured control queue overflow outcomes.
    pub(super) control_outcomes: Vec<ControlPlaneOutcome>,
}

/// One committed route-version transition and its traffic treatment.
#[derive(Clone, Debug)]
pub(super) struct BoundaryRouteApplication {
    pub(super) target: crucible::model::ResolvedFaultTarget,
    pub(super) old_route: FaultObjectId,
    pub(super) policy: NetworkInFlightPolicy,
}

impl BoundaryNetworkState {
    pub(super) fn active_outages(
        &self,
        now: u64,
    ) -> Vec<(crucible::model::ResolvedFaultTarget, u64)> {
        self.outages
            .iter()
            .filter_map(|(key, outage)| {
                (now < outage.unavailable_until)
                    .then_some((key.target.clone(), outage.unavailable_until))
            })
            .collect()
    }

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
        let control_entries = self
            .control_planes
            .values()
            .try_fold(0_usize, |total, control| {
                total
                    .checked_add(control.contributions.len())
                    .and_then(|value| value.checked_add(control.events.len()))
                    .and_then(|value| value.checked_add(control.overflow_timeouts.len()))
            });
        if self.outages.len() > 65_536
            || self.negotiated_modes.len() > 65_536
            || self.route_transitions.len() > 65_536
            || self.contact_plans.len() > 65_536
            || self.associations.len() > 65_536
            || association_candidates.is_none_or(|count| count > 65_536)
            || self.control_planes.len() > 65_536
            || control_entries.is_none_or(|count| count > 262_144)
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
        for (target, control) in &self.control_planes {
            if !matches!(
                target,
                crucible::model::ResolvedFaultTarget::NetworkForwarder { .. }
                    | crucible::model::ResolvedFaultTarget::NetworkPath { .. }
                    | crucible::model::ResolvedFaultTarget::NetworkAttachment { .. }
                    | crucible::model::ResolvedFaultTarget::NetworkContact { .. }
            ) || control.events.windows(2).any(|pair| {
                (pair[0].release_nanos, pair[0].sequence)
                    >= (pair[1].release_nanos, pair[1].sequence)
            }) || control.overflow_timeouts.windows(2).any(|pair| {
                (pair[0].deadline_nanos, pair[0].action.id())
                    >= (pair[1].deadline_nanos, pair[1].action.id())
            }) {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "restored control-plane state is not canonically ordered",
                    ),
                });
            }
            for contribution in control.contributions.values() {
                let service = topology
                    .network_policy_artifact(&contribution.service_curve)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from(
                            "restored control-plane service curve is absent from World",
                        ),
                    })?;
                let crucible::model::NetworkPolicyArtifactKind::ServiceCurve { segments } =
                    &service.artifact
                else {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "restored control-plane service curve has the wrong class",
                        ),
                    });
                };
                if segments.as_slice() != contribution.segments
                    || contribution.queue_bound == 0
                    || contribution.event_work_bits == 0
                {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "restored control-plane contribution violates its World contract",
                        ),
                    });
                }
                let overflow = topology
                    .network_policy_artifact(&contribution.overflow_policy)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from(
                            "restored control-plane overflow policy is absent from World",
                        ),
                    })?;
                let crucible::model::NetworkPolicyArtifactKind::Overflow {
                    disposition,
                    timeout_nanos,
                    typed_error,
                } = &overflow.artifact
                else {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "restored control-plane overflow policy has the wrong class",
                        ),
                    });
                };
                if contribution.overflow != *disposition
                    || contribution.timeout_nanos != timeout_nanos.map(|value| value.get())
                    || contribution.typed_error.as_ref() != typed_error.as_ref()
                {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "restored control-plane overflow policy changed semantics",
                        ),
                    });
                }
            }
            let mut contributions = control.contributions.values();
            if let Some(first) = contributions.next()
                && contributions.any(|contribution| {
                    contribution.overflow != first.overflow
                        || contribution.timeout_nanos != first.timeout_nanos
                        || contribution.typed_error != first.typed_error
                })
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "restored control-plane contributors disagree on overflow semantics",
                    ),
                });
            }
            if control
                .contributions
                .values()
                .map(|item| item.queue_bound)
                .min()
                .is_some_and(|bound| {
                    u64::try_from(control.events.len()).map_or(true, |count| count > bound)
                })
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("restored control-plane queue exceeds its bound"),
                });
            }
            for event in &control.events {
                if &event.action.target != target || !is_control_event(&event.action) {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "restored control event does not belong to its queue target",
                        ),
                    });
                }
                let (operation, technology, schema, digest) =
                    control_event_contract(&event.action, topology, self, Some(event.operation))?;
                if event.operation != operation
                    || event.technology != technology
                    || event.result_schema != schema
                    || event.result_digest != digest
                {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "restored control event violates its typed operation contract",
                        ),
                    });
                }
            }
            if control
                .events
                .iter()
                .any(|event| event.sequence >= control.next_sequence)
                || control.overflow_timeouts.iter().any(|timeout| {
                    timeout.action.target != *target || !is_control_event(&timeout.action)
                })
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "restored control-plane event sequence or timeout owner is invalid",
                    ),
                });
            }
        }
        Ok(())
    }

    fn apply_control_service_action(
        &mut self,
        action: &ResolvedBindingAction,
        topology: &crucible::model::WorldFaultTopology,
    ) -> Result<(), SchedulerError> {
        let target = action.target.clone();
        if action.kind == BindingActionKind::RemovePersistent {
            if let Some(control) = self.control_planes.get_mut(&target) {
                control.contributions.remove(&action.binding);
                if control.contributions.is_empty()
                    && control.events.is_empty()
                    && control.overflow_timeouts.is_empty()
                {
                    self.control_planes.remove(&target);
                }
            }
            return Ok(());
        }
        let EffectSpecification::Network(NetworkEffectSpecification::ControlPlaneService {
            service_curve,
            queue_bound,
            overflow_policy,
            event_work_bits,
        }) = action.effect.specification()
        else {
            return Err(network_effect_application_error(
                action,
                "control-service executor received another effect",
            ));
        };
        let service = topology
            .network_policy_artifact(service_curve)
            .ok_or_else(|| {
                network_effect_application_error(action, "control service curve disappeared")
            })?;
        let crucible::model::NetworkPolicyArtifactKind::ServiceCurve { segments } =
            &service.artifact
        else {
            return Err(network_effect_application_error(
                action,
                "control service curve changed type after admission",
            ));
        };
        let overflow = topology
            .network_policy_artifact(overflow_policy)
            .ok_or_else(|| {
                network_effect_application_error(action, "control overflow policy disappeared")
            })?;
        let crucible::model::NetworkPolicyArtifactKind::Overflow {
            disposition,
            timeout_nanos,
            typed_error,
        } = &overflow.artifact
        else {
            return Err(network_effect_application_error(
                action,
                "control overflow policy changed type after admission",
            ));
        };
        let control = self.control_planes.entry(target).or_default();
        let prior_cursor = control.contributions.get(&action.binding).map_or(
            action.coordinate.virtual_nanos,
            |prior| {
                prior
                    .service_cursor_nanos
                    .max(action.coordinate.virtual_nanos)
            },
        );
        let queue_bound = u64::from(queue_bound.get());
        if control
            .contributions
            .iter()
            .filter(|(binding, _contribution)| *binding != &action.binding)
            .any(|(_binding, contribution)| {
                contribution.overflow != *disposition
                    || contribution.timeout_nanos != timeout_nanos.map(|value| value.get())
                    || contribution.typed_error.as_ref() != typed_error.as_ref()
            })
        {
            return Err(network_effect_application_error(
                action,
                "simultaneous control services disagree on overflow semantics",
            ));
        }
        let effective_queue_bound = control
            .contributions
            .iter()
            .filter(|(binding, _contribution)| *binding != &action.binding)
            .map(|(_binding, contribution)| contribution.queue_bound)
            .chain(std::iter::once(queue_bound))
            .min()
            .ok_or_else(|| {
                network_effect_application_error(action, "control queue has no effective bound")
            })?;
        if u64::try_from(control.events.len()).map_or(true, |length| length > effective_queue_bound)
        {
            return Err(network_effect_application_error(
                action,
                "control service update would shrink the queue below its occupancy",
            ));
        }
        control.contributions.insert(
            action.binding.clone(),
            ControlPlaneContribution {
                service_curve: service_curve.clone(),
                overflow_policy: overflow_policy.clone(),
                activation_nanos: action.coordinate.virtual_nanos,
                segments: segments.as_slice().to_vec(),
                queue_bound,
                overflow: *disposition,
                timeout_nanos: timeout_nanos.map(|timeout| timeout.get()),
                typed_error: typed_error.clone(),
                event_work_bits: event_work_bits.get(),
                service_cursor_nanos: prior_cursor,
                transition_sequence: action.transition_sequence,
            },
        );
        Ok(())
    }

    fn enqueue_control_event(
        &mut self,
        action: ResolvedBindingAction,
        topology: &crucible::model::WorldFaultTopology,
        now: u64,
        application: &mut BoundaryNetworkApplication,
    ) -> Result<bool, SchedulerError> {
        if self
            .control_planes
            .get(&action.target)
            .is_none_or(|control| control.contributions.is_empty())
        {
            return Ok(false);
        }
        let contract = control_event_contract(&action, topology, self, None)?;
        let Some(control) = self.control_planes.get_mut(&action.target) else {
            return Ok(false);
        };
        let mut policies = control.contributions.values();
        let first = policies.next().ok_or_else(|| {
            network_effect_application_error(&action, "control service lost all contributors")
        })?;
        let overflow = first.overflow;
        let timeout_nanos = first.timeout_nanos;
        let typed_error = first.typed_error.clone();
        let queue_bound = control
            .contributions
            .values()
            .map(|contribution| contribution.queue_bound)
            .min()
            .ok_or_else(|| {
                network_effect_application_error(&action, "control queue has no bound")
            })?;
        if policies.any(|policy| {
            policy.overflow != overflow
                || policy.timeout_nanos != timeout_nanos
                || policy.typed_error != typed_error
        }) {
            return Err(network_effect_application_error(
                &action,
                "simultaneous control services disagree on overflow semantics",
            ));
        }
        if u64::try_from(control.events.len()).is_ok_and(|length| length >= queue_bound) {
            match overflow {
                crucible::model::NetworkPolicyOverflow::DropNewest => {
                    control.dropped_events =
                        control.dropped_events.checked_add(1).ok_or_else(|| {
                            network_effect_application_error(
                                &action,
                                "control drop count overflowed",
                            )
                        })?;
                    application.control_outcomes.push(ControlPlaneOutcome {
                        action,
                        kind: ControlPlaneOutcomeKind::Dropped,
                        result: None,
                    });
                    return Ok(true);
                }
                crucible::model::NetworkPolicyOverflow::DropOldest => {
                    if !control.events.is_empty() {
                        let dropped = control.events.remove(0);
                        control.dropped_events =
                            control.dropped_events.checked_add(1).ok_or_else(|| {
                                network_effect_application_error(
                                    &action,
                                    "control drop count overflowed",
                                )
                            })?;
                        application.control_outcomes.push(ControlPlaneOutcome {
                            action: dropped.action,
                            kind: ControlPlaneOutcomeKind::Dropped,
                            result: None,
                        });
                    }
                }
                crucible::model::NetworkPolicyOverflow::TypedError => {
                    control.typed_errors =
                        control.typed_errors.checked_add(1).ok_or_else(|| {
                            network_effect_application_error(
                                &action,
                                "control typed-error count overflowed",
                            )
                        })?;
                    application.control_outcomes.push(ControlPlaneOutcome {
                        action,
                        kind: ControlPlaneOutcomeKind::TypedError,
                        result: typed_error,
                    });
                    return Ok(true);
                }
                crucible::model::NetworkPolicyOverflow::Timeout => {
                    let deadline = now
                        .checked_add(timeout_nanos.ok_or_else(|| {
                            network_effect_application_error(
                                &action,
                                "control timeout policy omitted its duration",
                            )
                        })?)
                        .ok_or_else(|| {
                            network_effect_application_error(
                                &action,
                                "control timeout coordinate overflowed",
                            )
                        })?;
                    control.overflow_timeouts.push(ControlPlaneTimeout {
                        deadline_nanos: deadline,
                        action,
                    });
                    control.overflow_timeouts.sort_by(|left, right| {
                        left.deadline_nanos
                            .cmp(&right.deadline_nanos)
                            .then_with(|| left.action.id().cmp(&right.action.id()))
                    });
                    application.next_wakeup_nanos =
                        earliest_wakeup(application.next_wakeup_nanos, Some(deadline));
                    return Ok(true);
                }
            }
        }

        let (operation, technology, result_schema, result_digest) = contract;
        let mut release_nanos = now;
        for contribution in control.contributions.values_mut() {
            let start = contribution.service_cursor_nanos.max(now);
            let finish = route::network_service_finish(
                start,
                contribution.event_work_bits,
                None,
                &[NetworkServiceCurveState {
                    activation_nanos: contribution.activation_nanos,
                    segments: contribution.segments.clone(),
                }],
                &action,
            )?;
            contribution.service_cursor_nanos = finish;
            release_nanos = release_nanos.max(finish);
        }
        let sequence = control.next_sequence;
        control.next_sequence = control.next_sequence.checked_add(1).ok_or_else(|| {
            network_effect_application_error(&action, "control event sequence overflowed")
        })?;
        control.events.push(QueuedNetworkControlEvent {
            sequence,
            operation,
            technology,
            result_schema,
            result_digest,
            release_nanos,
            action,
        });
        control.events.sort_by(|left, right| {
            left.release_nanos
                .cmp(&right.release_nanos)
                .then_with(|| left.sequence.cmp(&right.sequence))
        });
        application.next_wakeup_nanos = earliest_wakeup(
            application.next_wakeup_nanos,
            (release_nanos > now).then_some(release_nanos),
        );
        Ok(true)
    }

    fn drain_completed_control_work(
        &mut self,
        now: u64,
        application: &mut BoundaryNetworkApplication,
    ) -> Result<(), SchedulerError> {
        for control in self.control_planes.values_mut() {
            let expired = control
                .overflow_timeouts
                .partition_point(|timeout| timeout.deadline_nanos <= now);
            control.timed_out_events = control
                .timed_out_events
                .checked_add(u64::try_from(expired).map_err(|_error| {
                    SchedulerError::BoundaryViolation {
                        message: String::from("control timeout count exceeds u64"),
                    }
                })?)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("control timeout count overflowed"),
                })?;
            application
                .control_outcomes
                .extend(control.overflow_timeouts.drain(..expired).map(|timeout| {
                    ControlPlaneOutcome {
                        action: timeout.action,
                        kind: ControlPlaneOutcomeKind::TimedOut,
                        result: None,
                    }
                }));
            let ready = control
                .events
                .partition_point(|event| event.release_nanos <= now);
            application
                .ready_control_events
                .extend(control.events.drain(..ready));
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
        self.drain_completed_control_work(coordinate.virtual_nanos, &mut application)?;
        let actions = actions.into_iter().collect::<Vec<_>>();
        for action in &actions {
            if matches!(
                action.effect.specification(),
                EffectSpecification::Network(
                    NetworkEffectSpecification::ControlPlaneService { .. }
                )
            ) {
                self.apply_control_service_action(action, topology)?;
            }
        }
        for action in actions {
            if matches!(
                action.effect.specification(),
                EffectSpecification::Network(
                    NetworkEffectSpecification::ControlPlaneService { .. }
                )
            ) {
                continue;
            }
            let key = NetworkEffectStateKey::from_action(&action);
            if is_control_event(&action)
                && self.enqueue_control_event(
                    action.clone(),
                    topology,
                    coordinate.virtual_nanos,
                    &mut application,
                )?
            {
                continue;
            }
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
        for control in self.control_planes.values() {
            application.next_wakeup_nanos = earliest_wakeup(
                application.next_wakeup_nanos,
                control.events.first().map(|event| event.release_nanos),
            );
            application.next_wakeup_nanos = earliest_wakeup(
                application.next_wakeup_nanos,
                control
                    .overflow_timeouts
                    .first()
                    .map(|timeout| timeout.deadline_nanos),
            );
        }
        application.ready_control_events.sort_by(|left, right| {
            left.release_nanos
                .cmp(&right.release_nanos)
                .then_with(|| left.sequence.cmp(&right.sequence))
                .then_with(|| left.action.id().cmp(&right.action.id()))
        });
        self.advance_associations(coordinate.virtual_nanos, topology, &mut application)?;
        application.next_wakeup_nanos = earliest_wakeup(
            application.next_wakeup_nanos,
            self.next_wakeup_nanos(coordinate.virtual_nanos),
        );
        self.validate_bounds()?;
        Ok(application)
    }

    pub(super) fn apply_ready_control_event(
        &mut self,
        coordinate: FaultCoordinate,
        event: QueuedNetworkControlEvent,
        topology: &crucible::model::WorldFaultTopology,
    ) -> Result<BoundaryNetworkApplication, SchedulerError> {
        let contributions = self
            .control_planes
            .get_mut(&event.action.target)
            .map(|control| std::mem::take(&mut control.contributions));
        let result = self.apply_actions(coordinate, [event.action.clone()], topology);
        if let Some(contributions) = contributions {
            let Some(control) = self.control_planes.get_mut(&event.action.target) else {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "control target disappeared while applying a serviced event",
                    ),
                });
            };
            control.contributions = contributions;
        }
        result
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
            if state.phase != AssociationPhase::Authenticating {
                state.next_scan_nanos = now
                    .checked_add(policy.scan_interval_nanos.get())
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("association scan coordinate overflowed"),
                    })?;
                application.next_wakeup_nanos =
                    earliest_wakeup(application.next_wakeup_nanos, Some(state.next_scan_nanos));
            }
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
        append_evidence_count(material, self.control_planes.len())?;
        for (target, control) in &self.control_planes {
            append_resolved_target_evidence(material, target)?;
            material.extend_from_slice(&control.next_sequence.to_be_bytes());
            material.extend_from_slice(&control.dropped_events.to_be_bytes());
            material.extend_from_slice(&control.typed_errors.to_be_bytes());
            material.extend_from_slice(&control.timed_out_events.to_be_bytes());
            append_evidence_count(material, control.contributions.len())?;
            for (binding, contribution) in &control.contributions {
                append_evidence_bytes(material, binding.as_str().as_bytes())?;
                append_evidence_bytes(material, contribution.service_curve.as_str().as_bytes())?;
                append_evidence_bytes(material, contribution.overflow_policy.as_str().as_bytes())?;
                material.extend_from_slice(&contribution.activation_nanos.to_be_bytes());
                material.extend_from_slice(&contribution.queue_bound.to_be_bytes());
                material.push(control_overflow_tag(contribution.overflow));
                material.extend_from_slice(
                    &contribution.timeout_nanos.unwrap_or(u64::MAX).to_be_bytes(),
                );
                append_optional_fault_object_id(material, contribution.typed_error.as_ref())?;
                material.extend_from_slice(&contribution.event_work_bits.to_be_bytes());
                material.extend_from_slice(&contribution.service_cursor_nanos.to_be_bytes());
                material.extend_from_slice(&contribution.transition_sequence.to_be_bytes());
                append_evidence_count(material, contribution.segments.len())?;
                for segment in &contribution.segments {
                    material.extend_from_slice(&segment.at_nanos.to_be_bytes());
                    material.extend_from_slice(&segment.rate_bps.get().to_be_bytes());
                }
            }
            append_evidence_count(material, control.events.len())?;
            for event in &control.events {
                append_control_event_evidence(material, event)?;
            }
            append_evidence_count(material, control.overflow_timeouts.len())?;
            for timeout in &control.overflow_timeouts {
                material.extend_from_slice(&timeout.deadline_nanos.to_be_bytes());
                let encoded = serde_json::to_vec(&timeout.action).map_err(|error| {
                    SchedulerError::BoundaryViolation {
                        message: format!("encode control timeout evidence: {error}"),
                    }
                })?;
                append_evidence_bytes(material, &encoded)?;
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
                    (association.phase != AssociationPhase::Authenticating)
                        .then_some(association.next_scan_nanos),
                    association.transfer_complete_nanos,
                ]
                .into_iter()
                .flatten()
            }))
            .chain(self.control_planes.values().flat_map(|control| {
                [
                    control.events.first().map(|event| event.release_nanos),
                    control
                        .overflow_timeouts
                        .first()
                        .map(|timeout| timeout.deadline_nanos),
                ]
                .into_iter()
                .flatten()
            }))
            .filter(|coordinate| *coordinate > now)
            .min()
    }
}

fn is_control_event(action: &ResolvedBindingAction) -> bool {
    matches!(
        action.effect.specification(),
        EffectSpecification::Network(
            NetworkEffectSpecification::RouteTransition { .. }
                | NetworkEffectSpecification::Association { .. }
                | NetworkEffectSpecification::Contact { .. }
                | NetworkEffectSpecification::ForwarderLifecycle { .. }
        )
    )
}

fn control_event_contract(
    action: &ResolvedBindingAction,
    topology: &crucible::model::WorldFaultTopology,
    state: &BoundaryNetworkState,
    restored_operation: Option<crucible::model::FaultOperation>,
) -> Result<
    (
        crucible::model::FaultOperation,
        FaultObjectId,
        FaultObjectId,
        ContentHash,
    ),
    SchedulerError,
> {
    let parse = |value: &'static str| {
        FaultObjectId::parse(value).map_err(|_error| {
            network_effect_application_error(action, "built-in control schema is invalid")
        })
    };
    match action.effect.specification() {
        EffectSpecification::Network(NetworkEffectSpecification::RouteTransition {
            new_route,
            ..
        }) => Ok((
            crucible::model::FaultOperation::NetworkRoute,
            parse("network-routing-v1")?,
            parse("network-route-id-v1")?,
            ContentHash::from_bytes(new_route.as_str().as_bytes()),
        )),
        EffectSpecification::Network(NetworkEffectSpecification::Association { .. }) => {
            let crucible::model::ResolvedFaultTarget::NetworkAttachment { attachment, .. } =
                &action.target
            else {
                return Err(network_effect_application_error(
                    action,
                    "association control event has a non-attachment target",
                ));
            };
            let declaration = topology
                .network_attachments
                .iter()
                .find(|candidate| candidate.id.as_str() == attachment.as_str())
                .ok_or_else(|| {
                    network_effect_application_error(
                        action,
                        "association target disappeared from World",
                    )
                })?;
            let operation = if let Some(operation) = restored_operation {
                if !matches!(
                    operation,
                    crucible::model::FaultOperation::NetworkAssociate
                        | crucible::model::FaultOperation::NetworkHandoff
                ) {
                    return Err(network_effect_application_error(
                        action,
                        "restored association event has an invalid operation",
                    ));
                }
                operation
            } else if state.associations.keys().any(|key| {
                key.target == action.target
                    && state
                        .associations
                        .get(key)
                        .is_some_and(|association| association.current.is_some())
            }) {
                crucible::model::FaultOperation::NetworkHandoff
            } else {
                crucible::model::FaultOperation::NetworkAssociate
            };
            Ok((
                operation,
                FaultObjectId::parse(declaration.technology.as_str().to_owned()).map_err(
                    |_error| {
                        network_effect_application_error(
                            action,
                            "attachment technology is not a control object ID",
                        )
                    },
                )?,
                parse("network-association-inputs-i64-v1")?,
                ContentHash::from_bytes(
                    &route::mapped_network_integers(action)?
                        .into_iter()
                        .flat_map(i64::to_be_bytes)
                        .collect::<Vec<_>>(),
                ),
            ))
        }
        EffectSpecification::Network(NetworkEffectSpecification::Contact { intervals, .. }) => {
            Ok((
                if action.kind == BindingActionKind::RemovePersistent {
                    crucible::model::FaultOperation::NetworkTeardown
                } else {
                    crucible::model::FaultOperation::NetworkAcquire
                },
                parse("network-contact-v1")?,
                parse("network-contact-plan-v1")?,
                ContentHash::from_bytes(intervals.as_str().as_bytes()),
            ))
        }
        EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
            transition,
            ..
        }) => Ok((
            crucible::model::FaultOperation::NetworkChange,
            parse("network-forwarder-v1")?,
            parse("network-forwarder-state-v1")?,
            ContentHash::from_bytes(&[*transition as u8]),
        )),
        _ => Err(network_effect_application_error(
            action,
            "non-control effect entered the control queue",
        )),
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

fn append_resolved_target_evidence(
    material: &mut Vec<u8>,
    target: &crucible::model::ResolvedFaultTarget,
) -> Result<(), SchedulerError> {
    append_evidence_bytes(material, target.canonical_material().as_bytes())
}

fn append_control_event_evidence(
    material: &mut Vec<u8>,
    event: &QueuedNetworkControlEvent,
) -> Result<(), SchedulerError> {
    let encoded = serde_json::to_vec(event).map_err(|error| SchedulerError::BoundaryViolation {
        message: format!("encode network control-event evidence: {error}"),
    })?;
    append_evidence_bytes(material, &encoded)
}

const fn control_overflow_tag(overflow: crucible::model::NetworkPolicyOverflow) -> u8 {
    match overflow {
        crucible::model::NetworkPolicyOverflow::DropNewest => 1,
        crucible::model::NetworkPolicyOverflow::DropOldest => 2,
        crucible::model::NetworkPolicyOverflow::TypedError => 3,
        crucible::model::NetworkPolicyOverflow::Timeout => 4,
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

    fn bounded(value: u32) -> crucible::model::BoundedCount {
        crucible::model::BoundedCount::new(crucible::model::CountLimit::QueueEntries, value)
            .unwrap_or_else(|error| panic!("test bound should be valid: {error}"))
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
            expected_precondition: None,
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
            expected_precondition: None,
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

    fn control_service_action() -> ResolvedBindingAction {
        control_service_action_with("control-service-binding", 1, "control-overflow")
    }

    fn control_service_action_with(
        binding: &str,
        queue_bound: u32,
        overflow_policy: &str,
    ) -> ResolvedBindingAction {
        let effect = EffectRequest::new(
            crucible::model::EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::ControlPlaneService {
                service_curve: id("control-service"),
                queue_bound: bounded(queue_bound),
                overflow_policy: id(overflow_policy),
                event_work_bits: positive(10),
            }),
        )
        .unwrap_or_else(|error| panic!("test control service should be valid: {error}"));
        ResolvedBindingAction {
            kind: BindingActionKind::UpsertPersistent,
            binding: id(binding),
            target: crucible::model::ResolvedFaultTarget::NetworkPath {
                path_version: id("route-a"),
                direction: crucible::model::FaultDirection::AToB,
            },
            phase: FaultPhase::Boundary,
            effect: Arc::new(effect),
            mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
            mapped_digest: ContentHash::from_bytes(b"control-service"),
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            cause: BindingActionCause::Signal,
            expected_precondition: None,
        }
    }

    fn route_transition_action(binding: &str, new_route: &str) -> ResolvedBindingAction {
        let effect = EffectRequest::new(
            crucible::model::EFFECT_SEMANTIC_VERSION,
            EffectLifetime::StateMachine,
            EffectSpecification::Network(NetworkEffectSpecification::RouteTransition {
                old_route: id("route-a"),
                new_route: id(new_route),
                convergence_events: id("route-convergence"),
                in_flight_policy: crucible::model::NetworkInFlightPolicy::Preserve,
            }),
        )
        .unwrap_or_else(|error| panic!("test route transition should be valid: {error}"));
        ResolvedBindingAction {
            kind: BindingActionKind::Apply,
            binding: id(binding),
            target: crucible::model::ResolvedFaultTarget::NetworkPath {
                path_version: id("route-a"),
                direction: crucible::model::FaultDirection::AToB,
            },
            phase: FaultPhase::Boundary,
            effect: Arc::new(effect),
            mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
            mapped_digest: ContentHash::from_bytes(new_route.as_bytes()),
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            cause: BindingActionCause::Signal,
            expected_precondition: None,
        }
    }

    fn control_topology() -> crucible::model::WorldFaultTopology {
        crucible::model::WorldFaultTopology {
            network_policy_artifacts: vec![
                crucible::model::WorldNetworkPolicyArtifact {
                    id: id("control-overflow"),
                    semantic_version: 1,
                    artifact: crucible::model::NetworkPolicyArtifactKind::Overflow {
                        disposition: crucible::model::NetworkPolicyOverflow::DropNewest,
                        timeout_nanos: None,
                        typed_error: None,
                    },
                },
                crucible::model::WorldNetworkPolicyArtifact {
                    id: id("control-service"),
                    semantic_version: 1,
                    artifact: crucible::model::NetworkPolicyArtifactKind::ServiceCurve {
                        segments: crucible::model::NetworkServiceSegments::new(vec![
                            crucible::model::NetworkServiceSegment {
                                at_nanos: 0,
                                rate_bps: positive(1_000_000_000),
                            },
                        ])
                        .unwrap_or_else(|error| panic!("test service curve: {error}")),
                    },
                },
                crucible::model::WorldNetworkPolicyArtifact {
                    id: id("route-convergence"),
                    semantic_version: 1,
                    artifact: crucible::model::NetworkPolicyArtifactKind::StateMachine {
                        initial: id("pending"),
                        states: vec![id("pending"), id("ready")],
                        transitions: vec![crucible::model::NetworkPolicyTransition {
                            from: id("pending"),
                            event: id("converge"),
                            to: id("ready"),
                            delay_nanos: 0,
                            traffic_policy: crucible::model::NetworkInFlightPolicy::Preserve,
                        }],
                    },
                },
                crucible::model::WorldNetworkPolicyArtifact {
                    id: id("route-replacement-result"),
                    semantic_version: 1,
                    artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                        schema: id("network-route-id-v1"),
                        bytes: b"route-c".to_vec(),
                    },
                },
            ],
            network_paths: vec![crucible::model::WorldNetworkPath {
                id: crucible::model::SignalId::parse("route-c")
                    .unwrap_or_else(|error| panic!("test route ID: {error}")),
                direction: crucible::model::FaultDirection::AToB,
                hops: Vec::new(),
                mtu_bytes: 1_500,
            }],
            ..crucible::model::WorldFaultTopology::default()
        }
    }

    fn route_replacement_action() -> ResolvedBindingAction {
        let effect = EffectRequest::new(
            crucible::model::EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Opportunity,
            EffectSpecification::Network(NetworkEffectSpecification::ControlResultTransform {
                technology: id("network-routing-v1"),
                operations: crucible::model::OperationSet::new(vec![
                    crucible::model::FaultOperation::NetworkRoute,
                ])
                .unwrap_or_else(|error| panic!("test operation set: {error}")),
                kind: crucible::model::NetworkControlResultKind::Replace,
                result: Some(id("route-replacement-result")),
            }),
        )
        .unwrap_or_else(|error| panic!("test control transform should be valid: {error}"));
        ResolvedBindingAction {
            kind: BindingActionKind::Apply,
            binding: id("route-transform"),
            target: route_transition_action("ignored", "route-b").target,
            phase: FaultPhase::Resolve,
            effect: Arc::new(effect),
            mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
            mapped_digest: ContentHash::from_bytes(b"route-transform"),
            transition_sequence: 1,
            opportunity: Some(ContentHash::from_bytes(b"control-opportunity")),
            coordinate: FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: None,
            },
            cause: BindingActionCause::Opportunity(ContentHash::from_bytes(b"control-opportunity")),
            expected_precondition: None,
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
                contact: id("contact-a"),
                service_resource: id("resource-a"),
                route_cost: positive(1),
                routing_propagation_nanos: 1,
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

    #[test]
    fn control_service_queues_executes_and_reports_overflow_without_bypasses() {
        let topology = control_topology();
        let mut state = BoundaryNetworkState::default();
        let queued = state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                [
                    control_service_action(),
                    route_transition_action("route-event-a", "route-b"),
                    route_transition_action("route-event-b", "route-c"),
                ],
                &topology,
            )
            .unwrap_or_else(|error| panic!("queue control events: {error}"));
        assert!(queued.ready_control_events.is_empty());
        assert_eq!(queued.next_wakeup_nanos, Some(10));
        assert_eq!(queued.control_outcomes.len(), 1);
        assert!(matches!(
            queued.control_outcomes[0].kind,
            ControlPlaneOutcomeKind::Dropped
        ));

        let mut released = state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 10,
                    retired_instructions: None,
                },
                [route_transition_action("route-event-c", "route-c")],
                &topology,
            )
            .unwrap_or_else(|error| panic!("release control event: {error}"));
        assert_eq!(released.ready_control_events.len(), 1);
        assert!(released.control_outcomes.is_empty());
        assert_eq!(released.next_wakeup_nanos, Some(20));
        let event = released.ready_control_events.remove(0);
        let applied = state
            .apply_ready_control_event(
                FaultCoordinate {
                    virtual_nanos: 10,
                    retired_instructions: None,
                },
                event,
                &topology,
            )
            .unwrap_or_else(|error| panic!("apply serviced route event: {error}"));
        assert_eq!(applied.route_transitions.len(), 1);
        assert_eq!(
            state.route_path_override(&id("route-a"), 10),
            Some(&id("route-b"))
        );
    }

    #[test]
    fn control_service_updates_reject_conflicting_overflow_and_occupied_queue_shrink() {
        let mut topology = control_topology();
        topology
            .network_policy_artifacts
            .push(crucible::model::WorldNetworkPolicyArtifact {
                id: id("control-timeout"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::Overflow {
                    disposition: crucible::model::NetworkPolicyOverflow::Timeout,
                    timeout_nanos: Some(positive(5)),
                    typed_error: None,
                },
            });
        topology
            .network_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));

        let mut conflicting = BoundaryNetworkState::default();
        let error = conflicting
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                [
                    control_service_action(),
                    control_service_action_with("control-service-binding-b", 1, "control-timeout"),
                ],
                &topology,
            )
            .err()
            .unwrap_or_else(|| panic!("conflicting overflow policies must fail"));
        assert!(error.to_string().contains("disagree on overflow semantics"));

        let mut occupied = BoundaryNetworkState::default();
        occupied
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                [
                    control_service_action_with("control-service-binding", 2, "control-overflow"),
                    route_transition_action("route-event-a", "route-b"),
                    route_transition_action("route-event-b", "route-c"),
                ],
                &topology,
            )
            .unwrap_or_else(|error| panic!("fill control queue: {error}"));
        let error = occupied
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                [control_service_action()],
                &topology,
            )
            .err()
            .unwrap_or_else(|| panic!("occupied queue shrink must fail"));
        assert!(
            error
                .to_string()
                .contains("shrink the queue below its occupancy")
        );
    }

    #[test]
    fn control_overflow_executes_drop_oldest_typed_error_and_timeout_exactly() {
        let set_overflow = |topology: &mut crucible::model::WorldFaultTopology,
                            disposition,
                            timeout_nanos,
                            typed_error| {
            let declaration = topology
                .network_policy_artifacts
                .iter_mut()
                .find(|artifact| artifact.id == id("control-overflow"))
                .unwrap_or_else(|| panic!("control overflow artifact"));
            declaration.artifact = crucible::model::NetworkPolicyArtifactKind::Overflow {
                disposition,
                timeout_nanos,
                typed_error,
            };
        };
        let actions = || {
            [
                control_service_action(),
                route_transition_action("route-event-a", "route-b"),
                route_transition_action("route-event-b", "route-c"),
            ]
        };

        let mut drop_oldest_topology = control_topology();
        set_overflow(
            &mut drop_oldest_topology,
            crucible::model::NetworkPolicyOverflow::DropOldest,
            None,
            None,
        );
        let mut drop_oldest = BoundaryNetworkState::default();
        let application = drop_oldest
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                actions(),
                &drop_oldest_topology,
            )
            .unwrap_or_else(|error| panic!("drop-oldest control queue: {error}"));
        assert_eq!(application.control_outcomes.len(), 1);
        assert_eq!(
            application.control_outcomes[0].action.binding,
            id("route-event-a")
        );
        assert_eq!(
            drop_oldest
                .control_planes
                .values()
                .next()
                .and_then(|control| control.events.first())
                .map(|event| &event.action.binding),
            Some(&id("route-event-b"))
        );

        let mut typed_topology = control_topology();
        typed_topology
            .network_policy_artifacts
            .push(crucible::model::WorldNetworkPolicyArtifact {
                id: id("control-busy"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: id("network-control-error-v1"),
                    bytes: b"busy".to_vec(),
                },
            });
        set_overflow(
            &mut typed_topology,
            crucible::model::NetworkPolicyOverflow::TypedError,
            None,
            Some(id("control-busy")),
        );
        typed_topology
            .network_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));
        let mut typed = BoundaryNetworkState::default();
        let application = typed
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                actions(),
                &typed_topology,
            )
            .unwrap_or_else(|error| panic!("typed-error control queue: {error}"));
        assert_eq!(application.control_outcomes.len(), 1);
        assert!(matches!(
            application.control_outcomes[0].kind,
            ControlPlaneOutcomeKind::TypedError
        ));
        assert_eq!(
            application.control_outcomes[0].result,
            Some(id("control-busy"))
        );

        let mut timeout_topology = control_topology();
        set_overflow(
            &mut timeout_topology,
            crucible::model::NetworkPolicyOverflow::Timeout,
            Some(positive(5)),
            None,
        );
        let mut timeout = BoundaryNetworkState::default();
        let application = timeout
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                actions(),
                &timeout_topology,
            )
            .unwrap_or_else(|error| panic!("timeout control queue: {error}"));
        assert!(application.control_outcomes.is_empty());
        assert_eq!(application.next_wakeup_nanos, Some(5));
        let application = timeout
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 5,
                    retired_instructions: None,
                },
                [],
                &timeout_topology,
            )
            .unwrap_or_else(|error| panic!("expire control timeout: {error}"));
        assert_eq!(application.control_outcomes.len(), 1);
        assert!(matches!(
            application.control_outcomes[0].kind,
            ControlPlaneOutcomeKind::TimedOut
        ));
        assert_eq!(
            application.control_outcomes[0].action.binding,
            id("route-event-b")
        );
    }

    #[test]
    fn control_contributors_compose_by_minimum_bound_and_latest_committed_finish() {
        let topology = control_topology();
        let first_service =
            control_service_action_with("control-service-binding-a", 2, "control-overflow");
        let mut slower_service =
            control_service_action_with("control-service-binding-b", 1, "control-overflow");
        slower_service.effect = Arc::new(
            EffectRequest::new(
                crucible::model::EFFECT_SEMANTIC_VERSION,
                EffectLifetime::Persistent,
                EffectSpecification::Network(NetworkEffectSpecification::ControlPlaneService {
                    service_curve: id("control-service"),
                    queue_bound: bounded(1),
                    overflow_policy: id("control-overflow"),
                    event_work_bits: positive(20),
                }),
            )
            .unwrap_or_else(|error| panic!("slower test control service: {error}")),
        );
        let mut state = BoundaryNetworkState::default();
        let application = state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                [
                    first_service.clone(),
                    slower_service.clone(),
                    route_transition_action("route-event-a", "route-b"),
                    route_transition_action("route-event-b", "route-c"),
                ],
                &topology,
            )
            .unwrap_or_else(|error| panic!("compose control services: {error}"));
        assert_eq!(application.control_outcomes.len(), 1);
        assert_eq!(application.next_wakeup_nanos, Some(20));

        let mut remove_first = first_service;
        remove_first.kind = BindingActionKind::RemovePersistent;
        remove_first.coordinate.virtual_nanos = 1;
        let mut remove_second = slower_service;
        remove_second.kind = BindingActionKind::RemovePersistent;
        remove_second.coordinate.virtual_nanos = 1;
        let removed = state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 1,
                    retired_instructions: None,
                },
                [remove_first, remove_second],
                &topology,
            )
            .unwrap_or_else(|error| panic!("remove control services: {error}"));
        assert_eq!(removed.next_wakeup_nanos, Some(20));
        let released = state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 20,
                    retired_instructions: None,
                },
                [],
                &topology,
            )
            .unwrap_or_else(|error| panic!("release committed control event: {error}"));
        assert_eq!(released.ready_control_events.len(), 1);
    }

    #[test]
    fn queued_association_operation_identity_survives_checkpoint_state_changes() {
        let policy = id("association-policy");
        let mut topology = association_topology(policy.clone());
        let control = control_topology();
        topology
            .network_policy_artifacts
            .extend(control.network_policy_artifacts);
        topology
            .network_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));
        let signal = |value| {
            crucible::model::SignalId::parse(value)
                .unwrap_or_else(|error| panic!("test signal ID: {error}"))
        };
        topology
            .network_attachments
            .push(crucible::model::WorldNetworkAttachment {
                id: signal("attachment-a"),
                interface: signal("interface-a"),
                candidates: vec![signal("segment-a"), signal("segment-b")],
                technology: signal("network-wireless-v1"),
                semantic_version: 1,
                authentication: signal("authentication-a"),
                address_continuity: signal("address-continuity-a"),
            });

        let association = association_action(policy.clone(), [10, 20]);
        let mut service =
            control_service_action_with("association-control-service", 2, "control-overflow");
        service.target = association.target.clone();
        let mut state = BoundaryNetworkState::default();
        state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                [service, association.clone(), association.clone()],
                &topology,
            )
            .unwrap_or_else(|error| panic!("queue association events: {error}"));
        assert!(state.control_planes.values().next().is_some_and(|control| {
            control.events.len() == 2
                && control.events.iter().all(|event| {
                    event.operation == crucible::model::FaultOperation::NetworkAssociate
                })
        }));

        state.associations.insert(
            NetworkEffectStateKey::from_action(&association),
            AssociationState {
                policy,
                candidates: vec![(id("segment-a"), 10), (id("segment-b"), 20)],
                phase: AssociationPhase::Associated,
                current: Some(id("segment-a")),
                pending: None,
                pending_since_nanos: None,
                transfer_complete_nanos: None,
                next_scan_nanos: 2,
                preserve_queued: false,
                preserve_address: false,
                transition_sequence: 1,
            },
        );
        let encoded = serde_json::to_vec(&state)
            .unwrap_or_else(|error| panic!("encode boundary checkpoint: {error}"));
        let restored: BoundaryNetworkState = serde_json::from_slice(&encoded)
            .unwrap_or_else(|error| panic!("decode boundary checkpoint: {error}"));
        restored
            .validate_bounds()
            .unwrap_or_else(|error| panic!("restored bounds: {error}"));
        restored
            .validate_topology(&topology)
            .unwrap_or_else(|error| panic!("restored association queue: {error}"));
    }

    #[test]
    fn typed_control_replacement_changes_the_real_serviced_route_result() {
        let topology = control_topology();
        let mut state = BoundaryNetworkState::default();
        state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                [
                    control_service_action(),
                    route_transition_action("route-event", "route-b"),
                ],
                &topology,
            )
            .unwrap_or_else(|error| panic!("queue route event: {error}"));
        let mut released = state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: 10,
                    retired_instructions: None,
                },
                [],
                &topology,
            )
            .unwrap_or_else(|error| panic!("release route event: {error}"));
        let event = released.ready_control_events.remove(0);
        let transformed =
            apply_network_control_transforms(event, &[route_replacement_action()], &topology)
                .unwrap_or_else(|error| panic!("replace route result: {error}"))
                .unwrap_or_else(|| panic!("replacement should retain the control event"));
        state
            .apply_ready_control_event(
                FaultCoordinate {
                    virtual_nanos: 10,
                    retired_instructions: None,
                },
                transformed,
                &topology,
            )
            .unwrap_or_else(|error| panic!("apply replacement route result: {error}"));
        assert_eq!(
            state.route_path_override(&id("route-a"), 10),
            Some(&id("route-c"))
        );
    }
}
