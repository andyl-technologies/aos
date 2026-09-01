//! Maintains contact-service and custody-release ownership for routed frames.

use super::*;

pub(in super::super) fn earliest_wakeup(
    current: Option<u64>,
    candidate: Option<u64>,
) -> Option<u64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.min(candidate)),
        (Some(current), None) => Some(current),
        (None, candidate) => candidate,
    }
}

pub(in super::super) fn apply_network_custody_removals(
    state: &mut NetworkEffectRuntimeState,
    pending_outputs: &mut [crucible::BackendNetworkOutput],
    actions: &[ResolvedBindingAction],
    now: u64,
) -> Result<bool, SchedulerError> {
    let mut released_due = false;
    for action in actions.iter().filter(|action| {
        action.kind == BindingActionKind::RemovePersistent
            && action.effect.kind() == crucible::model::EffectKind::NetworkCustodyQueue
    }) {
        let Some(queue) = state
            .custody_queues
            .remove(&NetworkEffectStateKey::from_action(action))
        else {
            continue;
        };
        let opportunities = queue
            .reservations
            .iter()
            .map(|reservation| reservation.opportunity)
            .chain(
                queue
                    .overflow_timeouts
                    .iter()
                    .map(|timeout| timeout.opportunity),
            )
            .collect::<BTreeSet<_>>();
        cancel_network_contact_reservations(
            &mut state.contact_services,
            &NetworkEffectStateKey::from_action(action),
            &opportunities,
            now,
            action,
        )?;
        for opportunity in queue
            .reservations
            .iter()
            .map(|reservation| reservation.opportunity)
            .chain(
                queue
                    .overflow_timeouts
                    .iter()
                    .map(|timeout| timeout.opportunity),
            )
        {
            let output = pending_outputs
                .iter_mut()
                .find(|output| {
                    output.fault_continuation.cursor().queue_opportunity() == Some(opportunity)
                })
                .ok_or_else(|| {
                    network_effect_application_error(
                        action,
                        "removed custody entry has no scheduler-owned pending frame",
                    )
                })?;
            output
                .fault_continuation
                .cursor_mut()
                .reschedule_queue_until(opportunity, now)
                .map_err(|error| network_effect_application_error(action, &error.to_string()))?;
            let mut effects = output.fault_continuation.resolved_frame_effects().clone();
            effects.require_serialization();
            output
                .fault_continuation
                .set_resolved_frame_effects(effects);
            released_due = true;
        }
    }
    Ok(released_due)
}

pub(in super::super) fn cancel_network_contact_reservations(
    services: &mut BTreeMap<NetworkContactServiceKey, NetworkContactServiceState>,
    owner: &NetworkEffectStateKey,
    opportunities: &BTreeSet<ContentHash>,
    now: u64,
    action: &impl NetworkEffectContext,
) -> Result<(), SchedulerError> {
    for (key, service) in services {
        service.settled_cursor_nanos = service.settled_cursor_nanos.max(key.start_nanos);
        let (removed_bundles, removed_bytes) = service
            .reservations
            .iter()
            .filter(|reservation| {
                reservation.custody_owner.as_ref() == Some(owner)
                    && opportunities.contains(&reservation.opportunity)
                    && reservation.finish_nanos > now
            })
            .try_fold((0_u64, 0_u64), |(bundles, bytes), reservation| {
                bundles
                    .checked_add(1)
                    .zip(bytes.checked_add(reservation.bytes))
            })
            .ok_or_else(|| {
                network_effect_application_error(action, "contact cancellation count overflowed")
            })?;
        service.reservations.retain(|reservation| {
            reservation.custody_owner.as_ref() != Some(owner)
                || !opportunities.contains(&reservation.opportunity)
                || reservation.finish_nanos <= now
        });
        service.settled_cursor_nanos = service.settled_cursor_nanos.max(
            service
                .reservations
                .iter()
                .filter(|reservation| reservation.finish_nanos <= now)
                .map(|reservation| reservation.finish_nanos)
                .max()
                .unwrap_or(key.start_nanos),
        );
        service.reservations.retain(|reservation| {
            reservation.finish_nanos > now
                || reservation.custody_owner.as_ref() != Some(owner)
                || !opportunities.contains(&reservation.opportunity)
        });
        service.served_bundles = service
            .served_bundles
            .checked_sub(removed_bundles)
            .ok_or_else(|| {
                network_effect_application_error(action, "contact bundle cancellation underflowed")
            })?;
        service.served_bytes =
            service
                .served_bytes
                .checked_sub(removed_bytes)
                .ok_or_else(|| {
                    network_effect_application_error(
                        action,
                        "contact byte cancellation underflowed",
                    )
                })?;
        service.service_cursor_nanos = service.settled_cursor_nanos.max(
            service
                .reservations
                .iter()
                .map(|reservation| reservation.finish_nanos)
                .max()
                .unwrap_or(key.start_nanos),
        );
    }
    Ok(())
}

pub(in super::super) fn prune_network_contact_services(
    state: &mut NetworkEffectRuntimeState,
    now: u64,
) {
    let live_custody = state
        .custody_queues
        .iter()
        .flat_map(|(owner, queue)| {
            queue
                .reservations
                .iter()
                .map(|reservation| (owner.clone(), reservation.opportunity))
        })
        .collect::<BTreeSet<_>>();
    for (key, service) in &mut state.contact_services {
        service.settled_cursor_nanos = service.settled_cursor_nanos.max(key.start_nanos);
        service.reservations.retain(|reservation| {
            let live = reservation.custody_owner.as_ref().is_some_and(|owner| {
                live_custody.contains(&(owner.clone(), reservation.opportunity))
            });
            if reservation.finish_nanos <= now && !live {
                service.settled_cursor_nanos =
                    service.settled_cursor_nanos.max(reservation.finish_nanos);
                false
            } else {
                true
            }
        });
        service.service_cursor_nanos = service.settled_cursor_nanos.max(
            service
                .reservations
                .iter()
                .map(|reservation| reservation.finish_nanos)
                .max()
                .unwrap_or(key.start_nanos),
        );
    }
}

pub(in super::super) fn network_contact_reservation_count(
    state: &NetworkEffectRuntimeState,
) -> Option<usize> {
    state
        .contact_services
        .values()
        .try_fold(0_usize, |total, service| {
            total.checked_add(service.reservations.len())
        })
}

pub(in super::super) fn network_contact_entry_count(
    state: &NetworkEffectRuntimeState,
) -> Option<usize> {
    state
        .contact_services
        .len()
        .checked_add(network_contact_reservation_count(state)?)
}

pub(in super::super) fn admit_network_contact_service_keys(
    state: &NetworkEffectRuntimeState,
    keys: &BTreeSet<NetworkContactServiceKey>,
    additional_reservations: usize,
    resource_limits: FaultResourceLimits,
) -> Result<(), SchedulerError> {
    let additional = keys
        .iter()
        .filter(|key| !state.contact_services.contains_key(*key))
        .count();
    let current = network_contact_entry_count(state).ok_or_else(|| {
        map_network_resource_limit(
            FaultResourceLimitError::Representation {
                field: "network_contact_entries",
                value: u64::MAX,
            },
            resource_limits,
        )
    })?;
    let requested = additional
        .checked_add(additional_reservations)
        .ok_or_else(|| {
            map_network_resource_limit(
                FaultResourceLimitError::Representation {
                    field: "network_contact_entries",
                    value: u64::MAX,
                },
                resource_limits,
            )
        })?;
    reserve_network_resource(
        "network_contact_entries",
        current,
        requested,
        resource_limits,
    )
}

pub(in super::super) fn availability_allows(
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
            direction == crucible::model::FaultDirection::Egress
        }
    }
}
