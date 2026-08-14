//! Production ownership of signal-driven network interception.
//!
//! The interceptor lives inside the backend quantum loop so committed QEMU
//! frames cannot bypass the exact pre-routing fault boundary. The executable
//! network adapter is layered onto this owner; the runtime itself is never
//! shared through a test-only or process-global side channel.

mod boundary;
mod evidence;
mod route;

use evidence::*;

/// Canonical sequence encoding for checkpoint maps whose keys are not JSON strings.
pub(super) mod ordered_map_entries {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Serialize};

    /// Serializes entries in their strict `BTreeMap` key order.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error when an entry cannot be encoded.
    pub(super) fn serialize<S, K, V>(
        value: &BTreeMap<K, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        K: Serialize,
        V: Serialize,
    {
        value.iter().collect::<Vec<_>>().serialize(serializer)
    }

    /// Decodes entries while rejecting duplicates and noncanonical order.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error for malformed, duplicate, or unordered entries.
    pub(super) fn deserialize<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        D: serde::Deserializer<'de>,
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
    {
        let entries = Vec::<(K, V)>::deserialize(deserializer)?;
        let mut result = BTreeMap::new();
        for (key, value) in entries {
            if result
                .last_key_value()
                .is_some_and(|(prior, _value)| prior >= &key)
            {
                return Err(serde::de::Error::custom(
                    "checkpoint map entries are not in strict canonical order",
                ));
            }
            result.insert(key, value);
        }
        Ok(result)
    }
}

mod ordered_nested_map_entries {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Serialize};

    /// Serializes both map levels as canonical ordered entry sequences.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error when an entry cannot be encoded.
    pub(super) fn serialize<S, K, K2, V>(
        value: &BTreeMap<K, BTreeMap<K2, V>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        K: Serialize,
        K2: Serialize,
        V: Serialize,
    {
        value
            .iter()
            .map(|(key, entries)| (key, entries.iter().collect::<Vec<_>>()))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    /// Decodes both map levels while rejecting duplicates and noncanonical order.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error for malformed, duplicate, or unordered entries.
    pub(super) fn deserialize<'de, D, K, K2, V>(
        deserializer: D,
    ) -> Result<BTreeMap<K, BTreeMap<K2, V>>, D::Error>
    where
        D: serde::Deserializer<'de>,
        K: Deserialize<'de> + Ord,
        K2: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
    {
        let entries = Vec::<(K, Vec<(K2, V)>)>::deserialize(deserializer)?;
        let mut result = BTreeMap::new();
        for (key, nested_entries) in entries {
            if result
                .last_key_value()
                .is_some_and(|(prior, _value)| prior >= &key)
            {
                return Err(serde::de::Error::custom(
                    "checkpoint outer map entries are not in strict canonical order",
                ));
            }
            let mut nested = BTreeMap::new();
            for (nested_key, value) in nested_entries {
                if nested
                    .last_key_value()
                    .is_some_and(|(prior, _value)| prior >= &nested_key)
                {
                    return Err(serde::de::Error::custom(
                        "checkpoint nested map entries are not in strict canonical order",
                    ));
                }
                nested.insert(nested_key, value);
            }
            result.insert(key, nested);
        }
        Ok(result)
    }
}

use route::{availability_allows, earliest_wakeup, network_effect_application_error};

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use super::*;
use crucible::model::{
    BindingActionKind, ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION,
    FaultObjectId, FaultObservation, FaultObservationKind, FaultOpportunity, FaultPhase,
    NetworkAvailabilityState, NetworkEffectSpecification, NetworkInFlightPolicy,
    OpportunityPayload, ResolvedBindingAction,
};
use crucible::{BackendNetworkOutputInterceptor, SchedulerEventLogAppend};

const HARD_PENDING_NETWORK_FRAMES: usize = 65_536;
const HARD_PENDING_NETWORK_BYTES: usize = 1_073_741_824;
const HARD_CONTACT_SERVICE_RESERVATIONS: usize = 262_144;
const HARD_CONTACT_SERVICE_STATES: usize = 262_144;
const NETWORK_ADAPTER_CHECKPOINT_VERSION: u16 = 7;

fn stage_pending_network_output(
    pending: &mut Vec<crucible::BackendNetworkOutput>,
    output: crucible::BackendNetworkOutput,
) -> Result<(), SchedulerError> {
    if output.fault_continuation.protocol_expansion_path().len()
        > crucible::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "network protocol-expansion depth exceeds hard bound {}",
                crucible::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
            ),
        });
    }
    if pending.len() == HARD_PENDING_NETWORK_FRAMES {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "signal-driven pending network frame count exceeds hard bound {HARD_PENDING_NETWORK_FRAMES}"
            ),
        });
    }
    let occupied = pending.iter().try_fold(0_usize, |total, queued| {
        total.checked_add(queued.payload.len())
    });
    let required = occupied.and_then(|total| total.checked_add(output.payload.len()));
    if required.is_none_or(|bytes| bytes > HARD_PENDING_NETWORK_BYTES) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "signal-driven pending network bytes exceed hard bound {HARD_PENDING_NETWORK_BYTES}"
            ),
        });
    }
    pending.push(output);
    Ok(())
}

fn validate_pending_network_outputs(
    pending: &[crucible::BackendNetworkOutput],
) -> Result<(), SchedulerError> {
    if pending.len() > HARD_PENDING_NETWORK_FRAMES {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "restored pending network frame count exceeds hard bound {HARD_PENDING_NETWORK_FRAMES}"
            ),
        });
    }
    if pending.iter().any(|output| {
        output.fault_continuation.protocol_expansion_path().len()
            > crucible::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
    }) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "restored network protocol-expansion depth exceeds hard bound {}",
                crucible::model::HARD_NETWORK_PROTOCOL_EXPANSION_DEPTH
            ),
        });
    }
    if pending.iter().any(|output| {
        let cursor = output.fault_continuation.cursor();
        cursor.queue_priority().is_some_and(|priority| priority > 3)
            || cursor.queue_priority().is_some()
                && cursor.repeated_phase_effect()
                    != Some(crucible::model::EffectKind::NetworkCustodyQueue)
    }) {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "restored network queue priority is invalid or has no custody owner",
            ),
        });
    }
    let bytes = pending.iter().try_fold(0_usize, |total, output| {
        total.checked_add(output.payload.len())
    });
    if bytes.is_none_or(|bytes| bytes > HARD_PENDING_NETWORK_BYTES) {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "restored pending network bytes exceed hard bound {HARD_PENDING_NETWORK_BYTES}"
            ),
        });
    }
    Ok(())
}

fn validate_network_adapter_checkpoint(
    checkpoint: &NetworkAdapterCheckpoint,
) -> Result<(), SchedulerError> {
    if checkpoint.semantic_version != NETWORK_ADAPTER_CHECKPOINT_VERSION
        || checkpoint.coordinate.is_none() && checkpoint.coordinate_sequence != 0
        || checkpoint.coordinate.is_none() && checkpoint.journal_sequence != 0
        || checkpoint.coordinate.is_some()
            && checkpoint.journal_sequence <= checkpoint.coordinate_sequence
        || !checkpoint
            .observations
            .validate(checkpoint.journal_sequence)
        || checkpoint.effect_state.token_buckets.len() > 65_536
        || checkpoint.effect_state.queues.len() > 65_536
        || checkpoint.effect_state.burst_states.len() > 65_536
        || checkpoint.effect_state.state_machines.len() > 65_536
        || checkpoint.effect_state.connection_tables.len() > 65_536
        || checkpoint.effect_state.shared_media.len() > 65_536
        || checkpoint.effect_state.backpressure.len() > 65_536
        || checkpoint.effect_state.custody_queues.len() > 65_536
        || checkpoint.effect_state.contact_services.len() > HARD_CONTACT_SERVICE_STATES
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "network adapter checkpoint schema or top-level bounds are invalid",
            ),
        });
    }
    let connection_entries = checkpoint
        .effect_state
        .connection_tables
        .values()
        .try_fold(0_usize, |total, table| total.checked_add(table.len()))
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("network connection checkpoint count overflowed"),
        })?;
    if connection_entries > 4_194_304
        || checkpoint
            .effect_state
            .connection_tables
            .iter()
            .any(|(key, table)| {
                key.effect != crucible::model::EffectKind::NetworkConnectionState
                    || table.len() > 4_194_304
                    || table.values().any(|entry| {
                        entry.machine.current.as_str().is_empty()
                            || entry.machine.pending.len() > 65_536
                            || entry
                                .machine
                                .pending
                                .iter()
                                .any(|pending| pending.state.as_str().is_empty())
                            || entry
                                .machine
                                .pending
                                .windows(2)
                                .any(|pair| pair[0].commit_nanos > pair[1].commit_nanos)
                    })
            })
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("network connection checkpoint exceeds hard bounds"),
        });
    }
    if checkpoint
        .effect_state
        .state_machines
        .iter()
        .any(|(key, machine)| {
            key.effect != crucible::model::EffectKind::NetworkFirewallDisposition
                || machine.current.as_str().is_empty()
                || machine.pending.len() > 65_536
                || machine
                    .pending
                    .iter()
                    .any(|pending| pending.state.as_str().is_empty())
                || machine
                    .pending
                    .windows(2)
                    .any(|pair| pair[0].commit_nanos > pair[1].commit_nanos)
        })
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("network state-machine checkpoint is invalid"),
        });
    }
    let medium_key_bytes = checkpoint
        .effect_state
        .shared_media
        .values()
        .flat_map(|medium| &medium.reservations)
        .try_fold(0_usize, |total, reservation| {
            total.checked_add(reservation.arbitration_key.len())
        })
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("network medium checkpoint key bytes overflowed"),
        })?;
    let medium_reservations = checkpoint
        .effect_state
        .shared_media
        .values()
        .try_fold(0_usize, |total, medium| {
            total.checked_add(medium.reservations.len())
        })
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("network medium checkpoint reservation count overflowed"),
        })?;
    if medium_key_bytes > HARD_PENDING_NETWORK_BYTES
        || medium_reservations > HARD_PENDING_NETWORK_FRAMES
        || checkpoint
            .effect_state
            .shared_media
            .iter()
            .any(|(key, medium)| {
                key.effect != crucible::model::EffectKind::NetworkSharedMedium
                    || medium.resources.is_empty()
                    || medium.resources.len() > 65_536
                    || medium.policy.as_str().is_empty()
                    || medium.reservations.len() > HARD_PENDING_NETWORK_FRAMES
                    || medium.resources.windows(2).any(|pair| pair[0] >= pair[1])
                    || medium.reservations.iter().any(|reservation| {
                        reservation.producer.as_str().is_empty()
                            || reservation.arbitration_key.len() > HARD_PENDING_NETWORK_BYTES
                            || reservation.arrival_nanos > reservation.start_nanos
                            || reservation.start_nanos >= reservation.finish_nanos
                            || reservation.duration_nanos
                                != reservation.finish_nanos - reservation.start_nanos
                            || reservation.transmit_power_femtowatts == 0
                    })
            })
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("network shared-medium checkpoint exceeds hard bounds"),
        });
    }
    for medium in checkpoint.effect_state.shared_media.values() {
        let mut opportunities = BTreeSet::new();
        if medium.reservations.iter().any(|reservation| {
            medium
                .resources
                .binary_search(&reservation.producer)
                .is_err()
                || !opportunities.insert(reservation.opportunity)
        }) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "network shared-medium checkpoint has an unknown producer or repeated reservation",
                ),
            });
        }
    }
    for (target, queue) in &checkpoint.effect_state.queues {
        if queue.reservations.len() > HARD_PENDING_NETWORK_FRAMES
            || queue.served_frames_by_class.len() > 65_536
            || queue.served_bytes_by_class.len() > 65_536
            || queue.reservations.iter().any(|reservation| {
                reservation.service_curves.len() > 65_536
                    || reservation.base_ready_nanos > reservation.ready_nanos
                    || reservation.ready_nanos > reservation.service_start_nanos
                    || reservation.service_start_nanos > reservation.finish_nanos
                    || reservation
                        .bytes
                        .checked_mul(8)
                        .is_none_or(|bits| bits != reservation.payload_bits)
                    || reservation.remaining_nano_bits == 0
                    || u128::from(reservation.payload_bits)
                        .checked_mul(1_000_000_000)
                        .is_none_or(|demand| reservation.remaining_nano_bits > demand)
                    || reservation
                        .service_curves
                        .iter()
                        .any(|curve| curve.segments.is_empty() || curve.segments.len() > 65_536)
            })
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network adapter queue checkpoint exceeds hard bounds"),
            });
        }
        if queue.configuration.is_none() && !queue.reservations.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network queue checkpoint omitted its configuration"),
            });
        }
        if let Some(configuration) = &queue.configuration {
            let parameters_required = !matches!(
                configuration.discipline,
                crucible::model::NetworkQueueDiscipline::Fifo
            );
            if &configuration.owner.target != target
                || !matches!(
                    configuration.owner.effect,
                    crucible::model::EffectKind::NetworkQueuePolicy
                        | crucible::model::EffectKind::NetworkServiceCurve
                )
                || parameters_required != configuration.discipline_parameters.is_some()
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("network queue checkpoint configuration is invalid"),
                });
            }
        }
        let mut opportunities = BTreeSet::new();
        if queue
            .reservations
            .iter()
            .any(|reservation| !opportunities.insert(reservation.opportunity))
            || queue
                .reservations
                .windows(2)
                .any(|pair| pair[0].finish_nanos > pair[1].service_start_nanos)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("network queue checkpoint schedule overlaps or repeats"),
            });
        }
    }
    if checkpoint
        .effect_state
        .backpressure
        .iter()
        .any(|(key, pause)| {
            key.effect != crucible::model::EffectKind::NetworkPauseBackpressure
                || pause.class.as_str().is_empty()
        })
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("network backpressure checkpoint is invalid"),
        });
    }
    let custody_entries = checkpoint
        .effect_state
        .custody_queues
        .values()
        .try_fold(0_usize, |total, queue| {
            total
                .checked_add(queue.reservations.len())
                .and_then(|total| total.checked_add(queue.overflow_timeouts.len()))
        })
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("network custody checkpoint count overflowed"),
        })?;
    let contact_reservations = checkpoint
        .effect_state
        .contact_services
        .values()
        .try_fold(0_usize, |total, service| {
            total.checked_add(service.reservations.len())
        })
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("network contact reservation count overflowed"),
        })?;
    if custody_entries > HARD_PENDING_NETWORK_FRAMES
        || contact_reservations > HARD_CONTACT_SERVICE_RESERVATIONS
        || checkpoint
            .effect_state
            .custody_queues
            .iter()
            .any(|(key, queue)| {
                key.effect != crucible::model::EffectKind::NetworkCustodyQueue
                    || queue.configuration.as_ref().is_none_or(|configuration| {
                        &configuration.owner != key
                            || configuration.capacity_bytes == 0
                            || configuration.capacity_bundles == 0
                            || configuration.expiry_nanos == 0
                            || configuration.max_visited_hops == 0
                            || configuration.max_visited_hops > 256
                            || u64::try_from(queue.reservations.len())
                                .ok()
                                .is_none_or(|count| count > configuration.capacity_bundles)
                            || queue
                                .reservations
                                .iter()
                                .try_fold(0_u64, |total, reservation| {
                                    total.checked_add(reservation.bytes)
                                })
                                .is_none_or(|bytes| bytes > configuration.capacity_bytes)
                            || queue.reservations.iter().any(|reservation| {
                                reservation.bundle.priority != configuration.priority
                                    || reservation
                                        .enqueue_nanos
                                        .checked_add(configuration.expiry_nanos)
                                        != Some(reservation.expiry_nanos)
                            })
                            || queue.overflow_timeouts.iter().any(|timeout| {
                                timeout.bundle.priority != configuration.priority
                                    || timeout.enqueue_nanos >= timeout.deadline_nanos
                                    || timeout.deadline_nanos > timeout.expiry_nanos
                                    || timeout
                                        .enqueue_nanos
                                        .checked_add(configuration.expiry_nanos)
                                        != Some(timeout.expiry_nanos)
                            })
                    })
                    || queue.reservations.windows(2).any(|pair| {
                        (
                            pair[0].bundle.priority.rank(),
                            pair[0].enqueue_nanos,
                            &pair[0].bundle,
                        ) >= (
                            pair[1].bundle.priority.rank(),
                            pair[1].enqueue_nanos,
                            &pair[1].bundle,
                        )
                    })
                    || queue.overflow_timeouts.windows(2).any(|pair| {
                        (pair[0].deadline_nanos, &pair[0].bundle)
                            >= (pair[1].deadline_nanos, &pair[1].bundle)
                    })
                    || queue.reservations.iter().any(|reservation| {
                        reservation.bytes != reservation.bundle.length_bytes
                            || reservation.enqueue_nanos >= reservation.expiry_nanos
                            || reservation.release_nanos > reservation.expiry_nanos
                            || reservation.contact_path.len()
                                > usize::try_from(
                                    queue
                                        .configuration
                                        .as_ref()
                                        .map_or(0, |configuration| configuration.max_visited_hops),
                                )
                                .unwrap_or(0)
                            || reservation.contact_path_committed
                                && reservation.contact_path.is_empty()
                    })
            })
        || checkpoint
            .effect_state
            .contact_services
            .iter()
            .any(|(key, service)| {
                key.source == key.destination
                    || key.start_nanos >= key.end_nanos
                    || service.settled_cursor_nanos < key.start_nanos
                    || service.settled_cursor_nanos > service.service_cursor_nanos
                    || service.service_cursor_nanos < key.start_nanos
                    || service.reservations.windows(2).any(|pair| {
                        (
                            pair[0].start_nanos,
                            pair[0].finish_nanos,
                            pair[0].opportunity,
                        ) >= (
                            pair[1].start_nanos,
                            pair[1].finish_nanos,
                            pair[1].opportunity,
                        ) || pair[0].finish_nanos > pair[1].start_nanos
                    })
                    || service.reservations.iter().any(|reservation| {
                        reservation.start_nanos >= reservation.finish_nanos
                            || reservation.finish_nanos > reservation.arrival_nanos
                            || reservation.finish_nanos > key.end_nanos
                            || reservation.bytes == 0
                    })
                    || service.service_cursor_nanos
                        != service.settled_cursor_nanos.max(
                            service
                                .reservations
                                .iter()
                                .map(|reservation| reservation.finish_nanos)
                                .max()
                                .unwrap_or(key.start_nanos),
                        )
                    || service.served_bundles
                        < u64::try_from(service.reservations.len()).unwrap_or(u64::MAX)
                    || service.served_bytes
                        < service
                            .reservations
                            .iter()
                            .try_fold(0_u64, |total, reservation| {
                                total.checked_add(reservation.bytes)
                            })
                            .unwrap_or(u64::MAX)
            })
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("network custody/contact checkpoint is invalid"),
        });
    }
    let mut custody_bundles = BTreeSet::new();
    let mut custody_opportunities = BTreeSet::new();
    if checkpoint
        .effect_state
        .custody_queues
        .values()
        .flat_map(|queue| {
            queue
                .reservations
                .iter()
                .map(|reservation| (&reservation.bundle, reservation.opportunity))
                .chain(
                    queue
                        .overflow_timeouts
                        .iter()
                        .map(|timeout| (&timeout.bundle, timeout.opportunity)),
                )
        })
        .any(|(bundle, opportunity)| {
            !custody_bundles.insert(bundle.clone()) || !custody_opportunities.insert(opportunity)
        })
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("network custody checkpoint repeats bundle ownership"),
        });
    }
    checkpoint.effect_state.boundary.validate_bounds()
}

#[derive(Clone, Debug)]
#[allow(
    dead_code,
    reason = "the complete transition record is retained for deterministic fault diagnostics"
)]
struct NetworkAvailabilityTransitionRecord {
    action: ContentHash,
    binding: FaultObjectId,
    target: crucible::model::ResolvedFaultTarget,
    phase: FaultPhase,
    transition_sequence: u64,
    old_state: NetworkAvailabilityState,
    state: NetworkAvailabilityState,
    queued_policy: NetworkInFlightPolicy,
    in_flight_policy: NetworkInFlightPolicy,
    source: crucible::NodeId,
    destination: crucible::NodeId,
    in_flight: crucible::NetworkInFlightDropEvidence,
    queued: Vec<crucible::BackendNetworkOutput>,
    evidence: ContentHash,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
struct NetworkEffectStateKey {
    binding: FaultObjectId,
    target: crucible::model::ResolvedFaultTarget,
    effect: crucible::model::EffectKind,
}

impl NetworkEffectStateKey {
    fn from_action(action: &ResolvedBindingAction) -> Self {
        Self {
            binding: action.binding.clone(),
            target: action.target.clone(),
            effect: action.effect.kind(),
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct NetworkTokenBucketState {
    tokens_nano_bits: u128,
    last_refill_nanos: u64,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkQueueReservation {
    enqueue_nanos: u64,
    base_ready_nanos: u64,
    ready_nanos: u64,
    service_start_nanos: u64,
    finish_nanos: u64,
    bytes: u64,
    payload_bits: u64,
    remaining_nano_bits: u128,
    base_rate_bps: Option<u64>,
    service_curves: Vec<NetworkServiceCurveState>,
    class: Option<FaultObjectId>,
    opportunity: ContentHash,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkServiceCurveState {
    activation_nanos: u64,
    segments: Vec<crucible::model::NetworkServiceSegment>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct NetworkQueueConfiguration {
    owner: NetworkEffectStateKey,
    discipline: crucible::model::NetworkQueueDiscipline,
    discipline_parameters: Option<FaultObjectId>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct NetworkQueueState {
    configuration: Option<NetworkQueueConfiguration>,
    service_cursor_nanos: u64,
    reservations: Vec<NetworkQueueReservation>,
    served_frames_by_class: BTreeMap<FaultObjectId, u64>,
    served_bytes_by_class: BTreeMap<FaultObjectId, u64>,
    red_average_bytes_q32: u128,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkPauseState {
    class: FaultObjectId,
    paused_until: Option<u64>,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkPendingStateTransition {
    state: FaultObjectId,
    commit_nanos: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkStateMachineRuntime {
    current: FaultObjectId,
    pending: Vec<NetworkPendingStateTransition>,
    transition_sequence: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkConnectionEntry {
    machine: NetworkStateMachineRuntime,
    created_by: ContentHash,
    last_used_nanos: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkMediumReservation {
    opportunity: ContentHash,
    producer: FaultObjectId,
    arbitration_key: Vec<u8>,
    arrival_nanos: u64,
    start_nanos: u64,
    finish_nanos: u64,
    duration_nanos: u64,
    transmit_power_femtowatts: u64,
    terminal_collision_applied: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkMediumState {
    resources: Vec<FaultObjectId>,
    policy: FaultObjectId,
    transition_sequence: u64,
    service_cursor_nanos: u64,
    reservations: Vec<NetworkMediumReservation>,
}

/// Stable identity of one guest-originated bundle across queue retries.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
struct NetworkBundleIdentity {
    producer: FaultObjectId,
    destination: FaultObjectId,
    producer_sequence: u64,
    protocol_expansion_path: Vec<u16>,
    generated_response_depth: u8,
    generated_response_cause: Option<ContentHash>,
    forwarding_mutation_path: Vec<ContentHash>,
    length_bytes: u64,
    payload_digest: ContentHash,
    priority: crucible::model::NetworkBundlePriority,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct NetworkCustodyConfiguration {
    owner: NetworkEffectStateKey,
    capacity_bytes: u64,
    capacity_bundles: u64,
    expiry_nanos: u64,
    custody_policy: FaultObjectId,
    route_contact_plan: FaultObjectId,
    priority: crucible::model::NetworkBundlePriority,
    max_visited_hops: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkCustodyReservation {
    bundle: NetworkBundleIdentity,
    opportunity: ContentHash,
    enqueue_nanos: u64,
    expiry_nanos: u64,
    release_nanos: u64,
    bytes: u64,
    contact_path: Vec<FaultObjectId>,
    contact_path_committed: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkCustodyTimeout {
    bundle: NetworkBundleIdentity,
    opportunity: ContentHash,
    enqueue_nanos: u64,
    expiry_nanos: u64,
    deadline_nanos: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct NetworkCustodyQueueState {
    configuration: Option<NetworkCustodyConfiguration>,
    reservations: Vec<NetworkCustodyReservation>,
    overflow_timeouts: Vec<NetworkCustodyTimeout>,
    admitted_bundles: u64,
    released_bundles: u64,
    dropped_bundles: u64,
    expired_bundles: u64,
    missed_contact_bundles: u64,
    stale_plan_bundles: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
struct NetworkContactServiceKey {
    plan: FaultObjectId,
    contact: FaultObjectId,
    service_resource: FaultObjectId,
    source: FaultObjectId,
    destination: FaultObjectId,
    start_nanos: u64,
    end_nanos: u64,
}

fn network_contact_service_identity(key: &NetworkContactServiceKey) -> [u8; 32] {
    let mut material = Vec::new();
    for value in [
        &key.plan,
        &key.contact,
        &key.service_resource,
        &key.source,
        &key.destination,
    ] {
        let bytes = value.as_str().as_bytes();
        material.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        material.extend_from_slice(bytes);
    }
    material.extend_from_slice(&key.start_nanos.to_be_bytes());
    material.extend_from_slice(&key.end_nanos.to_be_bytes());
    ContentHash::from_bytes(&material).bytes
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct NetworkContactServiceState {
    settled_cursor_nanos: u64,
    service_cursor_nanos: u64,
    served_bundles: u64,
    served_bytes: u64,
    reservations: Vec<NetworkContactServiceReservation>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct NetworkContactServiceReservation {
    custody_owner: Option<NetworkEffectStateKey>,
    opportunity: ContentHash,
    start_nanos: u64,
    finish_nanos: u64,
    arrival_nanos: u64,
    bytes: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct NetworkEffectRuntimeState {
    #[serde(with = "ordered_map_entries")]
    token_buckets: BTreeMap<NetworkEffectStateKey, NetworkTokenBucketState>,
    #[serde(with = "ordered_map_entries")]
    queues: BTreeMap<crucible::model::ResolvedFaultTarget, NetworkQueueState>,
    #[serde(with = "ordered_map_entries")]
    burst_states: BTreeMap<NetworkEffectStateKey, FaultObjectId>,
    #[serde(with = "ordered_map_entries")]
    state_machines: BTreeMap<NetworkEffectStateKey, NetworkStateMachineRuntime>,
    #[serde(with = "ordered_nested_map_entries")]
    connection_tables:
        BTreeMap<NetworkEffectStateKey, BTreeMap<ContentHash, NetworkConnectionEntry>>,
    #[serde(with = "ordered_map_entries")]
    shared_media: BTreeMap<NetworkEffectStateKey, NetworkMediumState>,
    #[serde(with = "ordered_map_entries")]
    backpressure: BTreeMap<NetworkEffectStateKey, NetworkPauseState>,
    #[serde(with = "ordered_map_entries")]
    custody_queues: BTreeMap<NetworkEffectStateKey, NetworkCustodyQueueState>,
    #[serde(with = "ordered_map_entries")]
    contact_services: BTreeMap<NetworkContactServiceKey, NetworkContactServiceState>,
    boundary: boundary::BoundaryNetworkState,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkAdapterCheckpoint {
    semantic_version: u16,
    coordinate: Option<u64>,
    coordinate_sequence: u64,
    journal_sequence: u64,
    observations: super::storage_faults::ProductionFaultObservationJournal,
    effect_state: NetworkEffectRuntimeState,
}

struct StagedNetworkRestore {
    scheduler: SingleScheduler,
    pending_outputs: Vec<crucible::BackendNetworkOutput>,
    adapter: NetworkAdapterCheckpoint,
    identity: ContentHash,
}

fn stage_network_restore(
    checkpoint: &ProductionFaultRuntimeCheckpoint,
    scheduler: &SingleScheduler,
) -> Result<StagedNetworkRestore, SchedulerError> {
    let network =
        checkpoint
            .network_state()
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "restored production fault runtime omitted its network continuation",
                ),
            })?;
    let (scheduler_state, pending_outputs, adapter_bytes, identity) = network.into_parts();
    validate_pending_network_outputs(&pending_outputs)?;
    if scheduler.network_checkpoint() != scheduler_state {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("scheduler and production-fault network continuations differ"),
        });
    }
    let adapter: NetworkAdapterCheckpoint =
        serde_json::from_slice(&adapter_bytes).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("decode production network adapter checkpoint: {error}"),
            }
        })?;
    validate_network_adapter_checkpoint(&adapter)?;
    validate_medium_pending_links(&adapter.effect_state, &pending_outputs)?;
    let staged_scheduler = scheduler.clone();
    let actual = network_state_digest_from_parts(
        &staged_scheduler,
        &pending_outputs,
        adapter.coordinate,
        adapter.coordinate_sequence,
        adapter.journal_sequence,
        &adapter.observations,
        &adapter.effect_state,
    )?;
    if actual != identity {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "restored network continuation identity {}, expected {}",
                actual.to_hex(),
                identity.to_hex()
            ),
        });
    }
    Ok(StagedNetworkRestore {
        scheduler: staged_scheduler,
        pending_outputs,
        adapter,
        identity,
    })
}

fn validate_medium_pending_links(
    state: &NetworkEffectRuntimeState,
    pending_outputs: &[crucible::BackendNetworkOutput],
) -> Result<(), SchedulerError> {
    let pending_opportunities = pending_outputs
        .iter()
        .filter_map(|output| output.fault_continuation.cursor().queue_opportunity())
        .collect::<Vec<_>>();
    let pending = pending_opportunities
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if pending.len() != pending_opportunities.len() {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("pending network frames repeat queue opportunity ownership"),
        });
    }
    if state
        .shared_media
        .values()
        .flat_map(|medium| &medium.reservations)
        .any(|reservation| !pending.contains(&reservation.opportunity))
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "network shared-medium checkpoint reservation has no pending frame",
            ),
        });
    }
    if state
        .custody_queues
        .values()
        .flat_map(|queue| {
            queue
                .reservations
                .iter()
                .map(|reservation| reservation.opportunity)
                .chain(
                    queue
                        .overflow_timeouts
                        .iter()
                        .map(|timeout| timeout.opportunity),
                )
        })
        .any(|opportunity| !pending.contains(&opportunity))
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("network custody checkpoint entry has no pending frame"),
        });
    }
    Ok(())
}

fn validate_custody_contact_topology(
    state: &NetworkEffectRuntimeState,
    pending_outputs: &[crucible::BackendNetworkOutput],
    topology: &crucible::model::WorldFaultTopology,
) -> Result<(), SchedulerError> {
    let invalid = || SchedulerError::BoundaryViolation {
        message: String::from("network custody/contact checkpoint topology join is invalid"),
    };
    let output_bundle = |output: &crucible::BackendNetworkOutput,
                         priority: crucible::model::NetworkBundlePriority|
     -> Result<NetworkBundleIdentity, SchedulerError> {
        let route = output.route.as_ref().ok_or_else(invalid)?;
        Ok(NetworkBundleIdentity {
            producer: FaultObjectId::parse(&output.source.name).map_err(|_error| invalid())?,
            destination: FaultObjectId::parse(&route.destination.name)
                .map_err(|_error| invalid())?,
            producer_sequence: output.sequence,
            protocol_expansion_path: output.fault_continuation.protocol_expansion_path().to_vec(),
            generated_response_depth: output.fault_continuation.generated_response_depth(),
            generated_response_cause: output.fault_continuation.generated_response_cause(),
            forwarding_mutation_path: output
                .fault_continuation
                .forwarding_mutation_path()
                .to_vec(),
            length_bytes: u64::try_from(output.payload.len()).map_err(|_error| invalid())?,
            payload_digest: ContentHash::from_bytes(&output.payload),
            priority,
        })
    };
    for (key, service) in &state.contact_services {
        let plan = topology
            .network_policy_artifact(&key.plan)
            .ok_or_else(invalid)?;
        let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &plan.artifact
        else {
            return Err(invalid());
        };
        let interval = intervals
            .iter()
            .find(|interval| interval.contact == key.contact)
            .ok_or_else(invalid)?;
        let traffic_open = interval
            .start_nanos
            .checked_add(interval.acquisition_nanos)
            .ok_or_else(invalid)?;
        let traffic_close = interval
            .end_nanos
            .checked_sub(interval.teardown_nanos)
            .ok_or_else(invalid)?;
        if interval.service_resource != key.service_resource
            || interval.source != key.source
            || interval.destination != key.destination
            || interval.start_nanos != key.start_nanos
            || interval.end_nanos != key.end_nanos
            || service.service_cursor_nanos > traffic_close
            || service.reservations.iter().any(|reservation| {
                reservation.start_nanos < traffic_open || reservation.finish_nanos > traffic_close
            })
        {
            return Err(invalid());
        }
    }
    for (owner, queue) in &state.custody_queues {
        let configuration = queue.configuration.as_ref().ok_or_else(invalid)?;
        let plan = topology
            .network_policy_artifact(&configuration.route_contact_plan)
            .ok_or_else(invalid)?;
        let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &plan.artifact
        else {
            return Err(invalid());
        };
        for reservation in &queue.reservations {
            let output = pending_outputs
                .iter()
                .find(|output| {
                    output.fault_continuation.cursor().queue_opportunity()
                        == Some(reservation.opportunity)
                })
                .ok_or_else(invalid)?;
            if reservation.bundle.priority != configuration.priority
                || output_bundle(output, reservation.bundle.priority)? != reservation.bundle
            {
                return Err(invalid());
            }
            let cursor = output.fault_continuation.cursor();
            if cursor.not_before_nanos() != reservation.release_nanos
                || cursor.release_nanos() != reservation.release_nanos
                || cursor.repeated_phase_effect()
                    != Some(crucible::model::EffectKind::NetworkCustodyQueue)
                || cursor.queue_priority() != Some(reservation.bundle.priority.rank())
            {
                return Err(invalid());
            }
            let mut node = reservation.bundle.producer.clone();
            let mut seen = BTreeSet::new();
            let mut expected_identities = BTreeSet::new();
            let mut last_arrival = None;
            let mut previous_arrival = None;
            let mut first_open = None;
            for contact in &reservation.contact_path {
                if !seen.insert(contact.clone()) {
                    return Err(invalid());
                }
                let interval = intervals
                    .iter()
                    .find(|interval| &interval.contact == contact)
                    .ok_or_else(invalid)?;
                if interval.source != node {
                    return Err(invalid());
                }
                first_open.get_or_insert(
                    interval
                        .start_nanos
                        .checked_add(interval.acquisition_nanos)
                        .ok_or_else(invalid)?,
                );
                node = interval.destination.clone();
                let service_key = NetworkContactServiceKey {
                    plan: configuration.route_contact_plan.clone(),
                    contact: interval.contact.clone(),
                    service_resource: interval.service_resource.clone(),
                    source: interval.source.clone(),
                    destination: interval.destination.clone(),
                    start_nanos: interval.start_nanos,
                    end_nanos: interval.end_nanos,
                };
                let ledger = state
                    .contact_services
                    .get(&service_key)
                    .and_then(|service| {
                        service.reservations.iter().find(|entry| {
                            entry.custody_owner.as_ref() == Some(owner)
                                && entry.opportunity == reservation.opportunity
                        })
                    });
                if reservation.contact_path_committed {
                    let ledger = ledger.ok_or_else(invalid)?;
                    let expected_arrival = ledger
                        .finish_nanos
                        .checked_add(interval.routing_propagation_nanos)
                        .ok_or_else(invalid)?;
                    let earliest_start = previous_arrival.unwrap_or(reservation.enqueue_nanos);
                    if ledger.bytes != reservation.bytes
                        || ledger.arrival_nanos != expected_arrival
                        || ledger.start_nanos < earliest_start
                    {
                        return Err(invalid());
                    }
                    if !expected_identities.insert(network_contact_service_identity(&service_key)) {
                        return Err(invalid());
                    }
                    last_arrival = Some(ledger.arrival_nanos);
                    previous_arrival = Some(ledger.arrival_nanos);
                } else if ledger.is_some() {
                    return Err(invalid());
                }
            }
            if !reservation.contact_path.is_empty() && node != reservation.bundle.destination {
                return Err(invalid());
            }
            if reservation.contact_path_committed {
                let expected_identities = expected_identities.into_iter().collect::<Vec<_>>();
                if last_arrival != Some(reservation.release_nanos)
                    || output
                        .fault_continuation
                        .resolved_frame_effects()
                        .accounted_contact_services()
                        != expected_identities
                {
                    return Err(invalid());
                }
            } else if let Some(first_open) = first_open
                && (reservation.release_nanos < first_open
                    || !output
                        .fault_continuation
                        .resolved_frame_effects()
                        .accounted_contact_services()
                        .is_empty())
            {
                return Err(invalid());
            }
        }
        for timeout in &queue.overflow_timeouts {
            let policy = topology
                .network_policy_artifact(&configuration.custody_policy)
                .ok_or_else(invalid)?;
            let crucible::model::NetworkPolicyArtifactKind::Overflow {
                disposition: crucible::model::NetworkPolicyOverflow::Timeout,
                timeout_nanos: Some(timeout_duration),
                typed_error: None,
            } = &policy.artifact
            else {
                return Err(invalid());
            };
            let expected_deadline = timeout
                .enqueue_nanos
                .checked_add(timeout_duration.get())
                .ok_or_else(invalid)?
                .min(timeout.expiry_nanos);
            let output = pending_outputs
                .iter()
                .find(|output| {
                    output.fault_continuation.cursor().queue_opportunity()
                        == Some(timeout.opportunity)
                })
                .ok_or_else(invalid)?;
            if timeout.bundle.priority != configuration.priority
                || output_bundle(output, timeout.bundle.priority)? != timeout.bundle
                || !output
                    .fault_continuation
                    .resolved_frame_effects()
                    .accounted_contact_services()
                    .is_empty()
            {
                return Err(invalid());
            }
            let cursor = output.fault_continuation.cursor();
            if timeout.deadline_nanos != expected_deadline
                || cursor.not_before_nanos() != timeout.deadline_nanos
                || cursor.release_nanos() != timeout.deadline_nanos
                || cursor.repeated_phase_effect()
                    != Some(crucible::model::EffectKind::NetworkCustodyQueue)
                || cursor.queue_priority() != Some(timeout.bundle.priority.rank())
            {
                return Err(invalid());
            }
        }
    }
    for (key, service) in &state.contact_services {
        for ledger in &service.reservations {
            let Some(owner) = &ledger.custody_owner else {
                continue;
            };
            let queue = state.custody_queues.get(owner).ok_or_else(invalid)?;
            let mut matching = queue.reservations.iter().filter(|reservation| {
                reservation.opportunity == ledger.opportunity
                    && reservation.contact_path_committed
                    && reservation.bytes == ledger.bytes
                    && reservation.contact_path.contains(&key.contact)
            });
            if matching.next().is_none() || matching.next().is_some() {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn checkpoint_network_effect_state(
    state: &NetworkEffectRuntimeState,
    pending_outputs: &[crucible::BackendNetworkOutput],
    now: u64,
) -> NetworkEffectRuntimeState {
    let pending = pending_outputs
        .iter()
        .filter_map(|output| output.fault_continuation.cursor().queue_opportunity())
        .collect::<BTreeSet<_>>();
    let mut checkpoint = state.clone();
    checkpoint.shared_media.retain(|_key, medium| {
        medium
            .reservations
            .retain(|reservation| pending.contains(&reservation.opportunity));
        !medium.reservations.is_empty()
    });
    checkpoint.custody_queues.retain(|_key, queue| {
        queue
            .reservations
            .retain(|reservation| pending.contains(&reservation.opportunity));
        queue
            .overflow_timeouts
            .retain(|timeout| pending.contains(&timeout.opportunity));
        queue.configuration.is_some()
    });
    for (key, service) in &mut checkpoint.contact_services {
        service.reservations.retain(|reservation| {
            let retained_custody = reservation
                .custody_owner
                .as_ref()
                .is_some_and(|_owner| pending.contains(&reservation.opportunity));
            if reservation.finish_nanos <= now && !retained_custody {
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
    checkpoint
}

fn network_state_digest_from_parts(
    scheduler: &SingleScheduler,
    pending_outputs: &[crucible::BackendNetworkOutput],
    coordinate: Option<u64>,
    coordinate_sequence: u64,
    journal_sequence: u64,
    observations: &super::storage_faults::ProductionFaultObservationJournal,
    effect_state: &NetworkEffectRuntimeState,
) -> Result<ContentHash, SchedulerError> {
    let mut material = Vec::new();
    material.extend_from_slice(&scheduler.network_continuation_digest()?.bytes);
    material.extend_from_slice(&coordinate.unwrap_or(u64::MAX).to_be_bytes());
    material.extend_from_slice(&coordinate_sequence.to_be_bytes());
    material.extend_from_slice(&journal_sequence.to_be_bytes());
    let encoded_observations =
        serde_json::to_vec(observations).map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("encode pending production fault observations: {error}"),
        })?;
    material.extend_from_slice(&encoded_observations);
    let pending_count = u64::try_from(pending_outputs.len()).map_err(|_error| {
        SchedulerError::BoundaryViolation {
            message: String::from("pending network output count exceeds the checkpoint width"),
        }
    })?;
    material.extend_from_slice(&pending_count.to_be_bytes());
    for output in pending_outputs {
        append_backend_output_evidence(&mut material, output)?;
    }
    append_network_effect_state(&mut material, effect_state)?;
    Ok(ContentHash::from_bytes(&material))
}

/// One globally ordered cursor shared by every production fault opportunity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ProductionFaultEvaluationCursor {
    coordinate: Option<u64>,
    coordinate_sequence: u64,
    journal_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProductionFaultEvaluationSequence {
    pub(super) same_coordinate: u64,
    pub(super) journal: u64,
}

impl ProductionFaultEvaluationCursor {
    pub(super) fn next_sequence(
        &mut self,
        coordinate: u64,
    ) -> Result<ProductionFaultEvaluationSequence, SchedulerError> {
        if self.coordinate == Some(coordinate) {
            self.coordinate_sequence =
                self.coordinate_sequence.checked_add(1).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: String::from(
                            "signal fault evaluation sequence space is exhausted",
                        ),
                    }
                })?;
        } else {
            self.coordinate_sequence = 0;
        }
        self.coordinate = Some(coordinate);
        let journal = self.journal_sequence;
        self.journal_sequence = self.journal_sequence.checked_add(1).ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: String::from("fault observation journal sequence space is exhausted"),
            }
        })?;
        Ok(ProductionFaultEvaluationSequence {
            same_coordinate: self.coordinate_sequence,
            journal,
        })
    }
}

/// Thread-safe owner of the global production fault evaluation cursor.
pub(super) type SharedProductionFaultEvaluationCursor = Arc<Mutex<ProductionFaultEvaluationCursor>>;

/// Owns the production signal continuation at the pre-routing network seam.
pub(super) struct ProductionFaultNetworkInterceptor {
    runtime: Arc<Mutex<ProductionFaultRuntime>>,
    cursor: SharedProductionFaultEvaluationCursor,
    observations: super::storage_faults::ProductionStorageObservations,
    topology: crucible::model::WorldFaultTopology,
    links: Vec<crucible::LinkDef>,
    transition_ledger: BTreeMap<ContentHash, NetworkAvailabilityTransitionRecord>,
    effect_state: NetworkEffectRuntimeState,
}

impl ProductionFaultNetworkInterceptor {
    pub(super) fn active_outages(
        &self,
        now: u64,
    ) -> Vec<(crucible::model::ResolvedFaultTarget, u64)> {
        self.effect_state.boundary.active_outages(now)
    }

    pub(super) fn active_queue_evidence(
        &self,
    ) -> Result<Vec<super::ProductionNetworkQueueEvidence>, SchedulerError> {
        self.effect_state
            .queues
            .iter()
            .filter(|(_target, queue)| !queue.reservations.is_empty())
            .map(|(target, queue)| {
                let encoded = serde_json::to_vec(&(target, queue)).map_err(|error| {
                    SchedulerError::BoundaryViolation {
                        message: format!("encode production queue evidence: {error}"),
                    }
                })?;
                Ok(super::ProductionNetworkQueueEvidence {
                    target: target.clone(),
                    reservations: queue.reservations.len(),
                    continuation_digest: ContentHash::from_bytes(&encoded),
                    last_finish_nanos: queue
                        .reservations
                        .iter()
                        .map(|reservation| reservation.finish_nanos)
                        .max(),
                })
            })
            .collect()
    }

    /// Returns the restored runtime shared by non-network fault coordinators.
    pub(super) fn shared_runtime(&self) -> Arc<Mutex<ProductionFaultRuntime>> {
        Arc::clone(&self.runtime)
    }

    /// Returns the restored evaluation cursor shared by device coordinators.
    pub(super) fn shared_cursor(&self) -> SharedProductionFaultEvaluationCursor {
        Arc::clone(&self.cursor)
    }

    #[cfg(test)]
    fn new(
        runtime: ProductionFaultRuntime,
        topology: crucible::model::WorldFaultTopology,
        links: Vec<crucible::LinkDef>,
    ) -> Self {
        Self::with_shared_runtime(
            Arc::new(Mutex::new(runtime)),
            Arc::new(Mutex::new(ProductionFaultEvaluationCursor::default())),
            Arc::new(Mutex::new(
                super::storage_faults::ProductionFaultObservationJournal::default(),
            )),
            topology,
            links,
        )
    }

    /// Creates an interceptor sharing one continuation with device coordinators.
    pub(super) fn with_shared_runtime(
        runtime: Arc<Mutex<ProductionFaultRuntime>>,
        cursor: SharedProductionFaultEvaluationCursor,
        observations: super::storage_faults::ProductionStorageObservations,
        topology: crucible::model::WorldFaultTopology,
        links: Vec<crucible::LinkDef>,
    ) -> Self {
        Self {
            runtime,
            cursor,
            observations,
            topology,
            links,
            transition_ledger: BTreeMap::new(),
            effect_state: NetworkEffectRuntimeState::default(),
        }
    }

    /// Restores an authenticated adapter, scheduler, and pending-frame continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the runtime has no paired network state,
    /// its schema/bounds are invalid, scheduler restoration fails, or the
    /// independently recomputed continuation identity differs.
    #[allow(
        clippy::too_many_arguments,
        reason = "restore authenticates and atomically stages each independent runtime owner"
    )]
    pub(super) fn restore(
        plan: crucible::model::FaultSignalPlan,
        artifacts: Option<Arc<dyn SignalArtifactProvider>>,
        scenario_seed: ContentHash,
        checkpoint: ProductionFaultRuntimeCheckpoint,
        host_manifests: crucible::model::HostFaultAdapterManifests,
        nodes: &mut ProductionNodeSet,
        topology: crucible::model::WorldFaultTopology,
        links: Vec<crucible::LinkDef>,
        scheduler: &mut SingleScheduler,
        pending_outputs: &mut Vec<crucible::BackendNetworkOutput>,
        observations: super::storage_faults::ProductionStorageObservations,
    ) -> Result<Self, SchedulerError> {
        let staged = stage_network_restore(&checkpoint, scheduler)?;
        staged
            .adapter
            .effect_state
            .boundary
            .validate_topology(&topology)?;
        validate_custody_contact_topology(
            &staged.adapter.effect_state,
            &staged.pending_outputs,
            &topology,
        )?;
        let mut runtime = ProductionFaultRuntime::restore(
            plan,
            artifacts,
            scenario_seed,
            checkpoint,
            host_manifests,
            nodes,
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("restore production signal fault continuation: {error}"),
        })?;
        let authenticated = runtime.take_restored_network_state().ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: String::from(
                    "authenticated production fault runtime lost its network continuation",
                ),
            }
        })?;
        if authenticated.id() != staged.identity {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "production fault and staged network continuation identities differ",
                ),
            });
        }
        *observations
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault observation journal lock is poisoned"),
            })? = staged.adapter.observations.clone();
        let restored = Self {
            runtime: Arc::new(Mutex::new(runtime)),
            cursor: Arc::new(Mutex::new(ProductionFaultEvaluationCursor {
                coordinate: staged.adapter.coordinate,
                coordinate_sequence: staged.adapter.coordinate_sequence,
                journal_sequence: staged.adapter.journal_sequence,
            })),
            observations,
            topology,
            links,
            transition_ledger: BTreeMap::new(),
            effect_state: staged.adapter.effect_state,
        };
        *scheduler = staged.scheduler;
        *pending_outputs = staged.pending_outputs;
        Ok(restored)
    }

    /// Captures the fault runtime together with all network adapter state.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if the scheduler/pending state cannot be
    /// encoded or a live QEMU node cannot supply checkpoint evidence.
    pub(super) fn checkpoint(
        &self,
        scheduler: &SingleScheduler,
        pending_outputs: &[crucible::BackendNetworkOutput],
        backend: &mut ProductionNodeSet,
    ) -> Result<ProductionFaultRuntimeCheckpoint, SchedulerError> {
        let cursor_guard = self
            .cursor
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault evaluation cursor lock is poisoned"),
            })?;
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?;
        let observations =
            self.observations
                .lock()
                .map_err(|_| SchedulerError::BoundaryViolation {
                    message: String::from("production fault observation journal lock is poisoned"),
                })?;
        if !observations.validate(cursor_guard.journal_sequence) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("production fault observation journal is inconsistent"),
            });
        }
        let cursor = *cursor_guard;
        let effect_state = checkpoint_network_effect_state(
            &self.effect_state,
            pending_outputs,
            cursor.coordinate.unwrap_or(0),
        );
        let network_state = network_state_digest_from_parts(
            scheduler,
            pending_outputs,
            cursor.coordinate,
            cursor.coordinate_sequence,
            cursor.journal_sequence,
            &observations,
            &effect_state,
        )?;
        let adapter_state = serde_json::to_vec(&NetworkAdapterCheckpoint {
            semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
            coordinate: cursor.coordinate,
            coordinate_sequence: cursor.coordinate_sequence,
            journal_sequence: cursor.journal_sequence,
            observations: observations.clone(),
            effect_state,
        })
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("encode production network adapter checkpoint: {error}"),
        })?;
        let network_checkpoint = ProductionNetworkStateCheckpoint::new(
            network_state,
            scheduler.network_checkpoint(),
            pending_outputs.to_vec(),
            adapter_state,
        );
        runtime
            .checkpoint_with_network_state(backend, network_checkpoint)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("capture production fault continuation: {error}"),
            })
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
        pending_outputs: &mut Vec<crucible::BackendNetworkOutput>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let mut cursor = self
            .cursor
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault evaluation cursor lock is poisoned"),
            })?;
        let cursor_before = *cursor;
        let sequence = cursor.next_sequence(coordinate.virtual_nanos)?;
        let mut staged_scheduler = scheduler.clone();
        let mut staged_pending = pending_outputs.clone();
        let mut staged_effect_state = self.effect_state.clone();
        let shared_runtime = Arc::clone(&self.runtime);
        let mut runtime = shared_runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?;
        let host_before = runtime.host_state().clone();
        let mut evaluation =
            match runtime.evaluate_boundary(coordinate, sequence.same_coordinate, backend) {
                Ok(evaluation) => evaluation,
                Err(error) => {
                    *cursor = cursor_before;
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!("signal fault boundary failed closed: {error}"),
                    });
                }
            };
        let staged = (|| {
            let impulses = runtime.drain_host_impulses();
            staged_scheduler
                .record_pending_signal_fault_search_frontiers(runtime.drain_search_choices())?;
            if impulses
                .iter()
                .any(|action| action.phase != FaultPhase::Boundary)
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("network boundary produced a non-boundary impulse"),
                });
            }
            let network_actions = evaluation
                .actions
                .iter()
                .filter(|action| {
                    matches!(
                        action.effect.specification(),
                        EffectSpecification::Network(_)
                    )
                })
                .cloned()
                .collect::<Vec<_>>();
            super::fault_implementation::require_network_actions_implemented(
                network_actions.iter(),
            )
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "network action is absent from the production implementation registry: {error}"
                ),
            })?;
            let mut network_boundary_actions = network_actions
                .iter()
                .filter(|action| action.phase == FaultPhase::Boundary)
                .cloned()
                .collect::<Vec<_>>();
            let mut storage_boundary_actions = Vec::new();
            for action in impulses {
                match action.effect.specification() {
                    EffectSpecification::Network(_) => {
                        super::fault_implementation::require_network_actions_implemented([
                            &action,
                        ])
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!(
                                "network impulse is absent from the production implementation registry: {error}"
                            ),
                        })?;
                        network_boundary_actions.push(action);
                    }
                    EffectSpecification::Storage(_) => storage_boundary_actions.push(action),
                    EffectSpecification::Node(_) => {
                        return Err(SchedulerError::BoundaryViolation {
                            message: String::from(
                                "node action escaped the QEMU boundary adapter as a host impulse",
                            ),
                        });
                    }
                }
            }
            let _custody_release_due = route::apply_network_custody_removals(
                &mut staged_effect_state,
                &mut staged_pending,
                &network_actions,
                coordinate.virtual_nanos,
            )?;
            let mut boundary_application = staged_effect_state.boundary.apply_actions(
                coordinate,
                network_boundary_actions,
                &self.topology,
            )?;
            let mut ready_control_events =
                std::mem::take(&mut boundary_application.ready_control_events);
            let mut control_index = 0_usize;
            while control_index < ready_control_events.len() {
                if ready_control_events.len() > 262_144 {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "network control-event batch exceeds the hard action bound",
                        ),
                    });
                }
                let event = ready_control_events[control_index].clone();
                control_index += 1;
                let opportunity_sequence = cursor.next_sequence(coordinate.virtual_nanos)?;
                let opportunity = FaultOpportunity::new(
                    event.action.target.clone(),
                    event.operation,
                    FaultPhase::Resolve,
                    coordinate,
                    opportunity_sequence.same_coordinate,
                    None,
                    OpportunityPayload::NetworkControl {
                        technology: event.technology.clone(),
                        event_sequence: event.sequence,
                        request_digest: event.action.id(),
                        result_schema: event.result_schema.clone(),
                        result_digest: event.result_digest,
                    },
                )
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("construct network control opportunity: {error}"),
                })?;
                let control_evaluation = runtime
                    .evaluate_opportunity(
                        &opportunity,
                        opportunity_sequence.same_coordinate,
                        backend,
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("signal network control opportunity failed: {error}"),
                    })?;
                if !runtime.drain_host_impulses().is_empty() {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "network control opportunity produced a boundary impulse",
                        ),
                    });
                }
                evaluation
                    .observations
                    .extend(control_evaluation.observations);
                evaluation.next_wakeup_nanos = earliest_wakeup(
                    evaluation.next_wakeup_nanos,
                    control_evaluation.next_wakeup_nanos,
                );
                super::fault_implementation::require_network_actions_implemented(
                    control_evaluation.actions.iter(),
                )
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "network control action is absent from the production implementation registry: {error}"
                    ),
                })?;
                let transformed = apply_network_control_transforms(
                    event,
                    &control_evaluation.actions,
                    &self.topology,
                )?;
                let Some(transformed) = transformed else {
                    continue;
                };
                let mut applied = staged_effect_state.boundary.apply_ready_control_event(
                    coordinate,
                    transformed,
                    &self.topology,
                )?;
                boundary_application.next_wakeup_nanos = earliest_wakeup(
                    boundary_application.next_wakeup_nanos,
                    applied.next_wakeup_nanos,
                );
                boundary_application
                    .clear_queued_targets
                    .append(&mut applied.clear_queued_targets);
                boundary_application
                    .clear_table_targets
                    .append(&mut applied.clear_table_targets);
                boundary_application
                    .address_discontinuities
                    .append(&mut applied.address_discontinuities);
                boundary_application
                    .route_transitions
                    .append(&mut applied.route_transitions);
                boundary_application
                    .control_outcomes
                    .append(&mut applied.control_outcomes);
                ready_control_events.append(&mut applied.ready_control_events);
            }
            for outcome in &boundary_application.control_outcomes {
                evaluation.observations.push(FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::EffectRejected,
                    coordinate,
                    binding: Some(outcome.action.binding.clone()),
                    target: Some(outcome.action.target.clone()),
                    opportunity: outcome.action.opportunity,
                    evidence: control_plane_outcome_evidence(outcome)?,
                });
            }
            for (target, queue_targets, downtime_nanos) in
                &boundary_application.drain_queued_targets
            {
                let unavailable_from = queue_targets
                    .iter()
                    .filter_map(|queue_target| staged_effect_state.queues.get(queue_target))
                    .flat_map(|queue| queue.reservations.iter())
                    .map(|reservation| reservation.finish_nanos)
                    .max()
                    .unwrap_or(coordinate.virtual_nanos)
                    .max(coordinate.virtual_nanos);
                staged_effect_state
                    .boundary
                    .defer_outage_until_queues_drain(target, unavailable_from, *downtime_nanos)?;
            }
            boundary_application.next_wakeup_nanos = staged_effect_state
                .boundary
                .next_wakeup_nanos(coordinate.virtual_nanos);
            for target in boundary_application.clear_queued_targets {
                if let Some(queue) = staged_effect_state.queues.remove(&target) {
                    let removed = queue
                        .reservations
                        .into_iter()
                        .map(|reservation| reservation.opportunity)
                        .collect::<BTreeSet<_>>();
                    staged_pending.retain(|output| {
                        output
                            .fault_continuation
                            .cursor()
                            .queue_opportunity()
                            .is_none_or(|opportunity| !removed.contains(&opportunity))
                    });
                }
            }
            for target in boundary_application.clear_table_targets {
                staged_effect_state
                    .state_machines
                    .retain(|key, _machine| key.target != target);
                staged_effect_state
                    .connection_tables
                    .retain(|key, _table| key.target != target);
            }
            let mut removed_attachment_opportunities = BTreeSet::new();
            for target in &boundary_application.address_discontinuities {
                let crucible::model::ResolvedFaultTarget::NetworkAttachment { endpoint, .. } =
                    target
                else {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "association address discontinuity did not target an attachment",
                        ),
                    });
                };
                staged_pending.retain(|output| {
                    let affected = output.source.name == endpoint.as_str()
                        || output.destination.name == endpoint.as_str()
                        || output
                            .fault_continuation
                            .cursor()
                            .completed_phases()
                            .iter()
                            .any(|completed| &completed.target == target);
                    if affected
                        && let Some(opportunity) =
                            output.fault_continuation.cursor().queue_opportunity()
                    {
                        removed_attachment_opportunities.insert(opportunity);
                    }
                    !affected
                });
                for link in &self.links {
                    let (endpoint_a, endpoint_b) = link.endpoints();
                    if endpoint_a.name == endpoint.as_str() || endpoint_b.name == endpoint.as_str()
                    {
                        let _a_to_b = staged_scheduler
                            .drop_network_inflight_for_route(endpoint_a, endpoint_b)?;
                        let _b_to_a = staged_scheduler
                            .drop_network_inflight_for_route(endpoint_b, endpoint_a)?;
                    }
                }
            }
            if !removed_attachment_opportunities.is_empty() {
                for queue in staged_effect_state.queues.values_mut() {
                    queue.reservations.retain(|reservation| {
                        !removed_attachment_opportunities.contains(&reservation.opportunity)
                    });
                }
            }
            let mut removed_route_opportunities = BTreeSet::new();
            for transition in &boundary_application.route_transitions {
                staged_pending.retain_mut(|output| {
                    if output.fault_continuation.cursor().route_path_version()
                        != Some(&transition.old_route)
                    {
                        return true;
                    }
                    match transition.policy {
                        NetworkInFlightPolicy::Preserve => true,
                        NetworkInFlightPolicy::Reevaluate => {
                            output
                                .fault_continuation
                                .cursor_mut()
                                .reevaluate_route_path();
                            true
                        }
                        NetworkInFlightPolicy::Drop | NetworkInFlightPolicy::TypedError => {
                            if let Some(opportunity) =
                                output.fault_continuation.cursor().queue_opportunity()
                            {
                                removed_route_opportunities.insert(opportunity);
                            }
                            false
                        }
                    }
                });
                if matches!(
                    transition.policy,
                    NetworkInFlightPolicy::Drop | NetworkInFlightPolicy::TypedError
                ) {
                    let crucible::model::ResolvedFaultTarget::NetworkPath { direction, .. } =
                        &transition.target
                    else {
                        return Err(SchedulerError::BoundaryViolation {
                            message: String::from(
                                "route transition action did not target a network path",
                            ),
                        });
                    };
                    let (source, destination) = self
                        .topology
                        .network_path_endpoints(&transition.old_route, *direction)
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!("resolve route-transition path endpoints: {error}"),
                        })?;
                    let _dropped = staged_scheduler.drop_network_inflight_for_route(
                        &crucible::NodeId {
                            name: source.as_str().to_owned(),
                        },
                        &crucible::NodeId {
                            name: destination.as_str().to_owned(),
                        },
                    )?;
                }
            }
            if !removed_route_opportunities.is_empty() {
                for queue in staged_effect_state.queues.values_mut() {
                    queue.reservations.retain(|reservation| {
                        !removed_route_opportunities.contains(&reservation.opportunity)
                    });
                }
            }
            let (observations, records) = self.stage_availability_transition_drops(
                coordinate,
                &network_actions,
                &host_before,
                &mut staged_scheduler,
                &mut staged_pending,
                None,
            )?;
            evaluation.observations.extend(observations);
            let backpressure_wakeup = route::apply_network_backpressure_transitions(
                &mut staged_effect_state,
                &mut staged_pending,
                &network_actions,
                &self.topology,
                coordinate.virtual_nanos,
            )?;
            staged_scheduler.set_signal_fault_wakeup(earliest_wakeup(
                evaluation.next_wakeup_nanos,
                earliest_wakeup(boundary_application.next_wakeup_nanos, backpressure_wakeup),
            ))?;
            {
                let mut journal =
                    self.observations
                        .lock()
                        .map_err(|_| SchedulerError::BoundaryViolation {
                            message: String::from(
                                "production fault observation journal lock is poisoned",
                            ),
                        })?;
                if journal.contains_sequence(sequence.journal) {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "fault observation sequence {} was reused at a scheduler boundary",
                            sequence.journal,
                        ),
                    });
                }
                journal
                    .append(sequence.journal, evaluation.observations)
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: error.to_string(),
                    })?;
            }
            let block_rollback = backend.checkpoint_block_boundary_state().map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!("capture storage boundary rollback state: {error}"),
                }
            })?;
            if let Err(error) = backend.apply_block_boundary_actions(
                coordinate,
                sequence.journal,
                &storage_boundary_actions,
            ) {
                self.observations
                    .lock()
                    .map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from(
                            "production fault observation journal lock is poisoned",
                        ),
                    })?
                    .rollback_sequence(sequence.journal)
                    .map_err(|rollback_error| SchedulerError::BoundaryViolation {
                        message: rollback_error.to_string(),
                    })?;
                return Err(SchedulerError::BoundaryViolation {
                    message: format!("apply storage fault boundary: {error}"),
                });
            }
            let journal_commit = (|| {
                let mut journal =
                    self.observations
                        .lock()
                        .map_err(|_| SchedulerError::BoundaryViolation {
                            message: String::from(
                                "production fault observation journal lock is poisoned",
                            ),
                        })?;
                let committed = staged_scheduler
                    .condition_event_log_prefix()
                    .point()
                    .at()
                    .ticks;
                let append =
                    staged_scheduler.append_fault_observations(journal.drain_ready(committed))?;
                Ok(append)
            })();
            let append = match journal_commit {
                Ok(append) => append,
                Err(error) => {
                    let block_rollback_error =
                        backend.restore_block_boundary_state(block_rollback).err();
                    self.observations
                        .lock()
                        .map_err(|_| SchedulerError::BoundaryViolation {
                            message: String::from(
                                "production fault observation journal lock is poisoned",
                            ),
                        })?
                        .rollback_sequence(sequence.journal)
                        .map_err(|rollback_error| SchedulerError::BoundaryViolation {
                            message: rollback_error.to_string(),
                        })?;
                    if let Some(rollback_error) = block_rollback_error {
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "storage boundary failed and its exact rollback failed: {error}; {rollback_error}"
                            ),
                        });
                    }
                    return Err(error);
                }
            };
            Ok((append, records))
        })();
        let (append, records) = match staged {
            Ok(staged) => staged,
            Err(error) => {
                runtime.poison();
                return Err(error);
            }
        };
        *scheduler = staged_scheduler;
        *pending_outputs = staged_pending;
        self.effect_state = staged_effect_state;
        for record in records {
            self.transition_ledger.insert(record.action, record);
        }
        Ok(append)
    }

    fn stage_availability_transition_drops(
        &self,
        coordinate: FaultCoordinate,
        actions: &[ResolvedBindingAction],
        host_before: &crucible::model::HostFaultActionState,
        scheduler: &mut SingleScheduler,
        queued_outputs: &mut Vec<crucible::BackendNetworkOutput>,
        ready_outputs: Option<&mut Vec<crucible::BackendNetworkOutput>>,
    ) -> Result<
        (
            Vec<FaultObservation>,
            Vec<NetworkAvailabilityTransitionRecord>,
        ),
        SchedulerError,
    > {
        let transitions = actions
            .iter()
            .filter(|action| action.kind == BindingActionKind::UpsertPersistent)
            .filter(|action| {
                matches!(
                    action.effect.specification(),
                    EffectSpecification::Network(NetworkEffectSpecification::Availability {
                        state,
                        ..
                    }) if *state != NetworkAvailabilityState::Up
                )
            })
            .collect::<Vec<_>>();
        if transitions.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let mut blockers =
            BTreeMap::<(crucible::NodeId, crucible::NodeId), Vec<&ResolvedBindingAction>>::new();
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
                            "cannot resolve availability transition route `{}` to `{}`: {error}",
                            source.name, destination.name
                        ),
                    })?;
                let matching = transitions
                    .iter()
                    .copied()
                    .filter(|action| transition_blocks_route(action, &stages))
                    .collect::<Vec<_>>();
                if !matching.is_empty() {
                    blockers.insert((source.clone(), destination.clone()), matching);
                }
            }
        }

        let mut queued_by_route = BTreeMap::<
            (crucible::NodeId, crucible::NodeId),
            Vec<crucible::BackendNetworkOutput>,
        >::new();
        partition_transition_queued_outputs(
            scheduler,
            &blockers,
            queued_outputs,
            &mut queued_by_route,
        )?;
        if let Some(ready_outputs) = ready_outputs {
            partition_transition_queued_outputs(
                scheduler,
                &blockers,
                ready_outputs,
                &mut queued_by_route,
            )?;
        }

        let mut observations = Vec::new();
        let mut records = Vec::new();
        for ((source, destination), route_blockers) in blockers {
            let destructive_in_flight = route_blockers.iter().any(|action| {
                let EffectSpecification::Network(NetworkEffectSpecification::Availability {
                    in_flight_policy,
                    ..
                }) = action.effect.specification()
                else {
                    return false;
                };
                matches!(
                    in_flight_policy,
                    NetworkInFlightPolicy::Drop | NetworkInFlightPolicy::TypedError
                )
            });
            let in_flight = if destructive_in_flight {
                scheduler.drop_network_inflight_for_route(&source, &destination)?
            } else {
                let mut preview = scheduler.clone();
                preview.drop_network_inflight_for_route(&source, &destination)?
            };
            let queued = queued_by_route
                .remove(&(source.clone(), destination.clone()))
                .unwrap_or_default();
            if in_flight.frame_count == 0 && queued.is_empty() {
                continue;
            }
            for action in route_blockers {
                let EffectSpecification::Network(NetworkEffectSpecification::Availability {
                    state,
                    queued_policy,
                    in_flight_policy,
                }) = action.effect.specification()
                else {
                    continue;
                };
                let old_state = host_before
                    .matching(&action.target, action.phase)
                    .find(|prior| prior.binding == action.binding)
                    .and_then(|prior| {
                        let EffectSpecification::Network(
                            NetworkEffectSpecification::Availability { state, .. },
                        ) = prior.effect.specification()
                        else {
                            return None;
                        };
                        Some(*state)
                    })
                    .unwrap_or(NetworkAvailabilityState::Up);
                let evidence = availability_transition_evidence(
                    action,
                    old_state,
                    *state,
                    *queued_policy,
                    *in_flight_policy,
                    &source,
                    &destination,
                    &in_flight,
                    &queued,
                )?;
                observations.push(FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::NetworkProfile,
                    coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence,
                });
                if *queued_policy == NetworkInFlightPolicy::TypedError
                    || *in_flight_policy == NetworkInFlightPolicy::TypedError
                {
                    observations.push(FaultObservation {
                        semantic_version: FAULT_RUNTIME_STATE_VERSION,
                        kind: FaultObservationKind::EffectRejected,
                        coordinate,
                        binding: Some(action.binding.clone()),
                        target: Some(action.target.clone()),
                        opportunity: action.opportunity,
                        evidence,
                    });
                }
                records.push(NetworkAvailabilityTransitionRecord {
                    action: action.id(),
                    binding: action.binding.clone(),
                    target: action.target.clone(),
                    phase: action.phase,
                    transition_sequence: action.transition_sequence,
                    old_state,
                    state: *state,
                    queued_policy: *queued_policy,
                    in_flight_policy: *in_flight_policy,
                    source: source.clone(),
                    destination: destination.clone(),
                    in_flight: in_flight.clone(),
                    queued: queued.clone(),
                    evidence,
                });
            }
        }
        Ok((observations, records))
    }
}

fn transition_blocks_route(
    action: &ResolvedBindingAction,
    stages: &[crucible::model::WorldNetworkRouteFaultTarget],
) -> bool {
    let EffectSpecification::Network(NetworkEffectSpecification::Availability { state, .. }) =
        action.effect.specification()
    else {
        return false;
    };
    stages.iter().any(|stage| {
        stage.target == action.target
            && stage.phases().contains(&action.phase)
            && !availability_allows(*state, stage.direction)
    })
}

fn partition_transition_queued_outputs(
    scheduler: &SingleScheduler,
    blockers: &BTreeMap<(crucible::NodeId, crucible::NodeId), Vec<&ResolvedBindingAction>>,
    outputs: &mut Vec<crucible::BackendNetworkOutput>,
    dropped: &mut BTreeMap<
        (crucible::NodeId, crucible::NodeId),
        Vec<crucible::BackendNetworkOutput>,
    >,
) -> Result<(), SchedulerError> {
    let mut retained = Vec::new();
    for output in std::mem::take(outputs) {
        for route in scheduler.resolve_backend_network_routes(&output)? {
            let key = (output.source.clone(), route.destination.clone());
            let mut routed = output.clone();
            routed.destination = route.destination.clone();
            routed.route = Some(route);
            let Some(route_blockers) = blockers.get(&key) else {
                retained.push(routed);
                continue;
            };
            let mut destructive = false;
            for action in route_blockers {
                let EffectSpecification::Network(NetworkEffectSpecification::Availability {
                    queued_policy,
                    ..
                }) = action.effect.specification()
                else {
                    continue;
                };
                match queued_policy {
                    NetworkInFlightPolicy::Preserve => {
                        routed.fault_continuation.preserve_availability(
                            action.binding.clone(),
                            action.target.clone(),
                            action.phase,
                            action.transition_sequence,
                        )
                    }
                    NetworkInFlightPolicy::Reevaluate => {}
                    NetworkInFlightPolicy::Drop | NetworkInFlightPolicy::TypedError => {
                        destructive = true;
                    }
                }
            }
            dropped.entry(key).or_default().push(routed.clone());
            if !destructive {
                retained.push(routed);
            }
        }
    }
    *outputs = retained;
    Ok(())
}

fn apply_network_control_transforms(
    mut event: boundary::QueuedNetworkControlEvent,
    actions: &[ResolvedBindingAction],
    topology: &crucible::model::WorldFaultTopology,
) -> Result<Option<boundary::QueuedNetworkControlEvent>, SchedulerError> {
    for action in actions {
        let EffectSpecification::Network(NetworkEffectSpecification::ControlResultTransform {
            technology,
            operations,
            kind,
            result,
        }) = action.effect.specification()
        else {
            return Err(network_effect_application_error(
                action,
                "non-transform effect matched a network control opportunity",
            ));
        };
        if technology != &event.technology || !operations.contains(event.operation) {
            return Err(network_effect_application_error(
                action,
                "network control transform violated its admitted technology or operation filter",
            ));
        }
        match kind {
            crucible::model::NetworkControlResultKind::Drop
            | crucible::model::NetworkControlResultKind::Stale
            | crucible::model::NetworkControlResultKind::Error => return Ok(None),
            crucible::model::NetworkControlResultKind::Bias => {
                let (schema, bytes) = network_control_result(topology, result.as_ref(), action)?;
                if schema.as_str() != "network-score-bias-i64-v1" || bytes.len() != 8 {
                    return Err(network_effect_application_error(
                        action,
                        "association bias requires network-score-bias-i64-v1 and eight bytes",
                    ));
                }
                let bias = i64::from_be_bytes(bytes.as_slice().try_into().map_err(|_error| {
                    network_effect_application_error(action, "control bias has the wrong width")
                })?);
                bias_control_mapping(&mut event.action, bias, action)?;
                event.result_digest = ContentHash::from_bytes(
                    &route::mapped_network_integers(&event.action)?
                        .into_iter()
                        .flat_map(i64::to_be_bytes)
                        .collect::<Vec<_>>(),
                );
            }
            crucible::model::NetworkControlResultKind::Replace => {
                let (schema, bytes) = network_control_result(topology, result.as_ref(), action)?;
                replace_control_result(&mut event, schema, bytes, topology, action)?;
            }
        }
    }
    Ok(Some(event))
}

fn network_control_result<'a>(
    topology: &'a crucible::model::WorldFaultTopology,
    result: Option<&FaultObjectId>,
    action: &ResolvedBindingAction,
) -> Result<(&'a FaultObjectId, &'a Vec<u8>), SchedulerError> {
    let result = result.ok_or_else(|| {
        network_effect_application_error(action, "control transform omitted its result artifact")
    })?;
    let declaration = topology.network_policy_artifact(result).ok_or_else(|| {
        network_effect_application_error(action, "control result disappeared after admission")
    })?;
    let crucible::model::NetworkPolicyArtifactKind::ControlResult { schema, bytes } =
        &declaration.artifact
    else {
        return Err(network_effect_application_error(
            action,
            "control result changed type after admission",
        ));
    };
    Ok((schema, bytes))
}

fn bias_control_mapping(
    action: &mut ResolvedBindingAction,
    bias: i64,
    transform: &ResolvedBindingAction,
) -> Result<(), SchedulerError> {
    let mut mapping = action.mapping_output.as_ref().clone();
    let values = match &mut mapping {
        crucible::model::ResolvedMappingOutput::Parameter { value, .. } => {
            std::slice::from_mut(value)
        }
        crucible::model::ResolvedMappingOutput::ServiceProfile { inputs, .. } => {
            inputs.as_mut_slice()
        }
        _ => {
            return Err(network_effect_application_error(
                transform,
                "control bias requires a numeric association mapping",
            ));
        }
    };
    for value in values {
        *value = match value {
            crucible::model::SignalValue::I64(value) => {
                crucible::model::SignalValue::I64(value.checked_add(bias).ok_or_else(|| {
                    network_effect_application_error(transform, "control bias overflowed i64")
                })?)
            }
            crucible::model::SignalValue::U64(value) => {
                let biased = i128::from(*value) + i128::from(bias);
                crucible::model::SignalValue::U64(u64::try_from(biased).map_err(|_error| {
                    network_effect_application_error(transform, "control bias overflowed u64")
                })?)
            }
            crucible::model::SignalValue::DurationNanos(value) => {
                let biased = i128::from(*value) + i128::from(bias);
                crucible::model::SignalValue::DurationNanos(u64::try_from(biased).map_err(
                    |_error| {
                        network_effect_application_error(
                            transform,
                            "control bias overflowed duration",
                        )
                    },
                )?)
            }
            crucible::model::SignalValue::RatePerSecond(value) => {
                let biased = i128::from(*value) + i128::from(bias);
                crucible::model::SignalValue::RatePerSecond(u64::try_from(biased).map_err(
                    |_error| {
                        network_effect_application_error(transform, "control bias overflowed rate")
                    },
                )?)
            }
            crucible::model::SignalValue::ProbabilityMillionths(value) => {
                let biased = i64::from(*value).checked_add(bias).ok_or_else(|| {
                    network_effect_application_error(
                        transform,
                        "control bias overflowed probability",
                    )
                })?;
                crucible::model::SignalValue::ProbabilityMillionths(u32::try_from(biased).map_err(
                    |_error| {
                        network_effect_application_error(
                            transform,
                            "control bias left the probability domain",
                        )
                    },
                )?)
            }
            _ => {
                return Err(network_effect_application_error(
                    transform,
                    "control bias encountered a non-integer mapping",
                ));
            }
        };
    }
    action.mapping_output = Arc::new(mapping);
    action.mapped_digest = ContentHash::from_bytes(
        &serde_json::to_vec(action.mapping_output.as_ref()).map_err(|error| {
            network_effect_application_error(
                transform,
                &format!("encode biased control mapping: {error}"),
            )
        })?,
    );
    Ok(())
}

fn replace_control_result(
    event: &mut boundary::QueuedNetworkControlEvent,
    schema: &FaultObjectId,
    bytes: &[u8],
    topology: &crucible::model::WorldFaultTopology,
    transform: &ResolvedBindingAction,
) -> Result<(), SchedulerError> {
    let EffectSpecification::Network(specification) = event.action.effect.specification() else {
        return Err(network_effect_application_error(
            transform,
            "control event lost its network effect",
        ));
    };
    let replacement = match specification {
        NetworkEffectSpecification::RouteTransition {
            old_route,
            convergence_events,
            in_flight_policy,
            ..
        } if schema.as_str() == "network-route-id-v1" => {
            let route = parse_control_object_id(bytes, transform)?;
            if !topology
                .network_paths
                .iter()
                .any(|candidate| candidate.id.as_str() == route.as_str())
            {
                return Err(network_effect_application_error(
                    transform,
                    "replacement route is absent from World",
                ));
            }
            NetworkEffectSpecification::RouteTransition {
                old_route: old_route.clone(),
                new_route: route,
                convergence_events: convergence_events.clone(),
                in_flight_policy: *in_flight_policy,
            }
        }
        NetworkEffectSpecification::Association { policy }
            if schema.as_str() == "network-association-inputs-i64-v1" =>
        {
            if bytes.is_empty() || !bytes.len().is_multiple_of(8) {
                return Err(network_effect_application_error(
                    transform,
                    "replacement association inputs require nonempty packed i64 values",
                ));
            }
            let inputs = bytes
                .chunks_exact(8)
                .map(|chunk| {
                    let encoded: [u8; 8] = chunk.try_into().map_err(|_error| {
                        network_effect_application_error(
                            transform,
                            "replacement association input width is invalid",
                        )
                    })?;
                    Ok(crucible::model::SignalValue::I64(i64::from_be_bytes(
                        encoded,
                    )))
                })
                .collect::<Result<Vec<_>, SchedulerError>>()?;
            let mut mapping = event.action.mapping_output.as_ref().clone();
            match &mut mapping {
                crucible::model::ResolvedMappingOutput::Parameter { value, .. }
                    if inputs.len() == 1 =>
                {
                    *value = inputs[0].clone();
                }
                crucible::model::ResolvedMappingOutput::ServiceProfile {
                    inputs: current, ..
                } if inputs.len() == 1 || inputs.len() == current.len() => {
                    *current = inputs;
                }
                _ => {
                    return Err(network_effect_application_error(
                        transform,
                        "replacement association input arity is invalid",
                    ));
                }
            }
            event.action.mapping_output = Arc::new(mapping);
            event.action.mapped_digest = ContentHash::from_bytes(
                &serde_json::to_vec(event.action.mapping_output.as_ref()).map_err(|error| {
                    network_effect_application_error(
                        transform,
                        &format!("encode replaced control mapping: {error}"),
                    )
                })?,
            );
            NetworkEffectSpecification::Association {
                policy: policy.clone(),
            }
        }
        NetworkEffectSpecification::Contact {
            range_delay_lookup,
            beams,
            gateways,
            ..
        } if schema.as_str() == "network-contact-plan-v1" => {
            let intervals = parse_control_object_id(bytes, transform)?;
            let Some(declaration) = topology.network_policy_artifact(&intervals) else {
                return Err(network_effect_application_error(
                    transform,
                    "replacement contact plan is absent",
                ));
            };
            let crucible::model::NetworkPolicyArtifactKind::ContactPlan {
                intervals: replacement_intervals,
            } = &declaration.artifact
            else {
                return Err(network_effect_application_error(
                    transform,
                    "replacement contact plan has the wrong class",
                ));
            };
            if replacement_intervals.iter().any(|interval| {
                beams.as_slice().binary_search(&interval.beam).is_err()
                    || gateways
                        .as_slice()
                        .binary_search(&interval.gateway)
                        .is_err()
            }) {
                return Err(network_effect_application_error(
                    transform,
                    "replacement contact plan uses an undeclared beam or gateway",
                ));
            }
            NetworkEffectSpecification::Contact {
                intervals,
                range_delay_lookup: range_delay_lookup.clone(),
                beams: beams.clone(),
                gateways: gateways.clone(),
            }
        }
        NetworkEffectSpecification::ForwarderLifecycle {
            downtime_nanos,
            queue_policy,
            table_policy,
            ..
        } if schema.as_str() == "network-forwarder-state-v1" && bytes.len() == 1 => {
            let transition = match bytes[0] {
                1 => crucible::model::NetworkForwarderTransition::Restart,
                2 => crucible::model::NetworkForwarderTransition::Reset,
                3 => crucible::model::NetworkForwarderTransition::PowerLoss,
                _ => {
                    return Err(network_effect_application_error(
                        transform,
                        "replacement forwarder transition tag is invalid",
                    ));
                }
            };
            NetworkEffectSpecification::ForwarderLifecycle {
                transition,
                downtime_nanos: *downtime_nanos,
                queue_policy: *queue_policy,
                table_policy: *table_policy,
            }
        }
        _ => {
            return Err(network_effect_application_error(
                transform,
                "replacement control-result schema does not match the operation",
            ));
        }
    };
    event.action.effect = Arc::new(
        crucible::model::EffectRequest::new(
            crucible::model::EFFECT_SEMANTIC_VERSION,
            event.action.effect.lifetime(),
            EffectSpecification::Network(replacement),
        )
        .map_err(|error| {
            network_effect_application_error(
                transform,
                &format!("validate replacement control result: {error}"),
            )
        })?,
    );
    event.result_schema = schema.clone();
    event.result_digest = ContentHash::from_bytes(bytes);
    Ok(())
}

#[cfg(test)]
#[path = "network_faults/tests.rs"]
mod tests;
