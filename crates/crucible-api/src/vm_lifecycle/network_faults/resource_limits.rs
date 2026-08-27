//! Aggregate resource admission for the production network fault runtime.
//!
//! Queue ownership spans ordinary interface queues, shared media, and custody
//! storage. These helpers measure that single aggregate before mutation and
//! preserve authored LIMIT-2 coordinates through the scheduler boundary.

use super::*;

pub(super) fn reserve_network_resource(
    field: &'static str,
    current: usize,
    requested: usize,
    limits: FaultResourceLimits,
) -> Result<(), SchedulerError> {
    let current = u64::try_from(current).map_err(|_| {
        map_network_resource_limit(
            FaultResourceLimitError::Representation {
                field,
                value: u64::MAX,
            },
            limits,
        )
    })?;
    let requested = u64::try_from(requested).map_err(|_| {
        map_network_resource_limit(
            FaultResourceLimitError::Representation {
                field,
                value: u64::MAX,
            },
            limits,
        )
    })?;
    limits
        .reserve(field, current, requested)
        .map_err(|error| map_network_resource_limit(error, limits))
}

pub(super) fn reserve_network_resource_u64(
    field: &'static str,
    current: u64,
    requested: u64,
    limits: FaultResourceLimits,
) -> Result<(), SchedulerError> {
    limits
        .reserve(field, current, requested)
        .map_err(|error| map_network_resource_limit(error, limits))
}

pub(super) fn map_network_resource_limit(
    error: FaultResourceLimitError,
    limits: FaultResourceLimits,
) -> SchedulerError {
    super::super::quantum_loop::map_journal_limit(error, limits)
}

pub(super) fn network_queue_resource_usage(
    state: &NetworkEffectRuntimeState,
    limits: FaultResourceLimits,
) -> Result<(u64, u64), SchedulerError> {
    let mut frames = 0_u64;
    let mut bytes = 0_u64;
    let mut add = |count: usize, payload_bytes: u64| -> Result<(), SchedulerError> {
        frames = frames
            .checked_add(u64::try_from(count).map_err(|_| {
                map_network_resource_limit(
                    FaultResourceLimitError::Representation {
                        field: "network_queue_frames",
                        value: u64::MAX,
                    },
                    limits,
                )
            })?)
            .ok_or_else(|| {
                map_network_resource_limit(
                    FaultResourceLimitError::Representation {
                        field: "network_queue_frames",
                        value: u64::MAX,
                    },
                    limits,
                )
            })?;
        bytes = bytes.checked_add(payload_bytes).ok_or_else(|| {
            map_network_resource_limit(
                FaultResourceLimitError::Representation {
                    field: "network_queue_bytes",
                    value: u64::MAX,
                },
                limits,
            )
        })?;
        Ok(())
    };

    for queue in state.queues.values() {
        let queue_bytes = queue
            .reservations
            .iter()
            .try_fold(0_u64, |total, reservation| {
                total.checked_add(reservation.bytes)
            })
            .ok_or_else(|| queue_byte_representation_error(limits))?;
        add(queue.reservations.len(), queue_bytes)?;
    }
    for medium in state.shared_media.values() {
        let medium_bytes = medium
            .reservations
            .iter()
            .try_fold(0_u64, |total, reservation| {
                total.checked_add(reservation.bytes)
            })
            .ok_or_else(|| queue_byte_representation_error(limits))?;
        add(medium.reservations.len(), medium_bytes)?;
    }
    for queue in state.custody_queues.values() {
        let custody_bytes = queue
            .reservations
            .iter()
            .map(|reservation| reservation.bytes)
            .chain(
                queue
                    .overflow_timeouts
                    .iter()
                    .map(|timeout| timeout.bundle.length_bytes),
            )
            .try_fold(0_u64, |total, payload| total.checked_add(payload))
            .ok_or_else(|| queue_byte_representation_error(limits))?;
        add(
            queue
                .reservations
                .len()
                .checked_add(queue.overflow_timeouts.len())
                .ok_or_else(|| {
                    map_network_resource_limit(
                        FaultResourceLimitError::Representation {
                            field: "network_queue_frames",
                            value: u64::MAX,
                        },
                        limits,
                    )
                })?,
            custody_bytes,
        )?;
    }
    Ok((frames, bytes))
}

fn queue_byte_representation_error(limits: FaultResourceLimits) -> SchedulerError {
    map_network_resource_limit(
        FaultResourceLimitError::Representation {
            field: "network_queue_bytes",
            value: u64::MAX,
        },
        limits,
    )
}
