//! Aggregate production event-record accounting and validation.
//!
//! Referenced events enter as cumulative counters charged once when each
//! batch is staged, so accounting never rescans the emitted history. Pending
//! observations and raw QEMU events drain every boundary and are measured
//! directly.

use super::*;

pub(in crate::production_fault_runtime) fn validate_production_event_state(
    referenced: ReferencedEventUsage,
    pending_observations: &[FaultObservation],
    additional_observations: &[FaultObservation],
    pending_qemu_events: &PendingQemuEventMap,
    resource_limits: FaultResourceLimits,
) -> Result<(), ProductionFaultRuntimeError> {
    let _ = production_event_state_usage(
        referenced,
        pending_observations,
        additional_observations,
        pending_qemu_events,
        resource_limits,
    )?;
    Ok(())
}

pub(in crate::production_fault_runtime) fn production_event_state_usage(
    referenced: ReferencedEventUsage,
    pending_observations: &[FaultObservation],
    additional_observations: &[FaultObservation],
    pending_qemu_events: &PendingQemuEventMap,
    resource_limits: FaultResourceLimits,
) -> Result<(u64, u64), ProductionFaultRuntimeError> {
    resource_limits.reserve("event_records", 0, referenced.records)?;
    resource_limits.reserve("event_log_bytes", 0, referenced.log_bytes)?;
    let (records, bytes) = extend_observation_usage(
        pending_observations,
        resource_limits,
        referenced.records,
        referenced.log_bytes,
    )?;
    let (records, bytes) =
        extend_observation_usage(additional_observations, resource_limits, records, bytes)?;
    extend_pending_qemu_event_usage(pending_qemu_events, resource_limits, records, bytes)
}

pub(in crate::production_fault_runtime) fn validate_production_record_state(
    referenced: ReferencedEventUsage,
    pending_observations: &[FaultObservation],
    pending_qemu_events: &PendingQemuEventMap,
    qemu_issued_actions: &QemuActionMap<ResolvedBindingAction>,
    qemu_action_commits: &QemuActionMap<CommittedQemuActionEvidence>,
    qemu_active_rule_ids: &QemuActionSet,
    resource_limits: FaultResourceLimits,
) -> Result<(), ProductionFaultRuntimeError> {
    let _current = production_record_state_usage(
        referenced,
        pending_observations,
        pending_qemu_events,
        qemu_issued_actions,
        qemu_action_commits,
        qemu_active_rule_ids,
        resource_limits,
    )?;
    Ok(())
}

pub(in crate::production_fault_runtime) fn production_record_state_usage(
    referenced: ReferencedEventUsage,
    pending_observations: &[FaultObservation],
    pending_qemu_events: &PendingQemuEventMap,
    qemu_issued_actions: &QemuActionMap<ResolvedBindingAction>,
    qemu_action_commits: &QemuActionMap<CommittedQemuActionEvidence>,
    qemu_active_rule_ids: &QemuActionSet,
    resource_limits: FaultResourceLimits,
) -> Result<u64, ProductionFaultRuntimeError> {
    let (event_state_records, _bytes) = production_event_state_usage(
        referenced,
        pending_observations,
        &[],
        pending_qemu_events,
        resource_limits,
    )?;
    let ledger_records = qemu_issued_actions
        .len()
        .checked_add(qemu_action_commits.len())
        .and_then(|records| records.checked_add(qemu_active_rule_ids.len()))
        .and_then(|records| u64::try_from(records).ok())
        .ok_or(FaultResourceLimitError::Representation {
            field: "event_records",
            value: u64::MAX,
        })?;
    resource_limits.reserve("event_records", event_state_records, ledger_records)?;
    event_state_records
        .checked_add(ledger_records)
        .ok_or_else(|| {
            FaultResourceLimitError::Representation {
                field: "event_records",
                value: u64::MAX,
            }
            .into()
        })
}
