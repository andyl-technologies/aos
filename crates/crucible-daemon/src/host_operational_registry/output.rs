//! Concrete owning operational responses under the registry's original child account.

use super::*;

pub(super) struct PolicySnapshot {
    pub(super) policy_revision: u64,
    pub(super) reservation_revision: u64,
    pub(super) admitted_resources: HostResourceVector,
    pub(super) transition: Option<u64>,
    pub(super) requested_policy: HostRamPolicy,
}

pub(super) fn policy_snapshot(status: &HostRamStatus) -> PolicySnapshot {
    PolicySnapshot {
        policy_revision: status.policy_revision,
        reservation_revision: status.reservation_revision,
        admitted_resources: status.admitted_resources,
        transition: status.transition,
        requested_policy: status.requested_policy,
    }
}

pub(super) fn bytes(count: u64) -> Result<(), HostOperationalError> {
    crucible::owned_decode::charge_bytes(count)
        .map_err(|source| HostOperationalError::Admission { source })
}

pub(super) fn vector<T>(count: usize) -> Result<Vec<T>, HostOperationalError> {
    let mut values = Vec::new();
    crucible::owned_decode::reserve_vec(&mut values, count)
        .map_err(|source| HostOperationalError::Admission { source })?;
    Ok(values)
}

pub(super) fn copy_status(source: &HostRamStatus) -> Result<HostRamStatus, HostOperationalError> {
    let mut reasons = vector(source.limitation_reasons.len())?;
    for reason in &source.limitation_reasons {
        bytes(reason.len() as u64)?;
        let mut copied = String::new();
        copied.try_reserve_exact(reason.len()).map_err(|source| {
            HostOperationalError::Admission {
                source: crucible::owned_decode::DecodeAdmissionError::new(source),
            }
        })?;
        copied.push_str(reason);
        reasons.push(copied);
    }
    Ok(HostRamStatus {
        target: source.target,
        observation_sequence: source.observation_sequence,
        policy_revision: source.policy_revision,
        applied_policy_revision: source.applied_policy_revision,
        reservation_revision: source.reservation_revision,
        requested_policy: source.requested_policy,
        applied_policy: source.applied_policy,
        placement_receipt: source.placement_receipt,
        effective_resident_target_bytes: source.effective_resident_target_bytes,
        effective_floor_bytes: source.effective_floor_bytes,
        limitation_reasons: reasons,
        measurements_available: source.measurements_available,
        activity: source.activity,
        private_resident_bytes: source.private_resident_bytes,
        shared_resident_bytes_observed: source.shared_resident_bytes_observed,
        preserved_backing_bytes: source.preserved_backing_bytes,
        private_dirty_bytes: source.private_dirty_bytes,
        writeback_pending_bytes: source.writeback_pending_bytes,
        convergence: source.convergence,
        accepted_unique_update_count: source.accepted_unique_update_count,
        remaining_unique_update_capacity: source.remaining_unique_update_capacity,
        history_disk_bytes: source.history_disk_bytes,
        transition: source.transition,
        admitted_resources: source.admitted_resources,
        outer_caps: Vec::new(),
        outstanding_operations: Vec::new(),
    })
}

pub(super) fn admit_operation_snapshot() -> Result<(), HostOperationalError> {
    // The bounded supervisor refuses a larger roster before allocating. Its
    // snapshot owns ids, statuses and at most three deadline sources per row;
    // deadline calculation also stages three scalar candidate limits per row.
    let row = std::mem::size_of::<u64>()
        + std::mem::size_of::<HostOperationStatus>()
        + 3 * std::mem::size_of::<HostDeadlineSource>()
        + 3 * std::mem::size_of::<(Duration, HostDeadlineSource)>();
    bytes((HOST_OPERATIONAL_MAX_OPERATIONS * row) as u64)
}

pub(super) fn copy_acceptance(
    source: &HostOperationalResponse,
) -> Result<HostOperationalResponse, HostOperationalError> {
    match source {
        HostOperationalResponse::PolicyUpdate {
            request_digest,
            target,
            disposition,
            policy_revision,
            reservation_revision,
            transition,
            accepted_policy,
        } => {
            let accepted_policy = if let Some(policy) = accepted_policy {
                bytes(std::mem::size_of::<HostRamPolicy>() as u64)?;
                Some(Box::new(**policy))
            } else {
                None
            };
            Ok(HostOperationalResponse::PolicyUpdate {
                request_digest: *request_digest,
                target: *target,
                disposition: *disposition,
                policy_revision: *policy_revision,
                reservation_revision: *reservation_revision,
                transition: *transition,
                accepted_policy,
            })
        }
        HostOperationalResponse::OuterCapAmendment {
            request_digest,
            target,
            disposition,
            accepted_cap_revision,
            accepted_allowance,
        } => Ok(HostOperationalResponse::OuterCapAmendment {
            request_digest: *request_digest,
            target: *target,
            disposition: *disposition,
            accepted_cap_revision: *accepted_cap_revision,
            accepted_allowance: *accepted_allowance,
        }),
        _ => Err(HostOperationalError::Unavailable),
    }
}
