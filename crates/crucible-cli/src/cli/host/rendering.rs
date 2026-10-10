//! Host operational receipt and coherent status JSON rendering.
//!
//! Acceptance receipts retain their original revisions. Physical counters stay
//! null when observation is unavailable; desired residency never implies movement.

use super::*;

pub(super) fn response_json(response: &HostOperationalResponse) -> serde_json::Value {
    use serde_json::json;
    let disposition = |value| match value {
        HostOperationalDisposition::Accepted => "accepted",
        HostOperationalDisposition::Replayed => "replayed",
        HostOperationalDisposition::RevisionConflict => "revision-conflict",
        HostOperationalDisposition::NotCurrent => "not-current",
        HostOperationalDisposition::Unsupported => "unsupported",
        HostOperationalDisposition::AdmissionRefused => "admission-refused",
        HostOperationalDisposition::HistoryCapacityRefused => "history-capacity-refused",
        HostOperationalDisposition::RateLimited => "rate-limited",
        HostOperationalDisposition::Unavailable => "unavailable",
        HostOperationalDisposition::Terminal => "terminal",
    };
    match response {
        HostOperationalResponse::Targets {
            target,
            targets,
            next,
        } => json!({
            "kind": "targets", "daemon_epoch": hex_bytes(&target.daemon_epoch),
            "owner": hex_bytes(&target.owner_id),
            "targets": targets.iter().copied().map(target_json).collect::<Vec<_>>(),
            "next": next.map(target_json), "snapshot": false,
        }),
        HostOperationalResponse::Capabilities {
            target,
            capabilities,
            qualification,
        } => json!({
            "kind": "capabilities", "target": target_json(*target),
            "logical_ram_bytes": capabilities.logical_ram_bytes,
            "compulsory_resident_bytes": capabilities.compulsory_resident_bytes,
            "minimum_execution_peak_bytes": capabilities.minimum_execution_peak_bytes,
            "maximum_paging_io_slots": capabilities.maximum_paging_io_slots,
            "dynamic_residency": capabilities.dynamic_residency,
            "disk_oriented": capabilities.disk_oriented,
            "resident_required": capabilities.resident_required,
            "qualification": {
                "backend": format!("{:?}", qualification.backend),
                "authenticated_pages": qualification.authenticated_pages,
                "fault_safe_progress": qualification.fault_safe_progress,
                "bounded_execution_peak": qualification.bounded_execution_peak,
                "hot_fork": qualification.hot_fork,
                "lazy_restore": qualification.lazy_restore,
                "authenticated_transfer": qualification.authenticated_transfer,
                "evidence": qualification.evidence.map(|digest| hex_bytes(&digest)),
            },
        }),
        HostOperationalResponse::PolicyUpdate {
            request_digest,
            target,
            disposition: result,
            policy_revision,
            reservation_revision,
            transition,
            accepted_policy,
        } => json!({
            "kind": "policy-update", "request_digest": hex_bytes(request_digest),
            "target": target_json(*target), "disposition": disposition(*result),
            "policy_revision": policy_revision, "reservation_revision": reservation_revision,
            "transition": transition,
            "accepted_policy": accepted_policy.as_deref().copied().map(policy_json),
        }),
        HostOperationalResponse::OuterCapAmendment {
            request_digest,
            target,
            disposition: result,
            accepted_cap_revision,
            accepted_allowance,
        } => json!({
            "kind": "outer-cap-amendment", "request_digest": hex_bytes(request_digest),
            "target": outer_cap_target_json(*target), "disposition": disposition(*result),
            "accepted_cap_revision": accepted_cap_revision,
            "accepted_allowance": accepted_allowance.map(|value|
                json!({"allowance_ms": value.map(|duration| duration.as_millis())})),
        }),
        HostOperationalResponse::Status(status) => {
            let operations = status.outstanding_operations.iter().map(|operation| {
                let deadline = operation.effective_deadline.as_ref().map(|deadline| {
                    use crucible_api::host_operational::HostDeadlineSource;
                    let sources = deadline.sources.iter().map(|source| match source {
                        HostDeadlineSource::Progress(revision) => json!({"kind": "progress", "revision": revision}),
                        HostDeadlineSource::Total(revision) => json!({"kind": "total", "revision": revision}),
                        HostDeadlineSource::Outer { cap_id, revision } => json!({"kind": "outer", "cap_id": hex_bytes(cap_id), "revision": revision}),
                    }).collect::<Vec<_>>();
                    json!({"remaining_ms": deadline.remaining.as_millis(), "sources": sources})
                });
                json!({"operation_id": operation.operation_id, "class": format!("{:?}", operation.class),
                    "started_policy_revision": operation.started_policy_revision,
                    "applied_policy_revision": operation.applied_policy_revision,
                    "completed_work_units": operation.completed_work_units,
                    "outstanding_work_units": operation.outstanding_work_units,
                    "progress_kind": format!("{:?}", operation.progress_kind),
                    "state": format!("{:?}", operation.state), "effective_deadline": deadline})
            }).collect::<Vec<_>>();
            let caps = status
                .outer_caps
                .iter()
                .map(|cap| {
                    json!({
                        "target": outer_cap_target_json(cap.target), "class": format!("{:?}", cap.class),
                        "status": outer_cap_json(&cap.status),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "kind": "status", "target": target_json(status.target),
                "observation_sequence": status.observation_sequence,
                "policy_revision": status.policy_revision, "reservation_revision": status.reservation_revision,
                "requested_policy": policy_json(status.requested_policy), "applied_policy": policy_json(status.applied_policy),
                "effective_resident_target_bytes": status.effective_resident_target_bytes,
                "effective_floor_bytes": status.effective_floor_bytes,
                "limitation_reasons": status.limitation_reasons,
                "measurements_available": status.measurements_available,
                "activity": status.activity.map(|activity| json!({
                    "successful_missing_installs": activity.successful_missing_installs,
                    "successful_missing_read_installs": activity.successful_missing_read_installs,
                    "successful_missing_write_installs": activity.successful_missing_write_installs,
                    "write_protect_transitions": activity.write_protect_transitions,
                    "preservation_reads": activity.preservation_reads,
                    "preservation_writes": activity.preservation_writes,
                    "physical_discards": activity.physical_discards,
                    "prefetched_pages": activity.prefetched_pages,
                })),
                "private_resident_bytes": status.measurements_available.then_some(status.private_resident_bytes),
                "shared_resident_bytes_observed": status.measurements_available.then_some(status.shared_resident_bytes_observed),
                "preserved_backing_bytes": status.measurements_available.then_some(status.preserved_backing_bytes),
                "private_dirty_bytes": status.measurements_available.then_some(status.private_dirty_bytes),
                "writeback_pending_bytes": status.measurements_available.then_some(status.writeback_pending_bytes),
                "convergence": format!("{:?}", status.convergence),
                "accepted_unique_update_count": status.accepted_unique_update_count,
                "remaining_unique_update_capacity": status.remaining_unique_update_capacity,
                "history_disk_bytes": status.history_disk_bytes, "transition": status.transition,
                "admitted_resources": resource_json(status.admitted_resources),
                "outer_caps": caps, "outstanding_operations": operations,
            })
        }
    }
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}

fn target_json(target: HostRamTarget) -> serde_json::Value {
    serde_json::json!({"daemon_epoch": hex_bytes(&target.daemon_epoch), "owner": hex_bytes(&target.owner_id),
        "node": hex_bytes(&target.node_id), "owner_generation": target.owner_generation,
        "arena_generation": target.arena_generation, "retained_template": target.retained_template})
}

fn outer_cap_target_json(target: HostOuterCapTarget) -> serde_json::Value {
    let (kind, owner) = match target.owner {
        HostOuterCapOwner::Execution(owner) => ("execution", owner),
        HostOuterCapOwner::Service(owner) => ("service", owner),
    };
    serde_json::json!({"daemon_epoch": hex_bytes(&target.daemon_epoch),
        "owner_kind": kind, "owner": hex_bytes(&owner),
        "owner_generation": target.owner_generation, "cap_id": hex_bytes(&target.cap_id)})
}

fn policy_json(policy: crucible_api::host_operational::HostRamPolicy) -> serde_json::Value {
    let mode = match policy.mode {
        HostRamMode::Managed => "managed",
        HostRamMode::DiskOriented => "disk-oriented",
        HostRamMode::ResidentRequired => "resident-required",
    };
    let latency = HostOperationClass::ALL.iter().map(|class| {
        let budget = policy.latency.get(*class);
        serde_json::json!({"class": format!("{class:?}"), "poll_interval_ms": budget.poll_interval.as_millis(),
            "progress_timeout_ms": budget.progress_timeout.map(|duration| duration.as_millis()),
            "total_timeout_ms": budget.total_timeout.map(|duration| duration.as_millis())})
    }).collect::<Vec<_>>();
    serde_json::json!({"mode": mode, "resident_target_bytes": policy.resident_target_bytes,
        "eviction_preference": policy.eviction_preference, "writeback_bytes_per_second": policy.writeback_bytes_per_second,
        "maximum_paging_io_in_flight": policy.maximum_paging_io_in_flight,
        "prefetch_on_increase": policy.prefetch_on_increase, "latency": latency})
}

fn resource_json(
    resources: crucible_api::host_operational::HostResourceVector,
) -> serde_json::Value {
    serde_json::json!({"resident_peak_bytes": resources.resident_peak_bytes, "backing_peak_bytes": resources.backing_peak_bytes,
        "metadata_bytes": resources.metadata_bytes, "staging_bytes": resources.staging_bytes,
        "paging_io_slots": resources.paging_io_slots, "cpu_slots": resources.cpu_slots,
        "task_slots": resources.task_slots, "file_descriptors": resources.file_descriptors})
}

fn outer_cap_json(cap: &crucible_api::host_operational::HostOuterCapStatus) -> serde_json::Value {
    serde_json::json!({"revision": cap.revision, "allowance_ms": cap.allowance.map(|duration| duration.as_millis()),
        "remaining_ms": cap.remaining.map(|duration| duration.as_millis()), "state": format!("{:?}", cap.state)})
}
