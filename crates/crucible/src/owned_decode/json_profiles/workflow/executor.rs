//! Owns the required executor deployment fields in the closed workflow schema.
//!
//! Every operational value is authored by the operator. These fields describe
//! deployment requirements; only the consuming original owners can admit them.
//! Campaign-service settings remain in the separate `campaignServer` object.
//!
//! Each entry in `hostOperationBudgets` has this required JSON shape; an
//! explicit null selects no allowance, while an omitted field refuses:
//!
//! ```json
//! {"pollMillis": 10, "progressMillis": null, "totalMillis": 30000}
//! ```

use serde::Deserialize;

use super::{ResourceVector, ServiceServer};

/// Deserializes the complete required executor deployment object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorDeployment<'input> {
    /// Describes the executor's distinct local socket namespace.
    #[serde(borrow)]
    pub endpoint: ExecutorEndpoint<'input>,
    /// Bounds the executor listener, independently of the campaign listener.
    pub server: ServiceServer,
    /// Names one canonical child directory of the retained state root.
    #[serde(borrow)]
    pub ledger_directory: &'input str,
    /// Bounds one materialized checkpoint object in bytes.
    pub maximum_checkpoint_bytes: u64,
    /// Identifies the authored daemon incarnation in canonical byte order.
    pub daemon_epoch: [u8; 16],
    /// Identifies the authored immutable checkpoint-store namespace.
    pub store_namespace: crucible_campaign::CampaignHash,
    /// Specifies the complete deployed execution ceilings.
    pub capacity: ExecutorCapacity,
    /// Specifies independently accounted host operational ceilings.
    pub host_operational_capacity: ExecutorHostOperationalCapacity,
    /// Specifies the number of executor assignment workers.
    pub worker_count: usize,
    /// Selects the supported host architecture.
    pub host_architecture: ExecutorHostArchitecture,
    /// Names the exact authored QEMU capability profile.
    #[serde(borrow, rename = "qemuProfile")]
    pub execution_profile: &'input str,
    /// Specifies the Linux process and physical storage containment contract.
    #[serde(borrow)]
    pub host: ExecutorHost<'input>,
    /// Specifies the complete physical vector assigned to one attempt.
    pub assignment_resources: ResourceVector,
    /// Specifies modeled request ceilings independently of physical peaks.
    pub assignment_limits: ExecutorAssignmentLimits,
    /// Specifies every original host operation class without fallback values.
    pub host_operation_budgets: ExecutorOperationBudgets,
}

/// Deserializes one exact executor socket contract.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorEndpoint<'input> {
    /// Names the absolute socket path in its operator-installed namespace.
    #[serde(borrow)]
    pub path: &'input str,
    /// Specifies the effective user that owns the endpoint and parent directory.
    pub owner_user_id: u32,
    /// Specifies the effective group that owns the endpoint and parent directory.
    pub owner_group_id: u32,
    /// Specifies the exact socket permission bits.
    pub socket_mode: u32,
}

/// Deserializes the complete deployed executor capacity.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorCapacity {
    /// Bounds the simultaneous execution count.
    pub maximum_concurrent_executions: u32,
    /// Bounds the aggregate virtual CPU count.
    pub maximum_vcpus: u32,
    /// Bounds the complete resident peak, including its metadata subsets.
    pub maximum_resident_bytes: u64,
    /// Bounds writable materialization and backing.
    pub maximum_disk_bytes: u64,
    /// Bounds deterministic work for one execution.
    pub maximum_execution_quanta: u64,
}

/// Deserializes independent host operational resource ceilings.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorHostOperationalCapacity {
    /// Bounds simultaneous paging and preservation I/O.
    pub maximum_paging_io_slots: u64,
    /// Bounds process and worker tasks.
    pub maximum_task_slots: u64,
    /// Bounds owned file descriptors.
    pub maximum_file_descriptors: u64,
    /// Bounds the metadata subset of the resident peak.
    pub maximum_metadata_bytes: u64,
    /// Bounds the transient staging subset of resident and backing peaks.
    pub maximum_staging_bytes: u64,
}

/// Selects the finite architecture supported by this deployment schema.
#[derive(Deserialize)]
pub enum ExecutorHostArchitecture {
    /// Selects the existing x86-64 host and direct-kernel guest route.
    #[serde(rename = "x86_64")]
    X86_64,
}

/// Deserializes the paired Linux process and storage containment contract.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorHost<'input> {
    /// Names the existing delegated cgroup-v2 root.
    #[serde(borrow)]
    pub cgroup_root: &'input str,
    /// Names the existing project-quota run root.
    #[serde(borrow)]
    pub run_root: &'input str,
    /// Identifies the shared daemon-incarnation child namespace.
    #[serde(borrow)]
    pub attempt_namespace: &'input str,
    /// Specifies the first installed child project identifier.
    pub first_project_id: u32,
    /// Specifies the finite installed project-identifier range.
    pub project_id_count: u32,
    /// Specifies the distinct unprivileged child user.
    pub child_user_id: u32,
    /// Specifies the distinct unprivileged child group.
    pub child_group_id: u32,
    /// Bounds tasks in one child cgroup.
    pub maximum_tasks: u32,
    /// Bounds descriptors in one child process.
    pub maximum_file_descriptors: u64,
    /// Bounds each node's retained host-service tasks.
    pub maximum_node_host_service_tasks: u64,
    /// Bounds each node's retained host-service descriptors.
    pub maximum_node_host_service_file_descriptors: u64,
    /// Bounds each node's retained host-service resident memory.
    pub maximum_node_host_service_resident_bytes: u64,
    /// Bounds one operational watcher's resident memory.
    pub watcher_service_resident_bytes: u64,
    /// Bounds entries and inodes in one attempt namespace.
    pub maximum_inodes: u64,
    /// Bounds physical child containment and reap without renewing its original.
    pub finish_timeout_millis: u64,
    /// Specifies the independently authored memory-lock entitlement.
    pub maximum_locked_bytes: u64,
}

/// Deserializes the modeled limits accepted for one assignment.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorAssignmentLimits {
    /// Bounds virtual CPUs in one modeled execution.
    pub maximum_vcpus: u32,
    /// Bounds modeled resident memory in bytes.
    pub maximum_resident_bytes: u64,
    /// Bounds modeled writable disk in bytes.
    pub maximum_disk_bytes: u64,
    /// Bounds deterministic work for one execution.
    pub maximum_execution_quanta: u64,
}

/// Deserializes the required canonical host operation roster.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorOperationBudgets {
    /// Bounds original setup and registration.
    pub setup: ExecutorOperationBudget,
    /// Bounds host waiting during a guest quantum.
    pub quantum: ExecutorOperationBudget,
    /// Bounds authenticated page-in work.
    pub page_in: ExecutorOperationBudget,
    /// Bounds dirty-page preservation.
    pub writeback: ExecutorOperationBudget,
    /// Bounds initial fingerprint registration.
    pub fingerprint_initialization: ExecutorOperationBudget,
    /// Bounds incremental fingerprint work.
    pub fingerprint_update: ExecutorOperationBudget,
    /// Bounds original quiescence and stopped-state handoff.
    pub quiescence: ExecutorOperationBudget,
    /// Bounds checkpoint capture.
    pub checkpoint_capture: ExecutorOperationBudget,
    /// Bounds checkpoint publication.
    pub checkpoint_publication: ExecutorOperationBudget,
    /// Bounds restore work.
    pub restore: ExecutorOperationBudget,
    /// Bounds genuine child reconstruction.
    pub fork_rearm: ExecutorOperationBudget,
    /// Bounds authenticated object transfer.
    pub transfer: ExecutorOperationBudget,
    /// Bounds preparation of executable state.
    pub preparation: ExecutorOperationBudget,
    /// Bounds independent containment and cleanup.
    pub cleanup: ExecutorOperationBudget,
}

/// Deserializes the original polling and deadline requirements of one class.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutorOperationBudget {
    /// Specifies the responsive polling slice in milliseconds.
    pub poll_millis: u64,
    /// Specifies a progress allowance, or explicitly selects no such allowance.
    #[serde(deserialize_with = "required_optional_millis")]
    pub progress_millis: Option<u64>,
    /// Specifies a total allowance, or explicitly selects no such allowance.
    #[serde(deserialize_with = "required_optional_millis")]
    pub total_millis: Option<u64>,
}

// A missing field must refuse; only an explicit JSON null selects no allowance.
// The derive's deserialize_with edge preserves its fixed missing-field error.
fn required_optional_millis<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<u64>::deserialize(deserializer)
}

#[cfg(test)]
mod tests {
    use super::ExecutorOperationBudget;

    #[test]
    fn explicit_null_is_the_only_absent_allowance_form() -> Result<(), serde_json::Error> {
        let budget: ExecutorOperationBudget =
            serde_json::from_str(r#"{"pollMillis":10,"progressMillis":null,"totalMillis":null}"#)?;

        assert_eq!(budget.poll_millis, 10);
        assert_eq!(budget.progress_millis, None);
        assert_eq!(budget.total_millis, None);
        Ok(())
    }

    #[test]
    fn omitted_progress_allowance_refuses() {
        assert!(
            serde_json::from_str::<ExecutorOperationBudget>(
                r#"{"pollMillis":10,"totalMillis":30}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn omitted_total_allowance_refuses() {
        assert!(
            serde_json::from_str::<ExecutorOperationBudget>(
                r#"{"pollMillis":10,"progressMillis":30}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_allowance_refuses() {
        assert!(
            serde_json::from_str::<ExecutorOperationBudget>(
                r#"{"pollMillis":10,"progressMillis":null,"totalMillis":30,"remainingMillis":30}"#,
            )
            .is_err()
        );
    }
}
