//! Explicit capability contracts and real actor configuration for component fixtures.
//!
//! These helpers accept complete authored physical bounds independently of the
//! original modeled request limits. They do not qualify native memory placement.

use crucible_campaign::{CampaignCodecError, ExecutorDescription};

use crate::{HostOperationalCapacity, LocalExecutorCapabilityService, LocalExecutorSupervisor};

/// Configures the real fixture actor before binding its advertised capabilities.
///
/// # Errors
/// Reports inconsistent authored capacity, an already admitted owner, or an
/// advertisement that differs from the actor's actual enforced resource bounds.
pub(crate) fn capability_service<L, V>(
    supervisor: LocalExecutorSupervisor<L, V>,
    description: ExecutorDescription,
    watcher_service_resident_bytes: u64,
) -> Result<LocalExecutorCapabilityService<L, V>, CampaignCodecError> {
    let aggregate = description.capabilities().aggregate_resources();
    let assignment = description.capabilities().assignment_resources();
    let operational = HostOperationalCapacity::new(
        aggregate.paging_io_slots,
        aggregate.task_slots,
        aggregate.file_descriptors,
        aggregate.metadata_bytes,
        aggregate.staging_bytes,
    )
    .map_err(|_| invalid_fixture_bounds())?;
    let supervisor = supervisor
        .with_host_operation_budgets(crucible_api::host_operational::HostOperationBudgets {
            classes: [crucible_api::host_operational::HostOperationBudget::finite(
                std::time::Duration::from_secs(300),
            ); crucible_api::host_operational::HostOperationClass::ALL.len()],
        })
        .map_err(|_| invalid_fixture_bounds())?
        .with_host_operational_capacity(operational)
        .map_err(|_| invalid_fixture_bounds())?
        .with_host_assignment_resources(
            crucible_api::host_operational::HostResourceVector {
                resident_peak_bytes: assignment.resident_peak_bytes,
                backing_peak_bytes: assignment.backing_peak_bytes,
                metadata_bytes: assignment.metadata_bytes,
                staging_bytes: assignment.staging_bytes,
                paging_io_slots: assignment.paging_io_slots,
                cpu_slots: assignment.cpu_slots,
                task_slots: assignment.task_slots,
                file_descriptors: assignment.file_descriptors,
            },
            description.capabilities().assignment_limits(),
            watcher_service_resident_bytes,
        )
        .map_err(|_| invalid_fixture_bounds())?;
    LocalExecutorCapabilityService::new(supervisor, description)
}

fn invalid_fixture_bounds() -> CampaignCodecError {
    CampaignCodecError::InvalidValue {
        reason: "component fixture physical bounds do not fit its actual actor",
    }
}
