//! Registered startup refusal before original operations and service effects.
//!
//! Real local descriptors and the existing service bank expose ordering only;
//! this fixture issues no installed native profile or physical process grant.

use super::*;
use std::sync::Arc;

use crate::ram_control::{RamControlClient, RamControlRegistrar, RamControlRegistration};
use crucible_linux_resource::host_services::HostServiceAllocator;
use crucible_linux_resource::host_supervision::HostOperationBudgets;
use crucible_linux_resource::ram_policy::{
    HostRamMode, HostRamPolicy, HostRamTarget, HostResourceVector,
};
use crucible_protocol::ram_control::RamControlError;

struct RefusingRegistrar;

impl RamControlRegistrar for RefusingRegistrar {
    fn register(
        &self,
        _: HostRamTarget,
        _: HostRamPolicy,
        _: HostResourceVector,
        _: HostOperationSupervisor,
        _: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }
}

#[test]
fn missing_installed_profile_refuses_before_setup_or_service_reservation()
-> Result<(), Box<dyn std::error::Error>> {
    let budgets = HostOperationBudgets::default();
    let supervisor = HostOperationSupervisor::new(budgets, None)?;
    let services = HostServiceAllocator::new(1, 1, 4096)?;
    let occupied = services.reserve_resources(1, 1, 4096)?;
    let registration = RamControlRegistration {
        target: HostRamTarget {
            daemon_epoch: [1; 32],
            owner_id: [2; 32],
            node_id: [3; 32],
            owner_generation: 1,
            arena_generation: 1,
            retained_template: false,
        },
        initial_policy: HostRamPolicy {
            mode: HostRamMode::Managed,
            resident_target_bytes: 4096,
            eviction_preference: 50,
            writeback_bytes_per_second: 4096,
            maximum_paging_io_in_flight: 1,
            prefetch_on_increase: false,
            latency: budgets,
        },
        resources: HostResourceVector {
            resident_peak_bytes: 8192,
            backing_peak_bytes: 8192,
            metadata_bytes: 4096,
            staging_bytes: 4096,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 1,
        },
        spill_quota_bytes: 4096,
        host_services: services.clone(),
        registrar: Arc::new(RefusingRegistrar),
    };
    // An ordinary file is intentionally not a cancellation event. Reaching
    // fdinfo validation would produce another real initiating refusal.
    let contract = QemuChildProcessContract::for_test(
        File::open("/dev/null")?.into(),
        File::open("/dev/null")?.into(),
        4096,
    );
    let original_cap = supervisor.cap_id();
    let original_budgets = supervisor.budgets()?;

    let refusal = OriginalPluginStartup::prepare(&supervisor, &contract, &registration, 1)
        .err()
        .ok_or("registered startup unexpectedly issued an installed profile")?;

    assert!(matches!(
        &refusal.source,
        PluginStartupCause::InstalledProfileUnavailable
    ));
    assert!(refusal.original_after.is_none());
    assert!(refusal._control.is_none());
    assert!(supervisor.operation_statuses()?.is_empty());
    assert_eq!(supervisor.cap_id(), original_cap);
    assert_eq!(supervisor.budgets()?, original_budgets);
    assert!(services.reserve_resources(1, 1, 4096).is_err());
    drop(refusal);
    drop(occupied);
    let same_capacity = services.reserve_resources(1, 1, 4096)?;

    drop(same_capacity);
    let with_capacity = OriginalPluginStartup::prepare(&supervisor, &contract, &registration, 1)
        .err()
        .ok_or("registered startup bypassed the missing profile after capacity became free")?;
    assert!(matches!(
        &with_capacity.source,
        PluginStartupCause::InstalledProfileUnavailable
    ));
    assert!(with_capacity._control.is_none());
    assert!(with_capacity.original_after.is_none());
    drop(with_capacity);
    let still_full_capacity = services.reserve_resources(1, 1, 4096)?;

    // No hidden start/complete cycle consumed the original operation identity.
    let first_setup = supervisor.begin_control(HostOperationClass::Setup)?;
    assert_eq!(first_setup.status()?.operation_id, 1);
    first_setup.complete()?;
    drop(still_full_capacity);
    Ok(())
}
