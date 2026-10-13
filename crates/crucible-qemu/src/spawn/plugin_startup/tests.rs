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

    let refusal = OriginalPluginStartup::prepare(
        &supervisor,
        &contract,
        &registration,
        1,
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        None,
    )
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
    let with_capacity = OriginalPluginStartup::prepare(
        &supervisor,
        &contract,
        &registration,
        1,
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        None,
    )
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

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
#[test]
fn startup_outside_request_keeps_the_actual_body_and_subscriber_extents() {
    let hosted = u64::try_from(
        std::mem::size_of::<OriginalPluginStartup>()
            + std::mem::size_of::<Option<PluginStartupState>>()
            + std::mem::size_of::<PluginStartupState>()
            + std::mem::size_of::<PluginStartupError>()
            + FDINFO_BYTES
            + 1,
    )
    .unwrap()
        + HostServiceLease::metadata_bytes();

    let requested = OriginalPluginStartup::host_allocation_extent().unwrap();

    assert_eq!(
        OriginalPluginStartup::control_allocation_extent(),
        Some(hosted)
    );
    assert_eq!(
        requested,
        hosted + HostOperationGuard::original_setup_cancellation_bytes()
    );
    assert!(requested > hosted);
}

// This fixed host fixture exercises the original and receiver cuts only. It
// constructs no process-purpose loan, native entitlement or spawn capability.
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
fn hosted_startup() -> Result<
    (
        OriginalPluginStartup,
        rustix::fd::OwnedFd,
        HostServiceAllocator,
    ),
    Box<dyn std::error::Error>,
> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let extent = OriginalPluginStartup::host_allocation_extent()?;
    let services = HostServiceAllocator::new(1, 2, extent)?;
    let control = services.reserve_resources(
        0,
        1,
        OriginalPluginStartup::control_allocation_extent().ok_or("unrepresentable host extent")?,
    )?;
    let original = supervisor.begin_control(HostOperationClass::Setup)?;
    let event = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )?;
    let subscriber = services.reserve_resources(
        0,
        1,
        HostOperationGuard::original_setup_cancellation_bytes(),
    )?;
    let alias = rustix::io::fcntl_dupfd_cloexec(&event, 3)?;
    original.retain_original_setup_cancellation(alias, subscriber)?;
    let basis = original.serialize_original_setup_basis()?;
    let mut cap_id = [0; 32];
    cap_id.copy_from_slice(&basis[16..48]);
    let u64_at = |offset: usize| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&basis[offset..offset + 8]);
        u64::from_be_bytes(bytes)
    };
    let metadata = rustix::fs::fstat(&event)?;
    let record = StartupOperation::new(StartupOperationFields {
        cap_id,
        operation_id: u64_at(48),
        original_start_ns: u64_at(56),
        absolute_end_ns: u64_at(64),
        poll_ns: u64_at(72),
        process_generation: 1,
        original_total_metadata_bytes: extent,
        cancellation_device: metadata.st_dev,
        cancellation_inode: metadata.st_ino,
        cancellation_event_id: event_identity(event.as_raw_fd())?,
        cancellation_descriptor: super::super::QEMU_STARTUP_CANCELLATION_FD,
    })?;
    let startup = OriginalPluginStartup {
        body: Box::new(Some(PluginStartupState {
            services: services.clone(),
            workspace: None,
            original,
            record,
        })),
        _control: control,
    };
    Ok((startup, event, services))
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
#[test]
fn unavailable_receiver_keeps_the_actual_setup_and_control_owned()
-> Result<(), Box<dyn std::error::Error>> {
    let (startup, event, services) = hosted_startup()?;
    let before = startup.record()?;

    let refusal = startup
        .require_preexec_receiver()
        .err()
        .ok_or("receiver unexpectedly issued")?;

    assert!(matches!(
        refusal.source,
        PluginStartupCause::ReceiverPurposeUnavailable
    ));
    assert!(refusal.original_after.is_none());
    assert_eq!(startup.record()?, before);
    assert_eq!(
        startup.state()?.original.status()?.state,
        crucible_linux_resource::host_supervision::HostOperationState::Running
    );
    assert!(services.reserve_resources(0, 1, 1).is_err());
    startup.complete()?;
    drop(startup);
    drop(event);
    let released =
        services.reserve_resources(0, 2, OriginalPluginStartup::host_allocation_extent()?)?;
    drop(released);
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
#[test]
fn cancelled_setup_precedes_the_receiver_unavailable_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    let (startup, event, _) = hosted_startup()?;
    rustix::io::write(&event, &1u64.to_ne_bytes())?;

    let refusal = startup
        .require_preexec_receiver()
        .err()
        .ok_or("cancelled Setup continued")?;

    assert!(matches!(refusal.source, PluginStartupCause::Original(_)));
    assert!(startup.check().is_err());
    Ok(())
}
