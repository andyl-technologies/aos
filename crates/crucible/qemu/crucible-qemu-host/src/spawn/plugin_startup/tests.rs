//! Registered startup refusal before original operations and service effects.
//!
//! Real local descriptors and the existing service bank expose ordering only;
//! this fixture issues no installed native profile or physical process grant.

use super::*;
use std::sync::Arc;
use std::os::unix::fs::FileTypeExt;

use crate::ram_control::{RamControlClient, RamControlRegistrar, RamControlRegistration};
use crucible_host_resources::host_services::HostServiceAllocator;
use crucible_host_resources::host_supervision::HostOperationBudgets;
use crucible_host_resources::ram_policy::{
    HostRamMode, HostRamPolicy, HostRamTarget, HostResourceVector,
};
use crucible_qemu_protocol::ram_control::RamControlError;

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
        Some(&registration),
        1,
        #[cfg(target_os = "linux")]
        None,
        #[cfg(target_os = "linux")]
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
        Some(&registration),
        1,
        #[cfg(target_os = "linux")]
        None,
        #[cfg(target_os = "linux")]
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
        + std::mem::size_of::<SourceHostControlLease>() as u64;

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

// These component controls retain real Setup and resource loans. The actual ELF
// reader supplies the observation; no PluginStartupState or Source is fabricated.
#[cfg(target_os = "linux")]
fn component_setup() -> Result<
    (
        HostOperationSupervisor,
        HostOperationGuard,
        rustix::fd::OwnedFd,
        HostServiceAllocator,
        crucible_host_resources::host_services::HostServiceLease,
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
    let subscriber = services.reserve_resources(
        0,
        1,
        HostOperationGuard::original_setup_cancellation_bytes(),
    )?;
    let event = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )?;
    let alias = rustix::io::fcntl_dupfd_cloexec(&event, 3)?;
    let original = supervisor.begin_control(HostOperationClass::Setup)?;
    original.retain_original_setup_cancellation(alias, subscriber)?;
    Ok((supervisor, original, event, services, control))
}

#[cfg(target_os = "linux")]
#[test]
fn receiver_component_refusal_retains_actual_setup_and_control_until_physical_drop()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::artifact_identity::native_constructor_test_support as artifacts;
    use std::io::Write;

    let (_supervisor, original, event, services, control) = component_setup()?;
    let mut file = tempfile::tempfile()?;
    file.write_all(&artifacts::receiver_elf(&[artifacts::receiver_record(
        0, 0,
    )]))?;
    let observation = artifacts::observe_receiver(&file, &original)?;
    let before = original.serialize_original_setup_basis()?;

    let refusal = check_receiver_under_original(&original, || {
        observation
            .check_source_activation()
            .map_err(PluginStartupCause::Receiver)
    })
    .expect_err("current refusal-only artifact cannot accept Source startup");

    assert!(matches!(
        refusal.source,
        PluginStartupCause::Receiver(
            crate::artifact_identity::NativeReceiverError::SourceActivationUnavailable
        )
    ));
    assert!(refusal.original_after.is_none());
    assert_eq!(original.serialize_original_setup_basis()?, before);
    assert_eq!(
        original.status()?.state,
        crucible_host_resources::host_supervision::HostOperationState::Running
    );
    assert!(services.reserve_resources(0, 1, 1).is_err());
    drop(refusal);
    // Error observation does not return either live descriptor/control loan.
    assert!(services.reserve_resources(0, 1, 1).is_err());
    original.complete()?;
    drop(file);
    drop(original);
    drop(event);
    drop(control);
    let released =
        services.reserve_resources(0, 2, OriginalPluginStartup::host_allocation_extent()?)?;
    drop(released);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn cancelled_setup_precedes_artifact_refusal_and_preserves_independent_original_post()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::artifact_identity::native_constructor_test_support as artifacts;
    use std::cell::Cell;
    use std::io::Write;

    let (_supervisor, original, event, services, control) = component_setup()?;
    let mut file = tempfile::tempfile()?;
    file.write_all(&artifacts::receiver_elf(&[artifacts::receiver_record(
        0, 0,
    )]))?;
    let observation = artifacts::observe_receiver(&file, &original)?;
    rustix::io::write(&event, &1u64.to_ne_bytes())?;
    let expected = original
        .check_original_setup_cancellation()
        .expect_err("actual event revoked Setup");
    let visited = Cell::new(false);

    let refusal = check_receiver_under_original(&original, || {
        visited.set(true);
        observation
            .check_source_activation()
            .map_err(PluginStartupCause::Receiver)
    })
    .expect_err("cancelled Setup cannot consult receiver readiness");

    assert!(!visited.get());
    assert!(matches!(refusal.source, PluginStartupCause::Original(source) if source == expected));
    assert_eq!(refusal.original_after, original.wait_slice().err());
    // The event revocation and raw operation post are independent: reading
    // the event does not cancel or complete the supervisor's operation.
    assert!(refusal.original_after.is_none());
    assert!(services.reserve_resources(0, 1, 1).is_err());
    drop(refusal);
    drop(file);
    drop(original);
    drop(event);
    drop(control);
    let released =
        services.reserve_resources(0, 2, OriginalPluginStartup::host_allocation_extent()?)?;
    drop(released);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn actual_artifact_first_cause_keeps_a_later_same_original_cancellation_post()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::artifact_identity::native_constructor_test_support as artifacts;
    use std::io::Write;

    let (supervisor, original, event, services, control) = component_setup()?;
    let mut file = tempfile::tempfile()?;
    file.write_all(&artifacts::receiver_elf(&[artifacts::receiver_record(
        0, 0,
    )]))?;
    let observation = artifacts::observe_receiver(&file, &original)?;

    let refusal = check_receiver_under_original(&original, || {
        let first = observation
            .check_source_activation()
            .map_err(PluginStartupCause::Receiver);
        supervisor.cancel().map_err(PluginStartupCause::Original)?;
        first
    })
    .expect_err("artifact first and later original post must both survive");

    assert!(matches!(
        refusal.source,
        PluginStartupCause::Receiver(
            crate::artifact_identity::NativeReceiverError::SourceActivationUnavailable
        )
    ));
    assert_eq!(refusal.original_after, original.wait_slice().err());
    assert!(refusal.original_after.is_some());
    assert!(services.reserve_resources(0, 1, 1).is_err());
    drop(refusal);
    drop(file);
    drop(original);
    drop(event);
    drop(control);
    let released =
        services.reserve_resources(0, 2, OriginalPluginStartup::host_allocation_extent()?)?;
    drop(released);
    Ok(())
}

// Real Setup guards and local kernel files establish constructor ordering only.
// These controls create no installed Source or native construction authority.
#[test]
fn startup_constructor_refuses_before_physical_birth_after_cancellation()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin_control(HostOperationClass::Setup)?;
    supervisor.cancel()?;
    let mut entered = false;

    let (first, after) = observe_startup_under_original(&original, || {
        entered = true;
        File::open("/dev/null").map_err(PluginStartupCause::Kernel)
    });

    assert!(!entered);
    assert!(matches!(first, Err(PluginStartupCause::Original(_))));
    assert!(after.is_some());
    Ok(())
}

#[test]
fn startup_constructor_preserves_kernel_refusal_and_independent_post()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin_control(HostOperationClass::Setup)?;

    let (first, after) = observe_startup_under_original(&original, || {
        let file = File::open("/dev/null").map_err(PluginStartupCause::Kernel)?;
        supervisor.cancel().map_err(PluginStartupCause::Original)?;
        drop(file);
        Err::<(), _>(PluginStartupCause::Kernel(io::Error::from_raw_os_error(
            libc::EBADF,
        )))
    });

    assert!(matches!(first, Err(PluginStartupCause::Kernel(error))
        if error.raw_os_error() == Some(libc::EBADF)));
    assert!(after.is_some());
    Ok(())
}

#[test]
fn startup_constructor_retains_physical_result_across_refused_post()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin_control(HostOperationClass::Setup)?;

    let (first, after) = observe_startup_under_original(&original, || {
        let file = File::open("/dev/null").map_err(PluginStartupCause::Kernel)?;
        supervisor.cancel().map_err(PluginStartupCause::Original)?;
        Ok(file)
    });

    let retained = first?;
    assert!(after.is_some());
    assert!(retained.metadata()?.file_type().is_char_device());
    drop(retained);
    Ok(())
}
