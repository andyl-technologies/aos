//! Prepared actor handoff, complete resource reservations, and terminal custody.

use super::*;

fn authored_assignment_operation_budgets()
-> crucible_linux_resource::host_supervision::HostOperationBudgets {
    use crucible_linux_resource::host_supervision::{
        HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets,
    };
    HostOperationBudgets {
        classes: [HostOperationBudget::finite(std::time::Duration::from_secs(300));
            HOST_OPERATION_CLASS_COUNT],
    }
}

#[test]
fn preparation_registry_refusal_retains_the_original_directory_writer() {
    use crucible_linux_resource::ram_policy::HostResourceVector;

    let directory = TempDir::new().expect("original ledger directory");
    let registry = crate::HostOperationalRegistry::default();
    let epoch = DaemonEpoch::from_bytes([0xd4; 16]).expect("original epoch");
    let capacity = ExecutorCapacity::new(1, 4, 8192, 8192, 64).expect("finite capacity");
    let original = PreparedExecutorActor::new(
        LocalExecutorSupervisor::new(
            MemoryAssignmentLedger::default(),
            AllowAllAttemptAdmission,
            epoch,
            capacity,
        )
        .with_host_operational_registry(registry.clone())
        .expect("component registry binding"),
    )
    .expect("one existing admission authority");
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("actual writer lock");
    let mut rejected =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, epoch, capacity)
            .with_host_operational_capacity(
                crate::HostOperationalCapacity::new(4, 64, 128, 4096, 4096)
                    .expect("eight-dimensional capacity"),
            )
            .expect("authored physical capacity")
            .with_host_operational_registry(registry)
            .expect("same registry is not replaced");
    let resources = HostResourceVector {
        resident_peak_bytes: 1024,
        backing_peak_bytes: 1024,
        metadata_bytes: 128,
        staging_bytes: 128,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 1,
        file_descriptors: 8,
    };
    rejected
        .reserve_host_ram_service([0xd5; 32], resources)
        .expect("real Service charge before constructor ownership transfer");

    assert!(PreparedExecutorActor::new(rejected).is_err());
    drop(original);
    assert!(
        DirectoryAssignmentLedger::open(directory.path()).is_err(),
        "uncertain startup cleanup retains the original charged actor and writer lock"
    );
}

#[test]
fn preparation_handoff_preserves_complete_service_charges_and_one_admission_authority() {
    use crate::host_operational_registry::HostResourceAdmission;
    use crucible_linux_resource::ram_policy::{HostRamTarget, HostResourceVector};

    let epoch = DaemonEpoch::from_bytes([0xd1; 16]).expect("daemon");
    let registry = crate::HostOperationalRegistry::default();
    registry
        .configure_bootstrap_limits(
            crucible_api::vm_lifecycle::HostRamBootstrapLimits::new(2, 8, 2, 8, 8 * 1024 * 1024)
                .expect("bootstrap"),
        )
        .expect("bootstrap owner");
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 2, 4 * 1024 * 1024, 8192, 64).expect("authored physical capacity"),
    )
    .with_host_operational_capacity(
        crate::HostOperationalCapacity::new(1, 64, 128, 128, 128).expect("operational capacity"),
    )
    .expect("install capacity")
    .with_host_operation_budgets(authored_assignment_operation_budgets())
    .expect("authored finite operation roster")
    .with_host_assignment_resources(
        crucible_linux_resource::ram_policy::HostResourceVector {
            resident_peak_bytes: 4 * 1024 * 1024,
            backing_peak_bytes: 8192,
            metadata_bytes: 128,
            staging_bytes: 128,
            paging_io_slots: 1,
            cpu_slots: 2,
            task_slots: 64,
            file_descriptors: 128,
        },
        AttemptResourceLimits::new(2, 4096, 8192, 64).expect("authored assignment limits"),
        1024 * 1024,
    )
    .expect("actual advertised assignment entitlement")
    .with_host_operational_registry(registry.clone())
    .expect("history entitlement");
    let (aggregate, assignment) = supervisor
        .host_resource_capacities()
        .expect("physical bounds");
    let advertised = description_with_limits(
        epoch,
        1,
        crucible_campaign::ExecutorResourceBounds::new(
            crate::executor_capability::portable_resources(aggregate),
            crate::executor_capability::portable_resources(assignment),
            AttemptResourceLimits::new(2, 4096, 8192, 64).expect("original limits"),
        )
        .expect("exact actor advertisement"),
    );
    let prepared = PreparedExecutorActor::new(supervisor).expect("one preparation actor");
    let expected_custody = prepared.preparation_custody();
    let campaign = prepared.campaign_port();
    assert!(Arc::ptr_eq(&campaign.capacity_custody(), &expected_custody));
    let owner = [0xd2; 32];
    let resources = HostResourceVector {
        resident_peak_bytes: 1024,
        backing_peak_bytes: 2048,
        metadata_bytes: 32,
        staging_bytes: 32,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 4,
        file_descriptors: 16,
    };
    prepared
        .with_supervisor(|actor| actor.reserve_host_ram_service(owner, resources))
        .expect("global preparation charge");
    let target = HostRamTarget {
        daemon_epoch: crate::host_operational_registry::operational_identity(epoch.as_bytes()),
        owner_id: owner,
        node_id: [0xd3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    };
    registry
        .configure_owner(target.daemon_epoch, owner, resources)
        .expect("node partition");
    registry
        .admit_node(target, resources)
        .expect("live native entitlement");
    assert!(
        !registry
            .service_nodes_cleaned(owner)
            .expect("known service")
    );
    assert!(
        prepared
            .with_supervisor(|actor| actor.release_host_ram_service_after_cleanup(owner))
            .is_err()
    );

    let (executor, admission) = prepared.into_parts(advertised).expect("same actor handoff");
    assert_eq!(
        executor
            .actor
            .lock()
            .expect("actual handoff actor")
            .supervisor()
            .availability()
            .resident_bytes(),
        4 * 1024 * 1024 - 1024
    );
    assert_eq!(
        executor
            .actor
            .lock()
            .expect("actual handoff actor")
            .supervisor()
            .availability()
            .disk_bytes(),
        6144
    );
    assert!(admission.release_after_cleanup(target).is_err());
    assert!(admission.service_nodes_cleaned(owner).is_err());
    assert!(registry.capacity_custody().is_err());
    assert!(campaign.with_supervisor(|_| Ok(())).is_err());
    let shared = Arc::new(SharedExecutor::new(
        executor,
        checkpoint_store(standalone_ram_retention()),
        1,
        0,
        Vec::new(),
        None,
        None,
    ));
    admission
        .bind(&shared)
        .expect("one route switches to same charged actor");
    assert!(admission.bind(&shared).is_err());
    let current_custody = registry.capacity_custody().expect("current pool actor");
    assert!(Arc::ptr_eq(&current_custody, &expected_custody));
    assert_eq!(
        campaign
            .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
            .expect("same campaign actor after handoff"),
        4 * 1024 * 1024 - 1024
    );
    drop(expected_custody);
    shared.state.store(POOL_SHUTTING_DOWN, Ordering::Release);
    assert!(registry.admit_node(target, resources).is_err());
    assert!(campaign.with_supervisor(|_| Ok(())).is_err());
    assert!(
        !registry
            .service_nodes_cleaned(owner)
            .expect("retained service")
    );
    assert!(registry.release_service_after_cleanup(owner).is_err());
    admission
        .release_after_cleanup(target)
        .expect("actual physical node cleanup during shutdown");
    assert!(
        registry
            .service_nodes_cleaned(owner)
            .expect("physical cleanup")
    );
    assert_eq!(
        shared
            .executor
            .lock()
            .expect("actor")
            .supervisor()
            .availability()
            .resident_bytes(),
        4 * 1024 * 1024 - 1024
    );
    registry
        .release_service_after_cleanup(owner)
        .expect("service ends after node cleanup even during pool shutdown");
    let actor = shared.executor.lock().expect("actor");
    assert_eq!(
        actor.supervisor().availability().resident_bytes(),
        4 * 1024 * 1024
    );
    assert_eq!(actor.supervisor().availability().disk_bytes(), 8192);
    drop(actor);
    drop(shared);
    assert!(registry.capacity_custody().is_ok());
    drop(current_custody);
    assert!(
        registry.capacity_custody().is_ok(),
        "terminal registry retains cleanup custody"
    );
    assert!(registry.admit_node(target, resources).is_err());
}

#[test]
fn failed_preparation_handoff_keeps_the_original_ledger_available_for_cleanup() {
    use crucible_linux_resource::ram_policy::HostResourceVector;

    let epoch = DaemonEpoch::from_bytes([0xe1; 16]).expect("daemon");
    let registry = crate::HostOperationalRegistry::default();
    registry
        .configure_bootstrap_limits(
            crucible_api::vm_lifecycle::HostRamBootstrapLimits::new(2, 8, 2, 8, 8 * 1024 * 1024)
                .expect("bootstrap"),
        )
        .expect("bootstrap owner");
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        capacity(),
    )
    .with_host_operational_capacity(
        crate::HostOperationalCapacity::new(1, 8, 32, 256, 256).expect("operational capacity"),
    )
    .expect("capacity")
    .with_host_operational_registry(registry.clone())
    .expect("registry");
    let prepared = PreparedExecutorActor::new(supervisor).expect("original actor");
    let owner = [0xe2; 32];
    let resources = HostResourceVector {
        resident_peak_bytes: 1024,
        backing_peak_bytes: 2048,
        metadata_bytes: 32,
        staging_bytes: 32,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 4,
        file_descriptors: 16,
    };
    prepared
        .with_supervisor(|actor| actor.reserve_host_ram_service(owner, resources))
        .expect("genuine charge");
    let cleanup_owner = prepared.preparation_custody();
    let charged_before = prepared
        .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
        .expect("original capacity");
    let reconciliation_failure = prepared
        .with_startup_supervisor(|actor| {
            assert_eq!(actor.availability().resident_bytes(), charged_before);
            assert!(registry.capacity_custody().is_err());
            assert!(registry.service_nodes_cleaned(owner).is_err());
            assert!(prepared.with_supervisor(|_| Ok(())).is_err());
            Err::<(), _>("startup reconciliation failure")
        })
        .expect("exclusive startup loan");
    assert_eq!(
        reconciliation_failure,
        Err("startup reconciliation failure")
    );
    assert_eq!(
        prepared
            .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
            .expect("same actor restored"),
        charged_before
    );
    assert!(
        registry
            .service_nodes_cleaned(owner)
            .expect("same service restored")
    );
    let foreign_epoch = DaemonEpoch::from_bytes([0xe3; 16]).expect("foreign daemon");

    assert!(prepared.into_parts(description(foreign_epoch)).is_err());
    assert_eq!(
        registry
            .owner_ceiling(
                crate::host_operational_registry::operational_identity(epoch.as_bytes()),
                owner,
            )
            .expect("original charged actor survives refusal"),
        resources
    );
    assert!(
        registry
            .service_nodes_cleaned(owner)
            .expect("empty native ledger")
    );
    registry
        .release_service_after_cleanup(owner)
        .expect("original actor discharges genuine reservation");
    drop(cleanup_owner);
}

#[test]
fn preparation_service_headroom_checks_all_dimensions_without_partial_reservation() {
    use crucible_linux_resource::ram_policy::HostResourceVector;

    let epoch = DaemonEpoch::from_bytes([0xf1; 16]).expect("daemon");
    let registry = crate::HostOperationalRegistry::default();
    registry
        .configure_bootstrap_limits(
            crucible_api::vm_lifecycle::HostRamBootstrapLimits::new(2, 8, 2, 8, 8 * 1024 * 1024)
                .expect("bootstrap"),
        )
        .expect("bootstrap owner");
    let assignment = HostResourceVector {
        resident_peak_bytes: 2 * 1024 * 1024,
        backing_peak_bytes: 2048,
        metadata_bytes: 32,
        staging_bytes: 32,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 4,
        file_descriptors: 16,
    };
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 2, 4 * 1024 * 1024, 8192, 64).expect("authored physical capacity"),
    )
    .with_host_operational_capacity(
        crate::HostOperationalCapacity::new(2, 16, 64, 128, 128).expect("operational capacity"),
    )
    .expect("capacity")
    .with_host_operation_budgets(authored_assignment_operation_budgets())
    .expect("authored finite operation roster")
    .with_host_assignment_resources(
        assignment,
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("authored original limits"),
        1024 * 1024,
    )
    .expect("assignment entitlement")
    .with_host_operational_registry(registry.clone())
    .expect("registry");
    let prepared = PreparedExecutorActor::new(supervisor).expect("original actor");
    let owner = [0xf2; 32];
    let overflowing_services = [
        HostResourceVector {
            resident_peak_bytes: 2 * 1024 * 1024 + 1,
            ..assignment
        },
        HostResourceVector {
            backing_peak_bytes: 6145,
            ..assignment
        },
        HostResourceVector {
            metadata_bytes: 129,
            ..assignment
        },
        HostResourceVector {
            staging_bytes: 129,
            ..assignment
        },
        HostResourceVector {
            paging_io_slots: 2,
            ..assignment
        },
        HostResourceVector {
            cpu_slots: 2,
            ..assignment
        },
        HostResourceVector {
            task_slots: 13,
            ..assignment
        },
        HostResourceVector {
            file_descriptors: 49,
            ..assignment
        },
        HostResourceVector {
            resident_peak_bytes: u64::MAX,
            ..assignment
        },
    ];

    for service in overflowing_services {
        assert!(
            registry
                .reserve_service_with_assignment_headroom(owner, service, assignment)
                .is_err()
        );
        assert_eq!(
            prepared
                .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
                .expect("unchanged actor"),
            4 * 1024 * 1024
        );
        assert!(registry.service_nodes_cleaned(owner).is_err());
    }
    let forged_future_peak = HostResourceVector {
        resident_peak_bytes: 2 * 1024 * 1024 - 1,
        ..assignment
    };
    assert!(
        registry
            .reserve_service_with_assignment_headroom(owner, assignment, forged_future_peak)
            .is_err()
    );

    registry
        .reserve_service_with_assignment_headroom(owner, assignment, assignment)
        .expect("actual service and authored future assignment fit");
    assert_eq!(
        prepared
            .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
            .expect("charged actor"),
        2 * 1024 * 1024
    );
    assert_eq!(
        prepared
            .with_supervisor(|actor| Ok(actor.availability().disk_bytes()))
            .expect("charged actor"),
        6144
    );
    registry
        .release_service_after_cleanup(owner)
        .expect("no native owners or watchers were created");
}

#[test]
fn preparation_terminal_custody_keeps_full_registry_charge_until_last_physical_clone() {
    assert_registry_terminal_charge_survives_handoff(true, false);
}

#[test]
fn preparation_terminal_custody_preserves_registry_after_failed_pool_startup() {
    assert_registry_terminal_charge_survives_handoff(false, false);
}

#[test]
fn preparation_terminal_custody_never_erases_a_persisted_service_charge() {
    assert_registry_terminal_charge_survives_handoff(true, true);
}

fn assert_registry_terminal_charge_survives_handoff(
    publish_pool: bool,
    retain_other_service: bool,
) {
    use crucible_linux_resource::ram_policy::HostResourceVector;

    let directory = tempfile::TempDir::new().expect("registry directory");
    let epoch = DaemonEpoch::from_bytes([0xb6; 16]).expect("daemon epoch");
    let owner = [0xb7; 32];
    let resources = HostResourceVector {
        resident_peak_bytes: 128 * 1024 * 1024,
        backing_peak_bytes: 16 * 1024 * 1024,
        metadata_bytes: 64 * 1024 * 1024,
        staging_bytes: 8 * 1024 * 1024,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 1,
        file_descriptors: 128,
    };
    let capacity = ExecutorCapacity::new(1, 4, 256 * 1024 * 1024, 64 * 1024 * 1024, 64)
        .expect("authored aggregate");
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        capacity,
    )
    .with_host_operational_capacity(
        crate::HostOperationalCapacity::new(4, 64, 1024, 128 * 1024 * 1024, 32 * 1024 * 1024)
            .expect("complete aggregate"),
    )
    .expect("actual operational capacity")
    .with_host_operation_budgets(authored_assignment_operation_budgets())
    .expect("authored finite operation roster")
    .with_host_assignment_resources(
        HostResourceVector {
            resident_peak_bytes: 4 * 1024 * 1024,
            backing_peak_bytes: 1024,
            metadata_bytes: 128,
            staging_bytes: 128,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 8,
            file_descriptors: 32,
        },
        AttemptResourceLimits::new(1, 1024, 0, 64).expect("independent modeled limits"),
        1024 * 1024,
    )
    .expect("authored assignment");
    supervisor
        .reserve_host_ram_service(owner, resources)
        .expect("reserve before registry bytes");
    let retained = if retain_other_service {
        let resources = HostResourceVector {
            resident_peak_bytes: 1024 * 1024,
            backing_peak_bytes: 1024,
            metadata_bytes: 128,
            staging_bytes: 128,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 8,
        };
        supervisor
            .reserve_host_ram_service([0xb8; 32], resources)
            .expect("separate still-owned durable service");
        resources
    } else {
        HostResourceVector::default()
    };
    let registry =
        crate::HostOperationalRegistry::open_admitted(directory.path(), owner, resources)
            .expect("actual admitted writer");
    let supervisor = supervisor
        .with_host_operational_registry(registry.clone())
        .expect("attachment without duplicate history charge");
    let (aggregate, assignment) = supervisor
        .host_resource_capacities()
        .expect("actual eight dimensions");
    let advertised = description_with_limits(
        epoch,
        1,
        crucible_campaign::ExecutorResourceBounds::new(
            crate::executor_capability::portable_resources(aggregate),
            crate::executor_capability::portable_resources(assignment),
            AttemptResourceLimits::new(1, 1024, 0, 64).expect("original modeled limits"),
        )
        .expect("physical advertisement"),
    );
    let prepared = PreparedExecutorActor::new(supervisor).expect("genuine startup actor");
    let early_custody = prepared.preparation_custody();
    let early_weak = Arc::downgrade(&early_custody);
    let (executor, admission) = prepared.into_parts(advertised).expect("same actor handoff");
    let original_actor = executor.actor.clone();
    let shared = if publish_pool {
        let shared = Arc::new(SharedExecutor::new(
            executor,
            checkpoint_store(standalone_ram_retention()),
            1,
            0,
            Vec::new(),
            None,
            None,
        ));
        admission.bind(&shared).expect("bind actual pool actor");
        Some(shared)
    } else {
        // This is the actual fallible startup interval after handoff, before
        // any pool or worker exists. Its guard must preserve the same charge.
        drop(executor);
        None
    };
    let charged = original_actor
        .lock()
        .expect("actor")
        .supervisor()
        .host_resource_availability()
        .expect("actual accounting");
    assert_eq!(
        charged.resident_peak_bytes,
        aggregate.resident_peak_bytes
            - resources.resident_peak_bytes
            - retained.resident_peak_bytes
    );
    assert_eq!(
        charged.backing_peak_bytes,
        aggregate.backing_peak_bytes - resources.backing_peak_bytes - retained.backing_peak_bytes
    );
    assert_eq!(
        charged.metadata_bytes,
        aggregate.metadata_bytes - resources.metadata_bytes - retained.metadata_bytes
    );
    assert_eq!(
        charged.staging_bytes,
        aggregate.staging_bytes - resources.staging_bytes - retained.staging_bytes
    );
    assert_eq!(
        charged.paging_io_slots,
        aggregate.paging_io_slots - resources.paging_io_slots - retained.paging_io_slots
    );
    assert_eq!(
        charged.cpu_slots,
        aggregate.cpu_slots - resources.cpu_slots - retained.cpu_slots
    );
    assert_eq!(
        charged.task_slots,
        aggregate.task_slots - resources.task_slots - retained.task_slots
    );
    assert_eq!(
        charged.file_descriptors,
        aggregate.file_descriptors - resources.file_descriptors - retained.file_descriptors
    );
    drop(early_custody);
    let last_physical_clone = registry.clone();
    drop(shared);
    drop(registry);
    assert!(
        early_weak.upgrade().is_some(),
        "prehandoff custody still owns the actual charged actor"
    );
    assert_eq!(
        original_actor
            .lock()
            .expect("same actor")
            .supervisor()
            .host_resource_availability()
            .expect("remaining exact charge"),
        charged
    );
    assert!(
        crate::HostOperationalRegistry::open_admitted(directory.path(), owner, resources).is_err(),
        "last external clone still holds actual writer lock"
    );

    drop(last_physical_clone);
    let after_close = original_actor
        .lock()
        .expect("same actor")
        .supervisor()
        .host_resource_availability()
        .expect("same accounting after physical close");
    let expected_after_close = HostResourceVector {
        resident_peak_bytes: aggregate.resident_peak_bytes - retained.resident_peak_bytes,
        backing_peak_bytes: aggregate.backing_peak_bytes - retained.backing_peak_bytes,
        metadata_bytes: aggregate.metadata_bytes - retained.metadata_bytes,
        staging_bytes: aggregate.staging_bytes - retained.staging_bytes,
        paging_io_slots: aggregate.paging_io_slots - retained.paging_io_slots,
        cpu_slots: aggregate.cpu_slots - retained.cpu_slots,
        task_slots: aggregate.task_slots - retained.task_slots,
        file_descriptors: aggregate.file_descriptors - retained.file_descriptors,
    };
    assert_eq!(after_close, expected_after_close);
    drop(admission);
    assert_eq!(
        early_weak.upgrade().is_some(),
        retain_other_service,
        "known cleanup breaks cycles; remaining physical authority retains original accounting"
    );
    let reopened =
        crate::HostOperationalRegistry::open_admitted(directory.path(), owner, resources)
            .expect("actual writer descriptors closed before discharge");
    drop(reopened);
}
