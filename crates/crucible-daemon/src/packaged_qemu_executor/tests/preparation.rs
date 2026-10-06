//! Component evidence for real preparation admission, identity and containment.

use super::super::preparation::{prepare_component_runtime as prepare_runtime, run_capture};
use super::*;

#[test]
fn production_preparation_refuses_uninstalled_ledger_quota_before_ledger_io() {
    let directory = tempfile::TempDir::new().expect("directory");
    let config = config(&directory, 1);
    let catalog_root = config.ram_catalog().expect("authored catalog").root();
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let basis = authenticate_packaged_campaigns(&repository, &config.campaigns, false)
        .expect("campaign admission");

    let result = super::super::preparation::prepare_runtime(
        &repository,
        Arc::new(DirectoryBlobBackend::new(
            "unqualified-catalog-checkpoints",
            directory.path().join("checkpoints"),
        )),
        &basis,
        &config,
    );

    let error = result
        .err()
        .expect("physical ledger quota admission must refuse");
    let PackagedQemuExecutorError::RegistryQuota(
        crucible_linux_resource::LinuxProjectQuotaError::Io {
            operation,
            path,
            source,
        },
    ) = error
    else {
        panic!("the fixture must refuse the original ledger quota: {error:?}");
    };
    assert_eq!(operation, "open-physical-quota-root");
    assert_eq!(path, config.ledger_root);
    assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
    assert!(!config.ledger_root.exists());
    assert!(!config.lifecycle.run_state_root().exists());
    assert!(!catalog_root.exists());
}

fn preparation_scenario() -> ScenarioDefForm {
    let world = World::from_nodes(vec![crucible::WorldNode {
        id: NodeId {
            name: String::from("prepared-node"),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: 16,
        cmdline: String::new(),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("one preparation node");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(42),
    )
    .expect("preparation scenario")
}

#[test]
fn cold_preparation_uses_real_service_and_releases_only_after_capture_and_join() {
    let directory = tempfile::TempDir::new().expect("directory");
    let config = config(&directory, 1);
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let basis = authenticate_packaged_campaigns(&repository, &config.campaigns, false)
        .expect("campaign admission");
    let prepared = prepare_runtime(
        &repository,
        Arc::new(DirectoryBlobBackend::new(
            "preparation-checkpoints",
            directory.path().join("checkpoints"),
        )),
        &basis,
        &config,
    )
    .expect("actual preparation actor");
    let baseline_resident = prepared
        .actor
        .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
        .expect("genuine registry service remains charged");
    let scenario = preparation_scenario();
    let mut owners = Vec::new();
    for _ in 0..2 {
        run_capture(&prepared, &config, &scenario, |context| {
            assert!(context.runtime_basis().is_none());
            let owner = context.host_ram_owner_id().expect("service owner");
            assert_eq!(
                context.host_outer_cap_owner(),
                Some(crucible_api::host_operational::HostOuterCapOwner::Service(
                    owner
                ))
            );
            owners.push(owner);
            assert_eq!(
                context.resources().maximum_disk_bytes(),
                config
                    .assignment_limits()
                    .expect("original semantic limits")
                    .maximum_disk_bytes()
            );
            assert_eq!(
                prepared
                    .actor
                    .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
                    .expect("real actor"),
                baseline_resident
                    - config
                        .assignment_resources()
                        .expect("authored launch peak")
                        .resident_peak_bytes
            );
            let factory =
                crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(context)
                    .expect("production factory accepts genuine service");
            factory
                .configure_world(&[crucible_api::vm_lifecycle::ProductionHostRamLaunchShape {
                    node: String::from("prepared-node"),
                    declared_ram_bytes: 16 * 1024 * 1024,
                    vcpus: 1,
                }])
                .expect("factory resolves admitted service partition");
            Ok(())
        })
        .expect("cold capture has no remaining native owners");
        assert_eq!(
            prepared
                .actor
                .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
                .expect("real actor"),
            baseline_resident
        );
    }
    assert_ne!(owners[0], owners[1]);
}

#[test]
fn unfinished_preparation_retains_all_charges_and_original_failure() {
    let directory = tempfile::TempDir::new().expect("directory");
    let config = config(&directory, 1);
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let basis = authenticate_packaged_campaigns(&repository, &config.campaigns, false)
        .expect("campaign admission");
    let prepared = prepare_runtime(
        &repository,
        Arc::new(DirectoryBlobBackend::new(
            "preparation-checkpoints",
            directory.path().join("checkpoints"),
        )),
        &basis,
        &config,
    )
    .expect("actual preparation actor");
    let baseline_resident = prepared
        .actor
        .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
        .expect("genuine registry service remains charged");
    let mut held = None;
    let result: Result<(), _> =
        run_capture(&prepared, &config, &preparation_scenario(), |context| {
            let factory =
                crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(context)
                    .expect("production RAM authority");
            factory
                .configure_world(&[crucible_api::vm_lifecycle::ProductionHostRamLaunchShape {
                    node: String::from("prepared-node"),
                    declared_ram_bytes: 16 * 1024 * 1024,
                    vcpus: 1,
                }])
                .expect("world");
            // This component reserves an unpublished budget owner, without
            // claiming a native cgroup/controller or creating a guest process.
            let target = crucible_api::host_operational::HostRamTarget {
                daemon_epoch: context.host_daemon_epoch(),
                owner_id: context.host_ram_owner_id().expect("genuine service"),
                node_id: [0x53; 32],
                owner_generation: 1,
                arena_generation: 1,
                retained_template: false,
            };
            prepared
                .host_operational_registry
                .admit_node(
                    target,
                    context
                        .host_ram_resource_ceiling()
                        .expect("immutable node ceiling"),
                )
                .expect("real actor budget reservation");
            held = Some(target);
            Err(PackagedQemuExecutorError::NoCampaigns)
        });
    assert!(
        matches!(result, Err(PackagedQemuExecutorError::PreparationCleanup {
        preparation: Some(ref primary), ..
    }) if matches!(primary.as_ref(), PackagedQemuExecutorError::NoCampaigns))
    );
    assert_eq!(
        prepared
            .actor
            .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
            .expect("retained actor"),
        baseline_resident
            - config
                .assignment_resources()
                .expect("authored launch peak")
                .resident_peak_bytes
    );

    // Dropping failed composition must not remove the genuine charged actor.
    // The positive cold-capture case covers proven discharge; this deliberately
    // unresolved component reservation exercises process-lifetime quarantine.
    let target = held.expect("retained physical owner");
    let registry = prepared.host_operational_registry.clone();
    drop(prepared);
    assert!(
        registry
            .owner_ceiling(target.daemon_epoch, target.owner_id)
            .is_ok()
    );
    assert!(
        !registry
            .service_nodes_cleaned(target.owner_id)
            .expect("same charged actor")
    );
    assert!(
        registry
            .release_service_after_cleanup(target.owner_id)
            .is_err()
    );
    assert!(crate::DirectoryAssignmentLedger::open(&config.ledger_root).is_err());
}

#[test]
fn retained_service_observer_waits_for_node_cleanup_then_discharges_once() {
    use super::super::hot_fork::retained_service::RetainedTemplateServiceFactory;
    use crucible_api::host_operational::HostResourceVector;
    use crucible_api::vm_lifecycle::ProductionHotForkCleanupObserver;
    use crucible_qemu::ram_control::RamControlRegistrar;

    let directory = tempfile::TempDir::new().expect("directory");
    let service_resources = HostResourceVector {
        resident_peak_bytes: 513 * 1024 * 1024,
        backing_peak_bytes: 1024 * 1024 * 1024,
        metadata_bytes: 128 * 1024 * 1024,
        staging_bytes: 16 * 1024 * 1024,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 96,
        file_descriptors: 2048,
    };
    let config = config(&directory, 1)
        .with_retained_template_resources(service_resources)
        .expect("authored independent template entitlement");
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let basis = authenticate_packaged_campaigns(&repository, &config.campaigns, false)
        .expect("campaign admission");
    let prepared = prepare_runtime(
        &repository,
        Arc::new(DirectoryBlobBackend::new(
            "retained-service-checkpoints",
            directory.path().join("checkpoints"),
        )),
        &basis,
        &config,
    )
    .expect("real capacity actor");
    let available = || {
        prepared
            .actor
            .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
            .expect("actual retained capacity")
    };
    let available_before = available();

    let all_available = || {
        prepared
            .actor
            .with_supervisor(|actor| {
                actor
                    .host_resource_availability()
                    .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
            })
            .expect("actual complete resource availability")
    };
    let complete_before = all_available();
    let interactive = RetainedTemplateServiceFactory::new(&prepared, &config)
        .start_for_interactive_session(
            &preparation_scenario(),
            crate::ExecutionCancellation::default(),
        )
        .expect("fresh interactive Service uses the same actual capacity actor");
    assert!(!interactive.context().host_ram_retained_template());
    assert!(!interactive.native_context().host_ram_retained_template());
    assert!(matches!(
        interactive.context().host_outer_cap_owner(),
        Some(crucible_api::host_operational::HostOuterCapOwner::Service(
            _
        ))
    ));
    assert_eq!(
        all_available(),
        HostResourceVector {
            resident_peak_bytes: complete_before.resident_peak_bytes
                - service_resources.resident_peak_bytes,
            backing_peak_bytes: complete_before.backing_peak_bytes
                - service_resources.backing_peak_bytes,
            metadata_bytes: complete_before.metadata_bytes - service_resources.metadata_bytes,
            staging_bytes: complete_before.staging_bytes - service_resources.staging_bytes,
            paging_io_slots: complete_before.paging_io_slots - service_resources.paging_io_slots,
            cpu_slots: complete_before.cpu_slots - service_resources.cpu_slots,
            task_slots: complete_before.task_slots - service_resources.task_slots,
            file_descriptors: complete_before.file_descriptors - service_resources.file_descriptors,
        }
    );
    // No native node was created. The actual zero-node ledger permits the
    // final Service owner to join its watcher before releasing the whole vector.
    drop(interactive);
    assert_eq!(all_available(), complete_before);

    let mut authentication = RetainedTemplateServiceFactory::new(&prepared, &config)
        .start_for_archive_authentication(
            &preparation_scenario(),
            crate::ExecutionCancellation::default(),
        )
        .expect("authentication reserves the original full Service vector");
    let authentication_charge = all_available();
    assert_finding_binding_preserves_service(&mut authentication);
    assert_eq!(all_available(), authentication_charge);
    authentication
        .release_after_world_cleanup()
        .expect("component has no native borrowers and joins the actual watcher");
    assert_eq!(all_available(), complete_before);

    let mut missing_watcher_task = service_resources;
    missing_watcher_task.task_slots = 1;
    let mut missing_watcher_memory = service_resources;
    missing_watcher_memory.resident_peak_bytes = config.host.watcher_service_resident_bytes() - 1;
    missing_watcher_memory.metadata_bytes = 1;
    missing_watcher_memory.staging_bytes = 1;
    for insufficient in [missing_watcher_task, missing_watcher_memory] {
        let insufficient_config = config
            .clone()
            .with_retained_template_resources(insufficient)
            .expect("syntactically valid component ceiling");
        assert!(
            RetainedTemplateServiceFactory::new(&prepared, &insufficient_config)
                .start(&preparation_scenario(), None)
                .is_err()
        );
        assert_eq!(available(), available_before);
    }
    let service = RetainedTemplateServiceFactory::new(&prepared, &config)
        .start(&preparation_scenario(), None)
        .expect("service and future assignment headroom");
    let context = service.context();
    assert!(context.host_ram_retained_template());
    assert!(service.native_context().host_ram_retained_template());
    let owner = context.host_ram_owner_id().expect("service namespace");
    assert_eq!(
        available(),
        available_before - service_resources.resident_peak_bytes
    );
    let factory = crate::qemu_campaign_lifecycle::create_host_ram_registration_factory(context)
        .expect("same real service registrar");
    factory
        .configure_world(&[crucible_api::vm_lifecycle::ProductionHostRamLaunchShape {
            node: "prepared-node".into(),
            declared_ram_bytes: 16 * 1024 * 1024,
            vcpus: 1,
        }])
        .expect("whole world partition");
    let target = crucible_api::host_operational::HostRamTarget {
        daemon_epoch: context.host_daemon_epoch(),
        owner_id: owner,
        node_id: [0x54; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: true,
    };
    let node_resources = context
        .host_ram_resource_ceiling()
        .expect("immutable admitted node ceiling");
    assert_eq!(
        node_resources.resident_peak_bytes + config.host.watcher_service_resident_bytes(),
        service_resources.resident_peak_bytes,
    );
    assert_eq!(node_resources.task_slots + 1, service_resources.task_slots);
    prepared
        .host_operational_registry
        .admit_node(target, node_resources)
        .expect("real unpublished node budget reservation");

    assert!(service.after_world_cleanup().is_err());
    assert!(
        !prepared
            .host_operational_registry
            .service_nodes_cleaned(owner)
            .expect("same node ledger")
    );
    assert_eq!(
        available(),
        available_before - service_resources.resident_peak_bytes
    );

    // This component fixture never spawns or publishes a process or controller.
    // Its actual unpublished reservation can therefore attest no borrowers.
    prepared
        .host_operational_registry
        .retire_unpublished_after_cleanup(target, node_resources)
        .expect("exact unpublished node disposition");
    service
        .after_world_cleanup()
        .expect("watcher joined before service discharge");
    assert_eq!(available(), available_before);
    service
        .after_world_cleanup()
        .expect("repeat acknowledgement stays idempotent");
    assert_eq!(available(), available_before);

    let outer = crucible_linux_resource::host_supervision::HostOperationSupervisor::new(
        crucible_linux_resource::host_supervision::HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .expect("one original preparation cap");
    let constrained = RetainedTemplateServiceFactory::new(&prepared, &config)
        .with_outer_supervisor(outer.clone());
    let original_binding = outer.outer_cap_binding().expect("original cap binding");
    let mut previous_owner = None;
    for _ in 0..2 {
        let borrowed = constrained
            .start(&preparation_scenario(), None)
            .expect("fresh independent Service borrows the unchanged outer cap");
        let current_owner = borrowed.context().host_ram_owner_id().expect("fresh owner");
        assert_ne!(previous_owner, Some(current_owner));
        assert_eq!(
            borrowed
                .context()
                .host_operation_supervisor()
                .expect("genuine live Service supervisor")
                .outer_cap_binding()
                .expect("same original start and disposition"),
            original_binding
        );
        assert_eq!(
            available(),
            available_before - service_resources.resident_peak_bytes
        );
        borrowed
            .release_after_world_cleanup()
            .expect("actual idle watcher joins before exact Service release");
        assert_eq!(available(), available_before);
        previous_owner = Some(current_owner);
    }

    let uncertain = RetainedTemplateServiceFactory::new(&prepared, &config)
        .start(&preparation_scenario(), None)
        .expect("independently charged pre-node owner");
    let uncertain_owner = uncertain.context().host_ram_owner_id().expect("owner");
    assert!(
        prepared
            .host_operational_registry
            .service_nodes_cleaned(uncertain_owner)
            .expect("no node has been admitted")
    );

    // Native setup may own a cgroup or quota before node admission. Explicit
    // uncertainty must retain the whole charge despite this empty node ledger.
    uncertain.retain_after_unknown_cleanup();
    assert_eq!(
        available(),
        available_before - service_resources.resident_peak_bytes
    );
}

/// Exercises linear finding claims on a genuinely admitted component Service.
/// The root constructor models authenticated selection; no guest or kernel
/// restoration is claimed by this actor/cap/capacity regression.
fn assert_finding_binding_preserves_service(
    service: &mut super::super::hot_fork::retained_service::RetainedTemplateService,
) {
    use crate::executor_supervisor::SelectedExactCheckpointRoot;

    let checkpoint = |byte: u8| {
        ExactCheckpointId::parse(&format!(
            "crucible.executor.exact-checkpoint-root@exact-manifest.6.{}",
            format!("{byte:02x}").repeat(32)
        ))
        .expect("component exact checkpoint id")
    };
    let requested = checkpoint(0x71);
    let foreign = checkpoint(0x72);
    let original_owner = service.context().host_outer_cap_owner();
    let original_limits = service.native_context().resources();
    let supervisor = service
        .context()
        .host_operation_supervisor()
        .expect("original admitted authentication supervisor")
        .clone();
    let original_cap = supervisor.outer_cap_binding().expect("original live cap");

    let mut absent = None;
    assert!(
        service
            .bind_authenticated_finding_debug(requested, &mut absent)
            .is_err()
    );
    assert!(absent.is_none());
    let mut substituted = Some(SelectedExactCheckpointRoot::from_test_checkpoint(foreign));
    assert!(
        service
            .bind_authenticated_finding_debug(requested, &mut substituted)
            .is_err()
    );
    assert!(
        substituted
            .as_ref()
            .is_some_and(|root| root.authorizes(foreign))
    );
    assert_eq!(service.context().resume_checkpoint(), None);
    assert_eq!(service.native_context().resume_checkpoint(), None);
    assert_eq!(
        supervisor
            .outer_cap_binding()
            .expect("unchanged original cap"),
        original_cap
    );

    let mut selected = Some(SelectedExactCheckpointRoot::from_test_checkpoint(requested));
    service
        .bind_authenticated_finding_debug(requested, &mut selected)
        .expect("same owner binds the matching linear finding claim");
    assert!(selected.is_none());
    assert_eq!(service.context().resume_checkpoint(), Some(requested));
    assert_eq!(
        service.native_context().resume_checkpoint(),
        Some(requested)
    );
    assert!(service.context().selected_checkpoint_authorizes(requested));
    assert!(
        !service
            .native_context()
            .selected_checkpoint_authorizes(requested)
    );
    assert_eq!(service.context().host_outer_cap_owner(), original_owner);
    assert_eq!(service.native_context().resources(), original_limits);
    assert_eq!(
        supervisor
            .outer_cap_binding()
            .expect("same cap after binding"),
        original_cap
    );
    assert_eq!(
        service
            .native_context()
            .host_operation_supervisor()
            .expect("same physical cap")
            .outer_cap_binding()
            .expect("same original physical start"),
        original_cap,
    );

    let mut repeated = Some(SelectedExactCheckpointRoot::from_test_checkpoint(requested));
    assert!(
        service
            .bind_authenticated_finding_debug(requested, &mut repeated)
            .is_err()
    );
    assert!(
        repeated
            .as_ref()
            .is_some_and(|root| root.authorizes(requested))
    );
    assert!(service.context().selected_checkpoint_authorizes(requested));
}
