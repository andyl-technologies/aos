//! Native child RAM staging under independently admitted service and execution owners.
//!
//! This flight consumes a real queued assignment through the repository worker.
//! Guest RAM comparisons use actual native captures; descriptor setup, cancellation,
//! child reap, source rollback, and capacity discharge use production ownership.

use super::paging_native::environment::{OPERATOR, with_native_repository_environment};
use super::*;
use crate::packaged_qemu_executor::hot_fork::retained_service::RetainedTemplateServiceFactory;
use crate::packaged_qemu_executor::preparation::PackagedPreparation;
use crate::qemu_hot_fork_world_factory::{
    QemuHotForkSourceWorldKey, QemuHotForkWorldLifecycleFactory, QemuHotForkWorldLifecycleStart,
    QemuSingleHotForkSourceWorldProvider,
};
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct,
    AttemptExecutionReconciliationStep, ComposedQemuAttemptResourceGuardFactory,
    QemuAttemptProductionVmLifecycleFactory, QemuProductionHotForkWorldLifecycleFactory,
    RepositoryAttemptWorker, decode_crucible_attempt_execution,
    encode_crucible_configuration_artifact, encode_crucible_scenario_artifact,
};
use crucible_api::host_operational::{
    HostOperationalControl, HostOperationalRequest, HostOperationalResponse, HostRamActivity,
    HostRamOwnerTarget, HostRamStatus, HostResourceVector,
};
use crucible_campaign::{
    AttemptRetentionPolicyDisposition, CampaignExecutorStore, ExecutorResumeService,
};
use crucible_linux_resource::host_supervision::{HostOperationBudget, HostOperationClass};
use crucible_qemu::{QemuAsyncDriverPolicy, QemuShutdownPolicy};

#[test]
#[ignore = "requires the isolated six-CPU AOS paging VM and actual native fork support"]
fn production_managed_hot_fork_preserves_ram_and_reaps_fresh_child() {
    let source = native_scenario();
    let evidence = with_native_repository_environment(
        "fork",
        32_000,
        |root, storage| native_repository(&source, root, storage),
        fork_resources,
        |prepared, config, repository| run_flight(prepared, config, repository, source.clone()),
    );
    publish_flight_evidence(evidence);
    println!("MANAGED_HOT_FORK_CHILD_NATIVE_PASS");
}

pub(super) fn fork_resources(mut config: PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig {
    // Registry and catalog each own one CPU; the source and child each retain
    // their complete two-CPU entitlement throughout the overlapping interval.
    config.capacity = ExecutorCapacity::new(1, 6, 2 << 30, 4 << 30, 150_000)
        .expect("independent source and child capacity in the six-CPU outer VM");
    let catalog = config
        .ram_catalog()
        .expect("independently admitted RAM catalog");
    let mut catalog_resources = catalog.resources();
    // The restored source and both native capture roots can coexist. Each
    // independent decode retains its own metadata loan until its last reader.
    catalog_resources.resident_peak_bytes = 160 * 1024 * 1024;
    catalog_resources.metadata_bytes = 96 * 1024 * 1024;
    let fork_catalog = PackagedRamCatalogConfig::new(
        catalog.root(),
        catalog.project_id(),
        catalog.maximum_inodes(),
        catalog_resources,
        catalog.maximum_sqlite_heap_bytes(),
    )
    .expect("three independently decoded RAM roots fit the catalog service");
    config = config
        .with_ram_catalog(fork_catalog)
        .expect("fork catalog retains the operator-installed physical quota");

    config
        .with_retained_template_resources(HostResourceVector {
            resident_peak_bytes: 513 * 1024 * 1024,
            backing_peak_bytes: 1024 * 1024 * 1024,
            metadata_bytes: 128 * 1024 * 1024,
            staging_bytes: 16 * 1024 * 1024,
            paging_io_slots: 1,
            cpu_slots: 2,
            task_slots: 69,
            file_descriptors: 1056,
        })
        .expect("complete independently authored retained-template entitlement")
}

fn run_flight(
    prepared: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    repository: Arc<CampaignRepository>,
    source: ScenarioDefForm,
) -> NativeForkEvidence {
    let available_before = available_resources(prepared);
    let promoted = super::paging_native::accepted_promotion::promote_accepted_checkpoint(
        prepared,
        config,
        Arc::clone(&repository),
        &source,
    );
    assert_eq!(available_resources(prepared), available_before);

    let queued = enqueue_promoted_resume(
        prepared,
        &promoted,
        AssignmentId::from_bytes([0xe2; 16]).expect("fresh resumed assignment identity"),
    );
    let child_charge = config.assignment_resources().expect("child vector");
    assert_resource_charge(
        available_before,
        available_resources(prepared),
        child_charge,
    );

    let store = CampaignExecutorStore::new(repository);
    let mut worker = RepositoryAttemptWorker::new(
        store.clone(),
        NativeForkModel {
            store,
            config: config.clone(),
            prepared,
            checkpoint: promoted.checkpoint,
            completed: false,
            evidence: None,
        },
    );
    let (queued, result) = worker.execute(queued).into_parts();
    assert!(matches!(result, Err(AttemptWorkerFailure::Canceled(_))));
    assert!(
        worker.model().completed,
        "worker must reach native child and source cleanup"
    );
    assert_resource_charge(
        available_before,
        available_resources(prepared),
        child_charge,
    );
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .stage_and_reconcile_cancellation(&queued)
                .map_err(|_| crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("durable cancellation after both native worlds have stopped");
    assert_eq!(available_resources(prepared), available_before);
    worker
        .model_mut()
        .evidence
        .take()
        .expect("verified native fork evidence")
}

/// Enqueues a fresh real execution with its durable promoted root authority.
pub(super) fn enqueue_promoted_resume(
    prepared: &PackagedPreparation,
    promoted: &super::paging_native::accepted_promotion::AcceptedPromotion,
    assignment_id: AssignmentId,
) -> crate::executor_supervisor::QueuedAttempt {
    let original = &promoted.request;
    let assignment = SubmitAttemptRequest::new(
        assignment_id,
        original.daemon_epoch(),
        original.lineage(),
        original.attempt(),
        original.resources(),
        original.retention(),
        original.retention_policy(),
    )
    .expect("original semantic and retention basis for a fresh execution");
    let resume = crucible_campaign::ResumeAttemptExecutionRequest::new(
        &assignment,
        promoted.prior_execution,
        promoted.checkpoint,
    )
    .expect("authenticated actual paused execution and promoted root");
    prepared
        .actor
        .with_supervisor(|actor| {
            let accepted = actor
                .resume_attempt_execution(&resume)
                .map_err(|_| crucible_api::host_operational::HostOperationalError::Unavailable)?;
            assert!(matches!(
                accepted.disposition(),
                crucible_campaign::ResumeAttemptExecutionDisposition::Accepted { .. }
            ));
            actor
                .next_queued()
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("durable actual resume admission and linear selected-root ownership")
}

struct NativeForkEvidence {
    topology: String,
    source_root: String,
    changed_root: String,
    activity: HostRamActivity,
}

struct NativeForkModel<'a> {
    store: CampaignExecutorStore,
    config: PackagedQemuExecutorConfig,
    prepared: &'a PackagedPreparation,
    checkpoint: ExactCheckpointId,
    completed: bool,
    evidence: Option<NativeForkEvidence>,
}

impl AttemptExecutionModel for NativeForkModel<'_> {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        assert!(context.host_ram_owner_id().is_some());
        assert!(context.host_operation_supervisor().is_some());
        allow_nested_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("real repository scenario, configuration and execution basis");
        assert_eq!(context.resume_checkpoint(), Some(self.checkpoint));
        let available_with_child = available_resources(self.prepared);
        let mut selected = context.take_selected_checkpoint();
        let service = Arc::new(
            RetainedTemplateServiceFactory::new(self.prepared, &self.config)
                .start_for_resume(input.scenario(), self.checkpoint, context, &mut selected)
                .expect("independent Service with the actual selected exact root"),
        );
        assert!(
            selected.is_none(),
            "source Service consumes the linear root only on success"
        );
        allow_nested_operations(service.context());
        let source_charge = self
            .config
            .retained_template_resources()
            .expect("source vector");
        assert_resource_charge(
            available_with_child,
            available_resources(self.prepared),
            source_charge,
        );

        let host = LinuxQemuAttemptHostResourceFactory::open(self.config.host.clone())
            .expect("actual source cgroup and project quota");
        let mut resume = QemuAttemptProductionVmLifecycleFactory::new(
            self.config.lifecycle.clone(),
            ComposedQemuAttemptResourceGuardFactory::new(host),
        );
        let scenario = input.scenario().scenario_def();
        let initial_configuration = match input.start() {
            crate::CrucibleResolvedAttemptStart::Branch { parent, .. } => parent,
            _ => input.start().configuration(),
        };
        let mut parent = resume
            .begin_resume(
                &self.prepared.checkpoints,
                self.checkpoint,
                crate::QemuExactResumeBasis::new(
                    &scenario,
                    input.scenario(),
                    initial_configuration,
                    None,
                ),
                service.context(),
            )
            .expect("actual lazy native restore from the promoted CAS-backed root");
        let before = parent
            .capture_portable_exact_checkpoint_with_boundary(&mut || Ok(()))
            .expect("actual immutable restored parent RAM capture");
        let expected_record = before.ram_sources()[0].root().record().encode();
        let source_root = before.ram_sources()[0].root().record().digest().to_string();
        let topology = before.ram_sources()[0]
            .root()
            .record()
            .topology()
            .digest()
            .to_string();
        let world = parent
            .prepare_hot_fork_source_world()
            .expect("native retained source barriers and RAM seal")
            .with_cleanup_observer(service.clone());
        let parent_status = owner_status(self.prepared, service.context());
        assert!(parent_status.target.retained_template);

        let key = QemuHotForkSourceWorldKey::for_execution(
            &input,
            context,
            context
                .runtime_basis()
                .expect("actual accepted Execution incarnation"),
        )
        .expect("exact source lookup binding");
        let provider = QemuSingleHotForkSourceWorldProvider::new(key, world);
        let child_config = child_config(&self.config);
        let host = LinuxQemuAttemptHostResourceFactory::open(child_config.host.clone())
            .expect("actual child containment");
        let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
            provider,
            ComposedQemuAttemptResourceGuardFactory::new(host),
            self.config.lifecycle.run_state_root().join("fork-child"),
            QemuShutdownPolicy {
                control_quit_wait: Duration::from_secs(30),
                qmp_quit_wait: Duration::from_secs(30),
                sigterm_wait: Duration::from_secs(30),
                sigkill_wait: Duration::from_secs(30),
                reap_wait: Duration::from_secs(30),
            },
            QemuAsyncDriverPolicy::new(
                Duration::from_secs(300),
                Duration::from_secs(300),
                Duration::from_secs(300),
                Duration::from_secs(300),
            ),
        );
        let mut child = match factory
            .try_start(&input, context)
            .expect("actual native child fork")
        {
            QemuHotForkWorldLifecycleStart::Started(child) => child,
            QemuHotForkWorldLifecycleStart::Declined => {
                panic!("native source unexpectedly declined")
            }
        };
        let initial = child
            .capture_attempt_checkpoint(context)
            .expect("actual child RAM at its adopted initial boundary")
            .into_closure();
        assert_eq!(
            initial.ram_sources()[0].root().record().encode(),
            expected_record
        );
        drop(initial);
        let initial_status =
            registered_owner_status(&self.prepared.host_operational_registry, context);
        assert!(!initial_status.target.retained_template);
        assert_ne!(
            initial_status.target.owner_id,
            parent_status.target.owner_id
        );
        assert_ne!(
            initial_status.target.arena_generation,
            parent_status.target.arena_generation
        );
        assert_eq!(
            initial_status.target.owner_id,
            context.host_ram_owner_id().expect("child owner")
        );
        self.prepared
            .host_operational_registry
            .apply_native_qualification_policy(initial_status.target, 0)
            .expect("real child paused reclamation beneath the capability gate");
        let configuration = input.start().configuration().clone();
        for _ in 0..16 {
            child
                .drive_quantum(QuantumRequest {
                    configuration: configuration.clone(),
                    control: Vec::new(),
                })
                .expect("first child quantum and independent COW writes");
        }
        let changed = child
            .capture_attempt_checkpoint(context)
            .expect("actual child RAM after execution")
            .into_closure();
        assert_ne!(
            changed.ram_sources()[0].root().record().encode(),
            expected_record
        );
        let changed_root = changed.ram_sources()[0]
            .root()
            .record()
            .digest()
            .to_string();
        drop(changed);
        let after = registered_owner_status(&self.prepared.host_operational_registry, context);
        assert_eq!(after.admitted_resources, initial_status.admitted_resources);
        assert_eq!(
            after.reservation_revision,
            initial_status.reservation_revision
        );
        let activity = after.activity.expect("actual child native fault activity");
        assert!(activity.successful_missing_installs > 0);
        assert!(activity.physical_discards > 0);
        assert_resource_charge(
            available_with_child,
            available_resources(self.prepared),
            source_charge,
        );
        child
            .shutdown()
            .expect("actual child reap and source worker joins");
        let mut reconciled = false;
        for _ in 0..64 {
            if child
                .reconcile_execution_disposition(crate::AttemptExecutionDisposition::Canceled)
                .expect("exact native source-side resource reconciliation")
                == AttemptExecutionReconciliationStep::Complete
            {
                reconciled = true;
                break;
            }
        }
        assert!(reconciled, "native child disposition remained pending");
        assert!(factory.recover(child).is_ok());
        assert_resource_charge(
            available_with_child,
            available_resources(self.prepared),
            source_charge,
        );
        let world = factory
            .source_provider_mut_for_test()
            .take_available()
            .expect("reusable original CAS-backed source");
        let after_child = owner_status(self.prepared, service.context());
        assert_eq!(after_child.target, parent_status.target);
        assert_eq!(
            after_child.admitted_resources,
            parent_status.admitted_resources
        );
        assert_eq!(
            after_child.reservation_revision,
            parent_status.reservation_revision
        );
        let mut parent = world
            .recover()
            .expect("roll back the exact source barriers");
        let after = parent
            .capture_portable_exact_checkpoint_with_boundary(&mut || Ok(()))
            .expect("actual source RAM after child writes");
        assert_eq!(
            before.ram_sources()[0].root().record(),
            after.ram_sources()[0].root().record(),
            "child writes must not modify the retained source RAM",
        );
        drop(after);
        drop(before);
        parent
            .shutdown()
            .expect("source reap, source joins and final FD closure");
        service
            .release_after_world_cleanup()
            .expect("actual source owner discharge");
        assert_eq!(available_resources(self.prepared), available_with_child);
        self.evidence = Some(NativeForkEvidence {
            topology,
            source_root,
            changed_root,
            activity,
        });
        self.completed = true;
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "operator cancellation after completed native fork verification",
        )))
    }
}

fn publish_flight_evidence(evidence: NativeForkEvidence) {
    let artifacts = crate::paging_qualification::artifacts::artifact_hash;
    let kernel_id = crate::paging_qualification::artifacts::kernel_build_id()
        .expect("actual booted kernel GNU build ID");
    let kernel_id = kernel_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let graph = std::env::var("CRUCIBLE_PAGING_BUILD_GRAPH").expect("immutable Nix input graph");
    let receipt = serde_json::json!({
        "edition": 1,
        "host_kernel_build_id": kernel_id,
        "build_graph_sha256": graph,
        "host_kernel_blake3": artifacts(&super::paging_native::environment::environment_path("CRUCIBLE_PAGING_KERNEL")).expect("kernel artifact").to_string(),
        "qemu_blake3": artifacts(&super::paging_native::environment::environment_path("CRUCIBLE_PAGING_QEMU")).expect("QEMU artifact").to_string(),
        "plugin_blake3": artifacts(&super::paging_native::environment::environment_path("CRUCIBLE_PAGING_PLUGIN")).expect("plugin artifact").to_string(),
        "topology_blake3": evidence.topology,
        "source_ram_root": evidence.source_root,
        "changed_child_ram_root": evidence.changed_root,
        "profile": {
            "machine": "pc-q35-9.2", "accelerator": "sim", "thread_mode": "single",
            "architecture": "x86_64", "guest_ram_bytes": 67_108_864,
            "vcpu_count": 1, "page_bytes": 4096, "outer_cpu_slots": 6,
        },
        "operations": {
            "accepted_promotion": true, "cas_lazy_restore": true, "hot_fork": true,
            "initial_ram_identity": true, "child_cow_separation": true,
            "source_ram_preserved": true, "independent_full_peaks_retained": true,
            "cleanup_before_discharge": true, "strict_low_peak": false, "transfer": false,
        },
        "activity": {
            "successful_missing_installs": evidence.activity.successful_missing_installs,
            "physical_discards": evidence.activity.physical_discards,
        },
    });
    println!("managed_hot_fork_receipt={receipt}");
}

fn allow_nested_operations(context: &AttemptExecutionContext) {
    let supervisor = context
        .host_operation_supervisor()
        .expect("actual original cap");
    let (revision, mut budgets) = supervisor.budgets().expect("actual budget roster");
    for class in HostOperationClass::ALL {
        budgets.classes[class as usize] = HostOperationBudget::finite(Duration::from_secs(300));
    }
    supervisor
        .update_budgets(revision, budgets)
        .expect("finite native flight allowances");
}

fn available_resources(prepared: &PackagedPreparation) -> HostResourceVector {
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .host_resource_availability()
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("actual eight-dimensional capacity actor")
}

pub(super) fn assert_resource_charge(
    before: HostResourceVector,
    after: HostResourceVector,
    charge: HostResourceVector,
) {
    macro_rules! assert_dimension {
        ($($dimension:ident),+ $(,)?) => {
            $(assert_eq!(
                before.$dimension.checked_sub(after.$dimension),
                Some(charge.$dimension),
                stringify!($dimension),
            );)+
        };
    }

    assert_dimension!(
        resident_peak_bytes,
        backing_peak_bytes,
        metadata_bytes,
        staging_bytes,
        paging_io_slots,
        cpu_slots,
        task_slots,
        file_descriptors,
    );
}

fn owner_status(
    prepared: &PackagedPreparation,
    context: &AttemptExecutionContext,
) -> HostRamStatus {
    registered_owner_status(&prepared.host_operational_registry, context)
}

fn registered_owner_status(
    registry: &crate::HostOperationalRegistry,
    context: &AttemptExecutionContext,
) -> HostRamStatus {
    let target = match registry
        .execute(
            OPERATOR,
            HostOperationalRequest::ListTargets {
                target: HostRamOwnerTarget {
                    daemon_epoch: context.host_daemon_epoch(),
                    owner_id: context.host_ram_owner_id().expect("actual owner"),
                },
                after: None,
                limit: 2,
            },
        )
        .expect("actual native owner discovery")
    {
        HostOperationalResponse::Targets { targets, next, .. } => {
            assert_eq!(targets.len(), 1);
            assert!(next.is_none());
            targets[0]
        }
        other => panic!("unexpected target discovery {other:?}"),
    };
    match registry
        .execute(OPERATOR, HostOperationalRequest::Status { target })
        .expect("actual native controller status")
    {
        HostOperationalResponse::Status(status) => *status,
        other => panic!("unexpected status {other:?}"),
    }
}

fn child_config(config: &PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig {
    let mut child = config.clone();
    let host = &config.host;
    child.host = LinuxQemuAttemptHostConfig::new(
        super::paging_native::environment::environment_path("CRUCIBLE_PAGING_CGROUP")
            .join("fork-child"),
        super::paging_native::environment::environment_path("CRUCIBLE_PAGING_STORAGE")
            .join("fork-child"),
        "paging-fork-child",
        32_010,
        1,
        host.child_user_id(),
        host.child_group_id(),
        host.maximum_tasks(),
        host.maximum_file_descriptors(),
        host.maximum_node_host_service_tasks(),
        host.maximum_node_host_service_file_descriptors(),
        host.maximum_node_host_service_resident_bytes(),
        host.watcher_service_resident_bytes(),
        host.maximum_inodes(),
        Duration::from_secs(30),
    )
    .expect("independent child project-ID and cgroup namespace");
    child
}

fn native_scenario() -> ScenarioDefForm {
    let world = World::from_nodes(vec![crucible::WorldNode {
        id: NodeId {
            name: "memory".into(),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: 64,
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
    .expect("unmodified AOS Linux guest");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(42),
    )
    .expect("immutable native scenario")
}

pub(super) fn native_repository(
    source: &ScenarioDefForm,
    _root: &std::path::Path,
    storage: super::paging_native::environment::NativeCampaignStorage,
) -> Arc<CampaignRepository> {
    let launch = crucible_qemu::QemuLaunchArtifactIdentity::authenticate(
        super::paging_native::environment::environment_path("CRUCIBLE_PAGING_QEMU"),
        super::paging_native::environment::environment_path("CRUCIBLE_PAGING_PLUGIN"),
    )
    .expect("actual matching native launch artifact markers");
    let repository = Arc::new(CampaignRepository::new(storage.backend, storage.refs));
    let scenario = encode_crucible_scenario_artifact(source).expect("actual scenario encoding");
    let scenario_id = repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .expect("authenticated immutable scenario publication");
    let configuration = encode_crucible_configuration_artifact(
        &scenario,
        &Configuration::genesis(source.scenario_def()).schedule,
    )
    .expect("canonical genesis encoding");
    let configuration_id = repository
        .publish_configuration_artifact(
            scenario.scenario(),
            scenario_id,
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .expect("authenticated immutable genesis publication");
    let lineage = CampaignLineage::new(
        scenario.scenario(),
        scenario_id,
        configuration.configuration(),
        configuration_id,
        "crucible-test",
        launch.qemu_build_id(),
        BTreeMap::from([("control".into(), 1)]),
        scenario.payload_schema(),
        crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
    )
    .expect("real campaign lineage");
    let policy = packaged_policy(scenario.scenario())
        .with_attempt_timeout_policy(
            crucible_campaign::CampaignAttemptTimeoutPolicy::new(
                None,
                Some(50_000),
                Some(1_200_000),
            )
            .expect("finite original assignment watchdog and modeled quantum bound"),
        )
        .expect("canonical policy-keyed operational cap");
    repository
        .create("packaged", &lineage, &policy, &BTreeMap::new())
        .expect("actual authoritative campaign");
    repository
}

pub(super) fn native_request(
    repository: &CampaignRepository,
    config: &PackagedQemuExecutorConfig,
) -> SubmitAttemptRequest {
    let head = repository.head("packaged").expect("actual campaign head");
    let lineage = head.snapshot().lineage();
    let funded = repository
        .apply_control(
            "packaged",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.native-fork.v1",
                    b"fund",
                )),
                expected_snapshot: head.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("attempt budget"),
                ),
            },
        )
        .expect("actual campaign budget");
    repository
        .apply_control(
            "packaged",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.native-fork.v1",
                    b"resume",
                )),
                expected_snapshot: funded.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("actual running campaign");
    let attempt = repository
        .admit_initial_discovery_if_ready("packaged")
        .expect("authoritative attempt admission")
        .expect("initial discovery");
    let retention = repository
        .attempt_retention_policy_basis_at(
            repository
                .head("packaged")
                .expect("admitted campaign head")
                .snapshot_id(),
            attempt,
        )
        .expect("actual admission-bound retention and timeout policy");
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0xe1; 16]).expect("assignment identity"),
        config.daemon_epoch,
        lineage,
        attempt,
        config.assignment_limits().expect("authored request bounds"),
        ExecutionRetentionIntent::Discard,
        AttemptRetentionPolicyDisposition::Required(retention),
    )
    .expect("actual accepted assignment request")
}
