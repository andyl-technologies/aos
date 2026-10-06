//! First-quantum RAM and scheduler identity across independently owned restores.
//!
//! Each lane captures, publishes, and promotes its own accepted execution. The
//! resident oracle materializes its restored RAM before execution; the cold lane
//! reaches its first quantum through the actual authenticated missing-page source.
//! Their selected checkpoint claims and Service caps are never reused.

use super::super::hot_fork_native::{enqueue_promoted_resume, fork_resources, native_repository};
use super::*;
use crate::packaged_qemu_executor::hot_fork::retained_service::RetainedTemplateServiceFactory;
use crate::packaged_qemu_executor::preparation::PackagedPreparation;
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct, RepositoryAttemptWorker,
    decode_crucible_attempt_execution,
};
use crucible_campaign::CampaignExecutorStore;

struct RestoreEvidence {
    boundary: Boundary,
    ram_record: Vec<u8>,
    missing_installs: u64,
    launch_to_first_quantum_ns: u64,
}

#[test]
#[ignore = "requires the isolated AOS paging VM and genuine accepted native promotion"]
fn production_lazy_restore_first_cold_quantum_matches_resident_oracle() {
    let source = paging_scenario();
    let resident = run_lane(&source, "restore-resident", 33_000, false);
    let cold = run_lane(&source, "restore-cold", 33_100, true);

    assert_eq!(resident.boundary, cold.boundary);
    assert_eq!(resident.ram_record, cold.ram_record);
    assert!(cold.missing_installs > 0);
    println!("managed_lazy_restore_first_quantum_identity=true");
    println!("managed_lazy_restore_published_ram_root_identity=true");
    println!(
        "managed_lazy_restore_resident_launch_to_first_quantum_ns={}",
        resident.launch_to_first_quantum_ns
    );
    println!(
        "managed_lazy_restore_missing_installs={}",
        cold.missing_installs
    );
    println!(
        "managed_lazy_restore_cold_launch_to_first_quantum_ns={}",
        cold.launch_to_first_quantum_ns
    );
    println!("managed_lazy_restore_cleanup_before_discharge=true");
    println!("managed_lazy_restore_host_cache=uncontrolled");
    println!("MANAGED_LAZY_RESTORE_NATIVE_PASS");
}

fn run_lane(source: &ScenarioDefForm, lane: &str, project: u32, cold: bool) -> RestoreEvidence {
    environment::with_native_repository_environment(
        lane,
        project,
        |root, storage| native_repository(source, root, storage),
        fork_resources,
        |prepared, config, repository| {
            let available = available_resident(prepared);
            let promoted = accepted_promotion::promote_accepted_checkpoint(
                prepared,
                config,
                Arc::clone(&repository),
                source,
            );
            assert_eq!(available_resident(prepared), available);
            let queued = enqueue_promoted_resume(
                prepared,
                &promoted,
                AssignmentId::from_bytes([if cold { 0xf2 } else { 0xf1 }; 16])
                    .expect("fresh independent resumed assignment"),
            );
            let charge = config
                .assignment_resources()
                .expect("execution vector")
                .resident_peak_bytes;
            assert_eq!(available_resident(prepared), available - charge);
            let store = CampaignExecutorStore::new(repository);
            let mut worker = RepositoryAttemptWorker::new(
                store.clone(),
                RestoreModel {
                    store,
                    config: config.clone(),
                    prepared,
                    checkpoint: promoted.checkpoint,
                    cold,
                    evidence: None,
                },
            );
            let (queued, outcome) = worker.execute(queued).into_parts();
            assert!(matches!(outcome, Err(AttemptWorkerFailure::Canceled(_))));
            assert_eq!(available_resident(prepared), available - charge);
            prepared
                .actor
                .with_supervisor(|actor| {
                    actor
                        .stage_and_reconcile_cancellation(&queued)
                        .map_err(|_| {
                            crucible_api::host_operational::HostOperationalError::Unavailable
                        })
                })
                .expect("durable cancellation after actual restored world cleanup");
            assert_eq!(available_resident(prepared), available);
            worker
                .model_mut()
                .evidence
                .take()
                .expect("completed native first-quantum oracle")
        },
    )
}

struct RestoreModel<'a> {
    store: CampaignExecutorStore,
    config: PackagedQemuExecutorConfig,
    prepared: &'a PackagedPreparation,
    checkpoint: ExactCheckpointId,
    cold: bool,
    evidence: Option<RestoreEvidence>,
}

impl AttemptExecutionModel for RestoreModel<'_> {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        accepted_promotion::extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("authenticated actual scenario and resumed execution basis");
        assert_eq!(context.resume_checkpoint(), Some(self.checkpoint));
        let available = available_resident(self.prepared);
        let mut selected = context.take_selected_checkpoint();
        let service = RetainedTemplateServiceFactory::new(self.prepared, &self.config)
            .start_for_resume(input.scenario(), self.checkpoint, context, &mut selected)
            .expect("fresh Service consumes its own selected checkpoint claim");
        assert!(selected.is_none());
        accepted_promotion::extend_native_operations(service.context());
        let host = LinuxQemuAttemptHostResourceFactory::open(self.config.host.clone())
            .expect("actual containment and operator-installed quota");
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            self.config.lifecycle.clone(),
            ComposedQemuAttemptResourceGuardFactory::new(host),
        );
        let scenario = input.scenario().scenario_def();
        let initial = match input.start() {
            crate::CrucibleResolvedAttemptStart::Branch { parent, .. } => parent,
            _ => input.start().configuration(),
        };
        // This physical wall-clock measurement includes the genuine restore
        // launch, owner discovery and cold-policy request, then stops as soon
        // as the first restored quantum completes. It never affects guest time.
        let restore_started = operational_monotonic_nanoseconds();
        let mut lifecycle = factory
            .begin_resume(
                &self.prepared.checkpoints,
                self.checkpoint,
                crate::QemuExactResumeBasis::new(&scenario, input.scenario(), initial, None),
                service.context(),
            )
            .expect("fresh native lazy restore from the actually promoted CAS root");
        let registry = &self.prepared.host_operational_registry;
        let target = discover_target(registry, service.context());
        if !self.cold {
            // Only the reference lane performs a full native RAM read before
            // execution. The cold lane must preserve its missing-page frontier.
            drop(capture(&mut lifecycle, service.context()));
        } else {
            registry
                .apply_native_qualification_policy(target, 0)
                .expect("actual cold placement beneath the public capability gate");
        }
        let before = status(registry, target);
        let configuration = lifecycle
            .resume_state()
            .expect("restored scheduler cut")
            .into_parts()
            .0;
        QemuFreshAttemptLifecycleOwner::drive_quantum(
            &mut lifecycle,
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
        )
        .expect("first restored quantum with real authenticated kernel missing faults");
        let launch_to_first_quantum_ns = operational_monotonic_nanoseconds()
            .checked_sub(restore_started)
            .expect("monotonic operational restore measurement");
        // Observe activity before the oracle capture can materialize other pages.
        let after = status(registry, target);
        let missing_installs = after
            .activity
            .expect("actual native counters")
            .successful_missing_installs
            .checked_sub(
                before
                    .activity
                    .expect("pre-quantum native counters")
                    .successful_missing_installs,
            )
            .expect("monotonic owner-local successful installation counters");
        if self.cold {
            assert!(
                missing_installs > 0,
                "first quantum must actually fault on cold RAM"
            );
        }
        assert_eq!(before.admitted_resources, after.admitted_resources);
        assert_eq!(before.reservation_revision, after.reservation_revision);
        let observed_boundary = boundary(&mut lifecycle);
        let closure = capture(&mut lifecycle, service.context());
        let ram_record = closure.ram_sources()[0].root().record().encode();
        drop(closure);

        QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
            .expect("actual restored process reap and source worker joins");
        service
            .release_after_world_cleanup()
            .expect("cleanup-bound Service discharge");
        assert_eq!(available_resident(self.prepared), available);
        self.evidence = Some(RestoreEvidence {
            boundary: observed_boundary,
            ram_record,
            missing_installs,
            launch_to_first_quantum_ns,
        });
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "operator cancellation after completed native cold-restore oracle",
        )))
    }
}

pub(super) fn capture(
    lifecycle: &mut ProductionVmLifecycleLoop,
    context: &AttemptExecutionContext,
) -> crucible_api::vm_lifecycle::ProductionExactCheckpointClosure {
    let operation = context
        .host_operation_supervisor()
        .expect("original Service cap")
        .begin(HostOperationClass::CheckpointCapture)
        .expect("original finite capture operation");
    let closure = lifecycle
        .capture_portable_exact_checkpoint_with_boundary(&mut || {
            operation.wait_slice().map(|_| ()).map_err(|error| {
                SchedulerError::OperationalBoundary {
                    class: crucible::SchedulerOperationalFailureClass::Terminal,
                    message: error.to_string(),
                }
            })
        })
        .expect("actual frozen RAM capture under the original Service cap");
    operation
        .complete()
        .expect("completed capture without renewing the outer cap");
    closure
}

fn available_resident(prepared: &PackagedPreparation) -> u64 {
    prepared
        .actor
        .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
        .expect("actual capacity actor")
}

pub(super) fn discover_target(
    registry: &crate::HostOperationalRegistry,
    context: &AttemptExecutionContext,
) -> HostRamTarget {
    match registry
        .execute(
            OPERATOR,
            HostOperationalRequest::ListTargets {
                target: HostRamOwnerTarget {
                    daemon_epoch: context.host_daemon_epoch(),
                    owner_id: context.host_ram_owner_id().expect("actual restored owner"),
                },
                after: None,
                limit: 2,
            },
        )
        .expect("actual restored arena discovery")
        .value()
    {
        HostOperationalResponse::Targets { targets, next, .. } => {
            assert_eq!(targets.len(), 1);
            assert!(next.is_none());
            targets[0]
        }
        other => panic!("unexpected restored target response {other:?}"),
    }
}

// Operational duration is evidence only; it never advances guest virtual time.
fn operational_monotonic_nanoseconds() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .expect("positive operational monotonic seconds")
        .checked_mul(1_000_000_000)
        .and_then(|seconds| {
            seconds.checked_add(u64::try_from(now.tv_nsec).expect("positive nanoseconds"))
        })
        .expect("bounded operational clock")
}
