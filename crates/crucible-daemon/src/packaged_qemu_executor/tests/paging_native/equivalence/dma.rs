//! Holds a genuine virtqueue completion while the original controller requests reclaim.
//!
//! The shared-memory backend copies transport bytes, but its virtio caller owns
//! the mapped element until actual completion pushes the used descriptor. This
//! flight requires the native inventory to witness that separate map lifetime.

use super::*;
use crucible::model::ResolvedFaultTarget;
use crucible_linux_resource::host_supervision::HostOperationGuard;
use crucible_qemu::{
    QemuAsyncDriverRuntimeError, QemuNodeChannelError, QemuTestBlockCompletionObserver,
    QemuTestBlockRequestIdentity, QmpHotForkBlockBarrierState,
};
use std::sync::{Condvar, Mutex};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Armed,
    Held,
    Requested,
    Released,
    Converged,
}

struct State {
    phase: Phase,
    requested_revision: u64,
    original_reservation: u64,
    original_resources: HostResourceVector,
    discards_before: u64,
    held_observations: usize,
    held_bounce_maps: u64,
    released_generation: u64,
}

struct CompletionGate {
    registry: crate::HostOperationalRegistry,
    target: HostRamTarget,
    guard: Arc<HostOperationGuard>,
    state: Mutex<State>,
    completion: Condvar,
    // One admitted allocation precedes the Arc, Mutex and scalar evidence. Every
    // node and worker borrower retains it through actual completion and cleanup.
    _credit: crucible_cas::owned_decode::ResourceLoan,
}

impl QemuTestBlockCompletionObserver for CompletionGate {
    fn before_completion(
        &self,
        _target: &ResolvedFaultTarget,
        _request: QemuTestBlockRequestIdentity,
        _guest_icount: u64,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let mut state = self.state.lock().expect("original completion gate");
        if state.phase != Phase::Armed {
            return Ok(());
        }
        state.phase = Phase::Held;
        while matches!(state.phase, Phase::Held | Phase::Requested) {
            let slice = self.guard.wait_slice().map_err(|error| {
                QemuAsyncDriverRuntimeError::operational_supervision(
                    "hold authentic virtqueue completion",
                    error,
                )
            })?;
            let (next, _) = self
                .completion
                .wait_timeout(state, slice.min(Duration::from_millis(1)))
                .expect("original completion condition");
            state = next;
        }
        Ok(())
    }

    fn observation_guard(&self) -> Option<Arc<HostOperationGuard>> {
        let state = self.state.lock().expect("original observation state");
        (!matches!(state.phase, Phase::Armed | Phase::Converged)).then(|| Arc::clone(&self.guard))
    }

    fn observe_native(
        &self,
        report: &QmpHotForkBlockBarrierState,
    ) -> Result<(), QemuNodeChannelError> {
        let maps = report.ram_borrowers();
        assert!(maps.consistent && maps.paging_requested);
        let mut state = self.state.lock().expect("genuine held request state");
        let observed = status(&self.registry, self.target);
        assert_eq!(observed.reservation_revision, state.original_reservation);
        assert_eq!(observed.admitted_resources, state.original_resources);
        assert!(!matches!(
            observed.convergence,
            crucible_api::host_operational::HostRamConvergence::Failed
                | crucible_api::host_operational::HostRamConvergence::Quarantined
        ));
        match state.phase {
            Phase::Held => {
                assert_eq!(
                    maps.direct_maps, 0,
                    "managed buffers use native bounce maps"
                );
                assert!(
                    maps.bounce_maps > 0,
                    "the actual virtqueue map must remain borrowed"
                );
                state.held_bounce_maps = maps.bounce_maps;
                state.discards_before = observed
                    .activity
                    .expect("real native activity")
                    .physical_discards;
                let previous_revision = observed.policy_revision;
                drop(observed);
                self.registry
                    .apply_native_qualification_policy(self.target, 0)
                    .expect("same controller accepts reclaim without reducing its complete peak");
                let requested = status(&self.registry, self.target);
                assert_eq!(requested.policy_revision, previous_revision + 1);
                assert!(requested.applied_policy_revision < requested.policy_revision);
                state.requested_revision = requested.policy_revision;
                state.phase = Phase::Requested;
            }
            Phase::Requested => {
                assert!(maps.bounce_maps > 0);
                assert_eq!(observed.policy_revision, state.requested_revision);
                assert!(observed.applied_policy_revision < state.requested_revision);
                assert_eq!(
                    observed
                        .activity
                        .expect("real held cut activity")
                        .physical_discards,
                    state.discards_before,
                    "no physical discard while the native map is borrowed"
                );
                assert!(observed.placement_receipt.is_none());
                state.held_observations += 1;
                if state.held_observations == 3 {
                    state.phase = Phase::Released;
                    self.completion.notify_one();
                }
            }
            Phase::Released => {
                if maps.direct_maps == 0
                    && maps.bounce_maps == 0
                    && observed.applied_policy_revision == state.requested_revision
                    && observed
                        .activity
                        .expect("actual applied reclaim")
                        .physical_discards
                        > state.discards_before
                {
                    state.released_generation = maps.generation;
                    state.phase = Phase::Converged;
                }
            }
            Phase::Armed | Phase::Converged => {}
        }
        Ok(())
    }
}

pub(crate) fn run(source: ScenarioDefForm, lifecycle: ProductionVmLifecycleConfig) {
    assert_eq!(
        source.world().vm_nodes().len(),
        1,
        "one original native map inventory"
    );
    let mut reference = None;
    for (ordinal, held) in [false, true].into_iter().enumerate() {
        let lane = if held { "dma-held" } else { "dma-reference" };
        let catalog = environment::NativeCatalogBudget {
            resources: HostResourceVector {
                resident_peak_bytes: 512 << 20,
                backing_peak_bytes: 8 << 30,
                metadata_bytes: 256 << 20,
                staging_bytes: 32 << 20,
                paging_io_slots: 1,
                cpu_slots: 1,
                task_slots: 1,
                file_descriptors: 128,
            },
            // Respects the existing bounded inode cleanup contract.
            maximum_inodes: 1_048_576,
            installation_capacity: Some(
                ExecutorCapacity::new(1, 14, 32 << 30, 64 << 30, 150_000)
                    .expect("complete original service/catalog installation"),
            ),
            installation_operational_capacity: Some(
                crate::HostOperationalCapacity::new(32, 4096, 65_536, 8 << 30, 2 << 30)
                    .expect("complete original metadata and staging"),
            ),
        };
        let boundary = environment::with_native_repository_environment_with_catalog(
            lane,
            62_000 + u32::try_from(ordinal).expect("two lanes") * 100,
            catalog,
            |root, storage| native_repository(&source, root, storage),
            |config| resources(config, &source, NativeEquivalenceCase::Origins),
            |prepared, config, repository| {
                install_lifecycle_assets(config, &lifecycle)
                    .expect("admitted catalog owns native lifecycle assets");
                let before = available_resources(prepared);
                let result = run_capture(prepared, config, &source, |context| {
                    extend_native_operations(context);
                    let scope = context
                        .host_operation_supervisor()
                        .expect("same original Service cap");
                    let credit = repository
                        .blob_backend()
                        .metadata_resources()
                        .expect("same admitted operator metadata authority")
                        .reserve_resources(
                            0,
                            u64::try_from(
                                std::mem::size_of::<CompletionGate>()
                                    + std::mem::size_of::<GateSlot>()
                                    + std::mem::size_of::<HostOperationGuard>()
                                    + 6 * std::mem::size_of::<usize>(),
                            )
                            .expect("audited scalar gate allocation"),
                        )
                        .expect("precharged original observer custody");
                    let guard = Arc::new(
                        scope
                            .begin(HostOperationClass::Quiescence)
                            .expect("original finite quiescence before any request hold"),
                    );
                    let original = config
                        .admitted_lifecycle_config()
                        .expect("original catalog admits the lifecycle projection");
                    // The gate is armed after native registration and before the first quantum.
                    // A small shared slot lets construction install the same real observer.
                    let gate_slot = Arc::new(GateSlot {
                        gate: Mutex::new(None),
                        _credit: credit.clone(),
                    });
                    let configured = if held {
                        original.with_block_completion_observer_for_test(gate_slot.clone())
                    } else {
                        original
                    };
                    let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
                        .expect("actual full cgroup and project quota vector");
                    let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
                        configured,
                        ComposedQemuAttemptResourceGuardFactory::new(host),
                    );
                    let mut running = factory
                        .begin_fresh(&source.scenario_def(), &source, context)
                        .expect("actual independently admitted native Service");
                    let target = super::super::faults::discover_target(
                        &prepared.host_operational_registry,
                        context,
                    );
                    let initial = status(&prepared.host_operational_registry, target);
                    if held {
                        *gate_slot.gate.lock().expect("original observer slot") =
                            Some(Arc::new(CompletionGate {
                                registry: prepared.host_operational_registry.clone(),
                                target,
                                guard: Arc::clone(&guard),
                                state: Mutex::new(State {
                                    phase: Phase::Armed,
                                    requested_revision: 0,
                                    original_reservation: initial.reservation_revision,
                                    original_resources: initial.admitted_resources,
                                    discards_before: 0,
                                    held_observations: 0,
                                    held_bounce_maps: 0,
                                    released_generation: 0,
                                }),
                                completion: Condvar::new(),
                                _credit: credit.clone(),
                            }));
                    }
                    drop(initial);
                    let boundary = drive_to_depth(&mut running, &source, 0, context);
                    if held {
                        let gate = gate_slot
                            .gate
                            .lock()
                            .expect("same retained gate")
                            .as_ref()
                            .expect("actual armed gate")
                            .clone();
                        let state = gate.state.lock().expect("actual final map evidence");
                        assert!(state.phase == Phase::Converged);
                        assert!(state.held_bounce_maps > 0 && state.released_generation > 0);
                        assert_eq!(state.held_observations, 3);
                    }
                    running
                        .shutdown()
                        .expect("actual native reap and source/service join");
                    drop(running);
                    drop(factory);
                    drop(gate_slot);
                    guard
                        .complete()
                        .expect("original finite operation completes after cleanup");
                    Ok(boundary)
                })
                .expect("same original service reservation reconciles after physical close");
                assert_eq!(
                    available_resources(prepared),
                    before,
                    "all eight dimensions restored"
                );
                result
            },
        );
        if let Some(reference) = &reference {
            assert_eq!(
                &boundary, reference,
                "held DMA completion preserves the canonical guest boundary"
            );
        } else {
            reference = Some(boundary);
        }
    }
    println!("dma_borrowers_actual_mapped_virtqueue_retained=true");
    println!("dma_borrowers_policy_pending_without_cut_until_completion=true");
    println!("dma_borrowers_real_completion_zero_maps_and_convergence=true");
    println!("dma_borrowers_canonical_guest_boundary_and_full_cleanup=true");
    println!("MANAGED_DMA_BORROWERS_NATIVE_PASS");
}

struct GateSlot {
    gate: Mutex<Option<Arc<CompletionGate>>>,
    _credit: crucible_cas::owned_decode::ResourceLoan,
}

impl GateSlot {
    fn gate(&self) -> Option<Arc<CompletionGate>> {
        self.gate
            .lock()
            .expect("pre-admitted observer slot")
            .clone()
    }
}

impl QemuTestBlockCompletionObserver for GateSlot {
    fn before_completion(
        &self,
        target: &ResolvedFaultTarget,
        request: QemuTestBlockRequestIdentity,
        guest_icount: u64,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.gate().map_or(Ok(()), |gate| {
            gate.before_completion(target, request, guest_icount)
        })
    }

    fn observation_guard(&self) -> Option<Arc<HostOperationGuard>> {
        self.gate().and_then(|gate| gate.observation_guard())
    }

    fn observe_native(
        &self,
        report: &QmpHotForkBlockBarrierState,
    ) -> Result<(), QemuNodeChannelError> {
        self.gate()
            .map_or(Ok(()), |gate| gate.observe_native(report))
    }
}
