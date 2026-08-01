//! Backend-backed executor for QEMU VM realization.

use crucible::{
    AdvanceOutcome, Backend, BackendError, Checkpoint, Configuration, ContentHash, EventLogOffset,
    ExecutionHorizon, Icount, RuntimeState, SchedulerState,
};

use super::{
    QemuBakedGenesisRestoreAdmission, QemuVmRealizationError, QemuVmRealizationExecutor,
    QemuVmReplayRequest, QemuVmSnapshot, validate_checkpoint_matches_config,
    validate_runtime_matches_admission,
};
use crate::{QemuLoadvmCommandAuthorization, QemuLoadvmRealizationAdmission};

/// Adapts a concrete backend into the QEMU realization executor contract.
pub struct QemuBackendRealizationExecutor<B> {
    backend: B,
}

impl<B> QemuBackendRealizationExecutor<B> {
    /// Builds a realization executor over an owned backend.
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<B> QemuVmRealizationExecutor for QemuBackendRealizationExecutor<B>
where
    B: Backend,
{
    fn load_exact_snapshot(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        self.backend
            .restore(&snapshot.checkpoint)
            .map_err(|source| backend_executor_error("restore exact snapshot", source))?;
        let runtime_id = self.backend_runtime_id("sample exact snapshot fingerprint")?;
        let runtime = exact_runtime_from_checkpoint(config, &snapshot.checkpoint, runtime_id)?;
        validate_runtime_matches_admission(&runtime, admission)?;
        Ok(runtime)
    }

    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        _authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        self.backend
            .restore(&snapshot.checkpoint)
            .map_err(|source| backend_executor_error("restore exact snapshot probe", source))?;
        let runtime_id = self.backend_runtime_id("sample exact snapshot probe fingerprint")?;
        exact_runtime_from_checkpoint(config, &snapshot.checkpoint, runtime_id)
    }

    fn load_baked_genesis(
        &mut self,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let snapshot = admission.snapshot();
        self.backend
            .restore(&snapshot.checkpoint)
            .map_err(|source| backend_executor_error("restore baked genesis", source))?;
        let runtime_id = self.backend_runtime_id("sample baked genesis fingerprint")?;
        Ok(runtime_from_scheduled_backend_material(
            config,
            &snapshot.checkpoint,
            runtime_id,
            EventLogOffset::default(),
        ))
    }

    fn replay_one_quantum(
        &mut self,
        runtime: RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<RuntimeState, QemuVmRealizationError> {
        let horizon = replay_horizon_from_runtime(&runtime)?;
        let event_log = runtime.event_log;
        match self
            .backend
            .advance_to_horizon(horizon)
            .map_err(|source| backend_executor_error("advance replay quantum", source))?
        {
            AdvanceOutcome::ReachedHorizon => {}
            AdvanceOutcome::Paused { at } => {
                return Err(QemuVmRealizationError::Executor {
                    operation: "advance replay quantum",
                    message: format!(
                        "backend paused at {} before replay horizon {}",
                        at.retired, horizon.icount.retired
                    ),
                });
            }
        }

        let checkpoint = self
            .backend
            .snapshot()
            .map_err(|source| backend_executor_error("snapshot replay quantum", source))?;
        let runtime_id = self.backend_runtime_id("sample replay quantum fingerprint")?;
        Ok(runtime_from_scheduled_backend_material(
            &request.to,
            &checkpoint,
            runtime_id,
            event_log,
        ))
    }
}

impl<B> QemuBackendRealizationExecutor<B>
where
    B: Backend,
{
    fn backend_runtime_id(
        &mut self,
        operation: &'static str,
    ) -> Result<ContentHash, QemuVmRealizationError> {
        self.backend
            .fingerprint()
            .map(|fingerprint| fingerprint.hash)
            .map_err(|source| backend_executor_error(operation, source))
    }
}

fn exact_runtime_from_checkpoint(
    config: &Configuration,
    checkpoint: &Checkpoint,
    runtime_id: ContentHash,
) -> Result<RuntimeState, QemuVmRealizationError> {
    validate_checkpoint_matches_config(checkpoint, config, "backend realization")?;
    Ok(runtime_from_checkpoint_material(
        config, checkpoint, runtime_id,
    ))
}

fn runtime_from_checkpoint_material(
    config: &Configuration,
    checkpoint: &Checkpoint,
    runtime_id: ContentHash,
) -> RuntimeState {
    let scheduler = checkpoint
        .state
        .as_ref()
        .map(|state| state.scheduler.clone())
        .unwrap_or_else(|| SchedulerState::from_schedule(&config.schedule));
    let event_log = checkpoint
        .state
        .as_ref()
        .map(|state| state.event_log)
        .unwrap_or_default();
    RuntimeState {
        id: runtime_id,
        configuration: config.id(),
        node_blobs: checkpoint.node_blobs.clone(),
        node_icounts: checkpoint.node_icounts.clone(),
        scheduler,
        event_log,
    }
}

fn runtime_from_scheduled_backend_material(
    config: &Configuration,
    checkpoint: &Checkpoint,
    runtime_id: ContentHash,
    event_log: EventLogOffset,
) -> RuntimeState {
    RuntimeState {
        id: runtime_id,
        configuration: config.id(),
        node_blobs: checkpoint.node_blobs.clone(),
        node_icounts: checkpoint.node_icounts.clone(),
        scheduler: SchedulerState::from_schedule(&config.schedule),
        event_log,
    }
}

fn replay_horizon_from_runtime(
    runtime: &RuntimeState,
) -> Result<ExecutionHorizon, QemuVmRealizationError> {
    let current = runtime
        .node_icounts
        .values()
        .map(|icount| icount.retired)
        .max()
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "derive replay horizon",
            message: String::from("runtime has no restored node instruction counts"),
        })?;
    let retired = current
        .checked_add(1)
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "derive replay horizon",
            message: String::from("current instruction count is already at u64::MAX"),
        })?;
    Ok(ExecutionHorizon {
        icount: Icount { retired },
    })
}

fn backend_executor_error(operation: &'static str, source: BackendError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation,
        message: source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use crucible::{
        BackendInput, CheckpointKind, ControlFaultAction, ControlFaultDecision, Decision,
        ExecutionFingerprint, Fault, FaultTag, MaterializedState, NodeBlobRef, NodeFault, NodeId,
        RestartPolicy, RngDecision, RngStreamId, ScenarioDef, Schedule, World,
    };

    use super::*;
    use crate::savevm_policy::validate_loadvm_realized_runtime;
    use crate::{
        QemuBakedGenesisSnapshot, QemuCachedAncestor, QemuReplayOracleValidation,
        QemuSavevmPolicyError, QemuVmLoadvmAdmissionPolicy, QemuVmRealizationStore, resume_qemu_vm,
    };

    type SharedLog = Rc<RefCell<Vec<RealizationCall>>>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum RealizationCall {
        ExactSnapshot(ContentHash),
        NearestAncestor(ContentHash),
        BakedGenesis(ContentHash),
        BackendRestore(ContentHash),
        BackendAdvance(u64),
        BackendSnapshot,
        BackendFingerprint,
    }

    struct ScriptedStore {
        log: SharedLog,
        exact_snapshots: Vec<(ContentHash, QemuVmSnapshot)>,
        ancestors: Vec<(ContentHash, QemuCachedAncestor)>,
        baked: QemuBakedGenesisSnapshot,
    }

    struct ScriptedBackend {
        log: SharedLog,
        fingerprints: Vec<ContentHash>,
        snapshots: Vec<Checkpoint>,
    }

    #[derive(Clone, Copy)]
    struct AdmittingLoadvmPolicy;

    impl QemuVmRealizationStore for ScriptedStore {
        fn exact_snapshot(
            &mut self,
            config: &Configuration,
        ) -> Result<Option<QemuVmSnapshot>, QemuVmRealizationError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::ExactSnapshot(config.id()));
            Ok(self
                .exact_snapshots
                .iter()
                .find(|(id, _)| *id == config.id())
                .map(|(_, snapshot)| snapshot.clone()))
        }

        fn nearest_cached_ancestor(
            &mut self,
            config: &Configuration,
        ) -> Result<Option<QemuCachedAncestor>, QemuVmRealizationError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::NearestAncestor(config.id()));
            Ok(self
                .ancestors
                .iter()
                .find(|(id, _)| *id == config.id())
                .map(|(_, ancestor)| ancestor.clone()))
        }

        fn baked_genesis(
            &mut self,
            world: &World,
            _def: &ScenarioDef,
        ) -> Result<QemuBakedGenesisSnapshot, QemuVmRealizationError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::BakedGenesis(world.id));
            Ok(self.baked.clone())
        }
    }

    impl Backend for ScriptedBackend {
        fn advance_to_horizon(
            &mut self,
            horizon: ExecutionHorizon,
        ) -> Result<AdvanceOutcome, BackendError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::BackendAdvance(horizon.icount.retired));
            Ok(AdvanceOutcome::ReachedHorizon)
        }

        fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::BackendFingerprint);
            let hash = if self.fingerprints.is_empty() {
                hash("backend-fingerprint", "scripted")
            } else {
                self.fingerprints.remove(0)
            };
            Ok(ExecutionFingerprint { hash })
        }

        fn deliver_input(&mut self, _input: BackendInput) -> Result<(), BackendError> {
            Ok(())
        }

        fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
            self.log.borrow_mut().push(RealizationCall::BackendSnapshot);
            if self.snapshots.is_empty() {
                Err(BackendError::NotImplemented {
                    operation: "scripted backend snapshot",
                })
            } else {
                Ok(self.snapshots.remove(0))
            }
        }

        fn restore(&mut self, checkpoint: &Checkpoint) -> Result<(), BackendError> {
            self.log
                .borrow_mut()
                .push(RealizationCall::BackendRestore(checkpoint.id));
            Ok(())
        }

        fn shutdown(&mut self) -> Result<(), BackendError> {
            Ok(())
        }
    }

    impl QemuVmLoadvmAdmissionPolicy for AdmittingLoadvmPolicy {
        fn authorize_baked_genesis_runtime(self) -> QemuLoadvmCommandAuthorization {
            QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test()
        }

        fn authorize_loadvm_runtime(
            self,
        ) -> Result<QemuLoadvmCommandAuthorization, QemuSavevmPolicyError> {
            Ok(QemuLoadvmCommandAuthorization::runtime_realization_for_test())
        }

        fn accept_loadvm_realized_runtime(
            self,
            validation: QemuReplayOracleValidation,
        ) -> Result<QemuLoadvmRealizationAdmission, QemuSavevmPolicyError> {
            validate_loadvm_realized_runtime(validation)
        }
    }

    #[test]
    fn qemu_backend_realization_executor_restores_exact_snapshot()
    -> Result<(), QemuVmRealizationError> {
        let log = shared_log();
        let world = world("backend-exact-loadvm");
        let def = scenario("backend-exact-loadvm");
        let config = config_with_decisions(def.clone(), 1);
        let snapshot = QemuVmSnapshot {
            checkpoint: checkpoint_for_config("backend-exact-loadvm", &config),
            replay_oracle_validation: QemuReplayOracleValidation::Match {
                runtime_hash: config.id(),
            },
        };
        let mut store = scripted_store(Rc::clone(&log), &world);
        store.exact_snapshots.push((config.id(), snapshot.clone()));
        let backend = scripted_backend(Rc::clone(&log), vec![config.id()], Vec::new());
        let mut executor = QemuBackendRealizationExecutor::new(backend);

        let realization = resume_qemu_vm(
            &world,
            &config,
            &mut store,
            &mut executor,
            AdmittingLoadvmPolicy,
        )?;

        assert_eq!(realization.runtime.configuration, config.id());
        assert_eq!(
            logged(&log),
            vec![
                RealizationCall::ExactSnapshot(config.id()),
                RealizationCall::BackendRestore(snapshot.checkpoint.id),
                RealizationCall::BackendFingerprint,
            ]
        );

        Ok(())
    }

    #[test]
    fn qemu_backend_realization_executor_replays_from_cached_ancestor()
    -> Result<(), QemuVmRealizationError> {
        let log = shared_log();
        let world = world("backend-ancestor-replay");
        let def = scenario("backend-ancestor-replay");
        let ancestor = config_with_decisions(def.clone(), 1);
        let target = Configuration {
            def: def.clone(),
            schedule: ancestor.schedule.clone().appended(control_fault_decision()),
        };
        let ancestor_checkpoint = checkpoint_with_qemu_icount(
            checkpoint_for_config("backend-ancestor-replay", &ancestor),
            41,
        );
        let replay_checkpoint = checkpoint_with_qemu_icount(
            checkpoint_for_config("backend-ancestor-replay-target", &target),
            42,
        );
        let ancestor_snapshot = QemuVmSnapshot {
            checkpoint: ancestor_checkpoint,
            replay_oracle_validation: QemuReplayOracleValidation::Match {
                runtime_hash: ancestor.id(),
            },
        };
        let mut store = scripted_store(Rc::clone(&log), &world);
        store
            .exact_snapshots
            .push((ancestor.id(), ancestor_snapshot.clone()));
        store.ancestors.push((
            target.id(),
            QemuCachedAncestor {
                configuration: ancestor.clone(),
                checkpoint: ancestor_snapshot.checkpoint.clone(),
            },
        ));
        let backend = scripted_backend(
            Rc::clone(&log),
            vec![ancestor.id(), target.id()],
            vec![replay_checkpoint.clone()],
        );
        let mut executor = QemuBackendRealizationExecutor::new(backend);

        let realization = resume_qemu_vm(
            &world,
            &target,
            &mut store,
            &mut executor,
            AdmittingLoadvmPolicy,
        )?;

        assert_eq!(realization.runtime.configuration, target.id());
        assert_eq!(realization.runtime.node_blobs, replay_checkpoint.node_blobs);
        assert_eq!(
            realization.runtime.node_icounts,
            replay_checkpoint.node_icounts
        );
        assert_eq!(
            realization.runtime.scheduler,
            SchedulerState::from_schedule(&target.schedule)
        );
        assert_eq!(
            logged(&log),
            vec![
                RealizationCall::ExactSnapshot(target.id()),
                RealizationCall::NearestAncestor(target.id()),
                RealizationCall::ExactSnapshot(ancestor.id()),
                RealizationCall::BackendRestore(ancestor_snapshot.checkpoint.id),
                RealizationCall::BackendFingerprint,
                RealizationCall::BackendAdvance(42),
                RealizationCall::BackendSnapshot,
                RealizationCall::BackendFingerprint,
            ]
        );
        let genesis = Configuration::genesis(scenario("backend-baked-genesis"));
        let baked = store.baked.clone();
        let baked_admission = QemuBakedGenesisRestoreAdmission::new(
            &baked,
            &world,
            QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
        )?;
        let baked_runtime = executor.load_baked_genesis(&genesis, baked_admission)?;
        assert_eq!(baked_runtime.configuration, genesis.id());

        Ok(())
    }

    fn scripted_store(log: SharedLog, world: &World) -> ScriptedStore {
        ScriptedStore {
            log,
            exact_snapshots: Vec::new(),
            ancestors: Vec::new(),
            baked: QemuBakedGenesisSnapshot {
                world_id: world.id,
                checkpoint: Checkpoint::with_node_blobs(
                    hash("checkpoint", "baked-genesis"),
                    hash("configuration", "baked-by-executor"),
                    CheckpointKind::Fat,
                    BTreeMap::new(),
                ),
            },
        }
    }

    fn scripted_backend(
        log: SharedLog,
        fingerprints: Vec<ContentHash>,
        snapshots: Vec<Checkpoint>,
    ) -> ScriptedBackend {
        ScriptedBackend {
            log,
            fingerprints,
            snapshots,
        }
    }

    fn shared_log() -> SharedLog {
        Rc::new(RefCell::new(Vec::new()))
    }

    fn logged(log: &SharedLog) -> Vec<RealizationCall> {
        log.borrow().clone()
    }

    fn world(name: &str) -> World {
        World::from_content_hash(hash("world", name))
    }

    fn scenario(name: &str) -> ScenarioDef {
        ScenarioDef::from_canonical_material("crucible.test.qemu.backend-executor", name)
    }

    fn config_with_decisions(def: ScenarioDef, count: usize) -> Configuration {
        let mut schedule = Schedule::empty();
        for value in 0..count {
            schedule = schedule.appended(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name(format!("stream-{value}")),
                value: value as u64,
            }));
        }
        Configuration { def, schedule }
    }

    fn checkpoint_for_config(name: &str, config: &Configuration) -> Checkpoint {
        Checkpoint::with_node_blobs(
            hash("checkpoint", name),
            config.id(),
            CheckpointKind::Fat,
            qemu_materialized_node_blobs(config),
        )
    }

    fn checkpoint_with_qemu_icount(mut checkpoint: Checkpoint, retired: u64) -> Checkpoint {
        checkpoint
            .node_icounts
            .insert(qemu_node_id(), Icount { retired });
        checkpoint.state = Some(MaterializedState::from_checkpoint_parts(
            &checkpoint.node_icounts,
            &checkpoint.node_blobs,
        ));
        checkpoint
    }

    fn qemu_materialized_node_blobs(config: &Configuration) -> BTreeMap<NodeId, NodeBlobRef> {
        BTreeMap::from([(
            qemu_node_id(),
            NodeBlobRef::baked(hash(
                "qemu-test-node-blob",
                &format!("config={:?}", config.id().bytes),
            )),
        )])
    }

    fn qemu_node_id() -> NodeId {
        NodeId {
            name: String::from("qemu"),
        }
    }

    fn control_fault_decision() -> Decision {
        Decision::ControlFault(ControlFaultDecision {
            at: Default::default(),
            sequence: 1,
            action: ControlFaultAction::Inject {
                tag: FaultTag::from_name("backend-ancestor-fault"),
                fault: Fault::Node(NodeFault::Crash {
                    node: qemu_node_id(),
                    restart: RestartPolicy::StayDown,
                }),
            },
        })
    }

    fn hash(domain: &str, material: &str) -> ContentHash {
        ContentHash::from_canonical_material(domain, material)
    }
}
