//! Tests for QEMU real-node realization execution.

// crucible-lint: allow panic-shortcut -- fixture setup uses panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::rc::Rc;

use crucible::{
    BackendInput, CheckpointKind, Decision, DecisionRngState, ExecutionFingerprint,
    MaterializedState, NodeBlobRef, ObservableEvent, RngDecision, RngStreamId, ScenarioDef,
    Schedule, SchedulerState, World,
};

use super::*;
use crate::{
    QemuBakedGenesisSnapshot, QemuExactSnapshotPolicy, QemuLoadvmCommandPurpose, QemuNodeChild,
    QemuNodeRestoreAdmission, QemuReplayOracleValidation, QemuShutdownTargetError,
};

type SharedLog = Rc<RefCell<Vec<NodeExecutorCall>>>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum NodeExecutorCall {
    Launch {
        config: ContentHash,
        checkpoint: ContentHash,
        authorization: QemuLoadvmCommandPurpose,
        admission: QemuNodeRestoreAdmission,
    },
    GuardedLaunch {
        config: ContentHash,
        snapshot: ContentHash,
        checkpoint: ContentHash,
    },
    GuardedThinLaunch {
        config: ContentHash,
        checkpoint: ContentHash,
        admission: QemuNodeRestoreAdmission,
    },
    PrepareObservationStream,
    Advance(u64),
    Fingerprint,
    CurrentIcount,
    Seal,
    Capture(ContentHash),
    PrepareHotFork {
        bindings: usize,
        maximum_ring_image_bytes: usize,
    },
    Snapshot,
    Restore,
    Shutdown,
}

struct ScriptedLauncher {
    log: SharedLog,
    runtime_id: ContentHash,
    current_icount: Icount,
}

struct ScriptedNode {
    log: SharedLog,
    runtime_id: ContentHash,
    current_icount: Icount,
    shutdown_event: Option<ObservableEvent>,
}

struct ScriptedGuardedLauncher {
    log: SharedLog,
    snapshot: ContentHash,
    runtime_id: ContentHash,
    current_icount: Icount,
    vmstate: File,
}

struct ScriptedThinLauncher {
    log: SharedLog,
    checkpoint: ContentHash,
    runtime_id: ContentHash,
    current_icount: Icount,
}

impl QemuNodeLauncher for ScriptedLauncher {
    type Node = ScriptedNode;
}

impl QemuHotForkTemplatePreparer for ScriptedNode {
    fn prepare_retained_hot_fork_template(
        &mut self,
        block_snapshot_bindings: &[crate::QmpHotForkBlockSnapshotBinding],
        maximum_ring_image_bytes: usize,
    ) -> Result<(), QemuVmRealizationError> {
        self.log
            .borrow_mut()
            .push(NodeExecutorCall::PrepareHotFork {
                bindings: block_snapshot_bindings.len(),
                maximum_ring_image_bytes,
            });
        if self.runtime_id == ContentHash::from_bytes(b"hot-fork-preparation-failure") {
            return Err(QemuVmRealizationError::Executor {
                operation: "prepare scripted retained hot-fork template",
                message: String::from("injected preparation failure"),
            });
        }
        Ok(())
    }
}

impl QemuNodeRealizationLauncher for ScriptedLauncher {
    fn launch_restored_node(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        self.log.borrow_mut().push(NodeExecutorCall::Launch {
            config: config.id(),
            checkpoint: restore.checkpoint().id,
            authorization: restore.authorization().purpose(),
            admission: restore.admission(),
        });
        Ok(ScriptedNode {
            log: Rc::clone(&self.log),
            runtime_id: self.runtime_id,
            current_icount: self.current_icount,
            shutdown_event: None,
        })
    }
}

impl QemuNodeLauncher for ScriptedGuardedLauncher {
    type Node = ScriptedNode;
}

impl QemuGuardedNodeRealizationLauncher for ScriptedGuardedLauncher {
    fn launch_materialized_exact_node_guarded(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        restore: QemuNodeRestorePlan<'_>,
        _process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        if snapshot.id() != self.snapshot {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "scripted guarded launch",
                message: String::from("snapshot differs from selected exact root"),
            });
        }
        self.log.borrow_mut().push(NodeExecutorCall::GuardedLaunch {
            config: config.id(),
            snapshot: snapshot.id(),
            checkpoint: restore.checkpoint().id,
        });
        Ok(ScriptedNode {
            log: Rc::clone(&self.log),
            runtime_id: self.runtime_id,
            current_icount: self.current_icount,
            shutdown_event: None,
        })
    }
}

impl QemuCapturedVmStateSource for ScriptedGuardedLauncher {
    fn capture_vmstate_after_reap(&self) -> Result<QemuCapturedVmState, QemuVmRealizationError> {
        let logical_length = self
            .vmstate
            .metadata()
            .map_err(|source| QemuVmRealizationError::Executor {
                operation: "inspect scripted captured VMState",
                message: source.to_string(),
            })?
            .len();
        let file = self
            .vmstate
            .try_clone()
            .map_err(|source| QemuVmRealizationError::Executor {
                operation: "duplicate scripted captured VMState",
                message: source.to_string(),
            })?;
        Ok(QemuCapturedVmState::from_unvalidated_test_file(
            file,
            logical_length,
        ))
    }
}

impl QemuNodeLauncher for ScriptedThinLauncher {
    type Node = ScriptedNode;
}

impl QemuGuardedThinNodeRealizationLauncher for ScriptedThinLauncher {
    fn launch_thin_path_node_guarded(
        &mut self,
        config: &Configuration,
        restore: QemuNodeRestorePlan<'_>,
        _process_contract: &QemuChildProcessContract,
    ) -> Result<Self::Node, QemuVmRealizationError> {
        if restore.checkpoint().id != self.checkpoint {
            return Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "scripted guarded thin launch",
                message: String::from("checkpoint differs from prepared thin-path VMState"),
            });
        }
        self.log
            .borrow_mut()
            .push(NodeExecutorCall::GuardedThinLaunch {
                config: config.id(),
                checkpoint: restore.checkpoint().id,
                admission: restore.admission(),
            });
        Ok(ScriptedNode {
            log: Rc::clone(&self.log),
            runtime_id: self.runtime_id,
            current_icount: self.current_icount,
            shutdown_event: None,
        })
    }
}

impl Backend for ScriptedNode {
    fn advance_to_horizon(
        &mut self,
        horizon: crucible::ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        self.current_icount = horizon.icount;
        self.log
            .borrow_mut()
            .push(NodeExecutorCall::Advance(horizon.icount.retired));
        Ok(AdvanceOutcome::ReachedHorizon)
    }

    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
        self.log.borrow_mut().push(NodeExecutorCall::Fingerprint);
        Ok(ExecutionFingerprint {
            hash: self.runtime_id,
        })
    }

    fn deliver_input(&mut self, _input: BackendInput) -> Result<(), BackendError> {
        Ok(())
    }

    fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
        self.log.borrow_mut().push(NodeExecutorCall::Snapshot);
        Err(BackendError::NotImplemented {
            operation: "scripted snapshot",
        })
    }

    fn restore(&mut self, _checkpoint: &Checkpoint) -> Result<(), BackendError> {
        self.log.borrow_mut().push(NodeExecutorCall::Restore);
        Err(BackendError::NotImplemented {
            operation: "scripted restore",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.log.borrow_mut().push(NodeExecutorCall::Shutdown);
        Ok(())
    }
}

impl QemuRealizedNodeBackend for ScriptedNode {
    fn prepare_authoritative_observation_stream(&mut self) -> Result<(), BackendError> {
        self.log
            .borrow_mut()
            .push(NodeExecutorCall::PrepareObservationStream);
        Ok(())
    }

    fn advance_live_to_horizon(
        &mut self,
        horizon: crucible::ExecutionHorizon,
        _event_log: &mut EventLog,
    ) -> Result<AdvanceOutcome, BackendError> {
        Backend::advance_to_horizon(self, horizon)
    }

    fn seal_live_observation_boundary(
        &mut self,
        _event_log: &mut EventLog,
    ) -> Result<(), BackendError> {
        self.log.borrow_mut().push(NodeExecutorCall::Seal);
        Ok(())
    }

    fn capture_live_exact_snapshot_paused(
        &mut self,
        _node: &NodeId,
        checkpoint: Checkpoint,
    ) -> Result<QemuVmSnapshot, BackendError> {
        self.log
            .borrow_mut()
            .push(NodeExecutorCall::Capture(checkpoint.id));
        QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun).map_err(|source| {
            BackendError::Rejected {
                message: source.to_string(),
            }
        })
    }

    fn shutdown_live_with_event_log(
        &mut self,
        event_log: &mut EventLog,
    ) -> Result<(), BackendError> {
        if let Some(event) = self.shutdown_event.take() {
            event_log
                .append_observable_events([event])
                .map_err(|source| BackendError::Rejected {
                    message: source.to_string(),
                })?;
        }
        if self.runtime_id == ContentHash::from_bytes(b"hot-fork-shutdown-failure") {
            return Err(BackendError::Rejected {
                message: String::from("injected retained-template shutdown failure"),
            });
        }
        Backend::shutdown(self)?;
        Ok(())
    }

    fn current_icount(&mut self) -> Result<Icount, BackendError> {
        self.log.borrow_mut().push(NodeExecutorCall::CurrentIcount);
        Ok(self.current_icount)
    }
}

#[test]
fn qemu_node_realization_executor_loads_baked_genesis_before_node_replay()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "baked"));
    let config = Configuration::genesis(scenario("baked"));
    let checkpoint = checkpoint_for_config("baked", &config, &node, 3, CheckpointKind::Fat)?;
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint,
    };
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let runtime_id = hash("runtime", "baked");
    let launcher = scripted_launcher(Rc::clone(&log), runtime_id, 3);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);

    let runtime = executor.load_baked_genesis(&config, admission)?;

    assert_eq!(runtime.id, runtime_id);
    assert_eq!(runtime.configuration, config.id());
    assert_eq!(
        logged(&log),
        vec![
            NodeExecutorCall::Launch {
                config: config.id(),
                checkpoint: baked.checkpoint.id,
                authorization: QemuLoadvmCommandPurpose::BakedGenesisRealization,
                admission: QemuNodeRestoreAdmission::BakedGenesis { world_id: world.id },
            },
            NodeExecutorCall::PrepareObservationStream,
            NodeExecutorCall::Fingerprint,
        ]
    );
    Ok(())
}

#[test]
fn guarded_exact_root_launcher_binds_snapshot_before_runtime_admission()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let config = Configuration::genesis(scenario("guarded-exact-root"));
    let runtime_id = hash("runtime", "guarded-exact-root");
    let checkpoint =
        checkpoint_for_config("guarded-exact-root", &config, &node, 7, CheckpointKind::Fat)?;
    let snapshot = QemuVmSnapshot::diskless(
        checkpoint,
        QemuReplayOracleValidation::Match {
            runtime_hash: runtime_id,
        },
    )?;
    let launcher = ScriptedGuardedLauncher {
        log: Rc::clone(&log),
        snapshot: snapshot.id(),
        runtime_id,
        current_icount: Icount { retired: 7 },
        vmstate: scripted_vmstate(),
    };
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);
    let process_contract = test_process_contract();
    let runtime = executor.resume_materialized_exact_snapshot_guarded(
        &process_contract,
        &config,
        &snapshot,
    )?;

    assert_eq!(runtime.id, runtime_id);
    assert_eq!(runtime.configuration, config.id());
    assert_eq!(
        logged(&log),
        vec![
            NodeExecutorCall::GuardedLaunch {
                config: config.id(),
                snapshot: snapshot.id(),
                checkpoint: snapshot.checkpoint().id,
            },
            NodeExecutorCall::PrepareObservationStream,
            NodeExecutorCall::Fingerprint,
        ]
    );
    Ok(())
}

#[test]
fn exact_checkpoint_artifact_is_lent_only_after_sealed_shutdown()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let config = Configuration::genesis(scenario("captured-artifact"));
    let runtime_id = hash("runtime", "captured-artifact");
    let checkpoint =
        checkpoint_for_config("captured-artifact", &config, &node, 11, CheckpointKind::Fat)?;
    let snapshot = QemuVmSnapshot::diskless(
        checkpoint.clone(),
        QemuReplayOracleValidation::Match {
            runtime_hash: runtime_id,
        },
    )?;
    let launcher = ScriptedGuardedLauncher {
        log: Rc::clone(&log),
        snapshot: snapshot.id(),
        runtime_id,
        current_icount: Icount { retired: 11 },
        vmstate: scripted_vmstate(),
    };
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);
    executor.resume_materialized_exact_snapshot_guarded(
        &test_process_contract(),
        &config,
        &snapshot,
    )?;

    let (captured, vmstate) = executor.capture_exact_checkpoint_artifact(checkpoint.clone())?;
    let mut bytes = vec![
        0_u8;
        usize::try_from(vmstate.logical_length()).map_err(|_| {
            QemuVmRealizationError::Executor {
                operation: "allocate scripted captured VMState",
                message: String::from("captured length does not fit usize"),
            }
        })?
    ];
    let read =
        vmstate
            .read_at(&mut bytes, 0)
            .map_err(|source| QemuVmRealizationError::Executor {
                operation: "read scripted captured VMState",
                message: source.to_string(),
            })?;

    assert_eq!(captured.checkpoint(), &checkpoint);
    assert_eq!(read, bytes.len());
    assert_eq!(bytes, b"scripted stable VMState");
    assert!(!executor.live_backend_is_active());
    let calls = logged(&log);
    let capture = calls
        .iter()
        .position(|call| matches!(call, NodeExecutorCall::Capture(_)))
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "inspect scripted capture ordering",
            message: String::from("capture call missing"),
        })?;
    let shutdown = calls
        .iter()
        .position(|call| matches!(call, NodeExecutorCall::Shutdown))
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "inspect scripted capture ordering",
            message: String::from("shutdown call missing"),
        })?;
    assert!(capture < shutdown);
    Ok(())
}

#[test]
fn guarded_replay_validation_reaps_fat_probe_before_thin_launch()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "guarded-replay-validation"));
    let config = Configuration::genesis(scenario("guarded-replay-validation"));
    let runtime_id = hash("runtime", "guarded-replay-validation");
    let exact = QemuVmSnapshot::diskless(
        checkpoint_for_config(
            "guarded-replay-validation-exact",
            &config,
            &node,
            0,
            CheckpointKind::Fat,
        )?,
        QemuReplayOracleValidation::NotRun,
    )?;
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint: checkpoint_for_config(
            "guarded-replay-validation-thin",
            &config,
            &node,
            0,
            CheckpointKind::Fat,
        )?,
    };
    let exact_launcher = ScriptedGuardedLauncher {
        log: Rc::clone(&log),
        snapshot: exact.id(),
        runtime_id,
        current_icount: Icount { retired: 0 },
        vmstate: scripted_vmstate(),
    };
    let thin_launcher = ScriptedThinLauncher {
        log: Rc::clone(&log),
        checkpoint: baked.checkpoint.id,
        runtime_id,
        current_icount: Icount { retired: 0 },
    };
    let launcher = QemuReplayValidationNodeLauncher::new(exact_launcher, thin_launcher);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);
    let process_contract = test_process_contract();

    let fat_runtime = executor.load_materialized_exact_snapshot_probe_guarded(
        &process_contract,
        &config,
        &exact,
        QemuExactSnapshotPolicy::production().authorize_loadvm_probe(),
    )?;
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let thin_runtime =
        executor.load_prepared_baked_genesis_guarded(&process_contract, &config, admission)?;

    assert_eq!(fat_runtime.id, runtime_id);
    assert_eq!(thin_runtime.id, runtime_id);
    assert_eq!(
        logged(&log),
        vec![
            NodeExecutorCall::GuardedLaunch {
                config: config.id(),
                snapshot: exact.id(),
                checkpoint: exact.checkpoint().id,
            },
            NodeExecutorCall::PrepareObservationStream,
            NodeExecutorCall::Fingerprint,
            NodeExecutorCall::Shutdown,
            NodeExecutorCall::GuardedThinLaunch {
                config: config.id(),
                checkpoint: baked.checkpoint.id,
                admission: QemuNodeRestoreAdmission::BakedGenesis { world_id: world.id },
            },
            NodeExecutorCall::PrepareObservationStream,
            NodeExecutorCall::Fingerprint,
        ]
    );
    Ok(())
}

#[test]
fn failed_realization_surrenders_the_active_node_for_quarantine()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "quarantine"));
    let config = Configuration::genesis(scenario("quarantine"));
    let checkpoint = checkpoint_for_config("quarantine", &config, &node, 3, CheckpointKind::Fat)?;
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint,
    };
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let launcher = scripted_launcher(Rc::clone(&log), hash("runtime", "quarantine"), 3);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);
    executor.load_baked_genesis(&config, admission)?;

    assert!(executor.take_active_node_for_quarantine().is_some());
    assert!(!executor.live_backend_is_active());
    assert!(executor.take_active_node_for_quarantine().is_none());
    Ok(())
}

#[test]
fn failed_warm_launch_retains_child_and_poison_blocks_relaunch()
-> Result<(), Box<dyn std::error::Error>> {
    let child = QemuNodeChild::new(Command::new("sleep").arg("60").spawn()?);
    let process_id = child.process_id();
    let error = QemuWarmRestoreLaunchError::FailedCleanup {
        primary: Box::new(QemuWarmRestoreLaunchError::MissingQmpChannel),
        cleanup: QemuShutdownTargetError::new("forced cleanup", "forced reap failure"),
        unreaped_child: Some(Box::new(child)),
    };
    let mut retained = None;

    assert!(matches!(
        retain_warm_restore_result(Err(error), &mut retained),
        Err(QemuVmRealizationError::Executor { .. })
    ));
    assert!(matches!(
        require_no_failed_launch_child(&retained),
        Err(QemuVmRealizationError::ReapQuarantined { .. })
    ));

    let mut retained = retained.ok_or("failed launch did not retain its direct child")?;
    retained.force_kill_and_reap_failed_realization()?;
    assert!(crate::linux_process_identity(process_id)?.is_none());
    Ok(())
}

#[test]
fn qemu_node_realization_executor_replays_without_generic_snapshot_or_restore()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "replay"));
    let genesis = Configuration::genesis(scenario("replay"));
    let target = config_with_decision_values(genesis.def.clone(), &[42]);
    let checkpoint =
        checkpoint_for_config("replay-genesis", &genesis, &node, 9, CheckpointKind::Fat)?;
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint,
    };
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let launcher = scripted_launcher(Rc::clone(&log), hash("runtime", "genesis"), 9);
    let mut executor = QemuNodeRealizationExecutor::new(node.clone(), launcher);
    let runtime = executor.load_baked_genesis(&genesis, admission)?;
    let replay_runtime_id = hash("runtime", "replay");
    executor
        .active_node
        .as_mut()
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "test setup",
            message: String::from("active node missing"),
        })?
        .runtime_id = replay_runtime_id;

    let runtime = executor.replay_one_quantum(
        runtime,
        QemuVmReplayRequest {
            from: genesis,
            to: target.clone(),
            decision: target.schedule.decisions()[0].clone(),
        },
    )?;

    assert_eq!(runtime.id, replay_runtime_id);
    assert_eq!(runtime.configuration, target.id());
    assert_eq!(
        runtime.node_icounts.get(&node),
        Some(&Icount { retired: 10 })
    );
    assert!(!logged(&log).contains(&NodeExecutorCall::Snapshot));
    assert!(!logged(&log).contains(&NodeExecutorCall::Restore));
    assert!(logged(&log).contains(&NodeExecutorCall::Advance(10)));
    assert!(logged(&log).contains(&NodeExecutorCall::CurrentIcount));
    Ok(())
}

#[test]
fn replay_rejects_a_foreign_event_log_before_backend_work() -> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "foreign-event-log"));
    let genesis = Configuration::genesis(scenario("foreign-event-log"));
    let target = config_with_decision_values(genesis.def.clone(), &[7]);
    let checkpoint =
        checkpoint_for_config("foreign-event-log", &genesis, &node, 4, CheckpointKind::Fat)?;
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint,
    };
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let launcher = scripted_launcher(Rc::clone(&log), hash("runtime", "foreign-event-log"), 4);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);
    let mut runtime = executor.load_baked_genesis(&genesis, admission)?;
    runtime.event_log = EventLogOffset::new(hash("event-log", "foreign"), 17, 3);
    let before = logged(&log);

    let error = executor
        .replay_one_quantum(
            runtime,
            QemuVmReplayRequest {
                from: genesis,
                to: target.clone(),
                decision: target.schedule.decisions()[0].clone(),
            },
        )
        .err()
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "test foreign event-log continuation",
            message: String::from("foreign event-log continuation was unexpectedly accepted"),
        })?;

    assert!(matches!(error, QemuVmRealizationError::Executor { .. }));
    assert_eq!(logged(&log), before);
    Ok(())
}

#[test]
fn replay_preserves_an_exact_nonzero_event_log_continuation() -> Result<(), QemuVmRealizationError>
{
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "resumed-event-log"));
    let genesis = Configuration::genesis(scenario("resumed-event-log"));
    let target = config_with_decision_values(genesis.def.clone(), &[8]);
    let mut checkpoint =
        checkpoint_for_config("resumed-event-log", &genesis, &node, 6, CheckpointKind::Fat)?;
    let resumed = EventLogOffset::new(hash("event-log", "resumed"), 4096, 23);
    checkpoint.state = Some(MaterializedState::from_components(
        checkpoint
            .state
            .as_ref()
            .map(|state| state.vm_snapshots.clone())
            .unwrap_or_default(),
        BTreeMap::new(),
        SchedulerState::from_schedule(&genesis.schedule),
        DecisionRngState::empty(),
        resumed,
    ));
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint,
    };
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let launcher = scripted_launcher(Rc::clone(&log), hash("runtime", "resumed-event-log"), 6);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);
    let runtime = executor.load_baked_genesis(&genesis, admission)?;
    assert_eq!(runtime.event_log, resumed);

    let replayed = executor.replay_one_quantum(
        runtime,
        QemuVmReplayRequest {
            from: genesis,
            to: target.clone(),
            decision: target.schedule.decisions()[0].clone(),
        },
    )?;

    assert_eq!(replayed.event_log, resumed);
    assert!(logged(&log).contains(&NodeExecutorCall::Advance(7)));
    Ok(())
}

#[test]
fn qemu_node_realization_executor_loads_probe_without_runtime_admission()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let config = Configuration::genesis(scenario("probe"));
    let snapshot = QemuVmSnapshot::diskless(
        checkpoint_for_config("probe", &config, &node, 0, CheckpointKind::Fat)?,
        QemuReplayOracleValidation::NotRun,
    )?;
    let runtime_id = hash("runtime", "probe");
    let launcher = scripted_launcher(Rc::clone(&log), runtime_id, 0);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);

    let runtime = executor.load_exact_snapshot_for_replay_oracle_probe(
        &config,
        &snapshot,
        QemuExactSnapshotPolicy::production().authorize_loadvm_probe(),
    )?;

    assert_eq!(runtime.id, runtime_id);
    assert_eq!(runtime.configuration, config.id());
    assert_eq!(
        logged(&log),
        vec![
            NodeExecutorCall::Launch {
                config: config.id(),
                checkpoint: snapshot.checkpoint.id,
                authorization: QemuLoadvmCommandPurpose::ReplayOracleProbe,
                admission: QemuNodeRestoreAdmission::ReplayOracleProbe,
            },
            NodeExecutorCall::PrepareObservationStream,
            NodeExecutorCall::Fingerprint,
        ]
    );
    Ok(())
}

#[test]
fn live_realization_capability_borrows_only_the_installed_node_and_reaps_it()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "live-capability"));
    let config = Configuration::genesis(scenario("live-capability"));
    let checkpoint =
        checkpoint_for_config("live-capability", &config, &node, 17, CheckpointKind::Fat)?;
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint,
    };
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let launcher = scripted_launcher(Rc::clone(&log), hash("runtime", "live-capability"), 17);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);

    executor.load_baked_genesis(&config, admission)?;
    let backend = executor.live_backend_mut()?;
    backend
        .advance_to_horizon(crucible::ExecutionHorizon {
            icount: Icount { retired: 18 },
        })
        .map_err(|source| QemuVmRealizationError::Executor {
            operation: "advance test live backend",
            message: source.to_string(),
        })?;
    let current = backend
        .current_icount()
        .map_err(|source| QemuVmRealizationError::Executor {
            operation: "read test live-backend icount",
            message: source.to_string(),
        })?;
    assert_eq!(current, Icount { retired: 18 });
    assert_eq!(backend.event_log().offset(), EventLogOffset::default());

    assert!(executor.seal_live_observation_boundary()?);
    let shutdown = executor.shutdown_live_backend()?;
    assert!(shutdown.observation_boundary_unchanged());
    assert!(executor.live_backend_mut().is_err());
    assert_eq!(
        logged(&log)
            .iter()
            .filter(|call| matches!(call, NodeExecutorCall::Shutdown))
            .count(),
        1
    );
    Ok(())
}

#[test]
fn final_drain_change_is_measured_from_the_executor_owned_log() -> Result<(), QemuVmRealizationError>
{
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "owned-final-log"));
    let config = Configuration::genesis(scenario("owned-final-log"));
    let checkpoint =
        checkpoint_for_config("owned-final-log", &config, &node, 17, CheckpointKind::Fat)?;
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint,
    };
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let launcher = scripted_launcher(Rc::clone(&log), hash("runtime", "owned-final-log"), 17);
    let mut executor = QemuNodeRealizationExecutor::new(node.clone(), launcher);
    executor.load_baked_genesis(&config, admission)?;
    assert!(executor.seal_live_observation_boundary()?);
    executor
        .active_node
        .as_mut()
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "test final event-log drain",
            message: String::from("active node missing"),
        })?
        .shutdown_event = Some(ObservableEvent::coverage_block(
        Icount { retired: 17 },
        node,
        0x4010,
        4,
    ));

    let shutdown = executor.shutdown_live_backend()?;

    assert!(!shutdown.observation_boundary_unchanged());
    assert_ne!(executor.event_log.offset(), EventLogOffset::default());
    Ok(())
}

#[test]
fn live_exact_capture_authenticates_and_seals_the_installed_basis()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "live-capture"));
    let config = Configuration::genesis(scenario("live-capture"));
    let checkpoint =
        checkpoint_for_config("live-capture", &config, &node, 23, CheckpointKind::Fat)?;
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint: checkpoint.clone(),
    };
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let launcher = scripted_launcher(Rc::clone(&log), hash("runtime", "live-capture"), 23);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);
    executor.load_baked_genesis(&config, admission)?;

    let snapshot = executor.capture_live_exact_snapshot(checkpoint.clone())?;

    assert_eq!(snapshot.checkpoint(), &checkpoint);
    assert!(logged(&log).contains(&NodeExecutorCall::Seal));
    assert!(logged(&log).contains(&NodeExecutorCall::Capture(checkpoint.id)));
    assert!(
        executor
            .live_backend_mut()?
            .advance_to_horizon(crucible::ExecutionHorizon {
                icount: Icount { retired: 24 },
            })
            .is_err()
    );
    executor.shutdown_live_backend()?;
    Ok(())
}

#[test]
fn live_exact_capture_rejects_a_foreign_log_after_sealing_without_capture()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let world = World::from_content_hash(hash("world", "foreign-capture-log"));
    let config = Configuration::genesis(scenario("foreign-capture-log"));
    let mut checkpoint = checkpoint_for_config(
        "foreign-capture-log",
        &config,
        &node,
        31,
        CheckpointKind::Fat,
    )?;
    let baked = QemuBakedGenesisSnapshot {
        world_id: world.id,
        checkpoint: checkpoint.clone(),
    };
    let admission = QemuBakedGenesisRestoreAdmission::new(
        &baked,
        &world,
        QemuLoadvmCommandAuthorization::baked_genesis_realization_for_test(),
    )?;
    let launcher = scripted_launcher(Rc::clone(&log), hash("runtime", "foreign-capture-log"), 31);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);
    executor.load_baked_genesis(&config, admission)?;
    let state =
        checkpoint
            .state
            .as_ref()
            .ok_or_else(|| QemuVmRealizationError::InvalidCheckpoint {
                role: "test live exact capture",
                message: String::from("test checkpoint has no materialized state"),
            })?;
    checkpoint.state = Some(MaterializedState::from_components(
        state.vm_snapshots.clone(),
        state.device_overlays.clone(),
        state.scheduler.clone(),
        state.decision_rng.clone(),
        EventLogOffset::new(hash("event-log", "foreign-capture-log"), 64, 1),
    ));

    let error = executor
        .capture_live_exact_snapshot(checkpoint)
        .err()
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "test foreign capture log",
            message: String::from("foreign capture log was unexpectedly accepted"),
        })?;

    assert!(matches!(
        error,
        QemuVmRealizationError::InvalidCheckpoint { .. }
    ));
    assert!(logged(&log).contains(&NodeExecutorCall::Seal));
    assert!(
        !logged(&log)
            .iter()
            .any(|call| matches!(call, NodeExecutorCall::Capture(_)))
    );
    assert!(
        executor
            .live_backend_mut()?
            .advance_to_horizon(crucible::ExecutionHorizon {
                icount: Icount { retired: 32 },
            })
            .is_err()
    );
    executor.shutdown_live_backend()?;
    Ok(())
}

#[test]
fn retained_hot_fork_template_moves_exact_configuration_and_event_prefix() {
    let log = shared_log();
    let configuration = hash("configuration", "retained-template");
    let offset = EventLogOffset::new(hash("event-prefix", "retained-template"), 41, 7);
    let mut executor = QemuNodeRealizationExecutor {
        node: node_id(),
        launcher: scripted_launcher(Rc::clone(&log), configuration, 0),
        active_node: Some(ScriptedNode {
            log: Rc::clone(&log),
            runtime_id: configuration,
            current_icount: Icount { retired: 0 },
            shutdown_event: None,
        }),
        active_configuration: Some(configuration),
        event_log: EventLog::from_offset(offset),
        observation_sealed: false,
    };

    let prepared = executor
        .prepare_active_hot_fork_template(&[], 8 * 1024 * 1024)
        .expect("prepare exact retained template");

    assert_eq!(prepared.configuration(), configuration);
    assert_eq!(prepared.event_log().offset(), offset);
    assert!(executor.active_node.is_none());
    assert_eq!(executor.active_configuration, None);
    assert_eq!(executor.event_log.offset(), EventLog::new().offset());
    assert_eq!(
        logged(&log),
        vec![NodeExecutorCall::PrepareHotFork {
            bindings: 0,
            maximum_ring_image_bytes: 8 * 1024 * 1024,
        }]
    );

    let (node, identity) = prepared.into_parts();
    assert_eq!(identity.configuration(), configuration);
    assert_eq!(identity.fork_event_log().offset(), offset);
    let recovered = QemuPreparedHotForkTemplate::from_reconciled_parts(node, identity);
    assert_eq!(recovered.configuration(), configuration);
    assert_eq!(recovered.event_log().offset(), offset);
}

#[test]
fn retained_hot_fork_demotion_reaps_or_returns_the_exact_source() {
    let log = shared_log();
    let configuration = hash("configuration", "retained-template-demotion");
    let offset = EventLogOffset::new(hash("event-prefix", "retained-template-demotion"), 11, 2);
    let mut executor = QemuNodeRealizationExecutor {
        node: node_id(),
        launcher: scripted_launcher(Rc::clone(&log), configuration, 0),
        active_node: Some(ScriptedNode {
            log: Rc::clone(&log),
            runtime_id: configuration,
            current_icount: Icount { retired: 0 },
            shutdown_event: None,
        }),
        active_configuration: Some(configuration),
        event_log: EventLog::from_offset(offset),
        observation_sealed: false,
    };

    executor
        .prepare_active_hot_fork_template(&[], 4096)
        .expect("prepare retained template")
        .shutdown_for_demotion()
        .expect("demote retained template");
    assert_eq!(logged(&log).last(), Some(&NodeExecutorCall::Shutdown));

    let failure = ContentHash::from_bytes(b"hot-fork-shutdown-failure");
    let mut executor = QemuNodeRealizationExecutor {
        node: node_id(),
        launcher: scripted_launcher(Rc::clone(&log), failure, 0),
        active_node: Some(ScriptedNode {
            log,
            runtime_id: failure,
            current_icount: Icount { retired: 0 },
            shutdown_event: None,
        }),
        active_configuration: Some(failure),
        event_log: EventLog::from_offset(offset),
        observation_sealed: false,
    };
    let failed = executor
        .prepare_active_hot_fork_template(&[], 4096)
        .expect("prepare failing retained template")
        .shutdown_for_demotion()
        .expect_err("shutdown must fail");
    let (retained, source) = failed.into_parts();

    assert_eq!(retained.configuration(), failure);
    assert_eq!(retained.event_log().offset(), offset);
    assert!(matches!(source, BackendError::Rejected { .. }));
}

#[test]
fn retained_hot_fork_preparation_failure_keeps_exact_active_owner() {
    let log = shared_log();
    let configuration = hash("configuration", "retained-template-failure");
    let failure = ContentHash::from_bytes(b"hot-fork-preparation-failure");
    let offset = EventLogOffset::new(hash("event-prefix", "retained-template-failure"), 9, 3);
    let mut executor = QemuNodeRealizationExecutor {
        node: node_id(),
        launcher: scripted_launcher(Rc::clone(&log), failure, 0),
        active_node: Some(ScriptedNode {
            log: Rc::clone(&log),
            runtime_id: failure,
            current_icount: Icount { retired: 0 },
            shutdown_event: None,
        }),
        active_configuration: Some(configuration),
        event_log: EventLog::from_offset(offset),
        observation_sealed: false,
    };

    assert!(
        executor
            .prepare_active_hot_fork_template(&[], 4096)
            .is_err()
    );
    assert!(executor.active_node.is_some());
    assert_eq!(executor.active_configuration, Some(configuration));
    assert_eq!(executor.event_log.offset(), offset);
    assert_eq!(
        logged(&log),
        vec![NodeExecutorCall::PrepareHotFork {
            bindings: 0,
            maximum_ring_image_bytes: 4096,
        }]
    );
}

#[test]
fn retained_hot_fork_preparation_requires_exact_active_configuration() {
    let log = shared_log();
    let runtime = hash("runtime", "orphan-node");
    let mut executor = QemuNodeRealizationExecutor {
        node: node_id(),
        launcher: scripted_launcher(Rc::clone(&log), runtime, 0),
        active_node: Some(ScriptedNode {
            log: Rc::clone(&log),
            runtime_id: runtime,
            current_icount: Icount { retired: 0 },
            shutdown_event: None,
        }),
        active_configuration: None,
        event_log: EventLog::new(),
        observation_sealed: false,
    };

    assert!(
        executor
            .prepare_active_hot_fork_template(&[], 4096)
            .is_err()
    );
    assert!(executor.active_node.is_some());
    assert!(logged(&log).is_empty());
}

fn scripted_launcher(
    log: SharedLog,
    runtime_id: ContentHash,
    current_icount: u64,
) -> ScriptedLauncher {
    ScriptedLauncher {
        log,
        runtime_id,
        current_icount: Icount {
            retired: current_icount,
        },
    }
}

fn scripted_vmstate() -> File {
    let mut file = tempfile::tempfile().expect("create scripted VMState");
    file.write_all(b"scripted stable VMState")
        .expect("write scripted VMState");
    file.sync_all().expect("synchronize scripted VMState");
    file
}

fn checkpoint_for_config(
    name: &str,
    config: &Configuration,
    node: &NodeId,
    icount: u64,
    kind: CheckpointKind,
) -> Result<Checkpoint, QemuVmRealizationError> {
    Checkpoint::from_recorded_configuration(
        config,
        None,
        crucible::VirtualTime::default(),
        BTreeMap::from([(node.clone(), Icount { retired: icount })]),
        kind,
        BTreeMap::from([(node.clone(), NodeBlobRef::baked(hash("blob", name)))]),
    )
    .map_err(|source| QemuVmRealizationError::Store {
        operation: "build test checkpoint",
        message: source.to_string(),
    })
}

fn config_with_decision_values(def: ScenarioDef, values: &[u64]) -> Configuration {
    let mut schedule = Schedule::empty();
    for value in values {
        schedule = schedule.appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(format!("stream-{value}")),
            value: *value,
        }));
    }
    Configuration { def, schedule }
}

fn scenario(name: &str) -> ScenarioDef {
    ScenarioDef::from_canonical_material("crucible.test.qemu.node-executor.scenario", name)
}

fn node_id() -> NodeId {
    NodeId {
        name: String::from("qemu"),
    }
}

fn hash(domain: &str, material: &str) -> ContentHash {
    ContentHash::from_canonical_material(domain, material)
}

fn shared_log() -> SharedLog {
    Rc::new(RefCell::new(Vec::new()))
}

fn logged(log: &SharedLog) -> Vec<NodeExecutorCall> {
    log.borrow().clone()
}

fn test_process_contract() -> QemuChildProcessContract {
    let (_cgroup_reader, cgroup_writer) =
        std::os::unix::net::UnixStream::pair().expect("cgroup socket pair");
    let (cancellation_reader, _cancellation_writer) =
        std::os::unix::net::UnixStream::pair().expect("cancellation socket pair");
    QemuChildProcessContract::from_unvalidated_test_descriptors(
        cgroup_writer.into(),
        cancellation_reader.into(),
        u32::MAX,
        u64::MAX,
        u64::MAX,
    )
}
