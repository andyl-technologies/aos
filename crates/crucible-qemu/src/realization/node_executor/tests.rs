//! Tests for QEMU real-node realization execution.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crucible::{
    BackendInput, CheckpointKind, Decision, DecisionRngState, ExecutionFingerprint,
    MaterializedState, NodeBlobRef, ObservableEvent, RngDecision, RngStreamId, ScenarioDef,
    Schedule, SchedulerState, World,
};

use super::*;
use crate::{
    QemuBakedGenesisSnapshot, QemuExactSnapshotPolicy, QemuLoadvmCommandPurpose,
    QemuNodeRestoreAdmission, QemuReplayOracleValidation,
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
    PrepareObservationStream,
    Advance(u64),
    Fingerprint,
    CurrentIcount,
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

impl QemuNodeRealizationLauncher for ScriptedLauncher {
    type Node = ScriptedNode;

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
        Ok(())
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
