//! Tests for QEMU real-node realization execution.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crucible::{
    BackendInput, CheckpointKind, Decision, ExecutionFingerprint, NodeBlobRef, RngDecision,
    RngStreamId, ScenarioDef, Schedule, World,
};

use super::*;
use crate::{
    QemuBakedGenesisSnapshot, QemuLoadvmCommandPurpose, QemuNodeRestoreAdmission,
    QemuReplayOracleValidation,
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
            NodeExecutorCall::Fingerprint,
        ]
    );
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
fn qemu_node_realization_executor_rejects_probe_load_without_admission()
-> Result<(), QemuVmRealizationError> {
    let log = shared_log();
    let node = node_id();
    let config = Configuration::genesis(scenario("probe"));
    let snapshot = QemuVmSnapshot {
        checkpoint: checkpoint_for_config("probe", &config, &node, 0, CheckpointKind::Fat)?,
        replay_oracle_validation: QemuReplayOracleValidation::NotRun,
    };
    let launcher = scripted_launcher(Rc::clone(&log), hash("runtime", "probe"), 0);
    let mut executor = QemuNodeRealizationExecutor::new(node, launcher);

    let error = executor
        .load_exact_snapshot_for_replay_oracle_probe(
            &config,
            &snapshot,
            QemuLoadvmCommandAuthorization::runtime_realization_for_test(),
        )
        .err()
        .ok_or_else(|| QemuVmRealizationError::Executor {
            operation: "test assertion",
            message: String::from("probe load unexpectedly succeeded"),
        })?;

    assert!(error.to_string().contains("replay-oracle probes require"));
    assert!(logged(&log).is_empty());
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
