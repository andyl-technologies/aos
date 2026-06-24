//! Checks the scheduler-facing QEMU node wrapper.

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::error::Error;
use std::process::Command;
use std::rc::Rc;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, Backend, BackendError, BackendInput, Checkpoint, CheckpointKind, ContentHash,
    ExecutionFingerprint, ExecutionHorizon, Icount, NodeId,
};
use crucible_qemu::{
    QemuNode, QemuNodeChannelError, QemuNodeChannelPlane, QemuNodeChannels, QemuNodeChild,
    QemuNodeEmittedFrame, QemuNodeIdleState, QemuNodeLifecycleState, QemuPluginIpcControlChannel,
    QemuQmpMachineControlChannel, QemuShmemHotPathChannel, QemuShutdownPolicy, QemuShutdownRung,
};

type SharedLog = Rc<RefCell<Vec<ChannelCall>>>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChannelCall {
    ShmemCurrentIcount,
    ShmemAdvance(u64),
    ShmemDeliver { node: String, payload: Vec<u8> },
    ShmemEmit,
    ShmemIdle,
    ShmemFingerprint,
    QmpSnapshot,
    QmpRestore(ContentHash),
    PluginQuit,
    QmpQuit,
}

#[derive(Clone)]
struct ScriptedPluginControl {
    log: SharedLog,
    fail_quit: bool,
}

#[derive(Clone)]
struct ScriptedShmemHotPath {
    log: SharedLog,
    fail_advance: bool,
}

#[derive(Clone)]
struct ScriptedQmpMachineControl {
    log: SharedLog,
    fail_snapshot: bool,
}

impl QemuPluginIpcControlChannel for ScriptedPluginControl {
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.borrow_mut().push(ChannelCall::PluginQuit);
        if self.fail_quit {
            return Err(QemuNodeChannelError::new("send_quit", "control closed"));
        }
        Ok(())
    }
}

impl QemuShmemHotPathChannel for ScriptedShmemHotPath {
    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
        self.log.borrow_mut().push(ChannelCall::ShmemCurrentIcount);
        Ok(Icount { retired: 11 })
    }

    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, QemuNodeChannelError> {
        self.log
            .borrow_mut()
            .push(ChannelCall::ShmemAdvance(horizon.icount.retired));
        if self.fail_advance {
            return Err(QemuNodeChannelError::new(
                "advance_to_horizon",
                "futex wake failed",
            ));
        }
        Ok(AdvanceOutcome::ReachedHorizon)
    }

    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
        self.log.borrow_mut().push(ChannelCall::ShmemDeliver {
            node: input.node.name,
            payload: input.payload,
        });
        Ok(())
    }

    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
        self.log.borrow_mut().push(ChannelCall::ShmemEmit);
        Ok(Some(QemuNodeEmittedFrame {
            source: node_id("vm-a"),
            destination: node_id("vm-b"),
            sequence: 7,
            payload: vec![8, 9],
        }))
    }

    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
        self.log.borrow_mut().push(ChannelCall::ShmemIdle);
        Ok(QemuNodeIdleState {
            current_icount: Icount { retired: 13 },
            next_deadline: Some(Icount { retired: 21 }),
        })
    }

    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
        self.log.borrow_mut().push(ChannelCall::ShmemFingerprint);
        Ok(ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        })
    }
}

impl QemuQmpMachineControlChannel for ScriptedQmpMachineControl {
    fn save_checkpoint(&mut self) -> Result<Checkpoint, QemuNodeChannelError> {
        self.log.borrow_mut().push(ChannelCall::QmpSnapshot);
        if self.fail_snapshot {
            return Err(QemuNodeChannelError::new("save_checkpoint", "QMP error"));
        }
        Ok(checkpoint("snapshot"))
    }

    fn restore_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<(), QemuNodeChannelError> {
        self.log
            .borrow_mut()
            .push(ChannelCall::QmpRestore(checkpoint.id));
        Ok(())
    }

    fn quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.log.borrow_mut().push(ChannelCall::QmpQuit);
        Ok(())
    }
}

#[test]
fn qemu_node_owns_one_child_and_exactly_three_channel_roles() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Rc::clone(&log), false, false, false)?;

    assert_eq!(
        node.channel_roles(),
        [
            QemuNodeChannelPlane::PluginIpcControl,
            QemuNodeChannelPlane::ShmemHotPath,
            QemuNodeChannelPlane::QmpMachineControl,
        ]
    );
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
    assert!(!node.child_reaped());
    assert!(recorded(&log).is_empty());

    let report = node.shutdown_child()?;
    assert!(report.reaped);
    assert!(node.child_reaped());
    assert_eq!(
        report
            .attempts
            .iter()
            .map(|attempt| attempt.rung)
            .collect::<Vec<_>>(),
        [
            QemuShutdownRung::ControlQuit,
            QemuShutdownRung::QmpQuit,
            QemuShutdownRung::Sigterm,
        ]
    );
    assert_eq!(
        node.lifecycle_state(),
        QemuNodeLifecycleState::ShutdownRequested
    );

    Ok(())
}

#[test]
fn qemu_node_routes_scheduler_operations_over_strict_channels() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Rc::clone(&log), false, false, false)?;

    assert_eq!(node.current_icount()?, Icount { retired: 11 });
    assert_eq!(
        Backend::advance_to_horizon(
            &mut node,
            ExecutionHorizon {
                icount: Icount { retired: 19 },
            },
        )?,
        AdvanceOutcome::ReachedHorizon
    );
    Backend::deliver_input(
        &mut node,
        BackendInput {
            node: node_id("vm-a"),
            payload: vec![1, 2, 3],
        },
    )?;
    assert_eq!(
        node.emit_frame()?,
        Some(QemuNodeEmittedFrame {
            source: node_id("vm-a"),
            destination: node_id("vm-b"),
            sequence: 7,
            payload: vec![8, 9],
        })
    );
    assert_eq!(
        node.idle_state()?,
        QemuNodeIdleState {
            current_icount: Icount { retired: 13 },
            next_deadline: Some(Icount { retired: 21 }),
        }
    );
    assert_eq!(
        Backend::fingerprint(&mut node)?,
        ExecutionFingerprint {
            hash: content_hash("fingerprint", "vm-a"),
        }
    );

    let saved = Backend::snapshot(&mut node)?;
    assert_eq!(saved, checkpoint("snapshot"));
    Backend::restore(&mut node, &saved)?;
    let report = node.shutdown_child()?;

    assert!(report.reaped);
    assert_eq!(
        node.lifecycle_state(),
        QemuNodeLifecycleState::ShutdownRequested
    );
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::ShmemAdvance(19),
            ChannelCall::ShmemDeliver {
                node: String::from("vm-a"),
                payload: vec![1, 2, 3],
            },
            ChannelCall::ShmemEmit,
            ChannelCall::ShmemIdle,
            ChannelCall::ShmemFingerprint,
            ChannelCall::QmpSnapshot,
            ChannelCall::QmpRestore(content_hash("checkpoint", "snapshot")),
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );

    Ok(())
}

#[test]
fn qemu_node_reports_shmem_failures_as_backend_rejections() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Rc::clone(&log), false, true, false)?;

    let result = Backend::advance_to_horizon(
        &mut node,
        ExecutionHorizon {
            icount: Icount { retired: 99 },
        },
    );

    assert_eq!(
        result,
        Err(BackendError::Rejected {
            message: String::from(
                "shmem hot path channel operation advance_to_horizon failed: futex wake failed"
            ),
        })
    );
    assert_eq!(recorded(&log), vec![ChannelCall::ShmemAdvance(99)]);
    assert!(node.shutdown_child()?.reaped);

    Ok(())
}

#[test]
fn qemu_node_reports_qmp_failures_without_touching_hot_path() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Rc::clone(&log), false, false, true)?;

    let result = Backend::snapshot(&mut node);

    assert_eq!(
        result,
        Err(BackendError::Rejected {
            message: String::from(
                "QMP machine control channel operation save_checkpoint failed: QMP error"
            ),
        })
    );
    assert_eq!(recorded(&log), vec![ChannelCall::QmpSnapshot]);
    assert!(node.shutdown_child()?.reaped);

    Ok(())
}

#[test]
fn qemu_node_shutdown_continues_to_reap_when_plugin_quit_fails() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Rc::clone(&log), true, false, false)?;

    let report = node.shutdown_child()?;

    assert!(report.reaped);
    assert!(node.child_reaped());
    assert_eq!(
        report
            .failures
            .iter()
            .map(|failure| failure.rung)
            .collect::<Vec<_>>(),
        [QemuShutdownRung::ControlQuit]
    );
    assert_eq!(
        recorded(&log),
        vec![ChannelCall::PluginQuit, ChannelCall::QmpQuit]
    );
    assert_eq!(
        node.lifecycle_state(),
        QemuNodeLifecycleState::ShutdownRequested
    );

    Ok(())
}

#[test]
fn qemu_node_repeated_shutdown_is_idempotent_after_reap() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Rc::clone(&log), false, false, false)?;

    let first = node.shutdown_child()?;
    let first_log = recorded(&log);
    let second = node.shutdown_child()?;

    assert!(first.reaped);
    assert!(second.reaped);
    assert!(second.attempts.is_empty());
    assert!(second.failures.is_empty());
    assert_eq!(recorded(&log), first_log);
    assert_eq!(
        first_log,
        vec![ChannelCall::PluginQuit, ChannelCall::QmpQuit]
    );
    assert!(node.child_reaped());

    Ok(())
}

fn scripted_node(
    log: SharedLog,
    fail_plugin_quit: bool,
    fail_shmem_advance: bool,
    fail_qmp_snapshot: bool,
) -> Result<QemuNode, Box<dyn Error>> {
    let channels = QemuNodeChannels::new(
        ScriptedPluginControl {
            log: Rc::clone(&log),
            fail_quit: fail_plugin_quit,
        },
        ScriptedShmemHotPath {
            log: Rc::clone(&log),
            fail_advance: fail_shmem_advance,
        },
        ScriptedQmpMachineControl {
            log,
            fail_snapshot: fail_qmp_snapshot,
        },
    );
    let child = Command::new("sleep").arg("60").spawn()?;
    Ok(QemuNode::new(
        QemuNodeChild::new(child),
        channels,
        node_shutdown_policy(),
    ))
}

fn node_shutdown_policy() -> QemuShutdownPolicy {
    let mut policy = QemuShutdownPolicy::fast_test();
    policy.sigterm_wait = Duration::from_secs(2);
    policy.sigkill_wait = Duration::from_secs(1);
    policy.reap_wait = Duration::from_secs(1);
    policy
}

fn shared_log() -> SharedLog {
    Rc::new(RefCell::new(Vec::new()))
}

fn recorded(log: &SharedLog) -> Vec<ChannelCall> {
    log.borrow().clone()
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn checkpoint(name: &str) -> Checkpoint {
    Checkpoint {
        id: content_hash("checkpoint", name),
        configuration: content_hash("configuration", name),
        kind: CheckpointKind::Fat,
    }
}

fn content_hash(domain: &str, material: &str) -> ContentHash {
    ContentHash::from_canonical_material(domain, material)
}
