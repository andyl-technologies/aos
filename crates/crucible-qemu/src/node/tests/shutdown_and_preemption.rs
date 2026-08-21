//! QEMU-node preemption, debugger, failure, and shutdown behavior.

use super::*;

#[cfg(target_os = "linux")]
#[test]
fn orphan_quarantine_ignores_a_reused_process_identity() -> Result<(), Box<dyn Error>> {
    let current = linux_process_identity(std::process::id())?
        .ok_or("test process should have a Linux process identity")?;
    let mismatched = QemuProcessIdentity {
        start_time_ticks: current
            .start_time_ticks
            .checked_add(1)
            .ok_or("test start-time tick should increment")?,
        ..current
    };

    quarantine_orphaned_qemu_process(&mismatched, Duration::from_millis(10))?;
    assert!(linux_process_identity(std::process::id())?.is_some());
    Ok(())
}

#[test]
fn qemu_node_publishes_scheduler_preemption_before_owned_run() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_runtime(
        Arc::clone(&log),
        false,
        false,
        false,
        [
            QemuAsyncWaitOutcome::Completed,
            QemuAsyncWaitOutcome::Completed,
        ],
    )?;

    SimulationBackend::step_to(&mut node, VirtualTime { ticks: 23 })?;
    SimulationBackend::apply(
        &mut node,
        &BackendEffect::Preemption(crucible::PreemptionDecision {
            node: node_id("vm-a"),
            at: Icount { retired: 27 },
            kind: crucible::PreemptionKind::InterruptAt {
                target_vcpu: crucible::VcpuId { index: 1 },
                irq: crucible::IrqVector { vector: 48 },
            },
        }),
        VirtualTime { ticks: 23 },
    )?;
    SimulationBackend::step_to(&mut node, VirtualTime { ticks: 29 })?;

    let calls = recorded(&log);
    let command_index = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::ShmemPreemption(_)))
        .ok_or("preemption command was not published")?;
    let second_run_index = calls
        .iter()
        .rposition(|call| matches!(call, ChannelCall::ShmemStart(29)))
        .ok_or("second RUN was not started")?;
    assert!(command_index < second_run_index);
    assert_eq!(
        calls[command_index],
        ChannelCall::ShmemPreemption(SchedulerPreemptionCommand {
            at_icount: 27,
            deadline_icount: 23,
            ceiling_icount: 29,
            kind: ShmemSchedulerPreemptionKind::InterruptAt {
                target_vcpu: 1,
                irq: 48,
            },
        })
    );

    SimulationBackend::shutdown(&mut node)?;
    Ok(())
}

#[test]
fn qemu_node_open_gdbstub_reports_configured_channel() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_runtime(
        Arc::clone(&log),
        false,
        false,
        false,
        [QemuAsyncWaitOutcome::Completed],
    )?
    .with_gdbstub(QemuGdbstubChannelConfig::new(
        "tcp:127.0.0.1:9001",
        "127.0.0.1:0",
    )?);

    let info = SimulationBackend::open_gdbstub(
        &mut node,
        node_id("vm-a"),
        GdbListen::new("127.0.0.1:0")?,
    )?;

    assert_eq!(info.node, node_id("vm-a"));
    assert_eq!(info.qemu_endpoint, "tcp:127.0.0.1:9001");
    let active_listener = node
        .active_gdbstub_listener()
        .expect("open_gdbstub should bind an operator listener");
    assert_ne!(active_listener.port(), 0);
    assert_eq!(info.operator_listen.as_str(), active_listener.to_string());
    assert!(
        TcpListener::bind(active_listener).is_err(),
        "gdbstub attach should keep the operator listener bound"
    );
    assert!(info.is_out_of_band_debug_proxy());
    assert!(matches!(
        SimulationBackend::open_gdbstub(
            &mut node,
            node_id("vm-a"),
            GdbListen::new("127.0.0.1:0")?,
        ),
        Err(BackendError::Rejected { message }) if message.contains("already active")
    ));
    assert_eq!(recorded(&log), Vec::<ChannelCall>::new());
    assert!(node.shutdown_child()?.reaped);

    Ok(())
}

#[test]
fn qemu_node_reports_shmem_failures_as_backend_rejections() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, true, false)?;

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
                "bounded QEMU async driver failed: QEMU async shared-memory channel failed: advance_to_horizon failed: futex wake failed"
            ),
        })
    );
    assert_eq!(
        recorded(&log),
        vec![ChannelCall::HostYield, ChannelCall::ShmemStart(99)]
    );
    assert!(node.shutdown_child()?.reaped);

    Ok(())
}

#[test]
fn qemu_node_timeout_reports_crash_and_runs_shutdown() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_runtime(
        Arc::clone(&log),
        false,
        false,
        false,
        [QemuAsyncWaitOutcome::TimedOut],
    )?;

    let result = Backend::advance_to_horizon(
        &mut node,
        ExecutionHorizon {
            icount: Icount { retired: 31 },
        },
    );

    match result {
        Err(BackendError::Rejected { message }) => {
            assert!(message.contains("QEMU node crashed during bounded await"));
            assert!(message.contains("BoundedAwaitTimeout"));
        }
        other => panic!("expected bounded timeout crash, got {other:?}"),
    }
    assert!(node.child_reaped());
    assert_eq!(
        node.lifecycle_state(),
        QemuNodeLifecycleState::ShutdownRequested
    );
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::HostYield,
            ChannelCall::ShmemStart(31),
            ChannelCall::HostAwait {
                wait: QemuAsyncWait::AdvanceCompletion,
                timeout: Duration::from_millis(4),
                outcome: QemuAsyncWaitOutcome::TimedOut,
            },
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );

    Ok(())
}

#[test]
fn qemu_node_terminates_after_indeterminate_qmp_save_failure() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, true)?;

    let mut checkpoint = checkpoint("qmp-failure");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );
    let result = node.capture_exact_snapshot(&node_identity, checkpoint.clone());

    let error = result.expect_err("failed QMP save must reject exact capture");
    assert!(error.to_string().contains("save_checkpoint_vmstate"));
    assert!(error.to_string().contains("QMP error"));
    assert!(error.to_string().contains("terminated and reaped"));
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpStop,
            ChannelCall::HostCheckpointClearWhileStopped,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpExactSave(checkpoint.id),
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );
    assert!(node.child_reaped());

    Ok(())
}

#[test]
fn qemu_node_qmp_timeout_terminates_indeterminate_save_job() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            qmp_snapshot_timeout: true,
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::Completed],
    )?;

    let mut checkpoint = checkpoint("qmp-timeout");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );
    let result = node.capture_exact_snapshot(&node_identity, checkpoint.clone());

    let error = result.expect_err("timed-out QMP save must crash and reject exact capture");
    let message = error.to_string();
    assert!(message.contains("timed out"));
    assert!(message.contains("terminated and reaped"));
    assert!(message.contains("save_checkpoint_vmstate"));
    assert!(node.child_reaped());
    assert_eq!(
        node.lifecycle_state(),
        QemuNodeLifecycleState::ShutdownRequested
    );
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpStop,
            ChannelCall::HostCheckpointClearWhileStopped,
            ChannelCall::ShmemCurrentIcount,
            ChannelCall::QmpExactSave(checkpoint.id),
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
        ]
    );

    Ok(())
}

#[test]
fn qemu_node_shutdown_continues_to_reap_when_plugin_quit_fails() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), true, false, false)?;

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
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;

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
