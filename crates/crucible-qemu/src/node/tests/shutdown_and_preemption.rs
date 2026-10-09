//! QEMU-node preemption, debugger, failure, and shutdown behavior.

use super::*;

#[cfg(feature = "kernel-swap-measurement")]
#[test]
fn kernel_swap_admission_unsupported_node_preserves_owner_and_zero_channel_effects()
-> Result<(), Box<dyn Error>> {
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let contract = unvalidated_hot_fork_process_contract()?;
    let mut cancellation = crate::QmpKernelSwapCancellation::new(&contract)?;
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::CheckpointCapture)?;
    let before = recorded(&log);

    let result = node.discover_kernel_swap_admission(&mut cancellation, 17, &original);

    assert!(matches!(
        result,
        Err(crate::QmpError::InvalidBound {
            operation: "kernel-swap admission channel unavailable",
        })
    ));
    assert!(!cancellation.requires_native_retirement());
    assert!(original.wait_slice().is_ok());
    assert_eq!(recorded(&log), before);
    Ok(())
}

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

#[cfg(target_os = "linux")]
#[test]
fn process_identity_components_reuse_preowned_executable_storage() -> Result<(), Box<dyn Error>> {
    let current = linux_process_identity(std::process::id())?
        .ok_or("test process should have a Linux process identity")?;
    let (process_id, start_time_ticks) =
        super::super::linux_process_identity_components(std::process::id(), &current.executable)?;

    assert_eq!(process_id, current.process_id);
    assert_eq!(start_time_ticks, current.start_time_ticks);
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
            at: crucible::SimInstant { ticks: 27 },
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
            at_tick: 27,
            deadline_tick: 23,
            ceiling_tick: 29,
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
fn qemu_node_keeps_exact_preemption_after_an_idle_time_jump() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_runtime(
        Arc::clone(&log),
        false,
        false,
        false,
        [QemuAsyncWaitOutcome::Completed],
    )?;

    // The VM can advance logical time without retiring any instruction.
    node.last_observed_time = VirtualTime { ticks: 1_000 };
    SimulationBackend::apply(
        &mut node,
        &BackendEffect::Preemption(crucible::PreemptionDecision {
            node: node_id("vm-a"),
            at: crucible::SimInstant { ticks: 1_001 },
            kind: crucible::PreemptionKind::InterruptAt {
                target_vcpu: crucible::VcpuId { index: 1 },
                irq: crucible::IrqVector { vector: 48 },
            },
        }),
        VirtualTime { ticks: 1_000 },
    )?;
    SimulationBackend::step_to(&mut node, VirtualTime { ticks: 1_050 })?;

    assert!(
        recorded(&log).contains(&ChannelCall::ShmemPreemption(SchedulerPreemptionCommand {
            at_tick: 1_001,
            deadline_tick: 1_000,
            ceiling_tick: 1_050,
            kind: ShmemSchedulerPreemptionKind::InterruptAt {
                target_vcpu: 1,
                irq: 48,
            },
        }))
    );
    SimulationBackend::shutdown(&mut node)?;
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
    assert_native_capture_failure_reaps(
        ScriptedNodeOptions {
            fail_qmp_snapshot: true,
            ..ScriptedNodeOptions::default()
        },
        "QMP error",
    )
}

#[test]
fn qemu_node_qmp_timeout_terminates_indeterminate_save_job() -> Result<(), Box<dyn Error>> {
    assert_native_capture_failure_reaps(
        ScriptedNodeOptions {
            qmp_snapshot_timeout: true,
            ..ScriptedNodeOptions::default()
        },
        "timed out",
    )
}

fn assert_native_capture_failure_reaps(
    options: ScriptedNodeOptions,
    expected_failure: &str,
) -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node =
        scripted_node_with_options(Arc::clone(&log), options, [QemuAsyncWaitOutcome::Completed])?;
    let mut checkpoint = checkpoint("indeterminate-native-save");
    checkpoint.virtual_time = node.synchronize_observed_time()?;
    let node_identity = node_id("vm-a");
    checkpoint.node_icounts.insert(
        node_identity.clone(),
        Icount {
            retired: checkpoint.virtual_time.ticks,
        },
    );

    // The current native hot-fork path uses the same post-save failure cleanup
    // as admitted descriptor capture, and must never resume an uncertain job.
    let error = node
        .capture_native_hot_fork_vmstate_paused(&node_identity, checkpoint.clone())
        .expect_err("indeterminate QMP save must reject native capture");

    let message = error.to_string();
    assert!(message.contains("save_checkpoint_vmstate"), "{message}");
    assert!(message.contains(expected_failure), "{message}");
    assert!(message.contains("terminated and reaped"), "{message}");
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
            ChannelCall::HostCheckpointQuiesce,
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

#[test]
fn qemu_node_retires_process_endpoints_after_normal_reap() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            track_process_endpoint_retirement: true,
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::Completed],
    )?;

    let report = node.shutdown_child()?;

    assert!(report.reaped);
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
            ChannelCall::QmpRetireProcessScopedEndpoints,
        ]
    );
    Ok(())
}

#[test]
fn qemu_node_retires_process_endpoints_when_already_reaped() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            track_process_endpoint_retirement: true,
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::Completed],
    )?;

    assert!(node.shutdown_child()?.reaped);
    let second = node.shutdown_child()?;

    assert!(second.reaped);
    assert!(second.attempts.is_empty());
    assert_eq!(
        recorded(&log),
        vec![
            ChannelCall::PluginQuit,
            ChannelCall::QmpQuit,
            ChannelCall::QmpRetireProcessScopedEndpoints,
            ChannelCall::QmpRetireProcessScopedEndpoints,
        ]
    );
    Ok(())
}

#[test]
fn qemu_node_retires_process_endpoints_after_crash_reap() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            track_process_endpoint_retirement: true,
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::TimedOut],
    )?;

    let result = Backend::advance_to_horizon(
        &mut node,
        ExecutionHorizon {
            icount: Icount { retired: 31 },
        },
    );

    assert!(matches!(result, Err(BackendError::Rejected { .. })));
    assert!(node.child_reaped());
    assert_eq!(
        recorded(&log).last(),
        Some(&ChannelCall::QmpRetireProcessScopedEndpoints)
    );
    Ok(())
}

#[test]
fn qemu_node_retains_process_endpoints_when_reap_fails() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions {
            track_process_endpoint_retirement: true,
            ..ScriptedNodeOptions::default()
        },
        [QemuAsyncWaitOutcome::Completed],
    )?;

    // Reap the fixture's owned child before installing the controlled
    // externally parented process that remains alive through every rung.
    assert!(node.shutdown_child()?.reaped);
    node.child = QemuNodeProcessControl::External(Box::new(UnreapableExternalProcessControl));
    log.lock().unwrap().clear();

    let error = node
        .shutdown_child()
        .expect_err("an unreapable process must fail shutdown");

    let QemuNodeError::Shutdown {
        source: crate::QemuShutdownError::LeakedChild { report },
    } = error
    else {
        panic!("expected a leaked-child shutdown error, got {error:?}");
    };
    assert!(report.leaked);
    assert!(!report.reaped);
    assert_eq!(
        recorded(&log),
        vec![ChannelCall::PluginQuit, ChannelCall::QmpQuit]
    );
    Ok(())
}

#[test]
fn bounded_scheduler_preemption_rejects_externally_owned_process() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        Arc::clone(&log),
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
    )?;
    assert!(node.shutdown_child()?.reaped);
    node.child = QemuNodeProcessControl::External(Box::new(UnreapableExternalProcessControl));

    let evidence = crate::BoundedSchedulerPreemptionEvidence::default();
    node.enable_bounded_scheduler_preemption(evidence.claim()?);
    let error = node
        .advance_to_ceiling_report(Icount { retired: 31 })
        .expect_err("externally owned process must be rejected before pidfd_open");

    assert!(matches!(
        error,
        QemuNodeError::BoundedSchedulerPreemptionTarget {
            target: QemuBoundedSchedulerPreemptionTargetError::ExternallyOwned,
        }
    ));
    assert!(evidence.snapshot().is_none());
    assert!(evidence.claim().is_err());
    Ok(())
}

#[test]
fn bounded_scheduler_preemption_rejects_reaped_direct_child() -> Result<(), Box<dyn Error>> {
    let log = shared_log();
    let mut node = scripted_node_with_options(
        log,
        ScriptedNodeOptions::default(),
        [QemuAsyncWaitOutcome::Completed],
    )?;
    assert!(node.shutdown_child()?.reaped);

    let evidence = crate::BoundedSchedulerPreemptionEvidence::default();
    node.enable_bounded_scheduler_preemption(evidence.claim()?);
    let error = node
        .advance_to_ceiling_report(Icount { retired: 31 })
        .expect_err("reaped direct child must be rejected before pidfd_open");

    assert!(matches!(
        error,
        QemuNodeError::BoundedSchedulerPreemptionTarget {
            target: QemuBoundedSchedulerPreemptionTargetError::AlreadyReaped,
        }
    ));
    assert!(evidence.snapshot().is_none());
    assert!(evidence.claim().is_err());
    Ok(())
}

#[test]
fn managed_reset_unsupported_node_has_zero_channel_effects() -> Result<(), Box<dyn Error>> {
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
    let before = recorded(&log);

    let pending = crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest::new(
        crucible_protocol::SelectionRequest::new(3, "flight.ready", "w001", None, 97)?,
        9,
        11,
        0,
        0x7000,
    );
    let result = node.reset_selectable_under_original(&pending, &original);

    assert!(matches!(
        result,
        Err(crate::QmpError::SelectableResetBoundary { .. })
    ));
    assert_eq!(recorded(&log), before);
    assert!(original.wait_slice().is_ok());
    Ok(())
}

#[test]
fn reset_transition_blocks_ordinary_advances_and_keeps_each_custody_state()
-> Result<(), Box<dyn Error>> {
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
    for state in [
        super::super::guarded_reset::ResetResumeState::Requested,
        super::super::guarded_reset::ResetResumeState::Observed,
        super::super::guarded_reset::ResetResumeState::Reconciled,
        super::super::guarded_reset::ResetResumeState::InFlight,
    ] {
        let log = shared_log();
        let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
        node.reset_resume_pending = Some(super::super::guarded_reset::ResetResumeTransition {
            state,
            original: Arc::clone(&original),
        });
        let before = recorded(&log);

        assert!(node.advance_to_ceiling(Icount { retired: 31 }).is_err());
        assert!(node.advance_to_next_idle(Icount { retired: 31 }).is_err());
        assert!(node.resume_after_restore().is_err());
        let retained = node
            .reset_resume_pending
            .as_ref()
            .expect("reset custody remains");
        assert_eq!(retained.state, state);
        assert!(Arc::ptr_eq(&retained.original, &original));
        assert!(!node.selectable_reply_is_checkpoint_quiescent());
        assert_eq!(recorded(&log), before);
    }
    Ok(())
}

#[test]
fn reset_resume_rejects_another_live_original_before_channel_effects() -> Result<(), Box<dyn Error>>
{
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
    let replacement = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
    node.reset_resume_pending = Some(super::super::guarded_reset::ResetResumeTransition {
        state: super::super::guarded_reset::ResetResumeState::Reconciled,
        original: Arc::clone(&original),
    });
    let before = recorded(&log);

    let error = node
        .resume_reset_to_fresh_idle_under_original(Icount { retired: 31 }, &replacement)
        .expect_err("a different live operation cannot renew reset continuation");

    assert!(error.to_string().contains("retained original operation"));
    assert_eq!(recorded(&log), before);
    let retained = node
        .reset_resume_pending
        .as_ref()
        .expect("original remains owned");
    assert_eq!(
        retained.state,
        super::super::guarded_reset::ResetResumeState::Reconciled
    );
    assert!(Arc::ptr_eq(&retained.original, &original));
    assert_eq!(original.status()?.completed_work_units, 0);
    assert_eq!(replacement.status()?.completed_work_units, 0);
    assert!(original.wait_slice().is_ok());
    assert!(replacement.wait_slice().is_ok());
    Ok(())
}

#[test]
fn reset_transition_retains_original_until_node_drop_and_unwind() -> Result<(), Box<dyn Error>> {
    println!(
        "reset layout: state={} transition={} optional={} node={} align={}",
        std::mem::size_of::<super::super::guarded_reset::ResetResumeState>(),
        std::mem::size_of::<super::super::guarded_reset::ResetResumeTransition>(),
        std::mem::size_of::<Option<super::super::guarded_reset::ResetResumeTransition>>(),
        std::mem::size_of::<QemuNode>(),
        std::mem::align_of::<QemuNode>(),
    );

    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    for unwind in [false, true] {
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )?;
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation)?);
        let weak = Arc::downgrade(&original);
        let mut node = scripted_node(shared_log(), false, false, false)?;
        node.reset_resume_pending = Some(super::super::guarded_reset::ResetResumeTransition {
            state: super::super::guarded_reset::ResetResumeState::Observed,
            original: Arc::clone(&original),
        });
        drop(original);
        assert!(weak.upgrade().is_some());

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _owned_node = node;
            if unwind {
                panic!("authored reset owner unwind");
            }
        }));

        assert_eq!(outcome.is_err(), unwind);
        assert!(weak.upgrade().is_none());
    }
    Ok(())
}
