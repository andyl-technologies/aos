//! Resumes only an accepted native console stop after a fresh mapped RUN.
//!
//! The original host publisher, origin acceptance, mapped runtime and node
//! driver are real. Native retirement and the pre-ACK frontier writer remain
//! explicit external providers; these controls do not execute QEMU or UART.

use super::*;
use std::io::Read;
use std::sync::mpsc;

use crucible_protocol::native_console::{NativeConsoleFrontier, NativeConsolePhase};

/// Checks the actual first-await seam without racing the earlier execution wake.
struct ResumeCheckedRuntime {
    inner: crate::QemuLiveHostIoRuntime,
    log: SharedLog,
    first_await: Option<mpsc::Sender<bool>>,
    fail_completion: bool,
}

impl crate::QemuHostIoRuntime for ResumeCheckedRuntime {
    fn prepare_advance_completion(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.inner.prepare_advance_completion(timeout)
    }

    fn await_node_publication(
        &mut self,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.inner.await_node_publication(timeout)
    }

    fn retain_advance_initial_state(&mut self, state: Option<crate::QemuNodeIdleState>) {
        self.inner.retain_advance_initial_state(state);
    }

    fn arm_advance_completion_fence(
        &mut self,
        fence: Option<crate::QemuAdvanceCompletionFence>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.inner.arm_advance_completion_fence(fence)
    }

    fn completed_quantum_boundary(&self) -> Option<crate::QemuCompletedQuantumBoundary> {
        self.inner.completed_quantum_boundary()
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.inner.publish_current_execution_fingerprint(timeout)
    }

    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.inner.yield_to_control_plane()
    }

    fn await_child(
        &mut self,
        wait: crate::QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        if wait == crate::QemuAsyncWait::AdvanceCompletion
            && let Some(first_await) = self.first_await.take()
        {
            let resumed = recorded(&self.log)
                .iter()
                .filter(|call| matches!(call, ChannelCall::QmpContinue))
                .count()
                == 1;
            first_await.send(resumed).map_err(|error| {
                QemuAsyncDriverRuntimeError::new("report first-await resume", error.to_string())
            })?;
            if !resumed {
                return Err(QemuAsyncDriverRuntimeError::new(
                    "verify accepted console resume",
                    "accepted console stop was not resumed after the fresh AUTH/ceiling",
                ));
            }
        }
        if self.fail_completion {
            return Err(QemuAsyncDriverRuntimeError::new(
                "complete resumed quantum",
                "injected completion refusal after acknowledged QMP continuation",
            ));
        }
        self.inner.await_child(wait, timeout)
    }

    fn repoll_child(
        &mut self,
        wait: crate::QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.inner.repoll_child(wait, timeout)
    }
}

fn retain_accepted_stop(
    node: &mut QemuNode,
    boundary: crate::QemuCompletedQuantumBoundary,
) -> Result<(), QemuNodeError> {
    let outcome = AdvanceOutcome::Paused {
        at: Icount { retired: 100 },
    };
    let report = crate::QemuAsyncNodeStepReport {
        ceiling: Some(Icount { retired: 200 }),
        outcome: crate::QemuAsyncNodeStepOutcome::Completed { advance: outcome },
        final_state: Some(boundary.idle_state()),
        completed_boundary: Some(boundary),
        inbound_frames_consumed: 0,
        emitted_frames: Vec::new(),
        yielded_before_quantum: false,
        yielded_after_quantum: false,
        hot_path_operations: Vec::new(),
        async_operations: Vec::new(),
    };
    assert_eq!(boundary.console_output_sequence(), Some(2));
    assert_eq!(
        node.finish_advance_report(Icount { retired: 200 }, report)?,
        outcome
    );
    Ok(())
}

fn assert_next_mapped_run_resumes(
    bounded_preemption: bool,
    fail_completion: bool,
) -> Result<(), Box<dyn Error>> {
    let crate::native_console_owner::AcceptedConsoleStopFixture {
        fixture,
        region,
        channel,
        runtime,
        mut notifications,
        boundary,
    } = crate::native_console_owner::accepted_console_stop_fixture()?;
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    node.channels.shmem_hot_path = Box::new(channel);
    let (first_await, continuation_ready) = mpsc::channel();
    node.host_io_runtime = Box::new(ResumeCheckedRuntime {
        inner: runtime,
        log: Arc::clone(&log),
        first_await: Some(first_await),
        fail_completion,
    });
    node.async_policy = crate::QemuAsyncDriverPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    retain_accepted_stop(&mut node, boundary)?;
    assert!(node.console_output_resume_pending);
    assert!(!recorded(&log).contains(&ChannelCall::QmpContinue));

    let evidence = crate::BoundedSchedulerPreemptionEvidence::default();
    if bounded_preemption {
        node.enable_bounded_scheduler_preemption(evidence.claim()?);
    }
    let old_authorization = fixture.authorization()?;
    let plan_hash = fixture.plan_hash()?;
    let slot = region.node_slot(0)?;
    let segment = region.native_console_segment(0)?;
    let (mut node, result, publication) = std::thread::scope(|scope| {
        let host = scope.spawn(move || {
            let result = node.advance_to_ceiling_report(Icount { retired: 300 });
            (node, result)
        });
        let publication = (|| -> Result<(), Box<dyn Error>> {
            let resumed = continuation_ready.recv_timeout(Duration::from_secs(2))?;
            let authorization = fixture.authorization()?;
            assert_eq!(authorization.phase, NativeConsolePhase::Grant);
            assert_ne!(
                authorization.owner.authorization,
                old_authorization.owner.authorization
            );
            assert_eq!(slot.snapshot().max_advance_icount, 300);
            if !resumed {
                return Err(
                    "accepted console stop was not resumed after the fresh AUTH/ceiling".into(),
                );
            }
            if fail_completion {
                return Ok(());
            }
            let mut wake = [0; 8];
            notifications.read_exact(&mut wake)?;

            // The first wake requests execution. Only after that resume does
            // this external provider retire to the requested coordinate.
            slot.publish_reached_icount(300)?;
            notifications.read_exact(&mut wake)?;
            let pair = segment.clamp.snapshot()?;
            segment.frontier.store(NativeConsoleFrontier {
                sequence: 2,
                ring_end: 2,
                logical_ps: 300,
                raw_prefix: 5,
                owner: authorization.owner,
                accepted_advance: pair.advance,
                logical_generation: authorization.logical_generation,
                request: pair.request,
                plan_hash,
            })?;
            slot.publish_control_boundary(300, 5)?;
            slot.acknowledge_control_boundary();
            Ok(())
        })();
        // Reap the original host waiter on every provider refusal path.
        let (node, result) = host.join().unwrap();
        (node, result, publication)
    });
    let shutdown = node.shutdown_child();
    assert!(!node.console_output_resume_pending);
    let setup_finish = fixture.finish();
    publication?;
    if fail_completion {
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected completion refusal after acknowledged QMP continuation")
        );
    } else {
        let report = result?;
        assert!(matches!(
            report.outcome,
            crate::QemuAsyncNodeStepOutcome::Completed { .. }
        ));
    }
    assert_eq!(
        recorded(&log)
            .iter()
            .filter(|call| matches!(call, ChannelCall::QmpContinue))
            .count(),
        1
    );
    shutdown?;
    setup_finish?;
    Ok(())
}

#[test]
fn accepted_console_stop_resumes_after_fresh_mapped_run() -> Result<(), Box<dyn Error>> {
    assert_next_mapped_run_resumes(false, false)
}

#[test]
fn accepted_console_stop_resumes_in_bounded_preemption_hook() -> Result<(), Box<dyn Error>> {
    assert_next_mapped_run_resumes(true, false)
}

#[test]
fn failed_continue_retains_console_stop_until_acknowledged_source_resume()
-> Result<(), Box<dyn Error>> {
    for bounded_preemption in [false, true] {
        let accepted = crate::native_console_owner::accepted_console_stop_fixture()?;
        let log = shared_log();
        let mut node = scripted_node_with_options(
            Arc::clone(&log),
            ScriptedNodeOptions {
                fail_qmp_resume_once: true,
                ..ScriptedNodeOptions::default()
            },
            [QemuAsyncWaitOutcome::Completed],
        )?;
        node.channels.shmem_hot_path = Box::new(accepted.channel);
        node.host_io_runtime = Box::new(accepted.runtime);
        retain_accepted_stop(&mut node, accepted.boundary)?;
        if bounded_preemption {
            let evidence = crate::BoundedSchedulerPreemptionEvidence::default();
            node.enable_bounded_scheduler_preemption(evidence.claim()?);
        }

        let advance = node.advance_to_ceiling_report(Icount { retired: 300 });
        let retained_after_failure = node.console_output_resume_pending;
        let authorization = accepted.fixture.authorization()?;
        let ceiling = accepted.region.node_slot(0)?.snapshot().max_advance_icount;
        let resumed = node.resume_after_exact_snapshot();
        let retained_after_resume = node.console_output_resume_pending;
        let shutdown = node.shutdown_child();
        let setup_finish = accepted.fixture.finish();

        assert!(
            advance
                .unwrap_err()
                .to_string()
                .contains("injected QMP resume failure")
        );
        assert!(retained_after_failure);
        assert_eq!(authorization.phase, NativeConsolePhase::Grant);
        assert_eq!(ceiling, 300);
        resumed?;
        assert!(!retained_after_resume);
        assert_eq!(
            recorded(&log)
                .iter()
                .filter(|call| matches!(call, ChannelCall::QmpContinue))
                .count(),
            2
        );
        shutdown?;
        setup_finish?;
    }
    Ok(())
}

#[test]
fn mapped_clamp_without_console_operation_does_not_resume() -> Result<(), Box<dyn Error>> {
    let mapped =
        crate::supervision::host_io_runtime::tests::completed_boundary::MappedCompletion::new();
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    node.channels.shmem_hot_path = Box::new(mapped.channel);
    node.host_io_runtime = Box::new(mapped.runtime);
    node.async_policy = crate::QemuAsyncDriverPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let mut notifications = mapped.notifications;
    let slot = mapped.producer.node_slot(0)?;

    let (mut node, result) = std::thread::scope(|scope| {
        let host = scope.spawn(move || {
            let result = Backend::advance_to_horizon(
                &mut node,
                ExecutionHorizon {
                    icount: Icount { retired: 100 },
                },
            );
            (node, result)
        });
        let mut wake = [0; 8];
        for generation in [2, 4] {
            loop {
                notifications.read_exact(&mut wake).unwrap();
                if slot.snapshot().control_boundary_ack == generation {
                    break;
                }
            }
            slot.publish_reached_icount(100).unwrap();
            slot.publish_control_boundary(100, 1).unwrap();
            slot.acknowledge_control_boundary();
            slot.mark_running();
        }
        host.join().unwrap()
    });
    let boundary = node.completed_quantum_boundary();
    let pending = node.console_output_resume_pending;
    let shutdown = node.shutdown_child();

    assert_eq!(result?, AdvanceOutcome::ReachedHorizon);
    assert_eq!(
        boundary.and_then(crate::QemuCompletedQuantumBoundary::console_output_sequence),
        None
    );
    assert!(!pending);
    assert!(!recorded(&log).contains(&ChannelCall::QmpContinue));
    shutdown?;
    Ok(())
}

#[test]
fn acknowledged_continue_clears_console_stop_even_when_completion_fails()
-> Result<(), Box<dyn Error>> {
    for bounded_preemption in [false, true] {
        assert_next_mapped_run_resumes(bounded_preemption, true)?;
    }
    Ok(())
}

#[test]
fn checkpoint_pause_retains_console_stop_until_explicit_source_resume() -> Result<(), Box<dyn Error>>
{
    let accepted = crate::native_console_owner::accepted_console_stop_fixture()?;
    let log = shared_log();
    let mut node = scripted_node(Arc::clone(&log), false, false, false)?;
    node.channels.shmem_hot_path = Box::new(accepted.channel);
    retain_accepted_stop(&mut node, accepted.boundary)?;

    let pause = node.pause_at_exact_checkpoint_boundary();
    let retained_after_pause = node.console_output_resume_pending;
    let calls_after_pause = recorded(&log);
    let resume = node.resume_after_exact_snapshot();
    let retained_after_resume = node.console_output_resume_pending;
    let shutdown = node.shutdown_child();
    let setup_finish = accepted.fixture.finish();

    pause?;
    assert!(retained_after_pause);
    assert!(calls_after_pause.contains(&ChannelCall::QmpStop));
    assert!(!calls_after_pause.contains(&ChannelCall::QmpContinue));
    resume?;
    assert!(!retained_after_resume);
    assert_eq!(
        recorded(&log)
            .iter()
            .filter(|call| matches!(call, ChannelCall::QmpContinue))
            .count(),
        1
    );
    shutdown?;
    setup_finish?;
    Ok(())
}
