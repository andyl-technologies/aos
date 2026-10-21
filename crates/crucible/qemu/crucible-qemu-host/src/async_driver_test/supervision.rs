//! Checks actual driver-issued operation cancellation at publication boundaries.
//!
//! The scripted target records effects; it grants no native Source authority.

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationStatus,
    HostOperationSupervisor,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeRefusalCut {
    Yield(usize),
    Fence,
    Wait(usize),
    Renew,
}

struct SupervisedRuntime {
    supervisor: HostOperationSupervisor,
    scripted: ScriptedRuntime,
    cancel_on_yield: Option<usize>,
    cancel_on_wait: bool,
    refuse_at: Option<RuntimeRefusalCut>,
    final_yield_operations: Vec<HostOperationStatus>,
}

impl SupervisedRuntime {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            supervisor: HostOperationSupervisor::new(
                HostOperationBudgets::default(),
                Some(Duration::from_secs(5)),
            )?,
            scripted: ScriptedRuntime::new([QemuAsyncWaitOutcome::Completed]),
            cancel_on_yield: None,
            cancel_on_wait: false,
            refuse_at: None,
            final_yield_operations: Vec::new(),
        })
    }

    fn cancel(&self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.supervisor.cancel().map_err(|source| {
            QemuAsyncDriverRuntimeError::operational_supervision("fixture cancellation", source)
        })
    }

    fn refuse(&self, cut: RuntimeRefusalCut) -> Result<(), QemuAsyncDriverRuntimeError> {
        if self.refuse_at == Some(cut) {
            self.cancel()?;
            return Err(QemuAsyncDriverRuntimeError::new(
                "actual runtime first refusal",
                "adapter returned after canceling its actual supervisor",
            ));
        }
        Ok(())
    }
}

impl QemuHostIoRuntime for SupervisedRuntime {
    fn host_operation_supervisor(&self) -> Option<&HostOperationSupervisor> {
        Some(&self.supervisor)
    }

    fn publish_current_execution_fingerprint(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.scripted.publish_current_execution_fingerprint(timeout)
    }

    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.scripted.yield_to_control_plane()?;
        if self.scripted.yields == 2 {
            self.final_yield_operations =
                self.supervisor.operation_statuses().map_err(|source| {
                    QemuAsyncDriverRuntimeError::operational_supervision(
                        "fixture yield observation",
                        source,
                    )
                })?;
        }
        if self.cancel_on_yield == Some(self.scripted.yields) {
            self.cancel()?;
        }
        self.refuse(RuntimeRefusalCut::Yield(self.scripted.yields))?;
        Ok(())
    }

    fn arm_advance_completion_fence(
        &mut self,
        fence: Option<QemuAdvanceCompletionFence>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.scripted.arm_advance_completion_fence(fence)?;
        self.refuse(RuntimeRefusalCut::Fence)
    }

    fn repoll_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let outcome = self.scripted.repoll_child(wait, timeout)?;
        self.refuse(RuntimeRefusalCut::Wait(self.scripted.repolls + 1))?;
        Ok(outcome)
    }

    fn await_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        let outcome = self.scripted.await_child(wait, timeout)?;
        if self.cancel_on_wait {
            self.cancel()?;
        }
        self.refuse(RuntimeRefusalCut::Wait(1))?;
        Ok(outcome)
    }

    fn renew_advance_completion_poll(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.scripted.renew_advance_completion_poll(timeout)?;
        self.refuse(RuntimeRefusalCut::Renew)
    }
}

fn run(
    target: &mut ScriptedTarget,
    runtime: &mut SupervisedRuntime,
) -> Result<QemuAsyncNodeStepReport, QemuAsyncDriverError> {
    run_bounded_qemu_node_step(
        target,
        runtime,
        QemuAsyncDriverPolicy::fast_test(),
        &QemuCrashDetector::new("vm-a"),
        horizon(12),
    )
}

#[test]
fn issued_quantum_cancelled_during_yield_cannot_publish() -> Result<(), Box<dyn std::error::Error>>
{
    let mut target = ScriptedTarget::completed();
    let mut runtime = SupervisedRuntime::new()?;
    runtime.cancel_on_yield = Some(1);

    let result = run(&mut target, &mut runtime);

    assert!(matches!(result, Err(QemuAsyncDriverError::Runtime(_))));
    assert!(target.started.is_empty());
    assert_eq!(target.finished, 0);
    assert_eq!(target.shutdowns, 0);
    assert_eq!(runtime.scripted.awaits, 0);
    Ok(())
}

#[test]
fn issued_quantum_cancelled_after_publication_cannot_arm_wait()
-> Result<(), Box<dyn std::error::Error>> {
    let mut target = ScriptedTarget::completed();
    let mut runtime = SupervisedRuntime::new()?;

    let cancellation = runtime.supervisor.clone();
    let result = run_bounded_qemu_node_step_with_start_hook(
        &mut target,
        &mut runtime,
        QemuAsyncDriverPolicy::fast_test(),
        &QemuCrashDetector::new("vm-a"),
        horizon(12),
        |_target, _pending| {
            cancellation.cancel().map_err(|error| {
                QemuNodeChannelError::new("fixture cancellation", error.to_string())
            })
        },
    );

    assert!(matches!(result, Err(QemuAsyncDriverError::Runtime(_))));
    assert_eq!(target.started, vec![12]);
    assert_eq!(target.finished, 0);
    assert_eq!(target.shutdowns, 0);
    assert!(runtime.scripted.armed_fences.is_empty());
    assert_eq!(runtime.scripted.awaits, 0);
    Ok(())
}

#[test]
fn issued_quantum_cancelled_during_wait_cannot_finish() -> Result<(), Box<dyn std::error::Error>> {
    let mut target = ScriptedTarget::completed();
    let mut runtime = SupervisedRuntime::new()?;
    runtime.cancel_on_wait = true;

    let result = run(&mut target, &mut runtime);

    assert!(matches!(result, Err(QemuAsyncDriverError::Runtime(_))));
    assert_eq!(target.started, vec![12]);
    assert_eq!(target.finished, 0);
    assert_eq!(target.shutdowns, 0);
    assert_eq!(runtime.scripted.awaits, 1);
    Ok(())
}

#[test]
fn issued_quantum_cancelled_during_final_yield_cannot_complete()
-> Result<(), Box<dyn std::error::Error>> {
    let mut target = ScriptedTarget::completed();
    let mut runtime = SupervisedRuntime::new()?;
    runtime.cancel_on_yield = Some(2);

    let result = run(&mut target, &mut runtime);

    assert!(matches!(result, Err(QemuAsyncDriverError::Runtime(_))));
    assert_eq!(target.finished, 1);
    let operations = &runtime.final_yield_operations;
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].class, HostOperationClass::Quantum);
    assert_eq!(operations[0].state, HostOperationState::Running);
    assert_eq!(operations[0].completed_work_units, 0);
    Ok(())
}

#[test]
fn issued_quantum_completes_only_after_final_yield() -> Result<(), Box<dyn std::error::Error>> {
    let mut target = ScriptedTarget::completed();
    let mut runtime = SupervisedRuntime::new()?;

    let report = run(&mut target, &mut runtime)?;

    assert!(matches!(
        report.outcome,
        QemuAsyncNodeStepOutcome::Completed { .. }
    ));
    assert_eq!(runtime.scripted.yields, 2);
    assert_eq!(target.finished, 1);
    let operations = &runtime.final_yield_operations;
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].class, HostOperationClass::Quantum);
    assert_eq!(operations[0].state, HostOperationState::Running);
    assert_eq!(operations[0].completed_work_units, 0);
    assert!(runtime.supervisor.operation_statuses()?.is_empty());
    Ok(())
}

#[test]
fn unsupported_metadata_runtime_refuses_without_diagnostic_allocation() {
    use crucible_host_resources::test_support::TestAllocationObserver;
    use std::borrow::Cow;

    let runtime = ScriptedRuntime::new([]);

    let (result, counts) =
        TestAllocationObserver::count(|| runtime.reserve_fault_manifest_metadata(1));

    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("unsupported runtime cannot issue a metadata lease"),
    };
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(matches!(error.message, Cow::Borrowed(_)));
    assert_eq!(error.operation, "reserve fault manifest metadata");
    assert_eq!(
        error.to_string(),
        "reserve fault manifest metadata failed: runtime has no admitted node service allocator"
    );
    assert_eq!(runtime.yields, 0);
    assert_eq!(runtime.awaits, 0);
}

#[test]
fn runtime_refusals_keep_first_and_actual_original_post_at_every_runtime_cut()
-> Result<(), Box<dyn std::error::Error>> {
    for cut in [
        RuntimeRefusalCut::Yield(1),
        RuntimeRefusalCut::Fence,
        RuntimeRefusalCut::Wait(1),
        RuntimeRefusalCut::Wait(2),
        RuntimeRefusalCut::Renew,
        RuntimeRefusalCut::Yield(2),
    ] {
        let mut target = ScriptedTarget::completed();
        let mut runtime = SupervisedRuntime::new()?;
        runtime.refuse_at = Some(cut);
        if matches!(cut, RuntimeRefusalCut::Wait(2) | RuntimeRefusalCut::Renew) {
            runtime.scripted = ScriptedRuntime::new([
                QemuAsyncWaitOutcome::TimedOut,
                QemuAsyncWaitOutcome::Completed,
            ]);
        }

        let error = run(&mut target, &mut runtime).expect_err("actual runtime cut refuses");

        let QemuAsyncDriverError::Runtime(error) = error else {
            panic!("initiating runtime refusal must remain typed at {cut:?}");
        };
        assert_eq!(error.operation, "actual runtime first refusal", "{cut:?}");
        assert_eq!(
            error.operational_supervision_post(),
            Some(
                crucible_host_resources::host_supervision::HostSupervisionError::Terminal {
                    state: HostOperationState::Canceled,
                }
            ),
            "{cut:?}",
        );
        assert_eq!(
            target.finished,
            usize::from(cut == RuntimeRefusalCut::Yield(2))
        );
        assert_eq!(target.shutdowns, 0);
        assert!(
            error
                .to_string()
                .contains("independent host operation postcheck failed")
        );
    }
    Ok(())
}

#[test]
fn lifecycle_runtime_refusals_keep_first_and_actual_original_post()
-> Result<(), Box<dyn std::error::Error>> {
    for wait in [
        QemuAsyncWait::Handshake,
        QemuAsyncWait::QmpCommand,
        QemuAsyncWait::ProcessEvent,
    ] {
        for cut in [RuntimeRefusalCut::Wait(1), RuntimeRefusalCut::Wait(2)] {
            let mut target = ScriptedTarget::completed();
            let mut runtime = SupervisedRuntime::new()?;
            runtime.refuse_at = Some(cut);
            runtime.scripted = ScriptedRuntime::new([
                QemuAsyncWaitOutcome::TimedOut,
                QemuAsyncWaitOutcome::Completed,
            ]);

            let result = await_bounded_lifecycle_event(
                &mut target,
                &mut runtime,
                QemuAsyncDriverPolicy::fast_test(),
                &QemuCrashDetector::new("vm-a"),
                wait,
            );

            let QemuAsyncDriverError::Runtime(error) = result.expect_err("adapter refuses") else {
                panic!("initiating runtime error must remain typed at {wait:?}/{cut:?}");
            };
            assert_eq!(error.operation, "actual runtime first refusal");
            // Cleanup remains live after outer cancellation so containment can
            // still run; its independent post is genuinely successful.
            let expected_post = (wait != QemuAsyncWait::ProcessEvent).then_some(
                crucible_host_resources::host_supervision::HostSupervisionError::Terminal {
                    state: HostOperationState::Canceled,
                },
            );
            assert_eq!(error.operational_supervision_post(), expected_post,);
            assert_eq!(target.shutdowns, 0);
            assert!(target.started.is_empty());
        }
    }
    Ok(())
}
