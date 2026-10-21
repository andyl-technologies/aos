//! Checks actual driver-issued operation cancellation at publication boundaries.
//!
//! The scripted target records effects; it grants no native Source authority.

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationStatus,
    HostOperationSupervisor,
};

struct SupervisedRuntime {
    supervisor: HostOperationSupervisor,
    scripted: ScriptedRuntime,
    cancel_on_yield: Option<usize>,
    cancel_on_wait: bool,
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
            final_yield_operations: Vec::new(),
        })
    }

    fn cancel(&self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.supervisor.cancel().map_err(|source| {
            QemuAsyncDriverRuntimeError::operational_supervision("fixture cancellation", source)
        })
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
        Ok(())
    }

    fn arm_advance_completion_fence(
        &mut self,
        fence: Option<QemuAdvanceCompletionFence>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.scripted.arm_advance_completion_fence(fence)
    }

    fn repoll_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError> {
        self.scripted.repoll_child(wait, timeout)
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
        Ok(outcome)
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
