//! Native failure injection that preserves the underlying Linux authority.

use crate::ExecutionCancellation;
use crate::{
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    QemuAttemptResourceGuardFactory,
};
use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::QemuVmRealizationError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct FinishFailingFactory<R> {
    pub(super) inner: R,
    pub(super) failures: Arc<AtomicUsize>,
}

pub(super) struct FinishFailingGuard<G> {
    inner: G,
    failures: Arc<AtomicUsize>,
}

impl<R: QemuAttemptResourceGuardFactory> QemuAttemptResourceGuardFactory
    for FinishFailingFactory<R>
{
    type Guard = FinishFailingGuard<R::Guard>;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>
    {
        Ok(FinishFailingGuard {
            inner: self
                .inner
                .begin(resources, cancellation, selected_checkpoint)?,
            failures: Arc::clone(&self.failures),
        })
    }
}

impl<G: QemuAttemptOperationalBoundary> QemuAttemptOperationalBoundary for FinishFailingGuard<G> {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.inner.resource_limits()
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        self.inner.cancellation()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.inner.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.inner.charge_execution_quantum()
    }
}

impl<G: QemuAttemptResourceGuard> QemuAttemptResourceGuard for FinishFailingGuard<G> {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(QemuVmRealizationError::Executor {
                operation: "finish native atomic-world target resources",
                message: "injected target guard finish failure".into(),
            });
        }
        self.inner.finish()
    }

    fn quarantine(&mut self) {
        self.inner.quarantine();
    }
}

impl<G: QemuAttemptProcessResourceGuard> QemuAttemptProcessResourceGuard for FinishFailingGuard<G> {
    fn native_resource_controller(
        &mut self,
    ) -> Result<Option<crucible_qemu::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        self.inner.native_resource_controller()
    }

    fn child_process_contract(
        &self,
    ) -> Result<&crucible_qemu::QemuChildProcessContract, QemuVmRealizationError> {
        self.inner.child_process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: crucible_qemu::QemuLaunchResourceRequirements,
    ) -> Result<crucible_qemu::QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.inner.prepare_generation_run_directory(requirements)
    }

    fn retain_failed_launch_child(&mut self, child: crucible_qemu::QemuNodeChild) {
        self.inner.retain_failed_launch_child(child);
    }
}

impl<G: crucible_qemu::QemuHotForkChildProcessOwner> crucible_qemu::QemuHotForkChildProcessOwner
    for FinishFailingGuard<G>
{
    type Authority = G::Authority;
    fn retain_hot_fork_child(
        &mut self,
        basis: crucible_qemu::QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, crucible_qemu::QemuNodeChannelError> {
        self.inner.retain_hot_fork_child(basis)
    }
}
