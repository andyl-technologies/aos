//! Real-QEMU rejection of missing or aliased branch-private child files.

// crucible-lint: allow panic-shortcut -- native gate assertions use panic shortcuts.
#![allow(clippy::expect_used)]

use super::*;
use crate::{
    ExecutionCancellation, QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard,
    QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory,
};
use crucible_qemu::{
    QemuChildProcessContract, QemuHotForkChildProcessBasis, QemuLaunchResourceRequirements,
    QemuNodeChannelError, QemuPreparedRunDirectory, QemuVmRealizationError,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
pub(super) enum ChildFileFault {
    Missing,
    Aliased,
}

impl ChildFileFault {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Missing => "omission",
            Self::Aliased => "alias",
        }
    }
}

pub(super) struct InvalidChildFileFactory<R> {
    pub(super) inner: R,
    pub(super) fault: Option<ChildFileFault>,
    pub(super) injected_files: Arc<AtomicUsize>,
}

pub(super) struct InvalidChildFileGuard<G> {
    inner: G,
    fault: Option<ChildFileFault>,
    prepared_files: Vec<PathBuf>,
    injected_files: Arc<AtomicUsize>,
}

impl<R: QemuAttemptResourceGuardFactory> QemuAttemptResourceGuardFactory
    for InvalidChildFileFactory<R>
{
    type Guard = InvalidChildFileGuard<R::Guard>;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>
    {
        Ok(InvalidChildFileGuard {
            inner: self
                .inner
                .begin(resources, cancellation, selected_checkpoint)?,
            fault: self.fault,
            prepared_files: Vec::new(),
            injected_files: Arc::clone(&self.injected_files),
        })
    }
}

impl<G: QemuAttemptOperationalBoundary> QemuAttemptOperationalBoundary
    for InvalidChildFileGuard<G>
{
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

impl<G: QemuAttemptResourceGuard> QemuAttemptResourceGuard for InvalidChildFileGuard<G> {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        self.inner.finish()
    }

    fn quarantine(&mut self) {
        self.inner.quarantine();
    }
}

impl<G: QemuAttemptProcessResourceGuard> QemuAttemptProcessResourceGuard
    for InvalidChildFileGuard<G>
{
    fn native_resource_controller(
        &mut self,
    ) -> Result<Option<crucible_qemu::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        self.inner.native_resource_controller()
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.inner.child_process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let directory = self.inner.prepare_generation_run_directory(requirements)?;

        let named_file = directory
            .path()
            .join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME);
        match self.fault {
            None => {}
            Some(ChildFileFault::Missing) => {
                // The descriptor remains pinned while its required name is gone.
                fs::remove_file(&named_file).expect("remove named child VMState destination");
                self.injected_files.fetch_add(1, Ordering::SeqCst);
            }
            Some(ChildFileFault::Aliased) => {
                self.prepared_files.push(named_file);
                if self.prepared_files.len() == 2 {
                    let anchor = directory.path().join("aliased-child-vmstate");
                    fs::File::create(&anchor).expect("create distinct alias target");
                    for path in &self.prepared_files {
                        // Both destinations now name one new inode, distinct
                        // from each child file retained by the resource guard.
                        fs::remove_file(path).expect("remove original child destination");
                        fs::hard_link(&anchor, path).expect("alias child destinations");
                        self.injected_files.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        Ok(directory)
    }

    fn retain_failed_launch_child(&mut self, child: crucible_qemu::QemuNodeChild) {
        self.inner.retain_failed_launch_child(child);
    }
}

impl<G: crucible_qemu::QemuHotForkChildProcessOwner> crucible_qemu::QemuHotForkChildProcessOwner
    for InvalidChildFileGuard<G>
{
    type Authority = G::Authority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        self.inner.retain_hot_fork_child(basis)
    }
}
