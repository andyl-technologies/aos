//! Retained aggregate host resources for portable observation preparation.
//!
//! Source authentication and restored-session construction execute as
//! sequential leases over one Linux cgroup and project-quota owner. The owner
//! remains live across the phase boundary and releases its quota tree only
//! after the final restored lifecycle has reaped its process generation.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::{
    LinuxQemuAttemptHostConfig, QemuChildProcessContract, QemuLaunchResourceRequirements,
    QemuNodeChild, QemuPreparedRunDirectory, QemuVmRealizationError,
};

use super::{LinuxQemuAttemptHostResourceFactory, LinuxQemuAttemptHostResourceOwner};
use crate::{QemuAttemptHostResourceFactory, QemuAttemptHostResourceOwner};

/// Linux workspace retained by a prepared portable observation resume.
pub(crate) type RetainedLinuxQemuAttemptWorkspace =
    RetainedQemuAttemptWorkspace<LinuxQemuAttemptHostResourceOwner>;

/// One host owner retained across sequential observation execution phases.
pub(crate) struct RetainedQemuAttemptWorkspace<H>
where
    H: QemuAttemptHostResourceOwner,
{
    shared: Arc<Mutex<RetainedQemuAttemptWorkspaceState<H>>>,
    path: PathBuf,
    terminal: bool,
}

struct RetainedQemuAttemptWorkspaceState<H>
where
    H: QemuAttemptHostResourceOwner,
{
    owner: Option<H>,
    lease_active: bool,
}

impl RetainedQemuAttemptWorkspace<LinuxQemuAttemptHostResourceOwner> {
    /// Allocates and seals one aggregate Linux request workspace.
    pub(crate) fn allocate(
        config: LinuxQemuAttemptHostConfig,
        resources: AttemptResourceLimits,
    ) -> Result<Self, QemuVmRealizationError> {
        let mut factory = LinuxQemuAttemptHostResourceFactory::open(config)?;
        let mut owner = factory.begin(resources)?;
        let path = owner.host.seal_supervisor_workspace()?;

        Ok(Self::from_owner(owner, path))
    }
}

impl<H> RetainedQemuAttemptWorkspace<H>
where
    H: QemuAttemptHostResourceOwner,
{
    fn from_owner(owner: H, path: PathBuf) -> Self {
        Self {
            shared: Arc::new(Mutex::new(RetainedQemuAttemptWorkspaceState {
                owner: Some(owner),
                lease_active: false,
            })),
            path,
            terminal: false,
        }
    }

    /// Returns the sealed diagnostic path for supervisor-owned metadata.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a factory for the next sequential execution phase.
    pub(crate) fn factory(&self) -> RetainedQemuAttemptHostResourceFactory<H> {
        RetainedQemuAttemptHostResourceFactory {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Reaps the shared process boundary and removes the quota tree.
    pub(crate) fn close(mut self) -> Result<(), QemuVmRealizationError> {
        let result = self.finish();
        self.terminal = true;
        result
    }

    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state =
            self.shared
                .lock()
                .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                    operation: "release retained observation workspace",
                    message: String::from("workspace owner lock is poisoned"),
                })?;
        if state.lease_active {
            if let Some(owner) = state.owner.as_mut() {
                owner.quarantine();
            }
            state.lease_active = false;
            return Err(QemuVmRealizationError::ReapQuarantined {
                operation: "release retained observation workspace",
                message: String::from("an execution lease remains active"),
            });
        }
        let Some(mut owner) = state.owner.take() else {
            return Ok(());
        };
        if let Err(error) = owner.finish() {
            owner.quarantine();
            return Err(error);
        }
        Ok(())
    }
}

impl<H> Drop for RetainedQemuAttemptWorkspace<H>
where
    H: QemuAttemptHostResourceOwner,
{
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        if self.finish().is_err() {
            let mut state = self
                .shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(owner) = state.owner.as_mut() {
                owner.quarantine();
            }
        }
        self.terminal = true;
    }
}

/// Sequential lease factory over one retained observation workspace.
pub(crate) struct RetainedQemuAttemptHostResourceFactory<H>
where
    H: QemuAttemptHostResourceOwner,
{
    shared: Arc<Mutex<RetainedQemuAttemptWorkspaceState<H>>>,
}

impl<H> Clone for RetainedQemuAttemptHostResourceFactory<H>
where
    H: QemuAttemptHostResourceOwner,
{
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

pub(crate) struct RetainedQemuAttemptHostResourceOwner<H>
where
    H: QemuAttemptHostResourceOwner,
{
    shared: Arc<Mutex<RetainedQemuAttemptWorkspaceState<H>>>,
    resources: AttemptResourceLimits,
    contract: QemuChildProcessContract,
    terminal: bool,
}

impl<H> QemuAttemptHostResourceFactory for RetainedQemuAttemptHostResourceFactory<H>
where
    H: QemuAttemptHostResourceOwner,
{
    type Owner = RetainedQemuAttemptHostResourceOwner<H>;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        let mut state =
            self.shared
                .lock()
                .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                    operation: "begin retained observation execution lease",
                    message: String::from("workspace owner lock is poisoned"),
                })?;
        if state.lease_active {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "begin retained observation execution lease",
                message: String::from("another execution phase remains active"),
            });
        }
        let owner =
            state
                .owner
                .as_mut()
                .ok_or_else(|| QemuVmRealizationError::ExecutorUnavailable {
                    operation: "begin retained observation execution lease",
                    message: String::from("workspace owner is no longer available"),
                })?;
        if owner.resource_limits() != resources {
            return Err(QemuVmRealizationError::Executor {
                operation: "begin retained observation execution lease",
                message: String::from("execution phase requested a different resource basis"),
            });
        }
        let contract = owner
            .child_process_contract()?
            .try_clone_for_attempt_generation()
            .map_err(|error| QemuVmRealizationError::ExecutorUnavailable {
                operation: "duplicate retained observation process contract",
                message: error.to_string(),
            })?;
        owner.cancellation_signal()?;
        state.lease_active = true;

        Ok(RetainedQemuAttemptHostResourceOwner {
            shared: Arc::clone(&self.shared),
            resources,
            contract,
            terminal: false,
        })
    }
}

impl<H> QemuAttemptHostResourceOwner for RetainedQemuAttemptHostResourceOwner<H>
where
    H: QemuAttemptHostResourceOwner,
{
    type CancellationSignal = H::CancellationSignal;

    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Ok(&self.contract)
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        let mut state = retained_workspace_state(&self.shared)?;
        retained_workspace_owner(&mut state)?.prepare_generation_run_directory(requirements)
    }

    fn cancellation_signal(&self) -> Result<Self::CancellationSignal, QemuVmRealizationError> {
        let mut state = retained_workspace_state(&self.shared)?;
        retained_workspace_owner(&mut state)?.cancellation_signal()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = retained_workspace_state(&self.shared)?;
        retained_workspace_owner(&mut state)?.check_operational_boundary()
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        match self.shared.lock() {
            Ok(mut state) => {
                if let Some(owner) = state.owner.as_mut() {
                    owner.retain_failed_launch_child(child);
                } else {
                    let _leaked = Box::leak(Box::new(child));
                }
            }
            Err(_) => {
                let _leaked = Box::leak(Box::new(child));
            }
        }
    }

    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.terminal {
            return Ok(());
        }
        let mut state = retained_workspace_state(&self.shared)?;
        state.lease_active = false;
        self.terminal = true;
        Ok(())
    }

    fn quarantine(&mut self) {
        if self.terminal {
            return;
        }
        let mut state = self
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(owner) = state.owner.as_mut() {
            owner.quarantine();
        }
        state.lease_active = false;
        self.terminal = true;
    }
}

fn retained_workspace_state<H>(
    shared: &Arc<Mutex<RetainedQemuAttemptWorkspaceState<H>>>,
) -> Result<MutexGuard<'_, RetainedQemuAttemptWorkspaceState<H>>, QemuVmRealizationError>
where
    H: QemuAttemptHostResourceOwner,
{
    shared
        .lock()
        .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
            operation: "access retained observation workspace",
            message: String::from("workspace owner lock is poisoned"),
        })
}

fn retained_workspace_owner<H>(
    state: &mut RetainedQemuAttemptWorkspaceState<H>,
) -> Result<&mut H, QemuVmRealizationError>
where
    H: QemuAttemptHostResourceOwner,
{
    state
        .owner
        .as_mut()
        .ok_or_else(|| QemuVmRealizationError::ExecutorUnavailable {
            operation: "access retained observation workspace",
            message: String::from("workspace owner is no longer available"),
        })
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture failures should identify the exact ownership transition.
    #![allow(clippy::expect_used)]

    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crucible::NodeId;
    use crucible_api::{ProductionVmNodeGeneration, ProductionVmNodeLease};

    use super::*;
    use crate::{
        ComposedQemuAttemptResourceGuardFactory, ExecutionCancellation,
        QemuAttemptCancellationSignal, QemuAttemptGenerationResourceOwner,
        QemuAttemptResourceGuardFactory,
    };

    #[derive(Default)]
    struct FakeWorkspaceCounters {
        signals: AtomicUsize,
        finishes: AtomicUsize,
        quarantines: AtomicUsize,
    }

    struct FakeWorkspaceOwner {
        resources: AttemptResourceLimits,
        contract: QemuChildProcessContract,
        root: PathBuf,
        counters: Arc<FakeWorkspaceCounters>,
        terminal: bool,
    }

    impl QemuAttemptHostResourceOwner for FakeWorkspaceOwner {
        type CancellationSignal = FakeWorkspaceCancellation;

        fn resource_limits(&self) -> AttemptResourceLimits {
            self.resources
        }

        fn child_process_contract(
            &self,
        ) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
            Ok(&self.contract)
        }

        fn prepare_generation_run_directory(
            &mut self,
            _requirements: QemuLaunchResourceRequirements,
        ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
            Err(QemuVmRealizationError::Executor {
                operation: "prepare fake observation generation",
                message: String::from("the ownership test does not launch QEMU"),
            })
        }

        fn cancellation_signal(&self) -> Result<Self::CancellationSignal, QemuVmRealizationError> {
            Ok(FakeWorkspaceCancellation {
                counters: Arc::clone(&self.counters),
            })
        }

        fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
            Ok(())
        }

        fn retain_failed_launch_child(&mut self, _child: QemuNodeChild) {}

        fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
            if self.terminal {
                return Ok(());
            }
            std::fs::remove_dir_all(&self.root).map_err(|error| {
                QemuVmRealizationError::ExecutorUnavailable {
                    operation: "remove fake observation workspace",
                    message: error.to_string(),
                }
            })?;
            self.counters.finishes.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
            Ok(())
        }

        fn quarantine(&mut self) {
            if self.terminal {
                return;
            }
            let _ = std::fs::remove_dir_all(&self.root);
            self.counters.quarantines.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
    }

    struct FakeWorkspaceCancellation {
        counters: Arc<FakeWorkspaceCounters>,
    }

    impl QemuAttemptCancellationSignal for FakeWorkspaceCancellation {
        fn signal(&self) -> Result<(), QemuVmRealizationError> {
            self.counters.signals.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn resources() -> AttemptResourceLimits {
        AttemptResourceLimits::new(1, 64 * 1024 * 1024, 128 * 1024 * 1024, 8)
            .expect("fake workspace resources")
    }

    fn workspace_fixture() -> (
        tempfile::TempDir,
        PathBuf,
        Arc<FakeWorkspaceCounters>,
        RetainedQemuAttemptWorkspace<FakeWorkspaceOwner>,
    ) {
        let parent = tempfile::tempdir().expect("workspace parent");
        let root = parent.path().join("quota-root");
        std::fs::create_dir(&root).expect("fake quota root");
        let (cgroup_procs, _cgroup_peer) = UnixStream::pair().expect("fake cgroup descriptors");
        let (cancellation, _cancellation_peer) =
            UnixStream::pair().expect("fake cancellation descriptors");
        let limits = resources();
        let counters = Arc::new(FakeWorkspaceCounters::default());
        let owner = FakeWorkspaceOwner {
            resources: limits,
            contract: QemuChildProcessContract::from_unvalidated_test_descriptors(
                cgroup_procs.into(),
                cancellation.into(),
                limits.maximum_vcpus(),
                limits.maximum_resident_bytes(),
                limits.maximum_disk_bytes(),
            ),
            root: root.clone(),
            counters: Arc::clone(&counters),
            terminal: false,
        };
        let workspace = RetainedQemuAttemptWorkspace::from_owner(owner, root.clone());
        (parent, root, counters, workspace)
    }

    fn generation() -> ProductionVmNodeGeneration {
        ProductionVmNodeGeneration::new(
            NodeId {
                name: String::from("vm"),
            },
            1,
        )
        .expect("valid test generation")
    }

    #[test]
    fn source_generation_must_reap_before_restore_lease_and_final_cleanup() {
        let (_parent, root, counters, workspace) = workspace_fixture();
        let mut source_factory = ComposedQemuAttemptResourceGuardFactory::new(workspace.factory());
        let source_guard = source_factory
            .begin(resources(), ExecutionCancellation::default())
            .expect("source execution lease");
        let mut source = QemuAttemptGenerationResourceOwner::new(source_guard, 1)
            .expect("source generation owner");
        let mut source_generation = source
            .register_generation(generation())
            .expect("source physical generation");

        let mut restore_factory = ComposedQemuAttemptResourceGuardFactory::new(workspace.factory());
        assert!(
            restore_factory
                .begin(resources(), ExecutionCancellation::default())
                .is_err()
        );
        assert!(root.exists());
        assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);

        source_generation
            .finish()
            .expect("source generation reaped");
        source.finish().expect("source execution lease released");
        let restore_guard = restore_factory
            .begin(resources(), ExecutionCancellation::default())
            .expect("restore lease after source reap");
        let mut restore = QemuAttemptGenerationResourceOwner::new(restore_guard, 1)
            .expect("restored generation owner");
        let mut restored_generation = restore
            .register_generation(generation())
            .expect("restored physical generation");
        assert!(root.exists());
        assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);

        restored_generation
            .finish()
            .expect("restored generation reaped");
        restore.finish().expect("restore execution lease released");
        workspace.close().expect("final workspace cleanup");
        assert!(!root.exists());
        assert_eq!(counters.finishes.load(Ordering::SeqCst), 1);
        assert_eq!(counters.quarantines.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn canceled_abandoned_phase_quarantines_and_removes_workspace() {
        let (_parent, root, counters, workspace) = workspace_fixture();
        let cancellation = ExecutionCancellation::default();
        let mut factory = ComposedQemuAttemptResourceGuardFactory::new(workspace.factory());
        let guard = factory
            .begin(resources(), cancellation.clone())
            .expect("observation execution lease");

        cancellation.cancel();
        drop(guard);
        drop(workspace);

        assert!(!root.exists());
        assert_eq!(counters.signals.load(Ordering::SeqCst), 1);
        assert_eq!(counters.finishes.load(Ordering::SeqCst), 0);
        assert_eq!(counters.quarantines.load(Ordering::SeqCst), 1);
    }
}
