//! Production source-world launch regressions through scripted QMP.

// crucible-lint: allow panic-shortcut -- fixture-only unreachable process retention and assertions use panic shortcuts.
// crucible-lint: allow rust-allow -- the scripted indeterminate branch deliberately panics if an impossible owned-child path is reached.
#![allow(clippy::expect_used, clippy::panic)]

use std::fs::{File, OpenOptions};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_api::vm_lifecycle::prepared_hot_fork_source_world_for_test;
use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::{
    LinuxQemuHotForkChildProcessAuthority, QemuAsyncDriverPolicy, QemuChildProcessContract,
    QemuCrashDetector, QemuHotForkChildProcessBasis, QemuHotForkChildProcessOwner,
    QemuLaunchResourceRequirements, QemuNodeChannelError, QemuPreparedRunDirectory,
    QemuShutdownPolicy, QemuTestHotForkOutcome, QemuVmRealizationError, linux_process_identity,
    scripted_hot_fork_source_for_test,
};
use rustix::process::{Pid, PidfdFlags, pidfd_open};

use super::*;
use crate::{
    ExecutionCancellation, QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard,
    QemuAttemptResourceGuard,
};

struct ScriptedLaunchGuard {
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    process_contract: QemuChildProcessContract,
    run_root: tempfile::TempDir,
    preparations: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
    retained_child_requests: Arc<Mutex<Vec<crucible_qemu::QmpHotForkRequest>>>,
    terminal: bool,
}

impl QemuAttemptOperationalBoundary for ScriptedLaunchGuard {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }
}

impl QemuAttemptResourceGuard for ScriptedLaunchGuard {
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        self.terminal = true;
        Ok(())
    }

    fn quarantine(&mut self) {
        if !self.terminal {
            self.quarantines.fetch_add(1, Ordering::SeqCst);
            self.terminal = true;
        }
    }
}

impl QemuAttemptProcessResourceGuard for ScriptedLaunchGuard {
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        Ok(&self.process_contract)
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        requirements
            .validate_ceiling(
                self.resources.maximum_vcpus(),
                self.resources.maximum_resident_bytes(),
                self.resources.maximum_disk_bytes(),
            )
            .map_err(|source| launch_test_error(source.to_string()))?;

        let generation = self.run_root.path().join(format!(
            "generation-{}",
            self.preparations.load(Ordering::SeqCst)
        ));
        std::fs::create_dir(&generation).map_err(|source| launch_test_error(source.to_string()))?;
        File::create(generation.join(crucible_qemu::DEFAULT_VMSTATE_FILE_NAME))
            .map_err(|source| launch_test_error(source.to_string()))?;
        if requirements.has_root_overlay() {
            File::create(generation.join(crucible_qemu::DEFAULT_ROOT_OVERLAY_FILE_NAME))
                .map_err(|source| launch_test_error(source.to_string()))?;
        }
        QemuPreparedRunDirectory::open_for_test_requirements(
            requirements,
            &generation,
            &self.process_contract,
        )
        .map_err(|source| launch_test_error(source.to_string()))
    }

    fn retain_failed_launch_child(&mut self, _child: crucible_qemu::QemuNodeChild) {}
}

impl QemuHotForkChildProcessOwner for ScriptedLaunchGuard {
    type Authority = crucible_qemu::LinuxQemuHotForkChildProcessAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        let process_id =
            Pid::from_raw(i32::try_from(basis.child_process_id()).map_err(|error| {
                QemuNodeChannelError::new("retain scripted child", error.to_string())
            })?)
            .ok_or_else(|| {
                QemuNodeChannelError::new("retain scripted child", "child PID must be positive")
            })?;
        let descriptor = pidfd_open(process_id, PidfdFlags::empty()).map_err(|error| {
            QemuNodeChannelError::new("open scripted child pidfd", error.to_string())
        })?;
        let identity = linux_process_identity(basis.child_process_id())
            .map_err(|error| {
                QemuNodeChannelError::new("authenticate scripted child", error.to_string())
            })?
            .ok_or_else(|| {
                QemuNodeChannelError::new(
                    "authenticate scripted child",
                    "scripted child process is absent",
                )
            })?;
        self.retained_child_requests
            .lock()
            .map_err(|_error| {
                QemuNodeChannelError::new(
                    "record scripted child request",
                    "scripted child request registry is poisoned",
                )
            })?
            .push(basis.request());

        Ok(
            LinuxQemuHotForkChildProcessAuthority::from_unvalidated_test_parts(
                basis, identity, descriptor,
            ),
        )
    }
}

fn scripted_guard(
    resources: AttemptResourceLimits,
    preparations: Arc<AtomicUsize>,
    quarantines: Arc<AtomicUsize>,
) -> Result<ScriptedLaunchGuard, Box<dyn Error>> {
    let cgroup = tempfile::tempdir()?;
    let cgroup_directory: OwnedFd = File::open(cgroup.path())?.into();
    let cgroup_procs: OwnedFd = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(cgroup.path().join("cgroup.procs"))?
        .into();
    let cancellation = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )?;
    let process_contract = QemuChildProcessContract::from_unvalidated_hot_fork_test_descriptors(
        cgroup_directory,
        cgroup_procs,
        cancellation,
        resources.maximum_vcpus(),
        resources.maximum_resident_bytes(),
        resources.maximum_disk_bytes(),
    );

    Ok(ScriptedLaunchGuard {
        resources,
        cancellation: ExecutionCancellation::default(),
        process_contract,
        run_root: tempfile::tempdir()?,
        preparations,
        quarantines,
        retained_child_requests: Arc::new(Mutex::new(Vec::new())),
        terminal: false,
    })
}

fn launch_test_error(message: impl Into<String>) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "build scripted hot-fork launch target",
        message: message.into(),
    }
}

#[test]
fn indeterminate_qmp_launch_retains_source_world_and_prepared_directory()
-> Result<(), Box<dyn Error>> {
    let source = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Indeterminate)?;
    let (node, generation, source_world) = prepared_hot_fork_source_world_for_test(source)?;
    let source_world = Arc::new(Mutex::new(source_world));
    let retained_source = Arc::clone(&source_world);
    let weak_source = Arc::downgrade(&source_world);
    let continuation = source_world
        .lock()
        .map_err(|_| std::io::Error::other("source-world lock poisoned"))?
        .fork_continuation()?;
    let assembly = crate::QemuHotForkWorldAssembly::<
        QemuHotForkAttemptReconciliation<
            LinuxQemuHotForkReconciliationBackend<
                crate::QemuHotForkWorldNodeTarget<ScriptedLaunchGuard>,
            >,
        >,
    >::new(continuation);
    let preparations = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let resources = AttemptResourceLimits::new(2, 1024 * 1024 * 1024, 1024 * 1024 * 1024, 8)?;
    let guard = scripted_guard(
        resources,
        Arc::clone(&preparations),
        Arc::clone(&quarantines),
    )?;
    let mut target = QemuHotForkWorldResourceOwner::new(guard, 1)?;
    let error = QemuHotForkAttemptReconciliation::launch_from_source_world(
        source_world,
        node,
        &mut target,
        generation,
        assembly.child_launch_token(),
    )
    .err()
    .ok_or_else(|| std::io::Error::other("indeterminate fork unexpectedly succeeded"))?;
    let (failure, returned_owner) = error.into_parts();

    assert!(matches!(
        failure,
        LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(
            QemuHotForkLaunchError::Indeterminate { .. }
        )
    ));
    let returned_owner = returned_owner
        .into_recoverable_parts()
        .err()
        .ok_or_else(|| std::io::Error::other("indeterminate child authority was recoverable"))?;
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert!(target.finish().is_err());
    assert_eq!(quarantines.load(Ordering::SeqCst), 1);
    drop(retained_source);
    drop(returned_owner);
    assert!(weak_source.upgrade().is_some());
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn rearmed_source_drops_child_contract_after_installed_child_takes_ownership()
-> Result<(), Box<dyn Error>> {
    let source = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked)?;
    let (node, generation, source_world) = prepared_hot_fork_source_world_for_test(source)?;
    let source_world = Arc::new(Mutex::new(source_world));
    let retained_source = Arc::clone(&source_world);
    let continuation = source_world
        .lock()
        .map_err(|_| std::io::Error::other("source-world lock poisoned"))?
        .fork_continuation()?;
    let assembly = crate::QemuHotForkWorldAssembly::<
        QemuHotForkAttemptReconciliation<
            LinuxQemuHotForkReconciliationBackend<
                crate::QemuHotForkWorldNodeTarget<ScriptedLaunchGuard>,
            >,
        >,
    >::new(continuation);
    let preparations = Arc::new(AtomicUsize::new(0));
    let quarantines = Arc::new(AtomicUsize::new(0));
    let resources = AttemptResourceLimits::new(2, 1024 * 1024 * 1024, 1024 * 1024 * 1024, 8)?;
    let guard = scripted_guard(
        resources,
        Arc::clone(&preparations),
        Arc::clone(&quarantines),
    )?;
    let retained_requests = Arc::clone(&guard.retained_child_requests);
    let mut target = QemuHotForkWorldResourceOwner::new(guard, 1)?;
    let mut reconciliation = QemuHotForkAttemptReconciliation::launch_from_source_world(
        source_world,
        node.clone(),
        &mut target,
        generation,
        assembly.child_launch_token(),
    )?;

    let rearmed_stage = retained_source
        .lock()
        .map_err(|_| std::io::Error::other("source-world lock poisoned"))?
        .prepared_source(&node)?
        .hot_fork_child_process_contract_stage_for_test();
    assert!(rearmed_stage.is_none());
    assert_eq!(
        retained_requests
            .lock()
            .map_err(|_| std::io::Error::other("retained request registry is poisoned"))?
            .len(),
        1
    );

    reconciliation.admit_child()?;
    reconciliation.install_scheduler_node(
        node.clone(),
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new(node.name.clone()),
    )?;
    reconciliation.request_termination()?;
    for _ in 0..200 {
        match reconciliation.reconcile_step()? {
            QemuHotForkReconciliationStep::AwaitingPublication => break,
            QemuHotForkReconciliationStep::ChildRunning => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            QemuHotForkReconciliationStep::ChildDiagnosticsDrained
            | QemuHotForkReconciliationStep::Advanced(_) => {}
            QemuHotForkReconciliationStep::Complete => {
                return Err(std::io::Error::other(
                    "child reconciled before publication disposition",
                )
                .into());
            }
        }
    }
    assert_eq!(
        reconciliation.phase(),
        QemuHotForkReconciliationPhase::AwaitingPublication
    );
    reconciliation.reconcile_publication(QemuHotForkPublicationDisposition::Canceled)?;
    for _ in 0..8 {
        if reconciliation.reconcile_step()? == QemuHotForkReconciliationStep::Complete {
            break;
        }
    }
    assert_eq!(
        reconciliation.phase(),
        QemuHotForkReconciliationPhase::Reconciled
    );

    drop(reconciliation);
    target.finish()?;
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert_eq!(quarantines.load(Ordering::SeqCst), 0);

    let source_world = Arc::try_unwrap(retained_source)
        .map_err(|_| std::io::Error::other("reconciled child retained the source world"))?
        .into_inner()
        .map_err(|_| std::io::Error::other("source-world lock poisoned"))?;
    source_world.retire()?;
    Ok(())
}
