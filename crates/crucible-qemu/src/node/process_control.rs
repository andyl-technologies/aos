//! Process-control adaptation for direct and QEMU-parented node generations.
//!
//! A freshly spawned QEMU is a direct daemon child and carries a
//! [`std::process::Child`] wait handle. A hot-fork generation is instead a
//! direct child of its retained source QEMU. The latter must use pidfd signals
//! and source-parent status observations without pretending that the daemon
//! owns `waitpid` authority.

use std::fmt;
use std::process::ExitStatus;
use std::time::Duration;

use super::{
    QemuChildWait, QemuHotForkChildProcessBasis, QemuNodeChild, QemuReap, QemuShutdownRung,
    QemuShutdownTargetError,
};

/// Non-owning process-control loan for one externally parented QEMU node.
///
/// The implementation may signal only the exact authenticated process
/// generation and must derive terminal status from its real direct parent. It
/// must not call `waitpid` for a process the daemon did not spawn. Dropping the
/// loan must not release or forget the outer lifecycle's sole process, cgroup,
/// parent-status, or quarantine authority.
///
/// Hot-fork assembly accepts this capability only together with the opaque
/// branch-private scheduler continuation. The process owner remains outside
/// [`super::QemuNode`] and outlives every loan installed into the modeled node.
pub trait QemuNodeExternalProcessControl: fmt::Debug + Send {
    /// Returns the exact retained-template process-generation basis.
    #[must_use]
    fn hot_fork_process_basis(&self) -> QemuHotForkChildProcessBasis;

    /// Returns the positive operating-system process identifier.
    #[must_use]
    fn process_id(&self) -> u32;

    /// Returns whether the real direct parent has observed terminal status.
    #[must_use]
    fn reaped(&self) -> bool;

    /// Polls the real parent once for an exact terminal status.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when the source-parent status
    /// channel fails or contradicts the retained process generation.
    fn try_wait_natural_exit(&mut self) -> Result<Option<ExitStatus>, QemuShutdownTargetError>;

    /// Sends `SIGTERM` through the exact process-generation capability.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when the exact signal fails.
    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError>;

    /// Sends `SIGKILL` through the exact process-generation capability.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when the exact signal fails.
    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError>;

    /// Waits boundedly for the real parent to observe terminal status.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when polling fails or the process
    /// generation changes.
    fn wait_for_exit(
        &mut self,
        rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError>;

    /// Performs the final bounded parent-status observation.
    ///
    /// This method observes but does not release the source parent's retained
    /// status record; release remains an outer-lifecycle operation after
    /// semantic publication reconciliation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuShutdownTargetError`] when polling fails or the process
    /// generation changes.
    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError>;
}

/// Keeps checkpoint custody with the actual externally parented process loan.
///
/// The real direct parent retains wait authority. Dropping this adapter cannot
/// manufacture a reap or return native custody from a signal request.
#[derive(Debug)]
pub(super) struct ExternalNodeProcess {
    control: Box<dyn QemuNodeExternalProcessControl>,
    #[cfg(target_os = "linux")]
    checkpoint_original: Option<super::exact_snapshot::capture_original::CheckpointOriginal>,
}

impl ExternalNodeProcess {
    #[cfg(target_os = "linux")]
    fn observe_reap(&mut self) {
        if self.control.reaped()
            && let Some(original) = self.checkpoint_original.as_mut()
        {
            original.retire_after_reap();
        }
    }
}

impl Drop for ExternalNodeProcess {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.observe_reap();
        // Without a real parent receipt, the original's receiving destructor
        // retains its actual event, operation, and account through containment.
    }
}

pub(super) enum QemuNodeProcessControl {
    Direct(QemuNodeChild),
    External(ExternalNodeProcess),
}

impl fmt::Debug for QemuNodeProcessControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(child) => formatter.debug_tuple("Direct").field(child).finish(),
            Self::External(control) => formatter.debug_tuple("External").field(control).finish(),
        }
    }
}

impl QemuNodeProcessControl {
    pub(super) fn external(control: Box<dyn QemuNodeExternalProcessControl>) -> Self {
        Self::External(ExternalNodeProcess {
            control,
            #[cfg(target_os = "linux")]
            checkpoint_original: None,
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn checkpoint_original(
        &self,
    ) -> Option<&super::exact_snapshot::capture_original::CheckpointOriginal> {
        match self {
            Self::Direct(child) => child.checkpoint_original.as_ref(),
            Self::External(child) => child.checkpoint_original.as_ref(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn checkpoint_original_slot(
        &mut self,
    ) -> &mut Option<super::exact_snapshot::capture_original::CheckpointOriginal> {
        match self {
            Self::Direct(child) => &mut child.checkpoint_original,
            Self::External(child) => &mut child.checkpoint_original,
        }
    }

    pub(super) fn reaped(&self) -> bool {
        match self {
            Self::Direct(child) => child.reaped(),
            Self::External(child) => child.control.reaped(),
        }
    }

    pub(super) fn process_id(&self) -> u32 {
        match self {
            Self::Direct(child) => child.process_id(),
            Self::External(child) => child.control.process_id(),
        }
    }

    pub(super) fn try_wait_natural_exit(
        &mut self,
    ) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        match self {
            Self::Direct(child) => child.try_wait_natural_exit(),
            Self::External(child) => {
                let result = child.control.try_wait_natural_exit();
                #[cfg(target_os = "linux")]
                child.observe_reap();
                result
            }
        }
    }

    pub(super) fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        match self {
            Self::Direct(child) => child.send_sigterm(),
            Self::External(child) => child.control.send_sigterm(),
        }
    }

    pub(super) fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        match self {
            Self::Direct(child) => child.send_sigkill(),
            Self::External(child) => child.control.send_sigkill(),
        }
    }

    pub(super) fn wait_for_exit(
        &mut self,
        rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        match self {
            Self::Direct(child) => child.wait_for_exit(rung, timeout),
            Self::External(child) => {
                let result = child.control.wait_for_exit(rung, timeout);
                #[cfg(target_os = "linux")]
                child.observe_reap();
                result
            }
        }
    }

    pub(super) fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        match self {
            Self::Direct(child) => child.reap(timeout),
            Self::External(child) => {
                let result = child.control.reap(timeout);
                #[cfg(target_os = "linux")]
                child.observe_reap();
                result
            }
        }
    }

    pub(super) fn force_kill_and_reap_failed_realization(
        &mut self,
    ) -> Result<(), QemuShutdownTargetError> {
        match self {
            Self::Direct(child) => child.force_kill_and_reap_failed_realization(),
            Self::External(_) => Err(QemuShutdownTargetError::new(
                "reap failed QEMU realization",
                "externally parented QEMU must be reconciled by its retained outer lifecycle",
            )),
        }
    }

    pub(super) fn into_direct_child(self) -> Option<QemuNodeChild> {
        match self {
            Self::Direct(child) => Some(child),
            Self::External(_control) => None,
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn retain_external_launch_cleanup(
    process: Box<dyn QemuNodeExternalProcessControl>,
    cleanup: crate::launch_cleanup::LaunchCleanup,
) -> Box<dyn QemuNodeExternalProcessControl> {
    Box::new(ExternalLaunchCleanup { process, cleanup })
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ExternalLaunchCleanup {
    process: Box<dyn QemuNodeExternalProcessControl>,
    cleanup: crate::launch_cleanup::LaunchCleanup,
}

#[cfg(target_os = "linux")]
impl ExternalLaunchCleanup {
    fn observe_terminal(&self) {
        let _ = self.cleanup.observe_external_process(self.process.as_ref());
    }
}

#[cfg(target_os = "linux")]
impl QemuNodeExternalProcessControl for ExternalLaunchCleanup {
    fn hot_fork_process_basis(&self) -> QemuHotForkChildProcessBasis {
        self.process.hot_fork_process_basis()
    }
    fn process_id(&self) -> u32 {
        self.process.process_id()
    }
    fn reaped(&self) -> bool {
        self.observe_terminal();
        self.process.reaped()
    }
    fn try_wait_natural_exit(&mut self) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        let status = self.process.try_wait_natural_exit()?;
        self.observe_terminal();
        Ok(status)
    }
    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.process.send_sigterm()
    }
    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.process.send_sigkill()
    }
    fn wait_for_exit(
        &mut self,
        rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        let status = self.process.wait_for_exit(rung, timeout)?;
        self.observe_terminal();
        Ok(status)
    }
    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        let status = self.process.reap(timeout)?;
        self.observe_terminal();
        Ok(status)
    }
}

#[cfg(target_os = "linux")]
impl Drop for ExternalLaunchCleanup {
    fn drop(&mut self) {
        self.observe_terminal();
        if !self.cleanup.cleanup_proven() {
            self.cleanup.quarantine();
        }
    }
}
