//! Attempt-scoped live-QEMU session composition.
//!
//! The adapter in this module binds three independently testable authorities:
//! policy-controlled VM realization, an operational resource/cancellation
//! guard installed before launch, and a modeled attempt driver that receives
//! only the already-realized backend. Assignment IDs and daemon epochs never
//! cross this boundary.

use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuNodeChild,
    QemuPreparedRunDirectory, QemuVmRealizationError,
};

use crate::ExecutionCancellation;

/// Read-only operational boundary available to a modeled attempt driver.
///
/// This capability cannot release or quarantine resource enforcement.
pub trait QemuAttemptOperationalBoundary {
    /// Returns the exact hard ceilings installed for this attempt.
    #[must_use]
    fn resource_limits(&self) -> AttemptResourceLimits;

    /// Returns the process-local cancellation signal watched by the guard.
    #[must_use]
    fn cancellation(&self) -> &ExecutionCancellation;

    /// Checks cancellation and the remaining execution-quanta budget.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::Canceled`] after cancellation and a
    /// stable executor error after a hard resource ceiling is exhausted.
    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError>;

    /// Charges one scheduler-authorized execution quantum before guest progress.
    ///
    /// # Errors
    ///
    /// Returns a stable executor error when the admitted quantum ceiling is
    /// exhausted, or [`QemuVmRealizationError::Canceled`] after cancellation.
    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError>;
}

/// Checked per-attempt execution-quantum counter for concrete resource guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuExecutionQuantumCounter {
    ceiling: u64,
    charged: u64,
}

impl QemuExecutionQuantumCounter {
    /// Creates a zero-spent counter from the admitted resource limits.
    #[must_use]
    pub const fn new(resources: AttemptResourceLimits) -> Self {
        Self {
            ceiling: resources.maximum_execution_quanta(),
            charged: 0,
        }
    }

    /// Returns the exact admitted quantum ceiling.
    #[must_use]
    pub const fn ceiling(self) -> u64 {
        self.ceiling
    }

    /// Returns the number of quanta charged so far.
    #[must_use]
    pub const fn charged(self) -> u64 {
        self.charged
    }

    /// Charges one quantum before guest progress.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::Executor`] without changing the
    /// counter when the exact admitted ceiling has already been spent.
    pub fn charge(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.charged >= self.ceiling {
            return Err(QemuVmRealizationError::Executor {
                operation: "charge QEMU execution quantum",
                message: String::from("execution quantum ceiling is exhausted"),
            });
        }
        self.charged += 1;
        Ok(())
    }
}

/// Operational guard installed before one attempt can launch QEMU.
///
/// A conforming guard owns the host-side CPU, memory, writable-disk, and
/// execution-quanta enforcement for its lifetime. Its cancellation path must
/// be able to interrupt a blocked process operation rather than relying only
/// on caller polling.
pub trait QemuAttemptResourceGuard: QemuAttemptOperationalBoundary {
    /// Releases the installed resource controls after QEMU has been reaped.
    ///
    /// This operation must be idempotent. An error may report cleanup
    /// diagnostics only after the guard has completed its release ladder.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when cleanup completed with an
    /// operational diagnostic failure.
    fn finish(&mut self) -> Result<(), QemuVmRealizationError>;

    /// Transfers enforcement to a supervisor-owned quarantine after failed reap.
    ///
    /// This operation is infallible and idempotent. It must keep every resource
    /// ceiling active until the quarantine reaper attests that the process is
    /// gone; it must not release the guard in the calling session.
    fn quarantine(&mut self);
}

/// Resource guard that can lend one sealed child-process launch contract.
///
/// The returned capability is read-only and cannot release cgroup, quota,
/// cancellation, quantum, watcher, or quarantine ownership. It remains valid
/// only while the attempt guard is live.
pub trait QemuAttemptProcessResourceGuard: QemuAttemptResourceGuard {
    /// Returns the exact child-process containment contract for this attempt.
    ///
    /// # Errors
    ///
    /// Returns an operational error after terminal cleanup has closed launch
    /// authority or when the host owner cannot authenticate the contract.
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError>;

    /// Provisions and lends the descriptor-pinned run-directory capability.
    ///
    /// # Errors
    ///
    /// Returns an operational error when the launch profile exceeds the admitted
    /// resources or the aggregate storage identity, fresh generation
    /// directory, or VMState policy cannot be authenticated.
    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError>;

    /// Retains a direct child whose failed realization could not reap it.
    ///
    /// This transfer is infallible: the guard must retain the nonduplicable
    /// child authority itself or move it to a nondroppable quarantine owner.
    /// It must not release attempt resources until that owner attests reap.
    fn retain_failed_launch_child(&mut self, child: QemuNodeChild);
}

/// Factory for one pre-launch attempt resource guard.
pub(crate) trait QemuAttemptResourceGuardFactory {
    /// Guard retained for the complete process lifetime.
    type Guard: QemuAttemptResourceGuard;

    /// Installs the exact admitted resource and cancellation contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the host cannot install every
    /// requested ceiling. Failure must leave no reservation or process behind.
    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, QemuAttemptResourceGuardBeginFailure>;
}

/// Failed resource construction and any selection claim not yet spent.
#[derive(Debug)]
pub(crate) struct QemuAttemptResourceGuardBeginFailure {
    // Box only the large diagnostic; this failure still owns the selection claim.
    error: Box<QemuVmRealizationError>,
    selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
}

impl QemuAttemptResourceGuardBeginFailure {
    pub(crate) fn before_checkpoint_claim(
        error: QemuVmRealizationError,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Self {
        Self {
            error: Box::new(error),
            selected_checkpoint,
        }
    }

    pub(crate) fn after_checkpoint_claim(error: QemuVmRealizationError) -> Self {
        Self {
            error: Box::new(error),
            selected_checkpoint: None,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        QemuVmRealizationError,
        Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) {
        (*self.error, self.selected_checkpoint)
    }
}

impl From<QemuVmRealizationError> for QemuAttemptResourceGuardBeginFailure {
    fn from(error: QemuVmRealizationError) -> Self {
        Self::after_checkpoint_claim(error)
    }
}
