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

/// Resource guard that lends launch and monotonic kernel-control capabilities.
///
/// The launch contract is read-only. Native resource control can only tighten
/// the same pinned physical reservation; neither capability releases cgroup,
/// quota, watcher or quarantine ownership. Retirement closes their authority.
pub trait QemuAttemptProcessResourceGuard: QemuAttemptResourceGuard {
    /// Retains the actual target purpose in its existing RAM cleanup custody.
    ///
    /// # Errors
    /// Refuses missing target ownership, a foreign contract or keeper admission.
    #[cfg(target_os = "linux")]
    fn bind_fork_target_ram_custody(
        &mut self,
        _contract: &QemuChildProcessContract,
        _registration: &crucible_qemu::ram_control::RamControlRegistration,
        _supervisor: &crucible_linux_resource::host_supervision::HostOperationSupervisor,
        _guest_ram_bytes: u64,
        _custody: &crucible_qemu::QemuRamLaunchCustody,
    ) -> Result<(), QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "retain same-family QEMU target RAM purpose",
            message: String::from("guard has no authenticated target RAM keeper"),
        })
    }

    /// Reports retained same-family target custody before source cleanup.
    #[cfg(target_os = "linux")]
    fn fork_target_is_owned(&self) -> bool {
        false
    }

    /// Lends the genuine source owner's single same-family target permit.
    ///
    /// # Errors
    /// Refuses non-source, terminal or already loaned physical ownership.
    #[cfg(target_os = "linux")]
    fn lend_fork_target_permit(
        &mut self,
    ) -> Result<crucible_qemu::LinuxQemuForkTargetPermit, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "lend same-family QEMU target permit",
            message: String::from("guard has no genuine source owner"),
        })
    }

    /// Prepares a target generation under this source's existing project quota.
    ///
    /// # Errors
    /// Refuses a foreign target contract, missing source or unavailable storage.
    #[cfg(target_os = "linux")]
    fn prepare_fork_target_run_directory(
        &mut self,
        _target_contract: &QemuChildProcessContract,
        _requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "prepare same-family QEMU target directory",
            message: String::from("guard has no genuine source storage owner"),
        })
    }

    /// Checks actual Node, host and Preparation custody before publication.
    ///
    /// # Errors
    /// Refuses absent or different original physical custody without effects.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn verify_parent_park_binding(
        &self,
        _source: &crucible_qemu::QemuNodeSetPreparedHotForkSource<'_>,
        original: &std::sync::Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
        _decoder: &crucible_qemu::OriginalActorParkCaller,
    ) -> Result<(), crucible_qemu::OriginalActorParkQuiescenceError> {
        Err(crucible_qemu::OriginalActorParkQuiescenceError::Binding {
            first: crucible_qemu::OriginalActorAccountError::Unavailable,
            original_after: original.wait_slice().err(),
        })
    }

    /// Enters the fixed actor phase through the actual containing host owner.
    ///
    /// # Errors
    /// Refuses missing original slot, actor or concrete physical host custody.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn enter_parent_park_quiescence(
        &self,
        _source: &crucible_qemu::QemuNodeSetPreparedHotForkSource<'_>,
        original: &std::sync::Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
        _decoder: &crucible_qemu::OriginalActorParkCaller,
    ) -> Result<
        crucible_qemu::OriginalActorParkQuiescence,
        crucible_qemu::OriginalActorParkQuiescenceError,
    > {
        Err(crucible_qemu::OriginalActorParkQuiescenceError::Binding {
            first: crucible_qemu::OriginalActorAccountError::Unavailable,
            original_after: original.wait_slice().err(),
        })
    }

    /// Constructs the fixed pair imports through the actual retained host.
    ///
    /// # Errors
    /// Refuses missing original physical custody or actual import admission.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn prepare_parent_park_imports(
        &self,
        _source: &crucible_qemu::QemuNodeSetPreparedHotForkSource<'_>,
        _original: &std::sync::Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
        _decoder: &crucible_qemu::OriginalActorParkCaller,
        _actor: &crucible_linux_resource::host_supervision::HostOperationGuard,
        _family: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu::OriginalActorParkImports, crucible_qemu::OriginalActorParkImportError>
    {
        Err(crucible_qemu::OriginalActorAccountError::Unavailable.into())
    }

    /// Retains the existing registry through private original control retirement.
    ///
    /// This is a custody binding, not a resource grant or retirement assertion.
    ///
    /// # Errors
    /// Refuses replacing a previously retained registry binding.
    fn retain_original_native_registry(
        &mut self,
        _registry: crate::HostOperationalRegistry,
    ) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }

    /// Lends monotonic kernel control tied to this physical owner's retirement.
    ///
    /// # Errors
    /// Returns an operational error when live pinned authority cannot be lent.
    /// Non-native fixture guards return `None`; production admission requires
    /// the actual controller before granting realized RAM resources.
    fn native_resource_controller(
        &mut self,
    ) -> Result<Option<crucible_qemu::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        Ok(None)
    }

    /// Launches a fresh node through the same retained physical owner.
    ///
    /// Original owners preserve their closed generation witness and typed
    /// refusal custody. Other owners use the ordinary admitted fresh route.
    ///
    /// # Errors
    /// Returns the actual fresh admission or launch refusal.
    fn launch_fresh_node(
        &self,
        config: &crucible_qemu::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu::QemuNode, crucible_qemu::QemuLiveNodeStepGateError> {
        crucible_qemu::launch_qemu_production_fresh_node(config, admission)
    }

    /// Lends the actual installed issuer without duplicating the native owner.
    ///
    /// # Errors
    /// Refuses absent, retired, foreign or uncertain installed original custody.
    fn installed_node_issuer(
        &self,
    ) -> Result<crucible_qemu::InstalledNodeLaunchIssuer, crucible_qemu::QemuLiveNodeStepGateError>
    {
        Err(
            crucible_qemu::QemuLiveNodeStepGateError::OriginalNativeAccount {
                source: crucible_qemu::OriginalActorAccountError::Unavailable,
            },
        )
    }

    /// Restores an exact node through the same retained physical issuer.
    ///
    /// # Errors
    /// Refuses owners without installed original custody, or actual restore and
    /// independent original checks. The consumed request cannot select an issuer.
    fn launch_exact_node(
        &self,
        _request: crucible_qemu::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu::QemuProductionExactRestoreLaunch,
        crucible_qemu::QemuLiveNodeStepGateError,
    > {
        Err(
            crucible_qemu::QemuLiveNodeStepGateError::OriginalNativeAccount {
                source: crucible_qemu::OriginalActorAccountError::Unavailable,
            },
        )
    }

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
    /// Consumes one source permit through the same actual host factory.
    ///
    /// # Errors
    /// Refuses factories without a genuine same-family target consumer.
    #[cfg(target_os = "linux")]
    fn begin_fork_target(
        &mut self,
        _permit: crucible_qemu::LinuxQemuForkTargetPermit,
        _resources: AttemptResourceLimits,
        _cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuAttemptResourceGuardBeginFailure> {
        Err(QemuVmRealizationError::Executor {
            operation: "begin same-family QEMU target guard",
            message: String::from("factory has no genuine target consumer"),
        }
        .into())
    }

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
