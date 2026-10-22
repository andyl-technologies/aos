//! Attempt-scoped live-QEMU session composition.
//!
//! The adapter in this module binds three independently testable authorities:
//! policy-controlled VM realization, an operational resource/cancellation
//! guard installed before launch, and a modeled attempt driver that receives
//! only the already-realized backend. Assignment IDs and daemon epochs never
//! cross this boundary.

use crucible_campaign::AttemptResourceLimits;
use crucible_qemu_host::{
    QemuChildProcessContract, QemuLaunchResourceRequirements, QemuNodeChild,
    QemuPreparedRunDirectory, QemuVmRealizationError,
};

use crate::ExecutionCancellation;
use crate::executor_supervisor::SelectedExactCheckpointRoot;

mod resource_begin;
pub use resource_begin::QemuAttemptResourceGuardBeginReport;
pub use resource_begin::QemuAttemptResourceGuardCleanupFailure;

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
    /// Recovers existing selected storage only after its exact native returns.
    ///
    /// The storage checks its genuine saved Target loans independently. This
    /// method cannot substitute guard state, Arc uniqueness or error history
    /// for physical role return; unsupported owners keep the storage unchanged.
    #[cfg(target_os = "linux")]
    fn recover_target_construction_storage(
        &mut self,
        _storage: &mut crate::TargetConstructionStorage,
    ) -> bool {
        false
    }

    /// Attempts the same installed controls' cleanup after QEMU has been reaped.
    ///
    /// Successful return is idempotent. A refusal moves its actual cause to
    /// the caller and independently records any performed quarantine transfer.
    /// Neither diagnostic history nor a quarantine observation proves return;
    /// a quarantined guard remains refused on subsequent calls.
    ///
    /// # Errors
    /// Returns the actual cleanup leaf and its existing reporting policy while
    /// preserving separately observed custody. A repeated terminal observation
    /// does not repeat host cleanup or manufacture another physical owner.
    fn finish(&mut self) -> Result<(), QemuAttemptResourceGuardCleanupFailure>;

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
    /// Copies this actual containing World's identity without issuing resources.
    ///
    /// # Errors
    /// Refuses owners without an actual selected native World. Coordinates
    /// cannot replace the genuine per-member permits or their original payer.
    #[cfg(target_os = "linux")]
    fn native_world_identity(
        &self,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
        QemuVmRealizationError,
    > {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "observe actual native World identity",
            message: String::from("owner has no selected native World"),
        })
    }

    /// Pins this exact selected node's existing native kernel controller.
    ///
    /// # Errors
    /// Refuses an unknown node or failed physical ownership; no other member
    /// may substitute its controller.
    fn native_resource_controller_for_node(
        &mut self,
        _node: &crucible_engine::NodeId,
    ) -> Result<Option<crucible_qemu_host::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        self.native_resource_controller()
    }

    /// Routes Park through an explicitly selected member.
    ///
    /// # Errors
    /// Preserves actual physical/original refusal.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn retain_parent_park_cleanup_for_node(
        &self,
        _node: &crucible_engine::NodeId,
    ) -> Result<crucible_qemu_host::OriginalParentParkCleanup, QemuVmRealizationError> {
        self.retain_parent_park_cleanup()
    }

    /// Routes Park through an explicitly selected member.
    ///
    /// # Errors
    /// Preserves actual physical/original refusal.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn verify_parent_park_binding_for_node(
        &self,
        _node: &crucible_engine::NodeId,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<(), crucible_qemu_host::OriginalActorParkQuiescenceError> {
        self.verify_parent_park_binding(source, original, decoder)
    }

    /// Routes Park through an explicitly selected member.
    ///
    /// # Errors
    /// Preserves actual physical/original refusal.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn enter_parent_park_quiescence_for_node(
        &self,
        _node: &crucible_engine::NodeId,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<
        crucible_qemu_host::OriginalActorParkQuiescence,
        crucible_qemu_host::OriginalActorParkQuiescenceError,
    > {
        self.enter_parent_park_quiescence(source, original, decoder)
    }

    /// Routes Park through an explicitly selected member.
    ///
    /// # Errors
    /// Preserves actual physical/original refusal.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn prepare_parent_park_imports_for_node(
        &self,
        _node: &crucible_engine::NodeId,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu_host::OriginalActorParkImports, crucible_qemu_host::OriginalActorParkImportError>
    {
        self.prepare_parent_park_imports(source, original, decoder, actor, family)
    }

    /// Borrows the selected Target role for one actual registration callback.
    ///
    /// # Errors
    /// Refuses before callback invocation if this guard has no matching Target.
    #[cfg(target_os = "linux")]
    fn with_fork_target_ram_admission_for_node(
        &self,
        _node: &crucible_engine::NodeId,
        _contract: &QemuChildProcessContract,
        _prepare: &mut dyn FnMut(
            &crucible_qemu_host::QemuForkTargetRamAdmission<'_>,
        ) -> Result<
            crucible_qemu_host::ram_control::RamControlRegistration,
            QemuVmRealizationError,
        >,
    ) -> Result<crucible_qemu_host::ram_control::RamControlRegistration, QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "borrow selected Target RAM admission",
            message: String::from("guard has no retained Target role"),
        })
    }

    /// Reserves real cloned-contract storage before duplicating its descriptors.
    ///
    /// # Errors
    /// Refuses a foreign node/contract, absent Source payer or exhausted peak.
    #[cfg(target_os = "linux")]
    fn reserve_contract_controls_for_node(
        &self,
        _node: &crucible_engine::NodeId,
        _contract: &QemuChildProcessContract,
        _descriptors: u64,
        _bytes: u64,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::SourceHostControlLease,
        QemuVmRealizationError,
    > {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "reserve selected contract control owner",
            message: String::from("guard has no genuine Source control payer"),
        })
    }

    /// Retains Target RAM with this exact selected member before resource birth.
    ///
    /// # Errors
    /// Refuses a foreign node, contract or actual same-family custody.
    #[cfg(target_os = "linux")]
    fn bind_fork_target_ram_custody_for_node(
        &mut self,
        _node: &crucible_engine::NodeId,
        contract: &QemuChildProcessContract,
        registration: &crucible_qemu_host::ram_control::RamControlRegistration,
        supervisor: &crucible_host_resources::host_supervision::HostOperationSupervisor,
        guest_ram_bytes: u64,
        custody: &crucible_qemu_host::QemuRamLaunchCustody,
    ) -> Result<(), QemuVmRealizationError> {
        self.bind_fork_target_ram_custody(
            contract,
            registration,
            supervisor,
            guest_ram_bytes,
            custody,
        )
    }

    /// Lends the selected member's retained contract without another admission.
    ///
    /// # Errors
    /// Refuses an unknown node or failed actual member ownership.
    fn child_process_contract_for_node(
        &self,
        _node: &crucible_engine::NodeId,
    ) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.child_process_contract()
    }

    /// Prepares storage through the exact selected member's existing quota.
    ///
    /// # Errors
    /// Refuses an unknown node, retired member or unavailable actual storage.
    fn prepare_generation_run_directory_for_node(
        &mut self,
        _node: &crucible_engine::NodeId,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.prepare_generation_run_directory(requirements)
    }

    /// Borrows the selected member's real installed issuer.
    ///
    /// # Errors
    /// Refuses an unknown, absent or retired actual native member.
    fn installed_node_issuer_for_node(
        &self,
        _node: &crucible_engine::NodeId,
    ) -> Result<crucible_qemu_host::InstalledNodeLaunchIssuer, crucible_qemu_host::QemuLiveNodeStepGateError>
    {
        self.installed_node_issuer()
    }

    /// Launches with the selected member's actual retained issuer and contract.
    ///
    /// # Errors
    /// Refuses a foreign node or the genuine launch admission and its postcut.
    fn launch_fresh_node_for_node(
        &self,
        _node: &crucible_engine::NodeId,
        config: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu_host::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu_host::QemuNode, crucible_qemu_host::QemuLiveNodeStepGateError> {
        self.launch_fresh_node(config, admission)
    }

    /// Restores through the same selected member's retained issuer.
    ///
    /// # Errors
    /// Refuses a foreign node or genuine restore admission and its postcut.
    fn launch_exact_node_for_node(
        &self,
        _node: &crucible_engine::NodeId,
        request: crucible_qemu_host::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu_host::QemuProductionExactRestoreLaunch,
        crucible_qemu_host::QemuLiveNodeStepGateError,
    > {
        self.launch_exact_node(request)
    }

    /// Retains an unreaped child in the actual selected containing member.
    fn retain_failed_launch_child_for_node(
        &mut self,
        _node: &crucible_engine::NodeId,
        child: QemuNodeChild,
    ) {
        self.retain_failed_launch_child(child);
    }

    /// Reports a selected member's separately retained same-family Target.
    #[cfg(target_os = "linux")]
    fn fork_target_is_owned_for_node(&self, _node: &crucible_engine::NodeId) -> bool {
        self.fork_target_is_owned()
    }

    /// Moves only the selected member's genuine same-family Target permit.
    ///
    /// # Errors
    /// Refuses an unknown node, unavailable Source or occupied Target.
    #[cfg(target_os = "linux")]
    fn prepare_fork_target_for_node(
        &mut self,
        _node: &crucible_engine::NodeId,
    ) -> Result<crucible_qemu_host::QemuForkTargetPreparation, QemuVmRealizationError> {
        self.prepare_fork_target()
    }

    /// Prepares Target storage under this selected Source's existing quota.
    ///
    /// # Errors
    /// Refuses an unknown node, foreign Target or unavailable actual storage.
    #[cfg(target_os = "linux")]
    fn prepare_fork_target_run_directory_for_node(
        &mut self,
        _node: &crucible_engine::NodeId,
        contract: &QemuChildProcessContract,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.prepare_fork_target_run_directory(contract, requirements)
    }

    /// Retains the actual target purpose in its existing RAM cleanup custody.
    ///
    /// # Errors
    /// Refuses missing target ownership, a foreign contract or keeper admission.
    #[cfg(target_os = "linux")]
    fn bind_fork_target_ram_custody(
        &mut self,
        _contract: &QemuChildProcessContract,
        _registration: &crucible_qemu_host::ram_control::RamControlRegistration,
        _supervisor: &crucible_host_resources::host_supervision::HostOperationSupervisor,
        _guest_ram_bytes: u64,
        _custody: &crucible_qemu_host::QemuRamLaunchCustody,
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
    fn prepare_fork_target(
        &mut self,
    ) -> Result<crucible_qemu_host::QemuForkTargetPreparation, QemuVmRealizationError> {
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

    /// Lends the retained account's Cleanup when physical disposition begins.
    ///
    /// # Errors
    /// Refuses missing original account custody or its finite Cleanup policy.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn retain_parent_park_cleanup(
        &self,
    ) -> Result<crucible_qemu_host::OriginalParentParkCleanup, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "retain parent Park Cleanup",
            message: String::from("guard has no original Cleanup owner"),
        })
    }

    /// Checks actual Node, host and Preparation custody before publication.
    ///
    /// # Errors
    /// Refuses absent or different original physical custody without effects.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn verify_parent_park_binding(
        &self,
        _source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        _decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<(), crucible_qemu_host::OriginalActorParkQuiescenceError> {
        Err(crucible_qemu_host::OriginalActorParkQuiescenceError::Binding {
            first: crucible_qemu_host::OriginalActorAccountError::Unavailable,
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
        _source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        _decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<
        crucible_qemu_host::OriginalActorParkQuiescence,
        crucible_qemu_host::OriginalActorParkQuiescenceError,
    > {
        Err(crucible_qemu_host::OriginalActorParkQuiescenceError::Binding {
            first: crucible_qemu_host::OriginalActorAccountError::Unavailable,
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
        _source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        _original: &std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        _decoder: &crucible_qemu_host::OriginalActorParkCaller,
        _actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        _family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu_host::OriginalActorParkImports, crucible_qemu_host::OriginalActorParkImportError>
    {
        Err(crucible_qemu_host::OriginalActorAccountError::Unavailable.into())
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
    ) -> Result<Option<crucible_qemu_host::LinuxQemuNativeResourceController>, QemuVmRealizationError>
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
        config: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu_host::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu_host::QemuNode, crucible_qemu_host::QemuLiveNodeStepGateError> {
        crucible_qemu_host::launch_qemu_production_fresh_node(config, admission)
    }

    /// Lends the actual installed issuer without duplicating the native owner.
    ///
    /// # Errors
    /// Refuses absent, retired, foreign or uncertain installed original custody.
    fn installed_node_issuer(
        &self,
    ) -> Result<crucible_qemu_host::InstalledNodeLaunchIssuer, crucible_qemu_host::QemuLiveNodeStepGateError>
    {
        Err(
            crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeAccount {
                source: crucible_qemu_host::OriginalActorAccountError::Unavailable,
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
        _request: crucible_qemu_host::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu_host::QemuProductionExactRestoreLaunch,
        crucible_qemu_host::QemuLiveNodeStepGateError,
    > {
        Err(
            crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeAccount {
                source: crucible_qemu_host::OriginalActorAccountError::Unavailable,
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

/// Transfers actual logical World custody before its first physical effect.
///
/// The production caller installs its prepaid pending construction owner here.
/// Custody refusal retains both exact holders; checked preparation is a separate
/// positive-admission phase.
pub(crate) trait SourceWorldConstructor:
    crucible_qemu_host::LinuxQemuNativeWorldConstructor
{
    /// Borrows the same Main role that owns this receiver's nominal entry proof.
    fn source_selection(&self) -> &crate::PreparedSourceSelector;
}

/// Borrows the actual Main-owned Source constructor for this one admission.
pub(crate) type NativeWorldBeforeEffects<'a> = dyn SourceWorldConstructor + 'a;

/// Factory for one pre-launch attempt resource guard.
pub(crate) trait QemuAttemptResourceGuardFactory {
    /// Retains the same actual backend factory, without a new allocation bank.
    fn retain_fork_target_factory(&self) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }

    /// Authenticates the same unreturned body and canonical no-birth journal.
    ///
    /// # Errors
    /// Refuses foreign, attempted or uncertain Worlds without consuming custody.
    fn verify_unborn_native_world(
        &self,
        _loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
        _controls: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldControlLease,
    ) -> Result<(), QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "verify exact unborn World construction",
            message: String::from("factory has no exact pending World owner"),
        })
    }

    /// Returns only a canonically proven never-born World after body destruction.
    ///
    /// # Errors
    /// Preserves attempted, foreign or incompletely returned custody.
    fn abort_unborn_native_world(
        &mut self,
        _loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "abort exact unborn World construction",
            message: String::from("factory has no exact pending World owner"),
        })
    }

    /// Retries only the exact retained pending World through its saved Cleanup.
    ///
    /// # Errors
    /// Refuses absent actual construction custody; no sibling/global cleanup runs.
    fn retry_native_world_construction(
        &mut self,
        _loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "retry actual pending World construction",
            message: String::from("factory has no exact pending World owner"),
        })
    }

    /// Selects the genuine containing Main without reserving or entering work.
    ///
    /// The private producer validates its actual queue and locks before it
    /// constructs the fixed prepared bodies. The default grants no producer.
    fn source_main_producer(&self) -> Option<crate::SourceMainProducer> {
        None
    }

    /// Enters a genuine World Preparation while retaining its exact Main role.
    ///
    /// # Errors
    /// Refuses missing actual pool custody before consuming any no-entry proof.
    fn prepare_world_admission(
        &self,
        _selection: crate::PreparedSourceSelector,
        _registration: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
    ) -> Result<crate::qemu_resource_guard::SourceWorldAdmission, QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "prepare actual Source World admission",
            message: String::from("factory has no real World Preparation origin"),
        })
    }

    /// Installs the selected World's genuine disjoint node owners together.
    ///
    /// # Errors
    /// Preserves selected checkpoint custody and all partial member effects.
    fn begin_world(
        &mut self,
        _admission: &mut crate::qemu_resource_guard::SourceWorldAdmission,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
        _consumer_control_bytes: u64,
        _registration: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        _before_effects: &mut NativeWorldBeforeEffects<'_>,
    ) -> Result<Self::Guard, QemuAttemptResourceGuardBeginFailure> {
        let _ = (resources, cancellation);
        Err(
            QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                QemuVmRealizationError::ExecutorUnavailable {
                    operation: "begin authenticated native World",
                    message: String::from("factory has no real before-effects Source owner"),
                },
                selected_checkpoint,
            ),
        )
    }

    /// Consumes one source permit through the same actual host factory.
    ///
    /// # Errors
    /// Refuses factories without a genuine same-family target consumer.
    #[cfg(target_os = "linux")]
    fn begin_fork_target(
        &mut self,
        _permit: crucible_qemu_host::LinuxQemuForkTargetPermit,
        _resources: AttemptResourceLimits,
        _cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuAttemptResourceGuardBeginFailure> {
        Err(QemuVmRealizationError::Executor {
            operation: "begin same-family QEMU target guard",
            message: String::from("factory has no genuine target consumer"),
        }
        .into())
    }

    /// Composes the selected Targets while preserving any actual installed guard.
    ///
    /// A returned optional error is the independent post-install refusal. Its
    /// actual guard must be retained before the caller reports that cause.
    ///
    /// # Errors
    /// Refuses unsupported factories or pre-guard composition. Actual host
    /// ownership remains in the supplied Main-held selected storage on error.
    #[cfg(target_os = "linux")]
    fn begin_fork_target_world(
        &mut self,
        _members: &mut crate::TargetConstructionStorage,
        _resources: AttemptResourceLimits,
        _cancellation: ExecutionCancellation,
    ) -> Result<(Self::Guard, Option<QemuVmRealizationError>), QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "compose actual selected Target World",
            message: String::from("factory has no retained selected Target composition"),
        })
    }

    /// Guard retained for the complete process lifetime.
    type Guard: QemuAttemptResourceGuard;

    /// Installs the exact admitted resource and cancellation contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAttemptResourceGuardBeginFailure`] when the host cannot
    /// install every requested ceiling. Clean rollback returns any unspent
    /// selected-root claim. Failed rollback retains both causes and its actual
    /// quarantine observation; it does not attest physical process return.
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
    // Finite inline history creates no failure-time diagnostic owner allocation.
    error: QemuAttemptResourceGuardBeginReport,
    selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
}

impl QemuAttemptResourceGuardBeginFailure {
    pub(crate) fn before_checkpoint_claim(
        error: QemuVmRealizationError,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Self {
        Self {
            error: error.into(),
            selected_checkpoint,
        }
    }

    pub(crate) fn after_checkpoint_claim(error: QemuVmRealizationError) -> Self {
        Self {
            error: error.into(),
            selected_checkpoint: None,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        QemuAttemptResourceGuardBeginReport,
        Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) {
        (self.error, self.selected_checkpoint)
    }

    pub(crate) fn rollback(
        first: QemuVmRealizationError,
        cleanup: QemuAttemptResourceGuardCleanupFailure,
    ) -> Self {
        Self {
            error: QemuAttemptResourceGuardBeginReport::after_rollback(first, cleanup),
            selected_checkpoint: None,
        }
    }

    pub(crate) fn from_report(
        error: QemuAttemptResourceGuardBeginReport,
        selected_checkpoint: Option<crate::executor_supervisor::SelectedExactCheckpointRoot>,
    ) -> Self {
        Self {
            error,
            selected_checkpoint,
        }
    }
}

impl From<QemuVmRealizationError> for QemuAttemptResourceGuardBeginFailure {
    fn from(error: QemuVmRealizationError) -> Self {
        Self::after_checkpoint_claim(error)
    }
}
