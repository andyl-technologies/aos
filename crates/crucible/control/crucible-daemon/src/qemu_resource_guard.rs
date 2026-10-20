//! Exact host-resource composition for one local QEMU attempt.
//!
//! The host factory behind this module owns one indivisible authority covering
//! the child-process containment contract and every writable artifact reachable
//! by that child. The daemon wraps that authority with signal-driven execution
//! cancellation and an exact scheduler-quantum counter. Keeping process and
//! filesystem ownership in one type prevents a caller from accidentally pairing
//! a cgroup from one attempt with a quota or run directory from another.

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::{ProductionVmNodeGeneration, ProductionVmNodeLease};
use crucible_engine::{NodeId, SchedulerOperationalFailureClass};
use crucible_control_api::LifecycleApiError;
use crucible_campaign::AttemptResourceLimits;


use crucible_qemu_host::{
    LinuxQemuAttemptCancellationSignal, LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory,
    LinuxQemuAttemptHostOwner, QemuChildProcessContract, QemuHotForkChildProcessBasis,
    QemuHotForkChildProcessOwner, QemuLaunchResourceRequirements, QemuNodeChannelError,
    QemuNodeChild, QemuPreparedRunDirectory, QemuVmRealizationError,
};

use crate::crucible_qemu_session::{
    NativeWorldBeforeEffects, QemuAttemptResourceGuardBeginFailure,
};
use crate::executor_supervisor::{
    ExecutionCancellationHook, ExecutionCancellationHookRegistration, SelectedExactCheckpointRoot,
};
use crate::{
    ExecutionCancellation, QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard,
    QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory, QemuExecutionQuantumCounter,
};

/// Maximum distinct scheduler nodes retained by one attempt generation owner.
pub const MAX_QEMU_ATTEMPT_GENERATION_NODES: usize = 65_536;

/// Maximum simultaneously retained process generations for one scheduler node.
///
/// Terminal replacement deliberately stages one successor before the active
/// child exits. No third generation may enter until one of those two exact
/// leases is released or the process-free staged successor is rolled back.
const MAX_QEMU_ATTEMPT_GENERATIONS_PER_NODE: usize = 2;

/// Sticky process-cancellation capability owned independently of a host guard.
///
/// Implementations must make cancellation visible to an already-minted child
/// and close future child minting before returning success. The operation must
/// be idempotent because registration and cancellation can race.
pub trait QemuAttemptCancellationSignal: Send + Sync + 'static {
    /// Publishes sticky cancellation to the attempt process boundary.
    ///
    /// # Errors
    ///
    /// Returns an operational error when cancellation could not be made visible
    /// to every existing and future child process.
    fn signal(&self) -> Result<(), QemuVmRealizationError>;
}

/// Indivisible host authority for one attempt's process and writable storage.
///
/// A conforming owner installs exact CPU, resident-memory, aggregate writable-
/// byte, and process ceilings before lending its child contract. Its writable
/// quota covers the pinned VMState container, overlays, logs, and every other
/// artifact the child can mutate. Normal release is legal only after process
/// reap; quarantine retains both process and filesystem enforcement.
pub trait QemuAttemptHostResourceOwner {
    /// Recovers only this selected Target's already-returned backing vector.
    ///
    /// Exact native loan receipts are checked inside `storage`. This operation
    /// admits no host resource and grants no permission from an empty process.
    #[cfg(target_os = "linux")]
    fn recover_target_construction_storage(
        &mut self,
        _storage: &mut crate::TargetConstructionStorage,
    ) -> bool {
        false
    }

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

    /// Runs the concrete RAM companion while this exact Target remains borrowed.
    ///
    /// # Errors
    /// Refuses before the callback when no genuine Target admission is retained.
    #[cfg(target_os = "linux")]
    fn with_fork_target_ram_admission(
        &self,
        _contract: &QemuChildProcessContract,
        _prepare: &mut dyn FnMut(
            &crucible_qemu_host::QemuForkTargetRamAdmission<'_>,
        ) -> Result<
            crucible_qemu_host::ram_control::RamControlRegistration,
            QemuVmRealizationError,
        >,
    ) -> Result<crucible_qemu_host::ram_control::RamControlRegistration, QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "borrow actual Target RAM admission",
            message: String::from("host has no retained Target role"),
        })
    }

    /// Prepays a cloned contract under this member's genuine Source control payer.
    ///
    /// # Errors
    /// Refuses missing Source custody, a foreign contract or an exhausted peak.
    #[cfg(target_os = "linux")]
    fn reserve_contract_controls(
        &self,
        _contract: &QemuChildProcessContract,
        _descriptors: u64,
        _bytes: u64,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::SourceHostControlLease,
        QemuVmRealizationError,
    > {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "reserve actual contract control owner",
            message: String::from("host has no genuine Source control payer"),
        })
    }

    /// Selects an already admitted member of this same containing World.
    ///
    /// Ordinary single-owner implementations retain their existing route. A
    /// World owner must override this method with exact node matching; node
    /// coordinates themselves never issue resources or native permission.
    ///
    /// # Errors
    /// Refuses an unknown member or unavailable physical ownership.
    fn node_owner(&self, _node: &NodeId) -> Result<&Self, QemuVmRealizationError> {
        Ok(self)
    }

    /// Mutably borrows the exact retained member without cloning its custody.
    ///
    /// # Errors
    /// Refuses an unknown member or unavailable physical ownership.
    fn node_owner_mut(&mut self, _node: &NodeId) -> Result<&mut Self, QemuVmRealizationError> {
        Ok(self)
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
            message: String::from("host has no authenticated target RAM keeper"),
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
            message: String::from("host has no genuine source owner"),
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
            message: String::from("host has no genuine source storage owner"),
        })
    }

    /// Lends the actual retained account's Cleanup only when disposition begins.
    ///
    /// # Errors
    /// Refuses unavailable original account custody or its finite Cleanup policy.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn retain_parent_park_cleanup(
        &self,
    ) -> Result<crucible_qemu_host::OriginalParentParkCleanup, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "retain parent Park Cleanup",
            message: String::from("host has no original Cleanup owner"),
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
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
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
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
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
        _original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        _decoder: &crucible_qemu_host::OriginalActorParkCaller,
        _actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        _family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu_host::OriginalActorParkImports, crucible_qemu_host::OriginalActorParkImportError>
    {
        Err(crucible_qemu_host::OriginalActorAccountError::Unavailable.into())
    }

    /// Independent cancellation capability registered with the supervisor.
    type CancellationSignal: QemuAttemptCancellationSignal;

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

    /// Finishes the same original host with its retained registry controller.
    ///
    /// # Errors
    /// Refuses incomplete physical or control retirement under the original.
    fn finish_with_original_registry(
        &mut self,
        _registry: &crate::HostOperationalRegistry,
    ) -> Result<(), QemuVmRealizationError> {
        self.finish()
    }

    /// Returns the exact resource basis installed by this owner.
    #[must_use]
    fn resource_limits(&self) -> AttemptResourceLimits;

    /// Validates the installed basis against this owner's actual admission.
    ///
    /// Default owners require equality. A concrete owner may report a lower
    /// authenticated process ceiling while preserving all other obligations.
    #[must_use]
    fn matches_admitted_limits(&self, admitted: AttemptResourceLimits) -> bool {
        self.resource_limits() == admitted
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

    /// Returns the sealed child-process launch contract.
    ///
    /// # Errors
    ///
    /// Returns an operational error after terminal cleanup has closed launch
    /// authority or when the contract cannot be authenticated.
    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError>;

    /// Provisions and lends the descriptor-pinned run-directory capability.
    ///
    /// # Errors
    ///
    /// Returns an operational error when launch admission, retained aggregate
    /// storage authentication, or fresh generation-directory provisioning
    /// fails.
    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError>;

    /// Duplicates the narrow sticky process-cancellation capability.
    ///
    /// # Errors
    ///
    /// Returns an operational error when cancellation authority cannot be
    /// retained independently for the execution signal.
    fn cancellation_signal(&self) -> Result<Self::CancellationSignal, QemuVmRealizationError>;

    /// Checks host-enforced limits at one bounded operational boundary.
    ///
    /// # Errors
    ///
    /// Returns a terminal resource error after a hard ceiling is exhausted, or
    /// an availability error when enforcement state cannot be authenticated.
    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError>;

    /// Retains a failed launch's nonduplicable direct-child wait authority.
    fn retain_failed_launch_child(&mut self, child: QemuNodeChild);

    /// Reaps every process and releases the aggregate filesystem reservation.
    ///
    /// This operation must be idempotent. Success attests that process reap
    /// completed before filesystem and cgroup release. An error retains every
    /// authority needed by [`Self::quarantine`].
    ///
    /// # Errors
    ///
    /// Returns an operational error when complete release cannot be attested.
    fn finish(&mut self) -> Result<(), QemuVmRealizationError>;

    /// Transfers process and writable-storage enforcement to quarantine.
    ///
    /// This operation is infallible and idempotent. It must never release the
    /// filesystem reservation before the quarantine owner attests process reap.
    fn quarantine(&mut self);
}

/// Factory installing one indivisible host-resource authority.
pub trait QemuAttemptHostResourceFactory {
    /// Retains the same existing factory body for partial-Source cleanup.
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

    /// Selects the actual Main queue without issuing a native or Service role.
    fn source_main_producer(&self) -> Option<crate::SourceMainProducer> {
        None
    }

    /// Consumes a genuine source permit without allocating another project quota.
    ///
    /// # Errors
    /// Refuses a factory without the matching concrete target consumer.
    #[cfg(target_os = "linux")]
    fn begin_fork_target(
        &mut self,
        _permit: crucible_qemu_host::LinuxQemuForkTargetPermit,
        _resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "begin same-family QEMU target host",
            message: String::from("factory has no genuine target consumer"),
        })
    }

    /// Installs the selected real Targets into their already retained storage.
    ///
    /// The callback borrows the actual optional host. Refusal leaves it there;
    /// success may move it only into its containing guard. Implementations do
    /// no fallible work after that move and never manufacture a Target permit.
    ///
    /// # Errors
    /// Preserves genuine preparation, birth or composition refusal; a factory
    /// without the selected native consumer refuses before calling `install`.
    #[cfg(target_os = "linux")]
    fn with_fork_target_world(
        &mut self,
        _members: &mut crate::TargetConstructionStorage,
        _resources: AttemptResourceLimits,
        _install: &mut dyn FnMut(&mut Option<Self::Owner>) -> Result<(), QemuVmRealizationError>,
    ) -> Result<(), QemuVmRealizationError> {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "begin selected same-family Target World",
            message: String::from("factory has no actual selected Target consumer"),
        })
    }

    /// Exact owner returned for one accepted attempt.
    type Owner: QemuAttemptHostResourceOwner;

    /// Installs every hard host ceiling before process launch becomes possible.
    ///
    /// # Errors
    ///
    /// Returns an operational error when CPU, memory, aggregate writable bytes,
    /// process supervision, or cleanup ownership cannot be installed exactly.
    /// Failure must leave no process or unowned reservation behind.
    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError>;
}

/// Internal extension that pre-seals a supervisor-selected checkpoint root.
pub(crate) trait QemuAttemptSelectedHostResourceFactory:
    QemuAttemptHostResourceFactory
{
    fn reserve_main_worker_controls(
        &self,
        _bytes: u64,
    ) -> Result<
        Option<
            crucible_host_resources::host_services::process_birth::AuthenticatedNativePoolPurpose,
        >,
        QemuVmRealizationError,
    > {
        Ok(None)
    }

    fn begin_world(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
        _consumer_control_bytes: u64,
        _registration: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        _before_effects: &mut NativeWorldBeforeEffects<'_>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        let _ = resources;
        Err(
            QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                QemuVmRealizationError::ExecutorUnavailable {
                    operation: "begin authenticated native World",
                    message: String::from("host factory has no real before-effects Source owner"),
                },
                selected_checkpoint,
            ),
        )
    }

    fn begin_selected(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    >;
}

/// Cloneable bounded access to one exclusive host-resource allocator.
///
/// A production Linux allocator owns one cgroup and project-quota namespace
/// for its complete lifetime, while the fixed executor pool gives each worker
/// an independently owned execution model. This facade lets those workers
/// share the one allocator without duplicating namespace authority. Allocation
/// and exact pending-construction cleanup share the mutex; cleanup entry refuses
/// contention. Returned attempt owners execute guests outside this facade.
pub struct SharedQemuAttemptHostResourceFactory<H> {
    host: Arc<Mutex<H>>,
    cleanup: Option<crate::lifecycle_cleanup::LifecycleCleanupHandle>,
}

impl<H> SharedQemuAttemptHostResourceFactory<H> {
    /// Wraps one already-open exclusive allocator for fixed-worker sharing.
    #[must_use]
    pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(Mutex::new(host)),
            cleanup: None,
        }
    }

    pub(crate) fn with_lifecycle_cleanup(
        host: H,
        cleanup: crate::lifecycle_cleanup::LifecycleCleanupHandle,
    ) -> Self {
        Self {
            host: Arc::new(Mutex::new(host)),
            cleanup: Some(cleanup),
        }
    }

    /// Reserves real permanent worker bodies under the same authenticated pool.
    ///
    /// # Errors
    /// Refuses busy or poisoned custody, or the actual Main bank admission.
    /// This before-birth admission never waits for another host constructor.
    pub(crate) fn reserve_main_worker_controls(
        &self,
        bytes: u64,
    ) -> Result<
        Option<
            crucible_host_resources::host_services::process_birth::AuthenticatedNativePoolPurpose,
        >,
        QemuVmRealizationError,
    >
    where
        H: QemuAttemptSelectedHostResourceFactory,
    {
        self.host
            .try_lock()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "reserve permanent Main worker bodies",
                message: String::from("host custody is busy or poisoned"),
            })?
            .reserve_main_worker_controls(bytes)
    }

    /// Borrows the SAME Main queue for an outer service construction owner.
    /// The returned strong alias must never be stored in this factory or F.
    pub(crate) fn lifecycle_cleanup_owner(
        &self,
    ) -> Result<Option<Arc<crate::lifecycle_cleanup::LifecycleCleanupQueue>>, QemuVmRealizationError>
    {
        self.cleanup
            .as_ref()
            .map(|handle| handle.owner().map_err(cleanup_reservation_error))
            .transpose()
    }

    /// Returns the number of fixed-worker handles retaining the allocator.
    #[must_use]
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.host)
    }
}

impl SharedQemuAttemptHostResourceFactory<LinuxQemuAttemptHostResourceFactory> {
    #[cfg(test)]
    // crucible-lint: allow panic-shortcut -- the causal fixture intentionally poisons the same retained native factory mutex.
    #[allow(
        clippy::expect_used,
        reason = "The causal fixture poisons real factory custody."
    )]
    pub(crate) fn poison_custody_for_test(&self) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.host.lock().expect("actual factory before poison");
            panic!("poison the actual factory custody mutex");
        }));
        assert!(result.is_err());
    }

    /// Exclusively borrows the same allocator for terminal standalone teardown.
    ///
    /// # Errors
    /// Refuses any strong or weak factory borrower or poisoned native custody.
    pub(crate) fn exclusive_factory(
        &mut self,
    ) -> Result<&mut LinuxQemuAttemptHostResourceFactory, QemuVmRealizationError> {
        Arc::get_mut(&mut self.host)
            .ok_or_else(|| QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow actual Main factory for terminal retirement",
                message: String::from("actual factory borrowers remain"),
            })?
            .get_mut()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow actual Main factory for terminal retirement",
                message: String::from("actual factory custody is poisoned"),
            })
    }

    /// Retires the same concrete factory's permanent Main Target dispatcher.
    ///
    /// # Errors
    /// Returns the existing typed outcome and actual physical closure observed
    /// under the same allocator lock. A historical failure can coexist with
    /// closure; unavailable custody returns a failure and never asserts closure.
    pub(crate) fn finish_target_dispatcher(&self) -> (Result<(), QemuVmRealizationError>, bool) {
        let mut host = match self.host.try_lock() {
            Ok(host) => host,
            Err(_) => {
                return (
                    Err(QemuVmRealizationError::ExecutorUnavailable {
                        operation: "retire shared Main Target dispatcher",
                        message: String::from("actual host-resource allocator is unobservable"),
                    }),
                    false,
                );
            }
        };
        let work = host.finish_target_dispatcher();
        let physically_closed = host.target_dispatcher_physically_retired();
        (work, physically_closed)
    }
}

impl<H> Clone for SharedQemuAttemptHostResourceFactory<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            cleanup: self.cleanup.clone(),
        }
    }
}

impl<H> QemuAttemptHostResourceFactory for SharedQemuAttemptHostResourceFactory<H>
where
    H: QemuAttemptHostResourceFactory,
{
    fn verify_unborn_native_world(
        &self,
        loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
        controls: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldControlLease,
    ) -> Result<(), QemuVmRealizationError> {
        self.host
            .try_lock()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "verify exact unborn World construction",
                message: String::from("actual factory custody is busy or poisoned"),
            })?
            .verify_unborn_native_world(loan, controls)
    }

    /// Returns only a canonically proven never-born World after body destruction.
    ///
    /// # Errors
    /// Preserves attempted, foreign or incompletely returned custody.
    fn abort_unborn_native_world(
        &mut self,
        loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        self.host
            .try_lock()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "abort exact unborn World construction",
                message: String::from("actual factory custody is busy or poisoned"),
            })?
            .abort_unborn_native_world(loan)
    }

    fn retry_native_world_construction(
        &mut self,
        loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        self.host
            .try_lock()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "retry actual pending World construction",
                message: String::from("actual factory custody is busy or poisoned"),
            })?
            .retry_native_world_construction(loan)
    }

    fn source_main_producer(&self) -> Option<crate::SourceMainProducer> {
        self.cleanup
            .as_ref()
            .map(|cleanup| cleanup.source_main_producer())
    }

    type Owner = H::Owner;

    fn retain_fork_target_factory(&self) -> Option<Self> {
        Some(self.clone())
    }

    #[cfg(target_os = "linux")]
    fn begin_fork_target(
        &mut self,
        permit: crucible_qemu_host::LinuxQemuForkTargetPermit,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        self.host
            .lock()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "allocate shared same-family QEMU target resources",
                message: String::from("host-resource allocator lock is poisoned"),
            })?
            .begin_fork_target(permit, resources)
    }

    #[cfg(target_os = "linux")]
    fn with_fork_target_world(
        &mut self,
        members: &mut crate::TargetConstructionStorage,
        resources: AttemptResourceLimits,
        install: &mut dyn FnMut(&mut Option<Self::Owner>) -> Result<(), QemuVmRealizationError>,
    ) -> Result<(), QemuVmRealizationError> {
        self.host
            .try_lock()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "borrow actual selected Target factory",
                message: String::from("host-resource allocator is busy or poisoned"),
            })?
            .with_fork_target_world(members, resources, install)
    }

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        self.host
            .lock()
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "allocate shared QEMU attempt host resources",
                message: String::from("host-resource allocator lock is poisoned"),
            })?
            .begin(resources)
    }
}

impl<H> QemuAttemptSelectedHostResourceFactory for SharedQemuAttemptHostResourceFactory<H>
where
    H: QemuAttemptSelectedHostResourceFactory,
{
    fn begin_world(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
        consumer_control_bytes: u64,
        registration: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        before_effects: &mut NativeWorldBeforeEffects<'_>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        let mut host = match self.host.lock() {
            Ok(host) => host,
            Err(_) => {
                return Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        QemuVmRealizationError::ExecutorUnavailable {
                            operation: "install shared native node World",
                            message: String::from("host-resource allocator lock is poisoned"),
                        },
                        selected_checkpoint,
                    ),
                );
            }
        };
        host.begin_world(
            resources,
            selected_checkpoint,
            consumer_control_bytes,
            registration,
            before_effects,
        )
    }

    fn begin_selected(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        let mut host = match self.host.lock() {
            Ok(host) => host,
            Err(_) => {
                return Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        QemuVmRealizationError::ExecutorUnavailable {
                            operation: "allocate shared QEMU attempt host resources",
                            message: String::from("host-resource allocator lock is poisoned"),
                        },
                        selected_checkpoint,
                    ),
                );
            }
        };
        host.begin_selected(resources, selected_checkpoint)
    }
}

/// Concrete Linux allocator for one indivisible QEMU process/storage owner.
#[derive(Debug)]
pub struct LinuxQemuAttemptHostResourceFactory {
    host: LinuxQemuAttemptHostFactory,
}

impl LinuxQemuAttemptHostResourceFactory {
    /// Prices fixed factory/pool bodies before the same Main constructs them.
    ///
    /// Selected World names/arrays and launcher state are charged separately
    /// at that actual selection, before its constructor callback.
    ///
    /// # Errors
    /// Refuses an unrepresentable concrete control layout.
    pub(crate) fn normal_pool_control_bytes(
        capacity: usize,
    ) -> Result<u64, QemuVmRealizationError> {
        let (shared, _) = std::alloc::Layout::new::<(usize, usize)>()
            .extend(std::alloc::Layout::new::<Mutex<Self>>())
            .map_err(|_| QemuVmRealizationError::ExecutorUnavailable {
                operation: "price normal factory shared body",
                message: String::from("actual shared body layout overflows"),
            })?;
        let pool =
            LinuxQemuAttemptHostFactory::normal_pool_control_extent(capacity).ok_or_else(|| {
                QemuVmRealizationError::ExecutorUnavailable {
                    operation: "price normal pool fixed arrays",
                    message: String::from("actual fixed-array layout overflows"),
                }
            })?;
        u64::try_from(shared.pad_to_align().size())
            .ok()
            .and_then(|bytes| bytes.checked_add(pool))
            .ok_or_else(|| QemuVmRealizationError::ExecutorUnavailable {
                operation: "price normal pool containing bodies",
                message: String::from("actual containing extent overflows"),
            })
    }

    /// Checks actual closed Source/Target roster state without releasing custody.
    ///
    /// # Errors
    /// Refuses absent, foreign, occupied or uncertain authentic normal custody.
    pub(crate) fn verify_native_quiescent(&self) -> Result<(), QemuVmRealizationError> {
        self.host.verify_native_quiescent()
    }

    /// Retires the dispatcher at this actual factory's whole-owner boundary.
    ///
    /// # Errors
    /// Refuses live jobs or uncertain saved-cleanup, worker or alias retirement.
    pub(crate) fn finish_target_dispatcher(&mut self) -> Result<(), QemuVmRealizationError> {
        self.host.finish_target_dispatcher()
    }

    /// Observes the same factory's actual dispatcher, debit and World closure.
    ///
    /// This fact does not enter Cleanup or permit another return or birth.
    pub(crate) fn target_dispatcher_physically_retired(&self) -> bool {
        self.host.target_dispatcher_physically_retired()
    }

    pub(crate) fn bind_normal_pool(
        &mut self,
        pool: crucible_host_resources::host_services::process_birth::AuthenticatedNativePoolPurpose,
    ) -> Result<(), crucible_qemu_host::OriginalActorAccountError> {
        self.host.bind_normal_pool(pool)
    }

    /// Opens and exclusively owns the configured cgroup and storage roots.
    ///
    /// # Errors
    ///
    /// Returns a stable executor error for invalid host policy and an
    /// availability error for I/O or namespace contention.
    pub fn open(config: LinuxQemuAttemptHostConfig) -> Result<Self, QemuVmRealizationError> {
        LinuxQemuAttemptHostFactory::open(config).map(|host| Self { host })
    }

    /// Wraps an already-open exact Linux host allocator.
    #[must_use]
    pub const fn new(host: LinuxQemuAttemptHostFactory) -> Self {
        Self { host }
    }

    /// Binds the same concrete factory to its externally retained native pairs.
    ///
    /// The shared facade and actual Linux allocator remain the genuine shipped
    /// owners. This consumes only a weak account binding; original domain,
    /// Source and launch eligibility still require their physical owners.
    ///
    /// # Errors
    /// Refuses a poisoned or already bound concrete factory.
    #[cfg(feature = "private-measurement-domain")]
    pub fn bind_original_accounts(
        &mut self,
        binding: crucible_qemu_host::OriginalNativeAccountFactoryBinding,
    ) -> Result<(), crucible_qemu_host::OriginalActorAccountError> {
        self.host.bind_original_accounts(binding)
    }
}

/// Concrete Linux process/storage owner with its exact campaign resource basis.
#[derive(Debug)]
#[must_use = "finish the Linux QEMU host owner or transfer it to quarantine"]
pub struct LinuxQemuAttemptHostResourceOwner {
    resources: AttemptResourceLimits,
    host: LinuxHostSet,
}

mod linux_world;
pub use linux_world::LinuxWorldCancellationSignal;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
use linux_world::park_route_error;
#[cfg(target_os = "linux")]
pub(crate) use linux_world::{LinuxTargetWorldStorage, world_node_key};

#[derive(Debug)]
enum LinuxHostSet {
    Single(LinuxQemuAttemptHostOwner),
    World {
        identity: crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
        members: Vec<LinuxWorldMember>,
    },
}

#[derive(Debug)]
struct LinuxWorldMember {
    key: [u8; 32],
    owner: LinuxQemuAttemptHostResourceOwner,
}

impl LinuxQemuAttemptHostResourceOwner {
    /// Returns the exact pinned aggregate attempt-root path for diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an executor error after the storage owner moved to quarantine.
    pub fn run_directory(&self) -> Result<&Path, QemuVmRealizationError> {
        self.single()?.run_directory()
    }
}

impl QemuAttemptCancellationSignal for LinuxQemuAttemptCancellationSignal {
    fn signal(&self) -> Result<(), QemuVmRealizationError> {
        LinuxQemuAttemptCancellationSignal::signal(self)
    }
}

fn effective_linux_limits(
    admitted: AttemptResourceLimits,
    effective: (u32, u64, u64),
) -> Result<AttemptResourceLimits, QemuVmRealizationError> {
    if effective.0 != admitted.maximum_vcpus()
        || effective.1 == 0
        || effective.1 > admitted.maximum_resident_bytes()
        || effective.2 != admitted.maximum_disk_bytes()
    {
        return Err(QemuVmRealizationError::Executor {
            operation: "authenticate effective Linux QEMU limits",
            message: String::from("effective owner exceeds or changes its original obligations"),
        });
    }
    AttemptResourceLimits::new(
        effective.0,
        effective.1,
        effective.2,
        admitted.maximum_execution_quanta(),
    )
    .map_err(|source| QemuVmRealizationError::ModelCopy {
        source: Box::new(source),
    })
}

impl QemuAttemptHostResourceFactory for LinuxQemuAttemptHostResourceFactory {
    fn verify_unborn_native_world(
        &self,
        loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
        controls: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldControlLease,
    ) -> Result<(), QemuVmRealizationError> {
        self.host.verify_unborn_native_world(loan, controls)
    }

    /// Returns only a canonically proven never-born World after body destruction.
    ///
    /// # Errors
    /// Preserves attempted, foreign or incompletely returned custody.
    fn abort_unborn_native_world(
        &mut self,
        loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        self.host.abort_unborn_native_world(loan)
    }

    fn retry_native_world_construction(
        &mut self,
        loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        self.host.retry_native_world_construction(loan)
    }

    type Owner = LinuxQemuAttemptHostResourceOwner;

    fn begin_fork_target(
        &mut self,
        permit: crucible_qemu_host::LinuxQemuForkTargetPermit,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        let mut host = self.host.begin_fork_target(
            permit,
            resources.maximum_vcpus(),
            resources.maximum_resident_bytes(),
            resources.maximum_disk_bytes(),
        )?;
        let effective = match effective_linux_limits(resources, host.resource_ceiling()) {
            Ok(effective) => effective,
            Err(error) => {
                host.quarantine();
                return Err(error);
            }
        };
        Ok(LinuxQemuAttemptHostResourceOwner {
            resources: effective,
            host: LinuxHostSet::Single(host),
        })
    }

    #[cfg(target_os = "linux")]
    fn with_fork_target_world(
        &mut self,
        members: &mut crate::TargetConstructionStorage,
        resources: AttemptResourceLimits,
        install: &mut dyn FnMut(&mut Option<Self::Owner>) -> Result<(), QemuVmRealizationError>,
    ) -> Result<(), QemuVmRealizationError> {
        members.with_native_world(&mut self.host, resources, install)
    }

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Owner, QemuVmRealizationError> {
        let host = self.host.begin(
            resources.maximum_vcpus(),
            resources.maximum_resident_bytes(),
            resources.maximum_disk_bytes(),
        )?;
        let effective = effective_linux_limits(resources, host.resource_ceiling());
        let Ok(resources) = effective else {
            let mut host = host;
            host.quarantine();
            return Err(QemuVmRealizationError::Executor {
                operation: "install Linux QEMU host resources",
                message: String::from("combined Linux owner returned a different resource basis"),
            });
        };
        Ok(LinuxQemuAttemptHostResourceOwner {
            resources,
            host: LinuxHostSet::Single(host),
        })
    }
}

impl QemuAttemptSelectedHostResourceFactory for LinuxQemuAttemptHostResourceFactory {
    fn reserve_main_worker_controls(
        &self,
        bytes: u64,
    ) -> Result<
        Option<
            crucible_host_resources::host_services::process_birth::AuthenticatedNativePoolPurpose,
        >,
        QemuVmRealizationError,
    > {
        self.host.reserve_main_worker_controls(bytes)
    }

    fn begin_world(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
        consumer_control_bytes: u64,
        registration: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        before_effects: &mut NativeWorldBeforeEffects<'_>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        use crucible_host_resources::host_services::process_birth::{
            NativeNodeReservation, NativeWorldIdentity, ServiceBirthError,
        };
        let identity = match registration.native_world_identity() {
            Ok(identity) => NativeWorldIdentity {
                owner: identity.owner,
                selection: identity.selection,
            },
            Err(source) => {
                return Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        QemuVmRealizationError::ExecutorUnavailable {
                            operation: "borrow selected native World identity",
                            message: source.to_string(),
                        },
                        selected_checkpoint,
                    ),
                );
            }
        };
        let checkpoint = selected_checkpoint
            .as_ref()
            .map(|root| root.process_contract_root());
        let mut node_count = 0_usize;
        let count = registration.visit_native_nodes(&mut |_name, _row| {
            node_count = node_count.checked_add(1).ok_or_else(|| {
                crucible_control_api::host_operational::HostRamAdmissionError::contract(
                    "native World node count overflows",
                )
            })?;
            Ok(())
        });
        let controls = count
            .map_err(|source| QemuVmRealizationError::ExecutorUnavailable {
                operation: "price selected native World controls",
                message: source.to_string(),
            })
            .and_then(|()| LinuxQemuAttemptHostResourceOwner::world_control_bytes(node_count))
            .and_then(|bytes| {
                consumer_control_bytes.checked_add(bytes).ok_or_else(|| {
                    QemuVmRealizationError::ExecutorUnavailable {
                        operation: "price selected native World controls",
                        message: String::from("selected containing extent overflows"),
                    }
                })
            });
        let controls = match controls {
            Ok(controls) => controls,
            Err(source) => {
                return Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        source,
                        selected_checkpoint,
                    ),
                );
            }
        };
        let hosts = self.host.begin_native_world(
            identity,
            controls,
            checkpoint,
            before_effects,
            |accept| {
                registration
                    .visit_native_nodes(&mut |_name, row| {
                        accept(NativeNodeReservation {
                            node: row.node,
                            resources: row.resources,
                            source_host_descriptors: row.source_host_descriptors,
                            target_host_descriptors: row.target_host_descriptors,
                        })
                        .map_err(|source| {
                            crucible_control_api::host_operational::HostRamAdmissionError::contract(
                                source.to_string(),
                            )
                        })
                    })
                    .map_err(|source| ServiceBirthError::Policy(source.to_string()))
            },
        );
        let hosts = match hosts {
            Ok(hosts) => hosts,
            Err(source) => {
                return Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        source,
                        selected_checkpoint,
                    ),
                );
            }
        };
        let mut members: Vec<LinuxWorldMember> = Vec::new();
        if members.try_reserve_exact(hosts.len()).is_err() {
            // Actual node constructors already retain their original partial
            // custody in the pool; this refusal cannot reissue their cells.
            for mut node in hosts {
                node.owner.quarantine();
            }
            return Err(
                QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                    QemuVmRealizationError::ExecutorUnavailable {
                        operation: "allocate prepaid World member directory",
                        message: String::from("actual containing World allocation refused"),
                    },
                    selected_checkpoint,
                ),
            );
        }
        for node in hosts {
            let limits = node.owner.resource_ceiling();
            let member_resources = match AttemptResourceLimits::new(
                limits.0,
                limits.1,
                limits.2,
                resources.maximum_execution_quanta(),
            ) {
                Ok(limits) => limits,
                Err(source) => {
                    let mut node = node;
                    node.owner.quarantine();
                    for member in &mut members {
                        member.owner.quarantine();
                    }
                    return Err(
                        QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                            QemuVmRealizationError::ExecutorUnavailable {
                                operation: "retain installed World member limits",
                                message: source.to_string(),
                            },
                            selected_checkpoint,
                        ),
                    );
                }
            };
            members.push(LinuxWorldMember {
                key: node.key,
                owner: LinuxQemuAttemptHostResourceOwner {
                    resources: member_resources,
                    host: LinuxHostSet::Single(node.owner),
                },
            });
        }
        Ok((
            LinuxQemuAttemptHostResourceOwner {
                resources,
                host: LinuxHostSet::World { identity, members },
            },
            selected_checkpoint,
        ))
    }

    fn begin_selected(
        &mut self,
        resources: AttemptResourceLimits,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<
        (Self::Owner, Option<SelectedExactCheckpointRoot>),
        QemuAttemptResourceGuardBeginFailure,
    > {
        let host = match selected_checkpoint.as_ref() {
            Some(selected_checkpoint) => self.host.begin_exact_checkpoint(
                resources.maximum_vcpus(),
                resources.maximum_resident_bytes(),
                resources.maximum_disk_bytes(),
                selected_checkpoint.process_contract_root(),
            ),
            None => self.host.begin(
                resources.maximum_vcpus(),
                resources.maximum_resident_bytes(),
                resources.maximum_disk_bytes(),
            ),
        };
        let host = match host {
            Ok(host) => host,
            Err(error) => {
                return Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        error,
                        selected_checkpoint,
                    ),
                );
            }
        };
        let effective = effective_linux_limits(resources, host.resource_ceiling());
        let Ok(resources) = effective else {
            let mut host = host;
            host.quarantine();
            return Err(
                QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                    QemuVmRealizationError::Executor {
                        operation: "install Linux QEMU host resources",
                        message: String::from(
                            "combined Linux owner returned a different resource basis",
                        ),
                    },
                    selected_checkpoint,
                ),
            );
        };
        Ok((
            LinuxQemuAttemptHostResourceOwner {
                resources,
                host: LinuxHostSet::Single(host),
            },
            selected_checkpoint,
        ))
    }
}

impl QemuAttemptHostResourceOwner for LinuxQemuAttemptHostResourceOwner {
    #[cfg(target_os = "linux")]
    fn recover_target_construction_storage(
        &mut self,
        storage: &mut crate::TargetConstructionStorage,
    ) -> bool {
        storage.recover_native_hosts(self)
    }

    fn native_world_identity(
        &self,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
        QemuVmRealizationError,
    > {
        match &self.host {
            LinuxHostSet::World { identity, .. } => Ok(*identity),
            LinuxHostSet::Single(_) => Err(linux_world::world_route_error()),
        }
    }

    #[cfg(target_os = "linux")]
    fn with_fork_target_ram_admission(
        &self,
        contract: &QemuChildProcessContract,
        prepare: &mut dyn FnMut(
            &crucible_qemu_host::QemuForkTargetRamAdmission<'_>,
        ) -> Result<
            crucible_qemu_host::ram_control::RamControlRegistration,
            QemuVmRealizationError,
        >,
    ) -> Result<crucible_qemu_host::ram_control::RamControlRegistration, QemuVmRealizationError> {
        self.single()?
            .borrow_fork_target_ram_admission(contract)?
            .with_registration(prepare)
    }

    fn node_owner(&self, node: &NodeId) -> Result<&Self, QemuVmRealizationError> {
        self.member(node)
    }

    fn node_owner_mut(&mut self, node: &NodeId) -> Result<&mut Self, QemuVmRealizationError> {
        self.member_mut(node)
    }

    #[cfg(target_os = "linux")]
    fn reserve_contract_controls(
        &self,
        contract: &QemuChildProcessContract,
        descriptors: u64,
        bytes: u64,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::SourceHostControlLease,
        QemuVmRealizationError,
    > {
        self.single()?
            .reserve_contract_controls(contract, descriptors, bytes)
    }

    fn bind_fork_target_ram_custody(
        &mut self,
        contract: &QemuChildProcessContract,
        registration: &crucible_qemu_host::ram_control::RamControlRegistration,
        supervisor: &crucible_host_resources::host_supervision::HostOperationSupervisor,
        guest_ram_bytes: u64,
        custody: &crucible_qemu_host::QemuRamLaunchCustody,
    ) -> Result<(), QemuVmRealizationError> {
        self.single_mut()?.bind_fork_target_ram_custody(
            contract,
            registration,
            supervisor,
            guest_ram_bytes,
            custody,
        )
    }
    fn fork_target_is_owned(&self) -> bool {
        match &self.host {
            LinuxHostSet::Single(host) => host.fork_target_is_owned(),
            LinuxHostSet::World { members, .. } => members
                .iter()
                .any(|member| member.owner.fork_target_is_owned()),
        }
    }

    fn prepare_fork_target(
        &mut self,
    ) -> Result<crucible_qemu_host::QemuForkTargetPreparation, QemuVmRealizationError> {
        self.single_mut()?.prepare_fork_target()
    }

    fn prepare_fork_target_run_directory(
        &mut self,
        target_contract: &QemuChildProcessContract,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.single_mut()?
            .prepare_fork_target_run_directory(target_contract, requirements)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn retain_parent_park_cleanup(
        &self,
    ) -> Result<crucible_qemu_host::OriginalParentParkCleanup, QemuVmRealizationError> {
        self.single()?.retain_parent_park_cleanup()
    }

    /// Checks actual Node, host and Preparation custody before publication.
    ///
    /// # Errors
    /// Refuses absent or different original physical custody without effects.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn verify_parent_park_binding(
        &self,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<(), crucible_qemu_host::OriginalActorParkQuiescenceError> {
        source.verify_original_park_binding(
            self.single().map_err(|_| park_route_error(original))?,
            decoder,
            original,
        )
    }

    /// Enters the fixed actor phase through the actual containing host owner.
    ///
    /// # Errors
    /// Refuses missing original slot, actor or concrete physical host custody.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn enter_parent_park_quiescence(
        &self,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<
        crucible_qemu_host::OriginalActorParkQuiescence,
        crucible_qemu_host::OriginalActorParkQuiescenceError,
    > {
        source.enter_original_park_quiescence(
            self.single().map_err(|_| park_route_error(original))?,
            decoder,
            original,
        )
    }

    /// Constructs the fixed pair imports through the actual retained host.
    ///
    /// # Errors
    /// Refuses missing original physical custody or actual import admission.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn prepare_parent_park_imports(
        &self,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu_host::OriginalActorParkImports, crucible_qemu_host::OriginalActorParkImportError>
    {
        source.prepare_original_park_imports(
            self.single()
                .map_err(|_| crucible_qemu_host::OriginalActorAccountError::Unavailable)?,
            decoder,
            original,
            actor,
            family,
        )
    }

    type CancellationSignal = LinuxWorldCancellationSignal;

    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn matches_admitted_limits(&self, admitted: AttemptResourceLimits) -> bool {
        match &self.host {
            LinuxHostSet::Single(host) => effective_linux_limits(admitted, host.resource_ceiling())
                .is_ok_and(|effective| effective == self.resources),
            LinuxHostSet::World { .. } => admitted == self.resources,
        }
    }

    fn native_resource_controller(
        &mut self,
    ) -> Result<Option<crucible_qemu_host::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        self.single_mut()?.native_resource_controller().map(Some)
    }

    fn launch_fresh_node(
        &self,
        config: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu_host::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu_host::QemuNode, crucible_qemu_host::QemuLiveNodeStepGateError> {
        self.single()
            .map_err(node_route_launch_error)?
            .launch_fresh_node(config, admission)
    }

    fn installed_node_issuer(
        &self,
    ) -> Result<crucible_qemu_host::InstalledNodeLaunchIssuer, crucible_qemu_host::QemuLiveNodeStepGateError>
    {
        self.single()
            .map_err(node_route_launch_error)?
            .lend_installed_node_issuer()
    }

    fn launch_exact_node(
        &self,
        request: crucible_qemu_host::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu_host::QemuProductionExactRestoreLaunch,
        crucible_qemu_host::QemuLiveNodeStepGateError,
    > {
        self.single()
            .map_err(node_route_launch_error)?
            .launch_exact_node(request)
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.single()?.process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.single_mut()?
            .prepare_generation_run_directory(requirements)
    }

    fn cancellation_signal(&self) -> Result<Self::CancellationSignal, QemuVmRealizationError> {
        self.world_cancellation_signal()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        match &mut self.host {
            LinuxHostSet::Single(host) => host.check_operational_boundary(),
            LinuxHostSet::World { members, .. } => {
                let mut first = None;
                for member in members {
                    if let Err(error) = member.owner.check_operational_boundary() {
                        first.get_or_insert(error);
                    }
                }
                first.map_or(Ok(()), Err)
            }
        }
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        match &mut self.host {
            LinuxHostSet::Single(host) => host.retain_failed_child(child),
            LinuxHostSet::World { .. } => {
                // This unkeyed cut has no legitimate member; retain uncertain
                // custody rather than assigning the child to a first node.
                std::mem::forget(child);
                self.quarantine();
            }
        }
    }

    fn finish_with_original_registry(
        &mut self,
        registry: &crate::HostOperationalRegistry,
    ) -> Result<(), QemuVmRealizationError> {
        match &mut self.host {
            LinuxHostSet::Single(host) => match host.prepare_original_native_retirement()? {
                Some(physical) => registry.retire_original_native_world(physical),
                None => host.finish(),
            },
            LinuxHostSet::World { members, .. } => {
                for member in members {
                    member.owner.finish_with_original_registry(registry)?;
                }
                Ok(())
            }
        }
    }

    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        match &mut self.host {
            LinuxHostSet::Single(host) => host.finish(),
            LinuxHostSet::World { members, .. } => {
                for member in members {
                    member.owner.finish()?;
                }
                Ok(())
            }
        }
    }

    fn quarantine(&mut self) {
        match &mut self.host {
            LinuxHostSet::Single(host) => host.quarantine(),
            LinuxHostSet::World { members, .. } => {
                for member in members {
                    member.owner.quarantine();
                }
            }
        }
    }
}

impl QemuHotForkChildProcessOwner for LinuxQemuAttemptHostResourceOwner {
    type Authority = crucible_qemu_host::LinuxQemuHotForkChildProcessAuthority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        self.single_mut()
            .map_err(|source| {
                QemuNodeChannelError::new("retain exact hot-fork child", source.to_string())
            })?
            .retain_hot_fork_child(basis)
    }
}

mod generation_resource;
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
pub(crate) use generation_resource::ProcessStageContractRefusal;

pub use generation_resource::*;

/// Factory adding signal-driven cancellation and quantum accounting to a host owner.
pub struct ComposedQemuAttemptResourceGuardFactory<H> {
    host: H,
}

impl<H> Clone for ComposedQemuAttemptResourceGuardFactory<H>
where
    H: Clone,
{
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
        }
    }
}

impl<H> ComposedQemuAttemptResourceGuardFactory<H> {
    /// Creates a resource-guard factory over one host-resource allocator.
    #[must_use]
    pub const fn new(host: H) -> Self {
        Self { host }
    }
}

// Terminal containment is not physical return. The first raw leaf moves to
// the caller's history; this finite state prevents a later call or Drop from
// retrying the effect or treating delivered diagnostics as successful cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComposedResourceRetirement {
    Active,
    Returned,
    Quarantined,
}

/// One exact attempt resource guard composed from a host owner.
#[must_use = "finish the QEMU resource guard or transfer it to quarantine"]
pub struct ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    quantum_counter: QemuExecutionQuantumCounter,
    cancellation_failure: Arc<Mutex<Option<String>>>,
    cancellation_registration: Option<ExecutionCancellationHookRegistration>,
    original_native_registry: Option<crate::HostOperationalRegistry>,
    host: H,
    retirement: ComposedResourceRetirement,
}

impl<H> fmt::Debug for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner + fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComposedQemuAttemptResourceGuard")
            .field("resources", &self.resources)
            .field("quantum_counter", &self.quantum_counter)
            .field("host", &self.host)
            .field("retirement", &self.retirement)
            .finish_non_exhaustive()
    }
}

impl<H> QemuAttemptResourceGuardFactory for ComposedQemuAttemptResourceGuardFactory<H>
where
    H: QemuAttemptSelectedHostResourceFactory,
{
    fn verify_unborn_native_world(
        &self,
        loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
        controls: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldControlLease,
    ) -> Result<(), QemuVmRealizationError> {
        self.host.verify_unborn_native_world(loan, controls)
    }

    /// Returns only a canonically proven never-born World after body destruction.
    ///
    /// # Errors
    /// Preserves attempted, foreign or incompletely returned custody.
    fn abort_unborn_native_world(
        &mut self,
        loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        self.host.abort_unborn_native_world(loan)
    }

    fn retry_native_world_construction(
        &mut self,
        loan: &crucible_host_resources::host_services::process_birth::AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), QemuVmRealizationError> {
        self.host.retry_native_world_construction(loan)
    }

    fn source_main_producer(&self) -> Option<crate::SourceMainProducer> {
        self.host.source_main_producer()
    }

    fn begin_world(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
        consumer_control_bytes: u64,
        registration: &dyn crate::vm_lifecycle::ProductionHostRamRegistrationFactory,
        before_effects: &mut NativeWorldBeforeEffects<'_>,
    ) -> Result<Self::Guard, QemuAttemptResourceGuardBeginFailure> {
        let (host, selected_checkpoint) = self.host.begin_world(
            resources,
            selected_checkpoint,
            consumer_control_bytes,
            registration,
            before_effects,
        )?;
        ComposedQemuAttemptResourceGuard::from_installed_host(
            host,
            resources,
            cancellation,
            selected_checkpoint,
        )
    }

    type Guard = ComposedQemuAttemptResourceGuard<H::Owner>;

    fn retain_fork_target_factory(&self) -> Option<Self> {
        self.host.retain_fork_target_factory().map(Self::new)
    }

    #[cfg(target_os = "linux")]
    fn begin_fork_target(
        &mut self,
        permit: crucible_qemu_host::LinuxQemuForkTargetPermit,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuAttemptResourceGuardBeginFailure> {
        let host = self.host.begin_fork_target(permit, resources)?;
        ComposedQemuAttemptResourceGuard::from_installed_host(host, resources, cancellation, None)
    }

    #[cfg(target_os = "linux")]
    fn begin_fork_target_world(
        &mut self,
        members: &mut crate::TargetConstructionStorage,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<(Self::Guard, Option<QemuVmRealizationError>), QemuVmRealizationError> {
        let mut installed = None;
        self.host
            .with_fork_target_world(members, resources, &mut |host| {
                let outcome = ComposedQemuAttemptResourceGuard::from_retained_target_host(
                    host,
                    resources,
                    cancellation.clone(),
                )?;
                installed = Some(outcome);
                Ok(())
            })?;
        installed.ok_or(QemuVmRealizationError::CleanupRetained {
            operation: "retain actual composed Target World result",
        })
    }

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<Self::Guard, QemuAttemptResourceGuardBeginFailure> {
        let (host, selected_checkpoint) =
            self.host.begin_selected(resources, selected_checkpoint)?;
        ComposedQemuAttemptResourceGuard::from_installed_host(
            host,
            resources,
            cancellation,
            selected_checkpoint,
        )
    }
}

impl<H> ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    /// Moves an already retained host only after all pre-guard setup succeeds.
    ///
    /// Main keeps `host` on every early refusal. The independent postcheck is
    /// returned beside its actual guard, allowing the same Pending owner to
    /// record G before reporting failure. This method performs no rollback.
    #[cfg(target_os = "linux")]
    fn from_retained_target_host(
        host: &mut Option<H>,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<(Self, Option<QemuVmRealizationError>), QemuVmRealizationError> {
        let retained = host
            .as_mut()
            .ok_or(QemuVmRealizationError::CleanupRetained {
                operation: "borrow selected Target host before composition",
            })?;
        if !retained.matches_admitted_limits(resources) {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "compose selected Target World",
                message: String::from("host does not retain the admitted aggregate limits"),
            });
        }
        let effective = retained.resource_limits();
        let signal = retained.cancellation_signal()?;
        let cancellation_failure = Arc::new(Mutex::new(None));
        let hook: Arc<dyn ExecutionCancellationHook> = Arc::new(ProcessCancellationHook {
            signal,
            failure: Arc::clone(&cancellation_failure),
        });
        let registration = cancellation.register_hook(hook).map_err(|message| {
            QemuVmRealizationError::Executor {
                operation: "install selected Target cancellation hook",
                message: String::from(message),
            }
        })?;

        // Setup has only borrowed the Main-held host. G owns it before the
        // next check can report a post refusal, so that report cannot erase H.
        let retained = host.take().ok_or(QemuVmRealizationError::CleanupRetained {
            operation: "move selected Target host into its actual guard",
        })?;
        let mut guard = Self {
            resources: effective,
            cancellation,
            quantum_counter: QemuExecutionQuantumCounter::new(effective),
            cancellation_failure,
            cancellation_registration: Some(registration),
            original_native_registry: None,
            host: retained,
            retirement: ComposedResourceRetirement::Active,
        };
        let first_post = guard.check_operational_boundary().err();
        Ok((guard, first_post))
    }

    // Both fresh admission and permit consumption retain the same cancellation
    // and quantum composition; the physical host is already installed here.
    fn from_installed_host(
        mut host: H,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        selected_checkpoint: Option<SelectedExactCheckpointRoot>,
    ) -> Result<Self, QemuAttemptResourceGuardBeginFailure> {
        if !host.matches_admitted_limits(resources) {
            return Err(release_failed_begin_with_claim(
                &mut host,
                QemuVmRealizationError::Executor {
                    operation: "install QEMU host resources",
                    message: String::from(
                        "host resource owner did not install the exact admitted limits",
                    ),
                },
                selected_checkpoint,
            ));
        }

        // The owner has authenticated any monotonic refinement. All subsequent
        // node admission and status use the actual enforced basis.
        let resources = host.resource_limits();

        let signal = match host.cancellation_signal() {
            Ok(signal) => signal,
            Err(error) => {
                return Err(release_failed_begin_with_claim(
                    &mut host,
                    error,
                    selected_checkpoint,
                ));
            }
        };
        let cancellation_failure = Arc::new(Mutex::new(None));
        let hook: Arc<dyn ExecutionCancellationHook> = Arc::new(ProcessCancellationHook {
            signal,
            failure: Arc::clone(&cancellation_failure),
        });
        let cancellation_registration = match cancellation.register_hook(hook) {
            Ok(registration) => registration,
            Err(message) => {
                return Err(release_failed_begin_with_claim(
                    &mut host,
                    QemuVmRealizationError::Executor {
                        operation: "install QEMU cancellation hook",
                        message: String::from(message),
                    },
                    selected_checkpoint,
                ));
            }
        };

        let mut guard = ComposedQemuAttemptResourceGuard {
            resources,
            cancellation,
            quantum_counter: QemuExecutionQuantumCounter::new(resources),
            cancellation_failure,
            cancellation_registration: Some(cancellation_registration),
            original_native_registry: None,
            host,
            retirement: ComposedResourceRetirement::Active,
        };
        if let Err(error) = guard.check_operational_boundary() {
            return match guard.finish_raw() {
                Ok(()) => Err(
                    QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
                        error,
                        selected_checkpoint,
                    ),
                ),
                Err(cleanup) => Err(QemuAttemptResourceGuardBeginFailure::rollback(
                    error, cleanup,
                )),
            };
        }
        let _spent_selected_checkpoint_claim = selected_checkpoint;
        Ok(guard)
    }

    /// Performs the one actual close, retaining its raw first cause.
    ///
    /// Failed close records actual quarantine. Begin rollback keeps the raw
    /// cause; the public method maps generic quarantine to its terminal category.
    /// Neither caller repeats cleanup or quarantine.
    fn finish_raw(
        &mut self,
    ) -> Result<(), crate::crucible_qemu_session::QemuAttemptResourceGuardCleanupFailure> {
        use crate::crucible_qemu_session::QemuAttemptResourceGuardCleanupFailure;

        match self.retirement {
            ComposedResourceRetirement::Returned => return Ok(()),
            ComposedResourceRetirement::Quarantined => {
                return Err(QemuAttemptResourceGuardCleanupFailure::canceled_status(
                    if self.original_native_registry.is_some() {
                        "repeat quarantined original native retirement"
                    } else {
                        "repeat quarantined attempt host retirement"
                    },
                )
                .after_quarantine());
            }
            ComposedResourceRetirement::Active => {}
        }
        self.cancellation_registration = None;
        let result = finish_host_raw(&mut self.host, self.original_native_registry.as_ref());
        self.retirement = if result.is_ok() {
            ComposedResourceRetirement::Returned
        } else {
            ComposedResourceRetirement::Quarantined
        };
        result
    }
}

impl<H> QemuAttemptOperationalBoundary for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.retirement != ComposedResourceRetirement::Active {
            return Err(QemuVmRealizationError::Executor {
                operation: "check QEMU attempt resources",
                message: String::from("attempt resource guard is already terminal"),
            });
        }
        if let Some(message) = cancellation_failure(&self.cancellation_failure)? {
            return Err(QemuVmRealizationError::Executor {
                operation: "signal QEMU process cancellation",
                message,
            });
        }
        if self.cancellation.is_canceled() {
            return Err(QemuVmRealizationError::Canceled {
                operation: "QEMU attempt resource boundary",
            });
        }
        self.host.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.check_operational_boundary()?;
        self.quantum_counter.charge()
    }
}

impl<H> QemuAttemptResourceGuard for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    #[cfg(target_os = "linux")]
    fn recover_target_construction_storage(
        &mut self,
        storage: &mut crate::TargetConstructionStorage,
    ) -> bool {
        self.host.recover_target_construction_storage(storage)
    }

    fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
        let original_registry = self.original_native_registry.is_some();
        self.finish_raw().map_err(|failure| {
            if original_registry {
                failure
            } else {
                failure.terminal_category()
            }
        })
    }

    fn quarantine(&mut self) {
        if self.retirement != ComposedResourceRetirement::Active {
            return;
        }
        self.cancellation_registration = None;
        self.host.quarantine();
        self.retirement = ComposedResourceRetirement::Quarantined;
    }
}

impl<H> QemuAttemptProcessResourceGuard for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    #[cfg(target_os = "linux")]
    fn native_world_identity(
        &self,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
        QemuVmRealizationError,
    > {
        self.host.native_world_identity()
    }

    fn native_resource_controller_for_node(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<crucible_qemu_host::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        self.host.node_owner_mut(node)?.native_resource_controller()
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn retain_parent_park_cleanup_for_node(
        &self,
        node: &NodeId,
    ) -> Result<crucible_qemu_host::OriginalParentParkCleanup, QemuVmRealizationError> {
        self.host.node_owner(node)?.retain_parent_park_cleanup()
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn verify_parent_park_binding_for_node(
        &self,
        node: &NodeId,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<(), crucible_qemu_host::OriginalActorParkQuiescenceError> {
        self.host
            .node_owner(node)
            .map_err(|_| park_route_error(original))?
            .verify_parent_park_binding(source, original, decoder)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn enter_parent_park_quiescence_for_node(
        &self,
        node: &NodeId,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<
        crucible_qemu_host::OriginalActorParkQuiescence,
        crucible_qemu_host::OriginalActorParkQuiescenceError,
    > {
        self.host
            .node_owner(node)
            .map_err(|_| park_route_error(original))?
            .enter_parent_park_quiescence(source, original, decoder)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn prepare_parent_park_imports_for_node(
        &self,
        node: &NodeId,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu_host::OriginalActorParkImports, crucible_qemu_host::OriginalActorParkImportError>
    {
        self.host
            .node_owner(node)
            .map_err(|_| crucible_qemu_host::OriginalActorAccountError::Unavailable)?
            .prepare_parent_park_imports(source, original, decoder, actor, family)
    }

    #[cfg(target_os = "linux")]
    fn with_fork_target_ram_admission_for_node(
        &self,
        node: &NodeId,
        contract: &QemuChildProcessContract,
        prepare: &mut dyn FnMut(
            &crucible_qemu_host::QemuForkTargetRamAdmission<'_>,
        ) -> Result<
            crucible_qemu_host::ram_control::RamControlRegistration,
            QemuVmRealizationError,
        >,
    ) -> Result<crucible_qemu_host::ram_control::RamControlRegistration, QemuVmRealizationError> {
        self.host
            .node_owner(node)?
            .with_fork_target_ram_admission(contract, prepare)
    }

    #[cfg(target_os = "linux")]
    fn reserve_contract_controls_for_node(
        &self,
        node: &NodeId,
        contract: &QemuChildProcessContract,
        descriptors: u64,
        bytes: u64,
    ) -> Result<
        crucible_host_resources::host_services::process_birth::SourceHostControlLease,
        QemuVmRealizationError,
    > {
        self.host
            .node_owner(node)?
            .reserve_contract_controls(contract, descriptors, bytes)
    }

    #[cfg(target_os = "linux")]
    fn bind_fork_target_ram_custody_for_node(
        &mut self,
        node: &NodeId,
        contract: &QemuChildProcessContract,
        registration: &crucible_qemu_host::ram_control::RamControlRegistration,
        supervisor: &crucible_host_resources::host_supervision::HostOperationSupervisor,
        guest_ram_bytes: u64,
        custody: &crucible_qemu_host::QemuRamLaunchCustody,
    ) -> Result<(), QemuVmRealizationError> {
        self.host
            .node_owner_mut(node)?
            .bind_fork_target_ram_custody(
                contract,
                registration,
                supervisor,
                guest_ram_bytes,
                custody,
            )
    }

    fn child_process_contract_for_node(
        &self,
        node: &NodeId,
    ) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.host.node_owner(node)?.child_process_contract()
    }

    fn prepare_generation_run_directory_for_node(
        &mut self,
        node: &NodeId,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.host
            .node_owner_mut(node)?
            .prepare_generation_run_directory(requirements)
    }

    fn installed_node_issuer_for_node(
        &self,
        node: &NodeId,
    ) -> Result<crucible_qemu_host::InstalledNodeLaunchIssuer, crucible_qemu_host::QemuLiveNodeStepGateError>
    {
        self.host
            .node_owner(node)
            .map_err(node_route_launch_error)?
            .installed_node_issuer()
    }

    fn launch_fresh_node_for_node(
        &self,
        node: &NodeId,
        config: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu_host::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu_host::QemuNode, crucible_qemu_host::QemuLiveNodeStepGateError> {
        self.host
            .node_owner(node)
            .map_err(node_route_launch_error)?
            .launch_fresh_node(config, admission)
    }

    fn launch_exact_node_for_node(
        &self,
        node: &NodeId,
        request: crucible_qemu_host::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu_host::QemuProductionExactRestoreLaunch,
        crucible_qemu_host::QemuLiveNodeStepGateError,
    > {
        self.host
            .node_owner(node)
            .map_err(node_route_launch_error)?
            .launch_exact_node(request)
    }

    fn retain_failed_launch_child_for_node(&mut self, node: &NodeId, child: QemuNodeChild) {
        match self.host.node_owner_mut(node) {
            Ok(owner) => owner.retain_failed_launch_child(child),
            Err(_) => {
                // A routing refusal cannot certify reap or destroy the only
                // child handle. Preserve it and quarantine the whole World.
                std::mem::forget(child);
                self.quarantine();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn fork_target_is_owned_for_node(&self, node: &NodeId) -> bool {
        self.host
            .node_owner(node)
            .map_or(true, |owner| owner.fork_target_is_owned())
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target_for_node(
        &mut self,
        node: &NodeId,
    ) -> Result<crucible_qemu_host::QemuForkTargetPreparation, QemuVmRealizationError> {
        self.host.node_owner_mut(node)?.prepare_fork_target()
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target_run_directory_for_node(
        &mut self,
        node: &NodeId,
        contract: &QemuChildProcessContract,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.host
            .node_owner_mut(node)?
            .prepare_fork_target_run_directory(contract, requirements)
    }

    #[cfg(target_os = "linux")]
    fn bind_fork_target_ram_custody(
        &mut self,
        contract: &QemuChildProcessContract,
        registration: &crucible_qemu_host::ram_control::RamControlRegistration,
        supervisor: &crucible_host_resources::host_supervision::HostOperationSupervisor,
        guest_ram_bytes: u64,
        custody: &crucible_qemu_host::QemuRamLaunchCustody,
    ) -> Result<(), QemuVmRealizationError> {
        self.host.bind_fork_target_ram_custody(
            contract,
            registration,
            supervisor,
            guest_ram_bytes,
            custody,
        )
    }
    #[cfg(target_os = "linux")]
    fn fork_target_is_owned(&self) -> bool {
        self.host.fork_target_is_owned()
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target(
        &mut self,
    ) -> Result<crucible_qemu_host::QemuForkTargetPreparation, QemuVmRealizationError> {
        self.host.prepare_fork_target()
    }

    #[cfg(target_os = "linux")]
    fn prepare_fork_target_run_directory(
        &mut self,
        target_contract: &QemuChildProcessContract,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.host
            .prepare_fork_target_run_directory(target_contract, requirements)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn retain_parent_park_cleanup(
        &self,
    ) -> Result<crucible_qemu_host::OriginalParentParkCleanup, QemuVmRealizationError> {
        self.host.retain_parent_park_cleanup()
    }

    /// Checks actual Node, host and Preparation custody before publication.
    ///
    /// # Errors
    /// Refuses absent or different original physical custody without effects.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn verify_parent_park_binding(
        &self,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<(), crucible_qemu_host::OriginalActorParkQuiescenceError> {
        self.host
            .verify_parent_park_binding(source, original, decoder)
    }

    /// Enters the fixed actor phase through the actual containing host owner.
    ///
    /// # Errors
    /// Refuses missing original slot, actor or concrete physical host custody.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn enter_parent_park_quiescence(
        &self,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
    ) -> Result<
        crucible_qemu_host::OriginalActorParkQuiescence,
        crucible_qemu_host::OriginalActorParkQuiescenceError,
    > {
        self.host
            .enter_parent_park_quiescence(source, original, decoder)
    }

    /// Constructs the fixed pair imports through the actual retained host.
    ///
    /// # Errors
    /// Refuses missing original physical custody or actual import admission.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn prepare_parent_park_imports(
        &self,
        source: &crucible_qemu_host::QemuNodeSetPreparedHotForkSource<'_>,
        original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        decoder: &crucible_qemu_host::OriginalActorParkCaller,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crucible_qemu_host::OriginalActorParkImports, crucible_qemu_host::OriginalActorParkImportError>
    {
        self.host
            .prepare_parent_park_imports(source, original, decoder, actor, family)
    }

    fn retain_original_native_registry(
        &mut self,
        registry: crate::HostOperationalRegistry,
    ) -> Result<(), QemuVmRealizationError> {
        if self.original_native_registry.is_some()
            || self.retirement != ComposedResourceRetirement::Active
        {
            return Err(QemuVmRealizationError::Executor {
                operation: "retain original native registry",
                message: String::from("original registry is already bound or guard is terminal"),
            });
        }
        self.original_native_registry = Some(registry);
        Ok(())
    }

    fn native_resource_controller(
        &mut self,
    ) -> Result<Option<crucible_qemu_host::LinuxQemuNativeResourceController>, QemuVmRealizationError>
    {
        self.host.native_resource_controller()
    }

    fn launch_fresh_node(
        &self,
        config: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        admission: crucible_qemu_host::QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<crucible_qemu_host::QemuNode, crucible_qemu_host::QemuLiveNodeStepGateError> {
        self.host.launch_fresh_node(config, admission)
    }

    fn installed_node_issuer(
        &self,
    ) -> Result<crucible_qemu_host::InstalledNodeLaunchIssuer, crucible_qemu_host::QemuLiveNodeStepGateError>
    {
        self.host.installed_node_issuer()
    }

    fn launch_exact_node(
        &self,
        request: crucible_qemu_host::QemuProductionExactRestoreRequest,
    ) -> Result<
        crucible_qemu_host::QemuProductionExactRestoreLaunch,
        crucible_qemu_host::QemuLiveNodeStepGateError,
    > {
        self.host.launch_exact_node(request)
    }

    fn child_process_contract(&self) -> Result<&QemuChildProcessContract, QemuVmRealizationError> {
        self.host.child_process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.host.prepare_generation_run_directory(requirements)
    }

    fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        self.host.retain_failed_launch_child(child);
    }
}

impl<H> QemuHotForkChildProcessOwner for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner + QemuHotForkChildProcessOwner,
{
    fn retain_hot_fork_child_for_node(
        &mut self,
        node: &NodeId,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        if self.retirement != ComposedResourceRetirement::Active {
            return Err(QemuNodeChannelError::new(
                "retain selected forked child",
                "aggregate World is terminal",
            ));
        }
        match self.host.node_owner_mut(node) {
            Ok(owner) => owner.retain_hot_fork_child(basis),
            Err(source) => {
                // A failed selector cannot return a reported live child to an
                // ordinary path. The containing kernel owners retain all jobs.
                self.quarantine();
                Err(QemuNodeChannelError::new(
                    "retain selected forked child",
                    source.to_string(),
                ))
            }
        }
    }

    type Authority = H::Authority;

    fn retain_hot_fork_child(
        &mut self,
        basis: QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, QemuNodeChannelError> {
        if self.retirement != ComposedResourceRetirement::Active {
            return Err(QemuNodeChannelError::new(
                "retain forked child process",
                "attempt resource guard is already terminal",
            ));
        }
        self.host.retain_hot_fork_child(basis)
    }
}

impl<H> Drop for ComposedQemuAttemptResourceGuard<H>
where
    H: QemuAttemptHostResourceOwner,
{
    fn drop(&mut self) {
        self.quarantine();
    }
}

fn generation_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: message.into(),
    }
}

fn attempt_operational_error(
    operation: &'static str,
    error: QemuVmRealizationError,
) -> LifecycleApiError {
    let class = match &error {
        QemuVmRealizationError::ExecutorUnavailable { .. }
        | QemuVmRealizationError::ModelCopy { .. } => SchedulerOperationalFailureClass::Retryable,
        #[cfg(target_os = "linux")]
        QemuVmRealizationError::TargetDispatcherRetirement { source } => {
            if source.is_retryable() {
                SchedulerOperationalFailureClass::Retryable
            } else {
                SchedulerOperationalFailureClass::Terminal
            }
        }
        #[cfg(target_os = "linux")]
        QemuVmRealizationError::NativePoolReturn { .. } => {
            SchedulerOperationalFailureClass::Retryable
        }
        QemuVmRealizationError::Canceled { .. } => SchedulerOperationalFailureClass::Canceled,
        #[cfg(target_os = "linux")]
        QemuVmRealizationError::HostMemoryLimit { .. } => {
            SchedulerOperationalFailureClass::Terminal
        }
        QemuVmRealizationError::CleanupRetained { .. }
        | QemuVmRealizationError::ReapQuarantined { .. }
        | QemuVmRealizationError::Store { .. }
        | QemuVmRealizationError::Executor { .. }
        | QemuVmRealizationError::InvalidCheckpoint { .. }
        | QemuVmRealizationError::InvalidAncestor { .. }
        | QemuVmRealizationError::ReplayOracleMismatch { .. } => {
            SchedulerOperationalFailureClass::Terminal
        }
    };
    LifecycleApiError::AttemptOperational {
        class,
        message: format!("{operation}: {error}"),
    }
}

fn terminal_attempt_operational_error(message: impl Into<String>) -> LifecycleApiError {
    LifecycleApiError::AttemptOperational {
        class: SchedulerOperationalFailureClass::Terminal,
        message: message.into(),
    }
}

struct ProcessCancellationHook<S> {
    signal: S,
    failure: Arc<Mutex<Option<String>>>,
}

impl<S> fmt::Debug for ProcessCancellationHook<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessCancellationHook")
            .finish_non_exhaustive()
    }
}

impl<S> ExecutionCancellationHook for ProcessCancellationHook<S>
where
    S: QemuAttemptCancellationSignal,
{
    fn signal(&self) {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.signal.signal()));
        let message = match result {
            Ok(Ok(())) => return,
            Ok(Err(error)) => error.to_string(),
            Err(_) => String::from("process cancellation callback panicked"),
        };
        let mut failure = match self.failure.lock() {
            Ok(failure) => failure,
            Err(poisoned) => poisoned.into_inner(),
        };
        if failure.is_none() {
            *failure = Some(message);
        }
    }
}

fn cancellation_failure(
    failure: &Mutex<Option<String>>,
) -> Result<Option<String>, QemuVmRealizationError> {
    failure
        .lock()
        .map(|failure| failure.clone())
        .map_err(|_| QemuVmRealizationError::Executor {
            operation: "read QEMU cancellation hook state",
            message: String::from("cancellation hook diagnostic state is poisoned"),
        })
}

/// Performs host cleanup once and reports its original cause before adaptation.
///
/// Both pre-guard rollback and installed-guard retirement use this same effect
/// cut. An error transfers the host to quarantine once; it never becomes proof
/// that the actual host resources physically returned.
fn finish_host_raw<H>(
    host: &mut H,
    registry: Option<&crate::HostOperationalRegistry>,
) -> Result<(), crate::crucible_qemu_session::QemuAttemptResourceGuardCleanupFailure>
where
    H: QemuAttemptHostResourceOwner,
{
    let result = match registry {
        Some(registry) => host.finish_with_original_registry(registry),
        None => host.finish(),
    };
    result.map_err(|error| {
        host.quarantine();
        crate::crucible_qemu_session::QemuAttemptResourceGuardCleanupFailure::quarantined(error)
    })
}

fn release_failed_begin_with_claim<H>(
    host: &mut H,
    original: QemuVmRealizationError,
    selected_checkpoint: Option<SelectedExactCheckpointRoot>,
) -> QemuAttemptResourceGuardBeginFailure
where
    H: QemuAttemptHostResourceOwner,
{
    match finish_host_raw(host, None) {
        Ok(()) => QemuAttemptResourceGuardBeginFailure::before_checkpoint_claim(
            original,
            selected_checkpoint,
        ),
        Err(cleanup) => QemuAttemptResourceGuardBeginFailure::rollback(original, cleanup),
    }
}

#[cfg(test)]
mod tests;

fn node_route_launch_error(
    source: QemuVmRealizationError,
) -> crucible_qemu_host::QemuLiveNodeStepGateError {
    crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeContract { source }
}

fn cleanup_reservation_error(source: LifecycleApiError) -> QemuVmRealizationError {
    QemuVmRealizationError::ExecutorUnavailable {
        operation: "reserve same Main lifecycle cleanup custody",
        message: source.to_string(),
    }
}
