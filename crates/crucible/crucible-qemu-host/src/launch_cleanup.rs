//! Private final-close custody for an admitted QEMU launch.
//!
//! Every launch borrower keeps a clone after its descriptors and service leases
//! in field order. The last clone therefore closes only after those resources.
//! Actual wait and join authorities supply terminal proofs; socket closure,
//! cancellation, worker exit, and elapsed time never substitute for them.
//! Unpublished owners retain strong admission authority. Publication switches
//! to independent retirement authority; closing the registry's controller prepares
//! retirement, while final resource destruction still owns capacity discharge.
//! The final observer frees its shared allocation before the extracted record
//! retires custody; the original control loan is the finalizer's last field.
//! Controller progress takes its prepaid first-error allocation and journal
//! before provider entry. Erased errors share only the independent finalizer;
//! an actual error retaining its launch cannot create an ownership cycle.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

use crucible_host_resources::ram_policy::{HostRamTarget, HostResourceVector};

use crate::ram_control::{RamControlRegistrar, RamControlRegistration, RamControlRetirementAuthority};
use crucible_qemu_protocol::ram_control::RamControlError;

mod retained_record;
use retained_record::RetainedCleanupRecord;

mod retained_finalizer;
use retained_finalizer::RetainedCleanupFinalizer;

mod retirement_cause;
pub(crate) use retirement_cause::ControllerReturnCause;

mod retirement_history;
pub(crate) use retirement_history::ControllerReturnJournal;
pub use retirement_history::{RamControlRetirementHistory, RamControlRetirementRecord};

mod shutdown_journal;
pub(crate) use shutdown_journal::ShutdownJournal;
pub use shutdown_journal::{
    QemuShutdownAttempts, QemuShutdownFailures, QemuShutdownObservations, QemuShutdownRefusal,
};

#[cfg(target_os = "linux")]
mod unreaped_child;
#[cfg(target_os = "linux")]
pub(crate) use unreaped_child::UnreapedChildRetention;

/// Transfers both prelaunch allocations away from the root before effects.
#[derive(Debug)]
pub(crate) struct ControllerReturnStorage {
    pub(crate) cause: crucible_engine::SharedOperationalCause<ControllerReturnCause>,
    pub(crate) journal: ControllerReturnJournal,
}

/// Retains final-close custody for one independently admitted QEMU launch.
///
/// Clones share one cleanup record and one exact resource reservation. Target
/// preparation, pinned storage and staged transports retain this capability
/// before creating physical borrowers. Only the private process and worker
/// owners can supply terminal proofs; this capability exposes no release API.
#[derive(Clone, Debug)]
pub struct QemuRamLaunchCustody {
    pub(crate) cleanup: LaunchCleanup,
}

impl QemuRamLaunchCustody {
    /// Retains the exact registrar and resources of an existing launch admission.
    #[must_use]
    pub fn new(registration: &RamControlRegistration) -> Self {
        Self {
            cleanup: LaunchCleanup::new(registration),
        }
    }

    /// Observes disposition through the exact retained external process loan.
    ///
    /// The real direct parent must have reaped the fork generation previously
    /// bound by successful process retention. This observation releases no
    /// capacity; all physical borrowers still retain their cleanup clones.
    ///
    /// # Errors
    /// Refuses an unbound, foreign, or poisoned process-generation basis.
    #[cfg(target_os = "linux")]
    pub fn observe_process_disposition(
        &self,
        process: &dyn crate::QemuNodeExternalProcessControl,
    ) -> Result<bool, RamControlError> {
        self.cleanup.observe_external_process(process)
    }

    pub(crate) fn validates(&self, registration: &RamControlRegistration) -> bool {
        self.cleanup.inner.target == Some(registration.target)
            && self.cleanup.inner.authority.lock().is_ok_and(|authority| {
                !authority.published
                    && authority.resources == registration.resources
                    && authority
                        .registrar
                        .as_ref()
                        .is_some_and(|registrar| Arc::ptr_eq(registrar, &registration.registrar))
            })
    }

    pub(crate) fn same_launch(&self, other: &Self) -> bool {
        self.cleanup.inner.same_owner(&other.cleanup.inner)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LaunchCleanup {
    inner: RetainedCleanupRecord,
}

/// Retains admitted manifest metadata and its original native cleanup authority.
///
/// Copies share one charge. Every derived manifest or World declaration must
/// finish using its reserved allocation before the final lease is dropped.
/// Native cleanup may prepare retirement earlier; its complete resource ledger
/// remains retained until this final borrower also disposes its metadata.
#[derive(Clone, Debug)]
pub struct QemuFaultManifestMetadataLease {
    // Release the resident sublease before allowing final outer retirement.
    _service: crucible_host_resources::host_services::HostServiceLease,
    _cleanup: LaunchCleanup,
}

impl QemuFaultManifestMetadataLease {
    pub(crate) fn new(
        service: crucible_host_resources::host_services::HostServiceLease,
        cleanup: LaunchCleanup,
    ) -> Self {
        Self {
            _service: service,
            _cleanup: cleanup,
        }
    }
}

struct CleanupAuthority {
    registrar: Option<Arc<dyn RamControlRegistrar>>,
    published_retirement: Option<Arc<dyn RamControlRetirementAuthority>>,
    published: bool,
    resources: HostResourceVector,
}

/// Separates immutable cause custody from the last accounting transition.
struct CleanupRecord {
    // Release this identity alias before the finalizer can discharge accounting.
    registration_identity: Option<(HostRamTarget, std::sync::Weak<dyn RamControlRegistrar>)>,
    retirement_storage: Mutex<Option<ControllerReturnStorage>>,
    shutdown_storage: Mutex<Option<ShutdownJournal>>,
    retirement_claimed: AtomicBool,
    finalizer: RetainedCleanupFinalizer,
}

impl std::ops::Deref for CleanupRecord {
    type Target = CleanupFinalizer;

    fn deref(&self) -> &Self::Target {
        &self.finalizer
    }
}

impl std::fmt::Debug for CleanupRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.finalizer.fmt(formatter)
    }
}

struct CleanupFinalizer {
    target: Option<HostRamTarget>,
    authority: Mutex<CleanupAuthority>,
    #[cfg(target_os = "linux")]
    source_purpose: Mutex<
        Option<
            crucible_host_resources::host_services::process_birth::AuthenticatedSourceHostPurpose,
        >,
    >,
    #[cfg(target_os = "linux")]
    installed_incarnation: Mutex<Option<crate::linux_attempt_host::InstalledIncarnationRetirement>>,
    #[cfg(target_os = "linux")]
    target_binding: Mutex<Option<crate::linux_attempt_host::OriginalNativeNodeBinding>>,
    #[cfg(target_os = "linux")]
    target_workspace: Mutex<Option<crate::spawn::OriginalDeviceDigestWorkspace>>,
    #[cfg(target_os = "linux")]
    source_spawn_control: Mutex<
        Option<crucible_host_resources::host_services::process_birth::SourceHostControlLease>,
    >,
    #[cfg(target_os = "linux")]
    preexec_claimed: AtomicBool,
    #[cfg(target_os = "linux")]
    abandoned_preexec: OnceLock<crate::spawn::preexec_setup::PreexecAbandonment>,
    #[cfg(target_os = "linux")]
    preexec_failure: OnceLock<crate::spawn::preexec_setup::PreexecFailureRecord>,
    #[cfg(target_os = "linux")]
    child_return_claimed: AtomicBool,
    #[cfg(target_os = "linux")]
    abandoned_child: OnceLock<Mutex<crate::node::AbandonedChild>>,
    child_started: AtomicBool,
    child_reaped: AtomicBool,
    pending_joins: AtomicUsize,
    pending_imports: AtomicUsize,
    #[cfg(target_os = "linux")]
    external_basis: Mutex<Option<crate::QemuHotForkChildProcessBasis>>,
    // The shared allocation and every extracted physical owner close first.
    #[cfg(target_os = "linux")]
    source_control:
        Option<crucible_host_resources::host_services::process_birth::SourceHostControlLease>,
}

impl CleanupFinalizer {
    fn source_process_collected(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            // The actual Source Child records this independently of the local
            // cleanup flags. Unknown custody keeps the original charge held.
            self.source_purpose.try_lock().is_ok_and(|purpose| {
                purpose
                    .as_ref()
                    .is_none_or(|purpose| purpose.verify_process_returned_or_unstarted().is_ok())
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            true
        }
    }
}

impl std::fmt::Debug for CleanupFinalizer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CleanupRecord")
            .field("target", &self.target)
            .field("child_started", &self.child_started.load(Ordering::Acquire))
            .field("child_reaped", &self.child_reaped.load(Ordering::Acquire))
            .field("pending_joins", &self.pending_joins.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl LaunchCleanup {
    pub(crate) fn same_return_owner(&self, other: &Self) -> bool {
        self.inner.same_owner(&other.inner)
    }

    /// Transfers the original prelaunch cause and journal to one return owner.
    ///
    /// Taking it before provider entry avoids a cycle if that provider's actual
    /// error itself retains this launch. A refused claim never calls a provider.
    pub(crate) fn claim_controller_return(&self) -> Option<ControllerReturnStorage> {
        self.inner
            .retirement_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        self.inner.retirement_storage.try_lock().ok()?.take()
    }

    /// Moves the prepaid shutdown cells before any target effect or report.
    pub(crate) fn claim_shutdown_journal(&self) -> Option<ShutdownJournal> {
        self.inner.shutdown_storage.try_lock().ok()?.take()
    }

    pub(crate) fn matches_return_registration(
        &self,
        registration: &RamControlRegistration,
    ) -> bool {
        self.inner
            .registration_identity
            .as_ref()
            .is_some_and(|(target, registrar)| {
                *target == registration.target
                    && std::sync::Weak::ptr_eq(registrar, &Arc::downgrade(&registration.registrar))
            })
    }

    pub(crate) fn retained_control_bytes() -> Option<u64> {
        RetainedCleanupRecord::allocation_peak_bytes()
    }

    pub(crate) fn new(registration: &RamControlRegistration) -> Self {
        Self {
            inner: RetainedCleanupRecord::new(CleanupFinalizer {
                target: Some(registration.target),
                authority: Mutex::new(CleanupAuthority {
                    registrar: Some(Arc::clone(&registration.registrar)),
                    published_retirement: None,
                    published: false,
                    resources: registration.resources,
                }),
                #[cfg(target_os = "linux")]
                source_purpose: Mutex::new(None),
                #[cfg(target_os = "linux")]
                installed_incarnation: Mutex::new(None),
                #[cfg(target_os = "linux")]
                target_binding: Mutex::new(None),
                #[cfg(target_os = "linux")]
                target_workspace: Mutex::new(None),
                #[cfg(target_os = "linux")]
                source_spawn_control: Mutex::new(None),
                #[cfg(target_os = "linux")]
                preexec_claimed: AtomicBool::new(false),
                #[cfg(target_os = "linux")]
                abandoned_preexec: OnceLock::new(),
                #[cfg(target_os = "linux")]
                preexec_failure: OnceLock::new(),
                #[cfg(target_os = "linux")]
                child_return_claimed: AtomicBool::new(false),
                #[cfg(target_os = "linux")]
                abandoned_child: OnceLock::new(),
                child_started: AtomicBool::new(false),
                child_reaped: AtomicBool::new(false),
                pending_joins: AtomicUsize::new(0),
                pending_imports: AtomicUsize::new(0),
                #[cfg(target_os = "linux")]
                external_basis: Mutex::new(None),
                #[cfg(target_os = "linux")]
                source_control: None,
            }),
        }
    }

    /// Keeps the genuine Source payer before the shared cleanup body is born.
    ///
    /// RAM registration remains optional. Its absence supplies no authority:
    /// the actual installed Source admission retains the same Main charge.
    ///
    /// # Errors
    /// Refuses changed Source custody or exhausted actual control capacity.
    #[cfg(target_os = "linux")]
    pub(crate) fn new_source(
        registration: Option<&RamControlRegistration>,
        admission: &crate::linux_attempt_host::InstalledSourceAdmission,
    ) -> Result<Self, crate::linux_attempt_host::OriginalActorAccountError> {
        admission.check()?;
        let bytes = Self::retained_control_bytes()
            .ok_or(crate::linux_attempt_host::OriginalActorAccountError::Unavailable)?;
        let control = admission
            .host_purpose()
            .reserve_controls(0, bytes)
            .map_err(crate::linux_attempt_host::OriginalActorAccountError::from)?;
        Ok(Self {
            inner: RetainedCleanupRecord::new(CleanupFinalizer {
                target: registration.map(|registration| registration.target),
                authority: Mutex::new(CleanupAuthority {
                    registrar: registration.map(|registration| Arc::clone(&registration.registrar)),
                    published_retirement: None,
                    published: false,
                    resources: registration
                        .map_or(admission.resources(), |registration| registration.resources),
                }),
                source_purpose: Mutex::new(Some(admission.host_purpose().clone())),
                installed_incarnation: Mutex::new(None),
                target_binding: Mutex::new(None),
                target_workspace: Mutex::new(None),
                #[cfg(target_os = "linux")]
                source_spawn_control: Mutex::new(None),
                #[cfg(target_os = "linux")]
                preexec_claimed: AtomicBool::new(false),
                #[cfg(target_os = "linux")]
                abandoned_preexec: OnceLock::new(),
                #[cfg(target_os = "linux")]
                preexec_failure: OnceLock::new(),
                #[cfg(target_os = "linux")]
                child_return_claimed: AtomicBool::new(false),
                #[cfg(target_os = "linux")]
                abandoned_child: OnceLock::new(),
                child_started: AtomicBool::new(false),
                child_reaped: AtomicBool::new(false),
                pending_joins: AtomicUsize::new(0),
                pending_imports: AtomicUsize::new(0),
                external_basis: Mutex::new(None),
                source_control: Some(control),
            }),
        })
    }

    /// Reserves the containing launch's sole pre-exec abandonment recipient.
    ///
    /// The linear token is created before handover effects. It cannot be cloned
    /// or replaced after a failed attempt on the same launch.
    #[cfg(target_os = "linux")]
    pub(crate) fn claim_preexec(&self) -> Option<PreexecRetention> {
        self.inner
            .preexec_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(PreexecRetention {
            cleanup: self.clone(),
        })
    }

    /// Publishes the sole pre-exec refusal into already funded storage.
    #[cfg(target_os = "linux")]
    pub(crate) fn retain_preexec_failure(
        &self,
        failure: crate::spawn::preexec_setup::PreexecFailureRecord,
    ) {
        self.inner.preexec_failure.get_or_init(|| failure);
    }

    /// Borrows the original cause without copying or locking its owner.
    #[cfg(target_os = "linux")]
    pub(crate) fn preexec_failure(
        &self,
    ) -> Option<&crate::spawn::preexec_setup::PreexecFailureRecord> {
        self.inner.preexec_failure.get()
    }

    /// Borrows retained handover history for component regression checks.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn abandoned_preexec(
        &self,
    ) -> Option<&crate::spawn::preexec_setup::PreexecAbandonment> {
        self.inner.abandoned_preexec.get()
    }

    /// Prepays the real spawn descriptor overlap before pair construction.
    ///
    /// # Errors
    /// Refuses another Source owner, repeated publication or uncertain funding.
    #[cfg(target_os = "linux")]
    pub(crate) fn reserve_source_spawn_controls(
        &self,
        admission: &crate::linux_attempt_host::InstalledSourceAdmission,
    ) -> Result<(), crate::linux_attempt_host::OriginalAccountCheckError> {
        let held = self
            .inner
            .source_purpose
            .lock()
            .map_err(|_| crate::linux_attempt_host::OriginalAccountCheckError::Unavailable)?;
        if !held
            .as_ref()
            .is_some_and(|purpose| purpose.same_owner(admission.host_purpose()))
        {
            return Err(crate::linux_attempt_host::OriginalAccountCheckError::Unavailable);
        }
        let mut controls = self
            .inner
            .source_spawn_control
            .lock()
            .map_err(|_| crate::linux_attempt_host::OriginalAccountCheckError::Unavailable)?;
        if controls.is_some() || self.inner.child_started.load(Ordering::Acquire) {
            return Err(crate::linux_attempt_host::OriginalAccountCheckError::Unavailable);
        }
        *controls = Some(
            admission
                .host_purpose()
                .reserve_controls(16, 0)
                .map_err(crate::linux_attempt_host::OriginalAccountCheckError::from)?,
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_installed_incarnation(
        &self,
        retirement: crate::linux_attempt_host::InstalledIncarnationRetirement,
    ) -> Result<(), RamControlError> {
        let mut held = self
            .inner
            .installed_incarnation
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if held.is_some() || self.inner.child_started.load(Ordering::Acquire) {
            return Err(RamControlError::AuthorityMismatch);
        }
        *held = Some(retirement);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_target_binding(
        &self,
        binding: crate::linux_attempt_host::OriginalNativeNodeBinding,
    ) -> Result<(), RamControlError> {
        let Ok(mut held) = self.inner.target_binding.lock() else {
            std::mem::forget(binding);
            return Err(RamControlError::AuthorityMismatch);
        };
        if held.is_some() || self.inner.child_started.load(Ordering::Acquire) {
            std::mem::forget(binding);
            return Err(RamControlError::AuthorityMismatch);
        }
        *held = Some(binding);
        held.as_ref()
            .ok_or(RamControlError::AuthorityMismatch)?
            .retain_launch_cleanup(self)
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        Ok(())
    }

    /// Publishes the complete Target holder before body or descriptor birth.
    ///
    /// # Errors
    /// Refuses occupied, poisoned or already exposed Target workspace custody.
    #[cfg(target_os = "linux")]
    pub(crate) fn retain_target_workspace(
        &self,
        purpose: crate::linux_attempt_host::OriginalDeviceDigestWorkspacePurpose,
    ) -> Result<(), RamControlError> {
        let Ok(mut held) = self.inner.target_workspace.lock() else {
            std::mem::forget(purpose);
            return Err(RamControlError::AuthorityMismatch);
        };
        if held.is_some() || self.inner.child_started.load(Ordering::Acquire) {
            std::mem::forget(purpose);
            return Err(RamControlError::AuthorityMismatch);
        }
        // This inline holder is in the already paid record before its separate
        // body or memfd can be born. Failure retains the same full purpose.
        *held = Some(crate::spawn::OriginalDeviceDigestWorkspace::new(purpose));
        Ok(())
    }

    /// Constructs only the workspace already retained by this paid record.
    ///
    /// # Errors
    /// Retains the same holder on missing custody, aliasing or kernel refusal.
    #[cfg(target_os = "linux")]
    pub(crate) fn create_target_workspace(
        &self,
    ) -> Result<(), crate::spawn::DeviceDigestWorkspaceIssueError> {
        self.inner
            .target_workspace
            .lock()
            .map_err(|_| crate::spawn::DeviceDigestWorkspaceIssueError::Unavailable)?
            .as_mut()
            .ok_or(crate::spawn::DeviceDigestWorkspaceIssueError::Unavailable)?
            .create()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_target_binding_mut<T>(
        &self,
        borrow: impl FnOnce(&mut crate::linux_attempt_host::OriginalNativeNodeBinding) -> T,
    ) -> Result<T, RamControlError> {
        let mut held = self
            .inner
            .target_binding
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        let binding = held.as_mut().ok_or(RamControlError::AuthorityMismatch)?;
        Ok(borrow(binding))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn reserve_source_child_owner(
        &self,
        supervisor: crucible_host_resources::host_supervision::HostOperationSupervisor,
    ) -> Result<crate::node::SourceLaunchReservation, crate::OriginalActorAccountError> {
        let lender = {
            let held = self
                .inner
                .installed_incarnation
                .try_lock()
                .map_err(|_| crate::OriginalActorAccountError::Unavailable)?;
            held.as_ref()
                .ok_or(crate::OriginalActorAccountError::Unavailable)?
                .source_cleanup_lender()?
        };
        let controller = lender.controller()?;
        controller.reserve_child_owner(lender, supervisor)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retained_target_cleanup(
        &self,
    ) -> Result<crate::linux_attempt_host::TargetCleanupOriginal, crate::OriginalActorAccountError>
    {
        let lender = {
            let held = self
                .inner
                .target_binding
                .try_lock()
                .map_err(|_| crate::OriginalActorAccountError::Unavailable)?;
            held.as_ref()
                .ok_or(crate::OriginalActorAccountError::Unavailable)?
                .target_cleanup_lender()?
        };
        // Both binding and roster locks end before lazy entry or Original checks.
        lender.retained_original()
    }

    pub(crate) fn child_started(&self) {
        self.inner.child_started.store(true, Ordering::Release);
    }

    pub(crate) fn child_reaped(&self) {
        self.inner.child_reaped.store(true, Ordering::Release);
    }

    // A never-created child has no process borrower; a created child must have
    // its own physical receipt. A source parent's reap is not this receipt.
    pub(crate) fn process_returned_or_unstarted(&self) -> bool {
        (!self.inner.child_started.load(Ordering::Acquire)
            || self.inner.child_reaped.load(Ordering::Acquire))
            && self.inner.source_process_collected()
    }

    pub(crate) fn process_reaped(&self) -> bool {
        self.inner.child_started.load(Ordering::Acquire)
            && self.inner.child_reaped.load(Ordering::Acquire)
            && self.inner.source_process_collected()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bind_external_process(
        &self,
        basis: crate::QemuHotForkChildProcessBasis,
    ) -> Result<(), RamControlError> {
        let mut bound = self
            .inner
            .external_basis
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if bound.is_some_and(|existing| existing != basis) {
            return Err(RamControlError::AuthorityMismatch);
        }
        *bound = Some(basis);
        self.child_started();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn observe_external_process(
        &self,
        process: &dyn crate::QemuNodeExternalProcessControl,
    ) -> Result<bool, RamControlError> {
        let basis = process.hot_fork_process_basis();
        let bound = *self
            .inner
            .external_basis
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if bound != Some(basis) {
            return Err(RamControlError::AuthorityMismatch);
        }
        let reaped = process.reaped();
        if reaped {
            self.child_reaped();
        }
        Ok(reaped)
    }

    pub(crate) fn update_resources(
        &self,
        resources: HostResourceVector,
    ) -> Result<(), RamControlError> {
        let mut authority = self
            .inner
            .authority
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if authority.published {
            return Err(RamControlError::AuthorityMismatch);
        }
        authority.resources = resources;
        Ok(())
    }

    pub(crate) fn source_join(&self) -> Result<LaunchSourceJoin, RamControlError> {
        self.inner
            .pending_joins
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                pending.checked_add(1)
            })
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        Ok(LaunchSourceJoin {
            cleanup: self.clone(),
            joined: false,
        })
    }

    /// Observes publication without treating unavailable custody as absence.
    ///
    /// # Errors
    /// Refuses contended or poisoned authority access while retaining the controller.
    pub(crate) fn publication(&self) -> Result<bool, RamControlError> {
        self.inner
            .authority
            .try_lock()
            .map(|authority| authority.published)
            .map_err(|_| RamControlError::AuthorityMismatch)
    }

    pub(crate) fn is_published(&self) -> bool {
        self.inner
            .authority
            .lock()
            .is_ok_and(|authority| authority.published)
    }

    // A monitor import and its native aliases are independent physical
    // borrowers. Only exact release plus closefd acknowledgements discharge
    // this ticket; a failed exchange conservatively keeps the actor charged.
    pub(crate) fn descriptor_import(&self) -> Result<LaunchDescriptorImport, RamControlError> {
        self.inner
            .pending_imports
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                pending.checked_add(1)
            })
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        Ok(LaunchDescriptorImport {
            cleanup: self.clone(),
            closed: false,
        })
    }

    pub(crate) fn cleanup_proven(&self) -> bool {
        self.process_returned_or_unstarted()
            && self.inner.pending_joins.load(Ordering::Acquire) == 0
            && self.inner.pending_imports.load(Ordering::Acquire) == 0
    }

    pub(crate) fn quarantine(&self) {
        if let Ok(authority) = self.inner.authority.lock()
            && let Some(registrar) = &authority.registrar
            && let Some(target) = self.inner.target
        {
            let _ = registrar.quarantine_unpublished(target, authority.resources);
        }
    }

    // The independently issued receipt survives scoped registrar destruction
    // without retaining a controller/registry cycle.
    pub(crate) fn published(&self) -> Result<(), RamControlError> {
        let mut authority = self
            .inner
            .authority
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if authority.published {
            return Ok(());
        }
        let registrar = authority
            .registrar
            .as_ref()
            .ok_or(RamControlError::AuthorityMismatch)?;
        let retirement = registrar.retirement_authority(
            self.inner
                .target
                .ok_or(RamControlError::AuthorityMismatch)?,
        )?;
        authority.published_retirement = Some(retirement);
        let registrar = authority.registrar.take();
        authority.published = true;
        drop(authority);
        drop(registrar);
        Ok(())
    }
}

/// Publishes at most one abandoned handover into its already allocated launch.
///
/// Only `claim_preexec` creates this uncloneable token. Its consuming transfer
/// is therefore the sole initializer and never waits for another publisher.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct PreexecRetention {
    cleanup: LaunchCleanup,
}

#[cfg(target_os = "linux")]
impl PreexecRetention {
    /// Keeps the actual allocation and unresolved history through process exit.
    pub(crate) fn retain(self, history: crate::spawn::preexec_setup::PreexecAbandonment) {
        self.cleanup.inner.abandoned_preexec.get_or_init(|| history);
        // Keep the real shared allocation, containing authority and exact
        // history through process exit; an inline forgotten record is no owner.
        std::mem::forget(self.cleanup);
    }
}

/// Records only completion of the unique source-worker join authority.
#[derive(Debug)]
pub(crate) struct LaunchSourceJoin {
    cleanup: LaunchCleanup,
    joined: bool,
}

impl LaunchSourceJoin {
    pub(crate) fn joined(&mut self) {
        if !self.joined {
            self.joined = true;
            self.cleanup
                .inner
                .pending_joins
                .fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Debug)]
pub(crate) struct LaunchDescriptorImport {
    cleanup: LaunchCleanup,
    closed: bool,
}

impl LaunchDescriptorImport {
    pub(crate) fn closed(&mut self) {
        if !self.closed {
            self.closed = true;
            self.cleanup
                .inner
                .pending_imports
                .fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Keeps the complete existing Target holder ahead of implicit field Drop.
///
/// A poisoned field still contains its actual owner. Taking that same body
/// prevents the generic unhanded workspace destructor from substituting local
/// uniqueness for process/import/join/registrar proof; it allocates no keeper.
#[cfg(target_os = "linux")]
fn retain_unproven_target_workspace(
    workspace: &mut Mutex<Option<crate::spawn::OriginalDeviceDigestWorkspace>>,
) {
    let held = match workspace.get_mut() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(workspace) = held.take() {
        std::mem::forget(workspace);
    }
}

impl Drop for CleanupFinalizer {
    fn drop(&mut self) {
        // Normal refusal has already closed its local owner. Destroy the real
        // cause and its control before registrar retirement can refund the
        // containing allocation. Uncertain history retains this same allocation
        // instead, so final destruction cannot race a live receiver.
        #[cfg(target_os = "linux")]
        drop(self.preexec_failure.take());

        let source_collected = self.source_process_collected();
        let Ok(authority) = self.authority.get_mut() else {
            #[cfg(target_os = "linux")]
            retain_unproven_target_workspace(&mut self.target_workspace);
            #[cfg(target_os = "linux")]
            retain_unproven_source(&mut self.source_purpose, &mut self.source_control);
            #[cfg(target_os = "linux")]
            retain_unproven_spawn_controls(&mut self.source_spawn_control);
            return;
        };
        let reaped = !self.child_started.load(Ordering::Acquire)
            || self.child_reaped.load(Ordering::Acquire);
        let proven = reaped
            && source_collected
            && self.pending_joins.load(Ordering::Acquire) == 0
            && self.pending_imports.load(Ordering::Acquire) == 0;
        let mut released = if authority.published {
            match authority.published_retirement.take() {
                Some(retirement) if proven => {
                    if retirement.retire_after_cleanup().is_ok() {
                        true
                    } else {
                        std::mem::forget(retirement);
                        false
                    }
                }
                Some(retirement) => {
                    std::mem::forget(retirement);
                    false
                }
                None => false,
            }
        } else if let (Some(registrar), Some(target)) = (authority.registrar.take(), self.target) {
            let released = proven
                && registrar
                    .retire_unpublished_after_cleanup(target, authority.resources)
                    .is_ok();
            if !released {
                let _ = registrar.quarantine_unpublished(target, authority.resources);
            }
            released
        } else {
            // Only an actual nominal Source holder supplies native-only cleanup.
            // Missing RAM registration is never interpreted as blanket success.
            #[cfg(target_os = "linux")]
            {
                proven
                    && self.target.is_none()
                    && self
                        .source_purpose
                        .get_mut()
                        .is_ok_and(|held| held.is_some())
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        };

        #[cfg(target_os = "linux")]
        if released {
            released = self.target_workspace.get_mut().is_ok_and(|held| {
                held.as_mut()
                    .is_none_or(|workspace| workspace.retire_after_reap().is_ok())
            });
        }

        #[cfg(target_os = "linux")]
        if !released {
            retain_unproven_target_workspace(&mut self.target_workspace);
            retain_unproven_source(&mut self.source_purpose, &mut self.source_control);
            #[cfg(target_os = "linux")]
            retain_unproven_spawn_controls(&mut self.source_spawn_control);
        }

        // This is the last cleanup Arc: physical process, source/import aliases
        // and the actual registry retirement have all closed. A node facade's
        // Drop alone never reaches this transition or releases its live share.
        #[cfg(target_os = "linux")]
        if released
            && let Ok(held) = self.installed_incarnation.get_mut()
            && let Some(retirement) = held.take()
        {
            retirement.retire_after_physical_cleanup();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests;

/// Preserves the same Main charge when real final-close evidence is absent.
#[cfg(target_os = "linux")]
fn retain_unproven_source(
    purpose: &mut Mutex<
        Option<
            crucible_host_resources::host_services::process_birth::AuthenticatedSourceHostPurpose,
        >,
    >,
    control: &mut Option<
        crucible_host_resources::host_services::process_birth::SourceHostControlLease,
    >,
) {
    let held = purpose
        .get_mut()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(purpose) = held.take() {
        std::mem::forget(purpose);
    }
    if let Some(control) = control.take() {
        std::mem::forget(control);
    }
}

#[cfg(target_os = "linux")]
fn retain_unproven_spawn_controls(
    controls: &mut Mutex<
        Option<crucible_host_resources::host_services::process_birth::SourceHostControlLease>,
    >,
) {
    let held = controls
        .get_mut()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(control) = held.take() {
        std::mem::forget(control);
    }
}
