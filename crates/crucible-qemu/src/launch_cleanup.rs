//! Private final-close custody for an admitted QEMU launch.
//!
//! Every launch borrower keeps a clone after its descriptors and service leases
//! in field order. The last clone therefore closes only after those resources.
//! Actual wait and join authorities supply terminal proofs; socket closure,
//! cancellation, worker exit, and elapsed time never substitute for them.
//! Unpublished owners retain strong admission authority. Publication switches
//! to independent retirement authority; closing the registry's controller prepares
//! retirement, while final resource destruction still owns capacity discharge.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible_linux_resource::ram_policy::{HostRamTarget, HostResourceVector};

use crate::ram_control::{
    RamControlRegistrar, RamControlRegistration, RamControlRetirementAuthority,
};
use crucible_protocol::ram_control::RamControlError;

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
        self.cleanup.inner.target == registration.target
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
        Arc::ptr_eq(&self.cleanup.inner, &other.cleanup.inner)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LaunchCleanup {
    inner: Arc<CleanupRecord>,
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
    _service: crucible_linux_resource::host_services::HostServiceLease,
    _cleanup: LaunchCleanup,
}

impl QemuFaultManifestMetadataLease {
    pub(crate) fn new(
        service: crucible_linux_resource::host_services::HostServiceLease,
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

struct CleanupRecord {
    target: HostRamTarget,
    authority: Mutex<CleanupAuthority>,
    child_started: AtomicBool,
    child_reaped: AtomicBool,
    pending_joins: AtomicUsize,
    pending_imports: AtomicUsize,
    #[cfg(target_os = "linux")]
    external_basis: Mutex<Option<crate::QemuHotForkChildProcessBasis>>,
}

impl std::fmt::Debug for CleanupRecord {
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
    pub(crate) fn new(registration: &RamControlRegistration) -> Self {
        Self {
            inner: Arc::new(CleanupRecord {
                target: registration.target,
                authority: Mutex::new(CleanupAuthority {
                    registrar: Some(Arc::clone(&registration.registrar)),
                    published_retirement: None,
                    published: false,
                    resources: registration.resources,
                }),
                child_started: AtomicBool::new(false),
                child_reaped: AtomicBool::new(false),
                pending_joins: AtomicUsize::new(0),
                pending_imports: AtomicUsize::new(0),
                #[cfg(target_os = "linux")]
                external_basis: Mutex::new(None),
            }),
        }
    }

    pub(crate) fn child_started(&self) {
        self.inner.child_started.store(true, Ordering::Release);
    }

    pub(crate) fn child_reaped(&self) {
        self.inner.child_reaped.store(true, Ordering::Release);
    }

    pub(crate) fn process_reaped(&self) -> bool {
        self.inner.child_started.load(Ordering::Acquire)
            && self.inner.child_reaped.load(Ordering::Acquire)
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
        (!self.inner.child_started.load(Ordering::Acquire)
            || self.inner.child_reaped.load(Ordering::Acquire))
            && self.inner.pending_joins.load(Ordering::Acquire) == 0
            && self.inner.pending_imports.load(Ordering::Acquire) == 0
    }

    pub(crate) fn quarantine(&self) {
        if let Ok(authority) = self.inner.authority.lock()
            && let Some(registrar) = &authority.registrar
        {
            let _ = registrar.quarantine_unpublished(self.inner.target, authority.resources);
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
        let retirement = registrar.retirement_authority(self.inner.target)?;
        authority.published_retirement = Some(retirement);
        let registrar = authority.registrar.take();
        authority.published = true;
        drop(authority);
        drop(registrar);
        Ok(())
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

impl Drop for CleanupRecord {
    fn drop(&mut self) {
        let Ok(authority) = self.authority.get_mut() else {
            return;
        };
        let reaped = !self.child_started.load(Ordering::Acquire)
            || self.child_reaped.load(Ordering::Acquire);
        let proven = reaped
            && self.pending_joins.load(Ordering::Acquire) == 0
            && self.pending_imports.load(Ordering::Acquire) == 0;
        if authority.published {
            if let Some(retirement) = authority.published_retirement.take()
                && (!proven || retirement.retire_after_cleanup().is_err())
            {
                // Uncertain physical cleanup retains the original charge and
                // authority; destroying the wrapper is never disposition.
                std::mem::forget(retirement);
            }
            return;
        }
        let Some(registrar) = authority.registrar.take() else {
            return;
        };
        let released = proven
            && registrar
                .retire_unpublished_after_cleanup(self.target, authority.resources)
                .is_ok();
        if !released {
            // Refusal conservatively leaves the actor's exact reservation held.
            // This callback receives no fabricated diagnostics or native receipt.
            if !authority.published {
                let _ = registrar.quarantine_unpublished(self.target, authority.resources);
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
