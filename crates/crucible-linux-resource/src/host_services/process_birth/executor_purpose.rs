//! Publishes one checked normal executor purpose in the existing main account.
//!
//! The permanent slot keeps accepted funding through failures, aliases and
//! uncertain physical retirement. No request vector is itself credit, and this
//! resident purpose does not replace the actual project-quota backing owner.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{
    AuthenticatedProcessResources, AuthenticatedServiceFamily, HostServiceLease,
    HostServiceLeasePair, ServiceBirthError,
};
use crate::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
    HostSupervisionBootstrap,
};
use crate::ram_policy::HostResourceVector;

mod host_descriptors;
mod target_dispatcher;
pub use target_dispatcher::AuthenticatedTargetDispatcherPurpose;

use host_descriptors::HostDescriptorPartition;

/// Retains one actual same-main native/executor purpose and immutable limits.
///
/// Only checked publication beneath authenticated process resources constructs
/// this owner. Its resident and metadata debits stay in the permanent main slot;
/// kernel containment alone cannot construct it or certify native readiness.
/// Physical backing must be bound by the existing Service before native birth.
pub struct AuthenticatedNativeSlotPurpose {
    original: Arc<HostOperationGuard>,
    supervisor: HostOperationSupervisor,
    family: Arc<AuthenticatedServiceFamily>,
    bounds: HostResourceVector,
    _resident: HostServiceLease,
    _metadata: HostServiceLeasePair,
    owner: &'static AuthenticatedProcessResources,
    native_roster_claimed: std::sync::atomic::AtomicBool,
    assigned: std::sync::Mutex<HostResourceVector>,
    host_descriptors: std::sync::Mutex<Option<HostDescriptorPartition>>,
}

/// Retains the sole checked native subdivision beneath its original executor.
///
/// This owner has no scalar constructor and cannot be cloned or reissued.
/// Its assignment remains in the permanent main ledger even after this facade
/// drops; process and native retirement cannot replenish the containing bank.
pub struct AuthenticatedNativeSubdivision {
    owner: Arc<AuthenticatedNativeSlotPurpose>,
    bounds: HostResourceVector,
    local_file_descriptors: u64,
}

impl std::fmt::Debug for AuthenticatedNativeSubdivision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedNativeSubdivision { .. }")
    }
}

impl std::fmt::Debug for AuthenticatedNativeSlotPurpose {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedNativeSlotPurpose { .. }")
    }
}

impl AuthenticatedProcessResources {
    /// Debits and publishes the sole normal executor in this original main.
    ///
    /// The request is a limit, not funding: both existing counters must accept
    /// the actual remaining amount, including control storage. Attempt occupancy
    /// is permanent even on refusal; successful publication precedes its postcut.
    ///
    /// # Errors
    /// Refuses repeated admission, absent delegation, expired original, malformed
    /// request, exhausted current counters, changed family or supervision refusal.
    pub fn admit_executor_purpose(
        &'static self,
        bounds: HostResourceVector,
        budgets: HostOperationBudgets,
    ) -> Result<Arc<AuthenticatedNativeSlotPurpose>, ServiceBirthError> {
        if self
            .executor_attempted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ServiceBirthError::policy(
                "normal executor original attempt is occupied",
            ));
        }
        validate_request(bounds)?;
        if !self.is_live() || !self.birth.delegated_executor {
            return Err(ServiceBirthError::policy(
                "normal executor has no authenticated delegated original",
            ));
        }
        let controls = control_extent()?;
        let metadata_bytes = bounds.metadata_bytes.checked_add(controls).ok_or_else(|| {
            ServiceBirthError::policy("normal executor metadata extent overflows")
        })?;
        let metadata = self
            .reserve_metadata(metadata_bytes)
            .map_err(ServiceBirthError::from)?;
        let resident = self
            .reserve_resident(
                bounds.task_slots,
                bounds.file_descriptors,
                bounds.resident_peak_bytes - bounds.metadata_bytes,
            )
            .map_err(ServiceBirthError::from)?;
        let family = self.retain_executor_family()?;
        let supervisor = self
            .derive_executor_supervisor(budgets)
            .map_err(ServiceBirthError::from)?;
        let original = Arc::new(
            supervisor
                .begin_work(HostOperationClass::Preparation, 0)
                .map_err(ServiceBirthError::from)?,
        );
        let purpose = Arc::new(AuthenticatedNativeSlotPurpose {
            original,
            supervisor,
            family,
            bounds,
            _resident: resident,
            _metadata: metadata,
            owner: self,
            native_roster_claimed: std::sync::atomic::AtomicBool::new(false),
            assigned: std::sync::Mutex::new(HostResourceVector::default()),
            host_descriptors: std::sync::Mutex::new(None),
        });
        if let Err(purpose) = self.executor_purpose.set(purpose) {
            // This can only follow an inconsistent occupied slot. Its complete
            // debit and original remain retained rather than inventing a refund.
            std::mem::forget(purpose);
            return Err(ServiceBirthError::policy(
                "normal executor publication is uncertain",
            ));
        }
        let published = self
            .executor_purpose
            .get()
            .ok_or_else(|| ServiceBirthError::policy("normal executor purpose is unpublished"))?;
        published.check()?;
        Ok(Arc::clone(published))
    }
}

impl AuthenticatedNativeSlotPurpose {
    /// Checks the original main and its retained admission phase and family.
    ///
    /// # Errors
    /// Refuses the first original operation, expired main or changed family.
    /// Completed preparation remains valid custody without renewing its clock.
    pub fn check(&self) -> Result<(), ServiceBirthError> {
        self.original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)?;
        if !self.owner.is_live() {
            return Err(ServiceBirthError::policy("normal executor main expired"));
        }
        self.family.check()?;
        if let Some(partition) = self
            .host_descriptors
            .lock()
            .map_err(|_| ServiceBirthError::policy("normal descriptor custody is uncertain"))?
            .as_ref()
        {
            partition.check()?;
        }
        self.original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)
    }

    /// Completes the actual initial preparation without ending main custody.
    ///
    /// Only the caller that finishes the entire prepared executor uses this
    /// transition. Later native preparation must enter a new running class
    /// beneath the same unchanged main end, not reuse this completed guard.
    ///
    /// # Errors
    /// Refuses the initiating preparation failure, main cancellation/expiry,
    /// changed family or uncertain completion. The permanent debit stays held.
    pub fn complete_preparation(&self) -> Result<(), ServiceBirthError> {
        self.check()?;
        self.original.complete().map_err(ServiceBirthError::from)?;
        self.check()
    }

    /// Occupies this purpose's sole native roster before any native effect.
    ///
    /// The common issuer must validate and reserve every subdivision beneath
    /// these immutable bounds. Occupancy never refunds or retries on refusal.
    ///
    /// # Errors
    /// Refuses repeated claims, a failed original phase or changed main/family.
    pub fn claim_native_roster(
        self: &Arc<Self>,
        request: HostResourceVector,
    ) -> Result<AuthenticatedNativeSubdivision, ServiceBirthError> {
        if self
            .native_roster_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ServiceBirthError::policy(
                "normal native roster is occupied",
            ));
        }
        validate_request(request)?;
        self.assign(request)?;
        self.family.install_native_limits(request, &self.original)?;
        let local_file_descriptors = request.file_descriptors / 2;
        let mut retained = self
            .host_descriptors
            .lock()
            .map_err(|_| ServiceBirthError::policy("normal descriptor custody is uncertain"))?;
        if retained.is_some() {
            return Err(ServiceBirthError::policy(
                "normal descriptor partition is occupied",
            ));
        }
        // Publish the funded physical owner before any irreversible limit or
        // census effect. Failed admission leaves the same occupied owner held.
        *retained = Some(HostDescriptorPartition::new(
            self.owner.birth.descriptors,
            local_file_descriptors,
            self.owner
                .resident
                .retain_descriptor_remainder()
                .map_err(ServiceBirthError::from)?,
        )?);
        retained
            .as_mut()
            .ok_or_else(|| ServiceBirthError::policy("normal descriptor partition is absent"))?
            .install(&self.original)?;
        drop(retained);
        self.check()?;
        Ok(AuthenticatedNativeSubdivision {
            owner: Arc::clone(self),
            bounds: request,
            local_file_descriptors,
        })
    }

    /// Assigns an actual executor Service before its nested allocator is born.
    ///
    /// Every assignment is cumulative and disjoint from the native subdivision.
    /// An uncertain postcut keeps the assigned vector rather than refunding it.
    ///
    /// # Errors
    /// Refuses the original main, overflow, a poisoned ledger or exhaustion of
    /// any unchanged containing component.
    pub fn assign_executor_service(
        &self,
        request: HostResourceVector,
    ) -> Result<(), ServiceBirthError> {
        self.assign(request)
    }

    fn assign(&self, request: HostResourceVector) -> Result<(), ServiceBirthError> {
        self.check()?;
        let mut used = self
            .assigned
            .lock()
            .map_err(|_| ServiceBirthError::policy("normal executor assignments are uncertain"))?;
        let next = checked_assignment(*used, request, self.bounds)?;
        *used = next;
        drop(used);
        self.check()
    }

    /// Validates an entered native preparation under this exact outer owner.
    ///
    /// A completed initial phase cannot substitute for a fresh running guard.
    /// Identity is structural; neither class nor bounds alone grants authority.
    ///
    /// # Errors
    /// Retains original/caller cancellation or expiry before rejecting a wrong
    /// class or unrelated supervisor. No operation or status roster is allocated.
    pub fn verify_native_preparation(
        &self,
        preparation: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.check()?;
        verify_preparation(&self.supervisor, preparation)?;
        self.check()
    }

    /// Borrows the opaque actual family for pre-watcher namespace matching.
    #[must_use]
    pub fn family(&self) -> &Arc<AuthenticatedServiceFamily> {
        &self.family
    }

    /// Returns immutable paid request bounds, which issue no additional credit.
    #[must_use]
    pub fn bounds(&self) -> HostResourceVector {
        self.bounds
    }

    /// Borrows the initial preparation for actual admission and completion.
    ///
    /// The consumer completes this phase only after genuine preparation. Later
    /// work enters its own class beneath the same original outer incarnation.
    #[must_use]
    pub fn original(&self) -> &Arc<HostOperationGuard> {
        &self.original
    }

    /// Derives class policy beneath the same original outer incarnation.
    ///
    /// # Errors
    /// Refuses original expiry, cancellation, changed family or invalid budgets.
    pub fn derive_supervisor(
        &self,
        budgets: HostOperationBudgets,
    ) -> Result<HostOperationSupervisor, ServiceBirthError> {
        self.check()?;
        self.supervisor
            .new_budget_owner(budgets)
            .map_err(ServiceBirthError::from)
    }
}

impl AuthenticatedNativeSubdivision {
    /// Returns the retained local table ceiling beneath the same aggregate grant.
    ///
    /// This number describes an already-issued subdivision; it is not a
    /// constructor or authority for another process table.
    #[must_use]
    pub fn local_file_descriptors(&self) -> u64 {
        self.local_file_descriptors
    }

    /// Checks the same permanently assigned original main and family.
    ///
    /// # Errors
    /// Preserves expired, cancelled or uncertain containing custody.
    pub fn check(&self) -> Result<(), ServiceBirthError> {
        self.owner.check()
    }

    /// Returns this subdivision's unchanged request bounds, not another grant.
    #[must_use]
    pub fn bounds(&self) -> HostResourceVector {
        self.bounds
    }

    /// Borrows the actual retained family for pre-watcher containment checks.
    #[must_use]
    pub fn family(&self) -> &Arc<AuthenticatedServiceFamily> {
        self.owner.family()
    }

    /// Verifies a genuinely entered preparation under this same original main.
    ///
    /// # Errors
    /// Refuses a completed, expired or unrelated preparation.
    pub fn verify_native_preparation(
        &self,
        preparation: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.owner.verify_native_preparation(preparation)
    }

    /// Checks an exact retained preparation after active or completed admission.
    ///
    /// This verifies same Main/class custody without treating a completed guard
    /// as new work authority or renewing any operation deadline.
    ///
    /// # Errors
    /// Refuses another Main/class, failed original or uncertain retained phase.
    pub fn verify_retained_native_preparation(
        &self,
        preparation: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.check()?;
        if !preparation.shares_outer_cap(&self.owner.supervisor)
            || preparation.status().map_err(ServiceBirthError::from)?.class
                != HostOperationClass::Preparation
        {
            return Err(ServiceBirthError::policy(
                "retained native preparation belongs to another Main or class",
            ));
        }
        preparation
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)?;
        self.check()
    }

    /// Enters native preparation without replacing the containing original end.
    ///
    /// Its actual operation and guard storage must be assigned from this
    /// subdivision before the caller requests this transition.
    ///
    /// # Errors
    /// Refuses the original main, changed family or preparation admission.
    pub fn begin_native_preparation(&self) -> Result<HostOperationGuard, ServiceBirthError> {
        self.check()?;
        self.owner
            .supervisor
            .begin_work(HostOperationClass::Preparation, 0)
            .map_err(ServiceBirthError::from)
    }
}

fn checked_assignment(
    used: HostResourceVector,
    request: HostResourceVector,
    ceiling: HostResourceVector,
) -> Result<HostResourceVector, ServiceBirthError> {
    let add = |left: u64, right: u64| {
        left.checked_add(right)
            .ok_or_else(|| ServiceBirthError::policy("normal executor assignment overflows"))
    };
    let next = HostResourceVector {
        resident_peak_bytes: add(used.resident_peak_bytes, request.resident_peak_bytes)?,
        backing_peak_bytes: add(used.backing_peak_bytes, request.backing_peak_bytes)?,
        metadata_bytes: add(used.metadata_bytes, request.metadata_bytes)?,
        staging_bytes: add(used.staging_bytes, request.staging_bytes)?,
        cpu_slots: add(used.cpu_slots, request.cpu_slots)?,
        task_slots: add(used.task_slots, request.task_slots)?,
        file_descriptors: add(used.file_descriptors, request.file_descriptors)?,
        paging_io_slots: add(used.paging_io_slots, request.paging_io_slots)?,
    };
    if !next.fits(ceiling) {
        return Err(ServiceBirthError::policy(
            "normal registry and native assignments exceed their original executor",
        ));
    }
    Ok(next)
}

fn verify_preparation(
    supervisor: &HostOperationSupervisor,
    preparation: &HostOperationGuard,
) -> Result<(), ServiceBirthError> {
    preparation
        .verify_operation_class(HostOperationClass::Preparation)
        .map_err(ServiceBirthError::from)?;
    if !preparation.shares_outer_cap(supervisor) {
        return Err(ServiceBirthError::policy(
            "normal native preparation has a different original main",
        ));
    }
    Ok(())
}

fn validate_request(bounds: HostResourceVector) -> Result<(), ServiceBirthError> {
    if bounds.resident_peak_bytes == 0
        || bounds.metadata_bytes == 0
        || bounds.metadata_bytes > bounds.resident_peak_bytes
        || bounds.staging_bytes > bounds.resident_peak_bytes
        || bounds.backing_peak_bytes == 0
        || bounds.cpu_slots == 0
        || bounds.task_slots == 0
        || bounds.file_descriptors == 0
    {
        return Err(ServiceBirthError::policy(
            "normal executor request is not a complete finite partition",
        ));
    }
    Ok(())
}

fn control_extent() -> Result<u64, ServiceBirthError> {
    let mut bytes = HostSupervisionBootstrap::structure_bytes().map_err(ServiceBirthError::from)?;
    for layout in [
        std::alloc::Layout::new::<AuthenticatedNativeSlotPurpose>(),
        std::alloc::Layout::new::<HostOperationGuard>(),
    ] {
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(layout)
        .map_err(super::message)?;
        bytes = bytes
            .checked_add(u64::try_from(layout.pad_to_align().size()).map_err(super::message)?)
            .ok_or_else(|| ServiceBirthError::policy("normal executor controls overflow"))?;
    }
    let leases = HostServiceLease::metadata_bytes()
        .checked_mul(4)
        .ok_or_else(|| ServiceBirthError::policy("normal executor lease controls overflow"))?;
    bytes
        .checked_add(host_descriptors::CENSUS_BYTES as u64)
        .and_then(|bytes| bytes.checked_add(leases))
        .ok_or_else(|| ServiceBirthError::policy("normal executor controls overflow"))
}

#[cfg(test)]
mod tests;
