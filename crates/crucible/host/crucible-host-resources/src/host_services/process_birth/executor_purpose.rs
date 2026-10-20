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

mod source_host;
pub use source_host::{
    AuthenticatedSourceChild, AuthenticatedSourceHostPurpose, SourceHostControlLease,
    WeakSourceHostPurpose,
};

mod native_pool;
pub use native_pool::{
    AuthenticatedNativeNodeClaim, AuthenticatedNativeNodeHostWindow,
    AuthenticatedNativePoolPurpose, AuthenticatedNativeWorldClaim,
    AuthenticatedNativeWorldCleanupLoan, AuthenticatedNativeWorldControlLease,
    NativeNodeReservation, NativePoolRefusal, NativePoolReturnError, NativeWorldIdentity,
    NativeWorldReturn,
};

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
    cleanup: std::sync::OnceLock<
        Result<Arc<HostOperationGuard>, crate::host_supervision::HostSupervisionError>,
    >,
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
    node: Option<AuthenticatedNativeNodeClaim>,
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
                .begin(HostOperationClass::Preparation)
                .map_err(ServiceBirthError::from)?,
        );
        let purpose = Arc::new(AuthenticatedNativeSlotPurpose {
            original,
            cleanup: std::sync::OnceLock::new(),
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

    // This once-only worker admission occurs before any Source or worker body.
    // Its original is the actual initial Main Preparation, not a new operation.
    fn check_worker_admission(&self) -> Result<(), ServiceBirthError> {
        self.original.try_verify_unlent_preparation()?;
        if !self.owner.is_live() {
            return Err(ServiceBirthError::policy("normal executor main expired"));
        }
        self.family.check()?;
        if let Some(partition) = self
            .host_descriptors
            .try_lock()
            .map_err(|_| {
                ServiceBirthError::policy("normal descriptor custody is busy or uncertain")
            })?
            .as_ref()
        {
            partition.check()?;
        }
        self.original
            .try_verify_unlent_preparation()
            .map_err(ServiceBirthError::from)
    }

    /// Enters and retains this same Main's one outer Cleanup on first demand.
    ///
    /// Construction failure and service retirement call this only when actual
    /// cleanup begins. It preserves the original Preparation as its origin,
    /// including terminal-parent eligibility; it does not enter a fresh
    /// Preparation, supervisor or interval on retry. Its controls were priced
    /// at this Main purpose's own before-birth admission.
    ///
    /// # Errors
    /// Retains the first genuine Cleanup admission refusal, or this same
    /// Cleanup's cancellation, expiry or uncertain synchronization.
    pub fn retained_cleanup(&self) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        let cleanup = self
            .cleanup
            .get_or_init(|| self.original.begin_original_cleanup_control().map(Arc::new));
        let cleanup = cleanup
            .as_ref()
            .map_err(|source| ServiceBirthError::from(*source))?;
        cleanup.wait_slice().map_err(ServiceBirthError::from)?;
        Ok(Arc::clone(cleanup))
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
    fn claim_native_pool_root(
        self: &Arc<Self>,
        request: HostResourceVector,
        shared_descriptors: u64,
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
            request.file_descriptors,
            shared_descriptors,
            self._resident.clone(),
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
            node: None,
            owner: Arc::clone(self),
            bounds: request,
            local_file_descriptors: 0,
        })
    }

    /// Observes the remaining authored Main vector after actual Service assignments.
    ///
    /// This copy is not credit. Only the once-only checked pool constructor can
    /// occupy it; a concurrent assignment is rechecked there before effects.
    ///
    /// # Errors
    /// Refuses changed Main, uncertain assignments or any inconsistent axis.
    pub fn remaining_native_capacity(&self) -> Result<HostResourceVector, ServiceBirthError> {
        self.check()?;
        let held = self
            .assigned
            .lock()
            .map_err(|_| ServiceBirthError::policy("normal Main assignments are uncertain"))?;
        let sub = |left: u64, right: u64| {
            left.checked_sub(right).ok_or_else(|| {
                ServiceBirthError::policy("normal Main assignments exceed their original")
            })
        };
        let remaining = HostResourceVector {
            resident_peak_bytes: sub(self.bounds.resident_peak_bytes, held.resident_peak_bytes)?,
            backing_peak_bytes: sub(self.bounds.backing_peak_bytes, held.backing_peak_bytes)?,
            metadata_bytes: sub(self.bounds.metadata_bytes, held.metadata_bytes)?,
            staging_bytes: sub(self.bounds.staging_bytes, held.staging_bytes)?,
            cpu_slots: sub(self.bounds.cpu_slots, held.cpu_slots)?,
            task_slots: sub(self.bounds.task_slots, held.task_slots)?,
            file_descriptors: sub(self.bounds.file_descriptors, held.file_descriptors)?,
            paging_io_slots: sub(self.bounds.paging_io_slots, held.paging_io_slots)?,
        };
        drop(held);
        self.check()?;
        Ok(remaining)
    }

    /// Claims the same once-only native subdivision as a checked node pool.
    ///
    /// The request is the aggregate simultaneous native obligation, not one
    /// assignment multiplied after publication. Child issuance partitions this
    /// real retained purpose; it never repeats the Main debit or root claim.
    /// `consumer_control_bytes` is requested geometry for the actual containing
    /// factory and all simultaneously retained World/node control storage. It
    /// must be derived from those concrete types before their allocation, and
    /// is occupied together with this pool's own storage before publication.
    ///
    /// # Errors
    /// Refuses a foreign or inactive Preparation, an occupied root claim,
    /// exhausted Main capacity, or an unrepresentable pool control extent.
    /// Refused root/kernel/descriptor effects remain in the permanent Main.
    pub fn claim_native_pool(
        self: &Arc<Self>,
        request: HostResourceVector,
        consumer_control_bytes: u64,
        consumer_file_descriptors: u64,
        original: &Arc<HostOperationGuard>,
    ) -> Result<AuthenticatedNativePoolPurpose, NativePoolRefusal> {
        let result = (|| {
            self.verify_native_preparation(original)?;
            let layout = native_pool::checked_layout(
                request,
                consumer_control_bytes,
                consumer_file_descriptors,
            )?;
            let root = self.claim_native_pool_root(request, consumer_file_descriptors)?;
            AuthenticatedNativePoolPurpose::publish(root, layout, original)
        })();
        let after = self.verify_native_preparation(original).err();
        native_pool::finish_root(result, after)
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
    // Permanent workers belong to the containing Main pool, not a node loan.
    // Refuse a node here instead of entering its independently locked ledger.
    fn check_worker_admission(&self) -> Result<(), ServiceBirthError> {
        if self.node.is_some() {
            return Err(ServiceBirthError::policy(
                "permanent worker admission requires the containing Main pool root",
            ));
        }
        self.owner.check_worker_admission()
    }

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
        self.owner.check()?;
        if let Some(node) = &self.node {
            node.bounds()?;
        }
        Ok(())
    }

    /// Returns the actual node assignment epoch, not a new reservation.
    #[must_use]
    pub fn assignment_epoch(&self) -> Option<u64> {
        self.node.as_ref().map(|node| node.assignment_epoch())
    }

    /// Returns the fixed containing pool's node bound, not new resource credit.
    ///
    /// # Errors
    /// Refuses a retired or absent node assignment.
    pub fn pool_node_capacity(&self) -> Result<usize, ServiceBirthError> {
        self.check()?;
        self.node
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node pool is absent"))?
            .pool_capacity()
    }

    /// Closes this consumed node only after its real native controls are freed.
    ///
    /// This move remains refused while any issued Source/Target landing is
    /// live. The genuine native roster invokes it after exclusive control free;
    /// copied limits or an operation completion cannot return the assignment.
    ///
    /// # Errors
    /// Retains the same assignment on live landing, changed Main or uncertainty.
    pub fn retire_after_control_free(
        &mut self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), NativePoolReturnError> {
        let node = self
            .node
            .as_mut()
            .ok_or_else(|| ServiceBirthError::policy("native return node is absent"))?;
        node.retire_after_control_free(cleanup)
    }

    /// Enters once and borrows this exact node's existing World Cleanup.
    ///
    /// # Errors
    /// Refuses stale node/World custody, saved admission failure or terminal Cleanup.
    pub fn retained_world_cleanup(&self) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        self.node
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native return node is absent"))?
            .retained_world_cleanup()
    }

    /// Verifies an already-latched exact World Cleanup without entering one.
    ///
    /// # Errors
    /// Refuses stale/foreign assignment, a different guard, changed pins or bound.
    pub fn verify_world_cleanup(
        &self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.node
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native return node is absent"))?
            .verify_world_cleanup(cleanup)
    }

    /// Observes actual node assignment return, without returning another credit.
    #[must_use]
    pub fn is_physically_returned(&self) -> bool {
        self.node
            .as_ref()
            .is_some_and(|node| node.is_physically_returned())
    }

    /// Retains this node's Target landing before its actual saved Preparation effects.
    ///
    /// # Errors
    /// Refuses absent node custody, foreign/inactive Preparation or postcut.
    pub fn reserve_node_target_window(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), NativePoolRefusal> {
        match self.node.as_ref() {
            Some(node) => node.reserve_target_window(original),
            None => native_pool::missing_node_window(
                self.owner.verify_native_preparation(original).err(),
            ),
        }
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
            .begin(HostOperationClass::Preparation)
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
