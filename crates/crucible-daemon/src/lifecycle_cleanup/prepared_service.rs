//! Keeps the original prepared Box and Service phase in their admitted Main role.
//!
//! The type-erased Box is the caller's existing allocation. Only the originating
//! typed handle projects it, while a different mutex owns the Service phase.
//! Borrow order is prepared owner, then Service, then control cell. No control
//! cell callback enters either owner mutex, and no borrowed reference escapes.

use std::any::Any;
use std::marker::PhantomData;

use super::*;
use crate::packaged_qemu_executor::{RetainedServiceStart, RetainedTemplateService};

pub(crate) type PreparedSourceProjection =
    for<'a> fn(&'a (dyn Any + Send)) -> Option<&'a (dyn std::error::Error + 'static)>;

/// Borrows initiating identity and the same owner's complete stored history.
#[derive(Clone, Copy)]
pub(crate) struct PreparedSourceProjections {
    pub(crate) first: PreparedSourceProjection,
    pub(crate) history: PreparedSourceProjection,
}

pub(super) struct PreparedCell {
    pub(super) projection: Option<PreparedSourceProjection>,
    pub(super) history_projection: Option<PreparedSourceProjection>,
    pub(super) epoch: u64,
    pub(super) owner: Option<Box<dyn Any + Send>>,
    pub(super) operations: Option<super::prepared_driver::PreparedBodyOperations>,
    pub(super) cleanup_failure: Option<crate::ProductionVmConstructionCleanupError>,
    pub(super) panic_payload: Option<Box<dyn Any + Send>>,
    pub(super) body_closed: bool,
    pub(super) post_body_taken: bool,
    pub(super) pending_post_body: Option<ProductionVmConstructionPostBody>,
}

pub(super) struct ServiceCell {
    pub(super) epoch: u64,
    pub(super) role: Option<PreparedRole>,
    pub(super) start: Option<RetainedServiceStart>,
    pub(super) return_body: Option<ProductionVmConstructionPostBody>,
    pub(super) queued_owner: Option<
        Box<
            dyn ProductionVmCleanupOwner<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = ProductionVmConstructionPostBody,
                >,
        >,
    >,
    pub(super) queued_owner_borrowed: bool,
    pub(super) panic_payload: Option<Box<dyn Any + Send>>,
    pub(super) transport_sequence: u64,
    pub(super) completed_transport_sequence: u64,
    pub(super) transport_receiver: Option<(u64, ServiceMainReceiver)>,
}

impl PreparedCell {
    pub(super) fn installed<T: Send + 'static>(
        epoch: u64,
        owner: Box<T>,
        projections: PreparedSourceProjections,
        operations: super::prepared_driver::PreparedBodyOperations,
    ) -> Self {
        Self {
            epoch,
            owner: Some(owner),
            projection: Some(projections.first),
            history_projection: Some(projections.history),
            operations: Some(operations),
            cleanup_failure: None,
            panic_payload: None,
            body_closed: false,
            post_body_taken: false,
            pending_post_body: None,
        }
    }

    pub(super) const fn empty() -> Self {
        Self {
            projection: None,
            history_projection: None,
            epoch: 0,
            owner: None,
            operations: None,
            cleanup_failure: None,
            panic_payload: None,
            body_closed: false,
            post_body_taken: false,
            pending_post_body: None,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.owner.is_none()
            && self.pending_post_body.is_none()
            && self.cleanup_failure.is_none()
            && self.panic_payload.is_none()
    }

    fn with_owner<T: Send + 'static, R>(
        &mut self,
        epoch: u64,
        apply: impl FnOnce(&mut T) -> R,
    ) -> Result<R, ServiceMainPreclaimError> {
        if self.epoch != epoch {
            return Err(unavailable("prepared Main role epoch is stale"));
        }
        let owner = self
            .owner
            .as_mut()
            .and_then(|owner| owner.downcast_mut::<T>())
            .ok_or_else(|| unavailable("prepared Main owner is absent or has another type"))?;
        Ok(apply(owner))
    }
}

impl ServiceCell {
    pub(super) fn installed(epoch: u64, start: Option<RetainedServiceStart>) -> Self {
        Self {
            epoch,
            role: None,
            start,
            return_body: None,
            queued_owner: None,
            queued_owner_borrowed: false,
            panic_payload: None,
            transport_sequence: 0,
            completed_transport_sequence: 0,
            transport_receiver: None,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.role.is_none()
            && self.start.is_none()
            && self.return_body.is_none()
            && self.queued_owner.is_none()
            && !self.queued_owner_borrowed
            && self.transport_receiver.is_none()
            && self.panic_payload.is_none()
    }

    pub(super) const fn empty() -> Self {
        Self {
            epoch: 0,
            role: None,
            start: None,
            return_body: None,
            queued_owner: None,
            queued_owner_borrowed: false,
            panic_payload: None,
            transport_sequence: 0,
            completed_transport_sequence: 0,
            transport_receiver: None,
        }
    }
}

/// Selects one original prepared allocation without owning the containing queue.
///
/// The type parameter is fixed by installation. Checked projection cannot
/// replace an unknown body or turn its selection into native authority.
#[must_use = "the Main-owned prepared body requires its same retirement path"]
pub(crate) struct PreparedSourceHandle<T> {
    pub(super) key: ServiceMainPreclaim,
    pub(super) owner: PhantomData<fn() -> T>,
}

/// Borrows the whole Service phase retained outside the World-containing body.
///
/// This is a nonissuing selector. Release is deliberately absent: only the
/// actual postbody driver may release Service after factual World return, or
/// after the exact construction journal proves that World never started.
#[derive(Debug)]
pub(crate) struct ServiceMainHandle {
    pub(super) key: ServiceMainPreclaim,
}

impl<T> std::fmt::Debug for PreparedSourceHandle<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSourceHandle")
            .field("key", &self.key)
            .finish()
    }
}

impl ServiceMainPreclaim {
    /// Copies the same nonowning selection for scoped Service operations.
    pub(crate) fn handle(&self) -> ServiceMainHandle {
        ServiceMainHandle {
            key: self.copy_selection(),
        }
    }

    pub(super) fn copy_selection(&self) -> Self {
        Self {
            queue: Weak::clone(&self.queue),
            index: self.index,
            epoch: self.epoch,
        }
    }

    pub(super) fn containing_queue(
        &self,
    ) -> Result<Arc<LifecycleCleanupQueue>, ServiceMainPreclaimError> {
        self.queue
            .upgrade()
            .ok_or_else(|| unavailable("containing Main owner is absent"))
    }
}

impl<T: Send + 'static> PreparedSourceHandle<T> {
    pub(super) fn from_key(key: ServiceMainPreclaim) -> Self {
        Self {
            key,
            owner: PhantomData,
        }
    }

    /// Runs one scoped operation against the same original prepared allocation.
    ///
    /// Type, epoch and phase are checked before the callback. The callback must
    /// preserve its body's own owning failure states before returning a report.
    pub(crate) fn with_prepared<R>(
        &self,
        apply: impl FnOnce(&mut T) -> R,
    ) -> Result<R, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("prepared Main role is absent"))?;
        let mut prepared = slot
            .prepared
            .try_lock()
            .map_err(|_| unavailable("prepared Main body is borrowed or poisoned"))?;
        if !slot.is(CleanupPhase::Reserved) || !slot.work_is_open() {
            return Err(unavailable("prepared Main work has entered retirement"));
        }
        prepared.with_owner(self.key.epoch, apply)
    }

    /// Borrows Service through its independent same-role owner mutex.
    pub(crate) fn service_main_handle(&self) -> ServiceMainHandle {
        self.key.handle()
    }
}

impl ServiceMainHandle {
    /// Borrows startup state without returning an owning Service alias.
    pub(crate) fn with_start<R>(
        &self,
        apply: impl FnOnce(&mut RetainedServiceStart) -> R,
    ) -> Result<R, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("Service Main role is absent"))?;
        let mut service = slot
            .service
            .try_lock()
            .map_err(|_| unavailable("Service Main phase is borrowed or poisoned"))?;
        if service.epoch != self.key.epoch
            || !slot.is(CleanupPhase::Reserved)
            || !slot.work_is_open()
        {
            return Err(unavailable(
                "Service Main work has entered retirement or another epoch",
            ));
        }
        let start = service
            .start
            .as_mut()
            .filter(|start| start.matches_main_role(&self.key))
            .ok_or_else(|| unavailable("Service Main phase is absent or foreign"))?;
        Ok(apply(start))
    }

    /// Projects a ready Service for the duration of its same scoped borrow.
    pub(crate) fn with_ready<R>(
        &self,
        apply: impl FnOnce(&RetainedTemplateService) -> R,
    ) -> Result<R, ServiceMainPreclaimError> {
        self.with_start(|start| {
            start
                .ready()
                .map(apply)
                .ok_or_else(|| unavailable("Service Main phase is not ready"))
        })?
    }

    /// Observes the same phase's factual release journal without cleanup work.
    pub(crate) fn is_released(&self) -> Result<bool, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("Service Main role is absent"))?;
        let service = slot
            .service
            .try_lock()
            .map_err(|_| unavailable("Service Main phase is borrowed or poisoned"))?;
        if service.epoch != self.key.epoch {
            return Err(unavailable("Service Main release epoch is stale"));
        }
        let start = service
            .start
            .as_ref()
            .filter(|start| start.matches_main_role(&self.key))
            .ok_or_else(|| unavailable("Service Main release phase is absent or foreign"))?;
        Ok(start.is_released())
    }
}

fn unavailable(message: &'static str) -> ServiceMainPreclaimError {
    ServiceMainPreclaimError::Role(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn exact_prepared_projection_preserves_file_on_foreign_type_and_epoch() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"same prepared body").unwrap();
        let body = Box::new(file);
        let identity = std::ptr::from_ref(body.as_ref());
        let mut cell = PreparedCell {
            projection: None,
            history_projection: None,
            epoch: 7,
            owner: Some(body),
            operations: None,
            cleanup_failure: None,
            panic_payload: None,
            body_closed: false,
            post_body_taken: false,
            pending_post_body: None,
        };

        let mismatched = cell.with_owner::<String, _>(7, |_| panic!("foreign type was borrowed"));
        assert!(mismatched.is_err());
        let stale = cell.with_owner::<std::fs::File, _>(8, |_| panic!("stale epoch was borrowed"));
        assert!(stale.is_err());
        cell.with_owner::<std::fs::File, _>(7, |file| {
            assert_eq!(std::ptr::from_ref(file), identity);
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"same prepared body");
        })
        .unwrap();
        assert!(cell.owner.is_some());
    }
}

impl<T> Clone for PreparedSourceHandle<T> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.copy_selection(),
            owner: PhantomData,
        }
    }
}

impl Clone for ServiceMainHandle {
    fn clone(&self) -> Self {
        Self {
            key: self.key.copy_selection(),
        }
    }
}

/// Tracks one actual external receiver until its owned aliases are destroyed.
///
/// It creates no native permission. Unacknowledged Drop deliberately retains
/// the counter; a lost acknowledgement cannot certify physical alias return.
#[must_use = "acknowledge only after actual owned alias destruction"]
#[derive(Debug)]
pub struct ServiceMainReceiver {
    pub(super) key: ServiceMainPreclaim,
    aliases_destroyed: bool,
    returned: bool,
}

impl ServiceMainHandle {
    /// Registers an actual receiver before cloning or handing it live aliases.
    pub(crate) fn retain_receiver(&self) -> Result<ServiceMainReceiver, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("Service receiver role is absent"))?;
        // The Service owner lock serializes receiver admission with actual
        // Service closure and epoch reuse. Atomic phase checks alone leave an
        // ABA window between observing Reserved and incrementing its counter.
        let service = slot
            .service
            .try_lock()
            .map_err(|_| unavailable("Service receiver owner is borrowed or poisoned"))?;
        if service.epoch != self.key.epoch
            || service
                .start
                .as_ref()
                .is_none_or(|start| !start.matches_main_role(&self.key) || start.ready().is_none())
        {
            return Err(unavailable("Service receiver has no same ready owner"));
        }
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || !slot.is(CleanupPhase::Reserved)
            || !slot.work_is_open()
        {
            return Err(unavailable("Service receiver role is retiring or stale"));
        }
        slot.external_receivers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| unavailable("Service receiver count overflow"))?;
        // Retirement can start after the admission check. This registered debt
        // still prevents Service release; no live aliases have left yet.
        if !slot.work_is_open() {
            let _returned = slot.external_receivers.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |count| count.checked_sub(1),
            );
            return Err(unavailable("Service receiver work entered retirement"));
        }
        Ok(ServiceMainReceiver {
            key: self.key.copy_selection(),
            aliases_destroyed: false,
            returned: false,
        })
    }
}

impl ServiceMainReceiver {
    pub(super) fn can_reserve_input_return(&self) -> bool {
        !self.aliases_destroyed && !self.returned
    }

    pub(super) fn new_registered(key: ServiceMainPreclaim) -> Self {
        Self {
            key,
            aliases_destroyed: false,
            returned: false,
        }
    }

    pub(super) fn record_alias_destruction(&mut self) {
        self.aliases_destroyed = true;
    }

    /// Acknowledges this receiver's actual owned-alias destruction.
    ///
    /// # Errors
    /// Returns the same explicit acknowledgment if its original role is
    /// unavailable or inconsistent. No native operation or new guard is used.
    pub fn return_after_alias_destruction(mut self) -> Result<(), Self> {
        self.aliases_destroyed = true;
        if self.try_return() { Ok(()) } else { Err(self) }
    }

    pub(super) fn try_return(&mut self) -> bool {
        if self.returned {
            return true;
        }
        if !self.aliases_destroyed {
            return false;
        }
        let Some(queue) = self.key.queue.upgrade() else {
            return false;
        };
        let Some(slot) = queue.slots.get(self.key.index) else {
            return false;
        };
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch {
            return false;
        }
        // This receiver's own outstanding count prevents epoch reuse until the
        // successful subtraction. No lock or callback is needed to acknowledge
        // the caller's already completed destruction cut.
        if slot
            .external_receivers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            })
            .is_err()
        {
            slot.publish(CleanupPhase::DestructionRefused);
            return false;
        }
        self.returned = true;
        true
    }

    /// Keeps this exact receiver in a same-role protected failure.
    pub fn into_failure(self, phase: &'static str) -> super::PreparedSourceFailure {
        let mut failure = self
            .key
            .handle()
            .prepared_selector()
            .typed::<()>()
            .failure(phase);
        failure.receiver = Some(self);
        failure
    }
}

impl Drop for ServiceMainReceiver {
    fn drop(&mut self) {
        // Drop never declares alias destruction. It may only repeat the pure
        // acknowledgement already selected by the explicit successful caller
        // cut above; an unclosed receiver leaves its debt occupied.
        if self.aliases_destroyed {
            let _returned = self.try_return();
        }
    }
}

/// Carries only an original role selection through an existing erased closure.
///
/// Selecting a type is nonissuing; every actual operation checks that same
/// stored Box's type, exact epoch, and irreversible work barrier.
#[derive(Debug)]
pub struct PreparedSourceSelector {
    pub(super) key: ServiceMainPreclaim,
}

impl Clone for PreparedSourceSelector {
    fn clone(&self) -> Self {
        Self {
            key: self.key.copy_selection(),
        }
    }
}

impl PreparedSourceSelector {
    pub(crate) fn typed<T: Send + 'static>(&self) -> PreparedSourceHandle<T> {
        PreparedSourceHandle::from_key(self.key.copy_selection())
    }
}

impl<T> PreparedSourceHandle<T> {
    pub(crate) fn erase(&self) -> PreparedSourceSelector {
        PreparedSourceSelector {
            key: self.key.copy_selection(),
        }
    }
}

impl ServiceMainHandle {
    pub(crate) fn prepared_selector(&self) -> PreparedSourceSelector {
        PreparedSourceSelector {
            key: self.key.copy_selection(),
        }
    }
}

impl PreparedSourceSelector {
    /// Copies only the original nonissuing Service selection.
    pub(crate) fn service_main_handle(&self) -> ServiceMainHandle {
        self.key.handle()
    }
}

impl PreparedSourceSelector {
    /// Observes actual body destruction for this same occupied original epoch.
    ///
    /// This pure journal query grants no cleanup, World return or reuse. Target
    /// metadata return uses it to distinguish an actual absent external body
    /// from a missing launcher/header; the latter is never a destruction proof.
    ///
    /// # Errors
    /// Refuses unavailable or stale role identity, preserving all owning callers.
    pub(crate) fn external_body_destroyed(&self) -> Result<bool, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("body observation role is absent"))?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch {
            return Err(unavailable("body observation role epoch is stale"));
        }
        let destroyed = slot.body_destroyed_epoch.load(Ordering::Acquire) >= self.key.epoch;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch {
            return Err(unavailable("body observation role changed epoch"));
        }
        Ok(destroyed)
    }

    /// Observes actual terminal payload disposal for this original role epoch.
    ///
    /// No native operation, Service release, or body-complete stage substitutes
    /// for this journal. A later epoch cannot erase the original completed fact.
    pub(crate) fn is_released(&self) -> Result<bool, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("completed prepared role is absent"))?;
        Ok(slot.completed_epoch.load(Ordering::Acquire) >= self.key.epoch)
    }
}

impl<T> PreparedSourceHandle<T> {
    /// Observes actual whole-role disposal before this factory may be reused.
    pub(crate) fn is_released(&self) -> Result<bool, ServiceMainPreclaimError> {
        self.erase().is_released()
    }

    /// Borrows only cleanup state after the same actual lifecycle body was destroyed.
    pub(crate) fn with_prepared_after_body<R>(
        &self,
        apply: impl FnOnce(&mut T) -> R,
    ) -> Result<R, ServiceMainPreclaimError>
    where
        T: Send + 'static,
    {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("postbody prepared role is absent"))?;
        let mut prepared = slot
            .prepared
            .try_lock()
            .map_err(|_| unavailable("postbody prepared body is borrowed or poisoned"))?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || slot.body_destroyed_epoch.load(Ordering::Acquire) < self.key.epoch
            || slot.is(CleanupPhase::Free)
        {
            return Err(unavailable(
                "same actual body destruction has not been observed",
            ));
        }
        prepared.with_owner(self.key.epoch, apply)
    }
}

impl PreparedSourceSelector {
    pub(super) fn with_erased_after_body<R>(
        &self,
        apply: impl FnOnce(&mut (dyn Any + Send)) -> R,
    ) -> Result<R, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("postbody role is absent"))?;
        let mut prepared = slot
            .prepared
            .try_lock()
            .map_err(|_| unavailable("postbody owner is borrowed or poisoned"))?;
        if prepared.epoch != self.key.epoch
            || slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || slot.body_destroyed_epoch.load(Ordering::Acquire) < self.key.epoch
            || slot.is(CleanupPhase::Free)
        {
            return Err(unavailable("same actual body destruction is not observed"));
        }
        let owner = prepared
            .owner
            .as_mut()
            .ok_or_else(|| unavailable("same postbody owner is absent"))?;
        Ok(apply(owner.as_mut()))
    }
}

impl ServiceMainHandle {
    /// Borrows only a pure ownership tail after factual World and alias return.
    ///
    /// The callback may move the already parent-paid pristine imported capsule;
    /// it must perform no IO, new Original entry, native work or user callback.
    /// This cut never reopens the irreversible Source work gate. Startup must
    /// preserve any designated export until this same-mutex transfer completes.
    pub(crate) fn with_start_after_world_return<R>(
        &self,
        apply: impl FnOnce(&mut RetainedServiceStart) -> R,
    ) -> Result<R, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("post-World Service role is absent"))?;
        let mut service = slot
            .service
            .try_lock()
            .map_err(|_| unavailable("post-World Service phase is borrowed or poisoned"))?;
        if service.epoch != self.key.epoch
            || slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || slot.body_destroyed_epoch.load(Ordering::Acquire) < self.key.epoch
            || slot.controls_closed_epoch.load(Ordering::Acquire) < self.key.epoch
            || slot.worlds_returned_epoch.load(Ordering::Acquire) < self.key.epoch
            || slot.external_receivers.load(Ordering::Acquire) != 0
            || slot.is(CleanupPhase::Free)
        {
            return Err(unavailable(
                "same actual World, body or external aliases remain retained",
            ));
        }
        let start = service
            .start
            .as_mut()
            .filter(|start| start.matches_main_role(&self.key))
            .ok_or_else(|| unavailable("post-World Service phase is absent or foreign"))?;
        Ok(apply(start))
    }
}

impl PreparedSourceSelector {
    /// Compares only the original weak queue, slot and epoch selections.
    pub(crate) fn same_role(&self, other: &Self) -> bool {
        self.key.same_role(&other.key)
    }
}

impl<T: Send + 'static> PreparedSourceHandle<T> {
    /// Borrows a still-open custody destination for a pure same-role body return.
    ///
    /// This operation accepts the original external owner after the work barrier
    /// closes. The callback must validate that owner's real launcher selection
    /// before moving any caller Option. It may only move existing owners: no IO,
    /// callbacks, Original entry or native work. Its result is never discarded
    /// by a later phase check.
    pub(crate) fn with_prepared_for_return<R>(
        &self,
        apply: impl FnOnce(&mut T) -> R,
    ) -> Result<R, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("returned body role is absent"))?;
        let mut prepared = slot
            .prepared
            .try_lock()
            .map_err(|_| unavailable("returned body destination is borrowed or poisoned"))?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || prepared.epoch != self.key.epoch
            || !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared))
            || slot.body_destroyed_epoch.load(Ordering::Acquire) >= self.key.epoch
            || prepared.body_closed
            || prepared.post_body_taken
        {
            return Err(unavailable(
                "same body return destination is stale or already closed",
            ));
        }
        prepared.with_owner(self.key.epoch, apply)
    }
}

impl ServiceMainHandle {
    /// Retries only the exact Main-owned body through its saved cleanup path.
    ///
    /// This closes the work barrier before calling the fixed registered owner
    /// operation. Typed first and post errors remain in Main. A successful
    /// body journal is not PostBody transfer, controls close, World return or
    /// Service release; those cuts remain with canonical retirement.
    ///
    /// # Errors
    /// Refuses stale, borrowed, terminal, poisoned or physically pending custody
    /// without moving an owner or replacing its raw failure with a diagnostic.
    pub(crate) fn retry_prepared_body(&self) -> Result<bool, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("prepared body retry role is absent"))?;
        let mut prepared = slot
            .prepared
            .try_lock()
            .map_err(|_| unavailable("prepared body retry is borrowed or poisoned"))?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || prepared.epoch != self.key.epoch
            || !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared))
            || prepared.owner.is_none()
            || prepared.post_body_taken
        {
            return Err(unavailable(
                "same prepared body is stale, transferred or terminal",
            ));
        }
        slot.request_retirement();
        super::prepared_driver::retry_body_in_place(slot, &mut prepared)
            .map_err(ServiceMainPreclaimError::Role)?;
        Ok(prepared.body_closed)
    }
}

impl<T: Send + 'static> PreparedSourceHandle<T> {
    /// Retries this same registered body's cleanup without transferring its tail.
    pub(crate) fn retry_prepared_body(&self) -> Result<bool, ServiceMainPreclaimError> {
        self.service_main_handle().retry_prepared_body()
    }
}

impl PreparedSourceSelector {
    /// Closes future work without entering an Original or proving alias return.
    pub(crate) fn request_retirement(&self) {
        let Some(queue) = self.key.queue.upgrade() else {
            return;
        };
        let Some(slot) = queue.slots.get(self.key.index) else {
            return;
        };
        if slot.epoch.load(Ordering::Acquire) == self.key.epoch {
            slot.request_retirement();
        }
    }
}

impl ServiceMainReceiver {
    /// Compares the same original role selection without registering a lease.
    pub(crate) fn matches_main_role(&self, key: &ServiceMainPreclaim) -> bool {
        self.key.same_role(key)
    }
}

impl ServiceMainHandle {
    /// Moves existing receiving aliases into their original preborn role.
    ///
    /// This fixed custody cut precedes returned Loop publication. It waits only
    /// on the short control mutex: no prepared/Service lock, IO, callbacks or
    /// destructors execute while holding it. Matching poison accepts custody
    /// into quarantine, and never claims cleanup or alias acknowledgement.
    ///
    /// # Errors
    /// Keeps the caller Option unchanged on missing Main, stale/foreign role,
    /// occupied input or non-returnable phase. A valid unique input cannot race
    /// another owner of its same move-only receiver.
    pub(crate) fn adopt_retirement_input(
        &self,
        input: &mut Option<crate::packaged_qemu_executor::ServiceRetirementInput>,
    ) -> Result<(), ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("receiving input role is absent"))?;
        let (mut cell, poisoned) = match slot.cell.lock() {
            Ok(cell) => (cell, false),
            Err(poison) => (poison.into_inner(), true),
        };
        let quarantined = slot.is(CleanupPhase::DestructionRefused);
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || cell.epoch != self.key.epoch
            || !(slot.is(CleanupPhase::Reserved)
                || slot.is(CleanupPhase::RetryingPrepared)
                || slot.is(CleanupPhase::PostBodyPending)
                || slot.is(CleanupPhase::Returning)
                || quarantined)
            || (!quarantined && cell.owner.is_some())
            || (!quarantined
                && cell.handoff
                && (slot.body_destroyed_epoch.load(Ordering::Acquire) < self.key.epoch
                    || slot.controls_closed_epoch.load(Ordering::Acquire) < self.key.epoch))
            || cell.retirement_input.is_some()
            || cell.retirement_input_reserved
            || !input
                .as_ref()
                .is_some_and(|input| input.matches_main_role(&self.key))
        {
            return Err(unavailable(
                "same receiving input destination is foreign or occupied",
            ));
        }
        // Custody adoption is permitted before live work is exposed. Only an
        // explicit retirement request closes the work gate.
        cell.retirement_input = input.take();
        if poisoned || quarantined {
            slot.publish(CleanupPhase::DestructionRefused);
        }
        Ok(())
    }
}

impl ServiceMainHandle {
    /// Observes actual same-cell acceptance of the original external body.
    ///
    /// The actual handoff and owner/destruction journal establish custody only.
    /// Neither acceptance nor body destruction proves native or Service return.
    ///
    /// # Errors
    /// Refuses an unavailable, borrowed, poisoned or foreign original epoch.
    pub(crate) fn external_body_accepted(&self) -> Result<bool, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| unavailable("external body role is absent"))?;
        let cell = slot
            .cell
            .try_lock()
            .map_err(|_| unavailable("external body acceptance is borrowed or poisoned"))?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch || cell.epoch != self.key.epoch {
            return Err(unavailable(
                "external body acceptance belongs to another epoch",
            ));
        }
        Ok(cell.handoff
            && (cell.owner.is_some()
                || slot.body_destroyed_epoch.load(Ordering::Acquire) >= self.key.epoch))
    }
}
