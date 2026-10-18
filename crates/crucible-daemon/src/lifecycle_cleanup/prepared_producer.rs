//! Installs fixed prepared bodies only after their original Main slot is locked.
//!
//! Every refusal precedes construction and returns the unchanged input. The
//! private build functions move inputs and allocate only the already paid token,
//! Pending and carrier; they perform no IO, Original entry or native operation.

use super::prepared_service::{PreparedCell, PreparedSourceProjections, ServiceCell};
use super::*;
use crate::packaged_qemu_executor::RetainedServiceStart;

/// Classifies the actual fixed constructor recipe without issuing authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedRole {
    /// Retains a genuine Source construction and its independently owned Service.
    Source,
    /// Retains a genuine Target borrowing its actual Source checkout.
    Target,
}

/// Selects the actual Main queue without admitting a new native or Service role.
///
/// The real shared factory creates this opaque weak selector. Construction is
/// private to the backend and verifies its same containing Main before birth.
#[derive(Clone)]
pub struct SourceMainProducer {
    queue: Weak<LifecycleCleanupQueue>,
}

impl LifecycleCleanupHandle {
    pub(crate) fn source_main_producer(&self) -> SourceMainProducer {
        SourceMainProducer {
            queue: Weak::clone(&self.queue),
        }
    }
}

impl SourceMainProducer {
    /// Checks that a checkout selects an actual Source in this same Main queue.
    ///
    /// This metadata check grants no Target permission. The genuine checkout,
    /// logical Target slot and native preparation still authorize their own
    /// effects. A borrowed or retiring Source retains the unchanged input.
    pub(crate) fn verify_source_selector(
        &self,
        source: &prepared_service::PreparedSourceSelector,
    ) -> Result<(), ServiceMainPreclaimError> {
        if !Weak::ptr_eq(&self.queue, &source.key.queue) {
            return Err(role("Target checkout belongs to another containing Main"));
        }
        let queue = source.key.containing_queue()?;
        queue
            ._pool
            .verify_retained_main()
            .map_err(ServiceMainPreclaimError::Main)?;
        let slot = queue
            .slots
            .get(source.key.index)
            .ok_or_else(|| role("Source checkout role is absent"))?;
        let service = slot
            .service
            .try_lock()
            .map_err(|_| role("Source checkout Service is borrowed or poisoned"))?;
        if slot.epoch.load(Ordering::Acquire) != source.key.epoch
            || service.epoch != source.key.epoch
            || service.role != Some(PreparedRole::Source)
            || !slot.is(CleanupPhase::Reserved)
            || !slot.work_is_open()
            || !service
                .start
                .as_ref()
                .is_some_and(|start| start.matches_main_role(&source.key))
        {
            return Err(role("same occupied Source role is not open for a checkout"));
        }
        Ok(())
    }

    /// Builds the fixed paid body only after all custody checks have succeeded.
    ///
    /// The function pointer is restricted to reviewed private constructors.
    /// It must move inputs and initialize fixed bodies without fallible work,
    /// IO, calls to user code or Original entry while these locks are held.
    pub(crate) fn reserve_with_prepared<T, I>(
        &self,
        prepared_role: PreparedRole,
        input: I,
        constructor_bytes: u64,
        build: fn(I, WorldLifecycleCleanupReservation) -> (Box<T>, Option<RetainedServiceStart>),
        projections: PreparedSourceProjections,
    ) -> Result<prepared_service::PreparedSourceHandle<T>, (I, ServiceMainPreclaimError)>
    where
        T: ProductionVmCleanupOwner<
                Failure = crate::ProductionVmConstructionCleanupError,
                PostBody = ProductionVmConstructionPostBody,
            > + 'static,
    {
        let Some(queue) = self.queue.upgrade() else {
            return Err((input, role("prepared containing Main is unavailable")));
        };
        if let Err(first) = queue._pool.verify_retained_main() {
            return Err((input, ServiceMainPreclaimError::Main(first)));
        }
        let Ok(minimum_body) = u64::try_from(std::mem::size_of::<T>()) else {
            return Err((input, role("prepared body extent is not representable")));
        };
        if constructor_bytes < minimum_body || constructor_bytes > queue.constructor_bytes {
            return Err((
                input,
                role("actual prepared constructor exceeds its admitted Main extent"),
            ));
        }
        for (index, slot) in queue.slots.iter().enumerate() {
            if !slot.claim(CleanupPhase::Free, CleanupPhase::Reserving) {
                continue;
            }
            // A stale observer can still borrow an already empty previous
            // epoch. No input, token, owner or new epoch has moved at these
            // contention cuts, so release acquired locks before restoring Free.
            let mut prepared = match slot.prepared.try_lock() {
                Ok(prepared) => prepared,
                Err(std::sync::TryLockError::WouldBlock) => {
                    let _restored = slot.claim(CleanupPhase::Reserving, CleanupPhase::Free);
                    continue;
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    slot.publish(CleanupPhase::DestructionRefused);
                    return Err((input, role("free prepared Main storage is poisoned")));
                }
            };
            let mut service = match slot.service.try_lock() {
                Ok(service) => service,
                Err(std::sync::TryLockError::WouldBlock) => {
                    drop(prepared);
                    let _restored = slot.claim(CleanupPhase::Reserving, CleanupPhase::Free);
                    continue;
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    slot.publish(CleanupPhase::DestructionRefused);
                    return Err((input, role("free Service Main storage is poisoned")));
                }
            };
            let mut cell = match slot.cell.try_lock() {
                Ok(cell) => cell,
                Err(std::sync::TryLockError::WouldBlock) => {
                    drop(service);
                    drop(prepared);
                    let _restored = slot.claim(CleanupPhase::Reserving, CleanupPhase::Free);
                    continue;
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    slot.publish(CleanupPhase::DestructionRefused);
                    return Err((input, role("free Main control storage is poisoned")));
                }
            };
            if !prepared.is_empty()
                || !service.is_empty()
                || slot.external_return_reserved.load(Ordering::Acquire)
                || cell.owner.is_some()
                || cell.controls.is_some()
                || cell.first_failure.is_some()
                || cell.post_body.is_some()
                || cell.incoming_post_body.is_some()
                || cell.control_failure.is_some()
                || cell.retirement_input.is_some()
                || cell.retirement_input_reserved
                || cell.panic_payload.is_some()
                || cell.controls_bound
                || cell.handoff
                || slot.report_references.load(Ordering::Acquire) != report_refs::CLOSED
                || slot.external_receivers.load(Ordering::Acquire) != 0
                || !slot.is(CleanupPhase::Reserving)
            {
                slot.publish(CleanupPhase::DestructionRefused);
                return Err((input, role("free Main role retains prior custody")));
            }
            let Some(epoch) = cell.epoch.checked_add(1) else {
                slot.publish(CleanupPhase::DestructionRefused);
                return Err((input, role("prepared Main role epoch is exhausted")));
            };

            // All refusal cuts precede these fixed constructor allocations.
            // Original token identity and input are moved only once, and no
            // unpublished body is ever returned into a local factory slot.
            let reservation = reservation::new_world_reservation(&self.queue, index, epoch);
            let key = reservation.service_preclaim();
            let (owner, initial_service) = build(input, reservation);
            *prepared = PreparedCell::installed(
                epoch,
                owner,
                projections,
                super::prepared_driver::PreparedBodyOperations::for_owner::<T>(),
            );
            *service = ServiceCell::installed(epoch, initial_service);
            service.role = Some(prepared_role);
            cell.epoch = epoch;
            cell.handoff = false;
            slot.epoch.store(epoch, Ordering::Release);
            slot.report_references.store(0, Ordering::Release);
            slot.transport_return_sequence.store(0, Ordering::Release);
            slot.retirement_requested.store(false, Ordering::Release);
            slot.export_abandoned.store(false, Ordering::Release);
            slot.work_gate.reset_before_publication();
            slot.terminal_disposed.store(false, Ordering::Release);
            let handle = prepared_service::PreparedSourceHandle::from_key(key);
            drop(cell);
            drop(service);
            drop(prepared);
            slot.publish(CleanupPhase::Reserved);
            return Ok(handle);
        }
        Err((
            input,
            role("all admitted prepared Main roles remain occupied"),
        ))
    }
}

fn role(message: &'static str) -> ServiceMainPreclaimError {
    ServiceMainPreclaimError::Role(message)
}
