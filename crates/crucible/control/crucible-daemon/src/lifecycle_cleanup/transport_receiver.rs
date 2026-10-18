//! Retains remote-observation receiver acknowledgments in the original Main role.
//!
//! The actual token enters the existing Service cell before aliases escape.
//! Its external handle carries only a same-role sequence and one report pin.
//! An explicit alias-destruction journal precedes any fallible borrow, allowing
//! Main to retry the same acknowledgment after a neutral transport error.

use super::prepared_service::{ServiceCell, ServiceMainHandle, ServiceMainReceiver};
use super::*;

/// Selects the actual receiver already retained in its original Main Service cell.
///
/// Dropping the handle never claims alias destruction. The Main-owned receiver
/// remains occupied unless the explicit consuming return records that real cut.
#[must_use = "record actual alias destruction before discarding the receiver handle"]
#[derive(Debug)]
pub(crate) struct ServiceMainReceiverHandle {
    key: ServiceMainPreclaim,
    sequence: u64,
    report_reference: bool,
}

impl ServiceMainHandle {
    /// Retains one transport receiver in Main before handing out live aliases.
    ///
    /// All fallible checks precede its census/report registration. An occupied
    /// transport slot refuses another receiver before its alias construction.
    pub(crate) fn retain_receiver_in_main(
        &self,
    ) -> Result<ServiceMainReceiverHandle, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| role("transport receiver role is absent"))?;
        let mut service = slot
            .service
            .try_lock()
            .map_err(|_| role("transport receiver phase is borrowed or poisoned"))?;
        let cell = slot
            .cell
            .try_lock()
            .map_err(|_| role("transport receiver report storage is borrowed or poisoned"))?;
        if cell.epoch != self.key.epoch
            || service.epoch != self.key.epoch
            || slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || !slot.is(CleanupPhase::Reserved)
            || !slot.work_is_open()
            || service.transport_receiver.is_some()
            || service
                .start
                .as_ref()
                .is_none_or(|start| !start.matches_main_role(&self.key) || start.ready().is_none())
        {
            return Err(role("transport receiver has no vacant same ready role"));
        }
        let sequence = service
            .transport_sequence
            .checked_add(1)
            .ok_or_else(|| role("transport receiver sequence is exhausted"))?;
        if slot.external_receivers.load(Ordering::Acquire) == usize::MAX
            || slot.report_references.load(Ordering::Acquire) >= report_refs::CLOSED - 1
        {
            return Err(role("transport receiver census is exhausted"));
        }

        // Service serializes all receiver admissions, and the control mutex
        // serializes report registration. Concurrent returns only subtract.
        if !report_refs::register(slot, self.key.epoch) {
            return Err(role("transport report role could not be pinned"));
        }
        slot.external_receivers.fetch_add(1, Ordering::AcqRel);
        service.transport_sequence = sequence;
        service.transport_receiver = Some((
            sequence,
            ServiceMainReceiver::new_registered(self.key.copy_selection()),
        ));
        Ok(ServiceMainReceiverHandle {
            key: self.key.copy_selection(),
            sequence,
            report_reference: true,
        })
    }
}

impl ServiceMainReceiverHandle {
    /// Records actual owned-alias destruction and retries its Main-held token.
    ///
    /// Recording the exact sequence precedes the fallible phase borrow. A
    /// refused borrow leaves both token and acknowledgment reachable by Main.
    ///
    /// # Errors
    /// Refuses unavailable, stale, borrowed or inconsistent original custody.
    /// The original Main cell retains the token and any recorded return fact.
    pub(crate) fn return_after_alias_destruction(self) -> Result<(), ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or_else(|| role("transport return role is absent"))?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch {
            return Err(role("transport return epoch is stale"));
        }
        // This handle's report pin prevents role reuse until its Drop below.
        // A late old sequence cannot acknowledge a subsequently admitted one.
        slot.transport_return_sequence
            .fetch_max(self.sequence, Ordering::AcqRel);
        let mut service = slot
            .service
            .try_lock()
            .map_err(|_| role("transport return remains recorded in a borrowed Main phase"))?;
        if service.epoch != self.key.epoch {
            return Err(role("transport return phase changed epoch"));
        }
        if !retry_transport_return(slot, &mut service, self.key.epoch)
            || service.completed_transport_sequence < self.sequence
        {
            return Err(role(
                "same transport receiver acknowledgment remains retained",
            ));
        }
        Ok(())
    }
}

/// Retries only an acknowledgment whose actual alias-destruction cut was recorded.
pub(super) fn retry_transport_return(
    slot: &CleanupSlot,
    service: &mut ServiceCell,
    epoch: u64,
) -> bool {
    if service.epoch != epoch || slot.epoch.load(Ordering::Acquire) != epoch {
        return false;
    }
    let Some((sequence, receiver)) = service.transport_receiver.as_mut() else {
        return service.completed_transport_sequence == service.transport_sequence;
    };
    if slot.transport_return_sequence.load(Ordering::Acquire) < *sequence {
        return false;
    }
    receiver.record_alias_destruction();
    if !receiver.try_return() {
        return false;
    }
    service.completed_transport_sequence = *sequence;
    drop(service.transport_receiver.take());
    true
}

impl Drop for ServiceMainReceiverHandle {
    fn drop(&mut self) {
        if self.report_reference {
            // Only the report pin returns here. Unrecorded aliases retain the
            // separate original receiver token and its actual census in Main.
            terminal::return_report_reference(&self.key, false);
            self.report_reference = false;
        }
    }
}

fn role(message: &'static str) -> ServiceMainPreclaimError {
    ServiceMainPreclaimError::Role(message)
}
