//! Observes the concrete original process-return mailbox before custody returns.
//!
//! The enclosing trait-object Box is charged by its actual owning Cnp observer.
//! The same mailbox may also be retained by the supervisor and journal slot; this
//! per-view observation conservatively charges its actual Rc allocation again.
//! Equal identities never discount unrelated native or runtime custody.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_engine::node_contract::{EffectKnowledge, OperationFailure};

impl NativeSlot {
    pub(super) fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crucible_engine::node_contract::RuntimeError> {
        if self.process != std::process::id() {
            return Err(crucible_engine::node_contract::RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(crucible_engine::node_contract::RuntimeError::ThreadAffinity);
        }
        if self.transferred {
            return Ok(None);
        }
        retained_mailbox_storage_precredit_data(&self.mailbox, maximum)
    }

    /// Reports actual reserved mailbox backing to the sibling whole-world slot.
    ///
    /// Unsupported returned or busy phases remain unknown and return None.
    ///
    /// # Errors
    /// Refuses arithmetic overflow or backing above the requested storage bound.
    pub(super) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        if self.transferred {
            return Ok(None);
        }
        retained_mailbox_storage_data(&self.mailbox, maximum)
    }
}

// A borrowed data loan must not construct NativeSlot: its Drop intentionally
// releases an unused original reservation. Inspect the original flags in place.
pub(super) fn retained_mailbox_storage_data(
    mailbox: &Rc<Mailbox>,
    maximum: usize,
) -> Result<Option<usize>, OperationFailure> {
    if !mailbox.reserved.get()
        || !mailbox.expected.get()
        || mailbox.returned.get()
        || mailbox.reaped.get()
        || mailbox.journal_retained.get()
        || mailbox.polling.get()
        || mailbox.invalid.get()
    {
        return Ok(None);
    }
    let mut counter = Counter::new(maximum);
    counter.rc(mailbox).map_err(|_| OperationFailure {
        effects: EffectKnowledge::None,
        reason: "packet process mailbox requested storage".to_owned(),
    })?;
    Ok(Some(counter.bytes()))
}

// The typed precredit path borrows the actual mailbox; constructing a temporary
// NativeSlot would run its reservation-releasing Drop and alter custody.
pub(super) fn retained_mailbox_storage_precredit_data(
    mailbox: &Rc<Mailbox>,
    maximum: usize,
) -> Result<Option<usize>, crucible_engine::node_contract::RuntimeError> {
    if !mailbox.reserved.get()
        || !mailbox.expected.get()
        || mailbox.returned.get()
        || mailbox.reaped.get()
        || mailbox.journal_retained.get()
        || mailbox.polling.get()
        || mailbox.invalid.get()
    {
        return Ok(None);
    }
    let mut counter = Counter::new(maximum);
    counter
        .rc(mailbox)
        .map_err(|_| crucible_engine::node_contract::RuntimeError::ResourceLimit)?;
    Ok(Some(counter.bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_mailbox_requested_layout_is_bounded_and_busy_or_returned_refuses()
    -> Result<(), QualificationError> {
        let mailbox = Rc::new(Mailbox {
            reserved: Cell::new(false),
            expected: Cell::new(false),
            returned: Cell::new(false),
            reaped: Cell::new(false),
            journal_retained: Cell::new(false),
            polling: Cell::new(false),
            invalid: Cell::new(false),
            native: Cell::new(None),
            journal: Cell::new(None),
            keepalive: Cell::new(None),
        });
        let slot = NativeSlot {
            process: std::process::id(),
            thread: std::thread::current().id(),
            mailbox,
            transferred: false,
        };
        // Match the compiled Rc<Mailbox> request, including its retained slots.
        let counter_bytes = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or(QualificationError::Refused("mailbox layout overflow"))?;
        let padding = std::mem::align_of::<Mailbox>()
            .max(std::mem::align_of::<usize>())
            .checked_sub(1)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(QualificationError::Refused("mailbox layout overflow"))?;
        let mailbox_requested_bytes = std::mem::size_of::<Mailbox>()
            .checked_add(counter_bytes)
            .and_then(|bytes| bytes.checked_add(padding))
            .ok_or(QualificationError::Refused("mailbox layout overflow"))?;

        assert_eq!(
            slot.retained_requested_storage_data(mailbox_requested_bytes)
                .map_err(|error| QualificationError::Evidence(error.reason))?,
            None
        );
        slot.mailbox.reserved.set(true);
        slot.mailbox.expected.set(true);
        let bytes = slot
            .retained_requested_storage_data(mailbox_requested_bytes)
            .map_err(|error| QualificationError::Evidence(error.reason))?
            .ok_or(QualificationError::Refused("missing original mailbox row"))?;
        assert_eq!(bytes, mailbox_requested_bytes);
        assert!(bytes >= std::mem::size_of::<Mailbox>() + 2 * std::mem::size_of::<usize>());
        assert!(slot.retained_requested_storage_data(bytes - 1).is_err());
        slot.mailbox.polling.set(true);
        assert!(matches!(
            slot.retained_requested_storage_data(mailbox_requested_bytes),
            Ok(None)
        ));
        slot.mailbox.polling.set(false);
        slot.mailbox.returned.set(true);
        assert!(matches!(
            slot.retained_requested_storage_data(mailbox_requested_bytes),
            Ok(None)
        ));
        slot.mailbox.returned.set(false);
        slot.mailbox.journal_retained.set(true);
        assert!(matches!(
            slot.retained_requested_storage_data(mailbox_requested_bytes),
            Ok(None)
        ));
        Ok(())
    }

    #[test]
    fn typed_original_slot_observer_preserves_reservation_and_refuses_foreign_before_backing() {
        let mailbox = Rc::new(Mailbox {
            reserved: Cell::new(true),
            expected: Cell::new(true),
            returned: Cell::new(false),
            reaped: Cell::new(false),
            journal_retained: Cell::new(false),
            polling: Cell::new(false),
            invalid: Cell::new(false),
            native: Cell::new(None),
            journal: Cell::new(None),
            keepalive: Cell::new(None),
        });
        let mut original = NativeSlot {
            process: std::process::id(),
            thread: std::thread::current().id(),
            mailbox: Rc::clone(&mailbox),
            transferred: false,
        };
        let bytes = original
            .retained_requested_storage_precredit_data(usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(
            original
                .retained_requested_storage_precredit_data(bytes)
                .unwrap(),
            Some(bytes)
        );
        assert_eq!(
            original.retained_requested_storage_precredit_data(bytes - 1),
            Err(crucible_engine::node_contract::RuntimeError::ResourceLimit)
        );
        assert!(mailbox.expected.get());
        assert!(!mailbox.returned.get());
        assert!(!original.transferred);
        mailbox.polling.set(true);
        assert_eq!(
            original
                .retained_requested_storage_precredit_data(bytes)
                .unwrap(),
            None
        );
        original.process = original.process.wrapping_add(1);
        assert_eq!(
            original.retained_requested_storage_precredit_data(0),
            Err(crucible_engine::node_contract::RuntimeError::ForeignAuthority)
        );
        assert!(mailbox.expected.get());
        assert!(mailbox.polling.get());
        // Restore creator before the fixture's existing ordinary Drop semantics.
        original.process = std::process::id();
        mailbox.polling.set(false);
    }
}
