//! Observes the concrete original process-return mailbox before custody returns.
//!
//! The enclosing trait-object Box is charged by its actual owning Cnp observer.
//! The same mailbox may also be retained by the supervisor and journal slot; this
//! per-view observation conservatively charges its actual Rc allocation again.
//! Equal identities never discount unrelated native or runtime custody.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible::node_contract::{EffectKnowledge, OperationFailure};

impl NativeSlot {
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
}
