//! Observes an exact peer return without consuming any retained borrower.
//!
//! The retained physical session supplies the mapping and original offer.
//! A bounded ticket/sequence cut records metadata only. Actual Source member
//! consumption, producer terminal publication and receiver Closed are separate.

use super::*;
use crucible_qemu_protocol::publisher_subscription::{PUBLISHER_RETURN_BYTES, PublisherReturn};

const RETURN_WORD: usize = TICKET_WORD + 1;

/// Keeps the first exact stable return in the session's prepaid body.
#[derive(Debug)]
pub(super) struct RetainedReceiverReturn {
    record: PublisherReturn,
    bytes: [u8; PUBLISHER_RETURN_BYTES],
}

pub(super) fn observation_scratch_bytes() -> Option<usize> {
    PUBLISHER_RETURN_BYTES.checked_add(size_of::<PublisherReturn>().checked_mul(2)?)
}

impl<Custody> SessionBody<Custody> {
    /// Attempts both independent physical cuts before returning either refusal.
    pub(in super::super) fn revoke_command_and_observe_return(
        &mut self,
    ) -> Result<(), OperationFailure> {
        let revocation = self.revoke_command_offer();
        let observation = self.observe_command_return();

        revocation.and(observation.map(|_| ()))
    }

    /// Retains one bounded return observation from this actual session.
    ///
    /// Negative semantic statuses and partial masks remain factual metadata.
    /// They neither authorize physical consumption nor prevent observing debt
    /// after permission revocation. No mapped word or event is changed here.
    pub(in super::super) fn observe_command_return(
        &mut self,
    ) -> Result<Option<PublisherReturn>, OperationFailure> {
        let result = self.observe_command_return_with(|_| {});
        if let Err(first) = result {
            self.command.return_observation_first.get_or_insert(first);
            self.command.first.get_or_insert(first);
        }
        result
    }

    // The private seam changes actual atomic words in final-cut controls. It
    // supplies no Source, operation or peer-return authority.
    fn observe_command_return_with(
        &mut self,
        after_copy: impl FnOnce(&[AtomicU64]),
    ) -> Result<Option<PublisherReturn>, OperationFailure> {
        let offer = self
            .command
            .offer
            .as_ref()
            .ok_or(OperationFailure::Geometry)?;
        if !offer.publication_committed || !offer.ticket_attempted {
            return Err(OperationFailure::Geometry);
        }
        let loan = PublisherLoanIdentity {
            ticket_serial: offer.publication.ticket_serial,
            offer_generation: offer.publication.offer_generation,
            command_sequence: offer.publication.sequence,
        };
        let born_views = offer.publication.cohort.borrowed_mask;
        let words = self.command_words()?;
        let before_ticket = words[TICKET_WORD].load(Ordering::SeqCst);
        let ticket = PublisherTicket::decode(u64::from_be(before_ticket))
            .map_err(|_| OperationFailure::Geometry)?;
        if ticket.serial != loan.ticket_serial {
            return Err(OperationFailure::Geometry);
        }
        match ticket.phase {
            PublisherTicketPhase::Issued | PublisherTicketPhase::Acquired => {
                if self.command.receiver.is_some() {
                    return Err(OperationFailure::Geometry);
                }
                return Ok(None);
            }
            PublisherTicketPhase::Withdrawn
                if offer.withdrawn && self.command.receiver.is_none() =>
            {
                return Ok(None);
            }
            PublisherTicketPhase::ReturnRequested => {}
            _ => return Err(OperationFailure::Geometry),
        }

        let before_sequence = words[RETURN_WORD].load(Ordering::SeqCst);
        let sequence = u64::from_be(before_sequence);
        if sequence == 0 || sequence == u64::MAX || sequence & 1 != 0 {
            return Err(OperationFailure::Geometry);
        }
        let mut bytes = [0; PUBLISHER_RETURN_BYTES];
        for (index, chunk) in bytes.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(
                &words[RETURN_WORD + index]
                    .load(Ordering::SeqCst)
                    .to_ne_bytes(),
            );
        }
        after_copy(words);
        if words[RETURN_WORD].load(Ordering::SeqCst) != before_sequence
            || words[TICKET_WORD].load(Ordering::SeqCst) != before_ticket
        {
            return Err(OperationFailure::Geometry);
        }
        let record = PublisherReturn::decode(&bytes).map_err(|_| OperationFailure::Geometry)?;
        if record.sequence != sequence
            || record.loan != loan
            || record.returned_view_mask & !born_views != 0
        {
            return Err(OperationFailure::Geometry);
        }
        if let Some(retained) = self.command.receiver.as_ref() {
            if retained.bytes != bytes || retained.record != record {
                return Err(OperationFailure::Geometry);
            }
        } else {
            self.command.receiver = Some(RetainedReceiverReturn { record, bytes });
        }
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests;
