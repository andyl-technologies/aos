//! Publishes physical command offers through the actual retained session map.
//!
//! These atomic process-protocol operations issue no Source membership or
//! Original. Their caller must retain the actual producer loans and serialize
//! the complete lender/cohort cut before calling them. They never call a lender
//! while holding the session lock, preserving the publisher's lock order.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};

use crucible_qemu_protocol::publisher_subscription::{
    PUBLISHER_PUBLICATION_BYTES, PUBLISHER_TICKET_MAX_SERIAL, PublisherLoanIdentity,
    PublisherPermission, PublisherPublication, PublisherTicket, PublisherTicketPhase,
};

use super::{OperationFailure, PUBLISHER_HEADER_BYTES, PUBLISHER_REGION_BYTES, SessionBody};

const PUBLICATION_WORD: usize = PUBLISHER_HEADER_BYTES / 8;
const PUBLICATION_WORDS: usize = PUBLISHER_PUBLICATION_BYTES / 8;
const TICKET_WORD: usize = PUBLICATION_WORD + PUBLICATION_WORDS;

/// Retains one physical offer's exact bytes before any shared mutation.
#[derive(Debug)]
struct RetainedOffer {
    publication: PublisherPublication,
    bytes: [u8; PUBLISHER_PUBLICATION_BYTES],
    publication_attempted: bool,
    publication_committed: bool,
    ticket_attempted: bool,
    ticket_issued: bool,
    withdrawal_attempted: bool,
    withdrawn: bool,
    revocation_attempted: bool,
    revoked: bool,
}

/// Lives in the session's prepaid body before mappings or command birth.
#[derive(Debug, Default)]
pub(super) struct CommandJournal {
    offer: Option<RetainedOffer>,
    first: Option<OperationFailure>,
}

impl CommandJournal {
    pub(super) fn has_offer(&self) -> bool {
        self.offer.is_some()
    }

    /// Prices concurrent by-value publication and canonical encoding scratch.
    /// The enclosing body already prices the retained offer and its byte array.
    pub(super) fn encoding_extent() -> Option<usize> {
        size_of::<PublisherPublication>()
            .checked_mul(2)?
            .checked_add(PUBLISHER_PUBLICATION_BYTES.checked_mul(2)?)?
            .checked_add(crucible_qemu_protocol::boundary_action::ACTION_BYTES)?
            .checked_add(
                crucible_qemu_protocol::publisher_subscription::PUBLISHER_COMMAND_BYTES
                    .checked_mul(2)?,
            )
    }
}

impl<Custody> SessionBody<Custody> {
    /// Returns atomic words only while this exact mapping remains retained.
    fn command_words(&self) -> Result<&[AtomicU64], OperationFailure> {
        if self.mapping_return_uncertain {
            return Err(OperationFailure::Geometry);
        }
        let address = self.mapping.ok_or(OperationFailure::Geometry)?;
        if !address.is_multiple_of(align_of::<AtomicU64>()) {
            return Err(OperationFailure::Geometry);
        }

        // SAFETY: construct_with journals the exact page-aligned, zero-filled
        // shared mapping before exposing this body. All mutable protocol words
        // are accessed atomically. This borrow prevents local unmapping, and
        // the containing Source retains its real remote mapping borrowers.
        Ok(unsafe {
            std::slice::from_raw_parts(
                address as *const AtomicU64,
                PUBLISHER_REGION_BYTES / size_of::<AtomicU64>(),
            )
        })
    }

    /// Publishes one already retained cohort and its immutable command once.
    ///
    /// No event or futex is rung here. A born offer is retained even if its
    /// publication CAS or ticket transition refuses. The caller must record
    /// its independent Original/cohort post before notification.
    pub(super) fn publish_command_offer(
        &mut self,
        publication: PublisherPublication,
    ) -> Result<PublisherLoanIdentity, OperationFailure> {
        let result = self.publish_command_offer_inner(publication);
        if let Err(first) = result {
            self.command.first.get_or_insert(first);
        }
        result
    }

    fn publish_command_offer_inner(
        &mut self,
        publication: PublisherPublication,
    ) -> Result<PublisherLoanIdentity, OperationFailure> {
        if self.command.first.is_some()
            || self.command.offer.is_some()
            || self.failure.is_some()
            || self.original_after.is_some()
            || !self.exported
            || publication.sequence != 2
            || publication.offer_generation != 1
            || publication.ticket_serial != 1
            || publication.permission != PublisherPermission::Borrowable
            || publication.command.is_none()
            || !publication.cohort.cohort_current
            || !(1..=4).contains(&publication.cohort.row_count)
            || publication.cohort.borrowed_mask != (1 << publication.cohort.row_count) - 1
            || publication.cohort.projected_mask != publication.cohort.borrowed_mask
            || publication.cohort.parents[..publication.cohort.row_count as usize]
                .iter()
                .any(|row| row.state != 0)
        {
            return Err(OperationFailure::Geometry);
        }
        let bytes = publication
            .encode()
            .map_err(|_| OperationFailure::Geometry)?;
        let purpose = self.purpose.ok_or(OperationFailure::Geometry)?;
        let binding = publication.cohort.binding;
        if purpose.capability != binding.cap
            || purpose.reservation != binding.reservation
            || purpose.account_generation != binding.account_generation
            || purpose.process_generation != binding.process_generation
        {
            return Err(OperationFailure::Geometry);
        }
        let issued = PublisherTicket {
            serial: publication.ticket_serial,
            phase: PublisherTicketPhase::Issued,
        }
        .encode()
        .map_err(|_| OperationFailure::Geometry)?;
        let words = self.command_words()?;
        if words[PUBLICATION_WORD].load(Ordering::SeqCst) != 0
            || words[TICKET_WORD].load(Ordering::SeqCst) != 0
        {
            return Err(OperationFailure::Geometry);
        }

        // The canonical journal receives every coordinate before the first
        // actual shared effect. Failure cannot recreate local birth privilege.
        self.command.offer = Some(RetainedOffer {
            publication,
            bytes,
            publication_attempted: true,
            publication_committed: false,
            ticket_attempted: false,
            ticket_issued: false,
            withdrawal_attempted: false,
            withdrawn: false,
            revocation_attempted: false,
            revoked: false,
        });
        let offer = self
            .command
            .offer
            .as_ref()
            .ok_or(OperationFailure::Geometry)?;
        let words = self.command_words()?;
        words[PUBLICATION_WORD]
            .compare_exchange(0, 1_u64.to_be(), Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| OperationFailure::Geometry)?;
        for (index, chunk) in offer.bytes.chunks_exact(8).enumerate().skip(1) {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(chunk);
            words[PUBLICATION_WORD + index].store(u64::from_ne_bytes(bytes), Ordering::SeqCst);
        }
        words[PUBLICATION_WORD].store(publication.sequence.to_be(), Ordering::SeqCst);
        let offer = self
            .command
            .offer
            .as_mut()
            .ok_or(OperationFailure::Geometry)?;
        offer.publication_committed = true;
        offer.ticket_attempted = true;

        self.command_words()?[TICKET_WORD]
            .compare_exchange(0, issued.to_be(), Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| OperationFailure::Geometry)?;
        self.command
            .offer
            .as_mut()
            .ok_or(OperationFailure::Geometry)?
            .ticket_issued = true;

        Ok(PublisherLoanIdentity {
            ticket_serial: publication.ticket_serial,
            offer_generation: publication.offer_generation,
            command_sequence: publication.sequence,
        })
    }

    /// Attempts only the exact Issued-to-Withdrawn race, without waiting.
    ///
    /// A receiver that already acquired the ticket wins. Neither that outcome
    /// nor a successful withdrawal proves Source loans or mapping children
    /// returned; those real borrowers remain in the containing Source.
    pub(super) fn withdraw_command_offer(&mut self) -> Result<bool, OperationFailure> {
        let result = self.withdraw_command_offer_inner();
        if let Err(first) = result {
            self.command.first.get_or_insert(first);
        }
        result
    }

    fn withdraw_command_offer_inner(&mut self) -> Result<bool, OperationFailure> {
        let offer = self
            .command
            .offer
            .as_mut()
            .ok_or(OperationFailure::Geometry)?;
        if !offer.publication_attempted
            || !offer.publication_committed
            || !offer.ticket_attempted
            || !offer.ticket_issued
            || offer.withdrawal_attempted
            || !(1..=PUBLISHER_TICKET_MAX_SERIAL).contains(&offer.publication.ticket_serial)
        {
            return Err(OperationFailure::Geometry);
        }
        let serial = offer.publication.ticket_serial;
        let issued = PublisherTicket {
            serial,
            phase: PublisherTicketPhase::Issued,
        }
        .encode()
        .map_err(|_| OperationFailure::Geometry)?;
        let withdrawn = PublisherTicket {
            serial,
            phase: PublisherTicketPhase::Withdrawn,
        }
        .encode()
        .map_err(|_| OperationFailure::Geometry)?;
        offer.withdrawal_attempted = true;

        let result = self.command_words()?[TICKET_WORD].compare_exchange(
            issued.to_be(),
            withdrawn.to_be(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        let won = match result {
            Ok(_) => true,
            Err(actual) => {
                let actual = PublisherTicket::decode(u64::from_be(actual))
                    .map_err(|_| OperationFailure::Geometry)?;
                if actual.serial != serial
                    || !matches!(
                        actual.phase,
                        PublisherTicketPhase::Acquired | PublisherTicketPhase::ReturnRequested
                    )
                {
                    return Err(OperationFailure::Geometry);
                }
                false
            }
        };
        self.command
            .offer
            .as_mut()
            .ok_or(OperationFailure::Geometry)?
            .withdrawn = won;
        Ok(won)
    }

    /// Revokes an existing offer without changing its immutable command.
    ///
    /// The old command identity remains in the retained journal. The next wire
    /// sequence makes existing recipients' exact-publication posts refuse;
    /// permission also prevents a new receiver from acquiring the offer. This
    /// physical change neither consumes the ticket nor returns any Source loan.
    pub(super) fn revoke_command_offer(&mut self) -> Result<(), OperationFailure> {
        let result = self.revoke_command_offer_inner();
        if let Err(first) = result {
            self.command.first.get_or_insert(first);
        }
        result
    }

    fn revoke_command_offer_inner(&mut self) -> Result<(), OperationFailure> {
        let offer = self
            .command
            .offer
            .as_mut()
            .ok_or(OperationFailure::Geometry)?;
        if offer.revocation_attempted {
            return if offer.revoked {
                Ok(())
            } else {
                Err(OperationFailure::Geometry)
            };
        }
        if !offer.publication_committed {
            return Err(OperationFailure::Geometry);
        }
        let previous = offer.publication.sequence;
        let sequence = previous
            .checked_add(2)
            .filter(|sequence| *sequence < u64::MAX)
            .ok_or(OperationFailure::Geometry)?;

        // Once attempted, an uncertain seqlock transition is retained rather
        // than retried. The actual born command and ticket are never replaced.
        offer.revocation_attempted = true;
        let words = self.command_words()?;
        words[PUBLICATION_WORD]
            .compare_exchange(
                previous.to_be(),
                (sequence - 1).to_be(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| OperationFailure::Geometry)?;
        words[PUBLICATION_WORD + 3].store(
            (PublisherPermission::Revoked as u64).to_be(),
            Ordering::SeqCst,
        );
        words[PUBLICATION_WORD].store(sequence.to_be(), Ordering::SeqCst);
        self.command
            .offer
            .as_mut()
            .ok_or(OperationFailure::Geometry)?
            .revoked = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
