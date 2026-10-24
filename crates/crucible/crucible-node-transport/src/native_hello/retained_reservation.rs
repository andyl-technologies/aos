//! Retains native Hello bank allocation and journal construction in one capsule.
//!
//! The empty capsule precedes fallible reservation. A successful bank moves into
//! one shared allocation, then the journal retains that same bank. Actual pointer
//! equality establishes the sole alias discount in the backing census.

use super::*;
use crate::retained_metadata::requested_storage::shared_header_storage_data;
use std::mem::{align_of, size_of};

/// Retains the actual native Hello constructor, including failed bank partials.
pub(crate) struct OriginalNativeHelloReservation {
    owner: ProtocolCaptureOwner,
    raw_bank: Option<OriginalFrameReservation>,
    shared_bank: Option<Rc<RefCell<OriginalFrameReservation>>>,
    journal: Option<OriginalNativeHelloJournal>,
    complete: bool,
}

impl OriginalNativeHelloReservation {
    /// Installs the capsule before reserving the actual two-direction bank.
    ///
    /// The caller independently admits the defining construction row and keeps
    /// this destination on either outcome. This reserves bytes, not a connection,
    /// negotiated feature, bootstrap ACK or native execution permission.
    ///
    /// # Errors
    /// Refuses an occupied destination, invalid framing limits, reservation
    /// failure or changed creator. Every initialized partial remains retained.
    pub(crate) fn reserve_into_data(
        maximum_bytes: usize,
        maximum_nesting: usize,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        *output = Some(Self {
            owner: ProtocolCaptureOwner::new(),
            raw_bank: None,
            shared_bank: None,
            journal: None,
            complete: false,
        });
        let original = output.as_mut().ok_or_else(refused)?;
        original.owner.ensure_current()?;
        Self::construction_data(maximum_bytes, maximum_nesting)?;

        let framed_bytes = framed_bytes_data(maximum_bytes)?;
        OriginalFrameReservation::reserve_retained_into_data(
            framed_bytes,
            1,
            &mut original.raw_bank,
        )?;
        let bank = original.raw_bank.take().ok_or_else(refused)?;
        original.shared_bank = Some(Rc::new(RefCell::new(bank)));
        let bank = original.shared_bank.as_ref().ok_or_else(refused)?;
        original.journal = Some(OriginalNativeHelloJournal {
            bank: Rc::clone(bank),
            maximum_bytes,
            maximum_nesting,
            owner: ProtocolCaptureOwner::new(),
            attempted: false,
            received: false,
            write_started: false,
            failed: false,
        });
        original.owner.ensure_current()?;
        original.complete = true;
        Ok(())
    }

    /// Prices the actual literal backing and its shared bank allocation.
    ///
    /// The enclosing owner separately counts this capsule's inline layout.
    /// Parsing, negotiation and stream/exchange construction are separate rows.
    ///
    /// # Errors
    /// Refuses invalid Hello framing or checked requested-layout overflow.
    pub(crate) fn construction_data(
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<[usize; 3], ProviderError> {
        if !(1..=64).contains(&maximum_nesting) {
            return Err(refused());
        }
        let literals =
            OriginalNativeHelloJournal::reservation_requested_storage_data(maximum_bytes)?;
        let bank = OriginalFrameReservation::retained_reservation_requested_bytes_data(
            framed_bytes_data(maximum_bytes)?,
            1,
        )?;
        if bank != literals {
            return Err(refused());
        }
        let retained = shared_payload_data(literals)?;
        let transient = OriginalFrameReservation::retained_reservation_constructor_transient_data()
            .checked_add(size_of::<Self>())
            .and_then(|n| n.checked_add(size_of::<Option<Self>>()))
            .and_then(|n| n.checked_add(size_of::<RefCell<OriginalFrameReservation>>()))
            .and_then(|n| n.checked_add(size_of::<OriginalNativeHelloJournal>()))
            .ok_or_else(refused)?;
        Ok([retained, transient, Self::counter_scratch_data()])
    }

    /// Counts actual surviving raw and shared bank capacities exactly once.
    ///
    /// Distinct retained banks receive separate charges. Only the actual shared
    /// pointer equality between the capsule and journal permits deduplication.
    ///
    /// # Errors
    /// Refuses a foreign creator, an outstanding mutable bank borrow or overflow.
    pub(crate) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        let Self {
            owner,
            raw_bank,
            shared_bank,
            journal,
            complete: _,
        } = self;
        owner.ensure_current()?;
        let mut retained = raw_bank
            .as_ref()
            .map_or(0, OriginalFrameReservation::allocated_bytes);
        if let Some(bank) = shared_bank {
            retained = retained
                .checked_add(shared_bank_data(bank)?)
                .ok_or_else(refused)?;
        }
        if let Some(journal) = journal {
            journal.owner.ensure_current()?;
            if shared_bank
                .as_ref()
                .is_none_or(|bank| !Rc::ptr_eq(bank, &journal.bank))
            {
                retained = retained
                    .checked_add(shared_bank_data(&journal.bank)?)
                    .ok_or_else(refused)?;
            }
        }
        Ok(retained)
    }

    /// Lends the same completed journal without transferring its original bank.
    ///
    /// # Errors
    /// Refuses an incomplete constructor, absent journal, stale creator or callback.
    pub(crate) fn with_journal_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&OriginalNativeHelloJournal) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.owner.ensure_current()?;
        if !self.complete {
            return Err(refused());
        }
        let journal = self.journal.as_ref().ok_or_else(refused)?;
        journal.owner.ensure_current()?;
        let result = inspect(journal);
        let terminal = self
            .owner
            .ensure_current()
            .and_then(|()| journal.owner.ensure_current());
        let result = result?;
        terminal?;
        Ok(result)
    }

    /// Transfers the same completed journal into an already retained destination.
    ///
    /// The original shared bank stays here. The receiver must retain this
    /// destination through all later framing checks and count proven aliases.
    ///
    /// # Errors
    /// Refuses an occupied destination, incomplete reservation, missing journal
    /// or foreign creator. No allocation or I/O occurs.
    pub(super) fn transfer_journal_into_data(
        &mut self,
        output: &mut Option<OriginalNativeHelloJournal>,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if output.is_some() || !self.complete || self.journal.is_none() {
            return Err(refused());
        }
        self.journal
            .as_ref()
            .ok_or_else(refused)?
            .owner
            .ensure_current()?;
        *output = self.journal.take();
        Ok(())
    }

    /// Checks whether this actual reservation already counts the same bank.
    ///
    /// # Errors
    /// Refuses a foreign creator or journal owner.
    pub(super) fn counts_bank_data(
        &self,
        bank: &Rc<RefCell<OriginalFrameReservation>>,
    ) -> Result<bool, ProviderError> {
        self.owner.ensure_current()?;
        if self
            .shared_bank
            .as_ref()
            .is_some_and(|original| Rc::ptr_eq(original, bank))
        {
            return Ok(true);
        }
        if let Some(journal) = &self.journal {
            journal.owner.ensure_current()?;
            return Ok(Rc::ptr_eq(&journal.bank, bank));
        }
        Ok(false)
    }

    /// Lends a mutable journal exclusively for negative constructor fixtures.
    #[cfg(test)]
    pub(super) fn journal_mut_fixture_data(&mut self) -> Option<&mut OriginalNativeHelloJournal> {
        self.journal.as_mut()
    }

    /// Names actual reservation, shared-bank construction and census controls.
    pub(crate) fn counter_scratch_data() -> usize {
        OriginalFrameReservation::retained_reservation_counter_scratch_data()
            + size_of::<&mut Option<Self>>()
            + size_of::<&mut Self>()
            + size_of::<Option<&mut Self>>()
            + size_of::<&Self>()
            + size_of::<&OriginalFrameReservation>()
            + size_of::<Option<&OriginalFrameReservation>>()
            + size_of::<Rc<RefCell<OriginalFrameReservation>>>()
            + size_of::<&Rc<RefCell<OriginalFrameReservation>>>() * 3
            + size_of::<Option<&Rc<RefCell<OriginalFrameReservation>>>>()
            + size_of::<std::cell::Ref<'static, OriginalFrameReservation>>()
            + size_of::<
                Result<std::cell::Ref<'static, OriginalFrameReservation>, std::cell::BorrowError>,
            >()
            + size_of::<&OriginalNativeHelloJournal>()
            + size_of::<Option<&OriginalNativeHelloJournal>>()
            + size_of::<ProtocolCaptureOwner>() * 2
            + size_of::<[usize; 3]>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<usize>() * 9
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>() * 3
            + size_of::<Result<(), ProviderError>>() * 4
    }

    /// Names separate journal inspection and its actual Copy result controls.
    pub(crate) fn journal_loan_counter_scratch_data<R: Copy>() -> usize {
        Self::counter_scratch_data()
            + size_of::<R>()
            + size_of::<Result<R, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

fn framed_bytes_data(maximum_bytes: usize) -> Result<usize, ProviderError> {
    maximum_bytes
        .checked_add(4)
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(refused)
}

fn shared_payload_data(backing: usize) -> Result<usize, ProviderError> {
    shared_header_storage_data(1, align_of::<RefCell<OriginalFrameReservation>>())?
        .checked_add(size_of::<RefCell<OriginalFrameReservation>>())
        .and_then(|n| n.checked_add(backing))
        .ok_or_else(refused)
}

fn shared_bank_data(bank: &Rc<RefCell<OriginalFrameReservation>>) -> Result<usize, ProviderError> {
    let bank = bank.try_borrow().map_err(|_| refused())?;
    shared_payload_data(bank.allocated_bytes())
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("retained native Hello reservation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_framing_retains_the_empty_constructor_and_closes_retry() {
        let mut output = None;
        assert!(OriginalNativeHelloReservation::reserve_into_data(0, 64, &mut output).is_err());
        let original = output.as_ref().unwrap();
        assert_eq!(original.retained_backing_data().unwrap(), 0);
        assert!(original.with_journal_data(|_| Ok(())).is_err());
        assert!(OriginalNativeHelloReservation::reserve_into_data(64, 64, &mut output).is_err());
        assert!(!output.as_ref().unwrap().complete);
    }

    #[test]
    fn exact_quote_covers_the_same_two_direction_bank_and_actual_shared_header() {
        for maximum in [1, 65_536, MAXIMUM_HELLO_BYTES] {
            let row = OriginalNativeHelloReservation::construction_data(maximum, 64).unwrap();
            let mut output = None;
            OriginalNativeHelloReservation::reserve_into_data(maximum, 64, &mut output).unwrap();

            let original = output.as_ref().unwrap();
            assert_eq!(original.retained_backing_data().unwrap(), row[0]);
            assert!(original.raw_bank.is_none());
            let journal = original.journal.as_ref().unwrap();
            assert!(Rc::ptr_eq(
                original.shared_bank.as_ref().unwrap(),
                &journal.bank
            ));
            assert!(journal.original_frames().frames().next().is_none());
            assert!(
                OriginalNativeHelloReservation::reserve_into_data(maximum, 64, &mut output)
                    .is_err()
            );
        }
    }

    #[test]
    fn census_counts_distinct_journal_banks_and_refuses_an_outstanding_mutable_borrow() {
        let mut output = None;
        OriginalNativeHelloReservation::reserve_into_data(64, 64, &mut output).unwrap();
        let original = output.as_mut().unwrap();
        let shared = Rc::clone(original.shared_bank.as_ref().unwrap());
        let first = original.retained_backing_data().unwrap();

        let borrowed = shared.borrow_mut();
        assert!(original.retained_backing_data().is_err());
        drop(borrowed);
        assert_eq!(original.retained_backing_data().unwrap(), first);

        original.journal = Some(OriginalNativeHelloJournal::reserve(128, 64).unwrap());
        let separate =
            shared_payload_data(original.journal.as_ref().unwrap().allocated_bytes()).unwrap();
        assert_eq!(original.retained_backing_data().unwrap(), first + separate);
    }
}
