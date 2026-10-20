//! Preserves the actual Hello journal and its original literal bank as DATA.
//!
//! ```text
//! ["source-private.native-Hello-history/17",maximum_bytes,maximum_nesting,
//!  attempted,received,write_started,failed,compact_original_frames]
//! ```
//!
//! The historical owner has no stream, registrar or negotiation continuation.

use super::*;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::retained_metadata::{
    MetadataObserver, aliases::MetadataSharedKind, records::MetadataRecordKind,
};
use crate::transport::{DecodedCompactOriginalFrames, ValidatedCompactOriginalFrames};
use serde::{Serialize, Serializer};

struct HelloHistory<'a>(&'a OriginalNativeHelloJournal);

impl OriginalNativeHelloJournal {
    /// Checks an actual retained Hello-bank edge without redoing negotiation.
    ///
    /// # Errors
    /// Refuses a foreign original creator or another actual bank allocation.
    pub(crate) fn authenticate_settled17_bank_data(
        &self,
        actual: &Rc<RefCell<OriginalFrameReservation>>,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if !Rc::ptr_eq(&self.bank, actual) {
            return Err(invalid());
        }
        Ok(())
    }

    /// Borrows all original partial flags and literal bytes without new rights.
    ///
    /// # Errors
    /// Refuses a foreign originating owner or a currently borrowed frame bank.
    pub(crate) fn borrowed_settled17_data(&self) -> Result<impl Serialize + '_, ProviderError> {
        self.owner.ensure_current()?;
        self.bank.try_borrow().map_err(|_| invalid())?;
        Ok(HelloHistory(self))
    }

    /// Records the original bank's real shared edge and complete capacities.
    ///
    /// # Errors
    /// Refuses foreign origin, a borrowed bank or exhausted metadata admission.
    pub(crate) fn observe_settled17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        observer.observe(&self.maximum_bytes)?;
        observer.observe(&self.maximum_nesting)?;
        observer.observe(&self.attempted)?;
        observer.observe(&self.received)?;
        observer.observe(&self.write_started)?;
        observer.observe(&self.failed)?;
        observer.shared_original(MetadataSharedKind::FrameBank, self.bank.as_ref())?;
        self.bank
            .try_borrow()
            .map_err(|_| invalid())?
            .observe_owned11_metadata(observer)
    }
}

impl Serialize for HelloHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .owner
            .ensure_current()
            .map_err(serde::ser::Error::custom)?;
        let OriginalNativeHelloJournal {
            bank,
            maximum_bytes,
            maximum_nesting,
            owner: _,
            attempted,
            received,
            write_started,
            failed,
        } = self.0;
        let bank = bank.try_borrow().map_err(serde::ser::Error::custom)?;
        (
            "source-private.native-Hello-history/17",
            maximum_bytes,
            maximum_nesting,
            attempted,
            received,
            write_started,
            failed,
            bank.protocol_view_with_encoding(true),
        )
            .serialize(serializer)
    }
}

/// Owns the independently retained historical flags and complete literal bank.
pub(crate) struct HistoricalNativeHello17 {
    pub(crate) maximum_bytes: usize,
    pub(crate) maximum_nesting: usize,
    pub(crate) attempted: bool,
    pub(crate) received: bool,
    pub(crate) write_started: bool,
    pub(crate) failed: bool,
    pub(crate) frames: DecodedCompactOriginalFrames,
    bank_group: usize,
}

impl HistoricalNativeHello17 {
    /// Returns this actual same-pass Hello-bank group without a live Rc.
    pub(crate) const fn group_id_data(&self) -> usize {
        self.bank_group
    }
}

impl HistoricalNativeHello17 {
    /// Checks all fields and returns the real bank group in the validation pass.
    ///
    /// # Errors
    /// Refuses malformed flags, frame grammar, capacity rows or alias definitions.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, usize), ProviderError> {
        let mut fields = Fields::array(input)?;
        if plain_string(next(&mut fields)?)? != "source-private.native-Hello-history/17" {
            return Err(invalid());
        }
        let maximum_bytes = ledger
            .read::<usize>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
        let maximum_nesting = ledger
            .read::<usize>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
        let attempted = ledger
            .read::<bool>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
        let received = ledger
            .read::<bool>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
        let write_started = ledger
            .read::<bool>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
        let failed = ledger
            .read::<bool>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
        let frame_view = next(&mut fields)?;
        fields.finish()?;
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_HELLO_BYTES || maximum_nesting == 0 {
            return Err(invalid());
        }
        let start = ledger.rows.encoded_position();
        let layout = std::mem::size_of::<RefCell<OriginalFrameReservation>>();
        if ledger.row_aligned(
            MetadataRecordKind::Shared,
            1,
            std::mem::align_of::<RefCell<OriginalFrameReservation>>(),
        )? != layout
        {
            return Err(invalid());
        }
        let plan = read_literal_data(frame_view, ledger)?;
        plan.native17_target_data(ledger)?;
        let rows = ledger.rows.encoded_between(start)?;
        let bank_group = ledger.shared(MetadataSharedKind::FrameBank, layout, frame_view, rows)?;
        if !build {
            return Ok((None, bank_group));
        }
        Ok((
            Some(Self {
                maximum_bytes,
                maximum_nesting,
                attempted,
                received,
                write_started,
                failed,
                frames: plan.reconstruct()?,
                bank_group,
            }),
            bank_group,
        ))
    }
}

impl HistoricalType for HistoricalNativeHello17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|result| result.0)
    }
}

pub(crate) fn read_literal_data<'a>(
    input: &'a [u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<ValidatedCompactOriginalFrames<'a>, ProviderError> {
    let plan = ValidatedCompactOriginalFrames::validate(
        input,
        ledger.limits.maximum_input_bytes,
        ledger.maximum_literal_bytes,
    )?;
    let mut fields = Fields::array(input)?;
    for _ in 0..4 {
        next(&mut fields)?;
    }
    let bytes = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let slots = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    if ledger.row_aligned(MetadataRecordKind::Vector, 1, 1)? != bytes
        || ledger.row_aligned(
            MetadataRecordKind::Vector,
            crate::transport::original_frames::original_frame_slot_layout(),
            crate::transport::original_frames::original_frame_slot_alignment_data(),
        )? != slots
    {
        return Err(invalid());
    }
    ledger.literal_bytes = ledger
        .literal_bytes
        .checked_add(plan.allocated_bytes())
        .ok_or_else(invalid)?;
    if ledger.literal_bytes > ledger.maximum_literal_bytes {
        return Err(invalid());
    }
    Ok(plan)
}

fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next_value()?.ok_or_else(invalid)
}
