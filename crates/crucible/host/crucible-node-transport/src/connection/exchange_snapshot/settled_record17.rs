//! Reads actual complete and partial exchange records as historical DATA.
//!
//! The existing exchange wire view remains unchanged. Retained original
//! envelopes, canonical buffers and decoder caches remain independent owners;
//! partial send/receive progress never becomes an implicit completed exchange.

use super::settled17::HistoricalReceivedFrame17;
use super::*;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string, unsigned,
};
use crate::retained_metadata::{
    MetadataObserver, aliases::MetadataSharedKind, records::MetadataRecordKind,
};

/// Retains an exchange's independent planned and decoded historical fields.
pub(crate) struct HistoricalExchangeRecord17 {
    pub(crate) originals: Vec<Envelope>,
    pub(crate) canonical: Vec<Vec<u8>>,
    pub(crate) acknowledgements: Vec<HistoricalReceivedFrame17>,
    pub(crate) sent: usize,
    pub(crate) original_slots: Vec<Option<usize>>,
    original_actor: Option<(usize, usize)>,
}

impl ExchangeRecord {
    /// Appends every independent actual exchange field without requiring success.
    ///
    /// # Errors
    /// Refuses a foreign original actor, unsupported cache or exhausted bank.
    pub(crate) fn observe_settled17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            originals,
            canonical,
            acknowledgements,
            sent,
            original_slots,
            original_actor,
        } = self;
        if let Some((actor, frames)) = original_actor {
            actor.ensure_current()?;
            observer.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
            observer.shared_original(MetadataSharedKind::FrameBank, frames.as_ref())?;
        }
        observer.observe(originals)?;
        observe_original_canonical_byte_banks(canonical, observer)?;
        observer.vector::<ReceivedFrame>(acknowledgements.capacity())?;
        for frame in acknowledgements {
            frame.observe_settled17_metadata(observer)?;
        }
        observer.observe(sent)?;
        observer.observe(original_slots)
    }
}

impl HistoricalExchangeRecord17 {
    /// Reads unchanged original exchange framing and exact capacity records.
    ///
    /// # Errors
    /// Refuses malformed fields, capacity disagreement or unresolved actor edges.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|result| result.0)
    }

    /// Returns actual actor/frame groups even in the allocation-free pass.
    ///
    /// # Errors
    /// Refuses malformed fields, capacity disagreement or unresolved actor edges.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, Option<(usize, usize)>), ProviderError> {
        let mut fields = Fields::object(input)?;
        let originals = fields.named("originals")?;
        let originals_capacity = quantity(fields.named("originals_capacity")?)?;
        let canonical = fields.named("canonical")?;
        let canonical_capacity = quantity(fields.named("canonical_capacity")?)?;
        let acknowledgements = fields.named("acknowledgements")?;
        let acknowledgements_capacity = quantity(fields.named("acknowledgements_capacity")?)?;
        let sent = quantity(fields.named("sent")?)?;
        let slots = fields.named("original_slots")?;
        let slots_capacity = quantity(fields.named("original_slots_capacity")?)?;
        let actor = fields.named("original_actor")?;
        fields.finish()?;

        let original_actor = if actor == b"null" {
            None
        } else {
            if plain_string(actor)? != "same-original-endpoint" {
                return Err(invalid());
            }
            let actor = shared_reference_data::<crate::protocol_snapshot::ProtocolCaptureOwner>(
                ledger,
                MetadataSharedKind::ProtocolOwner,
            )?;
            let frames = shared_reference_data::<
                std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>,
            >(ledger, MetadataSharedKind::FrameBank)?;
            Some((actor, frames))
        };
        expect_vector_data::<Envelope>(ledger, originals_capacity)?;
        let (original_count, originals) =
            read_items_data::<Envelope>(originals, ledger, originals_capacity, build)?;
        expect_vector_data::<Vec<u8>>(ledger, canonical_capacity)?;
        let mut cursor = Fields::array(canonical)?;
        ledger.native17_target_vector_data::<Vec<u8>>(canonical_capacity)?;
        let mut canonical = reserve_data::<Vec<u8>>(canonical_capacity, build)?;
        let mut canonical_count = 0usize;
        while let Some(item) = cursor.next_value()? {
            canonical_count = canonical_count.checked_add(1).ok_or_else(invalid)?;
            if canonical_count > canonical_capacity {
                return Err(invalid());
            }
            let mut bank = Fields::array(item)?;
            let bytes = bank.next_value()?.ok_or_else(invalid)?;
            let capacity = quantity(bank.next_value()?.ok_or_else(invalid)?)?;
            bank.finish()?;
            expect_vector_data::<u8>(ledger, capacity)?;
            let (_, value) = read_items_data::<u8>(bytes, ledger, capacity, build)?;
            if let Some(value) = value {
                canonical.push(value);
            }
        }
        cursor.finish()?;
        expect_vector_data::<ReceivedFrame>(ledger, acknowledgements_capacity)?;
        let (_, acknowledgements) = read_items_data::<HistoricalReceivedFrame17>(
            acknowledgements,
            ledger,
            acknowledgements_capacity,
            build,
        )?;
        expect_vector_data::<Option<usize>>(ledger, slots_capacity)?;
        let (slot_count, original_slots) =
            read_items_data::<Option<usize>>(slots, ledger, slots_capacity, build)?;
        if canonical_count > original_count || slot_count > canonical_count || sent > slot_count {
            return Err(invalid());
        }
        if !build {
            return Ok((None, original_actor));
        }
        Ok((
            Some(Self {
                originals: originals.ok_or_else(invalid)?,
                canonical,
                acknowledgements: acknowledgements.ok_or_else(invalid)?,
                sent,
                original_slots: original_slots.ok_or_else(invalid)?,
                original_actor,
            }),
            original_actor,
        ))
    }

    /// Checks every retained original slot against the same current frame bank.
    ///
    /// Unsent originals remain planned DATA. A slot marked sent must have its
    /// complete physical I/O; this does not infer acknowledgement or success.
    ///
    /// # Errors
    /// Refuses changed actor/bank groups, missing slots, mismatched literal bytes
    /// or send progress that lacks its original complete framed proposal.
    pub(crate) fn authenticate_connection17_data(
        &self,
        connection: &crate::connection::HistoricalCurrentNativeConnection17,
    ) -> Result<(), ProviderError> {
        let groups = connection.group_ids_data();
        let Some(actual) = self.original_actor else {
            if self.sent != 0 || self.original_slots.iter().any(Option::is_some) {
                return Err(invalid());
            }
            return Ok(());
        };
        if actual != (groups.actor, groups.frames) {
            return Err(invalid());
        }
        for (index, slot) in self.original_slots.iter().enumerate() {
            let Some(slot) = slot else {
                if index < self.sent {
                    return Err(invalid());
                }
                continue;
            };
            let frame = connection.frames.frames.frame(*slot).ok_or_else(invalid)?;
            let canonical = self.canonical.get(index).ok_or_else(invalid)?;
            let original = self.originals.get(index).ok_or_else(invalid)?;
            let header: [u8; 4] = frame
                .bytes
                .get(..4)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?;
            if frame.direction != crate::transport::original_frames::FrameDirection::Outgoing
                || usize::try_from(u32::from_be_bytes(header)).map_err(|_| invalid())?
                    != canonical.len()
                || frame.bytes.get(4..) != Some(canonical.as_slice())
                || (index < self.sent
                    && (!frame.complete || frame.transferred != frame.bytes.len()))
            {
                return Err(invalid());
            }
            crate::protocol_snapshot::owned11::correspondence::envelope(original, canonical)?;
        }
        Ok(())
    }

    /// Returns the real same-pass actor and frame groups when they were present.
    pub(crate) const fn group_ids_data(&self) -> Option<(usize, usize)> {
        self.original_actor
    }

    /// Counts defining reader, borrowed cursor and result headers.
    pub(crate) const fn settled17_counter_scratch_data() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<Fields<'static>>()
            + std::mem::size_of::<Result<Option<Self>, ProviderError>>()
    }
}

impl HistoricalType for HistoricalExchangeRecord17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_data(input, ledger, build)
    }
}

fn quantity(input: &[u8]) -> Result<usize, ProviderError> {
    usize::try_from(unsigned(input)?).map_err(|_| invalid())
}

fn expect_vector_data<T>(
    ledger: &mut Ledger<'_, '_, '_>,
    expected: usize,
) -> Result<(), ProviderError> {
    if ledger.row_aligned(
        MetadataRecordKind::Vector,
        std::mem::size_of::<T>(),
        std::mem::align_of::<T>(),
    )? != expected
    {
        return Err(invalid());
    }
    Ok(())
}

fn reserve_data<T>(capacity: usize, build: bool) -> Result<Vec<T>, ProviderError> {
    let mut values = Vec::new();
    if build {
        values.try_reserve_exact(capacity).map_err(|_| invalid())?;
        if values.capacity() != capacity {
            return Err(invalid());
        }
    }
    Ok(values)
}

fn read_items_data<T: HistoricalType>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    capacity: usize,
    build: bool,
) -> Result<(usize, Option<Vec<T>>), ProviderError> {
    ledger.native17_target_vector_data::<T>(capacity)?;
    let mut values = reserve_data(capacity, build)?;
    let mut cursor = Fields::array(input)?;
    let mut count = 0usize;
    while let Some(item) = cursor.next_value()? {
        count = count.checked_add(1).ok_or_else(invalid)?;
        if count > capacity {
            return Err(invalid());
        }
        if let Some(value) = ledger.read::<T>(item, build)? {
            values.push(value);
        }
    }
    cursor.finish()?;
    Ok((count, build.then_some(values)))
}

fn shared_reference_data<T>(
    ledger: &mut Ledger<'_, '_, '_>,
    kind: MetadataSharedKind,
) -> Result<usize, ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, std::mem::align_of::<T>())?
        != std::mem::size_of::<T>()
    {
        return Err(invalid());
    }
    ledger.shared_reference(kind, std::mem::size_of::<T>())
}
