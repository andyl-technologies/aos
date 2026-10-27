//! Reserves complete owned11 banks inside their retained destination.
//!
//! `Some` means an attempt owns its partial capacity. Only `Ok(())` reports a
//! complete reservation; neither outcome supplies capture or native authority.

use super::*;
use crate::transport::original_frames::OriginalFrameReservation;
use std::mem::size_of;

impl ProtocolSnapshotReservation {
    /// Retains the snapshot owner before allocating any complete owned11 bank.
    ///
    /// Every child owner enters this destination before its first allocation.
    /// On refusal the caller keeps this same destination, its partial capacity
    /// and its error. An occupied destination cannot be retried. The caller may
    /// publish a complete reservation only after this method returns `Ok(())`.
    ///
    /// The constructor allocates DATA storage only. Installed source-profile,
    /// process, schema and native admission remain separate checks.
    ///
    /// # Errors
    /// Refuses an occupied destination, invalid positive limits, checked layout
    /// overflow, allocation failure or actual capacity beyond its exact quote.
    pub fn reserve_complete_owned11_into(
        maximum: usize,
        history_bytes: usize,
        lifetime_frames: usize,
        maximum_metadata_rows: usize,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        let requested = Self::original_owned11_reservation_requested_storage_data(
            maximum,
            history_bytes,
            lifetime_frames,
            maximum_metadata_rows,
        )?;
        Self::reserve_complete_owned11_with_backing_data(
            maximum,
            history_bytes,
            lifetime_frames,
            maximum_metadata_rows,
            requested,
            output,
        )
    }

    fn reserve_complete_owned11_with_backing_data(
        maximum: usize,
        history_bytes: usize,
        lifetime_frames: usize,
        maximum_metadata_rows: usize,
        admitted_bytes: usize,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(ProviderError::Conflict(
                "owned11 snapshot reservation already attempted",
            ));
        }
        Self::original_owned11_reservation_requested_storage_data(
            maximum,
            history_bytes,
            lifetime_frames,
            maximum_metadata_rows,
        )?;

        *output = Some(Self {
            bytes: Vec::new(),
            maximum,
            compact: true,
            owned11_records: None,
            owned11_aliases: None,
            original_assigned_cut: None,
            original_restore_cut: None,
            original_hello: None,
            complete: false,
            literal: None,
            codec: None,
            issuer: None,
        });
        let bank = output.as_mut().ok_or_else(exhausted)?;

        bank.owned11_records = Some(MetadataRecordBank::unallocated(maximum_metadata_rows)?);
        let record_bytes = MetadataRecordBank::reservation_requested_bytes(maximum_metadata_rows)?;
        require_remaining(bank, admitted_bytes, record_bytes)?;
        bank.owned11_records
            .as_mut()
            .ok_or_else(exhausted)?
            .reserve_retained_data()?;

        bank.owned11_aliases = Some(MetadataAliasBank::unallocated(maximum_metadata_rows)?);
        let alias_bytes = MetadataAliasBank::reservation_requested_bytes(maximum_metadata_rows)?;
        require_remaining(bank, admitted_bytes, alias_bytes)?;
        bank.owned11_aliases
            .as_mut()
            .ok_or_else(exhausted)?
            .reserve_retained_data()?;

        require_remaining(bank, admitted_bytes, maximum)?;
        bank.bytes
            .try_reserve_exact(maximum)
            .map_err(|_| exhausted())?;
        if bank.bytes.capacity() > maximum {
            return Err(exhausted());
        }

        let literal_bytes = OriginalFrameReservation::retained_reservation_requested_bytes_data(
            history_bytes,
            lifetime_frames,
        )?;
        require_remaining(bank, admitted_bytes, literal_bytes)?;
        OriginalFrameReservation::reserve_retained_into_data(
            history_bytes,
            lifetime_frames,
            &mut bank.literal,
        )?;
        if bank.allocated_bytes() > admitted_bytes {
            return Err(exhausted());
        }
        Ok(())
    }

    /// Quotes the genuine retained reservation and its constructor work.
    ///
    /// The tuple contains requested backing R, concrete constructor T and fixed
    /// controls S. R forwards the same defining four backing families used by
    /// the ordinary owned11 reservation. The destination header and enclosing
    /// owner allocation remain separate retained terms. Actual capacities are
    /// checked by the retained constructor and remain owned on refusal.
    ///
    /// This allocation-free DATA quote grants no capture, source or native
    /// permission. The enclosing caller admits all simultaneous owners first.
    ///
    /// # Errors
    /// Refuses the same constructor limits or checked layout overflow.
    pub fn owned11_retained_reservation_construction_data(
        maximum: usize,
        history_bytes: usize,
        lifetime_frames: usize,
        maximum_metadata_rows: usize,
    ) -> Result<(usize, usize, usize), ProviderError> {
        let retained = Self::original_owned11_reservation_requested_storage_data(
            maximum,
            history_bytes,
            lifetime_frames,
            maximum_metadata_rows,
        )?;
        let transient = size_of::<Self>()
            .checked_add(size_of::<Option<Self>>())
            .and_then(|bytes| bytes.checked_add(size_of::<Vec<u8>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<MetadataRecordBank>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Option<MetadataRecordBank>>()))
            .and_then(|bytes| {
                bytes.checked_add(size_of::<Result<MetadataRecordBank, ProviderError>>())
            })
            .and_then(|bytes| bytes.checked_add(size_of::<MetadataAliasBank>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Option<MetadataAliasBank>>()))
            .and_then(|bytes| {
                bytes.checked_add(size_of::<Result<MetadataAliasBank, ProviderError>>())
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    OriginalFrameReservation::retained_reservation_constructor_transient_data(),
                )
            })
            .ok_or_else(exhausted)?;
        Ok((
            retained,
            transient,
            Self::owned11_retained_reservation_counter_scratch_data(),
        ))
    }

    /// Names fixed controls before quoting or constructing retained owned11 banks.
    ///
    /// This covers direct constructor/quote views and the sequential defining
    /// record, alias and literal reservation controls. Enclosing source-owner,
    /// callbacks and full capture/serialization work have separate rows.
    pub fn owned11_retained_reservation_counter_scratch_data() -> usize {
        // Public four limits/requested bytes; inner five limits and three
        // child extents; remaining-check arguments/local; existing four-limit
        // backing quote plus alias layout and its three nested checked values;
        // both defining metadata reservation allowance/requested/layout controls;
        // construction quote's four limits plus R/T/S result coordinates.
        size_of::<usize>() * (5 + 8 + 3 + 8 + 9 + 7)
            + size_of::<&mut Option<Self>>() * 2
            + size_of::<&mut Self>()
            + size_of::<&Self>()
            + size_of::<Option<&mut Self>>()
            + size_of::<Result<&mut Self, ProviderError>>()
            + size_of::<&mut MetadataRecordBank>()
            + size_of::<Option<&mut MetadataRecordBank>>()
            + size_of::<Result<&mut MetadataRecordBank, ProviderError>>()
            + size_of::<&mut MetadataAliasBank>()
            + size_of::<Option<&mut MetadataAliasBank>>()
            + size_of::<Result<&mut MetadataAliasBank, ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(usize, usize, usize), ProviderError>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<std::collections::TryReserveError>()
            + size_of::<Result<(), ProviderError>>()
            + OriginalFrameReservation::retained_reservation_counter_scratch_data()
    }
}

fn require_remaining(
    bank: &ProtocolSnapshotReservation,
    admitted_bytes: usize,
    requested: usize,
) -> Result<(), ProviderError> {
    let remaining = admitted_bytes
        .checked_sub(bank.allocated_bytes())
        .ok_or_else(exhausted)?;
    if requested > remaining {
        return Err(exhausted());
    }
    Ok(())
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("retained owned11 snapshot reservation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_retained_constructor_matches_defining_backing_quote() -> Result<(), ProviderError> {
        let (retained, transient, scratch) =
            ProtocolSnapshotReservation::owned11_retained_reservation_construction_data(
                1024, 512, 2, 7,
            )?;
        assert!(transient > size_of::<ProtocolSnapshotReservation>());
        assert!(scratch > 0);
        assert_eq!(
            retained,
            ProtocolSnapshotReservation::original_owned11_reservation_requested_storage_data(
                1024, 512, 2, 7,
            )?
        );

        let mut output = None;
        ProtocolSnapshotReservation::reserve_complete_owned11_into(1024, 512, 2, 7, &mut output)?;
        let bank = output.as_ref().ok_or_else(exhausted)?;
        let ordinary = ProtocolSnapshotReservation::reserve_complete_owned11(1024, 512, 2, 7)?;
        assert_eq!(bank.allocated_bytes(), retained);
        assert_eq!(
            bank.original_allocation_facts()?,
            ordinary.original_allocation_facts()?
        );
        assert_eq!(
            bank.original_alias_allocation_facts()?,
            ordinary.original_alias_allocation_facts()?
        );
        assert!(bank.compact);
        assert!(!bank.complete);
        assert!(bank.issuer.is_none() && bank.codec.is_none());
        assert_eq!(
            bank.owned11_records
                .as_ref()
                .ok_or_else(exhausted)?
                .capacity_rows(),
            7
        );
        assert_eq!(
            bank.owned11_aliases
                .as_ref()
                .ok_or_else(exhausted)?
                .allocation_facts()
                .row_capacity,
            7
        );
        assert_eq!(
            bank.literal
                .as_ref()
                .ok_or_else(exhausted)?
                .snapshot_allocation_facts()
                .descriptor_capacity,
            4
        );
        Ok(())
    }

    #[test]
    fn late_literal_refusal_keeps_completed_metadata_and_encoded_backings()
    -> Result<(), ProviderError> {
        let required =
            ProtocolSnapshotReservation::original_owned11_reservation_requested_storage_data(
                1024, 512, 2, 7,
            )?;
        let mut output = None;
        assert!(
            ProtocolSnapshotReservation::reserve_complete_owned11_with_backing_data(
                1024,
                512,
                2,
                7,
                required - 1,
                &mut output,
            )
            .is_err()
        );
        let bank = output.as_ref().ok_or_else(exhausted)?;
        assert_eq!(bank.bytes.capacity(), 1024);
        assert!(bank.literal.is_none());
        let record_bytes = bank
            .owned11_records
            .as_ref()
            .ok_or_else(exhausted)?
            .allocated_bytes();
        let alias_bytes = bank
            .owned11_aliases
            .as_ref()
            .ok_or_else(exhausted)?
            .allocated_bytes();
        assert!(record_bytes > 0 && alias_bytes > 0);
        assert_eq!(bank.allocated_bytes(), 1024 + record_bytes + alias_bytes);
        assert!(!bank.complete && bank.issuer.is_none());
        let pointer = bank.bytes.as_ptr();
        let allocated = bank.allocated_bytes();

        assert!(
            ProtocolSnapshotReservation::reserve_complete_owned11_into(
                1024,
                512,
                2,
                7,
                &mut output,
            )
            .is_err()
        );
        let bank = output.as_ref().ok_or_else(exhausted)?;
        assert_eq!(bank.allocated_bytes(), allocated);
        assert_eq!(bank.bytes.as_ptr(), pointer);
        Ok(())
    }

    #[test]
    fn invalid_geometry_allocates_nothing_and_an_existing_owner_cannot_be_replaced()
    -> Result<(), ProviderError> {
        let mut output = None;
        assert!(
            ProtocolSnapshotReservation::reserve_complete_owned11_into(0, 512, 2, 7, &mut output,)
                .is_err()
        );
        assert!(output.is_none());

        ProtocolSnapshotReservation::reserve_complete_owned11_into(1024, 512, 2, 7, &mut output)?;
        let pointer = output.as_ref().ok_or_else(exhausted)?.bytes.as_ptr();
        assert!(
            ProtocolSnapshotReservation::reserve_complete_owned11_into(
                2048,
                1024,
                3,
                9,
                &mut output,
            )
            .is_err()
        );
        assert_eq!(
            output.as_ref().ok_or_else(exhausted)?.bytes.as_ptr(),
            pointer
        );
        Ok(())
    }
}
