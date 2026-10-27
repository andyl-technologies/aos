//! Pairs actual compact envelope banks with an explicit historical DATA reader.
//!
//! ```text
//! ["source-private.compact-envelope/18",["source-private.compact-bytes/7",raw_length,[base64_chunks]]]
//! ```
//!
//! The outer edition binds the private tag grammar, exact Envelope field order,
//! strictly UTF-8 ordered nested object keys and existing geometry restrictions.
//! The inner byte codec preserves every integer variant and floating-point bit.
//! Its exact byte reservation precedes the allocation-free binary validation;
//! the caller admits that complete failed-construction window independently.
//! Imported owners remain historical DATA, with no conversion into live custody.
//! This format covers one bank, not a whole journal, Source or native capsule.

use super::{CompactJson, ProviderError};
use crate::protocol_snapshot::compact_bytes::{self, BorrowedCompactBytes};
use crucible_source_birth_data::borrowed_literal::{OrderedFields, plain_string};
use serde::{Serialize, Serializer, ser::SerializeTuple};
use std::mem::size_of;

mod validate;

const TAG: &str = "source-private.compact-envelope/18";

/// Borrows the actual validated bank for the physical18 writer.
pub(in crate::client) struct BorrowedEnvelope18<'a> {
    bank: &'a CompactJson,
}

impl CompactJson {
    /// Validates the paired reader's geometry before lending the actual bank.
    ///
    /// # Errors
    /// Refuses unsupported root fields, scalar contracts or bank geometry.
    pub(in crate::client) fn physical18_data(
        &self,
    ) -> Result<BorrowedEnvelope18<'_>, ProviderError> {
        validate::envelope(&self.bytes)?;
        Ok(BorrowedEnvelope18 { bank: self })
    }
}

impl Serialize for BorrowedEnvelope18<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_tuple(2)?;
        fields.serialize_element(TAG)?;
        fields.serialize_element(&BorrowedCompactBytes::new(&self.bank.bytes))?;
        fields.end()
    }
}

/// Owns a structurally checked historical envelope bank without live authority.
///
/// The bank retains its exact original byte capacity. This type cannot populate
/// a live journal, renew credit, authenticate a request identity or supply native
/// permission. Complete journal identities, limits, content, pending failures and
/// allocation aliases require the enclosing paired history and Source checks.
pub struct HistoricalCompactEnvelope18 {
    bank: CompactJson,
}

impl HistoricalCompactEnvelope18 {
    /// Moves an already checked bank into the private enclosing historical owner.
    pub(in crate::client) fn into_historical_bank(self) -> CompactJson {
        self.bank
    }

    /// Reconstructs one explicit physical18 bank under independent DATA limits.
    ///
    /// The complete outer and compact-byte framing is checked before requesting
    /// one exact byte bank. Binary validation then borrows that bank without a
    /// DOM, key set, number normalization or additional owning population.
    /// Caller-owned encoded input remains independently retained throughout.
    /// These restrictions reserve no memory; the caller admits construction,
    /// every refused prefix and codec controls before invoking this method.
    ///
    /// # Errors
    /// Refuses unknown editions, malformed framing/base64, exceeded restrictions,
    /// unavailable exact storage or invalid bank tags, scalars, field ordering,
    /// UTF-8, nesting, array counts, duplicate keys and complete extents.
    pub fn decode(
        input: &[u8],
        maximum_input_bytes: usize,
        maximum_bank_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if input.len() > maximum_input_bytes {
            return Err(refused());
        }
        let mut fields = OrderedFields::array(input)?;
        if plain_string(fields.next_value()?.ok_or_else(invalid)?)? != TAG {
            return Err(invalid());
        }
        let encoded_bank = fields.next_value()?.ok_or_else(invalid)?;
        fields.finish()?;

        let bytes = compact_bytes::decode(encoded_bank, encoded_bank.len(), maximum_bank_bytes)?;
        validate::envelope(&bytes)?;
        Ok(Self {
            bank: CompactJson { bytes },
        })
    }

    /// Bounds this decoder's retained bank and named controls as `[R,T,S]` DATA.
    ///
    /// `R` includes the returned header and exact maximum byte reservation.
    /// There is no additional owning transient population. The supplied maximum
    /// restricts the complete sum; neither it nor this row admits an operation.
    /// Encoded input, output serialization, logical materialization, allocator
    /// residency and physical/compiler stack bounds remain independent.
    ///
    /// # Errors
    /// Refuses arithmetic overflow or a complete row exceeding the restriction.
    pub fn decoding_storage_data(
        maximum_bank_bytes: usize,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let retained = maximum_bank_bytes
            .checked_add(size_of::<Self>())
            .ok_or_else(refused)?;
        let scratch = Self::decoding_counter_scratch_data();
        retained
            .checked_add(scratch)
            .filter(|&peak| peak <= maximum)
            .ok_or_else(refused)?;
        Ok([retained, 0, scratch])
    }

    /// Names decoder controls without inspecting input or constructing an owner.
    ///
    /// Bounded recursive requested layouts do not measure a machine stack.
    pub fn decoding_counter_scratch_data() -> usize {
        validate::counter_scratch_data()
            + OrderedFields::counter_scratch_data()
            + compact_bytes::ValidatedCompactBytes::validation_counter_scratch_data()
            + size_of::<&[u8]>() * 4
            + size_of::<Vec<u8>>()
            + size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Result<Vec<u8>, ProviderError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Option<usize>>()
            + size_of::<[usize; 3]>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<[usize; 8]>()
    }

    /// Bounds the paired writer's complete encoded extent from a bank ceiling.
    ///
    /// The defining compact-byte supplier counts its actual fixed chunks and
    /// base64 expansion. This adds only the explicit outer tag and tuple syntax;
    /// no output, bank, sample Envelope or fake journal owner is constructed.
    ///
    /// # Errors
    /// Refuses checked encoding overflow or an extent above the restriction.
    pub fn maximum_encoded_bytes_data(
        maximum_bank_bytes: usize,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let inner = BorrowedCompactBytes::serialization_layout_data(maximum_bank_bytes)?;
        inner
            .maximum_encoded_bytes
            .checked_add(TAG.len() + 5)
            .filter(|&bytes| bytes <= maximum)
            .ok_or_else(refused)
    }

    /// Names bank validation, encoding-bound and fixed chunk writer controls.
    ///
    /// The chosen serializer and encoded output require independent admission.
    pub fn serialization_counter_scratch_data() -> usize {
        validate::counter_scratch_data()
            + BorrowedCompactBytes::requested_serialization_scratch_bytes()
            + size_of::<BorrowedEnvelope18<'static>>()
            + size_of::<Result<BorrowedEnvelope18<'static>, ProviderError>>()
            + size_of::<&str>()
            + size_of::<compact_bytes::CompactBytesSerializationLayoutData>()
            + size_of::<Result<compact_bytes::CompactBytesSerializationLayoutData, ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<usize>() * 10
    }

    /// Reports the complete retained bank capacity, excluding its inline header.
    pub fn retained_bank_bytes(&self) -> usize {
        self.bank.retained_bytes()
    }

    /// Borrows the complete logical envelope without allocating a tree.
    pub fn as_serializable(&self) -> impl Serialize + '_ {
        self.bank.as_serializable()
    }

    /// Borrows the same versioned physical bank without a byte copy.
    pub fn physical_data(&self) -> impl Serialize + '_ {
        BorrowedEnvelope18 { bank: &self.bank }
    }

    /// Materializes one independent historical Envelope under separate admission.
    ///
    /// Binary validation supplies no funding for this fresh logical population
    /// or its typed scalar construction. This does not validate method bodies,
    /// authenticate receipts or associate the envelope with a current Source.
    ///
    /// # Errors
    /// Refuses typed materialization or unavailable array storage.
    pub fn materialize_data(&self) -> Result<crate::envelope::Envelope, ProviderError> {
        self.bank.materialize_envelope()
    }
}

impl crate::retained_metadata::ObserveMetadata for HistoricalCompactEnvelope18 {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.bank)
    }
}

fn invalid() -> ProviderError {
    ProviderError::Frame("compact envelope18 historical DATA grammar")
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("compact envelope18 historical DATA storage")
}

#[cfg(test)]
mod tests;
