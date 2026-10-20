//! Reconstructs complete historical assigned-restore owners without a live cut.
//!
//! Exact assigned envelopes, proof extensions, canonical bytes, capacities,
//! literal slot and raw reply survive as typed data. The operational cut remains
//! in the original opaque payload owner; this module cannot mint or refresh it.
//!
//! ```text
//! ["complete",assigned_envelope,compact_bytes,capacity,literal_slot,raw_reply,
//!  "original-physical-cut-retained-by-opaque-owner-not-portable-time"]
//! ```

use super::envelope::ValidatedHistoricalEnvelope;
use super::json_value::HistoricalJsonLimits;
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;
use crate::retained_metadata::records::{MetadataRecordKind, MetadataRecordRows};
use crate::{
    ProviderError,
    envelope::{Envelope, MessageKind, Method},
};

/// Borrows checked complete assigned-restore data under the whole roster allowance.
pub struct ValidatedHistoricalAssignedCompleteRestore<'input, 'records> {
    original: ValidatedHistoricalEnvelope<'input, 'records>,
    bytes: ValidatedCompactBytes<'input>,
    capacity: usize,
    slot: usize,
    response: ValidatedHistoricalEnvelope<'input, 'records>,
    remaining: MetadataRecordRows<'records>,
}

impl<'input, 'records> ValidatedHistoricalAssignedCompleteRestore<'input, 'records> {
    /// Checks the complete tuple and exact metadata-row prefix before copying.
    ///
    /// The caller supplies already located immutable field spans from the closed
    /// whole11 tuple framing. This private entry does not accept a phase label or
    /// operational timestamp as evidence; only complete data is reconstructible.
    ///
    /// # Errors
    /// Refuses envelope grammar/capacity disagreement, differing byte-bank credit,
    /// oversized compact data, invalid literal slot or incomplete response data.
    pub(crate) fn validate_fields(
        original: &'input [u8],
        bytes: &'input [u8],
        capacity: usize,
        slot: usize,
        response: &'input [u8],
        records: MetadataRecordRows<'records>,
        limits: HistoricalJsonLimits,
    ) -> Result<Self, ProviderError> {
        require_prepare_restore(original)?;
        let original = ValidatedHistoricalEnvelope::validate(original, records, limits)?;
        let mut remaining = original.remaining_records();
        let row = remaining.next().ok_or_else(invalid)??;
        if row.kind != MetadataRecordKind::Vector
            || row.element_bytes != 1
            || row.alignment != 1
            || row.extent != capacity
            || capacity > limits.maximum_owned_backing_bytes
        {
            return Err(invalid());
        }
        let bytes = ValidatedCompactBytes::validate(bytes, limits.maximum_input_bytes, capacity)?;
        let response = ValidatedHistoricalEnvelope::validate(response, remaining, limits)?;
        original.authenticate_historical_restore_reply(&response)?;
        let remaining = response.remaining_records();
        Ok(Self {
            original,
            bytes,
            capacity,
            slot,
            response,
            remaining,
        })
    }

    /// Borrows the rows for the next complete typed field.
    pub fn remaining_records(&self) -> MetadataRecordRows<'records> {
        self.remaining.clone()
    }

    /// Reconstructs the final original envelope, byte bank and raw reply directly.
    ///
    /// Physical cut, actual Hello/actor/codec alias and native token authority are
    /// intentionally absent. Those remain associated with the original opaque
    /// source owner and must be reauthenticated by the fresh-target source gate.
    ///
    /// # Errors
    /// Refuses exact capacity reservation failure or differing original request/
    /// response correspondence, preserving the immutable borrowed inputs.
    pub fn reconstruct(&self) -> Result<HistoricalAssignedCompleteRestore, ProviderError> {
        let original = self.original.reconstruct()?;
        let response = self.response.reconstruct()?;
        if original.message != MessageKind::Request || original.method != Method::Begin {
            return Err(invalid());
        }
        original.matches_response(&response)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.capacity)
            .map_err(|_| ProviderError::ResourceExhausted("historical assigned byte bank"))?;
        if bytes.capacity() != self.capacity {
            return Err(invalid());
        }
        self.bytes.fill_preowned(&mut bytes)?;
        Ok(HistoricalAssignedCompleteRestore {
            original,
            bytes,
            slot: self.slot,
            response,
        })
    }
}

/// Owns historical complete assigned-restore data without live operational rights.
pub struct HistoricalAssignedCompleteRestore {
    original: Envelope,
    bytes: Vec<u8>,
    slot: usize,
    response: Envelope,
}

impl HistoricalAssignedCompleteRestore {
    pub(super) fn authenticate_literals(
        &self,
        bank: &crate::transport::DecodedCompactOriginalFrames,
    ) -> Result<(), ProviderError> {
        use crate::transport::original_frames::FrameDirection;
        let mut frames = bank.frames();
        let original = frames.nth(self.slot).ok_or_else(invalid)?;
        if original.direction != FrameDirection::Outgoing
            || !original.complete
            || original.transferred != original.bytes.len()
            || original.bytes.get(4..) != Some(self.bytes.as_slice())
        {
            return Err(invalid());
        }
        super::correspondence::envelope(&self.original, &self.bytes)?;
        for response in frames {
            if response.direction != FrameDirection::Incoming {
                continue;
            }
            if !response.complete || response.transferred != response.bytes.len() {
                return Err(invalid());
            }
            let body = response.bytes.get(4..).ok_or_else(invalid)?;
            if super::correspondence::is_response(body)? {
                // The actual publishing loop permits provider Blob requests
                // before this response. It never skips a mismatching response.
                return super::correspondence::envelope(&self.response, body);
            }
        }
        Err(invalid())
    }

    /// Borrows the exact assigned request and retained proof fields.
    pub fn original(&self) -> &Envelope {
        &self.original
    }

    /// Borrows the exact historical canonical request buffer.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reports the actual reconstructed byte vector capacity, including spare storage.
    pub fn canonical_capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Reports the historical literal-bank slot without authenticating that bank.
    pub fn literal_slot(&self) -> usize {
        self.slot
    }

    /// Borrows the retained raw original reply, before any DTO normalization.
    pub fn response(&self) -> &Envelope {
        &self.response
    }
}

fn invalid() -> ProviderError {
    ProviderError::Frame("historical assigned complete restore data or capacity")
}

fn require_prepare_restore(input: &[u8]) -> Result<(), ProviderError> {
    let mut envelope = super::typed::Fields::object(input)?;
    while let Some((name, body)) = envelope.pair()? {
        if name != b"\"body\"" {
            continue;
        }
        let mut fields = super::typed::Fields::object(body)?;
        while let Some((key, value)) = fields.pair()? {
            if key == b"\"kind\"" {
                return if value == b"\"prepare_restore\"" {
                    Ok(())
                } else {
                    Err(invalid())
                };
            }
        }
        return Err(invalid());
    }
    Err(invalid())
}

/// Retains the completed restore originals and their separately charged mapping reference.
pub struct HistoricalCompleteRestoreOwner {
    /// Retains exact assigned request/proof/bytes/raw reply and literal slot.
    pub assigned: HistoricalAssignedCompleteRestore,
    /// Retains the full canonical fresh mapping commitment from the same request.
    pub mapping: crucible_node_format::ContentRef,
    /// Retains the original fixed nonce without creating a fresh key association.
    pub nonce: [u8; 32],
}

// The closed owning walk fails to compile if a historical field is added.
super::retained_storage::fields!(
    HistoricalAssignedCompleteRestore,
    original,
    bytes,
    slot,
    response
);
super::retained_storage::fields!(HistoricalCompleteRestoreOwner, assigned, mapping, nonce);
