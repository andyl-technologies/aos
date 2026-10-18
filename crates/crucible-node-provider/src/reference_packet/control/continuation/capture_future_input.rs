//! Binds a newly decoded prebirth model to its actual immutable Control bytes.
//!
//! This separate inert owner uses the unchanged complete Control decoder. Its
//! fixed provenance facts allow a future counter to refuse an unrelated model
//! without adding provenance fields to any old decoded owner or wire grammar.

use super::*;
use std::mem::size_of;

/// Owns one fully decoded Control and its exact original input correspondence.
///
/// Only the defining decoder constructs this DATA. It grants no archive,
/// Source currentness, fresh adoption or native allocation permission.
pub struct PacketDecodedCaptureFutureControlData {
    decoded: PacketDecodedControlSnapshot,
    body_digest: [u8; 32],
    body_length: usize,
    reference_identity: [u8; 32],
}

/// Decodes the existing Control grammar and retains fixed input provenance.
///
/// The actual Source independently admits the existing decoder's complete
/// constructor row and this wrapper's header/counter work before calling. It
/// installs the returned owner in its spent construction attempt before any
/// later future-model visitor or callback. No second model parse occurs.
///
/// # Errors
/// Reports the unchanged decoder's fullref, canonical, typed, model-consistency
/// or finite-limit refusal. Provenance construction performs no allocation.
pub fn decode_packet_control_snapshot_for_capture_future_data(
    bytes: &[u8],
    reference: &ContentRef,
    maximum_bytes: usize,
) -> Result<PacketDecodedCaptureFutureControlData, ProviderError> {
    let decoded = decode_packet_control_snapshot(bytes, reference, maximum_bytes)?;
    Ok(PacketDecodedCaptureFutureControlData {
        decoded,
        body_digest: *blake3::hash(bytes).as_bytes(),
        body_length: bytes.len(),
        reference_identity: reference_identity(reference),
    })
}

impl PacketDecodedCaptureFutureControlData {
    /// Borrows the actual decoded model owner without mutable or owned escape.
    pub fn control_data(&self) -> &PacketDecodedControlSnapshot {
        &self.decoded
    }

    /// Checks the exact original input used by the defining successful decoder.
    ///
    /// This fixed hash walk does not parse, serialize or allocate. The complete
    /// decoder already verified this exact full reference against these bytes.
    ///
    /// # Errors
    /// Refuses any changed body, body length or full reference, including media.
    pub fn authenticate_body_data(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        if self.body_length != bytes.len()
            || self.reference_identity != reference_identity(reference)
            || self.body_digest != *blake3::hash(bytes).as_bytes()
        {
            return Err(ProviderError::Correlation(
                "same decoded prebirth Control input required",
            ));
        }
        Ok(())
    }

    /// Counts the actual wrapper root and every independently retained child.
    ///
    /// The inner census explicitly includes its inline root. Replacing that
    /// root with the actual enclosing wrapper header counts each owner once;
    /// no backing or constructor demand receives a refund or alias discount.
    ///
    /// # Errors
    /// Refuses inner metadata/layout failure, checked arithmetic overflow or
    /// actual retained requested storage above `maximum`.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        let inner = self.decoded.retained_requested_storage_data(usize::MAX)?;
        inner
            .checked_sub(size_of::<PacketDecodedControlSnapshot>())
            .and_then(|backing| backing.checked_add(size_of::<Self>()))
            .filter(|requested| *requested <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "prebirth Control wrapper actual backing",
            ))
    }

    /// Returns the complete actual inline wrapper layout for its new owner row.
    pub const fn header_requested_bytes_data() -> usize {
        size_of::<Self>()
    }

    /// Names additional fixed provenance constructor and authentication controls.
    ///
    /// The unchanged complete decoder's own constructor row remains separate.
    pub fn provenance_counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&Self>()
            + size_of::<&ContentRef>()
            + size_of::<&[u8]>()
            + size_of::<usize>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 32]>() * 3
            + size_of::<[&String; 4]>()
            + size_of::<std::array::IntoIter<&String, 4>>()
            + size_of::<Option<&String>>()
            + size_of::<[u8; 16]>()
            + size_of::<[u8; 8]>()
            + size_of::<Result<(), ProviderError>>()
    }

    /// Names the defining actual retained census and enclosing fixed controls.
    pub fn retained_metadata_counter_scratch_data() -> usize {
        PacketDecodedControlSnapshot::retained_metadata_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<usize>() * 2
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
    }
}

fn reference_identity(reference: &ContentRef) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("source-private.capture-future-control-input/17");
    for text in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ] {
        hash.update(&(text.len() as u128).to_le_bytes());
        hash.update(text.as_bytes());
    }
    hash.update(&reference.length.get().to_le_bytes());
    *hash.finalize().as_bytes()
}
