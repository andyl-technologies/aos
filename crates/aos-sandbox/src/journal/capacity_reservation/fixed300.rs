//! Private scalar framing shared by the fixed-width capacity DATA codecs.
//!
//! ```text
//! header[16] | scalar body[252] | self-binding identity[32]
//! ```
//!
//! Callers validate the header before reading this body and retain their own
//! version, kind, profile, geometry, and identity-domain policies.

use sha2::{Digest as _, Sha256};

use super::super::JournalError;
use super::take;

pub(super) const VALUE_BYTES: usize = 300;
pub(super) const IDENTITY_PAYLOAD_BYTES: usize = VALUE_BYTES - 32;

/// Holds only the common scalar body, without version or profile interpretation.
#[derive(Clone, Copy)]
pub(super) struct FixedCapacityBody {
    pub owner_id: [u8; 32],
    pub original_owner_cut_digest: [u8; 32],
    pub operation_id: [u8; 16],
    pub original_artifact_digest: [u8; 32],
    pub admission_owner_mutation_digest: [u8; 32],
    pub admission_native_preservation_union_digest: [u8; 32],
    pub remaining_transactions: u32,
    pub remaining_record_frames: u32,
    pub remaining_append_bytes: u64,
    pub maximum_retained_growth_entries: u32,
    pub maximum_retained_growth_bytes: u64,
    pub admission_transaction: [u8; 16],
    pub remaining_profile_digest: [u8; 32],
}

impl FixedCapacityBody {
    pub(super) fn encode_into(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.owner_id);
        bytes.extend_from_slice(&self.original_owner_cut_digest);
        bytes.extend_from_slice(&self.operation_id);
        bytes.extend_from_slice(&self.original_artifact_digest);
        bytes.extend_from_slice(&self.admission_owner_mutation_digest);
        bytes.extend_from_slice(&self.admission_native_preservation_union_digest);
        bytes.extend_from_slice(&self.remaining_transactions.to_be_bytes());
        bytes.extend_from_slice(&self.remaining_record_frames.to_be_bytes());
        bytes.extend_from_slice(&self.remaining_append_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_retained_growth_entries.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_retained_growth_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.admission_transaction);
        bytes.extend_from_slice(&self.remaining_profile_digest);
    }

    /// Reads a body after its caller has checked the exact 300-byte envelope.
    ///
    /// # Panics
    ///
    /// Panics if the private caller has not checked the body width and offset.
    pub(super) fn decode(value: &[u8], offset: &mut usize) -> Self {
        Self {
            owner_id: take::<32>(value, offset),
            original_owner_cut_digest: take::<32>(value, offset),
            operation_id: take::<16>(value, offset),
            original_artifact_digest: take::<32>(value, offset),
            admission_owner_mutation_digest: take::<32>(value, offset),
            admission_native_preservation_union_digest: take::<32>(value, offset),
            remaining_transactions: u32::from_be_bytes(take::<4>(value, offset)),
            remaining_record_frames: u32::from_be_bytes(take::<4>(value, offset)),
            remaining_append_bytes: u64::from_be_bytes(take::<8>(value, offset)),
            maximum_retained_growth_entries: u32::from_be_bytes(take::<4>(value, offset)),
            maximum_retained_growth_bytes: u64::from_be_bytes(take::<8>(value, offset)),
            admission_transaction: take::<16>(value, offset),
            remaining_profile_digest: take::<32>(value, offset),
        }
    }
}

/// Binds the exact header and body under the caller's unchanged domain policy.
///
/// # Errors
///
/// Rejects a payload other than 268 bytes or an unrepresentable length.
pub(super) fn floor_identity(
    payload: &[u8],
    domain: &[u8],
    width_error: &'static str,
) -> Result<[u8; 32], JournalError> {
    if payload.len() != IDENTITY_PAYLOAD_BYTES {
        return Err(JournalError::MalformedRecord(width_error));
    }

    let length = u32::try_from(payload.len()).map_err(|_| JournalError::JournalTooLarge)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(length.to_be_bytes());
    digest.update(payload);
    Ok(digest.finalize().into())
}
