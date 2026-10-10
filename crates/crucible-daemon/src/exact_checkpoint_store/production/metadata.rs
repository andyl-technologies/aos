//! Preallocation bounds and retained credits for whole-checkpoint metadata.
//!
//! Encoded buffers use their authenticated lengths. Typed inventories use
//! checked element counts and native Rust layouts; envelope parsing reserves
//! the public codec's scratch bound before constructing child catalogs.

use super::*;

pub(super) fn array_bytes<T>(count: usize) -> Result<u64, ExactCheckpointStoreError> {
    count
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| invalid_root("checkpoint metadata allocation bound overflow"))
}

pub(super) fn reserve_metadata(
    authority: Option<&Arc<dyn StorePhysicalQuotaGuard>>,
    bytes: u64,
) -> Result<crucible_cas::owned_decode::ResourceLoan, ExactCheckpointStoreError> {
    let authority = authority.ok_or(ExactCheckpointStoreError::UnsupportedBackend {
        capability: "checkpoint-metadata-resources",
    })?;
    authority.verify()?;
    Ok(authority.reserve_resources(0, bytes)?)
}

pub(super) fn reserve_envelope_decode(
    authority: Option<&Arc<dyn StorePhysicalQuotaGuard>>,
    bytes: &[u8],
    child_limit: usize,
) -> Result<crucible_cas::owned_decode::ResourceLoan, ExactCheckpointStoreError> {
    // Every encoded child contains two u16 length prefixes. This upper bound
    // also covers malformed input before the public decoder validates fields.
    let children = child_limit.min(bytes.len() / 4);
    let bound = ContentEnvelope::decoding_memory_bound(bytes.len(), children)?;
    let encoded = u64::try_from(bytes.len())
        .map_err(|_| invalid_root("checkpoint envelope length overflow"))?;
    let scratch = bound
        .checked_sub(encoded)
        .ok_or_else(|| invalid_root("checkpoint envelope scratch underflow"))?;
    reserve_metadata(authority, scratch)
}
