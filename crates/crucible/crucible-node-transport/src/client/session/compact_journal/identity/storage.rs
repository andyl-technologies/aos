//! Prices one complete compact request identity pass under real frame geometry.
//!
//! Outgoing preflight bounds canonical bytes before hashing. Incoming originals
//! have already passed the actual raw frame bound; their JCS output may expand.
//! Both cases therefore have frame-bounded lexical populations, independently
//! of a larger lifetime journal. No whole-envelope Value copies are priced here
//! because the actual borrowed writer no longer constructs them.

use super::*;
use crate::client::compact_json::CompactJson;
use crate::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
};
use crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack::{
    serde_error_storage, serde_error_storage_counter_scratch_data,
};
use std::mem::size_of;

pub(in crate::client::session::compact_journal) fn storage_data(
    maximum_frame_bytes: usize,
    maximum_journal_bytes: usize,
) -> Result<[usize; 3], ProviderError> {
    if maximum_frame_bytes == 0 || maximum_journal_bytes == 0 {
        return Err(credit());
    }
    // A known retry can widen its decimal sequence by at most twenty bytes.
    // The projection inserts a ten-byte origin string. Charge both independently
    // rather than deriving lexical event limits from normalized numeric widths.
    let lexical = maximum_frame_bytes
        .checked_add(20)
        .and_then(|bytes| bytes.checked_add("controller".len()))
        .ok_or_else(credit)?;
    let extent = original_json_value_storage_extent_data(lexical)?;
    let canonical = maximum_journal_bytes
        .checked_add(20)
        .ok_or_else(credit)?
        .min(extent.maximum_canonical_encoded_bytes);
    // The sink reserves exactly the measured projection length and cannot grow.
    // Sorting, escaping and diagnostics retain the defining supplier's complete
    // cumulative construction bounds, including refused partial work.
    let transient = [
        canonical,
        extent.canonical_work_requested_bytes,
        "blake3-256".len() + "cnp.request.v1".len() + 64,
        serde_error_storage(lexical)?,
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| {
        total.checked_add(bytes).ok_or_else(credit)
    })?;
    let scratch = counter_scratch_data();
    Ok([0, transient, scratch])
}

pub(in crate::client::session::compact_journal) fn counter_scratch_data() -> usize {
    CompactJson::envelope_preflight_counter_scratch_data()
        + serde_error_storage_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
        + size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<Output>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<Output, ProviderError>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<serde_json::Serializer<&'static mut Output>>()
        + size_of::<serde_json::ser::CompactFormatter>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<std::fmt::Arguments<'static>>()
        + size_of::<std::fmt::Formatter<'static>>()
        + size_of::<String>()
        + size_of::<Result<(), std::fmt::Error>>()
        // The pinned hash formatter uses ArrayString<64>: its fixed array and
        // length field are distinct from the final owned digest String.
        + size_of::<[u8; 64]>()
        + size_of::<usize>()
        + size_of::<HashRef>()
        + size_of::<Result<HashRef, ProviderError>>()
        + size_of::<ContractError>()
        + size_of::<io::Error>()
        + size_of::<Result<(), io::Error>>()
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<&Envelope>() * 3
        // Exhaustive projection bindings remain borrowed through the writer.
        + size_of::<&crate::envelope::Nullable<crucible_node_format::Id>>() * 7
        + size_of::<&String>()
        + size_of::<&crate::envelope::Method>()
        + size_of::<&serde_json::Map<String, serde_json::Value>>()
        + size_of::<&crucible_node_format::Extensions>()
        + size_of::<&RequestOrigin>()
        + size_of::<&mut Output>() * 3
        + size_of::<RequestOrigin>() * 3
        + size_of::<&str>() * 2
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<&[u8]>() * 2
        + size_of::<[usize; 4]>()
        + size_of::<std::array::IntoIter<usize, 4>>()
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<Option<usize>>() * 3
        + size_of::<u64>() * 2
        + size_of::<usize>() * 14
}
