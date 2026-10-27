//! Partitions the actual original Observe prefix without transport authority.
//!
//! Both lifetime records contain numeric requested-storage data only. The
//! generic and selected raw ACK work remain distinct. Transport supplies its
//! genuine compiled ACK facts and retains preparation/currentness/owner checks.

use super::super::report_ack::AckFixedLayoutData;
use super::super::report_query::OriginalReportQueryReceiveStorageData;
use super::{OriginalPacketPrefixStorageData, add, credit, sum};
use crate::ProviderError;
use serde_json::Value;
use std::mem::{align_of, size_of};

/// Keeps all persistent or uncertain prefix owners separate from returning work.
pub struct NativeObservePrefixLifetimeStorageData {
    /// Includes every plan, guard, canonical bank, cache and containment owner.
    /// The complete terminating open-ACK allowance stays here: a refused reply
    /// can remain in the original record, including arbitrary Error details.
    pub retained_requested_bytes: usize,
    /// Covers all construction/preparation/iterator work conservatively summed.
    pub maximum_simultaneous_transient_bytes: usize,
    /// Keeps the original quoted prefix counter window independently named.
    pub declared_counter_scratch_bytes: usize,
}

impl NativeObservePrefixLifetimeStorageData {
    /// Includes the original prefix counter window in the full returning phase.
    ///
    /// # Errors
    /// Refuses checked storage arithmetic overflow.
    pub fn work_requested_bytes(&self) -> Result<usize, ProviderError> {
        add(
            self.maximum_simultaneous_transient_bytes,
            self.declared_counter_scratch_bytes,
        )
    }

    fn peak(&self) -> Result<usize, ProviderError> {
        add(self.retained_requested_bytes, self.work_requested_bytes()?)
    }
}

/// Keeps a selected original Observe's independent encoding and ACK phases.
///
/// The original full quote/builder remains authoritative. Both new axes still
/// include every persistent owner from a terminating Error or malformed ACK.
pub struct NativeOriginalObservePrefixLifetimeStorageData {
    /// Counts all persistent and uncertain owners after the exact ACK split.
    pub retained_requested_bytes: usize,
    /// Counts the independent encoding/preparation phase before its counter.
    pub encoding: usize,
    /// Counts the returning raw ACK validation phase before its counter.
    pub acknowledgement: usize,
    /// Counts the original defining counter carried by both sequential phases.
    pub scratch: usize,
}

impl NativeOriginalObservePrefixLifetimeStorageData {
    /// Adds the original defining counter to the encoding work.
    ///
    /// # Errors
    /// Refuses checked requested-storage overflow.
    pub fn encoding_work_requested_bytes(&self) -> Result<usize, ProviderError> {
        add(self.encoding, self.scratch)
    }

    /// Adds the original defining counter to the returning ACK work.
    ///
    /// # Errors
    /// Refuses checked requested-storage overflow.
    pub fn acknowledgement_work_requested_bytes(&self) -> Result<usize, ProviderError> {
        add(self.acknowledgement, self.scratch)
    }
}

/// Partitions the unchanged full quote into persistent and returning work.
///
/// Every uncertain/failed ACK owner stays persistent. A successful partition
/// grants no read, construction, release, Source or native admission.
///
/// # Errors
/// Refuses checked overflow, an inconsistent partition or a peak above maximum.
pub fn native_observe_lifetime_storage_data(
    prefix: &OriginalPacketPrefixStorageData,
    maximum: usize,
) -> Result<NativeObservePrefixLifetimeStorageData, ProviderError> {
    let retained_requested_bytes = sum(&[
        prefix.original_plan_requested_bytes,
        prefix.acknowledgement_index_requested_bytes,
        prefix.canonical_requested_bytes,
        prefix.record_slots_requested_bytes,
        prefix.outgoing_guard_requested_bytes,
        prefix.successful_ack_cache_requested_bytes,
        prefix.one_open_ack_requested_bytes,
        prefix.containment_requested_bytes,
    ])?;
    let data = NativeObservePrefixLifetimeStorageData {
        retained_requested_bytes,
        maximum_simultaneous_transient_bytes: sum(&[
            prefix.construction_transient_requested_bytes,
            prefix.preparation_transient_requested_bytes,
            prefix.response_iterator_requested_bytes,
        ])?,
        declared_counter_scratch_bytes: prefix.declared_quote_scratch_bytes,
    };
    // This is an exact partition of the OLD full quote, not a smaller
    // allocation ceiling or a replacement for actual owning reconciliation.
    let peak = data.peak()?;
    if peak != prefix.requested_bytes()? || peak > maximum {
        return Err(credit());
    }
    Ok(data)
}

/// Adds the actual SDK empty-extension-root layout to the typed returned query.
///
/// This counts data only and does not authenticate a restricted incoming query.
///
/// # Errors
/// Refuses the unchanged checked tree-layout or requested-storage overflow.
pub fn native_observe_returned_query_storage_data(
    receive: &OriginalReportQueryReceiveStorageData,
) -> Result<usize, ProviderError> {
    let empty_extensions_root = crate::profile::requested_storage::tree_storage_data(
        1,
        0,
        size_of::<(String, Value)>(),
        align_of::<(String, Value)>(),
    )?;
    add(receive.typed_query_requested_bytes, empty_extensions_root)
}

/// Separates the original full raw ACK's retained and returning phases.
///
/// The true compiled ACK facts come from the upper consumer. The real ACK
/// calculation runs only after the original full partition and request checks;
/// an unused zero-request frame cap is neither validated nor interpreted.
///
/// # Errors
/// Preserves the original partition, frame-cap, ACK equality and overflow errors.
pub fn native_original_observe_lifetime_storage_data(
    prefix: &OriginalPacketPrefixStorageData,
    maximum_frame: usize,
    maximum: usize,
    acknowledgement_layout: &AckFixedLayoutData,
) -> Result<NativeOriginalObservePrefixLifetimeStorageData, ProviderError> {
    let old = native_observe_lifetime_storage_data(prefix, maximum)?;
    let (retained_ack, returning_ack) = if prefix.requests == 0 {
        if prefix.one_open_ack_requested_bytes != 0 {
            return Err(credit());
        }
        (0, 0)
    } else {
        let ack = super::super::report_ack::open_ack_lifetime_storage_data(
            maximum_frame,
            acknowledgement_layout,
        )?;
        if add(ack.retained, ack.returning)? != prefix.one_open_ack_requested_bytes {
            return Err(credit());
        }
        (ack.retained, ack.returning)
    };
    let retained = old
        .retained_requested_bytes
        .checked_sub(prefix.one_open_ack_requested_bytes)
        .and_then(|n| n.checked_add(retained_ack))
        .ok_or_else(credit)?;
    let result = NativeOriginalObservePrefixLifetimeStorageData {
        retained_requested_bytes: retained,
        encoding: old.maximum_simultaneous_transient_bytes,
        acknowledgement: returning_ack,
        scratch: old.declared_counter_scratch_bytes,
    };
    let phase = result
        .encoding_work_requested_bytes()?
        .max(result.acknowledgement_work_requested_bytes()?);
    if add(result.retained_requested_bytes, phase)? > prefix.requested_bytes()? {
        return Err(credit());
    }
    Ok(result)
}
