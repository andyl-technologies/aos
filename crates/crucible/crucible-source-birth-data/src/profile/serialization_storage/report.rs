//! Owns the closed serializer's requested-storage report and checked total.
//!
//! Reported components remain DATA; the report allocates no backing storage
//! and grants no Source or native authority.

use crate::ProviderError;

/// Reports independently named storage for an actual closed Serialize view.
///
/// The visitor creates no DOM. Actual Bytes serialization itself creates a
/// base64 String before visiting it, so all such temporary banks are admitted
/// from the same actual typed metadata walk BEFORE invoking Serialize.
pub struct OriginalSerializationStorageData {
    /// Reports the original dom and canonical scratch bytes component.
    pub dom_and_canonical_scratch_bytes: usize,
    /// Bounds only the independently owned Value backing, including empty map roots.
    pub retained_value_backing_bytes: usize,
    /// Reports the original projected parser requested bytes component.
    pub projected_parser_requested_bytes: usize,
    /// Bounds the canonical output bank independently of serializer scratch.
    pub canonical_output_requested_bytes: usize,
    /// Reports the original serializer temporary requested bytes component.
    pub serializer_temporary_requested_bytes: usize,
    /// Reports fixed storage for the actual typed counter implementation.
    pub declared_counter_scratch_bytes: usize,
    /// Reports the original maximum encoded bytes component.
    pub maximum_encoded_bytes: usize,
    /// Counts elements visited across all sequence containers.
    pub sequence_elements: usize,
    /// Reports the original sequence containers component.
    pub sequence_containers: usize,
    /// Counts logical serialized JSON values plus map-key strings.
    /// Typed metadata wrapper/alias visits are separate, not implied by this count.
    pub serialized_value_nodes: usize,
    /// Counts logical JSON string/key, array and object backing records.
    /// This is not the complete typed owner's capacity/alias roster.
    pub serialized_capacity_records: usize,
}

impl OriginalSerializationStorageData {
    /// Sums the original independently named requested-storage components.
    ///
    /// # Errors
    /// Refuses the original checked requested-storage overflow.
    pub fn requested_total(&self) -> Result<usize, ProviderError> {
        [
            self.dom_and_canonical_scratch_bytes,
            self.projected_parser_requested_bytes,
            self.canonical_output_requested_bytes,
            self.serializer_temporary_requested_bytes,
            self.declared_counter_scratch_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |sum, next| {
            sum.checked_add(next)
                .ok_or(ProviderError::ResourceExhausted(
                    "serialization requested storage",
                ))
        })
    }
}
