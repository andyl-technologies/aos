//! Prices the actual signed Index3 identity encoder before Host17 construction.
//!
//! The existing identity producer remains unchanged. These axes describe its
//! generated ContentRef, whole actual-index DOM/canonical work and fixed controls;
//! they issue no index signature, native permission or cold Source provenance.

use super::*;
use std::mem::size_of;

const MEDIA: &str = "application/vnd.crucible.native-signed-index-body.v3+json";

impl NativeArchiveRecord {
    /// Quotes the exact retained Index3 identity producer as storage DATA.
    ///
    /// The caller admits the fixed counter and its known scalar formatter term
    /// before this walk. Actual archive/source owners remain separately retained.
    /// The output order is retained reference backing, transient encoder work,
    /// and fixed counter scratch. No owning index or identity is constructed.
    ///
    /// # Errors
    /// Refuses an oversized actual index, unsupported serialization, checked
    /// overflow or a construction row above the independent requested ceiling.
    pub(crate) fn complete_original_index_identity_construction_data(
        &self,
        maximum_record_bytes: usize,
        maximum_requested_bytes: usize,
    ) -> Result<(usize, usize, usize), StateError> {
        let maximum = maximum_requested_bytes.min(self.limits.state.maximum_total_content_bytes);
        super::super::super::super::closure::bounded_record(
            self.index.as_ref(),
            maximum_record_bytes.min(self.limits.state.maximum_record_bytes),
        )?;
        let dom = NodeRuntime::capture_serialization_storage(self.index.as_ref(), maximum)
            .map_err(schema)?;
        let encoded = NodeRuntime::capture_encoded_output_storage(self.index.as_ref(), maximum)
            .map_err(schema)?;
        let retained = "blake3-256".len() + "cnp.blob.v1".len() + 64 + MEDIA.len();
        let transient = dom
            .checked_add(encoded)
            .and_then(|bytes| {
                bytes.checked_add(Self::complete_original_index_identity_counter_transient_data())
            })
            .ok_or_else(|| limit("Index3 identity construction overflow"))?;
        let scratch = Self::complete_original_index_identity_counter_scratch_data();
        retained
            .checked_add(transient)
            .and_then(|bytes| bytes.checked_add(scratch))
            .filter(|bytes| *bytes <= maximum)
            .ok_or_else(|| limit("Index3 identity construction exceeds admission"))?;
        Ok((retained, transient, scratch))
    }

    /// Names the existing U64 serializer's one simultaneous decimal String.
    ///
    /// This known temporary is admitted before the generic serialization walk;
    /// it is not inferred from a later returned row or a fresh target policy.
    pub(crate) fn complete_original_index_identity_counter_transient_data() -> usize {
        20
    }

    /// Names actual fixed identity and metadata/canonical counter controls.
    pub(crate) fn complete_original_index_identity_counter_scratch_data() -> usize {
        size_of::<ContentRef>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 64]>()
            + size_of::<[usize; 6]>()
            + size_of::<Result<(usize, usize, usize), StateError>>()
            + NodeRuntime::capture_serialization_counter_scratch_data()
    }
}
