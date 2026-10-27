//! Prices the only legacy response clones reachable through packet runtime.
//!
//! The closed packet call surface refuses outgoing legacy IDs before cloning.
//! Incoming provider retries can still clone an original response larger than
//! today's frame ceiling. These DATA rows price that actual retained history;
//! they neither fund a handoff nor authenticate a Source action.

use crate::{
    ProviderError,
    client::{ClientOriginal, CnpController, compact_json::CompactJson},
    envelope::{Envelope, RequestOrigin},
    retained_metadata::serialization_storage::{
        original_json_value_clone_storage_forest_counter_scratch_data,
        original_json_value_clone_storage_forest_data,
    },
};
use std::mem::{size_of, size_of_val};

impl CnpController {
    /// Measures actual provider replay extents before a packet runtime handoff.
    ///
    /// Returns `[largest original canonical response, fresh clone backing]`.
    /// Only provider-origin history is reachable after the closed packet call
    /// surface rejects outgoing legacy IDs. The complete original response,
    /// including envelope extensions, is measured without allocating a DOM,
    /// text bank or sorted key roster. An empty provider history returns zeros.
    /// Unresolved provider originals refuse the row.
    ///
    /// The clone bound includes its inline Envelope and remains independent of
    /// today's frame ceiling, unused quota and original allocation capacity.
    /// Later serialization must also allow growth of the replacement sequence
    /// number; this query reports the original response's canonical extent.
    /// Original owners, typed decoding, validation, serialization, simultaneous
    /// copies, diagnostics and physical stack require separate funding.
    ///
    /// The caller first admits
    /// [`Self::original_packet_runtime_provider_replay_counter_scratch_data`].
    /// Each result has the independent restriction `maximum`. This read-only
    /// DATA query grants no replay, allocation or Source permission and remains
    /// readable after fencing by the same original process and thread.
    ///
    /// # Errors
    /// Refuses foreign ownership, unresolved provider history, unsupported
    /// envelope or clone geometry, checked overflow, or either result above
    /// `maximum`.
    pub fn original_packet_runtime_provider_replay_storage_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 2], ProviderError> {
        self.protocol_owner.ensure_current()?;
        let mut canonical = 0;
        for original in self.custody.originals_by_origin(RequestOrigin::Provider) {
            let response = original.response.as_ref().ok_or_else(refused)?;
            let (_, bytes) = CompactJson::envelope_extents(response, usize::MAX, maximum)?;
            canonical = canonical.max(bytes);
        }

        let clone = if canonical == 0 {
            0
        } else {
            original_json_value_clone_storage_forest_data(canonical, 1)?
                .checked_add(size_of::<Envelope>())
                .ok_or_else(refused)?
        };
        if clone > maximum {
            return Err(refused());
        }
        Ok([canonical, clone])
    }

    /// Names the defining fixed controls before provider replay measurement.
    ///
    /// Iterator construction observes no entries. These requested control
    /// layouts grant no allocation, live ownership or physical stack bound.
    pub fn original_packet_runtime_provider_replay_counter_scratch_data(&self) -> usize {
        let originals = self.custody.originals_by_origin(RequestOrigin::Provider);
        size_of_val(&originals)
            + CompactJson::envelope_preflight_counter_scratch_data()
            + original_json_value_clone_storage_forest_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&ClientOriginal>()
            + size_of::<Option<&Envelope>>()
            + size_of::<[usize; 2]>()
            + size_of::<Result<[usize; 2], ProviderError>>()
            + size_of::<Result<(usize, usize), ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<usize>() * 7
    }
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("packet runtime original provider replay backing")
}
