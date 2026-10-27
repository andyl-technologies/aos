//! Prices runtime identity work before allocating or moving a suffix owner.
//!
//! Legacy retries use their actual frame expansion window independently of
//! remaining suffix credit. Legacy response clones instead use the original
//! journal's actual canonical debit, which can exceed the current frame limit.

use super::*;
use crate::retained_metadata::serialization_storage::{
    original_json_value_clone_storage_forest_counter_scratch_data,
    original_json_value_clone_storage_forest_data,
};

impl CnpController {
    /// Prices compact runtime identity work from this original session.
    ///
    /// Returns `[retained, transient, counter]` DATA without constructing a
    /// suffix, content store or replacement owner. The same private limits used
    /// by the later handoff must support its unchanged request ceiling and
    /// remaining byte allowance. Legacy retry identities still receive their
    /// complete frame-derived output window when that allowance is small.
    ///
    /// The caller first admits
    /// [`Self::original_compact_runtime_identity_counter_scratch_data`]. This
    /// query neither authenticates live ownership nor admits a Source handoff.
    /// Journal backing, legacy reply clones, connection work, typed bodies,
    /// materialization and failure owners require independent funding.
    ///
    /// # Errors
    /// Refuses unsupported original limits, exhausted or inconsistent remaining
    /// credit, checked overflow, or a complete row above `maximum`.
    pub fn original_compact_runtime_identity_storage_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let mut row = self
            .session
            .compact_runtime_identity_storage_data(&self.custody)?;
        row[2] = Self::original_compact_runtime_identity_counter_scratch_data();
        let peak = row.into_iter().try_fold(0usize, |total, bytes| {
            total.checked_add(bytes).ok_or_else(refused)
        })?;
        if peak > maximum {
            return Err(refused());
        }
        Ok(row)
    }

    /// Names the defining fixed controls before the runtime identity query.
    ///
    /// These requested layouts supply no physical stack bound or admission.
    pub fn original_compact_runtime_identity_counter_scratch_data() -> usize {
        ClientSession::compact_runtime_identity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<usize>() * 4
    }

    /// Bounds one fresh legacy response clone using actual retained bytes.
    ///
    /// A provider retry can clone a response retained before the current frame
    /// limit was selected. The original journal's irreversibly consumed complete
    /// canonical bytes bound that response independently of its current frame
    /// limit and independently of unconsumed suffix credit. An empty history
    /// needs no clone. This conservative bound includes an inline Envelope;
    /// the original owner remains separately retained and charged.
    ///
    /// This allocation-free DATA query prices resulting fresh clone backing
    /// only. It excludes codec work, other simultaneous copies, correlation,
    /// diagnostics and physical stack. It grants no permission to replay or
    /// move an owner. The caller first admits
    /// [`Self::original_compact_runtime_legacy_clone_counter_scratch_data`].
    ///
    /// # Errors
    /// Refuses inconsistent original debit, unsupported pinned clone layouts,
    /// checked overflow, or clone backing above `maximum`.
    pub fn original_compact_runtime_legacy_clone_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let [ceiling, retained] = self.custody.runtime_journal_bytes_data();
        if retained > ceiling {
            return Err(refused());
        }
        let bytes = if retained == 0 {
            0
        } else {
            original_json_value_clone_storage_forest_data(retained, 1)?
                .checked_add(size_of::<Envelope>())
                .ok_or_else(refused)?
        };
        if bytes > maximum {
            return Err(refused());
        }
        Ok(bytes)
    }

    /// Names the fixed controls before the original-debit clone query.
    pub fn original_compact_runtime_legacy_clone_counter_scratch_data() -> usize {
        original_json_value_clone_storage_forest_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<[usize; 2]>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<usize>() * 5
    }
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("compact runtime identity or legacy clone backing")
}
