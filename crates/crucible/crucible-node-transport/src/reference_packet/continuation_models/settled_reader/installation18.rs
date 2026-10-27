//! Prices the actual current inventory boundary retained by the Held installer.
//!
//! The historical restoration boundary cannot supply this demand: the current
//! pending queues and outputs may have changed. These quotes borrow the same
//! decoded model used by `installation_boundary18_data` and grant no phase.

use super::*;
use crate::retained_metadata::{MetadataObserver, serialization_storage};
use std::mem::size_of;

impl PacketSettledModel17Data {
    /// Quotes the formatter window before the boundary construction prewalk.
    ///
    /// The enclosing owner admits the fixed counter and metadata traversal
    /// first. No serializer, model validator or inventory hash runs here.
    ///
    /// # Errors
    /// Refuses metadata overflow or an independently short formatter maximum.
    pub(crate) fn installation_boundary18_quote_formatter_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_settled_history_metadata_data(&mut observer)?;
        let formatter =
            serialization_storage::original_serialization_formatter_temporary_storage_data(
                &observer.finish(),
            )?;
        if formatter > maximum {
            return Err(boundary_storage_refused());
        }
        Ok(formatter)
    }

    /// Quotes additional retained hash backing, construction work and controls.
    ///
    /// The caller admits the formatter window before this typed serialization
    /// walk. The shared Capture constructor prices the same current inventory
    /// and local validation, including reactive Stage/Commit record checks.
    /// No settled-route eligibility check runs: failed logical state remains
    /// historical DATA. Existing model backing stays separately charged.
    ///
    /// # Errors
    /// Refuses unsupported serialization, checked overflow or insufficient
    /// independent credit for the complete three-axis sum.
    pub(crate) fn installation_boundary18_construction_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let domain = match &self.state {
            CurrentModel::Producer(_) => "source-owned.packet-inventory.v1",
            CurrentModel::Reactive(_) => "source-owned.packet-connected-inventory/4",
        };
        // json_hash retains these three strings after its DOM and canonical
        // bytes drop. The result's inline header belongs to the installer.
        let retained = "blake3-256".len() + domain.len() + 64;
        let transient = self
            .capture_boundary17_construction_data(maximum)?
            .checked_add(size_of::<PacketModelCaptureBoundaryData>() * 2)
            .and_then(|bytes| bytes.checked_add(size_of::<HashRef>() * 2))
            .ok_or_else(boundary_storage_refused)?;
        let scratch = Self::installation_boundary18_construction_counter_scratch_data();
        if retained
            .checked_add(transient)
            .and_then(|bytes| bytes.checked_add(scratch))
            .is_none_or(|bytes| bytes > maximum)
        {
            return Err(boundary_storage_refused());
        }
        Ok([retained, transient, scratch])
    }

    /// Names the boundary quote, validation, hash and projection controls.
    ///
    /// Dynamic formatter work and compiler-generated frames remain separate.
    pub(crate) fn installation_boundary18_construction_counter_scratch_data() -> usize {
        Self::capture_boundary17_construction_counter_scratch_data()
            + Self::adoption18_construction_counter_scratch_data()
            + canonical::canonical_json_counter_scratch_bytes_data()
            + size_of::<&Self>()
            + size_of::<&str>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 64]>()
            + size_of::<[usize; 3]>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<Result<PacketModelCaptureBoundaryData, ProviderError>>()
            + size_of::<usize>() * 8
    }
}

fn boundary_storage_refused() -> ProviderError {
    ProviderError::ResourceExhausted("current model18 installation boundary storage")
}
