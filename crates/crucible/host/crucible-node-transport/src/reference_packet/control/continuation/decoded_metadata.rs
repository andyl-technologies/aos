//! Counts both actual decoded Control and independently parsed model ownership.
//!
//! The old Control decoder owns its complete `ControlRecord`, including its
//! model DOM, and a separate decoded model record with another model-state DOM.
//! Neither raw input length nor constructor demand substitutes for this census.

use super::*;
use crate::retained_metadata::{
    MetadataObserver, RetainedProtocolMetadataFacts,
    requested_storage::requested_metadata_backing_storage_data,
};
use std::mem::size_of;

impl PacketDecodedControlSnapshot {
    /// Counts actual initialized backing and the decoded Control's inline root.
    ///
    /// The exhaustive existing Control and model observers retain their own
    /// complete field rosters. The model DOM in the Control record and the
    /// independently parsed model record are separate owners and both count.
    /// This read-only DATA method grants no allocation or restoration right.
    ///
    /// The caller separately admits [`Self::retained_metadata_counter_scratch_data`]
    /// before this allocation-free walk. Parser temporaries, raw input banks,
    /// its surrounding once-attempt and future projection work remain separate.
    ///
    /// # Errors
    /// Refuses metadata traversal/layout overflow or actual retained requested
    /// storage above `maximum` without clearing or changing any decoded field.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.record
            .observe_settled_history_metadata_data(&mut observer)?;
        observer.observe(&self.model)?;
        let backing = requested_metadata_backing_storage_data(&observer.finish())?;
        size_of::<Self>()
            .checked_add(backing)
            .filter(|requested| *requested <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "decoded Control actual retained backing",
            ))
    }

    /// Names the actual fixed visitors and borrowed model-field headers.
    ///
    /// Compiler frames, allocator overhead and separately admitted parsing or
    /// future serialization work are outside this requested-layout DATA value.
    pub fn retained_metadata_counter_scratch_data() -> usize {
        use crate::reference_packet::continuation_models::{
            ModelCapacities, ModelRecord, PacketDecodedModelSnapshot, PacketModelKind,
        };

        ControlRecord::settled_history_counter_scratch_data()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<&Self>()
            + size_of::<&PacketDecodedModelSnapshot>()
            + size_of::<&ModelRecord>()
            + size_of::<(
                &String,
                &PacketModelKind,
                &U64,
                &ContentRef,
                &Position,
                &ModelCapacities,
                &Value,
            )>()
            + size_of::<(&usize, &usize, &usize, &usize, &usize, &usize)>()
            + size_of::<usize>() * 3
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }
}
