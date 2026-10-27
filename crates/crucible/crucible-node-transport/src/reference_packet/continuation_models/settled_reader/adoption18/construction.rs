//! Quotes the actual complete current-model transfer before its construction.
//!
//! The row separates the new attempt header, transferred existing backing,
//! validation allocations, by-value moves and fixed counter controls. The same
//! original escrow must retain the existing model charge through the move; this
//! DATA neither renews that charge nor grants any enclosing native phase.

use super::super::ReactiveModel17Data;
use super::*;
use crate::retained_metadata::{RetainedProtocolMetadataFacts, serialization_storage};
use std::{collections::BTreeSet, mem::align_of};

/// Reports the complete model component without supplying a native phase grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentModel18ConstructionData {
    owner: usize,
    transferred_backing: usize,
    validation_temporary: usize,
    moved_values: usize,
    counter: usize,
    requested: usize,
}

impl CurrentModel18ConstructionData {
    /// Returns the new header, transferred backing, validation, moves and controls.
    pub fn requested_terms_data(self) -> [usize; 5] {
        [
            self.owner,
            self.transferred_backing,
            self.validation_temporary,
            self.moved_values,
            self.counter,
        ]
    }

    /// Returns retained, temporary and fixed-control terms for this model alone.
    ///
    /// Retained storage includes the attempt and transferred existing backing;
    /// the original charge must follow that backing through the move. Temporary
    /// storage includes validation and by-value outputs. No enclosing archive,
    /// socket, Control, Hold or native phase permission follows from these axes.
    pub fn requested_phase_terms_data(self) -> [usize; 3] {
        // The private constructor checked the complete five-term sum, so both
        // nonnegative partial sums are representable as well.
        [
            self.owner + self.transferred_backing,
            self.validation_temporary + self.moved_values,
            self.counter,
        ]
    }

    /// Returns this whole model component's independently restricted demand.
    pub fn requested_bytes(self) -> usize {
        self.requested
    }
}

impl PacketSettledModel17Data {
    /// Quotes the defining validation and same-backing socket transfer as DATA.
    ///
    /// The caller admits this traversal and its fixed counters before quoting.
    /// Typed Bytes formatting requires the separate window returned by
    /// `adoption18_quote_formatter_temporary_data` before this call. That pure
    /// metadata prewalk does not invoke a serializer or construct a formatter.
    /// Existing decoded backing is reported explicitly, so its original charge
    /// can follow the ownership move. No allocation for another decoded model,
    /// native socket, archive, Control, Hold or phase grant is included here.
    /// Those independent owners must remain in the enclosing complete demand.
    /// Allocator overhead and compiler-generated frames remain separate.
    ///
    /// # Errors
    /// Refuses metadata/traversal overflow, unsupported serialization or a whole
    /// component demand larger than the independent requested-storage maximum.
    pub(crate) fn adoption18_construction_data(
        &self,
        maximum: usize,
    ) -> Result<CurrentModel18ConstructionData, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_settled_history_metadata_data(&mut observer)?;
        let facts = observer.finish();
        let transferred_backing = requested_metadata_backing_storage_data(&facts)?;
        let validation_temporary = match &self.state {
            CurrentModel::Producer(state) => {
                // The actual definition validator builds one set of borrowed
                // event IDs. Definition comparison itself borrows both sides.
                crate::retained_metadata::requested_storage::tree_storage_data(
                    1,
                    state.events.len(),
                    size_of::<&crucible_node_format::Id>(),
                    align_of::<&crucible_node_format::Id>(),
                )?
            }
            CurrentModel::Reactive(state) => state.adoption18_validation_temporary_data(facts)?,
        };
        let mut result = CurrentModel18ConstructionData {
            owner: size_of::<Option<CurrentModel18Adoption>>(),
            transferred_backing,
            validation_temporary,
            moved_values: moved_value_temporary_data(),
            counter: Self::adoption18_construction_counter_scratch_data(),
            requested: 0,
        };
        result.requested = result
            .requested_terms_data()
            .into_iter()
            .try_fold(0usize, |total, value| total.checked_add(value))
            .filter(|total| *total <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "current model18 construction",
            ))?;
        Ok(result)
    }

    /// Quotes formatter work before invoking the model construction serializer.
    ///
    /// This pure metadata prewalk uses only the already admitted observer and
    /// fixed counters. Its result must be admitted before the main quote's
    /// typed serializer runs; it grants no constructor or native phase.
    ///
    /// # Errors
    /// Refuses traversal, arithmetic or an insufficient formatter restriction.
    pub(crate) fn adoption18_quote_formatter_temporary_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_settled_history_metadata_data(&mut observer)?;
        let facts = observer.finish();
        let bytes = match &self.state {
            CurrentModel::Producer(_) => 0,
            CurrentModel::Reactive(_) => {
                serialization_storage::original_serialization_formatter_temporary_storage_data(
                    &facts,
                )?
            }
        };
        if bytes > maximum {
            return Err(ProviderError::ResourceExhausted(
                "current model18 quote formatter",
            ));
        }
        Ok(bytes)
    }

    /// Names the model quote's defining views and fixed constructor controls.
    pub(crate) fn adoption18_construction_counter_scratch_data() -> usize {
        size_of::<CurrentModel18ConstructionData>()
            + size_of::<Result<CurrentModel18ConstructionData, ProviderError>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<&Self>()
            + size_of::<&ProducerState>()
            + size_of::<&ReactiveModel17Data>()
            + size_of::<&PacketConnectedSourceProgram>()
            + size_of::<&mut Option<Self>>()
            + size_of::<&mut Option<CurrentModel18Adoption>>()
            + size_of::<&mut CurrentModel18Adoption>()
            + size_of::<&mut Option<UnixDatagram>>()
            + size_of::<&mut Option<CurrentModel18Program>>()
            + size_of::<ThreadId>()
            + size_of::<std::thread::Thread>()
            + size_of::<u32>()
            + size_of::<bool>() * 6
            + size_of::<BTreeSet<&crucible_node_format::Id>>()
            + size_of::<std::slice::Iter<'static, crate::reference_packet::PacketEvent>>()
            + size_of::<Option<&crate::reference_packet::PacketEvent>>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<usize>() * 5
            + serialization_storage::original_serialization_counter_scratch_data()
            + ReactiveModel17Data::adoption18_validation_counter_scratch_data()
    }
}

fn moved_value_temporary_data() -> usize {
    // Keep both concrete branches and their discriminated outputs. These are
    // by-value constructors, not a fresh allocation of the transferred backing.
    size_of::<CurrentModel18Adoption>()
        + size_of::<Option<CurrentModel18Adoption>>()
        + size_of::<PacketSettledModel17Data>()
        + size_of::<Option<PacketSettledModel17Data>>()
        + size_of::<CurrentModel18Program>()
        + size_of::<Option<CurrentModel18Program>>()
        + size_of::<PacketProgram>()
        + size_of::<PacketConnectedProgram>()
        + size_of::<ProducerState>()
        + size_of::<ReactiveModel17Data>()
        + size_of::<UnixDatagram>()
        + size_of::<Option<UnixDatagram>>()
}
