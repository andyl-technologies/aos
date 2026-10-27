//! Quotes the same ticket-selected current model before original Source birth.
//!
//! The completed decoder collection remains under its original archive. These
//! synchronous loans derive one model component without parsing worker output,
//! copying model backing or promoting historical DATA to a fresh phase grant.

use super::*;
use crate::node_state::{CompleteOriginalNativeTicket, RetainedCold17Collection};
use crucible_node_transport::protocol_snapshot::restored_settled17::{
    RestoredSettledNativeImportModelConstructionData, SealedHistoricalRestoredSettledNative17,
};
use std::mem::size_of;

impl CompleteOriginalRestorationSource {
    /// Quotes formatter work from this original ticket's retained current model.
    ///
    /// The caller first admits the fixed counter and metadata traversal. After
    /// this loan returns, it admits the formatter window before requesting the
    /// main model construction quote. No allocating model validation occurs.
    ///
    /// # Errors
    /// Refuses foreign archive/ticket custody, an incomplete or moved decoder
    /// collection, started target binding, changed original references, model
    /// metadata overflow or an insufficient formatter restriction.
    pub fn original_restored_model18_quote_formatter_temporary_data(
        &self,
        ticket: &CompleteOriginalNativeTicket,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.with_original_restored_model18_data(ticket, |native| {
            native
                .current_model18_quote_formatter_temporary_data(maximum)
                .map_err(|_| RuntimeError::ResourceLimit)
        })
    }

    /// Derives the model construction component from the original decoded owner.
    ///
    /// The caller admits this traversal, its defining counter and the separately
    /// quoted formatter window before entry. Admission callbacks run after this
    /// synchronous loan releases the collection guard. The returned component
    /// includes existing backing whose original charge must survive transfer;
    /// it supplies no complete Recipe, Initial, native admission or phase claim.
    ///
    /// # Errors
    /// Refuses foreign or unavailable original custody, started target binding,
    /// changed reference correspondence, unsupported typed serialization,
    /// arithmetic overflow or insufficient whole-model requested storage.
    pub fn original_restored_model18_construction_data(
        &self,
        ticket: &CompleteOriginalNativeTicket,
        maximum: usize,
    ) -> Result<RestoredSettledNativeImportModelConstructionData, RuntimeError> {
        self.with_original_restored_model18_data(ticket, |native| {
            native
                .current_model18_construction_data(maximum)
                .map_err(|_| RuntimeError::ResourceLimit)
        })
    }

    /// Names the original collection loan and model quote's fixed controls.
    ///
    /// Each formatter prewalk and construction traversal needs its own admitted
    /// invocation. Dynamic metadata work, formatter storage, enclosing phase
    /// owners and compiler-generated frames remain separate terms.
    pub fn original_restored_model18_construction_counter_scratch_data() -> usize {
        Self::restored_decoded_collection_prebirth_counter_scratch_data::<
            RestoredSettledNativeImportModelConstructionData,
        >() + Self::restored_decoded_collection_prebirth_counter_scratch_data::<usize>()
            + SealedHistoricalRestoredSettledNative17::current_model18_construction_counter_scratch_data()
            + size_of::<&CompleteOriginalNativeTicket>()
            + size_of::<&crate::node_state::NativeOwnerState>()
            + size_of::<&crate::node_state::CompleteRestoredSettledNativeRestorationData>()
            + size_of::<&SealedHistoricalRestoredSettledNative17>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[&ContentRef; 5]>()
            + size_of::<[[u8; 32]; 5]>()
            + size_of::<std::array::IntoIter<&ContentRef, 5>>()
            + size_of::<std::array::IntoIter<&str, 4>>()
            + size_of::<[u8; 8]>()
            + size_of::<usize>() * 2
            + size_of::<Result<(), RuntimeError>>()
    }

    fn with_original_restored_model18_data<R>(
        &self,
        ticket: &CompleteOriginalNativeTicket,
        inspect: impl FnOnce(&SealedHistoricalRestoredSettledNative17) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.with_restored_decoded_collection_prebirth_data(ticket, |collection| {
            let native = self.original_restored_model18_member_data(collection, ticket)?;
            inspect(native)
        })
    }

    fn original_restored_model18_member_data<'a>(
        &self,
        collection: &'a RetainedCold17Collection,
        ticket: &CompleteOriginalNativeTicket,
    ) -> Result<&'a SealedHistoricalRestoredSettledNative17, RuntimeError> {
        let owner = ticket.owner()?;
        let member = collection.member_data(self.archive(), ticket.owner_index)?;
        if &owner.state != member.references[0] {
            return Err(RuntimeError::ForeignAuthority);
        }

        // Ticket identity was checked before borrowing the collection. Keep the
        // separately validated construction row bound to these same five roles;
        // neither a worker bank nor an announced scalar selects another model.
        ticket
            .restored_native_import_construction_data()?
            .authenticate_original_references_data(member.references)?;
        Ok(member.native)
    }
}
