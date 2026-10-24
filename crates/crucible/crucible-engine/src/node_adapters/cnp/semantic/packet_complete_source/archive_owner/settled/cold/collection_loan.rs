//! Shares exact retained-collection custody guards before and after target birth.
//!
//! Metadata construction only borrows immutable completed owners. The separate
//! full conversion repeats the defining native current-checkpoint validator
//! after its independent prospective authentication row has been admitted.

use super::*;
use crate::node_state::RetainedCold17Collection;
use crucible_node_format::U64;
use crucible_node_transport::reference_packet::{
    control::PacketNative5UnderlyingRecord, service::complete_restore::PacketNativeRestoredRecord,
};

type CurrentCheckpoint17<'a> = (
    &'a PacketNativeRestoredRecord,
    &'a PacketNative5UnderlyingRecord,
    &'a ContentRef,
    U64,
);

impl<'a> OriginalRestoredSettledColdOwnerMetadata<'a> {
    /// Borrows the same completed decoder bank under an actual Source/ticket pair.
    ///
    /// `expected` must be the actual Source Rc selected from the genuine target
    /// authority's immutable roster. The caller authenticates that authority and
    /// roster before and after its synchronous loan; static-equal metadata does
    /// not establish Rc membership. This helper authenticates the exact Rc pair
    /// and archive/ticket/collection custody, without native semantic revalidation.
    ///
    /// # Errors
    /// Refuses another Source Rc, ticket/archive/collection, incomplete production
    /// validation, changed native roles, absent bodies or unequal original caps.
    pub(crate) fn from_retained_collection_data(
        archive: &'a CompleteOriginalRestorationSource,
        collection: &'a RetainedCold17Collection,
        expected: &'a Rc<PacketCompleteSemanticSource>,
        source: &Rc<PacketCompleteSemanticSource>,
        ticket: &'a CompleteOriginalNativeTicket,
    ) -> Result<Self, RuntimeError> {
        archive.inner.authenticate_birth()?;
        collection.authenticate_completed_data(archive.archive())?;
        collection.authenticate_production_declaration_data(archive.archive())?;
        if !Rc::ptr_eq(expected, source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        ticket.authenticate_source(archive)?;
        let owner = ticket.owner()?;
        let mut selected_owner = None;
        for (index, row) in archive.archive().owners().iter().enumerate() {
            if std::ptr::eq(row, owner) {
                selected_owner = Some(index);
                break;
            }
        }
        let owner_index = selected_owner.ok_or(RuntimeError::ForeignAuthority)?;
        let retained = collection.member_data(archive.archive(), owner_index)?;
        if &owner.state != retained.references[0] {
            return Err(RuntimeError::ForeignAuthority);
        }
        let data = ticket.restored_native_import_construction_data()?;
        data.authenticate_original_references_data(retained.references)?;
        let content = archive.content();
        let body = |reference| content.get(reference).ok_or(RuntimeError::InvalidReceipt);
        let input = RestoredSettledNative17Input {
            snapshot: (retained.references[0], body(retained.references[0])?),
            current_protocol: (retained.references[1], body(retained.references[1])?),
            control: (retained.references[2], body(retained.references[2])?),
            anchor: (retained.references[3], body(retained.references[3])?),
            journal: (retained.references[4], body(retained.references[4])?),
        };
        // The same immutable Source and fixed sealed-owner slots retain these
        // exact bodies. Full body hashing occurred under the strict constructor's
        // admission; this signing loan performs no unquoted repeated body walk.
        if data.archived_input_byte_extents_data()
            != input.roles_data().map(|(_, bytes)| bytes.len())
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let native = retained.native;
        if native
            .body_reference()
            .map_err(|_| RuntimeError::InvalidReceipt)?
            != retained.references[1]
            || native
                .encoded_body()
                .map_err(|_| RuntimeError::InvalidReceipt)?
                .len()
                != input.current_protocol.1.len()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let controller = retained.controller;
        controller
            .parts_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let node = retained.node;
        let source_history = retained.source_history;
        if node.node_data() != &source.installation().descriptor.id
            || !owner.evidence.contains(source_history.reference_data())
            || content.get(source_history.reference_data()).is_none()
            || content.get(node.reference_data()).is_none()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let limits = source_history.original_generic_limits_data();
        let installed = source.installation();
        if limits
            != (
                installed.maximum_operations,
                installed.maximum_semantic_bytes,
                installed.maximum_result_bytes,
                installed.maximum_authorization_bytes,
            )
            || source_history.historical_associations_count_data() > limits.0
            || node.retained_semantic_credit_data() > limits.1
        {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(OriginalRestoredSettledColdOwnerMetadata {
            source: expected,
            owner,
            host: archive.restored_host_record_data()?,
            native,
            controller,
            node,
            source_history,
            input,
            controller_reference: retained.controller_reference,
            native_before_reference: retained.native_before_reference,
            native_limits: retained.native_limits,
            source_decode_axes: retained.source_decode_axes,
        })
    }

    /// Declares fixed workspace for the shared metadata/full guard path.
    ///
    /// Provider current-checkpoint prewalk and full validator rows remain
    /// independent; this getter grants no construction or allocation credit.
    pub(crate) fn retained_collection_counter_scratch_data() -> usize {
        OriginalRestoredSettledColdGroup::counter_scratch_data()
    }

    /// Repeats the full native current-checkpoint guard under independent credit.
    ///
    /// Its defining auth2 bootstrap S, formatter prewalk T/S and complete
    /// construction T/S must all be admitted before entry. Metadata and Source
    /// history decode rows are not permission to run this allocating validator.
    ///
    /// # Errors
    /// Refuses a substituted or invalid complete current native checkpoint.
    pub(crate) fn authenticate_current_checkpoint_data(
        self,
    ) -> Result<OriginalRestoredSettledColdOwnerView<'a>, RuntimeError> {
        let checkpoint = self.source_history.current_checkpoint_data()?;
        self.native
            .authenticate_current_checkpoint_data(checkpoint.0, checkpoint.1, checkpoint.2)
            .map_err(|_| RuntimeError::InvalidReceipt)?;

        Ok(OriginalRestoredSettledColdOwnerView {
            source: self.source,
            owner: self.owner,
            host: self.host,
            native: self.native,
            controller: self.controller,
            node: self.node,
            source_history: self.source_history,
            input: self.input,
            controller_reference: self.controller_reference,
            native_before_reference: self.native_before_reference,
            native_limits: self.native_limits,
            source_decode_axes: self.source_decode_axes,
        })
    }
}

/// Names direct arguments/results introduced by the shared collection borrower.
pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    RetainedCold17Collection::completed_loan_counter_scratch_data()
        + size_of::<&CompleteOriginalRestorationSource>()
        + size_of::<&crate::node_state::VerifiedStateContent>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, NativeOwnerState>>>()
        + size_of::<Option<usize>>()
        + size_of::<&RetainedCold17Collection>()
        + size_of::<(
            &Rc<PacketCompleteSemanticSource>,
            &Rc<PacketCompleteSemanticSource>,
        )>()
        + size_of::<&CompleteOriginalNativeTicket>()
        + size_of::<OriginalRestoredSettledColdOwnerMetadata<'static>>()
        + size_of::<Result<OriginalRestoredSettledColdOwnerMetadata<'static>, RuntimeError>>()
        + size_of::<Result<OriginalRestoredSettledColdOwnerView<'static>, RuntimeError>>()
        + size_of::<CurrentCheckpoint17<'static>>()
        + size_of::<Result<CurrentCheckpoint17<'static>, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
}
