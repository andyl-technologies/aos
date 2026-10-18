//! Completes each Source root only after genuine parent and native custody join.
//!
//! The Source attempt keeps initialized parse and typed products on refusal.
//! Moving its completed result remains separate from all-owner publication.

use super::*;
use crate::node_adapters::cnp::OriginalInitial15ArchivedGroup;
use super::super::initial15_history::{
    HistoricalInitial15Scope17, authenticate_initial15_source_member17_data,
    initial15_source_member17_counter_scratch_data,
};
use super::super::parent_index::ParentArchive17ReadScope;

impl RetainedCold17Collection {
    /// Completes a real Source and its full original Initial15 correspondence.
    ///
    /// # Errors
    /// Refuses spent slots, missing actual operands, failed Source/native/SDK
    /// correspondence, renewed original custody or insufficient admitted storage.
    pub(super) fn read_completed_source_data(
        &mut self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        selected: usize,
        additional: usize,
    ) -> Result<(), StateError> {
        let source_index = RestoredArchive17SourceIndex::from_data(selected)?;
        let step = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::Source(source_index),
        )?;
        let scratch = source_counter_scratch_data();
        self.begin_terminal_stage_data(scope, step, 0, scratch)?;
        let maximum = maximum(scope)?;
        let member = self.member(selected)?;
        if member.source_attempt.is_some() || member.source.is_some() {
            return Err(refused("cold17 completed Source slot is already spent"));
        }
        let objects = member
            .objects
            .as_ref()
            .ok_or_else(|| refused("cold17 Source object map absent"))?;
        let literal = body(scope, &objects.semantic)?;
        let sdk = member
            .sdk_capture
            .as_ref()
            .ok_or_else(|| refused("cold17 Source SDK capture absent"))?;
        let prefix = body(scope, &sdk.request_data().history_prefix)?;
        let node = member
            .node
            .as_ref()
            .ok_or_else(|| refused("cold17 Source Node absent"))?;
        let controller = member
            .controller
            .as_ref()
            .ok_or_else(|| refused("cold17 Source Controller absent"))?;
        let native = member
            .native
            .as_ref()
            .ok_or_else(|| refused("cold17 Source native owner absent"))?;
        let quote = OriginalSourceRestoredSettled17Read::completed_decode_construction_data(
            &objects.semantic,
            node.reference_data(),
            literal,
            prefix,
            controller,
            native,
            sdk,
            maximum,
        )
        .map_err(crate::node_state::schema)?;
        let row_scratch = scratch
            .checked_add(quote.declared_counter_scratch_bytes_data())
            .ok_or_else(|| refused("cold17 Source constructor workspace overflow"))?;
        self.construct_terminal_stage_data(
            scope,
            step,
            quote.retained_requested_bytes_data(),
            quote.maximum_simultaneous_transient_bytes_data(),
            row_scratch,
        )?;

        let prior_cache = self.terminal_cache;
        let Self {
            members,
            parents,
            initial15_group,
            historical_scope,
            ..
        } = self;
        let parent = parents
            .last()
            .and_then(Option::as_ref)
            .ok_or_else(|| refused("cold17 Source parent occurrence absent"))?
            .borrow_data(scope)?;
        let group = initial15_group
            .as_ref()
            .ok_or_else(|| refused("cold17 original Initial15 group absent"))?;
        let historical = historical_scope
            .as_ref()
            .ok_or_else(|| refused("cold17 original historical scope absent"))?;
        let member = members
            .get_mut(selected)
            .and_then(Option::as_mut)
            .ok_or_else(|| refused("cold17 Source member absent"))?;
        let objects = member
            .objects
            .as_ref()
            .ok_or_else(|| refused("cold17 Source object map absent"))?;
        let ancestry = member
            .ancestry
            .as_ref()
            .ok_or_else(|| refused("cold17 Source ancestry absent"))?;
        let controller = member
            .controller
            .as_ref()
            .ok_or_else(|| refused("cold17 Source Controller absent"))?;
        let native = member
            .native
            .as_ref()
            .ok_or_else(|| refused("cold17 Source native owner absent"))?;
        let node = member
            .node
            .as_ref()
            .ok_or_else(|| refused("cold17 Source Node absent"))?;
        let sdk = member
            .sdk_capture
            .as_ref()
            .ok_or_else(|| refused("cold17 Source SDK capture absent"))?;
        let prelude = member
            .prelude
            .as_ref()
            .ok_or_else(|| refused("cold17 Source first component absent"))?;
        let input = OriginalSourceRestoredSettled17ReadInputs {
            controller,
            native,
            node,
            held: native
                .restoration_hold_data()
                .map_err(crate::node_state::schema)?,
            world: &scope.runtime.source_activation,
            inherited: None,
            prefix_bytes: prefix,
            runtime_reference: &scope.checkpoint.safe_point.runtime,
            parent_archive_reference: parent.index_reference_data()?,
            parent_manifest_reference: parent.manifest_reference_data()?,
            first_semantic_reference: &ancestry.first_semantic,
            restoration_hold_reference: &ancestry.restoration_hold,
            journal_ancestry: ancestry,
            checkpoint_reference: scope.checkpoint_reference,
            checkpoint_bytes: body(scope, scope.checkpoint_reference)?,
            maximum_coordinator_records: prelude.maximum_coordinator_records_data(),
            maximum_bank_bytes: record_maximum(scope)?,
            maximum_transcript: maximum,
        };
        OriginalSourceRestoredSettled17Read::read_completed_into_data(
            &objects.semantic,
            literal,
            &input,
            sdk,
            prior_cache,
            maximum,
            &mut member.source_attempt,
        )
        .map_err(crate::node_state::schema)?;

        // The component reader cannot infer its parent from caller references.
        // The genuine group and reconstructed historical scope close that join
        // while the typed result still resides in its original attempt.
        let attempt = member
            .source_attempt
            .as_mut()
            .ok_or_else(|| refused("cold17 Source decoder attempt absent"))?;
        authenticate_initial15_source_member17_data(
            &parent,
            group,
            scope,
            node,
            attempt
                .completed_data()
                .map_err(crate::node_state::schema)?,
            native,
            ancestry,
            historical,
        )?;
        attempt
            .take_completed_into_data(&mut member.source)
            .map_err(crate::node_state::schema)?;
        self.finish_terminal_stage_data(scope, step, additional)
    }
}

/// Names Source constructor, original-parent comparison and borrowed view controls.
pub(super) fn source_counter_scratch_data() -> usize {
    counter_scratch_data()
        + OriginalSourceRestoredSettled17Read::completed_decode_counter_scratch_data()
        + initial15_source_member17_counter_scratch_data()
        + size_of::<OriginalSourceRestoredSettled17ReadInputs<'static>>()
        + size_of::<&OriginalInitial15ArchivedGroup>()
        + size_of::<&HistoricalInitial15Scope17>()
        + size_of::<&ParentArchive17ReadScope<'static, 'static>>()
        + size_of::<Result<(), RuntimeError>>()
}
