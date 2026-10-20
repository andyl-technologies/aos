//! Prepares actual conditional model custody from a source-authenticated Tape2 pin.
//!
//! Complete Runtime7 and source journals remain owned. No physical backend,
//! capture facet, operation token or input permission is reconstructed here.
//! Readiness stays blocked until the owning runtime supplies its opaque validated
//! FIRST/SOURCE-CAPTURE/TARGET context through the distinct admission hook.

use super::*;
use crate::node_state::VerifiedStateContent;

/// Returns complete original source custody when fresh model preparation refuses.
pub struct Tape2PreparationFailure {
    error: TranscriptError,
    source: super::super::PinnedTape2Continuation,
}

impl Tape2PreparationFailure {
    /// Borrows the genuine target/source qualification refusal.
    pub fn error(&self) -> &TranscriptError {
        &self.error
    }

    /// Returns both the refusal and unchanged complete original source ownership.
    pub fn into_parts(self) -> (TranscriptError, super::super::PinnedTape2Continuation) {
        (self.error, self.source)
    }
}

impl TranscriptReplayNode {
    /// Prepares a fresh inactive model from complete original Tape2 source custody.
    ///
    /// The installed conditional policy independently qualifies the source/context
    /// for the exact fresh graph. Cursor, native boundary and all source bodies stay
    /// original. The complete Runtime7 is never projected into a legacy snapshot.
    /// Physical preservation remains unsupported; cached permissions are installed
    /// only by a later qualified whole-runtime restoration path.
    ///
    /// # Errors
    /// Returns unchanged original source ownership for foreign compatibility,
    /// nonfresh owners, unsupported selected codec or installed policy refusal.
    pub fn prepare_restored_original_lineage(
        source: super::super::PinnedTape2Continuation,
        graph: &AdmittedGraph,
        route: NodeRoute,
        context: &[InputPayload],
        policy: &dyn InstalledReplayPolicy,
    ) -> Result<Self, Tape2PreparationFailure> {
        let checked = (|| -> Result<Self, TranscriptError> {
            let binding = graph
                .binding(&route.node)
                .ok_or_else(|| invalid("fresh Tape2 binding absent"))?;
            if binding.compatibility != source.wire.binding.compatibility
                || graph.world_binding_hash()
                    != &source.source.runtime().source_activation.world_binding_hash
                || route.node != source.wire.route.node
                || route.owners.len() != source.wire.route.owners.len()
                || route
                    .owners
                    .iter()
                    .zip(&source.wire.route.owners)
                    .any(|(fresh, old)| {
                        fresh.owner != old.owner
                            || fresh.incarnation == old.incarnation
                            || fresh.generation <= old.generation
                    })
                || !binding
                    .compatibility
                    .operating_contract
                    .facets
                    .iter()
                    .any(|facet| {
                        facet.id.as_str()
                            == super::super::TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE
                            && facet.version == 2
                    })
                || !binding.compatibility.implementation.formats.contains(
                    &super::super::original_lineage_continuation_schema()
                        .map_err(|error| invalid(error.reason))?,
                )
            {
                return Err(invalid(
                    "fresh Tape2 scope differs from its authenticated source",
                ));
            }
            let mut model = Self::prepare(
                source.transcript.as_ref().clone(),
                graph,
                route,
                context,
                policy,
            )?;
            let cursor = model
                .cursor
                .as_mut()
                .ok_or_else(|| invalid("fresh Tape2 cursor absent"))?;
            if cursor.original_lineage.is_none() || model.preservation.is_some() {
                return Err(invalid(
                    "Tape2 restoration requires separate original lineage qualification",
                ));
            }
            cursor.next = usize::try_from(source.wire.cursor.next_record.get()).map_err(invalid)?;
            cursor.diverged = source.wire.cursor.diverged;
            model.boundary = source.wire.boundary;
            Ok(model)
        })();
        match checked {
            Ok(mut model) => {
                model.restored_lineage = Some(source);
                Ok(model)
            }
            Err(error) => Err(Tape2PreparationFailure { error, source }),
        }
    }

    pub(super) fn validate_tape2_restoration(
        &self,
        source_record: &ContentRef,
        record: &OriginalLineageRuntimeRecord,
        scope: &OriginalLineageNativeScope,
        content: &VerifiedStateContent,
    ) -> Result<(), OperationFailure> {
        let source = self.restored_lineage.as_ref().ok_or_else(|| {
            failure(
                "authentic complete Tape2 source custody absent",
                EffectKnowledge::None,
            )
        })?;
        if self.thread != std::thread::current().id()
            || self.quarantined
            || !self.operations.is_empty()
            || !self.inputs.is_empty()
            || !self.observations.is_empty()
            || source_record != source.source.runtime_reference()
            || record != source.source.runtime()
            || scope.coordinator_schema != 7
            || &scope.source_record != source_record
            || scope.source_capture != record.source_activation
            || scope.target.world_binding_hash != record.source_activation.world_binding_hash
            || scope.target.boundary != record.capture_cut
            || scope.target.generation <= record.source_activation.generation
            || scope.target.activation_id == record.source_activation.activation_id
            || self.cursor_snapshot().as_ref() != Some(&source.wire.cursor)
            || self.boundary != source.wire.boundary
            || self
                .ready
                .as_ref()
                .is_some_and(|(world, _)| world != &scope.target)
            || self
                .restored_lineage_target
                .as_ref()
                .is_some_and(|world| world != &scope.target)
            || self
                .route
                .owners
                .iter()
                .any(|fresh| !scope.target.owners.contains(fresh))
            || source
                .wire
                .route
                .owners
                .iter()
                .zip(&self.route.owners)
                .any(|(old, fresh)| {
                    !scope
                        .owners
                        .iter()
                        .any(|mapping| &mapping.source == old && &mapping.target == fresh)
                })
        {
            return Err(failure(
                "actual Tape2 source/target/cursor journal custody differs",
                EffectKnowledge::None,
            ));
        }
        let receipts = self.tape2_input_receipts(&scope.target)?;
        if !receipts.iter().map(|(ack, _)| ack).eq(scope
            .input_acknowledgements
            .iter()
            .filter(|ack| ack.node == self.route.node))
        {
            return Err(failure(
                "actual Tape2 fresh ACK evidence changed",
                EffectKnowledge::None,
            ));
        }
        for reference in &source.source.source().owner().evidence {
            if content.get(reference) != source.source.original_body(reference)
                || content.get(reference).is_none()
            {
                return Err(failure(
                    "actual Tape2 original journal body changed",
                    EffectKnowledge::None,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn admit_tape2_restoration(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        let source = self.restored_lineage.as_ref().ok_or_else(|| {
            failure(
                "authentic complete Tape2 source custody absent",
                EffectKnowledge::None,
            )
        })?;
        if context.source_record() != source.source.runtime_reference()
            || context.record() != source.source.runtime()
            || self.restored_lineage_target.is_some()
            || self.ready.is_some()
            || self.thread != std::thread::current().id()
            || self.quarantined
            || context.target().world_binding_hash
                != context.record().source_activation.world_binding_hash
            || context.target().boundary != context.record().capture_cut
            || context.target().generation <= context.record().source_activation.generation
            || context.target().activation_id == context.record().source_activation.activation_id
            || self
                .route
                .owners
                .iter()
                .any(|owner| !context.target().owners.contains(owner))
            || !self.operations.is_empty()
            || !self.inputs.is_empty()
            || !self.observations.is_empty()
            || self.cursor_snapshot().as_ref() != Some(&source.wire.cursor)
            || self.boundary != source.wire.boundary
        {
            return Err(failure(
                "Tape2 context was changed or already admitted",
                EffectKnowledge::None,
            ));
        }
        for reference in &source.source.source().owner().evidence {
            if context.original_body(reference) != source.source.original_body(reference)
                || context.original_body(reference).is_none()
            {
                return Err(failure(
                    "Tape2 context omits original source journals",
                    EffectKnowledge::None,
                ));
            }
        }
        self.restored_lineage_target = Some(context.target().clone());
        Ok(())
    }
}
