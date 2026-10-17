//! Binds original native Tape2 facts to actual conditional runtime permissions.
//!
//! The selected installed policy has authenticated the complete original native
//! journals independently. These callbacks additionally require this owning
//! node's current activation, cached terminal permission and consumed tape prefix.
//! Native adapters retain their strict current-scope path and default refusal.

use super::*;

impl TranscriptReplayNode {
    pub(super) fn conditional_input_scope(
        &self,
        batch: &RuntimeInputBatch,
    ) -> Result<SavedOriginalInputScope, OperationFailure> {
        self.same_world(batch.activation())?;
        if self
            .lineage_activation
            .as_ref()
            .is_some_and(|actual| !Rc::ptr_eq(&actual.authority, &batch.activation().authority))
        {
            return Err(failure(
                "foreign conditional runtime authority",
                EffectKnowledge::None,
            ));
        }
        let cursor = self
            .cursor
            .as_ref()
            .filter(|cursor| cursor.original_lineage.is_some() && !cursor.diverged)
            .ok_or_else(|| {
                failure(
                    "conditional original input is unqualified",
                    EffectKnowledge::None,
                )
            })?;
        if batch.node() != &self.route.node || batch.owners() != self.route.owners {
            return Err(failure(
                "conditional current input target differs",
                EffectKnowledge::None,
            ));
        }
        // Only the next request precondition is inspected. No future response,
        // ACK body or lineage evidence becomes a consumed-prefix authority here.
        let next = cursor.peek().ok_or_else(|| {
            failure(
                "conditional original Stage is absent",
                EffectKnowledge::None,
            )
        })?;
        let request: ControlRequest = serde_json::from_slice(&next.request.bytes)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let ControlRequest::Stage { input } = request else {
            return Err(failure(
                "conditional next request is not original Stage",
                EffectKnowledge::None,
            ));
        };
        if input.node != *batch.node()
            || input.stage_operation != *batch.stage_operation()
            || input.batch != *batch.batch()
            || input.owners != self.source_owners()?
            || input.cutoff != batch.cutoff()
            || input.inventory != *batch.inventory()
            || input.deliveries != batch.deliveries()
            || input.payloads != batch.payloads()
            || next.request.identity != *batch.stage_operation()
        {
            return Err(failure(
                "conditional original input precondition differs",
                EffectKnowledge::None,
            ));
        }
        Ok(SavedOriginalInputScope {
            source_activation: cursor.source.data.origin.activation.clone(),
            node: input.node,
            stage_operation: input.stage_operation,
            batch: input.batch,
            owners: input.owners,
            cutoff: input.cutoff,
            inventory: input.inventory,
        })
    }

    fn checked_conditional_terminal(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<super::super::tape2::OriginalLineageTapePrefix<'_>, OperationFailure> {
        self.same_world(original.activation())?;
        if self
            .lineage_activation
            .as_ref()
            .is_some_and(|actual| !Rc::ptr_eq(&actual.authority, &original.activation().authority))
        {
            return Err(failure(
                "foreign conditional terminal authority",
                EffectKnowledge::None,
            ));
        }
        let cached = self.original(original.token())?;
        if cached.admission.request() != original.request()
            || cached.outcome.as_ref() != Some(outcome)
        {
            return Err(failure(
                "conditional original terminal custody changed",
                EffectKnowledge::None,
            ));
        }
        self.original_lineage_tape()
            .map_err(|error| failure(error, EffectKnowledge::None))
    }

    pub(super) fn conditional_publication(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalPublicationClaim, OperationFailure> {
        let prefix = self.checked_conditional_terminal(original, outcome)?;
        let saved = prefix
            .publication_matching(original.token().operation(), publication)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        if saved.objects.len() > limits.maximum_objects {
            return Err(failure(
                "conditional original role credit",
                EffectKnowledge::None,
            ));
        }
        prefix
            .validate_publication_limits(&saved, limits)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let objects = prefix
            .read_original_bodies(&saved.objects, limits.maximum_bytes)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        saved
            .validate_recorded_bodies(limits, |reference| {
                objects
                    .iter()
                    .find(|object| object.reference == *reference)
                    .map(|object| object.bytes.as_slice())
            })
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let published = objects
            .iter()
            .find(|object| object.reference == saved.published)
            .ok_or_else(|| {
                failure(
                    "conditional original Event body absent",
                    EffectKnowledge::None,
                )
            })?;
        let event = canonical::decode(&published.bytes, published.bytes.len())
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        Ok(OriginalPublicationClaim {
            event,
            origin: saved.origin,
            published: saved.published,
            objects,
            rows: saved.rows,
        })
    }

    pub(super) fn validate_conditional_publication(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        let prefix = self.checked_conditional_terminal(original, outcome)?;
        let saved = prefix
            .publication_matching(original.token().operation(), publication)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        if saved.origin != claim.origin
            || saved.published != claim.published
            || saved.rows != claim.rows
            || saved.objects.len() != claim.objects.len()
            || !saved
                .objects
                .iter()
                .zip(&claim.objects)
                .all(|(reference, object)| reference == &object.reference)
        {
            return Err(failure(
                "conditional original publication claim changed",
                EffectKnowledge::None,
            ));
        }
        prefix
            .matches_original_bodies(&claim.objects)
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let published = claim
            .objects
            .iter()
            .find(|object| object.reference == claim.published)
            .ok_or_else(|| {
                failure(
                    "conditional original Event body absent",
                    EffectKnowledge::None,
                )
            })?;
        let event: crucible_node_contract::Event =
            canonical::decode(&published.bytes, published.bytes.len())
                .map_err(|error| failure(error, EffectKnowledge::None))?;
        if event != claim.event {
            return Err(failure(
                "conditional original Event changed",
                EffectKnowledge::None,
            ));
        }
        Ok(())
    }

    pub(super) fn replay_original_lineage(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        let scope = self.conditional_input_scope(batch)?;
        if lineage.source_scope() != &scope
            || !Rc::ptr_eq(
                &lineage.original().activation().authority,
                &batch.activation().authority,
            )
            || lineage.original().stage_operation() != batch.stage_operation()
            || lineage.original().batch() != batch.batch()
            || lineage.original().inventory() != batch.inventory()
        {
            return Err(failure(
                "conditional input lacks its actual runtime lineage seal",
                EffectKnowledge::None,
            ));
        }
        let saved = lineage
            .saved_reference_view(OriginalInputLineageLimits::default())
            .map_err(|error| failure(error, EffectKnowledge::None))?;
        let acknowledgement = self.replay_stage(batch, Some(provenance))?;
        // The original response was released only by the exact Stage above.
        // Compare its now-consumed metadata before returning current-model ACK.
        let original = match self
            .original_lineage_tape()
            .and_then(|prefix| prefix.input(batch.stage_operation()))
        {
            Ok(original) => original,
            Err(error) => {
                let divergence = self.divergence(&error.to_string());
                return Err(failure(
                    divergence.reason,
                    EffectKnowledge::MayHaveProgressed,
                ));
            }
        };
        if original != saved {
            let error = self.divergence("conditional original input lineage changed");
            return Err(failure(error.reason, EffectKnowledge::MayHaveProgressed));
        }
        Ok(acknowledgement)
    }
}

#[cfg(test)]
#[path = "node_lineage_tests.rs"]
mod tests;
