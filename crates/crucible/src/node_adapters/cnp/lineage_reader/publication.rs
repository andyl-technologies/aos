//! Associates actual source Events with retained common terminal publications.
//!
//! The standalone Event role is the selected codec's canonical projection of
//! the exact Event inside the original source ObservationBatch. It never renames
//! IDs, changes media roles, or obtains source authority from serialized data.

use super::control::{ReaderState, content, original_id};
use super::readiness::{refused, unknown};
use crate::node_contract::*;
use crate::node_scheduling::{InputPayload, NativePublication};
use crucible_node_contract::*;
use crucible_node_provider::{ProviderError, bodies::*, client::LineageWindowRequests};
use std::collections::BTreeSet;

impl ReaderState {
    pub(super) fn retain_publication_evidence(
        &mut self,
        result: &QuantumBeginResult,
        observation: &ObservationBatch,
        stop: &StopReceipt,
    ) -> Result<(), ProviderError> {
        let [event] = observation.events.as_slice() else {
            return Err(invalid());
        };
        let (published, bytes) = content(event)?;
        let mut dependencies = vec![event.payload.clone(), event.provenance_ref.clone()];
        dependencies.sort();
        dependencies.dedup();
        // This role is authenticated from the actual owning ObservationBatch,
        // not from a caller-supplied Event or a coordinate-to-ID lookup.
        let object = InputPayload {
            reference: published.clone(),
            bytes,
        };
        if self
            .boundary_evidence
            .get(&published)
            .is_some_and(|old| old != &object)
        {
            return Err(invalid());
        }
        self.runtime
            .boundary_evidence
            .insert(published.clone(), object);
        self.runtime
            .boundary_dependencies
            .insert(published.clone(), dependencies);
        self.retain_boundary_record(&event.payload, Vec::new())
            .map_err(failure)?;
        self.retain_boundary_record(
            &result.observation_batch,
            vec![published, event.provenance_ref.clone()],
        )
        .map_err(failure)?;
        let pending: PendingInventory = self.controller()?.record(&result.pending_inventory)?;
        let references = pending
            .entries
            .iter()
            .map(|entry| entry.state_ref.clone())
            .collect();
        self.retain_boundary_record(&result.pending_inventory, references)
            .map_err(failure)?;
        self.retain_boundary_record(
            &result.stop_receipt,
            vec![
                stop.observation_batch.clone(),
                stop.physical_measurement_ref.clone(),
                stop.input_custody.clone(),
                stop.pending_inventory.clone(),
            ],
        )
        .map_err(failure)?;
        Ok(())
    }

    pub(super) fn publication_claim(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalPublicationClaim, OperationFailure> {
        let (event, origin, published) = self
            .original_publication_scope(original, outcome, publication)
            .map_err(unknown)?;
        let roots = [
            &published,
            &origin.observation_batch,
            &origin.stop_receipt,
            &origin.measurement,
        ];
        let mut visited = BTreeSet::new();
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(4)
            .map_err(|_| refused("original publication traversal allocation"))?;
        pending.extend(roots);
        let mut bytes = 0usize;
        let mut edges = 0usize;
        // Check complete receiving credits and declared rows before copying any
        // original body. Foreign edges without authenticated rows still refuse.
        while let Some(reference) = pending.pop() {
            if !visited.insert(reference) {
                continue;
            }
            let object = self
                .boundary_evidence
                .get(reference)
                .ok_or_else(|| refused("original selected publication body missing"))?;
            let row = self
                .boundary_dependencies
                .get(reference)
                .ok_or_else(|| refused("original selected publication row missing"))?;
            bytes = bytes
                .checked_add(object.bytes.len())
                .filter(|size| *size <= limits.maximum_bytes)
                .ok_or_else(|| refused("original selected publication byte credit"))?;
            edges = edges
                .checked_add(row.len())
                .filter(|size| *size <= limits.maximum_edges)
                .ok_or_else(|| refused("original selected publication edge credit"))?;
            if visited.len() > limits.maximum_objects {
                return Err(refused("original selected publication role credit"));
            }
            pending
                .try_reserve(row.len())
                .map_err(|_| refused("original publication traversal credit"))?;
            pending.extend(row.iter());
        }
        let mut objects = Vec::new();
        let mut rows = Vec::new();
        objects
            .try_reserve_exact(visited.len())
            .map_err(|_| refused("original publication object allocation"))?;
        rows.try_reserve_exact(visited.len())
            .map_err(|_| refused("original publication row allocation"))?;
        for reference in visited {
            let original = self
                .boundary_evidence
                .get(reference)
                .ok_or_else(|| refused("original publication body vanished"))?;
            let mut body = Vec::new();
            body.try_reserve_exact(original.bytes.len())
                .map_err(|_| refused("original publication body allocation"))?;
            body.extend_from_slice(&original.bytes);
            objects.push(InputPayload {
                reference: reference.clone(),
                bytes: body,
            });
            let original_row = self
                .boundary_dependencies
                .get(reference)
                .ok_or_else(|| refused("original publication row vanished"))?;
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(original_row.len())
                .map_err(|_| refused("original publication edge allocation"))?;
            dependencies.extend(original_row.iter().cloned());
            rows.push(OriginalLineageRow {
                object: reference.clone(),
                dependencies,
            });
        }
        Ok(OriginalPublicationClaim {
            event,
            origin,
            published,
            objects,
            rows,
        })
    }

    pub(super) fn validate_publication_claim(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        let (event, origin, published) = self
            .original_publication_scope(original, outcome, publication)
            .map_err(unknown)?;
        if event != claim.event
            || origin != claim.origin
            || published != claim.published
            || claim.objects.len() != claim.rows.len()
            || claim.objects.iter().zip(&claim.rows).any(|(object, row)| {
                object.reference != row.object
                    || self.boundary_evidence.get(&row.object) != Some(object)
                    || self.boundary_dependencies.get(&row.object) != Some(&row.dependencies)
            })
        {
            return Err(refused("original selected publication scope/body changed"));
        }
        Ok(())
    }

    fn original_publication_scope(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
    ) -> Result<(Event, OriginalPublicationOrigin, ContentRef), ProviderError> {
        let OperationRequest::QuantumBegin { window: id, .. } = original.request() else {
            return Err(invalid());
        };
        let window = self.windows.get(id).ok_or_else(invalid)?;
        if !window.closed
            || !window.original.token().same_authority(original.token())
            || window.original.request() != original.request()
        {
            return Err(invalid());
        }
        let input = original.inputs().ok_or_else(invalid)?;
        let input_request = original_id("input", input.stage_operation())?;
        let begin_request = original_id("begin", original.token().operation())?;
        super::super::lineage::with_original_runtime_lineage(
            &self.guard,
            LineageWindowRequests {
                realization: &self.realization,
                input: &input_request,
                begin: &begin_request,
            },
            original,
            |lineage| {
                self.qualification.authenticate_window(&lineage)?;
                let source = lineage.source();
                let [event] = source.observation().events.as_slice() else {
                    return Err(invalid());
                };
                let stop = source.stop();
                let result = window.result.as_ref().ok_or_else(invalid)?;
                let scheduling = outcome.scheduling.as_ref().ok_or_else(invalid)?;
                if outcome.operation != *original.token().operation()
                    || outcome.node != original.token().route().node
                    || outcome.owners != original.token().route().owners
                    || scheduling.proof_ref != *source.measurement_reference()
                    || scheduling.publications.as_slice() != [publication.clone()]
                    || outcome.retained_outputs != [event.id.clone()]
                    || publication.publication_id != event.id
                    || publication.endpoint != event.source
                    || publication.native_sequence != event.source_sequence
                    || publication.publication != event.publication_position
                    || publication.payload != event.payload
                    || !publication.causal_parents.is_empty()
                    || !event.causal_parent_ids.is_empty()
                    || self.guard.content(&event.payload)? != publication.payload_bytes
                {
                    return Err(invalid());
                }
                let published = content(event)?.0;
                Ok((
                    event.clone(),
                    OriginalPublicationOrigin {
                        owner_binding_hash: stop.owner_binding_hash.clone(),
                        execution_owner_id: stop.execution_owner_id.clone(),
                        session_id: stop.session_id.clone(),
                        world_binding_hash: stop.world_binding_hash.clone(),
                        activation_id: stop.activation_id.clone(),
                        world_generation: stop.world_generation,
                        incarnation_id: stop.incarnation_id.clone(),
                        owner_generation: stop.owner_generation,
                        operation_id: stop.operation_id.clone(),
                        grant_id: stop.grant_id.clone().ok_or_else(invalid)?,
                        observation_batch: result.observation_batch.clone(),
                        stop_receipt: result.stop_receipt.clone(),
                        measurement: source.measurement_reference().clone(),
                    },
                    published,
                ))
            },
        )
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("original native/public terminal association changed")
}
fn failure(error: OperationFailure) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.reason))
}
