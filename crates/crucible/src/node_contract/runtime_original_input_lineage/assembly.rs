//! Issues associations only from actual retained terminal producer permissions.

use super::*;
use crate::node_scheduling::{NativePublication, event::Delivery};

impl NodeRuntime {
    pub(in crate::node_contract::runtime) fn prepare_original_input_lineage(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<Option<OriginalInputLineage>, RuntimePollFailure> {
        if !self
            .nodes
            .get(batch.node())
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?
            .requires_original_input_lineage(batch)
        {
            return Ok(None);
        }
        let consumer = self
            .nodes
            .get_mut(batch.node())
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let source_scope = consumer
            .original_input_lineage_scope(batch)
            .map_err(RuntimePollFailure::Native)?;
        if let Some(scope) = &source_scope {
            validate_scope(scope, batch)?;
            consumer
                .validate_original_input_lineage_scope(batch, scope)
                .map_err(RuntimePollFailure::Native)?;
        }
        let mut available = OriginalInputLineageLimits::default();
        for input in self.input_batches.values() {
            if let Some(lineage) = &input.lineage {
                for claim in lineage.publications() {
                    charge(&mut available, claim)?;
                }
            }
        }
        if batch.deliveries().len() > 64 {
            return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
        }
        let mut publications = Vec::new();
        publications
            .try_reserve_exact(batch.deliveries().len())
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        for delivery in batch.deliveries() {
            let route = self
                .checked_route(&delivery.producer)
                .map_err(RuntimePollFailure::Admission)?;
            if delivery.external_root.is_some()
                || route.owners.iter().any(|owner| {
                    self.owners.get(&owner.owner).is_none_or(|custody| {
                        matches!(
                            custody.lifecycle,
                            Lifecycle::Quarantined | Lifecycle::Released
                        )
                    })
                })
            {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OwnerUnavailable,
                ));
            }
            let mut original = self.operations.values().filter_map(|entry| {
                if entry.admission.token().route().node != delivery.producer {
                    return None;
                }
                let outcome = match &entry.result {
                    RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome) => {
                        outcome
                    }
                    _ => return None,
                };
                let observation = outcome.scheduling.as_ref()?;
                if observation.proof_ref != delivery.provenance_ref {
                    return None;
                }
                let mut matches = observation
                    .publications
                    .iter()
                    .filter(|publication| matches_delivery(publication, delivery));
                let publication = matches.next()?;
                if matches.next().is_some() {
                    return None;
                }
                Some((&entry.admission, outcome, publication))
            });
            let (admission, outcome, publication) = original
                .next()
                .ok_or(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
            if original.next().is_some() {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            let source = self
                .nodes
                .get(&delivery.producer)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            let claim = source
                .original_publication_lineage(admission, outcome, publication, available)
                .map_err(RuntimePollFailure::Native)?;
            source
                .validate_original_publication_lineage(admission, outcome, publication, &claim)
                .map_err(RuntimePollFailure::Native)?;
            validate_original(&claim, admission, delivery, source_scope.as_ref())?;
            if let Some(scope) = &source_scope {
                source
                    .validate_original_publication_target(
                        admission,
                        outcome,
                        publication,
                        &claim,
                        scope,
                    )
                    .map_err(RuntimePollFailure::Native)?;
            }
            geometry::validate_claim_geometry(&claim, available)
                .map_err(RuntimePollFailure::Admission)?;
            source
                .validate_original_publication_lineage(admission, outcome, publication, &claim)
                .map_err(RuntimePollFailure::Native)?;
            if let Some(scope) = &source_scope {
                source
                    .validate_original_publication_target(
                        admission,
                        outcome,
                        publication,
                        &claim,
                        scope,
                    )
                    .map_err(RuntimePollFailure::Native)?;
            }
            self.snapshots
                .get(&delivery.producer)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?
                .validate_current(source.as_ref())
                .map_err(RuntimePollFailure::Admission)?;
            charge(&mut available, &claim)?;
            publications.push(claim);
        }
        if let Some(scope) = &source_scope {
            let consumer = self
                .nodes
                .get(batch.node())
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            consumer
                .validate_original_input_lineage_scope(batch, scope)
                .map_err(RuntimePollFailure::Native)?;
            self.snapshots
                .get(batch.node())
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?
                .validate_current(consumer.as_ref())
                .map_err(RuntimePollFailure::Admission)?;
        }
        Ok(Some(OriginalInputLineage {
            data: Rc::new(OriginalInputLineageData {
                source_scope: source_scope
                    .unwrap_or_else(|| SavedOriginalInputScope::from_batch(batch)),
                original: Rc::new(batch.retained_copy()),
                publications,
            }),
        }))
    }
}

fn matches_delivery(publication: &NativePublication, delivery: &Delivery) -> bool {
    publication.publication_id == delivery.publication_id
        && publication.endpoint == delivery.producer_endpoint
        && publication.native_sequence == delivery.native_sequence
        && publication.publication == delivery.publication
        && publication.evaluation == delivery.evaluation
        && publication.causal_parents == delivery.causal_parents
        && publication.payload == delivery.payload
}

fn validate_original(
    claim: &OriginalPublicationClaim,
    admission: &OperationAdmission,
    delivery: &Delivery,
    conditional: Option<&SavedOriginalInputScope>,
) -> Result<(), RuntimePollFailure> {
    let origin = &claim.origin;
    let event = &claim.event;
    let source_activation = conditional.map(|scope| &scope.source_activation);
    let owner = if let Some(source) = source_activation {
        source.owners.iter().find(|owner| {
            owner.owner == origin.execution_owner_id
                && admission
                    .token()
                    .route()
                    .owners
                    .iter()
                    .any(|current| current.owner == owner.owner)
        })
    } else {
        admission
            .token()
            .route()
            .owners
            .iter()
            .find(|owner| owner.owner == origin.execution_owner_id)
    };
    let valid = owner.is_some_and(|owner| {
        owner.incarnation == origin.incarnation_id && owner.generation == origin.owner_generation
    }) && origin.operation_id == *admission.token().operation()
        && source_activation.map_or_else(
            || {
                origin.world_binding_hash == admission.activation().record().world_binding_hash
                    && origin.activation_id == admission.activation().record().activation_id
                    && origin.world_generation == admission.activation().record().generation
            },
            |source| {
                origin.world_binding_hash == source.world_binding_hash
                    && origin.activation_id == source.activation_id
                    && origin.world_generation == source.generation
            },
        )
        && matches!(admission.request(), OperationRequest::QuantumBegin { window, .. } if window == &origin.grant_id)
        && origin.measurement == delivery.provenance_ref
        && event.id == delivery.publication_id
        && event.source == delivery.producer_endpoint
        && event.source_sequence == delivery.native_sequence
        && event.payload == delivery.payload
        && event.publication_position == delivery.publication
        && event.position == delivery.publication
        && event.provenance_ref == delivery.provenance_ref
        && event.stage == EventStage::Publication
        && event.delivery_position.is_none()
        && event.causal_parent_ids.is_empty()
        && delivery.causal_parents.is_empty()
        && event.extensions.is_empty()
        && event.validate().is_ok();
    if !valid {
        return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
    }
    Ok(())
}

fn charge(
    available: &mut OriginalInputLineageLimits,
    claim: &OriginalPublicationClaim,
) -> Result<(), RuntimePollFailure> {
    let credit = || RuntimePollFailure::Admission(RuntimeError::ResourceLimit);
    available.maximum_objects = available
        .maximum_objects
        .checked_sub(claim.objects.len())
        .ok_or_else(credit)?;
    for object in &claim.objects {
        available.maximum_bytes = available
            .maximum_bytes
            .checked_sub(object.bytes.len())
            .ok_or_else(credit)?;
    }
    let direct = claim
        .rows
        .iter()
        .try_fold(0usize, |total, row| {
            total.checked_add(row.dependencies.len())
        })
        .ok_or_else(credit)?;
    let transitive =
        geometry::validate_claim_geometry(claim, OriginalInputLineageLimits::default())
            .map_err(RuntimePollFailure::Admission)?;
    // A single remaining edge budget conservatively covers both independently
    // bounded direct and complete-transitive inventories across all occurrences.
    available.maximum_edges = available
        .maximum_edges
        .checked_sub(direct.max(transitive))
        .ok_or_else(credit)?;
    Ok(())
}

fn validate_scope(
    scope: &SavedOriginalInputScope,
    batch: &RuntimeInputBatch,
) -> Result<(), RuntimePollFailure> {
    let source = &scope.source_activation;
    let same_owners = scope.owners.len() == batch.owners().len()
        && scope
            .owners
            .iter()
            .zip(batch.owners())
            .all(|(first, current)| first.owner == current.owner && source.owners.contains(first));
    let whole_owners = source.owners.len() == batch.activation().record().owners.len()
        && source
            .owners
            .iter()
            .zip(&batch.activation().record().owners)
            .all(|(first, current)| first.owner == current.owner);
    if scope.node != *batch.node()
        || scope.stage_operation != *batch.stage_operation()
        || scope.batch != *batch.batch()
        || scope.cutoff != batch.cutoff()
        || scope.inventory != *batch.inventory()
        || !same_owners
        || !whole_owners
    {
        return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
    }
    Ok(())
}
