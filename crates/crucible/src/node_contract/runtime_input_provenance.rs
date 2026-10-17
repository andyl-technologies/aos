//! Authenticated immutable input provenance beneath original staging custody.
//!
//! Provenance is separate from modeled payloads. Legacy input batch bytes stay
//! unchanged; nonempty provenance requires runtime continuation edition 2.

use crucible_node_contract::{ContentRef, Id, Validate};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::node_scheduling::{InputPayload, RuntimeInputBatch};

/// Bounds complete producer proof retrieval before consumer-native effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputProvenanceLimits {
    /// Limits original roots and their codec-selected dependency objects.
    pub maximum_objects: usize,
    /// Limits all original proof bytes, including shared dependencies.
    pub maximum_bytes: usize,
}

impl Default for InputProvenanceLimits {
    fn default() -> Self {
        Self {
            maximum_objects: 4096,
            maximum_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Preserves the explicit immutable provenance sidecar in continuation edition 2.
///
/// Serialized records convey historical data only. Their hashes do not issue
/// native proof authority or authorize another input batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedInputProvenance {
    /// Selects the closed sidecar format independently of native model codecs.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Binds the original consumer rather than a newly realized native instance.
    pub node: Id,
    /// Binds the original staging operation without authorizing another dispatch.
    pub stage_operation: Id,
    /// Binds the original frozen batch identity.
    pub batch: Id,
    /// Binds the complete original ordered delivery inventory.
    pub inventory: ContentRef,
    /// Lists the distinct original delivery proof roots in content order.
    pub roots: Vec<ContentRef>,
    /// Retains complete original roots and codec-selected dependency bytes.
    pub objects: Vec<InputPayload>,
}

/// Carries runtime-authenticated original producer proofs for one immutable input.
///
/// The runtime constructs this handle only after consulting actual retained
/// producer authority. Reading it does not permit execution, rebind a native
/// owner or reinterpret an evidence object as a modeled input payload.
#[derive(Debug)]
pub struct InputProvenanceClosure {
    activation: WorldActivation,
    saved: SavedInputProvenance,
}

impl InputProvenanceClosure {
    /// Returns the selected closed provenance format edition.
    pub fn version(&self) -> u16 {
        self.saved.schema_version
    }

    /// Returns the original complete committed world authority.
    pub fn activation(&self) -> &WorldActivation {
        &self.activation
    }

    /// Returns the original consumer node.
    pub fn node(&self) -> &Id {
        &self.saved.node
    }

    /// Returns the original staging operation identity.
    pub fn stage_operation(&self) -> &Id {
        &self.saved.stage_operation
    }

    /// Returns the original immutable input batch identity.
    pub fn batch(&self) -> &Id {
        &self.saved.batch
    }

    /// Returns the complete original delivery-inventory commitment.
    pub fn inventory(&self) -> &ContentRef {
        &self.saved.inventory
    }

    /// Borrows the original producer proof roots in content order.
    pub fn roots(&self) -> &[ContentRef] {
        &self.saved.roots
    }

    /// Borrows readable original proof objects independently of modeled payloads.
    pub fn objects(&self) -> &[InputPayload] {
        &self.saved.objects
    }

    pub(crate) fn retained_copy(&self) -> Self {
        Self {
            activation: self.activation.clone(),
            saved: self.saved.clone(),
        }
    }

    pub(super) fn from_validated(
        batch: &RuntimeInputBatch,
        roots: Vec<ContentRef>,
        objects: Vec<InputPayload>,
    ) -> Self {
        Self {
            activation: batch.activation().clone(),
            saved: SavedInputProvenance {
                schema_version: 1,
                node: batch.node().clone(),
                stage_operation: batch.stage_operation().clone(),
                batch: batch.batch().clone(),
                inventory: batch.inventory().clone(),
                roots,
                objects,
            },
        }
    }

    pub(crate) fn saved(&self) -> &SavedInputProvenance {
        &self.saved
    }

    pub(super) fn restore_validated(
        activation: &WorldActivation,
        saved: SavedInputProvenance,
    ) -> Self {
        Self {
            activation: activation.clone(),
            saved,
        }
    }
}

impl NodeRuntime {
    pub(super) fn prepare_input_provenance(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<Option<InputProvenanceClosure>, RuntimePollFailure> {
        let target = self
            .nodes
            .get(batch.node())
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        if !target.requires_input_provenance(batch) {
            return Ok(None);
        }
        let ceiling = InputProvenanceLimits::default();
        let mut available = ceiling;
        for input in self.input_batches.values() {
            if let Some(provenance) = &input.provenance {
                available.maximum_objects = available
                    .maximum_objects
                    .checked_sub(provenance.objects().len())
                    .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
                for object in provenance.objects() {
                    available.maximum_bytes = available
                        .maximum_bytes
                        .checked_sub(object.bytes.len())
                        .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
                }
            }
        }
        let mut objects = BTreeMap::new();
        let mut roots = BTreeSet::new();
        for delivery in batch.deliveries() {
            let route = self
                .checked_route(&delivery.producer)
                .map_err(RuntimePollFailure::Admission)?;
            if route.owners.iter().any(|owner| {
                self.owners.get(&owner.owner).is_none_or(|custody| {
                    matches!(
                        custody.lifecycle,
                        Lifecycle::Quarantined | Lifecycle::Released
                    )
                })
            }) {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OwnerUnavailable,
                ));
            }
            let original = self
                .operations
                .values()
                .filter_map(|entry| {
                    if entry.admission.token().route().node != delivery.producer {
                        return None;
                    }
                    let outcome = match &entry.result {
                        RetainedResult::Complete(outcome)
                        | RetainedResult::Acknowledged(outcome) => outcome,
                        _ => return None,
                    };
                    let observation = outcome.scheduling.as_ref()?;
                    (observation.proof_ref == delivery.provenance_ref
                        && observation.publications.iter().any(|publication| {
                            publication.publication_id == delivery.publication_id
                                && publication.endpoint == delivery.producer_endpoint
                                && publication.native_sequence == delivery.native_sequence
                                && publication.publication == delivery.publication
                                && publication.evaluation == delivery.evaluation
                                && publication.causal_parents == delivery.causal_parents
                                && publication.payload == delivery.payload
                        }))
                    .then(|| entry.admission.clone())
                })
                .collect::<Vec<_>>();
            if original.len() > 1 || (original.is_empty() && delivery.external_root.is_none()) {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            let source = self
                .nodes
                .get(&delivery.producer)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            let dependencies = source
                .input_provenance_dependencies(
                    batch.activation(),
                    &delivery.provenance_ref,
                    available,
                )
                .map_err(RuntimePollFailure::Native)?;
            let unique: BTreeSet<_> = dependencies.iter().collect();
            if dependencies.len() > available.maximum_objects
                || unique.len() != dependencies.len()
                || unique.contains(&delivery.provenance_ref)
                || source
                    .validate_input_provenance_dependencies(
                        batch.activation(),
                        &delivery.provenance_ref,
                        &dependencies,
                    )
                    .is_err()
            {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            let references: Vec<_> = std::iter::once(delivery.provenance_ref.clone())
                .chain(dependencies.iter().cloned())
                .collect();
            reserve_objects(&objects, &references, available)?;
            let root_objects = match original.first() {
                Some(original) => {
                    let references = [delivery.provenance_ref.clone()];
                    let retrieved = source
                        .read_operation_evidence(original, &references)
                        .map_err(RuntimePollFailure::Native)?;
                    source
                        .validate_operation_evidence(original, &references, &retrieved)
                        .map_err(RuntimePollFailure::Native)?;
                    retrieved
                }
                None => {
                    let references = [delivery.provenance_ref.clone()];
                    let retrieved = source
                        .read_boundary_evidence(
                            batch.activation(),
                            &references,
                            available.maximum_bytes,
                        )
                        .map_err(RuntimePollFailure::Native)?;
                    source
                        .validate_boundary_evidence(batch.activation(), &references, &retrieved)
                        .map_err(RuntimePollFailure::Native)?;
                    retrieved
                }
            };
            retain_objects(
                &mut objects,
                std::slice::from_ref(&delivery.provenance_ref),
                root_objects,
            )?;
            if !dependencies.is_empty() {
                let retrieved = source
                    .read_boundary_evidence(
                        batch.activation(),
                        &dependencies,
                        available.maximum_bytes,
                    )
                    .map_err(RuntimePollFailure::Native)?;
                source
                    .validate_boundary_evidence(batch.activation(), &dependencies, &retrieved)
                    .map_err(RuntimePollFailure::Native)?;
                retain_objects(&mut objects, &dependencies, retrieved)?;
            }
            roots.insert(delivery.provenance_ref.clone());
        }
        Ok(Some(InputProvenanceClosure::from_validated(
            batch,
            roots.into_iter().collect(),
            objects.into_values().collect(),
        )))
    }
}

pub(super) fn reserve_objects(
    retained: &BTreeMap<ContentRef, InputPayload>,
    references: &[ContentRef],
    limits: InputProvenanceLimits,
) -> Result<(), RuntimePollFailure> {
    let mut count = retained.len();
    let mut bytes = retained
        .values()
        .try_fold(0usize, |total, object| {
            total.checked_add(object.bytes.len())
        })
        .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
    for reference in references {
        reference
            .validate()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
        if !retained.contains_key(reference) {
            count = count
                .checked_add(1)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
            bytes = bytes
                .checked_add(
                    usize::try_from(reference.length.get())
                        .map_err(|_| RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?,
                )
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        }
    }
    if count > limits.maximum_objects || bytes > limits.maximum_bytes {
        return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
    }
    Ok(())
}

pub(super) fn retain_objects(
    retained: &mut BTreeMap<ContentRef, InputPayload>,
    references: &[ContentRef],
    objects: Vec<InputPayload>,
) -> Result<(), RuntimePollFailure> {
    if objects.len() != references.len() {
        return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
    }
    for (object, reference) in objects.into_iter().zip(references) {
        if object.reference != *reference
            || reference.verify(&object.bytes).is_err()
            || retained
                .get(reference)
                .is_some_and(|original| original != &object)
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        retained.insert(reference.clone(), object);
    }
    Ok(())
}

pub(super) fn validate_saved_inputs(inputs: &[SavedRuntimeInput]) -> Result<(), RuntimeError> {
    let limits = InputProvenanceLimits::default();
    let mut count = 0usize;
    let mut bytes = 0usize;
    for input in inputs {
        let Some(saved) = &input.provenance else {
            continue;
        };
        let roots: BTreeSet<_> = input
            .deliveries
            .iter()
            .map(|delivery| &delivery.provenance_ref)
            .collect();
        if saved.schema_version != 1
            || saved.node != input.node
            || saved.stage_operation != input.stage_operation
            || saved.batch != input.batch
            || saved.inventory != input.inventory
            || saved.roots.iter().collect::<Vec<_>>() != roots.into_iter().collect::<Vec<_>>()
            || saved
                .objects
                .windows(2)
                .any(|pair| pair[0].reference >= pair[1].reference)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        count = count
            .checked_add(saved.objects.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        for object in &saved.objects {
            bytes = bytes
                .checked_add(object.bytes.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            if count > limits.maximum_objects || bytes > limits.maximum_bytes {
                return Err(RuntimeError::ResourceLimit);
            }
            object
                .reference
                .verify(&object.bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
        if saved.roots.iter().any(|root| {
            saved
                .objects
                .binary_search_by(|object| object.reference.cmp(root))
                .is_err()
        }) {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "runtime_input_provenance_tests.rs"]
mod tests;
