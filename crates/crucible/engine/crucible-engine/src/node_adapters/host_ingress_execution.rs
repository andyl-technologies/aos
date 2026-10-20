//! Exact source FIFO validation and bounded original recorded-input proof access.

use std::collections::BTreeSet;

use super::*;
use crate::node_scheduling::{InputPayload, NativeExternalInputInventory, RuntimeInputBatch};

impl HostModelNode {
    pub(super) fn recorded_inventory(
        &self,
    ) -> Result<Vec<NativeExternalInputInventory>, OperationFailure> {
        self.recorded_ingress
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |ingress| Ok(vec![ingress.inventory()?]))
    }

    pub(super) fn read_recorded_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        if !self.same_world(activation) || self.quarantined || self.model.is_none() {
            return Err(failure(
                "recorded input original boundary custody unavailable",
            ));
        }
        let ingress = self
            .recorded_ingress
            .as_ref()
            .ok_or_else(|| failure("recorded input source was not selected"))?;
        let unique: BTreeSet<_> = references.iter().collect();
        if unique.len() != references.len() || references.len() > 32 {
            return Err(failure(
                "recorded input evidence roster exceeds source credit",
            ));
        }
        let mut total = 0usize;
        let mut output = Vec::new();
        output
            .try_reserve_exact(references.len())
            .map_err(|_| failure("recorded input evidence credit unavailable"))?;
        let state = state::state_receipt_objects(self)?;
        for reference in references {
            let object = ingress
                .objects()
                .chain(state.iter())
                .find(|object| &object.reference == reference)
                .ok_or_else(|| failure("recorded input original object absent or future"))?;
            total = total
                .checked_add(object.bytes.len())
                .ok_or_else(|| failure("recorded input evidence geometry overflow"))?;
            if total > maximum_bytes {
                return Err(failure("recorded input evidence byte credit exhausted"));
            }
            output.push(object.clone());
        }
        Ok(output)
    }

    pub(super) fn recorded_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        if !self.same_world(activation) || self.quarantined || self.model.is_none() {
            return Err(failure("recorded input original provenance unavailable"));
        }
        let ingress = self
            .recorded_ingress
            .as_ref()
            .ok_or_else(|| failure("recorded input source was not selected"))?;
        let state = state::state_receipt_objects(self)?;
        let source = ingress.definition().objects();
        let dependencies: Vec<_> = if root == ingress.definition().root() {
            source
                .iter()
                .filter(|object| &object.reference != root)
                .map(|object| object.reference.clone())
                .collect()
        } else if ingress.inventory()?.proof_ref == *root {
            source
                .iter()
                .map(|object| object.reference.clone())
                .collect()
        } else if state[0].reference == *root {
            state
                .iter()
                .skip(1)
                .map(|object| object.reference.clone())
                .collect()
        } else {
            return Err(failure(
                "recorded input provenance root differs from current owned codec",
            ));
        };
        let total = dependencies
            .iter()
            .chain(std::iter::once(root))
            .try_fold(0_u64, |sum, reference| {
                sum.checked_add(reference.length.get())
            })
            .ok_or_else(|| failure("recorded input provenance geometry overflow"))?;
        if dependencies.len() + 1 > limits.maximum_objects || total > limits.maximum_bytes as u64 {
            return Err(failure(
                "recorded input provenance complete credit exhausted",
            ));
        }
        Ok(dependencies)
    }

    pub(super) fn validate_recorded_provenance(
        &self,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
    ) -> Result<(), OperationFailure> {
        if !self.same_world(provenance.activation())
            || provenance.node() != batch.node()
            || provenance.stage_operation() != batch.stage_operation()
            || provenance.batch() != batch.batch()
            || provenance.inventory() != batch.inventory()
        {
            return Err(failure(
                "recorded input original batch provenance scope changed",
            ));
        }
        let ingress = self
            .recorded_ingress
            .as_ref()
            .ok_or_else(|| failure("recorded input source was not selected"))?;
        if batch.deliveries().is_empty() {
            if !provenance.roots().is_empty() || !provenance.objects().is_empty() {
                return Err(failure(
                    "empty recorded input batch has unrelated provenance",
                ));
            }
            return Ok(());
        }
        if provenance.roots() != std::slice::from_ref(ingress.definition().root()) {
            return Err(failure(
                "recorded input complete original root roster changed",
            ));
        }
        let expected: BTreeSet<_> = ingress
            .definition()
            .objects()
            .iter()
            .map(|object| (&object.reference, &object.bytes))
            .collect();
        let actual: BTreeSet<_> = provenance
            .objects()
            .iter()
            .map(|object| (&object.reference, &object.bytes))
            .collect();
        if expected != actual || actual.len() != provenance.objects().len() {
            return Err(failure(
                "recorded input complete original source bytes changed",
            ));
        }
        Ok(())
    }
}
