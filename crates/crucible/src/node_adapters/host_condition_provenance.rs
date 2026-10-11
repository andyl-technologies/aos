//! Selected Block receipt closure and original condition-consumer proof custody.

use super::*;
use crate::node_contract::{InputProvenanceClosure, InputProvenanceLimits};
use crate::node_scheduling::{InputPayload, RuntimeInputBatch};
use crucible_node_contract::{U64, Validate};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockReceipt {
    schema_version: u16,
    profile: String,
    node: Id,
    owners: Vec<OwnerIdentity>,
    boundary: Position,
    native: ContentRef,
    native_sequence: U64,
    input: Option<(Id, ContentRef, U64)>,
    pending_causes: ContentRef,
}

impl HostModelNode {
    pub(super) fn condition_stage_provenance(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
    ) -> Result<crate::node_scheduling::NativeInputAcknowledgement, OperationFailure> {
        let Some(HostModel::ConditionObserver(model)) = self.model.as_ref() else {
            return Err(failure(
                "original Host consumer producer-proof staging unsupported",
            ));
        };
        let expected: BTreeSet<_> = batch
            .deliveries()
            .iter()
            .map(|delivery| delivery.provenance_ref.clone())
            .collect();
        if !self.same_world(batch.activation())
            || !Rc::ptr_eq(
                &batch.activation().authority,
                &provenance.activation().authority,
            )
            || provenance.node() != batch.node()
            || provenance.stage_operation() != batch.stage_operation()
            || provenance.batch() != batch.batch()
            || provenance.inventory() != batch.inventory()
            || provenance.roots().iter().cloned().collect::<BTreeSet<_>>() != expected
        {
            return Err(failure(
                "condition opaque producer proof differs from original input scope",
            ));
        }
        // The native model retains the exact original sidecar before touching
        // its staged input buffers. A failed native stage keeps its old model.
        let mut staged_model = model.clone();
        staged_model.retain_provenance(provenance)?;
        let acknowledgement = self.stage_exact_inputs(batch)?;
        self.model = Some(HostModel::ConditionObserver(staged_model));
        Ok(acknowledgement)
    }

    pub(super) fn condition_producer_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        self.condition_block_proof_scope(activation)?;
        let mut roots = self.completed.values().filter(|original| {
            original
                .outcome
                .scheduling
                .as_ref()
                .is_some_and(|observation| &observation.proof_ref == root)
        });
        let original = roots
            .next()
            .ok_or_else(|| failure("original Block producer proof absent"))?;
        if roots.next().is_some() {
            return Err(failure(
                "original Block producer proof has ambiguous operation association",
            ));
        }
        self.validate_outcome(&original.original, &original.outcome)?;
        let object = original
            .evidence
            .iter()
            .find(|object| &object.reference == root)
            .ok_or_else(|| failure("original Block native receipt body absent"))?;
        object
            .reference
            .verify(&object.bytes)
            .map_err(|error| failure(&error.to_string()))?;
        let receipt: BlockReceipt =
            serde_json::from_slice(&object.bytes).map_err(|error| failure(&error.to_string()))?;
        if receipt.schema_version != 1
            || receipt.profile != HOST_EXACT_PROFILE
            || receipt.node != self.route.node
            || receipt.owners != self.route.owners
            || original
                .outcome
                .scheduling
                .as_ref()
                .map(|observation| observation.reached)
                != Some(receipt.boundary)
            || receipt.native_sequence > self.native_sequence.into()
            || receipt
                .input
                .as_ref()
                .is_some_and(|(batch, inventory, consumed)| {
                    // A reply grant retains its earlier consumed request without
                    // necessarily receiving another input cut. Authenticate that
                    // native original, not a fictitious current-grant batch.
                    !self
                        .staged
                        .iter()
                        .chain(self.input_history.values())
                        .any(|staged| {
                            staged.original.batch() == batch
                                && staged.original.inventory() == inventory
                                && consumed.get() <= staged.consumed as u64
                        })
                })
        {
            return Err(failure("original Block producer receipt scope changed"));
        }
        let mut dependencies = vec![receipt.native, receipt.pending_causes];
        dependencies.sort();
        if dependencies[0] == dependencies[1]
            || dependencies.iter().any(|dependency| dependency == root)
            || dependencies.len() > limits.maximum_objects
        {
            return Err(failure(
                "original Block producer dependency inventory invalid",
            ));
        }
        let bytes = dependencies.iter().try_fold(0usize, |count, reference| {
            let object = original
                .evidence
                .iter()
                .find(|object| &object.reference == reference)
                .ok_or_else(|| failure("original Block codec dependency body absent"))?;
            object
                .reference
                .verify(&object.bytes)
                .map_err(|error| failure(&error.to_string()))?;
            count
                .checked_add(object.bytes.len())
                .ok_or_else(|| failure("original Block proof size overflow"))
        })?;
        if bytes > limits.maximum_bytes {
            return Err(failure(
                "original Block producer dependency credit exhausted",
            ));
        }
        Ok(dependencies)
    }

    pub(super) fn condition_producer_objects(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.condition_block_proof_scope(activation)?;
        if references.len() > 4096 {
            return Err(failure("Block producer object credit exhausted"));
        }
        let mut total = 0usize;
        let mut objects = Vec::new();
        for reference in references {
            let mut retained: Option<&InputPayload> = None;
            for original in self.completed.values() {
                if let Some(object) = original
                    .evidence
                    .iter()
                    .find(|object| &object.reference == reference)
                {
                    self.validate_outcome(&original.original, &original.outcome)?;
                    if retained.is_some_and(|previous| previous != object) {
                        return Err(failure("original Block producer evidence collision"));
                    }
                    retained = Some(object);
                }
            }
            let object =
                retained.ok_or_else(|| failure("original Block producer dependency absent"))?;
            total = total
                .checked_add(object.bytes.len())
                .ok_or_else(|| failure("Block evidence size overflow"))?;
            if total > maximum_bytes {
                return Err(failure("Block producer object byte credit exhausted"));
            }
            object
                .reference
                .verify(&object.bytes)
                .map_err(|error| failure(&error.to_string()))?;
            // Materialize only after the whole object's original byte credit
            // is accepted; caller ceilings cannot trigger an oversized clone.
            objects.push(object.clone());
        }
        Ok(objects)
    }

    fn condition_block_proof_scope(
        &self,
        activation: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        if self.terminal_inventory.0.as_str() != HOST_CONDITION_INVENTORY_PROFILE
            || !self.same_world(activation)
            || self.quarantined
            || !matches!(self.model.as_ref(), Some(HostModel::Io(io)) if io.block_device().is_some())
        {
            return Err(failure(
                "selected original Block producer proof codec unsupported",
            ));
        }
        Ok(())
    }
}

// This is the selected DAG's static codec edge list, not a native producer
// authentication gate. The live producer path above separately authenticates
// the original receipt and native input history under its current activation.
pub(in crate::node_adapters) fn original_receipt_dependencies(
    bytes: &[u8],
) -> Result<Vec<ContentRef>, OperationFailure> {
    let receipt: BlockReceipt =
        serde_json::from_slice(bytes).map_err(|error| failure(&error.to_string()))?;
    if receipt.schema_version != 1
        || receipt.profile != HOST_EXACT_PROFILE
        || receipt.owners.is_empty()
        || receipt.owners.windows(2).any(|pair| pair[0] >= pair[1])
        || receipt
            .owners
            .iter()
            .any(|owner| owner.generation.get() == 0)
        || receipt.boundary.validate().is_err()
        || receipt.native == receipt.pending_causes
    {
        return Err(failure("condition original host receipt grammar changed"));
    }
    let mut dependencies = vec![receipt.native, receipt.pending_causes];
    dependencies.sort();
    Ok(dependencies)
}
