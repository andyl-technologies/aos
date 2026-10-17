//! Reopens actual byte-bearing condition model custody without live permissions.
//!
//! The complete selected native index keeps original operation/body associations
//! and source inventory labels. This inspection validates their closed grammar
//! and reconstructs the evaluator from its saved checkpoint. Installed signed
//! source verification and fresh native construction remain separate gates.

use super::*;
use crate::node_adapters::{ConditionDebugDefinition, ConditionDebugModel};
use crate::node_contract::NativeConditionStopInventory;
use crate::node_scheduling::event::Delivery;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryRoot {
    format: String,
    version: u16,
    activation: SavedRuntimeActivation,
    node: Id,
    owners: Vec<OwnerIdentity>,
    boundary: Position,
    native: ContentRef,
}

/// Reopens a complete original condition evaluator from selected native bodies.
///
/// This pure decoder checks the declared body DAG, original native operation
/// and staging associations, source inventory labels and installed definition.
/// It restores the original checkpoint and journal without reevaluating inputs.
/// The returned model establishes no native construction, live fence, current
/// durable publication, acknowledgement or resume authority.
///
/// # Errors
/// Refuses missing or changed bodies, dependency aliases, unsupported selected
/// grammars, changed owner/cut labels, inconsistent original histories, a foreign
/// definition or object/byte ceilings beyond the selected finite profile.
pub fn reopen_condition_model(
    inventory: &NativeConditionStopInventory,
    definition: ConditionDebugDefinition,
    maximum_bytes: usize,
    maximum_operations: usize,
    maximum_events: usize,
) -> Result<ConditionDebugModel, OperationFailure> {
    if maximum_bytes == 0
        || maximum_bytes > 16 << 20
        || maximum_operations == 0
        || maximum_operations > 4096
        || maximum_events == 0
        || maximum_events > 4096
    {
        return Err(failure("condition native reopening limits refused"));
    }
    let maximum_objects = maximum_objects(maximum_operations)?;
    let mut store = EvidenceDag::new(maximum_objects, maximum_bytes);
    for object in inventory
        .proof_objects
        .iter()
        .chain(std::iter::once(&inventory.receipt))
    {
        store.insert(
            object.reference.clone(),
            &object.bytes,
            ConditionDebugModel::original_dependencies(&object.bytes)?,
        )?;
    }
    let wire = store.encode(vec![inventory.receipt.reference.clone()])?;
    let (store, _) = EvidenceDag::decode(&wire, maximum_objects, maximum_bytes)?;
    let root: InventoryRoot = from_body(&store, &inventory.receipt.reference)?;
    if root.format != "crucible.host-condition-stop-inventory"
        || root.version != 1
        || root.node != inventory.node
        || root.owners != inventory.owners
        || root.boundary != inventory.boundary
        || root.activation.generation.get() == 0
        || root.owners.is_empty()
        || root.owners.windows(2).any(|pair| pair[0] >= pair[1])
        || root.owners.iter().any(|owner| owner.generation.get() == 0)
        || root
            .owners
            .iter()
            .any(|owner| !root.activation.owners.contains(owner))
    {
        return Err(failure("condition original inventory labels changed"));
    }
    let index: Index = from_body(&store, &root.native)?;
    if index.format != "crucible.host-condition-native-index"
        || index.schema_version != 4
        || index.profile != HOST_CONDITION_INVENTORY_PROFILE
        || index.node != root.node
        || index.owners != root.owners
        || index.boundary != root.boundary
        || index.operations.len() > maximum_operations
        || index
            .operations
            .windows(2)
            .any(|pair| pair[0].operation >= pair[1].operation)
        || index
            .input_history
            .len()
            .checked_add(usize::from(index.staged.is_some()))
            .is_none_or(|count| count > maximum_operations)
    {
        return Err(failure("condition original native index changed"));
    }
    validate_operations(&store, &index)?;
    validate_inputs(&store, &index)?;

    // Extract only the model's reachable bodies. The complete native index is
    // retained by the caller; it is not embedded recursively into this model.
    let mut model_store = EvidenceDag::new(maximum_objects, maximum_bytes);
    for object in store.closure(&index.native)? {
        model_store.insert(
            object.reference.clone(),
            object.bytes.as_slice(),
            object.dependencies.clone(),
        )?;
    }
    let bytes = model_store.encode(vec![index.native])?;
    let model = ConditionDebugModel::restore(definition, &bytes, maximum_bytes, maximum_events)?;
    if model.position() != index.boundary {
        return Err(failure("condition original evaluator cut changed"));
    }
    Ok(model)
}

fn validate_operations(store: &EvidenceDag, index: &Index) -> Result<(), OperationFailure> {
    let mut last_sequence = None;
    for original in &index.operations {
        let _: OperationRequest = from_body(store, &original.request)?;
        let outcome: OperationOutcome = from_body(store, &original.outcome)?;
        // Preserve the exact original list, including repeated associations to
        // the same body in Stop's complete world closure. Body ownership is
        // deduplicated; historical entries are not silently normalized.
        let references: std::collections::BTreeSet<_> = original.evidence.iter().collect();
        if outcome.operation != original.operation
            || outcome.node != index.node
            || outcome.owners != index.owners
        {
            return Err(failure(
                "condition original operation body association changed",
            ));
        }
        if let Some(observation) = &outcome.scheduling {
            if !references.contains(&observation.proof_ref)
                || observation
                    .bounds
                    .iter()
                    .any(|bound| !references.contains(&bound.proof_ref))
                || observation
                    .input_progress
                    .as_ref()
                    .is_some_and(|input| !references.contains(&input.proof_ref))
            {
                return Err(failure("condition original scheduling proof body omitted"));
            }
            for publication in &observation.publications {
                if !references.contains(&publication.payload)
                    || store.body(&publication.payload)? != publication.payload_bytes
                {
                    return Err(failure("condition original publication body changed"));
                }
                last_sequence = Some(
                    last_sequence.map_or(publication.native_sequence.get(), |last: u64| {
                        last.max(publication.native_sequence.get())
                    }),
                );
            }
        }
    }
    let expected = last_sequence
        .map(|last| {
            last.checked_add(1)
                .ok_or_else(|| failure("condition original native sequence overflow"))
        })
        .transpose()?
        .unwrap_or(0);
    if index.native_sequence.get() != expected {
        return Err(failure("condition original native sequence changed"));
    }
    Ok(())
}

fn validate_inputs(store: &EvidenceDag, index: &Index) -> Result<(), OperationFailure> {
    let mut stages = std::collections::BTreeSet::new();
    let mut batches = std::collections::BTreeSet::new();
    for input in index.input_history.iter().chain(index.staged.iter()) {
        let deliveries: Vec<Delivery> = from_body(store, &input.deliveries)?;
        let payloads: std::collections::BTreeSet<_> = input.payloads.iter().collect();
        let acknowledgement = &input.acknowledgement;
        if input.inventory != input.deliveries
            || !stages.insert(&input.stage_operation)
            || !batches.insert(&input.batch)
            || payloads.len() != input.payloads.len()
            || input.consumed.get() > deliveries.len() as u64
            || acknowledgement.stage_operation != input.stage_operation
            || acknowledgement.batch != input.batch
            || acknowledgement.node != index.node
            || acknowledgement.owners != index.owners
            || acknowledgement.cutoff != input.cutoff
            || acknowledgement.inventory != input.inventory
            || acknowledgement.proof_ref != input.acknowledgement_body
            || deliveries.iter().any(|delivery| {
                delivery.consumer != index.node
                    || delivery.delivery >= input.cutoff
                    || !payloads.contains(&delivery.payload)
            })
        {
            return Err(failure("condition original input custody changed"));
        }
        for reference in &input.payloads {
            store.body(reference)?;
        }
        store.body(&input.acknowledgement_body)?;
    }
    Ok(())
}

fn from_body<T: serde::de::DeserializeOwned>(
    store: &EvidenceDag,
    reference: &ContentRef,
) -> Result<T, OperationFailure> {
    serde_json::from_slice(store.body(reference)?).map_err(|error| failure(&error.to_string()))
}
