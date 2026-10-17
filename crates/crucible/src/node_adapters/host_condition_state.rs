//! Selected condition-world native indexes and deduplicated original bodies.
//!
//! Edition four retains original request, outcome, input, ACK and evidence
//! associations as content references into a complete byte-bearing DAG. It is
//! selected only by the installed condition inventory profile; legacy host
//! editions continue through their original declaration-order encoders.

use super::*;
use crate::node_adapters::condition_debug_model::dag::EvidenceDag;
use crate::node_scheduling::{InputPayload, NativeInputAcknowledgement};
use crucible_node_contract::U64;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    format: String,
    schema_version: u16,
    profile: String,
    node: Id,
    owners: Vec<OwnerIdentity>,
    boundary: Position,
    native: ContentRef,
    native_sequence: U64,
    staged: Option<InputIndex>,
    input_history: Vec<InputIndex>,
    pending_causes: ContentRef,
    operations: Vec<OperationIndex>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputIndex {
    stage_operation: Id,
    batch: Id,
    cutoff: Position,
    inventory: ContentRef,
    deliveries: ContentRef,
    payloads: Vec<ContentRef>,
    acknowledgement: NativeInputAcknowledgement,
    consumed: U64,
    acknowledgement_body: ContentRef,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationIndex {
    operation: Id,
    request: ContentRef,
    outcome: ContentRef,
    acknowledged: bool,
    capture: Option<ContentRef>,
    evidence: Vec<ContentRef>,
}

pub(super) fn maximum_objects(maximum_operations: usize) -> Result<usize, OperationFailure> {
    maximum_operations
        .checked_mul(16)
        .and_then(|count| count.checked_add(64))
        .map(|count| count.min(65_536))
        .ok_or_else(|| failure("condition native object count overflow"))
}

pub(super) fn selected(node: &HostModelNode) -> bool {
    node.terminal_inventory.0.as_str() == HOST_CONDITION_INVENTORY_PROFILE
        || matches!(node.model.as_ref(), Some(HostModel::ConditionObserver(_)))
}

pub(super) fn encode(node: &HostModelNode, maximum: usize) -> Result<Vec<u8>, OperationFailure> {
    let maximum = maximum.min(node.limits.maximum_capture_bytes);
    let maximum_objects = maximum_objects(node.limits.maximum_operations)?;
    let mut store = EvidenceDag::new(maximum_objects, maximum);
    let native = native_index(node, &mut store)?;
    let mut dependencies = vec![native.clone()];
    let staged = node
        .staged
        .as_ref()
        .map(|staged| input_index(staged, &mut store, &mut dependencies))
        .transpose()?;
    let input_history = node
        .input_history
        .values()
        .map(|staged| input_index(staged, &mut store, &mut dependencies))
        .collect::<Result<Vec<_>, _>>()?;
    let pending_causes = add_json(
        &mut store,
        &serde_json::json!({
            "schema": "crucible.condition-pending-causes.v1",
            "causes": node.pending_causes.iter().map(|(key, parents)| {
                serde_json::json!({
                    "time_ps": U64::new(key.0),
                    "source": key.1,
                    "sequence": key.2,
                    "parents": parents,
                })
            }).collect::<Vec<_>>(),
        }),
    )?;
    dependencies.push(pending_causes.clone());
    let mut operations = Vec::new();
    for (operation, completed) in &node.completed {
        let request = add_json(&mut store, completed.original.request())?;
        let outcome = add_json(&mut store, &completed.outcome)?;
        dependencies.extend([request.clone(), outcome.clone()]);
        let capture = completed
            .capture
            .as_ref()
            .map(|bytes| store.add(bytes, "application/octet-stream", Vec::new()))
            .transpose()?;
        dependencies.extend(capture.clone());
        let evidence = node.original_condition_objects(operation, completed)?.into_iter().map(|object| {
            let edges = super::super::condition_debug_model::ConditionDebugModel::original_dependencies(&object.bytes)?;
            store.insert(object.reference.clone(), &object.bytes, edges)?;
            Ok(object.reference.clone())
        }).collect::<Result<Vec<_>, OperationFailure>>()?;
        dependencies.extend(evidence.iter().cloned());
        operations.push(OperationIndex {
            operation: operation.clone(),
            request,
            outcome,
            acknowledged: completed.acknowledged,
            capture,
            evidence,
        });
    }
    dependencies.sort();
    dependencies.dedup();
    let index = Index {
        format: "crucible.host-condition-native-index".into(),
        schema_version: 4,
        profile: HOST_CONDITION_INVENTORY_PROFILE.into(),
        node: node.route.node.clone(),
        owners: node.route.owners.clone(),
        boundary: node.boundary,
        native,
        native_sequence: node.native_sequence.into(),
        staged,
        input_history,
        pending_causes,
        operations,
    };
    let bytes = super::super::condition_debug_model::native::canonical_bytes(&index)?;
    let root = store.add(&bytes, "application/json", dependencies)?;
    store.encode(vec![root])
}

fn input_index(
    staged: &execution::Staged,
    store: &mut EvidenceDag,
    dependencies: &mut Vec<ContentRef>,
) -> Result<InputIndex, OperationFailure> {
    let bytes = canonical::canonical_json(
        &serde_json::to_value(staged.original.deliveries())
            .map_err(|error| failure(&error.to_string()))?,
    )
    .map_err(|error| failure(&error.to_string()))?;
    let deliveries = staged.original.inventory().clone();
    store.insert(deliveries.clone(), &bytes, Vec::new())?;
    dependencies.push(deliveries.clone());
    let payloads = staged
        .original
        .payloads()
        .iter()
        .map(|object| {
            store.insert(object.reference.clone(), &object.bytes, Vec::new())?;
            Ok(object.reference.clone())
        })
        .collect::<Result<Vec<_>, OperationFailure>>()?;
    dependencies.extend(payloads.iter().cloned());
    store.insert(
        staged.acknowledgement_body.reference.clone(),
        &staged.acknowledgement_body.bytes,
        Vec::new(),
    )?;
    dependencies.push(staged.acknowledgement_body.reference.clone());
    Ok(InputIndex {
        stage_operation: staged.original.stage_operation().clone(),
        batch: staged.original.batch().clone(),
        cutoff: staged.original.cutoff(),
        inventory: staged.original.inventory().clone(),
        deliveries,
        payloads,
        acknowledgement: staged.acknowledgement.clone(),
        consumed: U64::new(staged.consumed as u64),
        acknowledgement_body: staged.acknowledgement_body.reference.clone(),
    })
}

fn native_index(
    node: &HostModelNode,
    store: &mut EvidenceDag,
) -> Result<ContentRef, OperationFailure> {
    if let Some(HostModel::ConditionObserver(model)) = node.model.as_ref() {
        let (reference, native) = model.capture_dag()?;
        for object in native.objects() {
            store.insert(
                object.reference.clone(),
                object.bytes.as_slice(),
                object.dependencies.clone(),
            )?;
        }
        Ok(reference)
    } else {
        store.add(&node.capture()?, "application/octet-stream", Vec::new())
    }
}

fn add_json(
    store: &mut EvidenceDag,
    value: &(impl Serialize + ?Sized),
) -> Result<ContentRef, OperationFailure> {
    let bytes = serde_json::to_vec(value).map_err(|error| failure(&error.to_string()))?;
    store.add(&bytes, "application/json", Vec::new())
}

pub(super) fn receipt_objects(node: &HostModelNode) -> Result<Vec<InputPayload>, OperationFailure> {
    let Some(HostModel::ConditionObserver(model)) = node.model.as_ref() else {
        return Ok(state::state_receipt_objects(node)?.into_iter().collect());
    };
    let (native, mut store) = model.capture_dag()?;
    let receipt_bytes = serde_json::to_vec(&serde_json::json!({
        "schema_version": 4,
        "profile": HOST_CONDITION_INVENTORY_PROFILE,
        "node": node.route.node,
        "owners": node.route.owners,
        "boundary": node.boundary,
        "native": native,
        "native_sequence": U64::new(node.native_sequence),
    }))
    .map_err(|error| failure(&error.to_string()))?;
    let receipt = store.add(
        &receipt_bytes,
        "application/octet-stream",
        vec![native.clone()],
    )?;
    let mut objects = vec![InputPayload {
        bytes: store.body(&receipt)?.to_vec(),
        reference: receipt.clone(),
    }];
    objects.extend(
        store
            .objects()
            .filter(|object| object.reference != receipt)
            .map(|object| InputPayload {
                reference: object.reference.clone(),
                bytes: object.bytes.as_slice().to_vec(),
            }),
    );
    Ok(objects)
}

pub(in crate::node_adapters) fn original_dependencies(
    bytes: &[u8],
) -> Result<Vec<ContentRef>, OperationFailure> {
    let index: Index =
        serde_json::from_slice(bytes).map_err(|error| failure(&error.to_string()))?;
    if index.format != "crucible.host-condition-native-index"
        || index.schema_version != 4
        || index.profile != HOST_CONDITION_INVENTORY_PROFILE
    {
        return Err(failure("condition native index selected grammar changed"));
    }
    let mut references = vec![index.native, index.pending_causes];
    for input in index.staged.iter().chain(&index.input_history) {
        references.push(input.deliveries.clone());
        references.push(input.acknowledgement_body.clone());
        references.extend(input.payloads.iter().cloned());
    }
    for operation in index.operations {
        references.extend([operation.request, operation.outcome]);
        references.extend(operation.capture);
        references.extend(operation.evidence);
    }
    references.sort();
    references.dedup();
    Ok(references)
}

#[path = "host_condition_reopen.rs"]
pub(in crate::node_adapters) mod reopen;
