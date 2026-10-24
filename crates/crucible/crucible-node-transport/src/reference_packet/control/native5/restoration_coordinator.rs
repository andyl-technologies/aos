//! Authenticates the explicit restored coordinator behind a genuine native permit.
//!
//! The Source MAC binds the actual WorldActivate request and full manifest; that
//! manifest binds these exact coordinator bytes. This parser then checks the
//! selected eleven-slot format, Runtime7/proof references, whole target roster,
//! paused scheduler and real local readiness. It never creates a phase permit.
//! Legacy coordinator/template authentication remains a separate unchanged path.

use crucible_node_format::{
    ActivationManifest, CaptureManifest, ContentRef, ContractError, HashRef, Position, Validate,
    WorldBinding, canonical,
};
use serde::Serialize;
use serde_json::{Map, Value};

use super::super::PacketControlSelection;
use crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationScope;
use crate::{ProviderError, bodies::ActivateRequest};

const FORMAT: &str = "crucible/coordinator-original-restoration-prepared/1";
const CONTEXT: &str = "crucible/original-lineage-restoration-context/1";
const PROOF: &str = "source-owned.complete-restoration-scope/1";

/// Checks full selected data after row admission and actual native MAC verification.
pub(crate) fn authenticate_original_restoration_coordinator_data(
    value: &Value,
    raw: &[u8],
    scope: &PacketRestorationActivationScope,
    local: &PacketControlSelection,
    staged: &ActivateRequest,
    ready: &ContentRef,
    manifest: &ActivationManifest,
) -> Result<(), ProviderError> {
    // The owning caller retains value before every fallible correspondence
    // check. This canonical comparison does not discard a newly parsed owner.
    if canonical::canonical_json(value)? != raw
        || canonical::content_ref(raw, "application/json")? != manifest.coordinator_state_ref
    {
        return Err(refused());
    }
    manifest.validate()?;
    let outer = array(value, 11)?;
    if outer[0].as_str() != Some(FORMAT) || outer[7].as_str() != Some("unqualified") {
        return Err(refused());
    }
    let target = array(&outer[1], 5)?;
    authenticate_target(target, scope, manifest)?;

    let world: WorldBinding =
        serde_json::from_value(outer[2].clone()).map_err(ContractError::from)?;
    world.validate()?;
    if world.identity()? != scope.target.world || local.world != scope.target.world {
        return Err(refused());
    }
    let capture: CaptureManifest =
        serde_json::from_value(outer[4].clone()).map_err(ContractError::from)?;
    capture.validate()?;
    if capture.world_binding_hash != scope.target.world {
        return Err(refused());
    }
    let artifact: ContentRef =
        serde_json::from_value(outer[3].clone()).map_err(ContractError::from)?;
    artifact.validate()?;

    let runtime = object(
        &outer[5],
        &[
            "schema_version",
            "source_activation",
            "capture_cut",
            "capture_ordinal",
            "owners",
            "operations",
            "inputs",
        ],
    )?;
    if runtime["schema_version"].as_u64() != Some(7)
        || canonical::content_ref(&canonical::canonical_json(&outer[5])?, "application/json")?
            != scope.source_runtime
        || !same(&capture.cut, &runtime["capture_cut"])?
        || !same(&capture.event_ordinal, &runtime["capture_ordinal"])?
    {
        return Err(refused());
    }
    let source_activation = object(
        &runtime["source_activation"],
        &[
            "generation",
            "activation_id",
            "world_binding_hash",
            "owners",
            "boundary",
        ],
    )?;
    if !same(
        &scope.target.world,
        &source_activation["world_binding_hash"],
    )? {
        return Err(refused());
    }
    let context = array(&outer[8], 5)?;
    if context[0].as_str() != Some(CONTEXT) || !same(&scope.source_runtime, &context[1])? {
        return Err(refused());
    }
    let native_scope = object(
        &context[3],
        &[
            "coordinator_schema",
            "source_record",
            "source_capture",
            "target",
            "owners",
            "first_scopes",
            "journals",
            "input_acknowledgements",
            "proof",
        ],
    )?;
    if native_scope["coordinator_schema"].as_u64() != Some(7)
        || !same(&scope.source_runtime, &native_scope["source_record"])?
        || native_scope["source_capture"] != runtime["source_activation"]
        || native_scope["target"] != outer[1]
        || !same(&scope.scope_proof, &native_scope["proof"])?
    {
        return Err(refused());
    }
    authenticate_scope_proof(&context[4], scope, &outer[1], &artifact)?;
    authenticate_owner_mapping(&native_scope["owners"], &runtime["owners"], &target[3])?;

    let scheduling = outer[6].as_object().ok_or_else(refused)?;
    if scheduling.get("schema_version").and_then(Value::as_u64) != Some(1)
        || scheduling.contains_key("original_epochs")
        || !same(
            &scope.target.world,
            scheduling.get("world_binding_hash").ok_or_else(refused)?,
        )?
        || scheduling.get("capture_cut") != runtime.get("capture_cut")
        || scheduling.get("capture_ordinal") != runtime.get("capture_ordinal")
        || scheduling.get("source_activation_id") != source_activation.get("activation_id")
        || scheduling.get("source_generation") != source_activation.get("generation")
        || scheduling.get("source_boundary") != source_activation.get("boundary")
        || scheduling.get("source_owners") != source_activation.get("owners")
    {
        return Err(refused());
    }
    let scheduling_hash = canonical::json_hash("cnp.scheduler-continuation.v1", &outer[6])?;
    if !same(&scheduling_hash, &context[2])? {
        return Err(refused());
    }
    let paused = array(&outer[9], 4)?;
    if paused[0] != outer[1]
        || paused[1] != outer[6]
        || paused[2] != native_scope["input_acknowledgements"]
        || !paused[3].is_null()
    {
        return Err(refused());
    }
    authenticate_preparations(&outer[10], target, &world, local, staged, ready, manifest)
}

fn authenticate_target(
    target: &[Value],
    scope: &PacketRestorationActivationScope,
    manifest: &ActivationManifest,
) -> Result<(), ProviderError> {
    if !same(&scope.target.generation, &target[0])?
        || !same(&scope.target.activation, &target[1])?
        || !same(&scope.target.world, &target[2])?
        || manifest.world_generation != scope.target.generation
        || manifest.activation_id != scope.target.activation
        || manifest.world_binding_hash != scope.target.world
        || manifest.transaction_id != scope.target.transaction
        || manifest.gate_id != scope.target.gate
        || !manifest.extensions.is_empty()
    {
        return Err(refused());
    }
    let owners = array(&target[3], 4)?;
    if manifest.owners.len() != 4 {
        return Err(refused());
    }
    let mut previous = None;
    for (actual, prepared) in owners.iter().zip(&manifest.owners) {
        let owner = object(actual, &["owner", "incarnation", "generation"])?;
        let id = owner["owner"].as_str().ok_or_else(refused)?;
        if previous.is_some_and(|last| last >= id)
            || !same(&prepared.owner_id, &owner["owner"])?
            || !same(&prepared.incarnation_id, &owner["incarnation"])?
            || !same(&prepared.owner_generation, &owner["generation"])?
        {
            return Err(refused());
        }
        previous = Some(id);
    }
    let boundary: Position =
        serde_json::from_value(target[4].clone()).map_err(ContractError::from)?;
    boundary.validate()?;
    Ok(())
}

fn authenticate_scope_proof(
    value: &Value,
    scope: &PacketRestorationActivationScope,
    target: &Value,
    artifact: &ContentRef,
) -> Result<(), ProviderError> {
    let proof = object(
        value,
        &[
            "schema",
            "source_artifact",
            "source_runtime",
            "target",
            "native_held_reference_identities",
        ],
    )?;
    if proof["schema"].as_str() != Some(PROOF)
        || !same(artifact, &proof["source_artifact"])?
        || !same(&scope.source_runtime, &proof["source_runtime"])?
        || &proof["target"] != target
        || canonical::content_ref(&canonical::canonical_json(value)?, "application/json")?
            != scope.scope_proof
    {
        return Err(refused());
    }
    for identity in array(&proof["native_held_reference_identities"], 3)? {
        if array(identity, 32)?
            .iter()
            .any(|byte| byte.as_u64().is_none_or(|byte| byte > 255))
        {
            return Err(refused());
        }
    }
    Ok(())
}

fn authenticate_owner_mapping(
    mappings: &Value,
    runtime: &Value,
    target: &Value,
) -> Result<(), ProviderError> {
    let mappings = array(mappings, 4)?;
    let originals = array(runtime, 4)?;
    let targets = array(target, 4)?;
    for ((mapping, original), target) in mappings.iter().zip(originals).zip(targets) {
        let mapping = object(mapping, &["source", "target"])?;
        let original = object(original, &["identity", "lifecycle", "operation", "domains"])?;
        if mapping["source"] != original["identity"] || &mapping["target"] != target {
            return Err(refused());
        }
    }
    Ok(())
}

fn authenticate_preparations(
    value: &Value,
    target: &[Value],
    world: &WorldBinding,
    local: &PacketControlSelection,
    staged: &ActivateRequest,
    ready: &ContentRef,
    manifest: &ActivationManifest,
) -> Result<(), ProviderError> {
    if staged.admission_id != local.admission
        || staged.prepared_token != local.prepared_token
        || staged.gate_id != local.gate
        || staged.world_binding_hash != local.world
        || staged.activation_id != manifest.activation_id
        || staged.world_generation != manifest.world_generation
    {
        return Err(refused());
    }
    let rows = array(value, 4)?;
    let [descriptor] = local.realization.descriptors.as_slice() else {
        return Err(refused());
    };
    let [local_owner] = local.realization.owners.as_slice() else {
        return Err(refused());
    };
    let [binding] = local.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let mut local_seen = false;
    let mut previous = None;
    for row in rows {
        let row = object(row, &["node", "readiness", "prepared_owners"])?;
        let node = row["node"].as_str().ok_or_else(refused)?;
        if previous.is_some_and(|last| last >= node) {
            return Err(refused());
        }
        previous = Some(node);
        let readiness = object(
            &row["readiness"],
            &["owners", "boundary", "state_inventory", "ready_receipt"],
        )?;
        let [owner] = array(&readiness["owners"], 1)? else {
            return Err(refused());
        };
        let owner = object(owner, &["owner", "incarnation", "generation"])?;
        let owner_id = owner["owner"].as_str().ok_or_else(refused)?;
        let prepared = manifest
            .owners
            .iter()
            .find(|one| one.owner_id.as_str() == owner_id)
            .ok_or_else(refused)?;
        let world_binding = world
            .node_bindings
            .iter()
            .find(|one| one.node_id.as_str() == node)
            .ok_or_else(refused)?;
        if prepared.binding_hashes.len() != 1
            || prepared.binding_hashes.first() != Some(&world_binding.binding_hash)
        {
            return Err(refused());
        }
        if !same(&prepared.incarnation_id, &owner["incarnation"])?
            || !same(&prepared.owner_generation, &owner["generation"])?
            || !same(&prepared.ready_receipt, &readiness["ready_receipt"])?
            || readiness["state_inventory"] != readiness["ready_receipt"]
            || readiness["boundary"] != target[4]
            || array(&row["prepared_owners"], 1)?[0]
                != serde_json::to_value(prepared).map_err(ContractError::from)?
        {
            return Err(refused());
        }
        if node == descriptor.id.as_str() {
            if local_seen
                || prepared.owner_id != local_owner.id
                || prepared.prepared_token != local.prepared_token
                || prepared.binding_hashes != [binding.identity()?]
                || &prepared.ready_receipt != ready
                || prepared.incarnation_id != binding.authority.incarnation_id
                || prepared.owner_generation != binding.authority.owner_generation
            {
                return Err(refused());
            }
            local_seen = true;
        }
    }
    if !local_seen || world.node_bindings.len() != 4 {
        return Err(refused());
    }
    for owner in &manifest.owners {
        let occurrences = rows
            .iter()
            .filter(|row| {
                row.get("readiness")
                    .and_then(|value| value.get("owners"))
                    .and_then(Value::as_array)
                    .and_then(|owners| owners.first())
                    .and_then(|value| value.get("owner"))
                    .and_then(Value::as_str)
                    == Some(owner.owner_id.as_str())
            })
            .count();
        if occurrences != 1 {
            return Err(refused());
        }
    }
    Ok(())
}

fn same<T: Serialize>(value: &T, actual: &Value) -> Result<bool, ProviderError> {
    Ok(serde_json::to_value(value).map_err(ContractError::from)? == *actual)
}

fn array(value: &Value, count: usize) -> Result<&[Value], ProviderError> {
    value
        .as_array()
        .filter(|rows| rows.len() == count)
        .map(Vec::as_slice)
        .ok_or_else(refused)
}

fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, ProviderError> {
    value
        .as_object()
        .filter(|fields| {
            fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key))
        })
        .ok_or_else(refused)
}

fn refused() -> ProviderError {
    ProviderError::Correlation("selected original-restoration coordinator differs")
}

/// Names the selected parser's concrete typed, borrowed and conversion views.
pub(crate) fn original_restoration_coordinator_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<WorldBinding>() + size_of::<Result<WorldBinding, serde_json::Error>>()
        + size_of::<CaptureManifest>() + size_of::<Result<CaptureManifest, serde_json::Error>>()
        + size_of::<ContentRef>() + size_of::<Result<ContentRef, serde_json::Error>>()
        + size_of::<Position>() + size_of::<Result<Position, serde_json::Error>>()
        + 4 * size_of::<HashRef>() + size_of::<Result<HashRef, ContractError>>()
        + 4 * size_of::<Value>() + size_of::<Result<Value, serde_json::Error>>()
        + 2 * size_of::<Vec<u8>>() + size_of::<Result<Vec<u8>, ContractError>>()
        + 5 * size_of::<&[Value]>() + 7 * size_of::<&Map<String, Value>>()
        + size_of::<Option<&str>>() + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<[&str; 9]>() + size_of::<[&str; 7]>()
        + size_of::<[&str; 5]>() + size_of::<[&str; 4]>()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
}
