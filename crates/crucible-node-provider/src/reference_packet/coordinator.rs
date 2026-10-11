//! Binds a selected static world to its actual post-Arm coordinator preparation.
//!
//! The installation contains the full initial coordinator template with an empty
//! preparation list. Only the actual native staged receipt fills that list. This
//! data validator issues no admission, Ready, class or activation authority.
//!
//! ```text
//! {"schema":"source-owned.packet-common-coordinator-installation/1",
//!  "template":{"schema":"crucible/coordinator-initial/1", ..., "preparations":[]}}
//! ```

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::control::PacketControlSelection;
use crate::{ProviderError, bodies::ActivateRequest};

const LIMIT: usize = 65_536;
const FIELDS: [&str; 17] = [
    "schema",
    "schema_version",
    "activation",
    "world",
    "ownership",
    "coordinator",
    "requirements",
    "nodes",
    "owners",
    "owner_bindings",
    "owner_conflicts",
    "preparations",
    "connections",
    "limits",
    "world_repeatability",
    "clock",
    "scheduler",
];

/// Supplies static source scope without predicting any native preparation.
///
/// Its complete template is independently enrolled before launch. The native
/// dispatcher separately joins the actual retained staged receipt before gate
/// opening; parsing or a matching content reference supplies no authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCoordinatorInstallation {
    /// Selects the distinct static-template grammar, edition 1.
    pub schema: String,
    /// Retains every original coordinator field, with preparations exactly empty.
    pub template: Value,
}

impl PacketCoordinatorInstallation {
    /// Decodes bounded canonical static scope and verifies the complete source roster.
    ///
    /// # Errors
    /// Refuses a foreign world, changed descriptor/binding/owner, predicted Ready,
    /// unsupported initial state, missing/unknown fields or exhausted bytes.
    pub fn decode(bytes: &[u8], selection: &PacketControlSelection) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, LIMIT)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused());
        }
        let installed: Self = serde_json::from_value(value).map_err(ContractError::from)?;
        installed.validate(selection)?;
        Ok(installed)
    }

    /// Rechecks all static scope before accepting a post-Arm body.
    ///
    /// # Errors
    /// Refuses changed world/source/owner data, noninitial ledgers or predicted Ready.
    pub fn validate(&self, selection: &PacketControlSelection) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(self, LIMIT)?;
        crate::connection::serialized_credit(selection, LIMIT)?;
        selection.provider.validate()?;
        selection.realization.validate()?;
        let object = self.template.as_object().ok_or_else(refused)?;
        let fields = &FIELDS;
        if self.schema != "source-owned.packet-common-coordinator-installation/1"
            || object.len() != fields.len()
            || fields.iter().any(|field| !object.contains_key(*field))
            || object.get("schema") != Some(&json!("crucible/coordinator-initial/1"))
            || object.get("schema_version") != Some(&json!(1))
            || object.get("preparations") != Some(&json!([]))
            || object.get("connections") != Some(&json!([]))
            || object.get("world_repeatability") != Some(&json!(Repeatability::Nondeterministic))
            || object.get("scheduler")
                != Some(&json!({
                    "state":"not_initialized", "operations":[], "inputs":[],
                    "publications":[], "deliveries":[], "reservations":[]
                }))
        {
            return Err(refused());
        }
        let world: WorldBinding =
            serde_json::from_value(object.get("world").cloned().ok_or_else(refused)?)
                .map_err(ContractError::from)?;
        world.validate()?;
        if world.identity()? != selection.world
            || !world.connections.is_empty()
            || world.node_bindings.len() != 1
            || selection.realization.bindings.len() != 1
            || selection.realization.descriptors.len() != 1
            || selection.realization.owners.len() != 1
            || selection.realization.owner_bindings.len() != 1
            || object.get("owner_bindings")
                != Some(
                    &serde_json::to_value(&selection.realization.owner_bindings)
                        .map_err(ContractError::from)?,
                )
        {
            return Err(refused());
        }
        let node = object
            .get("nodes")
            .and_then(Value::as_array)
            .filter(|nodes| nodes.len() == 1)
            .and_then(|nodes| nodes.first())
            .ok_or_else(refused)?;
        let node_fields = node.as_object().ok_or_else(refused)?;
        if node_fields.len() != 9
            || node_fields.keys().any(|field| {
                ![
                    "descriptor",
                    "binding",
                    "route",
                    "facets",
                    "native_thread_custody",
                    "operating_policy",
                    "guarantees",
                    "effective_repeatability",
                    "ports",
                ]
                .contains(&field.as_str())
            })
            || node.get("native_thread_custody") != Some(&json!("owner-thread"))
            || node.get("effective_repeatability") != Some(&json!(Repeatability::Nondeterministic))
        {
            return Err(refused());
        }
        if node.get("descriptor")
            != Some(
                &serde_json::to_value(&selection.realization.descriptors[0])
                    .map_err(ContractError::from)?,
            )
            || node.get("binding")
                != Some(
                    &serde_json::to_value(&selection.realization.bindings[0])
                        .map_err(ContractError::from)?,
                )
            || node.get("facets") != Some(&json!(["exact-execution"]))
        {
            return Err(refused());
        }
        let binding = &selection.realization.bindings[0];
        let owner = &selection.realization.owners[0];
        let descriptor = &selection.realization.descriptors[0];
        let binding_ref = NodeBindingRef {
            node_id: descriptor.id.clone(),
            binding_hash: binding.identity()?,
            extensions: Extensions::new(),
        };
        if world.node_bindings != [binding_ref]
            || owner.participant_ids != [descriptor.id.clone()]
            || selection.realization.owner_bindings[0].owner != *owner
            || node.get("route")
                != Some(&json!({
                    "node":descriptor.id, "owners":[{
                        "owner":owner.id,"incarnation":binding.authority.incarnation_id,
                        "generation":binding.authority.owner_generation
                    }]
                }))
            || object.get("owner_conflicts") != Some(&json!([[owner.id, []]]))
        {
            return Err(refused());
        }
        verify_static_content(
            object.get("ownership").ok_or_else(refused)?,
            &world.ownership_ref,
        )?;
        verify_static_content(
            object.get("coordinator").ok_or_else(refused)?,
            &world.coordinator_contract_ref,
        )?;
        verify_static_content(
            node.get("guarantees").ok_or_else(refused)?,
            &binding.compatibility.guarantees_ref,
        )?;
        validate_limits(object.get("limits").ok_or_else(refused)?)?;
        let activation = object.get("activation").ok_or_else(refused)?;
        let activation_fields = activation.as_object().ok_or_else(refused)?;
        if activation_fields.len() != 5
            || activation_fields.keys().any(|key| {
                ![
                    "generation",
                    "activation_id",
                    "world_binding_hash",
                    "owners",
                    "boundary",
                ]
                .contains(&key.as_str())
            })
        {
            return Err(refused());
        }
        let activation_id: Id = serde_json::from_value(
            activation
                .get("activation_id")
                .cloned()
                .ok_or_else(refused)?,
        )
        .map_err(ContractError::from)?;
        activation_id.validate()?;
        let generation: U64 =
            serde_json::from_value(activation.get("generation").cloned().ok_or_else(refused)?)
                .map_err(ContractError::from)?;
        if generation.get() == 0 {
            return Err(refused());
        }
        let identity = json!({"owner":owner.id,"incarnation":binding.authority.incarnation_id,
            "generation":binding.authority.owner_generation});
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        if object.get("clock") != Some(&json!(zero))
            || object.get("owners")
                != Some(&json!([{
                    "identity":identity,"lifecycle":"Prepared","operation":null,
                    "domains":owner.state_domain_ids
                }]))
            || object
                .get("activation")
                .and_then(|value| value.get("world_binding_hash"))
                != Some(&json!(selection.world))
            || object
                .get("activation")
                .and_then(|value| value.get("owners"))
                != Some(&json!([identity]))
            || object
                .get("activation")
                .and_then(|value| value.get("boundary"))
                != Some(&json!(zero))
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks the static part of a complete body before native control consumes it.
    ///
    /// # Errors
    /// Refuses changed/extra/missing fields or a missing/duplicate preparation.
    /// The actual staged receipt is authenticated later by `authenticate_staged`.
    pub fn validate_body(&self, bytes: &[u8]) -> Result<(), ProviderError> {
        let mut value = canonical::parse_json(bytes, LIMIT)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused());
        }
        let preparations = value
            .get("preparations")
            .and_then(Value::as_array)
            .filter(|rows| rows.len() == 1)
            .ok_or_else(refused)?;
        if preparations[0]
            .get("prepared_owners")
            .and_then(Value::as_array)
            .is_none_or(|owners| owners.len() != 1)
        {
            return Err(refused());
        }
        let object = value.as_object_mut().ok_or_else(refused)?;
        object.insert("preparations".into(), json!([]));
        if value != self.template {
            return Err(refused());
        }
        Ok(())
    }

    /// Joins a complete body to this actual native Arm and its retained Ready root.
    ///
    /// # Errors
    /// Refuses stale or foreign Arm/Ready, missing/duplicate owners, tampered body,
    /// changed static source scope or a preparation not born from the original Arm.
    pub fn authenticate_staged(
        &self,
        bytes: &[u8],
        selection: &PacketControlSelection,
        staged: &ActivateRequest,
        ready: &ContentRef,
    ) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(&(staged, ready), LIMIT)?;
        self.validate(selection)?;
        self.validate_body(bytes)?;
        let value = canonical::parse_json(bytes, LIMIT)?;
        let binding = &selection.realization.bindings[0];
        let owner = &selection.realization.owners[0];
        let identity = json!({"owner":owner.id,"incarnation":binding.authority.incarnation_id,
            "generation":binding.authority.owner_generation});
        let prepared = PreparedOwner {
            owner_id: owner.id.clone(),
            incarnation_id: binding.authority.incarnation_id.clone(),
            owner_generation: binding.authority.owner_generation,
            binding_hashes: vec![binding.identity()?],
            prepared_token: selection.prepared_token.clone(),
            ready_receipt: ready.clone(),
            extensions: Extensions::new(),
        };
        let expected = json!([{
            "node":selection.realization.descriptors[0].id,
            "readiness":{"owners":[identity], "boundary":self.template["clock"],
                "state_inventory":ready,"ready_receipt":ready},
            "prepared_owners":[prepared]
        }]);
        let activation = &self.template["activation"];
        if value.get("preparations") != Some(&expected)
            || activation.get("activation_id") != Some(&json!(staged.activation_id))
            || activation.get("generation") != Some(&json!(staged.world_generation))
            || staged.gate_id != selection.gate
            || staged.admission_id != selection.admission
            || staged.world_binding_hash != selection.world
            || staged.prepared_token != selection.prepared_token
        {
            return Err(refused());
        }
        Ok(())
    }
}

fn verify_static_content(value: &Value, expected: &ContentRef) -> Result<(), ProviderError> {
    let bytes = canonical::canonical_json(value)?;
    expected.verify(&bytes)?;
    Ok(())
}

fn validate_limits(value: &Value) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    if object.len() != 4
        || value.get("maximum_nodes") != Some(&json!(1))
        || value.get("maximum_owners") != Some(&json!(1))
        || value
            .get("maximum_operations")
            .and_then(Value::as_u64)
            .is_none_or(|count| count == 0 || count > 64)
        || value.get("maximum_retained_outputs") != Some(&json!(1))
    {
        return Err(refused());
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("packet original common coordinator scope differs")
}
