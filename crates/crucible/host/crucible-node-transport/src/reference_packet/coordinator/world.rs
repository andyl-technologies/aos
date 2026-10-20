//! Correlates one complete three-owner template with actual local Arm custody.
//!
//! The host independently installs the full roster before Child. This validator
//! checks complete membership and its local original Ready association. Another
//! peer's syntactically valid receipt is NOT authenticated here: the installed
//! host publisher must join all three actual native owners before activation.
//!
//! ```text
//! {"schema":"source-owned.packet-common-coordinator-installation/2",
//!  "participants":[{...},{...},{...}],"template":{...,"preparations":[]}}
//! ```

use std::collections::BTreeSet;

use crucible_node_format::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{FIELDS, LIMIT, refused, verify_static_content};
use crate::{
    ProviderError, bodies::ActivateRequest, reference_packet::control::PacketControlSelection,
};

const PARTICIPANTS: usize = 3;

/// Retains an explicitly installed full three-source coordinator grammar.
///
/// Its portable contents supply no class, admission, Ready or native authority.
/// The exact source installer and actual host publisher remain mandatory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketWorldCoordinatorInstallation {
    /// Selects the distinct full-world static-template edition 2.
    pub schema: String,
    /// Retains each exact independently installed local native selection.
    pub participants: Vec<PacketControlSelection>,
    /// Retains the complete static common coordinator with no predicted Ready.
    pub template: Value,
}

impl PacketWorldCoordinatorInstallation {
    /// Decodes finite canonical bytes without issuing any collection permission.
    ///
    /// # Errors
    /// Refuses an oversized, foreign, incomplete, duplicate or changed roster.
    pub fn decode(bytes: &[u8], local: &PacketControlSelection) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, LIMIT)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused());
        }
        let installed: Self = serde_json::from_value(value).map_err(ContractError::from)?;
        installed.validate(local)?;
        Ok(installed)
    }

    /// Verifies full static ownership and exact local source membership.
    ///
    /// # Errors
    /// Refuses predicted preparation, unsupported topology or initial state,
    /// omitted/duplicate nodes or owners, foreign local scope or exhausted bytes.
    pub fn validate(&self, local: &PacketControlSelection) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(self, LIMIT)?;
        crate::connection::serialized_credit(local, LIMIT)?;
        if self.schema != "source-owned.packet-common-coordinator-installation/2"
            || self.participants.len() != PARTICIPANTS
            || self
                .participants
                .iter()
                .filter(|peer| *peer == local)
                .count()
                != 1
        {
            return Err(refused());
        }
        let fields = self.template.as_object().ok_or_else(refused)?;
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        if fields.len() != FIELDS.len()
            || FIELDS.iter().any(|field| !fields.contains_key(*field))
            || self.template["schema"] != json!("crucible/coordinator-initial/1")
            || self.template["schema_version"] != json!(1)
            || self.template["preparations"] != json!([])
            || self.template["connections"] != json!([])
            || self.template["clock"] != json!(zero)
            || self.template["world_repeatability"] != json!(Repeatability::Nondeterministic)
            || self.template["scheduler"]
                != json!({
                    "state":"not_initialized", "operations":[], "inputs":[],
                    "publications":[], "deliveries":[], "reservations":[]
                })
        {
            return Err(refused());
        }
        let world: WorldBinding =
            serde_json::from_value(self.template["world"].clone()).map_err(ContractError::from)?;
        world.validate()?;
        if world.identity()? != local.world || !world.connections.is_empty() {
            return Err(refused());
        }
        verify_static_content(&self.template["ownership"], &world.ownership_ref)?;
        verify_static_content(
            &self.template["coordinator"],
            &world.coordinator_contract_ref,
        )?;
        self.validate_roster(&world)?;
        let activation = self.template["activation"]
            .as_object()
            .ok_or_else(refused)?;
        if activation.len() != 5
            || activation.keys().any(|key| {
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
        let activation_id: Id = serde_json::from_value(activation["activation_id"].clone())
            .map_err(ContractError::from)?;
        activation_id.validate()?;
        let generation: U64 = serde_json::from_value(activation["generation"].clone())
            .map_err(ContractError::from)?;
        if generation.get() == 0
            || activation["world_binding_hash"] != json!(local.world)
            || activation["boundary"] != json!(zero)
        {
            return Err(refused());
        }
        let limits = self.template["limits"].as_object().ok_or_else(refused)?;
        if limits.len() != 4
            || limits.get("maximum_nodes") != Some(&json!(3))
            || limits.get("maximum_owners") != Some(&json!(3))
            || limits.get("maximum_retained_outputs") != Some(&json!(3))
            || limits
                .get("maximum_operations")
                .and_then(Value::as_u64)
                .is_none_or(|count| count == 0 || count > 64)
        {
            return Err(refused());
        }
        Ok(())
    }

    fn validate_roster(&self, world: &WorldBinding) -> Result<(), ProviderError> {
        let nodes = self.template["nodes"].as_array().ok_or_else(refused)?;
        if nodes.len() != PARTICIPANTS || world.node_bindings.len() != PARTICIPANTS {
            return Err(refused());
        }
        let mut node_ids = BTreeSet::new();
        let mut owner_ids = BTreeSet::new();
        let mut identities = Vec::new();
        let mut owner_bindings = Vec::new();
        let mut owner_rows = Vec::new();
        let mut conflicts = Vec::new();
        for (index, peer) in self.participants.iter().enumerate() {
            peer.provider.validate()?;
            peer.realization.validate()?;
            peer.realize.validate()?;
            let realized = &peer.realization;
            if peer.world != world.identity()?
                || realized.descriptors.len() != 1
                || realized.bindings.len() != 1
                || realized.owners.len() != 1
                || realized.owner_bindings.len() != 1
            {
                return Err(refused());
            }
            let descriptor = &realized.descriptors[0];
            let binding = &realized.bindings[0];
            let owner = &realized.owners[0];
            if !node_ids.insert(descriptor.id.clone())
                || !owner_ids.insert(owner.id.clone())
                || owner.participant_ids != [descriptor.id.clone()]
                || realized.owner_bindings[0].owner != *owner
                || world.node_bindings[index]
                    != (NodeBindingRef {
                        node_id: descriptor.id.clone(),
                        binding_hash: binding.identity()?,
                        extensions: Extensions::new(),
                    })
            {
                return Err(refused());
            }
            let node = nodes[index].as_object().ok_or_else(refused)?;
            if node.len() != 9
                || node.keys().any(|key| {
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
                    .contains(&key.as_str())
                })
                || node.get("descriptor")
                    != Some(&serde_json::to_value(descriptor).map_err(ContractError::from)?)
                || node.get("binding")
                    != Some(&serde_json::to_value(binding).map_err(ContractError::from)?)
                || node.get("facets") != Some(&json!(["exact-execution"]))
                || node.get("native_thread_custody") != Some(&json!("owner-thread"))
                || node.get("effective_repeatability")
                    != Some(&json!(Repeatability::Nondeterministic))
            {
                return Err(refused());
            }
            verify_static_content(
                &nodes[index]["guarantees"],
                &binding.compatibility.guarantees_ref,
            )?;
            let identity = json!({"owner":owner.id,"incarnation":binding.authority.incarnation_id,
                "generation":binding.authority.owner_generation});
            if node.get("route") != Some(&json!({"node":descriptor.id,"owners":[identity]})) {
                return Err(refused());
            }
            identities.push(identity.clone());
            owner_bindings.push(realized.owner_bindings[0].clone());
            owner_rows.push(
                json!({"identity":identity,"lifecycle":"Prepared","operation":null,
                "domains":owner.state_domain_ids}),
            );
            conflicts.push(json!([owner.id, []]));
        }
        if self.template["activation"]["owners"] != json!(identities)
            || self.template["owner_bindings"]
                != serde_json::to_value(owner_bindings).map_err(ContractError::from)?
            || self.template["owners"] != json!(owner_rows)
            || self.template["owner_conflicts"] != json!(conflicts)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks the full static body and finite complete preparation roster.
    ///
    /// This is storage-shape validation only. Actual local Arm and complete host
    /// native ownership are checked separately before opening any native gate.
    ///
    /// # Errors
    /// Refuses changed static fields, noncanonical bytes or incomplete rows.
    pub fn validate_body(&self, bytes: &[u8]) -> Result<(), ProviderError> {
        let mut value = canonical::parse_json(bytes, LIMIT)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused());
        }
        let rows = value["preparations"]
            .as_array()
            .filter(|rows| rows.len() == PARTICIPANTS)
            .ok_or_else(refused)?;
        if rows.iter().any(|row| {
            row["prepared_owners"]
                .as_array()
                .is_none_or(|owners| owners.len() != 1)
        }) {
            return Err(refused());
        }
        value
            .as_object_mut()
            .ok_or_else(refused)?
            .insert("preparations".into(), json!([]));
        if value != self.template {
            return Err(refused());
        }
        Ok(())
    }

    /// Joins all portable preparation rows to THIS original local staged receipt.
    ///
    /// Full membership and every static field are checked, but foreign native
    /// readiness is authenticated by the host whole-world publisher separately.
    ///
    /// # Errors
    /// Refuses a missing, duplicated or foreign owner, changed static scope,
    /// stale local Arm/Ready, or an activation manifest differing from the rows.
    pub fn authenticate_staged(
        &self,
        bytes: &[u8],
        local: &PacketControlSelection,
        staged: &ActivateRequest,
        ready: &ContentRef,
        manifest: &ActivationManifest,
    ) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(&(staged, ready, manifest), LIMIT)?;
        self.validate(local)?;
        manifest.validate()?;
        let mut body = canonical::parse_json(bytes, LIMIT)?;
        if canonical::canonical_json(&body)? != bytes {
            return Err(refused());
        }
        let rows = body["preparations"]
            .as_array()
            .filter(|rows| rows.len() == PARTICIPANTS)
            .ok_or_else(refused)?;
        let mut prepared = Vec::new();
        for (index, peer) in self.participants.iter().enumerate() {
            let row = &rows[index];
            let receipt: ContentRef =
                serde_json::from_value(row["readiness"]["ready_receipt"].clone())
                    .map_err(ContractError::from)?;
            receipt.validate()?;
            let binding = &peer.realization.bindings[0];
            let owner = &peer.realization.owners[0];
            let actual = PreparedOwner {
                owner_id: owner.id.clone(),
                incarnation_id: binding.authority.incarnation_id.clone(),
                owner_generation: binding.authority.owner_generation,
                binding_hashes: vec![binding.identity()?],
                prepared_token: peer.prepared_token.clone(),
                ready_receipt: receipt.clone(),
                extensions: Extensions::new(),
            };
            let expected = json!({"node":peer.realization.descriptors[0].id,
                "readiness":{"owners":[{"owner":owner.id,
                    "incarnation":binding.authority.incarnation_id,
                    "generation":binding.authority.owner_generation}],
                    "boundary":self.template["clock"],"state_inventory":receipt,"ready_receipt":receipt},
                "prepared_owners":[actual]});
            if row != &expected || (peer == local && &actual.ready_receipt != ready) {
                return Err(refused());
            }
            prepared.push(actual);
        }
        body.as_object_mut()
            .ok_or_else(refused)?
            .insert("preparations".into(), json!([]));
        let activation = &self.template["activation"];
        if body != self.template
            || manifest.owners != prepared
            || activation["activation_id"] != json!(staged.activation_id)
            || activation["generation"] != json!(staged.world_generation)
            || staged.gate_id != local.gate
            || staged.admission_id != local.admission
            || staged.world_binding_hash != local.world
            || staged.prepared_token != local.prepared_token
        {
            return Err(refused());
        }
        Ok(())
    }
}
