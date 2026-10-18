//! Correlates three original native peers and the genuine host scheduler owner.
//!
//! The host independently installs the full roster before Child. This validator
//! checks complete membership and its local original Ready association. Another
//! peer's syntactically valid receipt is NOT authenticated here: the installed
//! host publisher must join all three actual native owners and the attached
//! original host scheduler owner before activation.
//!
//! ```text
//! {"schema":"source-owned.packet-connected-coordinator-installation/4",
//!  "participants":[{...},{...},{...}],"host":{...},"template":{...,"preparations":[]}}
//! ```

use std::collections::BTreeSet;

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{FIELDS, LIMIT, refused, verify_static_content};
use crate::{
    ProviderError, bodies::ActivateRequest, reference_packet::control::PacketControlSelection,
};

/// Bounds a complete edition-four coordinator object before parsing or copying.
///
/// The four-owner object travels through 4096-byte blob chunks. Its complete
/// object ceiling is independent of the unchanged 65,536-byte socket frame.
/// Earlier output-only coordinator editions retain their original ceiling.
pub const PACKET_CONNECTED_COORDINATOR_BYTES: usize = 131_072;

const PARTICIPANTS: usize = 3;
const WORLD_NODES: usize = PARTICIPANTS + 1;

/// Binds the genuine host owner of the common scheduler and connection state.
///
/// Every field is selected by the same original host source before launch.
/// This portable tuple does not authenticate attachment, Arm, Ready or capture.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedHostSelection {
    /// Retains the complete original host node descriptor with no native ports.
    pub descriptor: NodeDescriptor,
    /// Retains its independently selected implementation and live authority.
    pub binding: NodeBinding,
    /// Retains the actual owner of host queues, credits and coordinator state.
    pub owner: OwnerBinding,
    /// Names the source-generated original unopened preparation token.
    pub prepared_token: Id,
    /// Retains the complete initializer emitted by that original host source.
    pub initial_node: Value,
}

/// Retains an independently installed connected three-source coordinator grammar.
///
/// Its portable contents supply no class, admission, Ready or native authority.
/// The exact source installer and actual host publisher remain mandatory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedCoordinatorInstallation {
    /// Selects the distinct connected static-template edition 4.
    pub schema: String,
    /// Retains each exact independently installed local native selection.
    pub participants: Vec<PacketControlSelection>,
    /// Retains the separately owned original host scheduling participant.
    pub host: PacketConnectedHostSelection,
    /// Retains the complete static common coordinator with no predicted Ready.
    pub template: Value,
}

impl PacketConnectedCoordinatorInstallation {
    /// Decodes finite canonical bytes without issuing any collection permission.
    ///
    /// # Errors
    /// Refuses an oversized, foreign, incomplete, duplicate or changed roster.
    pub fn decode(bytes: &[u8], local: &PacketControlSelection) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, PACKET_CONNECTED_COORDINATOR_BYTES)?;
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
    /// Refuses incomplete or changed static membership and exhausted bytes.
    pub fn validate(&self, local: &PacketControlSelection) -> Result<(), ProviderError> {
        self.view().validate(local)
    }

    /// Checks the full static body and complete preparation roster.
    ///
    /// # Errors
    /// Refuses noncanonical bytes, changed static fields or incomplete rows.
    pub fn validate_body(&self, bytes: &[u8]) -> Result<(), ProviderError> {
        self.view().validate_body(bytes)
    }

    /// Joins complete preparation rows to this original staged receipt.
    ///
    /// # Errors
    /// Refuses changed static scope or a foreign local Arm or activation.
    pub fn authenticate_staged(
        &self,
        bytes: &[u8],
        local: &PacketControlSelection,
        staged: &ActivateRequest,
        ready: &ContentRef,
        manifest: &ActivationManifest,
    ) -> Result<(), ProviderError> {
        self.view()
            .authenticate_staged(bytes, local, staged, ready, manifest)
    }

    fn view(&self) -> CoordinatorView<'_> {
        CoordinatorView {
            schema: &self.schema,
            participants: &self.participants,
            host: &self.host,
            template: &self.template,
            edition: CoordinatorEdition::ConnectedFour,
        }
    }
}

// The edition comes only from the distinct installed Rust type, never a parsed
// request or normalized metadata. Both paths borrow the exact original tuple.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum CoordinatorEdition {
    ConnectedFour,
    CompleteFive,
}

#[derive(Serialize)]
pub(super) struct CoordinatorView<'a> {
    pub(super) schema: &'a str,
    pub(super) participants: &'a [PacketControlSelection],
    pub(super) host: &'a PacketConnectedHostSelection,
    pub(super) template: &'a Value,
    #[serde(skip)]
    pub(super) edition: CoordinatorEdition,
}

impl CoordinatorView<'_> {
    // The full private installation repeats source schema rosters. Its actual
    // Control template stays separately bounded before semantic validation.
    pub(super) fn validate_installation_extent_data(
        &self,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(self, maximum)?;
        if self.edition == CoordinatorEdition::CompleteFive {
            for participant in self.participants {
                crate::connection::serialized_credit(participant, LIMIT)?;
            }
            crate::connection::serialized_credit(self.host, LIMIT)?;
            crate::connection::serialized_credit(
                self.template,
                PACKET_CONNECTED_COORDINATOR_BYTES,
            )?;
        }
        Ok(())
    }

    /// Verifies full static ownership and exact local source membership.
    ///
    /// # Errors
    /// Refuses predicted preparation, unsupported topology or initial state,
    /// omitted/duplicate nodes or owners, foreign local scope or exhausted bytes.
    pub(super) fn validate(&self, local: &PacketControlSelection) -> Result<(), ProviderError> {
        self.validate_installation_extent_data(match self.edition {
            CoordinatorEdition::ConnectedFour => PACKET_CONNECTED_COORDINATOR_BYTES,
            CoordinatorEdition::CompleteFive => {
                super::continuation::PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES
            }
        })?;
        crate::connection::serialized_credit(local, LIMIT)?;
        if self.schema != self.edition.schema()
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
        if world.identity()? != local.world
            || world.connections.is_empty()
            || world.connections.len() > 4
        {
            return Err(refused());
        }
        verify_static_content(&self.template["ownership"], &world.ownership_ref)?;
        verify_static_content(
            &self.template["coordinator"],
            &world.coordinator_contract_ref,
        )?;
        self.validate_roster(&world)?;
        self.validate_topology(&world)?;
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
            || limits.get("maximum_nodes") != Some(&json!(WORLD_NODES))
            || limits.get("maximum_owners") != Some(&json!(WORLD_NODES))
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

    fn validate_topology(&self, world: &WorldBinding) -> Result<(), ProviderError> {
        let rows = self.template["connections"]
            .as_array()
            .ok_or_else(refused)?;
        if rows.len() != world.connections.len() {
            return Err(refused());
        }
        for (connection, row) in world.connections.iter().zip(rows) {
            let pair = row
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(refused)?;
            if pair[0] != json!(connection.id)
                || connection.producer.node_id == connection.consumer.node_id
                || !connection.extensions.is_empty()
                || !connection.features.is_empty()
            {
                return Err(refused());
            }
            verify_static_content(&pair[1], &connection.policy_ref)?;
            let policy = pair[1].as_object().ok_or_else(refused)?;
            const POLICY_FIELDS: [&str; 8] = [
                "schema_version",
                "maximum_payload_bytes",
                "maximum_pending_events",
                "maximum_pending_bytes",
                "visibility",
                "delivery",
                "causal_proof_ref",
                "state_domain_ids",
            ];
            if policy.len() != POLICY_FIELDS.len()
                || POLICY_FIELDS
                    .iter()
                    .any(|field| !policy.contains_key(*field))
                || policy["schema_version"] != json!(1)
                || policy["visibility"] != json!({"kind":"direct"})
                || policy["delivery"]
                    != json!({"kind":"fixed","latency_ps":connection.minimum_latency_ps})
                || connection.minimum_latency_ps.get() > 1024
            {
                return Err(refused());
            }
            for (field, ceiling) in [
                ("maximum_payload_bytes", 1024),
                ("maximum_pending_events", 32),
                ("maximum_pending_bytes", 32 * 1024),
            ] {
                let bound: U64 =
                    serde_json::from_value(policy[field].clone()).map_err(ContractError::from)?;
                if bound.get() == 0 || bound.get() > ceiling {
                    return Err(refused());
                }
            }
            let proof: ContentRef = serde_json::from_value(policy["causal_proof_ref"].clone())
                .map_err(ContractError::from)?;
            proof.validate()?;
            let domains: Vec<Id> = serde_json::from_value(policy["state_domain_ids"].clone())
                .map_err(ContractError::from)?;
            if domains.is_empty() || domains.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(refused());
            }
            for (endpoint, direction) in [
                (&connection.producer, Direction::Output),
                (&connection.consumer, Direction::Input),
            ] {
                let peer = self
                    .participants
                    .iter()
                    .find(|peer| peer.realization.descriptors[0].id == endpoint.node_id)
                    .ok_or_else(refused)?;
                let port = peer.realization.descriptors[0]
                    .ports
                    .iter()
                    .find(|port| port.id == endpoint.port_id)
                    .ok_or_else(refused)?;
                let lane = port
                    .lanes
                    .iter()
                    .find(|lane| lane.id == endpoint.lane_id)
                    .ok_or_else(refused)?;
                if lane.direction != direction
                    || port.interface_id != connection.interface_id
                    || lane.payload_schema != connection.payload_schema
                {
                    return Err(refused());
                }
            }
        }
        Ok(())
    }

    fn validate_roster(&self, world: &WorldBinding) -> Result<(), ProviderError> {
        let nodes = self.template["nodes"].as_array().ok_or_else(refused)?;
        if nodes.len() != WORLD_NODES || world.node_bindings.len() != WORLD_NODES {
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
                || node.get("facets") != Some(&self.edition.native_facets())
                || node.get("native_thread_custody") != Some(&json!("owner-thread"))
                || node.get("effective_repeatability")
                    != Some(&json!(Repeatability::Nondeterministic))
            {
                return Err(refused());
            }
            if self.edition == CoordinatorEdition::CompleteFive {
                super::continuation::validate_native(peer, &nodes[index])?;
            }
            verify_static_content(
                &nodes[index]["guarantees"],
                &binding.compatibility.guarantees_ref,
            )?;
            let ports = nodes[index]["ports"].as_array().ok_or_else(refused)?;
            if ports.len() != descriptor.ports.len() {
                return Err(refused());
            }
            for (port, row) in descriptor.ports.iter().zip(ports) {
                let pair = row
                    .as_array()
                    .filter(|pair| pair.len() == 2)
                    .ok_or_else(refused)?;
                if pair[0] != json!(port.id) {
                    return Err(refused());
                }
                verify_static_content(&pair[1], &port.configuration_ref)?;
            }
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
        let host = self.host;
        host.descriptor.validate()?;
        host.binding.validate()?;
        host.owner.validate()?;
        host.prepared_token.validate()?;
        let node = &host.descriptor;
        let binding = &host.binding;
        let owner = &host.owner.owner;
        let node_ref = NodeBindingRef {
            node_id: node.id.clone(),
            binding_hash: binding.identity()?,
            extensions: Extensions::new(),
        };
        let identity = json!({"owner":owner.id,
            "incarnation":binding.authority.incarnation_id,
            "generation":binding.authority.owner_generation});
        let initial = host.initial_node.as_object().ok_or_else(refused)?;
        const NODE_FIELDS: [&str; 9] = [
            "descriptor",
            "binding",
            "route",
            "facets",
            "native_thread_custody",
            "operating_policy",
            "guarantees",
            "effective_repeatability",
            "ports",
        ];
        if !node_ids.insert(node.id.clone())
            || !owner_ids.insert(owner.id.clone())
            || !node.ports.is_empty()
            || binding.compatibility.node_id != node.id
            || binding.compatibility.descriptor_hash != node.identity()?
            || binding.compatibility.configuration_ref != node.configuration_ref
            || binding.compatibility.execution_owner != *owner
            || binding.compatibility.capture_owner != *owner
            || owner.participant_ids != [node.id.clone()]
            || host.owner.node_bindings != [node_ref.clone()]
            || world.node_bindings[PARTICIPANTS] != node_ref
            || nodes[PARTICIPANTS] != host.initial_node
            || initial.len() != NODE_FIELDS.len()
            || NODE_FIELDS
                .iter()
                .any(|field| !initial.contains_key(*field))
            || initial["descriptor"] != json!(node)
            || initial["binding"] != json!(binding)
            || initial["route"] != json!({"node":node.id,"owners":[identity]})
            || initial["ports"] != json!([])
            || world
                .connections
                .iter()
                .any(|connection| connection.capture_owner_id != owner.id)
        {
            return Err(refused());
        }
        if self.edition == CoordinatorEdition::CompleteFive {
            super::continuation::validate_host(host, self.template)?;
        }
        verify_static_content(
            &initial["guarantees"],
            &binding.compatibility.guarantees_ref,
        )?;
        identities.push(identity.clone());
        owner_bindings.push(host.owner.clone());
        owner_rows.push(json!({"identity":identity,"lifecycle":"Prepared",
            "operation":null,"domains":owner.state_domain_ids}));
        conflicts.push(json!([owner.id, []]));
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
    pub(super) fn validate_body(&self, bytes: &[u8]) -> Result<(), ProviderError> {
        let mut value = canonical::parse_json(bytes, PACKET_CONNECTED_COORDINATOR_BYTES)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused());
        }
        let rows = value["preparations"]
            .as_array()
            .filter(|rows| rows.len() == WORLD_NODES)
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
        if value != *self.template {
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
    pub(super) fn authenticate_staged(
        &self,
        bytes: &[u8],
        local: &PacketControlSelection,
        staged: &ActivateRequest,
        ready: &ContentRef,
        manifest: &ActivationManifest,
    ) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(
            &(staged, ready, manifest),
            PACKET_CONNECTED_COORDINATOR_BYTES,
        )?;
        self.validate(local)?;
        manifest.validate()?;
        let mut body = canonical::parse_json(bytes, PACKET_CONNECTED_COORDINATOR_BYTES)?;
        if canonical::canonical_json(&body)? != bytes {
            return Err(refused());
        }
        let rows = body["preparations"]
            .as_array()
            .filter(|rows| rows.len() == WORLD_NODES)
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
        let host = self.host;
        let row = &rows[PARTICIPANTS];
        let receipt: ContentRef = serde_json::from_value(row["readiness"]["ready_receipt"].clone())
            .map_err(ContractError::from)?;
        receipt.validate()?;
        let binding = &host.binding;
        let owner = &host.owner.owner;
        let actual = PreparedOwner {
            owner_id: owner.id.clone(),
            incarnation_id: binding.authority.incarnation_id.clone(),
            owner_generation: binding.authority.owner_generation,
            binding_hashes: vec![binding.identity()?],
            prepared_token: host.prepared_token.clone(),
            ready_receipt: receipt.clone(),
            extensions: Extensions::new(),
        };
        let expected = json!({"node":host.descriptor.id,
            "readiness":{"owners":[{"owner":owner.id,
                "incarnation":binding.authority.incarnation_id,
                "generation":binding.authority.owner_generation}],
                "boundary":self.template["clock"],"state_inventory":receipt,
                "ready_receipt":receipt},"prepared_owners":[actual]});
        if row != &expected {
            return Err(refused());
        }
        prepared.push(actual);
        body.as_object_mut()
            .ok_or_else(refused)?
            .insert("preparations".into(), json!([]));
        let activation = &self.template["activation"];
        if body != *self.template
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

impl CoordinatorEdition {
    fn schema(self) -> &'static str {
        match self {
            Self::ConnectedFour => "source-owned.packet-connected-coordinator-installation/4",
            Self::CompleteFive => {
                super::super::continuation_contracts::PACKET_NATIVE5_COORDINATOR_SCHEMA
            }
        }
    }

    fn native_facets(self) -> Value {
        match self {
            Self::ConnectedFour => json!(["exact-execution"]),
            Self::CompleteFive => json!(["exact-execution", "preservation"]),
        }
    }
}

impl PacketConnectedCoordinatorInstallation {
    /// Names the returned private view and borrowed validation-call controls.
    ///
    /// Both connected and complete installations construct this same defining
    /// view value before validation. These headers supplement the separate
    /// installation extent getter; nested typed, JSON and validator work must
    /// still be admitted independently by the actual decoder caller.
    pub(in crate::reference_packet) fn borrowed_validation_counter_scratch_data() -> usize {
        use std::mem::size_of;

        // The view is returned by installation.view() and received by validate.
        size_of::<CoordinatorView<'static>>()
            + size_of::<CoordinatorView<'static>>()
            + size_of::<&CoordinatorView<'static>>()
            + size_of::<CoordinatorEdition>()
            + size_of::<&PacketConnectedCoordinatorInstallation>()
            + size_of::<&PacketControlSelection>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + super::continuation::validation_counter_scratch_data()
    }
}
