//! Retains original complete public preparation beneath selected native codecs.
//!
//! The closed record preserves historical data from opaque committed activation.
//! It cannot construct readiness or activation. Each selected backend separately
//! retains its actual raw Ready/session bodies and authenticates fresh restored
//! custody before projecting this source history into a new owner mapping.

use std::{collections::BTreeSet, io::Write};

use crucible_node_contract::{ContentRef, Id, Position, PreparedOwner, Validate, canonical};
use serde::{Deserialize, Serialize};

use crate::{
    node_contract::{
        EffectKnowledge, OperationFailure, OwnerIdentity, SavedRuntimeActivation, WorldActivation,
    },
    node_scheduling::InputPayload,
};

const FORMAT: &str = "crucible.original-public-world-preparation";
const MAXIMUM_PARTICIPANTS: usize = 64;
const MAXIMUM_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalNodePreparation {
    pub(super) node: Id,
    pub(super) owners: Vec<OwnerIdentity>,
    pub(super) boundary: Position,
    pub(super) state_inventory: ContentRef,
    pub(super) ready_receipt: ContentRef,
    pub(super) prepared_owners: Vec<PreparedOwner>,
}

/// Contains source history only; authenticated native import remains mandatory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalWorldPreparation {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    pub(super) activation: SavedRuntimeActivation,
    pub(super) nodes: Vec<OriginalNodePreparation>,
    pub(super) prepared_owners: Vec<PreparedOwner>,
    pub(super) coordinator: ContentRef,
    pub(super) publication: ContentRef,
}

impl OriginalWorldPreparation {
    /// Reads the complete original public barrier, never a current observation.
    pub(super) fn capture(
        activation: &WorldActivation,
        maximum_bytes: usize,
    ) -> Result<(Self, InputPayload, InputPayload, InputPayload), OperationFailure> {
        let owners = activation.prepared_owners().ok_or_else(|| {
            refusal("original committed activation has no complete public preparation")
        })?;
        let coordinator = activation.coordinator_snapshot().ok_or_else(|| {
            refusal("original committed activation omits its acknowledged coordinator body")
        })?;
        if coordinator.bytes.len() > maximum_bytes.min(MAXIMUM_BYTES) {
            return Err(refusal("original public coordinator exceeds codec credit"));
        }
        coordinator
            .reference
            .verify(&coordinator.bytes)
            .map_err(|error| refusal(&error.to_string()))?;
        if activation.node_preparations().is_empty()
            || activation.node_preparations().len() > MAXIMUM_PARTICIPANTS
            || owners.len() > MAXIMUM_PARTICIPANTS
        {
            return Err(refusal(
                "original public participant roster exceeds codec credit",
            ));
        }

        let nodes = activation
            .node_preparations()
            .iter()
            .map(|prepared| {
                let ready = prepared.readiness();
                Ok(OriginalNodePreparation {
                    node: prepared.node().clone(),
                    owners: ready.owners.clone(),
                    boundary: ready.boundary,
                    state_inventory: ready.state_inventory.clone(),
                    ready_receipt: ready.ready_receipt.clone(),
                    prepared_owners: prepared
                        .prepared_owners()
                        .ok_or_else(|| refusal("original native participant has no owner mapping"))?
                        .to_vec(),
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?;
        let publication_value = serde_json::json!({
            "format":"crucible.node-world-activation", "version":2,
            "activation":SavedRuntimeActivation::from(activation.record()),
            "node_preparations":activation.node_preparations(),
            "prepared_owners":owners,
            "coordinator_state_ref":coordinator.reference,
        });
        let publication_bytes = bounded_preparation_json(&publication_value, maximum_bytes)?;
        let publication = InputPayload {
            reference: canonical::content_ref(&publication_bytes, "application/json")
                .map_err(|error| refusal(&error.to_string()))?,
            bytes: publication_bytes,
        };
        let value = Self {
            format: FORMAT.to_owned(),
            schema_version: 1,
            activation: SavedRuntimeActivation::from(activation.record()),
            nodes,
            prepared_owners: owners.to_vec(),
            coordinator: coordinator.reference.clone(),
            publication: publication.reference.clone(),
        };
        value.validate()?;
        let body = value.encode(maximum_bytes)?;
        Ok((value, body, coordinator.clone(), publication))
    }

    /// Decodes original bytes as data, without issuing source or native authority.
    pub(super) fn decode(bytes: &[u8], maximum_bytes: usize) -> Result<Self, OperationFailure> {
        let value = canonical::parse_json(bytes, maximum_bytes.min(MAXIMUM_BYTES))
            .map_err(|error| refusal(&error.to_string()))?;
        if canonical::canonical_json(&value).map_err(|error| refusal(&error.to_string()))? != bytes
        {
            return Err(refusal(
                "original preparation record is not exact canonical bytes",
            ));
        }
        let record: Self = serde_json::from_value(value)
            .map_err(|_| refusal("original public preparation has unsupported closed fields"))?;
        record.validate()?;
        Ok(record)
    }

    /// Checks the exact original publisher grammar against retained source data.
    pub(super) fn validate_publication(
        &self,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<(), OperationFailure> {
        if bytes.len() > maximum.min(MAXIMUM_BYTES) {
            return Err(refusal(
                "original complete publication exceeds installed credit",
            ));
        }
        self.publication
            .verify(bytes)
            .map_err(|error| refusal(&error.to_string()))?;
        let nodes: Vec<_> = self
            .nodes
            .iter()
            .map(|node| {
                serde_json::json!({
                    "node":node.node,
                    "readiness":{
                        "owners":node.owners,"boundary":node.boundary,
                        "state_inventory":node.state_inventory,"ready_receipt":node.ready_receipt,
                    },
                    "prepared_owners":node.prepared_owners,
                })
            })
            .collect();
        let expected = canonical::canonical_json(&serde_json::json!({
            "format":"crucible.node-world-activation", "version":2,
            "activation":self.activation,"node_preparations":nodes,
            "prepared_owners":self.prepared_owners,"coordinator_state_ref":self.coordinator,
        }))
        .map_err(|error| refusal(&error.to_string()))?;
        if expected != bytes {
            return Err(refusal(
                "original complete publication changed its acknowledged preparation or coordinator",
            ));
        }
        Ok(())
    }

    pub(super) fn node(&self, node: &Id) -> Result<&OriginalNodePreparation, OperationFailure> {
        self.nodes
            .iter()
            .find(|prepared| &prepared.node == node)
            .ok_or_else(|| refusal("original public preparation omits the selected native node"))
    }

    fn encode(&self, maximum_bytes: usize) -> Result<InputPayload, OperationFailure> {
        let bytes = bounded_preparation_json(self, maximum_bytes)?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| refusal(&error.to_string()))?;
        Ok(InputPayload { reference, bytes })
    }

    fn validate(&self) -> Result<(), OperationFailure> {
        if self.format != FORMAT
            || self.schema_version != 1
            || self.nodes.is_empty()
            || self.nodes.len() > MAXIMUM_PARTICIPANTS
            || self.prepared_owners.is_empty()
            || self.prepared_owners.len() > MAXIMUM_PARTICIPANTS
            || self.activation.owners.len() != self.prepared_owners.len()
            || self.activation.generation.get() == 0
            || self
                .nodes
                .windows(2)
                .any(|pair| pair[0].node >= pair[1].node)
            || self
                .prepared_owners
                .windows(2)
                .any(|pair| pair[0].owner_id >= pair[1].owner_id)
        {
            return Err(refusal(
                "original public preparation roster or edition differs",
            ));
        }
        let mut covered = BTreeSet::new();
        for node in &self.nodes {
            if node.owners.is_empty()
                || node.owners.len() != node.prepared_owners.len()
                || node.boundary != self.activation.boundary
                || node.owners.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(refusal(
                    "original native readiness omits original participants or cut",
                ));
            }
            node.node
                .validate()
                .map_err(|error| refusal(&error.to_string()))?;
            node.state_inventory
                .validate()
                .map_err(|error| refusal(&error.to_string()))?;
            node.ready_receipt
                .validate()
                .map_err(|error| refusal(&error.to_string()))?;
            for (native, prepared) in node.owners.iter().zip(&node.prepared_owners) {
                prepared
                    .validate()
                    .map_err(|error| refusal(&error.to_string()))?;
                if prepared.owner_id != native.owner
                    || prepared.incarnation_id != native.incarnation
                    || prepared.owner_generation != native.generation
                    || prepared.ready_receipt != node.ready_receipt
                    || !self.activation.owners.contains(native)
                    || !self.prepared_owners.contains(prepared)
                {
                    return Err(refusal("original complete public owner aliases disagree"));
                }
                covered.insert(native.clone());
            }
        }
        if covered.len() != self.activation.owners.len() {
            return Err(refusal("original public owner roster is incomplete"));
        }
        self.publication
            .validate()
            .map_err(|error| refusal(&error.to_string()))?;
        self.coordinator
            .validate()
            .map_err(|error| refusal(&error.to_string()))?;
        Ok(())
    }
}

/// Stops serialization at the installed ceiling before growing its byte storage.
pub(super) fn bounded_preparation_json(
    value: &impl Serialize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, OperationFailure> {
    let maximum = maximum_bytes.min(MAXIMUM_BYTES);
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| refusal("original public preparation serialization exceeds credit"))?;
    let value = canonical::parse_json(&writer.bytes, maximum)
        .map_err(|error| refusal(&error.to_string()))?;
    let bytes = canonical::canonical_json(&value).map_err(|error| refusal(&error.to_string()))?;
    if bytes.len() > maximum {
        return Err(refusal(
            "original public preparation exceeds codec byte credit",
        ));
    }
    Ok(bytes)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(
                "original preparation record credit exhausted",
            ));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(std::io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn refusal(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.to_owned(),
    }
}
