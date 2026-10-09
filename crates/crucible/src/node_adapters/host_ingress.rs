//! Source-qualified finite recorded-input FIFO ownership for exact host storage.
//!
//! These records carry data only. Installed qualification must independently
//! authenticate the complete source, binding projection and compiled recipe
//! before an owned adapter may expose an arrival inventory. Physical sampling
//! and host-clock conversion are deliberately outside this edition.
//!
//! ```json
//! {"format":"crucible.recorded-logical-input","version":1,
//!  "endpoint":{"node_id":"disk","port_id":"data","lane_id":"input"},
//!  "closed_before":{"time_ps":"100000","microstep":"0","phase":0},
//!  "inputs":[]}
//! ```

use std::collections::BTreeSet;

use crucible_node_contract::{ContentRef, Endpoint, Id, Phase, Position, U64, canonical};
use serde::{Deserialize, Serialize};

use crate::node_contract::{ActivationRecord, OperationFailure};
use crate::node_scheduling::event::Delivery;
use crate::node_scheduling::{InputPayload, NativeExternalInput, NativeExternalInputInventory};

use super::host::failure;

/// Bounds the complete independently enrolled record source.
pub const MAXIMUM_RECORDED_INGRESS_BYTES: usize = 1024 * 1024;
/// Bounds original inputs retained by the first installed storage recipe.
pub const MAXIMUM_RECORDED_INGRESS_EVENTS: usize = 16;

/// Retains an original source identity and complete logical input body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedLogicalInput {
    /// Names the original event, independently of coordinates and payload equality.
    pub event: Id,
    /// Preserves the original source FIFO ordinal without coordinator renumbering.
    pub sequence: U64,
    /// Supplies an authored logical Publication coordinate with zero microstep.
    pub publication: Position,
    /// Retains the exact selected request body and complete content reference.
    pub payload: InputPayload,
}

/// Defines a closed immutable logical input source without issuing live authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedLogicalInputSource {
    /// Names this independent authored logical-input format.
    pub format: String,
    /// Selects its closed first edition.
    pub version: u16,
    /// Names the independently selected external input lane.
    pub endpoint: Endpoint,
    /// Excludes additional arrivals strictly before this finite boundary.
    pub closed_before: Position,
    /// Retains every original arrival in native source FIFO order.
    pub inputs: Vec<RecordedLogicalInput>,
}

/// Validates complete original source data without granting native arrival authority.
///
/// # Errors
/// Refuses wrong MIME roles, unavailable or noncanonical bytes, unknown editions,
/// invalid FIFO identities, malformed payloads, coordinates or finite overruns.
pub fn validate_recorded_input_source(
    original: &InputPayload,
) -> Result<RecordedLogicalInputSource, OperationFailure> {
    if original.reference.media_type != "application/json"
        || original.bytes.len() > MAXIMUM_RECORDED_INGRESS_BYTES
    {
        return Err(failure(
            "recorded input source codec requires bounded exact JSON",
        ));
    }
    original
        .reference
        .verify(&original.bytes)
        .map_err(contract)?;
    let value =
        canonical::parse_json(&original.bytes, MAXIMUM_RECORDED_INGRESS_BYTES).map_err(contract)?;
    let source: RecordedLogicalInputSource =
        serde_json::from_value(value).map_err(|error| failure(&error.to_string()))?;
    if canonical::canonical_json(
        &serde_json::to_value(&source).map_err(|error| failure(&error.to_string()))?,
    )
    .map_err(contract)?
        != original.bytes
        || source.format != "crucible.recorded-logical-input"
        || source.version != 1
        || source.inputs.len() > MAXIMUM_RECORDED_INGRESS_EVENTS
        || source.closed_before.phase != Phase::BoundaryControl
        || source.closed_before.microstep != U64::new(0)
        || source.closed_before.time_ps == U64::new(0)
    {
        return Err(failure(
            "recorded input source edition or closed interval differs",
        ));
    }
    let mut identities = BTreeSet::new();
    let mut previous = None;
    for input in &source.inputs {
        if !identities.insert(&input.event)
            || input.publication.phase != Phase::Publication
            || input.publication.microstep != U64::new(0)
            || input.publication >= source.closed_before
            || previous.is_some_and(|(sequence, publication)| {
                sequence >= input.sequence || publication > input.publication
            })
            || input.payload.bytes.len() > 4096
        {
            return Err(failure(
                "recorded input identity, FIFO or publication differs",
            ));
        }
        input
            .payload
            .reference
            .verify(&input.payload.bytes)
            .map_err(contract)?;
        previous = Some((input.sequence, input.publication));
    }
    Ok(source)
}

/// Retains the complete source, precise binding projection and installed recipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedIngressDefinition {
    source: RecordedLogicalInputSource,
    objects: Vec<InputPayload>,
    root: ContentRef,
}

impl RecordedIngressDefinition {
    /// Checks complete immutable data without accepting an installed source claim.
    ///
    /// The projection excludes only the designated record-root slot; its
    /// regenerated world and configuration are checked by the installed policy.
    ///
    /// # Errors
    /// Refuses unavailable bodies, malformed editions, changed references,
    /// unordered or duplicate arrivals, invalid coordinates, and finite overruns.
    pub fn new(
        original: InputPayload,
        projection: InputPayload,
        recipe: InputPayload,
    ) -> Result<Self, OperationFailure> {
        for object in [&original, &projection, &recipe] {
            if object.bytes.len() > MAXIMUM_RECORDED_INGRESS_BYTES {
                return Err(failure("recorded input object exceeds source ceiling"));
            }
            if object.reference.media_type != "application/json" {
                return Err(failure(
                    "recorded input source codec requires exact JSON roles",
                ));
            }
            object.reference.verify(&object.bytes).map_err(contract)?;
        }
        let complete_bytes = [&original, &projection, &recipe]
            .iter()
            .try_fold(0usize, |total, object| {
                total.checked_add(object.bytes.len())
            })
            .ok_or_else(|| failure("recorded input complete source geometry overflow"))?;
        if complete_bytes > MAXIMUM_RECORDED_INGRESS_BYTES {
            return Err(failure("recorded input complete source exceeds credit"));
        }
        let source = validate_recorded_input_source(&original)?;
        let bytes = canonical::canonical_json(&serde_json::json!({
            "format":"crucible.recorded-input-root","version":1,
            "source":original.reference,"projection":projection.reference,
            "recipe":recipe.reference
        }))
        .map_err(contract)?;
        let root = canonical::content_ref(&bytes, "application/json").map_err(contract)?;
        Ok(Self {
            source,
            root: root.clone(),
            objects: vec![
                original,
                projection,
                recipe,
                InputPayload {
                    reference: root,
                    bytes,
                },
            ],
        })
    }

    /// Returns the full immutable source-root reference, without live authority.
    #[must_use]
    pub fn root(&self) -> &ContentRef {
        &self.root
    }

    /// Returns the complete original logical source data.
    #[must_use]
    pub fn source(&self) -> &RecordedLogicalInputSource {
        &self.source
    }

    /// Returns every selected source dependency with its exact full reference.
    #[must_use]
    pub fn objects(&self) -> &[InputPayload] {
        &self.objects
    }
}

pub(super) struct RecordedIngressCustody {
    definition: RecordedIngressDefinition,
    cursor: usize,
    proofs: Vec<InputPayload>,
    activation: Option<ActivationRecord>,
}

impl RecordedIngressCustody {
    pub(super) fn new(definition: RecordedIngressDefinition) -> Self {
        Self {
            definition,
            cursor: 0,
            proofs: Vec::new(),
            activation: None,
        }
    }

    pub(super) fn definition(&self) -> &RecordedIngressDefinition {
        &self.definition
    }

    pub(super) fn arm(&mut self, activation: &ActivationRecord) -> Result<(), OperationFailure> {
        if let Some(original) = &self.activation {
            return if original == activation && self.cursor == 0 {
                Ok(())
            } else {
                Err(failure("recorded input original inactive scope changed"))
            };
        }
        let mut proofs = Vec::new();
        proofs
            .try_reserve_exact(self.definition.source.inputs.len() + 1)
            .map_err(|_| failure("recorded input proof credit unavailable"))?;
        for cursor in 0..=self.definition.source.inputs.len() {
            let bytes = canonical::canonical_json(&serde_json::json!({
                "format":"crucible.recorded-input-owned-prefix","version":1,
                "activation":{"id":activation.activation_id,"generation":activation.generation,
                    "world":activation.world_binding_hash,"owners":activation.owners,
                    "boundary":activation.boundary},"root":self.definition.root,
                "consumed_prefix":U64::new(cursor as u64)
            }))
            .map_err(contract)?;
            let reference = canonical::content_ref(&bytes, "application/json").map_err(contract)?;
            proofs.push(InputPayload { reference, bytes });
        }
        self.proofs = proofs;
        self.activation = Some(activation.clone());
        Ok(())
    }

    pub(super) fn inventory(&self) -> Result<NativeExternalInputInventory, OperationFailure> {
        let proof = self
            .proofs
            .get(self.cursor)
            .ok_or_else(|| failure("recorded input original activation proof absent"))?;
        Ok(NativeExternalInputInventory {
            endpoint: self.definition.source.endpoint.clone(),
            closed_before: self.definition.source.closed_before,
            proof_ref: proof.reference.clone(),
            inputs: self.definition.source.inputs[self.cursor..]
                .iter()
                .map(|input| NativeExternalInput {
                    event_id: input.event.clone(),
                    native_sequence: input.sequence,
                    publication: input.publication,
                    payload: input.payload.reference.clone(),
                    payload_bytes: input.payload.bytes.clone(),
                    provenance_ref: self.definition.root.clone(),
                })
                .collect(),
        })
    }

    pub(super) fn validate_delivery(
        &self,
        delivery: &Delivery,
        offset: usize,
    ) -> Result<(), OperationFailure> {
        let input = self
            .definition
            .source
            .inputs
            .get(self.cursor + offset)
            .ok_or_else(|| failure("recorded input original FIFO prefix exhausted"))?;
        let endpoint = &self.definition.source.endpoint;
        if delivery.external_root.as_ref() != Some(endpoint)
            || &delivery.producer_endpoint != endpoint
            || &delivery.consumer_endpoint != endpoint
            || delivery.connection_id.is_some()
            || delivery.connection_policy_ref.is_some()
            || delivery.publication_id != input.event
            || delivery.native_sequence != input.sequence
            || delivery.publication != input.publication
            || delivery.payload != input.payload.reference
            || delivery.provenance_ref != self.definition.root
            || !delivery.causal_parents.is_empty()
        {
            return Err(failure("recorded input differs from original owned FIFO"));
        }
        Ok(())
    }

    // Called only after the actual native model accepted this exact request.
    pub(super) fn consumed(&mut self) {
        self.cursor += 1;
    }

    pub(super) fn objects(&self) -> impl Iterator<Item = &InputPayload> {
        self.definition
            .objects
            .iter()
            .chain(self.proofs.iter().take(self.cursor + 1))
    }
}

fn contract(error: crucible_node_contract::ContractError) -> OperationFailure {
    failure(&error.to_string())
}
