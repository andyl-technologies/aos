//! Decodes every field emitted by the complete semantic and ancestry views.
//!
//! These closed data records contain no WorldActivation, operation admission or
//! input permission. Fresh custody is installed separately from Core's original
//! restoration context after complete archive and native verification.

use std::collections::BTreeMap;

use crate::{
    node_contract::{
        NodeRoute, OperationFailure, OperationOutcome, OperationRequest, OriginalLineageRow,
        OriginalPublicationOrigin, OwnerIdentity, SavedOriginalInputScope, SavedRuntimeActivation,
    },
    node_scheduling::{
        InputPayload, NativeInputAcknowledgement, NativeSchedulingObservation, event::Delivery,
    },
};
use crucible_node_format::{ContentRef, Extensions, Id, Position, PreparedOwner, U64};
use crucible_node_transport::bodies::{
    BeginRequest, InputRequest, InputResult, WorldActivateResult,
};
use serde::{Deserialize, Deserializer, Serialize};

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedReady {
    pub(in crate::node_adapters::cnp::semantic) owners: Vec<OwnerIdentity>,
    pub(in crate::node_adapters::cnp::semantic) boundary: Position,
    pub(in crate::node_adapters::cnp::semantic) state_inventory: ContentRef,
    pub(in crate::node_adapters::cnp::semantic) ready_receipt: ContentRef,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedBatch {
    pub(in crate::node_adapters::cnp::semantic) activation: SavedRuntimeActivation,
    pub(in crate::node_adapters::cnp::semantic) node: Id,
    pub(in crate::node_adapters::cnp::semantic) stage_operation: Id,
    pub(in crate::node_adapters::cnp::semantic) batch: Id,
    pub(in crate::node_adapters::cnp::semantic) owners: Vec<OwnerIdentity>,
    pub(in crate::node_adapters::cnp::semantic) cutoff: Position,
    pub(in crate::node_adapters::cnp::semantic) inventory: ContentRef,
    pub(in crate::node_adapters::cnp::semantic) deliveries: Vec<Delivery>,
    pub(in crate::node_adapters::cnp::semantic) payloads: Vec<InputPayload>,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedCommit {
    pub(in crate::node_adapters::cnp::semantic) activation: SavedRuntimeActivation,
    pub(in crate::node_adapters::cnp::semantic) node: Id,
    pub(in crate::node_adapters::cnp::semantic) stage_operation: Id,
    pub(in crate::node_adapters::cnp::semantic) batch: Id,
    pub(in crate::node_adapters::cnp::semantic) inventory: ContentRef,
    pub(in crate::node_adapters::cnp::semantic) cutoff: Position,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedCommitment {
    pub(in crate::node_adapters::cnp::semantic) original: ArchivedCommit,
    pub(in crate::node_adapters::cnp::semantic) request_id: Id,
    pub(in crate::node_adapters::cnp::semantic) extensions: Extensions,
    pub(in crate::node_adapters::cnp::semantic) context: Vec<InputPayload>,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) response: Option<InputResult>,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedInput {
    pub(in crate::node_adapters::cnp::semantic) original: ArchivedBatch,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) acknowledgement: Option<NativeInputAcknowledgement>,
    pub(in crate::node_adapters::cnp::semantic) watermark: U64,
    pub(in crate::node_adapters::cnp::semantic) request: InputRequest,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) commitment: Option<ArchivedCommitment>,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) response: Option<InputResult>,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedOperation {
    pub(in crate::node_adapters::cnp::semantic) operation: Id,
    pub(in crate::node_adapters::cnp::semantic) route: NodeRoute,
    pub(in crate::node_adapters::cnp::semantic) request: OperationRequest,
    pub(in crate::node_adapters::cnp::semantic) activation: SavedRuntimeActivation,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) inputs: Option<ArchivedBatch>,
    pub(in crate::node_adapters::cnp::semantic) begin: BeginRequest,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) outcome: Option<OperationOutcome>,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) failure: Option<OperationFailure>,
    pub(in crate::node_adapters::cnp::semantic) polls: U64,
    pub(in crate::node_adapters::cnp::semantic) begin_acknowledged: bool,
    pub(in crate::node_adapters::cnp::semantic) cancellation: (String, Option<OperationFailure>),
    pub(in crate::node_adapters::cnp::semantic) acknowledged: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) retirement: Option<InputPayload>,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedSemanticCustody {
    pub(in crate::node_adapters::cnp::semantic) schema: String,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) arm_attempt: Option<SavedRuntimeActivation>,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) ready: Option<ArchivedReady>,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) prepared_owner: Option<PreparedOwner>,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) activate_response: Option<WorldActivateResult>,
    pub(in crate::node_adapters::cnp::semantic) observe_sequence: U64,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) activation_attempt: Option<SavedRuntimeActivation>,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) active: Option<SavedRuntimeActivation>,
    pub(in crate::node_adapters::cnp::semantic) inputs: BTreeMap<Id, ArchivedInput>,
    pub(in crate::node_adapters::cnp::semantic) operations: BTreeMap<Id, ArchivedOperation>,
    pub(in crate::node_adapters::cnp::semantic) watermark: U64,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) observation:
        Option<(SavedRuntimeActivation, NativeSchedulingObservation)>,
    #[serde(deserialize_with = "required_nullable")]
    pub(in crate::node_adapters::cnp::semantic) reclaimed: Option<(OwnerIdentity, ContentRef)>,
    pub(in crate::node_adapters::cnp::semantic) retained_credit: usize,
    pub(in crate::node_adapters::cnp::semantic) quarantined: bool,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedPublication<Object> {
    pub(in crate::node_adapters::cnp::semantic) event: crucible_node_format::Event,
    pub(in crate::node_adapters::cnp::semantic) origin: OriginalPublicationOrigin,
    pub(in crate::node_adapters::cnp::semantic) published: ContentRef,
    pub(in crate::node_adapters::cnp::semantic) objects: Vec<Object>,
    pub(in crate::node_adapters::cnp::semantic) rows: Vec<OriginalLineageRow>,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedLineage<Object> {
    pub(in crate::node_adapters::cnp::semantic) source_scope: SavedOriginalInputScope,
    pub(in crate::node_adapters::cnp::semantic) original: ArchivedBatch,
    pub(in crate::node_adapters::cnp::semantic) publications: Vec<ArchivedPublication<Object>>,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters::cnp::semantic) struct ArchivedAncestryRecord<Object> {
    pub(in crate::node_adapters::cnp::semantic) schema: String,
    pub(in crate::node_adapters::cnp::semantic) lineages: Vec<ArchivedLineage<Object>>,
}

/// Selects a closed source ancestry grammar without trying multiple decoders.
#[derive(PartialEq)]
pub(in crate::node_adapters::cnp::semantic) enum ArchivedAncestry {
    Inline(ArchivedAncestryRecord<InputPayload>),
    References(ArchivedAncestryRecord<ContentRef>),
}

impl ArchivedAncestry {
    pub(in crate::node_adapters::cnp::semantic) fn schema(&self) -> &str {
        match self {
            Self::Inline(record) => &record.schema,
            Self::References(record) => &record.schema,
        }
    }

    pub(super) fn decode(value: &serde_json::Value) -> Result<Self, OperationFailure> {
        match value.get("schema").and_then(serde_json::Value::as_str) {
            Some("source-owned.packet-original-ancestry/5") => Ok(Self::Inline(
                ArchivedAncestryRecord::deserialize(value).map_err(super::unknown)?,
            )),
            Some("source-owned.packet-original-ancestry/12") => Ok(Self::References(
                ArchivedAncestryRecord::deserialize(value).map_err(super::unknown)?,
            )),
            _ => Err(super::refused("archived ancestry schema is unsupported")),
        }
    }
}

impl Serialize for ArchivedAncestry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Inline(record) => record.serialize(serializer),
            Self::References(record) => record.serialize(serializer),
        }
    }
}
