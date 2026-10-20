//! Streams every retained common semantic field without cloning history banks.

use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeStruct},
};

use super::super::state::{
    OriginalCancellation, OriginalInput, OriginalOperation, SemanticRuntimeCustody,
};
use crate::node_contract::{ActivationRecord, WorldActivation};
use crate::node_scheduling::{InputCustodyCommit, RuntimeInputBatch};

#[derive(Serialize)]
pub(in crate::node_adapters::cnp::semantic) struct ActivationView<'a> {
    generation: crucible_node_format::U64,
    activation_id: &'a crucible_node_format::Id,
    world_binding_hash: &'a crucible_node_format::HashRef,
    owners: &'a [crate::node_contract::OwnerIdentity],
    boundary: crucible_node_format::Position,
}

impl<'a> From<&'a ActivationRecord> for ActivationView<'a> {
    fn from(record: &'a ActivationRecord) -> Self {
        Self {
            generation: record.generation,
            activation_id: &record.activation_id,
            world_binding_hash: &record.world_binding_hash,
            owners: &record.owners,
            boundary: record.boundary,
        }
    }
}

fn activation(value: &WorldActivation) -> ActivationView<'_> {
    value.record().into()
}

pub(in crate::node_adapters::cnp::semantic) struct BatchView<'a>(
    pub(in crate::node_adapters::cnp::semantic) &'a RuntimeInputBatch,
);

impl Serialize for BatchView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let batch = self.0;
        let mut row = serializer.serialize_struct("OriginalBatch", 9)?;
        row.serialize_field("activation", &activation(batch.activation()))?;
        row.serialize_field("node", batch.node())?;
        row.serialize_field("stage_operation", batch.stage_operation())?;
        row.serialize_field("batch", batch.batch())?;
        row.serialize_field("owners", batch.owners())?;
        row.serialize_field("cutoff", &batch.cutoff())?;
        row.serialize_field("inventory", batch.inventory())?;
        row.serialize_field("deliveries", batch.deliveries())?;
        row.serialize_field("payloads", batch.payloads())?;
        row.end()
    }
}

struct CommitView<'a>(&'a InputCustodyCommit);

impl Serialize for CommitView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let original = self.0;
        let mut row = serializer.serialize_struct("OriginalCommit", 6)?;
        row.serialize_field("activation", &activation(original.activation()))?;
        row.serialize_field("node", original.node())?;
        row.serialize_field("stage_operation", original.stage_operation())?;
        row.serialize_field("batch", original.batch())?;
        row.serialize_field("inventory", original.inventory())?;
        row.serialize_field("cutoff", &original.cutoff())?;
        row.end()
    }
}

struct InputView<'a>(&'a OriginalInput);

impl Serialize for InputView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            original: CommitView<'a>,
            request_id: &'a crucible_node_format::Id,
            extensions: &'a crucible_node_format::Extensions,
            context: &'a [crate::node_scheduling::InputPayload],
            response: &'a Option<crucible_node_transport::bodies::InputResult>,
        }
        let input = self.0;
        let commitment = input.commitment.as_ref().map(|value| Commitment {
            original: CommitView(&value.original),
            request_id: &value.request_id,
            extensions: &value.extensions,
            context: &value.context,
            response: &value.response,
        });
        let mut row = serializer.serialize_struct("OriginalInput", 6)?;
        row.serialize_field("original", &BatchView(&input.original))?;
        row.serialize_field("acknowledgement", &input.acknowledgement)?;
        row.serialize_field("watermark", &input.watermark)?;
        row.serialize_field("request", &input.request)?;
        row.serialize_field("commitment", &commitment)?;
        row.serialize_field("response", &input.response)?;
        row.end()
    }
}

struct CancellationView<'a>(&'a OriginalCancellation);

impl Serialize for CancellationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (state, failure) = match self.0 {
            OriginalCancellation::NotAttempted => ("not-attempted", None),
            OriginalCancellation::Pending => ("pending", None),
            OriginalCancellation::Requested => ("requested", None),
            OriginalCancellation::Unsupported => ("unsupported", None),
            OriginalCancellation::Failed(failure) => ("failed", Some(failure)),
        };
        (state, failure).serialize(serializer)
    }
}

struct OperationView<'a>(&'a OriginalOperation);

impl Serialize for OperationView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let original = self.0;
        let admission = &original.admission;
        let mut row = serializer.serialize_struct("OriginalOperation", 13)?;
        row.serialize_field("operation", admission.token().operation())?;
        row.serialize_field("route", admission.token().route())?;
        row.serialize_field("request", admission.request())?;
        row.serialize_field("activation", &activation(admission.activation()))?;
        row.serialize_field("inputs", &admission.inputs().map(BatchView))?;
        row.serialize_field("begin", &original.begin)?;
        row.serialize_field("outcome", &original.outcome)?;
        row.serialize_field("failure", &original.failure)?;
        row.serialize_field("polls", &original.polls)?;
        row.serialize_field("begin_acknowledged", &original.begin_acknowledged)?;
        row.serialize_field("cancellation", &CancellationView(&original.cancellation))?;
        row.serialize_field("acknowledged", &original.acknowledged)?;
        row.serialize_field("retirement", &original.retirement)?;
        row.end()
    }
}

struct Operations<'a>(&'a SemanticRuntimeCustody);

impl Serialize for Operations<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_map(Some(self.0.operations.len()))?;
        for (identity, original) in &self.0.operations {
            rows.serialize_entry(identity, &OperationView(original))?;
        }
        rows.end()
    }
}

struct Inputs<'a>(&'a SemanticRuntimeCustody);

impl Serialize for Inputs<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_map(Some(self.0.inputs.len()))?;
        for (identity, original) in &self.0.inputs {
            rows.serialize_entry(identity, &InputView(original))?;
        }
        rows.end()
    }
}

pub(super) struct CustodyView<'a>(pub(super) &'a SemanticRuntimeCustody);

impl Serialize for CustodyView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let state = self.0;
        if state.installed_restoration.is_some() {
            return Err(serde::ser::Error::custom(
                "selected installed custody requires its continuation format",
            ));
        }
        let observation = state
            .observation
            .as_ref()
            .map(|(world, value)| (activation(world), value));
        let reclaimed = state
            .reclaimed
            .as_ref()
            .map(|value| (&value.owner, &value.receipt));
        let mut row = serializer.serialize_struct("SemanticCustody", 15)?;
        row.serialize_field("schema", "source-owned.packet-semantic-custody/5")?;
        row.serialize_field(
            "arm_attempt",
            &state.arm_attempt.as_ref().map(ActivationView::from),
        )?;
        row.serialize_field("ready", &state.ready)?;
        row.serialize_field("prepared_owner", &state.prepared_owner)?;
        row.serialize_field("activate_response", &state.activate_response)?;
        row.serialize_field("observe_sequence", &state.observe_sequence)?;
        row.serialize_field(
            "activation_attempt",
            &state.activation_attempt.as_ref().map(activation),
        )?;
        row.serialize_field("active", &state.active.as_ref().map(activation))?;
        row.serialize_field("inputs", &Inputs(state))?;
        row.serialize_field("operations", &Operations(state))?;
        row.serialize_field("watermark", &state.watermark)?;
        row.serialize_field("observation", &observation)?;
        row.serialize_field("reclaimed", &reclaimed)?;
        row.serialize_field("retained_credit", &state.credit.retained_bytes())?;
        row.serialize_field("quarantined", &state.quarantined)?;
        row.end()
    }
}

#[path = "view/restored_base17.rs"]
mod restored_base17;
pub(in crate::node_adapters::cnp::semantic) use restored_base17::RestoredBaseCustodyView;
pub(in crate::node_adapters::cnp::semantic) use restored_base17::counter_scratch_data as restored_base17_counter_scratch_data;
