//! Complete finite model snapshots and fresh owned effect-socket reconstruction.
//!
//! The snapshot retains model history; it excludes the control/transport owner,
//! which requires its own authenticated Native5 capture and settlement closure.
//! Decoding this data never grants capture, activation or restore authority.
//!
//! The closed model object has this shape:
//!
//! ```text
//! {schema: "source-owned.packet-native-model/5", kind: producer|reactive,
//!  captured_process, configuration, cut, capacities, state: {all model fields}}
//! ```

use crucible_node_format::{ContentRef, ContractError, HashRef, canonical};

use super::*;

/// Bounds one complete model object independently of control/protocol histories.
pub const PACKET_MODEL_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MODEL_SCHEMA: &str = "source-owned.packet-native-model/5";

/// Distinguishes the actual output-only and reactive model layouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketModelKind {
    /// Selects the original output-only callback program.
    Producer,
    /// Selects the original Delivery/Reaction/Publication program.
    Reactive,
}

/// Retains complete bytes captured directly from one original model allocation.
///
/// Construction is restricted to model capture methods. The containing native
/// controller must authenticate its complete owner, ticket and quiescent channel
/// before using this data as one leaf of a native capture.
pub struct PacketOriginalModelSnapshot {
    reference: ContentRef,
    bytes: Vec<u8>,
    configuration: ContentRef,
    cursor: Position,
    kind: PacketModelKind,
}

impl PacketOriginalModelSnapshot {
    /// Borrows the complete canonical model object's content identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the complete original canonical model bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the complete original model definition's identity.
    pub fn configuration(&self) -> &ContentRef {
        &self.configuration
    }

    /// Returns the original stopped full-position cursor.
    pub fn cursor(&self) -> Position {
        self.cursor
    }

    /// Returns the actual captured model layout.
    pub fn kind(&self) -> PacketModelKind {
        self.kind
    }
}

/// Holds bounded decoded model data, without a native restoration permission.
///
/// An installed Native5 adopter must independently authenticate the original
/// snapshot, complete controller/transport settlement and fresh target owner.
/// Adoption only reconstructs model state around a supplied owned datagram.
pub struct PacketDecodedModelSnapshot {
    pub(super) record: ModelRecord,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelCapacities {
    pub(super) events: usize,
    pub(super) reactions: usize,
    pub(super) delivered_inputs: usize,
    pub(super) publications: usize,
    pub(super) outputs: usize,
    pub(super) stages: usize,
}

#[derive(Serialize)]
struct CaptureView<'a, T> {
    schema: &'static str,
    kind: PacketModelKind,
    captured_process: U64,
    configuration: &'a ContentRef,
    cut: Position,
    capacities: &'a ModelCapacities,
    state: T,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelRecord {
    schema: String,
    pub(super) kind: PacketModelKind,
    pub(super) captured_process: U64,
    pub(super) configuration: ContentRef,
    pub(super) cut: Position,
    pub(super) capacities: ModelCapacities,
    pub(super) state: serde_json::Value,
}

pub(super) fn capture_model<T: Serialize>(
    state: T,
    kind: PacketModelKind,
    definition: &impl Serialize,
    cut: Position,
    capacities: ModelCapacities,
    maximum_bytes: usize,
) -> Result<PacketOriginalModelSnapshot, ProviderError> {
    let maximum = checked_limit(maximum_bytes)?;
    crate::connection::serialized_credit(definition, maximum)?;
    let definition = canonical::canonical_json(
        &serde_json::to_value(definition).map_err(crucible_node_format::ContractError::from)?,
    )?;
    let configuration = canonical::content_ref(&definition, "application/json")?;
    let view = CaptureView {
        schema: MODEL_SCHEMA,
        kind,
        captured_process: U64::new(u64::from(std::process::id())),
        configuration: &configuration,
        cut,
        capacities: &capacities,
        state,
    };
    // Complete borrowed-state credit precedes canonical materialization.
    crate::connection::serialized_credit(&view, maximum)?;
    let bytes = canonical::canonical_json(
        &serde_json::to_value(&view).map_err(crucible_node_format::ContractError::from)?,
    )?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    Ok(PacketOriginalModelSnapshot {
        reference,
        bytes,
        configuration,
        cursor: cut,
        kind,
    })
}

/// Decodes a complete bounded model object without authorizing its installation.
///
/// # Errors
/// Refuses excess before parsing, changed content, noncanonical or open-schema
/// bytes, an unsupported model edition, or malformed capture coordinates.
pub fn decode_packet_model_snapshot(
    bytes: &[u8],
    reference: &ContentRef,
    maximum_bytes: usize,
) -> Result<PacketDecodedModelSnapshot, ProviderError> {
    let maximum = checked_limit(maximum_bytes)?;
    if bytes.len() > maximum {
        return Err(ProviderError::ResourceExhausted(
            "packet model snapshot bytes",
        ));
    }
    reference.verify(bytes)?;
    if canonical::content_ref(bytes, "application/json")? != *reference {
        return Err(ProviderError::Correlation(
            "packet model snapshot content role",
        ));
    }
    let value = canonical::parse_json(bytes, maximum)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(ProviderError::Correlation(
            "packet model snapshot canonical bytes",
        ));
    }
    let record: ModelRecord =
        serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
    if record.schema != MODEL_SCHEMA || record.captured_process.get() == 0 {
        return Err(ProviderError::Correlation("packet model snapshot edition"));
    }
    record.cut.validate()?;
    record.configuration.validate()?;
    Ok(PacketDecodedModelSnapshot { record })
}

fn checked_limit(maximum_bytes: usize) -> Result<usize, ProviderError> {
    if maximum_bytes == 0 || maximum_bytes > PACKET_MODEL_SNAPSHOT_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "packet model snapshot credit",
        ));
    }
    Ok(maximum_bytes)
}

pub(super) fn check_definition(
    record: &ModelRecord,
    definition: &impl Serialize,
) -> Result<(), ProviderError> {
    let bytes = canonical::canonical_json(
        &serde_json::to_value(definition).map_err(crucible_node_format::ContractError::from)?,
    )?;
    if canonical::content_ref(&bytes, "application/json")? != record.configuration {
        return Err(ProviderError::Correlation(
            "packet original model definition",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct ProducerView<'a> {
    events: &'a [PacketEvent],
    next_event: usize,
    reached: Position,
    gate_closed: bool,
    outputs: &'a [PacketPublication],
    grants: &'a BTreeMap<Id, PacketGrant>,
    private_mutations: u64,
    packet_effects: u64,
    retired: &'a BTreeMap<Id, Vec<Id>>,
    failed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains the producer model fields shared by its bounded historical readers.
pub(super) struct ProducerState {
    events: Vec<PacketEvent>,
    next_event: usize,
    reached: Position,
    gate_closed: bool,
    outputs: Vec<PacketPublication>,
    grants: BTreeMap<Id, PacketGrant>,
    private_mutations: u64,
    packet_effects: u64,
    retired: BTreeMap<Id, Vec<Id>>,
    failed: bool,
}

#[derive(Serialize)]
struct ProducerDefinitionView<'a> {
    schema: &'static str,
    events: &'a [PacketEvent],
}

impl PacketProgram {
    /// Captures complete original model state at its actual stopped cursor.
    ///
    /// The actual effect socket and control/transport journals require a
    /// separate source-owned closure. This leaf grants no capture capability.
    ///
    /// # Errors
    /// Refuses another cursor, failed/incomplete originals or finite byte excess.
    pub fn capture_state(
        &self,
        cut: Position,
        maximum_bytes: usize,
    ) -> Result<PacketOriginalModelSnapshot, ProviderError> {
        if cut != self.reached || self.failed || self.grants.values().any(|row| !row.complete) {
            return Err(ProviderError::Correlation("packet model capture boundary"));
        }
        let definition = ProducerDefinitionView {
            schema: "source-owned.packet-program.v1",
            events: &self.events,
        };
        capture_model(
            ProducerView {
                events: &self.events,
                next_event: self.next_event,
                reached: self.reached,
                gate_closed: self.gate_closed,
                outputs: &self.outputs,
                grants: &self.grants,
                private_mutations: self.private_mutations,
                packet_effects: self.packet_effects,
                retired: &self.retired,
                failed: self.failed,
            },
            PacketModelKind::Producer,
            &definition,
            cut,
            ModelCapacities {
                events: self.events.capacity(),
                reactions: 0,
                delivered_inputs: 0,
                publications: 0,
                outputs: self.outputs.capacity(),
                stages: 0,
            },
            maximum_bytes,
        )
    }

    /// Reconstructs finite producer state around a genuine freshly owned socket.
    ///
    /// The outer installed Native5 owner must keep its restore gate held and
    /// authenticate complete settlement/target association before activation.
    ///
    /// # Errors
    /// Refuses the wrong model, changed definition, malformed history or excess.
    pub fn adopt_model_state(
        snapshot: PacketDecodedModelSnapshot,
        effect_socket: UnixDatagram,
    ) -> Result<Self, ProviderError> {
        let mut snapshot = Some(snapshot);
        let mut effect_socket = Some(effect_socket);
        let mut attempt = None;
        Self::adopt_model_state_retained_into(&mut snapshot, &mut effect_socket, &mut attempt)?;
        let mut completed = None;
        attempt
            .as_mut()
            .ok_or(ProviderError::Conflict("model adoption owner absent"))?
            .take_completed_into(&mut completed)?;
        completed.ok_or(ProviderError::Conflict("model adoption completion absent"))
    }
}

fn authenticate_producer_data(
    record: &ModelRecord,
    state: &ProducerState,
) -> Result<(), ProviderError> {
    if state.reached != record.cut
        || state.next_event > state.events.len()
        || state.grants.len() > MAXIMUM_OPERATIONS
        || state.retired.len() > state.grants.len()
        || state.failed
        || state
            .grants
            .iter()
            .any(|(id, grant)| id != &grant.operation || !grant.complete)
        || state
            .retired
            .keys()
            .any(|id| !state.grants.contains_key(id))
        || record.capacities.reactions != 0
        || record.capacities.delivered_inputs != 0
        || record.capacities.publications != 0
        || record.capacities.stages != 0
    {
        return Err(ProviderError::Correlation("packet producer model state"));
    }
    let definition = ProducerDefinitionView {
        schema: "source-owned.packet-program.v1",
        events: &state.events,
    };
    check_definition(record, &definition)?;
    if state.events.len() > record.capacities.events
        || record.capacities.events > MAXIMUM_EVENTS
        || state.outputs.len() > record.capacities.outputs
        || record.capacities.outputs > MAXIMUM_EVENTS
    {
        return Err(ProviderError::ResourceExhausted(
            "packet model vector capacity",
        ));
    }
    Ok(())
}

/// Reports a stopped model's complete inventory hash and Capture boundary data.
///
/// This projection authenticates bounded historical data. It constructs no
/// native model, datagram, registration, activation or restoration permission.
pub struct PacketModelCaptureBoundaryData {
    /// Retains the exact stopped local model position.
    pub local_cursor: Position,
    /// Reports the captured native gate, independently of host admission.
    pub gate_closed: bool,
    /// Counts outputs still owned by the captured model.
    pub retained_outputs: usize,
    /// Gives the earliest future callback completion, when one remains.
    pub earliest_pending_completion: Option<Position>,
    /// Hashes the exact original producer or reactive inventory grammar.
    pub inventory_hash: HashRef,
}

#[derive(Serialize)]
struct ProducerInventoryData<'a> {
    reached: Position,
    gate_closed: bool,
    pending: &'a [PacketEvent],
    retained_outputs: &'a [PacketPublication],
    private_mutations: U64,
    packet_effects: U64,
}

impl PacketDecodedModelSnapshot {
    /// Checks complete typed model data and derives the exact Capture boundary.
    ///
    /// The source separately admits the bounded typed projection scratch before
    /// calling. The model's same original data remains unchanged on refusal.
    ///
    /// # Errors
    /// Refuses invalid selected byte credit, malformed model histories, changed
    /// configuration/cursor, incomplete grants or impossible retained capacities.
    pub fn capture_boundary_data(
        &self,
        maximum_bytes: usize,
    ) -> Result<PacketModelCaptureBoundaryData, ProviderError> {
        let maximum = checked_limit(maximum_bytes)?;
        crate::connection::serialized_credit(&self.record.state, maximum)?;
        if self.record.kind == PacketModelKind::Reactive {
            return super::connected::continuation::capture_boundary_data(&self.record);
        }
        let state = ProducerState::deserialize(&self.record.state).map_err(ContractError::from)?;
        authenticate_producer_data(&self.record, &state)?;
        let pending = &state.events[state.next_event..];
        let inventory = ProducerInventoryData {
            reached: state.reached,
            gate_closed: state.gate_closed,
            pending,
            retained_outputs: &state.outputs,
            private_mutations: U64::new(state.private_mutations),
            packet_effects: U64::new(state.packet_effects),
        };
        Ok(PacketModelCaptureBoundaryData {
            local_cursor: state.reached,
            gate_closed: state.gate_closed,
            retained_outputs: state.outputs.len(),
            earliest_pending_completion: pending.iter().map(|event| event.completion).min(),
            inventory_hash: canonical::json_hash("source-owned.packet-inventory.v1", &inventory)?,
        })
    }
}

#[path = "continuation_models/producer_retained.rs"]
mod retained_adoption;
pub(crate) use retained_adoption::PacketDisplacedProducerModel;
pub use retained_adoption::PacketProducerModelAdoption;

pub(in crate::reference_packet) mod record_history;
pub use record_history::PacketModelRecordExpectation;

// Layout facts are data for Source's nonallocating JSON walk, never a permit.
pub(in crate::reference_packet) fn original_model_validation_layouts() -> [usize; 6] {
    use std::mem::{align_of, size_of};
    let connected = super::connected::continuation::original_validation_layouts();
    let slot = [
        size_of::<ModelRecord>(),
        size_of::<ModelCapacities>(),
        size_of::<ProducerState>(),
        size_of::<PacketEvent>(),
        size_of::<PacketPublication>(),
        size_of::<PacketInventory>(),
        size_of::<PacketGrant>(),
        connected[0],
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    let alignment = [
        align_of::<ModelRecord>(),
        align_of::<ModelCapacities>(),
        align_of::<ProducerState>(),
        align_of::<PacketEvent>(),
        align_of::<PacketPublication>(),
        align_of::<PacketInventory>(),
        align_of::<PacketGrant>(),
        connected[1],
    ]
    .into_iter()
    .max()
    .unwrap_or(1);
    [
        slot,
        alignment,
        size_of::<ModelRecord>(),
        size_of::<ProducerState>(),
        connected[2],
        connected[3],
    ]
}

impl PacketProgram {
    pub(crate) fn quote_original_live_capture_encoding(
        &self,
        maximum: usize,
    ) -> Result<super::serialization_storage::NativeModelCaptureEncodingData, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        let cursor = self.observe_original_live_capture_metadata(&mut observer)?;
        let facts = observer.finish();
        let definition = ProducerDefinitionView {
            schema: "source-owned.packet-program.v1",
            events: &self.events,
        };
        let state = ProducerView {
            events: &self.events,
            next_event: self.next_event,
            reached: self.reached,
            gate_closed: self.gate_closed,
            outputs: &self.outputs,
            grants: &self.grants,
            private_mutations: self.private_mutations,
            packet_effects: self.packet_effects,
            retired: &self.retired,
            failed: self.failed,
        };
        super::serialization_storage::model_encoding_storage_data(
            &definition,
            &state,
            cursor,
            [self.events.capacity(), 0, 0, 0, self.outputs.capacity(), 0],
            facts,
            maximum,
        )
    }
}

/// Names fixed historical model boundary validation and hash-construction views.
///
/// Heap/DOM/canonical/model projection storage must be admitted independently
/// from the actual Control input. This getter grants no native model or hold.
pub fn packet_model_capture_boundary_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<ProducerState>()
        + size_of::<ProducerInventoryData<'static>>()
        + size_of::<PacketModelCaptureBoundaryData>()
        + size_of::<Result<PacketModelCaptureBoundaryData, ProviderError>>()
        + size_of::<serde_json::Value>()
        + size_of::<Vec<u8>>()
        + size_of::<HashRef>()
        + size_of::<blake3::Hasher>()
        + crate::connection::original_serialized_credit_counter_scratch_data()
        + super::connected::continuation::capture_boundary_counter_scratch_data()
        + 20
}

#[path = "continuation_models/settled_history.rs"]
pub(crate) mod settled_history;

#[path = "continuation_models/settled_reader.rs"]
pub(crate) mod settled_reader;

pub(crate) use settled_reader::prepared::{
    PacketSettledPreparedModel17Data, PreparedControlHistory17, read_settled_prepared_model17_data,
    settled_prepared_model17_counter_scratch_data,
};

mod future17;

#[path = "continuation_models/decoder_counter.rs"]
mod decoder_counter;
pub(in crate::reference_packet) use decoder_counter::{
    model_decoder_counter_scratch_data, owned_json_decoder_counter_scratch_data,
};

// The complete Control/model decoder owns this distinct serde partial DAG.
pub(in crate::reference_packet) mod serde_partials;

pub(in crate::reference_packet) use decoder_counter::canonical_value_writer_frame_data;

pub(in crate::reference_packet) use decoder_counter::model_decoder_geometry_data;

pub(in crate::reference_packet) use decoder_counter::model_decoder_diagnostic_name_bytes_data;
