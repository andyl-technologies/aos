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

use crucible_node_contract::{ContentRef, canonical};
use serde::de::DeserializeOwned;

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

#[derive(Deserialize)]
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
        &serde_json::to_value(definition).map_err(crucible_node_contract::ContractError::from)?,
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
        &serde_json::to_value(&view).map_err(crucible_node_contract::ContractError::from)?,
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
        serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
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

pub(super) fn decode_state<T: DeserializeOwned>(
    record: &mut ModelRecord,
) -> Result<T, ProviderError> {
    Ok(serde_json::from_value(std::mem::take(&mut record.state))
        .map_err(crucible_node_contract::ContractError::from)?)
}

pub(super) fn check_definition(
    record: &ModelRecord,
    definition: &impl Serialize,
) -> Result<(), ProviderError> {
    let bytes = canonical::canonical_json(
        &serde_json::to_value(definition).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    if canonical::content_ref(&bytes, "application/json")? != record.configuration {
        return Err(ProviderError::Correlation(
            "packet original model definition",
        ));
    }
    Ok(())
}

pub(super) fn restore_vec<T>(
    values: Vec<T>,
    capacity: usize,
    maximum: usize,
) -> Result<Vec<T>, ProviderError> {
    if values.len() > capacity || capacity > maximum {
        return Err(ProviderError::ResourceExhausted(
            "packet model vector capacity",
        ));
    }
    let mut restored = Vec::new();
    restored
        .try_reserve_exact(capacity)
        .map_err(|_| ProviderError::ResourceExhausted("packet model vector allocation"))?;
    restored.extend(values);
    Ok(restored)
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerState {
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
        let mut record = snapshot.record;
        if record.kind != PacketModelKind::Producer {
            return Err(ProviderError::Correlation("packet producer model kind"));
        }
        let state: ProducerState = decode_state(&mut record)?;
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
        check_definition(&record, &definition)?;
        let events = restore_vec(state.events, record.capacities.events, MAXIMUM_EVENTS)?;
        let mut model = Self::new(events, effect_socket)?;
        model.next_event = state.next_event;
        model.reached = state.reached;
        model.gate_closed = state.gate_closed;
        model.outputs = restore_vec(state.outputs, record.capacities.outputs, MAXIMUM_EVENTS)?;
        model.grants = state.grants;
        model.private_mutations = state.private_mutations;
        model.packet_effects = state.packet_effects;
        model.retired = state.retired;
        model.failed = state.failed;
        Ok(model)
    }
}
