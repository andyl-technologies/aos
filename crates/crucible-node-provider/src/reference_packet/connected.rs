//! Source-owned phased packet reactions beneath original consumed-input custody.
//!
//! The source separates reaction from its next-microstep publication. Neither
//! staging nor commitment advances the modeled cursor. Every phase effect is
//! admitted by one original half-open grant and independently observed through
//! the actual owned datagram socket. This mechanism grants no public admission.

use std::{collections::BTreeMap, os::unix::net::UnixDatagram};

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};

use crate::{ProviderError, bodies::InputResult, envelope::Envelope};

use super::{PacketPublication, input::PacketInputCut};

mod inputs;

#[path = "continuation_models/connected.rs"]
pub(super) mod continuation;
pub(crate) use continuation::PacketDisplacedReactiveModel;
pub use continuation::PacketReactiveModelAdoption;
mod run;

pub use inputs::causal_parent_ids;

mod birth;

const MAXIMUM_BATCHES: usize = 16;
const MAXIMUM_EVENTS: usize = 32;
const MAXIMUM_OPERATIONS: usize = 64;
const MAXIMUM_BYTES: usize = 1024;
const MAXIMUM_MICROSTEPS: u64 = 16;
const MAXIMUM_RECORD: usize = 65_536;

/// Declares one exact original admitted connection independently of input frames.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketInputConnection {
    /// Names the immutable admitted connection.
    pub id: Id,
    /// Binds the complete source-installed connection policy bytes.
    pub policy: ContentRef,
    /// Names the declared original producer lane.
    pub producer: Endpoint,
    /// Names the declared original consumer lane.
    pub consumer: Endpoint,
    /// Gives the exact physical propagation delay in picoseconds.
    pub delay_ps: U64,
}

/// Installs a finite input-reactive source without selecting CPU or clock fidelity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedDefinition {
    /// Selects `source-owned.packet-connected-program/4`.
    pub schema: String,
    /// Declares all original input connections; frames cannot add another route.
    pub connections: Vec<PacketInputConnection>,
    /// Selects the local output lane, or null for a consuming sink.
    pub output: Option<Endpoint>,
}

/// Retains a complete source-native pending reaction under one consumed cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketReaction {
    /// Names the original staged public input event.
    pub input_event: Id,
    /// Retains the original public producer independently of native event labels.
    pub input_producer: Id,
    /// Retains the unchanged public recipient sequence, including sequence zero.
    pub input_sequence: U64,
    /// Names the immutable original input staging operation.
    pub stage_operation: Id,
    /// Names the original later source-consumed request.
    pub commit_request: Id,
    /// Retains the original complete payload bytes.
    pub payload: Bytes,
    /// Retains the actual recipient delivery as the immediate causal parent.
    pub parent: Position,
    /// Gives the admitted same-microstep native Reaction.
    pub evaluation: Position,
}

/// Retains one actual native Delivery independently of its later reaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketDeliveredInput {
    /// Retains exact original consumed bytes and full delivery/reaction coordinates.
    pub reaction: PacketReaction,
    /// Names the actual original exclusive grant that admitted the Delivery step.
    pub delivery_operation: Id,
}

/// Retains an actual reaction's publication without emitting it ahead of its cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketPendingPublication {
    /// Names the source-generated original output, once for this input.
    pub event: Id,
    /// Retains the source-owned original input reaction.
    pub reaction: PacketReaction,
    /// Names the actual original grant which evaluated that reaction.
    pub reaction_operation: Id,
    /// Gives the subsequent microstep's Publication position.
    pub publication: Position,
}

/// Retains an actual publication's complete input causality and native bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedPublication {
    /// Retains the actual emission grant, payload, native sequence and positions.
    pub output: PacketPublication,
    /// Retains the exact original consumed input and native reaction association.
    pub pending: PacketPendingPublication,
}

/// Retains complete phased native custody without granting common progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedInventory {
    /// Gives the actual original stopped cursor.
    pub reached: Position,
    /// Gives the actual nonexecuting native gate state.
    pub gate_closed: bool,
    /// Retains all source-consumed reactions not yet evaluated, in native order.
    pub reactions: Vec<PacketReaction>,
    /// Retains every actual completed Delivery step in canonical delivery order.
    pub delivered_inputs: Vec<PacketDeliveredInput>,
    /// Retains all actual evaluated publications not yet emitted.
    pub publications: Vec<PacketPendingPublication>,
    /// Retains all native emitted outputs until the original complete ACK.
    pub retained_outputs: Vec<PacketConnectedPublication>,
    /// Counts actual evaluated input reactions.
    pub reactions_completed: U64,
    /// Counts actual emitted packets independently of host collection.
    pub packet_effects: U64,
    /// Lists every original staged-byte record in stream order.
    pub stages: Vec<ContentRef>,
    /// Lists every original consumed-input record in stream order.
    pub commits: Vec<ContentRef>,
}

/// Retains an actual original phased grant, including its complete stopped inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedGrant {
    /// Names the original immutable operation.
    pub operation: Id,
    /// Gives its actual original starting cursor.
    pub start: Position,
    /// Gives its exclusive complete superdense ceiling.
    pub limit: Position,
    /// Retains the actual complete final native state.
    pub inventory: PacketConnectedInventory,
    /// Retains exactly this grant's actual new publications.
    pub newborn: Vec<PacketConnectedPublication>,
    /// Distinguishes completion from a retained unknown native effect.
    pub complete: bool,
}

/// Retains genuine original staging and its complete owned byte proof.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketStageRecord {
    /// Selects the exact source-native staged-byte edition.
    pub schema: String,
    /// Names the actual original native process.
    pub native_pid: U64,
    /// Retains the complete original native Input request.
    pub original: Envelope,
    /// Retains the exact original coordinator cut.
    pub cut: PacketInputCut,
    /// Retains the complete native public batch.
    pub batch: InputBatch,
    /// Retains all original canonical delivery and causal associations.
    pub deliveries: Vec<crate::input_commit::CommittedDeliveryV1>,
    /// Retains exact original payload bytes in the same complete event order.
    pub payloads: Vec<Bytes>,
    /// Retains native state before staging, unchanged by the transfer.
    pub inventory: PacketConnectedInventory,
}

/// Retains actual eligibility of the same staged byte population under native custody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCommitRecord {
    /// Selects the distinct native consumed-input edition.
    pub schema: String,
    /// Names the actual original native process.
    pub native_pid: U64,
    /// Retains the complete original later native Input request.
    pub original: Envelope,
    /// Names the actual retained original staged-byte proof.
    pub staged_record: ContentRef,
    /// Retains the actual original staging custody receipt.
    pub staging_receipt: ContentRef,
    /// Retains the exact original full cut.
    pub cut: PacketInputCut,
    /// Retains the native admitted reaction population, without execution.
    pub reactions: Vec<PacketReaction>,
    /// Preserves the unchanged actual modeled cursor at commitment.
    pub reached: Position,
}

/// Retains an actual original native input response and its full proof closure.
#[derive(Clone, Serialize, Deserialize)]
pub struct PacketInputReply {
    /// Contains the unchanged baseline Input result.
    pub result: InputResult,
    /// Contains the actual complete source-owned proof bodies.
    pub evidence: Vec<(ContentRef, Vec<u8>)>,
}

/// Retains the complete original connected source state and phased grant.
///
/// This edition never substitutes the output-only administrative projection
/// for actual staged-byte, consumed-input or publication custody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedNativeRecord {
    /// Selects `source-owned.packet-native/4` exclusively.
    pub schema: String,
    /// Names the original operating-system process which owns native effects.
    pub native_pid: U64,
    /// Retains the complete original source request.
    pub original: Envelope,
    /// Retains every actual native input, reaction and publication association.
    pub inventory: PacketConnectedInventory,
    /// Retains the complete original phased grant, or null for a lifecycle read.
    pub grant: Option<PacketConnectedGrant>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains an original staged input and its optional commit as inert history.
pub(super) struct OriginalStage {
    record: PacketStageRecord,
    record_ref: ContentRef,
    reply: PacketInputReply,
    commit: Option<OriginalCommit>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains the original commit record and reply beneath its staged input.
pub(super) struct OriginalCommit {
    record: PacketCommitRecord,
    record_ref: ContentRef,
    reply: PacketInputReply,
}

/// Owns the finite native input journal, phased callbacks and actual effect socket.
///
/// This source component supplies no public Ready, whole-node qualification,
/// capture, restart or replay authority. Its originating process exclusively
/// owns the actual socket and immutable original request/byte journals.
pub struct PacketConnectedProgram {
    definition: PacketConnectedDefinition,
    native_pid: u32,
    effect_socket: UnixDatagram,
    reached: Position,
    gate_closed: bool,
    reactions: Vec<PacketReaction>,
    delivered_inputs: Vec<PacketDeliveredInput>,
    publications: Vec<PacketPendingPublication>,
    outputs: Vec<PacketConnectedPublication>,
    stages: Vec<OriginalStage>,
    grants: BTreeMap<Id, PacketConnectedGrant>,
    retired: BTreeMap<Id, Vec<Id>>,
    reactions_completed: u64,
    packet_effects: u64,
    failed: bool,
}

/// Names the distinct native transition populations used by closed projections.
///
/// Named fields keep the event and batch capacities distinct when their actual
/// compiled limits differ; these values are bounds, never observed usage.
pub(crate) struct OriginalStoppedInventoryLimits {
    pub(crate) events: usize,
    pub(crate) batches: usize,
    pub(crate) payload_bytes: usize,
}

impl PacketConnectedProgram {
    /// Returns the actual finite inventory populations used by the startup projection.
    pub(crate) const fn original_stopped_inventory_row_limits_data()
    -> OriginalStoppedInventoryLimits {
        OriginalStoppedInventoryLimits {
            events: MAXIMUM_EVENTS,
            batches: MAXIMUM_BATCHES,
            payload_bytes: MAXIMUM_BYTES,
        }
    }

    pub(super) fn committed_input(
        &self,
    ) -> Result<(&PacketCommitRecord, &ContentRef), ProviderError> {
        self.current()?;
        let commit = self
            .stages
            .last()
            .and_then(|stage| stage.commit.as_ref())
            .ok_or(ProviderError::Correlation(
                "packet original consumed input absent",
            ))?;
        Ok((&commit.record, &commit.record_ref))
    }

    /// Installs the complete finite source definition and one genuine owned socket.
    ///
    /// # Errors
    /// Refuses unsupported schemas, duplicate/foreign routes or unavailable credit.
    pub fn new(
        definition: PacketConnectedDefinition,
        effect_socket: UnixDatagram,
    ) -> Result<Self, ProviderError> {
        validate_connected_program_definition(&definition)?;
        Ok(Self {
            definition,
            native_pid: std::process::id(),
            effect_socket,
            reached: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
            gate_closed: true,
            reactions: Vec::with_capacity(MAXIMUM_EVENTS),
            delivered_inputs: Vec::with_capacity(MAXIMUM_EVENTS),
            publications: Vec::with_capacity(MAXIMUM_EVENTS),
            outputs: Vec::with_capacity(MAXIMUM_EVENTS),
            stages: Vec::with_capacity(MAXIMUM_BATCHES),
            grants: BTreeMap::new(),
            retired: BTreeMap::new(),
            reactions_completed: 0,
            packet_effects: 0,
            failed: false,
        })
    }

    /// Borrows the complete immutable original source program definition.
    pub fn definition(&self) -> &PacketConnectedDefinition {
        &self.definition
    }

    fn current(&self) -> Result<(), ProviderError> {
        if self.native_pid != std::process::id() || self.failed {
            return Err(ProviderError::Correlation(
                "packet original native owner unavailable",
            ));
        }
        Ok(())
    }

    /// Opens the actual initial gate under a separately authenticated world barrier.
    ///
    /// This setter grants no common activation or class qualification.
    ///
    /// # Errors
    /// Refuses foreign-process, failed, already open or used original state.
    pub fn open_gate(&mut self) -> Result<(), ProviderError> {
        self.current()?;
        if !self.gate_closed || !self.stages.is_empty() || !self.grants.is_empty() {
            return Err(ProviderError::Conflict("packet connected initial gate"));
        }
        self.gate_closed = false;
        Ok(())
    }

    /// Reads complete original native custody without executing a step.
    ///
    /// # Errors
    /// Refuses foreign-process or failed original ownership and oversized inventory.
    pub fn inventory(&self) -> Result<PacketConnectedInventory, ProviderError> {
        self.current()?;
        let inventory = PacketConnectedInventory {
            reached: self.reached,
            gate_closed: self.gate_closed,
            reactions: self.reactions.clone(),
            delivered_inputs: self.delivered_inputs.clone(),
            publications: self.publications.clone(),
            retained_outputs: self.outputs.clone(),
            reactions_completed: U64::new(self.reactions_completed),
            packet_effects: U64::new(self.packet_effects),
            stages: self
                .stages
                .iter()
                .map(|stage| stage.record_ref.clone())
                .collect(),
            commits: self
                .stages
                .iter()
                .filter_map(|stage| {
                    stage
                        .commit
                        .as_ref()
                        .map(|commit| commit.record_ref.clone())
                })
                .collect(),
        };
        crate::connection::serialized_credit(&inventory, MAXIMUM_RECORD)?;
        Ok(inventory)
    }
}

fn validate_connected_program_definition(
    definition: &PacketConnectedDefinition,
) -> Result<(), ProviderError> {
    crate::connection::serialized_credit(definition, MAXIMUM_RECORD)?;
    if definition.schema != "source-owned.packet-connected-program/4"
        || definition.connections.is_empty()
        || definition.connections.len() > 4
    {
        return Err(ProviderError::Correlation(
            "packet connected source definition",
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    let node = &definition.connections[0].consumer.node_id;
    for route in &definition.connections {
        route.policy.validate()?;
        if !ids.insert(&route.id)
            || &route.consumer.node_id != node
            || route.producer == route.consumer
            || route.delay_ps.get() > 1024
        {
            return Err(ProviderError::Correlation(
                "packet connected complete routes",
            ));
        }
    }
    if definition
        .output
        .as_ref()
        .is_some_and(|output| &output.node_id != node)
    {
        return Err(ProviderError::Correlation("packet connected output owner"));
    }
    Ok(())
}

mod restore_fresh;

pub(crate) mod fresh_inventory;

mod stopped_inventory;

#[path = "connected/capture_inventory.rs"]
mod capture_inventory;

impl PacketConnectedProgram {
    /// Reads the same process's physical birth gate without building inventory.
    ///
    /// # Errors
    /// Refuses a native owner inherited by another process. Failed models never
    /// appear as unopened birth owners even when their gate remains closed.
    pub(super) fn original_native_birth_gate_closed_data(&self) -> Result<bool, ProviderError> {
        if self.native_pid != std::process::id() {
            return Err(ProviderError::Correlation("native birth model creator"));
        }
        Ok(self.gate_closed && !self.failed)
    }
}

impl PacketConnectedProgram {
    /// Checks the unchanged original model before the first selected report.
    ///
    /// This allocation-free census grants no Source, input or execution right.
    /// Reserved empty banks remain owned and independently counted in baseline R.
    ///
    /// # Errors
    /// Refuses a foreign, failed, closed, advanced, staged or otherwise used model.
    pub(crate) fn authenticate_original_initial_observation_data(
        &self,
    ) -> Result<(), ProviderError> {
        let Self {
            definition: _,
            native_pid,
            effect_socket: _,
            reached,
            gate_closed,
            reactions,
            delivered_inputs,
            publications,
            outputs,
            stages,
            grants,
            retired,
            reactions_completed,
            packet_effects,
            failed,
        } = self;
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        if *native_pid != std::process::id()
            || *failed
            || *gate_closed
            || *reached != zero
            || !reactions.is_empty()
            || !delivered_inputs.is_empty()
            || !publications.is_empty()
            || !outputs.is_empty()
            || !stages.is_empty()
            || !grants.is_empty()
            || !retired.is_empty()
            || *reactions_completed != 0
            || *packet_effects != 0
        {
            return Err(ProviderError::Correlation(
                "original initial reactive observation state",
            ));
        }
        Ok(())
    }
}

impl PacketConnectedProgram {
    /// Names the exact borrowed field views of the initial-state census.
    pub(crate) const fn original_initial_observation_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&u32>()
            + std::mem::size_of::<&Position>()
            + 2 * std::mem::size_of::<&bool>()
            + std::mem::size_of::<&Vec<PacketReaction>>()
            + std::mem::size_of::<&Vec<PacketDeliveredInput>>()
            + std::mem::size_of::<&Vec<PacketPendingPublication>>()
            + std::mem::size_of::<&Vec<PacketConnectedPublication>>()
            + std::mem::size_of::<&Vec<OriginalStage>>()
            + std::mem::size_of::<&BTreeMap<Id, PacketConnectedGrant>>()
            + std::mem::size_of::<&BTreeMap<Id, Vec<Id>>>()
            + 2 * std::mem::size_of::<&u64>()
            + std::mem::size_of::<Position>()
            + std::mem::size_of::<U64>()
            + std::mem::size_of::<Phase>()
            + std::mem::size_of::<Result<(), ProviderError>>()
            + std::mem::size_of::<bool>()
    }
}

#[cfg(test)]
mod initial_observation_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn model() -> Result<PacketConnectedProgram, ProviderError> {
        let endpoint = |node| -> Result<Endpoint, ProviderError> {
            Ok(Endpoint {
                node_id: Id::new(node)?,
                port_id: Id::new("port")?,
                lane_id: Id::new("lane")?,
            })
        };
        let (socket, _peer) = UnixDatagram::pair()?;
        PacketConnectedProgram::new(
            PacketConnectedDefinition {
                schema: "source-owned.packet-connected-program/4".into(),
                connections: vec![PacketInputConnection {
                    id: Id::new("actual-route")?,
                    policy: canonical::content_ref(b"original-policy", "application/octet-stream")?,
                    producer: endpoint("producer")?,
                    consumer: endpoint("consumer")?,
                    delay_ps: U64::new(1),
                }],
                output: None,
            },
            socket,
        )
    }

    #[test]
    fn actual_reactive_initial_owner_keeps_all_reserved_banks_and_rejects_used_state() -> TestResult
    {
        let mut value = model()?;
        assert!(
            value
                .authenticate_original_initial_observation_data()
                .is_err()
        );
        value.open_gate()?;
        let capacities = (
            value.reactions.capacity(),
            value.delivered_inputs.capacity(),
            value.publications.capacity(),
            value.outputs.capacity(),
            value.stages.capacity(),
        );
        value.authenticate_original_initial_observation_data()?;

        assert_eq!(
            capacities,
            (
                value.reactions.capacity(),
                value.delivered_inputs.capacity(),
                value.publications.capacity(),
                value.outputs.capacity(),
                value.stages.capacity()
            )
        );
        for changed in 0..5 {
            let mut used = model()?;
            used.open_gate()?;
            match changed {
                0 => used.reached = Position::new(U64::new(1), U64::new(0), Phase::BoundaryControl),
                1 => used.reactions_completed = 1,
                2 => used.packet_effects = 1,
                3 => used.failed = true,
                _ => used.native_pid = 0,
            }
            assert!(
                used.authenticate_original_initial_observation_data()
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn independently_owned_input_reaction_is_not_initial_even_at_zero_cursor() -> TestResult {
        let mut value = model()?;
        value.open_gate()?;
        value.authenticate_original_initial_observation_data()?;
        value.reactions.push(PacketReaction {
            input_event: Id::new("actual-input")?,
            input_producer: Id::new("producer")?,
            input_sequence: U64::new(0),
            stage_operation: Id::new("stage")?,
            commit_request: Id::new("commit")?,
            payload: Bytes::new(b"retained-input".to_vec()),
            parent: Position::new(U64::new(0), U64::new(0), Phase::Delivery),
            evaluation: Position::new(U64::new(0), U64::new(0), Phase::Reaction),
        });
        let pointer = value.reactions.as_ptr();
        let capacity = value.reactions.capacity();

        assert!(
            value
                .authenticate_original_initial_observation_data()
                .is_err()
        );
        assert_eq!(value.reactions.as_ptr(), pointer);
        assert_eq!(value.reactions.capacity(), capacity);
        assert_eq!(value.reactions[0].payload.as_slice(), b"retained-input");
        Ok(())
    }
}

pub(crate) use capture_inventory::observation17::{
    observation17_inventory_counter_scratch_data,
    original_observation17_inventory_formatter_storage_data,
    project_original_observation17_inventory_data,
};
