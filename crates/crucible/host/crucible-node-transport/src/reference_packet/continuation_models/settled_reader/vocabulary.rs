//! Reads the defining portable model DTO vocabulary with the existing typed ledger.

use super::*;
use crate::bodies::InputResult;
use crate::envelope::{Envelope, Nullable};
use crate::input_commit::CommittedDeliveryV1;
use crate::protocol_snapshot::owned11::typed::{historical_struct, plain_string};
use crate::reference_packet::connected::*;
use crate::reference_packet::input::PacketInputCut;
use crucible_node_format::*;

historical_struct!(Endpoint {
    node_id: Id,
    port_id: Id,
    lane_id: Id,
});

historical_struct!(CommittedDeliveryV1 {
    connection_id: Nullable<Id>,
    connection_policy_ref: Nullable<ContentRef>,
    external_root: Nullable<Endpoint>,
    provenance_ref: ContentRef,
    publication_id: Id,
    producer: Id,
    consumer: Id,
    producer_endpoint: Endpoint,
    consumer_endpoint: Endpoint,
    source_sequence: U64,
    native_sequence: U64,
    evaluation: Nullable<Position>,
    causal_parents: Vec<Position>,
    publication: Position,
    delivery: Position,
    payload: ContentRef,
});

historical_struct!(PacketInputCut {
    schema_version: u16,
    session_id: Id,
    incarnation_id: Id,
    node_id: Id,
    execution_owner_id: Id,
    owner_generation: U64,
    activation_id: Id,
    world_generation: U64,
    world_binding_hash: HashRef,
    stage_operation_id: Id,
    batch_id: Id,
    batch_sequence: U64,
    input_epoch: Id,
    batch_hash: HashRef,
    delivery_inventory: ContentRef,
    cutoff: Position,
});

historical_struct!(InputResult {
    accepted_event_ids: IdSet,
    input_watermark: U64,
    custody_receipt: ContentRef,
    inventory_hash: HashRef,
});

historical_struct!(PacketInputConnection {
    id: Id,
    policy: ContentRef,
    producer: Endpoint,
    consumer: Endpoint,
    delay_ps: U64,
});

historical_struct!(PacketConnectedDefinition {
    schema: String,
    connections: Vec<PacketInputConnection>,
    output: Option<Endpoint>,
});

historical_struct!(PacketReaction {
    input_event: Id,
    input_producer: Id,
    input_sequence: U64,
    stage_operation: Id,
    commit_request: Id,
    payload: Bytes,
    parent: Position,
    evaluation: Position,
});

historical_struct!(PacketDeliveredInput {
    reaction: PacketReaction,
    delivery_operation: Id,
});

historical_struct!(PacketPendingPublication {
    event: Id,
    reaction: PacketReaction,
    reaction_operation: Id,
    publication: Position,
});

historical_struct!(PacketConnectedPublication {
    output: PacketPublication,
    pending: PacketPendingPublication,
});

historical_struct!(PacketConnectedInventory {
    reached: Position,
    gate_closed: bool,
    reactions: Vec<PacketReaction>,
    delivered_inputs: Vec<PacketDeliveredInput>,
    publications: Vec<PacketPendingPublication>,
    retained_outputs: Vec<PacketConnectedPublication>,
    reactions_completed: U64,
    packet_effects: U64,
    stages: Vec<ContentRef>,
    commits: Vec<ContentRef>,
});

historical_struct!(PacketConnectedGrant {
    operation: Id,
    start: Position,
    limit: Position,
    inventory: PacketConnectedInventory,
    newborn: Vec<PacketConnectedPublication>,
    complete: bool,
});

historical_struct!(PacketStageRecord {
    schema: String,
    native_pid: U64,
    original: Envelope,
    cut: PacketInputCut,
    batch: InputBatch,
    deliveries: Vec<crate::input_commit::CommittedDeliveryV1>,
    payloads: Vec<Bytes>,
    inventory: PacketConnectedInventory,
});

historical_struct!(PacketCommitRecord {
    schema: String,
    native_pid: U64,
    original: Envelope,
    staged_record: ContentRef,
    staging_receipt: ContentRef,
    cut: PacketInputCut,
    reactions: Vec<PacketReaction>,
    reached: Position,
});

historical_struct!(PacketInputReply {
    result: InputResult,
    evidence: Vec<(ContentRef, Vec<u8>)>,
});

historical_struct!(Event {
    schema_version: Version,
    id: Id,
    source: Endpoint,
    destination: Endpoint,
    position: Position,
    stage: EventStage,
    publication_position: Position,
    delivery_position: Option<Position>,
    source_sequence: U64,
    causal_parent_ids: IdSet,
    payload: ContentRef,
    provenance_ref: ContentRef,
    extensions: Extensions,
});

historical_struct!(InputBatch {
    schema_version: Version,
    execution_owner_id: Id,
    input_epoch: Id,
    batch_id: Id,
    batch_sequence: U64,
    events: Vec<Event>,
    extensions: Extensions,
});

historical_struct!(PacketEvent {
    id: Id,
    evaluation: Position,
    completion: Position,
    payload: Option<Bytes>,
});

historical_struct!(PacketInventory {
    reached: Position,
    gate_closed: bool,
    pending: Vec<PacketEvent>,
    retained_outputs: Vec<PacketPublication>,
    private_mutations: U64,
    packet_effects: U64,
});

historical_struct!(PacketPublication {
    event: Id,
    operation: Id,
    sequence: U64,
    evaluation: Position,
    publication: Position,
    payload: Bytes,
});

historical_struct!(PacketGrant {
    operation: Id,
    start: Position,
    limit: Position,
    inventory: PacketInventory,
    newborn: Vec<PacketPublication>,
    complete: bool,
});

impl<T: HistoricalType> HistoricalType for Nullable<T> {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Ok(ledger.read::<Option<T>>(input, build)?.map(Self))
    }
}

impl<A: HistoricalType, B: HistoricalType> HistoricalType for (A, B) {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let a = ledger.read::<A>(fields.next()?.ok_or_else(invalid)?, build)?;
        let b = ledger.read::<B>(fields.next()?.ok_or_else(invalid)?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some((a.ok_or_else(invalid)?, b.ok_or_else(invalid)?)))
    }
}

impl HistoricalType for EventStage {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let stage = match plain_string(input)? {
            "publication" => Self::Publication,
            "delivery" => Self::Delivery,
            _ => return Err(invalid()),
        };
        Ok(build.then_some(stage))
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<Fields<'static>>()
        + size_of::<[&str; 3]>()
        + size_of::<(Option<Id>, Option<Id>, Option<Id>)>()
        + size_of::<Option<Nullable<Id>>>()
        + size_of::<Result<Option<Nullable<Id>>, ProviderError>>()
        + size_of::<Option<Nullable<ContentRef>>>()
        + size_of::<Result<Option<Nullable<ContentRef>>, ProviderError>>()
        + size_of::<Option<Nullable<Endpoint>>>()
        + size_of::<Result<Option<Nullable<Endpoint>>, ProviderError>>()
        + size_of::<Option<ContentRef>>()
        + size_of::<Result<Option<ContentRef>, ProviderError>>()
        + size_of::<Option<Id>>()
        + size_of::<Result<Option<Id>, ProviderError>>()
        + size_of::<Option<Endpoint>>()
        + size_of::<Result<Option<Endpoint>, ProviderError>>()
        + size_of::<Option<U64>>()
        + size_of::<Result<Option<U64>, ProviderError>>()
        + size_of::<Option<Nullable<Position>>>()
        + size_of::<Result<Option<Nullable<Position>>, ProviderError>>()
        + size_of::<Option<Vec<Position>>>()
        + size_of::<Result<Option<Vec<Position>>, ProviderError>>()
        + size_of::<Option<Position>>()
        + size_of::<Result<Option<Position>, ProviderError>>()
        + size_of::<Option<u16>>()
        + size_of::<Result<Option<u16>, ProviderError>>()
        + size_of::<Option<HashRef>>()
        + size_of::<Result<Option<HashRef>, ProviderError>>()
        + size_of::<Option<IdSet>>()
        + size_of::<Result<Option<IdSet>, ProviderError>>()
        + size_of::<Option<String>>()
        + size_of::<Result<Option<String>, ProviderError>>()
        + size_of::<Option<Vec<PacketInputConnection>>>()
        + size_of::<Result<Option<Vec<PacketInputConnection>>, ProviderError>>()
        + size_of::<Option<Option<Endpoint>>>()
        + size_of::<Result<Option<Option<Endpoint>>, ProviderError>>()
        + size_of::<Option<Bytes>>()
        + size_of::<Result<Option<Bytes>, ProviderError>>()
        + size_of::<Option<PacketReaction>>()
        + size_of::<Result<Option<PacketReaction>, ProviderError>>()
        + size_of::<Option<PacketPublication>>()
        + size_of::<Result<Option<PacketPublication>, ProviderError>>()
        + size_of::<Option<PacketPendingPublication>>()
        + size_of::<Result<Option<PacketPendingPublication>, ProviderError>>()
        + size_of::<Option<bool>>()
        + size_of::<Result<Option<bool>, ProviderError>>()
        + size_of::<Option<Vec<PacketReaction>>>()
        + size_of::<Result<Option<Vec<PacketReaction>>, ProviderError>>()
        + size_of::<Option<Vec<PacketDeliveredInput>>>()
        + size_of::<Result<Option<Vec<PacketDeliveredInput>>, ProviderError>>()
        + size_of::<Option<Vec<PacketPendingPublication>>>()
        + size_of::<Result<Option<Vec<PacketPendingPublication>>, ProviderError>>()
        + size_of::<Option<Vec<PacketConnectedPublication>>>()
        + size_of::<Result<Option<Vec<PacketConnectedPublication>>, ProviderError>>()
        + size_of::<Option<Vec<ContentRef>>>()
        + size_of::<Result<Option<Vec<ContentRef>>, ProviderError>>()
        + size_of::<Option<PacketConnectedInventory>>()
        + size_of::<Result<Option<PacketConnectedInventory>, ProviderError>>()
        + size_of::<Option<Envelope>>()
        + size_of::<Result<Option<Envelope>, ProviderError>>()
        + size_of::<Option<PacketInputCut>>()
        + size_of::<Result<Option<PacketInputCut>, ProviderError>>()
        + size_of::<Option<InputBatch>>()
        + size_of::<Result<Option<InputBatch>, ProviderError>>()
        + size_of::<Option<Vec<crate::input_commit::CommittedDeliveryV1>>>()
        + size_of::<Result<Option<Vec<crate::input_commit::CommittedDeliveryV1>>, ProviderError>>()
        + size_of::<Option<Vec<Bytes>>>()
        + size_of::<Result<Option<Vec<Bytes>>, ProviderError>>()
        + size_of::<Option<InputResult>>()
        + size_of::<Result<Option<InputResult>, ProviderError>>()
        + size_of::<Option<Vec<(ContentRef, Vec<u8>)>>>()
        + size_of::<Result<Option<Vec<(ContentRef, Vec<u8>)>>, ProviderError>>()
        + size_of::<Option<Version>>()
        + size_of::<Result<Option<Version>, ProviderError>>()
        + size_of::<Option<EventStage>>()
        + size_of::<Result<Option<EventStage>, ProviderError>>()
        + size_of::<Option<Option<Position>>>()
        + size_of::<Result<Option<Option<Position>>, ProviderError>>()
        + size_of::<Option<Extensions>>()
        + size_of::<Result<Option<Extensions>, ProviderError>>()
        + size_of::<Option<Vec<Event>>>()
        + size_of::<Result<Option<Vec<Event>>, ProviderError>>()
        + size_of::<Option<Option<Bytes>>>()
        + size_of::<Result<Option<Option<Bytes>>, ProviderError>>()
        + size_of::<Option<Vec<PacketEvent>>>()
        + size_of::<Result<Option<Vec<PacketEvent>>, ProviderError>>()
        + size_of::<Option<Vec<PacketPublication>>>()
        + size_of::<Result<Option<Vec<PacketPublication>>, ProviderError>>()
        + size_of::<Option<PacketInventory>>()
        + size_of::<Result<Option<PacketInventory>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

// The new17 owning path keeps typed children in the outer attempt on errors.
#[path = "vocabulary/retained.rs"]
pub(in crate::reference_packet) mod retained;
