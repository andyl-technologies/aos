//! Retains concrete model fields and pending typed children through every error.
//!
//! Attempt headers are inline in the caller's once owner. Child preflight funds
//! only the backing each real child builder allocates; no source-row credit is
//! treated as storage for these headers. Completed fields move only after the
//! final grammar check, and semantic checks run while the output remains owned.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};

use crate::reference_packet::continuation_models::settled_reader::retained::atomic_model_leaf;
atomic_model_leaf!(EventStage);

/// Owns the actual nullable child's pending state and its transparent output.
pub(crate) struct Nullable17ReadAttempt<T: Native17Build> {
    started: bool,
    completed: Option<Nullable<T>>,
    child: <Option<T> as Native17Build>::Attempt,
}

impl<T: Native17Build> Default for Nullable17ReadAttempt<T> {
    fn default() -> Self {
        Self {
            started: false,
            completed: None,
            child: Default::default(),
        }
    }
}

impl<T: Native17Build> Native17Build for Nullable<T> {
    type Attempt = Nullable17ReadAttempt<T>;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 nullable already attempted",
            ));
        }
        attempt.started = true;
        <Option<T> as Native17Build>::read_into_data(input, ledger, &mut attempt.child)?;
        attempt.completed = Some(Self(
            <Option<T> as Native17Build>::take_output_data(&mut attempt.child)
                .ok_or_else(invalid)?,
        ));
        Ok(())
    }
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        <Option<T> as Native17Build>::preflight_data(input, ledger)
    }
    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed.as_ref()
    }
    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.completed.take()
    }
    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &attempt.completed {
            <Option<T> as Native17Build>::observe_output_data(&value.0, observer)?;
        }
        <Option<T> as Native17Build>::observe_attempt_data(&attempt.child, observer)
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        <Option<T> as Native17Build>::observe_output_data(&value.0, observer)
    }
}

// Companions follow the exact existing object-field grammars above.
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(Endpoint {
    node_id: Id,
    port_id: Id,
    lane_id: Id,
});

native17_struct!(CommittedDeliveryV1 {
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

native17_struct!(PacketInputCut {
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

native17_struct!(InputResult {
    accepted_event_ids: IdSet,
    input_watermark: U64,
    custody_receipt: ContentRef,
    inventory_hash: HashRef,
});

native17_struct!(PacketInputConnection {
    id: Id,
    policy: ContentRef,
    producer: Endpoint,
    consumer: Endpoint,
    delay_ps: U64,
});

native17_struct!(PacketConnectedDefinition {
    schema: String,
    connections: Vec<PacketInputConnection>,
    output: Option<Endpoint>,
});

native17_struct!(PacketReaction {
    input_event: Id,
    input_producer: Id,
    input_sequence: U64,
    stage_operation: Id,
    commit_request: Id,
    payload: Bytes,
    parent: Position,
    evaluation: Position,
});

native17_struct!(PacketDeliveredInput {
    reaction: PacketReaction,
    delivery_operation: Id,
});

native17_struct!(PacketPendingPublication {
    event: Id,
    reaction: PacketReaction,
    reaction_operation: Id,
    publication: Position,
});

native17_struct!(PacketConnectedPublication {
    output: PacketPublication,
    pending: PacketPendingPublication,
});

native17_struct!(PacketConnectedInventory {
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

native17_struct!(PacketConnectedGrant {
    operation: Id,
    start: Position,
    limit: Position,
    inventory: PacketConnectedInventory,
    newborn: Vec<PacketConnectedPublication>,
    complete: bool,
});

native17_struct!(PacketStageRecord {
    schema: String,
    native_pid: U64,
    original: Envelope,
    cut: PacketInputCut,
    batch: InputBatch,
    deliveries: Vec<crate::input_commit::CommittedDeliveryV1>,
    payloads: Vec<Bytes>,
    inventory: PacketConnectedInventory,
});

native17_struct!(PacketCommitRecord {
    schema: String,
    native_pid: U64,
    original: Envelope,
    staged_record: ContentRef,
    staging_receipt: ContentRef,
    cut: PacketInputCut,
    reactions: Vec<PacketReaction>,
    reached: Position,
});

native17_struct!(PacketInputReply {
    result: InputResult,
    evidence: Vec<(ContentRef, Vec<u8>)>,
});

native17_struct!(Event {
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

native17_struct!(InputBatch {
    schema_version: Version,
    execution_owner_id: Id,
    input_epoch: Id,
    batch_id: Id,
    batch_sequence: U64,
    events: Vec<Event>,
    extensions: Extensions,
});

native17_struct!(PacketEvent {
    id: Id,
    evaluation: Position,
    completion: Position,
    payload: Option<Bytes>,
});

native17_struct!(PacketInventory {
    reached: Position,
    gate_closed: bool,
    pending: Vec<PacketEvent>,
    retained_outputs: Vec<PacketPublication>,
    private_mutations: U64,
    packet_effects: U64,
});

native17_struct!(PacketPublication {
    event: Id,
    operation: Id,
    sequence: U64,
    evaluation: Position,
    publication: Position,
    payload: Bytes,
});

native17_struct!(PacketGrant {
    operation: Id,
    start: Position,
    limit: Position,
    inventory: PacketInventory,
    newborn: Vec<PacketPublication>,
    complete: bool,
});
