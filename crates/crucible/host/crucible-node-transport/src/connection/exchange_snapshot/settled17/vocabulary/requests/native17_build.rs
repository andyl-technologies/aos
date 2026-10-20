//! Reconstructs each native17 field into a retained concrete owner.

use super::*;
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(AdmitRequest {
    bindings: Vec<NodeBinding>,
    world_binding_hash: HashRef,
    admission_receipt: ContentRef,
    extensions: Extensions,
});

native17_struct!(InputRequest {
    binding_hash: HashRef,
    owner_generation: U64,
    batch_id: Id,
    batch_sequence: U64,
    input_epoch: Id,
    events: Vec<Event>,
    batch_hash: HashRef,
    extensions: Extensions,
});

native17_struct!(ObserveRequest {
    binding_hash: HashRef,
    owner_generation: U64,
    after_observation_sequence: U64,
    maximum_items: U64,
    extensions: Extensions,
});

native17_struct!(PollRequest {
    after_observation_sequence: U64,
    extensions: Extensions,
});

native17_struct!(CancelRequest {
    reason: Id,
    extensions: Extensions,
});

native17_struct!(QuantumCloseRequest {
    grant_id: Id,
    activation_id: Id,
    world_generation: U64,
    owner_generation: U64,
    input_epoch: Id,
    quantum_index: U64,
    participant_ids: IdSet,
    cut: Position,
    policy_hash: HashRef,
    observation_batch_hash: HashRef,
    input_watermark: U64,
    deadline_disposition: BudgetOutcome,
    extensions: Extensions,
});

native17_struct!(AbortRequest {
    transaction_id: Id,
    reason: Id,
    extensions: Extensions,
});

native17_struct!(RetireRequest {
    request_ids: IdSet,
    operation_ids: IdSet,
    disposition: RetirementDisposition,
    custody_receipt: Nullable<ContentRef>,
    extensions: Extensions,
});

native17_struct!(BlobBeginRequest {
    transfer_id: Id,
    content: ContentRef,
    extensions: Extensions,
});

native17_struct!(BlobChunkRequest {
    transfer_id: Id,
    offset: U64,
    bytes: Bytes,
    extensions: Extensions,
});

native17_struct!(BlobFinishRequest {
    transfer_id: Id,
    extensions: Extensions,
});

native17_struct!(ReleaseRequest {
    realization_id: Id,
    extensions: Extensions,
});

native17_struct!(DiscoverRequest {
    profile_ids: IdSet,
    cursor: Option<Id> => omitted,
    extensions: Extensions,
});
