//! Reconstructs each native17 field into a retained concrete owner.

use super::*;
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(DiscoverResult {
    provider_manifest: ProviderManifest,
    profiles: Vec<NodeManifest>,
    facet_schemas: Vec<SchemaRef>,
    complete: bool,
    next_cursor: Nullable<Id>,
});

native17_struct!(RealizeResult {
    realization_manifest: RealizationManifest,
    prepared_token: Id,
    closed_gate_receipt: ContentRef,
});

native17_struct!(AdmitResult {
    accepted_binding_hashes: Vec<HashRef>,
    admission_id: Id,
});

native17_struct!(ActivateResult {
    staged: bool,
    gate_id: Id,
    staged_owner_ids: IdSet,
    activation_receipt: ContentRef,
});

native17_struct!(ObserveResult {
    observations: Vec<ObservationBatch>,
    next_sequence: U64,
    complete: bool,
    inventory_hash: HashRef,
});

native17_struct!(BeginAccepted {
    operation_id: Id,
    kind: BeginKind,
});

native17_struct!(PollResult {
    operation_id: Id,
    operation_state: OperationState,
    outcome: Nullable<Map<String, Value>>,
    observations: Vec<ObservationBatch>,
    next_observation_sequence: U64,
});

native17_struct!(CancelResult {
    cancel_requested: bool,
    operation_state: OperationState,
});

native17_struct!(QuantumCloseResult {
    grant_id: Id,
    quantum_index: U64,
    cut: Position,
    policy_hash: HashRef,
    activation_id: Id,
    world_generation: U64,
    owner_generation: U64,
    input_epoch: Id,
    stop_receipt: ContentRef,
    committed_batch: ContentRef,
    pending_inventory: ContentRef,
    next_allowed_quantum: Nullable<U64>,
});

native17_struct!(WorldActivateResult {
    armed_owner_ids: IdSet,
    gate_id: Id,
    activation_receipt: ContentRef,
});

native17_struct!(AbortResult {
    transaction_id: Id,
    owner_ids: IdSet,
    cleanup_receipt: ContentRef,
    effect: EffectCertainty,
});

native17_struct!(RetireResult {
    retired_request_ids: IdSet,
    retired_operation_ids: IdSet,
});

native17_struct!(BlobBeginResult {
    transfer_id: Id,
    next_offset: U64,
    maximum_chunk_bytes: U64,
});

native17_struct!(BlobChunkResult {
    transfer_id: Id,
    next_offset: U64,
});

native17_struct!(BlobFinishResult {
    transfer_id: Id,
    content: ContentRef,
});

native17_struct!(ReleaseResult {
    realization_id: Id,
    owner_ids: IdSet,
    cleanup_receipt: ContentRef,
    released: bool,
});

native17_struct!(ExactRunResult {
    grant_id: Id,
    reached: Position,
    stop_reason: StopReason,
    stop_receipt: ContentRef,
    observation_batch: ContentRef,
    pending_inventory: ContentRef,
    next_attention: Bound,
});

native17_struct!(QuantumBeginResult {
    grant_id: Id,
    quantum_index: U64,
    stop_receipt: ContentRef,
    observation_batch: ContentRef,
    pending_inventory: ContentRef,
    budget_outcome: BudgetOutcome,
    physical_measurement_ref: ContentRef,
});

native17_struct!(PauseResult {
    stop_receipt: ContentRef,
    physical_paused: bool,
    reached: Nullable<Position>,
    pending_inventory: ContentRef,
});

native17_struct!(CaptureResult {
    capture_manifest: ContentRef,
    owner_state_refs: Vec<ContentRef>,
    unchanged_cut_receipt: ContentRef,
});

native17_struct!(PrepareRestoreResult {
    transaction_id: Id,
    prepared_token: Id,
    world_binding_hash: HashRef,
    owner_binding_hash: HashRef,
    staged_owner_ids: IdSet,
    closed_gate_receipt: ContentRef,
    validated_manifest: ContentRef,
});

native17_struct!(ShutdownResult {
    observation_batch: ContentRef,
    pending_inventory: ContentRef,
    stopped: bool,
    reaped: bool,
    cleanup_receipt: ContentRef,
});
