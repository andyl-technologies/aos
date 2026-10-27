//! Completes actual baseline decoder partials for the closed runtime body graph.
//!
//! The existing defining macro binds every field to its real type. The method
//! and Begin rosters require each concrete root companion; adding an outgoing
//! alternative therefore cannot silently bypass these decoder controls. Typed
//! Vec backing remains governed by the independent sealed VectorElement graph.

use super::*;
use crate::bodies::RuntimeBodyDecoderCompanion;
use crate::bodies::*;
use crucible_node_format::*;
use serde_partials::DecoderPartial;

serde_partials::decoder_struct!(NotificationBody {
    operation_state,
    last_observation_sequence,
    details,
    extensions,
});

serde_partials::decoder_struct!(BeginAccepted { operation_id, kind });

serde_partials::decoder_struct!(BlobBeginRequest {
    transfer_id,
    content,
    extensions,
});

serde_partials::decoder_struct!(BlobBeginResult {
    transfer_id,
    next_offset,
    maximum_chunk_bytes,
});

serde_partials::decoder_struct!(BlobChunkRequest {
    transfer_id,
    offset,
    bytes,
    extensions,
});

serde_partials::decoder_struct!(BlobChunkResult {
    transfer_id,
    next_offset,
});

serde_partials::decoder_struct!(BlobFinishRequest {
    transfer_id,
    extensions,
});

serde_partials::decoder_struct!(BlobFinishResult {
    transfer_id,
    content,
});

serde_partials::decoder_struct!(Event {
    schema_version,
    id,
    source,
    destination,
    position,
    stage,
    publication_position,
    delivery_position,
    source_sequence,
    causal_parent_ids,
    payload,
    provenance_ref,
    extensions,
});

serde_partials::decoder_struct!(InputRequest {
    binding_hash,
    owner_generation,
    batch_id,
    batch_sequence,
    input_epoch,
    events,
    batch_hash,
    extensions,
});

serde_partials::decoder_struct!(InputResult {
    accepted_event_ids,
    input_watermark,
    custody_receipt,
    inventory_hash,
});

serde_partials::decoder_struct!(ObservationBatch {
    schema_version,
    execution_owner_id,
    owner_binding_hash,
    world_binding_hash,
    activation_id,
    world_generation,
    owner_generation,
    operation_id,
    grant_id,
    first_sequence,
    last_sequence,
    events,
    visibility,
    measurement_ref,
    extensions,
});

serde_partials::decoder_struct!(ObserveRequest {
    binding_hash,
    owner_generation,
    after_observation_sequence,
    maximum_items,
    extensions,
});

serde_partials::decoder_struct!(ObserveResult {
    observations,
    next_sequence,
    complete,
    inventory_hash,
});

serde_partials::decoder_struct!(PollRequest {
    after_observation_sequence,
    extensions,
});

serde_partials::decoder_struct!(PollResult {
    operation_id,
    operation_state,
    outcome,
    observations,
    next_observation_sequence,
});

serde_partials::decoder_struct!(RetireRequest {
    request_ids,
    operation_ids,
    disposition,
    custody_receipt,
    extensions,
});

serde_partials::decoder_struct!(RetireResult {
    retired_request_ids,
    retired_operation_ids,
});

serde_partials::decoder_struct!(ExactRunResult {
    grant_id,
    reached,
    stop_reason,
    stop_receipt,
    observation_batch,
    pending_inventory,
    next_attention,
});

serde_partials::decoder_struct!(QuantumBeginResult {
    grant_id,
    quantum_index,
    stop_receipt,
    observation_batch,
    pending_inventory,
    budget_outcome,
    physical_measurement_ref,
});

serde_partials::decoder_struct!(PauseResult {
    stop_receipt,
    physical_paused,
    reached,
    pending_inventory,
});

serde_partials::decoder_struct!(CaptureResult {
    capture_manifest,
    owner_state_refs,
    unchanged_cut_receipt,
});

serde_partials::decoder_struct!(PrepareRestoreResult {
    transaction_id,
    prepared_token,
    world_binding_hash,
    owner_binding_hash,
    staged_owner_ids,
    closed_gate_receipt,
    validated_manifest,
});

serde_partials::decoder_struct!(ShutdownResult {
    observation_batch,
    pending_inventory,
    stopped,
    reaped,
    cleanup_receipt,
});

serde_partials::decoder_struct!(Bound {
    kind,
    position,
    evidence,
});

macro_rules! companions {
    ($($type:ty),+ $(,)?) => {$(
        impl RuntimeBodyDecoderCompanion for $type {
            const DECODER_DIAGNOSTIC_NAMES_BYTES: usize = <Self as DecoderPartial>::DIAGNOSTIC_NAMES_BYTES;

            fn decoder_counter_scratch_data() -> usize {
                <Self as DecoderPartial>::partial_counter_data()
            }
        }
    )+};
}

companions!(
    ErrorRecord,
    NotificationBody,
    BeginAccepted,
    BeginRequest,
    BlobBeginRequest,
    BlobBeginResult,
    BlobChunkRequest,
    BlobChunkResult,
    BlobFinishRequest,
    BlobFinishResult,
    CaptureArguments,
    ContentRef,
    Endpoint,
    Event,
    ExactRunArguments,
    HashRef,
    InputRequest,
    InputResult,
    ObservationBatch,
    ObserveRequest,
    ObserveResult,
    PauseArguments,
    PollRequest,
    PollResult,
    Position,
    PrepareRestoreArguments,
    QuantumBeginArguments,
    RetireRequest,
    RetireResult,
    ShutdownArguments,
    ExactRunResult,
    QuantumBeginResult,
    PauseResult,
    CaptureResult,
    PrepareRestoreResult,
    ShutdownResult,
    Bound,
);

/// Names public-root and map-wrapper Fields views for each real record type.
///
/// The defining recursive field partials already own completed field slots.
/// This adds separate complete public/Fields/result views for the one active
/// occurrence of each distinct record along an acyclic typed decode path.
/// Literal JSON recursion has its own independent 65-frame control population.
pub(super) fn record_wrapper_controls_data() -> usize {
    macro_rules! controls {
        ($($type:ty),+ $(,)?) => {0 $(+ 2 * size_of::<$type>()
            + 2 * size_of::<Result<$type, serde_json::Error>>())+};
    }
    controls!(
        ErrorRecord,
        NotificationBody,
        BeginAccepted,
        BeginRequest,
        BlobBeginRequest,
        BlobBeginResult,
        BlobChunkRequest,
        BlobChunkResult,
        BlobFinishRequest,
        BlobFinishResult,
        CaptureArguments,
        ContentRef,
        Endpoint,
        Event,
        ExactRunArguments,
        HashRef,
        InputRequest,
        InputResult,
        ObservationBatch,
        ObserveRequest,
        ObserveResult,
        PauseArguments,
        PollRequest,
        PollResult,
        Position,
        PrepareRestoreArguments,
        QuantumBeginArguments,
        RetireRequest,
        RetireResult,
        ShutdownArguments,
        ExactRunResult,
        QuantumBeginResult,
        PauseResult,
        CaptureResult,
        PrepareRestoreResult,
        ShutdownResult,
        Bound,
    )
}

macro_rules! unit_partial {
    ($type:ident { $($variant:ident),+ $(,)? }) => {
        impl DecoderPartial for $type {
            const DIAGNOSTIC_NAMES_BYTES: usize = stringify!($type).len()
                $(+ 2 * stringify!($variant).len() + 8)+;

            fn partial_counter_data() -> usize {
                size_of::<Self>() + size_of::<Result<Self, serde_json::Error>>()
            }
        }
    };
}

unit_partial!(BoundKind {
    At,
    After,
    NoneUntilActivation,
    Unknown
});
unit_partial!(BudgetOutcome {
    WithinBudget,
    Stall,
    Timeout,
    Fail
});
unit_partial!(StopReason {
    Ceiling,
    Attention,
    InputRequired,
    Output,
    Idle,
    Canceled,
    Failed
});
unit_partial!(EventStage {
    Publication,
    Delivery
});
unit_partial!(RetirementDisposition {
    Consumed,
    AbandonedInertTransfer
});
unit_partial!(Visibility { Staged, Committed });

const _: fn(&BoundaryPolicy) = |value| match value {
    BoundaryPolicy::OrdinaryStop => {}
    BoundaryPolicy::InputBlockedPark => {}
};

const _: fn(&BoundKind) = |value| match value {
    BoundKind::At => {}
    BoundKind::After => {}
    BoundKind::NoneUntilActivation => {}
    BoundKind::Unknown => {}
};

const _: fn(&BudgetOutcome) = |value| match value {
    BudgetOutcome::WithinBudget => {}
    BudgetOutcome::Stall => {}
    BudgetOutcome::Timeout => {}
    BudgetOutcome::Fail => {}
};

const _: fn(&StopReason) = |value| match value {
    StopReason::Ceiling => {}
    StopReason::Attention => {}
    StopReason::InputRequired => {}
    StopReason::Output => {}
    StopReason::Idle => {}
    StopReason::Canceled => {}
    StopReason::Failed => {}
};

const _: fn(&EventStage) = |value| match value {
    EventStage::Publication => {}
    EventStage::Delivery => {}
};

const _: fn(&OperatingMode) = |value| match value {
    OperatingMode::Exact => {}
    OperatingMode::Quantized => {}
};

const _: fn(&OperationState) = |value| match value {
    OperationState::NotStarted => {}
    OperationState::Running => {}
    OperationState::Completed => {}
    OperationState::Unknown => {}
};

const _: fn(&EffectCertainty) = |value| match value {
    EffectCertainty::NotStarted => {}
    EffectCertainty::InProgress => {}
    EffectCertainty::Completed => {}
    EffectCertainty::Unknown => {}
};

const _: fn(&Phase) = |value| match value {
    Phase::BoundaryControl => {}
    Phase::Publication => {}
    Phase::Delivery => {}
    Phase::Reaction => {}
};

const _: fn(&RetirementDisposition) = |value| match value {
    RetirementDisposition::Consumed => {}
    RetirementDisposition::AbandonedInertTransfer => {}
};

const _: fn(&Visibility) = |value| match value {
    Visibility::Staged => {}
    Visibility::Committed => {}
};
