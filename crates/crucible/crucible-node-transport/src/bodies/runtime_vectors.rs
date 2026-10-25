//! Bounds typed runtime vector backing through the actual closed field graph.
//!
//! The covered methods are Input, Observe, Begin, Poll, Retire and the three
//! Blob methods, including every Begin argument variant. Provider-origin
//! requests are separately restricted by Connection before typed decoding.
//! This component excludes literal JSON, strings, Bytes decoding, validation
//! sets, diagnostics, inline controls, caller roots and all transport owners.
//! It is one input to SDK funding, not a complete R/T/S row or Source right.

use super::*;
use std::{collections::BTreeMap, mem::size_of};

// serde_core 1.0.228 caps Vec<T>'s initial reservation at this many bytes.
// A rejected first element can leave that entire reservation live. The pinned
// borrowed Value iterator supplies its real array length; no caller hint is used.
const CAUTIOUS_RESERVATION_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy)]
struct Shape {
    element_bytes: usize,
    vector_depth: usize,
}

impl Shape {
    const EMPTY: Self = Self {
        element_bytes: 0,
        vector_depth: 0,
    };

    const fn merge(self, other: Self) -> Self {
        Self {
            element_bytes: maximum(self.element_bytes, other.element_bytes),
            vector_depth: maximum(self.vector_depth, other.vector_depth),
        }
    }
}

const fn maximum(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

trait HeapShape {
    const SHAPE: Shape;
}

// Only strings and objects can be completed elements in this closed family.
// Each contributes its own two quote/bracket bytes, disjoint from descendants.
// Thus completed typed elements across all nested vectors number at most F/2.
trait VectorElement: HeapShape {}

impl VectorElement for Id {}
impl VectorElement for ContentRef {}
impl VectorElement for Event {}
impl VectorElement for ObservationBatch {}

impl<T: VectorElement> HeapShape for Vec<T> {
    const SHAPE: Shape = Shape {
        element_bytes: maximum(size_of::<T>(), T::SHAPE.element_bytes),
        vector_depth: 1 + T::SHAPE.vector_depth,
    };
}

impl<T: HeapShape> HeapShape for Option<T> {
    const SHAPE: Shape = T::SHAPE;
}

impl<T: HeapShape> HeapShape for Nullable<T> {
    const SHAPE: Shape = T::SHAPE;
}

// These opaque populations have their own JSON/string/byte backing rows. In
// particular, literal Value arrays do not use Serde's typed Vec reservation.
macro_rules! without_typed_vectors {
    ($($type:ty),+ $(,)?) => {$(
        impl HeapShape for $type {
            const SHAPE: Shape = Shape::EMPTY;
        }
    )+};
}

without_typed_vectors!(
    bool, u16, String, Id, U64, Bytes, Value,
    Map<String, Value>, BTreeMap<String, Value>,
    BoundaryPolicy, BoundKind, BudgetOutcome, StopReason, EventStage, OperatingMode, OperationState,
    Phase, RetirementDisposition, Visibility,
);

const fn field_shape<S, T: HeapShape>(_: fn(&S) -> &T) -> Shape {
    T::SHAPE
}

// The exhaustive pattern catches added fields; each accessor makes the real
// field type participate in the graph. No DTO or field witness is evaluated.
macro_rules! record {
    ($type:ident { $($field:ident),+ $(,)? }) => {
        impl HeapShape for $type {
            const SHAPE: Shape = {
                let _ = |value: &Self| {
                    let Self { $($field: _),+ } = value;
                };
                let mut shape = Shape::EMPTY;
                $(shape = shape.merge(field_shape(|value: &Self| &value.$field));)+
                shape
            };
        }
    };
}

record!(BeginAccepted { operation_id, kind });

record!(BeginRequest {
    kind,
    binding_hash,
    owner_generation,
    activation_id,
    world_generation,
    arguments,
    extensions,
});

record!(BlobBeginRequest {
    transfer_id,
    content,
    extensions,
});

record!(BlobBeginResult {
    transfer_id,
    next_offset,
    maximum_chunk_bytes,
});

record!(BlobChunkRequest {
    transfer_id,
    offset,
    bytes,
    extensions,
});

record!(BlobChunkResult {
    transfer_id,
    next_offset,
});

record!(BlobFinishRequest {
    transfer_id,
    extensions,
});

record!(BlobFinishResult {
    transfer_id,
    content,
});

record!(CaptureArguments {
    capture_id,
    participant_ids,
    cut_id,
    cut,
    event_ordinal,
    ordering_profile,
    preservation_contract,
});

record!(ContentRef {
    hash,
    length,
    media_type,
});

record!(Endpoint {
    node_id,
    port_id,
    lane_id,
});

record!(Event {
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

record!(ExactRunArguments {
    grant_id,
    participant_ids,
    realization_id,
    activation_id,
    world_generation,
    owner_generation,
    input_epoch,
    mode,
    ordering_profile,
    start,
    limit,
    boundary_policy,
    input_authorization,
    input_watermark,
});

record!(HashRef {
    algorithm,
    domain,
    digest,
});

record!(InputRequest {
    binding_hash,
    owner_generation,
    batch_id,
    batch_sequence,
    input_epoch,
    events,
    batch_hash,
    extensions,
});

record!(InputResult {
    accepted_event_ids,
    input_watermark,
    custody_receipt,
    inventory_hash,
});

record!(ObservationBatch {
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

record!(ObserveRequest {
    binding_hash,
    owner_generation,
    after_observation_sequence,
    maximum_items,
    extensions,
});

record!(ObserveResult {
    observations,
    next_sequence,
    complete,
    inventory_hash,
});

record!(PauseArguments {
    participant_ids,
    reason,
});

record!(PollRequest {
    after_observation_sequence,
    extensions,
});

record!(PollResult {
    operation_id,
    operation_state,
    outcome,
    observations,
    next_observation_sequence,
});

record!(Position {
    time_ps,
    microstep,
    phase,
});

record!(PrepareRestoreArguments {
    transaction_id,
    capture_manifest,
    expected_world_binding_hash,
    expected_owner_binding_hash,
    destination_owner_ids,
});

record!(QuantumBeginArguments {
    grant_id,
    participant_ids,
    realization_id,
    activation_id,
    world_generation,
    owner_generation,
    input_epoch,
    mode,
    ordering_profile,
    quantum_index,
    from_ps,
    until_ps,
    input_batch,
    input_watermark,
    policy_hash,
    wall_budget_ns,
});

record!(RetireRequest {
    request_ids,
    operation_ids,
    disposition,
    custody_receipt,
    extensions,
});

record!(RetireResult {
    retired_request_ids,
    retired_operation_ids,
});

record!(ShutdownArguments {
    participant_ids,
    reason,
});

record!(ExactRunResult {
    grant_id,
    reached,
    stop_reason,
    stop_receipt,
    observation_batch,
    pending_inventory,
    next_attention,
});

record!(QuantumBeginResult {
    grant_id,
    quantum_index,
    stop_receipt,
    observation_batch,
    pending_inventory,
    budget_outcome,
    physical_measurement_ref,
});

record!(PauseResult {
    stop_receipt,
    physical_paused,
    reached,
    pending_inventory,
});

record!(CaptureResult {
    capture_manifest,
    owner_state_refs,
    unchanged_cut_receipt,
});

record!(PrepareRestoreResult {
    transaction_id,
    prepared_token,
    world_binding_hash,
    owner_binding_hash,
    staged_owner_ids,
    closed_gate_receipt,
    validated_manifest,
});

record!(ShutdownResult {
    observation_batch,
    pending_inventory,
    stopped,
    reaped,
    cleanup_receipt,
});

record!(Bound {
    kind,
    position,
    evidence,
});

// Keep the closed Begin kind roster exhaustive and pair each argument with its
// actual terminal result. Adding a kind requires updating this same shape arm.
macro_rules! begin_variants {
    ($($variant:ident => ($argument:ty, $result:ty)),+ $(,)?) => {
        impl HeapShape for BeginKind {
            const SHAPE: Shape = {
                let _ = |kind: Self| match kind { $(Self::$variant => ()),+ };
                let mut shape = Shape::EMPTY;
                $(shape = shape.merge(<$argument>::SHAPE).merge(<$result>::SHAPE);)+
                shape
            };
        }
    };
}

begin_variants! {
    ExactRun => (ExactRunArguments, ExactRunResult),
    BoundarySettle => (ExactRunArguments, ExactRunResult),
    QuantumBegin => (QuantumBeginArguments, QuantumBeginResult),
    Pause => (PauseArguments, PauseResult),
    Capture => (CaptureArguments, CaptureResult),
    PrepareRestore => (PrepareRestoreArguments, PrepareRestoreResult),
    Shutdown => (ShutdownArguments, ShutdownResult),
}

const RUNTIME: Shape = {
    let mut shape = Shape::EMPTY;
    shape = shape.merge(InputRequest::SHAPE);
    shape = shape.merge(ObserveRequest::SHAPE);
    shape = shape.merge(BeginRequest::SHAPE);
    shape = shape.merge(PollRequest::SHAPE);
    shape = shape.merge(RetireRequest::SHAPE);
    shape = shape.merge(BlobBeginRequest::SHAPE);
    shape = shape.merge(BlobChunkRequest::SHAPE);
    shape = shape.merge(BlobFinishRequest::SHAPE);
    shape = shape.merge(InputResult::SHAPE);
    shape = shape.merge(ObserveResult::SHAPE);
    shape = shape.merge(BeginAccepted::SHAPE);
    shape = shape.merge(PollResult::SHAPE);
    shape = shape.merge(RetireResult::SHAPE);
    shape = shape.merge(BlobBeginResult::SHAPE);
    shape = shape.merge(BlobChunkResult::SHAPE);
    shape = shape.merge(BlobFinishResult::SHAPE);
    shape = shape.merge(ExactRunArguments::SHAPE);
    shape = shape.merge(QuantumBeginArguments::SHAPE);
    shape = shape.merge(PauseArguments::SHAPE);
    shape = shape.merge(CaptureArguments::SHAPE);
    shape = shape.merge(PrepareRestoreArguments::SHAPE);
    shape = shape.merge(ShutdownArguments::SHAPE);
    shape
};

/// Bounds completed and simultaneously constructing typed vector backing.
///
/// The caller establishes the actual canonical extent before using this row.
/// Complete vectors request less than twice their completed element bytes.
/// During reallocation the old bank can coexist with the new one; the factor
/// three includes both. Each active incomplete vector additionally receives a
/// full cautious reservation, including a failure before its first push.
///
/// This bound covers one decoding population only. Connection can decode an
/// original request beside a response while the caller holds another request;
/// the enclosing SDK phase must fund every simultaneous population separately.
/// All excluded backing named in this module remains independently required.
///
/// # Errors
/// Refuses zero extent, arithmetic overflow or either axis above the supplied
/// independent restriction. No quota, allocation or Source state changes.
pub(crate) fn typed_vector_storage_data(
    maximum_encoded_bytes: usize,
    restriction: usize,
) -> Result<[usize; 2], ProviderError> {
    if maximum_encoded_bytes == 0 {
        return Err(refused());
    }
    let elements = maximum_encoded_bytes / 2;
    let payload = elements
        .checked_mul(RUNTIME.element_bytes)
        .ok_or_else(refused)?;
    let completed = payload.checked_mul(2).ok_or_else(refused)?;
    let partials = RUNTIME
        .vector_depth
        .checked_mul(CAUTIOUS_RESERVATION_BYTES)
        .ok_or_else(refused)?;
    let constructing = payload
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(partials))
        .ok_or_else(refused)?;
    if completed > restriction || constructing > restriction {
        return Err(refused());
    }
    Ok([completed, constructing])
}

/// Names the fixed checked operands and results of the vector projection.
pub(crate) const fn counter_scratch_data() -> usize {
    // The field DAG is evaluated at compile time. These are the live checked
    // arithmetic operands and return slots; compiler stack is a separate cost.
    9 * size_of::<usize>()
        + 5 * size_of::<Option<usize>>()
        + size_of::<[usize; 2]>()
        + size_of::<Result<[usize; 2], ProviderError>>()
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("compact runtime typed vector projection")
}

#[cfg(test)]
mod tests;
