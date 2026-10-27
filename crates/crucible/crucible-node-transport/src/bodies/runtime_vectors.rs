//! Bounds typed runtime vector backing through the actual closed field graph.
//!
//! The covered methods are Input, Observe, Begin, Poll, Retire and the three
//! Blob methods, including every Begin argument variant. Provider-origin
//! requests are separately restricted by Connection before typed decoding.
//! This component excludes literal JSON, strings, Bytes decoding, validation
//! sets, diagnostics, inline controls, caller roots and all transport owners.
//! It is one input to SDK funding, not a complete R/T/S row or Source right.
//!
//! The same closed field and method rosters also drive an allocation-free input
//! preflight before the defining DTO serializers run. The preflight bounds
//! populations, eager Bytes encoding and literal recursion without admitting
//! their later construction or replacing complete frame sizing. The closed
//! method roster also requires concrete decoder companions for every body root.

use super::*;
use std::{collections::BTreeMap, mem::size_of};

mod preflight;

use preflight::Preflight;
pub(crate) use preflight::counter_scratch_data as packet_runtime_preflight_counter_scratch_data;

/// Names a concrete baseline root's decoder views and diagnostic literals.
///
/// Implementations under reference_packet reuse the defining partial graph.
/// This interface keeps that graph private while making every method/Begin
/// roster entry require its own real companion at compile time.
pub(crate) trait RuntimeBodyDecoderCompanion: Sized {
    /// Bounds the complete reachable type, field and variant name literals.
    const DECODER_DIAGNOSTIC_NAMES_BYTES: usize;

    /// Names explicit decoder controls, excluding backing and machine frames.
    fn decoder_counter_scratch_data() -> usize;
}

// serde_core 1.0.228 caps Vec<T>'s initial reservation at this many bytes.
// A rejected first element can leave that entire reservation live. The pinned
// borrowed Value iterator supplies its real array length; no caller hint is used.
const CAUTIOUS_RESERVATION_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy)]
struct Shape {
    element_bytes: usize,
    element_bytes_per_wire_byte: usize,
    vector_depth: usize,
    container_depth: usize,
}

impl Shape {
    const EMPTY: Self = Self {
        element_bytes: 0,
        element_bytes_per_wire_byte: 0,
        vector_depth: 0,
        container_depth: 0,
    };

    const fn merge(self, other: Self) -> Self {
        Self {
            element_bytes: maximum(self.element_bytes, other.element_bytes),
            element_bytes_per_wire_byte: maximum(
                self.element_bytes_per_wire_byte,
                other.element_bytes_per_wire_byte,
            ),
            vector_depth: maximum(self.vector_depth, other.vector_depth),
            container_depth: maximum(self.container_depth, other.container_depth),
        }
    }
}

const fn maximum(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

trait HeapShape {
    const SHAPE: Shape;

    fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError>;
}

// Each completed element contributes its own syntax, disjoint from nested
// vector elements. Records require objects. Keep the earlier, smaller positional
// separator/bracket allowance as a conservative bound; tightening the grammar
// does not grant a larger vector population or refund its funding component.
// The defining schema controls below pin every selected field as required.
trait VectorElement: HeapShape {
    const LOCAL_ENCODED_BYTES: usize;
}

impl VectorElement for Id {
    // Id validates its nonempty text during deserialization.
    const LOCAL_ENCODED_BYTES: usize = 3;
}

trait RecordFields {
    const FIELDS: &'static [&'static str];
}

macro_rules! record_vector_elements {
    ($($type:ty),+ $(,)?) => {$(
        impl VectorElement for $type {
            // Every required object field has at least one key/separator byte.
            // This retained lower bound also allows two container delimiters;
            // child value syntax never contributes to the local budget.
            const LOCAL_ENCODED_BYTES: usize = <Self as RecordFields>::FIELDS.len() + 1;
        }
    )+};
}

record_vector_elements!(ContentRef, Event, ObservationBatch);

impl<T: VectorElement> HeapShape for Vec<T> {
    const SHAPE: Shape = Shape {
        element_bytes: maximum(size_of::<T>(), T::SHAPE.element_bytes),
        element_bytes_per_wire_byte: maximum(
            size_of::<T>().div_ceil(T::LOCAL_ENCODED_BYTES),
            T::SHAPE.element_bytes_per_wire_byte,
        ),
        vector_depth: 1 + T::SHAPE.vector_depth,
        container_depth: 1 + T::SHAPE.container_depth,
    };

    fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
        counter.container(self.len())?;
        for element in self {
            element.preflight(counter)?;
        }
        Ok(())
    }
}

impl<T: HeapShape> HeapShape for Option<T> {
    const SHAPE: Shape = T::SHAPE;

    fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
        match self {
            Some(value) => value.preflight(counter),
            None => Ok(()),
        }
    }
}

impl<T: HeapShape> HeapShape for Nullable<T> {
    const SHAPE: Shape = T::SHAPE;

    fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
        self.0.preflight(counter)
    }
}

// Scalar fields have no typed vectors or unbounded serializer recursion. The
// dynamic String, Bytes and literal JSON implementations live in preflight.
macro_rules! scalar_shapes {
    ($($type:ty),+ $(,)?) => {$(
        impl HeapShape for $type {
            const SHAPE: Shape = Shape::EMPTY;

            fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
                counter.consume(1)
            }
        }
    )+};
}

scalar_shapes!(
    bool,
    u16,
    U64,
    BoundaryPolicy,
    BoundKind,
    BudgetOutcome,
    StopReason,
    EventStage,
    OperatingMode,
    OperationState,
    EffectCertainty,
    Phase,
    RetirementDisposition,
    Visibility,
);

const fn field_shape<S, T: HeapShape>(_: fn(&S) -> &T) -> Shape {
    T::SHAPE
}

// The exhaustive pattern catches added fields; each accessor makes the real
// field type participate in the graph. No DTO or field witness is evaluated.
macro_rules! record {
    ($type:ident { $($field:ident),+ $(,)? }) => {
        impl RecordFields for $type {
            const FIELDS: &'static [&'static str] = &[$(stringify!($field)),+];
        }

        impl HeapShape for $type {
            const SHAPE: Shape = {
                let _ = |value: &Self| {
                    let Self { $($field: _),+ } = value;
                };
                let mut shape = Shape::EMPTY;
                $(shape = shape.merge(field_shape(|value: &Self| &value.$field));)+
                shape.container_depth += 1;
                shape
            };

            fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
                counter.consume(1)?;
                $(self.$field.preflight(counter)?;)+
                Ok(())
            }
        }
    };
}

record!(ErrorRecord {
    code,
    message,
    effect,
    retryable,
    details,
});

record!(NotificationBody {
    operation_state,
    last_observation_sequence,
    details,
    extensions,
});

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

            fn preflight(&self, counter: &mut Preflight) -> Result<(), ProviderError> {
                counter.consume(1)
            }
        }

        impl RuntimeBodyDecoderCompanion for BeginKind {
            const DECODER_DIAGNOSTIC_NAMES_BYTES: usize = stringify!(BeginKind).len()
                $(+ 2 * stringify!($variant).len() + 8
                    + <$argument as RuntimeBodyDecoderCompanion>::DECODER_DIAGNOSTIC_NAMES_BYTES
                    + <$result as RuntimeBodyDecoderCompanion>::DECODER_DIAGNOSTIC_NAMES_BYTES)+;

            fn decoder_counter_scratch_data() -> usize {
                size_of::<Self>() + size_of::<Result<Self, serde_json::Error>>()
                    $(+ <$argument as RuntimeBodyDecoderCompanion>::decoder_counter_scratch_data()
                      + <$result as RuntimeBodyDecoderCompanion>::decoder_counter_scratch_data())+
            }
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

// One roster defines both the public immutable body family and its actual DTO
// vector graph. A new variant cannot bypass the sealed field-shape witnesses.
macro_rules! packet_requests {
    ($($(#[$documentation:meta])* $variant:ident($request:ty) => $result:ty),+ $(,)?) => {
        /// Borrows one immutable request from the closed packet runtime family.
        ///
        /// Every variant uses the defining DTO serializer. Callers cannot supply
        /// a serializer callback, override its method or select another schema.
        /// Begin arguments retain their separately validated kind-specific schema.
        /// Original body backing and all call construction require independent
        /// funding. This type grants no Source or native effect permission.
        #[derive(Serialize)]
        #[serde(untagged)]
        pub enum PacketRuntimeRequest<'a> {
            $($(#[$documentation])* $variant(&'a $request)),+
        }

        impl PacketRuntimeRequest<'_> {
            pub(crate) fn method(&self) -> Method {
                match self { $(Self::$variant(_) => Method::$variant),+ }
            }

            pub(crate) fn preflight_serialization(
                &self,
                extensions: &Extensions,
                maximum_frame: usize,
            ) -> Result<(), ProviderError> {
                let mut counter = Preflight::new(maximum_frame);
                match self { $(Self::$variant(body) => body.preflight(&mut counter)?),+ }
                extensions.preflight(&mut counter)
            }
        }

        const RUNTIME: Shape = {
            let mut shape = Shape::EMPTY;
            $(shape = shape.merge(<$request>::SHAPE).merge(<$result>::SHAPE);)+
            shape.merge(NotificationBody::SHAPE).merge(ErrorRecord::SHAPE)
        };

        /// Names all closed request/result and unsolicited-body decoder views.
        pub(crate) fn body_decoder_counter_scratch_data() -> usize {
            <$crate::bodies::BeginKind as RuntimeBodyDecoderCompanion>::decoder_counter_scratch_data()
                + <NotificationBody as RuntimeBodyDecoderCompanion>::decoder_counter_scratch_data()
                + <ErrorRecord as RuntimeBodyDecoderCompanion>::decoder_counter_scratch_data()
                $(+ <$request as RuntimeBodyDecoderCompanion>::decoder_counter_scratch_data()
                  + <$result as RuntimeBodyDecoderCompanion>::decoder_counter_scratch_data())+
        }

        /// Bounds diagnostic literals under the same exhaustive method roster.
        pub(crate) const BODY_DIAGNOSTIC_NAMES_BYTES: usize =
            <BeginKind as RuntimeBodyDecoderCompanion>::DECODER_DIAGNOSTIC_NAMES_BYTES
                + <NotificationBody as RuntimeBodyDecoderCompanion>::DECODER_DIAGNOSTIC_NAMES_BYTES
                + <ErrorRecord as RuntimeBodyDecoderCompanion>::DECODER_DIAGNOSTIC_NAMES_BYTES
                $(+ <$request as RuntimeBodyDecoderCompanion>::DECODER_DIAGNOSTIC_NAMES_BYTES
                  + <$result as RuntimeBodyDecoderCompanion>::DECODER_DIAGNOSTIC_NAMES_BYTES)+;
    };
}

packet_requests! {
    /// Borrows delivered input for its execution owner.
    Input(InputRequest) => InputResult,
    /// Borrows an execution owner's observation query.
    Observe(ObserveRequest) => ObserveResult,
    /// Borrows one of the seven baseline Begin argument kinds.
    Begin(BeginRequest) => BeginAccepted,
    /// Borrows a retained operation's progress query.
    Poll(PollRequest) => PollResult,
    /// Borrows authenticated retirement or inert abandonment data.
    Retire(RetireRequest) => RetireResult,
    /// Borrows an inert content-transfer reservation.
    BlobBegin(BlobBeginRequest) => BlobBeginResult,
    /// Borrows one immutable content chunk.
    BlobChunk(BlobChunkRequest) => BlobChunkResult,
    /// Borrows an inert content-transfer completion.
    BlobFinish(BlobFinishRequest) => BlobFinishResult,
}

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
    let payload = maximum_encoded_bytes
        .checked_mul(RUNTIME.element_bytes_per_wire_byte)
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

/// Bounds closed typed containers, literal recursion and the outer envelope.
///
/// Literal JSON permits 64 nested containers and one terminal scalar. Adding
/// the entire typed path conservatively covers literals in any record field;
/// Option and Nullable wrappers do not add serializer containers. The envelope
/// is the one container outside the exhaustive body roster.
pub(crate) const fn packet_runtime_serialization_depth() -> usize {
    RUNTIME.container_depth + 65 + 1
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("compact runtime typed vector projection")
}

#[cfg(test)]
mod tests;
