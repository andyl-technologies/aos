//! Observes the Source's separately retained original Observe report owners.
//!
//! Raw response maps, decoded results, report wrappers and report data each own
//! independent backing. The closed variants below count those actual owners.
//! They do not authenticate an Observe, compare source currency or grant Capture.

use super::*;
use crate::bodies::{MethodResult, ObserveResult, ResponseBody};
use crate::reference_packet::control::{PacketNative5Record, PacketNative5StorageSelection};
use crate::reference_packet::service::PacketNative5StorageLimits;
use crate::reference_packet::service::capture_allocation::{
    PacketNativeCaptureAllocationRecord, PacketNativeCaptureAllocationReport,
    PacketNativeCaptureAllocationScope, PacketNativeCaptureProtocolAllocation,
    PacketNativeCaptureRetainedGrowth, PacketNativeCaptureTransients,
};

/// Borrows the closed original-Observe families retained by Source Capture custody.
pub enum RetainedNativeCaptureAllocationData<'a> {
    /// Borrows raw and independently decoded Observe response fields or a refusal.
    Response(&'a ResponseBody),
    /// Borrows the selected wrapper, including its independent full native receipt5.
    Record(&'a PacketNativeCaptureAllocationRecord),
    /// Borrows the separately retained typed report and its exact child backing.
    Report(&'a PacketNativeCaptureAllocationReport),
}

impl RetainedNativeCaptureAllocationData<'_> {
    /// Reports actual retained child capacities and typed requested-layout facts.
    ///
    /// The caller separately counts outer inline slots, encoded banks, fullref
    /// clones and traversal scratch. Equal data in another original owner is not
    /// discounted; in particular the wrapper's native receipt owns an independent
    /// original Envelope even when the controller retains the same request.
    ///
    /// # Errors
    /// Refuses a typed response from another method family, checked extent
    /// overflow or bounded traversal exhaustion. No validation or I/O occurs.
    pub fn observe_retained_metadata(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        match self {
            Self::Response(response) => observe_response(response, &mut observer)?,
            Self::Record(record) => observer.observe(*record)?,
            Self::Report(report) => observer.observe(*report)?,
        }
        Ok(observer.finish())
    }
}

fn observe_response(
    response: &ResponseBody,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let ResponseBody { shape, result } = response;
    super::capture_data::observe_response_shape(shape, observer)?;
    match result {
        None => Ok(()),
        Some(MethodResult::Observe(value)) => observer.observe(value),
        Some(
            MethodResult::Hello(_)
            | MethodResult::Discover(_)
            | MethodResult::Realize(_)
            | MethodResult::Admit(_)
            | MethodResult::Activate(_)
            | MethodResult::Input(_)
            | MethodResult::Poll(_)
            | MethodResult::Cancel(_)
            | MethodResult::QuantumClose(_)
            | MethodResult::WorldActivate(_)
            | MethodResult::Abort(_)
            | MethodResult::Retire(_)
            | MethodResult::BlobBegin(_)
            | MethodResult::BlobChunk(_)
            | MethodResult::BlobFinish(_)
            | MethodResult::Release(_)
            | MethodResult::BeginAccepted(_)
            | MethodResult::ExactRun(_)
            | MethodResult::BoundarySettle(_)
            | MethodResult::QuantumBegin(_)
            | MethodResult::Pause(_)
            | MethodResult::Capture(_)
            | MethodResult::PrepareRestore(_)
            | MethodResult::Shutdown(_),
        ) => Err(ProviderError::Correlation(
            "retained native Capture Observe method family differs",
        )),
    }
}

fields!(
    ObserveResult,
    observations,
    next_sequence,
    complete,
    inventory_hash
);
fields!(
    PacketNative5StorageLimits,
    snapshot_bytes,
    control_snapshot_bytes,
    protocol_snapshot_bytes,
    frame_bank_bytes,
    frames_per_direction,
    hello_bytes,
    settlement_bytes
);
fields!(PacketNative5StorageSelection, storage, limits);
fields!(
    PacketNative5Record,
    schema,
    native_pid,
    original,
    binding_hash,
    session,
    incarnation,
    node,
    owner,
    owner_generation,
    input_epoch,
    world,
    native_record,
    storage_selection,
    capture_profile,
    confirmation_selection,
    ack_emitter_selection,
    complete_restore_selection,
    protocol_metadata_limits,
    protocol_metadata_birth_facts,
    restore_input_emitter_selection
);
fields!(
    PacketNativeCaptureAllocationRecord,
    schema,
    native,
    allocation
);
fields!(
    PacketNativeCaptureAllocationReport,
    schema,
    scope,
    before,
    after,
    metadata_banks,
    retained_requested_bytes,
    shared_edges,
    unique_roots,
    growth,
    transients
);
fields!(
    PacketNativeCaptureAllocationScope,
    native_pid,
    observe_request,
    observe_sequence,
    observe_hash,
    session,
    incarnation,
    node,
    owner,
    binding_hash,
    world,
    activation,
    world_generation,
    owner_generation,
    model_cursor,
    control_originals_before,
    endpoint_records_before,
    provider_next_sequence_before
);
fields!(
    PacketNativeCaptureProtocolAllocation,
    encoded_capacity,
    literal_and_descriptor_bytes,
    current_encoded_bytes
);
fields!(
    PacketNativeCaptureRetainedGrowth,
    observe_publication_bytes,
    capture_request_bytes,
    capture_publication_bytes,
    after_confirmation_bytes
);
fields!(
    PacketNativeCaptureTransients,
    observe_encoding_bytes,
    model_control_encoding_bytes,
    native_before_encoding_bytes,
    native_after_encoding_bytes,
    quote_scratch_bytes
);

// crucible-lint: allow panic-shortcut -- actual spare-capacity response data is the test observation.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "checks independent raw/typed Observe allocation without constructing native authority"
)]
mod tests {
    use super::*;
    use crate::bodies::{OperationState, ResponseShape};
    use crucible_node_format::{Extensions, ObservationBatch, U64, canonical};

    #[test]
    fn original_observe_counts_raw_result_and_independent_empty_typed_spare_bank() {
        let observations: Vec<ObservationBatch> = Vec::with_capacity(37);
        let expected_vector_bytes = observations.capacity() * size_of::<ObservationBatch>();
        let mut raw_string = String::with_capacity(91);
        raw_string.push_str("actual raw result backing");
        let expected_string_bytes = raw_string.capacity();
        let mut raw = serde_json::Map::new();
        raw.insert("retained".into(), serde_json::Value::String(raw_string));
        let response = ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: raw,
                extensions: Extensions::new(),
            },
            result: Some(MethodResult::Observe(ObserveResult {
                observations,
                next_sequence: U64::new(1),
                complete: true,
                inventory_hash: canonical::json_hash(
                    "cnp.test.inventory.v1",
                    &serde_json::json!({}),
                )
                .unwrap(),
            })),
        };

        let facts = RetainedNativeCaptureAllocationData::Response(&response)
            .observe_retained_metadata()
            .unwrap();

        assert_eq!(facts.vector_capacity_bytes, expected_vector_bytes);
        assert!(facts.string_capacity_bytes >= expected_string_bytes);
        assert!(facts.tree_containers >= 2);
        assert!(
            crate::retained_metadata::RetainedCaptureProtocolData::Response(&response)
                .observe_retained_metadata()
                .is_err()
        );
    }
}
