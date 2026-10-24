//! Observes independently retained selected transfer response owners as DATA.
//!
//! Raw result/error/extension maps and the typed PrepareRestore result are
//! separate owning copies. Only that typed family is covered. These facts
//! authenticate no request, native receipt, upload, Source action or context.

use super::*;
use crate::bodies::*;
use std::mem::size_of;

/// Names the fixed observer and borrowed selected-response layouts.
///
/// Caller-owned ResponseBody/Option headers, recursive/compiler frames and
/// physical allocator overhead are separate. Admit this counter window before
/// visiting the response; this DATA getter supplies no such admission.
pub fn original_complete_restore_transfer_response_counter_scratch_data() -> usize {
    size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<(&ResponseBody, &ResponseShape, &Option<MethodResult>)>()
        + size_of::<&PrepareRestoreResult>()
        + size_of::<(
            &crucible_node_format::Id,
            &crucible_node_format::Id,
            &crucible_node_format::HashRef,
            &crucible_node_format::HashRef,
            &Vec<crucible_node_format::Id>,
            &crucible_node_format::ContentRef,
            &crucible_node_format::ContentRef,
        )>()
        + size_of::<(
            &OperationState,
            &serde_json::Map<String, serde_json::Value>,
            &crucible_node_format::Extensions,
        )>()
        + size_of::<(
            &OperationState,
            &ErrorRecord,
            &crucible_node_format::Extensions,
        )>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

/// Observes actual selected response child capacities without serialization.
///
/// The enclosing original owner checks its creator before calling. Independently
/// owned raw and typed strings, vectors and maps each retain their full actual
/// capacity; equality never supplies an alias discount. No allocation or IO runs.
///
/// # Errors
/// Refuses another typed result family, unknown metadata, checked overflow or
/// observer exhaustion. Error responses retain their complete raw error data.
pub fn original_complete_restore_transfer_response_metadata_data(
    response: &ResponseBody,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::new();
    observe_response_metadata_data(response, &mut observer)?;
    Ok(observer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Id, canonical};
    use serde_json::{Map, Value};

    #[test]
    fn raw_and_typed_transfer_response_keep_spare_independent_backing() {
        let mut raw = String::with_capacity(263);
        raw.push_str("raw result retained separately");
        let capacity = raw.capacity();
        let mut result = Map::new();
        result.insert("raw".into(), Value::String(raw));
        let ids = Vec::<Id>::with_capacity(9);
        let vector = ids.capacity() * size_of::<Id>();
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        let response = ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result,
                extensions: Default::default(),
            },
            result: Some(MethodResult::PrepareRestore(PrepareRestoreResult {
                transaction_id: Id::new("source/transaction").unwrap(),
                prepared_token: Id::new("token/actual").unwrap(),
                world_binding_hash: canonical::hash("cnp.world-binding.v1", b"world").unwrap(),
                owner_binding_hash: canonical::hash("cnp.owner-binding.v1", b"owner").unwrap(),
                staged_owner_ids: ids,
                closed_gate_receipt: reference.clone(),
                validated_manifest: reference,
            })),
        };

        let facts = original_complete_restore_transfer_response_metadata_data(&response).unwrap();

        assert_eq!(facts.vector_capacity_bytes, vector);
        assert!(
            facts.string_capacity_bytes
                >= capacity + "source/transaction".len() + "token/actual".len()
        );
        assert!(facts.tree_containers >= 2);
    }

    #[test]
    fn transfer_error_children_are_counted_and_unrelated_typed_result_refuses() {
        let mut message = String::with_capacity(229);
        message.push_str("actual retained refusal");
        let capacity = message.capacity();
        let mut response = ResponseBody {
            shape: ResponseShape::Error {
                operation_state: OperationState::Unknown,
                error: ErrorRecord {
                    code: "OUTCOME_UNKNOWN".into(),
                    message,
                    effect: EffectCertainty::Unknown,
                    retryable: false,
                    details: Default::default(),
                },
                extensions: Default::default(),
            },
            result: None,
        };

        let facts = original_complete_restore_transfer_response_metadata_data(&response).unwrap();
        assert!(facts.string_capacity_bytes >= capacity);
        response.result = Some(MethodResult::Admit(AdmitResult {
            accepted_binding_hashes: Vec::new(),
            admission_id: Id::new("another/method").unwrap(),
        }));

        assert!(original_complete_restore_transfer_response_metadata_data(&response).is_err());
    }
}

pub(super) fn observe_response_metadata_data(
    response: &ResponseBody,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let ResponseBody { shape, result } = response;
    super::capture_data::observe_response_shape(shape, observer)?;
    match result {
        None => {}
        Some(MethodResult::PrepareRestore(value)) => {
            let PrepareRestoreResult {
                transaction_id,
                prepared_token,
                world_binding_hash,
                owner_binding_hash,
                staged_owner_ids,
                closed_gate_receipt,
                validated_manifest,
            } = value;
            observer.observe(transaction_id)?;
            observer.observe(prepared_token)?;
            observer.observe(world_binding_hash)?;
            observer.observe(owner_binding_hash)?;
            observer.observe(staged_owner_ids)?;
            observer.observe(closed_gate_receipt)?;
            observer.observe(validated_manifest)?;
        }
        Some(
            MethodResult::Hello(_)
            | MethodResult::Discover(_)
            | MethodResult::Realize(_)
            | MethodResult::Admit(_)
            | MethodResult::Activate(_)
            | MethodResult::Input(_)
            | MethodResult::Observe(_)
            | MethodResult::Cancel(_)
            | MethodResult::QuantumClose(_)
            | MethodResult::WorldActivate(_)
            | MethodResult::Abort(_)
            | MethodResult::Retire(_)
            | MethodResult::BlobBegin(_)
            | MethodResult::BlobChunk(_)
            | MethodResult::BlobFinish(_)
            | MethodResult::Release(_)
            | MethodResult::ExactRun(_)
            | MethodResult::BoundarySettle(_)
            | MethodResult::QuantumBegin(_)
            | MethodResult::Pause(_)
            | MethodResult::Shutdown(_)
            | MethodResult::Capture(_)
            | MethodResult::Poll(_)
            | MethodResult::BeginAccepted(_),
        ) => {
            return Err(ProviderError::Correlation(
                "retained transfer response method differs",
            ));
        }
    }
    Ok(())
}
