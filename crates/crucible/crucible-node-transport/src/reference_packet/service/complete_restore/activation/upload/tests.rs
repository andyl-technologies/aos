//! Checks inert upload framing, MAC scope, real owning metadata and finite loops.
//!
//! These controls issue no Source/Core/native grant, create no process/content
//! receiver and execute no upload. Their keys and portable DTOs are DATA only.

use super::*;
use crate::envelope::Nullable;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn request(bytes: &[u8]) -> Result<PacketRestorationActivationUploadRequest, ProviderError> {
    let request = PacketRestorationActivationUploadRequest {
        schema: PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE.into(),
        scope: super::super::tests::request()?.scope,
        role: PacketRestorationActivationUploadRole::Coordinator,
        coordinator: canonical::content_ref(bytes, "application/json")?,
        manifest: canonical::content_ref(b"actual-manifest-data", "application/json")?,
        maximum_frame_bytes: U64::new(65_536),
        chunk_bytes: U64::new(4096),
        maximum_requests: U64::new((bytes.len().div_ceil(4096) + 2) as u64),
        native_allocation: PacketRestorationActivationAllocationRow {
            retained_requested_bytes: U64::new(1),
            maximum_simultaneous_transient_bytes: U64::new(2),
            declared_counter_scratch_bytes: U64::new(3),
        },
    };
    request.validate_data()?;
    Ok(request)
}

fn original(request: &PacketRestorationActivationUploadRequest) -> Result<Envelope, ProviderError> {
    let body = serde_json::to_value(crate::bodies::BlobBeginRequest {
        transfer_id: Id::new("actual-assigned-upload")?,
        content: request.content_ref_data().clone(),
        extensions: Default::default(),
    })
    .map_err(ContractError::from)?;
    let Value::Object(body) = body else {
        return Err(invalid());
    };
    let mut extension = serde_json::Map::new();
    extension.insert(
        "request".into(),
        serde_json::to_value(request).map_err(ContractError::from)?,
    );
    let mut extensions = crucible_node_format::Extensions::new();
    extensions.insert(
        PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE.into(),
        Value::Object(extension),
    );
    let target = &request.scope.target;
    Ok(Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(target.session.clone())),
        incarnation_id: Nullable(Some(target.incarnation.clone())),
        node_id: Nullable(Some(target.node.clone())),
        execution_owner_id: Nullable(Some(target.owner.clone())),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(Id::new("actual-assigned-begin")?)),
        sequence: U64::new(44),
        method: Method::BlobBegin,
        body,
        extensions,
    })
}

#[test]
fn upload_assigned_projection_excludes_only_own_proof_and_preserves_content_sequence() -> TestResult
{
    let request = request(b"actual-coordinator-data")?;
    let original = original(&request)?;
    let digest =
        restoration_activation_upload_assigned_request_digest(&original, request.role, 65_536)?;
    let mut sealed = original.clone();
    sealed
        .extensions
        .get_mut(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?
        .insert("proof".into(), Value::Null);
    assert_eq!(
        digest,
        restoration_activation_upload_assigned_request_digest(&sealed, request.role, 65_536)?
    );

    let mut changed = original.clone();
    changed.sequence = U64::new(45);
    assert_ne!(
        digest,
        restoration_activation_upload_assigned_request_digest(&changed, request.role, 65_536)?
    );
    changed = original.clone();
    changed
        .body
        .insert("content".into(), serde_json::to_value(&request.manifest)?);
    assert!(
        restoration_activation_upload_assigned_request_digest(&changed, request.role, 65_536)
            .is_err()
    );
    changed = original;
    changed.extensions.insert("unknown".into(), Value::Null);
    assert!(
        restoration_activation_upload_assigned_request_digest(&changed, request.role, 65_536)
            .is_err()
    );
    Ok(())
}

#[test]
fn upload_mac_binds_both_full_refs_ordinal_loop_and_independent_row() -> TestResult {
    let request = request(b"actual-coordinator-data")?;
    let context = PacketRestorationActivationUploadContext {
        assigned_request: Bytes::new(
            restoration_activation_upload_assigned_request_digest(
                &original(&request)?,
                request.role,
                65_536,
            )?
            .to_vec(),
        ),
        request,
    };
    let proof = restoration_activation_upload_proof_data(&[9; 32], &context)?;
    verify_restoration_activation_upload_proof_data(&[9; 32], &context, &proof)?;
    assert!(verify_restoration_activation_upload_proof_data(&[8; 32], &context, &proof).is_err());
    for axis in 0..5 {
        let mut changed = context.clone();
        match axis {
            0 => {
                changed.request.manifest =
                    canonical::content_ref(b"other-manifest", "application/json")?
            }
            1 => changed.request.role = PacketRestorationActivationUploadRole::Manifest,
            2 => changed.request.chunk_bytes = U64::new(2048),
            3 => changed.request.native_allocation.retained_requested_bytes = U64::new(4),
            _ => changed.assigned_request = Bytes::new(vec![3; 32]),
        }
        assert!(
            verify_restoration_activation_upload_proof_data(&[9; 32], &changed, &proof).is_err()
        );
    }
    Ok(())
}

#[test]
fn upload_closed_projection_dominates_actual_independent_begin_backing() -> TestResult {
    let request = request(b"actual-coordinator-data")?;
    let mut original = original(&request)?;
    let context = PacketRestorationActivationUploadContext {
        request: request.clone(),
        assigned_request: Bytes::new(
            restoration_activation_upload_assigned_request_digest(&original, request.role, 65_536)?
                .to_vec(),
        ),
    };
    let proof = restoration_activation_upload_proof_data(&[9; 32], &context)?;
    original
        .extensions
        .get_mut(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?
        .insert("proof".into(), serde_json::to_value(proof)?);
    let mut observer = MetadataObserver::new();
    observer.observe(&original)?;
    let actual = requested_metadata_backing_storage_data(&observer.finish())?;
    let quoted = projection::frame(Method::BlobBegin, false, 4096, usize::MAX)?;
    assert!(actual <= quoted.dom_and_canonical_scratch_bytes);
    assert!(
        canonical::canonical_json(&serde_json::to_value(&original)?)?.len()
            <= quoted.maximum_encoded_bytes
    );
    let data = original_native_restoration_activation_upload_required_storage_data(&request)?;
    assert!(data.retained_requested_bytes.get() >= actual as u64);
    Ok(())
}

#[test]
fn upload_full_schema_and_exact_population_refuse_each_changed_boundary() -> TestResult {
    let schema = restoration_activation_upload_schema()?;
    authenticate_restoration_activation_upload_schema_data(&schema)?;
    let mut changed = schema.clone();
    changed.definition.length = U64::new(changed.definition.length.get() + 1);
    assert!(authenticate_restoration_activation_upload_schema_data(&changed).is_err());
    changed = schema;
    changed.definition.hash.domain = "foreign".into();
    assert!(authenticate_restoration_activation_upload_schema_data(&changed).is_err());

    let request = request(&vec![b' '; 4097])?;
    assert_eq!(request.maximum_requests.get(), 4);
    let mut wrong = request.clone();
    wrong.maximum_requests = U64::new(3);
    assert!(wrong.validate_data().is_err());
    wrong = request.clone();
    wrong.chunk_bytes = U64::new(0);
    assert!(wrong.validate_data().is_err());
    wrong = request.clone();
    wrong.coordinator.length = U64::new(131_073);
    wrong.maximum_requests = U64::new(131_073_u64.div_ceil(4096) + 2);
    assert!(wrong.validate_data().is_err());
    wrong = request.clone();
    wrong.manifest.length = U64::new(16_385);
    assert!(wrong.validate_data().is_err());
    wrong = request;
    wrong.maximum_frame_bytes = U64::new(65_537);
    assert!(wrong.validate_data().is_err());
    let mut fields = serde_json::to_value(&wrong)?;
    fields
        .as_object_mut()
        .ok_or_else(invalid)?
        .insert("unknown".into(), Value::Null);
    assert!(serde_json::from_value::<PacketRestorationActivationUploadRequest>(fields).is_err());
    Ok(())
}
