//! Exercises closed future geometry with actual typed DATA and no native scope.

use super::*;
use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest};
use crate::envelope::{Envelope, Nullable};
use crate::reference_packet::service::restored_settled_capture::upload::{
    PacketRestoredSettledCaptureUploadArtifact, PacketRestoredSettledCaptureUploadContinuation,
};
use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;
use crucible_node_format::{Bytes, Extensions, Id, U64, canonical};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn launch() -> Result<PacketNative5SourceLaunch, Box<dyn std::error::Error>> {
    let (_, _, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    // This is actual launch DATA only. It installs no Source, boot, ticket,
    // reservation, transfer or selected17 capability.
    Ok(serde_json::from_value(json!({
        "schema_version":5,"selection":selection,
        "program":{"kind":"producer","program":{"schema":"source-owned.packet-program.v1","events":[]}},
        "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
        "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
        "limits":{"frame_bytes":"65536","nesting":"64","requests":"256","journal_entries":"256","blob_chunk_bytes":"4096"},
        "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
        "effects":"/not-opened-by-data-control"
    }))?)
}

fn geometry(data: &Shape) -> [usize; 11] {
    let Shape {
        dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes,
        projected_parser_requested_bytes,
        canonical_output_requested_bytes,
        serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes,
        maximum_encoded_bytes,
        sequence_elements,
        sequence_containers,
        serialized_value_nodes,
        serialized_capacity_records,
    } = data;
    [
        *dom_and_canonical_scratch_bytes,
        *retained_value_backing_bytes,
        *projected_parser_requested_bytes,
        *canonical_output_requested_bytes,
        *serializer_temporary_requested_bytes,
        *declared_counter_scratch_bytes,
        *maximum_encoded_bytes,
        *sequence_elements,
        *sequence_containers,
        *serialized_value_nodes,
        *serialized_capacity_records,
    ]
}

fn dominates(future: &Shape, actual: &impl serde::Serialize) -> TestResult {
    let actual = actual_serialization_storage_data(actual, Default::default(), usize::MAX)?;
    for (axis, (future, actual)) in geometry(future)
        .into_iter()
        .zip(geometry(&actual))
        .enumerate()
    {
        assert!(
            actual <= future,
            "axis{axis}: actual{actual} >future{future}"
        );
    }
    Ok(())
}

fn artifact(
    launch: &PacketNative5SourceLaunch,
) -> Result<PacketRestoredSettledCaptureUploadArtifact, Box<dyn std::error::Error>> {
    let binding = &launch.selection.realization.bindings[0];
    let reference = canonical::content_ref(b"proof", "application/json")?;
    let other = canonical::content_ref(b"other", "application/json")?;
    let binding_hash = canonical::hash("cnp.owner-binding.v1", b"actual-data-binding")?;
    let large = Id::new("i".repeat(128))?;
    let row = json!({"retained_requested_bytes":"1000000000000000000","maximum_simultaneous_transient_bytes":"1000000000000000000","declared_counter_scratch_bytes":"1000000000000000000"});
    let mut runtime = reference.clone();
    runtime.media_type = "application/vnd.crucible.runtime-original-lineage+json;version=7".into();
    let mut coordinator = reference.clone();
    coordinator.media_type =
        "application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17".into();
    let mut parent = reference.clone();
    parent.media_type = "application/vnd.crucible.native-signed-index-body.v3+json".into();
    let mut scoped = reference.clone();
    scoped.media_type = "\"\\".repeat(64);
    Ok(serde_json::from_value(json!({
        "request":{
            "schema":restored_settled_capture_upload_schema_ids_data().0,
            "capture":{
                "schema":RESTORED_SETTLED_CAPTURE_REQUEST,
                "scope":{
                    "source_birth":scoped,"source_runtime":reference,"scope_proof":reference,
                    "target":{"native_pid":"2147483647","session":binding.authority.session_id,
                        "incarnation":binding.authority.incarnation_id,"node":binding.compatibility.node_id,
                        "owner":large,"owner_generation":U64::new(u64::MAX),
                        "binding_hash":binding_hash,"world":launch.selection.world,"activation":large,
                        "generation":U64::new(u64::MAX),"prepared_token":launch.selection.prepared_token,
                        "gate":launch.selection.gate,"admission":launch.selection.admission,"transaction":launch.selection.transaction},
                    "restoration":{"captured_owner_state":reference,"captured_control":reference,"captured_journal":reference,
                        "mapping":reference,"commit_request":reference,"commit_response":other,"context_digest":Bytes::new(vec![7;32])}
                },
                "capture":{"capture_id":large,"participant_ids":[binding.compatibility.node_id],
                    "cut_id":large,"cut":{"time_ps":U64::new(u64::MAX),"microstep":U64::new(u64::MAX),"phase":3},
                    "event_ordinal":U64::new(u64::MAX),"ordering_profile":"superdense-v1","preservation_contract":large},
                "capture_owner":large,"capture_operation":large,
                "runtime_object":runtime,"coordinator_checkpoint":coordinator,"parent_archive":parent,
                "first_observation":reference,"current_record":reference,"current_model":reference,"history_prefix":reference,
                "history_next_sequence":U64::new(u64::MAX),"native_schema":reference,"native_allocation":row
            },
            "ordinal":"history_prefix","transfer_id":large,"content":reference,"native_allocation":row
        },
        "proof":{"schema":"source-owned.packet-restored-settled-capture-upload-proof/17","algorithm":"blake3-256-mac",
            "context_digest":Bytes::new(vec![7;32]),"mac":Bytes::new(vec![9;32])}
    }))?)
}

fn original(
    launch: &PacketNative5SourceLaunch,
    method: Method,
) -> Result<Envelope, Box<dyn std::error::Error>> {
    let binding = &launch.selection.realization.bindings[0];
    let artifact = artifact(launch)?;
    let transfer = artifact.request.transfer_id.clone();
    let continuation = PacketRestoredSettledCaptureUploadContinuation {
        schema: restored_settled_capture_upload_schema_ids_data().2.into(),
        context_digest: Bytes::new(vec![7; 32]),
        capture_operation: artifact.request.capture.capture_operation.clone(),
        transfer_id: transfer.clone(),
    };
    let (body, extension) = match method {
        Method::BlobBegin => (
            serde_json::to_value(BlobBeginRequest {
                transfer_id: transfer,
                content: artifact.request.content.clone(),
                extensions: Extensions::new(),
            })?,
            serde_json::to_value(artifact)?,
        ),
        Method::BlobChunk => (
            serde_json::to_value(BlobChunkRequest {
                transfer_id: transfer,
                offset: U64::new(u64::MAX),
                bytes: Bytes::new(vec![7; 4096]),
                extensions: Extensions::new(),
            })?,
            serde_json::to_value(continuation)?,
        ),
        Method::BlobFinish => (
            serde_json::to_value(BlobFinishRequest {
                transfer_id: transfer,
                extensions: Extensions::new(),
            })?,
            serde_json::to_value(continuation)?,
        ),
        _ => return Err("unexpected method".into()),
    };
    let Value::Object(body) = body else {
        return Err("body is not object".into());
    };
    let mut extensions = Extensions::new();
    extensions.insert(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(), extension);
    Ok(Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(binding.authority.session_id.clone())),
        incarnation_id: Nullable(Some(binding.authority.incarnation_id.clone())),
        node_id: Nullable(Some(binding.compatibility.node_id.clone())),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(Some(binding.compatibility.capture_owner.id.clone())),
        request_id: Nullable(Some(Id::new("r".repeat(128))?)),
        operation_id: Nullable(None),
        sequence: U64::new(u64::MAX),
        method,
        body,
        extensions,
    })
}

#[test]
fn every_future_original_terminal_and_reply_axis_dominates_typed_wire_data() -> TestResult {
    let launch = launch()?;
    let projected = project_capture17_upload_future_data(&launch, usize::MAX)?;
    for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
        let phase = projected.phase_data(method)?;
        let original = original(&launch, method)?;
        original.validate()?;
        dominates(phase.original_data(), &original)?;
        let transfer = Id::new("t".repeat(128))?;
        let result = match method {
            Method::BlobBegin => {
                json!({"transfer_id":transfer,"next_offset":U64::new(u64::MAX),"maximum_chunk_bytes":U64::new(u64::MAX)})
            }
            Method::BlobChunk => json!({"transfer_id":transfer,"next_offset":U64::new(u64::MAX)}),
            Method::BlobFinish => {
                let mut reference = canonical::content_ref(b"proof", &"\"\\".repeat(64))?;
                reference.length = U64::new(u64::MAX);
                json!({"transfer_id":transfer,"content":reference})
            }
            _ => return Err("unexpected method".into()),
        };
        let body = json!({"status":"completed","operation_state":"completed","result":result,"extensions":{}});
        dominates(phase.reply_data(), &body)?;
        let mut terminal = original;
        terminal.message = MessageKind::Response;
        terminal.body = body.as_object().ok_or("not object")?.clone();
        terminal.extensions.clear();
        terminal.validate()?;
        dominates(phase.terminal_data(), &terminal)?;
    }
    Ok(())
}

#[test]
fn artifact_token_geometry_dominates_different_actual_participant_distributions() -> TestResult {
    let mut out = Projection::new(usize::MAX)?;
    participants(&mut out)?;
    let bound = out.finish(usize::MAX)?;
    let varied: Vec<Vec<Id>> = vec![
        Vec::new(),
        vec![Id::new("x".repeat(128))?],
        (0..64)
            .map(|n| Id::new(format!("n{n:03}{}", "x".repeat(124))))
            .collect::<Result<_, _>>()?,
        (0..2000)
            .map(|n| Id::new(format!("n{n:04}")))
            .collect::<Result<_, _>>()?,
    ];
    for ids in varied {
        // This control exercises the two independent artifact-token premises;
        // it does not claim the rest of an artifact fits alongside this array.
        assert!(
            ids.iter().map(|id| id.as_str().len()).sum::<usize>()
                <= MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES
        );
        assert!(serde_json::to_vec(&ids)?.len() <= MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES);
        dominates(&bound, &ids)?;
    }
    assert!(bound.maximum_encoded_bytes < MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES * 2);
    Ok(())
}

#[test]
fn exact_shape_maximum_admits_and_one_short_refuses_without_raising_caps() -> TestResult {
    let launch = launch()?;
    let projected = project_capture17_upload_future_data(&launch, usize::MAX)?;
    let mut maximum = 0;
    for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
        let phase = projected.phase_data(method)?;
        for shape in [
            phase.original_data(),
            phase.terminal_data(),
            phase.reply_data(),
        ] {
            maximum = maximum.max(shape.requested_total()?);
        }
    }
    project_capture17_upload_future_data(&launch, maximum)?;
    assert!(project_capture17_upload_future_data(&launch, maximum - 1).is_err());
    assert!(projected.phase_data(Method::Observe).is_err());
    Ok(())
}

#[test]
fn binding_absence_and_zero_blob_limit_refuse() -> TestResult {
    let mut missing_binding = launch()?;
    missing_binding.selection.realization.bindings.clear();
    assert!(project_capture17_upload_future_data(&missing_binding, usize::MAX).is_err());
    let mut launch = launch()?;
    launch.limits.blob_chunk_bytes = U64::new(0);
    assert!(project_capture17_upload_future_data(&launch, usize::MAX).is_err());
    Ok(())
}

#[test]
fn closed_base64_extent_matches_actual_bytes_formatter_tails_and_refuses_overflow() -> TestResult {
    for length in [0, 1, 2, 3, 4, 4094, 4095, 4096] {
        let actual = serde_json::to_value(Bytes::new(vec![7; length]))?;
        assert_eq!(
            encoded_bytes(length)?,
            actual.as_str().ok_or("Bytes did not encode text")?.len()
        );
    }
    assert!(encoded_bytes(usize::MAX).is_err());
    Ok(())
}
