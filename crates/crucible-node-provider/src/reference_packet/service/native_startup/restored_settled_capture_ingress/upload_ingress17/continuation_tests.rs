//! Checks actual typed continuation custody and pure DATA identity constraints.

use super::*;
use crate::envelope::Nullable;
use serde_json::json;

fn continuation() -> PacketRestoredSettledCaptureUploadContinuation {
    PacketRestoredSettledCaptureUploadContinuation {
        schema: restored_settled_capture_upload_schema_ids_data().2.into(),
        context_digest: Bytes::new(vec![7; 32]),
        capture_operation: Id::new("capture-operation").unwrap(),
        transfer_id: Id::new("transfer").unwrap(),
    }
}

#[test]
fn exact_continuation_identity_data_rejects_every_changed_field_or_digest() {
    // This standalone DATA comparison asserts no Source MAC or seed ownership.
    let actual = continuation();
    let transfer = actual.transfer_id.clone();
    let operation = actual.capture_operation.clone();
    let digest = actual.context_digest.as_slice();
    authenticate_identity(&actual, &transfer, &operation, digest).unwrap();

    for field in 0..4 {
        let mut changed = actual.clone();
        match field {
            0 => changed.schema.push_str("-changed"),
            1 => changed.context_digest = Bytes::new(vec![8; 32]),
            2 => changed.capture_operation = Id::new("other-operation").unwrap(),
            _ => changed.transfer_id = Id::new("other-transfer").unwrap(),
        }
        assert!(authenticate_identity(&changed, &transfer, &operation, digest).is_err());
    }
    for length in [0, 31, 33] {
        assert!(authenticate_identity(&actual, &transfer, &operation, &vec![7; length]).is_err());
    }
    assert!(authenticate_identity(&actual, &transfer, &operation, &[8; 32]).is_err());
}

fn original(method: Method) -> Envelope {
    let mut original = crate::envelope::tests::request();
    original.method = method;
    original.node_id = Nullable(Some(Id::new("node").unwrap()));
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(Some(Id::new("capture-owner").unwrap()));
    original.operation_id = Nullable(None);
    original.body = match method {
        Method::BlobChunk => json!({
            "transfer_id":"transfer", "offset":"8",
            "bytes":Bytes::new(vec![1,2,3,4]), "extensions":{},
        }),
        Method::BlobFinish => json!({"transfer_id":"transfer", "extensions":{}}),
        _ => panic!("unexpected test method"),
    }
    .as_object()
    .unwrap()
    .clone();
    original.extensions.clear();
    original.extensions.insert(
        RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(),
        serde_json::to_value(continuation()).unwrap(),
    );
    original
}

#[test]
fn actual_chunk_and_finish_lend_only_their_retained_typed_input_without_authority() {
    for method in [Method::BlobChunk, Method::BlobFinish] {
        let raw = original(method);
        let mut attempt = NativeRestoredSettledCaptureUploadAttempt::new_data(1);
        attempt.retain_original_data(raw.clone()).unwrap();
        attempt.decode_body_data(65536).unwrap();
        let before = serde_json::to_vec(&attempt).unwrap();

        let (retained, input, typed_continuation) =
            attempt.continuation_upload17_input_data().unwrap();
        assert_eq!(retained, &raw);
        assert_eq!(typed_continuation, &continuation());
        assert_eq!(input.key_data().transfer, &typed_continuation.transfer_id);
        match input {
            NativeCapture17UploadInput::Chunk { offset, bytes, .. } => {
                assert_eq!(method, Method::BlobChunk);
                assert_eq!(offset, U64::new(8));
                assert_eq!(bytes.as_slice(), &[1, 2, 3, 4]);
            }
            NativeCapture17UploadInput::Finish { .. } => assert_eq!(method, Method::BlobFinish),
            NativeCapture17UploadInput::Begin { .. } => panic!("continuation became Begin"),
        }
        // Typed continuation DATA does not acquire a seed, token or publication.
        assert!(attempt.assigned_upload17_quote_parts_data().is_err());
        assert!(attempt.published_upload17_data().is_err());
        assert!(attempt.prepared_upload17_reply_parts_data().is_err());
        assert!(attempt.begin_upload17_publication_data().is_err());
        assert!(attempt.upload_action.is_none());
        assert_eq!(serde_json::to_vec(&attempt).unwrap(), before);

        attempt.interrupt_data();
        let failed = serde_json::to_vec(&attempt).unwrap();
        assert!(attempt.continuation_upload17_input_data().is_err());
        assert_eq!(attempt.original_data().unwrap(), &raw);
        assert_eq!(serde_json::to_vec(&attempt).unwrap(), failed);
    }
}
