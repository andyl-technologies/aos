//! Checks actual sixteen-field partial custody without synthetic native rights.

use super::*;
use crate::{
    envelope::Nullable,
    protocol_snapshot::{
        owned11::{json_value::HistoricalJsonLimits, typed::Ledger},
        restored_settled17::{
            current_actions::CurrentCaptureStage17,
            current_capture17_upload_ingress::{
                BorrowedCurrentCaptureUploadIngress17, read_current_capture17_upload_ingress_data,
            },
        },
    },
    retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords},
};
use crucible_node_contract::{Id, canonical};
use serde_json::json;

fn original() -> Envelope {
    let mut original = crate::envelope::tests::request();
    original.method = Method::BlobBegin;
    original.node_id = Nullable(Some(Id::new("capture-node").unwrap()));
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(Some(Id::new("capture-owner").unwrap()));
    original.operation_id = Nullable(None);
    original.body = json!({
        "transfer_id":"transfer",
        "content":canonical::content_ref(b"actual", "application/json").unwrap(),
        "extensions":{},
    })
    .as_object()
    .unwrap()
    .clone();
    original.extensions.clear();
    // Deliberately no signed Source artifact: this fixture cannot authenticate
    // native upload authority, even after retaining the real typed Blob body.
    original
        .extensions
        .insert(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(), Value::Null);
    original
}

fn recorded(attempt: &NativeRestoredSettledCaptureUploadAttempt) -> (Vec<u8>, Vec<u8>) {
    let input = serde_json::to_vec(attempt).unwrap();
    let mut records = MetadataRecordBank::reserve(4096).unwrap();
    let mut observer = MetadataObserver::recording(&mut records);
    attempt
        .observe_settled_history_metadata_data(&mut observer)
        .unwrap();
    observer.finish();
    (input, serde_json::to_vec(&records).unwrap())
}

fn read<'input, 'rows>(
    input: &'input [u8],
    rows: &'rows [u8],
) -> Result<BorrowedCurrentCaptureUploadIngress17<'input, 'rows>, ProviderError> {
    let records = ValidatedMetadataRecords::validate(rows, 4096, 2 * 1024 * 1024)?;
    let mut ledger = Ledger::new(
        records.rows(),
        HistoricalJsonLimits {
            maximum_input_bytes: 65536,
            maximum_nodes: 4096,
            maximum_depth: 32,
            maximum_owned_backing_bytes: 2 * 1024 * 1024,
            maximum_tree_entries: 4096,
        },
    );
    let result = read_current_capture17_upload_ingress_data(input, &mut ledger)?;
    assert!(ledger.rows.next().is_none());
    Ok(result)
}

fn replace(input: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let matches: Vec<_> = input
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset))
        .collect();
    assert_eq!(matches.len(), 1);
    let offset = matches[0];
    let mut output = input.to_vec();
    output.splice(offset..offset + needle.len(), replacement.iter().copied());
    output
}

#[test]
fn actual_raw_and_failed_typed_blob_use_exact_sixteen_field_borrowed_grammar() {
    let mut attempt = NativeRestoredSettledCaptureUploadAttempt::new_data(7);
    let raw = original();
    attempt.retain_original_data(raw.clone()).unwrap();
    for failed_typed in [false, true] {
        if failed_typed {
            assert!(attempt.decode_body_data(65536).is_err());
            assert!(matches!(attempt.base.body, Some(Body::BlobBegin(_))));
            assert!(attempt.base.upload.is_none());
        }
        let (input, rows) = recorded(&attempt);
        let value: Value = serde_json::from_slice(&input).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 16);
        assert!(value.get("upload_action").unwrap().is_null());

        let borrowed = read(&input, &rows).unwrap();

        assert_eq!(borrowed.ordinal, 7);
        assert_eq!(borrowed.definition, input);
        assert_eq!(
            borrowed.original.raw_data(),
            serde_json::to_vec(&Some(&raw)).unwrap()
        );
        assert!(borrowed.upload_action.is_none());
        assert_eq!(borrowed.body == b"null", !failed_typed);
        assert!(matches!(borrowed.stage, CurrentCaptureStage17::Raw) != failed_typed);
        assert!(matches!(borrowed.stage, CurrentCaptureStage17::Failed) == failed_typed);
        for field in [
            borrowed.arguments,
            borrowed.capture,
            borrowed.capture_context,
            borrowed.confirmation,
            borrowed.checkpoint,
            borrowed.outputs,
        ] {
            assert_eq!(field, b"null");
        }
    }
    assert_eq!(attempt.original_data().unwrap(), &raw);
    assert!(attempt.phase17_data().is_err());
    assert!(
        attempt
            .authenticate_upload_source_data(&[0; 32], 65536)
            .is_err()
    );
    assert!(
        attempt
            .authenticate_retained_upload_source17_data(&[0; 32], 65536)
            .is_err()
    );
    assert!(attempt.assigned_upload17_quote_parts_data().is_err());
    assert!(attempt.prepared_upload17_reply_parts_data().is_err());
    assert!(attempt.begin_upload17_publication_data().is_err());
}

#[test]
fn missing_unknown_reordered_and_six_forbidden_nonnull_fields_refuse_exact_source_bytes() {
    let mut attempt = NativeRestoredSettledCaptureUploadAttempt::new_data(8);
    attempt.retain_original_data(original()).unwrap();
    assert!(attempt.decode_body_data(65536).is_err());
    let (input, rows) = recorded(&attempt);
    read(&input, &rows).unwrap();

    let missing = replace(&input, br#","upload_action":null"#, b"");
    assert!(read(&missing, &rows).is_err());
    let mut unknown = input[..input.len() - 1].to_vec();
    unknown.extend_from_slice(br#","unsupported":true}"#);
    assert!(read(&unknown, &rows).is_err());
    let reordered = replace(
        &input,
        br#","confirmation":null,"upload_action":null"#,
        br#","upload_action":null,"confirmation":null"#,
    );
    assert!(read(&reordered, &rows).is_err());
    for field in [
        "arguments",
        "capture",
        "capture_context",
        "confirmation",
        "checkpoint",
        "outputs",
    ] {
        let needle = format!(",\"{field}\":null");
        let replacement = format!(",\"{field}\":true");
        assert!(
            read(
                &replace(&input, needle.as_bytes(), replacement.as_bytes()),
                &rows
            )
            .is_err(),
            "{field}"
        );
    }
    let wrong_body = replace(&input, br#""kind":"blob_begin""#, br#""kind":"capture""#);
    assert!(read(&wrong_body, &rows).is_err());
}

#[test]
fn nonblob_raw_is_retained_and_poisoned_before_any_body_or_capture_decode() {
    let mut raw = original();
    raw.method = Method::Begin;
    let mut attempt = NativeRestoredSettledCaptureUploadAttempt::new_data(9);

    assert!(attempt.retain_original_data(raw.clone()).is_err());

    assert_eq!(attempt.original_data().unwrap(), &raw);
    assert!(attempt.base.stage == Stage::Failed);
    assert!(attempt.base.body.is_none());
    assert!(attempt.base.arguments.is_none());
    assert!(attempt.base.capture.is_none());
    assert!(attempt.base.capture_context.is_none());
    assert!(attempt.base.checkpoint.is_none());
    assert!(attempt.base.outputs.is_none());
    assert!(attempt.decode_body_data(65536).is_err());
    assert!(attempt.phase17_data().is_err());
    let (input, rows) = recorded(&attempt);
    let borrowed = read(&input, &rows).unwrap();
    assert_eq!(borrowed.body, b"null");
    assert!(matches!(borrowed.stage, CurrentCaptureStage17::Failed));
}

#[test]
fn wrapper_row_keeps_base_dynamic_bound_and_adds_its_real_fixed_layout_and_counter() {
    let base = original_restored_settled_capture_ingress_row_data(65536).unwrap();
    let wrapper = original_restored_settled_capture_upload_ingress_row_data(65536).unwrap();
    let fixed = size_of::<NativeRestoredSettledCaptureUploadAttempt>()
        + size_of::<RefCell<NativeRestoredSettledCaptureUploadAttempt>>()
        + crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            std::mem::align_of::<RefCell<NativeRestoredSettledCaptureUploadAttempt>>(),
        )
        .unwrap();
    assert_eq!(
        wrapper.retained_requested_bytes.get() - base.retained_requested_bytes.get(),
        u64::try_from(fixed).unwrap()
    );
    assert_eq!(
        wrapper.maximum_simultaneous_transient_bytes,
        base.maximum_simultaneous_transient_bytes
    );
    assert_eq!(
        wrapper.declared_counter_scratch_bytes.get() - base.declared_counter_scratch_bytes.get(),
        u64::try_from(original_restored_settled_capture_upload_ingress_counter_scratch_data())
            .unwrap()
    );
    assert!(original_restored_settled_capture_upload_ingress_row_data(0).is_err());
    assert!(original_restored_settled_capture_upload_ingress_row_data(usize::MAX).is_err());
}
