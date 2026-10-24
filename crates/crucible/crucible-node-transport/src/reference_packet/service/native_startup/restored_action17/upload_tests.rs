//! Checks raw-first upload union custody and its actual strict historical pair.

use super::*;
use crate::{
    envelope::Nullable,
    protocol_snapshot::{
        owned11::{json_value::HistoricalJsonLimits, typed::Ledger},
        restored_settled17::current_actions::HistoricalRestoredAction17,
    },
    retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords},
};
use crucible_node_format::Id;
use serde_json::{Value, json};

fn original(method: Method) -> Envelope {
    let mut original = crate::envelope::tests::request();
    original.method = method;
    original.node_id = Nullable(Some(Id::new("capture-upload-node").unwrap()));
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(Some(Id::new("capture-upload-owner").unwrap()));
    original.operation_id = Nullable(None);
    original.extensions.clear();
    original
        .extensions
        .insert(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(), Value::Null);
    original
}

fn recorded(attempt: &NativeRestoredSettledActionAttempt) -> (Vec<u8>, Vec<u8>) {
    let input = serde_json::to_vec(attempt).unwrap();
    let mut rows = MetadataRecordBank::reserve(8192).unwrap();
    let mut observer = MetadataObserver::recording(&mut rows);
    attempt
        .observe_settled_history_metadata_data(&mut observer)
        .unwrap();
    observer.finish();
    (input, serde_json::to_vec(&rows).unwrap())
}

fn read(input: &[u8], rows: &[u8]) -> Result<(), ProviderError> {
    let records = ValidatedMetadataRecords::validate(rows, 8192, 2 * 1024 * 1024)?;
    let mut ledger = Ledger::new(
        records.rows(),
        HistoricalJsonLimits {
            maximum_input_bytes: 65536,
            maximum_nodes: 8192,
            maximum_depth: 32,
            maximum_owned_backing_bytes: 2 * 1024 * 1024,
            maximum_tree_entries: 8192,
        },
    );
    assert!(
        ledger
            .read::<HistoricalRestoredAction17>(input, false)?
            .is_none()
    );
    assert!(ledger.rows.next().is_none());
    Ok(())
}

#[test]
fn three_blob_methods_retain_distinct_raw_upload_union_without_action_authority() {
    for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
        let raw = original(method);
        let mut attempt = NativeRestoredSettledActionAttempt::new_data(1);
        attempt.retain_original_data(raw.clone()).unwrap();
        let Some(Selected::CaptureUpload17(child)) = &attempt.selected else {
            panic!("wrong family")
        };
        assert_eq!(child.original_data().unwrap(), &raw);
        assert!(attempt.original.is_none());
        assert!(attempt.family_data().is_err());
        assert!(attempt.capture_data().is_err());
        assert!(attempt.input_reactive_data().is_err());
        let (input, rows) = recorded(&attempt);
        let value: Value = serde_json::from_slice(&input).unwrap();
        assert_eq!(value["selected"]["family"], "capture_upload17");
        assert_eq!(value["selected"]["data"].as_object().unwrap().len(), 16);
        read(&input, &rows).unwrap();

        // The original deliberately lacks a valid signed artifact/body. Failed
        // decoding retains that same real raw slot and cannot choose Capture.
        assert!(attempt.decode_body_data(65536).is_err());
        assert_eq!(attempt.original_data().unwrap(), &raw);
        assert!(attempt.capture_upload17_data().is_err());
        let (input, rows) = recorded(&attempt);
        read(&input, &rows).unwrap();
    }
}

#[test]
fn wrong_feature_does_not_fall_back_and_old_capture_reader_rejects_upload_roster() {
    let mut raw = original(Method::BlobBegin);
    raw.extensions.clear();
    raw.extensions
        .insert(RESTORED_SETTLED_CAPTURE_FEATURE.into(), Value::Null);
    let mut attempt = NativeRestoredSettledActionAttempt::new_data(1);
    assert!(attempt.retain_original_data(raw.clone()).is_err());
    assert_eq!(attempt.original_data().unwrap(), &raw);
    assert!(attempt.selected.is_none());
    assert!(attempt.failed);

    let mut upload = NativeRestoredSettledActionAttempt::new_data(1);
    upload
        .retain_original_data(original(Method::BlobBegin))
        .unwrap();
    let (input, rows) = recorded(&upload);
    read(&input, &rows).unwrap();
    let changed = String::from_utf8(input).unwrap().replacen(
        "\"family\":\"capture_upload17\"",
        "\"family\":\"capture\"",
        1,
    );
    assert!(read(changed.as_bytes(), &rows).is_err());
    // Replacing a discriminator is a DATA mutation, never a way to obtain the
    // absent final Capture registration/confirmation or native completion.
    assert!(upload.capture_data().is_err());
    assert_eq!(json!(upload.decoded), false);
}
