//! Checks selected shape accounting without manufacturing a validated SDK owner.

use super::*;
use crate::retained_metadata::{
    MetadataObserver, requested_storage::requested_metadata_backing_storage_data,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const MAXIMUM: usize = 256 * 1024 * 1024;

#[test]
fn concrete_envelope_and_typed_vector_backing_fit_the_shape_pool() -> TestResult {
    let mut envelope = crate::handshake::tests::original_hello_envelope();
    envelope.body.insert(
        "raw".to_owned(),
        serde_json::json!({
            "escaped": "\u{0000}\n\"\\𝄞",
            "nested": [{"values": [0, 1, 2]}, [], ""],
        }),
    );
    let ids = (0..65)
        .map(|index| Id::new(format!("participant-{index:03}")))
        .collect::<Result<Vec<_>, _>>()?;
    let references = vec![canonical::content_ref(b"typed field", "application/json")?; 65];
    let bytes = crucible_node_contract::Bytes::new((0..=255).collect());
    let value = serde_json::json!({
        "envelope": envelope, "ids": ids, "references": references, "bytes": bytes,
    });
    let admitted = typed_backing_data(&value, 0)?;

    let envelope: Envelope = read(&value["envelope"])?;
    let ids: Vec<Id> = read(&value["ids"])?;
    let references: Vec<ContentRef> = read(&value["references"])?;
    let bytes: crucible_node_contract::Bytes = read(&value["bytes"])?;
    let mut observer = MetadataObserver::new();
    observer.observe(&envelope)?;
    observer.observe(&ids)?;
    observer.observe(&references)?;
    observer.observe(&bytes)?;
    let actual = requested_metadata_backing_storage_data(&observer.finish())?;
    assert!(actual <= admitted);
    assert_eq!(bytes.as_slice().len(), 256);
    assert!(maximum_array_element_data() >= size_of::<ContentRef>());
    assert!(maximum_array_element_data() >= size_of::<(SerdeContent, SerdeContent)>());
    Ok(())
}

#[test]
fn sequential_rows_use_a_peak_and_unrelated_controller_payload_is_excluded() -> TestResult {
    let mut root = selected_shapes();
    let baseline = selected_work_data(root.as_object().ok_or_else(invalid)?, MAXIMUM)?;
    // Only the selected field shapes are supplied here. This is a counter test,
    // not an SDK history fixture or an accepted historical pair.
    root["unrelated-payload"] = serde_json::json!("x".repeat(100_000));
    let rows = root["capture"]["auxiliary_uploads"][0]["completed"]
        .as_array_mut()
        .ok_or_else(invalid)?;
    let chunk = rows[1].clone();
    for _ in 0..16 {
        rows.insert(1, chunk.clone());
    }
    assert_eq!(
        selected_work_data(root.as_object().ok_or_else(invalid)?, MAXIMUM)?,
        baseline
    );
    assert_eq!(
        selected_work_data(root.as_object().ok_or_else(invalid)?, baseline)?,
        baseline
    );
    assert!(selected_work_data(root.as_object().ok_or_else(invalid)?, baseline - 1).is_err());
    Ok(())
}

#[test]
fn independent_journal_and_dictionary_references_are_priced_before_comparison() -> TestResult {
    let mut root = selected_shapes();
    let baseline = selected_work_data(root.as_object().ok_or_else(invalid)?, MAXIMUM)?;
    root["custody"][3]["capture"]["identity"] = serde_json::json!({"digest": "x".repeat(8192)});
    let identity = selected_work_data(root.as_object().ok_or_else(invalid)?, MAXIMUM)?;
    assert!(identity > baseline);
    root["custody"][5][1][6] = serde_json::json!([
        ["digest", {"media_type": "x".repeat(8192)}, null, null, null]
    ]);
    assert!(selected_work_data(root.as_object().ok_or_else(invalid)?, MAXIMUM)? > identity);
    Ok(())
}

#[test]
fn another_family_or_nonempty_final_poll_refuses_before_a_typed_constructor() -> TestResult {
    let mut root = selected_shapes();
    root["capture"]["decoded"]["result"]["kind"] = serde_json::json!("observe");
    assert!(selected_work_data(root.as_object().ok_or_else(invalid)?, MAXIMUM).is_err());
    let mut root = selected_shapes();
    root["capture"]["confirmation"]["terminal"]["body"]["result"]["observations"] =
        serde_json::json!([{}]);
    assert!(selected_work_data(root.as_object().ok_or_else(invalid)?, MAXIMUM).is_err());
    assert!(grow_data(usize::MAX, size_of::<ContentRef>()).is_err());
    Ok(())
}

#[test]
fn selected_retained_owner_ignores_upload_payloads_and_has_an_exact_ceiling() -> TestResult {
    let mut root = selected_shapes();
    let baseline = selected_retained_data(root.as_object().ok_or_else(invalid)?, MAXIMUM)?;
    root["capture"]["auxiliary_uploads"][0]["completed"][1]["body"] =
        serde_json::json!({"data": "x".repeat(100_000)});
    assert_eq!(
        selected_retained_data(root.as_object().ok_or_else(invalid)?, MAXIMUM)?,
        baseline
    );
    assert_eq!(
        selected_retained_data(root.as_object().ok_or_else(invalid)?, baseline)?,
        baseline
    );
    assert!(selected_retained_data(root.as_object().ok_or_else(invalid)?, baseline - 1).is_err());

    root["capture"]["canonical"] = serde_json::json!([1, 256]);
    assert!(selected_retained_data(root.as_object().ok_or_else(invalid)?, MAXIMUM).is_err());
    root["capture"]["canonical"] = serde_json::json!([1, "2"]);
    assert!(selected_retained_data(root.as_object().ok_or_else(invalid)?, MAXIMUM).is_err());
    Ok(())
}

#[test]
fn selected_retained_bound_covers_independently_decoded_output_field_owners() -> TestResult {
    let mut root = selected_shapes();
    let mut original = crate::handshake::tests::original_hello_envelope();
    original.method = Method::Begin;
    original.body.insert(
        "retained".to_owned(),
        serde_json::json!({
            "escapes": "\u{0000}\n\"\\𝄞", "array": [{}, [], ""],
        }),
    );
    root["capture"]["original"] = serde_json::to_value(&original)?;
    root["capture"]["terminal"] = serde_json::to_value(&original)?;
    original.method = Method::Poll;
    root["capture"]["confirmation"]["original"] = serde_json::to_value(&original)?;
    original
        .body
        .insert("result".to_owned(), serde_json::json!({"observations": []}));
    root["capture"]["confirmation"]["terminal"] = serde_json::to_value(&original)?;
    let ids = (0..65)
        .map(|index| Id::new(format!("participant-{index:03}")))
        .collect::<Result<Vec<_>, _>>()?;
    let references = vec![canonical::content_ref(b"typed output field", "application/json")?; 65];
    root["capture"]["request"]["capture"]["participant_ids"] = serde_json::to_value(&ids)?;
    root["capture"]["context"]["request"]["capture"]["participant_ids"] =
        serde_json::to_value(&ids)?;
    root["capture"]["artifact"]["request"]["capture"]["participant_ids"] =
        serde_json::to_value(&ids)?;
    root["capture"]["decoded"]["result"]["data"]["owner_state_refs"] =
        serde_json::to_value(&references)?;
    let canonical_original = canonical::canonical_json(&root["capture"]["original"])?;
    root["capture"]["canonical"] = serde_json::to_value(&canonical_original)?;
    let admitted = selected_retained_data(root.as_object().ok_or_else(invalid)?, MAXIMUM)?;

    let mut observer = MetadataObserver::new();
    for envelope in [
        &root["capture"]["original"],
        &root["capture"]["terminal"],
        &root["capture"]["confirmation"]["original"],
        &root["capture"]["confirmation"]["terminal"],
    ] {
        observer.observe(&read::<Envelope>(envelope)?)?;
    }
    for _ in 0..3 {
        observer.observe(&read::<Vec<Id>>(&serde_json::to_value(&ids)?)?)?;
    }
    observer.observe(&read::<Vec<ContentRef>>(&serde_json::to_value(
        &references,
    )?)?)?;
    observer.observe(&read::<Vec<u8>>(&root["capture"]["canonical"])?)?;
    let actual = add_data(
        requested_metadata_backing_storage_data(&observer.finish())?,
        size_of::<ValidatedHistoricalRestoredSettledCapture17>(),
    )?;
    assert!(actual <= admitted);
    Ok(())
}

fn selected_shapes() -> Value {
    let mut capture = pair_shape("capture", "begin", "capture");
    for name in CAPTURE_FIELDS {
        if capture.get(name).is_none() {
            capture[name] = serde_json::json!({});
        }
    }
    capture["body"] = serde_json::json!({"kind": "capture"});
    capture["original"]["body"] = serde_json::json!({"kind": "capture"});
    capture["canonical"] = serde_json::json!([1, 2, 3]);
    capture["confirmation"] = pair_shape("confirmation", "poll", "poll");
    capture["confirmation"]["request"] = serde_json::json!({});
    capture["confirmation"]["receipt"] = serde_json::json!({});
    capture["request"] = serde_json::json!({"capture": {"participant_ids": []}});
    capture["context"] = serde_json::json!({"request": capture["request"]});
    capture["artifact"] = serde_json::json!({"request": capture["request"]});
    capture["decoded"]["result"]["data"]["owner_state_refs"] = serde_json::json!([]);
    let upload = serde_json::json!({
        "request": {}, "context": {}, "artifact": {}, "next_offset": "0",
        "maximum_chunk": "4096", "pending": null,
        "completed": [
            pair_shape("begin", "blob_begin", "blob_begin"),
            pair_shape("chunk", "blob_chunk", "blob_chunk"),
            pair_shape("finish", "blob_finish", "blob_finish"),
        ],
    });
    capture["auxiliary_uploads"] = serde_json::json!([upload, upload]);
    let journal = ["capture", "confirmation", "begin", "chunk", "finish"]
        .into_iter()
        .map(|id| (id.to_owned(), serde_json::json!({"identity": {}})))
        .collect::<Map<String, Value>>();
    serde_json::json!({
        "capture": capture, "node": "node", "execution_owner": "owner",
        "session": {"sequence": "3", "authority": {
            "session": "session", "incarnation": "incarnation", "limits": {},
        }},
        "custody": [null, null, null, journal, null,
            ["wrapper", [null, null, null, null, null, null, []], null, null]],
    })
}

fn pair_shape(id: &str, method: &str, result: &str) -> Value {
    serde_json::json!({
        "stage": "complete", "request_id": id, "frontier": "2",
        "original": {"method": method, "body": {}},
        "terminal": {"method": method, "body": {"result": {"observations": []}}},
        "decoded": {"result": {"kind": result, "data": {"observations": []}}},
        "body": {}, "continuation": null, "extension": {},
    })
}
