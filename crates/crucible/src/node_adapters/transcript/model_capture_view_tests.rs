//! Inert model inspection controls, separate from actual capture qualification.

use super::*;

fn fixture() -> Result<InputPayload, TranscriptError> {
    let cursor = crate::node_adapters::transcript::tests::tape2_models::input_model_cursor();
    let original = &cursor.source.data.origin;
    let binding_object = original
        .context
        .iter()
        .find(|object| object.reference == original.source_binding)
        .ok_or_else(|| invalid("synthetic binding absent"))?;
    let binding = serde_json::from_slice(&binding_object.bytes).map_err(invalid)?;
    let wire = Tape2ContinuationWire {
        schema_version: 2,
        runtime: canonical::content_ref(
            b"inert-runtime7",
            crate::node_state::ORIGINAL_LINEAGE_RUNTIME_MEDIA,
        )
        .map_err(invalid)?,
        route: original.route.clone(),
        binding,
        cursor: cursor.snapshot(),
        boundary: original.activation.boundary,
        transcript: cursor.source.reference().clone(),
        qualification: canonical::content_ref(b"inert-qualification", "application/json")
            .map_err(invalid)?,
        operation_evidence: Vec::new(),
        observations: Vec::new(),
        custody_objects: Vec::new(),
    };
    object(serde_json::to_value(wire).map_err(invalid)?)
}

fn object(value: serde_json::Value) -> Result<InputPayload, TranscriptError> {
    let bytes = canonical::canonical_json(&value).map_err(invalid)?;
    let reference = canonical::content_ref(&bytes, "application/json").map_err(invalid)?;
    Ok(InputPayload { reference, bytes })
}

#[test]
fn selected_capture_view_preserves_complete_reference_only_roles() -> Result<(), TranscriptError> {
    let original = fixture()?;
    let view = decode_original_lineage_model_capture(&original, original.bytes.len())?;
    assert_eq!(
        view.runtime().media_type,
        crate::node_state::ORIGINAL_LINEAGE_RUNTIME_MEDIA
    );
    assert_eq!(&view.cursor().transcript, view.transcript());
    assert!(!view.route().owners.is_empty());
    assert!(view.operation_evidence().next().is_none());
    assert!(view.observations().is_empty());
    assert!(view.custody_objects().is_empty());
    assert!(decode_original_lineage_model_capture(&original, original.bytes.len() - 1).is_err());
    Ok(())
}

#[test]
fn selected_capture_view_refuses_unsupported_open_and_excess_rows() -> Result<(), TranscriptError> {
    let original = fixture()?;
    for mutation in 0..3 {
        let mut value = canonical::parse_json(&original.bytes, MAXIMUM_BYTES).map_err(invalid)?;
        match mutation {
            0 => value["schema_version"] = serde_json::json!(1),
            1 => value["undeclared"] = serde_json::Value::Null,
            _ => {
                value["custody_objects"] =
                    serde_json::Value::Array(vec![value["runtime"].clone(); MAXIMUM_ROWS + 1])
            }
        }
        assert!(decode_original_lineage_model_capture(&object(value)?, MAXIMUM_BYTES).is_err());
    }
    Ok(())
}
