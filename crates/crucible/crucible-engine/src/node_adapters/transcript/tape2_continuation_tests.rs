//! Checks inert codec selection and future-prefix guards without native authority.

use super::*;

fn fixture() -> Result<(Tape2ContinuationWire, AuthenticatedTranscript), OperationFailure> {
    let cursor = crate::node_adapters::transcript::tests::tape2_models::input_model_cursor();
    let original = &cursor.source.data.origin;
    let object = original
        .context
        .iter()
        .find(|object| object.reference == original.source_binding)
        .ok_or_else(|| refused("synthetic binding absent"))?;
    let binding =
        serde_json::from_slice(&object.bytes).map_err(|error| refused(error.to_string()))?;
    let runtime = canonical::content_ref(
        b"inert-runtime7",
        crate::node_state::ORIGINAL_LINEAGE_RUNTIME_MEDIA,
    )
    .map_err(|error| refused(error.to_string()))?;
    let qualification = canonical::content_ref(b"inert-qualification", "application/json")
        .map_err(|error| refused(error.to_string()))?;
    Ok((
        Tape2ContinuationWire {
            schema_version: 2,
            runtime,
            route: original.route.clone(),
            binding,
            cursor: cursor.snapshot(),
            boundary: original.activation.boundary,
            transcript: cursor.source.reference().clone(),
            qualification,
            operation_evidence: Vec::new(),
            observations: Vec::new(),
            custody_objects: Vec::new(),
        },
        cursor.source,
    ))
}

#[test]
fn tape2_continuation_prefix_never_releases_future_input_metadata() -> Result<(), OperationFailure>
{
    let (mut wire, tape) = fixture()?;
    assert!(checked_records(&wire, &tape)?.is_empty());
    wire.cursor.next_record = 1.into();
    assert_eq!(checked_records(&wire, &tape)?.len(), 1);
    wire.cursor.next_record = (tape.data.records.len() as u64 + 1).into();
    assert!(checked_records(&wire, &tape).is_err());
    Ok(())
}

#[test]
fn tape2_continuation_changed_context_and_foreign_node_refuse() -> Result<(), OperationFailure> {
    let (wire, tape) = fixture()?;
    let mut changed = wire.clone();
    changed.cursor.source_context = canonical::content_ref(b"foreign-context", "application/json")
        .map_err(|error| refused(error.to_string()))?;
    assert!(checked_records(&changed, &tape).is_err());
    let mut foreign = wire;
    foreign.route.node = Id::new("foreign/consumer").map_err(|error| refused(error.to_string()))?;
    assert!(checked_records(&foreign, &tape).is_err());
    Ok(())
}

#[test]
fn tape2_continuation_schema_is_distinct_and_runtime_reference_required()
-> Result<(), OperationFailure> {
    let (wire, _tape) = fixture()?;
    let selected = original_lineage_continuation_schema()?;
    assert_eq!(selected.version, 2);
    assert_ne!(
        selected,
        crate::node_adapters::transcript::transcript_replay_continuation_schema()?
    );
    let mut value = serde_json::to_value(&wire).map_err(|error| refused(error.to_string()))?;
    assert_eq!(
        value["runtime"],
        serde_json::to_value(&wire.runtime).map_err(|error| refused(error.to_string()))?
    );
    let object = value
        .as_object_mut()
        .ok_or_else(|| refused("synthetic wire is not object"))?;
    object.remove("runtime");
    assert!(serde_json::from_value::<Tape2ContinuationWire>(value.clone()).is_err());
    let object = value
        .as_object_mut()
        .ok_or_else(|| refused("synthetic wire is not object"))?;
    object.insert(
        "runtime".into(),
        serde_json::to_value(&wire.runtime).map_err(|error| refused(error.to_string()))?,
    );
    object.insert("first_scope".into(), serde_json::Value::Null);
    assert!(serde_json::from_value::<Tape2ContinuationWire>(value).is_err());
    Ok(())
}
