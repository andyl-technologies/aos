//! Checks prospective framing/demand against actual inert Control registrations.

use super::*;
use crate::envelope::Nullable;
use serde_json::json;

fn inputs() -> Result<(CaptureArguments, BeginRequest, Envelope), ProviderError> {
    let arguments = CaptureArguments {
        capture_id: Id::new("capture-1")?,
        participant_ids: vec![Id::new("node-1")?],
        cut_id: Id::new("cut-1")?,
        cut: Position::new(U64::new(50), U64::new(0), Phase::BoundaryControl),
        event_ordinal: U64::new(17),
        ordering_profile: "superdense-v1".into(),
        preservation_contract: Id::new("contract-1")?,
    };
    let begin = BeginRequest {
        kind: BeginKind::Capture,
        binding_hash: canonical::hash("cnp.owner-binding.v1", b"DATA")?,
        owner_generation: U64::new(1),
        activation_id: Nullable(Some(Id::new("activation-1")?)),
        world_generation: U64::new(1),
        arguments: serde_json::to_value(&arguments)
            .map_err(crucible_node_contract::ContractError::from)?
            .as_object()
            .ok_or_else(refused)?
            .clone(),
        extensions: Extensions::new(),
    };
    let mut original = crate::envelope::tests::request();
    original.method = Method::Begin;
    original.execution_owner_id = Nullable(None);
    original.capture_owner_id = Nullable(Some(Id::new("capture-owner-1")?));
    original.body = serde_json::to_value(&begin)
        .map_err(crucible_node_contract::ContractError::from)?
        .as_object()
        .ok_or_else(refused)?
        .clone();
    original
        .extensions
        .insert(RESTORED_SETTLED_CAPTURE_FEATURE.into(), Value::Null);
    Ok((arguments, begin, original))
}

fn unknown() -> Result<Map<String, Value>, ProviderError> {
    object(ResponseShape::Error {
        operation_state: OperationState::Unknown,
        error: ErrorRecord {
            code: "OUTCOME_UNKNOWN".into(),
            message: "original native Capture remains unresolved".into(),
            effect: EffectCertainty::Unknown,
            retryable: false,
            details: Map::new(),
        },
        extensions: Extensions::new(),
    })
}

#[test]
fn pending_view_matches_actual_four_field_registration_and_metadata_counts()
-> Result<(), ProviderError> {
    // The existing constructor owns real finite model/Control DATA. These tests
    // perform inert private map edits, never Source/native admission or effects.
    for reactive in [false, true] {
        let mut control =
            crate::reference_packet::control::native5::current_control17_fixture_data(reactive)?;
        let (arguments, begin, original) = inputs()?;
        let hash_quote =
            PacketControl::quote_pending_capture17_request_hash_data(&original, usize::MAX)?;
        let mut attempt = None;
        PacketControl::complete_pending_capture17_request_hash_into_data(
            &hash_quote,
            &mut attempt,
        )?;
        let attempt = attempt.as_ref().ok_or_else(refused)?;
        let projected = control.quote_pending_capture17_history_data(
            &original,
            &begin,
            &arguments,
            attempt,
            usize::MAX,
        )?;
        let old = serde_json::to_vec(&control.borrowed_restored_settled_history_data()?)
            .map_err(crucible_node_contract::ContractError::from)?;
        let mut before = MetadataObserver::new();
        control.observe_restored_settled_history_metadata_data(&mut before)?;
        let before = before.finish();
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let operation = original.operation_id.0.as_ref().ok_or_else(refused)?;
        let bytes = serde_json::to_vec(&ControlHistory(
            &control,
            false,
            Some(PendingCapture17Fields {
                id,
                operation,
                begin: &begin,
                hash: attempt.completed_data(&original)?,
            }),
        ))
        .map_err(crucible_node_contract::ContractError::from)?;
        assert_eq!(bytes.len(), projected.encoded_bytes_data());
        assert_eq!(
            serde_json::to_vec(&control.borrowed_restored_settled_history_data()?)
                .map_err(crucible_node_contract::ContractError::from)?,
            old
        );

        control.originals.insert(
            id.clone(),
            (
                attempt.completed_data(&original)?.clone(),
                PacketControlReply {
                    body: unknown()?,
                    evidence: Vec::new(),
                },
            ),
        );
        control.begins.insert(operation.clone(), begin.clone());
        control.begin_requests.insert(operation.clone(), id.clone());
        control.current_operation = Some(operation.clone());
        let actual = serde_json::to_vec(&control.borrowed_restored_settled_history_data()?)
            .map_err(crucible_node_contract::ContractError::from)?;
        let mut after = MetadataObserver::new();
        control.observe_restored_settled_history_metadata_data(&mut after)?;
        let after = after.finish();

        assert_eq!(actual.len(), projected.encoded_bytes_data());
        assert_eq!(
            serde_json::from_slice::<Value>(&actual)
                .map_err(crucible_node_contract::ContractError::from)?,
            serde_json::from_slice::<Value>(&bytes)
                .map_err(crucible_node_contract::ContractError::from)?
        );
        assert_eq!(
            after.capacity_records - before.capacity_records,
            projected.additional_capacity_records_data()?
        );
        assert_eq!(
            after.tree_entries - before.tree_entries,
            projected.additional_tree_entries_data()?
        );
        let mut old: Value =
            serde_json::from_slice(&old).map_err(crucible_node_contract::ContractError::from)?;
        let mut actual: Value =
            serde_json::from_slice(&actual).map_err(crucible_node_contract::ContractError::from)?;
        for field in ["originals", "begins", "begin_requests", "current_operation"] {
            old.as_object_mut().ok_or_else(refused)?.remove(field);
            actual.as_object_mut().ok_or_else(refused)?.remove(field);
        }
        assert_eq!(actual, old);
    }
    Ok(())
}

#[test]
fn ordered_merge_places_new_rows_before_between_and_after_actual_entries()
-> Result<(), ProviderError> {
    let existing = BTreeMap::from([
        (Id::new("d")?, Id::new("value-d")?),
        (Id::new("p")?, Id::new("value-p")?),
    ]);
    for key in ["a", "m", "z"] {
        let key = Id::new(key)?;
        let value = Id::new("new-value")?;
        let mut actual = existing.clone();
        actual.insert(key.clone(), value.clone());
        let projected = MergedMap {
            map: &existing,
            key: &key,
            value: &value,
        };
        assert_eq!(
            serde_json::to_vec(&projected).map_err(crucible_node_contract::ContractError::from)?,
            serde_json::to_vec(&actual).map_err(crucible_node_contract::ContractError::from)?
        );
    }
    Ok(())
}

#[test]
fn normative_hash_matches_original_and_refuses_changed_full_original() -> Result<(), ProviderError>
{
    let (_, _, original) = inputs()?;
    let storage = PacketControl::quote_pending_capture17_request_hash_data(&original, usize::MAX)?;
    let mut attempt = None;
    PacketControl::complete_pending_capture17_request_hash_into_data(&storage, &mut attempt)?;
    let complete = attempt.as_ref().ok_or_else(refused)?;
    assert_eq!(
        complete.completed_data(&original)?,
        &original.request_hash(RequestOrigin::Controller)?
    );
    let mut foreign = original.clone();
    assert!(complete.completed_data(&foreign).is_ok());
    foreign.sequence = U64::new(2);
    assert!(complete.completed_data(&foreign).is_err());
    assert!(
        PacketControl::complete_pending_capture17_request_hash_into_data(&storage, &mut attempt)
            .is_err()
    );
    Ok(())
}

#[test]
fn exact_extent_short_limit_and_changed_correspondence_are_refused() -> Result<(), ProviderError> {
    let mut control =
        crate::reference_packet::control::native5::current_control17_fixture_data(false)?;
    let (arguments, mut begin, original) = inputs()?;
    let storage = PacketControl::quote_pending_capture17_request_hash_data(&original, usize::MAX)?;
    let mut attempt = None;
    PacketControl::complete_pending_capture17_request_hash_into_data(&storage, &mut attempt)?;
    let attempt = attempt.as_ref().ok_or_else(refused)?;
    let projected = control.quote_pending_capture17_history_data(
        &original,
        &begin,
        &arguments,
        attempt,
        usize::MAX,
    )?;
    assert!(
        control
            .quote_pending_capture17_history_data(
                &original,
                &begin,
                &arguments,
                attempt,
                projected.encoded_bytes_data()
            )
            .is_ok()
    );
    assert!(
        control
            .quote_pending_capture17_history_data(
                &original,
                &begin,
                &arguments,
                attempt,
                projected.encoded_bytes_data() - 1
            )
            .is_err()
    );
    begin.world_generation = U64::new(2);
    assert!(
        control
            .quote_pending_capture17_history_data(
                &original,
                &begin,
                &arguments,
                attempt,
                usize::MAX
            )
            .is_err()
    );
    begin.world_generation = U64::new(1);
    control.current_operation = Some(Id::new("busy")?);
    assert!(
        control
            .quote_pending_capture17_history_data(
                &original,
                &begin,
                &arguments,
                attempt,
                usize::MAX
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn formatter_work_covers_typed_history_and_unknown_projection_uses_defining_shape()
-> Result<(), ProviderError> {
    let control = crate::reference_packet::control::native5::current_control17_fixture_data(false)?;
    assert!(control.pending_capture17_formatter_work_data()? >= 20);
    let mut projection = crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection::new(usize::MAX)?;
    super::super::super::observe_control_growth::unknown_capture(&mut projection)?;
    let projected = projection.finish(usize::MAX)?;
    let mut count = Count { bytes: 0 };
    serde_json::to_writer(&mut count, &UnknownCapture)
        .map_err(crucible_node_contract::ContractError::from)?;
    let actual = unknown()?;
    assert_eq!(
        serde_json::to_value(UnknownCapture)
            .map_err(crucible_node_contract::ContractError::from)?,
        Value::Object(actual)
    );
    assert!(count.bytes <= projected.maximum_encoded_bytes);
    Ok(())
}

#[test]
fn actual_control_formatter_demand_ignores_raw_vec_spare_capacity() -> Result<(), ProviderError> {
    let mut control =
        crate::reference_packet::control::native5::current_control17_fixture_data(false)?;
    let before = control.pending_capture17_formatter_work_data()?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(1_048_576).map_err(|_| exhausted())?;
    raw.extend_from_slice(b"actual raw Control content");
    let reference = canonical::content_ref(&raw, "application/octet-stream")?;
    control.content.insert(reference, raw);
    assert_eq!(control.pending_capture17_formatter_work_data()?, before);
    Ok(())
}

#[test]
fn extension_correspondence_matches_json_and_protocol_map_backends() {
    let object = json!({"first": {"nested": [1, 2]}, "last": false});
    let mut expected = Extensions::new();
    expected.insert("last".into(), json!(false));
    expected.insert("first".into(), json!({"nested": [1, 2]}));

    assert!(extensions_match_data(Some(&object), &expected));

    let mut changed = expected.clone();
    changed.insert("last".into(), json!(true));
    assert!(!extensions_match_data(Some(&object), &changed));
    changed = expected.clone();
    changed.remove("last");
    changed.insert("other".into(), json!(false));
    assert!(!extensions_match_data(Some(&object), &changed));
    assert!(!extensions_match_data(Some(&Value::Null), &expected));
    assert!(!extensions_match_data(None, &Extensions::new()));
    assert!(extensions_match_data(Some(&json!({})), &Extensions::new()));
}
