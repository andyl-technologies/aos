//! Exact canonical bytes, original scratch lifetime and hostile segment extents.

use super::*;
use crate::EngineError;

fn origin() -> Result<crate::test_support::FixtureDecodeScope, EngineError> {
    crate::test_support::fixture_decode_scope(64 * 1024)
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })
}

#[test]
fn borrowed_payload_preserves_hex_unicode_and_key_order() -> Result<(), EngineError> {
    let _origin = origin()?;
    let payload = EventPayload::new(
        "k",
        BTreeMap::from([
            (
                String::from("z"),
                EventAttributeValue::String(String::from("é")),
            ),
            (String::from("b"), EventAttributeValue::Bytes(vec![0, 255])),
            (String::from("a"), EventAttributeValue::Bool(true)),
        ]),
    );
    let expected = "p.kind_len=1\np.kind=k\np.attributes=3\np.attribute.a.name_len=1\np.attribute.a.name=a\np.attribute.a.value.type=bool\np.attribute.a.value.value=true\np.attribute.b.name_len=1\np.attribute.b.name=b\np.attribute.b.value.type=bytes\np.attribute.b.value.len=2\np.attribute.b.value.value=00ff\np.attribute.z.name_len=1\np.attribute.z.name=z\np.attribute.z.value.type=string\np.attribute.z.value.len=2\np.attribute.z.value.value=é";

    assert_eq!(event_payload_material("p", &payload).to_string(), expected);
    assert_eq!(
        crate::model::hash_canonical_display("test", &event_payload_material("p", &payload))?,
        ContentHash::from_canonical_material("test", expected)
    );
    assert_eq!(
        crate::model::canonical_display_len(&event_payload_material("p", &payload))?,
        expected.len()
    );
    Ok(())
}

#[test]
fn diagnostic_override_matches_owned_payload_without_copying_details() -> Result<(), EngineError> {
    let _origin = origin()?;
    for details in [
        BTreeMap::new(),
        BTreeMap::from([
            (String::from("name"), EventAttributeValue::U64(99)),
            (String::from("a"), EventAttributeValue::Bool(false)),
            (String::from("z"), EventAttributeValue::Bytes(vec![0, 255])),
        ]),
        BTreeMap::from([(String::from("z"), EventAttributeValue::U64(7))]),
    ] {
        let diagnostic = EventDiagnosticPayload::new("é\nname", EventLevel::Warn, details);
        let expected_payload = diagnostic.event_payload();

        assert_eq!(
            diagnostic_event_payload_material(&diagnostic).to_string(),
            event_payload_material("diagnostic.event_payload", &expected_payload).to_string()
        );
    }
    Ok(())
}

#[test]
fn recursive_action_prefixes_preserve_canonical_bytes() -> Result<(), EngineError> {
    let _origin = origin()?;
    let action = Action::Group(vec![
        Action::Pass,
        Action::Group(vec![Action::Log {
            level: LogLevel::Warn,
            message: String::from("é\nx"),
        }]),
    ]);
    let expected = "action.kind=group\naction.actions=2\naction.action.0.kind=pass\naction.action.1.kind=group\naction.action.1.actions=1\naction.action.1.action.0.kind=log\naction.action.1.action.0.level=warn\naction.action.1.action.0.message_len=4\naction.action.1.action.0.message=é\nx";

    assert_eq!(
        trigger_action_material("action", &action).to_string(),
        expected
    );
    Ok(())
}

#[test]
fn repeated_borrowed_hashing_releases_original_scratch_credit() -> Result<(), EngineError> {
    let origin = origin()?;
    let retained = origin.retained_bytes();
    let payload = EventPayload::new("kind", BTreeMap::new());
    let material = event_payload_material("p", &payload);

    for _ in 0..2048 {
        let _hash = crate::model::hash_canonical_display("test", &material)?;
        let _length = crate::model::canonical_display_len(&material)?;
        assert_eq!(origin.retained_bytes(), retained);
    }
    Ok(())
}

#[test]
fn impossible_segment_count_refuses_before_array_allocation() {
    use super::super::event_codec::{
        SchedulerEventLogSegmentDecodeError, decode_scheduler_event_log_segment,
    };
    let _origin = origin().unwrap();
    let mut bytes = Vec::from(EVENT_LOG_SEGMENT_BINARY_MAGIC.as_slice());
    bytes.extend_from_slice(&EVENT_LOG_SEGMENT_BINARY_VERSION.to_le_bytes());
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());

    assert!(matches!(
        decode_scheduler_event_log_segment(&bytes),
        Err(
            SchedulerEventLogSegmentDecodeError::Truncated { field: "entries" }
                | SchedulerEventLogSegmentDecodeError::LengthTooLarge {
                    field: "entries",
                    ..
                }
        )
    ));
}
