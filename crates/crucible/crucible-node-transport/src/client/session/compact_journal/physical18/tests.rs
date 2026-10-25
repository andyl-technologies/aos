//! Checks whole-history preservation and refusal at the public DATA boundary.

use super::super::tests::{BANK_BYTES, TestResult, fixture};
use super::*;
use crate::client::compact_cursor::CompactContentLimits;
use crate::client::compact_metadata8::CompactMetadata8Limits;
use crate::connection::{ReceivedBody, ReceivedFrame};
use crate::envelope::{Method, RequestOrigin};
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crucible_node_format::{Id, U64};
use serde_json::{Value, json};

fn limits(input: &[u8]) -> CompactCustody18Limits {
    CompactCustody18Limits {
        maximum_input_bytes: input.len(),
        maximum_capacity_rows: 4096,
        maximum_backing_capacity_bytes: 16 * 1024 * 1024,
        maximum_envelope_bank_bytes: BANK_BYTES,
        json: HistoricalJsonLimits {
            maximum_input_bytes: input.len(),
            maximum_nodes: 65_536,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 16 * 1024 * 1024,
            maximum_tree_entries: 4096,
        },
        content: CompactMetadata8Limits {
            content: CompactContentLimits {
                max_input_bytes: input.len(),
                max_rows: 16,
                max_groups: 16,
                max_first_group_capacity_bytes: 1024 * 1024,
            },
            maximum_metadata_capacity_bytes: 1024 * 1024,
        },
    }
}

fn capture(custody: &CompactClientCustody) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut records = MetadataRecordBank::reserve(4096)?;
    Ok(serde_json::to_vec(
        &custody.physical_custody18_data(&mut records)?,
    )?)
}

pub(in crate::client::session::compact_journal) fn roundtrip(
    custody: &CompactClientCustody,
) -> Result<HistoricalCompactCustody18, Box<dyn std::error::Error>> {
    let encoded = capture(custody)?;
    let historical = HistoricalCompactCustody18::decode(&encoded, limits(&encoded))?;
    let mut records = MetadataRecordBank::reserve(4096)?;
    assert_eq!(
        serde_json::to_vec(&historical.physical_data(&mut records)?)?,
        encoded
    );
    assert_eq!(
        historical.retained_metadata_facts()?,
        custody.retained_metadata_facts()?
    );
    Ok(historical)
}

#[test]
fn empty_history_preserves_nonrenewing_limits() -> TestResult {
    let (_lease, _session, custody, _peer, _request) = fixture(BANK_BYTES);
    let historical = roundtrip(&custody)?;
    assert_eq!(
        historical.journal_limits_data(),
        [8, 262_144, 0, BANK_BYTES]
    );
    Ok(())
}

#[test]
fn both_namespaces_preserve_complete_banks_and_independent_identity_capacity() -> TestResult {
    let (_lease, _session, mut custody, _peer, mut request) = fixture(BANK_BYTES);
    request.body.insert(
        "variants".into(),
        json!([u64::MAX, i64::MIN, -0.0, f64::from_bits(1), "雪"]),
    );
    let mut key = String::with_capacity(513);
    key.push_str("same-original");
    let id = Id::new(key)?;
    request.request_id.0 = Some(id.clone());

    for origin in [RequestOrigin::Controller, RequestOrigin::Provider] {
        custody.retain_request(origin, &request, 0, 65_536)?;
        let retained = custody.journal_mut(origin).get_mut(&id).unwrap();
        retained.identity.algorithm.reserve(517);
        retained.identity.domain.reserve(521);
        retained.identity.digest.reserve(523);
        let mut response = request.clone();
        response.sequence = U64::new(19);
        response.message = crate::envelope::MessageKind::Response;
        custody.hold(origin, response)?;
        custody.complete_response(&id)?;
        let retained = custody.journal_mut(origin).remove(&id).unwrap();
        let mut key = String::with_capacity(1021);
        key.push_str(id.as_str());
        custody.journal_mut(origin).insert(Id::new(key)?, retained);
    }

    let charged = custody.retained_bytes;
    let historical = roundtrip(&custody)?;
    assert_eq!(historical.journal_limits_data()[2], charged);
    for origin in [RequestOrigin::Controller, RequestOrigin::Provider] {
        let source = custody.original(origin, &id).unwrap();
        let decoded = historical.original_data(origin, &id).unwrap();
        assert_eq!(decoded.identity(), source.identity());
        assert_eq!(decoded.materialize_request()?, request);
        assert!(decoded.has_response());
        assert_eq!(decoded.retained_bank_bytes(), source.retained_bank_bytes());
    }
    Ok(())
}

#[test]
fn pending_and_quarantined_populations_preserve_spares_and_float_bits() -> TestResult {
    use crate::bodies::{NotificationBody, OperationState};
    let (_lease, _session, mut custody, _peer, mut envelope) = fixture(BANK_BYTES);
    envelope.protocol.reserve(1024);
    let mut array = Vec::with_capacity(131);
    array.extend([json!(-0.0), json!(f64::from_bits(1)), json!(u64::MAX)]);
    let mut text = String::with_capacity(512);
    text.push_str("independent data");
    envelope.body.insert("array".into(), Value::Array(array));
    envelope.body.insert("text".into(), Value::String(text));
    let mut raw = envelope.clone();
    custody.hold(RequestOrigin::Provider, envelope)?;
    raw.protocol.reserve(2048);
    let typed = NotificationBody {
        operation_state: OperationState::Unknown,
        last_observation_sequence: U64::new(u64::MAX),
        details: json!({"different": [false, -0.0, "typed"]})
            .as_object()
            .unwrap()
            .clone(),
        extensions: Default::default(),
    };
    custody.unexpected = Some(ReceivedFrame {
        envelope: raw,
        body: ReceivedBody::Notification(Box::new(typed)),
    });

    let historical = roundtrip(&custody)?;
    assert_eq!(
        historical.pending_envelope_data(),
        custody.pending_envelope()
    );
    assert!(matches!(
        &historical.unexpected_frame_data().unwrap().body,
        ReceivedBody::Notification(_)
    ));
    Ok(())
}

#[test]
fn bootstrap_vocabulary_is_explicit_and_invalid_typed_funding_remains_data() -> TestResult {
    use crate::reference_packet::service::{
        complete_restore::import18::bootstrap_ack::*,
        native_startup::PacketNativeStartupAllocationRow,
    };
    use crucible_node_format::Bytes;
    let (_lease, _session, mut custody, _peer, mut envelope) = fixture(BANK_BYTES);
    envelope.method = Method::NativeImport18Bootstrap;
    let typed = PacketNativeImport18BootstrapRequest {
        schema: "invalid saved prefix".into(),
        recipe_identity: Bytes::new(vec![1; 7]),
        initial_funding: PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(u64::MAX),
            maximum_simultaneous_transient_bytes: U64::new(u64::MAX),
            declared_counter_scratch_bytes: U64::new(u64::MAX),
        },
    };
    assert!(typed.validate_data().is_err());
    custody.unexpected = Some(ReceivedFrame {
        envelope,
        body: ReceivedBody::NativeImport18Bootstrap(Box::new(
            PacketNativeImport18BootstrapReceivedBody::Request(typed),
        )),
    });

    let historical = roundtrip(&custody)?;
    let ReceivedBody::NativeImport18Bootstrap(body) =
        &historical.unexpected_frame_data().unwrap().body
    else {
        panic!("lost typed body");
    };
    let PacketNativeImport18BootstrapReceivedBody::Request(request) = body.as_ref() else {
        panic!("changed typed body");
    };
    assert!(request.validate_data().is_err());
    assert_eq!(
        request.initial_funding.retained_requested_bytes.get(),
        u64::MAX
    );

    // The same newer method must remain outside the old11 envelope vocabulary.
    let envelope = &historical.unexpected_frame_data().unwrap().envelope;
    let mut records = MetadataRecordBank::reserve(4096)?;
    let mut observer = MetadataObserver::recording(&mut records);
    observer.observe(envelope)?;
    let encoded_rows = serde_json::to_vec(records.rows())?;
    let rows = ValidatedMetadataRecords::validate(&encoded_rows, 4096, 1024 * 1024)?;
    let encoded = serde_json::to_vec(envelope)?;
    assert!(
        crate::protocol_snapshot::owned11::envelope::ValidatedHistoricalEnvelope::validate(
            &encoded,
            rows.rows(),
            limits(&encoded).json
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn whole_history_refuses_truncations_editions_rows_and_short_restrictions() -> TestResult {
    let (_lease, _session, mut custody, _peer, request) = fixture(BANK_BYTES);
    custody.retain_request(RequestOrigin::Controller, &request, 0, 65_536)?;
    let encoded = capture(&custody)?;
    let bound = limits(&encoded);
    for end in 0..encoded.len() {
        assert!(
            HistoricalCompactCustody18::decode(&encoded[..end], bound).is_err(),
            "accepted prefix {end}"
        );
    }
    let mut short = bound;
    short.maximum_input_bytes = encoded.len() - 1;
    assert!(HistoricalCompactCustody18::decode(&encoded, short).is_err());

    let value: Value = serde_json::from_slice(&encoded)?;
    let rows_encoded = serde_json::to_vec(&value[3])?;
    let rows = ValidatedMetadataRecords::validate(&rows_encoded, 4096, usize::MAX)?;
    let mut exact = bound;
    exact.maximum_capacity_rows = rows.row_count();
    exact.maximum_backing_capacity_bytes = rows.backing_capacity_bytes();
    HistoricalCompactCustody18::decode(&encoded, exact)?;
    short = exact;
    short.maximum_capacity_rows -= 1;
    assert!(HistoricalCompactCustody18::decode(&encoded, short).is_err());
    short = exact;
    short.maximum_backing_capacity_bytes -= 1;
    assert!(HistoricalCompactCustody18::decode(&encoded, short).is_err());

    // Replace only the array roster, preserving every struct field's original
    // serialization order in the nonempty journal surrounding it.
    let source = std::str::from_utf8(&encoded)?;
    let original_rows = std::str::from_utf8(&rows_encoded)?;
    for index in [0, 2] {
        for change in [-1i64, 1] {
            let mut changed = value[3].clone();
            let extent = changed[index][1].as_i64().unwrap();
            changed[index][1] = json!(extent + change);
            let changed_rows = serde_json::to_string(&changed)?;
            let changed = source.replacen(original_rows, &changed_rows, 1);
            assert_ne!(changed.as_bytes(), encoded);
            assert!(
                HistoricalCompactCustody18::decode(changed.as_bytes(), limits(changed.as_bytes()))
                    .is_err()
            );
        }
    }

    // Empty maps keep this mutation fixture free of struct-ordered JSON
    // objects; serializing Value must not independently reorder a HashRef.
    let (_empty_lease, _empty_session, empty, _empty_peer, _empty_request) = fixture(BANK_BYTES);
    let value: Value = serde_json::from_slice(&capture(&empty)?)?;
    let reject = |changed: Value| -> TestResult {
        let encoded = serde_json::to_vec(&changed)?;
        assert!(HistoricalCompactCustody18::decode(&encoded, limits(&encoded)).is_err());
        Ok(())
    };
    for index in [0, 1] {
        let mut changed = value.clone();
        changed[index] = json!("another/17");
        reject(changed)?;
    }
    for (field, number) in [(0, 0), (0, 4097), (2, 262_145), (3, 0), (3, BANK_BYTES + 1)] {
        let mut changed = value.clone();
        changed[2][field] = json!(number);
        reject(changed)?;
    }
    for index in 0..value[3].as_array().unwrap().len() {
        for column in [2, 3] {
            let mut changed = value.clone();
            let previous = changed[3][index][column].as_u64().unwrap();
            changed[3][index][column] = json!(previous * 2);
            reject(changed)?;
        }
    }
    let mut changed = value.clone();
    changed[3]
        .as_array_mut()
        .unwrap()
        .push(json!(["string", 0, 1, 1]));
    reject(changed)?;
    let mut changed = value;
    changed[2].as_array_mut().unwrap().push(Value::Null);
    reject(changed)?;
    Ok(())
}

#[test]
fn record_capture_refusal_preserves_original_credit_and_partial_caller_bank() -> TestResult {
    let (_lease, _session, mut custody, _peer, request) = fixture(BANK_BYTES);
    custody.retain_request(RequestOrigin::Controller, &request, 0, 65_536)?;
    let charge = custody.retained_bytes;
    let mut records = MetadataRecordBank::reserve(1)?;

    assert!(custody.physical_custody18_data(&mut records).is_err());
    assert_eq!(records.rows().len(), 1);
    assert_eq!(custody.retained_bytes, charge);
    assert_eq!(custody.originals().count(), 1);
    roundtrip(&custody)?;
    Ok(())
}
