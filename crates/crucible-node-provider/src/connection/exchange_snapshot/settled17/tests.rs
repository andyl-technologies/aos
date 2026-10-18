//! Exercises retained raw/typed disagreement and exact bank-capacity checks.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};
use crucible_node_contract::{HashRef, U64};

#[test]
fn retained_frame_keeps_independent_raw_and_typed_request_data() -> Result<(), ProviderError> {
    let mut envelope = crate::envelope::tests::request();
    envelope.method = crate::envelope::Method::Retire;
    let mut raw_text = String::with_capacity(79);
    raw_text.push_str("raw map retained independently");
    envelope
        .body
        .insert("raw_only".into(), serde_json::Value::String(raw_text));
    let mut algorithm = String::with_capacity(47);
    algorithm.push_str("blake3");
    let typed = ObserveRequest {
        binding_hash: HashRef {
            algorithm,
            domain: "owner-binding".into(),
            digest: "partial-history".into(),
        },
        owner_generation: U64::new(3),
        after_observation_sequence: U64::new(8),
        maximum_items: U64::new(11),
        extensions: Default::default(),
    };
    let frame = ReceivedFrame {
        envelope,
        body: ReceivedBody::Request(Box::new(RequestBody::Observe(typed))),
    };
    let input = serde_json::to_vec(&frame.borrowed_settled17_data())
        .map_err(crucible_node_contract::ContractError::from)?;
    let mut records = MetadataRecordBank::reserve(512)?;
    let mut observer = MetadataObserver::recording(&mut records);
    frame.observe_settled17_metadata(&mut observer)?;
    let facts = observer.finish();
    let encoded_records =
        serde_json::to_vec(&records).map_err(crucible_node_contract::ContractError::from)?;
    let backing = facts.string_capacity_bytes + facts.vector_capacity_bytes;
    let rows =
        ValidatedMetadataRecords::validate(&encoded_records, facts.capacity_records, backing)?;
    let limits = HistoricalJsonLimits {
        maximum_input_bytes: input.len() + 128,
        maximum_nodes: 4096,
        maximum_depth: 64,
        maximum_owned_backing_bytes: backing,
        maximum_tree_entries: 512,
    };

    let mut borrowed = Ledger::new(rows.rows(), limits);
    assert!(
        borrowed
            .read::<HistoricalReceivedFrame17>(&input, false)?
            .is_none()
    );
    assert!(borrowed.rows.next().is_none());
    let mut build = Ledger::new(rows.rows(), limits);
    let decoded = build
        .read::<HistoricalReceivedFrame17>(&input, true)?
        .ok_or_else(invalid)?;
    assert!(build.rows.next().is_none());

    assert_eq!(decoded.envelope, frame.envelope);
    assert_eq!(decoded.envelope.method, crate::envelope::Method::Retire);
    let ReceivedBody::Request(body) = decoded.body else {
        return Err(invalid());
    };
    let RequestBody::Observe(body) = *body else {
        return Err(invalid());
    };
    assert_eq!(body.binding_hash.algorithm.capacity(), 47);
    assert_eq!(body.maximum_items, U64::new(11));
    let text = std::str::from_utf8(&input).map_err(|_| invalid())?;
    let changed = text.replacen("\"Observe\"", "\"UnknownTypedCache\"", 1);
    let mut malformed = Ledger::new(rows.rows(), limits);
    assert!(
        malformed
            .read::<HistoricalReceivedFrame17>(changed.as_bytes(), false)
            .is_err()
    );
    Ok(())
}
