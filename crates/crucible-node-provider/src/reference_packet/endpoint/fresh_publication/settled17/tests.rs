//! Checks actual partial publication backing and strict borrowed rejection.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::retained_metadata::{
    MetadataObserver,
    records::{MetadataRecordBank, ValidatedMetadataRecords},
};

#[test]
fn partial_publication_preserves_independent_options_and_spare_backing() -> Result<(), ProviderError>
{
    let mut actual = NativeFreshReportPublication::new();
    actual.schema = Some(String::with_capacity(71));
    actual.raw = Vec::with_capacity(37);
    actual.raw.extend_from_slice(&[0, 255]);
    actual.inventory_raw = Vec::with_capacity(43);
    actual.completed_response = Some([19; 32]);
    actual.completed_record = Some(0);
    let mut evidence = Vec::with_capacity(3);
    let mut bytes = Vec::with_capacity(67);
    bytes.extend_from_slice(b"independent original evidence");
    evidence.push((
        ContentRef {
            hash: crucible_node_contract::HashRef {
                algorithm: "blake3".into(),
                domain: "data".into(),
                digest: "unvalidated-partial".into(),
            },
            length: U64::new(29),
            media_type: "application/octet-stream".into(),
        },
        bytes,
    ));
    actual.reply = Some(crate::reference_packet::control::PacketControlReply {
        body: Default::default(),
        evidence,
    });

    let input = serde_json::to_vec(&actual.borrowed_settled17_data())
        .map_err(crucible_node_contract::ContractError::from)?;
    let mut records = MetadataRecordBank::reserve(128)?;
    let mut observer = MetadataObserver::recording(&mut records);
    actual.observe_retained_metadata(&mut observer)?;
    let facts = observer.finish();
    let encoded_records =
        serde_json::to_vec(&records).map_err(crucible_node_contract::ContractError::from)?;
    let backing = facts.string_capacity_bytes + facts.vector_capacity_bytes;
    let rows =
        ValidatedMetadataRecords::validate(&encoded_records, facts.capacity_records, backing)?;
    let limits = HistoricalJsonLimits {
        maximum_input_bytes: input.len() + 256,
        maximum_nodes: 4096,
        maximum_depth: 64,
        maximum_owned_backing_bytes: backing,
        maximum_tree_entries: 128,
    };

    let mut borrowed = Ledger::new(rows.rows(), limits);
    assert!(
        borrowed
            .read::<HistoricalFreshReportPublication17>(&input, false)?
            .is_none()
    );
    assert!(borrowed.rows.next().is_none());
    let mut build = Ledger::new(rows.rows(), limits);
    let restored = build
        .read::<HistoricalFreshReportPublication17>(&input, true)?
        .ok_or_else(invalid)?;
    assert!(build.rows.next().is_none());

    assert_eq!(restored.schema.as_ref().map(String::capacity), Some(71));
    assert!(restored.data.is_none());
    assert!(restored.proof.is_none());
    assert!(restored.report.is_none());
    assert_eq!(restored.raw.0, [0, 255]);
    assert_eq!(restored.raw.0.capacity(), 37);
    assert!(restored.inventory_raw.0.is_empty());
    assert_eq!(restored.inventory_raw.0.capacity(), 43);
    assert!(restored.receipt.is_none());
    assert_eq!(
        restored.completed_response.map(|digest| digest.0),
        Some([19; 32])
    );
    assert_eq!(restored.completed_record, Some(0));
    let reply = restored.reply.ok_or_else(invalid)?;
    assert_eq!(reply.evidence.capacity(), 3);
    assert_eq!(reply.evidence[0].1.capacity(), 67);
    assert_eq!(reply.evidence[0].1, b"independent original evidence");

    let text = std::str::from_utf8(&input).map_err(|_| invalid())?;
    for changed in [
        text.replace("\"raw\":[37,", "\"raw\":[1,"),
        text.replacen("{", "{\"unknown\":null,", 1),
    ] {
        let mut ledger = Ledger::new(rows.rows(), limits);
        assert!(
            ledger
                .read::<HistoricalFreshReportPublication17>(changed.as_bytes(), false)
                .is_err()
        );
    }
    Ok(())
}
