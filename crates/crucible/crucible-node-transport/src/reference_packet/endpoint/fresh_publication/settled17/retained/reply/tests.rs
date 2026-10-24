//! Checks the real publication's late-field and later-bank refusal ownership.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 1024 * 1024,
        maximum_nodes: 65536,
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 8192,
    }
}

fn actual_publication(
    inventory_capacity: usize,
) -> Result<NativeFreshReportPublication, ProviderError> {
    let mut actual = NativeFreshReportPublication::new();
    let mut schema = String::with_capacity(71);
    schema.push_str("partial-publication");
    actual.schema = Some(schema);
    actual.raw = Vec::with_capacity(37);
    actual.raw.extend_from_slice(b"partial-raw");
    actual.inventory_raw = Vec::with_capacity(inventory_capacity);
    actual.completed_response = Some([19; 32]);
    actual.completed_record = Some(0);
    let mut evidence = Vec::with_capacity(3);
    let mut bytes = Vec::with_capacity(67);
    bytes.extend_from_slice(b"independent-evidence");
    evidence.push((
        crucible_node_format::canonical::content_ref(&bytes, "application/json")?,
        bytes,
    ));
    actual.reply = Some(crate::reference_packet::control::PacketControlReply {
        body: Default::default(),
        evidence,
    });
    Ok(actual)
}

fn rows(actual: &NativeFreshReportPublication) -> Result<(Vec<u8>, usize), ProviderError> {
    let mut records = MetadataRecordBank::reserve(8192)?;
    let mut observer = MetadataObserver::recording(&mut records);
    actual.observe_retained_metadata(&mut observer)?;
    let facts = observer.finish();
    Ok((
        serde_json::to_vec(&records).map_err(crucible_node_format::ContractError::from)?,
        facts.capacity_records,
    ))
}

#[test]
fn final_record_error_keeps_raw_reply_and_evidence_capacities() -> Result<(), ProviderError> {
    let actual = actual_publication(43)?;
    let input = serde_json::to_vec(&actual.borrowed_settled17_data())
        .map_err(crucible_node_format::ContractError::from)?;
    let changed = std::str::from_utf8(&input).map_err(|_| invalid())?.replace(
        "\"completed_record\":0",
        "\"completed_record\":\"invalid-index\"",
    );
    assert_ne!(changed.as_bytes(), input);
    let (encoded, count) = rows(&actual)?;
    let rows =
        ValidatedMetadataRecords::validate(&encoded, count, limits().maximum_owned_backing_bytes)?;
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    ledger.native17_target_embedded_root_data()?;
    let mut attempt = <HistoricalFreshReportPublication17 as Native17Build>::Attempt::default();
    assert!(
        HistoricalFreshReportPublication17::read_into_data(
            changed.as_bytes(),
            &mut ledger,
            &mut attempt
        )
        .is_err()
    );
    // Native17Fields follows the exact source roster: raw is field five;
    // reply is field eleven. Both are still direct owned fields after refusal.
    let raw_slot = &attempt.fields.tail.tail.tail.tail.head.output;
    let raw = raw_slot.as_ref().ok_or_else(invalid)?;
    assert_eq!(raw.0.capacity(), 37);
    let raw_pointer = raw.0.as_ptr();
    let reply_slot = &attempt
        .fields
        .tail
        .tail
        .tail
        .tail
        .tail
        .tail
        .tail
        .tail
        .tail
        .tail
        .head
        .output;
    let reply = reply_slot
        .as_ref()
        .and_then(Option::as_ref)
        .ok_or_else(invalid)?;
    assert_eq!(reply.evidence.capacity(), 3);
    assert_eq!(reply.evidence[0].1.capacity(), 67);
    let evidence_pointer = reply.evidence[0].1.as_ptr();
    let mut observer = MetadataObserver::new();
    HistoricalFreshReportPublication17::observe_attempt_data(&attempt, &mut observer)?;
    let retained = observer.finish();
    let consumed = ledger.rows.encoded_position();
    assert!(
        HistoricalFreshReportPublication17::read_into_data(&input, &mut ledger, &mut attempt)
            .is_err()
    );
    assert_eq!(ledger.rows.encoded_position(), consumed);
    assert_eq!(
        attempt
            .fields
            .tail
            .tail
            .tail
            .tail
            .head
            .output
            .as_ref()
            .ok_or_else(invalid)?
            .0
            .as_ptr(),
        raw_pointer
    );
    assert_eq!(
        attempt
            .fields
            .tail
            .tail
            .tail
            .tail
            .tail
            .tail
            .tail
            .tail
            .tail
            .tail
            .head
            .output
            .as_ref()
            .and_then(Option::as_ref)
            .ok_or_else(invalid)?
            .evidence[0]
            .1
            .as_ptr(),
        evidence_pointer
    );
    let mut observer = MetadataObserver::new();
    HistoricalFreshReportPublication17::observe_attempt_data(&attempt, &mut observer)?;
    assert_eq!(observer.finish(), retained);
    Ok(())
}

#[test]
fn later_inventory_target_refusal_keeps_earlier_raw_bank() -> Result<(), ProviderError> {
    let actual = actual_publication(1024 * 1024)?;
    let input = serde_json::to_vec(&actual.borrowed_settled17_data())
        .map_err(crucible_node_format::ContractError::from)?;
    let (encoded, count) = rows(&actual)?;
    let rows =
        ValidatedMetadataRecords::validate(&encoded, count, limits().maximum_owned_backing_bytes)?;

    // Price all fields through reference plus the next concrete child header.
    // Its large inventory byte bank is the first target backing left unfunded.
    let (prefix_requested, prefix_source_position) = {
        use crate::protocol_snapshot::owned11::typed::native17_build::Native17ChildSlot;

        let mut preflight = Ledger::new(rows.rows(), limits());
        preflight.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
        preflight.native17_target_embedded_root_data()?;
        let mut fields = Fields::object(&input)?;
        macro_rules! preceding_field {
            ($ty:ty, $name:literal) => {{
                Native17ChildSlot::<<$ty as Native17Build>::Attempt>::preflight_data(
                    &mut preflight,
                )?;
                <$ty as Native17Build>::preflight_data(fields.named($name)?, &mut preflight)?;
            }};
        }

        preceding_field!(Option<String>, "schema");
        preceding_field!(Option<PacketNativeFreshRestoreAllocationData>, "data");
        preceding_field!(Option<PacketNativeFreshRestoreAllocationProof>, "proof");
        preceding_field!(Option<PacketNativeFreshRestoreAllocationReport>, "report");
        preceding_field!(HistoricalByteBank17, "raw");
        preceding_field!(Option<ContentRef>, "reference");
        Native17ChildSlot::<<HistoricalByteBank17 as Native17Build>::Attempt>::preflight_data(
            &mut preflight,
        )?;
        let source_position = preflight.rows.encoded_position();
        (preflight.finish_native17_targets_data()?, source_position)
    };

    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.begin_native17_targets_data(prefix_requested)?;
    ledger.native17_target_embedded_root_data()?;
    let mut attempt = <HistoricalFreshReportPublication17 as Native17Build>::Attempt::default();
    let result =
        HistoricalFreshReportPublication17::read_into_data(&input, &mut ledger, &mut attempt);
    assert!(matches!(
        result,
        Err(ProviderError::ResourceExhausted(
            "native17 decoded target storage"
        ))
    ));
    assert!(ledger.rows.encoded_position() > prefix_source_position);

    let inventory = &attempt.fields.tail.tail.tail.tail.tail.tail.head;
    assert!(inventory.output.is_none());
    let inventory_child = inventory.child.child_data().ok_or_else(invalid)?;
    assert_eq!(inventory_child.capacity, Some(1024 * 1024));
    assert_eq!(inventory_child.buffer.capacity(), 0);
    let raw = attempt
        .fields
        .tail
        .tail
        .tail
        .tail
        .head
        .output
        .as_ref()
        .ok_or_else(invalid)?;
    assert_eq!(raw.0.capacity(), 37);
    assert_eq!(raw.0, b"partial-raw");
    Ok(())
}
