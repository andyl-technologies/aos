//! Exercises late read, target-allocation and correspondence refusal ownership.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::protocol_snapshot::restored_settled17::aliases::{
    RestoredSettledNative17AliasSummary, ValidatedRestoredSettledNative17Aliases,
};
use crate::retained_metadata::{
    aliases::MetadataAliasBank,
    records::{MetadataRecordBank, ValidatedMetadataRecords},
};

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 4 * 1024 * 1024,
        maximum_nodes: 131072,
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 32768,
    }
}

fn actual_control() -> Result<PacketControl, ProviderError> {
    let mut actual =
        crate::reference_packet::control::native5::current_control17_fixture_data(false)?;
    let mut payload = Vec::with_capacity(53);
    payload.extend_from_slice(b"retained-before-late-refusal");
    let reference = canonical::content_ref(&payload, "application/json")?;
    let mut proof = Vec::with_capacity(31);
    proof.extend_from_slice(b"retained-proof");
    let proof_ref = canonical::content_ref(&proof, "application/json")?;
    let mut evidence = Vec::with_capacity(7);
    evidence.push((proof_ref, proof));
    actual.originals.insert(
        Id::new("retained-original")?,
        (
            reference.hash.clone(),
            PacketControlReply {
                body: Map::new(),
                evidence,
            },
        ),
    );
    actual.content.insert(reference, payload);
    Ok(actual)
}

#[test]
fn later_control_field_error_keeps_the_same_typed_children_and_capacities()
-> Result<(), ProviderError> {
    let actual = actual_control()?;
    let input = serde_json::to_vec(&actual.borrowed_restored_settled_history_data()?)
        .map_err(crucible_node_contract::ContractError::from)?;
    let mut fields = Fields::object(&input)?;
    let mut final_field = None;
    while let Some((name, body)) = fields.pair()? {
        if plain_string(name)? == "complete_capture_allocation_selection" {
            final_field = Some(body);
        }
    }
    let original = std::str::from_utf8(final_field.ok_or_else(invalid)?).map_err(|_| invalid())?;
    let text = std::str::from_utf8(&input).map_err(|_| invalid())?;
    let changed = text.replacen(
        &format!("\"complete_capture_allocation_selection\":{original}"),
        "\"complete_capture_allocation_selection\":\"unknown-retained-selection\"",
        1,
    );
    assert_ne!(changed.as_bytes(), input);
    let mut records = MetadataRecordBank::reserve(16384)?;
    let mut aliases = MetadataAliasBank::reserve(1024)?;
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
    actual.observe_settled17_root_hold_metadata_data(&mut observer)?;
    actual.observe_restored_settled_history_metadata_data(&mut observer)?;
    let facts = observer.finish();
    let encoded_rows =
        serde_json::to_vec(&records).map_err(crucible_node_contract::ContractError::from)?;
    let encoded_aliases =
        serde_json::to_vec(&aliases).map_err(crucible_node_contract::ContractError::from)?;
    let rows = ValidatedMetadataRecords::validate(
        &encoded_rows,
        facts.capacity_records,
        limits().maximum_owned_backing_bytes,
    )?;
    let mut summaries = vec![RestoredSettledNative17AliasSummary::default(); 1024];
    let mut aliases =
        ValidatedRestoredSettledNative17Aliases::validate(&encoded_aliases, &mut summaries, 1024)?;
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    ledger.native17_target_embedded_root_data()?;
    ledger.settled_aliases = Some(aliases.views()?);
    read_current_control_identity17_data(br#""current-native-control-identity""#, &mut ledger)?;
    let mut attempt = CurrentControl17ReadAttempt::default();
    assert!(
        attempt
            .read_encoding_into(
                changed.as_bytes(),
                &mut ledger,
                true,
                ControlEncoding17::Standalone
            )
            .is_err()
    );
    assert!(attempt.completed_data().is_none());
    assert!(attempt.partial_selection_data().is_some());
    let payload = attempt
        .partial_content_data()
        .values()
        .next()
        .ok_or_else(invalid)?;
    assert_eq!(payload.capacity(), 53);
    let pointer = payload.as_ptr();
    let reply = &attempt
        .partial_originals_data()
        .values()
        .next()
        .ok_or_else(invalid)?
        .1;
    assert_eq!(reply.evidence.capacity(), 7);
    assert_eq!(reply.evidence[0].1.capacity(), 31);
    let mut observer = MetadataObserver::new();
    attempt.observe_attempt_data(&mut observer)?;
    let retained = observer.finish();
    let consumed = ledger.rows.encoded_position();
    assert!(
        attempt
            .read_encoding_into(&input, &mut ledger, true, ControlEncoding17::Standalone)
            .is_err()
    );
    assert_eq!(ledger.rows.encoded_position(), consumed);
    assert_eq!(
        attempt
            .partial_content_data()
            .values()
            .next()
            .ok_or_else(invalid)?
            .as_ptr(),
        pointer
    );
    let mut observer = MetadataObserver::new();
    attempt.observe_attempt_data(&mut observer)?;
    assert_eq!(observer.finish(), retained);
    Ok(())
}

#[test]
fn target_refusal_keeps_prior_content_rows_and_the_current_reference() -> Result<(), ProviderError>
{
    use super::super::maps::{CurrentContent17Data, retained::CurrentContent17ReadAttempt};
    let mut a = (
        canonical::content_ref(b"first", "application/json")?,
        b"first".as_slice(),
    );
    let mut b = (
        canonical::content_ref(b"second", "application/json")?,
        b"second".as_slice(),
    );
    if a.0 > b.0 {
        std::mem::swap(&mut a, &mut b);
    }
    let mut small = Vec::with_capacity(53);
    small.extend_from_slice(a.1);
    let mut large = Vec::with_capacity(1024 * 1024);
    large.extend_from_slice(b.1);
    let original = CurrentContent17Data(BTreeMap::from([(a.0, small), (b.0, large)]));
    let input =
        serde_json::to_vec(&original).map_err(crucible_node_contract::ContractError::from)?;
    let mut records = MetadataRecordBank::reserve(4096)?;
    let mut observer = MetadataObserver::recording(&mut records);
    observer.observe(&original)?;
    let facts = observer.finish();
    let encoded =
        serde_json::to_vec(&records).map_err(crucible_node_contract::ContractError::from)?;
    let rows = ValidatedMetadataRecords::validate(
        &encoded,
        facts.capacity_records,
        limits().maximum_owned_backing_bytes,
    )?;

    // Fund exactly the tree, first complete row and second full reference.
    // The next byte bank must refuse without dropping any initialized child.
    let (prefix_requested, prefix_source_position) = {
        use crate::retained_metadata::records::MetadataRecordKind;
        use std::mem::{align_of, size_of};

        let mut preflight = Ledger::new(rows.rows(), limits());
        preflight.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
        preflight.native17_target_embedded_root_data()?;
        let count = preflight.row_aligned(
            MetadataRecordKind::Tree,
            size_of::<ContentRef>() + size_of::<Vec<u8>>(),
            align_of::<ContentRef>().max(align_of::<Vec<u8>>()),
        )?;
        preflight.native17_target_tree_data::<ContentRef, Vec<u8>>(count)?;
        let mut entries = Fields::array(&input)?;
        let mut first = Fields::array(entries.next()?.ok_or_else(invalid)?)?;
        ContentRef::preflight_data(first.next()?.ok_or_else(invalid)?, &mut preflight)?;
        Vec::<u8>::preflight_data(first.next()?.ok_or_else(invalid)?, &mut preflight)?;
        first.finish()?;
        let mut second = Fields::array(entries.next()?.ok_or_else(invalid)?)?;
        ContentRef::preflight_data(second.next()?.ok_or_else(invalid)?, &mut preflight)?;
        let source_position = preflight.rows.encoded_position();
        (preflight.finish_native17_targets_data()?, source_position)
    };

    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.begin_native17_targets_data(prefix_requested)?;
    ledger.native17_target_embedded_root_data()?;
    let mut attempt = CurrentContent17ReadAttempt::default();
    let result = attempt.read_into(&input, &mut ledger, true);
    assert!(matches!(
        result,
        Err(ProviderError::ResourceExhausted(
            "native17 decoded target storage"
        ))
    ));
    assert!(ledger.rows.encoded_position() > prefix_source_position);

    assert_eq!(attempt.rows_data().len(), 1);
    let first = attempt.rows_data().values().next().ok_or_else(invalid)?;
    assert_eq!(first.capacity(), 53);
    let pointer = first.as_ptr();
    let reference = attempt.pending_reference_data().ok_or_else(invalid)?;
    let digest_pointer = reference.hash.digest.as_ptr();
    let consumed = ledger.rows.encoded_position();
    assert!(attempt.read_into(&input, &mut ledger, true).is_err());
    assert_eq!(ledger.rows.encoded_position(), consumed);
    assert_eq!(
        attempt
            .rows_data()
            .values()
            .next()
            .ok_or_else(invalid)?
            .as_ptr(),
        pointer
    );
    assert_eq!(
        attempt
            .pending_reference_data()
            .ok_or_else(invalid)?
            .hash
            .digest
            .as_ptr(),
        digest_pointer
    );
    Ok(())
}

#[test]
fn later_correspondence_refusal_keeps_the_completed_control_in_its_once_owner()
-> Result<(), ProviderError> {
    let actual = actual_control()?;
    let input = serde_json::to_vec(&actual.borrowed_restored_settled_history_data()?)
        .map_err(crucible_node_contract::ContractError::from)?;
    let mut records = MetadataRecordBank::reserve(16384)?;
    let mut aliases = MetadataAliasBank::reserve(1024)?;
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
    actual.observe_settled17_root_hold_metadata_data(&mut observer)?;
    actual.observe_restored_settled_history_metadata_data(&mut observer)?;
    let facts = observer.finish();
    let encoded_rows =
        serde_json::to_vec(&records).map_err(crucible_node_contract::ContractError::from)?;
    let encoded_aliases =
        serde_json::to_vec(&aliases).map_err(crucible_node_contract::ContractError::from)?;
    let rows = ValidatedMetadataRecords::validate(
        &encoded_rows,
        facts.capacity_records,
        limits().maximum_owned_backing_bytes,
    )?;
    let mut summaries = vec![RestoredSettledNative17AliasSummary::default(); 1024];
    let mut aliases =
        ValidatedRestoredSettledNative17Aliases::validate(&encoded_aliases, &mut summaries, 1024)?;
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    ledger.native17_target_embedded_root_data()?;
    ledger.settled_aliases = Some(aliases.views()?);
    read_current_control_identity17_data(br#""current-native-control-identity""#, &mut ledger)?;
    let mut attempt = CurrentControl17ReadAttempt::default();
    let groups =
        attempt.read_encoding_into(&input, &mut ledger, true, ControlEncoding17::Standalone)?;
    assert_eq!(
        attempt
            .completed_data()
            .ok_or_else(invalid)?
            .group_ids_data(),
        groups
    );
    let pointer = attempt
        .completed_data()
        .ok_or_else(invalid)?
        .content_data()
        .values()
        .next()
        .ok_or_else(invalid)?
        .as_ptr();

    // These inert ordinals deliberately contradict the retained absence of a
    // Hold. They cannot construct native evidence or a physical permission.
    attempt
        .completed
        .as_mut()
        .ok_or_else(invalid)?
        .complete_restored_evidence = Some(CurrentEvidence17Data {
        boot: 0,
        commit: 0,
        hold: 0,
    });
    assert!(
        attempt
            .completed_data()
            .ok_or_else(invalid)?
            .authenticate_local_groups_data()
            .is_err()
    );
    let retained = attempt.completed_data().ok_or_else(invalid)?;
    assert_eq!(
        retained
            .content_data()
            .values()
            .next()
            .ok_or_else(invalid)?
            .as_ptr(),
        pointer
    );
    assert_eq!(
        retained
            .content_data()
            .values()
            .next()
            .ok_or_else(invalid)?
            .capacity(),
        53
    );
    assert!(attempt.completed_data().is_some());
    Ok(())
}
