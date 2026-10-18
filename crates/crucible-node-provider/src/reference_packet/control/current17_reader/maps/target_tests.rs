//! Checks real Control map reconstruction demand before target allocation.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 1024 * 1024,
        maximum_nodes: 32768,
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 16384,
    }
}

#[test]
fn actual_content_tree_charges_its_nodes_and_children_in_both_passes() -> Result<(), ProviderError>
{
    let mut payload = Vec::with_capacity(53);
    payload.extend_from_slice(b"retained Control content");
    let reference = crucible_node_contract::canonical::content_ref(&payload, "application/json")?;
    let original = CurrentContent17Data(BTreeMap::from([(reference, payload)]));
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
    let modeled_backing = size_of::<CurrentContent17Data>()
        .checked_add(crate::retained_metadata::requested_metadata_backing_storage_data(&facts)?)
        .ok_or_else(invalid)?;

    // The concrete reader also requests retained child-attempt banks. Quote
    // those under the independent fixture ceiling before testing exact credit.
    let mut preflight = Ledger::new(rows.rows(), limits());
    preflight.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    preflight.native17_target_inline_root_data::<CurrentContent17Data>()?;
    assert!(
        preflight
            .read::<CurrentContent17Data>(&input, false)?
            .is_none()
    );
    assert!(preflight.rows.next().is_none());
    let expected = preflight.finish_native17_targets_data()?;
    assert!(expected >= modeled_backing);

    for build in [false, true] {
        let mut ledger = Ledger::new(rows.rows(), limits());
        ledger.begin_native17_targets_data(expected)?;
        ledger.native17_target_inline_root_data::<CurrentContent17Data>()?;
        let retained = ledger.read::<CurrentContent17Data>(&input, build)?;
        assert_eq!(retained.is_some(), build);
        assert!(ledger.rows.next().is_none());
        assert_eq!(ledger.finish_native17_targets_data()?, expected);
        if let Some(retained) = retained {
            assert_eq!(
                retained.0.values().next().ok_or_else(invalid)?.capacity(),
                53
            );
        }
    }

    let mut short = Ledger::new(rows.rows(), limits());
    short.begin_native17_targets_data(expected.checked_sub(1).ok_or_else(invalid)?)?;
    short.native17_target_inline_root_data::<CurrentContent17Data>()?;
    assert!(short.read::<CurrentContent17Data>(&input, false).is_err());
    assert!(short.finish_native17_targets_data().is_err());

    // A missing target-tree charge would consume child String rows before the
    // first zero-credit refusal. The actual node demand must fail at the tree.
    let mut expected_rows = rows.rows();
    expected_rows.next().ok_or_else(invalid)??;
    let first_row_end = expected_rows.encoded_position();
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.begin_native17_targets_data(0)?;
    assert!(ledger.read::<CurrentContent17Data>(&input, false).is_err());
    assert_eq!(ledger.rows.encoded_position(), first_row_end);
    assert!(ledger.finish_native17_targets_data().is_err());
    Ok(())
}
