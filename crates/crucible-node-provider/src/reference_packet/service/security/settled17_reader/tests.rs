//! Checks actual empty supervisor source metadata and fail-closed active history.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::protocol_snapshot::restored_settled17::aliases::{
    RestoredSettledNative17AliasSummary, ValidatedRestoredSettledNative17Aliases,
};
use crate::retained_metadata::{
    MetadataObserver,
    aliases::MetadataAliasBank,
    records::{MetadataRecordBank, ValidatedMetadataRecords},
};

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
fn actual_supervisor_preserves_exact_empty_capacities_and_group() -> Result<(), ProviderError> {
    let original = Supervisor::new()?;
    let view = original.borrowed_settled_history_data()?;
    let input = serde_json::to_vec(&view).map_err(crucible_node_contract::ContractError::from)?;
    let mut records = MetadataRecordBank::reserve(4096)?;
    let mut aliases = MetadataAliasBank::reserve(4096)?;
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
    observer.shared_original(MetadataSharedKind::NativeSupervisor, &original)?;
    original.observe_settled_history_metadata_data(&mut observer)?;
    let facts = observer.finish();
    let encoded_records =
        serde_json::to_vec(&records).map_err(crucible_node_contract::ContractError::from)?;
    let encoded_aliases =
        serde_json::to_vec(&aliases).map_err(crucible_node_contract::ContractError::from)?;
    let rows = ValidatedMetadataRecords::validate(
        &encoded_records,
        facts.capacity_records,
        limits().maximum_owned_backing_bytes,
    )?;
    let mut summaries = vec![RestoredSettledNative17AliasSummary::default(); 4096];
    let mut aliases =
        ValidatedRestoredSettledNative17Aliases::validate(&encoded_aliases, &mut summaries, 4096)?;

    let validated_group = {
        let mut ledger = Ledger::new(rows.rows(), limits());
        ledger.settled_aliases = Some(aliases.views()?);
        let (data, group) = read_current_native17_supervisor_root_data(&input, &mut ledger, false)?;
        assert!(data.is_none());
        assert!(ledger.rows.next().is_none());
        ledger.finish_aliases()?;
        group
    };
    let restored = {
        let mut ledger = Ledger::new(rows.rows(), limits());
        ledger.settled_aliases = Some(aliases.views()?);
        let (data, group) = read_current_native17_supervisor_root_data(&input, &mut ledger, true)?;
        assert_eq!(group, validated_group);
        assert!(ledger.rows.next().is_none());
        ledger.finish_aliases()?;
        data.ok_or_else(invalid)?
    };
    assert_eq!(restored.group, validated_group);
    assert_eq!(
        restored.banks.capacity_rows(),
        (
            original
                .incidents
                .try_borrow()
                .map_err(|_| invalid())?
                .capacity(),
            original
                .blobs
                .try_borrow()
                .map_err(|_| invalid())?
                .capacity()
        )
    );
    assert_eq!(
        serde_json::to_vec(&view).map_err(crucible_node_contract::ContractError::from)?,
        input
    );

    let text = std::str::from_utf8(&input).map_err(|_| invalid())?;
    let changed = text.replacen("\"incidents\":[]", "\"incidents\":[{}]", 1);
    assert_ne!(changed.as_bytes(), input);
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.settled_aliases = Some(aliases.views()?);
    assert!(
        read_current_native17_supervisor_root_data(changed.as_bytes(), &mut ledger, false).is_err()
    );
    assert_eq!(
        serde_json::to_vec(&view).map_err(crucible_node_contract::ContractError::from)?,
        input
    );
    Ok(())
}

#[test]
fn short_metadata_bank_keeps_the_original_supervisor_unchanged() -> Result<(), ProviderError> {
    let original = Supervisor::new()?;
    let before = serde_json::to_vec(&original.borrowed_settled_history_data()?)
        .map_err(crucible_node_contract::ContractError::from)?;
    let mut records = MetadataRecordBank::reserve(1)?;
    let mut aliases = MetadataAliasBank::reserve(4096)?;
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
    observer.shared_original(MetadataSharedKind::NativeSupervisor, &original)?;
    assert!(
        original
            .observe_settled_history_metadata_data(&mut observer)
            .is_err()
    );
    let _ = observer.finish();
    assert_eq!(
        serde_json::to_vec(&original.borrowed_settled_history_data()?)
            .map_err(crucible_node_contract::ContractError::from)?,
        before
    );
    Ok(())
}
