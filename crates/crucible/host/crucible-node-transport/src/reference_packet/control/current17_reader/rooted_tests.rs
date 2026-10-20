//! Exercises actual rooted Control writing without issuing restoration rights.

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

fn actual_capture(reactive: bool) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), ProviderError> {
    let control = super::super::native5::current_control17_fixture_data(reactive)?;
    let standalone = serde_json::to_vec(&control.borrowed_restored_settled_history_data()?)
        .map_err(crucible_node_format::ContractError::from)?;
    let rooted = serde_json::to_vec(&control.borrowed_rooted_current17_data()?)
        .map_err(crucible_node_format::ContractError::from)?;
    let mut records = MetadataRecordBank::reserve(16384)?;
    let mut aliases = MetadataAliasBank::reserve(1024)?;
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
    control.observe_settled17_root_hold_metadata_data(&mut observer)?;
    control.observe_restored_settled_history_metadata_data(&mut observer)?;
    observer.finish();
    Ok((
        standalone,
        rooted,
        serde_json::to_vec(&records).map_err(crucible_node_format::ContractError::from)?,
        serde_json::to_vec(&aliases).map_err(crucible_node_format::ContractError::from)?,
    ))
}

fn read_component(
    input: &[u8],
    records: &[u8],
    aliases: &[u8],
    build: bool,
    rooted: bool,
) -> Result<Option<CurrentControl17Data>, ProviderError> {
    let records = ValidatedMetadataRecords::validate(records, 16384, 64 * 1024 * 1024)?;
    let mut summaries = vec![RestoredSettledNative17AliasSummary::default(); 1024];
    let mut aliases =
        ValidatedRestoredSettledNative17Aliases::validate(aliases, &mut summaries, 1024)?;
    let mut ledger = Ledger::new(records.rows(), limits());
    ledger.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    ledger.native17_target_inline_root_data::<CurrentControl17Data>()?;
    ledger.settled_aliases = Some(aliases.views()?);
    read_current_control_identity17_data(br#""current-native-control-identity""#, &mut ledger)?;
    let encoding = if rooted {
        ControlEncoding17::Rooted { hold: None }
    } else {
        ControlEncoding17::Standalone
    };
    let decoded = CurrentControl17Data::read_encoding_data(input, &mut ledger, build, encoding)?;
    if ledger.rows.next().is_some() {
        return Err(invalid());
    }
    ledger.finish_aliases()?;
    ledger.finish_native17_targets_data()?;
    Ok(decoded)
}

#[test]
fn actual_rooted_writers_roundtrip_to_the_same_full_control_and_keep_old_grammar_closed()
-> Result<(), ProviderError> {
    for reactive in [false, true] {
        let (standalone, rooted, records, aliases) = actual_capture(reactive)?;
        assert!(read_component(&rooted, &records, &aliases, false, true)?.is_none());
        let decoded =
            read_component(&rooted, &records, &aliases, true, true)?.ok_or_else(invalid)?;
        decoded.authenticate_local_groups_data()?;
        assert_eq!(
            serde_json::to_vec(&decoded).map_err(crucible_node_format::ContractError::from)?,
            standalone
        );
        assert!(read_component(&rooted, &records, &aliases, false, false).is_err());
        assert!(read_component(&standalone, &records, &aliases, false, true).is_err());
    }
    Ok(())
}

#[test]
fn rooted_hold_role_cannot_invent_an_absent_defining_hold() -> Result<(), ProviderError> {
    let (_, rooted, records, aliases) = actual_capture(false)?;
    let text = std::str::from_utf8(&rooted).map_err(|_| invalid())?;
    let changed = text.replace(
        "\"complete_restored_hold\":null",
        "\"complete_restored_hold\":\"current-native-control-hold\"",
    );
    assert_ne!(changed.as_bytes(), rooted);
    assert!(read_component(changed.as_bytes(), &records, &aliases, false, true).is_err());
    Ok(())
}
