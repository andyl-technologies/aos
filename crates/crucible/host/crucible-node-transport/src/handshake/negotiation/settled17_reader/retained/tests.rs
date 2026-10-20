//! Checks retained registration fields and unfinished selected-extension children.

use super::*;
use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
use crate::protocol_snapshot::restored_settled17::aliases::{
    RestoredSettledNative17AliasSummary, ValidatedRestoredSettledNative17Aliases,
};
use crate::retained_metadata::{
    aliases::MetadataAliasBank,
    records::{MetadataRecordBank, ValidatedMetadataRecords},
};
use crucible_node_format::{ExtensionSelection, SemanticVersion};

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 1024 * 1024,
        maximum_nodes: 65536,
        // The defining historical JSON codec accepts depths through 64.
        maximum_depth: 64,
        maximum_owned_backing_bytes: 64 * 1024 * 1024,
        maximum_tree_entries: 16384,
    }
}

fn selection(name: &str) -> Result<ExtensionSelection, ProviderError> {
    let declaration = crucible_node_format::canonical::content_ref(
        b"inert selected declaration",
        "application/json",
    )?;
    Ok(ExtensionSelection {
        schema_digest: declaration.hash.clone(),
        declaration,
        identifier: Id::new(name)?,
        semantic_version: SemanticVersion {
            major: U64::new(1),
            minor: U64::new(0),
            patch: U64::new(0),
            prerelease: None,
            build: None,
        },
    })
}

#[test]
fn later_selected_child_error_keeps_prior_children_and_authority_fields()
-> Result<(), ProviderError> {
    let (_registrar, mut actual) = crate::handshake::tests::authority();
    actual.ensure_live()?;
    actual.extensions = Some(std::sync::Arc::from(
        vec![selection("retained-first")?, selection("retained-second")?].into_boxed_slice(),
    ));
    let input = serde_json::to_vec(&actual.borrowed_settled_history_data())
        .map_err(crucible_node_format::ContractError::from)?;
    let mut object = Fields::object(&input)?;
    let mut extensions = None;
    while let Some((name, body)) = object.pair()? {
        if plain_string(name)? == "extensions" {
            extensions = Some(body);
        }
    }
    let mut array = Fields::array(extensions.ok_or_else(invalid)?)?;
    array.next_value()?.ok_or_else(invalid)?;
    let second = array.next_value()?.ok_or_else(invalid)?;
    let mut child = Fields::object(second)?;
    let mut digest = None;
    while let Some((name, body)) = child.pair()? {
        if plain_string(name)? == "schema_digest" {
            digest = Some(body);
        }
    }
    let digest = digest.ok_or_else(invalid)?;
    let offset = (digest.as_ptr() as usize)
        .checked_sub(input.as_ptr() as usize)
        .ok_or_else(invalid)?;
    let mut changed = Vec::new();
    changed.extend_from_slice(&input[..offset]);
    changed.extend_from_slice(b"null");
    changed.extend_from_slice(&input[offset + digest.len()..]);
    let mut records = MetadataRecordBank::reserve(8192)?;
    let mut aliases = MetadataAliasBank::reserve(128)?;
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
    actual.observe_retained_metadata(&mut observer)?;
    let facts = observer.finish();
    let encoded_rows =
        serde_json::to_vec(&records).map_err(crucible_node_format::ContractError::from)?;
    let encoded_aliases =
        serde_json::to_vec(&aliases).map_err(crucible_node_format::ContractError::from)?;
    let rows = ValidatedMetadataRecords::validate(
        &encoded_rows,
        facts.capacity_records,
        limits().maximum_owned_backing_bytes,
    )?;
    let mut summaries = vec![RestoredSettledNative17AliasSummary::default(); 128];
    let mut aliases =
        ValidatedRestoredSettledNative17Aliases::validate(&encoded_aliases, &mut summaries, 128)?;
    let mut cache = vec![None; 128];
    let mut target_groups = [false; 128];
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.settled_aliases = Some(aliases.views()?);
    ledger.selected_groups = Some(&mut cache);
    ledger.bind_native17_target_groups_data(&mut target_groups)?;
    // Admit the owning child banks under the same fixed 64 MiB test bound.
    ledger.begin_native17_targets_data(limits().maximum_owned_backing_bytes)?;
    let mut attempt = HistoricalAuthority17ReadAttempt::default();
    assert!(HistoricalAuthority17::read_into_data(&changed, &mut ledger, &mut attempt).is_err());
    assert!(attempt.completed.is_none());
    assert!(attempt.connection.is_some());
    assert_eq!(attempt.selected.values.len(), 1);
    assert_eq!(attempt.selected.children.len(), 2);
    assert_eq!(
        attempt.selected.values[0].identifier.as_str(),
        "retained-first"
    );
    let pointer = attempt.selected.values[0].identifier.as_str().as_ptr();
    let connection = attempt
        .connection
        .as_ref()
        .ok_or_else(invalid)?
        .as_str()
        .as_ptr();
    let mut observer = MetadataObserver::new();
    HistoricalAuthority17::observe_attempt_data(&attempt, &mut observer)?;
    let retained = observer.finish();
    let consumed = ledger.rows.encoded_position();
    assert!(HistoricalAuthority17::read_into_data(&input, &mut ledger, &mut attempt).is_err());
    assert_eq!(ledger.rows.encoded_position(), consumed);
    assert_eq!(
        attempt.selected.values[0].identifier.as_str().as_ptr(),
        pointer
    );
    assert_eq!(
        attempt
            .connection
            .as_ref()
            .ok_or_else(invalid)?
            .as_str()
            .as_ptr(),
        connection
    );
    let mut observer = MetadataObserver::new();
    HistoricalAuthority17::observe_attempt_data(&attempt, &mut observer)?;
    assert_eq!(observer.finish(), retained);
    assert!(
        ledger
            .selected_groups
            .as_ref()
            .ok_or_else(invalid)?
            .iter()
            .all(Option::is_none)
    );
    Ok(())
}
