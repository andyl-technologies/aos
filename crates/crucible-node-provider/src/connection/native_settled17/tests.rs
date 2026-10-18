//! Checks emitted-order refusal and actual partial-frame capacity reconstruction.

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
use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};

fn limits() -> HistoricalJsonLimits {
    HistoricalJsonLimits {
        maximum_input_bytes: 4096,
        maximum_nodes: 4096,
        maximum_depth: 64,
        maximum_owned_backing_bytes: 4096,
        maximum_tree_entries: 4096,
    }
}

#[test]
fn native_entrypoint_refuses_the_host_canonical_field_order_before_rows()
-> Result<(), ProviderError> {
    let records = ValidatedMetadataRecords::validate(b"[]", 0, 0)?;
    let mut ledger = Ledger::new(records.rows(), limits());
    assert!(
        read_native17_connection_data(
            br#"{"authority":null,"schema":"source-private.connection-restored-settled/17"}"#,
            &mut ledger,
            false
        )
        .is_err()
    );
    assert!(ledger.rows.next().is_none());
    Ok(())
}

#[test]
fn stable_native_frame_leaf_keeps_partial_bytes_and_actual_capacities() -> Result<(), ProviderError>
{
    let mut frames = OriginalFrameReservation::reserve(64, 3)?;
    let slot = frames.begin(FrameDirection::Incoming, 5)?;
    frames.append(slot, &[0, 0])?;
    let handle = Rc::new(RefCell::new(frames));
    let frame = handle.borrow();
    let input = serde_json::to_vec(&frame.protocol_view_with_encoding(true))
        .map_err(crucible_node_contract::ContractError::from)?;
    let mut records = MetadataRecordBank::reserve(16)?;
    let mut aliases = MetadataAliasBank::reserve(4)?;
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
    observer.shared_original(MetadataSharedKind::FrameBank, handle.as_ref())?;
    frame.observe_owned11_metadata(&mut observer)?;
    let facts = observer.finish();
    let original_allocated = frame.allocated_bytes();
    let rows_input =
        serde_json::to_vec(&records).map_err(crucible_node_contract::ContractError::from)?;
    let aliases_input =
        serde_json::to_vec(&aliases).map_err(crucible_node_contract::ContractError::from)?;
    let rows = ValidatedMetadataRecords::validate(
        &rows_input,
        facts.capacity_records,
        facts.vector_capacity_bytes,
    )?;
    let mut summaries = [RestoredSettledNative17AliasSummary::default(); 4];
    let mut aliases =
        ValidatedRestoredSettledNative17Aliases::validate(&aliases_input, &mut summaries, 4)?;
    let mut ledger = Ledger::new(rows.rows(), limits());
    ledger.settled_aliases = Some(aliases.views()?);
    ledger.maximum_literal_bytes = original_allocated;
    let (restored, group) = read_native17_frame_root_data(&input, &mut ledger, true)?;
    let restored = restored.ok_or_else(invalid)?;
    assert_eq!(group, 0);
    assert_eq!(restored.frames.allocated_bytes(), original_allocated);
    let partial = restored.frames.frame(slot).ok_or_else(invalid)?;
    assert_eq!(partial.bytes, &[0, 0]);
    assert_eq!(partial.transferred, 2);
    assert!(!partial.complete);
    assert!(ledger.rows.next().is_none());
    ledger.finish_aliases()?;
    Ok(())
}
