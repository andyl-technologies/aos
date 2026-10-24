//! Compares current activation evidence with its original historical held model.

use super::*;
use crate::reference_packet::{
    control::PacketNative5UnderlyingRecord,
    service::complete_restore::{PacketNativeRestoredCommitHold, PacketNativeRestoredRecord},
};
use crucible_node_format::canonical;

/// Checks the unchanged model boundary through actual activation evidence.
///
/// `held` remains historical held-true evidence. The caller independently
/// authenticates the current completed phase, native MAC/child and actual
/// physical state before using this comparison within the same Source fence.
/// This never treats the old held bit as the current WorldActivate state.
///
/// # Errors
/// Refuses changed complete Commit/capture/mapping/context references, a changed
/// model cursor or full inventory hash, a lifecycle proof containing a grant,
/// mismatched native originals or bounded canonical construction failure.
pub fn authenticate_restoration_activation_held_correspondence_data(
    current: &PacketNativeRestoredRecord,
    underlying: &PacketNative5UnderlyingRecord,
    held: &PacketNativeRestoredCommitHold,
) -> Result<(), ProviderError> {
    current.validate_data()?;
    held.validate_data()?;
    if current.native_receipt.native_pid != held.native_pid
        || current.captured_owner_state != held.captured_owner_state
        || current.captured_journal != held.captured_journal
        || current.mapping != held.mapping
        || current.restore_commit != held.restore_commit
        || current.context_digest != held.context_digest
    {
        return Err(invalid());
    }
    let (cursor, inventory_hash) = match underlying {
        PacketNative5UnderlyingRecord::Producer(record) => {
            if record.native_pid != held.native_pid
                || record.grant.is_some()
                || record.original != current.native_receipt.original
            {
                return Err(invalid());
            }
            crate::connection::serialized_credit(&record.inventory, 65_536)?;
            (
                record.inventory.reached,
                canonical::json_hash("source-owned.packet-inventory.v1", &record.inventory)?,
            )
        }
        PacketNative5UnderlyingRecord::Reactive(record) => {
            if record.native_pid != held.native_pid
                || record.grant.is_some()
                || record.original != current.native_receipt.original
            {
                return Err(invalid());
            }
            crate::connection::serialized_credit(&record.inventory, 65_536)?;
            (
                record.inventory.reached,
                canonical::json_hash(
                    "source-owned.packet-connected-inventory/4",
                    &record.inventory,
                )?,
            )
        }
    };
    if cursor != held.local_cursor || inventory_hash != held.inventory_hash {
        return Err(invalid());
    }
    Ok(())
}
