//! Preserves immutable ancestry while permitting a separately verified cursor.

use super::*;
use crate::bodies::{decode_request, decode_response};
use crate::envelope::{Envelope, MessageKind, Method};
use crate::reference_packet::control::PacketNative5Record;

pub(super) fn lineage(
    held: &PacketNativeRestoredCommitHold,
    previous: &PacketNativeRestoredRecord,
    current: &PacketNativeRestoredRecord,
) -> Result<(), ProviderError> {
    held.validate_data()?;
    previous.validate_data()?;
    current.validate_data()?;
    if current.physical_gate_held
        || previous.physical_gate_held
        || current.native_receipt.native_pid != held.native_pid
        || current.native_receipt.world != held.target_world
        || current.native_receipt.owner != held.target_owner
        || current.captured_owner_state != held.captured_owner_state
        || current.captured_journal != held.captured_journal
        || current.mapping != held.mapping
        || current.restore_commit != held.restore_commit
        || current.context_digest != held.context_digest
        || previous.captured_owner_state != current.captured_owner_state
        || previous.captured_journal != current.captured_journal
        || previous.mapping != current.mapping
        || previous.restore_commit != current.restore_commit
        || previous.restore_response != current.restore_response
        || previous.context_digest != current.context_digest
    {
        return Err(invalid());
    }
    same_receipt_scope(&previous.native_receipt, &current.native_receipt)
}

fn same_receipt_scope(
    before: &PacketNative5Record,
    after: &PacketNative5Record,
) -> Result<(), ProviderError> {
    if before.schema != after.schema
        || before.native_pid != after.native_pid
        || before.binding_hash != after.binding_hash
        || before.session != after.session
        || before.incarnation != after.incarnation
        || before.node != after.node
        || before.owner != after.owner
        || before.owner_generation != after.owner_generation
        || before.input_epoch != after.input_epoch
        || before.world != after.world
        || before.storage_selection != after.storage_selection
        || before.capture_profile != after.capture_profile
        || before.confirmation_selection != after.confirmation_selection
        || before.ack_emitter_selection != after.ack_emitter_selection
        || before.complete_restore_selection != after.complete_restore_selection
        || before.protocol_metadata_limits != after.protocol_metadata_limits
        || before.protocol_metadata_birth_facts != after.protocol_metadata_birth_facts
        || before.restore_input_emitter_selection != after.restore_input_emitter_selection
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn record(
    restored: &PacketNativeRestoredRecord,
    producer: &PacketNativeRecord,
) -> Result<(), ProviderError> {
    if producer.schema != "source-owned.packet-native/2"
        || producer.native_pid != restored.native_receipt.native_pid
        || producer.original != restored.native_receipt.original
        || producer.inventory.gate_closed
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn pair_data(
    pair: super::pair_views::PairOwner<'_>,
    method: Method,
) -> Result<super::pair_views::Pair<'_>, ProviderError> {
    let (original, terminal, typed) = pair.completed_pair_data()?;
    original.validate()?;
    terminal.validate()?;
    if original.message != MessageKind::Request
        || original.method != method
        || !original.extensions.is_empty()
        || !terminal.extensions.is_empty()
    {
        return Err(invalid());
    }
    // Revalidate the full closed raw body; a copied typed response is not an
    // independently authenticated correspondence with the retained terminal.
    let request = decode_request(method, &original.body)?;
    if decode_response(&request, &terminal.body)? != *typed {
        return Err(invalid());
    }
    Ok((original, terminal, typed))
}

pub(super) fn same_route(previous: &Envelope, current: &Envelope) -> Result<(), ProviderError> {
    if previous.session_id != current.session_id
        || previous.incarnation_id != current.incarnation_id
        || previous.node_id != current.node_id
        || previous.execution_owner_id != current.execution_owner_id
        || previous.capture_owner_id.0.is_some()
        || current.capture_owner_id.0.is_some()
        || previous.request_id == current.request_id
        || previous.sequence >= current.sequence
    {
        return Err(invalid());
    }
    Ok(())
}
