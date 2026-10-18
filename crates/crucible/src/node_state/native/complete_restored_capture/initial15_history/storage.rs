//! Prices historical construction separately from actual retained scope backing.
//!
//! Prospective clone bounds come from the genuine original/current operands.
//! They are conservative row DATA. The retained census walks real capacities
//! after success or refusal and never substitutes the prospective bound for R.

use super::*;
use crucible_node_provider::protocol_snapshot::borrowed_json;

/// Prices the actual Bytes serializer's sole temporary formatter in Hold.
///
/// The completed Hold grammar fixes context_digest at exactly 32 bytes. The
/// unpadded URL-safe base64 serializer requests 43 UTF-8 bytes. U64's current
/// serializer uses its fixed stack bank; the other Hold fields borrow text.
pub(super) const fn hold_projection_transient_bytes_data() -> usize {
    (32 / 3) * 4 + 3
}

fn authenticate_hold_projection_data(
    held: &crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
) -> Result<(), StateError> {
    use crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold;
    // A new field requires reviewing the actual formatter-floor projection.
    let PacketNativeRestoredCommitHold {
        schema,
        native_pid: _,
        target_world: _,
        target_owner: _,
        target_owner_binding: _,
        target_activation: _,
        target_generation: _,
        captured_owner_state: _,
        captured_control: _,
        captured_journal: _,
        mapping: _,
        restore_commit: _,
        context_digest,
        local_cursor: _,
        inventory_hash: _,
        physical_gate_held: _,
    } = held;
    if schema != "source-owned.packet-restored-commit-held/12"
        || context_digest.as_slice().len() != 32
    {
        return Err(refused("historical scope Hold formatter grammar differs"));
    }
    Ok(())
}

/// Prices all future proof trees and scope copies from actual defining operands.
///
/// # Errors
/// Refuses another roster, missing target mapping, overflow or actual finite ceilings.
pub(super) fn construction_data(
    parent: &ParentArchive17ReadScope<'_, '_>,
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    operands: &proof::ScopeOperands17<'_>,
    bytes: &[u8],
    members: &[Initial15ScopeMember17<'_>; 3],
) -> Result<usize, StateError> {
    let maximum = maximum(parent, scope)?;
    let decoded = NodeRuntime::capture_selected_json_decode_storage(
        bytes,
        size_of::<proof::ScopeProof17>(),
        NodeRuntime::capture_map_node_storage::<String, Value>(),
        maximum,
    )
    .map_err(crate::node_state::schema)?;
    let original = operands.original_runtime_data()?;
    let target = &scope.runtime.source_activation;
    let parent_index = parent.manifest_data()?;
    if original.owners.len() != 4 || target.owners.len() != 4 || parent_index.owners.len() != 4 {
        return Err(refused("historical scope complete owner roster differs"));
    }
    let mut copies = 0usize;
    for member in members {
        let held = member
            .native
            .restoration_hold_data()
            .map_err(crate::node_state::schema)?;
        authenticate_hold_projection_data(held)?;
        copies = add(
            copies,
            NodeRuntime::capture_serialization_storage(held, maximum)
                .map_err(crate::node_state::schema)?,
            maximum,
        )?;
        copies = add(
            copies,
            NodeRuntime::capture_encoded_output_storage(held, maximum)
                .map_err(crate::node_state::schema)?,
            maximum,
        )?;
    }
    for term in [
        original.source_activation.owned_storage(),
        target.owned_storage(),
        operands
            .original
            .journal_data()
            .map_err(original_failure_data)?
            .runtime
            .owned_storage(),
        operands.reference.owned_storage(),
        Ok(4 * size_of::<OriginalLineageOwnerMapping>()),
        Ok(4 * size_of::<OriginalLineageJournal>()),
    ] {
        copies = add(copies, term.map_err(crate::node_state::schema)?, maximum)?;
    }
    for saved in &original.owners {
        let fresh = target
            .owners
            .iter()
            .find(|fresh| fresh.owner == saved.identity.owner)
            .ok_or_else(|| refused("historical scope target mapping absent"))?;
        copies = add(
            copies,
            saved
                .identity
                .owned_storage()
                .map_err(crate::node_state::schema)?,
            maximum,
        )?;
        copies = add(
            copies,
            fresh.owned_storage().map_err(crate::node_state::schema)?,
            maximum,
        )?;
    }
    for input in &original.inputs {
        if let Some(lineage) = &input.lineage {
            copies = add(copies, size_of::<SavedOriginalInputScope>(), maximum)?;
            copies = add(
                copies,
                lineage
                    .source
                    .owned_storage()
                    .map_err(crate::node_state::schema)?,
                maximum,
            )?;
        }
        if let Some(ack) = &input.acknowledgement {
            copies = add(copies, size_of::<NativeInputAcknowledgement>(), maximum)?;
            // Full old ACK backing is a conservative bound for its unchanged
            // fields; actual fresh owner/proof copies are charged independently.
            copies = add(
                copies,
                ack.owned_storage().map_err(crate::node_state::schema)?,
                maximum,
            )?;
            copies = add(
                copies,
                operands
                    .reference
                    .owned_storage()
                    .map_err(crate::node_state::schema)?,
                maximum,
            )?;
            copies = add(
                copies,
                input
                    .owners
                    .len()
                    .checked_mul(size_of::<crate::node_contract::OwnerIdentity>())
                    .ok_or_else(|| refused("historical scope ACK slot overflow"))?,
                maximum,
            )?;
            for owner in &input.owners {
                let mapped = target
                    .owners
                    .iter()
                    .find(|fresh| fresh.owner == owner.owner)
                    .ok_or_else(|| refused("historical scope ACK mapping absent"))?;
                copies = add(
                    copies,
                    mapped.owned_storage().map_err(crate::node_state::schema)?,
                    maximum,
                )?;
            }
        }
    }
    for owner in &parent_index.owners {
        let [node] = owner.participant_ids.as_slice() else {
            return Err(refused(
                "historical scope parent participant is not singleton",
            ));
        };
        copies = add(
            copies,
            node.owned_storage().map_err(crate::node_state::schema)?,
            maximum,
        )?;
        for saved in original
            .operations
            .iter()
            .filter(|saved| &saved.route.node == node)
        {
            let partitions = match saved.result {
                crate::node_contract::SavedRuntimeResult::Pending
                | crate::node_contract::SavedRuntimeResult::Acknowledged(_) => 2usize,
                crate::node_contract::SavedRuntimeResult::Complete(_)
                | crate::node_contract::SavedRuntimeResult::Failed(_) => 1usize,
            };
            let entry = size_of::<Id>()
                .checked_add(
                    saved
                        .operation
                        .owned_storage()
                        .map_err(crate::node_state::schema)?,
                )
                .and_then(|bytes| bytes.checked_mul(partitions))
                .ok_or_else(|| refused("historical scope operation journal copy overflow"))?;
            copies = add(copies, entry, maximum)?;
        }
        for saved in original.inputs.iter().filter(|saved| &saved.node == node) {
            copies = add(copies, size_of::<Id>(), maximum)?;
            copies = add(
                copies,
                saved
                    .stage_operation
                    .owned_storage()
                    .map_err(crate::node_state::schema)?,
                maximum,
            )?;
        }
    }
    // Original DOM, deserializer clone/typed root and roundtrip DOM overlap;
    // canonical bytes and encoder/parser temporary output are separate rows.
    decoded
        .checked_mul(3)
        .and_then(|n| {
            bytes
                .len()
                .checked_mul(2)
                .and_then(|encoded| n.checked_add(encoded))
        })
        .and_then(|n| n.checked_add(copies))
        .and_then(|n| n.checked_add(hold_projection_transient_bytes_data()))
        .and_then(|n| n.checked_add(HistoricalInitial15Scope17::counter_scratch_data()))
        .filter(|n| *n <= maximum)
        .ok_or_else(|| refused("historical scope complete construction row exhausted"))
}

impl HistoricalInitial15Scope17 {
    /// Counts backing of every actual initialized historical decoder owner.
    ///
    /// The enclosing output slot/Vec independently counts this inline header.
    ///
    /// # Errors
    /// Refuses another actor, defining storage overflow or the admitted bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_actor_data()?;
        let Self {
            archive_index: _,
            process: _,
            thread: _,
            value,
            canonical,
            proof,
            holds,
            hold_bytes,
            roundtrip,
            owners,
            first_scopes,
            journals,
            acknowledgements,
            completed,
            verified: _,
        } = self;
        let terms = [
            value.owned_storage()?,
            canonical.owned_storage()?,
            holds.iter().try_fold(0usize, |total, value| {
                total
                    .checked_add(value.owned_storage()?)
                    .ok_or(RuntimeError::ResourceLimit)
            })?,
            hold_bytes.iter().try_fold(0usize, |total, bytes| {
                total
                    .checked_add(bytes.owned_storage()?)
                    .ok_or(RuntimeError::ResourceLimit)
            })?,
            proof
                .as_ref()
                .map(proof::ScopeProof17::backing_data)
                .transpose()?
                .unwrap_or(0),
            roundtrip.owned_storage()?,
            owners.owned_storage()?,
            first_scopes.owned_storage()?,
            journals.owned_storage()?,
            acknowledgements.owned_storage()?,
            completed.owned_storage()?,
        ];
        terms.into_iter().try_fold(0usize, |total, bytes| {
            total
                .checked_add(bytes)
                .filter(|bytes| *bytes <= maximum)
                .ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Counts actual fixed borrowed decoder, hasher and constructor view frames.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<std::thread::Thread>() * 2
            + size_of::<proof::ScopeProof17>()
            + size_of::<Result<proof::ScopeProof17, serde_json::Error>>()
            + size_of::<proof::ScopeOperands17<'static>>()
            + size_of::<Result<proof::ScopeOperands17<'static>, StateError>>()
            + size_of::<Result<(), StateError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<[Result<usize, RuntimeError>; 6]>()
            + size_of::<std::array::IntoIter<Result<usize, RuntimeError>, 6>>()
            + size_of::<std::array::IntoIter<usize, 6>>()
            + size_of::<std::array::IntoIter<usize, 11>>()
            + size_of::<[usize; 11]>()
            + size_of::<std::array::IntoIter<&str, 4>>()
            + size_of::<std::slice::Iter<'static, Option<Value>>>()
            + size_of::<std::slice::Iter<'static, Option<Vec<u8>>>>()
            + size_of::<&crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold>()
            + size_of::<Result<&crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold, crucible_node_provider::ProviderError>>() * 3
            + size_of::<Result<&crucible_node_provider::reference_packet::service::complete_restore::transfer::PacketCompleteRestorePrepareRequest, crucible_node_provider::ProviderError>>() * 3
            + size_of::<crate::node_contract::ActivationRecord>()
            + size_of::<OriginalLineageNativeScope>()
            + size_of::<&[u8]>() * 3
            + size_of::<OriginalInitial15ArchivedOwnerRead<'static>>() * 2
            + size_of::<[[u8; 32]; 3]>()
            + size_of::<[Initial15ScopeMember17<'static>; 3]>()
            + size_of::<std::slice::Iter<'static, Initial15ScopeMember17<'static>>>()
            + size_of::<Result<serde_json::Value, serde_json::Error>>()
            + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
            + size_of::<[Option<&Id>; 3]>()
            + size_of::<[usize; 12]>()
            + size_of::<RestoredArchive17ValidationStep>()
            + size_of::<RestoredArchive17ValidationPrewalkData>()
            + size_of::<RestoredArchive17ValidationConstructionData>()
            + size_of::<Option<&dyn super::super::terminal::RestoredArchive17ValidationAdmission>>()
            + size_of::<std::slice::Iter<'static, crate::node_contract::SavedRuntimeOperation>>()
            + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageInputRecord>>(
            )
            + size_of::<std::slice::Iter<'static, crate::node_contract::SavedRuntimeOwner>>()
            + size_of::<std::slice::Iter<'static, crate::node_contract::OwnerIdentity>>()
            + size_of::<std::slice::Iter<'static, OriginalLineageOwnerMapping>>()
            + size_of::<std::slice::Iter<'static, crucible_node_contract::CapturedOwner>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 64]>()
            + size_of::<[u8; 20]>()
            + size_of::<String>()
            + size_of::<[u8; 4]>()
            + size_of::<[u8; 8]>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<std::ops::RangeInclusive<u8>>()
            + size_of::<Option<u64>>()
            + borrowed_json::counter_scratch_data() * 5
            + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            + NodeRuntime::original_json_value_counter_scratch_data()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + crucible_node_provider::reference_packet::service::complete_restore::restored_commit_hold_serialization_counter_scratch_data()
            + OriginalInitial15ArchivedGroup::counter_scratch_data()
    }
}

/// Admits actual Core/content/outer/partial owners with one independent future row.
///
/// # Errors
/// Refuses foreign origin, defining census errors, overflow or simultaneous exhaustion.
pub(super) fn admit_data(
    parent: &ParentArchive17ReadScope<'_, '_>,
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    owner: Option<&HistoricalInitial15Scope17>,
    additional: usize,
    temporary: usize,
) -> Result<(), StateError> {
    let maximum = maximum(parent, scope)?;
    let retained = owner
        .map(|owner| owner.retained_requested_storage_data(maximum))
        .transpose()
        .map_err(crate::node_state::schema)?
        .unwrap_or(0);
    [
        scope.retained_core_bytes_excluding_collection_data()?,
        scope.retained_verified_content_allocation_bytes()?,
        additional,
        size_of::<Option<HistoricalInitial15Scope17>>(),
        retained,
        temporary,
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| add(total, bytes, maximum))?;
    Ok(())
}

fn add(total: usize, bytes: usize, maximum: usize) -> Result<usize, StateError> {
    total
        .checked_add(bytes)
        .filter(|n| *n <= maximum)
        .ok_or_else(|| refused("historical scope simultaneous storage exhausted"))
}
