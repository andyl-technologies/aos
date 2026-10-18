//! Reuses the original administrative validator for an authenticated parent read.
//!
//! A parsed Index body cannot create a NativeArchiveRecord or load receipt. The
//! actual parent scope supplies its exact private manifest/owners/dependencies.

use super::*;
use crate::node_state::NativeOwnerState;
use crucible_node_contract::{CaptureManifest, ContentRef};

/// Reuses exact original journal grammar and joins actual parent settlement rows.
///
/// # Errors
/// Refuses another original capture, changed owner/runtime roles, unsettled
/// history or dependency rows that omit or add an original settlement role.
pub(in crate::node_state::native) fn authenticate_initial15_parent_parts_data(
    manifest: &CaptureManifest,
    owners: &[NativeOwnerState],
    administrative: &RuntimeOriginalCaptureJournal,
    runtime: &ContentRef,
    scheduler: &ContentRef,
    dependencies: &[ContentRef],
    maximum: usize,
) -> Result<(), StateError> {
    validate_journal(administrative, maximum)?;
    let [attempt] = administrative.attempts.as_slice() else {
        return Err(refused(
            "initial15 original archive requires one actual Capture attempt",
        ));
    };
    if owners.len() != 4
        || attempt.capture_id != manifest.capture_id
        || attempt.source_activation.world_binding_hash != manifest.world_binding_hash
        || attempt.cut != manifest.cut
        || attempt.ordinal != manifest.event_ordinal
        || &attempt.source_runtime != runtime
        || scheduler.media_type != "application/json"
    {
        return Err(refused("initial15 administrative manifest/runtime differs"));
    }
    for (saved, native) in attempt.owners.iter().zip(owners) {
        let OriginalCaptureOwnerState::Settled { snapshot, journal } = &saved.state else {
            return Err(refused("initial15 administrative owner is not settled"));
        };
        if saved.owner.owner != native.owner
            || saved.participants != native.participants
            || snapshot != &native.state
            || !native.evidence.contains(journal)
        {
            return Err(refused(
                "initial15 administrative owner differs from parent inventory",
            ));
        }
    }
    // An allocation-free set comparison preserves the exact original dependency
    // roster. The independent original validator above has checked all four rows.
    if !dependencies.contains(runtime)
        || dependencies.iter().any(|reference| {
            reference != runtime
                && !attempt.owners.iter().any(|owner| {
                    matches!(&owner.state,
                    OriginalCaptureOwnerState::Settled { snapshot, journal }
                    if reference == snapshot || reference == journal.as_ref())
                })
        })
        || attempt.owners.iter().any(|owner| {
            !matches!(&owner.state,
                OriginalCaptureOwnerState::Settled { snapshot, journal }
                if dependencies.contains(snapshot) && dependencies.contains(journal))
        })
    {
        return Err(refused(
            "initial15 administrative full dependency roles differ",
        ));
    }
    Ok(())
}
