//! Joins actual current17 administrative facts without an archive-load receipt.
//!
//! This validator reuses the defining original lifetime/once grammar. The
//! borrowed parent scope supplies all operands; no current generation source,
//! native key or selected-load marker is constructed from them.

use super::*;
use crate::node_state::NativeOwnerState;
use crucible_node_format::{CaptureManifest, ContentRef};
use crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentCheckpoint17;

/// Checks the exact actual parent journal and its all-attempt dependency roles.
///
/// # Errors
/// Refuses changed lifetime history, current manifest/checkpoint or owner rows,
/// omitted/extra full dependencies or a non-current17 coordinator role.
pub(in crate::node_state::native) fn authenticate_current17_parent_parts_data(
    manifest: &CaptureManifest,
    owners: &[NativeOwnerState],
    journal: &RuntimeOriginalCaptureJournal,
    checkpoint: &CoordinatorCommitmentCheckpoint17,
    dependencies: &[ContentRef],
    maximum_record: usize,
) -> Result<(), StateError> {
    validate_journal(journal, maximum_record)?;

    let current = journal
        .attempts
        .last()
        .ok_or_else(|| refused("parent administrative current attempt absent"))?;

    if owners.len() != 4
        || manifest.owners.len() != 4
        || current.capture_id != manifest.capture_id
        || current.source_activation.world_binding_hash != manifest.world_binding_hash
        || current.cut != manifest.cut
        || current.ordinal != manifest.event_ordinal
        || current.source_runtime != checkpoint.safe_point.runtime
        || manifest.coordinator_state_ref.media_type != crucible_node_transport::reference_packet::service::complete_restore::settled_recapture::COORDINATOR_CHECKPOINT17_MEDIA
    {
        return Err(refused(
            "current17 parent administrative cut or coordinator differs"
        ));
    }

    for (saved, native) in current.owners.iter().zip(owners) {
        let OriginalCaptureOwnerState::Settled { snapshot, journal } = &saved.state else {
            return Err(refused(
                "current17 parent administrative owner is unsettled",
            ));
        };
        if saved.owner.owner != native.owner
            || saved.participants != native.participants
            || snapshot != &native.state
            || !native.evidence.contains(journal)
        {
            return Err(refused("current17 parent administrative owner differs"));
        }
    }

    if dependencies.windows(2).any(|pair| pair[0] >= pair[1])
        || dependencies.iter().any(|reference| {
            !journal.attempts.iter().any(|attempt| {
                reference == &attempt.source_runtime
                    || attempt.owners.iter().any(|owner| {
                        matches!(
                            &owner.state,
                            OriginalCaptureOwnerState::Settled { snapshot, journal }
                                if reference == snapshot || reference == journal.as_ref()
                        )
                    })
            })
        })
        || journal.attempts.iter().any(|attempt| {
            !dependencies.contains(&attempt.source_runtime)
                || attempt.owners.iter().any(|owner| {
                    !matches!(
                        &owner.state,
                        OriginalCaptureOwnerState::Settled { snapshot, journal }
                            if dependencies.contains(snapshot)
                                && dependencies.contains(journal.as_ref())
                    )
                })
        })
    {
        return Err(refused(
            "current17 parent administrative full dependency roles differ",
        ));
    }

    Ok(())
}
