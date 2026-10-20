//! Classifies supported recovery cases without upgrading inventory to authority.
//!
//! Every candidate is checked before native adoption begins. Metadata packs are
//! provisional inputs only: final exhaustive namespace/source closure must prove
//! that each actual pack and index is required by a retained verified manifest.

use crate::{
    host_cache::{
        DetachedIndexStatus, NativeRecoveryCandidate, NativeRecoveryInspection, RecoveryIssue,
        VerifiedEncodedBody,
    },
    publisher_local::wire::BodyKind,
};
use std::io;
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};

/// Identifies candidate work, never native pin, content or serving authority.
pub(super) enum RecoveryCase {
    /// Identifies still-unadopted inline content for native verification.
    Inline,
    /// Names reconstruction metadata whose actual bytes still require retention.
    Manifest(Identity),
    /// Retains a verified container provisionally until exact source closure matching.
    Pack,
    /// Identifies a fully verified pack whose detached index needs a funded write.
    RepairIndex,
}

/// Classifies every bounded candidate before any adoption effect.
///
/// # Errors
/// Refuses global inventory errors and every unsupported or unresolved case.
pub(super) fn preflight(inventory: &NativeRecoveryInspection) -> io::Result<()> {
    preflight_repairable(inventory)?;
    for candidate in inventory.candidates() {
        if matches!(classify(candidate)?, RecoveryCase::RepairIndex) {
            return Err(unresolved(
                "detached index repair is not yet durably reconciled",
            ));
        }
    }
    Ok(())
}

/// Refuses unsupported candidates before any bounded startup index repair.
///
/// # Errors
/// Refuses global failures, pending content and corrupt or unhandled candidates.
pub(super) fn preflight_repairable(inventory: &NativeRecoveryInspection) -> io::Result<()> {
    if inventory.inventory_failure().is_some() || inventory.namespace_failure().is_some() {
        return Err(unresolved(
            "recovery inventory has unresolved global failures",
        ));
    }
    for candidate in inventory.candidates() {
        classify(candidate)?;
    }
    Ok(())
}

/// Classifies a genuine candidate while preserving all unresolved observations.
///
/// # Errors
/// Refuses pending bodies, loose chunks, mismatching indexes, unsupported key
/// fields and any issue beyond the sealed witness supplied by actual adoption.
/// A missing index is repair work, never a completed candidate for adoption.
pub(super) fn classify(candidate: &NativeRecoveryCandidate) -> io::Result<RecoveryCase> {
    if candidate.pending_observation().is_some() {
        return Err(unresolved("pending recovery body is not yet supported"));
    }
    let key = candidate.key();
    if key.kind == BodyKind::Sealed as i32 {
        if key.codec != 0
            || !key.pack_id.is_empty()
            || !matches!(candidate.issues(), [RecoveryIssue::SealedWitnessRequired])
        {
            return Err(unresolved(
                "sealed candidate retains unresolved fields or issues",
            ));
        }
        let descriptor =
            Descriptor::decode(&TERRANE_V1, &key.descriptor).map_err(io::Error::other)?;
        return match TERRANE_V1
            .kind(descriptor.domain())
            .map_err(io::Error::other)?
        {
            IdentityKind::Chunk => Ok(RecoveryCase::Inline),
            IdentityKind::Manifest => Ok(RecoveryCase::Manifest(
                TERRANE_V1
                    .from_digest(IdentityKind::Manifest, descriptor.digest())
                    .map_err(io::Error::other)?,
            )),
            _ => Err(unresolved("unsupported sealed descriptor kind")),
        };
    }
    if key.kind == BodyKind::Pack as i32
        && key.codec == 0
        && key.descriptor.is_empty()
        && candidate.issues().is_empty()
        && let Some(VerifiedEncodedBody::Pack(plan)) = candidate.verified()
        && key.pack_id.as_slice() == plan.pack_id().as_bytes()
    {
        return match plan.detached_index_status() {
            DetachedIndexStatus::Matches => Ok(RecoveryCase::Pack),
            DetachedIndexStatus::Missing => Ok(RecoveryCase::RepairIndex),
            DetachedIndexStatus::Mismatch => Err(unresolved(
                "recovery will not overwrite a mismatching detached index",
            )),
        };
    }
    Err(unresolved(
        "unsupported loose, missing-index or unresolved recovery candidate",
    ))
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}
