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
}

/// Classifies every bounded candidate before any adoption effect.
///
/// # Errors
/// Refuses global inventory errors and every unsupported or unresolved case.
pub(super) fn preflight(inventory: &NativeRecoveryInspection) -> io::Result<()> {
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
/// Refuses pending bodies, loose chunks, broken/missing indexes, unsupported key
/// fields and any issue beyond the sealed witness supplied by actual adoption.
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
        && plan.detached_index_status() == DetachedIndexStatus::Matches
        && key.pack_id.as_slice() == plan.pack_id().as_bytes()
    {
        return Ok(RecoveryCase::Pack);
    }
    Err(unresolved(
        "unsupported loose, missing-index or unresolved recovery candidate",
    ))
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}
