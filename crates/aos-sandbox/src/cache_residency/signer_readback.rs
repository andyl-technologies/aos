//! Joined nonauthorizing Cache observation from the signer-only views.
//!
//! The independent signer sees original fixed names through two read-only
//! idmapped mounts. It cannot retain the Controller's physical flock or
//! protected writers, so this paired readback is never a held authority cut.

use thiserror::Error;

use super::CacheResidencyProtectedJournalErrorV1;
use super::effect_owner::{
    CacheOwnerErrorV1, CacheOwnerLimitsV1, CacheSignerObjectReadbackV1, FIXED_CACHE_ROOT,
    SIGNER_OBJECT_VIEW, read_fixed_signer_cache_object_view_v1,
};
use super::protected_owner::{
    CacheResidencyRootReadOnlyPolicyHoldV1, PROTECTED_CACHE_ROOT, SIGNER_READ_ONLY_CACHE_VIEW,
    replay_fixed_signer_cache_policy_hold_with_limits_v1,
};
use super::signer_mount::require_signer_mount;

/// Reports the two independently replayed Cache views for one signer observation.
///
/// This value contains no writer lease, signature, all-owner cut, or effect
/// capability. A future signer exchange must bind it to a Controller-held
/// challenge and the root's separately verified authority barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheSignerJoinedReadbackV1 {
    /// Identifies the physical object root, lock, manifest, and durable head.
    pub physical: CacheSignerObjectReadbackV1,
    /// Identifies the active protected hold and complete quota envelope.
    pub protected: CacheResidencyRootReadOnlyPolicyHoldV1,
}

/// Rejects an unsafe or changing pair of signer-only Cache views.
#[derive(Debug, Error)]
pub enum CacheSignerReadbackErrorV1 {
    /// The mounted view or original fixed root cannot be trusted.
    #[error("unsafe Cache signer view: {0}")]
    View(#[from] std::io::Error),
    /// Physical Cache names, limits, or the manifest did not replay.
    #[error(transparent)]
    Physical(#[from] CacheOwnerErrorV1),
    /// Protected Cache journals or quota envelopes did not replay.
    #[error(transparent)]
    Protected(#[from] CacheResidencyProtectedJournalErrorV1),
    /// One of the two observations changed during the paired readback.
    #[error("stale Cache signer readback")]
    Stale,
}

/// Replays both signer views with matching source UID and physical quota limits.
///
/// Both views are checked again after the joined read. These checks reject
/// changed observations but do not hold either Controller-owned writer. Root
/// must still bind a fresh challenge to the typed held Cache callback and all
/// other owners before any Q04 compare-and-swap or effect handoff.
///
/// # Errors
///
/// Rejects unsafe mounts or source ownership, invalid physical or protected
/// replay, quota/limit mismatch, or changed observations.
pub fn read_fixed_signer_cache_owner_views_v1(
    limits: CacheOwnerLimitsV1,
) -> Result<CacheSignerJoinedReadbackV1, CacheSignerReadbackErrorV1> {
    let signer_uid = rustix::process::geteuid().as_raw();
    let object_mount = require_signer_mount(SIGNER_OBJECT_VIEW, FIXED_CACHE_ROOT, signer_uid)?;
    let journal_mount = require_signer_mount(
        SIGNER_READ_ONLY_CACHE_VIEW,
        PROTECTED_CACHE_ROOT,
        signer_uid,
    )?;
    if object_mount.source_uid() != journal_mount.source_uid() {
        return Err(CacheSignerReadbackErrorV1::Stale);
    }

    let physical = read_fixed_signer_cache_object_view_v1(limits)?;
    let protected = replay_fixed_signer_cache_policy_hold_with_limits_v1(limits)?;
    if physical.owner_uid() != journal_mount.source_uid() {
        return Err(CacheSignerReadbackErrorV1::Stale);
    }

    // A changed name or replay must never escape as a joined observation,
    // even when both individual reads were internally consistent.
    if replay_fixed_signer_cache_policy_hold_with_limits_v1(limits)? != protected
        || read_fixed_signer_cache_object_view_v1(limits)? != physical
        || require_signer_mount(SIGNER_OBJECT_VIEW, FIXED_CACHE_ROOT, signer_uid)? != object_mount
        || require_signer_mount(
            SIGNER_READ_ONLY_CACHE_VIEW,
            PROTECTED_CACHE_ROOT,
            signer_uid,
        )? != journal_mount
    {
        return Err(CacheSignerReadbackErrorV1::Stale);
    }

    Ok(CacheSignerJoinedReadbackV1 {
        physical,
        protected,
    })
}
