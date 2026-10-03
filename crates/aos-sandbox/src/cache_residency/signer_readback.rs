//! Joined nonauthorizing Cache observation from the signer-only views.
//!
//! The independent signer sees original fixed names through two read-only
//! idmapped mounts. It cannot retain the Controller's physical flock or
//! protected writers, so this paired readback is never a held authority cut.

use ed25519_dalek::SigningKey;
use thiserror::Error;

use super::CacheResidencyProtectedJournalErrorV1;
use super::effect_owner::{
    CacheOwnerErrorV1, CacheOwnerLimitsV1, CacheSignerObjectReadbackV1, FIXED_CACHE_ROOT,
    SIGNER_OBJECT_VIEW, read_fixed_signer_cache_object_view_v1,
};
use super::owner_readback::{
    CLOSED_CACHE_OWNER_READBACK_BYTES_V2, CacheOwnerReadbackChallengeV1, CacheOwnerReadbackErrorV1,
    CacheOwnerReadbackFieldsV1, cache_owner_limits_digest_v1, sign_closed_cache_owner_readback_v2,
};
use super::protected_owner::{
    CacheResidencyRootReadOnlyPolicyHoldV1, PROTECTED_CACHE_ROOT, SIGNER_READ_ONLY_CACHE_VIEW,
    derive_fixed_signer_cache_policy_hold_and_limits_v1,
};
use super::signer_mount::require_signer_mount;

/// Reports the two independently replayed Cache views for one signer observation.
///
/// This value contains no writer lease, signature, all-owner cut, or effect
/// capability. A future signer exchange must bind it to a Controller-held
/// challenge and the root's separately verified authority barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CacheSignerJoinedReadbackV1 {
    /// Identifies the physical object root, lock, manifest, and durable head.
    pub(crate) physical: CacheSignerObjectReadbackV1,
    /// Identifies the active protected hold and complete quota envelope.
    pub(crate) protected: CacheResidencyRootReadOnlyPolicyHoldV1,
    /// Holds the physical owner envelope derived from complete protected quotas.
    pub(crate) limits: CacheOwnerLimitsV1,
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
    /// The replayed facts cannot be encoded as a canonical signed packet.
    #[error(transparent)]
    Signing(#[from] CacheOwnerReadbackErrorV1),
    /// One of the two observations changed during the paired readback.
    #[error("stale Cache signer readback")]
    Stale,
}

/// Signs one challenge using facts replayed through both fixed signer views.
///
/// This method opens and replays the two original-name views itself, then
/// rechecks them after signing. The caller must authenticate the challenge as
/// root-owned and retain the Controller's writer across root's all-owner CAS;
/// this packet alone is not a held cut or publication authority. The caller
/// must supply the signer's separately provisioned heap ceiling. All other
/// physical limits are derived from the complete protected Cache quota set.
///
/// # Errors
///
/// Rejects missing or unsafe views, changed names or replay heads, invalid
/// limits, or a noncanonical challenge or packet.
pub fn sign_fixed_signer_cache_owner_readback_v2(
    maximum_memory_bytes: u64,
    challenge: CacheOwnerReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2], CacheSignerReadbackErrorV1> {
    let joined = read_fixed_signer_cache_owner_views_v1(maximum_memory_bytes)?;
    let physical = joined.physical;
    let (root_device, root_inode) = physical.root_identity();
    let (lock_device, lock_inode) = physical.lock_identity();
    let current = physical.currentness();
    let fields = CacheOwnerReadbackFieldsV1 {
        root_device,
        root_inode,
        root_uid: physical.owner_uid(),
        root_mode: 0o700,
        lock_device,
        lock_inode,
        manifest_generation: current.generation(),
        manifest_digest: current.digest(),
        limits_digest: cache_owner_limits_digest_v1(joined.limits)?,
    };
    let hold = joined.protected.hold;
    let quota_digest = joined.protected.replay.quota_digest;
    let packet = sign_closed_cache_owner_readback_v2(
        fields,
        physical.manifest_identity(),
        hold,
        quota_digest,
        challenge,
        signer_generation,
        signing_key,
    )?;

    if read_fixed_signer_cache_owner_views_v1(maximum_memory_bytes)? != joined {
        return Err(CacheSignerReadbackErrorV1::Stale);
    }
    Ok(packet)
}

/// Replays both signer views with matching source UID and physical quota limits.
///
/// Both views are checked again after the joined read. These checks reject
/// changed observations but do not hold either Controller-owned writer. Root
/// must still bind a fresh challenge to the typed held Cache callback and all
/// other owners before any Q04 compare-and-swap or effect handoff. The memory
/// ceiling needs signer-private deployment provenance; this helper cannot
/// establish it from the caller's value.
///
/// # Errors
///
/// Rejects unsafe mounts or source ownership, invalid physical or protected
/// replay, invalid derived limits, or changed observations.
pub(crate) fn read_fixed_signer_cache_owner_views_v1(
    maximum_memory_bytes: u64,
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

    let (protected, limits) =
        derive_fixed_signer_cache_policy_hold_and_limits_v1(maximum_memory_bytes)?;
    let physical = read_fixed_signer_cache_object_view_v1(limits)?;
    if physical.owner_uid() != journal_mount.source_uid() {
        return Err(CacheSignerReadbackErrorV1::Stale);
    }

    // A changed name or replay must never escape as a joined observation,
    // even when both individual reads were internally consistent.
    if derive_fixed_signer_cache_policy_hold_and_limits_v1(maximum_memory_bytes)?
        != (protected, limits)
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
        limits,
    })
}
