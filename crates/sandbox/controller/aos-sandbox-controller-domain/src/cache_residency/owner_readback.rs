//! Keeps actual Cache readback capture/signing and its physical error lane.
//!
//! Protocol owns the sole raw models, fields, codec and signature DATA recipes.
//! Native owners, actual keys, limits and independently owed posts remain here
//! and in the original upper signing programme; no Verified model is adopted.

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use aos_sandbox_protocol::cache_owner_readback::{
    CLOSED_CACHE_OWNER_READBACK_BODY_BYTES_V2, CLOSED_CACHE_OWNER_READBACK_BYTES_V2,
    CacheOwnerReadbackChallengeV1,
    CacheOwnerReadbackDataErrorV1, CacheOwnerReadbackFieldsDataV1,
    prepare_closed_cache_owner_readback_data_v2,
    cache_owner_readback_signing_preimage_data_v2, cache_owner_readback_signature_data_v2,
};
use ed25519_dalek::{Signer as _, SigningKey};
use thiserror::Error;

use super::effect_owner::{CacheOwnerErrorV1, CacheOwnerLimitsV1};

/// Rejects malformed, stale, or unauthenticated closed readbacks.
#[derive(Debug, Error)]
pub enum CacheOwnerReadbackErrorV1 {
    /// The credential, challenge, or readback framing is not canonical.
    #[error("noncanonical Cache owner readback")]
    NonCanonical,
    /// The packet does not bind this signer generation and held root session.
    #[error("stale Cache owner readback challenge")]
    Stale,
    /// The Cache-purpose signature does not verify.
    #[error("invalid Cache owner readback signature")]
    Signature,
    /// The physical owner lost its held fixed-name proof.
    #[error("Cache owner readback lost held custody: {0}")]
    Owner(#[from] CacheOwnerErrorV1),
}

impl From<CacheOwnerReadbackDataErrorV1> for CacheOwnerReadbackErrorV1 {
    fn from(cause: CacheOwnerReadbackDataErrorV1) -> Self {
        match cause {
            CacheOwnerReadbackDataErrorV1::NonCanonical => Self::NonCanonical,
            CacheOwnerReadbackDataErrorV1::Stale => Self::Stale,
            CacheOwnerReadbackDataErrorV1::Signature => Self::Signature,
        }
    }
}

pub(super) fn sign_closed_cache_owner_readback_v2(
    fields: CacheOwnerReadbackFieldsDataV1,
    manifest_identity: Option<(u64, u64)>,
    hold: CachePolicyHoldV1,
    quota_digest: ObjectDigest,
    challenge: CacheOwnerReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2], CacheOwnerReadbackErrorV1> {
    let bytes = prepare_closed_cache_owner_readback_data_v2(
        fields, manifest_identity, hold, quota_digest, challenge, signer_generation,
    ).map_err(CacheOwnerReadbackErrorV1::from)?;
    let preimage = cache_owner_readback_signing_preimage_data_v2(
        &bytes[..CLOSED_CACHE_OWNER_READBACK_BODY_BYTES_V2],
    );
    Ok(finish_closed_cache_owner_readback_v2(bytes, preimage, signing_key))
}

fn finish_closed_cache_owner_readback_v2(
    mut bytes: [u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2],
    preimage: Vec<u8>,
    signing_key: &SigningKey,
) -> [u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2] {
    let signature = signing_key.sign(&preimage);
    // Match the original signing temporary's lifetime, before copying.
    drop(preimage);
    cache_owner_readback_signature_data_v2(&mut bytes, &signature);
    bytes
}

#[cfg(test)]
pub(crate) fn sign_test_cache_owner_readback_v2(
    challenge: CacheOwnerReadbackChallengeV1,
    generation: u64,
    signing_key: &SigningKey,
    owner_uid: u32,
    hold: CachePolicyHoldV1,
    quota_digest: ObjectDigest,
) -> Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2], CacheOwnerReadbackErrorV1> {
    sign_closed_cache_owner_readback_v2(
        CacheOwnerReadbackFieldsDataV1 {
            root_device: 11,
            root_inode: 12,
            root_uid: owner_uid,
            root_mode: 0o700,
            lock_device: 11,
            lock_inode: 13,
            manifest_generation: 7,
            manifest_digest: ObjectDigest::from_bytes([4; 32]),
            limits_digest: ObjectDigest::from_bytes([5; 32]),
        },
        Some((11, 14)),
        hold,
        quota_digest,
        challenge,
        generation,
        signing_key,
    )
}

pub(super) fn cache_owner_limits_digest_v1(
    limits: CacheOwnerLimitsV1,
) -> Result<ObjectDigest, CacheOwnerReadbackErrorV1> {
    let positive = u64::try_from(limits.maximum_positive_entries)
        .map_err(|_| CacheOwnerReadbackErrorV1::NonCanonical)?;
    let negative = u64::try_from(limits.maximum_negative_entries)
        .map_err(|_| CacheOwnerReadbackErrorV1::NonCanonical)?;
    let pins =
        u64::try_from(limits.maximum_pins).map_err(|_| CacheOwnerReadbackErrorV1::NonCanonical)?;
    Ok(aos_sandbox_protocol::cache_state::physical_manifest::cache_physical_limit_fields_digest_v1([
        limits.maximum_memory_bytes, limits.maximum_disk_bytes, limits.disk_low_water_bytes,
        positive, negative, pins, limits.maximum_pinned_bytes,
    ]))
}
