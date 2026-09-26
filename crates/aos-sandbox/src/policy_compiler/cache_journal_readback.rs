//! Root policy precursor for fixed-name Cache journal replay.
//!
//! The readback checks the root-only mount and delegates complete Cache
//! verification to the Cache owner code. It does not issue policy binding or
//! public Create authority.

use crate::cache_residency::{
    CacheOwnerReadbackChallengeV1, CacheOwnerReadbackErrorV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyRootReadOnlyPolicyHoldV1,
    CacheResidencyRootReadOnlyReplayV1, PinnedCacheOwnerReadbackSignerV1,
    VerifiedClosedCacheOwnerReadbackV2, replay_fixed_root_read_only_cache_journals_v1,
    replay_fixed_root_read_only_cache_policy_hold_v1, verify_closed_cache_owner_readback_v2,
};
use crate::journal::CachePolicyHoldV1;

/// Reports a rejected joined Cache receipt under root's read-only replay.
#[derive(Debug, thiserror::Error)]
pub enum ClosedCacheJoinedReadbackErrorV2 {
    /// The signed and independently replayed Cache cut disagree.
    #[error("joined Cache receipt is stale")]
    Stale,
    /// The Cache-purpose packet failed canonical or signature verification.
    #[error(transparent)]
    Receipt(#[from] CacheOwnerReadbackErrorV1),
    /// The fixed read-only Cache view failed typed replay or name checks.
    #[error(transparent)]
    Journal(#[from] CacheResidencyProtectedJournalErrorV1),
}

/// Replays the root policy Cache view as nonauthorizing diagnostic evidence.
///
/// The fixed physical names and authority checks are owned by Cache code. A
/// Controller cut must be established separately before any Q04 admission.
///
/// # Errors
///
/// Rejects an unsafe mount, changed physical name, malformed journal or Cache
/// authority, expired manifest, or invalid typed replay.
pub fn read_fixed_policy_cache_journals_v1()
-> Result<CacheResidencyRootReadOnlyReplayV1, CacheResidencyProtectedJournalErrorV1> {
    replay_fixed_root_read_only_cache_journals_v1()
}

/// Observes one active protected Cache hold through the fixed root-only view.
///
/// The returned binding and epoch are Cache-owned observations. A future root
/// CAS must compare them against root-owned expected values; this function
/// cannot authorize Q04, public Create, or an effect handoff.
///
/// # Errors
///
/// Rejects an unsafe or changed view, missing or malformed hold, stale Cache
/// authority, or a hold that does not match the replayed project partition.
pub fn read_fixed_policy_cache_hold_v1()
-> Result<CacheResidencyRootReadOnlyPolicyHoldV1, CacheResidencyProtectedJournalErrorV1> {
    replay_fixed_root_read_only_cache_policy_hold_v1()
}

/// Compares a v2 Cache receipt with root's fixed read-only four-journal replay.
///
/// The caller must supply a durably spent root challenge, its independently
/// pinned Cache-purpose signer, and the root's exact expected hold. This
/// comparison does not hold the remote Cache writers or grant Q04; an ordered
/// all-owner CAS and recoverable handoff remain required.
///
/// # Errors
///
/// Rejects bad signatures or framing, absent or changed root-only mount,
/// invalid typed replay, or a mismatched hold or complete quota envelope.
pub fn verify_fixed_policy_cache_owner_readback_v2(
    bytes: &[u8],
    signer: &PinnedCacheOwnerReadbackSignerV1,
    challenge: CacheOwnerReadbackChallengeV1,
    expected_owner_uid: u32,
    expected_hold: CachePolicyHoldV1,
) -> Result<VerifiedClosedCacheOwnerReadbackV2, ClosedCacheJoinedReadbackErrorV2> {
    let observed = read_fixed_policy_cache_hold_v1()?;
    compare_cache_owner_readback_v2(
        bytes,
        signer,
        challenge,
        expected_owner_uid,
        expected_hold,
        observed,
    )
}

fn compare_cache_owner_readback_v2(
    bytes: &[u8],
    signer: &PinnedCacheOwnerReadbackSignerV1,
    challenge: CacheOwnerReadbackChallengeV1,
    expected_owner_uid: u32,
    expected_hold: CachePolicyHoldV1,
    observed: CacheResidencyRootReadOnlyPolicyHoldV1,
) -> Result<VerifiedClosedCacheOwnerReadbackV2, ClosedCacheJoinedReadbackErrorV2> {
    let receipt =
        verify_closed_cache_owner_readback_v2(bytes, signer, challenge, expected_owner_uid)?;
    if receipt.hold() != expected_hold
        || receipt.hold() != observed.hold
        || receipt.quota_digest() != observed.replay.quota_digest
    {
        return Err(ClosedCacheJoinedReadbackErrorV2::Stale);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{ObjectDigest, ProjectId};
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::cache_residency::{
        CacheResidencyProtectedOpenReportV1, encode_cache_owner_readback_signer_credential_v1,
        sign_test_cache_owner_readback_v2,
    };
    use crate::journal::RecoveryReport;

    #[test]
    fn joined_comparison_rejects_stale_hold_quota_and_replayed_packet() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let credential = encode_cache_owner_readback_signer_credential_v1(9, &key.verifying_key())
            .expect("Cache credential");
        let signer = PinnedCacheOwnerReadbackSignerV1::decode(&credential).expect("Cache pin");
        let challenge =
            CacheOwnerReadbackChallengeV1::new([6; 16], ObjectDigest::from_bytes([7; 32]))
                .expect("root challenge");
        let hold = CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .expect("active hold");
        let quota = ObjectDigest::from_bytes([10; 32]);
        let packet = sign_test_cache_owner_readback_v2(challenge, 9, &key, 811, hold, quota)
            .expect("signed joined receipt");
        let replay = CacheResidencyRootReadOnlyPolicyHoldV1 {
            replay: CacheResidencyRootReadOnlyReplayV1 {
                journals: CacheResidencyProtectedOpenReportV1 {
                    state: RecoveryReport::default(),
                    authority: RecoveryReport::default(),
                    clock: RecoveryReport::default(),
                },
                partitions: 1,
                quota_digest: quota,
            },
            hold_journal: RecoveryReport::default(),
            hold,
        };
        assert!(
            compare_cache_owner_readback_v2(&packet, &signer, challenge, 811, hold, replay).is_ok()
        );

        let mut changed_quota = replay;
        changed_quota.replay.quota_digest = ObjectDigest::from_bytes([11; 32]);
        assert!(
            compare_cache_owner_readback_v2(&packet, &signer, challenge, 811, hold, changed_quota)
                .is_err()
        );
        let different_hold = CachePolicyHoldV1::new(
            hold.project(),
            hold.partition(),
            ObjectDigest::from_bytes([12; 32]),
            hold.binding(),
            hold.epoch(),
        )
        .expect("different replay head");
        let mut changed_head = replay;
        changed_head.hold = different_hold;
        assert!(
            compare_cache_owner_readback_v2(&packet, &signer, challenge, 811, hold, changed_head)
                .is_err()
        );
        let stale_challenge =
            CacheOwnerReadbackChallengeV1::new([12; 16], ObjectDigest::from_bytes([7; 32]))
                .expect("new root challenge");
        assert!(
            compare_cache_owner_readback_v2(&packet, &signer, stale_challenge, 811, hold, replay)
                .is_err()
        );
    }
}
