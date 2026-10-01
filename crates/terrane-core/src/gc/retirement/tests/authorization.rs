//! Checks disjoint independently transcribed authorization/preparation bytes.

use super::*;

#[test]
fn permanent_authorizations_match_independent_disjoint_v2_bytes() {
    for (copy, local) in [(false, false), (true, false), (true, true)] {
        let bytes = auth_bytes(copy, local);
        let value = PermanentDeleteAuthorization::decode(&bytes).unwrap();
        assert_eq!(value.encode().unwrap(), bytes);
        assert_eq!(value.exclusion(), &exclusion());
        assert_eq!(value.nonce(), &NONCE);
        value.check_key(&key()).unwrap();
        assert!(value.check_key(&key().replace("gc/3/", "gc/4/")).is_err());
        assert!(value.check_key(&key().replace("3434", "3435")).is_err());
        assert!(value.check_key(&key().replace("gc/3/", "gc/03/")).is_err());
        value.check_commit_duration(0).unwrap();
        assert!(value.check_commit_duration(1).is_err());
        assert!(value.check_commit_duration(u64::MAX).is_err());
        assert_eq!(
            RemoteSweepDeleteAuthorization::decode(&bytes).is_ok(),
            !copy
        );
        assert_eq!(CopiedRetirementAuthorization::decode(&bytes).is_ok(), copy);
        for cut in 0..bytes.len() {
            assert!(
                PermanentDeleteAuthorization::decode(&bytes[..cut]).is_err(),
                "{copy}/{local} at {cut}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PermanentDeleteAuthorization::decode(&trailing).is_err());
        let mut noncanonical = bytes.clone();
        noncanonical.splice(2..3, [0x18, 2]);
        assert!(PermanentDeleteAuthorization::decode(&noncanonical).is_err());
        let mut unknown = bytes;
        unknown[1] = 1;
        assert!(PermanentDeleteAuthorization::decode(&unknown).is_err());
    }
}

#[test]
fn sweep_requires_initial_remote_artifacts_witness_and_full_checked_waits() {
    let value = RemoteSweepDeleteAuthorization::decode(&auth_bytes(false, false)).unwrap();
    assert_eq!(value.backend, remote());
    for field in 0..3 {
        let mut invalid = value.clone();
        invalid.artifacts[field].key = artifact_key(false);
        if field == 0 {
            invalid.artifacts[field].key = artifact_key(true);
        }
        assert!(invalid.encode().is_err());
    }
    let mut invalid = value.clone();
    invalid.witness[8] ^= 1;
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.artifacts[1].digest[0] ^= 1;
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.artifacts[0].size = 51;
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.lease.epoch += 1;
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.grace_elapsed_nanos -= 1;
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.deletion_elapsed_nanos -= 1;
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.deletion_seconds = 0;
    assert!(invalid.encode().is_err());
    invalid = value;
    invalid.grace_seconds = u64::MAX;
    invalid.deletion_seconds = u64::MAX;
    assert_eq!(invalid.encode(), Err(RetirementError::Exhausted));
}

#[test]
fn copied_retirement_requires_new_backend_matched_barrier_and_zero_removed_entries() {
    for local in [false, true] {
        let value = CopiedRetirementAuthorization::decode(&auth_bytes(true, local)).unwrap();
        let mut invalid = value.clone();
        invalid.barrier = CopiedRetirementAuthorization::decode(&auth_bytes(true, !local))
            .unwrap()
            .barrier;
        assert!(invalid.encode().is_err());
        invalid = value.clone();
        invalid.tombstone = tombstone_bytes();
        let len = invalid.tombstone.len();
        invalid.tombstone[len - 3] = 1;
        assert!(invalid.encode().is_err());
        invalid = value.clone();
        invalid.preparation = invalid.genesis;
        assert!(invalid.encode().is_err());
        invalid = value.clone();
        invalid.grace_elapsed_nanos = 0;
        assert!(invalid.encode().is_err());
        invalid = value;
        invalid.deletion_elapsed_nanos = 0;
        assert!(invalid.encode().is_err());
    }
    // Copy's exact shape may not acquire sweep key 7 or fabricated artifacts.
    let mut invalid = auth_bytes(true, false);
    invalid[0] = 0xb1;
    invalid.extend_from_slice(&[17, 0]);
    assert!(PermanentDeleteAuthorization::decode(&invalid).is_err());
}

#[test]
fn copied_preparation_is_disjoint_and_renewal_preserves_exact_plan() {
    for local in [false, true] {
        let bytes = plan_bytes(local);
        let plan = CopiedRetirementPlan::decode(&bytes).unwrap();
        assert_eq!(plan.encode().unwrap(), bytes);
        plan.check_key(&key()).unwrap();
        let mut preparation_bytes = vec![0x84, 2, 0, 3];
        preparation_bytes.extend(bytes);
        let preparation = CopiedRetirementPreparation::decode(&preparation_bytes).unwrap();
        assert_eq!(preparation.encode().unwrap(), preparation_bytes);
        assert!(PermanentDeleteOperation::decode(&preparation_bytes).is_err());
        let slot = OwnershipSlot {
            revision: 1,
            digest: [10; 32],
        };
        let mut authorization =
            CopiedRetirementAuthorization::decode(&auth_bytes(true, local)).unwrap();
        authorization
            .check_preparation(&preparation, &slot)
            .unwrap();
        authorization.lease.expiry += 1;
        authorization
            .check_preparation(&preparation, &slot)
            .unwrap();
        authorization.lease.holder = "B".into();
        assert!(
            authorization
                .check_preparation(&preparation, &slot)
                .is_err()
        );
        let mut abandoned = preparation.clone();
        abandoned.phase = PreparationPhase::Abandoned;
        abandoned.revision = 1;
        preparation.check_successor(&abandoned).unwrap();
        let mut restarted = abandoned.clone();
        restarted.phase = PreparationPhase::Preparing;
        restarted.revision = 2;
        assert!(abandoned.check_successor(&restarted).is_err());
        abandoned.plan.nonce[0] ^= 1;
        assert!(preparation.check_successor(&abandoned).is_err());
    }
}
