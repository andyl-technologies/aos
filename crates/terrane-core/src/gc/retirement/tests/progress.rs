//! Checks immutable owners, bounded deltas and continuing reconciliation duty.

use super::*;

#[test]
fn permanent_owner_selectors_match_independent_bytes_and_exact_pack_keys() {
    assert_eq!(
        PermanentOwnerSelection::CopiedVisibility.encode().unwrap(),
        [0x81, 0]
    );
    let mut bytes = vec![0x82, 0x50];
    bytes.extend_from_slice(&PACK);
    bytes.extend_from_slice(&[0x83, 1]);
    write_text(&mut bytes, &key());
    write_bytes(&mut bytes, &[7; 32]);
    let value = PermanentBurnOwner::decode(&bytes).unwrap();
    assert_eq!(value.encode().unwrap(), bytes);
    let mut invalid = value;
    invalid.pack[0] ^= 1;
    assert!(invalid.encode().is_err());
    for bytes in [
        &[0x81, 1][..],
        &[0x82, 0, 0][..],
        &[0x81, 2][..],
        &[0x81, 0, 0][..],
    ] {
        assert!(PermanentOwnerSelection::decode(bytes).is_err());
    }
}

#[test]
fn permanent_operations_have_no_done_and_preserve_authorization_owner_forever() {
    let mut bytes = vec![0x86, 2, 0, 0];
    bytes.extend(auth_bytes(false, false));
    bytes.extend_from_slice(&[0xf6, 0xf6]);
    let proposed = PermanentDeleteOperation::decode(&bytes).unwrap();
    assert_eq!(proposed.encode().unwrap(), bytes);
    let mut owned = proposed.clone();
    owned.revision = 1;
    owned.phase = OperationPhase::Owned;
    owned.owner = Some(OwnershipSlot {
        revision: 3,
        digest: [12; 32],
    });
    let pass_bytes = pass_bytes(false);
    owned.pass = Some(RecordPointer {
        key: format!("gc/3/reconcile/{}/1", "0e".repeat(32)),
        digest: *blake3::hash(&pass_bytes).as_bytes(),
    });
    proposed.check_successor(&owned).unwrap();
    owned.check_pass(&pass_bytes, &key()).unwrap();
    let mut next = owned.clone();
    next.revision = 2;
    next.pass.as_mut().unwrap().key = format!("gc/3/reconcile/{}/2", "0f".repeat(32));
    owned.check_successor(&next).unwrap();
    next.owner.as_mut().unwrap().digest[0] ^= 1;
    assert!(owned.check_successor(&next).is_err());
    next = owned.clone();
    next.phase = OperationPhase::Cancelled;
    next.revision = 2;
    next.owner = None;
    next.pass = None;
    assert!(owned.check_successor(&next).is_err());
    next = proposed.clone();
    next.phase = OperationPhase::Cancelled;
    next.revision = 1;
    proposed.check_successor(&next).unwrap();
    let mut future = proposed.clone();
    future.revision = 2;
    assert!(next.check_successor(&future).is_err());
    future = owned;
    future.owner = None;
    assert!(future.encode().is_err());
    bytes[3] = 3;
    assert!(PermanentDeleteOperation::decode(&bytes).is_err());
}

#[test]
fn permanent_pass_matches_independent_bytes_and_requires_whole_owner_state() {
    for local in [false, true] {
        let bytes = pass_bytes(local);
        let value = PermanentDeletePass::decode(&bytes).unwrap();
        assert_eq!(value.encode().unwrap(), bytes);
        let auth = PermanentDeleteAuthorization::decode(&auth_bytes(local, local)).unwrap();
        let owner = OwnershipSlot {
            revision: 3,
            digest: [12; 32],
        };
        value.check_owner(&auth, &key(), &owner).unwrap();
        value
            .check_key(
                &format!("gc/3/reconcile/{}/{}", "0e".repeat(32), value.revision),
                3,
            )
            .unwrap();
        assert!(
            value
                .check_key(
                    &format!("gc/3/reconcile/{}/{}", "0f".repeat(32), value.revision),
                    3
                )
                .is_err()
        );
        let mut wrong = value.clone();
        wrong.state.burn_owners = Some(vec![]);
        assert!(wrong.check_owner(&auth, &key(), &owner).is_err());
        wrong = value.clone();
        wrong.lease.expiry += 1;
        // The progress whole lease may change independently of initial owner age.
        wrong.check_owner(&auth, &key(), &owner).unwrap();
        wrong = value.clone();
        wrong.state.revision += 1;
        assert!(wrong.encode().is_err());
        if local {
            wrong = value;
            wrong.placement_fence = None;
            assert!(wrong.encode().is_err());
        }
        for cut in 0..bytes.len() {
            assert!(PermanentDeletePass::decode(&bytes[..cut]).is_err());
        }
    }
}

fn row(
    artifact: ObservedArtifact,
    instance: ObservedInstance,
    state: ObservationState,
) -> RequestObservation {
    RequestObservation {
        artifact,
        instance,
        state,
    }
}

#[test]
fn permanent_observations_use_unsigned_fieldwise_order_and_actual_instance_bounds() {
    let mut value = PermanentDeletePass::decode(&pass_bytes(false)).unwrap();
    value.observations = vec![
        row(
            ObservedArtifact::Pack,
            ObservedInstance::Unversioned,
            ObservationState::Planned,
        ),
        row(
            ObservedArtifact::Pack,
            ObservedInstance::Version(vec![1, 2]),
            ObservationState::Deferred,
        ),
        row(
            ObservedArtifact::Pack,
            ObservedInstance::Version(vec![2]),
            ObservationState::Indeterminate,
        ),
        row(
            ObservedArtifact::Pack,
            ObservedInstance::Marker(vec![1]),
            ObservationState::ConfirmedAbsent,
        ),
        row(
            ObservedArtifact::Index,
            ObservedInstance::Unversioned,
            ObservationState::Planned,
        ),
        row(
            ObservedArtifact::Trash(23),
            ObservedInstance::Marker(vec![1]),
            ObservationState::Deferred,
        ),
        row(
            ObservedArtifact::Trash(24),
            ObservedInstance::Unversioned,
            ObservationState::Indeterminate,
        ),
        row(
            ObservedArtifact::Trash(u64::MAX),
            ObservedInstance::Unversioned,
            ObservationState::ConfirmedAbsent,
        ),
    ];
    let bytes = value.encode().unwrap();
    assert_eq!(PermanentDeletePass::decode(&bytes).unwrap(), value);
    let mut wrong = value.clone();
    wrong.observations.swap(1, 2);
    assert!(wrong.encode().is_err());
    wrong = value.clone();
    wrong.observations[1] = wrong.observations[0].clone();
    assert!(wrong.encode().is_err());
    wrong = value.clone();
    wrong.observations[1].instance = ObservedInstance::Version(vec![]);
    assert!(wrong.encode().is_err());
    wrong = value;
    wrong.observations[1].instance = ObservedInstance::Marker(vec![0; 4097]);
    assert!(wrong.encode().is_err());
    let mut local = PermanentDeletePass::decode(&pass_bytes(true)).unwrap();
    local.observations = vec![row(
        ObservedArtifact::Pack,
        ObservedInstance::Version(vec![1]),
        ObservationState::Deferred,
    )];
    assert!(local.encode().is_err());
}

#[test]
fn completed_pass_preserves_deferred_duties_and_requires_all_prior_plans_resolved() {
    let mut initial = PermanentDeletePass::decode(&pass_bytes(false)).unwrap();
    initial.observations = vec![row(
        ObservedArtifact::Trash(7),
        ObservedInstance::Marker(vec![1]),
        ObservationState::Planned,
    )];
    let mut completed = initial.clone();
    completed.nonce[0] ^= 1;
    completed.revision += 1;
    completed.event += 1;
    completed.predecessor.revision += 1;
    completed.state.revision += 1;
    completed.phase = PassPhase::PassCompleted;
    completed.coverage = [PassCoverage::CandidateTraversalCompleted; 3];
    completed.observations.clear();
    initial.check_successor(&completed).unwrap();
    assert!(
        PermanentDeletePass::check_pass_history(&[initial.clone(), completed.clone()]).is_err()
    );
    completed.observations = vec![row(
        ObservedArtifact::Trash(7),
        ObservedInstance::Marker(vec![1]),
        ObservationState::Indeterminate,
    )];
    PermanentDeletePass::check_pass_history(&[initial, completed.clone()]).unwrap();
    let mut next = completed.clone();
    next.nonce[0] ^= 1;
    next.revision += 1;
    next.pass += 1;
    next.event = 0;
    next.predecessor.revision += 1;
    next.state.revision += 1;
    next.phase = PassPhase::Open;
    next.coverage = [PassCoverage::Unknown; 3];
    next.observations.clear();
    completed.check_successor(&next).unwrap();
    assert_eq!(next.owner, completed.owner);
    let mut wrong = completed.clone();
    wrong.coverage[2] = PassCoverage::Unknown;
    assert!(wrong.encode().is_err());
    wrong = completed;
    wrong.observations[0].state = ObservationState::Planned;
    assert!(wrong.encode().is_err());
}

#[test]
fn empty_completed_pass_starts_another_pass_and_checked_counters_never_wrap() {
    let mut first = PermanentDeletePass::decode(&pass_bytes(false)).unwrap();
    first.phase = PassPhase::PassCompleted;
    first.coverage = [PassCoverage::QualifiedAllVersionAbsenceAtObservation; 3];
    let mut next = first.clone();
    next.nonce[0] ^= 1;
    next.revision += 1;
    next.pass += 1;
    next.event = 0;
    next.predecessor.revision += 1;
    next.state.revision += 1;
    next.phase = PassPhase::Open;
    first.check_successor(&next).unwrap();
    first.pass = u64::MAX;
    assert_eq!(
        first.check_successor(&next),
        Err(RetirementError::Exhausted)
    );
    first.pass = 0;
    first.phase = PassPhase::Open;
    first.event = u64::MAX;
    assert_eq!(
        first.check_successor(&next),
        Err(RetirementError::Exhausted)
    );
    first.event = 0;
    first.revision = u64::MAX;
    assert_eq!(
        first.check_successor(&next),
        Err(RetirementError::Exhausted)
    );
}

#[test]
fn permanent_pass_rejects_oversized_unknown_and_wrong_coverage_shapes() {
    let bytes = pass_bytes(false);
    let mut oversized = bytes.clone();
    let observations = oversized
        .windows(4)
        .position(|bytes| bytes == [9, 0, 10, 0x80])
        .unwrap()
        + 3;
    oversized.splice(observations..observations + 1, [0x99, 0x10, 0x01]);
    assert!(PermanentDeletePass::decode(&oversized).is_err());

    let mut wrong_coverage = bytes.clone();
    let coverage = wrong_coverage
        .windows(5)
        .position(|bytes| bytes == [11, 0x83, 0x82, 0, 0])
        .unwrap();
    wrong_coverage[coverage + 3] = 1;
    assert!(PermanentDeletePass::decode(&wrong_coverage).is_err());

    let mut unknown = bytes;
    unknown[0] = 0xae;
    unknown.extend_from_slice(&[14, 0]);
    assert!(PermanentDeletePass::decode(&unknown).is_err());
    assert!(PermanentDeleteAuthorization::decode(&vec![0; MAX_RECORD_BYTES + 1]).is_err());

    let mut proposed_bytes = vec![0x86, 2, 0, 0];
    proposed_bytes.extend(auth_bytes(false, false));
    proposed_bytes.extend_from_slice(&[0xf6, 0xf6]);
    let proposed = PermanentDeleteOperation::decode(&proposed_bytes).unwrap();
    let initial = PermanentDeletePass::decode(&pass_bytes(false)).unwrap();
    initial.check_initial(&proposed).unwrap();
    let mut invalid = initial.clone();
    invalid.event = 1;
    assert!(invalid.check_initial(&proposed).is_err());
    invalid = initial;
    invalid.phase = PassPhase::PassCompleted;
    invalid.coverage = [PassCoverage::CandidateTraversalCompleted; 3];
    assert!(invalid.check_initial(&proposed).is_err());
}
