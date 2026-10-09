//! Pure receipt-authenticated historical successor regressions.

use super::*;

fn advance_claim(request: u8, prior: &RecoveredOwnershipLease) -> OwnershipClaimV1 {
    let previous = prior.assignment();
    OwnershipClaimV1::advance(
        [request; 16],
        LeaseAssignment::new(
            previous.sandbox(),
            previous.incarnation(),
            previous.epoch(),
            ObjectDigest::from_bytes([request; 32]),
        )
        .unwrap(),
        DesiredGeneration::new(prior.desired_generation().get() + 1),
        prior.node(),
        prior.expected_renewal_fence(),
        60,
    )
    .unwrap()
}

fn invalid_successors(prior: &RecoveredOwnershipLease) -> Vec<(&'static str, OwnershipClaimV1)> {
    let proposed = advance_claim(7, prior);
    let previous = prior.assignment();
    let mut cases = Vec::new();
    for (name, assignment, desired, node, fence) in [
        (
            "sandbox",
            LeaseAssignment::new(
                SandboxId::from_bytes([99; 16]),
                previous.incarnation(),
                previous.epoch(),
                proposed.assignment().digest(),
            )
            .unwrap(),
            proposed.desired_generation(),
            prior.node(),
            prior.expected_renewal_fence(),
        ),
        (
            "node",
            proposed.assignment(),
            proposed.desired_generation(),
            NodeId::from_bytes([99; 16]),
            prior.expected_renewal_fence(),
        ),
        (
            "incarnation",
            LeaseAssignment::new(
                previous.sandbox(),
                IncarnationId::from_bytes([99; 16]),
                previous.epoch(),
                proposed.assignment().digest(),
            )
            .unwrap(),
            proposed.desired_generation(),
            prior.node(),
            prior.expected_renewal_fence(),
        ),
        (
            "epoch",
            LeaseAssignment::new(
                previous.sandbox(),
                previous.incarnation(),
                AssignmentEpoch::new(previous.epoch().get() + 1),
                proposed.assignment().digest(),
            )
            .unwrap(),
            proposed.desired_generation(),
            prior.node(),
            prior.expected_renewal_fence(),
        ),
        (
            "same generation",
            proposed.assignment(),
            prior.desired_generation(),
            prior.node(),
            prior.expected_renewal_fence(),
        ),
        (
            "lower generation",
            proposed.assignment(),
            DesiredGeneration::new(prior.desired_generation().get() - 1),
            prior.node(),
            prior.expected_renewal_fence(),
        ),
        (
            "same digest",
            previous,
            proposed.desired_generation(),
            prior.node(),
            prior.expected_renewal_fence(),
        ),
        (
            "stale generation",
            proposed.assignment(),
            proposed.desired_generation(),
            prior.node(),
            ExpectedOwnershipLease::new(prior.generation() - 1, prior.digest()).unwrap(),
        ),
        (
            "stale digest",
            proposed.assignment(),
            proposed.desired_generation(),
            prior.node(),
            ExpectedOwnershipLease::new(prior.generation(), ObjectDigest::from_bytes([99; 32]))
                .unwrap(),
        ),
    ] {
        cases.push((
            name,
            OwnershipClaimV1::advance([7; 16], assignment, desired, node, fence, 60).unwrap(),
        ));
    }
    cases.push((
        "renewal changed generation",
        OwnershipClaimV1::renew(
            [7; 16],
            previous,
            proposed.desired_generation(),
            prior.node(),
            prior.expected_renewal_fence(),
            60,
        )
        .unwrap(),
    ));
    cases.push((
        "renewal changed digest",
        OwnershipClaimV1::renew(
            [7; 16],
            proposed.assignment(),
            prior.desired_generation(),
            prior.node(),
            prior.expected_renewal_fence(),
            60,
        )
        .unwrap(),
    ));
    cases
}

#[test]
fn signed_but_invalid_historical_advances_cannot_become_a_recovered_head() {
    let (_, _, _, prior) = acquired_history(42);
    for (name, claim) in invalid_successors(&prior) {
        let (_, mut records, data, prior) = acquired_history(42);
        // Correctly signed malicious artifacts and internally consistent pointers
        // must still fail the historical successor relation.
        let response = data.response(&claim, prior.generation() + 1);
        let verified = fixture(42)
            .verifier
            .verify_response(&claim, response, &test_clock(150))
            .unwrap();
        let recovered = verified.clone().into_recovered();
        let entry = completed_entry(claim.clone(), verified, 150);

        records.insert_completed(&entry, &data.authority);
        records.currents.insert(
            durable_current_key(claim.assignment().sandbox()),
            encode_current_pointer(*claim.request_id(), &recovered),
        );

        assert!(
            matches!(
                records.recover(42),
                Err(OwnershipHistoryError::CorruptState)
            ),
            "{name}",
        );
    }
}

#[test]
fn valid_advance_then_renewal_reconstructs_the_same_expired_historical_head() {
    let (mut history, mut records, data, prior) = acquired_history(42);
    let advance = advance_claim(7, &prior);
    publish_intent(&mut history, &mut records, &advance);
    publish_completion(&mut history, &mut records, &data, &advance);
    let advanced = history
        .current(prior.assignment().sandbox())
        .unwrap()
        .clone();
    let renewal = OwnershipClaimV1::renew(
        [8; 16],
        advanced.assignment(),
        advanced.desired_generation(),
        advanced.node(),
        advanced.expected_renewal_fence(),
        60,
    )
    .unwrap();

    publish_intent(&mut history, &mut records, &renewal);
    let response = publish_completion(&mut history, &mut records, &data, &renewal);
    let head = history
        .current(prior.assignment().sandbox())
        .unwrap()
        .clone();
    drop(history);

    let recovered = records.recover(42).unwrap();
    assert_eq!(recovered.current(prior.assignment().sandbox()), Some(&head));
    assert_eq!(head.exact_response(), response);
    assert!(
        fixture(42)
            .verifier
            .verify_response(&renewal, response, &test_clock(250),)
            .is_err()
    );
}
