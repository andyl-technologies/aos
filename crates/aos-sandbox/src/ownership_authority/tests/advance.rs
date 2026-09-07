//! Signed same-owner transition, crash recovery, and version-downgrade regressions.

use super::*;
use aos_sandbox_ownership_protocol::protocol::OwnershipProtocolErrorCodeV1;

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

fn acquired_store(
    path: &Path,
) -> (
    DurableOwnershipAuthority,
    TestAuthority,
    RecoveredOwnershipLease,
) {
    let mut issuer = fixture(42).authority;
    let mut store = open_test_store(path, 42).unwrap();
    let claim = acquire_claim(5);
    store.begin(&claim).unwrap();
    store
        .complete(*claim.request_id(), &mut issuer, &mut || {
            Ok(test_clock(150))
        })
        .unwrap();
    let prior = store.current(claim.assignment().sandbox()).unwrap().clone();
    (store, issuer, prior)
}

#[test]
fn advance_has_a_distinct_claim_and_receipt_without_reinterpreting_renewal() {
    let directory = TestDirectory::new("advance-codec");
    let (mut store, mut issuer, prior) = acquired_store(&directory.journal());
    let claim = advance_claim(7, &prior);
    let old_receipt =
        OwnershipTransactionReceiptV1::from_canonical_bytes(prior.canonical_receipt()).unwrap();
    assert_eq!(&old_receipt.canonical_bytes()[14..17], &[0, 0, 1]);
    assert_eq!(claim.canonical_bytes()[10], 3);
    assert_eq!(
        OwnershipClaimV1::from_canonical_bytes(claim.canonical_bytes()).unwrap(),
        claim
    );
    assert_eq!(
        claim.action().minimum_protocol_version(),
        ProtocolVersion::new(1, 1)
    );
    store.begin(&claim).unwrap();
    let response = store
        .complete(*claim.request_id(), &mut issuer, &mut || {
            Ok(test_clock(150))
        })
        .unwrap();
    let receipt = OwnershipTransactionReceiptV1::from_canonical_bytes(response.receipt()).unwrap();
    assert_eq!(receipt.action(), OwnershipClaimAction::Advance);
    assert_eq!(&receipt.canonical_bytes()[14..17], &[0, 1, 3]);
    let verified = fixture(42)
        .verifier
        .verify_response(&claim, response.clone(), &test_clock(150))
        .unwrap();
    assert_eq!(verified.desired_generation(), claim.desired_generation());
    assert_eq!(verified.assignment(), claim.assignment());
    assert!(verified.generation() > prior.generation());

    let mut downgraded = receipt.canonical_bytes().to_vec();
    downgraded[15] = 0;
    assert!(OwnershipTransactionReceiptV1::from_canonical_bytes(&downgraded).is_err());
    let mut unknown = claim.canonical_bytes().to_vec();
    unknown[10] = 4;
    assert!(OwnershipClaimV1::from_canonical_bytes(&unknown).is_err());
    let mut absent_prior = claim.canonical_bytes().to_vec();
    absent_prior[128..168].fill(0);
    assert!(OwnershipClaimV1::from_canonical_bytes(&absent_prior).is_err());
    let renew = OwnershipClaimV1::renew(
        *claim.request_id(),
        claim.assignment(),
        claim.desired_generation(),
        claim.node(),
        claim.expected_prior().unwrap(),
        claim.requested_maximum_seconds(),
    )
    .unwrap();
    assert_ne!(renew.digest(), claim.digest());
    assert!(
        fixture(42)
            .verifier
            .verify_response(&renew, response, &test_clock(150))
            .is_err()
    );
}

#[test]
fn issued_advance_resumes_exactly_then_renews_and_recovers_its_complete_chain() {
    let directory = TestDirectory::new("advance-resume");
    let path = directory.journal();
    let (mut store, mut issuer, prior) = acquired_store(&path);
    let claim = advance_claim(7, &prior);
    store.begin(&claim).unwrap();
    // The external issuer may commit before the local completion record.
    let issued = issuer.advance(&claim).unwrap();
    drop(store);
    let mut store = open_test_store(&path, 42).unwrap();
    assert_eq!(store.current(prior.assignment().sandbox()), Some(&prior));
    assert!(store.is_pending(claim.request_id()));
    let resumed = store
        .complete(*claim.request_id(), &mut issuer, &mut || {
            Ok(test_clock(150))
        })
        .unwrap();
    assert_eq!(resumed, issued);
    assert_eq!(issuer.requests.len(), 2);
    let advanced = store.current(prior.assignment().sandbox()).unwrap().clone();
    let renew = OwnershipClaimV1::renew(
        [8; 16],
        advanced.assignment(),
        advanced.desired_generation(),
        advanced.node(),
        advanced.expected_renewal_fence(),
        60,
    )
    .unwrap();
    store.begin(&renew).unwrap();
    store
        .complete(*renew.request_id(), &mut issuer, &mut || {
            Ok(test_clock(150))
        })
        .unwrap();
    let head = store.current(prior.assignment().sandbox()).unwrap().clone();
    assert_eq!(head.assignment(), claim.assignment());
    assert_eq!(head.desired_generation(), claim.desired_generation());
    assert!(head.generation() > advanced.generation());
    store.journal.compact().unwrap();
    drop(store);
    let mut reopened = open_test_store(&path, 42).unwrap();
    assert_eq!(reopened.current(prior.assignment().sandbox()), Some(&head));
    let calls = issuer.calls.get();
    assert_eq!(
        reopened
            .complete(*claim.request_id(), &mut issuer, &mut || panic!(
                "historical replay sampled time"
            ))
            .unwrap(),
        issued
    );
    assert_eq!(issuer.calls.get(), calls);
    assert!(matches!(
        reopened.begin(&advance_claim(9, &prior)),
        Err(DurableOwnershipAuthorityError::CompareAndSwapConflict)
    ));
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
fn invalid_same_owner_transitions_fail_before_intent_or_issuance() {
    let directory = TestDirectory::new("advance-invalid");
    let (mut store, issuer, prior) = acquired_store(&directory.journal());
    for (name, claim) in invalid_successors(&prior) {
        assert!(
            matches!(
                store.begin(&claim),
                Err(DurableOwnershipAuthorityError::CompareAndSwapConflict)
            ),
            "{name}"
        );
        assert!(!store.is_pending(claim.request_id()), "{name}");
        assert_eq!(store.entries.len(), 1, "{name}");
        assert_eq!(
            store.current(prior.assignment().sandbox()),
            Some(&prior),
            "{name}"
        );
        assert_eq!(issuer.calls.get(), 1, "{name}");
    }
}

#[test]
fn pending_advance_fences_renewal_and_competing_assignment_updates() {
    let directory = TestDirectory::new("advance-pending-cas");
    let (mut store, mut issuer, prior) = acquired_store(&directory.journal());
    let advance = advance_claim(7, &prior);
    assert_eq!(
        store.begin(&advance).unwrap(),
        DurableOwnershipBeginOutcome::Pending
    );
    assert_eq!(
        store.begin(&advance).unwrap(),
        DurableOwnershipBeginOutcome::Pending
    );
    let renewal = renewal_claim(9, &prior);
    for competing in [&renewal, &advance_claim(8, &prior)] {
        assert!(matches!(
            store.begin(competing),
            Err(DurableOwnershipAuthorityError::CompareAndSwapConflict)
        ));
    }
    let rebound = OwnershipClaimV1::advance(
        *advance.request_id(),
        advance.assignment(),
        advance.desired_generation(),
        advance.node(),
        advance.expected_prior().unwrap(),
        61,
    )
    .unwrap();
    assert!(matches!(
        store.begin(&rebound),
        Err(DurableOwnershipAuthorityError::IdempotencyConflict)
    ));
    assert_eq!(issuer.calls.get(), 1);
    store
        .complete(*advance.request_id(), &mut issuer, &mut || {
            Ok(test_clock(150))
        })
        .unwrap();
    assert!(matches!(
        store.begin(&renewal),
        Err(DurableOwnershipAuthorityError::CompareAndSwapConflict)
    ));
    assert_eq!(issuer.calls.get(), 2);
}

#[test]
fn signed_but_invalid_historical_advances_cannot_become_a_recovered_head() {
    let fixture_directory = TestDirectory::new("advance-history-cases");
    let (_, _, prior) = acquired_store(&fixture_directory.journal());
    for (index, (name, claim)) in invalid_successors(&prior).into_iter().enumerate() {
        let directory = TestDirectory::new(&format!("advance-history-{index}"));
        let (store, mut issuer, prior) = acquired_store(&directory.journal());
        drop(store);
        // Model a correctly signed malicious response and internally consistent
        // journal pointers. Historical chain validation must still reject it.
        let response = issuer.issue(&claim, prior.generation() + 1).unwrap();
        let verified = fixture(42)
            .verifier
            .verify_response(&claim, response, &test_clock(150))
            .unwrap();
        let recovered = verified.clone().into_recovered();
        let entry = completed_entry(claim.clone(), verified, 150);
        let mut journal = Journal::open(directory.journal(), ownership_journal_limits())
            .unwrap()
            .0;
        journal
            .commit(
                &JournalTransaction::new(
                    [90; 16],
                    vec![
                        JournalRecord::put(
                            RecordNamespace::Operation,
                            durable_entry_key(claim.request_id()),
                            encode_durable_entry(&entry, &issuer.authority),
                        ),
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            durable_current_key(claim.assignment().sandbox()),
                            encode_current_pointer(*claim.request_id(), &recovered),
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(
            matches!(
                open_test_store(&directory.journal(), 42),
                Err(DurableOwnershipAuthorityError::CorruptState)
            ),
            "{name}"
        );
    }
}

pub(super) fn session(authority: &KeyReference, minor: u16) -> NegotiatedOwnershipSessionV1 {
    let methods = vec![
        OwnershipMethodV1::Begin,
        OwnershipMethodV1::CompleteOrResume,
        OwnershipMethodV1::Query,
    ];
    let hello = OwnershipClientHelloV1::new(
        [71; 32],
        ProtocolVersion::new(1, minor),
        authority.clone(),
        methods.clone(),
        MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
    )
    .unwrap();
    NegotiatedOwnershipSessionV1::negotiate(&hello, [72; 32], authority.clone(), methods).unwrap()
}

#[test]
fn version_one_zero_cannot_submit_observe_or_resume_advance_transactions() {
    let directory = TestDirectory::new("advance-session");
    let (mut store, mut issuer, prior) = acquired_store(&directory.journal());
    let old_session = session(&issuer.authority, 0);
    let new_session = session(&issuer.authority, 1);
    let claim = advance_claim(7, &prior);
    let reference = OwnershipTransactionReferenceV1::from_claim(&claim);
    let body = OwnershipRequestBodyV1::Begin(Box::new(claim.clone()));
    assert_eq!(
        old_session.request(body.clone()),
        Err(OwnershipProtocolValidationError::IncompatibleProtocol)
    );
    assert_eq!(
        old_session.validate_request_parts(
            *old_session.binding(),
            OwnershipMethodV1::Begin,
            body.clone()
        ),
        Err(OwnershipProtocolValidationError::IncompatibleProtocol)
    );
    let begin = new_session.request(body).unwrap();
    let mut clock = || Ok(test_clock(150));
    let calls = issuer.calls.clone();
    {
        let mut service = crate::DurableOwnershipProtocolService::new(
            new_session.clone(),
            &mut store,
            &mut issuer,
            &mut clock,
        )
        .unwrap();
        assert_eq!(
            service.handle(&begin).unwrap().outcome(),
            &OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Pending)
        );
    }
    for completed in [false, true] {
        if completed {
            let mut service = crate::DurableOwnershipProtocolService::new(
                new_session.clone(),
                &mut store,
                &mut issuer,
                &mut clock,
            )
            .unwrap();
            let request = new_session
                .request(OwnershipRequestBodyV1::CompleteOrResume(reference))
                .unwrap();
            assert!(matches!(
                service.handle(&request).unwrap().outcome(),
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(_))
            ));
        }
        let before = calls.get();
        let mut service = crate::DurableOwnershipProtocolService::new(
            old_session.clone(),
            &mut store,
            &mut issuer,
            &mut clock,
        )
        .unwrap();
        for body in [
            OwnershipRequestBodyV1::Query(reference),
            OwnershipRequestBodyV1::CompleteOrResume(reference),
        ] {
            let request = old_session.request(body).unwrap();
            assert_eq!(
                service.handle(&request).unwrap().outcome(),
                &OwnershipResponseOutcomeV1::Error(
                    OwnershipProtocolErrorCodeV1::RequiredCapabilityUnavailable
                )
            );
            assert_eq!(calls.get(), before);
        }
    }
}
