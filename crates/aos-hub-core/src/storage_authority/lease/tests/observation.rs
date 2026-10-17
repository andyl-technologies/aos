//! Signing observations preserve byte identity and durable acknowledgment order.

use super::*;

#[tokio::test]
async fn observed_signing_keeps_signed_bytes_and_both_durable_cas_operations() {
    let publication = publication();
    let plain = RefCell::new(journal(&publication));
    let observed = RefCell::new(journal(&publication));
    let signer = keys().0;
    let prepare = |current: &RefCell<EpochLeaseIssuerJournal>| {
        current
            .borrow()
            .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
            .unwrap()
    };
    let plain_bytes = prepare(&plain)
        .commit_and_sign(
            &signer,
            |transition| durable_cas(&plain, transition),
            || Ok(clock(101)),
        )
        .await
        .unwrap();
    let mut events = Vec::new();
    let observed_bytes = prepare(&observed)
        .commit_and_sign_observed(
            &signer,
            |transition| durable_cas(&observed, transition),
            || Ok(clock(101)),
            |event| {
                // Signing begins only after the first exact journal acknowledgment.
                assert_eq!(observed.borrow().last_sequence, integer(1));
                events.push(event);
            },
        )
        .await
        .unwrap();

    assert_eq!(observed_bytes, plain_bytes);
    assert_eq!(*plain.borrow(), *observed.borrow());
    assert_eq!(
        events,
        vec![
            LeaseSignatureObservation {
                kind: LeaseSignatureKind::Lease,
                boundary: LeaseSignatureBoundary::Started
            },
            LeaseSignatureObservation {
                kind: LeaseSignatureKind::Lease,
                boundary: LeaseSignatureBoundary::Completed
            },
        ]
    );
}

#[tokio::test]
async fn no_sign_observation_can_bypass_failed_or_missing_durable_acknowledgment() {
    let publication = publication();
    let current = journal(&publication);
    let prepared = current
        .prepare_issue(&publication, cohort(&publication), KEY_ID, 130, clock(100))
        .unwrap();
    let mut events = Vec::new();

    let result = prepared
        .commit_and_sign_observed(
            &keys().0,
            |_| async { anyhow::bail!("actual commit failed") },
            || Ok(clock(101)),
            |event| events.push(event),
        )
        .await;

    assert!(result.is_err());
    assert!(events.is_empty());
    assert_eq!(current.last_sequence, integer(0));
}

#[test]
fn reply_sign_observation_keeps_canonical_signature_and_rejects_changed_original() {
    use crate::storage_authority::lease::control::*;
    let publication = publication();
    let installation = IssuerInstallation {
        format_version: 1,
        authority: publication.authority.clone(),
        issuer_resource_id: "observation-fixture-issuer".into(),
        runtime_identity: "observation-fixture-runtime".into(),
        executor_identity: EXECUTOR.into(),
    };
    let request = IssuerRequest {
        protocol_version: 1,
        installation: installation.clone(),
        nonce: "a".repeat(64),
        issued_at: integer(100),
        expires_at: integer(130),
        operation: IssuerOperation::Current,
    };
    let current = IssuerLiveState {
        installation: installation.clone(),
        journal: journal(&publication),
        publication,
    };
    let reply = IssuerReply {
        protocol_version: 1,
        issuer_key_id: KEY_ID.into(),
        installation,
        nonce: request.nonce.clone(),
        request_digest: request.digest().unwrap(),
        current: current.head().unwrap(),
        applied: None,
        lease: None,
    };
    let signer = keys().0;
    let plain = sign_issuer_reply(&signer, &request, reply.clone()).unwrap();
    let mut events = Vec::new();
    let observed =
        sign_issuer_reply_observed(&signer, &request, reply.clone(), |event| events.push(event))
            .unwrap();

    assert_eq!(plain, observed);
    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .all(|event| event.kind == LeaseSignatureKind::Reply));
    let mut changed = reply;
    changed.nonce = "b".repeat(64);
    events.clear();
    assert!(
        sign_issuer_reply_observed(&signer, &request, changed, |event| events.push(event)).is_err()
    );
    assert!(events.is_empty());
}
