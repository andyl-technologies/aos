//! Closed live issuer request/reply and retained denial-gap regressions.

use super::super::control::*;
use super::*;
use crate::storage_authority::control::StorageAuthorityDeniedTransition;
use crate::storage_authority::StorageAuthorityRemoteWatermark;

fn installation(p: &StorageAuthorityPublication) -> IssuerInstallation {
    IssuerInstallation {
        format_version: 1,
        authority: p.authority.clone(),
        issuer_resource_id: "permanent-issuer-resource".into(),
        runtime_identity: "dedicated-issuer".into(),
        executor_identity: EXECUTOR.into(),
    }
}

fn current(p: &StorageAuthorityPublication) -> IssuerLiveState {
    IssuerLiveState {
        installation: installation(p),
        publication: p.clone(),
        journal: EpochLeaseIssuerJournal::initialize_fresh_namespace(
            p,
            EXECUTOR,
            BoundedLeaseRevocationPolicy {
                timing_profile: profile(),
            },
            clock(100),
        )
        .unwrap(),
    }
}

fn request(p: &StorageAuthorityPublication, operation: IssuerOperation) -> IssuerRequest {
    IssuerRequest {
        protocol_version: 1,
        installation: installation(p),
        nonce: "a".repeat(64),
        issued_at: integer(100),
        expires_at: integer(130),
        operation,
    }
}

fn reply(request: &IssuerRequest, current: IssuerLiveState) -> IssuerReply {
    IssuerReply {
        protocol_version: 1,
        issuer_key_id: KEY_ID.into(),
        installation: request.installation.clone(),
        nonce: request.nonce.clone(),
        request_digest: request.digest().unwrap(),
        current: current.head().unwrap(),
        applied: None,
        lease: None,
    }
}

#[test]
fn live_codec_preserves_exact_counters_and_rejects_cross_record_forks() {
    let p = publication();
    let mut state = current(&p);
    state.validate().unwrap();
    let encoded = serde_json::to_vec(&state).unwrap();
    let decoded: IssuerLiveState = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, state);
    state.journal.publication_digest = "f".repeat(64);
    assert!(state.validate().is_err());
    state = current(&p);
    state.installation.executor_identity = "different".into();
    assert!(state.validate().is_err());
}

#[test]
fn live_request_is_closed_canonical_bounded_and_audience_pinned() {
    let p = publication();
    let mut r = request(&p, IssuerOperation::Current);
    let bytes = serde_json::to_vec(&r).unwrap();
    IssuerRequest::decode(&bytes)
        .unwrap()
        .validate(&installation(&p), 101)
        .unwrap();
    assert!(IssuerRequest::decode(&[b'x'; MAX_ISSUER_CONTROL_BYTES + 1]).is_err());
    let text = String::from_utf8(bytes).unwrap();
    assert!(IssuerRequest::decode(text.replacen("{", "{\"unknown\":1,", 1).as_bytes()).is_err());
    assert!(
        IssuerRequest::decode(text.replacen("{", "{\"protocol_version\":1,", 1).as_bytes())
            .is_err()
    );
    assert!(IssuerRequest::decode(format!(" {text}").as_bytes()).is_err());
    r.installation.issuer_resource_id = "changed".into();
    assert!(r.validate(&installation(&p), 101).is_err());
    r = request(&p, IssuerOperation::Current);
    r.expires_at = integer(131);
    assert!(r.validate(&installation(&p), 101).is_err());
    assert!(request(&p, IssuerOperation::Current)
        .validate(&installation(&p), 130)
        .is_err());
}

#[test]
fn signed_current_reply_pins_key_domain_nonce_and_request() {
    let p = publication();
    let r = request(&p, IssuerOperation::Current);
    let signer = EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &[7; 32]).unwrap();
    let verifier = EpochLeaseVerifier::from_bytes(
        KEY_ID.into(),
        &SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    let bytes = sign_issuer_reply(&signer, &r, reply(&r, current(&p))).unwrap();
    verify_issuer_reply(&verifier, &r, &bytes).unwrap();
    let wrong = EpochLeaseVerifier::from_bytes(
        KEY_ID.into(),
        &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(verify_issuer_reply(&wrong, &r, &bytes).is_err());
    let mut changed = r.clone();
    changed.nonce = "b".repeat(64);
    assert!(verify_issuer_reply(&verifier, &changed, &bytes).is_err());
    let mut altered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    altered["payload"]["current"]["journal"]["last_sequence"] = serde_json::json!("1");
    assert!(verify_issuer_reply(&verifier, &r, &serde_json::to_vec(&altered).unwrap()).is_err());
}

#[test]
fn control_success_requires_exact_applied_receipt() {
    let p = publication();
    let r = request(&p, IssuerOperation::Install(p.clone()));
    let signer = EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &[7; 32]).unwrap();
    let mut acknowledgment = reply(&r, current(&p));
    assert!(sign_issuer_reply(&signer, &r, acknowledgment.clone()).is_err());
    acknowledgment.applied = Some(IssuerPublicationReceipt::from_publication(&p).unwrap());
    sign_issuer_reply(&signer, &r, acknowledgment.clone()).unwrap();
    let mut contradictory = acknowledgment.clone();
    contradictory.current.journal.publication_digest = "f".repeat(64);
    assert!(sign_issuer_reply(&signer, &r, contradictory).is_err());
    acknowledgment.applied.as_mut().unwrap().publication_digest = "f".repeat(64);
    assert!(sign_issuer_reply(&signer, &r, acknowledgment).is_err());
}

#[test]
fn request_authentication_is_separate_from_legacy_storage_work_and_responses() {
    let p = publication();
    let r = request(&p, IssuerOperation::Current);
    let bytes = serde_json::to_vec(&r).unwrap();
    let key = crate::storage_work::StorageWorkKey::new(
        "private-native-publisher-key-at-least-thirty-two",
    )
    .unwrap();
    let sig = sign_issuer_request(&key, &bytes).unwrap();
    verify_issuer_request(&key, &sig, &bytes).unwrap();
    assert!(verify_issuer_request(&key, &"a".repeat(MAX_ISSUER_CONTROL_BYTES), &bytes).is_err());
    assert!(verify_issuer_request(&key, &sig.to_uppercase(), &bytes).is_err());
    assert!(key.verify_body(&sig, &bytes).is_err());
    assert!(
        crate::storage_authority::control::verify_authority_message(&key, false, &sig, &bytes)
            .is_err()
    );
}

#[test]
fn denied_gap_retains_issued_expiry_sequence_and_refuses_admitted_skip() {
    let p = publication();
    let mut journal = current(&p).journal;
    journal.last_sequence = integer(17);
    journal.largest_issued_expiry = integer(500);
    let blocked2 = next_publication(&p, StorageAuthorityAdmissionState::Blocked);
    let blocked3 = next_publication(&blocked2, StorageAuthorityAdmissionState::Blocked);
    let blocked4 = next_publication(&blocked3, StorageAuthorityAdmissionState::Blocked);
    let transition = StorageAuthorityDeniedTransition {
        publication: blocked4,
        expected_remote: Some(StorageAuthorityRemoteWatermark {
            authority_id: p.authority.authority_id.clone(),
            guard_namespace_id: p.authority.guard_namespace_id.clone(),
            generation: p.generation,
            digest: p.digest.clone(),
        }),
    };
    let committed = journal
        .prepare_denied_gap(&transition, clock(110))
        .unwrap()
        .next;
    assert_eq!(committed.generation.get(), 4);
    assert_eq!(committed.last_sequence.get(), 17);
    assert_eq!(committed.largest_issued_expiry.get(), 500);
    assert_eq!(committed.state, StorageAuthorityAdmissionState::Blocked);
    let mut admitted = transition.clone();
    admitted.publication = next_publication(&p, StorageAuthorityAdmissionState::Admitted);
    assert!(journal.prepare_denied_gap(&admitted, clock(110)).is_err());
    let mut stale = transition;
    stale.expected_remote.as_mut().unwrap().digest = "f".repeat(64);
    assert!(journal.prepare_denied_gap(&stale, clock(110)).is_err());
}

#[test]
fn denied_gap_refuses_same_predecessor_fork_and_terminal_retirement() {
    let p = publication();
    let mut journal = current(&p).journal;
    let mut denied = next_publication(&p, StorageAuthorityAdmissionState::Retired);
    denied.admission.expected_digest = Some("f".repeat(64));
    denied.digest = canonical_digest(&denied.admission).unwrap();
    let mut transition = StorageAuthorityDeniedTransition {
        publication: denied,
        expected_remote: Some(StorageAuthorityRemoteWatermark {
            authority_id: p.authority.authority_id.clone(),
            guard_namespace_id: p.authority.guard_namespace_id.clone(),
            generation: 1,
            digest: p.digest.clone(),
        }),
    };
    assert!(journal.prepare_denied_gap(&transition, clock(110)).is_err());
    transition.publication = next_publication(&p, StorageAuthorityAdmissionState::Retired);
    journal = journal
        .prepare_denied_gap(&transition, clock(110))
        .unwrap()
        .next;
    transition.expected_remote.as_mut().unwrap().generation = journal.generation.get();
    transition.expected_remote.as_mut().unwrap().digest = journal.admission_digest.clone();
    transition.publication = next_publication(
        &transition.publication,
        StorageAuthorityAdmissionState::Blocked,
    );
    assert!(journal.prepare_denied_gap(&transition, clock(120)).is_err());
}

#[tokio::test]
async fn issue_reply_checks_inner_signature_and_exact_cohort_and_sequence() {
    let p = publication();
    let mut state = current(&p);
    let r = request(
        &p,
        IssuerOperation::Issue {
            cohort: cohort(&p),
            requested_not_after: integer(900),
        },
    );
    let signer = EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &[7; 32]).unwrap();
    let verifier = EpochLeaseVerifier::from_bytes(
        KEY_ID.into(),
        &SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    // The shared issue fixture uses its own signer; use the same explicit fixture
    // seed rather than confuse an issuer reply pin with token's signature pin.
    let prepared = current(&p)
        .journal
        .prepare_issue(&p, cohort(&p), KEY_ID, 900, clock(100))
        .unwrap();
    let modeled = RefCell::new(current(&p).journal);
    let token = prepared
        .commit_and_sign(
            &signer,
            |transition| {
                modeled.replace(transition.next);
                async { Ok(()) }
            },
            || Ok(clock(101)),
        )
        .await
        .unwrap();
    state.journal = modeled.into_inner();
    let mut acknowledged = reply(&r, state.clone());
    acknowledged.lease = Some(String::from_utf8(token.clone()).unwrap());
    let bytes = sign_issuer_reply(&signer, &r, acknowledged.clone()).unwrap();
    verify_issuer_reply(&verifier, &r, &bytes).unwrap();

    let mut broken: serde_json::Value = serde_json::from_slice(&token).unwrap();
    broken["signature"] = serde_json::json!("0".repeat(128));
    acknowledged.lease = Some(serde_json::to_string(&broken).unwrap());
    assert!(verify_issuer_reply(
        &verifier,
        &r,
        &sign_issuer_reply(&signer, &r, acknowledged.clone()).unwrap()
    )
    .is_err());
    acknowledged.lease = Some(String::from_utf8(token).unwrap());
    acknowledged.current.journal.last_sequence = integer(2);
    assert!(verify_issuer_reply(
        &verifier,
        &r,
        &sign_issuer_reply(&signer, &r, acknowledged).unwrap()
    )
    .is_err());
}

#[test]
fn denied_reply_has_separate_domain_and_does_not_erase_issuance_history() {
    let p = publication();
    let mut state = current(&p);
    state.journal.last_sequence = integer(5);
    state.journal.largest_issued_expiry = integer(500);
    let transition = StorageAuthorityDeniedTransition {
        publication: next_publication(&p, StorageAuthorityAdmissionState::Blocked),
        expected_remote: Some(StorageAuthorityRemoteWatermark {
            authority_id: p.authority.authority_id.clone(),
            guard_namespace_id: p.authority.guard_namespace_id.clone(),
            generation: 1,
            digest: p.digest.clone(),
        }),
    };
    let r = request(&p, IssuerOperation::Deny(transition.clone()));
    state.journal = state
        .journal
        .prepare_denied_gap(&transition, clock(110))
        .unwrap()
        .next;
    state.publication = transition.publication.clone();
    let mut acknowledgment = reply(&r, state);
    acknowledgment.applied =
        Some(IssuerPublicationReceipt::from_publication(&transition.publication).unwrap());
    let signer = EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &[7; 32]).unwrap();
    let verifier = EpochLeaseVerifier::from_bytes(
        KEY_ID.into(),
        &SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    let bytes = sign_issuer_reply(&signer, &r, acknowledgment).unwrap();
    let verified = verify_issuer_reply(&verifier, &r, &bytes).unwrap();
    assert_eq!(verified.current.journal.last_sequence.get(), 5);
    assert_eq!(verified.current.journal.largest_issued_expiry.get(), 500);
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let payload = serde_json::to_vec(&verified).unwrap();
    envelope["signature"] = serde_json::json!(
        signer.sign_domain(b"aos.external-authority-issuer-reply.v1\0", &payload)
    );
    assert!(verify_issuer_reply(&verifier, &r, &serde_json::to_vec(&envelope).unwrap()).is_err());
}

#[test]
fn live_reply_time_check_uses_conservative_request_deadline_and_qualified_floor() {
    let p = publication();
    let r = request(&p, IssuerOperation::Current);
    let signer = EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &[7; 32]).unwrap();
    let verifier = EpochLeaseVerifier::from_bytes(KEY_ID.into(),
        &SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()).unwrap();
    let bytes = sign_issuer_reply(&signer, &r, reply(&r, current(&p))).unwrap();
    verify_issuer_reply_at_time(&verifier, &r, &bytes, || Ok(clock(127))).unwrap();
    assert!(verify_issuer_reply_at_time(&verifier, &r, &bytes, || Ok(clock(128))).is_err());
    assert!(verify_issuer_reply_at_time(&verifier, &r, &bytes, || Ok(clock(99))).is_err());
    assert!(verify_issuer_reply_at_time(&verifier, &r, &bytes, || Ok(LeaseClock {
        observed_at: 110, uncertainty: 3,
    })).is_err());
}

#[tokio::test]
async fn live_reply_time_check_rejects_inner_expiry_after_ordinary_signature_success() {
    let p = publication();
    let r = request(&p, IssuerOperation::Issue {
        cohort: cohort(&p), requested_not_after: integer(120),
    });
    let signer = EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &[7; 32]).unwrap();
    let verifier = EpochLeaseVerifier::from_bytes(KEY_ID.into(),
        &SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()).unwrap();
    let mut state = current(&p);
    let prepared = state.journal.prepare_issue(&p, cohort(&p), KEY_ID, 120, clock(100)).unwrap();
    let modeled = RefCell::new(state.journal.clone());
    let token = prepared.commit_and_sign(&signer, |transition| {
        modeled.replace(transition.next);
        async { Ok(()) }
    }, || Ok(clock(101))).await.unwrap();
    state.journal = modeled.into_inner();
    let mut acknowledged = reply(&r, state);
    acknowledged.lease = Some(String::from_utf8(token).unwrap());
    let bytes = sign_issuer_reply(&signer, &r, acknowledged).unwrap();
    verify_issuer_reply(&verifier, &r, &bytes).unwrap();
    verify_issuer_reply_at_time(&verifier, &r, &bytes, || Ok(clock(117))).unwrap();
    assert!(verify_issuer_reply_at_time(&verifier, &r, &bytes, || Ok(clock(118))).is_err());
}

#[test]
fn live_reply_verifies_all_wire_before_invoking_the_final_observer() {
    let p = publication();
    let r = request(&p, IssuerOperation::Current);
    let signer = EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &[7; 32]).unwrap();
    let verifier = EpochLeaseVerifier::from_bytes(KEY_ID.into(),
        &SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()).unwrap();
    let bytes = sign_issuer_reply(&signer, &r, reply(&r, current(&p))).unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    envelope["signature"] = serde_json::json!("0".repeat(128));
    let observed = std::cell::Cell::new(false);
    assert!(verify_issuer_reply_at_time(&verifier, &r,
        &serde_json::to_vec(&envelope).unwrap(), || {
            observed.set(true);
            Ok(clock(110))
        }).is_err());
    assert!(!observed.get());
}
