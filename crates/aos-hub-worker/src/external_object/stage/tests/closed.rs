//! Canonical closure compatibility and exact journal/response selection regressions.

use super::*;
use crate::external_object::stage::closed;

fn verify(f: &Fixture, receipt: &Receipt) -> Intent {
    f.intent(
        "verify-closed",
        Operation::VerifyClosedStage {
            upload_id: Some("source-upload".into()),
            close_receipt_digest: protocol::digest(receipt).unwrap(),
        },
    )
}

#[tokio::test]
async fn historical_closure_bytes_digest_and_public_outcome_are_preserved() {
    let f = Fixture::new(1).await;
    let (_, original) = f.closed_source();
    #[derive(serde::Serialize)]
    struct LegacyReceipt<'a> {
        turn: &'a Turn,
        outcome: &'a Outcome,
    }
    let legacy = LegacyReceipt {
        turn: &original.turn,
        outcome: &original.outcome,
    };
    let original_bytes = serde_json::to_vec(&legacy).unwrap();
    let decoded: Receipt = serde_json::from_slice(&original_bytes).unwrap();
    assert!(decoded.provider_version.is_none());
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), original_bytes);
    assert_eq!(
        protocol::digest(&legacy).unwrap(),
        protocol::digest(&decoded).unwrap()
    );
    let key = StorageWorkKey::new(b"stage-closure-fixture-independent-key").unwrap();
    assert_eq!(
        key.sign_body(&original_bytes).unwrap(),
        key.sign_body(&serde_json::to_vec(&decoded).unwrap())
            .unwrap()
    );

    let mut versioned = original.clone();
    versioned.provider_version = closed::response_version(Some("actual/version-one")).unwrap();
    versioned.validate().unwrap();
    assert_ne!(
        protocol::digest(&versioned).unwrap(),
        protocol::digest(&original).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&versioned.result().unwrap().outcome).unwrap(),
        serde_json::to_vec(&original.outcome).unwrap()
    );
}

#[tokio::test]
async fn exact_pending_journal_closure_survives_restart_and_refuses_substitution() {
    let f = Fixture::new(1).await;
    let (head, closed) = f.closed_source();
    assert_eq!(closed.turn.expected_incarnation.get(), 1);
    assert_eq!(head.incarnation.get(), 1);
    let (head, turn) = f.begin(&head, verify(&f, &closed), None, None).unwrap();
    state::verification_closure(&head, &f.config, &turn, &closed).unwrap();
    let restored: Head = serde_json::from_slice(&serde_json::to_vec(&head).unwrap()).unwrap();
    let (_, repeated) = f.begin(&restored, turn.intent.clone(), None, None).unwrap();
    assert!(repeated == turn);
    state::verification_closure(&restored, &f.config, &turn, &closed).unwrap();

    let mut substituted = closed.clone();
    substituted.provider_version = Some("another-actual-version".into());
    assert!(state::verification_closure(&head, &f.config, &turn, &substituted).is_err());
    substituted = closed.clone();
    if let Outcome::Closed { etag, .. } = &mut substituted.outcome {
        *etag = "\"another-actual-tag\"".into();
    }
    assert!(closed::validate_projection(&turn, &substituted).is_err());
    substituted = closed.clone();
    substituted.turn.intent.context.session_id = "another-session".into();
    assert!(closed::validate_projection(&turn, &substituted).is_err());
    let mut different = turn.clone();
    different.expected_incarnation = WireInteger::new(2);
    assert!(closed::validate_projection(&different, &closed).is_err());
    different = turn.clone();
    if let Operation::VerifyClosedStage { upload_id, .. } = &mut different.intent.operation {
        *upload_id = Some("another-provider-upload".into());
    }
    assert!(closed::validate_projection(&different, &closed).is_err());
    different = turn.clone();
    different.dispatch_nonce = "a".repeat(64);
    assert!(state::verification_closure(&head, &f.config, &different, &closed).is_err());
    different = turn.clone();
    different.intent.operation = Operation::AbortStage {
        upload_id: "source-upload".into(),
    };
    assert!(closed::validate_projection(&different, &closed).is_err());
    let mut changed = head.clone();
    changed
        .stage
        .as_mut()
        .unwrap()
        .closed
        .as_mut()
        .unwrap()
        .operation_id = "other-close".into();
    assert!(state::verification_closure(&changed, &f.config, &turn, &closed).is_err());
}

#[tokio::test]
async fn versioned_closure_is_admitted_only_with_the_exact_retained_digest() {
    let f = Fixture::new(1).await;
    let (mut head, mut receipt) = f.closed_source();
    receipt.provider_version = closed::response_version(Some("actual/v1")).unwrap();
    head.stage.as_mut().unwrap().closed.as_mut().unwrap().digest =
        protocol::digest(&receipt).unwrap();
    let (head, turn) = f.begin(&head, verify(&f, &receipt), None, None).unwrap();
    state::verification_closure(&head, &f.config, &turn, &receipt).unwrap();
    assert!(closed::validate_response(&receipt, Some("\"closed\""), Some("actual/v1")).is_ok());
    for version in [None, Some("null"), Some("actual/v2")] {
        assert!(closed::validate_response(&receipt, Some("\"closed\""), version).is_err());
    }
    for tag in [None, Some("W/\"closed\""), Some("\"changed\"")] {
        assert!(closed::validate_response(&receipt, tag, Some("actual/v1")).is_err());
    }
}

#[tokio::test]
async fn versionless_response_still_requires_original_strong_etag() {
    let f = Fixture::new(1).await;
    let (_, receipt) = f.closed_source();
    for version in [None, Some("null"), Some("actual-observed-read-version")] {
        assert!(closed::validate_response(&receipt, Some("\"closed\""), version).is_ok());
    }
    assert!(closed::validate_response(&receipt, Some("\"replacement\""), None).is_err());
    assert!(closed::validate_response(&receipt, None, None).is_err());
    assert!(closed::response_version(Some("bad\nversion")).is_err());
    assert!(closed::response_version(Some(&"v".repeat(513))).is_err());
    assert!(closed::response_version(Some("")).is_err());
    assert!(closed::response_version(None).unwrap().is_none());
    assert!(closed::response_version(Some("null")).unwrap().is_none());
}

#[tokio::test]
async fn nonclosure_receipt_cannot_claim_provider_version() {
    let f = Fixture::new(1).await;
    let (head, turn) = f
        .begin(
            &f.fresh(false),
            f.intent("create", Operation::CreateStage),
            None,
            None,
        )
        .unwrap();
    let (_, mut receipt) = f.terminal(
        &head,
        turn,
        Outcome::Created {
            upload_id: "provider-upload".into(),
        },
    );
    receipt.provider_version = Some("actual-version".into());
    assert!(receipt.validate().is_err());

    let empty = Fixture::new(0).await;
    let (_, mut receipt) = empty.closed_source();
    receipt.provider_version = closed::response_version(Some("actual-empty-put-version")).unwrap();
    receipt.validate().unwrap();
    assert!(closed::validate_response(
        &receipt,
        Some("\"empty\""),
        Some("actual-empty-put-version")
    )
    .is_ok());
}

#[derive(Default)]
struct BodyObservations {
    polls: std::cell::Cell<u64>,
    cancellation_invocations: std::cell::Cell<u64>,
}

struct UnpolledBody(std::rc::Rc<BodyObservations>);

impl UnpolledBody {
    fn poll(&self) {
        self.0.polls.set(self.0.polls.get() + 1);
    }
}

impl Drop for UnpolledBody {
    fn drop(&mut self) {
        self.0
            .cancellation_invocations
            .set(self.0.cancellation_invocations.get() + 1);
    }
}

#[tokio::test]
async fn refused_response_cancels_its_exact_owner_without_body_poll() {
    let f = Fixture::new(1).await;
    let (_, mut receipt) = f.closed_source();
    receipt.provider_version = Some("actual/v1".into());
    for (status, etag, version) in [
        (412, Some("\"closed\""), Some("actual/v1")),
        (503, Some("\"closed\""), Some("actual/v1")),
        (200, None, Some("actual/v1")),
        (200, Some("\"replacement\""), Some("actual/v1")),
        (200, Some("W/\"closed\""), Some("actual/v1")),
        (200, Some("\"closed\""), None),
        (200, Some("\"closed\""), Some("actual/v2")),
        (200, Some("\"closed\""), Some("bad\nversion")),
    ] {
        let observed = std::rc::Rc::new(BodyObservations::default());
        let body = UnpolledBody(std::rc::Rc::clone(&observed));
        assert!(closed::select_response(body, &receipt, status, etag, version).is_err());
        assert_eq!(observed.polls.get(), 0);
        assert_eq!(observed.cancellation_invocations.get(), 1);
    }
}

#[tokio::test]
async fn accepted_response_transfers_the_same_unpolled_owner() {
    let f = Fixture::new(1).await;
    let (_, mut receipt) = f.closed_source();
    for version in [None, Some("actual/v1")] {
        receipt.provider_version = version.map(str::to_owned);
        let observed = std::rc::Rc::new(BodyObservations::default());
        let body = UnpolledBody(std::rc::Rc::clone(&observed));
        let selected =
            closed::select_response(body, &receipt, 200, Some("\"closed\""), version).unwrap();
        assert!(std::rc::Rc::ptr_eq(&selected.0, &observed));
        assert_eq!(observed.polls.get(), 0);
        assert_eq!(observed.cancellation_invocations.get(), 0);

        selected.poll();
        assert_eq!(observed.polls.get(), 1);
        drop(selected);
        assert_eq!(observed.cancellation_invocations.get(), 1);
    }
}
