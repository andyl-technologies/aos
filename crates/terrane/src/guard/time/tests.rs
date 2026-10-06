//! Compares retained scalar checks with full verification using genuine native requests.
//!
//! These witnesses exercise token, clock and context checks only. Native physical
//! publication authority remains with the existing owning acknowledgment cases.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture and refusal assertions intentionally panic."
)]

use super::*;
use crate::bucket::FileBucket;
use crate::bucket::held::SingleHeld;
use crate::guard::{Guard, HistoryObservation};
use crate::ref_advance::native_fixture::NativeFixture;
use crate::ref_advance::tests::{Validator, fixture, request, token};
use crate::store::{StoreErrorKind, TestClock, TokioClock, TokioLocalFs};
use std::time::Duration;
use terrane_core::auth::{Attenuation, Caveat, Token, Verb, Verbs};

const REFERENCE: &str = "refs/heads/_/main";

// The actual shared native fixture uses this RFC 8032 test signing key.
const SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

async fn published_fixture() -> NativeFixture<TokioLocalFs> {
    let repository = fixture().await;
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await.unwrap();
    repository
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    repository
}

fn bounded_token(repository: &NativeFixture<TokioLocalFs>, expiry: u64) -> Vec<u8> {
    let mut authority = auth::verify(&token(), repository.guard().keys(), 100)
        .unwrap()
        .authority()
        .clone();
    authority.not_before = Some(99);
    authority.not_after = expiry;
    Token::issue(authority, &SECRET, repository.guard().keys()[0].public_key)
        .unwrap()
        .encode()
}

async fn captured_request(
    repository: &NativeFixture<TokioLocalFs>,
    clock: &TestClock,
    capability: &[u8],
) -> AuthorizedRef {
    let held = SingleHeld::acquire(repository.store()).await.unwrap();
    let destination = held.destination();
    let guard = repository
        .guard()
        .held_guard(destination, clock.clone())
        .unwrap();
    let proof = guard.store().identity_proof();
    let authorized = guard
        .authorize_observed(
            REFERENCE,
            capability,
            Verb::Commit,
            &[],
            "sdk",
            HistoryObservation::held(&proof),
        )
        .await
        .unwrap();
    assert_eq!(authorized.root_paths(), [b"/".to_vec()]);
    assert!(authorized.record().is_some());
    authorized
}

fn configured_guard(
    repository: &NativeFixture<TokioLocalFs>,
    clock: &TestClock,
    keys: Vec<IssuerKey>,
) -> Guard<FileBucket<TokioLocalFs, TokioClock, Validator>, TestClock> {
    Guard::new(
        repository.store().clone(),
        clock.clone(),
        keys,
        repository.guard().config().clone(),
    )
}

fn assert_denied(result: Result<(), StoreFailure>) {
    assert!(matches!(
        result.unwrap_err().kind(),
        StoreErrorKind::Denied { .. }
    ));
}

#[tokio::test]
async fn retained_scalar_checks_match_full_verification_across_current_times() {
    let repository = published_fixture().await;
    let clock = TestClock::new(100);
    let capability = bounded_token(&repository, 101);
    let authorized = captured_request(&repository, &clock, &capability).await;
    let guard = configured_guard(&repository, &clock, repository.guard().keys().to_vec());
    let retained = guard
        .retain_request_checks(
            std::slice::from_ref(&authorized),
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap();

    for wall in [98, 99, 100, 101, 102] {
        clock.set(wall, 0);
        let full = guard.refresh_authorized_time(&authorized);
        let reused = retained.recheck();
        assert_eq!(full.is_ok(), reused.is_ok(), "wall={wall}");
        if full.is_err() {
            assert_denied(full);
            assert_denied(reused);
        }
    }
}

#[tokio::test]
async fn retained_issuer_selection_preserves_retirement_and_duplicate_clock_rollback() {
    let repository = published_fixture().await;
    let clock = TestClock::new(100);
    let authorized = captured_request(&repository, &clock, &token()).await;
    let mut keys = repository.guard().keys().to_vec();
    keys[0].retirement = Some(101);
    let guard = configured_guard(&repository, &clock, keys);
    let retained = guard
        .retain_request_checks(
            std::slice::from_ref(&authorized),
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap();

    clock.set(101, 0);
    assert_denied(guard.refresh_authorized_time(&authorized));
    assert_denied(retained.recheck());

    clock.set(100, 0);
    let mut keys = repository.guard().keys().to_vec();
    let mut duplicate = keys[0].clone();
    duplicate.retirement = Some(99);
    keys.push(duplicate);
    let guard = configured_guard(&repository, &clock, keys);
    let retained = guard
        .retain_request_checks(
            std::slice::from_ref(&authorized),
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap();
    assert!(retained.recheck().is_ok());

    clock.set(98, 0);
    assert_denied(guard.refresh_authorized_time(&authorized));
    assert_denied(retained.recheck());
}

#[tokio::test]
async fn retained_caveats_reauthorize_exact_request_context() {
    let repository = published_fixture().await;
    let clock = TestClock::new(100);
    let base = captured_request(&repository, &clock, &token()).await;
    let epoch = base.record.as_ref().unwrap().writer_epoch;
    let restricted = Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                caveats: vec![
                    Caveat::Before(102),
                    Caveat::After(98),
                    Caveat::Ref(REFERENCE.into()),
                    Caveat::Root("/".into()),
                    Caveat::Verb(Verbs::new(Verb::Commit as u8).unwrap()),
                    Caveat::Domain(base.root_domains[0].clone()),
                    Caveat::Surface("sdk".into()),
                    Caveat::Epoch(REFERENCE.into(), epoch),
                ],
                ..Default::default()
            },
            &SECRET,
            repository.guard().keys()[0].public_key,
        )
        .unwrap()
        .encode();
    let authorized = captured_request(&repository, &clock, &restricted).await;
    let guard = configured_guard(&repository, &clock, repository.guard().keys().to_vec());
    let retained = guard
        .retain_request_checks(
            std::slice::from_ref(&authorized),
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap();
    assert!(retained.recheck().is_ok());

    let mut changed = Vec::new();
    let mut altered = authorized.clone();
    altered.reference = "refs/heads/_/other".into();
    changed.push(altered);
    let mut altered = authorized.clone();
    altered.root_paths = vec![b"/other".to_vec()];
    changed.push(altered);
    let mut altered = authorized.clone();
    altered.root_domains = vec!["other".into()];
    changed.push(altered);
    let mut altered = authorized.clone();
    altered.surface = "other".into();
    changed.push(altered);
    let mut altered = authorized.clone();
    altered.verb = Verb::Read;
    changed.push(altered);
    let mut altered = authorized.clone();
    altered.record.as_mut().unwrap().writer_epoch += 1;
    changed.push(altered);

    // Mutated contexts are untrusted negative inputs, never issued permissions.
    for altered in changed {
        assert_denied(guard.refresh_authorized_time(&altered));
        let error = guard
            .retain_request_checks(&[altered], Duration::ZERO, Duration::from_secs(30))
            .err()
            .unwrap();
        assert!(matches!(error.kind(), StoreErrorKind::Denied { .. }));
    }
    for wall in [98, 102] {
        clock.set(wall, 0);
        assert_denied(guard.refresh_authorized_time(&authorized));
        assert_denied(retained.recheck());
    }
}

#[tokio::test]
async fn retained_locality_matches_full_scalar_authorization() {
    let repository = published_fixture().await;
    let clock = TestClock::new(100);
    let mut authorized = captured_request(&repository, &clock, &token()).await;
    let expected = Locality {
        region: Some("expected".into()),
        ..Default::default()
    };
    let capability = Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                caveats: vec![Caveat::Locality(expected.clone())],
                ..Default::default()
            },
            &SECRET,
            repository.guard().keys()[0].public_key,
        )
        .unwrap()
        .encode();
    let verified = auth::verify(&capability, repository.guard().keys(), 100).unwrap();
    authorized.token_bytes = capability;

    assert!(refresh(repository.guard().keys(), &expected, &clock, &authorized).is_ok());
    assert!(authorize_retained(&verified, &authorized, &expected, 100).is_ok());
    assert_denied(refresh(
        repository.guard().keys(),
        &Locality::default(),
        &clock,
        &authorized,
    ));
    assert_denied(authorize_retained(
        &verified,
        &authorized,
        &Locality::default(),
        100,
    ));
}

#[tokio::test]
async fn retained_factory_reauthenticates_bytes_and_preserves_refusal() {
    let repository = published_fixture().await;
    let clock = TestClock::new(100);
    let authorized = captured_request(&repository, &clock, &token()).await;
    let guard = configured_guard(&repository, &clock, repository.guard().keys().to_vec());
    let mut malformed = authorized.clone();
    malformed.token_bytes = vec![0];
    assert_denied(guard.refresh_authorized_time(&malformed));
    let error = guard
        .retain_request_checks(
            &[authorized.clone(), malformed],
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Denied { .. }));

    let mut other = auth::verify(&token(), repository.guard().keys(), 100)
        .unwrap()
        .authority()
        .clone();
    other.subject = "other".into();
    let mut changed_principal = authorized.clone();
    changed_principal.token_bytes =
        Token::issue(other, &SECRET, repository.guard().keys()[0].public_key)
            .unwrap()
            .encode();
    assert_denied(guard.refresh_authorized_time(&changed_principal));
    let error = guard
        .retain_request_checks(
            &[changed_principal],
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Denied { .. }));

    let mut wrong_signature = repository.guard().keys().to_vec();
    wrong_signature[0].public_key = [0; 32];
    let mut unknown_issuer = repository.guard().keys().to_vec();
    unknown_issuer[0].issuer = "unknown".into();
    let mut unknown_key = repository.guard().keys().to_vec();
    unknown_key[0].key_id = "unknown".into();
    let mut retired = repository.guard().keys().to_vec();
    retired[0].retirement = Some(100);
    for keys in [
        Vec::new(),
        vec![repository.guard().keys()[0].clone(); 2],
        wrong_signature,
        unknown_issuer,
        unknown_key,
        retired,
    ] {
        let refused = configured_guard(&repository, &clock, keys);
        assert_denied(refused.refresh_authorized_time(&authorized));
        let error = refused
            .retain_request_checks(
                std::slice::from_ref(&authorized),
                Duration::ZERO,
                Duration::from_secs(30),
            )
            .err()
            .unwrap();
        assert!(matches!(error.kind(), StoreErrorKind::Denied { .. }));
    }
    let error = guard
        .retain_request_checks(&[], Duration::ZERO, Duration::from_secs(30))
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Invalid(_)));
}

#[tokio::test]
async fn retained_deadline_rechecks_same_clock_and_preserves_uniform_denial() {
    use std::error::Error;

    let repository = published_fixture().await;
    let clock = TestClock::new(100);
    clock.set(100, 10);
    let authorized = captured_request(&repository, &clock, &token()).await;
    let guard = configured_guard(&repository, &clock, repository.guard().keys().to_vec());
    let retained = guard
        .retain_request_checks(
            std::slice::from_ref(&authorized),
            Duration::from_secs(10),
            Duration::from_secs(30),
        )
        .unwrap();

    clock.set(100, 40);
    assert!(retained.recheck().is_ok());
    for ticks in [41, 9] {
        clock.set(100, ticks);
        let error = retained.recheck().unwrap_err();
        assert!(matches!(error.kind(), StoreErrorKind::Denied { .. }));
        // STORE-30 hides diagnostic detail for every denial, including expiry.
        assert!(error.source().is_none());
        let initial = guard
            .retain_request_checks(
                std::slice::from_ref(&authorized),
                Duration::from_secs(10),
                Duration::from_secs(30),
            )
            .err()
            .unwrap();
        assert!(matches!(initial.kind(), StoreErrorKind::Denied { .. }));
        assert!(initial.source().is_none());
    }
}

#[tokio::test]
async fn retained_clock_retention_refusal_precedes_empty_requests() {
    struct UnsupportedClock;

    #[cfg_attr(feature = "send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
    impl Clock for UnsupportedClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(100)
        }

        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
    }

    let repository = published_fixture().await;
    let guard = Guard::new(
        repository.store().clone(),
        UnsupportedClock,
        repository.guard().keys().to_vec(),
        repository.guard().config().clone(),
    );
    let error = guard
        .retain_request_checks(&[], Duration::ZERO, Duration::from_secs(30))
        .err()
        .unwrap();
    assert!(matches!(error.kind(), StoreErrorKind::Unsupported));
}
