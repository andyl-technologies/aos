//! Receiver-clock and unchanged-expiry checks for actual authority admission.

use std::cell::Cell;
use std::rc::Rc;

use aos_hub_db::storage_authority::control::StorageAuthorityOperation;
use aos_hub_db::storage_authority::PhysicalStorageAuthorityId;

use super::*;

const DEPLOYMENT: &str = "paired-native-deployment";
const NAMESPACE: &str = "account/actual-object-namespace";

fn request() -> StorageAuthorityRequest {
    StorageAuthorityRequest {
        version: 1,
        deployment_id: DEPLOYMENT.into(),
        guard_namespace_id: NAMESPACE.into(),
        nonce: "a".repeat(64),
        issued_at: 100,
        expires_at: 130,
        operation: StorageAuthorityOperation::Watermark(
            PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        ),
    }
}

#[tokio::test]
async fn future_authority_waits_without_admission_or_changing_the_original() {
    let original = request();
    let retained = original.clone();
    let clock = Rc::new(Cell::new(99));
    let waited = Rc::new(Cell::new(None));
    let (resume, ready) = tokio::sync::oneshot::channel();
    let mut checked = Box::pin(validate_when_current(
        &original,
        DEPLOYMENT,
        NAMESPACE,
        || clock.get(),
        |duration| {
            waited.set(Some(duration));
            async move { ready.await.unwrap() }
        },
    ));

    assert!(futures_util::poll!(&mut checked).is_pending());
    assert_eq!(waited.get(), Some(Duration::from_secs(1)));
    assert!(original
        .validate(DEPLOYMENT, NAMESPACE, clock.get())
        .is_err());

    clock.set(100);
    resume.send(()).unwrap();
    checked.await.unwrap();

    assert_eq!(original, retained);
    original
        .validate(DEPLOYMENT, NAMESPACE, clock.get())
        .unwrap();
}

#[tokio::test]
async fn authority_not_before_wait_is_bounded_and_rejects_excessive_skew() {
    let original = request();
    let clock = Cell::new(98);
    let waited = Cell::new(None);

    validate_when_current(
        &original,
        DEPLOYMENT,
        NAMESPACE,
        || clock.get(),
        |duration| {
            waited.set(Some(duration));
            async { clock.set(100) }
        },
    )
    .await
    .unwrap();

    assert_eq!(waited.get(), Some(Duration::from_secs(2)));
    assert!(validate_when_current(
        &original,
        DEPLOYMENT,
        NAMESPACE,
        || 97,
        |_| async { panic!("excessive future skew must not allocate a wait") }
    )
    .await
    .is_err());
    assert!(validate_when_current(
        &original,
        DEPLOYMENT,
        NAMESPACE,
        || i64::MIN,
        |_| async { panic!("overflowing skew must not allocate a wait") },
    )
    .await
    .is_err());
}

#[tokio::test]
async fn authority_wait_rechecks_clock_rollback_and_original_exclusive_expiry() {
    let original = request();

    for after_wait in [98, 99, 130, 131] {
        let clock = Cell::new(99);
        let result = validate_when_current(
            &original,
            DEPLOYMENT,
            NAMESPACE,
            || clock.get(),
            |_| async { clock.set(after_wait) },
        )
        .await;

        assert!(result.is_err(), "clock after wait: {after_wait}");
        assert_eq!(original.issued_at, 100);
        assert_eq!(original.expires_at, 130);
    }
}

#[tokio::test]
async fn malformed_future_authority_requests_are_rejected_before_waiting() {
    let original = request();

    for field in ["deployment", "namespace", "version", "nonce", "lifetime"] {
        let mut changed = original.clone();
        match field {
            "deployment" => changed.deployment_id = "another-deployment".into(),
            "namespace" => changed.guard_namespace_id = "another-namespace".into(),
            "version" => changed.version = 2,
            "nonce" => changed.nonce = "invalid".into(),
            "lifetime" => changed.expires_at = 131,
            _ => unreachable!(),
        }

        assert!(validate_when_current(
            &changed,
            DEPLOYMENT,
            NAMESPACE,
            || 99,
            |_| async { panic!("malformed original must not allocate a wait") }
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn current_authority_requests_keep_strict_freshness_without_waiting() {
    let original = request();

    for (observed, valid) in [(100, true), (129, true), (130, false), (131, false)] {
        let result = validate_when_current(
            &original,
            DEPLOYMENT,
            NAMESPACE,
            || observed,
            |_| async { panic!("current or expired original must not allocate a wait") },
        )
        .await;

        assert_eq!(result.is_ok(), valid, "receiver clock: {observed}");
    }
}
