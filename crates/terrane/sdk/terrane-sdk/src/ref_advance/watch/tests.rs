//! Exercises closing authorization across genuine native watch observations.

#![allow(clippy::unwrap_used)]

use std::time::{Duration, UNIX_EPOCH};

use terrane_format::auth::{Attenuation, Token};

use crate::{
    ref_advance::tests::{fixture, request, request_file_acl, secret, token},
    store::{Clock, StoreErrorKind, TokioClock},
};

const REFERENCE: &str = "refs/heads/_/main";

#[tokio::test]
async fn changed_horizon_refuses_pending_event_and_retry_preserves_every_sequence() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(REFERENCE, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let mut watch = coordinator.watch(REFERENCE, &token(), "sdk").await.unwrap();
    let pending = watch.read_pending().await.unwrap().unwrap();
    let cursor = watch.next_sequence;

    let second = coordinator
        .advance(&mut session, request(vec![first.commit]))
        .await
        .unwrap();
    let error = watch.emit(pending).await.unwrap_err();

    assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
    assert_eq!(watch.next_sequence, cursor);
    assert_eq!(watch.next().await.unwrap().unwrap().record, first);
    assert_eq!(watch.next().await.unwrap().unwrap().record, second);
    watch.close();
    assert!(watch.next().await.unwrap().is_none());
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn revoked_current_acl_refuses_pending_event_without_advancing_cursor() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(REFERENCE, &token(), "sdk").await.unwrap();
    let first = coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let mut watch = coordinator.watch(REFERENCE, &token(), "sdk").await.unwrap();
    let pending = watch.read_pending().await.unwrap().unwrap();
    let cursor = watch.next_sequence;

    coordinator
        .advance(
            &mut session,
            request_file_acl(vec![first.commit], b"revoked", 0),
        )
        .await
        .unwrap();
    let error = watch.emit(pending).await.unwrap_err();

    assert!(matches!(error.kind(), StoreErrorKind::Denied { .. }));
    assert_eq!(watch.next_sequence, cursor);
    assert!(matches!(
        watch.next().await.unwrap_err().kind(),
        StoreErrorKind::Denied { .. }
    ));
    assert_eq!(watch.next_sequence, cursor);
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}

#[tokio::test]
async fn expiry_after_log_read_refuses_pending_event_without_advancing_cursor() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(REFERENCE, &token(), "sdk").await.unwrap();
    coordinator
        .advance(&mut session, request(Vec::new()))
        .await
        .unwrap();
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 5;
    let expiring = Token::decode(&token())
        .unwrap()
        .attenuate(
            Attenuation {
                not_after: Some(expires),
                ..Attenuation::default()
            },
            &secret(),
            terrane_format::auth::public_key_from_secret(&secret()),
        )
        .unwrap()
        .encode();
    let mut watch = coordinator
        .watch(REFERENCE, &expiring, "sdk")
        .await
        .unwrap();
    let pending = watch.read_pending().await.unwrap().unwrap();
    let cursor = watch.next_sequence;

    // Wait across the genuine signed expiry using the actual injected clock.
    // No clock replacement or synthetic policy state supplies authority here.
    let past_expiry = UNIX_EPOCH + Duration::from_secs(expires + 1);
    if let Ok(remaining) = past_expiry.duration_since(TokioClock.now()) {
        TokioClock.sleep(remaining).await.unwrap();
    }
    let error = watch.emit(pending).await.unwrap_err();

    assert!(matches!(error.kind(), StoreErrorKind::Denied { .. }));
    assert_eq!(watch.next_sequence, cursor);
    tokio::fs::remove_dir_all(coordinator.store().root())
        .await
        .unwrap();
}
