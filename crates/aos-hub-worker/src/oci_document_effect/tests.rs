//! Provider counters for expiry across actual pending effect futures.

use super::*;
use aos_hub_core::hybrid_ingress::OciDocumentEffect;
use futures_util::future::{join, poll_fn};
use std::{cell::Cell, task::Poll};

fn original() -> OciDocumentEffect {
    OciDocumentEffect {
        protected_profile_digest: "a".repeat(64),
        acceptance_digest: "b".repeat(64),
        issued_at: 100,
        expires_at: 130,
        clock_uncertainty_seconds: 2,
    }
}

#[tokio::test]
async fn pending_create_or_part_cannot_renew_original_or_dispatch_next_effect() {
    for expired_after in [1, 2] {
        let original = original();
        let now = Cell::new(100);
        let creates = Cell::new(0);
        let parts = Cell::new(0);
        let completes = Cell::new(0);
        let blocked = Cell::new(false);
        let release = Cell::new(false);
        let wait = || async {
            blocked.set(true);
            poll_fn(|cx| {
                if release.get() {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        };
        let operation = stage(
            || original.check(now.get()),
            || async {
                creates.set(creates.get() + 1);
                if expired_after == 1 {
                    wait().await;
                }
                Ok("actual-provider-upload".into())
            },
            |upload| {
                let parts = &parts;
                let wait = &wait;
                async move {
                    assert_eq!(upload, "actual-provider-upload");
                    parts.set(parts.get() + 1);
                    if expired_after == 2 {
                        wait().await;
                    }
                    Ok("actual-provider-part".into())
                }
            },
            |upload, etag| {
                let completes = &completes;
                async move {
                    assert_eq!(upload, "actual-provider-upload");
                    assert_eq!(etag, "actual-provider-part");
                    completes.set(completes.get() + 1);
                    Ok(())
                }
            },
        );
        let advance_while_pending = async {
            poll_fn(|cx| {
                if blocked.get() {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
            now.set(128); // latest equals the exclusive original cutoff.
            release.set(true);
        };

        let (result, ()) = join(operation, advance_while_pending).await;

        assert!(result.is_err());
        assert_eq!(creates.get(), 1);
        assert_eq!(parts.get(), if expired_after == 1 { 0 } else { 1 });
        assert_eq!(completes.get(), 0);
        assert_eq!(original.expires_at, 130);
    }
}

#[tokio::test]
async fn live_original_dispatches_each_effect_once_and_refuses_initial_expiry() {
    for now in [100, 128] {
        let original = original();
        let creates = Cell::new(0);
        let parts = Cell::new(0);
        let completes = Cell::new(0);

        let result = stage(
            || original.check(now),
            || async {
                creates.set(creates.get() + 1);
                Ok("upload".into())
            },
            |_| async {
                parts.set(parts.get() + 1);
                Ok("part".into())
            },
            |_, _| async {
                completes.set(completes.get() + 1);
                Ok(())
            },
        )
        .await;

        assert_eq!(result.is_ok(), now == 100);
        let expected = if now == 100 { 1 } else { 0 };
        assert_eq!(
            (creates.get(), parts.get(), completes.get()),
            (expected, expected, expected)
        );
    }
}

#[tokio::test]
async fn pending_guard_authority_wait_keeps_unknown_intent_and_refuses_complete() {
    let original = original();
    let now = Cell::new(100);
    let pending_intent = Cell::new(true);
    let waiting = Cell::new(false);
    let release = Cell::new(false);
    let completes = Cell::new(0);
    let waiter = async {
        waiting.set(true);
        poll_fn(|cx| {
            if release.get() {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        Ok(())
    };
    let operation = dispatch_after(
        waiter,
        |_| original.check(now.get()),
        |_| async {
            completes.set(completes.get() + 1);
            pending_intent.set(false);
            Ok(String::from("provider-completed"))
        },
    );
    let expiry = async {
        poll_fn(|cx| {
            if waiting.get() {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        now.set(128);
        release.set(true);
    };

    let (result, ()) = join(operation, expiry).await;

    assert!(result.is_err());
    assert_eq!(completes.get(), 0);
    assert!(pending_intent.get());
}

#[tokio::test]
async fn cancelled_pending_sdk_retains_aggregate_capacity_and_memory_until_settlement() {
    use crate::direct_upload::provider_capacity;
    use crate::oci_projection_lifetime::{Owner, Scope};
    use std::rc::Rc;

    provider_capacity::configure(1).unwrap();
    let original = original();
    let now = Cell::new(100);
    let check = || original.check(now.get());
    let capacity = provider_capacity::acquire_checked(1, &check).await.unwrap();
    provider_capacity::record_dispatch();
    let memory = Rc::new(
        crate::mirror_import::buffers::acquire(false, &check)
            .await
            .unwrap(),
    );
    let owner = Owner::new((capacity, Rc::clone(&memory)));
    let request = Scope(Rc::clone(&owner));
    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    let pending_owner = Rc::clone(&owner);
    let actual_pending_sdk = async move {
        receiver.await.unwrap();
        drop(pending_owner);
    };
    let awaiting_capacity = provider_capacity::acquire_checked(1, &check);
    futures_util::pin_mut!(awaiting_capacity);
    assert!(futures_util::poll!(&mut awaiting_capacity).is_pending());
    assert_eq!(provider_capacity::observation().active, 1);
    assert_eq!(Rc::strong_count(&memory), 2);

    // Closing the original request denies new work but cannot release a native
    // promise's resource ownership or turn its pending journal into a receipt.
    drop(request);
    assert!(owner.check_open().is_err());
    drop(owner);
    now.set(128);
    assert_eq!(provider_capacity::observation().active, 1);
    assert_eq!(Rc::strong_count(&memory), 2);

    sender.send(()).unwrap();
    actual_pending_sdk.await;

    assert_eq!(provider_capacity::observation().active, 0);
    assert_eq!(provider_capacity::observation().peak_active, 1);
    assert_eq!(provider_capacity::observation().dispatches, 1);
    assert_eq!(Rc::strong_count(&memory), 1);
    assert!(awaiting_capacity.await.is_err());
    assert_eq!(original.expires_at, 130);
}
