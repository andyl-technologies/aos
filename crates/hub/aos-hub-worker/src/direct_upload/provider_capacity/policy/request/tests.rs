//! Real shared-pool occupancy, cutoff and future-cancellation regressions.

use std::{cell::Cell, future::Future as _, task::Context};

use super::*;

fn policy() -> Policy {
    Policy {
        version: 1,
        deployment_id: "deployment".into(),
        source_digest: "a".repeat(64),
        script_version: "script".into(),
        maximum_provider_requests: 3,
    }
}

#[tokio::test]
async fn compact_metadata_and_delete_share_actual_bulk_occupancy() {
    provider_capacity::configure(3).unwrap();
    let bulk = provider_capacity::acquire_class(2, Class::Bulk)
        .await
        .unwrap();
    let metadata = acquire(&policy(), Class::Metadata, &|| Ok(()))
        .await
        .unwrap();
    assert_eq!(provider_capacity::observation().active, 3);
    let selected = policy();
    let mut delete = Box::pin(acquire(&selected, Class::Foreground, &|| Ok(())));
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(delete.as_mut().poll(&mut context).is_pending());
    drop(metadata);
    let delete = delete.await.unwrap();
    assert_eq!(provider_capacity::observation().active, 3);
    drop(delete);
    drop(bulk);
    assert_eq!(provider_capacity::observation().active, 0);
}

#[tokio::test]
async fn original_cutoff_refuses_a_queued_request_without_another_dispatch() {
    provider_capacity::configure(3).unwrap();
    let occupied = provider_capacity::acquire_class(3, Class::Metadata)
        .await
        .unwrap();
    let valid = Cell::new(true);
    let fresh = || {
        anyhow::ensure!(valid.get(), "original expired");
        Ok(())
    };
    let selected = policy();
    let before = provider_capacity::observation();
    let mut queued = Box::pin(acquire(&selected, Class::Metadata, &fresh));
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(queued.as_mut().poll(&mut context).is_pending());
    valid.set(false);
    assert!(queued.as_mut().poll(&mut context).is_ready());
    assert_eq!(provider_capacity::observation().active, 3);
    assert_eq!(
        provider_capacity::observation().dispatches,
        before.dispatches
    );
    drop(queued);
    drop(occupied);
    assert_eq!(provider_capacity::observation().active, 0);
}

#[tokio::test]
async fn canceled_wait_and_owned_request_release_the_exact_pool_reservation() {
    provider_capacity::configure(3).unwrap();
    let occupied = provider_capacity::acquire_class(3, Class::Metadata)
        .await
        .unwrap();
    let selected = policy();
    let mut queued = Box::pin(acquire(&selected, Class::Metadata, &|| Ok(())));
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(queued.as_mut().poll(&mut context).is_pending());
    drop(queued);
    drop(occupied);
    // Reconfiguration proves the canceled future retained no waiter registration.
    provider_capacity::configure(4).unwrap();
    provider_capacity::configure(3).unwrap();
    let permit = acquire(&selected, Class::Metadata, &|| Ok(()))
        .await
        .unwrap();
    let observed = Cell::new(false);
    let pending = async {
        let _owner = permit;
        observed.set(true);
        futures_util::future::pending::<()>().await
    };
    let mut pending = Box::pin(pending);
    assert!(pending.as_mut().poll(&mut context).is_pending());
    assert!(observed.get());
    assert_eq!(provider_capacity::observation().active, 1);
    drop(pending);
    assert_eq!(provider_capacity::observation().active, 0);
}

#[tokio::test]
async fn verification_reuses_one_actual_slot_beside_atomic_copy_pair() {
    provider_capacity::configure(3).unwrap();
    let bulk = provider_capacity::acquire_class(2, Class::Bulk)
        .await
        .unwrap();
    let verification = acquire(&policy(), Class::Metadata, &|| Ok(()))
        .await
        .unwrap();
    let before = provider_capacity::observation();

    validate_held(&policy(), &verification, &|| Ok(())).unwrap();
    assert_eq!(provider_capacity::observation().active, 3);
    assert_eq!(
        provider_capacity::observation().dispatches,
        before.dispatches
    );

    drop(verification);
    assert_eq!(provider_capacity::observation().active, 2);
    drop(bulk);
    assert_eq!(provider_capacity::observation().active, 0);
}

#[tokio::test]
async fn verification_refuses_pair_ownership_and_incompatible_active_policy() {
    provider_capacity::configure(3).unwrap();
    let pair = provider_capacity::acquire_class(2, Class::Bulk)
        .await
        .unwrap();
    assert!(validate_held(&policy(), &pair, &|| Ok(())).is_err());
    drop(pair);

    let verification = acquire(&policy(), Class::Metadata, &|| Ok(()))
        .await
        .unwrap();
    let mut incompatible = policy();
    incompatible.maximum_provider_requests = 4;
    assert!(validate_held(&incompatible, &verification, &|| Ok(())).is_err());
    assert_eq!(provider_capacity::observation().active, 1);
    drop(verification);
    assert_eq!(provider_capacity::observation().active, 0);
}

#[tokio::test]
async fn verification_cutoff_and_canceled_response_keep_real_owner_custody() {
    provider_capacity::configure(3).unwrap();
    let verification = acquire(&policy(), Class::Metadata, &|| Ok(()))
        .await
        .unwrap();
    let before = provider_capacity::observation();
    assert!(validate_held(&policy(), &verification, &|| anyhow::bail!(
        "original expired"
    ))
    .is_err());
    assert_eq!(
        provider_capacity::observation().dispatches,
        before.dispatches
    );

    let selected = policy();
    let mut response = Box::pin(async {
        validate_held(&selected, &verification, &|| Ok(())).unwrap();
        let _owner = verification;
        futures_util::future::pending::<()>().await;
    });
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(response.as_mut().poll(&mut context).is_pending());
    assert_eq!(provider_capacity::observation().active, 1);

    drop(response);
    assert_eq!(provider_capacity::observation().active, 0);
}
