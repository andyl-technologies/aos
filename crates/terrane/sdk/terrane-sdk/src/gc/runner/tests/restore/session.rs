//! Qualifies restoration and fresh marking under the same original lease session.

use super::*;
use crate::gc::runner::maintenance::{MaintenanceCursor, MaintenanceHint};
use crate::store::Clock;

#[tokio::test]
async fn gc_restoration_native_hands_original_session_to_fresh_marking() {
    let fixture = Fixture::new().await;
    let (original, id, old_trash) = retired(&fixture).await;
    let before = image(&fixture).await;
    let expiry = original.lease().expiry;
    let ticks = fixture.clock.monotonic().as_secs();
    drop(original);

    fixture.clock.set(expiry + 1, ticks + 1);
    let mut restoration = Restoration::start_next(
        fixture.guard(),
        &fixture.authority,
        "restoration-to-marking".into(),
        1_000,
        windows(),
    )
    .await
    .unwrap();
    let lease = restoration.lease().clone();
    let retained_check = restoration.session.owned_check();
    let mut cursor = MaintenanceCursor::default();
    let hints = restoration.maintenance_hints(&mut cursor, 1).await.unwrap();
    assert_eq!(
        hints,
        vec![MaintenanceHint::ExcludedPack(selector(&old_trash))]
    );
    assert!(
        restoration
            .restore_pack(selector(&old_trash))
            .await
            .unwrap()
    );
    assert_restored(&fixture, &before, id).await;
    let restored = image(&fixture).await;
    assert!(
        restored
            .logical
            .get("gc/52/roots")
            .and_then(Option::as_ref)
            .is_none()
    );
    assert!(
        restored
            .logical
            .get("gc/52/state")
            .and_then(Option::as_ref)
            .is_none()
    );

    fixture.clock.set(expiry + 2, ticks + 2);
    let mut collection = restoration.begin_next_collection().await.unwrap();
    assert_eq!(collection.lease().holder, lease.holder);
    assert_eq!(collection.lease().epoch, lease.epoch);
    assert!(collection.lease().expiry > lease.expiry);
    assert_eq!(collection.roots().cycle, 52);
    assert_eq!(collection.state().cycle, 52);
    assert_eq!(collection.state().phase, Phase::Mark);
    assert!(
        collection.roots().roots.iter().any(|root| {
            root.reason == RootReason::Current && root.commit == fixture.head.commit
        })
    );
    assert!(retained_check().is_ok());
    let started = image(&fixture).await;
    for key in ["gc/51/roots", "gc/51/state"] {
        assert_eq!(started.logical.get(key), before.logical.get(key));
    }

    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();
    let fresh_trash = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fresh_trash.pack, *id.as_bytes());
    assert_eq!(fresh_trash.cycle, collection.state().cycle);
    assert_eq!(fresh_trash.epoch, lease.epoch);
    assert_eq!(fresh_trash.timestamp, expiry + 2);
    assert!(fresh_trash.cycle > old_trash.cycle);
    assert!(
        fixture
            .config
            .root
            .join(format!("trash/{}/{id}", old_trash.cycle))
            .exists()
    );
    assert!(!collection.restore_pack(selector(&old_trash)).await.unwrap());
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);

    // Poison after the handoff must invalidate the check retained before it.
    // Merely cloning lease bytes into a new Session would fail this witness.
    drop(collection.session.operation().unwrap());
    assert!(retained_check().is_err());
    assert!(collection.mark_batch(1).await.is_err());
}

#[tokio::test]
async fn gc_restoration_native_expired_handoff_creates_no_checkpoint() {
    let fixture = Fixture::new().await;
    let restoration = Restoration::start_next(
        fixture.guard(),
        &fixture.authority,
        "expired-restoration-handoff".into(),
        1_000,
        windows(),
    )
    .await
    .unwrap();
    let before = image(&fixture).await;
    let expiry = restoration.lease().expiry;
    let ticks = fixture.clock.monotonic().as_secs();
    fixture.clock.set(expiry + 1, ticks + 1);

    assert!(restoration.begin_next_collection().await.is_err());
    let after = image(&fixture).await;
    assert_eq!(after.logical, before.logical);
    assert_eq!(after.state, before.state);
    assert!(
        after
            .logical
            .get("gc/1/roots")
            .and_then(Option::as_ref)
            .is_none()
    );
}
