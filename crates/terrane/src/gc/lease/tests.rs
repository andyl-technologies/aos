//! Exercises selected collector leases against actual protected native storage.

#![allow(
    clippy::unwrap_used,
    reason = "Bounded native fixture assertions intentionally panic."
)]

use super::fixture::*;
use super::*;
use std::sync::Arc;
use std::time::Duration;
use terrane_core::bucket::BucketKey;

mod empty_roots;

#[tokio::test]
async fn native_gc_independent_collectors_have_one_selected_winner() {
    let fixture = Fixture::new().await;
    let other = fixture.reopen().await;
    let before = fixture.selected().await.0;
    fixture.fs.reset();

    let left_collector = fixture.collector();
    let right_collector = Collector::new(other.as_ref(), &fixture.authority);
    let (left, right) = tokio::join!(
        left_collector.acquire("A".into(), 20),
        right_collector.acquire("B".into(), 20)
    );

    assert_ne!(left.is_ok(), right.is_ok());
    let chosen = left.or(right).unwrap();
    let (mut after, lease) = fixture.selected().await;
    assert_eq!(chosen.lease, lease.unwrap());
    assert_eq!(chosen.revision, before.revision + 1);
    after.revision = before.revision;
    assert_eq!(after, before);
    assert_eq!(
        selection(fixture.reopen().await.store()).await.1,
        Some(chosen.lease)
    );
}

#[tokio::test]
async fn native_gc_renewal_uses_exact_whole_value_and_increases_revision() {
    let fixture = Fixture::new().await;
    let first = fixture.collector().acquire("A".into(), 20).await.unwrap();
    fixture.clock.set(105, 5);

    let renewed = fixture.collector().renew(&first.lease, 30).await.unwrap();

    assert_eq!(renewed.lease.holder, first.lease.holder);
    assert_eq!(renewed.lease.epoch, first.lease.epoch);
    assert_eq!(renewed.lease.expiry, 135);
    assert_eq!(renewed.revision, first.revision + 1);
    fixture.fs.reset();
    assert!(matches!(
        fixture.collector().renew(&first.lease, 40).await,
        Err(LeaseError::Lease(terrane_core::gc::GcError::LeaseLost))
    ));
    assert_eq!(fixture.fs.effects(), 0);
    assert_eq!(fixture.selected().await.1, Some(renewed.lease));
}

#[tokio::test]
async fn native_gc_live_other_holder_refuses_without_cache_repair_or_effects() {
    let fixture = Fixture::new().await;
    let first = fixture.collector().acquire("A".into(), 20).await.unwrap();
    let cache = fixture.config.root.join("gc/lease");
    std::fs::write(&cache, b"stale recoverable cache").unwrap();
    fixture.fs.reset();

    assert!(matches!(
        fixture.collector().acquire("B".into(), 20).await,
        Err(LeaseError::Lease(terrane_core::gc::GcError::LeaseLost))
    ));

    assert_eq!(fixture.fs.effects(), 0);
    assert_eq!(std::fs::read(&cache).unwrap(), b"stale recoverable cache");
    assert_eq!(fixture.selected().await.1, Some(first.lease));
}

#[tokio::test]
async fn native_gc_expired_lease_takeover_selects_a_higher_epoch() {
    let fixture = Fixture::new().await;
    let first = fixture.collector().acquire("A".into(), 20).await.unwrap();
    fixture.clock.set(120, 20);

    let takeover = fixture.collector().acquire("B".into(), 25).await.unwrap();

    assert_eq!(takeover.lease.holder, "B");
    assert_eq!(takeover.lease.epoch, first.lease.epoch + 1);
    assert_eq!(takeover.lease.expiry, 145);
    assert_eq!(takeover.revision, first.revision + 1);
    assert_eq!(fixture.selected().await.1, Some(takeover.lease));
}

async fn arrival(received: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || received.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn native_gc_queued_expiry_refuses_before_selected_slot_syscall() {
    let fixture = Fixture::new().await;
    let before = fixture.selected().await.0;
    let slot = fixture.slot(before.revision + 1);
    let (arrived, release) = fixture.fs.before_slot(slot.clone());
    let guard = Arc::clone(&fixture.guard);
    let authority = fixture.authority.clone();
    let worker = tokio::spawn(async move {
        Collector::new(guard.as_ref(), &authority)
            .acquire("A".into(), 20)
            .await
    });
    arrival(arrived).await;

    fixture.clock.set(120, 20);
    release.send(()).unwrap();

    assert!(worker.await.unwrap().is_err());
    assert!(!slot.exists());
    assert_eq!(fixture.selected().await, (before, None));
}

#[tokio::test]
async fn native_gc_queued_consumed_control_change_refuses_before_syscall() {
    queued_preimage_change(false).await;
}

#[tokio::test]
async fn native_gc_queued_predecessor_change_refuses_before_syscall() {
    queued_preimage_change(true).await;
}

async fn queued_preimage_change(predecessor: bool) {
    let fixture = Fixture::new().await;
    let before = fixture.selected().await.0;
    let slot = fixture.slot(before.revision + 1);
    let changed = if predecessor {
        fixture.slot(before.revision)
    } else {
        fixture.authority.control().join("registration.cbor")
    };
    let original = std::fs::read(&changed).unwrap();
    let (arrived, release) = fixture.fs.before_slot(slot.clone());
    let guard = Arc::clone(&fixture.guard);
    let authority = fixture.authority.clone();
    let worker = tokio::spawn(async move {
        Collector::new(guard.as_ref(), &authority)
            .acquire("A".into(), 20)
            .await
    });
    arrival(arrived).await;

    let mut altered = original.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    std::fs::write(&changed, altered).unwrap();
    release.send(()).unwrap();

    assert!(worker.await.unwrap().is_err());
    assert!(!slot.exists());
    std::fs::write(&changed, original).unwrap();
    assert_eq!(fixture.selected().await, (before, None));
}

#[tokio::test]
async fn native_gc_cancelled_waiter_retains_all_exclusions_through_slot_sync() {
    let fixture = Fixture::new().await;
    let before = fixture.selected().await.0;
    let slot = fixture.slot(before.revision + 1);
    let (arrived, release) = fixture.fs.after_slot(slot.clone());
    let guard = Arc::clone(&fixture.guard);
    let authority = fixture.authority.clone();
    let worker = tokio::spawn(async move {
        Collector::new(guard.as_ref(), &authority)
            .acquire("A".into(), 20)
            .await
    });
    arrival(arrived).await;
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    assert!(slot.exists());
    let namespace = fixture
        .config
        .root
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let paths = [
        namespace,
        fixture.authority.control().join("retention.lock"),
    ];
    let contenders = paths.map(|path| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    });

    for contender in &contenders {
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
    }
    release.send(()).unwrap();
    for contender in contenders {
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || contender.lock()),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    }

    let reopened = fixture.reopen().await;
    let (after, lease) = selection(reopened.store()).await;
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(
        lease.unwrap(),
        GcLease {
            holder: "A".into(),
            epoch: 1,
            expiry: 120
        }
    );
}

#[tokio::test]
async fn native_gc_queued_renewal_requires_the_original_expiry_to_remain_live() {
    let fixture = Fixture::new().await;
    let initial = fixture.collector().acquire("A".into(), 20).await.unwrap();
    let before = fixture.selected().await;
    fixture.clock.set(105, 5);
    let slot = fixture.slot(initial.revision + 1);
    let (arrived, release) = fixture.fs.before_slot(slot.clone());
    let guard = Arc::clone(&fixture.guard);
    let authority = fixture.authority.clone();
    let worker = tokio::spawn(async move {
        Collector::new(guard.as_ref(), &authority)
            .renew(&initial.lease, 30)
            .await
    });
    arrival(arrived).await;

    fixture.clock.set(120, 20);
    release.send(()).unwrap();

    assert!(worker.await.unwrap().is_err());
    assert!(!slot.exists());
    assert_eq!(fixture.selected().await, before);
}

#[tokio::test]
async fn native_gc_queued_clock_discontinuity_refuses_before_syscall() {
    for wall_rollback in [true, false] {
        let fixture = Fixture::new().await;
        fixture.clock.set(100, 10);
        let before = fixture.selected().await.0;
        let slot = fixture.slot(before.revision + 1);
        let (arrived, release) = fixture.fs.before_slot(slot.clone());
        let guard = Arc::clone(&fixture.guard);
        let authority = fixture.authority.clone();
        let worker = tokio::spawn(async move {
            Collector::new(guard.as_ref(), &authority)
                .acquire("A".into(), 20)
                .await
        });
        arrival(arrived).await;

        if wall_rollback {
            fixture.clock.set(99, 11);
        } else {
            fixture.clock.set(100, 9);
        }
        release.send(()).unwrap();

        assert!(worker.await.unwrap().is_err());
        assert!(!slot.exists());
        assert_eq!(fixture.selected().await, (before, None));
    }
}

#[tokio::test]
async fn native_gc_stale_configured_guard_refuses_without_effects() {
    use crate::store::Clock;
    let fixture = Fixture::new().await;
    let mut config = configuration();
    config.initial_acl = vec![("configured-other".into(), 1)];
    let changed = crate::guard::Guard::new(
        fixture.guard.store().clone(),
        fixture.clock.retain_native_clock().unwrap(),
        Vec::new(),
        config,
    );
    let before = fixture.selected().await;
    fixture.fs.reset();

    assert!(
        Collector::new(&changed, &fixture.authority)
            .acquire("A".into(), 20)
            .await
            .is_err()
    );

    assert_eq!(fixture.fs.effects(), 0);
    assert_eq!(fixture.selected().await, before);
}

#[tokio::test]
async fn native_gc_existing_open_does_not_recreate_coordination_or_control() {
    use crate::store::Clock;
    for missing_control in [true, false] {
        let fixture = Fixture::new().await;
        let path = if missing_control {
            fixture.parent.join("publication")
        } else {
            fixture
                .config
                .root
                .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name())
        };
        if missing_control {
            std::fs::remove_dir_all(&path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        fixture.fs.reset();

        assert!(
            crate::bucket::FileBucket::open(
                fixture.config.clone(),
                fixture.fs.clone(),
                fixture.clock.retain_native_clock().unwrap(),
                Validator,
            )
            .await
            .is_err()
        );

        assert!(!path.exists());
        assert_eq!(fixture.fs.effects(), 0);
    }
}

#[tokio::test]
async fn native_gc_final_selection_ack_requires_current_retained_clock() {
    let fixture = Fixture::new().await;
    let before = fixture.selected().await.0;
    fixture
        .fs
        .expire_after_root_sync(fixture.config.root.clone(), fixture.clock.clone());

    assert!(fixture.collector().acquire("A".into(), 20).await.is_err());

    let (after, selected) = fixture.selected().await;
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(
        selected,
        Some(GcLease {
            holder: "A".into(),
            epoch: 1,
            expiry: 120
        })
    );
}
