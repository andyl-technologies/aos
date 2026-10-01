//! Qualifies real root selection, mark checkpoints and permanent renewal poisoning.

#![allow(
    clippy::unwrap_used,
    reason = "Bounded native assertions intentionally panic."
)]

use super::fixture::Fixture;
use super::*;
use terrane_core::bucket::BucketKey;
use terrane_core::gc::{GcMark, Phase, RootReason};
use terrane_core::identity::{IdentityKind, TERRANE_V1};

mod notes;

fn windows() -> Windows {
    Windows::new(30, 60, 60, 90).unwrap()
}

#[tokio::test]
async fn gc_native_published_roots_mark_finish_and_resume() {
    let fixture = Fixture::new().await;
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .unwrap();
    assert!(
        collection
            .roots()
            .roots
            .iter()
            .any(|root| root.commit == fixture.head.commit && root.reason == RootReason::Current)
    );
    assert!(
        collection
            .roots()
            .roots
            .iter()
            .any(|root| root.commit == fixture.head.commit && root.reason == RootReason::ReflogGc)
    );

    collection.mark_batch(1).await.unwrap();
    assert!(!collection.state().checkpoints.is_empty());
    let selected = fixture.selected_state(1).await;
    assert_eq!(&selected, collection.state());
    let lease = collection.lease().clone();
    drop(collection);
    let mut resumed = Collection::resume(
        fixture.guard(),
        &fixture.authority,
        lease,
        1_000,
        1,
        windows(),
    )
    .await
    .unwrap();
    assert_eq!(resumed.state(), &selected);
    resumed.mark_batch(1).await.unwrap();
    let split_checkpoint = fixture.selected_state(1).await;
    assert_eq!(resumed.state(), &split_checkpoint);
    let lease = resumed.lease().clone();
    drop(resumed);
    let mut resumed = Collection::resume(
        fixture.guard(),
        &fixture.authority,
        lease,
        1_000,
        1,
        windows(),
    )
    .await
    .unwrap();
    assert_eq!(resumed.state(), &split_checkpoint);
    resumed.mark_batch(16).await.unwrap();
    assert!(resumed.state().pending.is_empty());
    assert_eq!(resumed.state().checkpoints, selected.checkpoints);
    let pointers = resumed.state().checkpoints.clone();
    resumed.finish_mark().await.unwrap();
    assert_eq!(resumed.state().checkpoints, pointers);
    assert_eq!(resumed.state().phase, Phase::Sweep);
    assert_eq!(fixture.selected_state(1).await, *resumed.state());

    let chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"published source")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let pointer = resumed
        .state()
        .checkpoints
        .iter()
        .find(|pointer| pointer.shard == chunk[0])
        .unwrap();
    let mark = GcMark::decode(
        &std::fs::read(
            fixture
                .config
                .root
                .join(format!("gc/1/mark/{}/{}", pointer.shard, pointer.revision)),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(mark.contains(&chunk));
    let completed = resumed.state().clone();
    let lease = resumed.lease().clone();
    drop(resumed);
    let reopened = Collection::resume(
        fixture.guard(),
        &fixture.authority,
        lease,
        1_000,
        1,
        windows(),
    )
    .await
    .unwrap();
    assert_eq!(reopened.state(), &completed);
    drop(reopened);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_native_takeover_refuses_old_mark_epoch_and_completes_new_cycle() {
    let fixture = Fixture::new().await;
    let mut original = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "original".into(),
        1_000,
        6,
        windows(),
    )
    .await
    .unwrap();
    original.mark_batch(1).await.unwrap();
    let previous = fixture.selected_state(6).await;
    let old_marks = previous
        .checkpoints
        .iter()
        .map(|pointer| {
            let path = fixture
                .config
                .root
                .join(format!("gc/6/mark/{}/{}", pointer.shard, pointer.revision,));
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect::<Vec<_>>();
    assert!(!old_marks.is_empty());

    let expiry = original.lease().expiry;
    fixture.clock.set(expiry, expiry - 100);
    let takeover = Collector::new(fixture.guard(), &fixture.authority)
        .acquire("takeover".into(), 1_000)
        .await
        .unwrap();
    assert!(takeover.lease.epoch > previous.epoch);
    fixture.fs.reset();

    assert!(
        Collection::resume(
            fixture.guard(),
            &fixture.authority,
            takeover.lease.clone(),
            1_000,
            6,
            windows(),
        )
        .await
        .is_err()
    );
    // Resume legitimately renewed ownership before refusing the old mark epoch.
    // One lease selection is permitted; no checkpoint selection follows it.
    assert!(fixture.fs.effects() > 0);
    let (renewed, revision) = fixture.selected_lease().await;
    assert_eq!(revision, takeover.revision + 1);
    assert_eq!(renewed.epoch, takeover.lease.epoch);
    assert_eq!(renewed.holder, takeover.lease.holder);
    assert!(renewed.expiry > takeover.lease.expiry);
    assert_eq!(fixture.selected_state(6).await, previous);
    for (path, bytes) in &old_marks {
        assert_eq!(std::fs::read(path).unwrap(), *bytes);
    }

    fixture.fs.reset();
    assert!(original.mark_batch(1).await.is_err());
    assert!(original.finish_mark().await.is_err());
    assert_eq!(fixture.fs.effects(), 0);
    drop(original);

    // Start always acquires actual ownership. Expire the renewed live lease
    // before selecting a genuinely fresh epoch and a different cycle.
    fixture.clock.set(renewed.expiry, renewed.expiry - 100);
    let mut fresh = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "fresh".into(),
        1_000,
        7,
        windows(),
    )
    .await
    .unwrap();
    assert!(fresh.lease().epoch > renewed.epoch);
    assert_eq!(fresh.roots().epoch, fresh.lease().epoch);
    assert_eq!(fresh.state().epoch, fresh.lease().epoch);
    assert!(fresh.state().checkpoints.is_empty());
    fresh.mark_batch(16).await.unwrap();
    fresh.finish_mark().await.unwrap();
    assert_eq!(fresh.state().phase, Phase::Sweep);
    assert_eq!(fixture.selected_state(7).await, *fresh.state());
    assert_eq!(fixture.selected_state(6).await, previous);
    for (path, bytes) in &old_marks {
        assert_eq!(std::fs::read(path).unwrap(), *bytes);
    }
    drop(fresh);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_native_stale_runner_renewal_stops_before_checkpoint_effects() {
    let fixture = Fixture::new().await;
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        2,
        windows(),
    )
    .await
    .unwrap();
    collection.mark_batch(1).await.unwrap();
    let previous = fixture.selected_state(2).await;
    Collector::new(fixture.guard(), &fixture.authority)
        .renew(collection.lease(), 10_000)
        .await
        .unwrap();
    fixture.fs.reset();

    assert!(collection.mark_batch(1).await.is_err());
    assert_eq!(fixture.fs.effects(), 0);
    assert_eq!(fixture.selected_state(2).await, previous);
    fixture.fs.reset();
    fixture.clock.set(101, 1);
    assert!(collection.mark_batch(1).await.is_err());
    assert!(collection.finish_mark().await.is_err());
    assert_eq!(fixture.fs.effects(), 0);
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_native_incomplete_mark_cannot_select_sweep() {
    let fixture = Fixture::new().await;
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        3,
        windows(),
    )
    .await
    .unwrap();
    let selected = fixture.selected_state(3).await;
    assert!(collection.finish_mark().await.is_err());
    assert_eq!(fixture.selected_state(3).await, selected);
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_native_canceled_checkpoint_keeps_exclusion_and_poisons_session() {
    use std::time::Duration;

    let fixture = Fixture::new().await;
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        4,
        windows(),
    )
    .await
    .unwrap();
    let previous = fixture.selected_state(4).await;
    let (arrived, release) = fixture.fs.before_slot(fixture.next_checkpoint_slot().await);
    let arrival =
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut operation = Box::pin(collection.mark_batch(1));
    tokio::select! {
        result = &mut operation => panic!("checkpoint ended before queued dispatch: {result:?}"),
        result = arrival => result.unwrap(),
    }
    drop(operation);

    let namespace = fixture
        .config
        .root
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(namespace)
        .unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));

    let config = fixture.config.clone();
    let fs = fixture.fs.clone();
    let clock = fixture.clock.retain_native_clock().unwrap();
    let mut reopen = tokio::spawn(async move {
        FileBucket::open(config, fs, clock, super::fixture::Validator).await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut reopen)
            .await
            .is_err()
    );
    release.send(()).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            contender.lock().unwrap();
            contender.unlock().unwrap();
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(10), reopen)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    assert_eq!(fixture.selected_state(4).await, previous);

    fixture.fs.reset();
    assert!(collection.mark_batch(1).await.is_err());
    assert!(collection.finish_mark().await.is_err());
    assert_eq!(fixture.fs.effects(), 0);
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_native_count_zero_keeps_parent_metadata_without_old_chunks() {
    let fixture = Fixture::new().await;
    let current = fixture.publish_count_zero().await;
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        5,
        windows(),
    )
    .await
    .unwrap();
    assert!(
        collection
            .roots()
            .roots
            .iter()
            .any(|root| root.commit == current.commit && root.reason == RootReason::Current)
    );
    assert!(
        collection
            .roots()
            .roots
            .iter()
            .any(|root| root.commit == fixture.head.commit
                && root.reason == RootReason::RetentionWitness)
    );
    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();

    let mut hashes = std::collections::BTreeSet::new();
    for pointer in &collection.state().checkpoints {
        let bytes = std::fs::read(
            fixture
                .config
                .root
                .join(format!("gc/5/mark/{}/{}", pointer.shard, pointer.revision)),
        )
        .unwrap();
        let mark = GcMark::decode(&bytes).unwrap();
        hashes.extend(mark.hashes().iter().copied());
    }
    assert!(hashes.contains(&fixture.head.commit));
    assert!(hashes.contains(&current.commit));
    assert!(
        hashes.contains(
            &TERRANE_V1
                .calculate(IdentityKind::Chunk, b"current source")
                .unwrap()
                .terrane_v1_digest()
                .unwrap()
        )
    );
    assert!(
        !hashes.contains(
            &TERRANE_V1
                .calculate(IdentityKind::Chunk, b"published source")
                .unwrap()
                .terrane_v1_digest()
                .unwrap()
        )
    );
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_native_queued_checkpoint_rechecks_actual_expiry_and_never_acknowledges() {
    use std::time::Duration;

    let fixture = Fixture::new().await;
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        6,
        windows(),
    )
    .await
    .unwrap();
    let selected = fixture.selected_state(6).await;
    let (arrived, release) = fixture.fs.before_slot(fixture.next_checkpoint_slot().await);
    let arrival =
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut operation = Box::pin(collection.mark_batch(1));
    tokio::select! {
        result = &mut operation => panic!("checkpoint ended before queued dispatch: {result:?}"),
        result = arrival => result.unwrap(),
    }
    // Renewal extends 1100 to 2100 using this exact injected clock instance.
    fixture.clock.set(2_100, 1);
    release.send(()).unwrap();
    assert!(operation.await.is_err());
    assert_eq!(fixture.selected_state(6).await, selected);

    fixture.clock.set(101, 2);
    fixture.fs.reset();
    assert!(collection.mark_batch(1).await.is_err());
    assert_eq!(fixture.fs.effects(), 0);
    drop(collection);
    fixture.cleanup();
}
