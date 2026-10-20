//! Checks missing-Trash recovery, fresh epochs, durable absence and local cancellation.

use super::support::*;
use crate::gc::runner::{Collection, CollectionError};
use crate::pack::{PackId, RecordState};
use crate::store::native_publication_effects::collection::test_fs::RetirementPhase;
use crate::store::native_publication_effects::collection_local_deletion::DeletionBoundary;
use crate::store::{Clock, ContentStore, EffectFault, StoreErrorKind};
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::gc::{CreationJournal, DeletePhase, JournalState, Phase, Tombstone};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Requires physical absence instead of treating another metadata error as missing.
#[track_caller]
fn assert_absent(path: &std::path::Path) {
    assert_eq!(
        std::fs::symlink_metadata(path).require_error().kind(),
        std::io::ErrorKind::NotFound
    );
}

/// Checks actual serving rows independently of the active exclusion binding.
fn assert_pack_rows(selected: &Image, pack: PackId, state: RecordState) {
    let mut members = 0;
    for shard in &selected.manifest.shards {
        let key = format!(
            "objects/index/{}/{}.idx",
            selected.manifest.generation, shard.shard
        );
        let rows = terrane_format::pack_format::decode_shard(
            selected.logical[&key].as_deref().require(),
            u8::try_from(shard.shard).require(),
        )
        .require();
        for row in rows.iter().filter(|row| row.pack == *pack.as_bytes()) {
            assert_eq!(row.state, state as u8);
            members += 1;
        }
    }
    assert!(members > 0);
}

/// Checks unaffected authority and prior logical values across catalog/lease changes.
fn assert_current_values(before: &Image, after: &Image) {
    assert_eq!(after.state.binding, before.state.binding);
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.branches, before.state.branches);
    assert_eq!(after.state.burn_owners, before.state.burn_owners);
    assert_eq!(after.manifest.inventory, before.manifest.inventory);
    assert_eq!(after.manifest.burns, before.manifest.burns);
    let mut expected_cap = before.cap.clone();
    expected_cap.generation = after.cap.generation;
    assert_eq!(after.cap, expected_cap);
    for (key, value) in &before.logical {
        if key != "gc/lease" && key != "CAPABILITIES" {
            assert_eq!(after.logical.get(key), Some(value));
        }
    }
}

#[tokio::test]
async fn missing_trash_crash_requires_fresh_retirement_and_full_d_before_done() {
    let mut fixture = Fixture::new().await;
    let (pack, upper) = orphan(&fixture).await;
    let pair = [
        fixture.config.root.join(pack.pack_key()),
        fixture.config.root.join(pack.index_key()),
    ];
    let bodies = pair.each_ref().map(|path| std::fs::read(path).require());
    let creators = [pack.pack_key(), pack.index_key()]
        .each_ref()
        .map(|key| std::fs::read(journal(&fixture, key)).require());
    let wall = upper.checked_add(windows().grace() + 1).require();
    fixture.clock.set(wall, wall.checked_sub(100).require());
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "missing-trash-collector".into(),
        10,
        51,
        windows(),
    )
    .await
    .require();
    collection.mark_batch(32).await.require();
    collection.finish_mark().await.require();
    let original = image(&fixture).await;

    // This real durability failure happens after exclusion publication but
    // before any Trash artifact exists. No old time or tombstone is fabricated.
    fixture.base.fs.fail_next_retirement(
        RetirementPhase::Pending,
        EffectFault::BeforeDirectorySync,
        false,
    );
    let error = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .require_error();
    assert_io(&error, "injected creation directory sync failure");
    fixture.base.fs.assert_retirement_hook_consumed();
    let crashed = image(&fixture).await;
    assert_current_values(&original, &crashed);
    assert_eq!(
        crashed.state.loss_generation,
        original.state.loss_generation + 1
    );
    assert!(crashed.cap.generation.require() > original.cap.generation.require());
    let old = crashed
        .manifest
        .exclusions
        .as_ref()
        .require()
        .iter()
        .find(|row| row.pack_id == *pack.as_bytes())
        .require()
        .clone();
    assert_eq!(old.cycle, collection.roots().cycle);
    assert_eq!(old.epoch, collection.lease().epoch);
    let mut exclusions = original.manifest.exclusions.clone().require();
    exclusions.push(old.clone());
    exclusions.sort_by_key(|row| row.pack_id);
    assert_eq!(crashed.manifest.exclusions, Some(exclusions));
    assert_pack_rows(&crashed, pack, RecordState::Tombstone);
    let old_trash_key = format!("trash/{}/{pack}", old.cycle);
    let old_trash = fixture.config.root.join(&old_trash_key);
    assert_absent(&old_trash);
    let pending_bytes = std::fs::read(journal(&fixture, &old_trash_key)).require();
    let pending_creator = CreationJournal::decode(&pending_bytes).require();
    assert_eq!(pending_creator.key, old_trash_key);
    assert_eq!(pending_creator.state, JournalState::Pending);
    drop(collection);

    fixture.reopen().await;
    let mut rejected = fresh_collection(&fixture, 210).await;
    let before_refusal = image(&fixture).await;
    assert_absent(&old_trash);
    assert!(
        before_refusal
            .manifest
            .exclusions
            .as_ref()
            .require()
            .contains(&old)
    );
    let error = rejected
        .own_local_pack(fixture.repository.coordinator(), old.clone())
        .await
        .require_error();
    assert!(matches!(error, CollectionError::Store(ref failure)
        if matches!(failure.kind(), StoreErrorKind::Denied {
            verb: "gc-first-ownership", pattern
        } if pattern == "current exact retired local triple")));
    let after_refusal = image(&fixture).await;
    assert_current_values(&before_refusal, &after_refusal);
    assert_eq!(after_refusal.manifest, before_refusal.manifest);
    assert_eq!(after_refusal.state.sources, before_refusal.state.sources);
    assert_eq!(
        after_refusal.state.loss_generation,
        before_refusal.state.loss_generation
    );
    let identity = TERRANE_V1
        .calculate(
            IdentityKind::Chunk,
            b"unreferenced genuine retirement candidate",
        )
        .require();
    assert_eq!(
        fixture.guard().store().has(&[identity]).await.require(),
        vec![false]
    );
    for (index, path) in pair.iter().enumerate() {
        assert_eq!(std::fs::read(path).require(), bodies[index]);
        let key = [pack.pack_key(), pack.index_key()][index].clone();
        assert_eq!(
            std::fs::read(journal(&fixture, &key)).require(),
            creators[index]
        );
    }
    assert_absent(&old_trash);
    assert!(fixture.fs.submitted().is_empty());
    assert!(fixture.fs.completed().is_empty());
    drop(rejected);

    let mut recovery = fresh_collection(&fixture, 211).await;
    let before_restore = image(&fixture).await;
    assert!(recovery.restore_pack(old.clone()).await.require());
    let restored = image(&fixture).await;
    assert_current_values(&before_restore, &restored);
    assert_eq!(restored.state.sources, before_restore.state.sources);
    assert_eq!(
        restored.state.loss_generation,
        before_restore.state.loss_generation
    );
    assert!(restored.cap.generation.require() > before_restore.cap.generation.require());
    let mut exclusions = before_restore.manifest.exclusions.clone().require();
    exclusions.retain(|row| row.pack_id != old.pack_id);
    assert_eq!(restored.manifest.exclusions, Some(exclusions));
    assert_pack_rows(&restored, pack, RecordState::Live);
    assert_absent(&old_trash);
    drop(recovery);

    // Restore and fresh retirement establish a new pre-deletion baseline.
    // No reopening follows that snapshot, so preserve its complete capabilities.
    fixture.reopened_capabilities = None;

    // Time preceding the new incarnation cannot shorten its new full-D wait.
    // Actual pack/index modification times independently establish fresh G.
    let previous = fixture.selected_lease().await;
    let ticks = fixture.clock.monotonic().as_secs();
    fixture.clock.set(
        previous
            .expiry
            .checked_add(windows().deletion() + 1)
            .require(),
        ticks.checked_add(windows().deletion() + 1).require(),
    );
    let mut fresh = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "fresh-trash-collector".into(),
        10,
        212,
        windows(),
    )
    .await
    .require();
    fresh.mark_batch(32).await.require();
    fresh.finish_mark().await.require();
    assert_eq!(fresh.state().phase, Phase::Sweep);
    assert_ne!(fresh.roots().cycle, old.cycle);
    assert!(fresh.lease().epoch > old.epoch);
    let fresh_upper = rounded_modified(&pair[0]).max(rounded_modified(&pair[1]));
    assert_eq!(fresh_upper, upper);
    let now = fixture
        .clock
        .now()
        .duration_since(UNIX_EPOCH)
        .require()
        .as_secs();
    assert!(now.checked_sub(fresh_upper).require() > windows().grace());
    let before_retirement = image(&fixture).await;
    let trash = fresh
        .retire_one(fixture.repository.coordinator())
        .await
        .require()
        .require();
    assert_eq!(trash.pack, old.pack_id);
    assert_eq!(trash.cycle, fresh.roots().cycle);
    assert_eq!(trash.epoch, fresh.lease().epoch);
    assert_ne!(trash.cycle, old.cycle);
    assert!(trash.epoch > old.epoch);
    assert!(
        trash
            .timestamp
            .checked_sub(crashed.manifest.written_at)
            .require()
            >= windows().deletion()
    );
    let selected = image(&fixture).await;
    assert_current_values(&before_retirement, &selected);
    assert_eq!(
        selected.state.loss_generation,
        before_retirement.state.loss_generation + 1
    );
    let requested = selected
        .manifest
        .exclusions
        .as_ref()
        .require()
        .iter()
        .find(|row| row.pack_id == old.pack_id)
        .require()
        .clone();
    assert_eq!(requested.cycle, trash.cycle);
    assert_eq!(requested.epoch, trash.epoch);
    assert_pack_rows(&selected, pack, RecordState::Tombstone);
    assert!(!fresh.restore_pack(old).await.require());
    assert_absent(&old_trash);
    let original = before(&fixture, &requested).await;
    assert_eq!(original.bodies[..2], bodies);
    assert_eq!(Tombstone::decode(&original.bodies[2]).require(), trash);
    assert_eq!(
        std::fs::read(journal(&fixture, &old_trash_key)).require(),
        pending_bytes
    );
    assert_ne!(original.journals[2].nonce, pending_creator.nonce);

    let initial_lease = fresh.lease().clone();
    fixture.clock.enable_timer();
    let started = fixture.clock.monotonic();
    let owned = fresh
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    assert!(
        fixture.clock.monotonic().checked_sub(started).require()
            >= Duration::from_secs(windows().deletion())
    );
    assert!(owned.authorization.elapsed_ns >= windows().deletion() * 1_000_000_000);
    assert_eq!(owned.authorization.cycle, trash.cycle);
    assert_eq!(owned.authorization.epoch, trash.epoch);
    assert_eq!(fresh.lease().epoch, initial_lease.epoch);
    assert_eq!(fresh.lease().holder, initial_lease.holder);
    assert!(fresh.lease().expiry > initial_lease.expiry);
    for (index, path) in original.paths.iter().enumerate() {
        assert_eq!(std::fs::read(path).require(), original.bodies[index]);
    }
    let done = fresh
        .resume_local_delete(
            fixture.repository.coordinator(),
            &owned.authorization.operation_key(),
        )
        .await
        .require();
    assert_done(&fixture, &original, &owned, &done).await;
    let completed = image(&fixture).await;
    assert_eq!(completed.cap, selected.cap);
    assert_eq!(completed.manifest, selected.manifest);
    assert_eq!(completed.state.sources, selected.state.sources);
    assert_eq!(
        completed.state.loss_generation,
        selected.state.loss_generation
    );
    assert_current_values(&selected, &completed);
    assert_absent(&old_trash);
    assert_eq!(fixture.base.fs.data_body_read_attempts(), 0);
    drop(fresh);
    fixture.cleanup();
}

#[tokio::test]
async fn fresh_higher_epoch_resumes_each_real_durable_prefix_without_old_marks() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();
    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    let key = owned.authorization.operation_key();
    drop(collection);

    for (cycle, phase) in [
        DeletePhase::Invalidated,
        DeletePhase::PackAbsent,
        DeletePhase::IndexAbsent,
        DeletePhase::ContainersConfirmed,
    ]
    .into_iter()
    .enumerate()
    {
        let mut fresh = fresh_collection(&fixture, 100 + cycle as u64).await;
        assert_ne!(fresh.roots().cycle, owned.authorization.cycle);
        fixture.fs.fault(phase, EffectFault::BeforeFileSync);
        let error = fresh
            .resume_local_delete(fixture.repository.coordinator(), &key)
            .await
            .require_error();
        assert!(
            matches!(error, crate::gc::runner::CollectionError::Store(ref error) if error.kind() == &StoreErrorKind::Unavailable { retry_after: None })
        );
        assert_io(&error, "injected creation file sync failure");
        fixture.fs.assert_consumed();
        assert_eq!(operation(&fixture, &key).authorization, owned.authorization);
        drop(fresh);
    }
    let mut fresh = fresh_collection(&fixture, 200).await;
    let done = fresh
        .resume_local_delete(fixture.repository.coordinator(), &key)
        .await
        .require();
    assert_done(&fixture, &original, &owned, &done).await;
    drop(fresh);
    fixture.cleanup();
}

#[tokio::test]
async fn owned_absence_resynchronizes_before_phase_and_done_is_idempotent() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();
    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    let key = owned.authorization.operation_key();
    fixture
        .fs
        .fault(DeletePhase::Invalidated, EffectFault::AfterUnlink);
    let error = collection
        .resume_local_delete(fixture.repository.coordinator(), &key)
        .await
        .require_error();
    assert!(
        matches!(error, crate::gc::runner::CollectionError::Store(ref error) if error.kind() == &StoreErrorKind::Unavailable { retry_after: None })
    );
    assert_io(&error, "injected local failure after unlink");
    fixture.fs.assert_consumed();
    assert!(!original.paths[0].exists());
    assert_eq!(operation(&fixture, &key).phase, DeletePhase::Invalidated);
    drop(collection);

    let mut fresh = fresh_collection(&fixture, 201).await;
    fixture
        .fs
        .fault(DeletePhase::Invalidated, EffectFault::BeforeDirectorySync);
    assert_io(
        &fresh
            .resume_local_delete(fixture.repository.coordinator(), &key)
            .await
            .require_error(),
        "injected creation directory sync failure",
    );
    fixture.fs.assert_consumed();
    assert_eq!(operation(&fixture, &key).phase, DeletePhase::Invalidated);
    drop(fresh);
    let mut fresh = fresh_collection(&fixture, 202).await;
    let done = fresh
        .resume_local_delete(fixture.repository.coordinator(), &key)
        .await
        .require();
    assert_done(&fixture, &original, &owned, &done).await;
    assert_eq!(
        fresh
            .resume_local_delete(fixture.repository.coordinator(), &key)
            .await
            .require(),
        done
    );
    drop(fresh);
    fixture.cleanup();
}

#[tokio::test]
async fn cancelled_waiter_retains_exclusion_until_worker_then_fresh_collector_finishes() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();
    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    let key = owned.authorization.operation_key();
    let (arrived, release) = fixture
        .fs
        .pause(DeletePhase::Invalidated, DeletionBoundary::BeforeOpen);
    let mut pending =
        Box::pin(collection.resume_local_delete(fixture.repository.coordinator(), &key));
    tokio::select! {
        result = &mut pending => panic!("operation completed before genuine worker handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    drop(pending);
    // The actual native worker still retains the same namespace exclusion.
    let coordination = fixture.config.root.join(
        terrane_format::bucket::BucketKey::parse("CAPABILITIES")
            .require()
            .lock_name(),
    );
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(coordination)
        .require();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(contender);

    {
        let competing = crate::bucket::held::SingleHeld::acquire(fixture.guard().store());
        release.send(()).require();
        let holder = tokio::time::timeout(Duration::from_secs(90), competing)
            .await
            .require()
            .require();
        drop(holder);
    }
    fixture.fs.assert_consumed();
    drop(collection);

    let mut fresh = fresh_collection(&fixture, 203).await;
    let done = fresh
        .resume_local_delete(fixture.repository.coordinator(), &key)
        .await
        .require();
    assert_done(&fixture, &original, &owned, &done).await;
    drop(fresh);
    fixture.cleanup();
}

#[tokio::test]
async fn changed_current_fence_reconciles_retained_index_after_container_absence() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let mut original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();
    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    let key = owned.authorization.operation_key();
    fixture
        .fs
        .fault(DeletePhase::ContainersConfirmed, EffectFault::BeforeUnlink);
    assert_io(
        &collection
            .resume_local_delete(fixture.repository.coordinator(), &key)
            .await
            .require_error(),
        "injected local unlink failure",
    );
    fixture.fs.assert_consumed();
    assert_eq!(
        operation(&fixture, &key).phase,
        DeletePhase::ContainersConfirmed
    );
    assert!(!original.paths[0].exists());
    assert!(!original.paths[1].exists());
    assert!(original.paths[2].exists());
    drop(collection);
    fixture
        .base
        .publish_notes(&[(
            "refs/notes/profiles/_/reconciliation",
            b"fresh current inventory",
        )])
        .await;

    original.logical = image(&fixture).await.logical;
    original.logical.remove("gc/lease");
    let mut fresh = fresh_collection(&fixture, 204).await;
    let done = fresh
        .resume_local_delete(fixture.repository.coordinator(), &key)
        .await
        .require();
    assert_done(&fixture, &original, &owned, &done).await;
    let selected = image(&fixture).await;
    let note_key =
        terrane_format::bucket::BucketKey::ref_record("refs/notes/profiles/_/reconciliation")
            .require();
    assert_eq!(
        selected.logical[note_key.as_str()].as_deref(),
        Some(b"fresh current inventory".as_slice())
    );
    drop(fresh);
    fixture.cleanup();
}

async fn cancellation_prefix(partial_owner: bool, invalidated: Option<u8>) {
    let mut fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();
    let owned = if partial_owner {
        fixture
            .fs
            .fault_first_ownership(2, EffectFault::BeforeFileSync);
        assert_io(
            &collection
                .own_local_pack(fixture.repository.coordinator(), requested.clone())
                .await
                .require_error(),
            "injected creation file sync failure",
        );
        fixture.fs.assert_consumed();
        let version = &original.journals[0];
        let record = terrane_format::gc::CreationJournal::decode(
            &std::fs::read(journal(&fixture, &version.key)).require(),
        )
        .require();
        let terrane_format::gc::JournalState::DeleteOwned { operation_key, .. } = record.state
        else {
            panic!("first ownership did not produce its actual prefix")
        };
        operation(&fixture, &operation_key)
    } else {
        collection
            .own_local_pack(fixture.repository.coordinator(), requested.clone())
            .await
            .require()
    };
    let key = owned.authorization.operation_key();
    drop(collection);
    fixture.reopen().await;
    let mut fresh = fresh_collection(&fixture, 205).await;
    let fault = invalidated.map_or(
        EffectFault::AfterCancelledIntentSync,
        EffectFault::BeforeCancelledJournalDirectorySync,
    );
    fixture.fs.fault(DeletePhase::Cancelled, fault);
    assert_io(
        &fresh.restore_pack(requested.clone()).await.require_error(),
        if invalidated.is_some() {
            "injected directory sync after journal invalidation"
        } else {
            "injected failure after durable Cancelled intent"
        },
    );
    fixture.fs.assert_consumed();
    assert_eq!(operation(&fixture, &key).phase, DeletePhase::Cancelled);
    assert!(
        image(&fixture)
            .await
            .manifest
            .exclusions
            .as_ref()
            .require()
            .iter()
            .any(|row| row.pack_id == requested.pack_id)
    );
    for (index, creator) in original.journals.iter().enumerate() {
        let actual = terrane_format::gc::CreationJournal::decode(
            &std::fs::read(journal(&fixture, &creator.key)).require(),
        )
        .require();
        assert_eq!(actual.nonce, creator.nonce);
        if invalidated.is_some_and(|prefix| index <= usize::from(prefix)) {
            assert_eq!(actual.state, terrane_format::gc::JournalState::Invalidated);
        } else if partial_owner && index > 0 {
            assert_eq!(actual, *creator);
        } else {
            assert!(matches!(
                actual.state,
                terrane_format::gc::JournalState::DeleteOwned { .. }
            ));
        }
    }
    drop(fresh);
    if invalidated == Some(2) {
        // All visible Invalidated journals cannot silently take ordinary restore
        // when their protected cancellation intent is missing or misnamed.
        let path = fixture.parent.join("publication").join(&key);
        let cancelled = std::fs::read(&path).require();
        std::fs::remove_file(&path).require();
        fixture.reopen().await;
        let mut fresh = fresh_collection(&fixture, 207).await;
        let error = fresh.restore_pack(requested.clone()).await.require_error();
        let crate::gc::runner::CollectionError::Store(error) = error else {
            panic!("expected exact protected lookup refusal: {error:?}")
        };
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Corrupt(crate::store::CorruptSubject::RefName("publication".into()))
        );
        drop(fresh);
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut restored = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .require();
        restored.write_all(&cancelled).require();
        restored.sync_all().require();
        let alias =
            path.with_file_name("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert_ne!(alias, path);
        let mut detached = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&alias)
            .require();
        detached.write_all(&cancelled).require();
        detached.sync_all().require();
        fixture.reopen().await;
        let mut fresh = fresh_collection(&fixture, 208).await;
        let error = fresh.restore_pack(requested.clone()).await.require_error();
        let crate::gc::runner::CollectionError::Store(error) = error else {
            panic!("expected exact misbound intent refusal: {error:?}")
        };
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Corrupt(crate::store::CorruptSubject::RefName("publication".into()))
        );
        drop(fresh);
        std::fs::remove_file(alias).require();
    }
    fixture.reopen().await;
    let mut fresh = fresh_collection(&fixture, 209).await;
    assert!(fresh.restore_pack(requested.clone()).await.require());
    for (index, path) in original.paths.iter().enumerate() {
        assert_eq!(std::fs::read(path).require(), original.bodies[index]);
        let creator = terrane_format::gc::CreationJournal::decode(
            &std::fs::read(journal(&fixture, &original.journals[index].key)).require(),
        )
        .require();
        assert_eq!(creator.nonce, original.journals[index].nonce);
        assert_eq!(creator.state, terrane_format::gc::JournalState::Invalidated);
    }
    assert!(
        !image(&fixture)
            .await
            .manifest
            .exclusions
            .as_ref()
            .require()
            .iter()
            .any(|row| row.pack_id == requested.pack_id)
    );
    assert_eq!(operation(&fixture, &key).authorization, owned.authorization);
    drop(fresh);
    fixture.cleanup();
}

#[tokio::test]
async fn restore_durably_cancels_exact_local_owner_before_clearing_exclusion() {
    tokio::join!(
        cancellation_prefix(true, None),
        cancellation_prefix(false, None),
        cancellation_prefix(false, Some(0)),
        cancellation_prefix(false, Some(1)),
        cancellation_prefix(false, Some(2)),
    );
}

#[tokio::test]
async fn restore_durably_cancels_authorized_only_local_intent_before_clearing_exclusion() {
    let mut fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();

    // Boundary zero durably publishes Authorized; boundary one has not yet
    // replaced the first creator journal when this actual sync fails.
    fixture
        .fs
        .fault_first_ownership(1, EffectFault::BeforeFileSync);
    assert_io(
        &collection
            .own_local_pack(fixture.repository.coordinator(), requested.clone())
            .await
            .require_error(),
        "injected creation file sync failure",
    );
    fixture.fs.assert_consumed();
    let directory = fixture.parent.join("publication").join(format!(
        "gc/{}/delete/{}",
        requested.cycle,
        PackId::from_random_bytes(requested.pack_id)
    ));
    let paths = std::fs::read_dir(&directory)
        .require()
        .map(|entry| entry.require().path())
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    let key = paths[0]
        .strip_prefix(fixture.parent.join("publication"))
        .require()
        .to_str()
        .require()
        .to_owned();
    let authorized = operation(&fixture, &key);
    assert_eq!(authorized.phase, DeletePhase::Authorized);
    for creator in &original.journals {
        assert_eq!(
            CreationJournal::decode(&std::fs::read(journal(&fixture, &creator.key)).require())
                .require(),
            *creator
        );
    }
    drop(collection);

    fixture.reopen().await;
    let mut fresh = fresh_collection(&fixture, 220).await;
    let selected = image(&fixture).await;
    fixture
        .fs
        .fault(DeletePhase::Cancelled, EffectFault::BeforeFileSync);
    assert_io(
        &fresh.restore_pack(requested.clone()).await.require_error(),
        "injected creation file sync failure",
    );
    fixture.fs.assert_consumed();
    assert_eq!(operation(&fixture, &key), authorized);
    // The real pre-rename sync failure leaves cancellation staging beside the
    // genuine operation. Reopen must retain it as private residue, not authority.
    let staging = std::fs::read_dir(&directory)
        .require()
        .map(|entry| entry.require().path())
        .filter(|path| {
            path.file_name()
                .require()
                .to_str()
                .require()
                .starts_with(".cancel-")
        })
        .collect::<Vec<_>>();
    assert_eq!(staging.len(), 1);
    let staging_path = &staging[0];
    let staging_name = staging_path.file_name().require().to_str().require();
    let staging_nonce = staging_name.strip_prefix(".cancel-").require();
    assert_eq!(staging_nonce.len(), 32);
    assert!(
        staging_nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let staging_bytes = std::fs::read(staging_path).require();
    let staged = terrane_format::gc::DeleteOperation::decode(&staging_bytes, &key).require();
    assert_eq!(staged.phase, DeletePhase::Cancelled);
    assert_eq!(staged.authorization, authorized.authorization);
    let refused = image(&fixture).await;
    assert_eq!(refused.manifest, selected.manifest);
    assert_eq!(refused.cap, selected.cap);
    assert_current_values(&selected, &refused);
    for (index, path) in original.paths.iter().enumerate() {
        assert_eq!(std::fs::read(path).require(), original.bodies[index]);
        assert_eq!(
            CreationJournal::decode(
                &std::fs::read(journal(&fixture, &original.journals[index].key)).require()
            )
            .require(),
            original.journals[index]
        );
    }
    drop(fresh);

    fixture.reopen().await;
    let mut fresh = fresh_collection(&fixture, 221).await;
    fixture.fs.fault(
        DeletePhase::Cancelled,
        EffectFault::AfterCancelledIntentSync,
    );
    assert_io(
        &fresh.restore_pack(requested.clone()).await.require_error(),
        "injected failure after durable Cancelled intent",
    );
    fixture.fs.assert_consumed();
    assert_eq!(operation(&fixture, &key).phase, DeletePhase::Cancelled);
    assert_eq!(
        operation(&fixture, &key).authorization,
        authorized.authorization
    );
    assert!(
        image(&fixture)
            .await
            .manifest
            .exclusions
            .as_ref()
            .require()
            .contains(&requested)
    );
    for creator in &original.journals {
        assert_eq!(
            CreationJournal::decode(&std::fs::read(journal(&fixture, &creator.key)).require())
                .require(),
            *creator
        );
    }
    drop(fresh);

    fixture.reopen().await;
    let mut fresh = fresh_collection(&fixture, 222).await;
    fixture.fs.fault(
        DeletePhase::Cancelled,
        EffectFault::BeforeCancelledJournalDirectorySync(2),
    );
    assert_io(
        &fresh.restore_pack(requested.clone()).await.require_error(),
        "injected directory sync after journal invalidation",
    );
    fixture.fs.assert_consumed();
    assert_eq!(operation(&fixture, &key).phase, DeletePhase::Cancelled);
    assert!(
        image(&fixture)
            .await
            .manifest
            .exclusions
            .as_ref()
            .require()
            .contains(&requested)
    );
    for creator in &original.journals {
        let actual =
            CreationJournal::decode(&std::fs::read(journal(&fixture, &creator.key)).require())
                .require();
        assert_eq!(actual.key, creator.key);
        assert_eq!(actual.nonce, creator.nonce);
        assert_eq!(actual.state, JournalState::Invalidated);
    }
    drop(fresh);

    fixture.reopen().await;
    let mut fresh = fresh_collection(&fixture, 223).await;
    assert!(fresh.restore_pack(requested.clone()).await.require());
    assert_eq!(operation(&fixture, &key).phase, DeletePhase::Cancelled);
    assert_eq!(
        operation(&fixture, &key).authorization,
        authorized.authorization
    );
    let restored = image(&fixture).await;
    assert!(
        !restored
            .manifest
            .exclusions
            .as_ref()
            .require()
            .contains(&requested)
    );
    assert_pack_rows(
        &restored,
        PackId::from_random_bytes(requested.pack_id),
        RecordState::Live,
    );
    for (index, path) in original.paths.iter().enumerate() {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path).require();
        assert_eq!((metadata.dev(), metadata.ino()), original.identities[index]);
        assert_eq!(std::fs::read(path).require(), original.bodies[index]);
        let creator = CreationJournal::decode(
            &std::fs::read(journal(&fixture, &original.journals[index].key)).require(),
        )
        .require();
        assert_eq!(creator.key, original.journals[index].key);
        assert_eq!(creator.nonce, original.journals[index].nonce);
        assert_eq!(creator.state, JournalState::Invalidated);
    }
    assert_eq!(std::fs::read(staging_path).require(), staging_bytes);
    assert_eq!(fixture.base.fs.data_body_read_attempts(), 0);
    drop(fresh);
    fixture.cleanup();
}
